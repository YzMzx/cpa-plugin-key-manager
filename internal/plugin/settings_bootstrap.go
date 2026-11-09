package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// The process lock serializes this editor; the file digest also detects external edits.
var bootstrapFileMu sync.Mutex

type settingsBootstrapError string

func (e settingsBootstrapError) Error() string {
	switch e {
	case "conflict":
		return "host configuration changed; reload advanced settings and retry"
	case "invalid":
		return "invalid bootstrap settings or missing restart/storage acknowledgement"
	default:
		return "host bootstrap configuration is unavailable"
	}
}
func (e settingsBootstrapError) SettingsBootstrapCode() string { return string(e) }

const (
	bootstrapConflict    settingsBootstrapError = "conflict"
	bootstrapInvalid     settingsBootstrapError = "invalid"
	bootstrapUnavailable settingsBootstrapError = "unavailable"
	bootstrapConfigLimit                        = 16 << 20
	bootstrapJSONLimit                          = 32 << 10
)

type bootstrapValues struct {
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	UsageDBFile string `json:"usage_db_file"`
}

type bootstrapSaveRequest struct {
	Revision  string `json:"expected_file_revision"`
	Bootstrap struct {
		Enabled     *bool   `json:"enabled"`
		Priority    *int    `json:"priority"`
		UsageDBFile *string `json:"usage_db_file"`
	} `json:"bootstrap"`
	AckRestart           bool `json:"ack_restart"`
	AckStoragePathChange bool `json:"ack_storage_path_change"`
}

// BootstrapSettings reports active values separately from restart-staged disk values.
// YAML content, removed legacy fields and low-level errors are never returned.
func (m *Manager) BootstrapSettings() map[string]any {
	m.mu.RLock()
	effective := bootstrapValues{Enabled: m.cfg.Enabled, Priority: m.cfg.Priority, UsageDBFile: m.cfg.Storage.UsageDBFile}
	m.mu.RUnlock()
	bootstrapFileMu.Lock()
	defer bootstrapFileMu.Unlock()
	return bootstrapSettingsView(effective)
}
func bootstrapSettingsView(effective bootstrapValues) map[string]any {
	result := map[string]any{"effective": effective, "configured": effective, "file_revision": "", "db_path_locked_by_env": strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_USAGE_DB")) != "", "available": false}
	raw, _, err := readBootstrapFile(FindHostConfigFile(""))
	if err != nil {
		result["error"] = bootstrapUnavailable.Error()
		return result
	}
	doc, err := parseBootstrapDocument(raw)
	if err != nil {
		result["error"] = bootstrapUnavailable.Error()
		return result
	}
	configured, _, err := readBootstrapValues(doc)
	if err != nil {
		result["error"] = bootstrapUnavailable.Error()
		return result
	}
	result["configured"] = configured
	result["file_revision"] = bootstrapRevision(raw)
	result["available"] = true
	return result
}

// SaveBootstrapSettings changes only three active plugin-local YAML settings. It does not
// call Configure, move/copy databases, mutate the effective configuration or change
// global plugins.enabled/plugins.dir. Host file watching may reload these staged
// values; loading a different database path still requires a host restart.
func (m *Manager) SaveBootstrapSettings(rawBody []byte) (map[string]any, error) {
	request, err := decodeBootstrapRequest(rawBody)
	if err != nil {
		return nil, err
	}
	bootstrapFileMu.Lock()
	defer bootstrapFileMu.Unlock()
	path := FindHostConfigFile("")
	raw, info, err := readBootstrapFile(path)
	if err != nil {
		return nil, bootstrapUnavailable
	}
	if !strings.EqualFold(request.Revision, bootstrapRevision(raw)) {
		return nil, bootstrapConflict
	}
	doc, err := parseBootstrapDocument(raw)
	if err != nil {
		return nil, bootstrapUnavailable
	}
	configured, _, err := readBootstrapValues(doc)
	if err != nil {
		return nil, bootstrapUnavailable
	}
	wantedPath := strings.TrimSpace(*request.Bootstrap.UsageDBFile)
	pathChanged := wantedPath != configured.UsageDBFile
	if strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_USAGE_DB")) != "" && pathChanged {
		return nil, bootstrapInvalid
	}
	if pathChanged && !request.AckStoragePathChange {
		return nil, bootstrapInvalid
	}
	root := doc.Content[0]
	plugins, err := bootstrapEnsureMap(root, "plugins")
	if err != nil {
		return nil, err
	}
	configs, err := bootstrapEnsureMap(plugins, "configs")
	if err != nil {
		return nil, err
	}
	plugin, err := bootstrapEnsureMap(configs, PluginID)
	if err != nil {
		return nil, err
	}
	if err := bootstrapSet(plugin, "enabled", "!!bool", strconv.FormatBool(*request.Bootstrap.Enabled)); err != nil {
		return nil, err
	}
	if err := bootstrapSet(plugin, "priority", "!!int", strconv.Itoa(*request.Bootstrap.Priority)); err != nil {
		return nil, err
	}
	storage, err := bootstrapEnsureMap(plugin, "storage")
	if err != nil {
		return nil, err
	}
	if err := bootstrapSet(storage, "usage_db_file", "!!str", wantedPath); err != nil {
		return nil, err
	}
	// Remove obsolete fields only inside this plugin's own YAML subtree.
	if err := bootstrapRemove(plugin, "admin_token"); err != nil {
		return nil, err
	}
	if err := bootstrapRemove(storage, "usage_file", "rules_file"); err != nil {
		return nil, err
	}
	if audit, err := bootstrapChildMap(plugin, "audit"); err != nil {
		return nil, err
	} else if audit != nil {
		if err := bootstrapRemove(audit, "trusted_proxies"); err != nil {
			return nil, err
		}
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return nil, bootstrapUnavailable
	}
	if err := encoder.Close(); err != nil {
		return nil, bootstrapUnavailable
	}
	if output.Len() > bootstrapConfigLimit {
		return nil, bootstrapUnavailable
	}
	if !bytes.Equal(output.Bytes(), raw) {
		if err := writeBootstrapFileCAS(path, output.Bytes(), info, bootstrapRevision(raw)); err != nil {
			return nil, err
		}
	}
	m.mu.RLock()
	effective := bootstrapValues{Enabled: m.cfg.Enabled, Priority: m.cfg.Priority, UsageDBFile: m.cfg.Storage.UsageDBFile}
	m.mu.RUnlock()
	return map[string]any{"ok": true, "requires_restart": true, "bootstrap": bootstrapSettingsView(effective)}, nil
}

func bootstrapRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func readBootstrapFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > bootstrapConfigLimit {
		return nil, nil, bootstrapUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, bootstrapUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, bootstrapConfigLimit+1))
	if err != nil || len(raw) > bootstrapConfigLimit {
		return nil, nil, bootstrapUnavailable
	}
	return raw, info, nil
}
func parseBootstrapDocument(raw []byte) (*yaml.Node, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&doc) != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, bootstrapUnavailable
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, bootstrapUnavailable
	}
	return &doc, nil
}
func bootstrapField(mapping *yaml.Node, key string) (*yaml.Node, error) {
	if mapping == nil {
		return nil, nil
	}
	if mapping.Kind != yaml.MappingNode {
		return nil, bootstrapUnavailable
	}
	var found *yaml.Node
	seen := map[string]bool{}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		name := mapping.Content[i]
		if name.Kind != yaml.ScalarNode || name.Value == "<<" || seen[name.Value] {
			return nil, bootstrapUnavailable
		}
		seen[name.Value] = true
		if name.Value == key {
			found = mapping.Content[i+1]
		}
	}
	return found, nil
}
func bootstrapChildMap(mapping *yaml.Node, key string) (*yaml.Node, error) {
	node, err := bootstrapField(mapping, key)
	if err != nil || node == nil {
		return node, err
	}
	if node.Kind != yaml.MappingNode || node.Anchor != "" {
		return nil, bootstrapUnavailable
	}
	return node, nil
}
func readBootstrapValues(doc *yaml.Node) (bootstrapValues, *yaml.Node, error) {
	defaults := DefaultConfig()
	values := bootstrapValues{Enabled: defaults.Enabled, Priority: defaults.Priority, UsageDBFile: defaults.Storage.UsageDBFile}
	root := doc.Content[0]
	plugins, err := bootstrapChildMap(root, "plugins")
	if err != nil {
		return values, nil, err
	}
	configs, err := bootstrapChildMap(plugins, "configs")
	if err != nil {
		return values, nil, err
	}
	plugin, err := bootstrapChildMap(configs, PluginID)
	if err != nil {
		return values, nil, err
	}
	if plugin == nil {
		return values, nil, nil
	}
	enabled, err := bootstrapField(plugin, "enabled")
	if err != nil {
		return values, nil, err
	}
	if enabled != nil && (enabled.Kind != yaml.ScalarNode || enabled.Tag != "!!bool" || enabled.Decode(&values.Enabled) != nil) {
		return values, nil, bootstrapUnavailable
	}
	priority, err := bootstrapField(plugin, "priority")
	if err != nil {
		return values, nil, err
	}
	if priority != nil && (priority.Kind != yaml.ScalarNode || priority.Tag != "!!int" || priority.Decode(&values.Priority) != nil) {
		return values, nil, bootstrapUnavailable
	}
	storage, err := bootstrapChildMap(plugin, "storage")
	if err != nil {
		return values, nil, err
	}
	path, err := bootstrapField(storage, "usage_db_file")
	if err != nil {
		return values, nil, err
	}
	if path != nil {
		if path.Kind != yaml.ScalarNode || path.Tag != "!!str" {
			return values, nil, bootstrapUnavailable
		}
		if strings.TrimSpace(path.Value) != "" {
			values.UsageDBFile = strings.TrimSpace(path.Value)
		}
	}
	return values, plugin, nil
}
func bootstrapEnsureMap(parent *yaml.Node, key string) (*yaml.Node, error) {
	node, err := bootstrapField(parent, key)
	if err != nil {
		return nil, err
	}
	if node == nil {
		node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
	}
	if node.Kind != yaml.MappingNode || node.Anchor != "" {
		return nil, bootstrapUnavailable
	}
	return node, nil
}
func bootstrapRemove(mapping *yaml.Node, keys ...string) error {
	if mapping == nil {
		return nil
	}
	remove := make(map[string]bool, len(keys))
	for _, key := range keys {
		remove[key] = true
	}
	// Removing an anchor may leave an unrelated host field with an unresolved alias.
	// Reject that uncommon legacy shape rather than rewrite other configuration.
	var hasAnchor func(*yaml.Node) bool
	hasAnchor = func(node *yaml.Node) bool {
		if node.Anchor != "" {
			return true
		}
		for _, child := range node.Content {
			if hasAnchor(child) {
				return true
			}
		}
		return false
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if remove[mapping.Content[i].Value] && hasAnchor(mapping.Content[i+1]) {
			return bootstrapUnavailable
		}
	}
	kept := make([]*yaml.Node, 0, len(mapping.Content))
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if !remove[mapping.Content[i].Value] {
			kept = append(kept, mapping.Content[i], mapping.Content[i+1])
		}
	}
	mapping.Content = kept
	return nil
}

func bootstrapSet(mapping *yaml.Node, key, tag, value string) error {
	node, err := bootstrapField(mapping, key)
	if err != nil {
		return err
	}
	if node == nil {
		node = &yaml.Node{}
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
	}
	if (node.Kind != 0 && node.Kind != yaml.ScalarNode) || node.Anchor != "" {
		return bootstrapUnavailable
	}
	head, line, foot := node.HeadComment, node.LineComment, node.FootComment
	*node = yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value, HeadComment: head, LineComment: line, FootComment: foot}
	return nil
}

func decodeBootstrapRequest(raw []byte) (bootstrapSaveRequest, error) {
	var request bootstrapSaveRequest
	if len(raw) == 0 || len(raw) > bootstrapJSONLimit {
		return request, bootstrapInvalid
	}
	var fields map[string]json.RawMessage
	if !bootstrapStrictObject(raw, map[string]bool{"expected_file_revision": true, "bootstrap": true, "ack_restart": true, "ack_storage_path_change": true}, &fields) {
		return request, bootstrapInvalid
	}
	var pluginFields map[string]json.RawMessage
	if !bootstrapStrictObject(fields["bootstrap"], map[string]bool{"enabled": true, "priority": true, "usage_db_file": true}, &pluginFields) {
		return request, bootstrapInvalid
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, bootstrapInvalid
		}
	}
	for _, value := range pluginFields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, bootstrapInvalid
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return request, bootstrapInvalid
	}
	if request.Bootstrap.Enabled == nil || request.Bootstrap.Priority == nil || request.Bootstrap.UsageDBFile == nil || !request.AckRestart {
		return request, bootstrapInvalid
	}
	if len(request.Revision) != 64 {
		return request, bootstrapInvalid
	}
	if _, err := hex.DecodeString(request.Revision); err != nil {
		return request, bootstrapInvalid
	}
	if *request.Bootstrap.Priority < -10000 || *request.Bootstrap.Priority > 10000 {
		return request, bootstrapInvalid
	}
	path := *request.Bootstrap.UsageDBFile
	if strings.TrimSpace(path) == "" || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return request, bootstrapInvalid
	}
	return request, nil
}
func bootstrapStrictObject(raw []byte, allowed map[string]bool, out *map[string]json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	values := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok || !allowed[key] {
			return false
		}
		if _, exists := values[key]; exists {
			return false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
		values[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return false
	}
	*out = values
	return true
}

// Unlike the legacy usage atomic helper, bootstrap writes retain the original
// permission bits so staging a secret never widens a 0600 host configuration.
func writeBootstrapFileCAS(path string, content []byte, original os.FileInfo, expected string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".key-manager-bootstrap-*")
	if err != nil {
		return bootstrapUnavailable
	}
	temp := file.Name()
	defer os.Remove(temp)
	if file.Chmod(original.Mode().Perm()) != nil {
		file.Close()
		return bootstrapUnavailable
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return bootstrapUnavailable
	}
	if file.Sync() != nil {
		file.Close()
		return bootstrapUnavailable
	}
	if file.Close() != nil {
		return bootstrapUnavailable
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, info, err := readBootstrapFile(path)
		if err != nil {
			return bootstrapUnavailable
		}
		if !os.SameFile(original, info) || info.Mode().Perm() != original.Mode().Perm() || bootstrapRevision(current) != expected {
			return bootstrapConflict
		}
		if err := os.Rename(temp, path); err == nil {
			return nil
		}
		if attempt < 2 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return bootstrapUnavailable
}
