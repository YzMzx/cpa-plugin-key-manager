package plugin

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"gopkg.in/yaml.v3"
)

// ReadHostConfigAPIKeys reads global client `api-keys` (or `access.api-keys`) from CLIProxyAPI's config.yaml on disk.
// hostConfigCache memoises the parsed api-keys of config.yaml keyed by path,
// modification time and size, so the admin overview does not re-read and re-parse
// the YAML on every refresh.
var hostConfigCache struct {
	sync.Mutex
	path  string
	mtime time.Time
	size  int64
	keys  []string
	valid bool
}

func ReadHostConfigAPIKeys(configPath string) []string {
	resolvedPath := FindHostConfigFile(configPath)
	info, errStat := os.Stat(resolvedPath)
	if errStat != nil || info.IsDir() {
		return nil
	}
	hostConfigCache.Lock()
	if hostConfigCache.valid && hostConfigCache.path == resolvedPath &&
		hostConfigCache.mtime.Equal(info.ModTime()) && hostConfigCache.size == info.Size() {
		cached := append([]string(nil), hostConfigCache.keys...)
		hostConfigCache.Unlock()
		return cached
	}
	hostConfigCache.Unlock()

	keys := readHostConfigAPIKeysUncached(resolvedPath)
	hostConfigCache.Lock()
	hostConfigCache.path = resolvedPath
	hostConfigCache.mtime = info.ModTime()
	hostConfigCache.size = info.Size()
	hostConfigCache.keys = append([]string(nil), keys...)
	hostConfigCache.valid = true
	hostConfigCache.Unlock()
	return keys
}

// invalidateHostConfigCache forces the next ReadHostConfigAPIKeys to re-read the
// file; used right after the plugin itself rewrites config.yaml.
func invalidateHostConfigCache() {
	hostConfigCache.Lock()
	hostConfigCache.valid = false
	hostConfigCache.Unlock()
}

func readHostConfigAPIKeysUncached(resolvedPath string) []string {
	raw, err := os.ReadFile(resolvedPath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var root struct {
		APIKeys []string `yaml:"api-keys"`
		Access  struct {
			APIKeys []string `yaml:"api-keys"`
		} `yaml:"access"`
	}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(root.APIKeys)+len(root.Access.APIKeys))
	for _, list := range [][]string{root.APIKeys, root.Access.APIKeys} {
		for _, item := range list {
			k := strings.TrimSpace(item)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
	}
	return out
}

// WriteHostConfigAPIKeys updates the global `api-keys` list in CLIProxyAPI's config.yaml on disk
// while preserving all other YAML nodes and comments.
//
// This compatibility helper is for offline configuration maintenance. Live
// management uses idempotent native PATCH/DELETE requests instead, so it cannot
// overwrite unrelated host updates. Rules themselves live only in SQLite.
func WriteHostConfigAPIKeys(configPath string, keys []string) error {
	resolvedPath := FindHostConfigFile(configPath)
	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("decode host config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("host config must be a YAML mapping")
	}
	rootMap := doc.Content[0]

	// Avoid rewriting CPA's main config (and reflowing its comments/formatting)
	// when the api-keys list already holds exactly these keys.
	if keysEqual(apiKeysFromNode(rootMap), dedupeKeys(keys)) {
		return nil
	}

	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	seen := make(map[string]struct{}, len(keys))
	for _, rawKey := range keys {
		k := strings.TrimSpace(rawKey)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: k,
		})
	}

	updated := false
	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		kNode := rootMap.Content[i]
		vNode := rootMap.Content[i+1]
		if kNode.Value == "api-keys" && (vNode.Kind == yaml.SequenceNode || vNode.Tag == "!!null") {
			rootMap.Content[i+1] = seqNode
			updated = true
			break
		}
		if kNode.Value == "access" && vNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(vNode.Content); j += 2 {
				if vNode.Content[j].Value == "api-keys" {
					vNode.Content[j+1] = seqNode
					updated = true
					break
				}
			}
		}
	}
	if !updated {
		rootMap.Content = append(rootMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "api-keys"},
			seqNode,
		)
	}

	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		_ = enc.Close()
		return err
	}
	_ = enc.Close()
	errWrite := usage.WriteFileAtomically(resolvedPath, []byte(buf.String()))
	invalidateHostConfigCache()
	return errWrite
}

// apiKeysFromNode returns the api-keys currently stored in a parsed config.yaml
// (either top level or under access:).
func apiKeysFromNode(rootMap *yaml.Node) []string {
	collect := func(seq *yaml.Node) []string {
		if seq == nil || seq.Kind != yaml.SequenceNode {
			return nil
		}
		out := make([]string, 0, len(seq.Content))
		for _, item := range seq.Content {
			if item != nil && item.Kind == yaml.ScalarNode {
				out = append(out, item.Value)
			}
		}
		return dedupeKeys(out)
	}
	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		k, v := rootMap.Content[i], rootMap.Content[i+1]
		if k.Value == "api-keys" {
			return collect(v)
		}
		if k.Value == "access" && v.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(v.Content); j += 2 {
				if v.Content[j].Value == "api-keys" {
					return collect(v.Content[j+1])
				}
			}
		}
	}
	return nil
}

// dedupeKeys trims, drops empties and removes duplicates while keeping order.
func dedupeKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, raw := range keys {
		k := strings.TrimSpace(raw)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// keysEqual compares two key lists as ordered sequences.
func keysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// configuredKeyList extracts the API key strings of the merged rules in order.
func configuredKeyList(rules []KeyRuleConfig) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.APIKey)
	}
	return out
}
