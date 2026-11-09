package plugin

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func bootstrapFixture(t *testing.T, raw string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_CONFIG_FILE", path)
	t.Setenv("CPA_DIR", dir)
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", "")
	m := NewManager(nil)
	m.mu.Lock()
	m.cfg = DefaultConfig()
	m.cfg.Enabled = true
	m.cfg.Priority = 100
	m.cfg.Storage.UsageDBFile = "active-storage.db"
	m.cfg.AdminToken = "active-plugin-secret"
	m.mu.Unlock()
	return m, path
}
func bootstrapPublicValues(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("decode public bootstrap values")
	}
	return out
}
func bootstrapBody(t *testing.T, m *Manager, patch func(map[string]any)) []byte {
	t.Helper()
	view := m.BootstrapSettings()
	configured := bootstrapPublicValues(t, view["configured"])
	input := map[string]any{"expected_file_revision": view["file_revision"], "bootstrap": map[string]any{"enabled": configured["enabled"], "priority": configured["priority"], "usage_db_file": configured["usage_db_file"]}, "ack_restart": true}
	if patch != nil {
		patch(input)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertBootstrapCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected bootstrap error")
	}
	coded, ok := err.(interface{ SettingsBootstrapCode() string })
	if !ok || coded.SettingsBootstrapCode() != want {
		t.Fatalf("unexpected safe error: %v", err)
	}
}

func TestBootstrapSettingsStagesOnlySelectedPluginFields(t *testing.T) {
	raw := "# host comment\nconfig-version: 8\nserver:\n  port: 8317 # port comment\n  tls: {enable: false}\naccess:\n  api-keys: [native-private-key]\nplugins:\n  enabled: true\n  dir: ./plugins\n  configs:\n    other-plugin: {enabled: true, custom: retained}\n    cpa-plugin-key-manager:\n      enabled: true # keep enabled comment\n      priority: 100\n      admin_token: disk-plugin-secret # keep token comment\n      storage:\n        usage_db_file: ./data/key_usage.db # keep path comment\n        timezone: Asia/Shanghai\n      audit: {retention_days: 7}\n      unknown: keep-this\n"
	m, path := bootstrapFixture(t, raw)
	before := m.BootstrapSettings()
	if before["available"] != true {
		t.Fatalf("unavailable: %v", before)
	}
	effective := bootstrapPublicValues(t, before["effective"])
	configured := bootstrapPublicValues(t, before["configured"])
	if effective["usage_db_file"] != "active-storage.db" || configured["usage_db_file"] != "./data/key_usage.db" || configured["admin_token_configured"] != true {
		t.Fatal("effective/configured not separated")
	}
	body := bootstrapBody(t, m, func(input map[string]any) {
		b := input["bootstrap"].(map[string]any)
		b["enabled"] = false
		b["priority"] = 250
		b["usage_db_file"] = "./new/history.db"
		b["admin_token"] = "new-plugin-secret"
		input["ack_storage_path_change"] = true
	})
	result, err := m.SaveBootstrapSettings(body)
	if err != nil {
		t.Fatal(err)
	}
	if result["ok"] != true || result["requires_restart"] != true {
		t.Fatal("restart requirement absent")
	}
	after := m.BootstrapSettings()
	if after["file_revision"] == before["file_revision"] {
		t.Fatal("whole file revision unchanged")
	}
	effective = bootstrapPublicValues(t, after["effective"])
	configured = bootstrapPublicValues(t, after["configured"])
	if effective["enabled"] != true || effective["priority"] != float64(100) || effective["usage_db_file"] != "active-storage.db" {
		t.Fatal("save changed effective configuration")
	}
	if configured["enabled"] != false || configured["priority"] != float64(250) || configured["usage_db_file"] != "./new/history.db" {
		t.Fatal("staged configuration absent")
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"# host comment", "# port comment", "# keep enabled comment", "# keep path comment", "# keep token comment", "native-private-key", "other-plugin:", "custom: retained", "unknown: keep-this", "timezone: Asia/Shanghai"} {
		if !strings.Contains(string(out), fragment) {
			t.Fatalf("lost unrelated config or comment: %s", fragment)
		}
	}
	var root map[string]any
	if yaml.Unmarshal(out, &root) != nil {
		t.Fatal("invalid rewritten YAML")
	}
	plugins := root["plugins"].(map[string]any)
	if plugins["enabled"] != true || plugins["dir"] != "./plugins" {
		t.Fatal("global plugin settings changed")
	}
	payload, _ := json.Marshal(map[string]any{"before": before, "result": result, "after": after})
	for _, secret := range []string{"active-plugin-secret", "disk-plugin-secret", "new-plugin-secret", "native-private-key"} {
		if bytes.Contains(payload, []byte(secret)) {
			t.Fatalf("public bootstrap response leaked %s", secret)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "new")); !os.IsNotExist(err) {
		t.Fatal("bootstrap save created or migrated database directory")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("host config permissions widened")
		}
	}
}

func TestBootstrapFileRevisionRejectsStaleAndMalformedEdits(t *testing.T) {
	m, path := bootstrapFixture(t, "server: {port: 8317}\nplugins: {configs: {cpa-plugin-key-manager: {enabled: true, priority: 100}}}\n")
	request := bootstrapBody(t, m, nil)
	modified := "# externally edited\nserver: {port: 9420}\n"
	if os.WriteFile(path, []byte(modified), 0600) != nil {
		t.Fatal("external edit")
	}
	_, err := m.SaveBootstrapSettings(request)
	assertBootstrapCode(t, err, "conflict")
	out, _ := os.ReadFile(path)
	if string(out) != modified {
		t.Fatal("stale request overwrote external config")
	}
	for _, raw := range []string{"server: [private-yaml-secret", "[]", "server: {port: 8317}\n---\nsecret: private-yaml-secret", "plugins: {configs: {cpa-plugin-key-manager: {priority: secret-value}}}"} {
		if os.WriteFile(path, []byte(raw), 0600) != nil {
			t.Fatal("write fixture")
		}
		view := m.BootstrapSettings()
		if view["available"] != false {
			t.Fatal("malformed config marked available")
		}
		payload, _ := json.Marshal(view)
		if bytes.Contains(payload, []byte("private-yaml-secret")) || bytes.Contains(payload, []byte("secret-value")) {
			t.Fatal("YAML error leaked config content")
		}
	}
}

func TestBootstrapDefaultsCreateOnlyMissingPluginStructure(t *testing.T) {
	m, path := bootstrapFixture(t, "# minimal host\nserver: {port: 8317}\napi-keys: [native]\n")
	request := bootstrapBody(t, m, nil)
	result, err := m.SaveBootstrapSettings(request)
	if err != nil {
		t.Fatal(err)
	}
	if result["requires_restart"] != true {
		t.Fatal("restart absent")
	}
	out, _ := os.ReadFile(path)
	var root map[string]any
	if yaml.Unmarshal(out, &root) != nil {
		t.Fatal("decode")
	}
	plugins := root["plugins"].(map[string]any)
	if _, ok := plugins["enabled"]; ok {
		t.Fatal("created global plugins.enabled")
	}
	if _, ok := plugins["dir"]; ok {
		t.Fatal("created global plugins.dir")
	}
	configured := bootstrapPublicValues(t, m.BootstrapSettings()["configured"])
	if configured["enabled"] != true || configured["priority"] != float64(100) {
		t.Fatal("missing values not defaulted")
	}
}

func TestBootstrapEnvironmentLocksStorageAndRequiresExplicitAcknowledgments(t *testing.T) {
	m, path := bootstrapFixture(t, "plugins:\n  configs:\n    cpa-plugin-key-manager:\n      storage: {usage_db_file: ./disk.db}\n")
	original, _ := os.ReadFile(path)
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", "/env-locked/database.db")
	if m.BootstrapSettings()["db_path_locked_by_env"] != true {
		t.Fatal("override lock absent")
	}
	input := bootstrapBody(t, m, func(data map[string]any) {
		data["bootstrap"].(map[string]any)["usage_db_file"] = "/env-locked/database.db"
		data["ack_storage_path_change"] = true
	})
	_, err := m.SaveBootstrapSettings(input)
	assertBootstrapCode(t, err, "invalid")
	if out, _ := os.ReadFile(path); !bytes.Equal(out, original) {
		t.Fatal("env override was written to host config")
	}
	if _, err = m.SaveBootstrapSettings(bootstrapBody(t, m, nil)); err != nil {
		t.Fatal("unchanged disk storage should remain editable under override")
	}
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", "")
	_, err = m.SaveBootstrapSettings(bootstrapBody(t, m, func(data map[string]any) { data["bootstrap"].(map[string]any)["usage_db_file"] = "./other.db" }))
	assertBootstrapCode(t, err, "invalid")
	_, err = m.SaveBootstrapSettings(bootstrapBody(t, m, func(data map[string]any) {
		data["ack_restart"] = false
		data["bootstrap"].(map[string]any)["enabled"] = false
	}))
	assertBootstrapCode(t, err, "invalid")
}

func TestBootstrapBlankTokenPreservesAndExplicitClearDoesNotEcho(t *testing.T) {
	m, path := bootstrapFixture(t, "plugins:\n  configs:\n    cpa-plugin-key-manager:\n      admin_token: existing-private-secret\n")
	if _, err := m.SaveBootstrapSettings(bootstrapBody(t, m, func(input map[string]any) { input["bootstrap"].(map[string]any)["admin_token"] = "   " })); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte("existing-private-secret")) {
		t.Fatal("blank token erased credential")
	}
	_, err := m.SaveBootstrapSettings(bootstrapBody(t, m, func(input map[string]any) {
		b := input["bootstrap"].(map[string]any)
		b["admin_token"] = "new-private-secret"
		b["clear_admin_token"] = true
	}))
	assertBootstrapCode(t, err, "invalid")
	result, err := m.SaveBootstrapSettings(bootstrapBody(t, m, func(input map[string]any) { input["bootstrap"].(map[string]any)["clear_admin_token"] = true }))
	if err != nil {
		t.Fatal(err)
	}
	configured := bootstrapPublicValues(t, m.BootstrapSettings()["configured"])
	if configured["admin_token_configured"] != false {
		t.Fatal("explicit token clear failed")
	}
	effective := bootstrapPublicValues(t, m.BootstrapSettings()["effective"])
	if effective["admin_token_configured"] != true {
		t.Fatal("token unexpectedly changed active configuration")
	}
	payload, _ := json.Marshal(result)
	for _, secret := range []string{"existing-private-secret", "new-private-secret", "active-plugin-secret"} {
		if bytes.Contains(payload, []byte(secret)) {
			t.Fatal("token leaked through response")
		}
	}
}

func TestBootstrapStrictRequestValidationNeverWritesInvalidInputs(t *testing.T) {
	m, path := bootstrapFixture(t, "server: {port: 8317}\n")
	for _, mutate := range []func(map[string]any){
		func(input map[string]any) { delete(input, "expected_file_revision") },
		func(input map[string]any) { input["expected_file_revision"] = "wrong" },
		func(input map[string]any) { input["unknown"] = "no" },
		func(input map[string]any) { delete(input["bootstrap"].(map[string]any), "enabled") },
		func(input map[string]any) { input["bootstrap"].(map[string]any)["priority"] = 10001 },
		func(input map[string]any) { input["bootstrap"].(map[string]any)["priority"] = -10001 },
		func(input map[string]any) { input["bootstrap"].(map[string]any)["usage_db_file"] = "" },
		func(input map[string]any) { input["bootstrap"].(map[string]any)["usage_db_file"] = "bad\npath" },
		func(input map[string]any) { input["bootstrap"].(map[string]any)["usage_db_file"] = "bad\rpath" },
		func(input map[string]any) {
			input["bootstrap"].(map[string]any)["usage_db_file"] = "bad" + string(rune(0)) + "path"
		},
		func(input map[string]any) { input["bootstrap"].(map[string]any)["admin_token"] = "bad\ttoken" },
		func(input map[string]any) {
			input["bootstrap"].(map[string]any)["admin_token"] = strings.Repeat("x", 4097)
		},
		func(input map[string]any) {
			input["bootstrap"].(map[string]any)["storage"] = map[string]any{"rules_file": "bad"}
		},
		func(input map[string]any) { input["bootstrap"].(map[string]any)["priority"] = nil },
	} {
		before, _ := os.ReadFile(path)
		_, err := m.SaveBootstrapSettings(bootstrapBody(t, m, mutate))
		assertBootstrapCode(t, err, "invalid")
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid request wrote config")
		}
	}
	valid := bootstrapBody(t, m, nil)
	for _, raw := range [][]byte{[]byte("   "), []byte("[]"), append(valid, []byte(" {}")...), []byte(strings.Replace(string(valid), "\"ack_restart\":true", "\"ack_restart\":true,\"ack_restart\":true", 1)), []byte(strings.Replace(string(valid), "\"enabled\":true", "\"enabled\":true,\"Enabled\":false", 1))} {
		_, err := m.SaveBootstrapSettings(raw)
		assertBootstrapCode(t, err, "invalid")
	}
}

func TestBootstrapUnavailableAndAtomicRecheckDoNotLeakOrOverwrite(t *testing.T) {
	m, path := bootstrapFixture(t, "server: {port: 8317}\n")
	raw, info, err := readBootstrapFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("server: {port: 9000}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = writeBootstrapFileCAS(path, []byte("should-not-appear"), info, bootstrapRevision(raw))
	assertBootstrapCode(t, err, "conflict")
	after, _ := os.ReadFile(path)
	if bytes.Contains(after, []byte("should-not-appear")) {
		t.Fatal("atomic recheck failed")
	}
	t.Setenv("CPA_CONFIG_FILE", filepath.Join(t.TempDir(), "unavailable-secret-path", "config.yaml"))
	response := m.BootstrapSettings()
	if response["available"] != false {
		t.Fatal("missing config available")
	}
	payload, _ := json.Marshal(response)
	if bytes.Contains(payload, []byte("unavailable-secret-path")) {
		t.Fatal("filesystem error leaked path")
	}
}

func TestBootstrapRejectsAmbiguousOrSharedTargetStructures(t *testing.T) {
	for _, text := range []string{
		"plugins: {configs: {cpa-plugin-key-manager: {enabled: true, enabled: false}}}\n",
		"plugins: {configs: {cpa-plugin-key-manager: {enabled: &shared true}}, other_enabled: *shared}\n",
		"plugins: {configs: {cpa-plugin-key-manager: &shared {enabled: true}}, other: *shared}\n",
		"plugins: {configs: {cpa-plugin-key-manager: {storage: &shared {usage_db_file: ./data.db}}}, other: *shared}\n",
	} {
		m, path := bootstrapFixture(t, text)
		before, _ := os.ReadFile(path)
		// Shared scalar anchors may be readable, but writes must never detach them or
		// alter another node using the same alias.
		_, err := m.SaveBootstrapSettings(bootstrapBody(t, m, nil))
		if err == nil {
			t.Fatal("ambiguous/shared target accepted")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("unsafe target modified file")
		}
	}
}
