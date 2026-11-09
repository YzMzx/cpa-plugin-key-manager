package plugin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// TestSQLiteRulesSurviveRestart is the SQLite-era restart check: rules mutated
// through the management API must be readable by a fresh Manager.
func TestSQLiteRulesSurviveRestart(t *testing.T) {
	isolateStateDirs(t)
	tmpDir := t.TempDir()
	cfgYAML := `
enabled: true
storage:
  usage_db_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "key_usage.db")) + `"
  pricing_cache_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "models_dev.json")) + `"
`
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(cfgYAML), SchemaVersion: pluginabi.SchemaVersion})

	first := NewManager(nil)
	if _, err := first.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("register: %v", err)
	}
	path := first.usageStore.SQLitePath()
	if path == "" {
		t.Fatalf("sqlite path empty after register")
	}
	t.Logf("db: %s", path)

	body, _ := json.Marshal(map[string]any{
		"api_key":        "sk-sqlite-restart",
		"name":           "重启保留",
		"allowed_models": []string{"*"},
	})
	if _, err := first.UpsertKeyRuleFromJSON(body); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	first.Shutdown()

	second := NewManager(nil)
	defer second.Shutdown()
	if _, err := second.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	ovReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    "/v0/management/key-guard/overview",
		Headers: http.Header{"Authorization": {"Bearer test-token"}},
	})
	raw, _ := second.HandleRPC(pluginabi.MethodManagementHandle, ovReq)
	resp := decodeEnvelope[pluginapi.ManagementResponse](t, raw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status %d: %s", resp.StatusCode, string(resp.Body))
	}
	if !strings.Contains(string(resp.Body), "sk-sqlite-restart") {
		t.Fatalf("rules did not survive restart: %s", string(resp.Body))
	}
}

func TestSQLiteOnlyConfigureIgnoresLegacyFilesAndExperimentalDatabase(t *testing.T) {
	isolateStateDirs(t)
	root := t.TempDir()
	livePath := filepath.Join(root, "data", "live.db")
	t.Setenv("CPA_DIR", root)
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", livePath)
	configPath := filepath.Join(root, "config.yaml")
	t.Setenv("CPA_CONFIG_FILE", configPath)
	if err := os.WriteFile(configPath, []byte("port: 8317\napi-keys: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "data"), 0755); err != nil {
		t.Fatal(err)
	}
	legacyRules := filepath.Join(root, "data", "key_guard_rules.json")
	legacyUsage := filepath.Join(root, "data", "key_usage_stats.json")
	originals := map[string][]byte{legacyRules: []byte(`{"version":1,"keys":[{"api_key":"must-not-import-json"}]}`), legacyUsage: []byte("invalid former JSON snapshot")}
	for path, content := range originals {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	experimental := filepath.Join(root, "data", "key_usage_stats.db")
	old, err := sqlitestore.Open(experimental, sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"version":1,"keys":[{"api_key":"must-not-import-db"}]}`
	if _, err := old.Conn().Exec("INSERT INTO rules_state(id,payload,updated_at) VALUES(1,?,?)", payload, "2020-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil)
	defer m.Shutdown()
	yaml := "enabled: true\nstorage:\n  usage_file: " + filepath.ToSlash(legacyUsage) + "\n  rules_file: " + filepath.ToSlash(legacyRules) + "\npricing:\n  sync_url: http://127.0.0.1:1/offline\n  http_timeout_seconds: 1\nkeys:\n  - api_key: sqlite-seed-key\n"
	raw, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(yaml), SchemaVersion: pluginabi.SchemaVersion})
	if err := m.Configure(raw); err != nil {
		t.Fatal(err)
	}
	if m.usageStore.SQLitePath() != filepath.Clean(livePath) {
		t.Fatalf("wrong live database: %s", m.usageStore.SQLitePath())
	}
	for _, key := range []string{"must-not-import-json", "must-not-import-db"} {
		if _, listed := m.cfg.ResolveKeyRule(key); listed {
			t.Fatalf("legacy rules imported: %s", key)
		}
	}
	if _, listed := m.cfg.ResolveKeyRule("sqlite-seed-key"); !listed {
		t.Fatal("first configured SQLite seed was not retained")
	}
	stored, _, err := m.rulesRepo.Load()
	if err != nil || !strings.Contains(string(stored), "sqlite-seed-key") {
		t.Fatalf("seed missing from SQLite rules_state: %v", err)
	}
	for path, original := range originals {
		current, err := os.ReadFile(path)
		if err != nil || string(current) != string(original) {
			t.Fatalf("legacy file modified: %s", path)
		}
	}
	if _, err := os.Stat(experimental); err != nil {
		t.Fatal("experimental database was removed")
	}
}

func TestSQLiteMissingRulesStateReturnsEmptyWithoutExternalFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configured.db")
	db, err := sqlitestore.Open(path, sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager(nil)
	state, err := m.loadRulesState(newRulesRepository(db))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 || len(state.Keys) != 0 || state.CustomPrices == nil {
		t.Fatalf("missing rules row did not produce empty state: %+v", state)
	}
	var rows int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM rules_state").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("read-only rules load unexpectedly wrote a row")
	}
}

func TestSQLiteConfigAndDiagnosticsDoNotExposeRemovedStorageFields(t *testing.T) {
	for _, field := range []string{"UsageFile", "RulesFile", "LegacyUsageDBFile"} {
		if _, found := reflect.TypeOf(StorageConfig{}).FieldByName(field); found {
			t.Fatalf("removed storage field still exists: %s", field)
		}
	}
	m := transactionManager(t)
	raw, _ := json.Marshal(map[string]any{"overview": m.BuildAdminOverview(""), "rules": m.ListKeyRulesAndDefaultPolicy(), "settings": m.GetRuntimeSettings(), "diagnostics": m.BuildPersistenceDiagnostics()})
	for _, removed := range []string{"rules_file", "usage_file", "legacy_usage_db_file", "deprecated", "process_args", "cwd", "home"} {
		if strings.Contains(string(raw), "\""+removed+"\"") {
			t.Fatalf("removed field leaked from API: %s", removed)
		}
	}
	diagnostics := m.BuildPersistenceDiagnostics()
	if diagnostics["usage_db_file"] == "" || diagnostics["usage_db_exists"] != true {
		t.Fatal("live SQLite diagnostics lost")
	}
}
