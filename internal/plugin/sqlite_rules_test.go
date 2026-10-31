package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

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
  usage_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "usage_stats.json")) + `"
  rules_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "key_guard_rules.json")) + `"
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
