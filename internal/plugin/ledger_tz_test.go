package plugin

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	pluginabi "github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// TestQueryLedgerUsesConfiguredTimezone pins the timezone contract: with no tz
// on the query the plugin falls back to storage.timezone, which defaults to
// Asia/Shanghai (UTC+8) instead of the container's UTC.
func TestQueryLedgerUsesConfiguredTimezone(t *testing.T) {
	isolateStateDirs(t)
	tmpDir := t.TempDir()

	mgr := NewManager(nil)
	defer mgr.Shutdown()

	cfgYAML := `enabled: true
storage:
  usage_db_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "key_usage.db")) + `"
`
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(cfgYAML), SchemaVersion: pluginabi.SchemaVersion})
	if _, err := mgr.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	now := time.Now()
	result := mgr.QueryLedger(usage.LedgerQuery{From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if result.Timezone != usage.DefaultTimezone {
		t.Fatalf("default ledger timezone = %q, want %q (UTC+8)", result.Timezone, usage.DefaultTimezone)
	}
	if _, offset := time.Now().In(mustLoad(t, result.Timezone)).Zone(); offset != 8*3600 {
		t.Fatalf("default ledger timezone offset = %d, want 28800 (UTC+8)", offset)
	}

	// An explicit tz on the query still wins.
	utc := mgr.QueryLedger(usage.LedgerQuery{From: now.Add(-time.Hour), To: now.Add(time.Hour), Timezone: "UTC"})
	if utc.Timezone != "UTC" {
		t.Fatalf("explicit tz = %q, want UTC", utc.Timezone)
	}
}

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load location %q: %v", name, err)
	}
	return loc
}
