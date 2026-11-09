package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func settingsRequest(t *testing.T, m *Manager, settings any, ack bool) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"settings": settings, "expected_revision": m.RulesRevision(), "ack_prune": ack})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRuntimeSettingsPartialPersistHotApplyAndRestartPriority(t *testing.T) {
	m := transactionManager(t)
	db := m.usageStore.DB()
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"settings-key","name":"unchanged"}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertCustomPrice("model-a", pricing.ModelPrice{Input: 2}); err != nil {
		t.Fatal(err)
	}
	oldPolicy := m.cfg.DefaultPolicy
	oldPrices := m.cfg.Pricing.CustomPrices
	raw := settingsRequest(t, m, map[string]any{"audit": map[string]any{"max_total_bytes": int64(1 << 30)}, "storage": map[string]any{"flush_interval_seconds": 23, "timezone": "UTC"}, "pricing": map[string]any{"auto_inject_include_usage": false}}, false)
	result, err := m.SaveRuntimeSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if result["ok"] != true || m.cfg.Storage.FlushIntervalSeconds != 23 || m.cfg.Storage.Timezone != "UTC" || m.cfg.Audit.MaxTotalBytes != 1<<30 || m.cfg.ShouldAutoInjectIncludeUsage() {
		t.Fatalf("not effective: %v", result)
	}
	if m.usageStore.DB() != db {
		t.Fatal("settings reopened database")
	}
	if !reflect.DeepEqual(m.cfg.DefaultPolicy, oldPolicy) || !reflect.DeepEqual(m.cfg.Pricing.CustomPrices, oldPrices) {
		t.Fatal("settings overwrote another rule domain")
	}
	if rule, ok := m.cfg.ResolveKeyRule("settings-key"); !ok || rule.Name != "unchanged" {
		t.Fatal("key changed")
	}
	if m.AuditStatus()["max_total_bytes"] != float64(1<<30) {
		t.Fatal("audit configuration not hot applied")
	}
	m.Shutdown()
	request, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("storage:\n  timezone: Asia/Shanghai\n  flush_interval_seconds: 5\naudit:\n  max_total_bytes: 67108864\n")})
	if err := m.Configure(request); err != nil {
		t.Fatal(err)
	}
	if m.cfg.Storage.Timezone != "UTC" || m.cfg.Storage.FlushIntervalSeconds != 23 || m.cfg.Audit.MaxTotalBytes != 1<<30 {
		t.Fatal("seed overwrote persisted settings after restart")
	}
}

func TestRuntimeSettingsCASStrictValidationAndPruneAcknowledgment(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	for _, raw := range []string{`{"settings":{"audit":{"enabled":false}}}`, `{"settings":{},"expected_revision":0}`} {
		_, err := m.SaveRuntimeSettings([]byte(raw))
		if !errors.Is(err, ErrSettingsRevision) {
			t.Fatalf("missing/stale CAS: %v", err)
		}
	}
	invalid := []string{`{"audit":{"max_records":0}}`, `{"storage":{"timezone":"Invalid/Zone"}}`, `{"storage":{"flush_interval_seconds":1.5}}`, `{"pricing":{"sync_url":"file:///tmp/private"}}`, `{"pricing":{"sync_url":"https://user:password@example.com/prices"}}`, `{"pricing":{"sync_url":"https://example.com/prices?token=secret"}}`, `{"audit":{"enabled":null}}`, `{"audit":{"enabled":true,"Enabled":false}}`, `{"keys":[]}`, `{"storage":{"usage_db_file":"other.db"}}`}
	for _, patch := range invalid {
		request := []byte(`{"settings":` + patch + `,"expected_revision":` + jsonNumber(revision) + `}`)
		if _, err := m.SaveRuntimeSettings(request); !errors.Is(err, ErrSettingsInvalid) {
			t.Fatalf("bad settings accepted: %s err=%v", patch, err)
		}
		if m.RulesRevision() != revision {
			t.Fatal("invalid settings advanced revision")
		}
	}
	small := map[string]any{"audit": map[string]any{"max_records": 2}, "storage": map[string]any{"ledger_retention_days": 10}}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, small, false)); !errors.Is(err, ErrSettingsPruneConfirmation) {
		t.Fatalf("no prune acknowledgement: %v", err)
	}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, small, true)); err != nil {
		t.Fatal(err)
	}
	if m.cfg.Audit.MaxRecords != 2 || m.cfg.Storage.LedgerRetentionDays != 10 {
		t.Fatal("confirmed smaller limits not applied")
	}
}
func jsonNumber(value uint64) string { raw, _ := json.Marshal(value); return string(raw) }

func TestRuntimeSettingsRepositoryFailureDoesNotPublishCandidate(t *testing.T) {
	m := transactionManager(t)
	old := runtimeSettingsFromConfig(m.cfg)
	revision := m.RulesRevision()
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE rules_state"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"storage": map[string]any{"timezone": "UTC"}}, false)); !errors.Is(err, ErrSettingsPersistence) {
		t.Fatalf("save should fail: %v", err)
	}
	if !reflect.DeepEqual(old, runtimeSettingsFromConfig(m.cfg)) || m.RulesRevision() != revision {
		t.Fatal("failed save changed effective settings")
	}
}

func TestRuntimeSettingsPreflushFailureDoesNotCommit(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	m.usageStore.BeginRequest("pending-settings", "settings-key", "", "model", "model", "openai", false)
	m.usageStore.ObserveResponse("pending-settings", "model", "model", []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	m.usageStore.CompleteRequest(pluginapi.RequestCompletion{RequestID: "pending-settings", Model: "model", Outcome: pluginapi.RequestCompletionSucceeded}, "settings-key", "")
	if _, err := m.usageStore.DB().Conn().Exec("ALTER TABLE key_usage RENAME TO key_usage_fault_fixture"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = m.usageStore.DB().Conn().Exec("ALTER TABLE key_usage_fault_fixture RENAME TO key_usage")
	})
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"storage": map[string]any{"timezone": "UTC"}}, false)); !errors.Is(err, ErrSettingsPersistence) {
		t.Fatalf("flush failure accepted: %v", err)
	}
	if m.RulesRevision() != revision || m.cfg.Storage.Timezone == "UTC" {
		t.Fatal("failed preflush committed settings")
	}
}

func TestRuntimeSettingsNoSecretsAndProtectedCachePaths(t *testing.T) {
	m := transactionManager(t)
	m.mu.Lock()
	m.cfg.Pricing.SyncURL = "https://user:private-pass@example.com/prices?token=hidden"
	m.mu.Unlock()
	value := m.GetRuntimeSettings()
	raw, _ := json.Marshal(value)
	for _, secret := range []string{"private-pass", "hidden", "api_key", "custom_prices", "default_policy"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("settings returned protected material: %s", secret)
		}
	}
	m.mu.Lock()
	m.cfg.Pricing.SyncURL = "https://models.dev/api.json"
	m.mu.Unlock()
	for _, path := range []string{m.cfg.Storage.UsageDBFile, m.cfg.Storage.UsageDBFile + "-wal", FindHostConfigFile("")} {
		if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"storage": map[string]any{"pricing_cache_file": path}}, false)); !errors.Is(err, ErrSettingsInvalid) {
			t.Fatalf("protected cache target allowed: %s %v", path, err)
		}
	}
}

func TestRuntimeSettingsPricingRestartAndStableNoop(t *testing.T) {
	m := transactionManager(t)
	var mu sync.Mutex
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openai":{"id":"openai","models":{"test-model":{"id":"test-model","cost":{"input":1,"output":2}}}}}`))
	}))
	defer server.Close()
	cache := filepath.Join(t.TempDir(), "runtime-prices.json")
	patch := map[string]any{"storage": map[string]any{"pricing_cache_file": cache}, "pricing": map[string]any{"sync_url": server.URL, "sync_interval_hours": 2, "http_timeout_seconds": 4}}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, patch, false)); err != nil {
		t.Fatal(err)
	}
	m.pricingSyncer.WaitInitialSync(2 * time.Second)
	mu.Lock()
	count := calls
	mu.Unlock()
	if count < 1 {
		t.Fatal("new pricing sync did not start")
	}
	if m.cfg.Storage.PricingCacheFile != cache || m.cfg.Pricing.HTTPTimeoutSeconds != 4 || m.cfg.Pricing.SyncIntervalHours != 2 {
		t.Fatal("pricing settings not effective")
	}
	revision := m.RulesRevision()
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{}, false)); err != nil {
		t.Fatal(err)
	}
	if m.RulesRevision() != revision {
		t.Fatal("identical settings caused a new revision")
	}
}

func TestRuntimeSettingsConfirmedAuditReductionPrunesImmediately(t *testing.T) {
	m := transactionManager(t)
	auditRequest(t, m, "settings-retention-1")
	auditRequest(t, m, "settings-retention-2")
	auditRequest(t, m, "settings-retention-3")
	if len(auditRecords(t, m)) != 3 {
		t.Fatal("fixture missing audit records")
	}
	revision := m.RulesRevision()
	patch := map[string]any{"audit": map[string]any{"max_records": 1}}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, patch, false)); !errors.Is(err, ErrSettingsPruneConfirmation) {
		t.Fatal("prune without confirmation")
	}
	if len(auditRecords(t, m)) != 3 || m.RulesRevision() != revision {
		t.Fatal("unconfirmed save pruned records")
	}
	result, err := m.SaveRuntimeSettings(settingsRequest(t, m, patch, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(auditRecords(t, m)) != 1 || result["apply_status"].(map[string]any)["ok"] != true {
		t.Fatal("confirmed audit limit not applied immediately")
	}
}

func TestRuntimeSettingsConcurrentCASAllowsOnlyOneWriter(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	requests := make([][]byte, 2)
	for i, zone := range []string{"UTC", "America/New_York"} {
		requests[i], _ = json.Marshal(map[string]any{"expected_revision": revision, "settings": map[string]any{"storage": map[string]any{"timezone": zone}}})
	}
	outcomes := make(chan error, 2)
	for _, body := range requests {
		go func(raw []byte) { _, err := m.SaveRuntimeSettings(raw); outcomes <- err }(body)
	}
	success, stale := 0, 0
	for i := 0; i < 2; i++ {
		err := <-outcomes
		if err == nil {
			success++
		} else if errors.Is(err, ErrSettingsRevision) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatalf("CAS did not serialize writes: %d/%d", success, stale)
	}
	// Close explicitly after all writers finish, before the temporary-directory
	// cleanup. This also makes lifecycle failures visible instead of log-only.
	m.Shutdown()
	if db := m.usageStore.DB(); db != nil {
		t.Fatalf("concurrent settings left database open: %+v", m.usageStore.PersistenceStatus())
	}
}
