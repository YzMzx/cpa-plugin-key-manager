package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func transactionManager(t *testing.T) *Manager {
	t.Helper()
	isolateStateDirs(t)
	dir := t.TempDir()
	t.Setenv("CPA_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("port: 8317\napi-keys: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil)
	// No network dependency is needed for rule transaction tests.
	m.lastSyncKey = fmt.Sprintf("https://models.dev/api.json|%s|24|30", filepath.Join(dir, "data", "models_dev.json"))
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Shutdown)
	m.hostKeySync = func(context.Context, string, []string) error { return nil }
	return m
}

func TestRuleSaveFailureDoesNotPublishCandidate(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"old-key","name":"before"}`)); err != nil {
		t.Fatal(err)
	}
	revision := m.RulesRevision()
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE rules_state"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"old-key","name":"after"}`)); err == nil {
		t.Fatal("save should fail")
	}
	rule, _ := m.cfg.ResolveKeyRule("old-key")
	if rule.Name != "before" || m.RulesRevision() != revision {
		t.Fatal("failed commit changed live state")
	}
}

func TestRenameIsAtomicAndPreservesSourceOnFailure(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"old-key","name":"before"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"taken"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"old-key","api_key":"taken"}`)); err == nil {
		t.Fatal("must reject existing destination")
	}
	if _, listed := m.cfg.ResolveKeyRule("old-key"); !listed {
		t.Fatal("source lost on rename failure")
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"old-key","api_key":"new-key"}`)); err != nil {
		t.Fatal(err)
	}
	if rule, _ := m.cfg.ResolveKeyRule("old-key"); rule.IsEnabled() {
		t.Fatal("old key is not explicitly denied after rename")
	}
	if _, listed := m.cfg.ResolveKeyRule("new-key"); !listed {
		t.Fatal("new key missing")
	}
}

func TestRenameSaveFailureLeavesOldKey(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"old-key"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE rules_state"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"old-key","api_key":"new-key"}`)); err == nil {
		t.Fatal("save should fail")
	}
	if _, ok := m.cfg.ResolveKeyRule("old-key"); !ok {
		t.Fatal("old key removed before commit")
	}
	if _, ok := m.cfg.ResolveKeyRule("new-key"); ok {
		t.Fatal("new key published before commit")
	}
}

func TestHostSyncFailurePersistsIntentWithoutResurrectingDeletion(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"deleted-key"}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteKeyRule("deleted-key"); err != nil {
		t.Fatal(err)
	}
	m.hostKeySync = func(context.Context, string, []string) error { return errors.New("offline") }
	m.syncPendingHost(context.Background(), "test-token")
	if !m.HostSyncStatus()["pending"].(bool) {
		t.Fatal("failed sync intent was cleared")
	}
	if err := m.SyncHostAPIKeys([]string{"deleted-key"}); err != nil {
		t.Fatal(err)
	}
	if rule, _ := m.cfg.ResolveKeyRule("deleted-key"); rule.IsEnabled() {
		t.Fatal("stale host key resurrected deletion")
	}
	var persisted DynamicRulesState
	raw, _, err := m.rulesRepo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted.HostSyncPending {
		t.Fatal("pending intent not durable")
	}
	m.hostKeySync = func(context.Context, string, []string) error { return nil }
	m.syncPendingHost(context.Background(), "test-token")
	if m.HostSyncStatus()["pending"].(bool) {
		t.Fatal("successful retry still pending")
	}
}

func TestManagementRejectsStaleRuleRevision(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"changed"}`)); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/key-guard/keys", Headers: http.Header{"Authorization": {"Bearer test"}, "X-Key-Guard-Revision": {strconv.FormatUint(revision, 10)}}, Body: []byte(`{"api_key":"stale"}`)})
	raw, err := m.HandleRPC(pluginabi.MethodManagementHandle, req)
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeEnvelope[pluginapi.ManagementResponse](t, raw)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if _, listed := m.cfg.ResolveKeyRule("stale"); listed {
		t.Fatal("stale mutation applied")
	}
}

func TestConfigureRejectsBrokenRulesAndRetainsEffectiveRules(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"retained","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.usageStore.DB().Conn().Exec("UPDATE rules_state SET payload='broken json' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(nil); err == nil {
		t.Fatal("broken rules must fail reload")
	}
	rule, found := m.cfg.ResolveKeyRule("retained")
	if !found || rule.IsEnabled() {
		t.Fatal("failed reload changed effective rules")
	}
}

func TestInvalidPriceRejectedBeforePersist(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	if err := m.UpsertCustomPrice("bad", pricing.ModelPrice{Input: -1}); err == nil {
		t.Fatal("negative price accepted")
	}
	if m.RulesRevision() != revision {
		t.Fatal("invalid price committed")
	}
}

func TestRenameCarriesQuotaAndLateUsage(t *testing.T) {
	m := transactionManager(t)
	if err := m.UpsertCustomPrice("test-model", pricing.ModelPrice{Input: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"source","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "before", APIKey: "source", Model: "test-model", Detail: pluginapi.UsageDetail{InputTokens: 100000}}, "")
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"source","api_key":"destination","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	_, used, _, _ := m.GetKeyQuota("destination")
	if used < 0.0999 || used > 0.1001 {
		t.Fatalf("rename lost spent quota: %v", used)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "late", APIKey: "source", Model: "test-model", Detail: pluginapi.UsageDetail{InputTokens: 50000}}, "")
	_, used, _, _ = m.GetKeyQuota("destination")
	if used < 0.1499 || used > 0.1501 {
		t.Fatalf("late usage lost after rename: %v", used)
	}
	if _, err := m.ResetKeyQuota("destination"); err != nil {
		t.Fatal(err)
	}
	_, used, _, _ = m.GetKeyQuota("destination")
	if used != 0 {
		t.Fatalf("reset lineage quota: %v", used)
	}
}

func TestRenameWaitsForActiveRequests(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"source"}`)); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "active", Model: "test-model", RequestedModel: "test-model", Headers: http.Header{"Authorization": {"Bearer source"}}})
	if _, err := m.handleRequestInterceptBefore(before); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"source","api_key":"destination"}`)); err == nil {
		t.Fatal("renamed active key")
	}
	completion, _ := json.Marshal(pluginapi.RequestCompletion{RequestID: "active", Outcome: pluginapi.RequestCompletionSucceeded})
	if _, err := m.handleRequestComplete(completion); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"source","api_key":"destination"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDeletedKeyIsDeniedBeforeHostAcknowledgement(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"revoked"}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteKeyRule("revoked"); err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: "revoked-attempt", Model: "test-model", Headers: http.Header{"Authorization": {"Bearer revoked"}}})
	raw, err := m.handleRequestInterceptBefore(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeEnvelope[pluginapi.RequestInterceptResponse](t, raw)
	if !resp.Terminate || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deleted key allowed: %+v", resp)
	}
}

func TestConfiguredChangesAdvanceRevisionButIdenticalReloadDoesNot(t *testing.T) {
	m := transactionManager(t)
	before := m.RulesRevision()
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	if got := m.RulesRevision(); got != before {
		t.Fatalf("same config changed revision: %d->%d", before, got)
	}
	raw, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("enabled: true\nstorage:\n  timezone: UTC\n")})
	if err := m.Configure(raw); err != nil {
		t.Fatal(err)
	}
	if got := m.RulesRevision(); got <= before {
		t.Fatalf("changed config did not advance: %d->%d", before, got)
	}
}

func TestRenameBackDoesNotDoubleCountQuotaSources(t *testing.T) {
	m := transactionManager(t)
	if err := m.UpsertCustomPrice("model", pricing.ModelPrice{Input: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"first","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "one", APIKey: "first", Model: "model", Detail: pluginapi.UsageDetail{InputTokens: 100000}}, "")
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"first","api_key":"second","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "two", APIKey: "second", Model: "model", Detail: pluginapi.UsageDetail{InputTokens: 50000}}, "")
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"second","api_key":"first","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	_, used, _, _ := m.GetKeyQuota("first")
	if used < 0.1499 || used > 0.1501 {
		t.Fatalf("rename back double counted: %v", used)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "three", APIKey: "first", Model: "model", Detail: pluginapi.UsageDetail{InputTokens: 10000}}, "")
	_, used, _, _ = m.GetKeyQuota("first")
	if used < 0.1599 || used > 0.1601 {
		t.Fatalf("new usage double counted: %v", used)
	}
}
