package plugin

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestUsageResetPreservesRenamedQuotaSourcesAndBaseline(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"retired-key","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.pricingEngine.SetCustomPrices(map[string]pricing.ModelPrice{"m": {Input: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	bill := func(id, key string, n int64) {
		m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: id, APIKey: key, Model: "m", Provider: "openai", Detail: pluginapi.UsageDetail{InputTokens: n}}, "")
	}
	bill("before", "retired-key", 100)
	if _, err := m.ResetKeyQuota("retired-key"); err != nil {
		t.Fatal(err)
	}
	bill("after", "retired-key", 200)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"retired-key","api_key":"active-key","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	_, before, _, _ := m.GetKeyQuota("active-key")
	if math.Abs(before-.0002) > 1e-12 {
		t.Fatalf("fixture quota=%g", before)
	}
	for _, target := range []string{"retired-key", "active-key", ""} {
		if err := m.ResetUsage(target); err != nil {
			t.Fatal(err)
		}
		_, after, _, _ := m.GetKeyQuota("active-key")
		if after != before {
			t.Fatalf("reset %q quota=%g want=%g", target, after, before)
		}
	}
	path := m.usageStore.SQLitePath()
	if err := m.usageStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.usageStore.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, after, _, _ := m.GetKeyQuota("active-key")
	if after != before {
		t.Fatalf("restarted quota=%g", after)
	}
	bill("late", "retired-key", 10)
	_, late, _, _ := m.GetKeyQuota("active-key")
	if math.Abs(late-(before+.00001)) > 1e-12 {
		t.Fatalf("retired source late cost=%g", late)
	}
}

func TestAdminOverviewCrossKeyOverflowIsExplicit(t *testing.T) {
	// No Configure: no remote pricing/network or real configuration access.
	m := NewManager(nil)
	if err := m.usageStore.ConfigureSQLite(filepath.Join(t.TempDir(), "usage.db"), time.Hour); err != nil {
		t.Fatal(err)
	}
	defer m.usageStore.Close()
	for _, key := range []string{"a", "b"} {
		m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: key, APIKey: key, Model: "m", Detail: pluginapi.UsageDetail{InputTokens: math.MaxInt64}}, "")
	}
	summary := m.BuildAdminOverview("")["summary"].(map[string]any)
	if summary["accounting_error"] == nil || summary["total_tokens"] != int64(math.MaxInt64) {
		t.Fatalf("overview silently wrapped: %+v", summary)
	}
}
