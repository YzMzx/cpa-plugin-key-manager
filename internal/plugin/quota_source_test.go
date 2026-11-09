package plugin

import (
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestQuotaSourceCannotBeRecreatedAsIndependentKey(t *testing.T) {
	m := transactionManager(t)
	if err := m.UpsertCustomPrice("model", pricing.ModelPrice{Input: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"original","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "old-cost", APIKey: "original", Model: "model", Detail: pluginapi.UsageDetail{InputTokens: 100000}}, "")
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"original","api_key":"renamed","quota_limit_usd":1}`)); err != nil {
		t.Fatal(err)
	}
	revision := m.RulesRevision()
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"original","quota_limit_usd":1}`)); err == nil {
		t.Fatal("independent key reused a live quota source")
	}
	if m.RulesRevision() != revision {
		t.Fatal("rejected source reuse committed rules")
	}
	rule, _ := m.cfg.ResolveKeyRule("original")
	if rule.IsEnabled() {
		t.Fatal("retired source was enabled by failed recreation")
	}
	_, used, _, _ := m.GetKeyQuota("renamed")
	if used < 0.0999 || used > 0.1001 {
		t.Fatalf("rejected recreation changed quota: %v", used)
	}
	m.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "late-old-cost", APIKey: "original", Model: "model", Detail: pluginapi.UsageDetail{InputTokens: 50000}}, "")
	_, used, _, _ = m.GetKeyQuota("renamed")
	if used < 0.1499 || used > 0.1501 {
		t.Fatalf("source protection lost late usage: %v", used)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"renamed","api_key":"original","quota_limit_usd":1}`)); err != nil {
		t.Fatalf("same-lineage rename back blocked: %v", err)
	}
	_, used, _, _ = m.GetKeyQuota("original")
	if used < 0.1499 || used > 0.1501 {
		t.Fatalf("rename back changed quota: %v", used)
	}
}

func TestQuotaSourceCannotBeTakenByDifferentLineage(t *testing.T) {
	m := transactionManager(t)
	for _, key := range []string{"first", "other"} {
		if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"` + key + `"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"first","api_key":"owner"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"orig_key":"other","api_key":"first"}`)); err == nil {
		t.Fatal("another lineage took a retained source")
	}
	if rule, found := m.cfg.ResolveKeyRule("other"); !found || !rule.IsEnabled() {
		t.Fatal("failed rename removed other source key")
	}
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"owner","name":"edited"}`)); err != nil {
		t.Fatalf("unrelated owner edit blocked: %v", err)
	}
}
