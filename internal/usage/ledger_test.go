package usage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func ledgerTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "usage.json")
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(file, time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, file
}

// feedLedgerRequest drives one complete request through the accounting path.
func feedLedgerRequest(t *testing.T, store *Store, reqID, apiKey, keyName, requested, served, source, provider, authID string, in, out, cacheRead int64) {
	t.Helper()
	store.BeginRequest(reqID, apiKey, keyName, requested, requested, source, false)
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID:     reqID,
		Provider:      provider,
		AuthID:        authID,
		Model:         requested,
		ResponseModel: served,
		APIKey:        apiKey,
		Detail: pluginapi.UsageDetail{
			InputTokens:     in,
			OutputTokens:    out,
			CacheReadTokens: cacheRead,
			TotalTokens:     in + out + cacheRead,
		},
	}, keyName)
}

// TestLedgerBillsRequestedModelNotSubstitution pins the billing rule: an upstream
// substitution must not create its own ledger model row.
func TestLedgerBillsRequestedModelNotSubstitution(t *testing.T) {
	store, _ := ledgerTestStore(t)

	feedLedgerRequest(t, store, "req-1", "sk-ledger", "账本测试", "gemini-3.8-flash-high", "gemini-4-argon-high", "openai", "antigravity", "antigravity-a@gmail.com.json", 100, 20, 40)
	feedLedgerRequest(t, store, "req-2", "sk-ledger", "账本测试", "gemini-3.8-flash-high", "gemini-3.8-flash-n", "openai", "antigravity", "antigravity-a@gmail.com.json", 50, 10, 0)

	now := time.Now()
	result := store.QueryLedger(LedgerQuery{
		From: now.Add(-2 * time.Hour),
		To:   now.Add(2 * time.Hour),
	})

	if result.Requests != 2 {
		t.Fatalf("requests = %d, want 2", result.Requests)
	}
	if result.ModelCount != 1 || len(result.Models) != 1 {
		t.Fatalf("substituted served names must not create rows, got models=%+v", result.Models)
	}
	if result.Models[0].Model != "gemini-3.8-flash-high" {
		t.Fatalf("ledger model = %q, want the requested model", result.Models[0].Model)
	}
	// InputTokens holds uncached input; prompt size = uncached + cache read.
	if got, want := result.InputTokens+result.CacheReadTokens, int64(150); got != want {
		t.Fatalf("prompt tokens = %d, want %d", got, want)
	}
	if got, want := result.CacheReadTokens, int64(40); got != want {
		t.Fatalf("cache read = %d, want %d", got, want)
	}
}

// TestLedgerFiltersAndBuckets covers key/account/model/source filters and bucketing.
func TestLedgerFiltersAndBuckets(t *testing.T) {
	store, _ := ledgerTestStore(t)

	feedLedgerRequest(t, store, "req-a", "sk-alpha", "Alpha租户", "claude-sonnet-4-6", "claude-sonnet-4-6", "claude", "claude", "claude-a@gmail.com.json", 10, 5, 0)
	feedLedgerRequest(t, store, "req-b", "sk-beta", "Beta租户", "gemini-3.8-flash-high", "gemini-3.8-flash-high", "openai", "antigravity", "antigravity-b@gmail.com.json", 20, 5, 0)

	now := time.Now()
	window := LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)}

	byKey := store.QueryLedger(LedgerQuery{From: window.From, To: window.To, Key: "alpha"})
	if byKey.Requests != 1 || len(byKey.Models) != 1 || byKey.Models[0].Model != "claude-sonnet-4-6" {
		t.Fatalf("key filter failed: %+v", byKey)
	}

	byAccount := store.QueryLedger(LedgerQuery{From: window.From, To: window.To, Account: "antigravity"})
	if byAccount.Requests != 1 || byAccount.Models[0].Model != "gemini-3.8-flash-high" {
		t.Fatalf("account filter failed: %+v", byAccount)
	}

	bySource := store.QueryLedger(LedgerQuery{From: window.From, To: window.To, Source: "claude"})
	if bySource.Requests != 1 || bySource.Models[0].Model != "claude-sonnet-4-6" {
		t.Fatalf("source filter failed: %+v", bySource)
	}

	byModel := store.QueryLedger(LedgerQuery{From: window.From, To: window.To, Model: "gemini-3.8-flash-high"})
	if byModel.Requests != 1 {
		t.Fatalf("model filter failed: %+v", byModel)
	}

	hourly := store.QueryLedger(LedgerQuery{From: window.From, To: window.To, Granularity: "hour"})
	if hourly.Granularity != "hour" || len(hourly.Series) == 0 {
		t.Fatalf("hour granularity failed: %+v", hourly)
	}

	all := store.QueryLedger(window)
	if len(all.UsedModels) != 2 || len(all.UsedSources) != 2 {
		t.Fatalf("used options = %v / %v", all.UsedModels, all.UsedSources)
	}
	if all.ModelCount != 2 || all.KeysTotal != 2 || all.KeysAvailable != 2 {
		t.Fatalf("unexpected summary: models=%d keys=%d/%d", all.ModelCount, all.KeysAvailable, all.KeysTotal)
	}
}

// TestLedgerPersistsAcrossReload verifies the ledger survives a restart.
func TestLedgerPersistsAcrossReload(t *testing.T) {
	store, file := ledgerTestStore(t)
	feedLedgerRequest(t, store, "req-p", "sk-persist", "持久化", "kimi-k2.6", "kimi-k2.6", "openai", "kimi", "kimi.json", 7, 3, 0)
	if err := store.FlushNow(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	_ = store.Close()

	reloaded := NewStore(pricing.NewEngine())
	if err := reloaded.ConfigurePersistence(file, time.Hour); err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer reloaded.Close()

	now := time.Now()
	result := reloaded.QueryLedger(LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)})
	if result.Requests != 1 || result.Models[0].Model != "kimi-k2.6" {
		t.Fatalf("ledger did not survive reload: %+v", result)
	}
	if status := reloaded.LedgerStatus(); status.Entries == 0 || status.RetentionDays == 0 {
		t.Fatalf("ledger status not reported: %+v", status)
	}
}

// TestLedgerResetClearsKey verifies "清零用量" also clears the ledger rows.
func TestLedgerResetClearsKey(t *testing.T) {
	store, _ := ledgerTestStore(t)
	feedLedgerRequest(t, store, "req-r", "sk-reset", "重置", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm.json", 5, 5, 0)
	if err := store.Reset("sk-reset"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	now := time.Now()
	result := store.QueryLedger(LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)})
	if result.Requests != 0 || len(result.Models) != 0 {
		t.Fatalf("ledger rows survived the reset: %+v", result)
	}
}

// TestLedgerPerKeyBreakdown covers the per-key table: totals per key plus the
// model breakdown inside each key, still billed by the requested model.
func TestLedgerPerKeyBreakdown(t *testing.T) {
	store, _ := ledgerTestStore(t)

	feedLedgerRequest(t, store, "k1-a", "sk-key-one", "Key One", "gemini-3.8-flash-high", "gemini-4-argon-high", "openai", "antigravity", "a.json", 100, 10, 0)
	feedLedgerRequest(t, store, "k1-b", "sk-key-one", "Key One", "claude-sonnet-4-6", "claude-sonnet-4-6", "claude", "claude", "b.json", 50, 5, 0)
	feedLedgerRequest(t, store, "k2-a", "sk-key-two", "Key Two", "kimi-k2.6", "kimi-k2.6", "openai", "kimi", "c.json", 20, 2, 0)

	now := time.Now()
	result := store.QueryLedger(LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)})

	if len(result.KeyRows) != 2 {
		t.Fatalf("key rows = %d, want 2", len(result.KeyRows))
	}
	first := result.KeyRows[0]
	if first.APIKey != "sk-key-one" || first.KeyName != "Key One" {
		t.Fatalf("largest key should come first, got %+v", first)
	}
	if first.Requests != 2 || first.TotalTokens != 165 {
		t.Fatalf("key totals wrong: %+v", first)
	}
	if len(first.Models) != 2 {
		t.Fatalf("per-key model breakdown = %d rows, want 2", len(first.Models))
	}
	if first.Models[0].Model != "gemini-3.8-flash-high" {
		t.Fatalf("models should be sorted by tokens, got %+v", first.Models)
	}
	if first.Models[0].Model == "gemini-4-argon-high" {
		t.Fatalf("substituted model leaked into the per-key breakdown")
	}
	var modelShareSum float64
	for _, m := range first.Models {
		modelShareSum += m.Share
	}
	if modelShareSum < 99.9 || modelShareSum > 100.1 {
		t.Fatalf("per-model shares should add up to 100%%, got %.2f", modelShareSum)
	}
	if first.Share <= 0 || first.Share > 100 {
		t.Fatalf("key share out of range: %.2f", first.Share)
	}
	if result.KeyRows[1].APIKey != "sk-key-two" || len(result.KeyRows[1].Models) != 1 {
		t.Fatalf("second key wrong: %+v", result.KeyRows[1])
	}
}
