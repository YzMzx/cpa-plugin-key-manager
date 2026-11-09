package usage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestFormerExampleKeysAreBilledAndPersistAcrossRestart(t *testing.T) {
	engine := pricing.NewEngine()
	if err := engine.SetCustomPrices(map[string]pricing.ModelPrice{"model-key-validation": {Input: 1, Output: 2}}, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "usage.db")
	store := NewStore(engine)
	if err := store.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	keys := []string{"sk-tenant-alpha-prod", "sk-tenant-beta-dev"}
	for i, key := range keys {
		id := []string{"formerly-excluded-alpha", "formerly-excluded-beta"}[i]
		if isInvalidKeyID(key) {
			t.Fatalf("legitimate key rejected: %s", key)
		}
		store.BeginRequest(id, key, "", "model-key-validation", "model-key-validation", "openai", false)
		store.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: id, APIKey: key, Model: "model-key-validation", Provider: "openai", AuthID: "test-account", Detail: pluginapi.UsageDetail{InputTokens: 100, OutputTokens: 50, TotalTokens: 150}}, "")
		store.CompleteRequest(pluginapi.RequestCompletion{RequestID: id, Model: "model-key-validation", Outcome: pluginapi.RequestCompletionSucceeded}, key, "")
	}
	assertBilled := func(s *Store) {
		t.Helper()
		snapshot := s.Snapshot("", "", nil, nil, nil, false)
		for _, key := range keys {
			stats := snapshot.Keys[key]
			if stats == nil || stats.TotalRequests != 1 || stats.SuccessRequests != 1 || stats.TotalTokens != 150 || stats.TotalCostNanoUSD != 200000 {
				t.Fatalf("billing lost for %s: %+v", key, stats)
			}
			if s.GetKeyCostUSD(key) <= 0 {
				t.Fatalf("quota cost does not advance for %s", key)
			}
		}
	}
	assertBilled(store)
	if err := store.FlushNow(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := NewStore(engine)
	if err := reopened.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertBilled(reopened)
}

func TestInvalidKeyIDsAreOnlyEmptyOrAnonymousSentinels(t *testing.T) {
	for _, key := range []string{"", " ", "__anonymous__", "anonymous", "Anonymous"} {
		if !isInvalidKeyID(key) {
			t.Fatalf("anonymous key accepted: %q", key)
		}
	}
	for _, key := range []string{"sk-tenant-alpha-prod", "sk-tenant-beta-dev", "sk-example", "legitimate-client", "anonymous-client"} {
		if isInvalidKeyID(key) {
			t.Fatalf("legitimate key rejected: %q", key)
		}
	}
}

func TestMaskAPIKeyShortValuesNeverPanicOrExposeWholeKey(t *testing.T) {
	for _, key := range []string{"a", "ab"} {
		if got := MaskAPIKey(key); got != "***" {
			t.Fatalf("short key was exposed: %q", got)
		}
	}
	for _, key := range []string{"短", "短钥", "a", "ab"} {
		s := NewStore(nil)
		s.BeginRequest("short-key-test", key, "", "m", "m", "openai", false)
		s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "short-key-test", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, key, "")
		if stats := s.Snapshot(key, "", nil, nil, nil, false).Keys[key]; stats == nil || stats.TotalRequests != 1 {
			t.Fatal("short key accounting lost")
		}
	}
}
