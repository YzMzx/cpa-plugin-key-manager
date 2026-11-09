package usage

import (
	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"path/filepath"
	"testing"
	"time"
)

func TestTraceRetriesAreSeparateBillableExecutionsAcrossCallbackOrders(t *testing.T) {
	orders := [][]string{{"complete", "success", "failure"}, {"complete", "failure", "success"}, {"failure", "success", "complete"}, {"success", "failure", "complete"}, {"failure", "complete", "success"}, {"success", "complete", "failure"}}
	for _, order := range orders {
		t.Run(order[0]+"-"+order[1], func(t *testing.T) {
			engine := pricing.NewEngine()
			_ = engine.SetCustomPrices(map[string]pricing.ModelPrice{"m": {Input: 1}}, nil)
			store := NewStore(engine)
			database := filepath.Join(t.TempDir(), "usage.db")
			if err := store.ConfigureSQLite(database, time.Hour); err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			store.BeginRequest("logical", "execution-key", "", "m", "m", "openai", false)
			success := pluginapi.UsageRecord{RequestID: "execution-success", TraceID: "shared-trace", APIKey: "execution-key", Provider: "provider", AuthID: "success-account", Model: "m", Detail: pluginapi.UsageDetail{InputTokens: 7, TotalTokens: 7}}
			failure := pluginapi.UsageRecord{RequestID: "execution-failed", TraceID: "shared-trace", APIKey: "execution-key", Provider: "provider", AuthID: "failed-account", Model: "m", Failed: true, Detail: pluginapi.UsageDetail{InputTokens: 3, TotalTokens: 3}}
			for _, step := range order {
				switch step {
				case "complete":
					store.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "shared-trace", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "execution-key", "")
				case "success":
					store.ObserveHostUsageRecord(success, "")
				case "failure":
					store.ObserveHostUsageRecord(failure, "")
				}
			}
			store.ObserveHostUsageRecord(success, "")
			store.ObserveHostUsageRecord(failure, "")
			stats := store.Snapshot("execution-key", "", nil, nil, nil, false).Keys["execution-key"]
			if stats == nil || stats.TotalRequests != 2 || stats.SuccessRequests != 1 || stats.FailedRequests != 1 || stats.InputTokens != 10 || stats.TotalCostNanoUSD != 10000 {
				t.Fatalf("attempt contributions corrupted: %+v", stats)
			}
			if len(store.accounts) != 2 {
				t.Fatal("execution accounts merged")
			}
			for _, account := range store.accounts {
				if account.AuthID == "success-account" && (account.SuccessRequests != 1 || account.InputTokens != 7) {
					t.Fatal("late failure changed success account")
				}
				if account.AuthID == "failed-account" && (account.FailedRequests != 1 || account.InputTokens != 3) {
					t.Fatal("failed account changed")
				}
			}
			if err := store.FlushNow(); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			restored := NewStore(engine)
			if err := restored.ConfigureSQLite(database, time.Hour); err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			after := restored.Snapshot("execution-key", "", nil, nil, nil, false).Keys["execution-key"]
			if after == nil || after.TotalRequests != 2 || after.InputTokens != 10 || after.TotalCostNanoUSD != 10000 {
				t.Fatal("attempt accounting did not survive restart")
			}
		})
	}
}

func TestSingleHostAttemptStillDeduplicatesWithLogicalCompletion(t *testing.T) {
	for _, hostFirst := range []bool{true, false} {
		for _, failed := range []bool{true, false} {
			store := NewStore(nil)
			store.BeginRequest("logical-single", "k", "", "m", "m", "openai", false)
			rec := pluginapi.UsageRecord{RequestID: "single-attempt", TraceID: "trace-single", APIKey: "k", Model: "m", Failed: failed, Detail: pluginapi.UsageDetail{InputTokens: 2}}
			outcome := pluginapi.RequestCompletionSucceeded
			if failed {
				outcome = pluginapi.RequestCompletionFailed
			}
			completion := func() {
				store.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical-single", TraceID: "trace-single", Model: "m", Outcome: outcome}, "k", "")
			}
			if hostFirst {
				store.ObserveHostUsageRecord(rec, "")
				completion()
			} else {
				completion()
				store.ObserveHostUsageRecord(rec, "")
			}
			stats := store.Snapshot("k", "", nil, nil, nil, false).Keys["k"]
			if stats.TotalRequests != 1 || stats.InputTokens != 2 {
				t.Fatalf("single attempt duplicated: %+v", stats)
			}
		}
	}
}
