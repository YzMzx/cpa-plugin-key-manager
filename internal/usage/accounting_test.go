package usage

import (
	"fmt"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"math"
	"testing"
	"time"
)

func TestHostRecordNeverGuessesAcrossExplicitRequestIDs(t *testing.T) {
	s := NewStore(nil)
	feedLedgerRequest(t, s, "request-a", "sk-identity", "", "model-a", "model-a", "openai", "provider", "acct", 4, 0, 0)
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "request-a", Model: "model-a", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-identity", "")
	s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "request-b", APIKey: "sk-identity", Model: "model-b", Provider: "provider", AuthID: "acct", Failed: true, Detail: pluginapi.UsageDetail{InputTokens: 6, TotalTokens: 6}}, "")
	snap := s.Snapshot("sk-identity", "", nil, nil, nil, false)
	ks := snap.Keys["sk-identity"]
	if ks.TotalRequests != 2 || ks.SuccessRequests != 1 || ks.FailedRequests != 1 || ks.TotalTokens != 10 {
		t.Fatalf("separate request identities merged: %+v", ks)
	}
}

func TestAnonymousHostFallbackRequiresUniqueActiveModel(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		model                string
		completed, ambiguous bool
		want                 int64
	}{{"unique", "model-a", false, false, 1}, {"different-model", "model-b", false, false, 2}, {"completed", "model-a", true, false, 2}, {"ambiguous", "model-a", false, true, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore(nil)
			s.BeginRequest("active-a", "sk-fallback", "", "model-a", "model-a", "openai", false)
			if tc.completed {
				s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "active-a", Model: "model-a", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-fallback", "")
			}
			if tc.ambiguous {
				s.BeginRequest("active-b", "sk-fallback", "", "model-a", "model-a", "openai", false)
			}
			s.ObserveHostUsageRecord(pluginapi.UsageRecord{APIKey: "sk-fallback", Model: tc.model, Detail: pluginapi.UsageDetail{InputTokens: 2, TotalTokens: 2}}, "")
			s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "active-a", Model: "model-a", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-fallback", "")
			ks := s.Snapshot("sk-fallback", "", nil, nil, nil, false).Keys["sk-fallback"]
			if ks.TotalRequests != tc.want {
				t.Fatalf("requests=%d want=%d", ks.TotalRequests, tc.want)
			}
		})
	}
}

func TestLateServedModelMovesOnlyCurrentRequestContribution(t *testing.T) {
	s := NewStore(nil)
	for _, id := range []string{"history", "changing", "parallel"} {
		feedLedgerRequest(t, s, id, "sk-tuples", "", "model-a", "model-a", "openai", "provider", "acct", 10, 0, 0)
	}
	s.ObserveStreamChunk("changing", "model-b", "model-a", []byte(`data: {"model":"model-b","usage":{"prompt_tokens":10,"completion_tokens":0}}`))
	snap := s.Snapshot("sk-tuples", "", nil, nil, nil, false)
	ks := snap.Keys["sk-tuples"]
	original, changed := ks.Models[tupleKey("model-a", "model-a")], ks.Models[tupleKey("model-a", "model-b")]
	if original == nil || original.Requests != 2 || original.TotalTokens != 20 || changed == nil || changed.Requests != 1 || changed.TotalTokens != 10 {
		t.Fatalf("shared tuple was moved: %+v", ks.Models)
	}
	acct := snap.Accounts["account::acct"]
	if acct.Requests != 3 || acct.Models["model-a"].Requests != 2 {
		t.Fatalf("account tuple changed other requests: %+v", acct)
	}
}

func TestLateFailureCorrectsAlreadyCountedSuccess(t *testing.T) {
	s := NewStore(nil)
	feedLedgerRequest(t, s, "terminal", "sk-terminal", "", "model-a", "model-a", "openai", "provider", "acct", 3, 2, 0)
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "terminal", Outcome: pluginapi.RequestCompletionFailed}, "sk-terminal", "")
	ks := s.Snapshot("sk-terminal", "", nil, nil, nil, false).Keys["sk-terminal"]
	if ks.TotalRequests != 1 || ks.SuccessRequests != 0 || ks.FailedRequests != 1 {
		t.Fatalf("terminal not corrected: %+v", ks)
	}
	if got := s.QueryLedger(LedgerQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}).Requests; got != 0 {
		t.Fatalf("failed request remained in ledger: %d", got)
	}
}

func TestCumulativeCostRoundingIndependentOfChunks(t *testing.T) {
	eng := pricing.NewEngine()
	if err := eng.SetCustomPrices(map[string]pricing.ModelPrice{"model-a": {Input: 0.0004}}, nil); err != nil {
		t.Fatal(err)
	}
	s := NewStore(eng)
	s.BeginRequest("fractional", "sk-fractional", "", "model-a", "model-a", "openai", true)
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "fractional", Model: "model-a", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-fractional", "")
	for count := 1; count <= 3; count++ {
		s.ObserveStreamChunk("fractional", "model-a", "model-a", []byte(fmt.Sprintf(`data: {"model":"model-a","usage":{"prompt_tokens":%d}}`, count)))
	}
	ks := s.Snapshot("sk-fractional", "", nil, nil, nil, false).Keys["sk-fractional"]
	if ks.TotalCostNanoUSD != 1 {
		t.Fatalf("per-chunk rounding inflated cost: %d", ks.TotalCostNanoUSD)
	}
}

func TestAccountingOverflowDoesNotAdvanceBilledUsage(t *testing.T) {
	eng := pricing.NewEngine()
	if err := eng.SetCustomPrices(map[string]pricing.ModelPrice{"model-a": {Input: 1000000}}, nil); err != nil {
		t.Fatal(err)
	}
	s := NewStore(eng)
	s.BeginRequest("overflow", "sk-overflow", "", "model-a", "model-a", "openai", false)
	s.mu.Lock()
	tr := s.byRequestID["overflow"]
	tr.ExtractedUsage = NormalizedUsage{UncachedInputTokens: math.MaxInt64, HasUsage: true}
	s.reconcileTrackerDeltaLocked(tr)
	s.mu.Unlock()
	if tr.BilledUsage.UncachedInputTokens != 0 || tr.CountedRequest {
		t.Fatal("failed calculation advanced billing")
	}
	if s.PersistenceStatus().AccountingError == "" {
		t.Fatal("accounting failure not exposed")
	}
}

func TestAggregateCostOverflowRejectsWithoutMutatingTracker(t *testing.T) {
	eng := pricing.NewEngine()
	if err := eng.SetCustomPrices(map[string]pricing.ModelPrice{"model-a": {Input: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"key", "tuple", "account-tuple", "ledger"} {
		t.Run(scope, func(t *testing.T) {
			s := NewStore(eng)
			feedLedgerRequest(t, s, "seed", "sk-max", "", "model-a", "model-a", "openai", "provider", "acct", 1, 0, 0)
			s.mu.Lock()
			switch scope {
			case "key":
				s.keys["sk-max"].TotalCostNanoUSD = math.MaxInt64
			case "tuple":
				s.keys["sk-max"].Models["model-a"].CostNanoUSD = math.MaxInt64
			case "account-tuple":
				s.accounts["account::acct"].Models["model-a"].CostNanoUSD = math.MaxInt64
			case "ledger":
				for _, entry := range s.ledger {
					entry.CostNanoUSD = math.MaxInt64
				}
			}
			s.mu.Unlock()
			s.BeginRequest("blocked", "sk-max", "", "model-a", "model-a", "openai", false)
			s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "blocked", APIKey: "sk-max", Model: "model-a", Provider: "provider", AuthID: "acct", Detail: pluginapi.UsageDetail{InputTokens: 1, TotalTokens: 1}}, "")
			tr, _ := s.LookupRequest("blocked")
			if tr.CountedRequest || tr.BilledUsage.UncachedInputTokens != 0 {
				t.Fatal("aggregate overflow advanced billing")
			}
			if s.PersistenceStatus().AccountingError == "" {
				t.Fatal("aggregate overflow was not exposed")
			}
		})
	}
}

func TestExplicitTraceMergeRemovesOnlyDuplicateContribution(t *testing.T) {
	s := NewStore(nil)
	s.BeginRequest("logical", "sk-trace", "", "model-a", "model-a", "openai", false)
	s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "attempt", TraceID: "trace", APIKey: "sk-trace", Model: "model-a", Provider: "provider", AuthID: "acct", Detail: pluginapi.UsageDetail{InputTokens: 5, TotalTokens: 5}}, "")
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "trace", Model: "model-a", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-trace", "")
	ks := s.Snapshot("sk-trace", "", nil, nil, nil, false).Keys["sk-trace"]
	if ks.TotalRequests != 1 || ks.TotalTokens != 5 {
		t.Fatalf("trace alias double counted: %+v", ks)
	}
}
