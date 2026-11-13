package usage

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"math"
	"testing"
	"time"
)

func TestTraceMergeAfterResetDoesNotRestoreDisplay(t *testing.T) {
	for _, target := range []string{"k", ""} {
		t.Run("target="+target, func(t *testing.T) {
			s := regressionStore(t)
			s.BeginRequest("logical", "k", "", "m", "m", "openai", false)
			s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "host", TraceID: "trace", APIKey: "k", Model: "m", Provider: "openai", AuthID: "account", Detail: pluginapi.UsageDetail{InputTokens: 100}}, "")
			before := s.GetKeyCostUSD("k")
			if err := s.Reset(target); err != nil {
				t.Fatal(err)
			}
			s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "trace", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
			if got := s.GetKeyCostUSD("k"); got != before {
				t.Fatalf("quota changed %g -> %g", before, got)
			}
			s.ObserveResponse("logical", "m", "m", []byte(`{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":60}}}`))
			if got := s.GetKeyCostUSD("k"); got != .000046 {
				t.Fatalf("late cache after reset merge not reconciled: %g", got)
			}
			snap := s.Snapshot("k", "", nil, nil, nil, false)
			if k := snap.Keys["k"]; k != nil && k.TotalRequests != 0 {
				t.Fatalf("reset display resurrected: %+v", k)
			}
			if n := s.QueryLedger(LedgerQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}).Requests; n != 0 {
				t.Fatalf("ledger resurrected: %d", n)
			}
			if a := snap.Accounts["account::account"]; a != nil && a.Requests > 1 {
				t.Fatalf("account duplicated: %+v", a)
			}
		})
	}
}

func TestTraceMergeEffectiveAccountPreservesOtherHistory(t *testing.T) {
	s := regressionStore(t)
	s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "history", APIKey: "other", Model: "m", Provider: "p", AuthID: "shared", Detail: pluginapi.UsageDetail{InputTokens: 50}}, "")
	s.BeginRequest("logical", "k", "", "m", "m", "openai", false)
	s.mu.Lock()
	s.byRequestID["logical"].Provider = "p"
	s.byRequestID["logical"].AuthIndex = "alternate"
	s.mu.Unlock()
	s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "host", TraceID: "trace", APIKey: "k", Model: "m", AuthID: "shared", Detail: pluginapi.UsageDetail{InputTokens: 100}}, "")
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "trace", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
	a := s.Snapshot("", "", nil, nil, nil, false).Accounts["account::shared"]
	if a == nil || a.Requests != 2 || a.TotalTokens != 150 {
		t.Fatalf("effective account erased unrelated history: %+v", a)
	}
}

func TestTraceMergeMissingLogicalModelPreservesHostCost(t *testing.T) {
	s := regressionStore(t)
	s.BeginRequest("logical", "k", "", "", "", "openai", false)
	s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "host", TraceID: "trace", APIKey: "k", Model: "m", Detail: pluginapi.UsageDetail{InputTokens: 100}}, "")
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "trace", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
	if got := s.GetKeyCostUSD("k"); got != .0001 {
		t.Fatalf("missing logical model lost host charge: %g", got)
	}
}

func TestTraceMergeRejectionPreservesAlreadyBilledQuota(t *testing.T) {
	for _, failure := range []string{"closing", "invalid", "aggregate"} {
		t.Run(failure, func(t *testing.T) {
			s := regressionStore(t)
			s.BeginRequest("logical", "k", "", "m", "m", "openai", false)
			s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: "host", TraceID: "trace", APIKey: "k", Model: "m", Detail: pluginapi.UsageDetail{InputTokens: 100}}, "")
			before := s.GetKeyCostUSD("k")
			s.mu.Lock()
			switch failure {
			case "closing":
				s.closing = true
			case "invalid":
				s.byRequestID["logical"].ExtractedUsage = NormalizedUsage{HasUsage: true, Invalid: true}
			case "aggregate":
				s.byRequestID["logical"].ExtractedUsage = NormalizedUsage{OutputTokens: math.MaxInt64, HasUsage: true}
			}
			s.mu.Unlock()
			s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "logical", TraceID: "trace", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
			if got := s.GetKeyCostUSD("k"); got != before {
				t.Fatalf("%s merge destroyed billed quota: %g -> %g", failure, before, got)
			}
			if k := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"]; k == nil || k.TotalTokens != 100 {
				t.Fatalf("%s merge destroyed billed stats: %+v", failure, k)
			}
			if s.PersistenceStatus().AccountingError == "" {
				t.Fatal("missing rejection diagnostic")
			}
		})
	}
}
