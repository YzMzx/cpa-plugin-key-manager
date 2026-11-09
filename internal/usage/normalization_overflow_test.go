package usage

import (
	"math"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestGeminiIntermediateTokenOverflowIsNeverBilledAsZero(t *testing.T) {
	for _, payload := range []string{
		`{"usageMetadata":{"promptTokenCount":9223372036854775807,"toolUsePromptTokenCount":1}}`,
		`{"usageMetadata":{"candidatesTokenCount":9223372036854775807,"thoughtsTokenCount":1}}`,
	} {
		u := ExtractResponseUsage("gemini", []byte(payload))
		if !u.Invalid {
			t.Fatal("overflow normalized into an apparently valid zero")
		}
		s := NewStore(nil)
		s.BeginRequest("overflow", "sk-overflow-input", "", "m", "m", "gemini", false)
		s.ObserveResponse("overflow", "m", "m", []byte(payload))
		s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "overflow", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-overflow-input", "")
		tracked, _ := s.LookupRequest("overflow")
		if tracked.CountedRequest || tracked.BilledUsage.HasUsage {
			t.Fatal("invalid usage advanced billing")
		}
		if s.PersistenceStatus().AccountingError == "" {
			t.Fatal("invalid usage had no diagnostic")
		}
	}
}

func TestOverflowFlagSurvivesAllUsageMerges(t *testing.T) {
	invalid := NormalizedUsage{UncachedInputTokens: math.MaxInt64, OutputTokens: 1, HasUsage: true}
	invalid.RecomputeTotal()
	if !invalid.Invalid {
		t.Fatal("orthogonal total overflow was not marked")
	}
	valid := NormalizedUsage{UncachedInputTokens: 1, HasUsage: true}
	for _, u := range []NormalizedUsage{MergeUsage(valid, invalid), MergeUsage(invalid, valid), MergeMaxUsage(valid, invalid), MergeMaxUsage(invalid, valid)} {
		if !u.Invalid {
			t.Fatal("merge erased normalization error")
		}
	}
	good := ExtractResponseUsage("gemini", []byte(`{"usageMetadata":{"promptTokenCount":3,"toolUsePromptTokenCount":2,"candidatesTokenCount":4,"thoughtsTokenCount":1}}`))
	if good.Invalid || good.UncachedInputTokens != 5 || good.OutputTokens != 5 || good.TotalTokens != 10 {
		t.Fatalf("normal usage changed: %+v", good)
	}
}
