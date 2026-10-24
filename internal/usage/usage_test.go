package usage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/tidwall/gjson"
)

func TestWriteFileAtomicallyOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "test.json")
	if err := WriteFileAtomically(p, []byte("first content")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := WriteFileAtomically(p, []byte("second content")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(data) != "second content" {
		t.Fatalf("got %q, want %q", string(data), "second content")
	}
}

func TestClaudeStreamIncrementalMerge(t *testing.T) {

	// Chunk 1: message_start contains input_tokens, cache_read_input_tokens, cache_creation_input_tokens, and initial output_tokens=1
	chunk1 := []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet-20241022\",\"usage\":{\"input_tokens\":150,\"cache_creation_input_tokens\":400,\"cache_read_input_tokens\":1200,\"output_tokens\":1}}}\n\n")
	// Chunk 2: content_block_delta (no usage)
	chunk2 := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n")
	// Chunk 3: message_delta at end of stream ONLY has output_tokens (input_tokens is omitted or 0)
	chunk3 := []byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":85}}\n\n")

	var acc NormalizedUsage
	acc = ObserveStreamChunkUsage("claude", chunk1, acc)
	acc = ObserveStreamChunkUsage("claude", chunk2, acc)
	acc = ObserveStreamChunkUsage("claude", chunk3, acc)

	if !acc.HasUsage {
		t.Fatalf("expected HasUsage=true")
	}
	if acc.UncachedInputTokens != 150 {
		t.Fatalf("UncachedInputTokens = %d, want 150 (must not be overwritten by message_delta)", acc.UncachedInputTokens)
	}
	if acc.CacheCreationTokens() != 400 {
		t.Fatalf("CacheWriteTokens = %d, want 400", acc.CacheWriteTokens)
	}
	if acc.CacheReadTokens != 1200 {
		t.Fatalf("CacheReadTokens = %d, want 1200", acc.CacheReadTokens)
	}
	if acc.OutputTokens != 85 {
		t.Fatalf("OutputTokens = %d, want 85", acc.OutputTokens)
	}
	if acc.TotalTokens != 150+400+1200+85 {
		t.Fatalf("TotalTokens = %d, want %d", acc.TotalTokens, 150+400+1200+85)
	}
}

func (u NormalizedUsage) CacheCreationTokens() int64 {
	return u.CacheWriteTokens
}

func TestMultiProtocolExtraction(t *testing.T) {
	// 1. OpenAI Chat Completions (prompt_tokens includes cached_tokens)
	openAIBody := []byte(`{
		"id": "chatcmpl-123",
		"model": "gpt-4o-2024-08-06",
		"usage": {
			"prompt_tokens": 1000,
			"completion_tokens": 250,
			"total_tokens": 1250,
			"prompt_tokens_details": {"cached_tokens": 600},
			"completion_tokens_details": {"reasoning_tokens": 50}
		}
	}`)
	uOpenAI := ExtractResponseUsage("openai", openAIBody)
	if uOpenAI.UncachedInputTokens != 400 || uOpenAI.CacheReadTokens != 600 || uOpenAI.OutputTokens != 250 || uOpenAI.ReasoningTokens != 50 {
		t.Fatalf("unexpected OpenAI usage: %+v", uOpenAI)
	}

	// 2. OpenAI Responses API (response.usage with input_tokens / output_tokens)
	responsesChunk := []byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-4o\",\"usage\":{\"input_tokens\":800,\"output_tokens\":120,\"total_tokens\":920,\"input_tokens_details\":{\"cached_tokens\":300}}}}\n\n")
	var uResp NormalizedUsage
	uResp = ObserveStreamChunkUsage("openai-response", responsesChunk, uResp)
	if uResp.UncachedInputTokens != 500 || uResp.CacheReadTokens != 300 || uResp.OutputTokens != 120 {
		t.Fatalf("unexpected OpenAI Responses usage: %+v", uResp)
	}

	// 3. Gemini usageMetadata (promptTokenCount includes cachedContentTokenCount; thoughtsTokenCount added to output)
	geminiBody := []byte(`{
		"candidates": [{"content": {"parts": [{"text": "answer"}]}}],
		"usageMetadata": {
			"promptTokenCount": 500,
			"candidatesTokenCount": 100,
			"thoughtsTokenCount": 40,
			"cachedContentTokenCount": 200,
			"totalTokenCount": 640
		}
	}`)
	uGemini := ExtractResponseUsage("gemini", geminiBody)
	if uGemini.UncachedInputTokens != 300 || uGemini.CacheReadTokens != 200 || uGemini.OutputTokens != 140 || uGemini.ReasoningTokens != 40 {
		t.Fatalf("unexpected Gemini usage: %+v", uGemini)
	}
}

func TestStreamOptionsProtocolGuard(t *testing.T) {
	rawReq := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}`)

	// 1. OpenAI Chat Completions streaming -> should inject
	injected, changed := MaybeInjectStreamIncludeUsage("openai", "/v1/chat/completions", true, rawReq)
	if !changed || !gjson.GetBytes(injected, "stream_options.include_usage").Bool() {
		t.Fatalf("expected stream_options.include_usage=true injected for openai chat completions, got: %s", string(injected))
	}

	// 2. Existing stream_options.include_usage=false -> must NOT overwrite
	explicitFalse := []byte(`{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false}}`)
	outFalse, changedFalse := MaybeInjectStreamIncludeUsage("openai", "/v1/chat/completions", true, explicitFalse)
	if changedFalse || gjson.GetBytes(outFalse, "stream_options.include_usage").Bool() {
		t.Fatalf("must not overwrite explicit include_usage=false")
	}

	// 3. Claude, Gemini, OpenAI Responses -> must NEVER inject
	for _, proto := range []string{"claude", "gemini", "openai-response", "codex"} {
		_, mod := MaybeInjectStreamIncludeUsage(proto, "", true, rawReq)
		if mod {
			t.Fatalf("must NOT inject stream_options for protocol %q", proto)
		}
	}

	// 4. OpenAI format but /v1/responses endpoint path -> must NOT inject
	if _, mod := MaybeInjectStreamIncludeUsage("openai", "/v1/responses", true, rawReq); mod {
		t.Fatalf("must NOT inject stream_options on /v1/responses path")
	}
}

func TestStoreDeduplicationAndProtocolConversionReconciliation(t *testing.T) {
	tmpDir := t.TempDir()
	usageFile := filepath.Join(tmpDir, "usage.json")

	eng := pricing.NewEngine()
	eng.SetCustomPrices(map[string]pricing.ModelPrice{
		"claude-3-5-sonnet-20241022": {
			Input:      3.0,
			Output:     15.0,
			CacheRead:  0.3,
			CacheWrite: 3.75,
		},
	}, nil)

	store := NewStore(eng)
	if err := store.ConfigurePersistence(usageFile, time.Hour); err != nil {
		t.Fatalf("ConfigurePersistence: %v", err)
	}
	defer store.Close()

	// Scenario: Request 1 is a streaming Claude request that gets translated to OpenAI downstream.
	// Interceptor sees OpenAI stream usage (without cache_write_tokens), while host `usage.handle`
	// sees the upstream Claude usage (including cache_creation_input_tokens=1000).
	reqID := "req-100"
	traceID := "trace-100"
	apiKey := "sk-tenant-alpha"
	model := "claude-3-5-sonnet-20241022"

	store.BeginRequest(reqID, apiKey, "Alpha", model, model, "openai", true)
	store.ObserveStreamChunk(reqID, model, model, []byte(`data: {"id":"1","model":"claude-3-5-sonnet-20241022","usage":{"prompt_tokens":2000,"completion_tokens":500,"prompt_tokens_details":{"cached_tokens":1000}}}`))

	// Step A: request.complete runs first
	store.CompleteRequest(pluginapi.RequestCompletion{
		RequestID:    reqID,
		TraceID:      traceID,
		SourceFormat: "openai",
		Model:        model,
		Stream:       true,
		Outcome:      pluginapi.RequestCompletionSucceeded,
		StatusCode:   200,
	}, apiKey, "Alpha")

	// Step B: usage.handle arrives right after with upstream Claude UsageDetail (including 400 cache write tokens)
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID: "attempt-1",
		TraceID:   traceID,
		Provider:  "claude",
		Model:     model,
		APIKey:    apiKey,
		Stream:    true,
		Detail: pluginapi.UsageDetail{
			InputTokens:         1000,
			OutputTokens:        500,
			CacheReadTokens:     1000,
			CacheCreationTokens: 400,
			TotalTokens:         2900,
		},
	}, "Alpha")

	snap := store.Snapshot(apiKey, "", nil, nil, nil, false)
	ks := snap.Keys[apiKey]
	if ks == nil {
		t.Fatalf("expected key stats for %s", apiKey)
	}
	// Must be counted as 1 request, NOT 2!
	if ks.TotalRequests != 1 || ks.SuccessRequests != 1 {
		t.Fatalf("expected TotalRequests=1 (no double counting), got TotalRequests=%d, Success=%d", ks.TotalRequests, ks.SuccessRequests)
	}
	// Tokens must reflect the reconciled union (1000 uncached input, 500 output, 1000 cache read, 400 cache write)
	if ks.InputTokens != 1000 || ks.OutputTokens != 500 || ks.CacheReadTokens != 1000 || ks.CacheWriteTokens != 400 {
		t.Fatalf("unexpected reconciled token counts: %+v", ks)
	}
	// Expected USD: (1000*3 + 500*15 + 1000*0.3 + 400*3.75) / 1e6 = (3000 + 7500 + 300 + 1500) / 1e6 = $0.012300
	if ks.TotalCostFormatted != "$0.012300" {
		t.Fatalf("TotalCostFormatted = %s, want $0.012300", ks.TotalCostFormatted)
	}

	// Verify hot-reload (ConfigurePersistence) retains in-memory data
	if err := store.ConfigurePersistence(usageFile, time.Hour); err != nil {
		t.Fatalf("reconfigure persistence failed: %v", err)
	}
	snapAfterReload := store.Snapshot(apiKey, "", nil, nil, nil, false)
	if snapAfterReload.Keys[apiKey].TotalRequests != 1 || snapAfterReload.Keys[apiKey].TotalCostFormatted != "$0.012300" {
		t.Fatalf("stats lost after hot-reload: %+v", snapAfterReload.Keys[apiKey])
	}
}

// TestUsageMirrorSurvivesEphemeralTarget verifies that billing history is mirrored
// to durable paths and restored when the configured file is recreated empty.
func TestUsageMirrorSurvivesEphemeralTarget(t *testing.T) {
	tmpDir := t.TempDir()
	ephemeralFile := filepath.Join(tmpDir, "data", "key_usage_stats.json")
	durableMirror := filepath.Join(tmpDir, "durable", "key_usage_stats.json")

	eng := pricing.NewEngine()
	source := NewStore(eng)
	source.SetMirrorFiles([]string{durableMirror})
	if err := source.ConfigurePersistence(ephemeralFile, time.Hour); err != nil {
		t.Fatalf("configure source: %v", err)
	}
	source.BeginRequest("req-1", "sk-mirror", "Mirrored", "gpt-4o", "gpt-4o", "openai", false)
	source.ObserveStreamChunk("req-1", "gpt-4o", "gpt-4o", []byte(`data: {"id":"1","model":"gpt-4o","usage":{"prompt_tokens":1000,"completion_tokens":500}}`))
	source.CompleteRequest(pluginapi.RequestCompletion{
		RequestID:  "req-1",
		Model:      "gpt-4o",
		Outcome:    pluginapi.RequestCompletionSucceeded,
		StatusCode: 200,
	}, "", "")
	if err := source.FlushNow(); err != nil {
		t.Fatalf("flush source: %v", err)
	}
	_ = source.Close()

	if info, errStat := os.Stat(durableMirror); errStat != nil || info.Size() == 0 {
		t.Fatalf("usage mirror was not written: %v", errStat)
	}

	// Simulate a container restart: the ./data file is gone.
	if err := os.RemoveAll(filepath.Join(tmpDir, "data")); err != nil {
		t.Fatalf("remove ephemeral dir: %v", err)
	}

	restored := NewStore(eng)
	restored.SetMirrorFiles([]string{durableMirror})
	if err := restored.ConfigurePersistence(ephemeralFile, time.Hour); err != nil {
		t.Fatalf("configure restored: %v", err)
	}
	defer restored.Close()

	snap := restored.Snapshot("sk-mirror", "", nil, nil, nil, false)
	stats := snap.Keys["sk-mirror"]
	if stats == nil || stats.TotalRequests != 1 {
		t.Fatalf("usage history was not restored from the durable mirror: %+v", stats)
	}
	if info, errStat := os.Stat(ephemeralFile); errStat != nil || info.Size() == 0 {
		t.Fatalf("restored snapshot was not written back to the configured path: %v", errStat)
	}
}
