package usage

import (
	"os"
	"path/filepath"
	"sort"
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

// TestTupleBucketsSeparateRequestedFromServed verifies that one request is billed
// into exactly one (requested, served) tuple and that the two names are stored.
func TestTupleBucketsSeparateRequestedFromServed(t *testing.T) {
	eng := pricing.NewEngine()
	eng.SetCustomPrices(map[string]pricing.ModelPrice{
		"gemini-3.8-flash-high": {Input: 1.0, Output: 2.0},
	}, nil)

	store := NewStore(eng)
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	const requested = "gemini-3.8-flash-high"
	const served = "gemini-3.8-flash-n"

	store.BeginRequest("req-tuple", "sk-tuple", "Tuple Key", requested, requested, "openai", false)
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID:     "req-tuple",
		Provider:      "antigravity",
		Model:         requested,
		ResponseModel: served,
		APIKey:        "sk-tuple",
		Detail:        pluginapi.UsageDetail{InputTokens: 1000, OutputTokens: 500, TotalTokens: 1500},
	}, "Tuple Key")

	snap := store.Snapshot("sk-tuple", "", nil, nil, nil, false)
	ks := snap.Keys["sk-tuple"]
	if ks == nil {
		t.Fatalf("missing key stats")
	}
	if len(ks.Models) != 1 {
		t.Fatalf("expected exactly one tuple bucket, got %v", modelKeys(ks.Models))
	}
	stats := ks.Models[tupleKey(requested, served)]
	if stats == nil {
		t.Fatalf("tuple bucket missing, got %v", modelKeys(ks.Models))
	}
	if stats.RequestedModel != requested || stats.ServedModel != served {
		t.Fatalf("tuple names wrong: %+v", stats)
	}
	if stats.Requests != 1 || stats.TotalTokens != 1500 {
		t.Fatalf("unexpected counters: %+v", stats)
	}
	if !stats.IsSubstituted() {
		t.Fatalf("substitution not detected")
	}
	// Cost is priced from the requested model.
	if stats.CostFormatted != "$0.002000" {
		t.Fatalf("cost should be priced from the requested model, got %s", stats.CostFormatted)
	}
}

// TestTupleKeepsBothRequestNamesForSameServedModel reproduces the real case where a
// served model is reached from two different requested names: each pair has its own
// counters, so the totals are never duplicated or guessed.
func TestTupleKeepsBothRequestNamesForSameServedModel(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	feed := func(reqID, requested, served string, tokens int64) {
		store.BeginRequest(reqID, "sk-split", "Split Key", requested, requested, "openai", false)
		store.ObserveHostUsageRecord(pluginapi.UsageRecord{
			RequestID:     reqID,
			Provider:      "antigravity",
			Model:         requested,
			ResponseModel: served,
			APIKey:        "sk-split",
			Detail:        pluginapi.UsageDetail{InputTokens: tokens, TotalTokens: tokens},
		}, "Split Key")
	}
	feed("req-1", "gemini-3.8-flash-high", "gemini-3.8-flash-n", 100)
	feed("req-2", "gemini-3.8-flash-high", "gemini-3.8-flash-n", 200)
	feed("req-3", "gemini-4-argon-high", "gemini-4-argon-high", 50)
	feed("req-4", "gemini-3.8-flash-high", "gemini-4-argon-high", 30)

	snap := store.Snapshot("sk-split", "", nil, nil, nil, false)
	ks := snap.Keys["sk-split"]
	if len(ks.Models) != 3 {
		t.Fatalf("expected 3 tuples, got %v", modelKeys(ks.Models))
	}
	highToN := ks.Models[tupleKey("gemini-3.8-flash-high", "gemini-3.8-flash-n")]
	if highToN == nil || highToN.Requests != 2 || highToN.TotalTokens != 300 {
		t.Fatalf("high->n tuple wrong: %+v", highToN)
	}
	argonDirect := ks.Models[tupleKey("gemini-4-argon-high", "gemini-4-argon-high")]
	if argonDirect == nil || argonDirect.Requests != 1 || argonDirect.TotalTokens != 50 {
		t.Fatalf("argon direct tuple wrong: %+v", argonDirect)
	}
	highToArgon := ks.Models[tupleKey("gemini-3.8-flash-high", "gemini-4-argon-high")]
	if highToArgon == nil || highToArgon.Requests != 1 || highToArgon.TotalTokens != 30 {
		t.Fatalf("high->argon tuple wrong: %+v", highToArgon)
	}
	if !argonDirect.IsSubstituted() == false {
		t.Fatalf("direct argon must not be marked as substituted")
	}
	// Key totals stay the exact sum of the tuples.
	if ks.TotalRequests != 4 || ks.TotalTokens != 380 {
		t.Fatalf("key totals must equal the tuple sum: %+v", ks)
	}
}

// TestTupleMigrationWhenServedModelArrivesLate covers a streaming response that
// only reveals the served model on a later chunk: the early slice moves to the
// final tuple instead of creating a duplicate row.
func TestTupleMigrationWhenServedModelArrivesLate(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	const requested = "gemini-3.8-flash-high"
	store.BeginRequest("req-late", "sk-late", "Late Key", requested, requested, "openai", true)
	store.ObserveStreamChunk("req-late", "gemini-3.8-flash-control", requested,
		[]byte(`data: {"model":"gemini-3.8-flash-control","usage":{"prompt_tokens":100,"completion_tokens":10}}`))
	store.CompleteRequest(pluginapi.RequestCompletion{
		RequestID: "req-late", Model: requested, Stream: true,
		Outcome: pluginapi.RequestCompletionSucceeded, StatusCode: 200,
	}, "sk-late", "Late Key")
	store.ObserveStreamChunk("req-late", "gemini-3.8-flash-n", requested,
		[]byte(`data: {"model":"gemini-3.8-flash-n","usage":{"prompt_tokens":100,"completion_tokens":10}}`))

	snap := store.Snapshot("sk-late", "", nil, nil, nil, false)
	ks := snap.Keys["sk-late"]
	if len(ks.Models) != 1 {
		t.Fatalf("expected the slice to migrate to a single tuple, got %v", modelKeys(ks.Models))
	}
	stats := ks.Models[tupleKey(requested, "gemini-3.8-flash-n")]
	if stats == nil {
		t.Fatalf("final tuple missing, got %v", modelKeys(ks.Models))
	}
	if stats.Requests != 1 || stats.TotalTokens != 110 {
		t.Fatalf("migrated counters wrong: %+v", stats)
	}
}

// TestZeroTokenTupleStillRecorded keeps a counted request (even a failed one with no
// tokens) attributed to its requested and served names.
func TestZeroTokenTupleStillRecorded(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	const model = "kimi-k3"
	store.BeginRequest("req-zero", "sk-zero", "Zero Key", model, model, "openai", false)
	store.CompleteRequest(pluginapi.RequestCompletion{
		RequestID: "req-zero", Model: model,
		Outcome: pluginapi.RequestCompletionFailed, StatusCode: 502,
	}, "sk-zero", "Zero Key")

	snap := store.Snapshot("sk-zero", "", nil, nil, nil, false)
	stats := snap.Keys["sk-zero"].Models[tupleKey(model, model)]
	if stats == nil {
		t.Fatalf("zero-token tuple missing")
	}
	if stats.Requests != 1 || stats.FailedRequests != 1 {
		t.Fatalf("failed request not counted: %+v", stats)
	}
	if stats.RequestedModel != model || stats.ServedModel != model {
		t.Fatalf("tuple names missing: %+v", stats)
	}
}

// TestIdleReconcileCreatesNoEmptyTuple keeps the phantom-row fix for the tuple model.
func TestIdleReconcileCreatesNoEmptyTuple(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	store.BeginRequest("req-idle", "sk-idle", "Idle Key", "gemini-3.8-flash-high", "gemini-3.8-flash-high", "openai", false)
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID: "req-idle", Provider: "antigravity", AuthID: "antigravity-idle@gmail.com.json",
		Model: "gemini-3.8-flash-high", ResponseModel: "gemini-3.8-flash-n", APIKey: "sk-idle",
		Detail: pluginapi.UsageDetail{InputTokens: 100, TotalTokens: 100},
	}, "Idle Key")
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID: "req-idle", Provider: "antigravity", AuthID: "antigravity-idle@gmail.com.json",
		Model: "gemini-3.8-flash-high", ResponseModel: "gemini-4-argon-high", APIKey: "sk-idle",
		Detail: pluginapi.UsageDetail{},
	}, "Idle Key")

	snap := store.Snapshot("sk-idle", "", nil, nil, nil, false)
	for name, ms := range snap.Keys["sk-idle"].Models {
		if ms.Requests == 0 && ms.TotalTokens == 0 {
			t.Fatalf("empty tuple %q must not be created: %+v", name, ms)
		}
	}
	for _, acct := range snap.Accounts {
		for name, ms := range acct.Models {
			if ms.Requests == 0 && ms.TotalTokens == 0 {
				t.Fatalf("empty account tuple %q must not be created: %+v", name, ms)
			}
		}
	}
}

// TestAccountTuplesGroupByProviderAndCredential covers the account dimension.
func TestAccountTuplesGroupByProviderAndCredential(t *testing.T) {
	eng := pricing.NewEngine()
	usageFile := filepath.Join(t.TempDir(), "usage.json")
	store := NewStore(eng)
	if err := store.ConfigurePersistence(usageFile, time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}

	feed := func(reqID, authID, requested, served string, tokens int64) {
		store.BeginRequest(reqID, "sk-acct", "Account Key", requested, requested, "openai", false)
		store.ObserveHostUsageRecord(pluginapi.UsageRecord{
			RequestID: reqID, Provider: "antigravity", AuthID: authID, AuthType: "oauth",
			Model: requested, ResponseModel: served, APIKey: "sk-acct",
			Detail: pluginapi.UsageDetail{InputTokens: tokens, TotalTokens: tokens},
		}, "Account Key")
	}
	feed("req-a", "antigravity-sly538876@gmail.com.json", "gemini-3.8-flash-high", "gemini-3.8-flash-n", 1000)
	feed("req-b", "antigravity-sly538876@gmail.com.json", "gemini-3.8-flash-high", "gemini-3.8-flash-control", 200)
	feed("req-c", "antigravity-yzmzxa@gmail.com.json", "gemini-4-argon-high", "gemini-4-argon-high", 400)

	snap := store.Snapshot("", "", nil, nil, nil, false)
	if len(snap.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(snap.Accounts))
	}
	var first *AccountStats
	for _, acct := range snap.Accounts {
		if acct.AuthID == "antigravity-sly538876@gmail.com.json" {
			first = acct
		}
	}
	if first == nil {
		t.Fatalf("expected credential bucket for sly538876")
	}
	if first.Requests != 2 || first.TotalTokens != 1200 {
		t.Fatalf("account totals wrong: %+v", first)
	}
	if len(first.Models) != 2 {
		t.Fatalf("expected 2 tuples on the account, got %v", modelKeys(first.Models))
	}
	nTuple := first.Models[tupleKey("gemini-3.8-flash-high", "gemini-3.8-flash-n")]
	if nTuple == nil || nTuple.ServedModel != "gemini-3.8-flash-n" {
		t.Fatalf("account tuple missing: %+v", nTuple)
	}
	if errFlush := store.FlushNow(); errFlush != nil {
		t.Fatalf("flush: %v", errFlush)
	}
	_ = store.Close()

	reloaded := NewStore(eng)
	if err := reloaded.ConfigurePersistence(usageFile, time.Hour); err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer reloaded.Close()
	reloadedSnap := reloaded.Snapshot("", "", nil, nil, nil, false)
	if len(reloadedSnap.Accounts) != 2 {
		t.Fatalf("accounts did not survive persistence")
	}
	var tokens int64
	for _, acct := range reloadedSnap.Accounts {
		tokens += acct.TotalTokens
	}
	if tokens != 1600 {
		t.Fatalf("account totals lost across reload: %d", tokens)
	}
}

// TestHashedCredentialsMergeIntoOneAccount keeps the identity normalization.
func TestHashedCredentialsMergeIntoOneAccount(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(t.TempDir(), "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure store: %v", err)
	}
	defer store.Close()

	feed := func(reqID, authID string, tokens int64) {
		store.BeginRequest(reqID, "sk-hash", "Hash Key", "glm-5.3", "glm-5.3", "openai", false)
		store.ObserveHostUsageRecord(pluginapi.UsageRecord{
			RequestID: reqID, Provider: "openai", AuthID: authID, Model: "glm-5.3", APIKey: "sk-hash",
			Detail: pluginapi.UsageDetail{InputTokens: tokens, TotalTokens: tokens},
		}, "Hash Key")
	}
	feed("req-1", "openai-compatibility:上海人工智能实验室:5dfdf0f0b3d3", 100)
	feed("req-2", "openai-compatibility:上海人工智能实验室:1989c9fb1cda", 200)

	snap := store.Snapshot("", "", nil, nil, nil, false)
	if len(snap.Accounts) != 1 {
		t.Fatalf("hashed credentials must share one account, got %d", len(snap.Accounts))
	}
	var acct *AccountStats
	for _, a := range snap.Accounts {
		acct = a
	}
	if acct.AuthID != "openai-compatibility:上海人工智能实验室" {
		t.Fatalf("account identity not normalized: %q", acct.AuthID)
	}
	if acct.Requests != 2 || acct.TotalTokens != 300 {
		t.Fatalf("merged totals wrong: %+v", acct)
	}
}

// TestLoadNormalizesTupleKeys drops malformed entries and re-keys by the stored names.

func modelKeys(models map[string]*ModelStats) []string {
	out := make([]string, 0, len(models))
	for k := range models {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
