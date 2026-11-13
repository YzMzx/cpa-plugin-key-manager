package usage

import (
	"bytes"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizedUsage holds orthogonal token counts for accurate multi-protocol billing.
//
// Orthogonal bucket definitions:
//   - UncachedInputTokens: Input tokens NOT served from cache (billed at `input` price)
//   - OutputTokens:        Total output/completion tokens including reasoning/thinking tokens (billed at `output` price)
//   - ReasoningTokens:     Subset of OutputTokens used for reasoning/thinking (informational)
//   - CacheReadTokens:     Cached input tokens read (billed at `cache_read` price)
//   - CacheWriteTokens:    Cache creation/write input tokens (billed at `cache_write` price)
//   - TotalTokens:         UncachedInputTokens + OutputTokens + CacheReadTokens + CacheWriteTokens
type NormalizedUsage struct {
	UncachedInputTokens int64  `json:"uncached_input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	ReasoningTokens     int64  `json:"reasoning_tokens,omitempty"`
	CacheReadTokens     int64  `json:"cache_read_tokens"`
	CacheWriteTokens    int64  `json:"cache_write_tokens"`
	TotalTokens         int64  `json:"total_tokens"`
	ResponseModel       string `json:"response_model,omitempty"`
	HasUsage            bool   `json:"has_usage"`
	// Invalid preserves arithmetic errors through stream/host merging; never bill a normalized zero after overflow.
	Invalid bool `json:"invalid,omitempty"`
	// Preserve original input semantics: cached tokens refine an inclusive total,
	// not an additional independent input bucket. Presence survives sparse events.
	inputTotal          int64
	inputPresent        bool
	inputInclusive      bool
	cacheReadPresent    bool
	cacheWritePresent   bool
	cacheWriteInclusive bool
	inputSource         string
}

// RecomputeTotal recalculates TotalTokens from the four orthogonal token buckets.
func (u *NormalizedUsage) RecomputeTotal() {
	if u.Invalid {
		u.HasUsage = true
	}
	if u.UncachedInputTokens < 0 {
		u.UncachedInputTokens = 0
	}
	if u.OutputTokens < 0 {
		u.OutputTokens = 0
	}
	if u.CacheReadTokens < 0 {
		u.CacheReadTokens = 0
	}
	if u.CacheWriteTokens < 0 {
		u.CacheWriteTokens = 0
	}
	calc, valid := checkedTokenSum(u.UncachedInputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	if !valid {
		u.Invalid = true
		u.HasUsage = true
		return
	}
	if calc > 0 || u.TotalTokens < calc {
		u.TotalTokens = calc
	}
	if u.UncachedInputTokens > 0 || u.OutputTokens > 0 || u.CacheReadTokens > 0 || u.CacheWriteTokens > 0 || u.TotalTokens > 0 {
		u.HasUsage = true
	}
}

// MergeUsage performs a non-zero field-by-field merge of `update` into `existing`.
// This is critical for streaming protocols like Anthropic Claude, where `message_start` carries
// `input_tokens` / `cache_read_input_tokens` / `cache_creation_input_tokens` and `message_delta`
// at the end of the stream only carries `output_tokens` (with input fields omitted or zero).
// A later chunk's zero field NEVER overwrites an earlier chunk's non-zero field.
func MergeUsage(existing, update NormalizedUsage) NormalizedUsage {
	if !update.HasUsage && !update.Invalid && update.ResponseModel == "" {
		return existing
	}
	merged := existing
	merged.Invalid = existing.Invalid || update.Invalid
	if update.UncachedInputTokens > 0 {
		merged.UncachedInputTokens = update.UncachedInputTokens
	}
	if update.OutputTokens > 0 {
		merged.OutputTokens = update.OutputTokens
	}
	if update.ReasoningTokens > 0 {
		merged.ReasoningTokens = update.ReasoningTokens
	}
	if update.CacheReadTokens > 0 {
		merged.CacheReadTokens = update.CacheReadTokens
	}
	if update.CacheWriteTokens > 0 {
		merged.CacheWriteTokens = update.CacheWriteTokens
	}
	if update.TotalTokens > merged.TotalTokens {
		merged.TotalTokens = update.TotalTokens
	}
	if strings.TrimSpace(update.ResponseModel) != "" {
		merged.ResponseModel = strings.TrimSpace(update.ResponseModel)
	}
	if update.HasUsage {
		merged.HasUsage = true
	}
	mergeInputEvidence(&merged, existing, update)
	merged.RecomputeTotal()
	return merged
}

// MergeMaxUsage merges cumulative evidence, reclassifying inclusive input when cache details arrive.
// Used when reconciling interceptor-extracted usage with host UsageRecord.Detail across protocol translations.
func MergeMaxUsage(a, b NormalizedUsage) NormalizedUsage {
	out := a
	out.Invalid = a.Invalid || b.Invalid
	if b.UncachedInputTokens > out.UncachedInputTokens {
		out.UncachedInputTokens = b.UncachedInputTokens
	}
	if b.OutputTokens > out.OutputTokens {
		out.OutputTokens = b.OutputTokens
	}
	if b.ReasoningTokens > out.ReasoningTokens {
		out.ReasoningTokens = b.ReasoningTokens
	}
	if b.CacheReadTokens > out.CacheReadTokens {
		out.CacheReadTokens = b.CacheReadTokens
	}
	if b.CacheWriteTokens > out.CacheWriteTokens {
		out.CacheWriteTokens = b.CacheWriteTokens
	}
	if b.TotalTokens > out.TotalTokens {
		out.TotalTokens = b.TotalTokens
	}
	if out.ResponseModel == "" && b.ResponseModel != "" {
		out.ResponseModel = b.ResponseModel
	}
	if a.HasUsage || b.HasUsage {
		out.HasUsage = true
	}
	mergeInputEvidence(&out, a, b)
	out.RecomputeTotal()
	return out
}

// MaybeInjectStreamIncludeUsage injects `"stream_options": {"include_usage": true}` into a streaming request
// ONLY when:
//  1. stream is true
//  2. sourceFormat is strictly OpenAI Chat Completions ("openai")
//  3. requestPath (if present) is not an incompatible endpoint (such as /v1/responses or /v1/messages)
//  4. body is valid JSON object and does not already specify `stream_options.include_usage`
func MaybeInjectStreamIncludeUsage(sourceFormat, requestPath string, stream bool, body []byte) ([]byte, bool) {
	if !stream || len(body) == 0 {
		return body, false
	}
	format := strings.ToLower(strings.TrimSpace(sourceFormat))
	if format != "openai" {
		return body, false
	}
	pathLower := strings.ToLower(strings.TrimSpace(requestPath))
	if pathLower != "" {
		if strings.Contains(pathLower, "/responses") ||
			strings.Contains(pathLower, "/messages") ||
			strings.Contains(pathLower, ":streamgeneratecontent") ||
			strings.Contains(pathLower, "/embeddings") ||
			strings.Contains(pathLower, "/images") {
			return body, false
		}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !gjson.ValidBytes(body) {
		return body, false
	}
	if gjson.GetBytes(body, "stream_options.include_usage").Exists() {
		return body, false
	}
	updated, err := sjson.SetBytes(body, "stream_options.include_usage", true)
	if err != nil {
		return body, false
	}
	return updated, true
}

var (
	markerUsage         = []byte(`"usage"`)
	markerUsageMetadata = []byte(`"usageMetadata"`)
)

// ExtractResponseUsage extracts NormalizedUsage from a non-streaming JSON response body across
// OpenAI Chat Completions, OpenAI Responses API, Anthropic Claude, and Google Gemini formats.
func ExtractResponseUsage(sourceFormat string, payload []byte) NormalizedUsage {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return NormalizedUsage{}
	}
	// If payload looks like SSE lines (e.g. a buffered stream), parse line by line
	if bytes.HasPrefix(trimmed, []byte("data:")) || bytes.HasPrefix(trimmed, []byte("event:")) {
		var acc NormalizedUsage
		acc = ObserveStreamChunkUsage(sourceFormat, trimmed, acc)
		return acc
	}
	if !gjson.ValidBytes(trimmed) {
		return NormalizedUsage{}
	}
	return extractFromValidJSON(sourceFormat, trimmed)
}

// ObserveStreamChunkUsage scans an SSE chunk (which may contain one or multiple lines/events)
// and incrementally merges any discovered usage fields into `current`.
func ObserveStreamChunkUsage(sourceFormat string, chunk []byte, current NormalizedUsage) NormalizedUsage {
	if len(chunk) == 0 {
		return current
	}
	// Fast path: skip JSON parsing if chunk contains neither "usage" nor "usageMetadata"
	if !bytes.Contains(chunk, markerUsage) && !bytes.Contains(chunk, markerUsageMetadata) {
		return current
	}

	remaining := chunk
	for len(remaining) > 0 {
		var line []byte
		if idx := bytes.IndexByte(remaining, '\n'); idx >= 0 {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		} else {
			line = remaining
			remaining = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte(":")) || bytes.HasPrefix(line, []byte("event:")) {
			continue
		}
		if bytes.HasPrefix(line, []byte("data:")) {
			line = bytes.TrimSpace(line[len("data:"):])
		}
		if len(line) == 0 || bytes.Equal(line, []byte("[DONE]")) {
			continue
		}
		if !bytes.Contains(line, markerUsage) && !bytes.Contains(line, markerUsageMetadata) {
			continue
		}
		if !gjson.ValidBytes(line) {
			continue
		}
		lineUsage := extractFromValidJSON(sourceFormat, line)
		if lineUsage.HasUsage || lineUsage.ResponseModel != "" {
			current = MergeUsage(current, lineUsage)
		}
	}
	return current
}

func extractFromValidJSON(sourceFormat string, data []byte) NormalizedUsage {
	root := gjson.ParseBytes(data)
	respModel := extractModelFromJSON(root)

	// 1. Check Gemini `usageMetadata` (top-level or nested under `response.usageMetadata` / `result.usageMetadata`)
	for _, path := range []string{"usageMetadata", "response.usageMetadata", "result.usageMetadata"} {
		node := root.Get(path)
		if node.Exists() && node.IsObject() {
			u := parseGeminiUsageNode(node)
			u.ResponseModel = respModel
			return u
		}
	}

	// 2. Check OpenAI Responses API `response.usage`
	if respUsage := root.Get("response.usage"); respUsage.Exists() && respUsage.IsObject() {
		u := parseOpenAIOrResponsesUsageNode(respUsage)
		if u.ResponseModel == "" {
			u.ResponseModel = respModel
		}
		return u
	}

	// 3. Check Anthropic `message.usage` (e.g. `message_start` SSE event)
	if msgUsage := root.Get("message.usage"); msgUsage.Exists() && msgUsage.IsObject() {
		u := parseAnthropicUsageNode(msgUsage)
		u.ResponseModel = respModel
		return u
	}

	// 4. Check top-level `usage`
	if usageNode := root.Get("usage"); usageNode.Exists() && usageNode.IsObject() {
		if isAnthropicUsageObject(root, usageNode, sourceFormat) {
			u := parseAnthropicUsageNode(usageNode)
			u.ResponseModel = respModel
			return u
		}
		u := parseOpenAIOrResponsesUsageNode(usageNode)
		u.ResponseModel = respModel
		return u
	}

	return NormalizedUsage{ResponseModel: respModel}
}

func extractModelFromJSON(root gjson.Result) string {
	for _, path := range []string{"model", "message.model", "response.model", "modelVersion"} {
		if v := strings.TrimSpace(root.Get(path).String()); v != "" {
			return v
		}
	}
	return ""
}

func isAnthropicUsageObject(root, usageNode gjson.Result, sourceFormat string) bool {
	// Explicit Anthropic fields or event types
	if usageNode.Get("cache_read_input_tokens").Exists() ||
		usageNode.Get("cache_creation_input_tokens").Exists() ||
		usageNode.Get("cache_creation").Exists() {
		return true
	}
	rootType := root.Get("type").String()
	if rootType == "message" || rootType == "message_start" || rootType == "message_delta" {
		return true
	}
	// If OpenAI-specific fields exist, it's OpenAI / Responses API
	if usageNode.Get("prompt_tokens").Exists() ||
		usageNode.Get("completion_tokens").Exists() ||
		usageNode.Get("prompt_tokens_details").Exists() ||
		usageNode.Get("input_tokens_details").Exists() ||
		usageNode.Get("output_tokens_details").Exists() {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(sourceFormat), "claude")
}

// parseAnthropicUsageNode parses Claude's usage object where `input_tokens` is ALREADY uncached
// and independent from `cache_read_input_tokens` and `cache_creation_input_tokens`.
func parseAnthropicUsageNode(node gjson.Result) NormalizedUsage {
	invalid := false
	token := func(n gjson.Result) int64 { return strictTokenInteger(n, &invalid) }
	input := token(node.Get("input_tokens"))
	output := token(node.Get("output_tokens"))
	cacheRead := token(node.Get("cache_read_input_tokens"))
	cacheWrite := token(node.Get("cache_creation_input_tokens"))

	var reasoning int64
	for _, rPath := range []string{"output_tokens_details.thinking_tokens", "output_tokens_details.reasoning_tokens", "thinking_tokens"} {
		if rNode := node.Get(rPath); rNode.Exists() {
			reasoning = token(rNode)
			break
		}
	}

	hasAny := node.Get("input_tokens").Exists() ||
		node.Get("output_tokens").Exists() ||
		node.Get("cache_read_input_tokens").Exists() ||
		node.Get("cache_creation_input_tokens").Exists()

	u := NormalizedUsage{
		UncachedInputTokens: maxInt64(0, input),
		OutputTokens:        maxInt64(0, output),
		ReasoningTokens:     maxInt64(0, reasoning),
		CacheReadTokens:     maxInt64(0, cacheRead),
		CacheWriteTokens:    maxInt64(0, cacheWrite),
		HasUsage:            hasAny,
	}
	u.Invalid = invalid
	u.inputPresent = node.Get("input_tokens").Exists()
	u.inputTotal = maxInt64(0, input)
	u.inputSource = "anthropic"
	u.cacheReadPresent = node.Get("cache_read_input_tokens").Exists()
	u.cacheWritePresent = node.Get("cache_creation_input_tokens").Exists()
	u.RecomputeTotal()
	return u
}

// parseOpenAIOrResponsesUsageNode parses OpenAI Chat Completions (`prompt_tokens`/`completion_tokens`)
// and OpenAI Responses API (`input_tokens`/`output_tokens`), where `prompt_tokens`/`input_tokens`
// includes `cached_tokens`.
func parseOpenAIOrResponsesUsageNode(node gjson.Result) NormalizedUsage {
	invalid := false
	token := func(n gjson.Result) int64 { return strictTokenInteger(n, &invalid) }
	var rawInput int64
	hasInput := false
	if n := node.Get("prompt_tokens"); n.Exists() {
		rawInput = token(n)
		hasInput = true
	} else if n := node.Get("input_tokens"); n.Exists() {
		rawInput = token(n)
		hasInput = true
	}

	var output int64
	hasOutput := false
	if n := node.Get("completion_tokens"); n.Exists() {
		output = token(n)
		hasOutput = true
	} else if n := node.Get("output_tokens"); n.Exists() {
		output = token(n)
		hasOutput = true
	}

	var cacheRead int64
	hasCacheRead := false
	for _, cPath := range []string{
		"prompt_tokens_details.cached_tokens",
		"input_tokens_details.cached_tokens",
		"cache_read_input_tokens",
		"cached_tokens",
	} {
		if n := node.Get(cPath); n.Exists() {
			cacheRead = token(n)
			hasCacheRead = true
			break
		}
	}

	var cacheWrite int64
	hasCacheWrite := false
	for _, wPath := range []string{
		"prompt_tokens_details.cache_write_tokens",
		"prompt_tokens_details.cache_creation_tokens",
		"input_tokens_details.cache_write_tokens",
		"input_tokens_details.cache_creation_tokens",
		"cache_creation_input_tokens",
	} {
		if n := node.Get(wPath); n.Exists() {
			cacheWrite = token(n)
			hasCacheWrite = true
			break
		}
	}

	var reasoning int64
	for _, rPath := range []string{
		"completion_tokens_details.reasoning_tokens",
		"output_tokens_details.reasoning_tokens",
		"reasoning_tokens",
	} {
		if n := node.Get(rPath); n.Exists() {
			reasoning = token(n)
			break
		}
	}

	total := token(node.Get("total_tokens"))
	hasTotal := node.Get("total_tokens").Exists()

	// In OpenAI Chat Completions & Responses API, prompt_tokens / input_tokens includes cached_tokens.
	uncachedInput := rawInput
	if cacheRead > 0 && rawInput >= cacheRead {
		uncachedInput = rawInput - cacheRead
	}
	if cacheWrite > 0 && uncachedInput >= cacheWrite && (node.Get("prompt_tokens_details.cache_write_tokens").Exists() || node.Get("input_tokens_details.cache_write_tokens").Exists()) {
		uncachedInput -= cacheWrite
	}

	u := NormalizedUsage{
		UncachedInputTokens: maxInt64(0, uncachedInput),
		OutputTokens:        maxInt64(0, output),
		ReasoningTokens:     maxInt64(0, reasoning),
		CacheReadTokens:     maxInt64(0, cacheRead),
		CacheWriteTokens:    maxInt64(0, cacheWrite),
		TotalTokens:         maxInt64(0, total),
		HasUsage:            hasInput || hasOutput || cacheRead > 0 || cacheWrite > 0 || hasTotal,
	}
	u.Invalid = invalid
	u.inputPresent, u.inputInclusive, u.inputTotal, u.inputSource = hasInput, true, maxInt64(0, rawInput), "openai"
	u.cacheReadPresent, u.cacheWritePresent = hasCacheRead, hasCacheWrite
	u.cacheWriteInclusive = node.Get("prompt_tokens_details.cache_write_tokens").Exists() || node.Get("input_tokens_details.cache_write_tokens").Exists()
	u.RecomputeTotal()
	return u
}

// parseGeminiUsageNode parses Gemini `usageMetadata`.
// In Gemini, `promptTokenCount` includes `cachedContentTokenCount`, and `thoughtsTokenCount`
// is billed as output alongside `candidatesTokenCount`.
func parseGeminiUsageNode(node gjson.Result) NormalizedUsage {
	invalid := false
	token := func(n gjson.Result) int64 { return strictTokenInteger(n, &invalid) }
	promptTokens := token(node.Get("promptTokenCount"))
	toolPromptTokens := token(node.Get("toolUsePromptTokenCount"))
	rawInput, inputValid := checkedTokenSum(maxInt64(0, promptTokens), maxInt64(0, toolPromptTokens))
	if !inputValid {
		return NormalizedUsage{HasUsage: true, Invalid: true}
	}

	candidatesTokens := token(node.Get("candidatesTokenCount"))
	thoughtsTokens := token(node.Get("thoughtsTokenCount"))
	cachedTokens := token(node.Get("cachedContentTokenCount"))
	totalTokens := token(node.Get("totalTokenCount"))

	uncachedInput := rawInput
	if cachedTokens > 0 && rawInput >= cachedTokens {
		uncachedInput = rawInput - cachedTokens
	}

	outputTokens, outputValid := checkedTokenSum(maxInt64(0, candidatesTokens), maxInt64(0, thoughtsTokens))
	if !outputValid {
		return NormalizedUsage{HasUsage: true, Invalid: true}
	}

	hasAny := node.Get("promptTokenCount").Exists() ||
		node.Get("candidatesTokenCount").Exists() ||
		node.Get("totalTokenCount").Exists() ||
		node.Get("cachedContentTokenCount").Exists()

	u := NormalizedUsage{
		UncachedInputTokens: maxInt64(0, uncachedInput),
		OutputTokens:        maxInt64(0, outputTokens),
		ReasoningTokens:     maxInt64(0, thoughtsTokens),
		CacheReadTokens:     maxInt64(0, cachedTokens),
		CacheWriteTokens:    0,
		TotalTokens:         maxInt64(0, totalTokens),
		HasUsage:            hasAny,
	}
	u.Invalid = invalid
	u.inputPresent, u.inputInclusive, u.inputTotal, u.inputSource = node.Get("promptTokenCount").Exists() || node.Get("toolUsePromptTokenCount").Exists(), true, rawInput, "gemini"
	u.cacheReadPresent = node.Get("cachedContentTokenCount").Exists()
	u.RecomputeTotal()
	return u
}

// NormalizeFromHostDetail converts CLIProxyAPI's `pluginapi.UsageDetail` (from `usage.handle`)
// into orthogonal `NormalizedUsage`.
func NormalizeFromHostDetail(provider string, d pluginapi.UsageDetail) NormalizedUsage {
	cacheRead := d.CacheReadTokens
	if cacheRead == 0 && d.CachedTokens > 0 && d.CacheCreationTokens == 0 {
		cacheRead = d.CachedTokens
	}
	cacheWrite := d.CacheCreationTokens

	uncachedInput := d.InputTokens
	provLower := strings.ToLower(strings.TrimSpace(provider))
	// In CPA's Detail, Claude's InputTokens is already uncached; for OpenAI/Gemini/Codex, InputTokens includes cacheRead
	if provLower != "claude" && provLower != "anthropic" {
		if cacheRead > 0 && uncachedInput >= cacheRead {
			uncachedInput -= cacheRead
		}
	}

	u := NormalizedUsage{
		UncachedInputTokens: maxInt64(0, uncachedInput),
		OutputTokens:        maxInt64(0, d.OutputTokens),
		ReasoningTokens:     maxInt64(0, d.ReasoningTokens),
		CacheReadTokens:     maxInt64(0, cacheRead),
		CacheWriteTokens:    maxInt64(0, cacheWrite),
		TotalTokens:         maxInt64(0, d.TotalTokens),
	}
	u.inputPresent, u.inputTotal, u.inputSource = d.InputTokens > 0, maxInt64(0, d.InputTokens), "host:"+provLower
	u.inputInclusive = provLower != "claude" && provLower != "anthropic"
	u.cacheReadPresent, u.cacheWritePresent = cacheRead > 0, cacheWrite > 0
	u.RecomputeTotal()
	return u
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
