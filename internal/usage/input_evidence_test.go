package usage

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"testing"
)

func TestInputEvidenceSparseCacheAndHostArrivalOrders(t *testing.T) {
	initial := ExtractResponseUsage("openai", []byte(`{"usage":{"prompt_tokens":100}}`))
	cache := ExtractResponseUsage("openai", []byte(`{"usage":{"prompt_tokens_details":{"cached_tokens":60}}}`))
	host := NormalizeFromHostDetail("openai", pluginapi.UsageDetail{InputTokens: 100, CacheReadTokens: 60})
	for _, pair := range [][2]NormalizedUsage{{initial, cache}, {cache, initial}, {initial, host}, {host, initial}} {
		for _, u := range []NormalizedUsage{MergeUsage(pair[0], pair[1]), MergeMaxUsage(pair[0], pair[1])} {
			if u.UncachedInputTokens != 40 || u.CacheReadTokens != 60 || u.TotalTokens != 100 {
				t.Fatalf("lost sparse cache evidence: %+v", u)
			}
		}
	}
}
func TestIndependentCacheWriteIsNotSubtractedFromInclusiveInput(t *testing.T) {
	initial := ExtractResponseUsage("openai", []byte(`{"usage":{"prompt_tokens":100}}`))
	native := NormalizeFromHostDetail("claude", pluginapi.UsageDetail{InputTokens: 100, CacheCreationTokens: 30})
	for _, pair := range [][2]NormalizedUsage{{initial, native}, {native, initial}} {
		u := MergeMaxUsage(pair[0], pair[1])
		if u.UncachedInputTokens != 100 || u.TotalTokens != 130 {
			t.Fatalf("native input changed: %+v", u)
		}
	}
	for _, name := range []string{"cache_write_tokens", "cache_creation_tokens"} {
		var body string
		if name == "cache_write_tokens" {
			body = `{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cache_write_tokens":30}}}`
		} else {
			body = `{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cache_creation_tokens":30}}}`
		}
		detail := ExtractResponseUsage("openai", []byte(body))
		got := MergeMaxUsage(initial, detail)
		want := int64(130)
		if name == "cache_write_tokens" {
			want = 100
		}
		if got.TotalTokens != want {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}
func TestStrictTokenRangeEdgesAndInvalidDetailPresence(t *testing.T) {
	for _, body := range []string{
		`{"usage":{"prompt_tokens_details":{"cached_tokens":18446744073709551616}}}`,
		`{"usage":{"output_tokens_details":{"reasoning_tokens":9223372036854775808}}}`,
		`{"usageMetadata":{"thoughtsTokenCount":1e100}}`,
		`{"type":"message_delta","usage":{"thinking_tokens":1.5}}`,
	} {
		u := ExtractResponseUsage("", []byte(body))
		if !u.Invalid || !u.HasUsage {
			t.Fatalf("invalid details discarded: %+v", u)
		}
	}
	max := ExtractResponseUsage("", []byte(`{"usage":{"prompt_tokens":9223372036854775807}}`))
	if max.Invalid || max.UncachedInputTokens != 9223372036854775807 {
		t.Fatal("int64 maximum rejected")
	}
	neg := ExtractResponseUsage("", []byte(`{"usage":{"prompt_tokens":-18446744073709551616}}`))
	if neg.Invalid || neg.UncachedInputTokens != 0 {
		t.Fatal("negative clamp changed")
	}
}
