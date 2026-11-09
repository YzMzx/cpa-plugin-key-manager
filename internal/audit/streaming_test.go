package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCaptureRawJSONFormatsWhitespaceWithoutChangingEscapesAndValues(t *testing.T) {
	raw := []byte(` {
  "api_key": "body-secret", "messages": [{"content":"\u4f60\u597d"}],
  "duplicate": 1, "duplicate": 2
} `)
	result := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
	if result.State != "stored_raw" || result.Truncated || result.Redacted || result.Body != string(FormatJSON(raw, MaxRequestBodyBytes)) {
		t.Fatalf("raw JSON changed: %s", result.State)
	}
	hash := sha256.Sum256([]byte(result.Body))
	if result.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("hash not saved formatted bytes")
	}
}

func TestCaptureRawJSONDenseAndDeepStructuresHaveNoAuditElementCap(t *testing.T) {
	for _, count := range []int{5000, 20000} {
		messages := make([]map[string]string, count)
		for i := range messages {
			messages[i] = map[string]string{"role": "user", "content": "plain text"}
		}
		raw, _ := json.Marshal(map[string]any{"messages": messages})
		result := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
		if result.State != "stored_raw" || result.Body != string(FormatJSON(raw, MaxRequestBodyBytes)) {
			t.Fatalf("dense %d omitted: %s", count, result.State)
		}
	}
	deep := []byte(`{"payload":` + strings.Repeat("[", 256) + "1" + strings.Repeat("]", 256) + `,"safe":"tail"}`)
	result := CaptureRawJSON(deep, "application/json", "", MaxRequestBodyBytes)
	if result.State != "stored_raw" || result.Body != string(FormatJSON(deep, MaxRequestBodyBytes)) {
		t.Fatalf("deep JSON changed: %s", result.State)
	}
}

func TestCaptureRawJSONTenMiBAndOnlyHardFormatLimits(t *testing.T) {
	raw := readableJSONBody(MaxRequestBodyBytes)
	result := CaptureRawJSON(raw, "application/json; charset=utf-8", "identity", MaxRequestBodyBytes)
	if result.State != "stored_raw" || result.Body != string(FormatJSON(raw, MaxRequestBodyBytes)) {
		t.Fatal("ten MiB raw body omitted")
	}
	for _, tc := range []struct {
		body                 []byte
		typ, encoding, state string
		limit                int
	}{
		{readableJSONBody(MaxRequestBodyBytes + 1), "application/json", "", "omitted_input_limit", MaxRequestBodyBytes},
		{[]byte(`{"safe":"body"}`), "application/json", "gzip", "omitted_encoding", MaxRequestBodyBytes},
		{[]byte("invalid"), "text/plain", "", "omitted_non_json", MaxRequestBodyBytes},
		{[]byte(`{"broken":`), "application/json", "", "omitted_invalid_json", MaxRequestBodyBytes},
		{[]byte("1"), "application/json", "", "omitted_non_container", MaxRequestBodyBytes},
		{raw, "application/json", "", "omitted_input_limit", 32768},
	} {
		got := CaptureRawJSON(tc.body, tc.typ, tc.encoding, tc.limit)
		if got.State != tc.state || got.Body != "" || got.SHA256 != "" {
			t.Fatalf("unsafe format behavior: %s want %s", got.State, tc.state)
		}
	}
}

func BenchmarkCaptureRawJSONTenMiB(b *testing.B) {
	raw := readableJSONBody(MaxRequestBodyBytes)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if result := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes); result.State != "stored_raw" {
			b.Fatal(result.State)
		}
	}
}
