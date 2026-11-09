package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Keep this fixture readable rather than an opaque ASCII/Base64-like blob.
func readableJSONBody(size int) []byte {
	const prefix = `{"messages":[{"role":"user","content":"`
	const suffix = `"}]}`
	remaining := size - len(prefix) - len(suffix)
	const phrase = "测试文本 "
	return []byte(prefix + strings.Repeat(phrase, remaining/len(phrase)) + strings.Repeat(" ", remaining%len(phrase)) + suffix)
}

func TestSanitizeTenMiBBodyAndLongMessage(t *testing.T) {
	raw := readableJSONBody(MaxRequestBodyBytes)
	if len(raw) != MaxRequestBodyBytes {
		t.Fatal("wrong boundary fixture size")
	}
	result := SanitizeBody(raw, "application/json", "", DefaultMaxBodyBytes)
	if result.State != "stored" || result.Truncated || len(result.Body) != MaxRequestBodyBytes {
		t.Fatalf("ten MiB not retained: state=%s size=%d", result.State, len(result.Body))
	}
	if !json.Valid([]byte(result.Body)) || !strings.Contains(result.Body, "测试文本") {
		t.Fatal("readable JSON lost")
	}
	sum := sha256.Sum256([]byte(result.Body))
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong sanitized hash")
	}
}

func TestSanitizeLargeBodyStillRedactsSecretsAndHonorsSmallerLimit(t *testing.T) {
	value := strings.Repeat("普通长提示词 ", 20000) + " private-active-key Bearer private-token secret@example.com"
	raw, _ := json.Marshal(map[string]any{"messages": []any{map[string]string{"role": "user", "content": value}}, "secret_key": "do-not-save"})
	if len(raw) <= 256*1024 {
		t.Fatal("fixture must exceed previous input cap")
	}
	result := SanitizeBody(raw, "application/json", "", MaxRequestBodyBytes, "private-active-key")
	if result.State != "stored" {
		t.Fatalf("large body omitted: %s", result.State)
	}
	for _, secret := range []string{"private-active-key", "private-token", "secret@example.com", "do-not-save"} {
		if strings.Contains(result.Body, secret) {
			t.Fatal("large body bypassed redaction")
		}
	}
	smaller := SanitizeBody(raw, "application/json", "", 32768, "private-active-key")
	if smaller.State != "omitted_output_limit" || smaller.Body != "" || smaller.SHA256 != "" {
		t.Fatal("smaller explicit cap ignored")
	}
	oversized := SanitizeBody(readableJSONBody(MaxRequestBodyBytes+1), "application/json", "", MaxRequestBodyBytes)
	if oversized.State != "omitted_input_limit" || oversized.Body != "" || oversized.SHA256 != "" {
		t.Fatal("input hard cap ignored")
	}
	expanded := []byte(`{"message":"` + strings.Repeat("< ", MaxRequestBodyBytes/4) + `"}`)
	escaped := SanitizeBody(expanded, "application/json", "", MaxRequestBodyBytes)
	if escaped.State != "omitted_output_limit" || escaped.Body != "" || escaped.SHA256 != "" {
		t.Fatal("escaped JSON exceeded retention cap")
	}
}

func TestLargeBodyDoesNotRaiseMetadataOrCredentialLimits(t *testing.T) {
	longKey, _ := json.Marshal(map[string]string{strings.Repeat("k", auditBodyKeyLimit+1): "safe"})
	if result := SanitizeBody(longKey, "application/json", "", MaxRequestBodyBytes); result.State != "omitted_string_limit" {
		t.Fatal("key cap widened with value cap")
	}
	if got := SanitizeText(strings.Repeat("text ", 1000), 160); got != "[OMITTED:limit]" {
		t.Fatal("metadata cap widened")
	}
	if result := SanitizeBody([]byte(`{"message":"safe"}`), "application/json", "", MaxRequestBodyBytes, strings.Repeat("x", auditSecretLimit+1)); result.State != "omitted_secret_limit" {
		t.Fatal("credential safety cap widened")
	}
}

func BenchmarkSanitizeLargeBody(b *testing.B) {
	for _, size := range []int{1 << 20, MaxRequestBodyBytes} {
		name := "1MiB"
		if size == MaxRequestBodyBytes {
			name = "10MiB"
		}
		b.Run(name, func(b *testing.B) {
			raw := readableJSONBody(size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if r := SanitizeBody(raw, "application/json", "", MaxRequestBodyBytes); r.State != "stored" {
					b.Fatal(r.State)
				}
			}
		})
	}
}
