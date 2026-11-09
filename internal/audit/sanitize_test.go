package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeNestedJSONAndInlineSecrets(t *testing.T) {
	raw := []byte(`{"model":"测试模型","messages":[{"role":"user","content":"你好，Bearer token-123 and sk-secretABC mail 用户@example.com call +1 555-123-4567 actual-key-XYZ"}],"nested":{"api_key":"private-key","Password":"private-pass","authorization":"private-auth","accessToken":"private-token","cookie":"private-cookie","email":"x@example.com","phone":"1234567890"},"link":"https://user:pass@example.com/path?api_key=url-secret&other=value#private-fragment","relative":"/path?token=query-secret&ok=1","image_url":{"url":"data:image/png;base64,private-image"},"headers":{"X-Custom":"private-header"}}`)
	result := SanitizeBody(raw, "application/json; charset=utf-8", "", 32768, "actual-key-XYZ")
	if result.State != "stored" || !result.Redacted || result.Truncated {
		t.Fatalf("result=%+v", result)
	}
	if !json.Valid([]byte(result.Body)) || !strings.Contains(result.Body, "你好") || !strings.Contains(result.Body, "测试模型") {
		t.Fatal("unicode/JSON not retained")
	}
	for _, secret := range []string{"token-123", "sk-secretABC", "用户@example.com", "555-123", "actual-key-XYZ", "private-key", "private-pass", "private-auth", "private-token", "private-cookie", "x@example.com", "1234567890", "url-secret", "private-fragment", "query-secret", "private-image", "private-header", "user:pass"} {
		if strings.Contains(result.Body, secret) {
			t.Fatalf("leaked %q in %s", secret, result.Body)
		}
	}
	sum := sha256.Sum256([]byte(result.Body))
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("digest is not sanitized bytes")
	}
	rawSum := sha256.Sum256(raw)
	if result.SHA256 == hex.EncodeToString(rawSum[:]) {
		t.Fatal("raw hash retained")
	}
}

func TestSanitizeUnicodeEscapesKeysAndReadableControlEscapes(t *testing.T) {
	result := SanitizeBody([]byte(`{"\u0061pi_key":"do-not-keep","message":"中文\nsecond\tline\u0000<unsafe>","secret-in-key":"ok"}`), "application/problem+json", "identity", 32768, "secret-in-key")
	if result.State != "stored" || strings.Contains(result.Body, "do-not-keep") || strings.Contains(result.Body, "secret-in-key") {
		t.Fatalf("unsafe %v", result)
	}
	if strings.ContainsAny(result.Body, "\n\r\x00") {
		t.Fatal("literal control chars in stored JSON")
	}
	if !strings.Contains(result.Body, `\n`) || !strings.Contains(result.Body, `\t`) || !strings.Contains(result.Body, `\u0000`) {
		t.Fatalf("readable escapes lost: %s", result.Body)
	}
}

func TestSanitizeOmissionNeverKeepsPartialRawOrRawDigest(t *testing.T) {
	cases := []struct {
		name                 string
		body                 []byte
		typ, encoding, state string
		max                  int
	}{
		{"invalid", []byte(`{"content":"private-prefix",`), "application/json", "", "omitted_invalid_json", 32768},
		{"trailing", []byte(`{"ok":1} {"secret":"private"}`), "application/json", "", "omitted_invalid_json", 32768},
		{"non-json", []byte("private-prefix"), "text/plain", "", "omitted_non_json", 32768},
		{"binary", []byte{0, 1, 0xff, 0x80}, "application/octet-stream", "", "omitted_non_json", 32768},
		{"invalid-utf8", []byte{'{', '"', 'a', '"', ':', '"', 255, '"', '}'}, "application/json", "", "omitted_invalid_json", 32768},
		{"compressed", []byte(`{"private":"secret"}`), "application/json", "gzip", "omitted_encoding", 32768},
		{"base64", []byte("eyJhcGlfa2V5Ijoic2VjcmV0In0="), "application/json", "base64", "omitted_encoding", 32768},
		{"base64-raw", []byte("eyJhcGlfa2V5Ijoic2VjcmV0In0="), "application/json", "", "omitted_invalid_json", 32768},
		{"json-scalar", []byte(`"secret"`), "application/json", "", "omitted_non_container", 32768},
		{"disabled", []byte(`{"ok":1}`), "application/json", "", "omitted_disabled", 0},
		{"tiny-output", []byte(`{"content":"private-prefix"}`), "application/json", "", "omitted_output_limit", 8},
		{"duplicate", []byte(`{"a":1,"a":2}`), "application/json", "", "omitted_ambiguous_json", 32768},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeBody(tc.body, tc.typ, tc.encoding, tc.max)
			if got.State != tc.state || got.Body != "" || got.SHA256 != "" {
				t.Fatalf("unsafe omit %+v", got)
			}
		})
	}
}

func TestSanitizeHardLimits(t *testing.T) {
	longString, _ := json.Marshal(map[string]string{"message": strings.Repeat("x", auditBodyStringLimit+1)})
	lots := `{"list":[` + strings.Repeat("1,", auditBodyElementLimit) + "1]}"
	depth := strings.Repeat("[", auditBodyDepthLimit+2) + "0" + strings.Repeat("]", auditBodyDepthLimit+2)
	wide := map[string]string{}
	for i := 0; i < 20; i++ {
		wide[strings.Repeat("k", i+1)] = strings.Repeat("x ", 1000)
	}
	output, _ := json.Marshal(wide)
	for _, tc := range []struct {
		raw   []byte
		state string
		limit int
	}{{longString, "omitted_input_limit", MaxRequestBodyBytes}, {[]byte(lots), "omitted_element_limit", MaxRequestBodyBytes}, {[]byte(depth), "omitted_depth_limit", MaxRequestBodyBytes}, {[]byte(strings.Repeat(" ", auditBodyInputLimit+1)), "omitted_input_limit", MaxRequestBodyBytes}, {output, "omitted_output_limit", 32768}} {
		got := SanitizeBody(tc.raw, "application/json", "", tc.limit)
		if got.State != tc.state || !got.Truncated || got.Body != "" || got.SHA256 != "" {
			t.Fatalf("unsafe limit %+v", got)
		}
	}
	if got := SanitizeBody(nil, "application/json", "", 1); got.State != "empty" || got.SHA256 != "" {
		t.Fatal(got)
	}
}

func TestSanitizeBase64AndMediaAreNotDecoded(t *testing.T) {
	encoded := strings.Repeat("c2VjcmV0", 20)
	raw, _ := json.Marshal(map[string]any{"opaque": encoded, "data": "tiny-secret", "audio": []any{"audio-secret"}, "image_url": "https://host/image?token=image-secret", "safe": "normal text"})
	got := SanitizeBody(raw, "application/json", "", 32768)
	if got.State != "stored" || !got.Redacted {
		t.Fatal(got)
	}
	for _, bad := range []string{encoded, "tiny-secret", "audio-secret", "image-secret"} {
		if strings.Contains(got.Body, bad) {
			t.Fatalf("opaque leak %q", bad)
		}
	}
	if !strings.Contains(got.Body, "normal text") {
		t.Fatal("safe content omitted")
	}
}

func TestSanitizeActualSecretAcrossEscapesAndLongTail(t *testing.T) {
	got := SanitizeBody([]byte(`{"message":"prefix a\u0062c-secret suffix","token":"raw-token"}`), "application/json", "", 32768, "abc-secret")
	if got.State != "stored" || strings.Contains(got.Body, "abc-secret") || strings.Contains(got.Body, "raw-token") {
		t.Fatal(got)
	}
}

func TestSanitizeTextSafeMetadataAndLimits(t *testing.T) {
	got := SanitizeText("模型 <tag>\nBearer hidden-token user@example.com /path?unusual=private-value#fragment actual-secret", 1024, "actual-secret")
	for _, bad := range []string{"hidden-token", "user@example.com", "private-value", "fragment", "actual-secret", "<tag>", "\n"} {
		if strings.Contains(got, bad) {
			t.Fatalf("unsafe metadata %q", got)
		}
	}
	if !strings.Contains(got, "模型") || !strings.Contains(got, `\n`) {
		t.Fatalf("readable metadata lost %q", got)
	}
	for _, limit := range []int{0, 1, 8, 32} {
		got := SanitizeText(strings.Repeat("x", auditMetadataLimit+1), limit)
		if len(got) > limit || strings.Contains(got, "xxxx") {
			t.Fatal("unsafe truncated metadata")
		}
	}
}

func TestSanitizeInlineJSONLabelAndNumericSecret(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"message": `nested {"api_key":"super-private"} https://host/path?unusual=hidden-value`, "count": 123456})
	got := SanitizeBody(raw, "application/json", "", 32768, "123456")
	if got.State != "stored" {
		t.Fatal(got)
	}
	for _, bad := range []string{"super-private", "hidden-value", "123456"} {
		if strings.Contains(got.Body, bad) {
			t.Fatalf("leaked inline or numeric secret %s", got.Body)
		}
	}
}

func TestSanitizeEmptySecretsAndMarkerCollisionFailClosed(t *testing.T) {
	if got := SanitizeText("safe text", 100, ""); got != "safe text" {
		t.Fatalf("empty secret changed metadata: %q", got)
	}
	got := SanitizeBody([]byte(`{"message":"Bearer private-token"}`), "application/json", "", 32768, "REDACTED")
	if got.State != "omitted_secret_collision" || got.Body != "" || got.SHA256 != "" {
		t.Fatal("placeholder retained a known secret", got)
	}
}

func FuzzSanitizeNeverKeepsUnsafePartialBody(f *testing.F) {
	f.Add([]byte(`{"message":"hello","api_key":"private"}`))
	f.Add([]byte{0, 1, 255})
	f.Fuzz(func(t *testing.T, body []byte) {
		got := SanitizeBody(body, "application/json", "", 32768, "private-active-key")
		if got.State == "stored" {
			if len(got.Body) > 32768 || !json.Valid([]byte(got.Body)) || strings.Contains(got.Body, "private-active-key") {
				t.Fatalf("unsafe stored body %+v", got)
			}
			sum := sha256.Sum256([]byte(got.Body))
			if got.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("bad sanitized hash")
			}
		} else if got.Body != "" || got.SHA256 != "" {
			t.Fatalf("unsafe omitted body %+v", got)
		}
	})
}

func TestSanitizeEmbeddedOpaqueAndStaticReplacementCollision(t *testing.T) {
	opaque := strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ", 5)
	raw, _ := json.Marshal(map[string]string{"message": "prefix " + opaque + " suffix"})
	got := SanitizeBody(raw, "application/json", "", 32768)
	if got.State != "stored" || strings.Contains(got.Body, opaque) {
		t.Fatal(got)
	}
	got = SanitizeBody([]byte(`{"password":"value"}`), "application/json", "", 32768, "REDACTED")
	if got.Body != "" || got.SHA256 != "" || got.State != "omitted_secret_collision" {
		t.Fatal("fixed marker contained known secret", got)
	}
}

func TestSanitizeCommonNestedSecretKeyNames(t *testing.T) {
	raw := []byte(`{"messages":[{"content":"safe"}],"nested":{"secret_key":"opaque-pass-ABC","aws_secret_access_key":"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD","signing_key":"sign-value","encryption_key":"enc-value","aws_access_key_id":"access-value"}}`)
	result := SanitizeBody(raw, "application/json", "", 32768)
	if result.State != "stored" {
		t.Fatalf("not stored: %s", result.State)
	}
	for _, secret := range []string{"opaque-pass-ABC", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD", "sign-value", "enc-value", "access-value"} {
		if strings.Contains(result.Body, secret) {
			t.Fatalf("secret field not redacted: %s", secret)
		}
	}
}

func TestSanitizeInlineBasicAuthorization(t *testing.T) {
	raw := []byte(`{"messages":[{"content":"Authorization: Basic dXNlcjpwYXNz"}],"other":"Basic YWJjOmRlZg=="}`)
	result := SanitizeBody(raw, "application/json", "", 32768)
	if result.State != "stored" || strings.Contains(result.Body, "dXNlcjpwYXNz") || strings.Contains(result.Body, "YWJjOmRlZg==") {
		t.Fatalf("inline authorization leaked: %s", result.Body)
	}
}
