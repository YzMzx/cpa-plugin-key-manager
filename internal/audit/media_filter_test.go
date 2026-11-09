package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func captureMedia(t *testing.T, raw []byte) BodyResult {
	t.Helper()
	r := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
	if r.State != "stored_raw_media_filtered" || r.Truncated || r.Redacted || !json.Valid([]byte(r.Body)) {
		t.Fatalf("invalid media capture: state=%s body=%s", r.State, r.Body)
	}
	sum := sha256.Sum256([]byte(r.Body))
	if r.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("hash does not describe saved media-filtered JSON")
	}
	return r
}

func TestMediaFilterOpenAIImagePreservesTextAndCutsPayload(t *testing.T) {
	payload := strings.Repeat("AAABBBccc111", 40000)
	raw, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "请解释图片，正文凭据 body-secret 保持明文"}, map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + payload, "detail": "auto"}}}}}})
	r := captureMedia(t, raw)
	if strings.Contains(r.Body, payload) || strings.Contains(r.Body, "data:image") || strings.Contains(r.Body, "https://private/REMOVE-IMAGE-URL") {
		t.Fatal("image locator or encoded payload retained")
	}
	if !strings.Contains(r.Body, "请解释图片") || !strings.Contains(r.Body, "body-secret") || !strings.Contains(r.Body, "[OMITTED:media]") {
		t.Fatal("normal request text not preserved")
	}
	if len(r.Body) >= len(raw)/10 {
		t.Fatal("media payload did not shrink")
	}
}

func TestMediaFilterProtocolShapesAndPreservedIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		secrets   []string
	}{
		{"anthropic", `{"messages":[{"content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"ANTHROPIC-ENCODED"}},{"type":"text","text":"keep text"}]}]}`, []string{"ANTHROPIC-ENCODED"}},
		{"anthropic-late-type", `{"content":[{"source":{"data":"SOURCE-PAYLOAD","url":"https://private/image.jpg"},"type":"image"}],"text":"keep text"}`, []string{"SOURCE-PAYLOAD", "https://private/image.jpg"}},
		{"gemini", `{"contents":[{"parts":[{"text":"keep text"},{"inlineData":{"mimeType":"image/png","data":"GEMINI-ENCODED"}},{"inline_data":{"mime_type":"audio/wav","data":"GEMINI-SNAKE"}}]}]}`, []string{"GEMINI-ENCODED", "GEMINI-SNAKE"}},
		{"openai-audio-file", `{"content":[{"type":"input_audio","input_audio":{"data":"AUDIO-PAYLOAD","format":"wav"}},{"type":"file","file":{"file_data":"FILE-PAYLOAD","file_id":"file-123","filename":"notes.txt"}}],"text":"keep text"}`, []string{"AUDIO-PAYLOAD", "FILE-PAYLOAD"}},
		{"flat-payloads", `{"base64":"B64-PAYLOAD","b64_json":"B64JSON-PAYLOAD","image_url":"https://private/file.png","audio_url":"https://private/file.wav","video":"https://private/video.mp4","fileData":"FILEDATA-PAYLOAD","text":"keep text"}`, []string{"B64-PAYLOAD", "B64JSON-PAYLOAD", "https://private/file.png", "https://private/file.wav", "https://private/video.mp4", "FILEDATA-PAYLOAD"}},
		{"gemini-file-uri", `{"contents":[{"parts":[{"fileData":{"mimeType":"application/pdf","fileUri":"https://private/document.pdf"}},{"text":"keep text"}]}]}`, []string{"https://private/document.pdf"}},
		{"escaped-data-uri", `{"custom":"\u0064ata:application/pdf;base64,PDF-PAYLOAD","text":"keep text"}`, []string{"PDF-PAYLOAD"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := captureMedia(t, []byte(tc.raw))
			for _, value := range tc.secrets {
				if strings.Contains(r.Body, value) {
					t.Fatalf("media retained: %s", value)
				}
			}
			if !strings.Contains(r.Body, "keep text") {
				t.Fatal("text lost")
			}
			if tc.name == "openai-audio-file" && (!strings.Contains(r.Body, "file-123") || !strings.Contains(r.Body, "notes.txt")) {
				t.Fatal("small file identity lost")
			}
		})
	}
}

func TestMediaFilterLeavesBusinessDataTokensOrderAndDuplicateKeys(t *testing.T) {
	raw := []byte(` {"z":90071992547409931234567890,"data":{"value":"business data","url":"https://normal/link"},"duplicate":1,"duplicate":2,"price":1.23000e+99,"escaped":"\u4f60\u597d","text":"https://normal/link?keep=yes","image_url":{"url":"https://private/REMOVE-IMAGE-URL"},"after":"unchanged body-secret"} `)
	r := captureMedia(t, raw)
	expected := bytes.Replace(raw, []byte(`{"url":"https://private/REMOVE-IMAGE-URL"}`), []byte(`"[OMITTED:media]"`), 1)
	var gotCompact, wantCompact bytes.Buffer
	_ = json.Compact(&gotCompact, []byte(r.Body))
	_ = json.Compact(&wantCompact, expected)
	if !bytes.Equal(gotCompact.Bytes(), wantCompact.Bytes()) {
		t.Fatalf("unrelated tokens changed: %s", r.Body)
	}
	plain := []byte(`{"data":{"records":[1,2,3]},"text":"https://normal/path","file_id":"file-123","count":1.000}`)
	result := CaptureRawJSON(plain, "application/json", "", MaxRequestBodyBytes)
	if result.State != "stored_raw" || result.Body != string(FormatJSON(plain, MaxRequestBodyBytes)) {
		t.Fatal("ordinary JSON mislabeled or changed")
	}
}

func TestMediaFilterHardFormatAndInputLimitsRemain(t *testing.T) {
	for _, tc := range []struct {
		raw                  []byte
		typ, encoding, state string
	}{
		{[]byte(`{"image_url":`), "application/json", "", "omitted_invalid_json"},
		{[]byte(`{"image_url":"base64"}`), "text/plain", "", "omitted_non_json"},
		{[]byte(`{"image_url":"base64"}`), "application/json", "gzip", "omitted_encoding"},
		{[]byte(`{"image_url":"` + strings.Repeat("x", MaxRequestBodyBytes) + `"}`), "application/json", "", "omitted_input_limit"},
	} {
		r := CaptureRawJSON(tc.raw, tc.typ, tc.encoding, MaxRequestBodyBytes)
		if r.State != tc.state || r.Body != "" || r.SHA256 != "" {
			t.Fatalf("format limit changed: %s want %s", r.State, tc.state)
		}
	}
}

func TestMediaFilterEscapedKeysDuplicateMediaAndNestedFileData(t *testing.T) {
	raw := []byte(`{"im\u0061ge_url":"https://private/escaped-image","duplicate":1,"duplicate":2,"image_url":"https://private/second-image","content":[{"type":"file","file":{"data":"FILE-NESTED-DATA","filename":"keep.txt","file_id":"file-keep"}}],"business":{"data":"keep business data"}}`)
	r := captureMedia(t, raw)
	for _, value := range []string{"ESCAPED-IMAGE", "SECOND-IMAGE", "FILE-NESTED-DATA"} {
		if strings.Contains(r.Body, value) {
			t.Fatalf("encoded media retained: %s", value)
		}
	}
	for _, value := range []string{`"duplicate": 1`, `"duplicate": 2`, "keep.txt", "file-keep", "keep business data", `"im\u0061ge_url"`} {
		if !strings.Contains(r.Body, value) {
			t.Fatalf("plain token changed: %s", value)
		}
	}
}

func TestMediaFilterDenseAndDeepJSONDoesNotOmitWholeRequest(t *testing.T) {
	raw := []byte(`{"nested":` + strings.Repeat("{\"wrapper\":", 512) + `{"image_url":"https://private/depth-image","text":"safe tail"}` + strings.Repeat("}", 512) + `,"text":"outer text"}`)
	r := captureMedia(t, raw)
	if strings.Contains(r.Body, "DEPTH-PAYLOAD") || !strings.Contains(r.Body, "safe tail") || !strings.Contains(r.Body, "outer text") {
		t.Fatal("deep media handling lost plain context")
	}
	many := []byte(`{"items":[` + strings.Repeat(`{"image_url":"https://private/dense-image","text":"safe"},`, 20000) + `{"text":"last"}]}`)
	dense := captureMedia(t, many)
	if strings.Contains(dense.Body, "https://private/dense-image") || strings.Count(dense.Body, `"text": "safe"`) != 20000 || !strings.Contains(dense.Body, "last") {
		t.Fatal("dense media filtering lost normal text")
	}
}

func FuzzFilterRequestMediaNeverCreatesInvalidJSON(f *testing.F) {
	for _, seed := range []string{`{"image_url":"https://private/image","text":"hello"}`, `{"type":"image","source":{"data":"base64","type":"base64"}}`, `["data:image/png;base64,aaa",{"data":"normal"}]`, `{"duplicate":1,"duplicate":2}`, `{"deep":[[[]]]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		result, filtered := FilterRequestMedia(raw)
		if !json.Valid(raw) {
			if filtered || !bytes.Equal(result, raw) {
				t.Fatal("invalid input changed")
			}
			return
		}
		if !json.Valid(result) {
			t.Fatal("filter created invalid JSON")
		}
		if !filtered && !bytes.Equal(result, raw) {
			t.Fatal("unfiltered lexical bytes changed")
		}
	})
}

func BenchmarkFilterRequestMediaLargeImage(b *testing.B) {
	payload := strings.Repeat("AbCdEf0123456789", 500000)
	raw := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"keep text"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + payload + `"}}]}]}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes); r.State != "stored_raw_media_filtered" {
			b.Fatal(r.State)
		}
	}
}

func TestMediaFilterDoesNotDeleteOrdinaryMediaNamedTextOrToolSchemas(t *testing.T) {
	raw := []byte(`{"image":"请描述封面文字","audio":"voice instructions","video":"not a file","image_url":"用户字段名，不是地址","data":{"value":"business text"},"tools":[{"type":"function","function":{"name":"describe","parameters":{"type":"object","properties":{"image":{"type":"string","description":"用户输入封面描述"},"audio":{"type":"string","description":"音频说明文本"},"video":{"type":"string","description":"视频标题"},"base64":{"type":"string","description":"格式定义，不是内容"},"inlineData":{"type":"object","properties":{"data":{"type":"string"}}}}}}}]}`)
	got := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
	if got.State != "stored_raw" || got.Body != string(FormatJSON(raw, MaxRequestBodyBytes)) {
		t.Fatalf("ordinary text or schema removed: %s", got.Body)
	}
	mixed := []byte(`{"image":"plain descriptive text","audio":"read aloud","video":"title","image_url":{"url":"https://private/picture.png"},"tools":[{"function":{"parameters":{"properties":{"image":{"type":"string","description":"keep schema"}}}}}]}`)
	filtered := captureMedia(t, mixed)
	for _, text := range []string{"plain descriptive text", "read aloud", "title", "keep schema", `"type": "string"`} {
		if !strings.Contains(filtered.Body, text) {
			t.Fatalf("normal media-named text lost: %s", text)
		}
	}
	if strings.Contains(filtered.Body, "https://private/picture.png") {
		t.Fatal("actual file location retained")
	}
}
