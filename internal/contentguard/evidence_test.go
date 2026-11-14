package contentguard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidencePrivacyIntegrityAndHashes(t *testing.T) {
	body := []byte(`{"system":"hidden-system","instructions":"hidden-instructions","systemInstruction":{"parts":[{"text":"hidden-gemini"}]},"tools":[{"description":"hidden-tools"}],"messages":[{"role":"developer","content":"hidden-developer"},{"role":"tool","content":"hidden-tool"},{"role":"user","content":[{"type":"text","text":"visible"},{"type":"image","text":"hidden-image","source":{"data":"hidden-payload"}},{"type":"tool_result","content":"hidden-result"}]}]}`)
	e := CaptureEvidence(body, false, 4096)
	if !json.Valid([]byte(e.Text)) || strings.Contains(e.Text, "hidden") || !strings.Contains(e.Text, "visible") || e.SHA256 != digest([]byte(e.Text)) || e.OriginalSHA256 != digest(body) || e.SHA256 == e.OriginalSHA256 {
		t.Fatalf("evidence %+v", e)
	}
	all := CaptureEvidence(body, true, 4096)
	if !strings.Contains(all.Text, "hidden-system") || strings.Contains(all.Text, "hidden-payload") || strings.Contains(all.Text, "hidden-image") {
		t.Fatalf("include semantics %+v", all)
	}
	text, state, truncated, sha := Evidence(body, false, 4096)
	if text != e.Text || state != e.State || truncated != e.Truncated || sha != e.SHA256 {
		t.Fatal("wrapper")
	}
}
func TestEvidenceOmissionNeverStoresRawPrefix(t *testing.T) {
	for _, body := range [][]byte{[]byte("raw secret"), []byte(`{"input":"secret"`), []byte(`{"x":1,"x":2}`), {0x1f, 0x8b, 1, 2}, []byte("null")} {
		e := CaptureEvidence(body, true, 1024)
		if e.Text != "" || e.SHA256 != "" || e.OriginalSHA256 != "" {
			t.Fatalf("invalid evidence %+v", e)
		}
	}
	huge := make([]byte, MaxInputBytes+1)
	e := CaptureEvidence(huge, true, 1024)
	if e.State != "omitted_oversize" || e.OriginalSHA256 != "" {
		t.Fatal("oversize hash")
	}
	e = CaptureEvidence([]byte(`{"prompt":"`+strings.Repeat("secret", 200)+`"}`), true, 20)
	if e.Text != "" || !e.Truncated || e.State != "omitted_output_budget" || e.SHA256 != "" || e.OriginalSHA256 == "" {
		t.Fatal("output omission", e)
	}
	for _, budget := range []int{-1, 0, (1 << 20) + 1} {
		e = CaptureEvidence([]byte("{}"), true, budget)
		if e.Text != "" {
			t.Fatal("bad budget")
		}
	}
}
func TestEvidenceMatchesPrivacy(t *testing.T) {
	in := []Match{{Role: RoleSystem, Snippet: "secret", Matched: "secret", Path: "secret"}, {Role: RoleTool, Snippet: "secret"}, {Role: RoleUser, Snippet: "visible"}, {Source: "classifier", Role: RoleUser, Snippet: "secret", Category: "secret"}}
	out := FilterEvidenceMatches(in, true, false)
	if out[0].Snippet != "" || out[0].Path != "" || out[1].Snippet != "" || out[2].Snippet != "visible" || out[3].Category != "" || in[0].Snippet != "secret" {
		t.Fatal("privacy filter", out)
	}
	for _, m := range FilterEvidenceMatches(in, false, true) {
		if m.Snippet != "" || m.Matched != "" {
			t.Fatal("capture disabled")
		}
	}
}
