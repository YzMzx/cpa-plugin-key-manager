package contentguard

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestExtractProtocolsAndRoles(t *testing.T) {
	cases := []struct {
		body string
		want map[string]string
	}{
		{`{"system":"sys","instructions":"dev","tools":[{"description":"tool definition"}],"messages":[{"role":"developer","content":"developer"},{"role":"user","content":"user"},{"role":"tool","content":"tool"},{"role":"assistant","content":"assistant"}]}`, map[string]string{"sys": RoleSystem, "dev": RoleSystem, "tool definition": RoleTool, "developer": RoleSystem, "user": RoleUser, "tool": RoleTool, "assistant": RoleAssistant}},
		{`{"input":[{"type":"function_call_output","output":"output"},{"type":"function_call","arguments":"arguments"},{"role":"user","content":[{"type":"input_text","text":"question"}]}]}`, map[string]string{"output": RoleTool, "arguments": RoleAssistant, "question": RoleUser}},
		{`{"systemInstruction":{"parts":[{"text":"sys"}]},"contents":[{"role":"model","parts":[{"text":"answer"}]},{"parts":[{"functionResponse":{"response":{"text":"result"}}},{"text":"question"}]}]}`, map[string]string{"sys": RoleSystem, "answer": RoleAssistant, "result": RoleTool, "question": RoleUser}},
		{`{"messages":[{"role":"system","content":[{"type":"thinking","text":"secret"}]}]}`, map[string]string{"secret": RoleSystem}},
		{`[{"role":"function","content":"legacy"}]`, map[string]string{"legacy": RoleTool}},
	}
	for _, tc := range cases {
		t.Run(tc.body[:min(25, len(tc.body))], func(t *testing.T) {
			got, ok := Extract([]byte(tc.body), 4096)
			if !ok {
				t.Fatal("parse failed")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("segments=%+v", got)
			}
			for _, s := range got {
				if tc.want[s.Text] != s.Role {
					t.Fatalf("unexpected segment %+v", s)
				}
			}
		})
	}
}

func TestExtractRejectsIncompleteAndOverBudget(t *testing.T) {
	bad := []string{
		`{"input":"bad","input":"good"}`,
		`{"input":"bad","\u0069nput":"good"}`,
		`{"messages":[{"role":"system","role":"user","content":"secret"}]}`,
		`{"input":"x"} null`,
		`{"input":"x"} trailing`,
		`{"input":"unfinished`,
		"plain text", "null", "true", "42", `"scalar"`,
		string([]byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'}),
		strings.Repeat("[", MaxJSONDepth+2) + "0" + strings.Repeat("]", MaxJSONDepth+2),
		"[" + strings.Repeat("0,", MaxJSONNodes) + "0]",
	}
	for _, body := range bad {
		if got, ok := Extract([]byte(body), MaxInputBytes); ok || len(got) != 0 {
			t.Fatalf("accepted %q", body[:min(80, len(body))])
		}
	}
	for _, budget := range []int{-1, 0, 5} {
		if got, ok := Extract([]byte(`{"input":"hello"}`), budget); ok || len(got) != 0 {
			t.Fatal("ignored byte budget")
		}
	}
	if _, ok := Extract(make([]byte, MaxInputBytes+1), MaxInputBytes+2); ok {
		t.Fatal("ignored hard ceiling")
	}
}

func TestExtractMediaSkippedWithoutFalseBase64Heuristic(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"ordinary"},{"type":"input_image","text":"hidden media","image_url":"secret"},{"type":"document","source":{"data":"payload"}},{"type":"text","text":"data:image/png;base64,abcd"}]}]}`
	got, ok := Extract([]byte(body), 4096)
	if !ok || len(got) != 1 || got[0].Text != "ordinary" {
		t.Fatalf("media leaked: %+v", got)
	}
	body = `{"input":"` + strings.Repeat("A", 2048) + `"}`
	got, ok = Extract([]byte(body), 4096)
	if !ok || len(got) != 1 {
		t.Fatal("ordinary long ASCII wrongly assumed base64")
	}
}

func TestExtractDeterministicAndSegmentBudget(t *testing.T) {
	body := []byte(`{"z":"last","a":"first"}`)
	for i := 0; i < 50; i++ {
		got, ok := Extract(body, 1024)
		if !ok || got[0].Text != "first" {
			t.Fatalf("nondeterministic: %+v", got)
		}
	}
	body = []byte("[" + strings.Repeat(`"x",`, MaxSegments) + `"x"]`)
	if got, ok := Extract(body, MaxInputBytes); ok || len(got) != 0 {
		t.Fatal("segment budget bypass")
	}
}

func FuzzExtractAndEvidence(f *testing.F) {
	for _, seed := range []string{`{"input":"你好"}`, `{"input":"a","input":"b"}`, `{"messages":[{"role":"system","content":"secret"}]}`, `{"input":[]}`, `{"system":"s","tools":[{"description":"t"}],"prompt":"p"}`, "[[]]", "{} null", string([]byte{255})} {
		f.Add([]byte(seed), uint16(1024), false)
	}
	f.Fuzz(func(t *testing.T, body []byte, budget uint16, include bool) {
		got, ok := Extract(body, int(budget))
		total := 0
		if !ok && len(got) != 0 {
			t.Fatal("partial extraction on invalid input")
		}
		for _, s := range got {
			total += len(s.Text)
			if !utf8.ValidString(s.Text) {
				t.Fatal("invalid UTF8")
			}
		}
		if total > int(budget) || len(got) > MaxSegments {
			t.Fatal("budget exceeded")
		}
		e := CaptureEvidence(body, include, int(budget))
		if e.Text != "" && (!json.Valid([]byte(e.Text)) || len(e.Text) > int(budget) || e.SHA256 != digest([]byte(e.Text))) {
			t.Fatal("invalid evidence")
		}
	})
}
