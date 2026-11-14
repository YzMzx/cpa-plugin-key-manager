package contentguard

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func testRule() Rule {
	return Rule{ID: "r1", Name: "test", Enabled: true, Kind: KindKeyword, Patterns: []string{"bad word"}, Action: ActionBlock, Severity: SeverityHigh, KeyMode: KeyModeAll}
}
func TestMatchNormalizationSnippetAndDecision(t *testing.T) {
	r := testRule()
	e, err := NewEngine([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	text := "前缀 ＢＡＤ\u200b  WORD 后缀"
	hits, err := e.ScanChecked(context.Background(), []Segment{{Role: RoleUser, Text: text}}, "", 8)
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}
	h := hits[0]
	if h.Snippet[h.Offset:h.Offset+len(h.Matched)] != h.Matched || !strings.Contains(h.Matched, "ＢＡＤ") || !utf8.ValidString(h.Snippet) {
		t.Fatalf("bad span: %+v", h)
	}
	if blocked, sev := Decide(ModeEnforce, hits); !blocked || sev != SeverityHigh {
		t.Fatal("decision")
	}
	if blocked, _ := Decide(ModeObserve, hits); blocked {
		t.Fatal("observe blocks")
	}
}
func TestMatcherScopeImmutabilityAndCaps(t *testing.T) {
	fp := strings.Repeat("a", 64)
	r := testRule()
	r.KeyMode = KeyModeInclude
	r.KeyFingerprints = []string{fp}
	r.Roles = []string{RoleUser}
	e, err := NewEngine([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	r.Roles[0] = RoleTool
	r.Patterns[0] = "different"
	segments := []Segment{{Role: RoleTool, Text: "bad word"}, {Role: RoleUser, Text: "bad word"}, {Role: RoleUser, Text: "bad word"}, {Role: RoleUser, Text: "bad word"}, {Role: RoleUser, Text: "bad word"}}
	if got := e.Scan(segments, fp, -100); len(got) != 3 || got[0].Snippet != "bad word" {
		t.Fatalf("caps %+v", got)
	}
	if got := e.Scan(segments, "", 99999999); len(got) != 0 {
		t.Fatal("key scope")
	}
	r = testRule()
	r.Kind = KindRegex
	r.Patterns = []string{"BAD\\s+WORD"}
	e, err = NewEngine([]Rule{r})
	if err != nil || len(e.Scan(segments, "", 0)) == 0 {
		t.Fatal("regex failed", err)
	}
}
func TestMatcherCancellationAndBudgets(t *testing.T) {
	e, _ := NewEngine([]Rule{testRule()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.ScanChecked(ctx, []Segment{{Text: "bad word"}}, "", 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, segments := range [][]Segment{make([]Segment, MaxSegments+1), {{Text: strings.Repeat("x", MaxSegmentScanBytes+1)}}} {
		if _, err := e.ScanChecked(context.Background(), segments, "", 0); !errors.Is(err, ErrScanBudget) {
			t.Fatal(err)
		}
	}
	r := testRule()
	r.Patterns = []string{strings.Repeat("x", 1000)}
	e, err := NewEngine([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ScanChecked(context.Background(), []Segment{{Text: strings.Repeat("y", MaxSegmentScanBytes)}}, "", 0); !errors.Is(err, ErrScanBudget) {
		t.Fatal("missing work bound", err)
	}
}
func TestRulesValidationBudgets(t *testing.T) {
	original := testRule()
	copy := original
	copy.Patterns = append([]string(nil), original.Patterns...)
	if _, err := ValidateRules([]Rule{original}); err != nil || !reflect.DeepEqual(original, copy) {
		t.Fatal("mutation", err)
	}
	cases := []Rule{testRule(), testRule(), testRule(), testRule(), testRule()}
	cases[0].Patterns = make([]string, MaxPatternsPerRule+1)
	cases[1].Patterns = []string{strings.Repeat(" ", MaxPatternBytes+1)}
	cases[2].Roles = make([]string, 5)
	cases[3].KeyFingerprints = make([]string, MaxKeyFingerprints+1)
	cases[4].Kind = KindRegex
	cases[4].Patterns = []string{"["}
	for _, r := range cases {
		if _, err := NewEngine([]Rule{r}); err == nil {
			t.Fatal("accepted invalid rule")
		}
	}
	if _, err := NewEngine(make([]Rule, MaxRules+1)); err == nil {
		t.Fatal("rule ceiling")
	}
}
func FuzzNormalizeSnippets(f *testing.F) {
	for _, s := range []string{"hello", "ＢＡＤ\u200b WORD", "你好世界", "   ", string([]byte{255})} {
		f.Add(s, 3)
	}
	f.Fuzz(func(t *testing.T, text string, contextBytes int) {
		if len(text) > 4096 {
			return
		}
		text = strings.ToValidUTF8(text, "")
		n := normalize(text)
		if len(n.origin) != len(n.text)+1 {
			t.Fatal("offset map")
		}
		s, off, m := makeSnippet(text, 0, len(text), contextBytes)
		if !utf8.ValidString(s) || !utf8.ValidString(m) || len(m) > maxMatchedBytes || len(s) > 1206 || off < 0 || off > len(s) {
			t.Fatal("snippet bounds")
		}
	})
}
