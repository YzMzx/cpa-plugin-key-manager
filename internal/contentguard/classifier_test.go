package contentguard

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func classifierSettings() ClassifierSettings {
	s := DefaultSettings().Classifier
	s.Enabled = true
	s.URL = "https://classifier.invalid/moderate"
	s.Format = FormatGeneric
	return s
}
func TestClassifierTextIncludesAllOverhead(t *testing.T) {
	segments := []Segment{{Role: RoleSystem, Text: strings.Repeat("你", 1000)}, {Role: RoleUser, Text: "next"}}
	for _, n := range []int{-1, 0, 1, 10, 500, 2000} {
		got := BuildClassifierText(segments, n)
		if utf8.RuneCountInString(got) > max(0, n) || !utf8.ValidString(got) {
			t.Fatalf("budget %d", n)
		}
	}
	got := BuildClassifierText([]Segment{{Role: strings.Repeat("x", 100000), Text: "hello"}}, 10)
	if len(got) > 10 {
		t.Fatal("unbounded role")
	}
}
func TestClassifierSchemaValidation(t *testing.T) {
	s := classifierSettings()
	for _, body := range []string{`{}`, `{"flagged":true,"score":2}`, `{"flagged":true,"score":-1}`, `{"flagged":true,"score":1e999}`, `{"flagged":true,"flagged":false}`, `{"flagged":true} {}`} {
		if _, err := parseClassifierResponse(s, []byte(body)); err == nil {
			t.Fatal("accepted", body)
		}
	}
	if got, err := parseClassifierResponse(s, []byte(`{"flagged":false,"score":0.9,"category":"test"}`)); err != nil || !got.Flagged {
		t.Fatal(got, err)
	}
	s.Format = FormatOpenAIModeration
	for _, body := range []string{`{"results":[{}]}`, `{"results":[]}`, `{"results":[{"flagged":false,"categories":{},"category_scores":{"bad":1.01}}]}`} {
		if _, err := parseClassifierResponse(s, []byte(body)); err == nil {
			t.Fatal("accepted OpenAI", body)
		}
	}
	got, err := parseClassifierResponse(s, []byte(`{"results":[{"flagged":false,"categories":{"a":false},"category_scores":{"a":0.8}}]}`))
	if err != nil || !got.Flagged || got.Category != "a" {
		t.Fatal(got, err)
	}
	if validScore(math.NaN()) || validScore(math.Inf(1)) {
		t.Fatal("nonfinite")
	}
}
func TestClassifierDisabledLimitsAndNoRedirect(t *testing.T) {
	calls := 0
	c := NewClassifier(1)
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("Authorization") != "Bearer credential" {
			t.Fatal("bearer missing")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.invalid/leak"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	s := classifierSettings()
	s.APIKey = "credential"
	s.Enabled = false
	if _, err := c.Classify(context.Background(), s, "hello"); ClassifierFailureCode(err) != "disabled" || calls != 0 {
		t.Fatal("disabled sends")
	}
	s.Enabled = true
	if _, err := c.Classify(context.Background(), s, strings.Repeat("x", s.MaxChars+1)); ClassifierFailureCode(err) != "input_too_large" || calls != 0 {
		t.Fatal("oversize sends")
	}
	_, err := c.Classify(context.Background(), s, "hello")
	if err == nil || calls != 1 || strings.Contains(err.Error(), "credential") {
		t.Fatal("redirect or error leak", err, calls)
	}
	s.URL = "https://example.invalid/?key=secret"
	if _, err = c.Classify(context.Background(), s, "hello"); ClassifierFailureCode(err) != "settings_invalid" || calls != 1 {
		t.Fatal("URL validation")
	}
}
func TestClassifierResponseAndConcurrencyCaps(t *testing.T) {
	c := NewClassifier(1)
	s := classifierSettings()
	c.slots <- struct{}{}
	if _, err := c.Classify(context.Background(), s, "x"); ClassifierFailureCode(err) != "busy" {
		t.Fatal(err)
	}
	<-c.slots
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1))), Header: http.Header{}, Request: req}, nil
	})
	if _, err := c.Classify(context.Background(), s, "x"); ClassifierFailureCode(err) != "response_too_large" {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Classify(ctx, s, "x"); ClassifierFailureCode(err) != "canceled" {
		t.Fatal(err)
	}
}
