package contentguard

import (
	"math"
	"testing"
)

func TestSettingsDefaultsAndValidation(t *testing.T) {
	s := DefaultSettings()
	if s.Enabled || s.Classifier.Enabled || s.Validate() != nil {
		t.Fatal("unsafe defaults")
	}
	mutations := []func(*Settings){
		func(s *Settings) { s.Mode = "bad" }, func(s *Settings) { s.MaxScanBytes = MaxInputBytes + 1 }, func(s *Settings) { s.OversizePolicy = "bad" },
		func(s *Settings) { s.MaxEvidenceBytes = 0 }, func(s *Settings) { s.SnippetContext = 501 }, func(s *Settings) { s.RetentionDays = 0 },
		func(s *Settings) { s.MaxRecords = 50001 }, func(s *Settings) { s.MaxTotalBytes = 0 }, func(s *Settings) { s.AutoDisable.Threshold = 0 },
		func(s *Settings) { s.Classifier.ScoreThreshold = math.NaN() }, func(s *Settings) { s.Classifier.TimeoutMS = 0 }, func(s *Settings) { s.Classifier.APIKey = "bad\nkey" },
		func(s *Settings) { s.Classifier.URL = "https://u:p@example.invalid" }, func(s *Settings) { s.Classifier.URL = "https://example.invalid/?secret=key" }, func(s *Settings) { s.Classifier.Format = "bad" },
	}
	for _, mutate := range mutations {
		s = DefaultSettings()
		mutate(&s)
		if s.Validate() == nil {
			t.Fatal("invalid settings accepted", s)
		}
	}
	old := DefaultSettings()
	next := old
	next.RetentionDays--
	if !MayPrune(old, next) {
		t.Fatal("retention prune")
	}
	next = old
	next.MaxRecords--
	if !MayPrune(old, next) {
		t.Fatal("count prune")
	}
	next = old
	next.MaxTotalBytes--
	if !MayPrune(old, next) {
		t.Fatal("byte prune")
	}
	if MayPrune(old, old) {
		t.Fatal("unchanged prunes")
	}
	state := DefaultState()
	state.Rules = []Rule{testRule()}
	cloned := state.Clone()
	cloned.Rules[0].Patterns[0] = "changed"
	if state.Rules[0].Patterns[0] == "changed" {
		t.Fatal("clone shares slice")
	}
	if len(Limits()) == 0 {
		t.Fatal("limits")
	}
}
