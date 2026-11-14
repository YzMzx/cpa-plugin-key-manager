package plugin

import (
	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContentGuardRegressionOldWindowAfterReenable(t *testing.T) {
	m := guardFixture(t)
	r := configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 2
	})
	fp := keyFingerprint("guard-client-key")
	m.recordDisableHit(r, "guard-client-key", fp, "old-execution")
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":false}`)); e != nil {
		t.Fatal(e)
	}
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":true}`)); e != nil {
		t.Fatal(e)
	}
	m.recordDisableHit(r, "guard-client-key", fp, "new-execution")
	reviewAssertEnabled(t, m)
}
func TestContentGuardRegressionDuplicateAfterReenable(t *testing.T) {
	m := guardFixture(t)
	r := configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 1
	})
	fp := keyFingerprint("guard-client-key")
	m.recordDisableHit(r, "guard-client-key", fp, "same-execution")
	guardAwait(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		k, _ := m.cfg.ResolveKeyRule("guard-client-key")
		return !k.IsEnabled()
	})
	guardAwait(t, func() bool { m.disableMu.Lock(); defer m.disableMu.Unlock(); return len(m.disablePending) == 0 })
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":true}`)); e != nil {
		t.Fatal(e)
	}
	m.recordDisableHit(r, "guard-client-key", fp, "same-execution")
	reviewAssertEnabled(t, m)
}
func TestContentGuardRegressionSameSecondTask(t *testing.T) {
	m := guardFixture(t)
	r := configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 1
	})
	// Set a timestamp matching the next edit's native second precision.
	stamp := time.Now().UTC().Format(time.RFC3339)
	if e := m.mutateRules(ruleMutation{}, func(s *DynamicRulesState) error {
		for i := range s.Keys {
			if s.Keys[i].APIKey == "guard-client-key" {
				s.Keys[i].UpdatedAt = stamp
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	task := disableTask{runtime: r, key: "guard-client-key", fingerprint: keyFingerprint("guard-client-key"), requestID: "old-task", at: time.Now(), keyUpdatedAt: stamp}
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":true,"name":"manual edit"}`)); e != nil {
		t.Fatal(e)
	}
	m.mu.RLock()
	k, _ := m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if k.UpdatedAt == stamp {
		t.Fatal("edit did not advance version")
	}
	m.autoDisableKey(task)
	m.mu.RLock()
	k, _ = m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if !k.IsEnabled() {
		t.Fatal("confirmed: stale task crossed same-second manual edit and disabled key")
	}
}
func TestContentGuardRegressionIncompleteScanDisables(t *testing.T) {
	m := guardFixture(t)
	configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 1
		s.Rules = append(s.Rules, contentguard.Rule{ID: "expensive", Name: "budget", Enabled: true, Kind: "keyword", Patterns: []string{strings.Repeat("x", 1000)}, Action: "flag", Severity: "low", KeyMode: "all"})
	})
	guardRequest(t, m, "partial-hit", "{\"input\":\"danger "+strings.Repeat("a", 240000)+"\"}")
	reviewAssertEnabled(t, m)
}
func TestContentGuardRegressionInflightOldScanDisablesEditedKey(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"flagged":true,"score":1}`))
	}))
	defer server.Close()
	m := guardFixture(t)
	configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 1
		s.Settings.Classifier.Enabled = true
		s.Settings.Classifier.URL = server.URL
		s.Settings.Classifier.Format = "generic"
		s.Settings.Classifier.Action = "block"
		s.Settings.Classifier.Severity = "high"
	})
	finished := make(chan struct{})
	go func() { defer close(finished); guardRequest(t, m, "old-inflight", `{"input":"safe"}`) }()
	<-started
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":false}`)); e != nil {
		t.Fatal(e)
	}
	if _, e := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"guard-client-key","enabled":true}`)); e != nil {
		t.Fatal(e)
	}
	close(release)
	<-finished
	reviewAssertEnabled(t, m)
}
func reviewAssertEnabled(t *testing.T, m *Manager) {
	t.Helper()
	m.disableMu.Lock()
	pending := len(m.disablePending)
	m.disableMu.Unlock()
	if pending != 0 {
		t.Fatal("unexpected automatic disable pending")
	}
	m.mu.RLock()
	k, _ := m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if !k.IsEnabled() {
		t.Fatal("key unexpectedly disabled")
	}
}
