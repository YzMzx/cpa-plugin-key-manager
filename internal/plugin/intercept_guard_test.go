package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func configureGuardForTest(t *testing.T, m *Manager, change func(*contentguard.State)) *interceptRuntime {
	t.Helper()
	state := contentguard.DefaultState()
	state.Settings.Enabled = true
	state.Settings.Mode = contentguard.ModeEnforce
	state.Rules = []contentguard.Rule{{ID: "danger", Name: "测试规则", Enabled: true, Kind: "keyword", Patterns: []string{"danger"}, Action: "block", Severity: "high", KeyMode: "all"}}
	if change != nil {
		change(&state)
	}
	err := m.mutateRules(ruleMutation{op: "test guard"}, func(next *DynamicRulesState) error { next.Intercept = &state; return nil })
	if err != nil {
		t.Fatal(err)
	}
	return m.interceptSnapshot()
}
func guardRequest(t *testing.T, m *Manager, id, body string) pluginapi.RequestInterceptResponse {
	t.Helper()
	req := pluginapi.RequestInterceptRequest{RequestID: id, CallerScope: ComputeCallerScope("guard-client-key"), SourceFormat: "openai", RequestedModel: "test-model", Model: "test-model", Body: []byte(body), Headers: http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer guard-client-key"}, "X-Forwarded-For": {"203.0.113.90"}}, Metadata: map[string]any{"request_path": "/v1/chat/completions?api_key=guard-client-key"}}
	raw, _ := json.Marshal(req)
	result, err := m.handleRequestInterceptBefore(raw)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result pluginapi.RequestInterceptResponse
	}
	if err = json.Unmarshal(result, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Result
}
func guardFixture(t *testing.T) *Manager {
	t.Helper()
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte("{\"api_key\":\"guard-client-key\",\"name\":\"Guard fixture\",\"max_concurrency\":1}")); err != nil {
		t.Fatal(err)
	}
	return m
}
func guardAwait(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("guard asynchronous work did not complete")
}
func guardEventCount(m *Manager) int {
	r := m.interceptSnapshot()
	if r == nil {
		return 0
	}
	_, n, err := r.store.List(context.Background(), contentguard.Query{Limit: 100})
	if err != nil {
		return 0
	}
	return n
}
func TestContentGuardBlocksBeforeSlotAndKeepsEvidence(t *testing.T) {
	m := guardFixture(t)
	r := configureGuardForTest(t, m, nil)
	body := "{\"messages\":[{\"role\":\"system\",\"content\":\"danger instructions\"},{\"role\":\"user\",\"content\":\"hello\"}]}"
	result := guardRequest(t, m, "guard-block", body)
	if !result.Terminate || result.StatusCode != 403 {
		t.Fatalf("not blocked: %+v", result)
	}
	if strings.Contains(string(result.ResponseBody), "danger") || strings.Contains(string(result.ResponseBody), "测试规则") {
		t.Fatal("client learned rule details")
	}
	if m.limiter.ActiveCountForKey("guard-client-key") != 0 {
		t.Fatal("blocked request consumed slot")
	}
	guardAwait(t, func() bool { return guardEventCount(m) == 1 })
	events, _, err := r.store.List(context.Background(), contentguard.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Body != "" || len(events[0].Matches) > 0 {
		t.Fatal("list exposed content")
	}
	e, err := r.store.Detail(context.Background(), events[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.Body, "danger") || e.BodySHA256 == "" || e.OriginalSHA256 == "" {
		t.Fatalf("missing bounded evidence: %+v", e)
	}
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "guard-client-key") || strings.Contains(string(raw), "203.0.113.90") || strings.Contains(e.Path, "?") {
		t.Fatal("identity/header/query leaked")
	}
	if string(result.Body) != "" {
		t.Fatal("blocked response copied request")
	}
}
func TestContentGuardObserveNeverDisables(t *testing.T) {
	m := guardFixture(t)
	configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.Mode = "observe"
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 1
	})
	result := guardRequest(t, m, "observe-one", "{\"input\":\"danger\"}")
	if result.Terminate {
		t.Fatal("observe blocked")
	}
	if m.limiter.ActiveCountForKey("guard-client-key") != 1 {
		t.Fatal("observe did not enter normal lifecycle")
	}
	guardAwait(t, func() bool { return guardEventCount(m) == 1 })
	m.mu.RLock()
	rule, _ := m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if !rule.IsEnabled() {
		t.Fatal("observe disabled key")
	}
}
func TestContentGuardAutomaticDisableAndPersistence(t *testing.T) {
	m := guardFixture(t)
	configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.Threshold = 2
	})
	body := "{\"input\":\"danger\"}"
	guardRequest(t, m, "execution-one", body)
	guardRequest(t, m, "execution-one", body)
	m.disableMu.Lock()
	pending := len(m.disablePending)
	m.disableMu.Unlock()
	if pending != 0 {
		t.Fatal("duplicate request advanced threshold")
	}
	guardRequest(t, m, "execution-two", body)
	guardAwait(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		rule, _ := m.cfg.ResolveKeyRule("guard-client-key")
		return !rule.IsEnabled()
	})
	guardAwait(t, func() bool { m.disableMu.Lock(); defer m.disableMu.Unlock(); return len(m.disablePending) == 0 })
	if m.HostSyncStatus()["pending"] != true {
		t.Fatal("host sync intent not durable")
	}
	if got := guardRequest(t, m, "after-disable", "{\"input\":\"safe\"}"); !got.Terminate {
		t.Fatal("disabled key still admitted")
	}
	m.Shutdown()
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	rule, _ := m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if rule.IsEnabled() {
		t.Fatal("restart revived disabled key")
	}
}
func TestContentGuardIncompleteDoesNotDisable(t *testing.T) {
	m := guardFixture(t)
	configureGuardForTest(t, m, func(s *contentguard.State) {
		s.Settings.OversizePolicy = "deny"
		s.Settings.AutoDisable.Enabled = true
		s.Settings.AutoDisable.MinSeverity = "low"
		s.Settings.AutoDisable.Threshold = 1
	})
	if got := guardRequest(t, m, "invalid-one", "not JSON danger"); !got.Terminate {
		t.Fatal("deny incomplete ignored")
	}
	guardAwait(t, func() bool { return guardEventCount(m) == 1 })
	m.mu.RLock()
	rule, _ := m.cfg.ResolveKeyRule("guard-client-key")
	m.mu.RUnlock()
	if !rule.IsEnabled() {
		t.Fatal("parse error disabled key")
	}
}
func TestContentGuardOmissionIncludesMatchCopies(t *testing.T) {
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprint(capture), func(t *testing.T) {
			m := guardFixture(t)
			r := configureGuardForTest(t, m, func(s *contentguard.State) {
				s.Settings.CaptureBody = capture
				s.Settings.EvidenceIncludeSystem = false
			})
			guardRequest(t, m, "system-hit", "{\"instructions\":\"danger private-system-text\",\"input\":\"safe\"}")
			guardAwait(t, func() bool { return guardEventCount(m) == 1 })
			events, _, _ := r.store.List(context.Background(), contentguard.Query{Limit: 10})
			e, err := r.store.Detail(context.Background(), events[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), "private-system-text") {
				t.Fatal("filtered text leaked through evidence")
			}
			if !capture && e.Body != "" {
				t.Fatal("disabled capture saved body")
			}
		})
	}
}
func TestContentGuardGenerationFencesOldEvidence(t *testing.T) {
	m := guardFixture(t)
	old := configureGuardForTest(t, m, nil)
	configureGuardForTest(t, m, func(s *contentguard.State) { s.Settings.Enabled = false })
	m.writeIntercept(interceptWork{runtime: old, event: contentguard.Event{Action: "blocked", Mode: "enforce", Severity: "high", BodyState: "omitted_disabled", KeyFingerprint: keyFingerprint("guard-client-key"), RuleNames: []string{"stale"}}})
	if n := guardEventCount(m); n != 0 {
		t.Fatalf("stale generation wrote %d rows", n)
	}
}
func TestContentGuardFailedSaveKeepsLivePolicy(t *testing.T) {
	m := guardFixture(t)
	old := configureGuardForTest(t, m, nil)
	revision := m.RulesRevision()
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE rules_state"); err != nil {
		t.Fatal(err)
	}
	err := m.mutateRules(ruleMutation{op: "failing guard"}, func(s *DynamicRulesState) error { s.Intercept.Settings.Enabled = false; return nil })
	if err == nil || m.RulesRevision() != revision || m.interceptSnapshot() != old {
		t.Fatal("failed commit published policy")
	}
}
