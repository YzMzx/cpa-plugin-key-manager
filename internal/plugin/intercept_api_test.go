package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
)

func interceptJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func interceptSave(t *testing.T, m *Manager, settings contentguard.Settings, rules []contentguard.Rule) map[string]any {
	t.Helper()
	request := map[string]any{"expected_revision": m.RulesRevision(), "settings": settings, "ack_prune": true}
	if rules != nil {
		request["rules"] = rules
	}
	value, err := m.SaveInterceptConfig(interceptJSON(t, request))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func interceptTestRule() contentguard.Rule {
	return contentguard.Rule{ID: "risk", Name: "风险", Enabled: true, Kind: contentguard.KindKeyword, Patterns: []string{"danger"}, Roles: []string{}, Action: contentguard.ActionBlock, Severity: contentguard.SeverityHigh, KeyMode: contentguard.KeyModeAll, KeyFingerprints: []string{}}
}

func TestInterceptConfigSecretLifecycleCASAndPersistence(t *testing.T) {
	m := transactionManager(t)
	settings := contentguard.DefaultSettings()
	settings.Classifier.APIKey = "private-classifier-secret"
	saved := interceptSave(t, m, settings, []contentguard.Rule{interceptTestRule()})
	raw := string(interceptJSON(t, saved))
	if strings.Contains(raw, settings.Classifier.APIKey) {
		t.Fatal("configuration echoed secret")
	}
	classifier := saved["settings"].(map[string]any)["classifier"].(map[string]any)
	if _, ok := classifier["api_key"]; ok || classifier["api_key_configured"] != true {
		t.Fatal("secret view contract")
	}
	revision := m.RulesRevision()
	if _, err := m.SaveInterceptConfig(interceptJSON(t, map[string]any{"expected_revision": revision - 1, "rules": []any{}})); !errors.Is(err, errInterceptRevision) {
		t.Fatalf("stale CAS=%v", err)
	}
	settings.Mode = contentguard.ModeEnforce
	settings.Classifier.APIKey = ""
	interceptSave(t, m, settings, nil)
	state, _ := m.interceptConfigSnapshot()
	if state.Settings.Classifier.APIKey != "private-classifier-secret" || len(state.Rules) != 1 {
		t.Fatal("blank key did not preserve secret/rules")
	}
	// Round-trip the response settings object, including api_key_configured.
	view := m.GetInterceptConfig()
	if _, err := m.SaveInterceptConfig(interceptJSON(t, map[string]any{"expected_revision": m.RulesRevision(), "settings": view["settings"]})); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveInterceptConfig(interceptJSON(t, map[string]any{"expected_revision": m.RulesRevision(), "clear_classifier_api_key": true})); err != nil {
		t.Fatal(err)
	}
	state, _ = m.interceptConfigSnapshot()
	if state.Settings.Classifier.APIKey != "" {
		t.Fatal("explicit clear failed")
	}
	before := m.RulesRevision()
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE rules_state"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveInterceptConfig(interceptJSON(t, map[string]any{"expected_revision": before, "rules": []any{}})); !errors.Is(err, contentguard.ErrUnavailable) {
		t.Fatalf("persistence error=%v", err)
	}
	state, after := m.interceptConfigSnapshot()
	if after != before || len(state.Rules) != 1 {
		t.Fatal("failed persistence published state")
	}
}

func TestInterceptStrictJSONAndPruneConfirmation(t *testing.T) {
	m := transactionManager(t)
	invalid := []string{
		"null", "{} {}", "[]", "{\"expected_revision\":0,\"rules\":null}",
		"{\"expected_revision\":0,\"expected_revision\":0,\"rules\":[]}",
		"{\"expected_revision\":0,\"Expected_Revision\":0,\"rules\":[]}",
		"{\"expected_revision\":0,\"rules\":[],\"secret-field\":1}",
		fmt.Sprintf("{\"expected_revision\":%d,\"settings\":{\"enabled\":false}}", m.RulesRevision()),
		fmt.Sprintf("{\"expected_revision\":%d,\"rules\":[null]}", m.RulesRevision()),
	}
	revision := m.RulesRevision()
	for _, raw := range invalid {
		if _, err := m.SaveInterceptConfig([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if m.RulesRevision() != revision {
		t.Fatal("invalid JSON mutated rules")
	}
	settings := contentguard.DefaultSettings()
	settings.RetentionDays--
	request := map[string]any{"expected_revision": revision, "settings": settings}
	if _, err := m.SaveInterceptConfig(interceptJSON(t, request)); !errors.Is(err, errInterceptPrune) {
		t.Fatalf("prune confirmation=%v", err)
	}
	request["ack_prune"] = true
	if _, err := m.SaveInterceptConfig(interceptJSON(t, request)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveInterceptConfig([]byte(strings.Repeat(" ", maxInterceptConfigBody+1))); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestInterceptConcurrentCASAndSnapshotRevision(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	raw := interceptJSON(t, map[string]any{"expected_revision": revision, "rules": []contentguard.Rule{interceptTestRule()}})
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.SaveInterceptConfig(raw)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, errInterceptRevision) {
				t.Errorf("save=%v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("CAS winners=%d", successes.Load())
	}
	// Each content change embeds its corresponding revision into the rule name.
	for i := 0; i < 20; i++ {
		expected := m.RulesRevision()
		rule := interceptTestRule()
		rule.Name = fmt.Sprint(expected + 1)
		if _, err := m.SaveInterceptConfig(interceptJSON(t, map[string]any{"expected_revision": expected, "rules": []contentguard.Rule{rule}})); err != nil {
			t.Fatal(err)
		}
		view := m.GetInterceptConfig()
		rules := view["rules"].([]contentguard.Rule)
		if rules[0].Name != fmt.Sprint(view["rules_revision"]) {
			t.Fatal("mixed content/revision snapshot")
		}
	}
}

func TestInterceptPreviewPlainJSONPrivacyAndValidation(t *testing.T) {
	m := transactionManager(t)
	settings := contentguard.DefaultSettings()
	settings.Mode = contentguard.ModeEnforce
	settings.EvidenceIncludeSystem = false
	interceptSave(t, m, settings, []contentguard.Rule{interceptTestRule()})
	body := interceptJSON(t, map[string]any{"messages": []any{map[string]any{"role": "system", "content": "danger hidden-system"}, map[string]any{"role": "user", "content": "safe-user"}}})
	view, err := m.TestInterceptRules(context.Background(), interceptJSON(t, map[string]any{"text": string(body)}))
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(interceptJSON(t, view))
	if view["would_block"] != true || view["parsed_json"] != true || strings.Contains(encoded, "hidden-system") || !strings.Contains(encoded, "safe-user") {
		t.Fatalf("preview=%s", encoded)
	}
	view, err = m.TestInterceptRules(context.Background(), interceptJSON(t, map[string]any{"text": "danger plain"}))
	if err != nil || view["would_block"] != true || view["parsed_json"] != false {
		t.Fatalf("plain preview=%v %v", view, err)
	}
	settings.CaptureBody = false
	interceptSave(t, m, settings, nil)
	view, err = m.TestInterceptRules(context.Background(), interceptJSON(t, map[string]any{"text": "danger plaintext-not-retained"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(interceptJSON(t, view)), "plaintext-not-retained") {
		t.Fatal("capture disabled leaked preview content")
	}
	for _, request := range []map[string]any{{"text": nil}, {"text": "{broken"}, {"text": "x", "classifier": nil}, {"text": "x", "unknown": "private"}, {"text": "x", "rules": nil}, {"text": "x", "key_fingerprint": "raw-key"}} {
		if _, err := m.TestInterceptRules(context.Background(), interceptJSON(t, request)); err == nil {
			t.Fatalf("accepted invalid preview %v", request)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.TestInterceptRules(ctx, interceptJSON(t, map[string]any{"text": "danger"})); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}

func TestInterceptClassifierExplicitOptInBudgetVerdictAndSecret(t *testing.T) {
	m := transactionManager(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid classifier payload")
		}
		if utf8.RuneCountInString(body["input"]) > 256 {
			t.Error("classifier text exceeded total character budget")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"flagged": true, "score": 0.9, "category": "private-classifier-secret", "reason": "private-classifier-secret hidden-system"})
	}))
	defer server.Close()
	settings := contentguard.DefaultSettings()
	settings.Mode = contentguard.ModeEnforce
	settings.Classifier.Enabled = true
	settings.Classifier.URL = server.URL
	settings.Classifier.Format = contentguard.FormatGeneric
	settings.Classifier.APIKey = "private-classifier-secret"
	settings.Classifier.MaxChars = 256
	settings.Classifier.Action = contentguard.ActionBlock
	settings.Classifier.Severity = contentguard.SeverityHigh
	interceptSave(t, m, settings, []contentguard.Rule{})
	request := map[string]any{"text": strings.Repeat("测试", 200)}
	view, err := m.TestInterceptRules(context.Background(), interceptJSON(t, request))
	if err != nil || calls.Load() != 0 || view["would_block"] != false {
		t.Fatal("default preview called network")
	}
	request["classifier"] = true
	view, err = m.TestInterceptRules(context.Background(), interceptJSON(t, request))
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(interceptJSON(t, view))
	if calls.Load() != 1 || view["would_block"] != true || view["severity"] != contentguard.SeverityHigh || strings.Contains(encoded, "private-classifier-secret") || strings.Contains(encoded, "hidden-system") {
		t.Fatalf("classification preview=%s", encoded)
	}
	request["text"] = "private-classifier-secret"
	view, err = m.TestInterceptRules(context.Background(), interceptJSON(t, request))
	if err != nil || strings.Contains(string(interceptJSON(t, view)), "private-classifier-secret") {
		t.Fatal("test text echoed configured classifier secret")
	}
}

func TestInterceptClassifierFailurePolicyCancellationAndScanBudget(t *testing.T) {
	m := transactionManager(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private upstream error", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	settings := contentguard.DefaultSettings()
	settings.Mode = contentguard.ModeEnforce
	settings.Classifier.Enabled = true
	settings.Classifier.URL = server.URL
	settings.Classifier.FailurePolicy = contentguard.PolicyDeny
	settings.Classifier.Severity = contentguard.SeverityHigh
	interceptSave(t, m, settings, []contentguard.Rule{})
	request := interceptJSON(t, map[string]any{"text": "preview", "classifier": true})
	view, err := m.TestInterceptRules(context.Background(), request)
	if err != nil || view["would_block"] != true || strings.Contains(string(interceptJSON(t, view)), "private upstream error") {
		t.Fatalf("failure policy=%v %v", view, err)
	}
	settings.Classifier.FailurePolicy = contentguard.PolicyAllow
	interceptSave(t, m, settings, nil)
	view, err = m.TestInterceptRules(context.Background(), request)
	if err != nil || view["would_block"] != false {
		t.Fatalf("allow failure policy=%v %v", view, err)
	}
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer hanging.Close()
	settings.Classifier.URL = hanging.URL
	interceptSave(t, m, settings, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := m.TestInterceptRules(ctx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("classifier cancellation=%v", err)
	}
	// Budget exhaustion must never be reported as a successful clean scan.
	interceptSave(t, m, settings, []contentguard.Rule{interceptTestRule()})
	if _, err := m.TestInterceptRules(context.Background(), interceptJSON(t, map[string]any{"text": strings.Repeat("x", contentguard.MaxSegmentScanBytes+1)})); err == nil {
		t.Fatal("incomplete scan returned success")
	}
}

func TestInterceptEventSecretSuppressionPreservesHashMeaning(t *testing.T) {
	settings := contentguard.DefaultSettings()
	settings.Classifier.APIKey = "private-classifier-secret"
	evidence := contentguard.CaptureEvidence([]byte(`{"input":"private-classifier-secret"}`), true, 64<<10)
	view := interceptEventView(contentguard.Event{Body: evidence.Text, BodyBytes: len(evidence.Text), BodySHA256: evidence.SHA256, OriginalSHA256: evidence.OriginalSHA256, BodyState: evidence.State}, true, settings)
	if strings.Contains(string(interceptJSON(t, view)), settings.Classifier.APIKey) || view["body_sha256"] != "" || view["body_state"] != "omitted_sensitive" {
		t.Fatal("secret body changed without clearing displayed checksum")
	}
}

func TestInterceptEventContractsNoGlobalCASAndPrivacy(t *testing.T) {
	m := transactionManager(t)
	ctx := context.Background()
	settings := contentguard.DefaultSettings()
	interceptSave(t, m, settings, []contentguard.Rule{})
	store := m.interceptSnapshot().store
	evidence := contentguard.CaptureEvidence([]byte(`{"messages":[{"role":"system","content":"hidden-system"},{"role":"user","content":"user-content"}]}`), true, 64<<10)
	id, err := store.Insert(ctx, contentguard.Event{BodyBytes: len(evidence.Text), BodySHA256: evidence.SHA256, OriginalSHA256: evidence.OriginalSHA256, CreatedAt: time.Now().UnixMilli(), RequestID: auditCorrelationID("request-id"), Action: contentguard.EventBlocked, Mode: contentguard.ModeEnforce, Severity: contentguard.SeverityHigh, Body: evidence.Text, BodyState: "stored_json_filtered", Matches: []contentguard.Match{{Source: "rule", Action: contentguard.ActionBlock, Severity: contentguard.SeverityHigh, Role: contentguard.RoleSystem, Snippet: "hidden-system", Matched: "hidden-system"}}, Classifier: &contentguard.ClassifierRecord{Reason: "hidden-system", Category: "hidden-system"}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := m.QueryInterceptEvents(ctx, contentguard.Query{Limit: 50, RequestID: "request-id"})
	if err != nil || list["total"] != 1 {
		t.Fatalf("list=%v %v", list, err)
	}
	if strings.Contains(string(interceptJSON(t, list)), "hidden-system") || strings.Contains(string(interceptJSON(t, list)), "user-content") {
		t.Fatal("list leaked evidence")
	}
	revision := m.RulesRevision()
	review := interceptJSON(t, map[string]any{"id": id, "status": contentguard.ReviewConfirmed, "note": "reviewed"})
	response := settingsHTTP(t, m, "POST", "/v0/management/key-guard/intercept/events/review", review, true, "999999")
	if response.StatusCode != 200 || m.RulesRevision() != revision {
		t.Fatalf("event review incorrectly used global CAS: %d %s", response.StatusCode, response.Body)
	}
	settings.EvidenceIncludeSystem = false
	interceptSave(t, m, settings, nil)
	detail, err := m.InterceptEventDetail(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(interceptJSON(t, detail))
	if strings.Contains(raw, "hidden-system") || !strings.Contains(raw, "user-content") {
		t.Fatalf("detail filtering=%s", raw)
	}
	exported, err := m.ExportInterceptEvents(ctx, interceptJSON(t, map[string]any{"ids": []string{id}}))
	if err != nil || exported["plugin_version"] != PluginVersion || exported["timezone"] == "" {
		t.Fatalf("export=%v %v", exported, err)
	}
	if strings.Contains(string(interceptJSON(t, exported)), "hidden-system") {
		t.Fatal("export bypassed system filter")
	}
	if _, err := m.ExportInterceptEvents(ctx, interceptJSON(t, map[string]any{"ids": []string{id, id}})); err == nil {
		t.Fatal("duplicate export IDs accepted")
	}
	status, err := m.InterceptStatus(ctx)
	if err != nil || status["today"] == nil || status["last_7_days"] == nil {
		t.Fatalf("status=%v %v", status, err)
	}
	settings.CaptureBody = false
	interceptSave(t, m, settings, nil)
	detail, err = m.InterceptEventDetail(ctx, id)
	if err != nil || strings.Contains(string(interceptJSON(t, detail)), "user-content") {
		t.Fatal("disabled capture still returned historical body")
	}
}
