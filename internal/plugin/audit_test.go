package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func auditRequest(t *testing.T, m *Manager, id string) {
	t.Helper()
	request := pluginapi.RequestInterceptRequest{RequestID: id, TraceID: "audit-trace", SourceFormat: "openai", Model: "audit-model", RequestedModel: "audit-model", Headers: http.Header{"Authorization": {"Bearer client-audit-secret"}, "X-Forwarded-For": {"203.0.113.99"}}, Metadata: map[string]any{"request_path": "/v1/chat/completions?api_key=client-audit-secret"}, Body: []byte(`{"model":"audit-model","api_key":"client-audit-secret","messages":[{"role":"user","content":"你好，联系 person@example.com，Bearer secret-token"}]}`)}
	raw, _ := json.Marshal(request)
	if _, err := m.HandleRPC(pluginabi.MethodRequestInterceptBefore, raw); err != nil {
		t.Fatal(err)
	}
}
func auditRecords(t *testing.T, m *Manager) []audit.Record {
	t.Helper()
	store, _ := m.auditSnapshot()
	if store == nil {
		t.Fatal("audit not configured")
	}
	result, err := store.List(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return result.Records
}
func TestAuditCaptureRawJSONPersistsWithoutHeadersOrResponseBody(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret","name":"audit key"}`)); err != nil {
		t.Fatal(err)
	}
	auditRequest(t, m, "audit-one")
	auditRequest(t, m, "audit-one")
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	listJSON, _ := json.Marshal(records)
	if strings.Contains(string(listJSON), "request_body") {
		t.Fatal("list contains body")
	}
	if records[0].IPSource != "" || records[0].ClientIP != "" {
		t.Fatal("trusted unverified forwarded IP")
	}
	if records[0].Path != "/v1/chat/completions" {
		t.Fatalf("query string retained: %q", records[0].Path)
	}
	store, _ := m.auditSnapshot()
	record, err := store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.BodyState != "stored_raw" || !strings.Contains(record.RequestBody, "你好") {
		t.Fatalf("body not decoded: %q %s", record.BodyState, record.RequestBody)
	}
	for _, secret := range []string{"client-audit-secret", "person@example.com", "secret-token"} {
		if !strings.Contains(record.RequestBody, secret) {
			t.Fatalf("explicitly requested raw body changed: %s", secret)
		}
	}
	sum := sha256.Sum256([]byte(record.RequestBody))
	if record.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("raw content hash mismatch")
	}
	response, _ := json.Marshal(pluginapi.ResponseInterceptRequest{RequestID: "audit-one", SourceFormat: "openai", Model: "audit-model", Body: []byte(`{"secret_response":"DO-NOT-RETAIN"}`)})
	if _, err := m.handleResponseInterceptAfter(response); err != nil {
		t.Fatal(err)
	}
	complete, _ := json.Marshal(pluginapi.RequestCompletion{RequestID: "audit-one", TraceID: "audit-trace", Model: "audit-model", Outcome: pluginapi.RequestCompletionSucceeded, StatusCode: 200, CompletedAt: time.Now()})
	if _, err := m.handleRequestComplete(complete); err != nil {
		t.Fatal(err)
	}
	record, err = store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != "succeeded" || record.StatusCode != 200 || strings.Contains(record.RequestBody, "DO-NOT-RETAIN") {
		t.Fatalf("invalid completion: %+v", record)
	}
	m.Shutdown()
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	restarted, _ := m.auditSnapshot()
	saved, err := restarted.Detail(context.Background(), record.ID)
	if err != nil || saved.RequestBody != record.RequestBody {
		t.Fatalf("restart lost audit: %v", err)
	}
}

func TestAuditRecordsLocallyRejectedRequest(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	auditRequest(t, m, "audit-rejected")
	for len(m.rejectedAuditSlots) > 0 {
		time.Sleep(time.Millisecond)
	}
	records := auditRecords(t, m)
	if len(records) != 1 || records[0].Outcome != "rejected" || records[0].StatusCode != 403 || records[0].BodyState != "omitted_rejected" {
		t.Fatalf("rejection not audited: %+v", records)
	}
}

func TestAuditManagementOnlyAndLazyBodyDetail(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret"}`)); err != nil {
		t.Fatal(err)
	}
	auditRequest(t, m, "audit-view")
	records := auditRecords(t, m)
	invoke := func(method, path string, query url.Values, auth bool) pluginapi.ManagementResponse {
		headers := http.Header{}
		if auth {
			headers.Set("Authorization", "Bearer management-test")
		}
		raw, _ := json.Marshal(pluginapi.ManagementRequest{Method: method, Path: path, Query: query, Headers: headers})
		response, err := m.handleManagement(raw)
		if err != nil {
			t.Fatal(err)
		}
		return decodeEnvelope[pluginapi.ManagementResponse](t, response)
	}
	for _, path := range []string{"/v0/management/key-guard/audit", "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/audit"} {
		if resp := invoke("GET", path, nil, false); resp.StatusCode != 401 {
			t.Fatalf("public audit status=%d", resp.StatusCode)
		}
	}
	resp := invoke("GET", "/v0/management/key-guard/audit", nil, true)
	if resp.StatusCode != 200 || strings.Contains(string(resp.Body), "request_body") {
		t.Fatalf("bad metadata list: %d %s", resp.StatusCode, resp.Body)
	}
	resp = invoke("GET", "/v0/management/key-guard/audit/detail", url.Values{"id": {records[0].ID}}, true)
	if resp.StatusCode != 200 || !strings.Contains(string(resp.Body), "request_body") {
		t.Fatalf("missing detail: %d", resp.StatusCode)
	}
	if resp = invoke("GET", "/v0/management/key-guard/audit/detail", url.Values{"id": {"audit-view"}}, true); resp.StatusCode != 404 {
		t.Fatal("requestid can enumerate detail")
	}
	for _, query := range []url.Values{{"limit": {"1000000"}}, {"offset": {"-1"}}, {"from": {"invalid"}}} {
		if resp = invoke("GET", "/v0/management/key-guard/audit", query, true); resp.StatusCode != 400 {
			t.Fatalf("invalid query accepted: %v", query)
		}
	}
	if resp = invoke("POST", "/v0/management/key-guard/audit", nil, true); resp.StatusCode != 405 {
		t.Fatal("audit mutation accepted")
	}
	if resp = invoke("GET", "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/audit/detail", url.Values{"id": {records[0].ID}}, true); resp.StatusCode != 401 {
		t.Fatal("resource route exposed audit")
	}
}

func TestAuditConfigurationCanDisableCollection(t *testing.T) {
	m := transactionManager(t)
	raw, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("audit:\n  enabled: false\n")})
	if err := m.Configure(raw); err != nil {
		t.Fatal(err)
	}
	auditRequest(t, m, "disabled-audit")
	if got := auditRecords(t, m); len(got) != 0 {
		t.Fatal("disabled audit recorded body")
	}
	if m.AuditStatus()["enabled"] != false {
		t.Fatal("disabled status missing")
	}
}

func TestAuditConfigDefaultsAndBounds(t *testing.T) {
	cfg, err := ParseConfigYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Audit.isEnabled() || cfg.Audit.RetentionDays != 7 || cfg.Audit.MaxBodyBytes != audit.DefaultMaxBodyBytes || cfg.Audit.MaxRecords != 10000 {
		t.Fatal("unsafe audit defaults")
	}
	for _, raw := range []string{"audit: {retention_days: -1}", "audit: {max_body_bytes: 10485761}", "audit: {max_total_bytes: 10}"} {
		if _, err := ParseConfigYAML([]byte(raw)); err == nil {
			t.Fatalf("invalid audit settings accepted: %s", raw)
		}
	}
}

func TestAuditUUIDAndNonstandardCorrelationCompletesAndFilters(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret"}`)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "caller-phone-12345678900"} {
		auditRequest(t, m, id)
		completion, _ := json.Marshal(pluginapi.RequestCompletion{RequestID: id, Outcome: pluginapi.RequestCompletionSucceeded, StatusCode: 200})
		if _, err := m.handleRequestComplete(completion); err != nil {
			t.Fatal(err)
		}
		value, err := m.QueryAudit(context.Background(), audit.Query{RequestID: id, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		items := value["items"].([]map[string]any)
		if len(items) != 1 || items[0]["outcome"] != "succeeded" {
			t.Fatalf("correlation failed: %v", items)
		}
		if strings.Contains(id, "phone") && strings.Contains(items[0]["request_id"].(string), "12345678900") {
			t.Fatal("nonstandard identifier PII retained")
		}
	}
}

func TestAuditUnknownSchemaAndLateModelsCannotLeakCredentials(t *testing.T) {
	m := transactionManager(t)
	key := "plain-credential-value"
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"plain-credential-value"}`)); err != nil {
		t.Fatal(err)
	}
	req := pluginapi.RequestInterceptRequest{RequestID: "late-secret-model", SourceFormat: "openai", Model: "model-plain-credential-value", RequestedModel: "model-plain-credential-value", Headers: http.Header{"Authorization": {"Bearer " + key}}, Metadata: map[string]any{"request_path": "/v1/chat/completions"}, Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)}
	raw, _ := json.Marshal(req)
	if _, err := m.handleRequestInterceptBefore(raw); err != nil {
		t.Fatal(err)
	}
	completion, _ := json.Marshal(pluginapi.RequestCompletion{RequestID: req.RequestID, Model: req.Model, Outcome: pluginapi.RequestCompletionSucceeded, Metadata: map[string]any{"api_key": key}})
	if _, err := m.handleRequestComplete(completion); err != nil {
		t.Fatal(err)
	}
	usage, _ := json.Marshal(pluginapi.UsageRecord{RequestID: req.RequestID, APIKey: key, Model: req.Model, ResponseModel: req.Model})
	if _, err := m.handleUsageRecord(usage); err != nil {
		t.Fatal(err)
	}
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("audit missing")
	}
	if strings.Contains(records[0].ServedModel, key) || strings.Contains(records[0].RequestedModel, key) {
		t.Fatal("late model callback restored redacted credential")
	}
	req.RequestID = "unknown-schema"
	req.Metadata = map[string]any{"request_path": "/arbitrary/custom"}
	req.Body = []byte(`{"sensitive_custom":"not-approved-for-capture"}`)
	raw, _ = json.Marshal(req)
	if _, err := m.handleRequestInterceptBefore(raw); err != nil {
		t.Fatal(err)
	}
	store, _ := m.auditSnapshot()
	result, err := store.List(context.Background(), audit.Query{RequestID: auditCorrelationID(req.RequestID), Limit: 10})
	if err != nil || len(result.Records) != 1 {
		t.Fatalf("query unknown: %v", err)
	}
	rec, err := store.Detail(context.Background(), result.Records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RequestBody != string(audit.FormatJSON(req.Body, audit.MaxRequestBodyBytes)) || rec.BodySHA256 == "" || rec.BodyState != "stored_raw" {
		t.Fatal("valid raw JSON was hidden by an old schema gate")
	}
}

func TestAuditFailureDoesNotBlockProxyRequest(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret"}`)); err != nil {
		t.Fatal(err)
	}
	m.stopAudit()
	if _, err := m.usageStore.DB().Conn().Exec("DROP TABLE client_request_audit"); err != nil {
		t.Fatal(err)
	}
	m.configureAudit(m.cfg.Audit)
	auditRequest(t, m, "audit-database-error")
	if count := m.limiter.ActiveCountForKey("client-audit-secret"); count != 1 {
		t.Fatalf("audit failure blocked admission: %d", count)
	}
}

func TestAuditCaptureFailureRemainsVisibleAfterSuccessfulWrite(t *testing.T) {
	m := transactionManager(t)
	m.recordAuditCaptureFailure()
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret"}`)); err != nil {
		t.Fatal(err)
	}
	auditRequest(t, m, "after-audit-failure")
	status := m.AuditStatus()
	if status["capture_failures"].(uint64) != 1 || status["last_capture_failure_at"] == nil {
		t.Fatal("capture failure hidden by successful write")
	}
}

func TestAuditLongPromptFlowsThroughCaptureSchemaAndDetail(t *testing.T) {
	m := transactionManager(t)
	// Functional size/lexical coverage uses a deterministic per-instance clock.
	// Elapsed-time omission is covered separately, without scheduler timing.
	fixed := time.Now()
	m.auditBodies = audit.NewBodyCaptureBudgetWithClock(func() time.Time { return fixed })
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"client-audit-secret"}`)); err != nil {
		t.Fatal(err)
	}
	prompt := strings.Repeat("这是长文本提示词 ", 60000) + " private-marker"
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]string{"role": "user", "content": prompt}}})
	if len(body) <= 1<<20 {
		t.Fatal("must exceed old store clamp")
	}
	req := pluginapi.RequestInterceptRequest{RequestID: "long-prompt", SourceFormat: "openai", Model: "audit-model", RequestedModel: "audit-model", Headers: http.Header{"Authorization": {"Bearer client-audit-secret"}}, Metadata: map[string]any{"request_path": "/v1/chat/completions"}, Body: body}
	raw, _ := json.Marshal(req)
	if _, err := m.handleRequestInterceptBefore(raw); err != nil {
		t.Fatal(err)
	}
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("missing long audit")
	}
	detail, err := m.AuditDetail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	record := detail["record"].(map[string]any)
	if record["body_state"] != "stored_raw" || len(record["request_body"].(string)) <= 1<<20 {
		t.Fatal("capture or schema still has hidden limit")
	}
}

func TestAuditConcurrentLargeRawBodiesAreNotSkippedAsBusy(t *testing.T) {
	m := transactionManager(t)
	// Functional size/lexical coverage uses a deterministic per-instance clock.
	// Elapsed-time omission is covered separately, without scheduler timing.
	fixed := time.Now()
	m.auditBodies = audit.NewBodyCaptureBudgetWithClock(func() time.Time { return fixed })
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]string{"role": "user", "content": strings.Repeat("长文本 ", 60000)}}, "api_key": "body-secret"})
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			m.beginAudit(pluginapi.RequestInterceptRequest{RequestID: fmt.Sprintf("raw-parallel-%d", index), SourceFormat: "openai", Model: "m", Body: body, Metadata: map[string]any{"request_path": "/v1/chat/completions"}}, "", "")
		}(i)
	}
	group.Wait()
	records := auditRecords(t, m)
	if len(records) != 4 {
		t.Fatalf("concurrent large requests lost: %d", len(records))
	}
	store, _ := m.auditSnapshot()
	for _, record := range records {
		detail, err := store.Detail(context.Background(), record.ID)
		if err != nil {
			t.Fatal(err)
		}
		if detail.BodyState != "stored_raw" || detail.RequestBody != string(audit.FormatJSON(body, audit.MaxRequestBodyBytes)) {
			t.Fatal("large raw body was skipped or rewritten")
		}
	}
}

func TestAuditTenMiBConfigurationAndExplicitSmallerCap(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{"audit: {max_body_bytes: 10485760}", audit.MaxRequestBodyBytes}, {"audit: {max_body_bytes: 32768}", 32768}} {
		cfg, err := ParseConfigYAML([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Audit.MaxBodyBytes != tc.want {
			t.Fatal("explicit body cap not respected")
		}
	}
}

func TestAuditNoLongerCapturesOrExposesNetworkMetadata(t *testing.T) {
	m := transactionManager(t)
	req := pluginapi.RequestInterceptRequest{RequestID: "no-network-monitoring", SourceFormat: "openai", Model: "audit-model", Headers: http.Header{"X-Forwarded-For": {"203.0.113.42"}, "X-Real-IP": {"198.51.100.23"}}, Metadata: map[string]any{"request_path": "/v1/chat/completions", "host_audit": map[string]any{"schema": "cpa.audit.network.v1", "peer_validated": true, "peer_ip": "127.0.0.1", "resolved_validated": true, "resolved_client_ip": "203.0.113.42"}}, Body: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)}
	raw, _ := json.Marshal(req)
	if _, err := m.handleRequestInterceptBefore(raw); err != nil {
		t.Fatal(err)
	}
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("audit missing")
	}
	value, err := m.AuditDetail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	output, _ := json.Marshal(value)
	for _, field := range []string{"client_ip", "peer_ip", "ip_source", "ip_note", "203.0.113.42", "198.51.100.23"} {
		if strings.Contains(string(output), field) {
			t.Fatalf("removed network monitoring still visible: %s", field)
		}
	}
	apiRequest, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/key-guard/audit", Headers: http.Header{"Authorization": {"Bearer admin"}}, Query: url.Values{"ip": {"203.0.113.42"}}})
	response, err := m.handleManagement(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeEnvelope[pluginapi.ManagementResponse](t, response).StatusCode; status != 400 {
		t.Fatalf("removed IP query accepted: %d", status)
	}
}

func TestAuditDenseConversationAndToolDefinitionsRemainFullyReadable(t *testing.T) {
	m := transactionManager(t)
	// This verifies full lexical/element retention, not CPU speed under race.
	// The real elapsed-time omission is covered by the separate advancing-clock test.
	fixed := time.Now()
	m.auditBodies = audit.NewBodyCaptureBudgetWithClock(func() time.Time { return fixed })
	messages := make([]map[string]any, 6000)
	for i := range messages {
		messages[i] = map[string]any{"role": "user", "content": "正常中文对话内容", "name": "speaker"}
	}
	tools := make([]map[string]any, 600)
	for i := range tools {
		tools[i] = map[string]any{"type": "function", "function": map[string]any{"name": "lookup", "description": "普通工具说明", "parameters": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "description": "参数描述"}}}}}
	}
	body, _ := json.Marshal(map[string]any{"model": "audit-model", "messages": messages, "tools": tools, "api_key": "client-audit-secret"})
	request := pluginapi.RequestInterceptRequest{RequestID: "dense-complex-request", SourceFormat: "openai", Model: "audit-model", Headers: http.Header{"Content-Type": {"application/json"}}, Metadata: map[string]any{"request_path": "/v1/chat/completions"}, Body: body}
	m.beginAudit(request, "client-audit-secret", "team")
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("dense audit missing")
	}
	store, _ := m.auditSnapshot()
	record, err := store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.BodyState != "stored_raw" || record.BodyTruncated || record.BodySHA256 == "" {
		t.Fatalf("dense JSON still omitted: %s", record.BodyState)
	}
	var saved struct {
		Messages []json.RawMessage
		Tools    []json.RawMessage
		APIKey   string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(record.RequestBody), &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Messages) != 6000 || len(saved.Tools) != 600 || saved.APIKey != "client-audit-secret" {
		t.Fatal("raw content completeness regressed")
	}
}

func TestAuditRawBodyOverExplicitSmallerLimitIsNotPartiallySaved(t *testing.T) {
	m := transactionManager(t)
	config, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("audit:\n  max_body_bytes: 512\n")})
	if err := m.Configure(config); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": strings.Repeat("长提示内容 ", 400)}}, "api_key": "body-secret"})
	m.beginAudit(pluginapi.RequestInterceptRequest{RequestID: "explicit-small-cap", SourceFormat: "openai", Model: "audit-model", Metadata: map[string]any{"request_path": "/v1/chat/completions"}, Body: payload}, "", "")
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("metadata missing")
	}
	value, err := m.AuditDetail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	record := value["record"].(map[string]any)
	if record["body_state"] != "omitted_input_limit" || record["body_truncated"] != true || record["body_sha256"] != nil && record["body_sha256"] != "" {
		t.Fatalf("explicit size limit bypassed: %v", record)
	}
	if body, ok := record["request_body"].(string); ok && body != "" {
		t.Fatal("raw partial body saved")
	}
}

func TestAuditFiltersSystemAndDeveloperWithoutChangingUpstreamRequest(t *testing.T) {
	m := transactionManager(t)
	req := pluginapi.RequestInterceptRequest{RequestID: "role-filter-persistence", SourceFormat: "openai", Model: "m", Body: []byte(`{"messages":[{"role":"system","content":"PRIVATE-SYSTEM-PROMPT"},{"role":"developer","content":"PRIVATE-DEVELOPER-PROMPT"},{"role":"user","content":"保留用户消息"},{"role":"assistant","content":"保留助手消息"},{"role":"tool","content":"保留工具消息"}],"model":"m"}`)}
	original := append([]byte(nil), req.Body...)
	m.beginAudit(req, "", "")
	if string(req.Body) != string(original) {
		t.Fatal("upstream request was modified")
	}
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("request audit record missing")
	}
	store, _ := m.auditSnapshot()
	saved, err := store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.BodyState != "stored_raw_system_filtered" || saved.BodyTruncated || saved.BodySHA256 == "" {
		t.Fatal("filtered request body not persisted")
	}
	for _, secret := range []string{"PRIVATE-SYSTEM-PROMPT", "PRIVATE-DEVELOPER-PROMPT", "保留工具消息"} {
		if strings.Contains(saved.RequestBody, secret) {
			t.Fatal("excluded role body reached database")
		}
	}
	for _, text := range []string{"保留用户消息", "保留助手消息"} {
		if !strings.Contains(saved.RequestBody, text) {
			t.Fatal("allowed role body lost")
		}
	}
}
