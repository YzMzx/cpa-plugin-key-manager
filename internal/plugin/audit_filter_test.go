package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAuditKeyOptionsAreOpaqueMaskedAndIndependent(t *testing.T) {
	m := NewManager(nil)
	key := "client-production-private-value"
	second := "another-client-private-value"
	admin := "management-private-value"
	m.mu.Lock()
	m.cfg.Keys = []KeyRuleConfig{{APIKey: key, Name: "生产 " + key + " " + admin}, {APIKey: second, Name: "测试"}, {APIKey: key, Name: "duplicate"}, {APIKey: " "}, {APIKey: "x", Name: "短密钥"}}
	m.cfg.AdminToken = admin
	m.mu.Unlock()
	options := m.AuditKeyOptions()
	if len(options) != 3 {
		t.Fatalf("options=%v", options)
	}
	for i, raw := range []string{key, second, "x"} {
		sum := sha256.Sum256([]byte(raw))
		want := hex.EncodeToString(sum[:])
		if options[i]["value"] != want {
			t.Fatalf("option %d has nonopaque/incorrect value", i)
		}
	}
	if !strings.Contains(options[0]["label"], "生产") || !strings.Contains(options[0]["label"], usage.MaskAPIKey(key)) {
		t.Fatalf("missing remark or mask: %q", options[0]["label"])
	}
	if !strings.HasSuffix(options[2]["label"], "***") {
		t.Fatal("short key exposed")
	}
	raw, _ := json.Marshal(options)
	for _, secret := range []string{key, second, admin} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("selector leaked unmasked credential")
		}
	}
	options[0]["label"] = "changed"
	if m.cfg.Keys[0].Name == "changed" {
		t.Fatal("selector aliases live config")
	}
}

func TestAuditFourFilterHTTPQueryContract(t *testing.T) {
	m := transactionManager(t)
	store, _ := m.auditSnapshot()
	key := "five-filter-private-key"
	sum := sha256.Sum256([]byte(key))
	fingerprint := hex.EncodeToString(sum[:])
	now := time.Now().Add(-time.Minute)
	record := audit.Record{RequestID: auditCorrelationID("filter-request"), TraceID: auditCorrelationID("filter-trace"), StartedAt: now.UnixMilli(), Path: "/v1/chat/completions", Protocol: "openai", KeyLabel: "生产 ALPHA 团队", KeyFingerprint: fingerprint, RequestedModel: "GPT-4.1-Mini", ServedModel: "upstream-preview", Outcome: "succeeded", BodyState: "empty"}
	if err := store.Begin(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	invoke := func(query url.Values) pluginapi.ManagementResponse {
		raw, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/key-guard/audit", Headers: http.Header{"Authorization": {"Bearer test-admin"}}, Query: query})
		response, err := m.handleManagement(raw)
		if err != nil {
			t.Fatal(err)
		}
		return decodeEnvelope[pluginapi.ManagementResponse](t, response)
	}
	query := url.Values{"key_fingerprint": {fingerprint}, "key_label": {"生产 alpha"}, "model": {"4.1-mi"}, "outcome": {"succeeded"}}
	response := invoke(query)
	var payload struct {
		Total int
		Items []map[string]any
	}
	if response.StatusCode != 200 || json.Unmarshal(response.Body, &payload) != nil || payload.Total != 1 || len(payload.Items) != 1 {
		t.Fatalf("five filters failed: %d %s", response.StatusCode, response.Body)
	}
	if _, present := payload.Items[0]["request_body"]; present {
		t.Fatal("filter list contains body")
	}
	// Legacy correlation/time filtering remains available for older API clients.
	legacy := url.Values{"request_id": {"filter-request"}, "trace_id": {"filter-trace"}, "from": {now.Add(-time.Second).Format(time.RFC3339Nano)}, "to": {time.Now().Format(time.RFC3339Nano)}}
	response = invoke(legacy)
	if response.StatusCode != 200 || json.Unmarshal(response.Body, &payload) != nil || payload.Total != 1 {
		t.Fatalf("legacy query failed: %d %s", response.StatusCode, response.Body)
	}
	for _, bad := range []url.Values{{"api_key": {key}}, {"key_fingerprint": {"not-a-fingerprint"}}, {"key_label": {strings.Repeat("x", 1025)}}} {
		response = invoke(bad)
		if response.StatusCode != 400 {
			t.Fatalf("unsafe/invalid query allowed: %d %s", response.StatusCode, response.Body)
		}
		if strings.Contains(string(response.Body), key) {
			t.Fatal("error echoed raw API key")
		}
	}
}
