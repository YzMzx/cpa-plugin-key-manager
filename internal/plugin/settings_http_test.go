package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func settingsHTTP(t *testing.T, m *Manager, method, path string, body []byte, credential bool, revision string) pluginapi.ManagementResponse {
	t.Helper()
	headers := http.Header{}
	if credential {
		headers.Set("Authorization", "Bearer settings-admin")
	}
	if revision != "" {
		headers.Set("X-Key-Guard-Revision", revision)
	}
	req, _ := json.Marshal(pluginapi.ManagementRequest{Method: method, Path: path, Body: body, Headers: headers})
	raw, err := m.handleManagement(req)
	if err != nil {
		t.Fatal(err)
	}
	return decodeEnvelope[pluginapi.ManagementResponse](t, raw)
}
func TestSettingsHTTPPersistsOneGiBAndEnforcesRevision(t *testing.T) {
	m := transactionManager(t)
	get := settingsHTTP(t, m, "GET", "/v0/management/key-guard/settings", nil, true, "")
	if get.StatusCode != 200 {
		t.Fatalf("GET=%d %s", get.StatusCode, get.Body)
	}
	var initial struct {
		RulesRevision uint64          `json:"rules_revision"`
		Settings      RuntimeSettings `json:"settings"`
		Bootstrap     json.RawMessage `json:"bootstrap"`
	}
	if json.Unmarshal(get.Body, &initial) != nil || len(initial.Bootstrap) == 0 {
		t.Fatal("missing unified response")
	}
	request, _ := json.Marshal(map[string]any{"settings": map[string]any{"audit": map[string]any{"max_total_bytes": 1073741824}, "storage": map[string]any{"timezone": "UTC"}}, "expected_revision": initial.RulesRevision})
	saved := settingsHTTP(t, m, "PUT", "/v0/management/key-guard/settings", request, true, strconv.FormatUint(initial.RulesRevision, 10))
	if saved.StatusCode != 200 || m.cfg.Audit.MaxTotalBytes != 1<<30 || m.ConfiguredTimezone() != "UTC" {
		t.Fatalf("settings not effective: %d %s", saved.StatusCode, saved.Body)
	}
	if status := m.AuditStatus()["max_total_bytes"]; status != float64(1<<30) {
		t.Fatal("audit did not apply new capacity")
	}
	stale := settingsHTTP(t, m, "PUT", "/v0/management/key-guard/settings", request, true, "")
	if stale.StatusCode != 409 {
		t.Fatalf("stale body CAS bypass: %d", stale.StatusCode)
	}
	for _, path := range []string{"/v0/management/key-guard/settings", "/v0/management/key-guard/settings/bootstrap", "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/settings"} {
		if response := settingsHTTP(t, m, "GET", path, nil, false, ""); response.StatusCode != 401 {
			t.Fatal("unauthenticated settings response")
		}
	}
	if response := settingsHTTP(t, m, "GET", "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/settings", nil, true, ""); response.StatusCode == 200 {
		t.Fatal("resource settings exposed")
	}
}
func TestAuditMediaPayloadDoesNotReachPersistence(t *testing.T) {
	m := transactionManager(t)
	encoded := strings.Repeat("PRIVATE_BASE64_PAYLOAD", 500)
	body, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": []any{map[string]string{"type": "text", "text": "保存正常提问"}, map[string]any{"type": "image_url", "image_url": map[string]string{"url": "data:image/png;base64," + encoded}}}}}})
	req := pluginapi.RequestInterceptRequest{RequestID: "media-persist", SourceFormat: "openai", Model: "m", Body: body, Headers: http.Header{"Content-Type": {"application/json"}}}
	m.beginAudit(req, "", "")
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("media request metadata dropped")
	}
	store, _ := m.auditSnapshot()
	detail, err := store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.BodyState != "stored_raw_media_filtered" || detail.BodyTruncated || detail.BodySHA256 == "" || !strings.Contains(detail.RequestBody, "保存正常提问") || strings.Contains(detail.RequestBody, encoded) || strings.Contains(detail.RequestBody, "data:image") {
		t.Fatalf("media payload retained or text lost: %s", detail.BodyState)
	}
	if len(detail.RequestBody) >= len(body) {
		t.Fatal("media filtering did not reduce retained size")
	}
}

func TestRemovedLegacyTokenNeverElevatesCallerPrivileges(t *testing.T) {
	m := NewManager(nil)
	// A stale YAML token is intentionally ignored by the current config parser.
	configured, err := ParseConfigYAML([]byte("admin_token: former-plugin-admin\nenabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cfg = configured
	m.mu.Unlock()
	for _, tc := range []struct {
		headers http.Header
		query   url.Values
		want    string
	}{
		{headers: http.Header{"Authorization": {"Bearer former-plugin-admin"}}, want: "former-plugin-admin"},
		{headers: http.Header{"X-Api-Key": {"client-key"}}, want: "client-key"},
		{query: url.Values{"api_key": {"query-client"}}, want: "query-client"},
		{},
	} {
		key, admin := m.ExtractCallerAPIKey(pluginapi.ManagementRequest{Headers: tc.headers, Query: tc.query})
		if admin || key != tc.want {
			t.Fatalf("caller privilege changed: key=%q admin=%v", key, admin)
		}
	}
}

func TestBootstrapHTTPRejectsRemovedTokenFieldsAndNeverEchoesLegacyState(t *testing.T) {
	m, _ := bootstrapFixture(t, "plugins:\n  configs:\n    cpa-plugin-key-manager:\n      admin_token: former-plugin-admin\n      storage: {usage_file: old-usage.json, rules_file: old-rules.json}\n      audit: {trusted_proxies: [127.0.0.1/32]}\n")
	response := settingsHTTP(t, m, "GET", "/v0/management/key-guard/settings/bootstrap", nil, true, "")
	if response.StatusCode != 200 {
		t.Fatalf("GET=%d", response.StatusCode)
	}
	for _, removed := range []string{"admin_token", "former-plugin-admin", "deprecated", "usage_file", "rules_file", "trusted_proxies"} {
		if strings.Contains(string(response.Body), removed) {
			t.Fatalf("GET exposed removed field %s", removed)
		}
	}
	for _, field := range []string{"admin_token", "clear_admin_token"} {
		body := bootstrapBody(t, m, func(request map[string]any) {
			if field == "admin_token" {
				request["bootstrap"].(map[string]any)[field] = "new-secret"
			} else {
				request["bootstrap"].(map[string]any)[field] = true
			}
		})
		response = settingsHTTP(t, m, "PUT", "/v0/management/key-guard/settings/bootstrap", body, true, "")
		if response.StatusCode != 400 {
			t.Fatalf("removed PUT field %s accepted: %d %s", field, response.StatusCode, response.Body)
		}
		if strings.Contains(string(response.Body), "new-secret") {
			t.Fatal("old field error echoed value")
		}
	}
}
