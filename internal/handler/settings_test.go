package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type settingsStub struct {
	saved          int
	bootstrapSaved int
	fail           error
}

func (s *settingsStub) GetRuntimeSettings() map[string]any {
	return map[string]any{"settings": map[string]any{"audit": map[string]any{"max_total_bytes": 1073741824}}, "rules_revision": 7}
}
func (s *settingsStub) SaveRuntimeSettings([]byte) (map[string]any, error) {
	s.saved++
	if s.fail != nil {
		return nil, s.fail
	}
	return map[string]any{"ok": true, "settings": map[string]any{}, "rules_revision": 8}, nil
}
func (s *settingsStub) BootstrapSettings() map[string]any {
	return map[string]any{"available": true, "effective": map[string]any{"admin_token_configured": true}}
}
func (s *settingsStub) SaveBootstrapSettings([]byte) (map[string]any, error) {
	s.bootstrapSaved++
	return map[string]any{"ok": true, "requires_restart": true}, nil
}

type settingsTestError string

func (e settingsTestError) Error() string        { return string(e) }
func (e settingsTestError) SettingsCode() string { return string(e) }

func TestUnifiedSettingsManagementRouteGuards(t *testing.T) {
	provider := &settingsStub{}
	req := pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/key-guard/settings"}
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 401 {
		t.Fatal("public settings accessible")
	}
	req.Headers = http.Header{"Authorization": {"Bearer test-admin"}}
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 200 || !strings.Contains(string(response.Body), "bootstrap") {
		t.Fatal("settings response missing bootstrap")
	}
	req.Path = "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/settings"
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 404 {
		t.Fatal("resource route settings accessible")
	}
	req.Path = "/v0/management/key-guard/settings"
	req.Method = http.MethodPut
	req.Body = []byte(`{"settings":{},"expected_revision":7}`)
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 200 || provider.saved != 1 {
		t.Fatal("settings PUT not dispatched")
	}
	req.Path = "/v0/management/key-guard/settings/bootstrap"
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 200 || provider.bootstrapSaved != 1 {
		t.Fatal("bootstrap PUT not dispatched")
	}
	req.Method = http.MethodDelete
	if response := handleSettingsRequest(context.Background(), provider, req); response.StatusCode != 405 {
		t.Fatal("unexpected settings mutation allowed")
	}
}
func TestUnifiedSettingsErrorsDoNotEchoSensitiveInput(t *testing.T) {
	for _, code := range []struct {
		err    error
		status int
	}{{settingsTestError("revision"), 409}, {settingsTestError("invalid"), 400}, {errors.New("secret-token"), 503}} {
		response := settingsError(code.err)
		if response.StatusCode != code.status || strings.Contains(string(response.Body), "secret-token") {
			t.Fatal("unsafe settings error")
		}
	}
}
