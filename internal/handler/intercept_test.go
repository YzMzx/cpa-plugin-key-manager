package handler

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type interceptStub struct {
	calls int
	query contentguard.Query
}

func (s *interceptStub) result() (map[string]any, error) {
	s.calls++
	return map[string]any{"ok": true}, nil
}
func (s *interceptStub) GetInterceptConfig() map[string]any                 { v, _ := s.result(); return v }
func (s *interceptStub) SaveInterceptConfig([]byte) (map[string]any, error) { return s.result() }
func (s *interceptStub) TestInterceptRules(context.Context, []byte) (map[string]any, error) {
	return s.result()
}
func (s *interceptStub) InterceptStatus(context.Context) (map[string]any, error) { return s.result() }
func (s *interceptStub) QueryInterceptEvents(_ context.Context, q contentguard.Query) (map[string]any, error) {
	s.query = q
	return s.result()
}
func (s *interceptStub) InterceptEventDetail(context.Context, string) (map[string]any, error) {
	return s.result()
}
func (s *interceptStub) ReviewInterceptEvent(context.Context, []byte) (map[string]any, error) {
	return s.result()
}
func (s *interceptStub) ExportInterceptEvents(context.Context, []byte) (map[string]any, error) {
	return s.result()
}
func (s *interceptStub) ConfiguredTimezone() string { return "Asia/Shanghai" }

func TestInterceptExactManagementRouteAndAuthentication(t *testing.T) {
	routes, _ := RegisterManagementEndpoints()
	count := 0
	for _, route := range routes {
		if strings.HasPrefix(route.Path, RouteManagementIntercept+"/") {
			count++
		}
	}
	if count != 8 {
		t.Fatalf("intercept routes=%d", count)
	}
	for _, tc := range []struct {
		path, method string
		credential   bool
		want         int
	}{
		{"/v0/management/key-guard/intercept/config", "GET", false, 401},
		{"/v0/management/key-guard/intercept/config", "GET", true, 200},
		{"/v0/management/key-guard/intercept/config", "DELETE", true, 405},
		{"/v0/management/key-guard/intercept/config", "GET,PUT", true, 405},
		{"/v0/management/key-guard/intercept/config/", "GET", true, 404},
		{" /v0/management/key-guard/intercept/config", "GET", true, 404},
		{"/v0/resource/plugins/cpa-plugin-key-manager/key-guard/intercept/config", "GET", true, 404},
		{"/other/key-guard/intercept/config", "GET", true, 404},
	} {
		provider := &interceptStub{}
		req := pluginapi.ManagementRequest{Method: tc.method, Path: tc.path}
		if tc.credential {
			req.Headers = http.Header{"Authorization": {"Bearer fake-host-management-credential"}}
		}
		got := handleInterceptRequest(context.Background(), provider, req)
		if got.StatusCode != tc.want {
			t.Errorf("%q %s got=%d want=%d", tc.path, tc.method, got.StatusCode, tc.want)
		}
		if tc.want != 200 && provider.calls != 0 {
			t.Fatal("rejected request reached provider")
		}
	}
	// A regular frontend API key header is not a management credential. Native
	// host middleware remains responsible for verifying any bearer value.
	req := pluginapi.ManagementRequest{Method: "GET", Path: "/v0/management/key-guard/intercept/config", Headers: http.Header{"X-Api-Key": {"ordinary-key"}}}
	if got := handleInterceptRequest(context.Background(), &interceptStub{}, req); got.StatusCode != 401 {
		t.Fatal("ordinary key header granted management access")
	}
}

func TestInterceptQueryValidationAndTimezone(t *testing.T) {
	req := pluginapi.ManagementRequest{Method: "GET", Path: "/v0/management/key-guard/intercept/events", Headers: http.Header{"X-Management-Key": {"test-admin"}}}
	for _, query := range []url.Values{
		{"limit": {"0"}}, {"limit": {"101"}}, {"limit": {"1", "2"}}, {"offset": {"-1"}}, {"offset": {"100001"}},
		{"api_key": {"secret"}}, {"unknown": {"x"}}, {"from": {"invalid"}}, {"from": {"2026-02-02"}, "to": {"2026-02-01"}}, {"review": {""}},
	} {
		req.Query = query
		s := &interceptStub{}
		if got := handleInterceptRequest(context.Background(), s, req); got.StatusCode != 400 || s.calls != 0 {
			t.Fatalf("query validation failed: %v", query)
		}
	}
	req.Query = url.Values{"from": {"2026-02-01"}, "to": {"2026-02-02"}, "limit": {"20"}, "offset": {"3"}, "request_id": {"trace"}}
	s := &interceptStub{}
	if got := handleInterceptRequest(context.Background(), s, req); got.StatusCode != 200 {
		t.Fatal(string(got.Body))
	}
	if s.query.From != 1769875200000 || s.query.Limit != 20 || s.query.Offset != 3 || s.query.RequestID != "trace" {
		t.Fatalf("query=%+v", s.query)
	}
	req.Body = []byte("{}")
	if got := handleInterceptRequest(context.Background(), s, req); got.StatusCode != 400 {
		t.Fatal("GET body accepted")
	}
}

func TestInterceptErrorsNeverEchoInputOrDatabaseDetails(t *testing.T) {
	for _, err := range []error{errors.New("secret-token database path"), contentguard.ErrInvalidQuery, contentguard.ErrNotFound, &contentguard.ValidationError{Message: "secret-token"}} {
		got := interceptError(err)
		if strings.Contains(string(got.Body), "secret-token") || got.StatusCode == 200 {
			t.Fatal("unsafe error")
		}
	}
}
