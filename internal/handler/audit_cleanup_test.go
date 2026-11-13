package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type cleanupProviderFixture struct {
	previews, applies int
	principal         string
	scope             string
	before            time.Time
	err               error
	deadline          time.Time
}

func (f *cleanupProviderFixture) AuditStorage(ctx context.Context) (map[string]any, error) {
	f.deadline, _ = ctx.Deadline()
	return map[string]any{"storage": map[string]any{"records": 2}}, f.err
}
func (f *cleanupProviderFixture) PreviewAuditCleanup(ctx context.Context, scope string, before time.Time, principal string) (map[string]any, error) {
	f.deadline, _ = ctx.Deadline()
	f.previews++
	f.principal = principal
	f.scope = scope
	f.before = before
	return map[string]any{"preview": map[string]any{"token": "opaque"}}, f.err
}
func (f *cleanupProviderFixture) CleanupAudit(ctx context.Context, token, principal string) (map[string]any, error) {
	f.deadline, _ = ctx.Deadline()
	f.applies++
	f.principal = principal
	return map[string]any{"ok": true}, f.err
}
func cleanupReq(method, path, body string, auth bool) pluginapi.ManagementRequest {
	r := pluginapi.ManagementRequest{Method: method, Path: "/v0/management" + path, Body: []byte(body), Headers: http.Header{}}
	if auth {
		r.Headers.Set("Authorization", "Bearer management-secret")
	}
	return r
}
func TestAuditCleanupHandlerRequiresNativeManagementAndPostConfirm(t *testing.T) {
	f := &cleanupProviderFixture{}
	for _, req := range []pluginapi.ManagementRequest{cleanupReq("GET", RouteManagementAuditStorage, "", false), cleanupReq("GET", RouteManagementAuditCleanup, "", true), cleanupReq("GET", RouteManagementAuditCleanupPreview, "", true)} {
		result := HandleAuditCleanupRequest(context.Background(), f, req)
		if result.StatusCode != 401 && result.StatusCode != 405 {
			t.Fatalf("unsafe method/auth %d", result.StatusCode)
		}
	}
	resource := cleanupReq("POST", RouteManagementAuditCleanup, `{"confirm":true,"token":"x"}`, true)
	resource.Path = "/v0/resource/plugins/cpa-plugin-key-manager/key-guard/audit/cleanup"
	if result := HandleAuditCleanupRequest(context.Background(), f, resource); result.StatusCode != 404 {
		t.Fatal("resource path accepted")
	}
	for _, body := range []string{`{}`, `{"token":"x"}`, `{"token":"x","confirm":false}`, `{"token":"x","confirm":true,"sql":"DELETE"}`, " \t ", "null", `{"token":"x","confirm":true,"confirm":false}`, `{"token":"x","confirm":true,"Confirm":false}`, `{"token":"x","confirm":true}{}`, strings.Repeat("x", 4097)} {
		if result := HandleAuditCleanupRequest(context.Background(), f, cleanupReq("POST", RouteManagementAuditCleanup, body, true)); result.StatusCode != 400 {
			t.Fatalf("bad body accepted %q =>%d", body, result.StatusCode)
		}
	}
	if f.applies != 0 {
		t.Fatal("destructive call during validation")
	}
	if result := HandleAuditCleanupRequest(context.Background(), f, cleanupReq("POST", RouteManagementAuditCleanup, `{"token":"x","confirm":true}`, true)); result.StatusCode != 200 || f.applies != 1 || f.principal != "management-secret" {
		t.Fatal("valid confirm failed")
	}
}
func TestAuditCleanupBudgetsOnlyExtendConfirmedApply(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		budget                   time.Duration
	}{
		{"storage", "GET", RouteManagementAuditStorage, "", 2 * time.Second},
		{"preview", "POST", RouteManagementAuditCleanupPreview, `{"scope":"all"}`, 2 * time.Second},
		{"apply", "POST", RouteManagementAuditCleanup, `{"token":"opaque","confirm":true}`, audit.CleanupApplyTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &cleanupProviderFixture{}
			started := time.Now()
			response := HandleAuditCleanupRequest(context.Background(), f, cleanupReq(tc.method, tc.path, tc.body, true))
			finished := time.Now()
			if response.StatusCode != 200 || f.deadline.Before(started.Add(tc.budget)) || f.deadline.After(finished.Add(tc.budget)) {
				t.Fatalf("wrong budget: status=%d deadline=%v", response.StatusCode, f.deadline)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			expected, _ := ctx.Deadline()
			HandleAuditCleanupRequest(ctx, f, cleanupReq(tc.method, tc.path, tc.body, true))
			if !f.deadline.Equal(expected) {
				t.Fatal("extended caller deadline")
			}
		})
	}
}

func TestAuditCleanupPreviewScopeAndTimestampValidation(t *testing.T) {
	f := &cleanupProviderFixture{}
	for _, body := range []string{`{}`, `{"scope":"bad"}`, `{"scope":"all","before":"2026-01-01T00:00:00Z"}`, `{"scope":"before","before":"2026-01-01"}`, `{"scope":"before","before":"2999-01-01T00:00:00Z"}`, `{"scope":"all","ids":["x"]}`} {
		if result := HandleAuditCleanupRequest(context.Background(), f, cleanupReq("POST", RouteManagementAuditCleanupPreview, body, true)); result.StatusCode != 400 {
			t.Fatalf("invalid preview %s accepted", body)
		}
	}
	result := HandleAuditCleanupRequest(context.Background(), f, cleanupReq("POST", RouteManagementAuditCleanupPreview, `{"scope":"before","before":"2026-01-01T00:00:00+08:00"}`, true))
	if result.StatusCode != 200 || f.previews != 1 || f.scope != "before" || f.before.IsZero() {
		t.Fatal("valid before scope failed")
	}
	for _, scope := range []string{"expired", "all"} {
		result = HandleAuditCleanupRequest(context.Background(), f, cleanupReq("POST", RouteManagementAuditCleanupPreview, `{"scope":"`+scope+`"}`, true))
		if result.StatusCode != 200 {
			t.Fatal("valid explicit scope failed")
		}
	}
	f.err = errors.New("raw dbpath secret credential")
	result = HandleAuditCleanupRequest(context.Background(), f, cleanupReq("GET", RouteManagementAuditStorage, "", true))
	if result.StatusCode != 503 || strings.Contains(string(result.Body), "credential") {
		t.Fatal("raw diagnostic leaked")
	}
}
