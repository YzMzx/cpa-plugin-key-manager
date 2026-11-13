package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const auditJobTestID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type auditJobFixture struct {
	SnapshotProvider                  // Any unrelated management call panics rather than silently succeeding.
	calls                             []string
	principal, argument, scope, owner string
	before, deadline                  time.Time
	err                               error
	legacyCalls                       int
}

func (f *auditJobFixture) call(ctx context.Context, op, argument, principal string) (map[string]any, error) {
	f.calls = append(f.calls, op)
	f.principal, f.argument = principal, argument
	f.deadline, _ = ctx.Deadline()
	if f.err != nil {
		return map[string]any{"unsafe": "principal/SQL/path"}, f.err
	}
	if f.owner != "" && f.owner != principal && op != "preview" {
		if op == "start" {
			return nil, fmt.Errorf("owner principal=%s SQL /private/db: %w", principal, audit.ErrCleanupPreviewExpired)
		}
		if op == "list" {
			return map[string]any{"jobs": []any{}}, nil
		}
		return nil, fmt.Errorf("owner principal=%s SQL /private/db: %w", principal, audit.ErrNotFound)
	}
	if op == "preview" {
		return map[string]any{"preview": map[string]any{"token": auditJobTestID}}, nil
	}
	if op == "list" {
		return map[string]any{"jobs": []any{map[string]any{"id": auditJobTestID, "state": "pending"}}}, nil
	}
	return map[string]any{"job": map[string]any{"id": auditJobTestID, "state": "pending"}}, nil
}
func (f *auditJobFixture) PreviewAuditCleanupJob(ctx context.Context, scope string, before time.Time, principal string) (map[string]any, error) {
	f.scope, f.before = scope, before
	return f.call(ctx, "preview", "", principal)
}
func (f *auditJobFixture) StartAuditCleanupJob(ctx context.Context, token, principal string) (map[string]any, error) {
	return f.call(ctx, "start", token, principal)
}
func (f *auditJobFixture) ListAuditCleanupJobs(ctx context.Context, principal string) (map[string]any, error) {
	return f.call(ctx, "list", "", principal)
}
func (f *auditJobFixture) GetAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	return f.call(ctx, "detail", id, principal)
}
func (f *auditJobFixture) CancelAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	return f.call(ctx, "cancel", id, principal)
}
func (f *auditJobFixture) ResumeAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	return f.call(ctx, "resume", id, principal)
}

// Legacy methods detect accidental fallthrough or synchronous deletion.
func (f *auditJobFixture) AuditStorage(context.Context) (map[string]any, error) {
	f.legacyCalls++
	return nil, nil
}
func (f *auditJobFixture) PreviewAuditCleanup(context.Context, string, time.Time, string) (map[string]any, error) {
	f.legacyCalls++
	return nil, nil
}
func (f *auditJobFixture) CleanupAudit(context.Context, string, string) (map[string]any, error) {
	f.legacyCalls++
	return nil, nil
}
func (f *auditJobFixture) QueryAudit(context.Context, audit.Query) (map[string]any, error) {
	f.legacyCalls++
	return nil, nil
}
func (f *auditJobFixture) AuditDetail(context.Context, string) (map[string]any, error) {
	f.legacyCalls++
	return nil, nil
}
func (f *auditJobFixture) AuditStatus() map[string]any { f.legacyCalls++; return nil }

func auditJobRequest(method, path, body string) pluginapi.ManagementRequest {
	return pluginapi.ManagementRequest{Method: method, Path: "/v0/management" + path, Headers: http.Header{"Authorization": {"Bearer fixture-admin"}}, Query: url.Values{"id": {auditJobTestID}}, Body: []byte(body)}
}
func auditJobCases() []struct {
	op, method, path, body string
	status                 int
} {
	return []struct {
		op, method, path, body string
		status                 int
	}{
		{"preview", "POST", RouteManagementAuditJobPreview, `{"scope":"all"}`, 200},
		{"start", "POST", RouteManagementAuditCleanupJobs, `{"token":"` + auditJobTestID + `","confirm":true}`, 202},
		{"list", "GET", RouteManagementAuditCleanupJobs, "", 200},
		{"detail", "GET", RouteManagementAuditJobDetail, "", 200},
		{"cancel", "POST", RouteManagementAuditJobCancel, `{"id":"` + auditJobTestID + `"}`, 200},
		{"resume", "POST", RouteManagementAuditJobResume, `{"id":"` + auditJobTestID + `"}`, 200},
	}
}

func TestAuditJobsContractAndTimeouts(t *testing.T) {
	for _, tc := range auditJobCases() {
		t.Run(tc.op, func(t *testing.T) {
			f := &auditJobFixture{}
			req := auditJobRequest(tc.method, tc.path, tc.body)
			started := time.Now()
			res := HandleManagementRequest(context.Background(), f, req, "")
			finished := time.Now()
			if res.StatusCode != tc.status || len(f.calls) != 1 || f.calls[0] != tc.op || f.legacyCalls != 0 {
				t.Fatalf("wrong dispatch/status: %d calls=%v legacy=%d", res.StatusCode, f.calls, f.legacyCalls)
			}
			if f.principal != "fixture-admin" {
				t.Fatal("principal not extracted")
			}
			budget := 5 * time.Second
			if tc.op == "cancel" {
				budget = 12 * time.Second
			}
			if f.deadline.Before(started.Add(budget)) || f.deadline.After(finished.Add(budget)) {
				t.Fatalf("wrong deadline %v", f.deadline)
			}
			if tc.op == "start" {
				var body map[string]any
				if json.Unmarshal(res.Body, &body) != nil || body["job"] == nil || body["ok"] != nil || body["deleted_records"] != nil {
					t.Fatalf("start did not return task: %s", res.Body)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			expected, _ := ctx.Deadline()
			HandleManagementRequest(ctx, f, req, "")
			if !f.deadline.Equal(expected) {
				t.Fatal("request extended caller deadline")
			}
			req.Headers = http.Header{"X-Management-Key": {" alternate-admin "}}
			HandleManagementRequest(context.Background(), f, req, "")
			if f.principal != "alternate-admin" {
				t.Fatal("management header not forwarded")
			}
			req.Headers.Set("Authorization", "bEaReR preferred-admin")
			HandleManagementRequest(context.Background(), f, req, "")
			if f.principal != "preferred-admin" {
				t.Fatal("bearer precedence differs from legacy")
			}
		})
	}
}

func TestAuditJobsNativeAuthExactRoutesAndMethods(t *testing.T) {
	for _, tc := range auditJobCases() {
		t.Run(tc.op, func(t *testing.T) {
			for _, mutate := range []func(*pluginapi.ManagementRequest){
				func(r *pluginapi.ManagementRequest) { r.Headers = nil },
				func(r *pluginapi.ManagementRequest) {
					r.Headers = http.Header{}
					r.Query.Set("api_key", "ordinary-key")
				},
				func(r *pluginapi.ManagementRequest) { r.Headers = http.Header{"X-Api-Key": {"ordinary-key"}} },
				func(r *pluginapi.ManagementRequest) { r.Path = "/v0/resource/plugins/cpa-plugin-key-manager" + tc.path },
				func(r *pluginapi.ManagementRequest) { r.Path += "/unknown" },
				func(r *pluginapi.ManagementRequest) { r.Path += "/" },
				func(r *pluginapi.ManagementRequest) { r.Path = "/elsewhere" + r.Path },
				func(r *pluginapi.ManagementRequest) { r.Method = "DELETE" },
			} {
				f := &auditJobFixture{}
				req := auditJobRequest(tc.method, tc.path, tc.body)
				mutate(&req)
				res := HandleAuditCleanupJobsRequest(context.Background(), f, req)
				if res.StatusCode < 400 || len(f.calls) != 0 || f.legacyCalls != 0 {
					t.Fatalf("unsafe request accepted: %+v status=%d", req, res.StatusCode)
				}
				res = HandleManagementRequest(context.Background(), f, req, "")
				if res.StatusCode < 400 || len(f.calls) != 0 || f.legacyCalls != 0 {
					t.Fatalf("unsafe outer dispatch status=%d", res.StatusCode)
				}
			}
			if tc.method == "POST" {
				f := &auditJobFixture{}
				req := auditJobRequest("GET", tc.path, tc.body)
				res := HandleManagementRequest(context.Background(), f, req, "")
				if tc.op == "start" {
					if res.StatusCode != 200 || len(f.calls) != 1 || f.calls[0] != "list" {
						t.Fatal("GET jobs mutated state")
					}
				} else if res.StatusCode != 405 || len(f.calls) != 0 {
					t.Fatal("GET invoked job mutation")
				}
			}
		})
	}
}

func TestAuditJobsStrictBodyAndHexValidation(t *testing.T) {
	for _, tc := range auditJobCases() {
		if tc.method != "POST" {
			continue
		}
		t.Run(tc.op, func(t *testing.T) {
			bodies := []string{"", " ", "null", "[]", "{}", "{", tc.body + "{}", tc.body + " null", strings.Repeat(" ", 4097) + tc.body,
				strings.TrimSuffix(tc.body, "}") + `,"unknown":true}`,
				strings.TrimSuffix(tc.body, "}") + `,"principal":"other-owner"}`,
				strings.TrimSuffix(tc.body, "}") + `,"sql":"DELETE"}`}
			switch tc.op {
			case "preview":
				bodies = append(bodies, `{"scope":null}`, `{"scope":"all","before":null}`, `{"scope":"all","scope":"expired"}`, `{"scope":"all","Scope":"expired"}`, `{"Scope":"all"}`, `{"scope":"all","sc\u006fpe":"before"}`, `{"scope":{}}`)
			case "start":
				bodies = append(bodies, `{"token":null,"confirm":true}`, `{"token":"`+auditJobTestID+`","confirm":null}`, `{"token":"`+auditJobTestID+`","confirm":false}`, `{"token":"`+auditJobTestID+`","confirm":"true"}`, strings.TrimSuffix(tc.body, "}")+`,"confirm":true}`, strings.Replace(tc.body, "token", "Token", 1))
			default:
				bodies = append(bodies, `{"id":null}`, `{"id":[]}`, strings.TrimSuffix(tc.body, "}")+`,"id":"`+auditJobTestID+`"}`, strings.Replace(tc.body, "id", "ID", 1))
			}
			if tc.op != "preview" {
				for _, id := range []string{"", "x", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), " " + auditJobTestID} {
					bodies = append(bodies, strings.Replace(tc.body, auditJobTestID, id, 1))
				}
			}
			for _, body := range bodies {
				f := &auditJobFixture{}
				res := HandleManagementRequest(context.Background(), f, auditJobRequest(tc.method, tc.path, body), "")
				if res.StatusCode != 400 || len(f.calls) != 0 {
					t.Fatalf("accepted malformed body %q => %d", body, res.StatusCode)
				}
			}
		})
	}
	for _, ids := range [][]string{nil, {""}, {"bad"}, {strings.Repeat("g", 64)}, {" " + auditJobTestID}, {auditJobTestID, auditJobTestID}} {
		f := &auditJobFixture{}
		req := auditJobRequest("GET", RouteManagementAuditJobDetail, "")
		req.Query["id"] = ids
		if res := HandleManagementRequest(context.Background(), f, req, ""); res.StatusCode != 400 || len(f.calls) != 0 {
			t.Fatal("invalid detail id accepted")
		}
	}
	// The full raw body, including whitespace, has an inclusive 4096-byte budget.
	body := `{"scope":"all"}`
	padded := body + strings.Repeat(" ", 4096-len(body))
	f := &auditJobFixture{}
	if res := HandleManagementRequest(context.Background(), f, auditJobRequest("POST", RouteManagementAuditJobPreview, padded), ""); res.StatusCode != 200 {
		t.Fatal("4096 byte valid body rejected")
	}
}

func TestAuditJobsPreviewScopeMatchesLegacy(t *testing.T) {
	for _, body := range []string{
		`{"scope":"bad"}`, `{"scope":" all "}`, `{"scope":"before"}`,
		`{"scope":"all","before":"2000-01-01T00:00:00Z"}`,
		`{"scope":"expired","before":"2000-01-01T00:00:00Z"}`,
		`{"scope":"before","before":"2000-01-01"}`,
		`{"scope":"before","before":"2000-01-01T00:00:00"}`,
		`{"scope":"before","before":"1969-12-31T23:59:59Z"}`,
		`{"scope":"before","before":"9999-12-31T23:59:59Z"}`,
	} {
		f := &auditJobFixture{}
		if res := HandleManagementRequest(context.Background(), f, auditJobRequest("POST", RouteManagementAuditJobPreview, body), ""); res.StatusCode != 400 || len(f.calls) != 0 {
			t.Fatalf("invalid scope/time %s", body)
		}
	}
	for _, body := range []string{`{"scope":"all"}`, `{"scope":"expired"}`, `{"scope":"before","before":"2000-01-01T08:00:00.123456789+08:00"}`} {
		f := &auditJobFixture{}
		if res := HandleManagementRequest(context.Background(), f, auditJobRequest("POST", RouteManagementAuditJobPreview, body), ""); res.StatusCode != 200 {
			t.Fatalf("valid preview rejected %s", body)
		}
		if f.scope == "before" && f.before.Format(time.RFC3339Nano) != "2000-01-01T08:00:00.123456789+08:00" {
			t.Fatal("lost scope cutoff")
		}
	}
}

func TestAuditJobsErrorsAreSafeAcrossAllOperations(t *testing.T) {
	for _, tc := range auditJobCases() {
		t.Run(tc.op, func(t *testing.T) {
			for _, ec := range []struct {
				err    error
				status int
			}{
				{audit.ErrCleanupPreviewExpired, 409}, {audit.ErrCleanupBusy, 409}, {audit.ErrCleanupJobState, 409}, {audit.ErrCleanupTooLarge, 413},
				{audit.ErrNotFound, 404}, {audit.ErrInvalidCleanup, 400}, {audit.ErrUnavailable, 503}, {context.Canceled, 503}, {context.DeadlineExceeded, 503}, {errors.New("unknown"), 503},
			} {
				f := &auditJobFixture{err: fmt.Errorf("SQL DELETE /private/db principal=fixture-admin: %w", ec.err)}
				res := HandleManagementRequest(context.Background(), f, auditJobRequest(tc.method, tc.path, tc.body), "")
				if res.StatusCode != ec.status {
					t.Fatalf("error status=%d want=%d", res.StatusCode, ec.status)
				}
				for _, secret := range []string{"SQL", "DELETE", "/private/db", "fixture-admin", "unsafe", "principal"} {
					if strings.Contains(string(res.Body), secret) {
						t.Fatalf("unsafe error %s", res.Body)
					}
				}
			}
			f := &auditJobFixture{owner: "other-owner"}
			res := HandleManagementRequest(context.Background(), f, auditJobRequest(tc.method, tc.path, tc.body), "")
			expected := 404
			if tc.op == "start" {
				expected = 409
			}
			if tc.op == "list" || tc.op == "preview" {
				expected = 200
			}
			if res.StatusCode != expected || strings.Contains(string(res.Body), "other-owner") || strings.Contains(string(res.Body), "fixture-admin") {
				t.Fatalf("cross-owner unsafe: %d %s", res.StatusCode, res.Body)
			}
		})
	}
	req := auditJobRequest("GET", RouteManagementAuditCleanupJobs, "")
	if res := HandleAuditCleanupJobsRequest(context.Background(), struct{}{}, req); res.StatusCode != 503 {
		t.Fatal("missing provider should be unavailable")
	}
}

func TestAuditJobsRoutesRegisteredOnlyAsManagement(t *testing.T) {
	routes, resources := RegisterManagementEndpoints()
	for _, tc := range auditJobCases() {
		count := 0
		for _, route := range routes {
			if route.Path == tc.path && route.Method == tc.method {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("route %s %s registered %d times", tc.method, tc.path, count)
		}
		for _, resource := range resources {
			if strings.Contains(resource.Path, "audit") {
				t.Fatal("audit resource route registered")
			}
		}
	}
}
