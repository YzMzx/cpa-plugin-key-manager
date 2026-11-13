package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAuthenticatedScopeOverridesUntrustedCredentialOrder(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keys = []KeyRuleConfig{{APIKey: "restricted"}}
	cfg.Normalize()
	headers := http.Header{"Authorization": {"Bearer forged"}, "X-Api-Key": {"restricted"}}
	if got := cfg.ResolveAPIKeyFromContext(headers, nil, map[string]any{"caller_scope": ComputeCallerScope("restricted")}); got != "restricted" {
		t.Fatalf("resolved %q instead of authenticated key", got)
	}
	if got := cfg.ResolveAPIKeyFromContext(headers, nil, map[string]any{"api_key": "restricted"}); got != "restricted" {
		t.Fatalf("ignored trusted identity: %q", got)
	}
	if got := cfg.ResolveAPIKeyFromContext(headers, nil, map[string]any{"caller_scope": ComputeCallerScope("missing")}); got != "" {
		t.Fatalf("unresolved scope fell back to %q", got)
	}
	if got := cfg.ResolveAPIKeyFromContext(headers, nil, nil); got != "" {
		t.Fatalf("ambiguous legacy headers accepted %q", got)
	}
	unlisted := http.Header{"Authorization": {"Bearer forged"}, "X-Goog-Api-Key": {"native-unlisted"}}
	if got := cfg.ResolveAPIKeyFromContext(unlisted, nil, map[string]any{"caller_scope": ComputeCallerScope("native-unlisted")}); got != "native-unlisted" {
		t.Fatalf("unlisted authenticated candidate lost: %q", got)
	}
	if got := cfg.ResolveAPIKeyFromContext(nil, url.Values{"key": {"native-unlisted"}}, map[string]any{"caller_scope": ComputeCallerScope("native-unlisted")}); got != "native-unlisted" {
		t.Fatalf("query scope: %q", got)
	}
}

func TestMixedCredentialsCannotBypassAdmissionOrScheduler(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"restricted","max_concurrency":1,"allowed_models":["allowed"],"upstream_binding":{"credentials":["bound"]}}`)); err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Authorization": {"Bearer forged"}, "X-Api-Key": {"restricted"}}
	intercept := func(id, model, scope string) pluginapi.RequestInterceptResponse {
		t.Helper()
		r := pluginapi.RequestInterceptRequest{RequestID: id, Model: model, RequestedModel: model, Headers: headers}
		if scope != "" {
			r.CallerScope = scope
		}
		raw, _ := json.Marshal(r)
		out, err := m.handleRequestInterceptBefore(raw)
		if err != nil {
			t.Fatal(err)
		}
		return decodeEnvelope[pluginapi.RequestInterceptResponse](t, out)
	}
	if r := intercept("forbidden", "forbidden", ComputeCallerScope("restricted")); !r.Terminate || r.StatusCode != 403 {
		t.Fatalf("model bypass: %+v", r)
	}
	if r := intercept("first", "allowed", ComputeCallerScope("restricted")); r.Terminate {
		t.Fatalf("valid denied: %+v", r)
	}
	if r := intercept("second", "allowed", ComputeCallerScope("restricted")); !r.Terminate || r.StatusCode != 429 {
		t.Fatalf("concurrency bypass: %+v", r)
	}
	if r := intercept("unknown", "allowed", ComputeCallerScope("unknown")); !r.Terminate {
		t.Fatal("unknown authoritative scope accepted")
	}
	if r := intercept("legacy", "allowed", ""); !r.Terminate {
		t.Fatal("ambiguous identity accepted")
	}
	raw, _ := json.Marshal(pluginapi.SchedulerPickRequest{Model: "allowed", Options: pluginapi.SchedulerOptions{Headers: headers, Metadata: map[string]any{"caller_scope": ComputeCallerScope("restricted")}}, Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "shared"}}})
	out, err := m.handleSchedulerPick(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := decodeEnvelope[pluginapi.SchedulerPickResponse](t, out); !r.Handled || !r.Reject {
		t.Fatalf("binding bypass: %+v", r)
	}
}

func TestExampleLookingKeysKeepGovernance(t *testing.T) {
	m := transactionManager(t)
	for _, key := range []string{"sk-tenant-alpha-prod", "sk-tenant-beta-dev"} {
		raw, _ := json.Marshal(KeyRuleConfig{APIKey: key, Enabled: boolPtrSecurity(false), AllowedModels: []string{"only"}})
		if _, err := m.UpsertKeyRuleFromJSON(raw); err != nil {
			t.Fatal(err)
		}
		rule, listed := m.cfg.ResolveKeyRule(key)
		if !listed || rule.IsEnabled() {
			t.Fatalf("saved rule discarded for %s", key)
		}
	}
}
func boolPtrSecurity(v bool) *bool { return &v }

func TestIdentityConflictAndFrontendCredentialMultiplicity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Keys = []KeyRuleConfig{{APIKey: "key"}}
	cfg.Normalize()
	for _, meta := range []map[string]any{{"caller_scope": ComputeCallerScope("key"), "api_key": "other"}, {"api_key": "key", "userApiKey": "other"}, {"caller_scope": 42}} {
		if _, ok := cfg.resolveAuthenticatedKey(http.Header{"Authorization": {"Bearer key"}}, nil, meta, ""); ok {
			t.Fatalf("conflicting identity accepted: %v", meta)
		}
	}
	if _, ok := cfg.resolveAuthenticatedKey(nil, nil, map[string]any{"caller_scope": ComputeCallerScope("key")}, ComputeCallerScope("other")); ok {
		t.Fatal("top-level and metadata scope conflict accepted")
	}
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"key"}`)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		headers http.Header
		query   url.Values
		deny    bool
	}{
		{"different headers", http.Header{"Authorization": {"Bearer key"}, "X-Api-Key": {"other"}}, nil, true},
		{"repeated header", http.Header{"Authorization": {"Bearer key", "Bearer other"}}, nil, true},
		{"query conflict", http.Header{"Authorization": {"Bearer key"}}, url.Values{"key": {"other"}}, true},
		{"same identity", http.Header{"Authorization": {"Bearer key"}, "X-Api-Key": {"key"}}, nil, false},
		{"query only", nil, url.Values{"key": {"key"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(pluginapi.FrontendAuthRequest{Headers: tc.headers, Query: tc.query})
			out, err := m.handleFrontendAuth(raw)
			if err != nil {
				t.Fatal(err)
			}
			r := decodeEnvelope[pluginapi.FrontendAuthResponse](t, out)
			if tc.deny {
				if r.Authenticated || r.DenyStatusCode != 401 {
					t.Fatalf("conflict not rejected: %+v", r)
				}
			} else if !r.Authenticated || r.Principal != "key" {
				t.Fatalf("valid credentials rejected: %+v", r)
			}
		})
	}
}
func TestIdentityResolutionCompatibilityBoundaries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	for _, tc := range []struct {
		name    string
		headers http.Header
		meta    map[string]any
		want    string
		ok      bool
	}{
		{"legacy", http.Header{"Authorization": {"Bearer native"}}, nil, "native", true},
		{"anonymous legacy", nil, map[string]any{}, "", true},
		{"same repeated", http.Header{"Authorization": {"Bearer native", "Bearer native"}}, nil, "native", true},
		{"scope and principal", nil, map[string]any{"caller_scope": ComputeCallerScope("native"), "api_key": "native"}, "native", true},
		{"bad principal", nil, map[string]any{"api_key": 42}, "", false},
		{"unknown scope mismatch", http.Header{"Authorization": {"Bearer other"}}, map[string]any{"caller_scope": ComputeCallerScope("native")}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := cfg.resolveAuthenticatedKey(tc.headers, nil, tc.meta, "")
			if key != tc.want || ok != tc.ok {
				t.Fatalf("got (%q,%v), want (%q,%v)", key, ok, tc.want, tc.ok)
			}
		})
	}
}
