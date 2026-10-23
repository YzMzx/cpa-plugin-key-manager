package authz

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAllowsModelWildcardAndVariants(t *testing.T) {
	patterns := []string{
		"claude-3-5-*",
		"claude-3-7-sonnet-*",
		"gpt-4o*",
		"!gpt-4o-audio-*",
		"gemini-2.5-pro",
	}

	cases := []struct {
		name       string
		candidates []string
		want       bool
	}{
		{
			name:       "exact match",
			candidates: []string{"gemini-2.5-pro"},
			want:       true,
		},
		{
			name:       "wildcard prefix match",
			candidates: []string{"claude-3-5-sonnet-20241022"},
			want:       true,
		},
		{
			name:       "thinking suffix stripped",
			candidates: []string{"claude-3-7-sonnet-20250219(high)"},
			want:       true,
		},
		{
			name:       "provider prefix stripped",
			candidates: []string{"anthropic/claude-3-5-haiku-20241022"},
			want:       true,
		},
		{
			name:       "gpt-4o base and mini match",
			candidates: []string{"gpt-4o", "gpt-4o-mini"},
			want:       true,
		},
		{
			name:       "negative rule blocks excluded model",
			candidates: []string{"gpt-4o-audio-preview"},
			want:       false,
		},
		{
			name:       "unlisted model rejected",
			candidates: []string{"o3-mini", "deepseek-r1"},
			want:       false,
		},
		{
			name:       "empty candidate rejected",
			candidates: []string{""},
			want:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AllowsModel(patterns, tc.candidates...)
			if got != tc.want {
				t.Fatalf("AllowsModel(%v, %v) = %v, want %v", patterns, tc.candidates, got, tc.want)
			}
		})
	}
}

func TestErrorResponseOpenAIAndAnthropicCompatibility(t *testing.T) {
	resp403 := NewForbiddenModelResponse("claude-3-opus-20240229")
	if !resp403.Terminate || resp403.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected 403 response: %+v", resp403)
	}
	var parsed403 map[string]any
	if err := json.Unmarshal(resp403.ResponseBody, &parsed403); err != nil {
		t.Fatalf("unmarshal 403 body: %v", err)
	}
	if parsed403["type"] != "error" {
		t.Fatalf("expected top-level type=error for Anthropic compatibility, got %v", parsed403["type"])
	}
	errObj, ok := parsed403["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", parsed403["error"])
	}
	if errObj["type"] != "permission_error" || errObj["code"] != "model_not_allowed" {
		t.Fatalf("unexpected 403 error fields: %+v", errObj)
	}

	resp429 := NewConcurrencyLimitResponse(5)
	if !resp429.Terminate || resp429.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unexpected 429 response: %+v", resp429)
	}
	if resp429.ResponseHeaders.Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After=1, got %q", resp429.ResponseHeaders.Get("Retry-After"))
	}
}

func TestSchedulerPickAndStrictTenantIsolation(t *testing.T) {
	sched := NewScheduler()
	candidates := []pluginapi.SchedulerAuthCandidate{
		{ID: "claude-alpha-1.json", Provider: "claude", Priority: 10, Attributes: map[string]string{"tenant": "alpha"}},
		{ID: "claude-alpha-2.json", Provider: "claude", Priority: 20, Attributes: map[string]string{"tenant": "alpha"}},
		{ID: "claude-beta-1.json", Provider: "claude", Priority: 100, Attributes: map[string]string{"tenant": "beta"}},
	}

	bindingRR := UpstreamBinding{
		AuthIDs:  []string{"claude-alpha-*"},
		Strategy: "round-robin",
	}

	pick1 := sched.Pick("sk-alpha", bindingRR, pluginapi.SchedulerPickRequest{
		Model:      "claude-3-5-sonnet",
		Candidates: candidates,
	})
	pick2 := sched.Pick("sk-alpha", bindingRR, pluginapi.SchedulerPickRequest{
		Model:      "claude-3-5-sonnet",
		Candidates: candidates,
	})
	if !pick1.Handled || pick1.Reject || pick1.AuthID != "claude-alpha-1.json" {
		t.Fatalf("unexpected pick1: %+v", pick1)
	}
	if !pick2.Handled || pick2.Reject || pick2.AuthID != "claude-alpha-2.json" {
		t.Fatalf("unexpected pick2: %+v", pick2)
	}

	// Test fill-first (priority order)
	bindingPriority := UpstreamBinding{
		AuthIDs:  []string{"claude-alpha-*"},
		Strategy: "fill-first",
	}
	pickPrio := sched.Pick("sk-alpha", bindingPriority, pluginapi.SchedulerPickRequest{
		Model:      "claude-3-5-sonnet",
		Candidates: candidates,
	})
	if !pickPrio.Handled || pickPrio.AuthID != "claude-alpha-2.json" {
		t.Fatalf("expected highest priority candidate claude-alpha-2.json, got %+v", pickPrio)
	}

	// Test strict isolation when bound credentials are missing
	bindingGamma := UpstreamBinding{
		AuthIDs: []string{"claude-gamma-*"},
	}
	pickGamma := sched.Pick("sk-gamma", bindingGamma, pluginapi.SchedulerPickRequest{
		Model:      "claude-3-5-sonnet",
		Candidates: candidates,
	})
	if !pickGamma.Handled || !pickGamma.Reject {
		t.Fatalf("expected strict rejection when bound auth is unavailable, got %+v", pickGamma)
	}
}
