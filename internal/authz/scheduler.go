package authz

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// UpstreamBinding defines how an API key is bound to specific upstream credentials or credential pools.
type UpstreamBinding struct {
	// AuthIDs lists allowed credential IDs, file names, labels, or prefixes (supports '*' wildcard).
	AuthIDs []string `yaml:"auth_ids" json:"auth_ids,omitempty"`
	// Providers optionally restricts allowed upstream provider types (e.g. ["claude", "openai"]).
	Providers []string `yaml:"providers" json:"providers,omitempty"`
	// Attributes optionally matches candidate Attributes key-value pairs (supports '*' wildcard).
	Attributes map[string]string `yaml:"attributes" json:"attributes,omitempty"`
	// Strategy selects among multiple matching candidates: "round-robin" (default) or "fill-first".
	Strategy string `yaml:"strategy" json:"strategy,omitempty"`
	// Strict controls behavior when no bound candidate is available:
	// when true (default if binding is configured), reject selection instead of falling back to shared pool.
	Strict *bool `yaml:"strict" json:"strict,omitempty"`
}

// HasRules reports whether any upstream credential binding constraint is configured.
func (b UpstreamBinding) HasRules() bool {
	return len(b.AuthIDs) > 0 || len(b.Providers) > 0 || len(b.Attributes) > 0
}

// IsStrict returns true unless Strict was explicitly set to false.
func (b UpstreamBinding) IsStrict() bool {
	if b.Strict == nil {
		return true
	}
	return *b.Strict
}

// Scheduler handles per-API-Key upstream credential selection and tenant isolation.
type Scheduler struct {
	mu       sync.Mutex
	rrCursor map[string]*atomic.Uint64
}

// NewScheduler creates a new tenant-isolating credential scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		rrCursor: make(map[string]*atomic.Uint64),
	}
}

// Pick selects a candidate credential for the given API Key and UpstreamBinding.
func (s *Scheduler) Pick(apiKey string, binding UpstreamBinding, req pluginapi.SchedulerPickRequest) pluginapi.SchedulerPickResponse {
	if !binding.HasRules() {
		return pluginapi.SchedulerPickResponse{Handled: false}
	}

	matched := FilterCandidates(binding, req.Candidates)
	if len(matched) == 0 {
		if binding.IsStrict() {
			return pluginapi.SchedulerPickResponse{
				Handled:      true,
				Reject:       true,
				RejectCode:   "auth_unavailable",
				RejectReason: fmt.Sprintf("no bound upstream credential available for API key (model=%s)", req.Model),
			}
		}
		return pluginapi.SchedulerPickResponse{Handled: false}
	}

	strategy := strings.ToLower(strings.TrimSpace(binding.Strategy))
	switch strategy {
	case "fill-first", "priority":
		// Sort by higher priority first, then stable by ID
		sorted := make([]pluginapi.SchedulerAuthCandidate, len(matched))
		copy(sorted, matched)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].Priority != sorted[j].Priority {
				return sorted[i].Priority > sorted[j].Priority
			}
			return sorted[i].ID < sorted[j].ID
		})
		return pluginapi.SchedulerPickResponse{
			Handled: true,
			AuthID:  sorted[0].ID,
		}
	default:
		// Default: round-robin across matching candidates within the highest available priority tier
		idx := s.nextIndex(apiKey) % uint64(len(matched))
		return pluginapi.SchedulerPickResponse{
			Handled: true,
			AuthID:  matched[idx].ID,
		}
	}
}

func (s *Scheduler) nextIndex(apiKey string) uint64 {
	s.mu.Lock()
	counter, ok := s.rrCursor[apiKey]
	if !ok {
		counter = &atomic.Uint64{}
		s.rrCursor[apiKey] = counter
	}
	s.mu.Unlock()
	return counter.Add(1) - 1
}

// FilterCandidates returns all candidates that satisfy the UpstreamBinding rules.
func FilterCandidates(binding UpstreamBinding, candidates []pluginapi.SchedulerAuthCandidate) []pluginapi.SchedulerAuthCandidate {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]pluginapi.SchedulerAuthCandidate, 0, len(candidates))
	for _, cand := range candidates {
		if candidateMatches(binding, cand) {
			out = append(out, cand)
		}
	}
	return out
}

func candidateMatches(binding UpstreamBinding, cand pluginapi.SchedulerAuthCandidate) bool {
	// 1. Check Provider filter if specified
	if len(binding.Providers) > 0 {
		provMatched := false
		candProv := strings.ToLower(strings.TrimSpace(cand.Provider))
		for _, p := range binding.Providers {
			if MatchWildcard(p, candProv) {
				provMatched = true
				break
			}
		}
		if !provMatched {
			return false
		}
	}

	// 2. Check AuthIDs filter if specified (matches ID, filename without .json, label, or prefix attribute)
	if len(binding.AuthIDs) > 0 {
		idMatched := false
		candTokens := candidateIdentityTokens(cand)
		for _, pattern := range binding.AuthIDs {
			pat := strings.TrimSpace(pattern)
			if pat == "" {
				continue
			}
			patNoJSON := strings.TrimSuffix(strings.ToLower(pat), ".json")
			for _, token := range candTokens {
				if MatchWildcard(pat, token) || (patNoJSON != "" && MatchWildcard(patNoJSON, token)) {
					idMatched = true
					break
				}
			}
			if idMatched {
				break
			}
		}
		if !idMatched {
			return false
		}
	}

	// 3. Check Attributes filter if specified
	if len(binding.Attributes) > 0 {
		for k, expectedPattern := range binding.Attributes {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			actualVal := ""
			if cand.Attributes != nil {
				actualVal = cand.Attributes[key]
				if actualVal == "" {
					// Try case-insensitive lookup
					for attrK, attrV := range cand.Attributes {
						if strings.EqualFold(attrK, key) {
							actualVal = attrV
							break
						}
					}
				}
			}
			if actualVal == "" && cand.Metadata != nil {
				if v, ok := cand.Metadata[key]; ok {
					actualVal = fmt.Sprint(v)
				}
			}
			if !MatchWildcard(expectedPattern, actualVal) {
				return false
			}
		}
	}

	return true
}

func candidateIdentityTokens(cand pluginapi.SchedulerAuthCandidate) []string {
	tokens := make([]string, 0, 6)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" {
			tokens = append(tokens, v)
		}
	}
	add(cand.ID)
	add(strings.TrimSuffix(cand.ID, ".json"))
	if cand.Attributes != nil {
		add(cand.Attributes["label"])
		add(cand.Attributes["name"])
		add(cand.Attributes["prefix"])
		add(cand.Attributes["id"])
	}
	if cand.Metadata != nil {
		if label, ok := cand.Metadata["label"].(string); ok {
			add(label)
		}
		if email, ok := cand.Metadata["email"].(string); ok {
			add(email)
		}
	}
	return tokens
}
