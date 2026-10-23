package authz

import (
	"strings"
)

// NormalizeModelVariants generates candidate model names for matching:
//  1. Raw trimmed string (lowercased)
//  2. Stripped thinking suffix, e.g., "claude-3-7-sonnet-20250219(high)" -> "claude-3-7-sonnet-20250219"
//  3. Stripped provider prefix, e.g., "anthropic/claude-3-5-sonnet" -> "claude-3-5-sonnet"
//  4. Stripped ":free" or tag suffix if needed
func NormalizeModelVariants(model string) []string {
	raw := strings.ToLower(strings.TrimSpace(model))
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	add(raw)

	// Strip thinking suffix in parentheses: model(high) -> model
	base := StripThinkingSuffix(raw)
	add(base)

	// Strip provider prefix: provider/model -> model
	if idx := strings.LastIndex(base, "/"); idx >= 0 && idx+1 < len(base) {
		add(base[idx+1:])
	}
	if idx := strings.LastIndex(raw, "/"); idx >= 0 && idx+1 < len(raw) {
		add(raw[idx+1:])
	}

	return out
}

// StripThinkingSuffix removes a trailing parenthesized suffix such as "(high)" or "(8192)".
func StripThinkingSuffix(model string) string {
	trimmed := strings.TrimSpace(model)
	if !strings.HasSuffix(trimmed, ")") {
		return trimmed
	}
	openIdx := strings.LastIndex(trimmed, "(")
	if openIdx <= 0 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:openIdx])
}

// MatchWildcard performs case-insensitive wildcard matching supporting '*' (zero or more chars)
// and '?' (single char).
func MatchWildcard(pattern, target string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	t := strings.ToLower(strings.TrimSpace(target))
	if p == "" {
		return false
	}
	if p == "*" {
		return t != ""
	}
	return wildcardMatchLower(p, t)
}

func wildcardMatchLower(pattern, target string) bool {
	pIdx, tIdx := 0, 0
	starIdx, matchIdx := -1, 0
	pLen, tLen := len(pattern), len(target)

	for tIdx < tLen {
		if pIdx < pLen && (pattern[pIdx] == '?' || pattern[pIdx] == target[tIdx]) {
			pIdx++
			tIdx++
		} else if pIdx < pLen && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = tIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			tIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < pLen && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == pLen
}

// AllowsModel checks if any of the candidate model identifiers (e.g. RequestedModel, NormalizedModel)
// is allowed by the configured model patterns.
//   - If patterns is empty, no models are allowed (returns false).
//   - Supports negative patterns prefixed with '!' (e.g. "!claude-3-opus*"), which take precedence.
//   - Supports exact match and '*' / '?' wildcards.
func AllowsModel(patterns []string, modelCandidates ...string) bool {
	if len(patterns) == 0 {
		return false
	}

	variants := make([]string, 0, len(modelCandidates)*2)
	seen := make(map[string]struct{}, len(modelCandidates)*2)
	for _, candidate := range modelCandidates {
		for _, v := range NormalizeModelVariants(candidate) {
			if _, ok := seen[v]; !ok {
				seen[v] = struct{}{}
				variants = append(variants, v)
			}
		}
	}
	if len(variants) == 0 {
		return false
	}

	// Check negative rules first
	for _, rawPattern := range patterns {
		pat := strings.TrimSpace(rawPattern)
		if !strings.HasPrefix(pat, "!") {
			continue
		}
		negPat := strings.TrimSpace(pat[1:])
		if negPat == "" {
			continue
		}
		for _, v := range variants {
			if MatchWildcard(negPat, v) {
				return false
			}
		}
	}

	// Check positive whitelist rules
	for _, rawPattern := range patterns {
		pat := strings.TrimSpace(rawPattern)
		if pat == "" || strings.HasPrefix(pat, "!") {
			continue
		}
		patBase := StripThinkingSuffix(pat)
		for _, v := range variants {
			if MatchWildcard(pat, v) || (patBase != pat && MatchWildcard(patBase, v)) {
				return true
			}
		}
	}

	return false
}
