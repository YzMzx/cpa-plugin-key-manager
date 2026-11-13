package plugin

import (
	"net/http"
	"net/url"
	"strings"
)

// credentialCandidates includes every supported source, including repeated header
// values. It does not authenticate them. A host caller scope must match a candidate
// before an unlisted candidate can become the accounting/policy identity.
func credentialCandidates(headers http.Header, query url.Values) []string {
	var keys []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			for _, k := range keys {
				if k == value {
					return
				}
			}
			keys = append(keys, value)
		}
	}
	for name, values := range headers {
		for _, value := range values {
			switch {
			case strings.EqualFold(name, "Authorization"):
				value = strings.TrimSpace(value)
				parts := strings.SplitN(value, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
					add(parts[1])
				} else {
					add(value)
				}
			case strings.EqualFold(name, "X-Goog-Api-Key"), strings.EqualFold(name, "X-Api-Key"):
				add(value)
			}
		}
	}
	for _, name := range []string{"key", "auth_token", "api_key"} {
		for _, value := range query[name] {
			add(value)
		}
	}
	return keys
}

// The bool distinguishes an absent legacy identity from an invalid/conflicting
// authoritative identity. Only the former may use the anonymous default policy.
func (c *Config) resolveAuthenticatedKey(headers http.Header, query url.Values, metadata map[string]any, callerScope string) (string, bool) {
	scope := strings.TrimSpace(callerScope)
	if value, exists := metadata["caller_scope"]; exists {
		v, ok := value.(string)
		if !ok {
			return "", false
		}
		v = strings.TrimSpace(v)
		if scope != "" && v != "" && scope != v {
			return "", false
		}
		if v != "" {
			scope = v
		}
	}
	principal := ""
	for _, name := range []string{"api_key", "user_api_key", "userApiKey"} {
		if value, exists := metadata[name]; exists {
			v, ok := value.(string)
			if !ok {
				return "", false
			}
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if principal != "" && principal != v {
				return "", false
			}
			principal = v
		}
	}
	if scope != "" {
		if principal != "" {
			if ComputeCallerScope(principal) != scope {
				return "", false
			}
			return principal, true
		}
		if key, ok := c.byCallerScope[scope]; ok {
			return key, true
		}
		for _, key := range credentialCandidates(headers, query) {
			if ComputeCallerScope(key) == scope {
				return key, true
			}
		}
		return "", false
	}
	if principal != "" {
		return principal, true
	}
	keys := credentialCandidates(headers, query)
	if len(keys) > 1 {
		return "", false
	}
	if len(keys) == 1 {
		return keys[0], true
	}
	return "", true
}
