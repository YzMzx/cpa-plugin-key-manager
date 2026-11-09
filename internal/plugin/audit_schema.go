package plugin

import (
	"encoding/json"
	"strings"
)

// Body capture is restricted to recognized JSON client operations, not arbitrary
// HTTP payloads encountered by another plugin or future host integration.
func auditKnownRequestSchema(protocol, path string, body []byte) bool {
	if len(body) == 0 || len(body) > 256<<10 {
		return false
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return false
	}
	has := func(name string) bool {
		value, ok := fields[name]
		return ok && len(value) > 0 && string(value) != "null"
	}
	switch protocol {
	case "openai", "openai-chat", "openai_chat", "openai-chat-completions":
		switch path {
		case "/v1/chat/completions", "/chat/completions":
			return has("messages")
		case "/v1/completions", "/completions":
			return has("prompt")
		case "/v1/embeddings", "/embeddings":
			return has("input")
		case "/v1/responses", "/responses":
			return has("input")
		}
	case "openai-responses", "openai_responses", "responses":
		return (path == "/v1/responses" || path == "/responses") && has("input")
	case "claude", "anthropic":
		return (path == "/v1/messages" || path == "/messages") && has("messages")
	case "gemini", "google-gemini":
		return (strings.HasPrefix(path, "/v1beta/models/") || strings.HasPrefix(path, "/v1/models/")) && (strings.HasSuffix(path, ":generateContent") || strings.HasSuffix(path, ":streamGenerateContent")) && has("contents")
	}
	return false
}
