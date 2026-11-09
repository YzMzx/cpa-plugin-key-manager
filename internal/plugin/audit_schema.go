package plugin

import (
	"strings"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/tidwall/gjson"
)

// Reject unrelated routes before expensive large-body sanitization.
func auditRequestSchemaField(protocol, path string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "openai", "openai-chat", "openai_chat", "openai-chat-completions":
		switch path {
		case "/v1/chat/completions", "/chat/completions":
			return "messages"
		case "/v1/completions", "/completions":
			return "prompt"
		case "/v1/embeddings", "/embeddings", "/v1/responses", "/responses":
			return "input"
		}
	case "openai-responses", "openai_responses", "responses":
		if path == "/v1/responses" || path == "/responses" {
			return "input"
		}
	case "claude", "anthropic":
		if path == "/v1/messages" || path == "/messages" {
			return "messages"
		}
	case "gemini", "google-gemini":
		if (strings.HasPrefix(path, "/v1beta/models/") || strings.HasPrefix(path, "/v1/models/")) && (strings.HasSuffix(path, ":generateContent") || strings.HasSuffix(path, ":streamGenerateContent")) {
			return "contents"
		}
	}
	return ""
}

// The sanitizer has already validated this JSON. Inspect its retained string
// without making a second full map/RawMessage copy of a large client payload.
func auditKnownRequestSchema(protocol, path, body string) bool {
	if len(body) == 0 || len(body) > audit.MaxRequestBodyBytes {
		return false
	}
	field := auditRequestSchemaField(protocol, path)
	if field == "" {
		return false
	}
	value := gjson.Get(body, field)
	return value.Exists() && value.Type != gjson.Null
}
