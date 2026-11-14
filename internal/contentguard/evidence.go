package contentguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// EvidenceResult distinguishes exact retained bytes from the complete original.
// SHA256 is empty when nothing is stored. OriginalSHA256 is empty when input
// exceeds the byte/JSON validation budget; it never denotes a prefix hash.
type EvidenceResult struct {
	Text           string
	State          string
	Truncated      bool
	SHA256         string
	OriginalSHA256 string
}

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

// CaptureEvidence accepts only a complete, bounded UTF-8 JSON object/array.
// It never stores malformed, compressed or unvalidated raw prefixes. Output is
// filtered JSON (not byte-for-byte original), and never contains media payloads.
func CaptureEvidence(body []byte, includeSystem bool, maxBytes int) EvidenceResult {
	out := EvidenceResult{State: "omitted_invalid"}
	if maxBytes <= 0 || maxBytes > 1<<20 {
		out.State = "omitted_budget"
		return out
	}
	if len(body) > MaxInputBytes {
		out.State = "omitted_oversize"
		out.Truncated = true
		return out
	}
	if len(body) == 0 {
		out.State = "empty"
		out.OriginalSHA256 = digest(body)
		return out
	}
	root, err := decodeJSON(body, MaxInputBytes)
	if err != nil {
		return out
	}
	switch root.(type) {
	case map[string]any, []any:
	default:
		return out
	}
	out.OriginalSHA256 = digest(body)
	filtered, _ := filterEvidence(root, includeSystem, 0)
	raw, err := json.Marshal(filtered)
	if err != nil {
		return out
	}
	if len(raw) > maxBytes {
		out.State = "omitted_output_budget"
		out.Truncated = true
		return out
	}
	out.Text = string(raw)
	out.State = "stored_json_filtered"
	out.SHA256 = digest(raw)
	return out
}

// Evidence is the compatibility wrapper; sha now explicitly hashes stored text.
func Evidence(body []byte, includeSystem bool, maxBytes int) (text, state string, truncated bool, sha string) {
	e := CaptureEvidence(body, includeSystem, maxBytes)
	return e.Text, e.State, e.Truncated, e.SHA256
}

func mediaType(t string) bool {
	switch strings.ToLower(t) {
	case "image", "image_url", "input_image", "input_audio", "audio", "output_audio", "video", "input_video", "file", "input_file", "document":
		return true
	}
	return false
}
func sensitiveKey(key string) bool {
	switch key {
	case "system", "developer", "instructions", "systemInstruction", "system_instruction", "tool", "tools", "functions", "tool_result", "functionResponse", "function_response":
		return true
	}
	return false
}
func sensitiveType(t string) bool {
	switch t {
	case "tool_result", "function_call_output", "tool_output", "mcp_call_output", "custom_tool_call_output":
		return true
	}
	return false
}
func filterEvidence(value any, includeSystem bool, depth int) (any, bool) {
	switch v := value.(type) {
	case string:
		if looksLikeMedia(v) {
			return nil, false
		}
		return v, true
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			if clean, ok := filterEvidence(item, includeSystem, depth+1); ok {
				out = append(out, clean)
			}
		}
		return out, true
	case map[string]any:
		t, _ := v["type"].(string)
		role, _ := v["role"].(string)
		if mediaType(t) || (!includeSystem && (mapRole(role) == RoleSystem || mapRole(role) == RoleTool || sensitiveType(t))) {
			return nil, false
		}
		out := map[string]any{}
		for key, item := range v {
			if !includeSystem && sensitiveKey(key) {
				continue
			}
			// Identifier fields are harmless but media/source fields must not be retained.
			if skipKeys[key] && !oneOf(key, "role", "type", "model", "id", "name", "status", "index") {
				continue
			}
			if clean, ok := filterEvidence(item, includeSystem, depth+1); ok {
				out[key] = clean
			}
		}
		return out, true
	default:
		return value, true
	}
}

// FilterEvidenceMatches retains verdict metadata while removing unauthorized
// snippets, matches, paths and classifier-derived content. It never mutates input.
func FilterEvidenceMatches(matches []Match, captureBody, includeSystem bool) []Match {
	out := append([]Match(nil), matches...)
	for i := range out {
		m := &out[i]
		if !captureBody || (!includeSystem && !oneOf(m.Role, RoleUser, RoleAssistant)) || m.Source == "classifier" {
			m.Snippet = ""
			m.Matched = ""
			m.Path = ""
			m.Offset = 0
			m.Category = ""
		}
	}
	return out
}
