package authz

import (
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
)

// FilterModelCatalogJSON filters model catalog JSON payloads (e.g. from /v1/models)
// so that only models matching patterns are preserved.
// Supports:
//  1. OpenAI / Anthropic format: {"object":"list","data":[{...id...}]}
//  2. Codex / custom format:     {"models":[{...id|slug|name...}]}
//  3. Bare array:                [{...id|slug|name...}]
//
// If the payload is not a recognizable JSON model catalog, rawJSON is returned unmodified.
func FilterModelCatalogJSON(rawJSON []byte, patterns []string) ([]byte, bool) {
	if len(rawJSON) == 0 {
		return rawJSON, false
	}
	if len(patterns) == 0 {
		// No models allowed: return empty list structure matching original shape
		return emptyModelCatalogJSON(rawJSON)
	}

	trimmed := strings.TrimSpace(string(rawJSON))
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return rawJSON, false
	}

	// 1. Check for {"data": [...]}
	dataRes := gjson.GetBytes(rawJSON, "data")
	if dataRes.IsArray() {
		var root map[string]any
		if err := json.Unmarshal(rawJSON, &root); err != nil {
			return rawJSON, false
		}
		rawList, ok := root["data"].([]any)
		if !ok {
			return rawJSON, false
		}
		filteredList := make([]any, 0, len(rawList))
		for _, item := range rawList {
			if m, ok := item.(map[string]any); ok {
				id := extractModelIdentifier(m)
				if id != "" && AllowsModel(patterns, id) {
					filteredList = append(filteredList, m)
				}
			}
		}
		root["data"] = filteredList
		// Update Anthropic specific first_id and last_id if present
		if _, hasFirst := root["first_id"]; hasFirst {
			if len(filteredList) > 0 {
				root["first_id"] = extractModelIdentifier(filteredList[0].(map[string]any))
				root["last_id"] = extractModelIdentifier(filteredList[len(filteredList)-1].(map[string]any))
				root["has_more"] = false
			} else {
				root["first_id"] = nil
				root["last_id"] = nil
				root["has_more"] = false
			}
		}
		out, err := json.Marshal(root)
		if err != nil {
			return rawJSON, false
		}
		return out, true
	}

	// 2. Check for {"models": [...]}
	modelsRes := gjson.GetBytes(rawJSON, "models")
	if modelsRes.IsArray() {
		var root map[string]any
		if err := json.Unmarshal(rawJSON, &root); err != nil {
			return rawJSON, false
		}
		rawList, ok := root["models"].([]any)
		if !ok {
			return rawJSON, false
		}
		filteredList := make([]any, 0, len(rawList))
		for _, item := range rawList {
			if m, ok := item.(map[string]any); ok {
				id := extractModelIdentifier(m)
				if id != "" && AllowsModel(patterns, id) {
					filteredList = append(filteredList, m)
				}
			}
		}
		root["models"] = filteredList
		out, err := json.Marshal(root)
		if err != nil {
			return rawJSON, false
		}
		return out, true
	}

	// 3. Check for bare array: [{...}, {...}]
	parsed := gjson.ParseBytes(rawJSON)
	if parsed.IsArray() {
		var rawList []any
		if err := json.Unmarshal(rawJSON, &rawList); err != nil {
			return rawJSON, false
		}
		filteredList := make([]any, 0, len(rawList))
		for _, item := range rawList {
			if m, ok := item.(map[string]any); ok {
				id := extractModelIdentifier(m)
				if id != "" && AllowsModel(patterns, id) {
					filteredList = append(filteredList, m)
				}
			}
		}
		out, err := json.Marshal(filteredList)
		if err != nil {
			return rawJSON, false
		}
		return out, true
	}

	return rawJSON, false
}

func extractModelIdentifier(m map[string]any) string {
	for _, key := range []string{"id", "slug", "name", "model"} {
		if val, ok := m[key].(string); ok && strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func emptyModelCatalogJSON(rawJSON []byte) ([]byte, bool) {
	if gjson.GetBytes(rawJSON, "data").IsArray() {
		var root map[string]any
		if err := json.Unmarshal(rawJSON, &root); err == nil {
			root["data"] = []any{}
			if _, hasFirst := root["first_id"]; hasFirst {
				root["first_id"] = nil
				root["last_id"] = nil
				root["has_more"] = false
			}
			if out, err := json.Marshal(root); err == nil {
				return out, true
			}
		}
		return []byte(`{"object":"list","data":[]}`), true
	}
	if gjson.GetBytes(rawJSON, "models").IsArray() {
		var root map[string]any
		if err := json.Unmarshal(rawJSON, &root); err == nil {
			root["models"] = []any{}
			if out, err := json.Marshal(root); err == nil {
				return out, true
			}
		}
		return []byte(`{"models":[]}`), true
	}
	if gjson.ParseBytes(rawJSON).IsArray() {
		return []byte(`[]`), true
	}
	return rawJSON, false
}
