package contentguard

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Segment is one piece of request text with its conversational role and the
// JSON location it was read from. Text is the decoded original string.
type Segment struct {
	Role string `json:"role"`
	Path string `json:"path"`
	Text string `json:"-"`
}

// skipKeys never carry conversational text: identifiers, media payloads,
// cache hints and signatures. Skipping them avoids scanning Base64 media.
var skipKeys = map[string]bool{
	"role": true, "type": true, "id": true, "tool_use_id": true, "call_id": true, "tool_call_id": true, "name": true,
	"image_url": true, "url": true, "data": true, "inline_data": true, "inlineData": true,
	"file_data": true, "fileData": true, "file_id": true, "file_url": true, "source": true, "media_type": true,
	"mime_type": true, "mimeType": true, "b64_json": true, "cache_control": true, "signature": true,
	"image": true, "audio": true, "input_audio": true, "video": true, "detail": true, "format": true,
	"model": true, "status": true, "index": true,
}

func mapRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "system", "developer":
		return RoleSystem
	case "assistant", "model":
		return RoleAssistant
	case "tool", "function", "ipython":
		return RoleTool
	default:
		return RoleUser
	}
}

// looksLikeMedia reports base64/data-URL payloads that only waste scan budget.
func looksLikeMedia(value string) bool {
	if strings.HasPrefix(value, "data:") && strings.Contains(value[:min(len(value), 256)], ";base64,") {
		return true
	}
	return false
}

type extractor struct {
	segments []Segment
	budget   int
}

func (x *extractor) add(role, path, text string) {
	if text == "" || x.budget <= 0 || len(x.segments) >= MaxSegments || looksLikeMedia(text) {
		return
	}
	if len(text) > x.budget {
		cut := x.budget
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut]
	}
	x.budget -= len(text)
	x.segments = append(x.segments, Segment{Role: role, Path: path, Text: text})
}

func child(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
func index(path string, i int) string { return path + "[" + strconv.Itoa(i) + "]" }

// collect walks any JSON value inside a message and records every string except
// identifier/media fields. depth bounds pathological nesting.
func (x *extractor) collect(value any, path, role string, depth int) {
	if depth > 64 || x.budget <= 0 {
		return
	}
	switch v := value.(type) {
	case string:
		x.add(role, path, v)
	case []any:
		for i, item := range v {
			x.collect(item, index(path, i), role, depth+1)
		}
	case map[string]any:
		if t, _ := v["type"].(string); mediaType(t) {
			return
		}
		blockRole := role
		if r, ok := v["role"].(string); ok && role != RoleSystem && role != RoleTool {
			blockRole = mapRole(r)
		}
		if t, _ := v["type"].(string); t != "" && blockRole != RoleSystem && blockRole != RoleTool {
			switch t {
			case "tool_result", "function_call_output", "tool_output", "mcp_call_output", "custom_tool_call_output":
				blockRole = RoleTool
			case "tool_use", "function_call", "tool_call", "reasoning", "thinking":
				blockRole = RoleAssistant
			}
		}
		for _, key := range sortedKeys(v) {
			if skipKeys[key] {
				continue
			}
			itemRole := blockRole
			switch key {
			case "system", "developer", "instructions", "systemInstruction", "system_instruction":
				itemRole = RoleSystem
			case "functionResponse", "function_response", "tool_result", "tool", "tools", "functions":
				itemRole = RoleTool
			case "functionCall", "function_call", "tool_calls":
				itemRole = RoleAssistant
			}
			if blockRole == RoleSystem || blockRole == RoleTool {
				itemRole = blockRole
			}
			x.collect(v[key], child(path, key), itemRole, depth+1)
		}
	}
}

func sortedKeys(v map[string]any) []string {
	keys := make([]string, 0, len(v))
	for key := range v {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (x *extractor) messages(list []any, path string) {
	for i, item := range list {
		itemPath := index(path, i)
		switch msg := item.(type) {
		case string:
			x.add(RoleUser, itemPath, msg)
		case map[string]any:
			if kind, _ := msg["type"].(string); mediaType(kind) {
				continue
			}
			role := RoleUser
			if r, ok := msg["role"].(string); ok {
				role = mapRole(r)
			} else if t, _ := msg["type"].(string); t != "" {
				switch t {
				case "function_call_output", "tool_result", "custom_tool_call_output":
					role = RoleTool
				case "function_call", "reasoning", "custom_tool_call":
					role = RoleAssistant
				}
			}
			for _, key := range sortedKeys(msg) {
				if key == "role" || skipKeys[key] {
					continue
				}
				x.collect(msg[key], child(itemPath, key), role, 1)
			}
		}
	}
}

// Extract returns the text segments of an OpenAI Chat/Responses, Anthropic,
// Gemini or legacy completion request. Unknown JSON falls back to every
// non-identifier string as user text. Invalid, duplicate, oversized or deeply
// nested JSON returns parsed=false and no segments; never scan an unchecked prefix.
func Extract(body []byte, budget int) (segments []Segment, parsed bool) {
	if budget <= 0 || len(body) > min(budget, MaxInputBytes) {
		return nil, false
	}
	x := &extractor{budget: budget}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, true
	}
	root, err := decodeJSON(trimmed, budget)
	if err != nil {
		return nil, false
	}
	switch v := root.(type) {
	case []any:
		x.messages(v, "$")
	case map[string]any:
		known := false
		for _, key := range []string{"system", "instructions", "systemInstruction", "system_instruction"} {
			if value, ok := v[key]; ok {
				known = true
				x.collect(value, key, RoleSystem, 1)
			}
		}
		for _, key := range []string{"tool", "tools", "functions", "tool_result", "functionResponse"} {
			if value, ok := v[key]; ok {
				known = true
				x.collect(value, key, RoleTool, 1)
			}
		}
		for _, key := range []string{"messages", "contents"} {
			if list, ok := v[key].([]any); ok {
				known = true
				x.messages(list, key)
			}
		}
		switch input := v["input"].(type) {
		case string:
			known = true
			x.add(RoleUser, "input", input)
		case []any:
			known = true
			x.messages(input, "input")
		}
		switch prompt := v["prompt"].(type) {
		case string:
			known = true
			x.add(RoleUser, "prompt", prompt)
		case []any:
			known = true
			x.collect(prompt, "prompt", RoleUser, 1)
		}
		if !known {
			x.collect(v, "", RoleUser, 0)
		}
	default:
		return nil, false
	}
	if len(x.segments) >= MaxSegments {
		return nil, false
	}
	return x.segments, true
}

// normalized holds a folded copy of a text plus a byte-offset map back to the
// original, so snippets show exactly what the client sent.
type normalized struct {
	text   string
	origin []int // origin[i] is the original byte offset of normalized byte i; len = len(text)+1
}

func foldRune(r rune) (rune, bool) {
	switch {
	case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF || r == 0x00AD || r == 0x180E:
		return 0, false
	case r == 0x3000:
		return ' ', true
	case r >= 0xFF01 && r <= 0xFF5E:
		r = r - 0xFF01 + 0x21
	}
	if unicode.IsSpace(r) {
		return ' ', true
	}
	return unicode.ToLower(r), true
}

// Normalize folds case, full-width ASCII, zero-width characters and whitespace
// runs. Patterns and scanned text use the same folding.
func Normalize(value string) string { return normalize(value).text }

func normalize(value string) normalized {
	var out strings.Builder
	out.Grow(len(value))
	origin := make([]int, 0, len(value)+1)
	lastSpace := true
	for offset, r := range value {
		folded, keep := foldRune(r)
		if !keep {
			continue
		}
		if folded == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		start := out.Len()
		out.WriteRune(folded)
		for i := start; i < out.Len(); i++ {
			origin = append(origin, offset)
		}
	}
	text := out.String()
	// Trim one trailing collapsed space.
	if strings.HasSuffix(text, " ") {
		text = text[:len(text)-1]
		origin = origin[:len(origin)-1]
	}
	origin = append(origin, len(value))
	return normalized{text: text, origin: origin}
}

// originalSpan maps a normalized [start,end) range back to the original text.
func (n normalized) originalSpan(start, end int) (int, int) {
	if start < 0 {
		start = 0
	}
	if end > len(n.text) {
		end = len(n.text)
	}
	// Matches end on rune boundaries, so origin[end] is the original offset of
	// the next retained rune (or the end of the original text).
	return n.origin[start], n.origin[end]
}
