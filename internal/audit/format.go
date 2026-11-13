package audit

import (
	"bytes"
	"encoding/json"
)

// FormatJSON only changes whitespace outside strings. It never decodes numbers,
// combines duplicate keys, sorts fields or rewrites escapes. If indentation would
// exceed the retained-body budget, keep the complete original instead of dropping
// or truncating content. The caller validates UTF-8 and JSON before this helper.
func FormatJSON(source []byte, maxBytes int) []byte {
	if len(source) == 0 || maxBytes < len(source) || !json.Valid(source) {
		return source
	}
	return formatJSON(source, maxBytes, nil)
}

func formatJSON(source []byte, maxBytes int, budget *bodyWorkBudget) []byte {
	var out bytes.Buffer
	out.Grow(min(len(source)+len(source)/4, maxBytes))
	depth := 0
	space := func(c byte) bool { return c == ' ' || c == '\n' || c == '\r' || c == '\t' }
	appendBytes := func(value []byte) bool {
		if len(value) > maxBytes-out.Len() {
			return false
		}
		budget.spend(len(value))
		out.Write(value)
		return true
	}
	line := func() bool {
		if 1+depth*2 > maxBytes-out.Len() {
			return false
		}
		budget.spend(1 + depth*2)
		out.WriteByte('\n')
		for i := 0; i < depth; i++ {
			out.WriteString("  ")
		}
		return true
	}
	for i := 0; i < len(source); {
		budget.spend(1)
		c := source[i]
		if space(c) {
			i++
			continue
		}
		if c == '"' {
			start := i
			i++
			for i < len(source) {
				budget.spend(1)
				if source[i] == '\\' {
					i += 2
					continue
				}
				if source[i] == '"' {
					i++
					break
				}
				i++
			}
			if !appendBytes(source[start:i]) {
				return source
			}
			continue
		}
		switch c {
		case '{', '[':
			if !appendBytes(source[i : i+1]) {
				return source
			}
			depth++
			i++
			next := i
			for next < len(source) && space(source[next]) {
				budget.spend(1)
				next++
			}
			if next < len(source) && source[next] != '}' && source[next] != ']' {
				if !line() {
					return source
				}
			}
		case '}', ']':
			depth--
			previous := i - 1
			for previous >= 0 && space(source[previous]) {
				budget.spend(1)
				previous--
			}
			if previous >= 0 && source[previous] != '{' && source[previous] != '[' {
				if !line() {
					return source
				}
			}
			if !appendBytes(source[i : i+1]) {
				return source
			}
			i++
		case ',':
			if !appendBytes(source[i:i+1]) || !line() {
				return source
			}
			i++
		case ':':
			if !appendBytes([]byte(": ")) {
				return source
			}
			i++
		default:
			start := i
			for i < len(source) && !space(source[i]) && source[i] != ',' && source[i] != '}' && source[i] != ']' {
				budget.spend(1)
				i++
			}
			if !appendBytes(source[start:i]) {
				return source
			}
		}
	}
	return out.Bytes()
}
