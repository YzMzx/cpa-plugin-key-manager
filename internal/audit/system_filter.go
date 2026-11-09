package audit

import (
	"bytes"
	"encoding/json"
	"sort"
)

// FilterSystemMessages removes complete system/developer messages only from request message
// root collections (messages/input/contents or a root array). Tool schemas and ordinary
// business objects are not interpreted as conversation messages. Input is read-only.
func FilterSystemMessages(source []byte) ([]byte, bool) {
	if !json.Valid(source) {
		return source, false
	}
	scan := systemMessageScanner{mediaScanner: mediaScanner{source: source, ends: make(map[int]int)}}
	start := scan.whitespace(0)
	scan.walk(start, start < len(source) && source[start] == '[', false)
	if len(scan.removals) == 0 {
		return source, false
	}
	sort.Slice(scan.removals, func(i, j int) bool { return scan.removals[i].start < scan.removals[j].start })
	var out bytes.Buffer
	out.Grow(len(source))
	previous := 0
	for _, patch := range scan.removals {
		out.Write(source[previous:patch.start])
		previous = patch.end
	}
	out.Write(source[previous:])
	return out.Bytes(), true
}

type systemMessageScanner struct {
	mediaScanner
	removals []mediaPatch
}

func (s *systemMessageScanner) isSystem(pos int) bool {
	if s.source[pos] != '{' {
		return false
	}
	pos = s.whitespace(pos + 1)
	for pos < len(s.source) && s.source[pos] != '}' {
		keyEnd := s.stringEnd(pos)
		key := s.text(pos, keyEnd)
		pos = s.whitespace(keyEnd)
		pos = s.whitespace(pos + 1)
		end := s.endValue(pos)
		if key == "role" && s.source[pos] == '"' && (s.text(pos, end) == "system" || s.text(pos, end) == "developer") {
			return true
		}
		pos = s.whitespace(end)
		if pos < len(s.source) && s.source[pos] == ',' {
			pos = s.whitespace(pos + 1)
		}
	}
	return false
}
func (s *systemMessageScanner) walk(pos int, messages, schema bool) int {
	pos = s.whitespace(pos)
	end := s.endValue(pos)
	if schema {
		return end
	}
	switch s.source[pos] {
	case '{':
		current := s.whitespace(pos + 1)
		for current < len(s.source) && s.source[current] != '}' {
			keyEnd := s.stringEnd(current)
			key := s.text(current, keyEnd)
			current = s.whitespace(keyEnd)
			current = s.whitespace(current + 1)
			childMessages := key == "messages" || key == "input" || key == "contents"
			if childMessages && s.source[current] == '[' {
				current = s.whitespace(s.walk(current, true, false))
			} else {
				current = s.whitespace(s.endValue(current))
			}
			if current < len(s.source) && s.source[current] == ',' {
				current = s.whitespace(current + 1)
			}
		}
	case '[':
		type element struct {
			start, end int
			remove     bool
		}
		var elements []element
		current := s.whitespace(pos + 1)
		for current < len(s.source) && s.source[current] != ']' {
			childEnd := s.endValue(current)
			remove := messages && s.isSystem(current)
			elements = append(elements, element{current, childEnd, remove})
			current = s.whitespace(childEnd)
			if current < len(s.source) && s.source[current] == ',' {
				current = s.whitespace(current + 1)
			}
		}
		for i := 0; i < len(elements); {
			if !elements[i].remove {
				i++
				continue
			}
			j := i
			for j+1 < len(elements) && elements[j+1].remove {
				j++
			}
			start, finish := elements[i].start, elements[j].end
			if j+1 < len(elements) {
				finish = elements[j+1].start
			} else if i > 0 {
				start = elements[i-1].end
			}
			s.removals = append(s.removals, mediaPatch{start: start, end: finish})
			i = j + 1
		}
	}
	return end
}
