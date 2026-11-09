package audit

import (
	"bytes"
	"encoding/json"
	"sort"
)

// FilterSystemMessages removes complete system/developer/tool messages only from request message
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
		if key == "role" && s.source[pos] == '"' && (s.text(pos, end) == "system" || s.text(pos, end) == "developer" || s.text(pos, end) == "tool") {
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
		// Track only removal runs; a dense 10 MiB array must not allocate one
		// bookkeeping struct for every scalar/message that will be retained.
		current := s.whitespace(pos + 1)
		previousEnd := -1
		runStart, runEnd, runPrevious := -1, 0, -1
		for current < len(s.source) && s.source[current] != ']' {
			childEnd := s.endValue(current)
			if messages && s.isSystem(current) {
				if runStart < 0 {
					runStart = current
					runPrevious = previousEnd
				}
				runEnd = childEnd
			} else {
				if runStart >= 0 {
					s.removals = append(s.removals, mediaPatch{start: runStart, end: current})
					runStart = -1
				}
				previousEnd = childEnd
			}
			current = s.whitespace(childEnd)
			if current < len(s.source) && s.source[current] == ',' {
				current = s.whitespace(current + 1)
			}
		}
		if runStart >= 0 {
			start := runStart
			if runPrevious >= 0 {
				start = runPrevious
			}
			s.removals = append(s.removals, mediaPatch{start: start, end: runEnd})
		}

	}
	return end
}
