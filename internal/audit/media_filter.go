package audit

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
)

// FilterRequestMedia replaces media payload values only. JSON must be valid;
// untouched lexical tokens, duplicate keys, numbers and escapes stay unchanged.
func FilterRequestMedia(source []byte) ([]byte, bool) {
	if !json.Valid(source) {
		return source, false
	}
	return filterRequestMedia(source, nil)
}

func filterRequestMedia(source []byte, budget *bodyWorkBudget) ([]byte, bool) {
	scan := mediaScanner{source: source, ends: make(map[int]int), budget: budget}
	scan.value(0, false, mediaRoot)
	if len(scan.patches) == 0 {
		return source, false
	}
	const marker = `"[OMITTED:media]"`
	var out bytes.Buffer
	out.Grow(min(len(source), 64<<10))
	previous := 0
	for _, patch := range scan.patches {
		budget.spend(patch.start - previous + len(marker))
		out.Write(source[previous:patch.start])
		out.WriteString(marker)
		previous = patch.end
	}
	budget.spend(len(source) - previous)
	out.Write(source[previous:])
	return out.Bytes(), true
}

type mediaPatch struct{ start, end int }
type mediaScanner struct {
	source  []byte
	patches []mediaPatch
	ends    map[int]int
	budget  *bodyWorkBudget
}

func (s *mediaScanner) whitespace(pos int) int {
	for pos < len(s.source) {
		s.budget.spend(1)
		switch s.source[pos] {
		case ' ', '\n', '\r', '\t':
			pos++
		default:
			return pos
		}
	}
	return pos
}
func (s *mediaScanner) stringEnd(pos int) int {
	pos++
	for pos < len(s.source) {
		s.budget.spend(1)
		if s.source[pos] == '\\' {
			pos += 2
			continue
		}
		if s.source[pos] == '"' {
			return pos + 1
		}
		pos++
	}
	return pos
}
func (s *mediaScanner) text(start, end int) string {
	s.budget.spend(end - start)
	if !bytes.ContainsRune(s.source[start+1:end-1], '\\') {
		return string(s.source[start+1 : end-1])
	}
	var value string
	_ = json.Unmarshal(s.source[start:end], &value)
	return value
}

var mediaFieldReplacer = strings.NewReplacer("_", "", "-", "", " ", "")

func mediaFieldKey(key string) string {
	return strings.ToLower(mediaFieldReplacer.Replace(key))
}
func heavyMediaField(key string) bool {
	switch mediaFieldKey(key) {
	case "imageurl", "imageurls", "image", "images", "base64", "b64json", "inputaudio", "audio", "audiourl", "audioinput", "audiooutput", "video", "videos", "videourl", "inlinedata", "filedata", "filecontent", "fileurl", "fileurls", "fileuri", "imagedata", "audiodata", "videodata":
		return true
	}
	return false
}

// Schema exemption is a path state, never inferred from payload keys such as
// enum/type/properties. Only protocol schema slots inherit it.
type mediaContext uint8

const (
	mediaOrdinary mediaContext = iota
	mediaRoot
	mediaTools
	mediaTool
	mediaFunctions
	mediaFunction
	mediaResponseFormat
	mediaJSONSchema
	mediaGenerationConfig
	mediaTextConfig
	mediaSchema
)

func schemaChild(parent mediaContext, key string) mediaContext {
	switch parent {
	case mediaRoot:
		switch key {
		case "tools":
			return mediaTools
		case "functions":
			return mediaFunctions
		case "response_format":
			return mediaResponseFormat
		case "generationConfig", "generation_config":
			return mediaGenerationConfig
		case "text":
			return mediaTextConfig
		}
	case mediaTool:
		switch key {
		case "function":
			return mediaFunction
		case "functionDeclarations", "function_declarations":
			return mediaFunctions
		case "parameters", "parametersJsonSchema", "parameters_json_schema", "input_schema":
			return mediaSchema
		}
	case mediaFunction:
		if key == "parameters" || key == "parametersJsonSchema" || key == "parameters_json_schema" {
			return mediaSchema
		}
	case mediaResponseFormat:
		if key == "json_schema" {
			return mediaJSONSchema
		}
		if key == "schema" {
			return mediaSchema
		}
	case mediaJSONSchema:
		if key == "schema" {
			return mediaSchema
		}
	case mediaGenerationConfig:
		if key == "responseSchema" || key == "response_schema" || key == "responseJsonSchema" || key == "response_json_schema" {
			return mediaSchema
		}
	case mediaTextConfig:
		if key == "format" {
			return mediaResponseFormat
		}
	}
	return mediaOrdinary
}
func mediaLocator(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return mediaDataURI(value) || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "file://") || strings.HasPrefix(value, "blob:")
}

// Decode only the locator prefix, including escaped characters and arbitrary
// leading whitespace. Never copy an entire escaped 10 MiB string to classify it.
func (s *mediaScanner) locatorPrefix(start, end int) string {
	var prefix [8]byte
	used := 0
	for pos := start + 1; pos < end-1 && used < len(prefix); {
		s.budget.spend(1)
		c := rune(s.source[pos])
		width := 1
		if c == '\\' && pos+1 < end-1 && s.source[pos+1] == '/' {
			c, width = '/', 2 // JSON permits \/; Go's UnquoteChar does not.
		} else if c == '\\' || c >= 128 {
			decoded, _, tail, err := strconv.UnquoteChar(string(s.source[pos:min(pos+12, end-1)]), '"')
			if err != nil {
				return ""
			}
			width = min(12, end-1-pos) - len(tail)
			c = decoded
		}
		pos += width
		if used == 0 && unicode.IsSpace(c) {
			continue
		}
		if c > 127 {
			return ""
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		prefix[used] = byte(c)
		used++
	}
	return string(prefix[:used])
}
func (s *mediaScanner) locatorAt(start, end int) bool {
	text := s.locatorPrefix(start, end)
	return strings.HasPrefix(text, "data:") || strings.HasPrefix(text, "https://") || strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "file://") || strings.HasPrefix(text, "blob:")
}
func (s *mediaScanner) dataURIAt(start, end int) bool {
	return strings.HasPrefix(s.locatorPrefix(start, end), "data:")
}
func encodedMedia(value string) bool {
	if len(value) < 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("+/=_-\r\n", c)) {
			return false
		}
	}
	return true
}
func (s *mediaScanner) payloadObject(pos int) bool {
	if s.source[pos] != '{' {
		return false
	}
	pos = s.whitespace(pos + 1)
	for pos < len(s.source) && s.source[pos] != '}' {
		keyEnd := s.stringEnd(pos)
		key := mediaFieldKey(s.text(pos, keyEnd))
		pos = s.whitespace(keyEnd)
		pos = s.whitespace(pos + 1)
		end := s.endValue(pos)
		if s.source[pos] == '"' {
			switch key {
			case "data", "base64", "b64json", "filedata", "bytes":
				if end-pos > 2 {
					return true
				}
			case "url", "uri", "fileuri":
				if s.locatorAt(pos, end) {
					return true
				}
			}
		}
		pos = s.whitespace(end)
		if pos < len(s.source) && s.source[pos] == ',' {
			pos = s.whitespace(pos + 1)
		}
	}
	return false
}
func (s *mediaScanner) removeFieldValue(key string, pos int, media bool) bool {
	if media && (key == "data" || key == "bytes") {
		return true
	}
	if media && (key == "url" || key == "uri") {
		return s.source[pos] == '"' && s.locatorAt(pos, s.stringEnd(pos))
	}
	if !heavyMediaField(key) {
		return false
	}
	if s.source[pos] == '"' {
		end := s.stringEnd(pos)
		if s.locatorAt(pos, end) {
			return true
		}
		value := s.text(pos, end)
		switch key {
		case "base64", "b64json", "filedata", "filecontent", "imagedata", "audiodata", "videodata":
			return true
		}
		return encodedMedia(value)
	}
	if s.source[pos] == '{' {
		return s.payloadObject(pos)
	}
	if s.source[pos] == '[' {
		index := s.whitespace(pos + 1)
		found := false
		for index < len(s.source) && s.source[index] != ']' {
			end := s.endValue(index)
			if s.source[index] == '"' {
				value := s.text(index, end)
				if !mediaLocator(value) && !encodedMedia(value) {
					return false
				}
			} else if !s.payloadObject(index) {
				return false
			}
			found = true
			index = s.whitespace(end)
			if index < len(s.source) && s.source[index] == ',' {
				index = s.whitespace(index + 1)
			}
		}
		return found
	}
	return false
}
func mediaBlockType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "image", "imageurl", "image_url", "input_image", "input_audio", "audio", "audio_url", "video", "video_url", "input_video", "file", "input_file", "document", "base64":
		return true
	}
	return false
}

// Cache container spans while scanning: late type fields must not cause each
// ancestor to rescan a long nested payload.
func (s *mediaScanner) endValue(pos int) int {
	pos = s.whitespace(pos)
	if pos >= len(s.source) {
		return pos
	}
	if end, ok := s.ends[pos]; ok {
		return end
	}
	if s.source[pos] == '"' {
		return s.stringEnd(pos)
	}
	if s.source[pos] != '{' && s.source[pos] != '[' {
		for pos < len(s.source) && s.source[pos] != ',' && s.source[pos] != '}' && s.source[pos] != ']' {
			s.budget.spend(1)
			switch s.source[pos] {
			case ' ', '\n', '\r', '\t':
				return pos
			}
			pos++
		}
		return pos
	}
	stack := make([]int, 0, 16)
	for pos < len(s.source) {
		s.budget.spend(1)
		switch s.source[pos] {
		case '"':
			pos = s.stringEnd(pos)
			continue
		case '{', '[':
			if end, ok := s.ends[pos]; ok {
				pos = end
				continue
			}
			stack = append(stack, pos)
		case '}', ']':
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			// Tiny spans are cheap to revisit and occur millions of times in dense
			// arrays. Do not build a map entry for every empty/small object.
			if pos+1-start >= 64 {
				s.ends[start] = pos + 1
			}
			if len(stack) == 0 {
				return pos + 1
			}
		}
		pos++
	}
	return pos
}
func (s *mediaScanner) objectIsMedia(pos int) bool {
	pos = s.whitespace(pos + 1)
	for pos < len(s.source) && s.source[pos] != '}' {
		keyStart := pos
		keyEnd := s.stringEnd(pos)
		key := mediaFieldKey(s.text(keyStart, keyEnd))
		pos = s.whitespace(keyEnd)
		pos = s.whitespace(pos + 1)
		end := s.endValue(pos)
		if key == "type" && s.source[pos] == '"' && mediaBlockType(s.text(pos, end)) {
			return true
		}
		pos = s.whitespace(end)
		if pos < len(s.source) && s.source[pos] == ',' {
			pos = s.whitespace(pos + 1)
		}
	}
	return false
}
func mediaDataURI(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 5 || !strings.EqualFold(value[:5], "data:") {
		return false
	}
	return strings.Contains(value, ",")
}
func (s *mediaScanner) value(pos int, inheritedMedia bool, context mediaContext) int {
	if context == mediaSchema {
		return s.endValue(pos)
	}
	pos = s.whitespace(pos)
	if pos >= len(s.source) {
		return pos
	}
	switch s.source[pos] {
	case '"':
		end := s.stringEnd(pos)
		if s.dataURIAt(pos, end) {
			s.patches = append(s.patches, mediaPatch{pos, end})
		}
		return end
	case '{':
		media := inheritedMedia || s.objectIsMedia(pos)
		pos = s.whitespace(pos + 1)
		for pos < len(s.source) && s.source[pos] != '}' {
			keyStart := pos
			keyEnd := s.stringEnd(pos)
			rawKey := s.text(keyStart, keyEnd)
			key := mediaFieldKey(rawKey)
			pos = s.whitespace(keyEnd)
			pos = s.whitespace(pos + 1)
			child := schemaChild(context, rawKey)
			remove := child != mediaSchema && s.removeFieldValue(key, pos, media)
			if remove {
				end := s.endValue(pos)
				s.patches = append(s.patches, mediaPatch{pos, end})
				pos = end
			} else {
				pos = s.value(pos, media && (key == "source" || key == "data" || key == "payload" || key == "file" || key == "files"), child)
			}
			pos = s.whitespace(pos)
			if pos < len(s.source) && s.source[pos] == ',' {
				pos = s.whitespace(pos + 1)
			}
		}
		return pos + 1
	case '[':
		pos = s.whitespace(pos + 1)
		for pos < len(s.source) && s.source[pos] != ']' {
			child := mediaOrdinary
			if context == mediaTools {
				child = mediaTool
			}
			if context == mediaFunctions {
				child = mediaFunction
			}
			pos = s.value(pos, inheritedMedia, child)
			pos = s.whitespace(pos)
			if pos < len(s.source) && s.source[pos] == ',' {
				pos = s.whitespace(pos + 1)
			}
		}
		return pos + 1
	default:
		return s.endValue(pos)
	}
}
