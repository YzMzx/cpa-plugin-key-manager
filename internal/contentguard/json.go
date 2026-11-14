package contentguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	MaxInputBytes = 10 << 20
	MaxJSONDepth  = 64
	MaxJSONNodes  = 32768
	MaxSegments   = 4096
)

var errJSON = errors.New("invalid or over-budget JSON")

// decodeJSON rejects duplicate fields (including escaped aliases), trailing
// values, invalid UTF-8 and excessive depth/node counts before extraction.
// The input byte ceiling also bounds strings skipped as media.
func decodeJSON(body []byte, budget int) (any, error) {
	if budget <= 0 || len(body) > min(budget, MaxInputBytes) || !utf8.Valid(body) {
		return nil, errJSON
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	nodes := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		nodes++
		if depth > MaxJSONDepth || nodes > MaxJSONNodes {
			return nil, errJSON
		}
		token, err := d.Token()
		if err != nil {
			return nil, errJSON
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delim {
		case '{':
			out := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, errJSON
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > 256 {
					return nil, errJSON
				}
				if _, exists := out[key]; exists {
					return nil, errJSON
				}
				item, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				out[key] = item
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errJSON
			}
			return out, nil
		case '[':
			out := []any{}
			for d.More() {
				item, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				out = append(out, item)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errJSON
			}
			return out, nil
		}
		return nil, errJSON
	}
	root, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errJSON
	}
	return root, nil
}
