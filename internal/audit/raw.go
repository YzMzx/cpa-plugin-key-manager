package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"strings"
	"unicode/utf8"
)

// CaptureRawJSON retains plaintext JSON with readable two-space indentation.
// Non-media values, credential strings, number lexemes, duplicate keys and escape
// sequences are unchanged. Media/file payload values use a small omission marker. If formatting exceeds the budget, the complete original is kept.
// Headers are never passed here; compression and binary data are not decoded.
// This helper has a deterministic scan-work budget. Production callers also use
// BodyCaptureBudget for nonblocking capacity and a cooperative elapsed-time limit.
func CaptureRawJSON(body []byte, contentType, contentEncoding string, maxBytes int) BodyResult {
	return captureRawJSON(body, contentType, contentEncoding, maxBytes, newBodyWorkBudget())
}

func captureRawJSON(body []byte, contentType, contentEncoding string, maxBytes int, budget *bodyWorkBudget) (result BodyResult) {
	defer func() {
		if failure := recover(); failure != nil {
			if _, ok := failure.(bodyBudgetExceeded); !ok {
				panic(failure)
			}
			result = BodyResult{State: "omitted_processing_limit", Truncated: true}
		}
	}()
	if len(body) == 0 {
		return BodyResult{State: "empty"}
	}
	if maxBytes <= 0 {
		return BodyResult{State: "omitted_disabled"}
	}
	if maxBytes > MaxRequestBodyBytes {
		maxBytes = MaxRequestBodyBytes
	}
	if len(body) > maxBytes {
		return BodyResult{State: "omitted_input_limit", Truncated: true}
	}
	if encoding := strings.TrimSpace(contentEncoding); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return BodyResult{State: "omitted_encoding"}
	}
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil || (!strings.EqualFold(media, "application/json") && !(strings.HasPrefix(strings.ToLower(media), "application/") && strings.HasSuffix(strings.ToLower(media), "+json"))) {
		return BodyResult{State: "omitted_non_json"}
	}
	budget.spend(2 * len(body))
	if !utf8.Valid(body) || !json.Valid(body) {
		return BodyResult{State: "omitted_invalid_json"}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return BodyResult{State: "omitted_non_container"}
	}
	withoutSystem, systemFiltered := filterSystemMessages(body, budget)
	filtered, mediaFiltered := filterRequestMedia(withoutSystem, budget)
	// Never fall back to an unfiltered payload if explanatory markers grow output.
	if len(filtered) > maxBytes {
		return BodyResult{State: "omitted_output_limit", Truncated: true}
	}
	formatted := formatJSON(filtered, maxBytes, budget)
	budget.spend(len(formatted))
	hash := sha256.Sum256(formatted)
	state := "stored_raw"
	if systemFiltered && mediaFiltered {
		state = "stored_raw_system_media_filtered"
	} else if systemFiltered {
		state = "stored_raw_system_filtered"
	} else if mediaFiltered {
		state = "stored_raw_media_filtered"
	}
	result = BodyResult{Body: string(formatted), State: state, SHA256: hex.EncodeToString(hash[:])}
	budget.checkDeadline()
	return result
}
