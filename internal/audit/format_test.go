package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatJSONIndentPreservesDuplicateKeysOrderAndNumbers(t *testing.T) {
	raw := []byte(` {"z":900719925474099312345678901234567890,"duplicate":1,"duplicate":2,"decimal":1.23000e+99,"negative":-0,"escaped":"\u4f60\u597d","punctuation":"a,{[\"x\"]}:","nested":[true,null,{"x":"plain-secret"}],"empty":{}} `)
	result := FormatJSON(raw, MaxRequestBodyBytes)
	if !json.Valid(result) || !bytes.Contains(result, []byte("\n  \"z\":")) {
		t.Fatalf("not formatted: %s", result)
	}
	var before, after bytes.Buffer
	if json.Compact(&before, raw) != nil || json.Compact(&after, result) != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("formatter changed JSON tokens")
	}
	if !bytes.Equal(FormatJSON(result, MaxRequestBodyBytes), result) {
		t.Fatal("format is not idempotent")
	}
	captured := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
	if captured.Body != string(result) || captured.State != "stored_raw" {
		t.Fatal("capture did not save formatted JSON")
	}
	sum := sha256.Sum256(result)
	if captured.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("saved hash mismatch")
	}
}

func TestFormatJSONBoundsNeverDropOrTruncateBody(t *testing.T) {
	raw := []byte(`{"list":[` + strings.Repeat("0,", 300) + `1]}`)
	got := CaptureRawJSON(raw, "application/json", "", len(raw))
	if got.State != "stored_raw" || got.Body != string(raw) || got.Truncated {
		t.Fatal("formatting expansion dropped a valid body")
	}
	source := []byte(`{"safe":"hello"}`)
	if !bytes.Equal(FormatJSON(source, len(source)-1), source) {
		t.Fatal("explicit lower budget altered input")
	}
	invalid := []byte(`{"broken":`)
	if !bytes.Equal(FormatJSON(invalid, 1024), invalid) {
		t.Fatal("formatter rewrote invalid source")
	}
	deep := []byte(`{"deep":` + strings.Repeat("[", 100) + "0" + strings.Repeat("]", 100) + `}`)
	if formatted := FormatJSON(deep, MaxRequestBodyBytes); !json.Valid(formatted) {
		t.Fatal("deep JSON invalid")
	}
}
