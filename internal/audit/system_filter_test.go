package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSystemMessageFilteringPreservesOtherRolesAndMessageOrder(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"system","content":"SYSTEM-SECRET"},{"role":"user","content":"用户提问"},{"content":"SECOND-SYSTEM","role":"system"},{"role":"assistant","content":"reply"},{"role":"developer","content":"keep-developer"},{"role":"tool","content":"keep-tool"}],"model":"m"}`)
	result := CaptureRawJSON(raw, "application/json", "", MaxRequestBodyBytes)
	if result.State != "stored_raw_system_filtered" || result.Truncated || !json.Valid([]byte(result.Body)) {
		t.Fatalf("bad filtered body: %s", result.State)
	}
	for _, secret := range []string{"SYSTEM-SECRET", "SECOND-SYSTEM", "keep-developer", "keep-tool"} {
		if strings.Contains(result.Body, secret) {
			t.Fatal("system content retained")
		}
	}
	var saved struct {
		Messages []struct {
			Role    string
			Content string
		}
	}
	if err := json.Unmarshal([]byte(result.Body), &saved); err != nil {
		t.Fatal(err)
	}
	want := []string{"user", "assistant"}
	if len(saved.Messages) != len(want) {
		t.Fatal("wrong remaining messages")
	}
	for i, role := range want {
		if saved.Messages[i].Role != role {
			t.Fatal("non-system order changed")
		}
	}
	sum := sha256.Sum256([]byte(result.Body))
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("hash mismatch")
	}
}

func TestSystemMessageFilterAllCommaBoundariesAndEscapes(t *testing.T) {
	system := `{"role":"system","content":"drop"}`
	user := `{"role":"user","content":"keep"}`
	for _, items := range [][]string{{system}, {system, system}, {system, user}, {user, system}, {system, user, system}, {user, system, system, user}, {system, system, user, user, system, system}} {
		raw := []byte(`{"messages":[ ` + strings.Join(items, " , ") + " ],\"same\":1,\"same\":2}")
		filtered, changed := FilterSystemMessages(raw)
		if !changed || !json.Valid(filtered) || bytes.Contains(filtered, []byte("drop")) {
			t.Fatalf("invalid deletion: %s", filtered)
		}
		if !bytes.Contains(filtered, []byte(`"same":1,"same":2`)) {
			t.Fatal("duplicate unrelated fields changed")
		}
	}
	escaped := []byte(`{"input":[{"r\u006fle":"s\u0079stem","content":"escaped-system"},{"role":"user","content":"keep"}]}`)
	filtered, changed := FilterSystemMessages(escaped)
	if !changed || bytes.Contains(filtered, []byte("escaped-system")) || !json.Valid(filtered) {
		t.Fatal("escaped role not filtered")
	}
}

func TestSystemFilteringIsScopedToMessageCollectionsAndDoesNotModifyInput(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"user","content":"literal role system text"}],"business":{"role":"system","content":"keep-business"},"tools":[{"type":"function","function":{"parameters":{"properties":{"messages":{"default":[{"role":"system","content":"keep-schema"}]}}}}}],"big":9007199254740993123456789}`)
	original := append([]byte(nil), raw...)
	filtered, changed := FilterSystemMessages(raw)
	if changed || !bytes.Equal(filtered, raw) || !bytes.Equal(raw, original) {
		t.Fatal("non-message content changed")
	}
	mixed := []byte(`{"messages":[{"role":"system","content":"drop-before-media"},{"role":"user","content":[{"type":"text","text":"keep-text"},{"type":"image_url","image_url":{"url":"data:image/png;base64,PRIVATE-MEDIA"}}]}]}`)
	copied := append([]byte(nil), mixed...)
	result := CaptureRawJSON(mixed, "application/json", "", MaxRequestBodyBytes)
	if result.State != "stored_raw_system_media_filtered" || strings.Contains(result.Body, "PRIVATE-MEDIA") || strings.Contains(result.Body, "drop-before-media") || !strings.Contains(result.Body, "keep-text") {
		t.Fatal("combined filtering failed")
	}
	if !bytes.Equal(mixed, copied) {
		t.Fatal("audit filtering changed upstream input")
	}
}

func FuzzSystemMessageFilterKeepsValidJSON(f *testing.F) {
	for _, raw := range []string{`{"messages":[{"role":"system"},{"role":"user"}]}`, `[{"role":"system"}]`, `{"input":[{"role":"user","content":"hi"}]}`} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 65536 || !json.Valid([]byte(raw)) {
			return
		}
		source := []byte(raw)
		before := append([]byte(nil), source...)
		filtered, _ := FilterSystemMessages(source)
		if !json.Valid(filtered) || !bytes.Equal(source, before) {
			t.Fatal("invalid output or modified source")
		}
	})
}

func TestDeveloperFilteringDoesNotInterpretNestedBusinessCollections(t *testing.T) {
	raw := []byte(`{"wrapper":{"messages":[{"content":"DROP-DEVELOPER","role":"developer"},{"role":"user","content":"literal role developer remains"}]},"input":[{"role":"developer","content":"DROP-INPUT"},{"role":"assistant","content":"keep"}],"business":{"role":"developer","content":"keep-business"}}`)
	filtered, changed := FilterSystemMessages(raw)
	if !changed || !json.Valid(filtered) || !bytes.Contains(filtered, []byte("DROP-DEVELOPER")) || bytes.Contains(filtered, []byte("DROP-INPUT")) {
		t.Fatalf("root developer not filtered or nested business changed: %s", filtered)
	}
	for _, text := range []string{"literal role developer remains", "keep-business"} {
		if !bytes.Contains(filtered, []byte(text)) {
			t.Fatal("non-message field changed")
		}
	}
}

func TestToolRoleFilteredOnlyAtRootMessagesAndNeverToolDefinitions(t *testing.T) {
	user := `{"role":"user","content":"USER-KEPT"}`
	tool := `{"role":"tool","tool_call_id":"SECRET-CALL-ID","content":"TOOL-RESULT-REMOVED"}`
	for _, key := range []string{"messages", "input", "contents"} {
		for _, items := range [][]string{{tool}, {tool, user}, {user, tool}, {tool, user, tool}, {user, tool, tool, user}} {
			raw := []byte("{\"" + key + "\":[" + strings.Join(items, ",") + "],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"tool-name-kept\"}}],\"business\":{\"role\":\"tool\",\"content\":\"business-kept\"}}")
			before := append([]byte(nil), raw...)
			filtered, changed := FilterSystemMessages(raw)
			if !changed || !json.Valid(filtered) || !bytes.Equal(raw, before) || bytes.Contains(filtered, []byte("TOOL-RESULT-REMOVED")) || bytes.Contains(filtered, []byte("SECRET-CALL-ID")) {
				t.Fatalf("tool content not removed safely: %s", filtered)
			}
			if !bytes.Contains(filtered, []byte("tool-name-kept")) || !bytes.Contains(filtered, []byte("business-kept")) {
				t.Fatal("tool definition or business content changed")
			}
		}
	}
	escaped := []byte(`[{"content":"escaped-tool-removed","role":"tool"},{"role":"assistant","tool_calls":[{"id":"call-kept","type":"function","function":{"name":"lookup","arguments":"{}"}}]}]`)
	filtered, changed := FilterSystemMessages(escaped)
	if !changed || !json.Valid(filtered) || bytes.Contains(filtered, []byte("escaped-tool-removed")) || !bytes.Contains(filtered, []byte("call-kept")) {
		t.Fatal("escaped root tool filtering or assistant call retention failed")
	}
}

func TestRoleFilterDenseScalarArraysUseBoundedAllocations(t *testing.T) {
	raw := []byte("{\"messages\":[" + strings.Repeat("null,", 200000) + "null]}")
	allocations := testing.AllocsPerRun(2, func() {
		filtered, changed := FilterSystemMessages(raw)
		if changed || !bytes.Equal(filtered, raw) {
			t.Fatal("dense ordinary array changed")
		}
	})
	if allocations > 64 {
		t.Fatalf("per-element allocation returned: %f", allocations)
	}
}

func TestToolRoleUnicodeEscapesAndDuplicateRoleCannotBypassFiltering(t *testing.T) {
	raw := []byte(`{"messages":[{"r\u006fle":"t\u006fol","content":"escaped-drop"},{"role":"user","role":"tool","content":"duplicate-drop"},{"role":"assistant","content":"keep"}]}`)
	filtered, changed := FilterSystemMessages(raw)
	if !changed || !json.Valid(filtered) || bytes.Contains(filtered, []byte("escaped-drop")) || bytes.Contains(filtered, []byte("duplicate-drop")) || !bytes.Contains(filtered, []byte("keep")) {
		t.Fatalf("escaped role filtering failed: %s", filtered)
	}
}
