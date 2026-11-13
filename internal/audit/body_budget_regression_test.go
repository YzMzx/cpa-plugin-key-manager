package audit

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMediaSchemaSpoofCannotHidePayload(t *testing.T) {
	for _, raw := range []string{
		`{"contents":[{"parts":[{"inlineData":{"enum":[],"mimeType":"image/png","data":"HIDDEN-PAYLOAD"}}]}]}`,
		`{"image_url":{"type":"object","url":"https://private/HIDDEN-PAYLOAD"}}`,
		`{"payload":{"properties":{"image_url":{"url":"https://private/HIDDEN-PAYLOAD"}}}}`,
		`{"to_ols":[{"function":{"parameters":{"image_url":"https://private/HIDDEN-PAYLOAD"}}}]}`,
		`{"messages":[{"content":{"tools":[{"function":{"parameters":{"image_url":"https://private/HIDDEN-PAYLOAD"}}}]}}]}`,
		`{"tools":[{"function":{"para_meters":{"image_url":"https://private/HIDDEN-PAYLOAD"}}}]}`,
	} {
		r := CaptureRawJSON([]byte(raw), "application/json", "", MaxRequestBodyBytes)
		if strings.Contains(r.Body, "HIDDEN-PAYLOAD") || r.State != "stored_raw_media_filtered" {
			t.Fatalf("schema spoof retained media: %s", r.Body)
		}
	}
}

func TestMediaSchemaContextPreservesLexicalDefinitions(t *testing.T) {
	raw := []byte(`{"tools":[{"type":"function","function":{"parameters":{"properties":{"image":{"default":"data:image/png;base64,SCHEMA-EXAMPLE","enum":["https://schema/example"]},"base64":{"const":"SCHEMA-CONST"}},"n":1.2300e+99,"dup":1,"dup":2}}}],"image_url":"https://private/HIDDEN-PAYLOAD"}`)
	got, changed := FilterRequestMedia(raw)
	want := bytes.Replace(raw, []byte(`"https://private/HIDDEN-PAYLOAD"`), []byte(`"[OMITTED:media]"`), 1)
	if !changed || !bytes.Equal(got, want) {
		t.Fatalf("tool schema lexical tokens changed: %s", got)
	}
}

func TestMediaLocatorJSONEscapedSlashes(t *testing.T) {
	for _, raw := range []string{
		`{"image_url":"https:\/\/private/HIDDEN-PAYLOAD"}`,
		`{"image_url":"https\u003a\/\/private/HIDDEN-PAYLOAD"}`,
		`{"custom":"data:image\/png;base64,HIDDEN-PAYLOAD"}`,
	} {
		got, changed := FilterRequestMedia([]byte(raw))
		if !changed || bytes.Contains(got, []byte("HIDDEN-PAYLOAD")) {
			t.Fatalf("JSON escapes bypassed media filter: %s", got)
		}
	}
}

func TestMediaProtocolSchemaPathsStayLexical(t *testing.T) {
	for _, raw := range []string{
		`{"tools":[{"input_schema":{"base64":"schema-example","image_url":"https://example/schema"}}]}`,
		`{"tools":[{"parameters":{"base64":"schema-example"}}]}`,
		`{"tools":[{"functionDeclarations":[{"parameters":{"base64":"schema-example"}}]}]}`,
		`{"functions":[{"parameters":{"base64":"schema-example"}}]}`,
		`{"response_format":{"json_schema":{"schema":{"base64":"schema-example"}}}}`,
		`{"generationConfig":{"responseSchema":{"base64":"schema-example"}}}`,
		`{"text":{"format":{"schema":{"base64":"schema-example"}}}}`,
	} {
		got, changed := FilterRequestMedia([]byte(raw))
		if changed || string(got) != raw {
			t.Fatalf("protocol schema changed: %s", got)
		}
	}
}

func TestMediaDenseSmallObjectsAllocationBudget(t *testing.T) {
	raw := []byte("[" + strings.Repeat(`{"k":"v"},`, (1<<20)/10-1) + `{"k":"v"}]`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, changed := FilterRequestMedia(raw)
	runtime.ReadMemStats(&after)
	if changed || !bytes.Equal(got, raw) || !json.Valid(got) {
		t.Fatal("business data changed")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("1 MiB small objects allocated %d bytes; budget 64 MiB", allocated)
	}
}

func TestMediaLocatorLongWhitespaceAndEscapedPrefix(t *testing.T) {
	for _, prefix := range []string{strings.Repeat(" ", 512), strings.Repeat(`\u0020`, 300), ""} {
		raw := []byte(`{"image_url":"` + prefix + `https://private/HIDDEN-PAYLOAD","text":"safe"}`)
		got, changed := FilterRequestMedia(raw)
		if !changed || bytes.Contains(got, []byte("HIDDEN-PAYLOAD")) || !bytes.Contains(got, []byte("safe")) {
			t.Fatal("locator bypassed bounded prefix detection")
		}
	}
	raw := []byte(`{"image_url":"\u0068ttps://private/` + strings.Repeat("PAYLOAD", 100000) + `"}`)
	scan := mediaScanner{source: raw}
	start := bytes.Index(raw, []byte(`"\u0068`))
	allocations := testing.AllocsPerRun(10, func() {
		if !scan.locatorAt(start, len(raw)-1) {
			t.Fatal("escaped locator not detected")
		}
	})
	if allocations > 2 {
		t.Fatalf("prefix detection allocated whole payload: %f", allocations)
	}
}

func TestBodyCaptureBudgetBusyAndRelease(t *testing.T) {
	for _, sizes := range [][]int{{1, 1, 1, 1}, {10 << 20, 10 << 20}} {
		var budget BodyCaptureBudget
		var weights []uint64
		for _, size := range sizes {
			weight, ok := budget.acquire(size)
			if !ok {
				t.Fatal("unexpected admission failure")
			}
			weights = append(weights, weight)
		}
		// Invalid JSON proves busy admission happens before any body processing.
		started := time.Now()
		got := budget.Capture([]byte("invalid"), "application/json", "", MaxRequestBodyBytes)
		if got.State != "omitted_busy" || got.Body != "" || got.SHA256 != "" || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("busy preparation blocked or processed: %+v", got)
		}
		for _, weight := range weights {
			budget.used.Add(^weight + 1)
		}
		for i := 0; i < 10; i++ {
			budget.Capture([]byte("invalid"), "application/json", "", MaxRequestBodyBytes)
		}
		if budget.used.Load() != 0 {
			t.Fatal("invalid-input capture leaked capacity")
		}
		if got := budget.Capture([]byte(`{"text":"retained"}`), "application/json", "", MaxRequestBodyBytes); got.State != "stored_raw" {
			t.Fatal(got.State)
		}
	}
}

func TestBodyCaptureBudgetDeadlineAndRelease(t *testing.T) {
	now := time.Now()
	budget := NewBodyCaptureBudgetWithClock(func() time.Time { now = now.Add(time.Second); return now })
	got := budget.Capture([]byte(`{"text":"safe"}`), "application/json", "", MaxRequestBodyBytes)
	if got.State != "omitted_processing_limit" || got.Body != "" || got.SHA256 != "" {
		t.Fatalf("deadline did not omit whole body: %+v", got)
	}
	if budget.used.Load() != 0 {
		t.Fatal("deadline exit leaked capacity")
	}
}

func TestBodyCaptureBudgetParallelBounded(t *testing.T) {
	var budget BodyCaptureBudget
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				weight, ok := budget.acquire(8 << 20)
				if !ok {
					continue
				}
				value := budget.used.Load()
				if value>>32 > bodyCaptureSlots || uint32(value) > bodyCaptureUnits {
					t.Error("capacity exceeded")
				}
				budget.used.Add(^weight + 1)
			}
		}()
	}
	wg.Wait()
	if budget.used.Load() != 0 {
		t.Fatal("capacity leaked")
	}
}

func TestCaptureWorkBudgetDropsWholeBody(t *testing.T) {
	raw := []byte(`{"text":"untouched","image_url":"https://private/secret"}`)
	for _, budget := range []*bodyWorkBudget{
		{remaining: 2, deadline: time.Now().Add(time.Hour)},
		{remaining: 2*len(raw) + 20, deadline: time.Now().Add(time.Hour)},
		{remaining: 128 << 20, deadline: time.Now().Add(-time.Second)},
	} {
		got := captureRawJSON(raw, "application/json", "", MaxRequestBodyBytes, budget)
		if got.State != "omitted_processing_limit" || got.Body != "" || got.SHA256 != "" || !got.Truncated {
			t.Fatalf("processing budget exposed partial body: %+v", got)
		}
	}
}

func TestMediaScannerLinearWorkForNestedLateTypes(t *testing.T) {
	raw := []byte(strings.Repeat(`{"wrapper":`, 1000) + `{"text":"keep"}` + strings.Repeat(`,"type":"object"}`, 1000))
	budget := &bodyWorkBudget{remaining: 64 * len(raw), deadline: time.Now().Add(time.Hour)}
	got, changed := filterRequestMedia(raw, budget)
	if changed || !bytes.Equal(got, raw) {
		t.Fatal("nested business data changed")
	}
}

func FuzzMediaSchemaSpoofAndLexicalContext(f *testing.F) {
	f.Add("enum", "https://example/media")
	f.Add("type", "data:image/png;base64,AA")
	f.Fuzz(func(t *testing.T, key, locator string) {
		if len(key) > 256 || len(locator) > 4096 {
			return
		}
		extra, _ := json.Marshal(key)
		value, _ := json.Marshal(locator)
		// The marker is the actual media payload; arbitrary siblings cannot grant a schema exemption.
		raw := []byte(`{"inlineData":{` + string(extra) + `:` + string(value) + `,"data":"HIDDEN-PAYLOAD"}}`)
		got, changed := FilterRequestMedia(raw)
		if !changed || !json.Valid(got) || bytes.Contains(got, []byte("HIDDEN-PAYLOAD")) {
			t.Fatal("schema-looking payload escaped filter")
		}
		schema := []byte(`{"tools":[{"function":{"parameters":` + string(raw) + `}}]}`)
		got, changed = FilterRequestMedia(schema)
		if changed || !bytes.Equal(got, schema) {
			t.Fatal("schema lexical bytes changed")
		}
	})
}

func BenchmarkMediaDenseSmallObjects(b *testing.B) {
	raw := []byte("[" + strings.Repeat(`{"k":"v"},`, (1<<20)/10-1) + `{"k":"v"}]`)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FilterRequestMedia(raw)
	}
}
