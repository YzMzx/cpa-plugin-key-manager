package contentguard

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "guard-test.db"), sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return NewStore(db)
}
func testEvent() Event {
	body := []byte(`{"input":"private body"}`)
	evidence := CaptureEvidence(body, true, 4096)
	return Event{Action: EventBlocked, Mode: ModeEnforce, Severity: SeverityHigh, Body: evidence.Text, BodyState: evidence.State, BodyBytes: len(evidence.Text), OriginalBytes: len(body), BodySHA256: evidence.SHA256, OriginalSHA256: evidence.OriginalSHA256, RuleNames: []string{"test"}, Matches: []Match{{Source: "rule", RuleID: "r1", RuleName: "test", Action: ActionBlock, Severity: SeverityHigh, Role: RoleUser, Snippet: "private match", Matched: "private", Offset: 0}}, Classifier: &ClassifierRecord{Flagged: true, Score: 0.9, Reason: "private reason"}}
}
func TestStoreMetadataDetailReviewExportAndPrune(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()
	e := testEvent()
	id, err := s.Insert(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	list, total, err := s.List(ctx, Query{Limit: 10})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatal(list, total, err)
	}
	if list[0].Body != "" || len(list[0].Matches) != 0 || list[0].Classifier != nil {
		t.Fatal("list leaks content", list[0])
	}
	got, err := s.Detail(ctx, id)
	if err != nil || got.Body != e.Body || got.OriginalSHA256 != e.OriginalSHA256 || got.OriginalBytes != e.OriginalBytes || len(got.Matches) != 1 || got.Classifier.Reason != "private reason" {
		t.Fatal("detail", got, err)
	}
	reviewed, err := s.Review(ctx, id, ReviewConfirmed, "approved")
	if err != nil || reviewed.ReviewStatus != ReviewConfirmed || reviewed.LogicalBytes != got.LogicalBytes {
		t.Fatal("review", reviewed, err)
	}
	exported, err := s.Export(ctx, []string{id, id, strings.Repeat("a", 32)})
	if err != nil || len(exported) != 1 {
		t.Fatal("export", err)
	}
	stats, err := s.Stats(ctx, 0)
	if err != nil || stats.Total != 1 || len(stats.TopRules) != 1 {
		t.Fatal("stats", stats, err)
	}
	settings := DefaultSettings()
	settings.MaxRecords = 1
	e.CreatedAt = time.Now().Add(time.Second).UnixMilli()
	second, err := s.InsertBounded(ctx, e, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Detail(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("capacity retained old", err)
	}
	if _, err = s.Detail(ctx, second); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(ctx, time.Now().Add(400*24*time.Hour), settings)
	if err != nil || n != 1 {
		t.Fatal("retention", n, err)
	}
}
func TestStoreByteCapacityAndRollback(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()
	settings := DefaultSettings()
	settings.MaxTotalBytes = 1 << 20
	settings.MaxEvidenceBytes = 1 << 20
	e := testEvent()
	evidence := CaptureEvidence([]byte(`{"input":"`+strings.Repeat("x", 600000)+`"}`), true, 1<<20)
	e.Body = evidence.Text
	e.BodySHA256 = evidence.SHA256
	e.BodyBytes = len(e.Body)
	first, err := s.InsertBounded(ctx, e, settings)
	if err != nil {
		t.Fatal(err)
	}
	e.CreatedAt = time.Now().Add(time.Second).UnixMilli()
	if _, err = s.InsertBounded(ctx, e, settings); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Detail(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Fatal("byte capacity", err)
	}
	stats, err := s.Stats(ctx, 0)
	if err != nil || stats.Records != 1 || stats.LogicalBytes > settings.MaxTotalBytes {
		t.Fatal(stats, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.InsertBounded(canceled, testEvent(), settings); err == nil {
		t.Fatal("cancel accepted")
	}
	settings.MaxRecords = 0
	if _, err = s.Prune(ctx, time.Now(), settings); err == nil {
		t.Fatal("invalid prune")
	}
	stats, err = s.Stats(ctx, 0)
	if err != nil || stats.Records != 1 {
		t.Fatal("failed mutation changed state", stats, err)
	}
}
func TestStoreValidationAndQuery(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()
	cases := []func(*Event){func(e *Event) { e.BodySHA256 = "wrong" }, func(e *Event) { e.BodyBytes++ }, func(e *Event) { e.BodyState = "omitted_invalid" }, func(e *Event) { e.KeyFingerprint = "raw-key" }, func(e *Event) { e.Classifier.Score = math.NaN() }, func(e *Event) { e.Matches[0].Snippet = strings.Repeat("x", 2000) }, func(e *Event) { e.Action = "unknown" }}
	for _, mutate := range cases {
		e := testEvent()
		mutate(&e)
		if _, err := s.Insert(ctx, e); err == nil {
			t.Fatal("invalid persisted")
		}
	}
	for _, q := range []Query{{Limit: 0}, {Limit: 101}, {Limit: 1, Offset: -1}, {Limit: 1, From: 10, To: 1}, {Limit: 1, KeyFingerprint: "key"}, {Limit: 1, Rule: "bad\n"}, {Limit: 1, Severity: "critical"}} {
		if _, _, err := s.List(ctx, q); !errors.Is(err, ErrInvalidQuery) {
			t.Fatal("query accepted", q, err)
		}
	}
	if _, err := s.Export(ctx, make([]string, MaxExport+1)); !errors.Is(err, ErrInvalidQuery) {
		t.Fatal(err)
	}
	if err := s.SetAutoDisabled(ctx, "bad", "disabled"); !errors.Is(err, ErrInvalidQuery) {
		t.Fatal(err)
	}
	var unavailable *Store
	if _, err := unavailable.Insert(ctx, testEvent()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestStoreExportByteBudget(t *testing.T) {
	s := tempStore(t)
	ctx := context.Background()
	e := testEvent()
	evidence := CaptureEvidence([]byte(`{"input":"`+strings.Repeat("x", 900000)+`"}`), true, 1<<20)
	e.Body = evidence.Text
	e.BodySHA256 = evidence.SHA256
	e.BodyBytes = len(e.Body)
	var ids []string
	settings := DefaultSettings()
	settings.MaxEvidenceBytes = 1 << 20
	for i := 0; i < 10; i++ {
		id, err := s.InsertBounded(ctx, e, settings)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := s.Export(ctx, ids); !errors.Is(err, ErrInvalidQuery) {
		t.Fatal("export memory budget", err)
	}
}
func TestStoreCapturePolicyDefenseInDepth(t *testing.T) {
	s := tempStore(t)
	settings := DefaultSettings()
	settings.CaptureBody = false
	id, err := s.InsertBounded(context.Background(), testEvent(), settings)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Detail(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "" || got.BodyBytes != 0 || got.BodySHA256 != "" || got.Matches[0].Snippet != "" || got.Classifier.Reason != "" {
		t.Fatal("capture privacy leak", got)
	}
	settings.CaptureBody = true
	settings.EvidenceIncludeSystem = false
	e := testEvent()
	e.Matches[0].Role = RoleSystem
	id, err = s.InsertBounded(context.Background(), e, settings)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.Detail(context.Background(), id)
	if err != nil || got.Matches[0].Snippet != "" || got.Classifier.Reason != "" {
		t.Fatal("system privacy leak", got, err)
	}
}
