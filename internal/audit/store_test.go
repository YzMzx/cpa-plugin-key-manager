package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func openAuditDB(t *testing.T) (*sqlitestore.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sqlitestore.Open(path, sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}
func auditRecord(id string) Record {
	body := `{"model":"model-a","messages":[{"role":"user","content":"safe prompt"}]}`
	hash := sha256.Sum256([]byte(body))
	return Record{RequestID: id, TraceID: "trace-" + id, StartedAt: time.Now().Add(-time.Minute).UnixMilli(), Method: "post", Path: "/v1/chat/completions?api_key=do-not-store#secret", ClientIP: "203.0.113.4", PeerIP: "127.0.0.1", IPSource: "peer", KeyLabel: "team", KeyFingerprint: strings.Repeat("a", 64), RequestedModel: "model-a", Protocol: "openai", BodyState: "stored", RequestBody: body, BodySHA256: hex.EncodeToString(hash[:])}
}
func mustBegin(t *testing.T, s *Store, r Record) {
	t.Helper()
	if err := s.Begin(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
func oneRecord(t *testing.T, s *Store, id string) Record {
	t.Helper()
	result, err := s.List(context.Background(), Query{RequestID: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("want one record got %+v", result)
	}
	return result.Records[0]
}

func TestAuditMigrationUpgradePreservesExistingSchema(t *testing.T) {
	db, _ := openAuditDB(t)
	ctx := context.Background()
	// Reapply the audit migrations while retaining unrelated migration history.
	// Dropping only the audit table must not replay later quota migrations.
	if _, err := db.Conn().Exec("INSERT INTO rules_state(id,payload,updated_at) VALUES(1,'preserved','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("DROP TABLE client_request_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("DELETE FROM schema_migrations WHERE version BETWEEN 2 AND 4"); err != nil {
		t.Fatal(err)
	}
	if err := sqlitestore.Migrate(ctx, db.Conn()); err != nil {
		t.Fatal(err)
	}
	if err := sqlitestore.Migrate(ctx, db.Conn()); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := db.Conn().QueryRow("SELECT payload FROM rules_state WHERE id=1").Scan(&payload); err != nil || payload != "preserved" {
		t.Fatal("migration changed existing rules")
	}
	var count int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=2").Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration2 count=%d err=%v", count, err)
	}
	rows, err := db.Conn().Query("PRAGMA table_info(client_request_audit)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			t.Fatal(err)
		}
		names[name] = true
	}
	if names["api_key"] || names["headers"] || names["error_body"] || !names["request_body"] || !names["logical_bytes"] {
		t.Fatal("unsafe or incomplete audit schema")
	}
}

func TestAuditRestartMetadataListAndRandomDetail(t *testing.T) {
	db, path := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	r := auditRecord("restart")
	r.ID = strings.Repeat("0", 64)
	mustBegin(t, s, r)
	meta := oneRecord(t, s, "restart")
	if !validID(meta.ID) || meta.ID == r.ID {
		t.Fatal("details ID must be generated randomly")
	}
	if meta.RequestBody != "" || meta.Path != "/v1/chat/completions" {
		t.Fatal("list exposed body or path query")
	}
	encoded, _ := json.Marshal(meta)
	if strings.Contains(string(encoded), "request_body") || strings.Contains(string(encoded), "do-not-store") {
		t.Fatalf("metadata leak %s", encoded)
	}
	detail, err := s.Detail(context.Background(), meta.ID)
	if err != nil || detail.RequestBody != r.RequestBody || detail.BodySHA256 != r.BodySHA256 {
		t.Fatalf("detail mismatch %+v %v", detail, err)
	}
	if _, err := s.Detail(context.Background(), r.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("request id must not be a detail locator")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitestore.Open(path, sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s = NewStore(reopened, Config{Enabled: true})
	detail, err = s.Detail(context.Background(), meta.ID)
	if err != nil || detail.RequestID != "restart" {
		t.Fatalf("restart lost audit: %+v %v", detail, err)
	}
	if _, err := reopened.Conn().Exec("UPDATE rules_state SET payload=payload"); err != nil {
		t.Fatal("audit unexpectedly owns DB lifecycle")
	}
}

func TestAuditBeginAndCompleteAreIdempotentAndNeverCreateBodylessRows(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	ctx := context.Background()
	r := auditRecord("once")
	mustBegin(t, s, r)
	first := oneRecord(t, s, "once")
	other := r
	other.RequestBody = `{"changed":true}`
	sum := sha256.Sum256([]byte(other.RequestBody))
	other.BodySHA256 = hex.EncodeToString(sum[:])
	mustBegin(t, s, other)
	detail, _ := s.Detail(ctx, first.ID)
	if detail.RequestBody != r.RequestBody || detail.ID != first.ID {
		t.Fatal("duplicate begin rewrote original")
	}
	if err := s.Complete(ctx, Completion{RequestID: "absent", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, Completion{RequestID: "once", Outcome: "success", StatusCode: 200, ServedModel: "served", InputTokens: 8, OutputTokens: 2, TotalTokens: 10}); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, Completion{RequestID: "once", Outcome: "failed", StatusCode: 500}); err != nil {
		t.Fatal(err)
	}
	detail, _ = s.Detail(ctx, first.ID)
	if detail.Outcome != "success" || detail.StatusCode != 200 || detail.TotalTokens != 10 || detail.CompletedAt < detail.StartedAt || detail.DurationMS <= 0 {
		t.Fatalf("bad completion %+v", detail)
	}
	rejected := auditRecord("rejected")
	rejected.Outcome = "rejected"
	rejected.StatusCode = 403
	mustBegin(t, s, rejected)
	if err := s.Complete(ctx, Completion{RequestID: "rejected", Outcome: "success", StatusCode: 200}); err != nil {
		t.Fatal(err)
	}
	got := oneRecord(t, s, "rejected")
	if got.Outcome != "rejected" || got.StatusCode != 403 {
		t.Fatal("rejection overwritten")
	}
	result, _ := s.List(ctx, Query{})
	if result.Total != 2 {
		t.Fatalf("late completion created row: %d", result.Total)
	}
}

func TestAuditFiltersPaginationAndSQLParameters(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	ctx := context.Background()
	base := time.Now().Add(-time.Hour).UnixMilli()
	for i := 0; i < 6; i++ {
		r := auditRecord(fmt.Sprintf("request-%d", i))
		r.StartedAt = base + int64(i)
		if i%2 == 0 {
			r.TraceID = "shared"
			r.KeyFingerprint = strings.Repeat("e", 64)
			r.RequestedModel = "even"
			r.ClientIP = "203.0.113.8"
		}
		mustBegin(t, s, r)
	}
	for _, q := range []Query{{RequestID: "request-0"}, {TraceID: "shared"}, {KeyFingerprint: strings.Repeat("e", 64)}, {Model: "even"}, {Outcome: "pending"}, {From: base, To: base + 1}} {
		result, err := s.List(ctx, q)
		if err != nil || result.Total < 1 {
			t.Fatalf("filter %+v => %+v %v", q, result, err)
		}
	}
	result, err := s.List(ctx, Query{Limit: 2, Offset: 2})
	if err != nil || result.Limit != 2 || result.Offset != 2 || result.Total != 6 || len(result.Records) != 2 || result.Records[0].RequestID != "request-3" {
		t.Fatalf("pagination %+v %v", result, err)
	}
	result, err = s.List(ctx, Query{Limit: 1000, RequestID: "' OR 1=1 --"})
	if err != nil || result.Limit != 100 || result.Total != 0 {
		t.Fatal("query was not parameterized or bounded")
	}
	for _, q := range []Query{{IP: "203.0.113.8"}, {Offset: -1}, {Offset: MaxQueryOffset + 1}, {From: 5, To: 4}, {From: -1}} {
		if _, err := s.List(ctx, q); !errors.Is(err, ErrInvalidQuery) {
			t.Fatalf("bad query allowed %+v", q)
		}
	}
}

func TestAuditExpirationIsUnreadableBeforePruneAndLateCompleteDoesNotRevive(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, RetentionDays: 1})
	ctx := context.Background()
	r := auditRecord("expired")
	mustBegin(t, s, r)
	meta := oneRecord(t, s, "expired")
	old := time.Now().Add(-48 * time.Hour).UnixMilli()
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET started_at=? WHERE id=?", old, meta.ID); err != nil {
		t.Fatal(err)
	}
	result, err := s.List(ctx, Query{})
	if err != nil || result.Total != 0 {
		t.Fatal("expired list visible")
	}
	if _, err := s.Detail(ctx, meta.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired detail visible")
	}
	if err := s.Complete(ctx, Completion{RequestID: "expired", Outcome: "success", StatusCode: 200}); err != nil {
		t.Fatal(err)
	}
	var completed int64
	if err := db.Conn().QueryRow("SELECT completed_at FROM client_request_audit WHERE id=?", meta.ID).Scan(&completed); err != nil || completed != 0 {
		t.Fatal("expired record revived")
	}
	mustBegin(t, s, auditRecord("fresh"))
	var count int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM client_request_audit").Scan(&count); err != nil || count != 1 {
		t.Fatal("begin did not enforce expiry")
	}
	if err := s.Prune(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	result, _ = s.List(ctx, Query{})
	if result.Total != 0 {
		t.Fatal("periodic prune failed")
	}
}

func TestAuditCapacityKeepsNewestRecordsAndLogicalBytesBounded(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, MaxRecords: 2})
	base := time.Now().Add(-time.Hour).UnixMilli()
	for i := 0; i < 4; i++ {
		r := auditRecord(fmt.Sprintf("capacity-%d", i))
		r.StartedAt = base + int64(i)
		mustBegin(t, s, r)
	}
	result, _ := s.List(context.Background(), Query{})
	if result.Total != 2 || result.Records[0].RequestID != "capacity-3" || result.Records[1].RequestID != "capacity-2" {
		t.Fatalf("count cap %+v", result)
	}
	small := NewStore(db, Config{Enabled: true, MaxRecords: 100, MaxTotalBytes: 900})
	for i := 0; i < 5; i++ {
		r := auditRecord(fmt.Sprintf("bytes-%d", i))
		r.StartedAt = base + int64(100+i)
		mustBegin(t, small, r)
	}
	status := small.Status()
	if status.LogicalBytes > 900 || status.Records > 1 || status.CapacityMode != "logical_payload_not_physical_file" {
		t.Fatalf("logical cap %+v", status)
	}
	tiny := NewStore(db, Config{Enabled: true, MaxTotalBytes: 1})
	if err := tiny.Begin(context.Background(), auditRecord("too-large")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversize should expose safe capacity error: %v", err)
	}
	if got := tiny.Status(); got.Records != 0 || got.LogicalBytes != 0 {
		t.Fatalf("oversize entry survived %+v", got)
	}
}

func TestAuditBodiesRequireKnownSchemaValidSanitizedHashAndSize(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, MaxBodyBytes: 128})
	ctx := context.Background()
	for _, tc := range []struct{ name, protocol, state, body, hash string }{{"unknown", "mystery", "stored", `{"secret":"never"}`, ""}, {"not-json", "openai", "stored", "raw secret", ""}, {"omitted", "openai", "omitted_unknown_schema", `{"secret":"never"}`, ""}, {"missing-hash", "openai", "stored", `{"safe":true}`, ""}, {"wrong-hash", "openai", "stored", `{"safe":true}`, strings.Repeat("0", 64)}, {"size", "openai", "stored", `{"text":"` + strings.Repeat("x", 200) + `"}`, ""}} {
		r := auditRecord(tc.name)
		r.Protocol, r.BodyState, r.RequestBody, r.BodySHA256 = tc.protocol, tc.state, tc.body, tc.hash
		mustBegin(t, s, r)
		meta := oneRecord(t, s, tc.name)
		detail, err := s.Detail(ctx, meta.ID)
		if err != nil || detail.RequestBody != "" || detail.BodySHA256 != "" {
			t.Fatalf("unsafe body persisted %s %+v %v", tc.name, detail, err)
		}
	}
	valid := auditRecord("safe")
	mustBegin(t, s, valid)
	meta := oneRecord(t, s, "safe")
	detail, _ := s.Detail(ctx, meta.ID)
	if detail.RequestBody != valid.RequestBody {
		t.Fatal("safe sanitized body lost")
	}
}

func TestAuditDisabledReadRetainedAndSafeErrors(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	mustBegin(t, s, auditRecord("retained"))
	disabled := NewStore(db, Config{})
	if !errors.Is(disabled.Begin(context.Background(), auditRecord("off")), ErrDisabled) {
		t.Fatal("disabled wrote")
	}
	result, err := disabled.List(context.Background(), Query{})
	if err != nil || result.Total != 1 {
		t.Fatal("disabled lost retained read")
	}
	if err := disabled.Prune(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if disabled.Status().Enabled {
		t.Fatal("disabled status incorrect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Begin(ctx, auditRecord("cancelled")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsafe cancellation error %v", err)
	}
	if _, err := db.Conn().Exec("DROP TABLE client_request_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(context.Background(), Query{RequestID: "private-key"}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private-key") {
		t.Fatalf("unsafe SQL error %v", err)
	}
}

func TestAuditConcurrentBeginIdempotency(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Begin(context.Background(), auditRecord("same")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	result, err := s.List(context.Background(), Query{})
	if err != nil || result.Total != 1 {
		t.Fatalf("duplicate race %+v %v", result, err)
	}
}

func TestAuditLateUsageEnrichmentPreservesTerminalMetadata(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	ctx := context.Background()
	r := auditRecord("enriched")
	r.TraceID = ""
	mustBegin(t, s, r)
	if err := s.Complete(ctx, Completion{RequestID: r.RequestID, InputTokens: 2, TotalTokens: 2}); err != nil {
		t.Fatal(err)
	}
	meta := oneRecord(t, s, r.RequestID)
	if meta.Outcome != "pending" || meta.CompletedAt != 0 || meta.StatusCode != 0 {
		t.Fatal("usage marked request completed")
	}
	if err := s.Complete(ctx, Completion{RequestID: r.RequestID, Outcome: "failed", StatusCode: 502, InputTokens: 10, OutputTokens: 3, TotalTokens: 13}); err != nil {
		t.Fatal(err)
	}
	before := oneRecord(t, s, r.RequestID)
	if err := s.Complete(ctx, Completion{RequestID: r.RequestID, TraceID: "later-trace", ServedModel: "actual", InputTokens: 5, OutputTokens: 4, TotalTokens: 14}); err != nil {
		t.Fatal(err)
	}
	after := oneRecord(t, s, r.RequestID)
	if after.Outcome != "failed" || after.StatusCode != 502 || after.CompletedAt != before.CompletedAt || after.DurationMS != before.DurationMS || after.InputTokens != 10 || after.OutputTokens != 4 || after.TotalTokens != 14 || after.TraceID != "later-trace" || after.ServedModel != "actual" {
		t.Fatalf("enrichment corrupts terminal %+v", after)
	}
	if err := s.Complete(ctx, Completion{RequestID: "unmatched", InputTokens: 10}); err != nil {
		t.Fatal(err)
	}
	result, _ := s.List(ctx, Query{})
	if result.Total != 1 {
		t.Fatal("usage enrichment created phantom record")
	}
}

func TestAuditRecordValidationAndDefaultBounds(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	st := s.Status()
	if st.RetentionDays != 7 || st.MaxRecords != 10000 || st.MaxBodyBytes != DefaultMaxBodyBytes || st.MaxTotalBytes != 64<<20 {
		t.Fatalf("default bounds %+v", st)
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.RequestID = "" }, func(r *Record) { r.TraceID = strings.Repeat("x", 257) }, func(r *Record) { r.KeyLabel = strings.Repeat("x", 1025) }, func(r *Record) { r.Outcome = "custom-secret-error" }, func(r *Record) { r.StatusCode = 999 }, func(r *Record) { r.InputTokens = -1 }, func(r *Record) { r.StartedAt = time.Now().Add(time.Hour).UnixMilli() }} {
		r := auditRecord("invalid")
		mutate(&r)
		if !errors.Is(s.Begin(context.Background(), r), ErrInvalidRecord) {
			t.Fatal("invalid metadata allowed")
		}
	}
	result, _ := s.List(context.Background(), Query{})
	if result.Total != 0 {
		t.Fatal("invalid record stored")
	}
}

func TestAuditPruneDoesNotHideCaptureFailureAndStatusHasTimeout(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.Begin(ctx, auditRecord("lost"))
	if err := s.Prune(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.Status().LastError == "" {
		t.Fatal("successful cleanup hid failed capture")
	}
	held, err := db.Conn().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	started := time.Now()
	status := s.Status()
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("status blocked %v", elapsed)
	}
	if status.LastError != ErrUnavailable.Error() {
		t.Fatal("status did not report bounded timeout")
	}
}

func TestAuditStoreRetainsTenMiBJSONWithoutOneMiBClamp(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	if store.Status().MaxBodyBytes != MaxRequestBodyBytes {
		t.Fatal("store still clamps large body")
	}
	body := string(readableJSONBody(MaxRequestBodyBytes))
	hash := sha256.Sum256([]byte(body))
	rec := auditRecord("ten-mib-store")
	rec.RequestBody = body
	rec.BodySHA256 = hex.EncodeToString(hash[:])
	mustBegin(t, store, rec)
	meta := oneRecord(t, store, rec.RequestID)
	if meta.RequestBody != "" {
		t.Fatal("metadata list exposed large body")
	}
	detail, err := store.Detail(context.Background(), meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.BodyState != "stored" || len(detail.RequestBody) != MaxRequestBodyBytes || detail.BodySHA256 != rec.BodySHA256 {
		t.Fatalf("large record lost: %s %d", detail.BodyState, len(detail.RequestBody))
	}
	if err := store.Complete(context.Background(), Completion{RequestID: rec.RequestID, Outcome: "succeeded", StatusCode: 200, ServedModel: "served-large-model"}); err != nil {
		t.Fatal(err)
	}
	after, err := store.Detail(context.Background(), meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RequestBody != body || after.BodySHA256 != rec.BodySHA256 || after.Outcome != "succeeded" {
		t.Fatal("metadata-only completion changed retained body")
	}
	var size int64
	if err := db.Conn().QueryRow("SELECT logical_bytes FROM client_request_audit WHERE id=?", meta.ID).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size != logicalBytes(after) {
		t.Fatalf("completion lost body capacity accounting: got %d want %d", size, logicalBytes(after))
	}
}
