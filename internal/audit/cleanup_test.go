package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuditStorageCountsUTF8AndSeparatesPhysicalScope(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, RetentionDays: 7})
	r := auditRecord("storage")
	r.RequestBody = ""
	r.BodySHA256 = ""
	r.BodyState = "empty"
	mustBegin(t, s, r)
	body := `{"message":"你好"}`
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET request_body=? WHERE request_id=?", body, "storage"); err != nil {
		t.Fatal(err)
	}
	usage, err := s.Storage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usage.Records != 1 || usage.ActiveRecords != 1 || usage.ExpiredRecords != 0 || usage.RequestBodyBytes != int64(len(body)) {
		t.Fatalf("wrong storage %+v", usage)
	}
	if usage.DBFileBytes <= 0 || usage.PhysicalSizeScope != "shared_sqlite_database_and_wal" || usage.CapacityMode != "logical_payload_not_physical_file" {
		t.Fatalf("wrong file scope %+v", usage)
	}
	raw, _ := json.Marshal(usage)
	if strings.Contains(string(raw), db.Path()) || strings.Contains(string(raw), "你好") {
		t.Fatal("storage leaked path or body")
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET started_at=?", time.Now().Add(-8*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	usage, err = s.Storage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usage.ActiveRecords != 0 || usage.ExpiredRecords != 1 {
		t.Fatal("expired accounting wrong")
	}
}

func TestPreviewAndApplyCleanupAreSnapshotBoundAndAuditOnly(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, RetentionDays: 7})
	for _, id := range []string{"old", "recent"} {
		mustBegin(t, s, auditRecord(id))
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET started_at=? WHERE request_id='old'", time.Now().Add(-3*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("INSERT INTO rules_state(id,payload,updated_at) VALUES(1,'keep-rules','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("INSERT INTO key_usage(api_key,total_requests) VALUES('keep-key',9)"); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PreviewCleanup(context.Background(), "before", time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Records != 1 || plan.BodyBytes <= 0 || plan.LogicalBytes <= plan.BodyBytes {
		t.Fatalf("wrong plan %+v", plan)
	}
	before, err := s.Storage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before.Records != 2 {
		t.Fatal("preview mutated")
	}
	fresh := auditRecord("after-preview")
	fresh.StartedAt = time.Now().Add(-4 * 24 * time.Hour).UnixMilli()
	mustBegin(t, s, fresh)
	deleted, err := s.ApplyCleanup(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Records != 1 || deleted.LogicalBytes != plan.LogicalBytes || deleted.BodyBytes != plan.BodyBytes {
		t.Fatalf("wrong result %+v", deleted)
	}
	after, err := s.Storage(context.Background())
	if err != nil || after.Records != 2 {
		t.Fatalf("wrong remaining %+v %v", after, err)
	}
	var count int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM client_request_audit WHERE request_id='after-preview'").Scan(&count); err != nil || count != 1 {
		t.Fatal("deleted post-preview request")
	}
	var payload string
	if err := db.Conn().QueryRow("SELECT payload FROM rules_state WHERE id=1").Scan(&payload); err != nil || payload != "keep-rules" {
		t.Fatal("rules modified")
	}
	var usage int
	if err := db.Conn().QueryRow("SELECT total_requests FROM key_usage WHERE api_key='keep-key'").Scan(&usage); err != nil || usage != 9 {
		t.Fatal("usage modified")
	}
	again, err := s.ApplyCleanup(context.Background(), plan)
	if err != nil || again.Records != 0 {
		t.Fatal("missing actual count on repeated store plan")
	}
}

func TestExpiredAndAllCleanupScopesAndInvalidPlans(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, RetentionDays: 7})
	mustBegin(t, s, auditRecord("expired"))
	mustBegin(t, s, auditRecord("active"))
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET started_at=? WHERE request_id='expired'", time.Now().Add(-8*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PreviewCleanup(context.Background(), "expired", time.Time{})
	if err != nil || plan.Records != 1 {
		t.Fatalf("expired plan %+v %v", plan, err)
	}
	result, err := s.ApplyCleanup(context.Background(), plan)
	if err != nil || result.Records != 1 {
		t.Fatal("expired apply")
	}
	plan, err = s.PreviewCleanup(context.Background(), "all", time.Time{})
	if err != nil || plan.Records != 1 {
		t.Fatal("all plan")
	}
	result, err = s.ApplyCleanup(context.Background(), plan)
	if err != nil || result.Records != 1 {
		t.Fatal("all apply")
	}
	for _, tc := range []struct {
		scope  string
		before time.Time
	}{{"", time.Time{}}, {"bad", time.Time{}}, {"before", time.Time{}}, {"before", time.Now().Add(time.Hour)}, {"all", time.Now()}, {"expired", time.Now()}} {
		if _, err := s.PreviewCleanup(context.Background(), tc.scope, tc.before); !errors.Is(err, ErrInvalidCleanup) {
			t.Fatalf("accepted invalid %+v", tc)
		}
	}
	if _, err := s.ApplyCleanup(context.Background(), CleanupPlan{Scope: "all", IDs: []string{"not-id"}}); !errors.Is(err, ErrInvalidCleanup) {
		t.Fatal("accepted arbitrary ID")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Storage(canceled); !errors.Is(err, ErrUnavailable) {
		t.Fatal("storage did not bound cancellation")
	}
}
