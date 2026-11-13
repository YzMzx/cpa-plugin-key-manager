package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

var cleanupOwner = strings.Repeat("a", 64)
var cleanupOtherOwner = strings.Repeat("b", 64)

func cleanupSeed(t *testing.T, s *Store, count int, logical int64, body string) {
	t.Helper()
	tx, err := s.db.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes,request_body) VALUES(?,?,?,?,?)")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := 0; i < count; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("%064x", i), fmt.Sprint(i), i+1, logical, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func cleanupStart(t *testing.T, s *Store, limits CleanupBatchLimits) (CleanupJobPreview, CleanupJob) {
	t.Helper()
	p, err := s.PreviewCleanupJob(context.Background(), "all", "", cleanupOwner, limits)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.StartCleanupJob(context.Background(), p.Token, cleanupOwner)
	if err != nil {
		t.Fatal(err)
	}
	return p, j
}
func cleanupRead(t *testing.T, s *Store, id string) CleanupJob {
	t.Helper()
	j, err := s.GetCleanupJob(context.Background(), id, cleanupOwner)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func cleanupCount(t *testing.T, s *Store, table string) int64 {
	t.Helper()
	var n int64
	if err := s.db.Conn().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCleanupJobRecordLimitAndRetentionSkip(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 1005, 1, "")
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := db.Conn().Exec("DELETE FROM client_request_audit WHERE request_id IN ('0','1004')"); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunCleanupJobBatch(context.Background(), CleanupBatchLimits{}); err != nil || !work {
		t.Fatal(work, err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.ProcessedRecords != 1000 || j.DeletedRecords != 999 || j.SkippedRecords != 1 || j.RemainingRecords != 5 {
		t.Fatalf("first %+v", j)
	}
	if _, err := s.RunCleanupJobBatch(context.Background(), CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "completed" || j.DeletedRecords != 1003 || j.SkippedRecords != 2 || j.DeletedLogicalBytes != 1003 || cleanupCount(t, s, "audit_cleanup_items") != 0 {
		t.Fatalf("final %+v", j)
	}
}

func TestCleanupJobTokenOwnershipIdempotencyAndUniqueActive(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 3, 10, "")
	ctx := context.Background()
	p, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCleanupJob(ctx, p.Token, cleanupOtherOwner); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross owner start", err)
	}
	var wg sync.WaitGroup
	results := make(chan CleanupJob, 12)
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := s.StartCleanupJob(ctx, p.Token, cleanupOwner)
			results <- j
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first CleanupJob
	for j := range results {
		if first.ID == "" {
			first = j
		}
		if first.ID != j.ID {
			t.Fatal("idempotency lost")
		}
	}
	if cleanupCount(t, s, "audit_cleanup_jobs") != 1 {
		t.Fatal("duplicate jobs")
	}
	for _, op := range []func(context.Context, string, string) (CleanupJob, error){s.GetCleanupJob, s.CancelCleanupJob, s.ResumeCleanupJob} {
		if _, err := op(ctx, first.ID, cleanupOtherOwner); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross owner operation", err)
		}
	}
	if jobs, err := s.ListCleanupJobs(ctx, cleanupOtherOwner); err != nil || len(jobs) != 0 {
		t.Fatal("cross owner list", jobs, err)
	}
	other, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOtherOwner, CleanupBatchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCleanupJob(ctx, other.Token, cleanupOtherOwner); !errors.Is(err, ErrCleanupBusy) {
		t.Fatal("second active", err)
	}
	// SQLite itself, not an in-memory lock, enforces the sole active slot.
	if _, err := db.Conn().Exec("INSERT INTO audit_cleanup_jobs SELECT ?,?,principal_hash,state,total_records,processed_records,deleted_records,skipped_records,remaining_records,deleted_logical_bytes,deleted_body_bytes,batches,batch_max_records,batch_max_bytes,created_at,updated_at,error_code FROM audit_cleanup_jobs LIMIT 1", strings.Repeat("c", 64), strings.Repeat("d", 64)); err == nil {
		t.Fatal("unique active index missing")
	}
	// The first token is still idempotent beyond the preview TTL.
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_jobs SET created_at=created_at-600000"); err != nil {
		t.Fatal(err)
	}
	again, err := s.StartCleanupJob(ctx, p.Token, cleanupOwner)
	if err != nil || again.ID != first.ID {
		t.Fatal("expired idempotency", again, err)
	}
	if _, err := s.CancelCleanupJob(ctx, first.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCleanupJob(ctx, other.Token, cleanupOtherOwner); err != nil {
		t.Fatal("cancel did not free active", err)
	}
}

func TestCleanupJobCancelPreservesCommittedProgress(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 4, 11, "")
	ctx := context.Background()
	p, j := cleanupStart(t, s, CleanupBatchLimits{MaxRecords: 2})
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	j, err := s.CancelCleanupJob(ctx, j.ID, cleanupOwner)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != "canceled" || j.ProcessedRecords != 2 || j.DeletedRecords != 2 || j.RemainingRecords != 2 || j.Batches != 1 {
		t.Fatalf("cancel %+v", j)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil || work {
		t.Fatal(work, err)
	}
	if cleanupCount(t, s, "client_request_audit") != 2 || cleanupCount(t, s, "audit_cleanup_items") != 0 {
		t.Fatal("canceled task consumed more work")
	}
	if again, err := s.StartCleanupJob(ctx, p.Token, cleanupOwner); err != nil || again.ID != j.ID || again.State != "canceled" {
		t.Fatal("canceled token restarted", again, err)
	}
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); !errors.Is(err, ErrCleanupJobState) {
		t.Fatal("resumed canceled job", err)
	}
}

func TestCleanupJobFailureRollsBackChunksAndResumes(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 250, 17, "test body")
	ctx := context.Background()
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := db.Conn().Exec(`CREATE TRIGGER cleanup_test_fail BEFORE DELETE ON client_request_audit WHEN old.request_id='220' BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !work || !errors.Is(err, ErrUnavailable) {
		t.Fatal(work, err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "failed" || j.ErrorCode != "storage_unavailable" || j.ProcessedRecords != 0 || j.Batches != 0 || j.RemainingRecords != 250 || cleanupCount(t, s, "client_request_audit") != 250 || cleanupCount(t, s, "audit_cleanup_items") != 250 {
		t.Fatalf("non-atomic failure %+v", j)
	}
	if _, err := db.Conn().Exec("DROP TRIGGER cleanup_test_fail"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "completed" || j.ProcessedRecords != 250 || j.DeletedLogicalBytes != 250*17 || j.DeletedBodyBytes != 250*9 || j.Batches != 1 {
		t.Fatalf("resume %+v", j)
	}
}

func TestCleanupJobSnapshotAndProgressSurviveReopen(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(fmt.Sprint(started), func(t *testing.T) {
			db, path := openAuditDB(t)
			s := NewStore(db, Config{})
			cleanupSeed(t, s, 5, 10, "")
			ctx := context.Background()
			p, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{MaxRecords: 2})
			if err != nil {
				t.Fatal(err)
			}
			var j CleanupJob
			if started {
				j, err = s.StartCleanupJob(ctx, p.Token, cleanupOwner)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := sqlitestore.Open(path, sqlitestore.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			s = NewStore(reopened, Config{})
			if err := sqlitestore.Migrate(ctx, reopened.Conn()); err != nil {
				t.Fatal("migration not idempotent", err)
			}
			if !started {
				j, err = s.StartCleanupJob(ctx, p.Token, cleanupOwner)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 4; i++ {
				work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{})
				if err != nil {
					t.Fatal(err)
				}
				if !work {
					break
				}
			}
			j = cleanupRead(t, s, j.ID)
			if j.State != "completed" || j.ProcessedRecords != 5 || j.DeletedRecords != 5 || j.Batches != 3 {
				t.Fatalf("recovery %+v", j)
			}
		})
	}
}

func TestCleanupJobCapturedAndCurrentBudgets(t *testing.T) {
	for _, tc := range []struct {
		name              string
		captured, current CleanupBatchLimits
		size              int64
		want              int64
	}{
		{"record_increase", CleanupBatchLimits{MaxRecords: 2}, CleanupBatchLimits{MaxRecords: 5}, 1, 2},
		{"record_decrease", CleanupBatchLimits{MaxRecords: 5}, CleanupBatchLimits{MaxRecords: 1}, 1, 1},
		{"bytes_increase", CleanupBatchLimits{MaxBytes: 16 << 20}, CleanupBatchLimits{MaxBytes: 128 << 20}, 10 << 20, 1},
		{"bytes_decrease", CleanupBatchLimits{MaxBytes: 128 << 20}, CleanupBatchLimits{MaxBytes: 16 << 20}, 10 << 20, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := openAuditDB(t)
			s := NewStore(db, Config{})
			cleanupSeed(t, s, 6, tc.size, "")
			_, j := cleanupStart(t, s, tc.captured)
			if _, err := s.RunCleanupJobBatch(context.Background(), tc.current); err != nil {
				t.Fatal(err)
			}
			j = cleanupRead(t, s, j.ID)
			if j.ProcessedRecords != tc.want {
				t.Fatalf("budget enlarged or ignored %+v", j)
			}
		})
	}
}

func TestCleanupJobCurrentMetadataOversizedFailsExplicitly(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 2, 1, "")
	ctx := context.Background()
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=? WHERE request_id='0'", 32<<20+1); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{MaxBytes: 128 << 20}); !work || !errors.Is(err, ErrCleanupTooLarge) {
		t.Fatal(work, err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "failed" || j.ErrorCode != "record_exceeds_batch_budget" || j.ProcessedRecords != 0 || cleanupCount(t, s, "audit_cleanup_items") != 2 {
		t.Fatalf("oversize %+v", j)
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupJobPreviewLimitExpiryAndTokenDigest(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 1, 3, "secret body must not be copied")
	ctx := context.Background()
	var first CleanupJobPreview
	for i := 0; i < 8; i++ {
		p, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = p
		}
	}
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); !errors.Is(err, ErrCleanupBusy) {
		t.Fatal("preview limit", err)
	}
	var digest string
	if err := db.Conn().QueryRow("SELECT token_hash FROM audit_cleanup_previews WHERE token_hash=?", cleanupDigest(first.Token)).Scan(&digest); err != nil || digest == first.Token || len(first.Token) != 64 {
		t.Fatal("raw token retained", err)
	}
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_previews SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCleanupJob(ctx, first.Token, cleanupOwner); !errors.Is(err, ErrCleanupPreviewExpired) {
		t.Fatal("expired token started", err)
	}
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	if cleanupCount(t, s, "audit_cleanup_previews") != 1 || cleanupCount(t, s, "audit_cleanup_items") != 1 {
		t.Fatal("expired snapshot leaked")
	}
	rows, err := db.Conn().Query("PRAGMA table_info(audit_cleanup_items)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "request_body" || name == "api_key" || name == "token" {
			t.Fatal("sensitive column", name)
		}
	}
}

func TestCleanupJobJSONAndScopeContract(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	for _, scope := range []string{"all", "expired", "before"} {
		before := ""
		if scope == "before" {
			before = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		}
		p, err := s.PreviewCleanupJob(ctx, scope, before, cleanupOwner, CleanupBatchLimits{})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(encoded, &payload); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"token", "expires_at", "records", "logical_bytes", "request_body_bytes", "batch_max_records", "batch_max_bytes", "scope", "before"} {
			if _, ok := payload[key]; !ok {
				t.Fatal("missing preview field", key)
			}
		}
	}
	for _, tc := range [][2]string{{"unknown", ""}, {"all", "2020-01-01T00:00:00Z"}, {"before", ""}, {"before", "garbage"}, {"before", time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}} {
		if _, err := s.PreviewCleanupJob(ctx, tc[0], tc[1], cleanupOwner, CleanupBatchLimits{}); !errors.Is(err, ErrInvalidCleanup) {
			t.Fatal("invalid scope accepted", tc, err)
		}
	}
}

func TestCleanupJobRejectInvalidLimits(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	for _, limits := range []CleanupBatchLimits{{MaxRecords: -1}, {MaxRecords: 5001}, {MaxBytes: -1}, {MaxBytes: 128<<20 + 1}} {
		if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, limits); !errors.Is(err, ErrInvalidCleanup) {
			t.Fatal("invalid preview budget accepted", limits, err)
		}
		if _, err := s.RunCleanupJobBatch(ctx, limits); !errors.Is(err, ErrInvalidCleanup) {
			t.Fatal("invalid execution budget accepted", limits, err)
		}
	}
}
