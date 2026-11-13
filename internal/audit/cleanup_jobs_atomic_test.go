package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCleanupJobFailureAtEveryCommitStageRollsBack(t *testing.T) {
	for _, stage := range []string{"items", "progress"} {
		t.Run(stage, func(t *testing.T) {
			db, _ := openAuditDB(t)
			s := NewStore(db, Config{})
			ctx := context.Background()
			cleanupSeed(t, s, 251, 2, "")
			_, j := cleanupStart(t, s, CleanupBatchLimits{})
			query := `CREATE TRIGGER cleanup_fail_commit BEFORE DELETE ON audit_cleanup_items BEGIN SELECT RAISE(ABORT,'item consumption unavailable'); END`
			if stage == "progress" {
				query = `CREATE TRIGGER cleanup_fail_commit BEFORE UPDATE ON audit_cleanup_jobs WHEN new.processed_records>old.processed_records BEGIN SELECT RAISE(ABORT,'progress unavailable'); END`
			}
			if _, err := db.Conn().Exec(query); err != nil {
				t.Fatal(err)
			}
			if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !work || !errors.Is(err, ErrUnavailable) {
				t.Fatal(work, err)
			}
			j = cleanupRead(t, s, j.ID)
			if j.State != "failed" || j.ProcessedRecords != 0 || j.Batches != 0 || cleanupCount(t, s, "client_request_audit") != 251 || cleanupCount(t, s, "audit_cleanup_items") != 251 {
				t.Fatalf("partial transaction at %s: %+v", stage, j)
			}
			if _, err := db.Conn().Exec("DROP TRIGGER cleanup_fail_commit"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
				t.Fatal(err)
			}
			j = cleanupRead(t, s, j.ID)
			if j.State != "completed" || j.ProcessedRecords != 251 || j.Batches != 1 {
				t.Fatalf("retry double counted %+v", j)
			}
		})
	}
}

func TestCleanupJobResumeCannotStealActiveSlot(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 2, 1, "")
	p, j := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=?", 32<<20+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !errors.Is(err, ErrCleanupTooLarge) {
		t.Fatal(err)
	}
	_, other := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); !errors.Is(err, ErrCleanupBusy) {
		t.Fatal("resume stole slot", err)
	}
	again, err := s.StartCleanupJob(ctx, p.Token, cleanupOwner)
	if err != nil || again.ID != j.ID || again.State != "failed" {
		t.Fatal("confirm replay resurrected failed", again, err)
	}
	if _, err := s.CancelCleanupJob(ctx, other.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupJobDeadlineRollsBackAndReleasesBorrowedConnection(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 2, 1, "")
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	// A local recursive SQL fixture holds the physical DELETE long enough for
	// cancellation to exercise database/sql's rollback rather than only acquisition.
	if _, err := db.Conn().Exec(`CREATE TRIGGER cleanup_slow_delete BEFORE DELETE ON client_request_audit BEGIN SELECT sum(x) FROM (WITH RECURSIVE counter(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM counter WHERE x<10000000) SELECT x FROM counter); END`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !work || !errors.Is(err, ErrUnavailable) {
		t.Fatal(work, err)
	}
	if stats := db.Conn().Stats(); stats.InUse != 0 {
		t.Fatalf("rollback lease leaked %+v", stats)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "failed" || j.ErrorCode != "batch_timeout" || j.ProcessedRecords != 0 || cleanupCount(t, s, "client_request_audit") != 2 || cleanupCount(t, s, "audit_cleanup_items") != 2 {
		t.Fatalf("deadline partially committed %+v", j)
	}
	if _, err := db.Conn().Exec("DROP TRIGGER cleanup_slow_delete"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResumeCleanupJob(context.Background(), j.ID, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCleanupJobBatch(context.Background(), CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
}
