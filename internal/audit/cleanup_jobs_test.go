package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestCleanupJobFullSnapshot(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	tx, err := db.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 1005; i++ {
		if _, err := tx.Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,?,?)", fmt.Sprintf("%064x", i), fmt.Sprint(i), i+1, 40<<10); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner := strings.Repeat("a", 64)
	preview, err := s.PreviewCleanupJob(ctx, "all", "", owner, CleanupBatchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Records != 1005 || preview.LogicalBytes != 1005*(40<<10) || preview.BatchMaxRecords != 1000 || preview.BatchMaxBytes != 32<<20 {
		t.Fatalf("not full snapshot: %+v", preview)
	}
	job, err := s.StartCleanupJob(ctx, preview.Token, owner)
	if err != nil {
		t.Fatal(err)
	}
	// A newly backfilled older row must never enter the captured scope.
	if _, err := db.Conn().Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,0,1)", strings.Repeat("f", 64), "backfill"); err != nil {
		t.Fatal(err)
	}
	work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{})
	if err != nil || !work {
		t.Fatalf("first batch: %v %v", work, err)
	}
	job, err = s.GetCleanupJob(ctx, job.ID, owner)
	if err != nil || job.ProcessedRecords != 819 || job.RemainingRecords != 186 || job.Batches != 1 {
		t.Fatalf("bounded batch: %+v %v", job, err)
	}
	work, err = s.RunCleanupJobBatch(ctx, CleanupBatchLimits{})
	if err != nil || !work {
		t.Fatalf("second batch: %v %v", work, err)
	}
	job, err = s.GetCleanupJob(ctx, job.ID, owner)
	if err != nil || job.State != "completed" || job.DeletedRecords != 1005 || job.ProcessedRecords != 1005 || job.RemainingRecords != 0 || job.Batches != 2 {
		t.Fatalf("completed: %+v %v", job, err)
	}
	var remaining string
	if err := db.Conn().QueryRow("SELECT request_id FROM client_request_audit").Scan(&remaining); err != nil || remaining != "backfill" {
		t.Fatalf("snapshot widened: %q %v", remaining, err)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil || work {
		t.Fatalf("idle: %v %v", work, err)
	}
}
