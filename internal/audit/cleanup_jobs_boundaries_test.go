package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func TestCleanupJobRealBodyFullSnapshotAndCurrentLengths(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	body := string(readableJSONBody(9 << 20))
	cleanupSeed(t, s, 4, int64(len(body))+128, body)
	p, j := cleanupStart(t, s, CleanupBatchLimits{})
	if p.RequestBodyBytes != 4*int64(len(body)) || p.RequestBodyBytes <= 32<<20 {
		t.Fatalf("truncated body snapshot %+v", p)
	}
	// Body length is separately checked, even with stale logical_bytes.
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.DeletedRecords != 3 || j.DeletedBodyBytes != 3*int64(len(body)) || j.DeletedLogicalBytes != 3 || j.RemainingRecords != 1 {
		t.Fatalf("body budget ignored %+v", j)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "completed" || j.DeletedBodyBytes != 4*int64(len(body)) {
		t.Fatalf("not all bodies deleted %+v", j)
	}
}

func TestCleanupJobQueriesReadOnlyCoveringIndexes(t *testing.T) {
	db, _ := openAuditDB(t)
	var tableRoot int
	if err := db.Conn().QueryRow("SELECT rootpage FROM sqlite_schema WHERE name='client_request_audit'").Scan(&tableRoot); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, query string
		args        []any
	}{
		{"snapshot", "SELECT id,started_at,logical_bytes,length(CAST(request_body AS BLOB)) FROM " + auditStorageMetadata + " ORDER BY started_at,id LIMIT ?", []any{100001}},
		{"current", cleanupCurrentMetadataQuery + "?)", []any{strings.Repeat("a", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Conn().Query("EXPLAIN "+tc.query, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			cursors := map[int]bool{}
			columns := 0
			for rows.Next() {
				var addr, p1, p2, p3, p5 int
				var opcode string
				var p4, comment sql.NullString
				if err := rows.Scan(&addr, &opcode, &p1, &p2, &p3, &p4, &p5, &comment); err != nil {
					t.Fatal(err)
				}
				if opcode == "OpenRead" && p2 == tableRoot {
					cursors[p1] = true
				}
				if opcode == "Column" && cursors[p1] {
					t.Fatalf("audit table column read %d", p2)
				}
				if opcode == "Column" && !cursors[p1] {
					columns++
				}
				if opcode == "Function" && strings.HasPrefix(p4.String, "length(") {
					t.Fatal("recomputed body length")
				}
			}
			if rows.Err() != nil || columns == 0 {
				t.Fatal("did not read metadata", rows.Err())
			}
		})
	}
}

func TestCleanupJobSnapshotMaximumAndNoPartialPreview(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	// Exercise the exact same bound/transaction code under every race run.
	// Full production capacity and five-second latency are independently checked
	// by BenchmarkCleanupJobPreview100000 using the PUBLIC entry, without race.
	const testBound = 31
	if maxCleanupRecords != 100000 {
		t.Fatal("production snapshot maximum changed")
	}
	cleanupSeed(t, s, testBound, 1, "")
	p, err := s.previewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}, testBound)
	if err != nil || p.Records != testBound {
		t.Fatalf("max snapshot %+v %v", p, err)
	}
	if _, err := db.Conn().Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,100001,1)", strings.Repeat("f", 64), "overflow"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.previewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}, testBound); !errors.Is(err, ErrCleanupTooLarge) {
		t.Fatal("silently truncated snapshot", err)
	}
	if cleanupCount(t, s, "audit_cleanup_previews") != 1 || cleanupCount(t, s, "audit_cleanup_items") != testBound {
		t.Fatal("overflow persisted partial snapshot")
	}
}

func TestCleanupJobConcurrentWorkersCommitOnce(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 31, 1, "")
	_, j := cleanupStart(t, s, CleanupBatchLimits{MaxRecords: 5})
	failures := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); failures <- err }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	j = cleanupRead(t, s, j.ID)
	if j.DeletedRecords != 31 || j.ProcessedRecords != 31 || j.Batches != 7 || j.State != "completed" {
		t.Fatalf("double-counted concurrent workers %+v", j)
	}
}

func TestCleanupJobTransientFailureCannotLoseActiveTask(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 3, 1, "")
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	for _, query := range []string{
		`CREATE TRIGGER cleanup_fail_delete BEFORE DELETE ON client_request_audit BEGIN SELECT RAISE(ABORT,'delete unavailable'); END`,
		`CREATE TRIGGER cleanup_fail_state BEFORE UPDATE ON audit_cleanup_jobs WHEN new.state='failed' BEGIN SELECT RAISE(ABORT,'state unavailable'); END`,
	} {
		if _, err := db.Conn().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !work || !errors.Is(err, ErrUnavailable) {
		t.Fatal(work, err)
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "queued" || j.ProcessedRecords != 0 || cleanupCount(t, s, "audit_cleanup_items") != 3 {
		t.Fatalf("lost task %+v", j)
	}
	for _, query := range []string{"DROP TRIGGER cleanup_fail_delete", "DROP TRIGGER cleanup_fail_state"} {
		if _, err := db.Conn().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); !work || err != nil {
		t.Fatal(work, err)
	}
	if cleanupRead(t, s, j.ID).State != "completed" {
		t.Fatal("not automatically retried")
	}
}

func TestCleanupJobCanceledContextReleasesConnectionAndRetainsWork(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 3, 1, "")
	_, j := cleanupStart(t, s, CleanupBatchLimits{})
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); done <- err }()
		cancel()
		<-done
		if stats := db.Conn().Stats(); stats.InUse != 0 {
			t.Fatalf("borrowed connection leaked %+v", stats)
		}
	}
	j = cleanupRead(t, s, j.ID)
	if j.State != "queued" || j.ProcessedRecords != 0 || cleanupCount(t, s, "audit_cleanup_items") != 3 {
		t.Fatalf("cancellation lost task %+v", j)
	}
	if _, err := s.RunCleanupJobBatch(context.Background(), CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupJobMetadataGCExcludesActiveAndBoundsHistory(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 1, 1, "")
	_, active := cleanupStart(t, s, CleanupBatchLimits{})
	now := time.Now().UnixMilli()
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_jobs SET updated_at=0 WHERE id=?", active.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 105; i++ {
		hash := fmt.Sprintf("%064x", i+100)
		updated := now + int64(i)
		if i == 0 {
			updated = 0
		}
		if _, err := tx.Exec("INSERT INTO audit_cleanup_jobs(id,token_hash,principal_hash,state,total_records,remaining_records,batch_max_records,batch_max_bytes,created_at,updated_at) VALUES(?,?,?,'failed',1,1,1000,33554432,?,?)", hash, hash, cleanupOwner, updated, updated); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec("INSERT INTO audit_cleanup_items(snapshot_hash,record_id,started_at,logical_bytes,body_bytes) VALUES(?,?,0,1,0)", hash, hash); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Trigger metadata GC without touching active audit records.
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	if cleanupCount(t, s, "audit_cleanup_jobs") != 101 || cleanupCount(t, s, "audit_cleanup_items") != 102 {
		t.Fatal("history not bounded or active lost")
	}
	if cleanupRead(t, s, active.ID).State != "queued" {
		t.Fatal("GC removed active")
	}
	jobs, err := s.ListCleanupJobs(ctx, cleanupOwner)
	if err != nil || len(jobs) == 0 || jobs[0].ID != active.ID {
		t.Fatal("active hidden by history", jobs, err)
	}
}

func TestCleanupJobIdleWorkerReclaimsExpiredMetadata(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 1, 1, "")
	ctx := context.Background()
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_previews SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil || work {
		t.Fatal(work, err)
	}
	if cleanupCount(t, s, "audit_cleanup_previews") != 0 || cleanupCount(t, s, "audit_cleanup_items") != 0 {
		t.Fatal("idle worker kept expired snapshots")
	}
	if cleanupCount(t, s, "client_request_audit") != 1 {
		t.Fatal("GC touched audit")
	}
}

func TestCleanupJobV6UpgradePreservesOtherTablesAndIsIdempotent(t *testing.T) {
	db, _ := openAuditDB(t)
	ctx := context.Background()
	for _, query := range []string{
		"DROP TABLE audit_cleanup_items", "DROP TABLE audit_cleanup_previews", "DROP TABLE audit_cleanup_jobs", "DROP INDEX client_request_audit_cleanup_metadata_idx", "DELETE FROM schema_migrations WHERE version=6",
		"INSERT INTO rules_state(id,payload,updated_at) VALUES(1,'test rules','now')",
		"INSERT INTO quota_usage(api_key,total_cost_nano_usd) VALUES('test quota',41)",
	} {
		if _, err := db.Conn().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	s := NewStore(db, Config{})
	cleanupSeed(t, s, 1, 7, "preserved test body")
	for i := 0; i < 2; i++ {
		if err := sqlitestore.Migrate(ctx, db.Conn()); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := cleanupStart(t, s, CleanupBatchLimits{})
	if p.Records != 1 || p.RequestBodyBytes != 19 {
		t.Fatal("migration changed audit", p)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	var rules string
	var quota int64
	if err := db.Conn().QueryRow("SELECT payload FROM rules_state").Scan(&rules); err != nil || rules != "test rules" {
		t.Fatal("rules changed", err)
	}
	if err := db.Conn().QueryRow("SELECT total_cost_nano_usd FROM quota_usage").Scan(&quota); err != nil || quota != 41 {
		t.Fatal("quota changed", err)
	}
	var versions int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=6").Scan(&versions); err != nil || versions != 1 {
		t.Fatal("migration not idempotent", err)
	}
}
