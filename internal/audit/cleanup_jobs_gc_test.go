package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCleanupJobExpiredSnapshotGCIsBoundedAndCannotResumePartial(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 6001, 1, "")
	p, j := cleanupStart(t, s, CleanupBatchLimits{})
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_jobs SET state='failed',updated_at=0 WHERE id=?", j.ID); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil || work {
		t.Fatal(work, err)
	}
	if n := cleanupCount(t, s, "audit_cleanup_items"); n != 1001 {
		t.Fatalf("GC must consume at most 5000 items, remaining=%d", n)
	}
	j = cleanupRead(t, s, j.ID)
	if j.ErrorCode != "snapshot_expired" {
		t.Fatalf("partial snapshot not marked expired %+v", j)
	}
	if _, err := s.ResumeCleanupJob(ctx, j.ID, cleanupOwner); !errors.Is(err, ErrCleanupJobState) {
		t.Fatal("resumed partly collected snapshot", err)
	}
	if again, err := s.StartCleanupJob(ctx, p.Token, cleanupOwner); err != nil || again.ID != j.ID {
		t.Fatal("expired snapshot token should remain idempotent until metadata collected", again, err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	if cleanupCount(t, s, "audit_cleanup_items") != 0 || cleanupCount(t, s, "audit_cleanup_jobs") != 0 || cleanupCount(t, s, "client_request_audit") != 6001 {
		t.Fatal("GC leaked metadata or touched audit")
	}
}

func TestCleanupJobRetainedPreviewDescriptorsHaveHardCap(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	// Sixteen EXPIRED descriptors and zero live previews must also hit the cap.
	// Give the first descriptor 6000 items so one bounded GC cannot finish it;
	// every other descriptor has one item. This cannot pass via the eight-live cap.
	if _, err := db.Conn().Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<16) INSERT INTO audit_cleanup_previews(token_hash,principal_hash,created_at,expires_at,scope,before_value,records,logical_bytes,body_bytes,batch_max_records,batch_max_bytes) SELECT printf('%064x',n),?,0,0,'all','',1,1,0,1000,33554432 FROM seq`, cleanupOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO audit_cleanup_items SELECT token_hash,token_hash,1,1,0 FROM audit_cleanup_previews WHERE token_hash!=printf('%064x',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<6000) INSERT INTO audit_cleanup_items SELECT printf('%064x',1),printf('%064x',n),n,1,0 FROM seq`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); !errors.Is(err, ErrCleanupBusy) {
		t.Fatal("sixteen retained descriptors did not enforce cap", err)
	}
	if _, err := s.RunCleanupJobBatch(ctx, CleanupBatchLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); err != nil {
		t.Fatal("bounded drain did not release descriptors", err)
	}
	if cleanupCount(t, s, "audit_cleanup_previews") != 1 || cleanupCount(t, s, "audit_cleanup_items") != 0 {
		t.Fatal("retained backlog not drained")
	}
}

func TestCleanupJobExpiredPreviewBacklogDoesNotUseValidPreviewSlots(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{})
	ctx := context.Background()
	cleanupSeed(t, s, 6001, 1, "")
	p, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("UPDATE audit_cleanup_previews SET expires_at=0 WHERE token_hash=?", cleanupDigest(p.Token)); err != nil {
		t.Fatal(err)
	}
	// Simulate eight expired descriptors sharing a partly collected backlog.
	for i := 0; i < 7; i++ {
		hash := strings.Repeat(string(rune('b'+i)), 64)
		if _, err := db.Conn().Exec("INSERT INTO audit_cleanup_previews SELECT ?,principal_hash,created_at,expires_at,scope,before_value,records,logical_bytes,body_bytes,batch_max_records,batch_max_bytes FROM audit_cleanup_previews LIMIT 1", hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PreviewCleanupJob(ctx, "all", "", cleanupOwner, CleanupBatchLimits{}); err != nil {
		t.Fatal("expired previews blocked fresh confirmation", err)
	}
	var live int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM audit_cleanup_previews WHERE expires_at>0").Scan(&live); err != nil || live != 1 {
		t.Fatal(live, err)
	}
}
