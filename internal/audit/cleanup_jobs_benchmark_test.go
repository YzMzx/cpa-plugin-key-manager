package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// Run explicitly with -run=^$ -bench=^BenchmarkCleanupJobPreview100000$
// -benchtime=1x. Race tests cover the identical implementation with a small
// exact/max+1 bound; production-size latency is not meaningful under the pure-Go
// SQLite driver's instruction-level race instrumentation. No production deadline
// or snapshot limit is changed for either path.
func BenchmarkCleanupJobPreview100000(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		db, err := sqlitestore.Open(filepath.Join(b.TempDir(), "capacity.db"), sqlitestore.Options{})
		if err != nil {
			b.Fatal(err)
		}
		s := NewStore(db, Config{})
		if _, err := db.Conn().Exec(`WITH RECURSIVE seq(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM seq WHERE n<99999) INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) SELECT printf('%064x',n),CAST(n AS TEXT),n+1,1 FROM seq`); err != nil {
			db.Close()
			b.Fatal(err)
		}
		b.StartTimer()
		started := time.Now()
		p, err := s.PreviewCleanupJob(context.Background(), "all", "", cleanupOwner, CleanupBatchLimits{})
		duration := time.Since(started)
		b.StopTimer()
		if err != nil || p.Records != 100000 || p.LogicalBytes != 100000 {
			db.Close()
			b.Fatalf("100000-row public preview: %+v %v", p, err)
		}
		if duration >= 5*time.Second {
			db.Close()
			b.Fatalf("public preview exceeded production budget: %s", duration)
		}
		b.ReportMetric(float64(duration.Nanoseconds()), "preview-ns/op")
		b.Logf("100000-row public preview duration: %s", duration)
		if _, err := db.Conn().Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,100001,1)", strings.Repeat("f", 64), "overflow"); err != nil {
			db.Close()
			b.Fatal(err)
		}
		if _, err := s.PreviewCleanupJob(context.Background(), "all", "", cleanupOwner, CleanupBatchLimits{}); !errors.Is(err, ErrCleanupTooLarge) {
			db.Close()
			b.Fatal("silently truncated 100001-row public snapshot", err)
		}
		var snapshots, items int
		if err := db.Conn().QueryRow("SELECT COUNT(*) FROM audit_cleanup_previews").Scan(&snapshots); err != nil {
			db.Close()
			b.Fatal(err)
		}
		if err := db.Conn().QueryRow("SELECT COUNT(*) FROM audit_cleanup_items").Scan(&items); err != nil {
			db.Close()
			b.Fatal(err)
		}
		if snapshots != 1 || items != 100000 {
			db.Close()
			b.Fatal("max+1 leaked partial snapshot", snapshots, items)
		}
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
