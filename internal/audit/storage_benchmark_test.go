package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func benchmarkAuditPayloadStore(b *testing.B) *Store {
	b.Helper()
	db, err := sqlitestore.Open(filepath.Join(b.TempDir(), "storage.db"), sqlitestore.Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	// Near the 1 GiB retention limit, without involving live plugin data.
	body := string(readableJSONBody(10 << 20))
	tx, err := db.Conn().Begin()
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 96; i++ {
		_, err = tx.Exec("INSERT INTO client_request_audit(id,request_id,started_at,request_body,logical_bytes) VALUES(?,?,0,?,?)", fmt.Sprintf("%064x", i), fmt.Sprint(i), body, len(body)+256)
		if err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return NewStore(db, Config{MaxTotalBytes: 1 << 30})
}

func BenchmarkAuditStorageLargePayload(b *testing.B) {
	s := benchmarkAuditPayloadStore(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		usage, err := s.Storage(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if usage.Records != 96 || usage.RequestBodyBytes != 96*(10<<20) {
			b.Fatalf("wrong storage: %+v", usage)
		}
	}
	b.StopTimer() // Exclude connection close/checkpoint and temporary file cleanup.
}

func BenchmarkAuditCleanupLargePayload(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := benchmarkAuditPayloadStore(b)
		plan, err := s.PreviewCleanup(context.Background(), "all", time.Time{})
		if err != nil {
			b.Fatal(err)
		}
		if !plan.Limited || plan.Records != 3 || plan.RemainingRecords != 93 {
			b.Fatalf("unbounded preview: %+v", plan)
		}
		b.StartTimer()
		result, err := s.ApplyCleanup(context.Background(), plan)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		if result.Records != plan.Records || result.BodyBytes != plan.BodyBytes || result.LogicalBytes != plan.LogicalBytes {
			b.Fatalf("wrong cleanup: %+v", result)
		}
		usage, err := s.Storage(context.Background())
		if err != nil || usage.Records != 96-plan.Records {
			b.Fatalf("cleanup incomplete: %+v %v", usage, err)
		}
	}
}
