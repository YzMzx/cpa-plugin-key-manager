package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func BenchmarkAuditStorageLargePayload(b *testing.B) {
	db, err := sqlitestore.Open(filepath.Join(b.TempDir(), "storage.db"), sqlitestore.Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
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
	s := NewStore(db, Config{MaxTotalBytes: 1 << 30})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		usage, err := s.Storage(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if usage.Records != 96 || usage.RequestBodyBytes != 96*int64(len(body)) {
			b.Fatalf("wrong storage: %+v", usage)
		}
	}
	b.StopTimer() // Exclude connection close/checkpoint and temporary file cleanup.
}
