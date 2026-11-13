package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCleanupPreviewBoundsRecordsAndBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		size  int64
		want  int64
	}{
		{"record_limit", 1001, 256, 1000},
		{"byte_limit", 4, 10 << 20, 3},
		{"exact_limit", 2, 16 << 20, 2},
		{"empty", 0, 256, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := openAuditDB(t)
			s := NewStore(db, Config{Enabled: true})
			tx, err := db.Conn().Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for i := 0; i < tc.count; i++ {
				if _, err := tx.Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,0,?)", fmt.Sprintf("%064x", i), fmt.Sprint(i), tc.size); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			plan, err := s.PreviewCleanup(context.Background(), "all", time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if plan.Records != tc.want || plan.RemainingRecords != int64(tc.count)-tc.want || plan.Limited != (int64(tc.count) > tc.want) {
				t.Fatalf("wrong bounded preview: %+v", plan)
			}
			for i, id := range plan.IDs {
				if id != fmt.Sprintf("%064x", i) {
					t.Fatal("not oldest prefix")
				}
			}
			result, err := s.ApplyCleanup(context.Background(), plan)
			if err != nil || result.Records != tc.want {
				t.Fatalf("apply: %+v %v", result, err)
			}
			next, err := s.PreviewCleanup(context.Background(), "all", time.Time{})
			if err != nil || next.Records != int64(tc.count)-tc.want {
				t.Fatalf("remaining preview: %+v %v", next, err)
			}
		})
	}
}

func TestCleanupRejectsOversizedOldestOrGrownSnapshot(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	mustBegin(t, s, auditRecord("oldest"))
	mustBegin(t, s, auditRecord("later"))
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET started_at=0 WHERE request_id='oldest'"); err != nil {
		t.Fatal(err)
	}
	plan, err := s.PreviewCleanup(context.Background(), "all", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=? WHERE request_id='oldest'", maxCleanupBatchBytes+1); err != nil {
		t.Fatal(err)
	}
	result, err := s.ApplyCleanup(context.Background(), plan)
	if !errors.Is(err, ErrUnavailable) || result != (CleanupResult{}) {
		t.Fatalf("grew beyond budget: %+v %v", result, err)
	}
	usage, err := s.Storage(context.Background())
	if err != nil || usage.Records != 2 {
		t.Fatalf("mutated oversized snapshot: %+v %v", usage, err)
	}
	if _, err := s.PreviewCleanup(context.Background(), "all", time.Time{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("skipped oversized oldest row")
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=9223372036854775807"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyCleanup(context.Background(), plan); !errors.Is(err, ErrUnavailable) {
		t.Fatal("overflow accepted")
	}
	// Body length must independently bound work, even if logical_bytes is stale.
	body := string(readableJSONBody(int(maxCleanupBatchBytes + 1)))
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=1,request_body=? WHERE request_id='oldest'", body); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=1 WHERE request_id='later'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyCleanup(context.Background(), plan); !errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized body accepted")
	}
	if _, err := s.PreviewCleanup(context.Background(), "all", time.Time{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("oversized body preview accepted")
	}
	usage, err = s.Storage(context.Background())
	if err != nil || usage.Records != 2 {
		t.Fatalf("body growth deleted rows: %+v %v", usage, err)
	}
}
