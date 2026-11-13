package audit

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCapacityCeilingTenGiBAndUnchangedDefault(t *testing.T) {
	for _, tc := range []struct{ input, want int64 }{{0, 64 << 20}, {1 << 30, 1 << 30}, {10 << 30, 10 << 30}, {(10 << 30) + 1, 10 << 30}} {
		s := NewStore(nil, Config{MaxTotalBytes: tc.input})
		if s.cfg.MaxTotalBytes != tc.want {
			t.Fatalf("capacity %d clamped to %d, want %d", tc.input, s.cfg.MaxTotalBytes, tc.want)
		}
	}
}

func TestPruneRetainsLogicalPayloadBeyondOneGiB(t *testing.T) {
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true, MaxTotalBytes: 10 << 30})
	// Small test rows with synthetic logical sizes exercise int64 accounting without
	// allocating a multi-gigabyte fixture or touching a real plugin database.
	for i := 0; i < 3; i++ {
		mustBegin(t, s, auditRecord(fmt.Sprint(i)))
		if _, err := db.Conn().Exec("UPDATE client_request_audit SET logical_bytes=? WHERE request_id=?", int64(2<<30), fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Prune(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	usage, err := s.Storage(context.Background())
	if err != nil || usage.Records != 3 || usage.LogicalBytes != 6<<30 || usage.MaxTotalBytes != 10<<30 || usage.UtilizationPercent != 60 {
		t.Fatalf("capacity truncated: %+v %v", usage, err)
	}
}
