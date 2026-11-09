package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func TestCancelledPruneReleasesConnectionBeforeReturning(t *testing.T) {
	database, err := sqlitestore.Open(filepath.Join(t.TempDir(), "audit.db"), sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := NewStore(database, Config{Enabled: true, RetentionDays: 7, MaxRecords: 100, MaxBodyBytes: 1024, MaxTotalBytes: 1 << 20})
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- store.Prune(ctx, time.Now()) }()
		cancel()
		<-done
		if stats := database.Conn().Stats(); stats.InUse != 0 {
			t.Fatalf("cancelled prune retained connection: %+v", stats)
		}
	}
}
