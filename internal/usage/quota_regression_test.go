package usage

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func TestQuotaMigrationSeedsOnceAndResetCannotReseed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sqlitestore.Open(path, sqlitestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Build a v4 fixture without touching any real database.
	for _, q := range []string{"DROP TABLE quota_usage", "DELETE FROM schema_migrations WHERE version=5", "INSERT INTO key_usage(api_key,total_cost_nano_usd) VALUES('retired',123000)"} {
		if _, err := db.Conn().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := sqlitestore.Migrate(context.Background(), db.Conn()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := regressionStore(t)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := s.GetKeyCostUSD("retired"); got != .000123 {
		t.Fatalf("migration cost=%g", got)
	}
	if err := s.Reset(""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = regressionStore(t)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.GetKeyCostUSD("retired"); got != .000123 {
		t.Fatalf("restart after migration/reset=%g", got)
	}
}

func TestResetFailureRestoresUnflushedWork(t *testing.T) {
	for _, target := range []string{"k", ""} {
		t.Run("target="+target, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "usage.db")
			s := regressionStore(t)
			if err := s.ConfigureSQLite(path, time.Hour); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if s.DB() != nil {
					_, _ = s.DB().Conn().Exec("DROP TRIGGER IF EXISTS fail_reset")
					_ = s.Close()
				}
			}()
			regressionBill(s, "seed", "k", 10)
			if err := s.FlushNow(); err != nil {
				t.Fatal(err)
			}
			regressionBill(s, "pending", "k", 90)
			if _, err := s.DB().Conn().Exec(`CREATE TRIGGER fail_reset BEFORE DELETE ON key_usage BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
				t.Fatal(err)
			}
			if err := s.Reset(target); err == nil {
				t.Fatal("reset should fail")
			}
			if !s.PersistenceStatus().Dirty {
				t.Fatal("lost dirty retry")
			}
			if _, err := s.DB().Conn().Exec("DROP TRIGGER fail_reset"); err != nil {
				t.Fatal(err)
			}
			if err := s.FlushNow(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = regressionStore(t)
			if err := s.ConfigureSQLite(path, time.Hour); err != nil {
				t.Fatal(err)
			}
			if k := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"]; k == nil || k.TotalTokens != 100 {
				t.Fatalf("lost failed-reset work: %+v", k)
			}
			if got := s.GetKeyCostUSD("k"); got != .0001 {
				t.Fatalf("lost quota=%g", got)
			}
		})
	}
}

func TestConcurrentResetAccountingAndFlushPreserveQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	s := regressionStore(t)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			regressionBill(s, fmt.Sprint(i), "k", 100)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := s.Reset(""); err != nil {
				errs <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := s.FlushNow(); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := s.GetKeyCostUSD("k"); got != .01 {
		t.Fatalf("concurrent quota=%g", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = regressionStore(t)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.GetKeyCostUSD("k"); got != .01 {
		t.Fatalf("persisted concurrent quota=%g", got)
	}
}
