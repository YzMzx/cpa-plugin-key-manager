package usage

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestFlushNowConcurrentLedgerUpdates(t *testing.T) {
	s := NewStore(nil)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				id := fmt.Sprintf("worker-%d-%d", worker, i)
				s.BeginRequest(id, "sk-race", "", "model-a", "model-a", "openai", false)
				s.ObserveHostUsageRecord(pluginapi.UsageRecord{RequestID: id, APIKey: "sk-race", Model: "model-a", Detail: pluginapi.UsageDetail{InputTokens: 2, TotalTokens: 2}}, "")
				if err := s.FlushNow(); err != nil {
					t.Errorf("flush: %v", err)
					return
				}
				s.QueryLedger(LedgerQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
			}
		}(worker)
	}
	wg.Wait()
	if got := s.Snapshot("sk-race", "", nil, nil, nil, false).Keys["sk-race"].TotalRequests; got != 400 {
		t.Fatalf("requests=%d, want 400", got)
	}
}

func waitForPersistence(t *testing.T, s *Store, predicate func(PersistenceStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if predicate(s.PersistenceStatus()) {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("persistence operation did not reach expected state")
}

func TestFlushSerializesSnapshotThroughCommit(t *testing.T) {
	s := NewStore(nil)
	path := filepath.Join(t.TempDir(), "usage.db")
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", path)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	feedLedgerRequest(t, s, "first", "sk-order", "", "model-a", "model-a", "openai", "provider", "acct", 2, 0, 0)
	held, err := s.DB().Conn().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = held.Close()
		}
	})
	first := make(chan error, 1)
	go func() { first <- s.FlushNow() }()
	waitForPersistence(t, s, func(st PersistenceStatus) bool { return st.Flushing })
	feedLedgerRequest(t, s, "second", "sk-order", "", "model-a", "model-a", "openai", "provider", "acct", 3, 0, 0)
	second := make(chan error, 1)
	go func() { second <- s.FlushNow() }()
	// The first batch cannot commit while we own the only database connection.
	// The second flush must not consume the newer dirty markers meanwhile.
	if !s.PersistenceStatus().Dirty {
		t.Fatal("inflight batch must report dirty")
	}
	if s.flushMu.TryLock() {
		s.flushMu.Unlock()
		t.Fatal("flush lost sequencing lock before commit")
	}
	if s.PersistenceStatus().DirtyKeys != 1 {
		t.Fatal("new request must stay queued behind first batch")
	}
	_ = held.Close()
	released = true
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	var requests, tokens int64
	if err := s.DB().Conn().QueryRow("SELECT total_requests,total_tokens FROM key_usage WHERE api_key=?", "sk-order").Scan(&requests, &tokens); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || tokens != 5 {
		t.Fatalf("out-of-order persistence: requests=%d tokens=%d", requests, tokens)
	}
	if status := s.PersistenceStatus(); status.Dirty || status.LastError != "" || status.LastSuccessAt == "" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestFailedReloadAndCloseKeepOldDatabaseAndDirtyUsage(t *testing.T) {
	s := NewStore(nil)
	path := filepath.Join(t.TempDir(), "usage.db")
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", path)
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	old := s.DB()
	feedLedgerRequest(t, s, "reload", "sk-private-secret", "", "model-a", "model-a", "openai", "provider", "acct", 7, 0, 0)
	if _, err := old.Conn().Exec("ALTER TABLE key_usage RENAME TO key_usage_broken"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSQLite(path, time.Minute); err == nil {
		t.Fatal("reload must report failed flush")
	}
	if s.DB() != old {
		t.Fatal("failed reload replaced old handle")
	}
	if err := s.Close(); err == nil {
		t.Fatal("close must report failed flush")
	}
	if s.DB() != old {
		t.Fatal("failed close discarded old handle")
	}
	if st := s.PersistenceStatus(); !st.Dirty || st.LastError == "" {
		t.Fatalf("failed write not exposed: %+v", st)
	}
	if _, err := old.Conn().Exec("ALTER TABLE key_usage_broken RENAME TO key_usage"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if s.DB() != old {
		t.Fatal("same-path reload must preserve shared rules repository handle")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := NewStore(nil)
	if err := reopened.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Snapshot("sk-private-secret", "", nil, nil, nil, false).Keys["sk-private-secret"]; got == nil || got.TotalTokens != 7 {
		t.Fatalf("pending history lost: %+v", got)
	}
}

func TestFailedCandidateOpenPreservesLiveStore(t *testing.T) {
	s := NewStore(nil)
	path := filepath.Join(t.TempDir(), "usage.db")
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := s.DB()
	feedLedgerRequest(t, s, "candidate", "sk-candidate", "", "model-a", "model-a", "openai", "provider", "acct", 9, 0, 0)
	if err := s.ConfigureSQLite(filepath.Join(path, "invalid.db"), time.Hour); err == nil {
		t.Fatal("invalid candidate must fail")
	}
	if s.DB() != old || s.Snapshot("sk-candidate", "", nil, nil, nil, false).Keys["sk-candidate"].TotalTokens != 9 {
		t.Fatal("candidate error changed live state")
	}
	if err := s.FlushNow(); err != nil {
		t.Fatal(err)
	}
}

func TestPeriodicFlushExposesFailureAndRecovers(t *testing.T) {
	s := NewStore(nil)
	path := filepath.Join(t.TempDir(), "usage.db")
	if err := s.ConfigureSQLite(path, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.DB().Conn().Exec("ALTER TABLE key_usage RENAME TO key_usage_broken"); err != nil {
		t.Fatal(err)
	}
	feedLedgerRequest(t, s, "periodic", "sk-periodic", "", "model-a", "model-a", "openai", "provider", "acct", 4, 0, 0)
	waitForPersistence(t, s, func(st PersistenceStatus) bool { return st.LastError != "" && st.Dirty })
	if _, err := s.DB().Conn().Exec("ALTER TABLE key_usage_broken RENAME TO key_usage"); err != nil {
		t.Fatal(err)
	}
	waitForPersistence(t, s, func(st PersistenceStatus) bool { return st.LastError == "" && !st.Dirty && st.LastSuccessAt != "" })
}

func TestResetWaitsForEarlierFlushAndDoesNotResurrectRows(t *testing.T) {
	s := NewStore(nil)
	path := filepath.Join(t.TempDir(), "usage.db")
	if err := s.ConfigureSQLite(path, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	feedLedgerRequest(t, s, "pre-reset", "sk-reset-order", "", "model-a", "model-a", "openai", "provider", "acct", 2, 0, 0)
	held, err := s.DB().Conn().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = held.Close()
		}
	})
	first := make(chan error, 1)
	go func() { first <- s.FlushNow() }()
	waitForPersistence(t, s, func(st PersistenceStatus) bool { return st.Flushing })
	reset := make(chan error, 1)
	go func() { reset <- s.Reset("") }()
	_ = held.Close()
	released = true
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-reset; err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB().Conn().QueryRow("SELECT COUNT(*) FROM key_usage").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old flush resurrected reset row: %d", count)
	}
}
