package usage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

// TestSQLitePersistsUsageAndLedger covers the SQLite backend: aggregates, the
// per-model tuple rows and the hourly ledger must all survive a reopen, and the
// schema migration must be idempotent.
func TestSQLitePersistsUsageAndLedger(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")

	store := NewStore(pricing.NewEngine())
	if err := store.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("configure sqlite: %v", err)
	}
	if got := store.SQLitePath(); got != dbPath {
		t.Fatalf("SQLitePath = %q, want %q", got, dbPath)
	}
	if lock := store.SQLiteLockPath(); lock != dbPath+".lock" {
		t.Fatalf("lock path = %q, want %q", lock, dbPath+".lock")
	}

	feedLedgerRequest(t, store, "db-req-1", "sk-db", "数据库", "gemini-3.8-flash-high", "gemini-4-argon-high",
		"openai", "antigravity", "antigravity-db@gmail.com.json", 100, 20, 40)
	feedLedgerRequest(t, store, "db-req-2", "sk-db", "数据库", "gemini-3.8-flash-high", "gemini-3.8-flash-n",
		"openai", "antigravity", "antigravity-db@gmail.com.json", 50, 10, 0)

	if err := store.FlushNow(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	_ = store.Close()

	// Reopen purely from SQLite.
	reopened := NewStore(pricing.NewEngine())
	if err := reopened.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	snap := reopened.Snapshot("sk-db", "", nil, nil, nil, false)
	ks := snap.Keys["sk-db"]
	if ks == nil {
		t.Fatalf("key stats missing after sqlite reload")
	}
	if ks.TotalRequests != 2 || ks.TotalTokens != 180 {
		t.Fatalf("aggregates wrong after reload: requests=%d tokens=%d", ks.TotalRequests, ks.TotalTokens)
	}
	if len(ks.Models) != 2 {
		t.Fatalf("tuple rows wrong after reload: %v", modelKeys(ks.Models))
	}
	toN := ks.Models[tupleKey("gemini-3.8-flash-high", "gemini-3.8-flash-n")]
	toArgon := ks.Models[tupleKey("gemini-3.8-flash-high", "gemini-4-argon-high")]
	if toN == nil || toN.Requests != 1 || toArgon == nil || toArgon.Requests != 1 {
		t.Fatalf("expected one tuple per served model, got %+v / %+v", toN, toArgon)
	}

	acct := snap.Accounts["account::antigravity-db@gmail.com.json"]
	if acct == nil || acct.Requests != 2 || len(acct.Models) != 2 {
		t.Fatalf("account data wrong after reload: %+v", acct)
	}

	now := time.Now()
	ledger := reopened.QueryLedger(LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)})
	if ledger.Requests != 2 || ledger.ModelCount != 1 || ledger.Models[0].Model != "gemini-3.8-flash-high" {
		t.Fatalf("ledger wrong after reload: %+v", ledger)
	}

	// Reopening again must be idempotent and keep the data.
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened: %v", err)
	}
	again := NewStore(pricing.NewEngine())
	if err := again.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("third open: %v", err)
	}
	if data := again.Snapshot("sk-db", "", nil, nil, nil, false); data.Keys["sk-db"].TotalRequests != 2 {
		t.Fatalf("second reopen lost data")
	}
	_ = again.Close()
}

// TestSQLiteIncrementalFlush verifies that only dirty rows are written: a second
// flush after one extra request must keep earlier rows intact.
func TestSQLiteIncrementalFlush(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")

	store := NewStore(pricing.NewEngine())
	if err := store.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("configure: %v", err)
	}
	feedLedgerRequest(t, store, "inc-1", "sk-a", "A", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm-a.json", 10, 1, 0)
	feedLedgerRequest(t, store, "inc-2", "sk-b", "B", "kimi-k3", "kimi-k3", "openai", "moonshot", "kimi-b.json", 20, 2, 0)
	if err := store.FlushNow(); err != nil {
		t.Fatalf("first flush: %v", err)
	}

	// Touch only sk-a, then flush again.
	feedLedgerRequest(t, store, "inc-3", "sk-a", "A", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm-a.json", 5, 1, 0)
	if err := store.FlushNow(); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	_ = store.Close()

	reopened := NewStore(pricing.NewEngine())
	if err := reopened.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	snap := reopened.Snapshot("", "", nil, nil, nil, false)
	if snap.Keys["sk-a"] == nil || snap.Keys["sk-a"].TotalRequests != 2 {
		t.Fatalf("sk-a should have 2 requests, got %+v", snap.Keys["sk-a"])
	}
	if snap.Keys["sk-b"] == nil || snap.Keys["sk-b"].TotalRequests != 1 {
		t.Fatalf("sk-b row was lost by the incremental flush: %+v", snap.Keys["sk-b"])
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened: %v", err)
	}
}

// TestSQLiteResetClearsPersistedRows verifies a reset is reflected in the database.
func TestSQLiteResetClearsPersistedRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("configure: %v", err)
	}
	feedLedgerRequest(t, store, "reset-1", "sk-reset", "重置", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm.json", 5, 5, 0)
	if err := store.Reset("sk-reset"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	_ = store.Close()

	reopened := NewStore(pricing.NewEngine())
	if err := reopened.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if _, ok := reopened.Snapshot("sk-reset", "", nil, nil, nil, false).Keys["sk-reset"]; ok {
		t.Fatalf("reset key still present in sqlite")
	}
	if ledger := reopened.LedgerStatus(); ledger.Entries != 0 {
		t.Fatalf("reset key still has ledger rows: %d", ledger.Entries)
	}
}

// TestSQLiteRejectsSecondWriter pins the cross-process writer lock: a second open
// of the same database must fail while the first handle is alive.
func TestSQLiteRejectsSecondWriter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")

	first := NewStore(pricing.NewEngine())
	if err := first.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("first open: %v", err)
	}

	second := NewStore(pricing.NewEngine())
	err := second.ConfigureSQLite(dbPath, time.Hour)
	if err == nil {
		_ = second.Close()
		t.Fatalf("second writer must be rejected while the first holds the lock")
	}

	_ = first.Close()
	if err := second.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("lock was not released after Close: %v", err)
	}
	_ = second.Close()
}
