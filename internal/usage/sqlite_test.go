package usage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
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

// TestSQLiteIgnoresAdjacentJSON pins the SQLite-only persistence boundary.
// Historical files are neither read, overwritten nor removed during configure/reload.
func TestSQLiteIgnoresAdjacentJSON(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "key_usage.db")
	oldPath := filepath.Join(dir, "key_usage_stats.json")
	old := []byte(`{"version":1,"keys":{"sk-old":{"api_key":"sk-old","total_requests":999}}}`)
	if err := os.WriteFile(oldPath, old, 0600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatal(err)
	}
	store.BeginRequest("sqlite-live", "sk-live", "live", "model", "model", "openai", false)
	store.ObserveResponse("sqlite-live", "model", "model", []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	store.CompleteRequest(pluginapi.RequestCompletion{RequestID: "sqlite-live", Outcome: pluginapi.RequestCompletionSucceeded}, "sk-live", "live")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	persisted := NewStore(pricing.NewEngine())
	if err := persisted.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatal(err)
	}
	defer persisted.Close()
	snap := persisted.Snapshot("", "", nil, nil, nil, false)
	if _, ok := snap.Keys["sk-old"]; ok {
		t.Fatal("historical JSON was read")
	}
	if live := snap.Keys["sk-live"]; live == nil || live.TotalRequests != 1 || live.TotalTokens != 5 {
		t.Fatalf("live SQLite records lost: %+v", live)
	}
	unchanged, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(unchanged, old) {
		t.Fatal("historical JSON was changed or removed")
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

// TestSQLiteFlushFailureIsRetried pins that a failed transaction re-queues its
// dirty markers instead of silently dropping the batch.
func TestSQLiteFlushFailureIsRetried(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("configure: %v", err)
	}

	// Break the schema so the next flush fails.
	if _, err := store.DB().Conn().Exec(`ALTER TABLE key_usage RENAME TO key_usage_broken`); err != nil {
		t.Fatalf("break schema: %v", err)
	}
	feedLedgerRequest(t, store, "retry-1", "sk-retry", "重试", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm-r.json", 7, 3, 0)
	if err := store.FlushNow(); err == nil {
		t.Fatalf("flush should fail while the table is missing")
	}

	// Repair the schema; the pending batch must still be written.
	if _, err := store.DB().Conn().Exec(`ALTER TABLE key_usage_broken RENAME TO key_usage`); err != nil {
		t.Fatalf("repair schema: %v", err)
	}
	if err := store.FlushNow(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	_ = store.Close()

	reopened := NewStore(pricing.NewEngine())
	if err := reopened.ConfigureSQLite(dbPath, time.Hour); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if ks := reopened.Snapshot("sk-retry", "", nil, nil, nil, false).Keys["sk-retry"]; ks == nil || ks.TotalRequests != 1 {
		t.Fatalf("failed batch was lost instead of retried: %+v", ks)
	}
}

// TestSQLiteFlushSnapshotsValues guards the race fix: mutations made after the
// batch is taken must not leak into the batch being written.
func TestSQLiteFlushSnapshotsValues(t *testing.T) {
	store := NewStore(pricing.NewEngine())
	feedLedgerRequest(t, store, "snap-1", "sk-snap", "快照", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm-s.json", 4, 1, 0)

	store.mu.Lock()
	batch := store.takeFlushBatchLocked()
	store.keys["sk-snap"].TotalRequests = 999
	for _, ms := range store.keys["sk-snap"].Models {
		ms.Requests = 999
	}
	store.mu.Unlock()

	if len(batch.keys) != 1 || batch.keys[0].TotalRequests != 1 {
		t.Fatalf("batch shares the live key struct: %+v", batch.keys)
	}
	for _, ms := range batch.keys[0].Models {
		if ms.Requests != 1 {
			t.Fatalf("batch shares live model tuples: %+v", ms)
		}
	}
}
