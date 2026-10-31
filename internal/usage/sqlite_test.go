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
	jsonPath := filepath.Join(dir, "usage.json")

	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(jsonPath, time.Hour); err != nil {
		t.Fatalf("configure json persistence: %v", err)
	}
	if err := store.EnableSQLite(dbPath); err != nil {
		t.Fatalf("enable sqlite: %v", err)
	}
	if got := store.SQLitePath(); got != dbPath {
		t.Fatalf("SQLitePath = %q, want %q", got, dbPath)
	}

	feedLedgerRequest(t, store, "db-req-1", "sk-db", "数据库", "gemini-3.8-flash-high", "gemini-4-argon-high",
		"openai", "antigravity", "antigravity-db@gmail.com.json", 100, 20, 40)
	feedLedgerRequest(t, store, "db-req-2", "sk-db", "数据库", "gemini-3.8-flash-high", "gemini-3.8-flash-n",
		"openai", "antigravity", "antigravity-db@gmail.com.json", 50, 10, 0)

	if err := store.FlushNow(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	_ = store.Close()

	// Reopen purely from SQLite (the JSON file is deleted to prove the DB carries the state).
	reopened := NewStore(pricing.NewEngine())
	if err := reopened.ConfigurePersistence(filepath.Join(dir, "missing.json"), time.Hour); err != nil {
		t.Fatalf("configure reopened store: %v", err)
	}
	if err := reopened.EnableSQLite(dbPath); err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer reopened.Close()

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

	// Migration must be idempotent: opening the same file again applies nothing new.
	again := NewStore(pricing.NewEngine())
	if err := again.EnableSQLite(dbPath); err != nil {
		t.Fatalf("third open: %v", err)
	}
	if data := again.Snapshot("sk-db", "", nil, nil, nil, false); data.Keys["sk-db"].TotalRequests != 2 {
		t.Fatalf("second reopen lost data")
	}
	_ = again.Close()
}

// TestSQLiteImportsExistingJSONHistory verifies an upgrade path: an existing JSON
// snapshot is imported into the database when the DB is still empty.
func TestSQLiteImportsExistingJSONHistory(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "usage.json")
	dbPath := filepath.Join(dir, "usage.db")

	legacy := NewStore(pricing.NewEngine())
	if err := legacy.ConfigurePersistence(jsonPath, time.Hour); err != nil {
		t.Fatalf("configure legacy store: %v", err)
	}
	feedLedgerRequest(t, legacy, "legacy-1", "sk-legacy", "旧数据", "kimi-k2.6", "kimi-k2.6",
		"openai", "kimi", "kimi.json", 10, 2, 0)
	if err := legacy.FlushNow(); err != nil {
		t.Fatalf("legacy flush: %v", err)
	}
	_ = legacy.Close()

	migrated := NewStore(pricing.NewEngine())
	if err := migrated.ConfigurePersistence(jsonPath, time.Hour); err != nil {
		t.Fatalf("configure migrated store: %v", err)
	}
	if err := migrated.EnableSQLite(dbPath); err != nil {
		t.Fatalf("enable sqlite: %v", err)
	}
	if ks := migrated.Snapshot("sk-legacy", "", nil, nil, nil, false).Keys["sk-legacy"]; ks == nil || ks.TotalRequests != 1 {
		t.Fatalf("json history was not imported: %+v", ks)
	}
	_ = migrated.Close()

	// The imported rows must be readable from the database alone.
	fresh := NewStore(pricing.NewEngine())
	if err := fresh.EnableSQLite(dbPath); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer fresh.Close()
	if ks := fresh.Snapshot("sk-legacy", "", nil, nil, nil, false).Keys["sk-legacy"]; ks == nil || ks.TotalRequests != 1 {
		t.Fatalf("imported history not persisted to sqlite: %+v", ks)
	}
	now := time.Now()
	if ledger := fresh.QueryLedger(LedgerQuery{From: now.Add(-2 * time.Hour), To: now.Add(2 * time.Hour)}); ledger.Requests != 1 {
		t.Fatalf("ledger not imported: %+v", ledger)
	}
}

// TestSQLiteResetClearsBothStores verifies a reset is reflected in the database.
func TestSQLiteResetClearsBothStores(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "usage.db")
	store := NewStore(pricing.NewEngine())
	if err := store.ConfigurePersistence(filepath.Join(dir, "usage.json"), time.Hour); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := store.EnableSQLite(dbPath); err != nil {
		t.Fatalf("enable sqlite: %v", err)
	}
	feedLedgerRequest(t, store, "reset-1", "sk-reset", "重置", "glm-5.3", "glm-5.3", "openai", "zhipu", "glm.json", 5, 5, 0)
	if err := store.Reset("sk-reset"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	_ = store.Close()

	reopened := NewStore(pricing.NewEngine())
	if err := reopened.EnableSQLite(dbPath); err != nil {
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
