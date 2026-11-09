package usage

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"path/filepath"
	"testing"
	"time"
)

// Emulate the owner phase after its final flush and sql.DB.Close has started.
// A retry must finish releasing the database, not try writing a new dirty batch.
func TestClosePendingRejectsLateAccountingAndStillReleasesHandle(t *testing.T) {
	store := NewStore(nil)
	if err := store.ConfigureSQLite(filepath.Join(t.TempDir(), "usage.db"), time.Hour); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.BeginRequest("before", "close-key", "", "m", "m", "openai", false)
	store.CompleteRequest(pluginapi.RequestCompletion{RequestID: "before", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "close-key", "")
	if err := store.FlushNow(); err != nil {
		t.Fatal(err)
	}
	store.stopFlusher()
	store.mu.Lock()
	store.closing = true
	database := store.db
	store.mu.Unlock()
	if err := database.Conn().Close(); err != nil {
		t.Fatal(err)
	}
	store.BeginRequest("late", "close-key", "", "m", "m", "openai", false)
	store.CompleteRequest(pluginapi.RequestCompletion{RequestID: "late", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "close-key", "")
	if store.PersistenceStatus().AccountingError == "" {
		t.Fatal("late accounting silently accepted during driver shutdown")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close retry attempted write to closed sql.DB: %v", err)
	}
	if store.DB() != nil {
		t.Fatal("close retry did not release owner handle")
	}
}
