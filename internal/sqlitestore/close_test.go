package sqlitestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCloseWaitsForCheckedOutDriverBeforeReleasingWriterLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	db, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	connection, err := db.Conn().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	done := make(chan error, 1)
	go func() { done <- db.Close() }()
	select {
	case err := <-done:
		t.Fatalf("close returned while driver still checked out: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if other, err := Open(path, Options{}); err == nil {
		_ = other.Close()
		t.Fatal("writer lock released before active driver closed")
	}
	_ = connection.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not finish after driver lease released")
	}
	if db.Conn().Stats().OpenConnections != 0 {
		t.Fatal("driver connections still open")
	}
	replacement, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = replacement.Close()
}

func TestCancelledTransactionsFinishClosingBeforeWriterLockIsReleased(t *testing.T) {
	for i := 0; i < 50; i++ {
		path := filepath.Join(t.TempDir(), "cancelled.db")
		db, err := Open(path, Options{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		tx, err := db.Conn().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		_ = tx.Rollback()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if db.Conn().Stats().OpenConnections != 0 {
			t.Fatal("cancelled transaction driver remains open")
		}
	}
}
