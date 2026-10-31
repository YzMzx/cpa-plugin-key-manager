// Package sqlitestore owns the shared SQLite database used by the plugin.
//
// The design follows yuluo688/credit-manager: a pure-Go SQLite driver, WAL mode,
// a single connection, transactional versioned migrations, and a host-owned
// cross-process writer lock so two plugin instances can never write the same
// database concurrently.
package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DefaultBusyTimeout is used when the caller does not provide one.
const DefaultBusyTimeout = 5 * time.Second

// Options configures Open.
type Options struct {
	// BusyTimeout bounds how long SQLite waits for a lock (0 → DefaultBusyTimeout).
	BusyTimeout time.Duration
	// SkipLock disables the cross-process writer lock (unit tests that only read).
	SkipLock bool
}

// DB is an open, migrated database with an exclusive cross-process writer lock.
type DB struct {
	db        *sql.DB
	path      string
	lock      *fileLock
	closeOnce sync.Once
	closeErr  error
}

// LockPath returns the lock file that guards the database.
func LockPath(databasePath string) string {
	return filepath.Clean(strings.TrimSpace(databasePath)) + ".lock"
}

// Open resolves the path, takes the writer lock, opens SQLite and applies migrations.
func Open(databasePath string, options Options) (*DB, error) {
	clean := strings.TrimSpace(databasePath)
	if clean == "" {
		return nil, fmt.Errorf("sqlitestore: database path is required")
	}
	clean = filepath.Clean(clean)
	if dir := filepath.Dir(clean); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sqlitestore: create directory: %w", err)
		}
	}

	var lock *fileLock
	if !options.SkipLock {
		acquired, errLock := acquireFileLock(LockPath(clean))
		if errLock != nil {
			return nil, errLock
		}
		lock = acquired
	}

	db, errOpen := sql.Open("sqlite", dsn(clean, options.BusyTimeout))
	if errOpen != nil {
		if lock != nil {
			_ = lock.release()
		}
		return nil, fmt.Errorf("sqlitestore: open: %w", errOpen)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if errPing := db.Ping(); errPing != nil {
		_ = db.Close()
		if lock != nil {
			_ = lock.release()
		}
		return nil, fmt.Errorf("sqlitestore: ping: %w", errPing)
	}

	store := &DB{db: db, path: clean, lock: lock}
	if errMigrate := Migrate(context.Background(), db); errMigrate != nil {
		_ = store.Close()
		return nil, errMigrate
	}
	return store, nil
}

func dsn(path string, busy time.Duration) string {
	if busy <= 0 || busy > 5*time.Minute {
		busy = DefaultBusyTimeout
	}
	query := url.Values{}
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()))
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(NORMAL)")
	return "file:" + filepath.ToSlash(path) + "?" + query.Encode()
}

// Conn exposes the underlying connection for package-level queries.
func (d *DB) Conn() *sql.DB { return d.db }

// Path reports the database file.
func (d *DB) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// LockFilePath reports the lock file (empty when the lock is disabled).
func (d *DB) LockFilePath() string {
	if d == nil || d.lock == nil {
		return ""
	}
	return d.lock.path
}

// Close closes the connection and releases the writer lock.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		var dbErr, lockErr error
		if d.db != nil {
			dbErr = d.db.Close()
		}
		if d.lock != nil {
			lockErr = d.lock.release()
		}
		if dbErr != nil {
			d.closeErr = dbErr
		} else if lockErr != nil {
			d.closeErr = lockErr
		}
	})
	return d.closeErr
}
