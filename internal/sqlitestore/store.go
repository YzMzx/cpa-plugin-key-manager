// Package sqlitestore owns the shared SQLite database used by the plugin.
//
// The design follows yuluo688/credit-manager: a pure-Go SQLite driver, WAL mode,
// a single connection, transactional versioned migrations, and a host-owned
// cross-process writer lock keyed by the canonical database path. Arbitrary
// hard-link aliases and concurrent filesystem namespace changes are not supported.
package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	db       *sql.DB
	path     string
	lock     *fileLock
	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

// LockPath returns the lock filename for a database path. Pass CanonicalPath
// when resolving a caller-supplied path, or use DB.LockFilePath after Open.
func LockPath(databasePath string) string {
	return filepath.Clean(strings.TrimSpace(databasePath)) + ".lock"
}

// Open resolves the path, takes the writer lock, opens SQLite and applies migrations.
func Open(databasePath string, options Options) (*DB, error) {
	clean, err := CanonicalPath(databasePath)
	if err != nil {
		return nil, err
	}
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
	filePath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && !strings.HasPrefix(filePath, "/") {
		// A drive path must be hierarchical, not the opaque URI file:C:/... .
		filePath = "/" + filePath
	}
	// Keep UNC paths in Path (file:////server/share/...), not Host: SQLite
	// rejects non-local URI authorities. URL.String escapes %, #, ? and UTF-8
	// without escaping directory separators or interpreting filename parameters.
	return (&url.URL{Scheme: "file", Path: filePath, RawQuery: query.Encode()}).String()
}

// Conn exposes the underlying connection for package-level queries.
func (d *DB) Conn() *sql.DB { return d.db }

// Path reports the absolute, symlink-resolved database file used by SQLite.
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
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return d.closeErr
	}
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			d.closeErr = err
			return err
		}
		// database/sql Close need not wait for checked-out connections. Retain
		// our cross-process writer lock until their actual driver Close finished.
		// Stats.OpenConnections decreases only after driverConn.finalClose.
		deadline := time.Now().Add(5 * time.Second)
		for d.db.Stats().OpenConnections > 0 {
			if time.Now().After(deadline) {
				return fmt.Errorf("sqlitestore: active connections have not closed; writer lock retained")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if d.lock != nil {
		if err := d.lock.release(); err != nil {
			return err
		}
	}
	d.closed = true
	return nil
}
