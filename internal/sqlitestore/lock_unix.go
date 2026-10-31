//go:build !windows

package sqlitestore

import (
	"fmt"
	"os"
	"syscall"
)

// fileLock is an exclusive, process-scoped writer lock backed by flock(2).
// The kernel releases it automatically when the file descriptor closes or the
// process dies, so a crash can never leave a stale lock behind.
type fileLock struct {
	path string
	file *os.File
}

func acquireFileLock(path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open lock file: %w", err)
	}
	if errLock := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); errLock != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sqlitestore: another process already owns %s: %w", path, errLock)
	}
	return &fileLock{path: path, file: file}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}
