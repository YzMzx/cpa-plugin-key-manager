package sqlitestore

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileLock is an exclusive, process-scoped writer lock backed by LockFileEx.
// Windows releases it automatically when the handle is closed or the process dies.
type fileLock struct {
	path string
	file *os.File
}

func acquireFileLock(path string) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open lock file: %w", err)
	}
	handle := windows.Handle(file.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sqlitestore: another process already owns %s: %w", path, err)
	}
	return &fileLock{path: path, file: file}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	handle := windows.Handle(l.file.Fd())
	overlapped := new(windows.Overlapped)
	_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
	err := l.file.Close()
	l.file = nil
	return err
}
