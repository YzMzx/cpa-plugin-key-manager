package sqlitestore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CanonicalPath returns an absolute database path with existing symlinks resolved.
// Missing trailing components are preserved, so it also works before Open creates
// the database directory. It does not create files or directories. Dangling links
// are errors, not alternate identities. Hard-link aliases and concurrent renames
// or symlink replacement are outside this path-based identity guarantee.
func CanonicalPath(databasePath string) (string, error) {
	path := strings.TrimSpace(databasePath)
	if path == "" {
		return "", fmt.Errorf("sqlitestore: database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: absolute database path: %w", err)
	}
	existing := absolute
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("sqlitestore: inspect database path: %w", err)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("sqlitestore: resolve database path: %w", err)
		}
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: resolve database symlinks: %w", err)
	}
	suffix, err := filepath.Rel(existing, absolute)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: resolve database suffix: %w", err)
	}
	return filepath.Join(resolved, suffix), nil
}
