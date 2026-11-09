package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// settingsSamePath resolves aliases before permitting a cache overwrite target.
// For a not-yet-existing cache, resolve the nearest existing parent so a symlink
// directory cannot disguise the live database/config filename.
func settingsSamePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	canonical := func(value string) string {
		absolute, err := filepath.Abs(filepath.Clean(value))
		if err != nil {
			return filepath.Clean(value)
		}
		current := absolute
		var rest []string
		for {
			if resolved, err := filepath.EvalSymlinks(current); err == nil {
				for i := len(rest) - 1; i >= 0; i-- {
					resolved = filepath.Join(resolved, rest[i])
				}
				return filepath.Clean(resolved)
			}
			parent := filepath.Dir(current)
			if parent == current {
				return absolute
			}
			rest = append(rest, filepath.Base(current))
			current = parent
		}
	}
	left, right := canonical(a), canonical(b)
	equal := left == right
	if runtime.GOOS == "windows" {
		equal = strings.EqualFold(left, right)
	}
	if equal {
		return true
	}
	ai, ae := os.Stat(a)
	bi, be := os.Stat(b)
	return ae == nil && be == nil && os.SameFile(ai, bi)
}
