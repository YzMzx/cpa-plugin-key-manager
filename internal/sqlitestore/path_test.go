package sqlitestore

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func mainDatabasePath(t *testing.T, db *DB) string {
	t.Helper()
	rows, err := db.Conn().Query("PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, path string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			t.Fatal(err)
		}
		if name == "main" {
			return filepath.Clean(path)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("main database not found")
	return ""
}

func TestOpenLiteralPathAndActualWriterLock(t *testing.T) {
	root := t.TempDir() // Keep URI delimiters inside the fixture even on broken implementations.
	names := []string{"normal.db", "hash#tail.db", "percent%23literal.db", "space 中文.db", "mixed %25# 中文.db", filepath.Join("目录 %23# space", "nested.db")}
	if runtime.GOOS != "windows" {
		names = append(names, "query?mode=memory&cache=shared.db", "back\\slash.db")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name)
			db, err := Open(path, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			actual := mainDatabasePath(t, db)
			want, err := filepath.EvalSymlinks(path)
			if err != nil {
				t.Errorf("literal database missing: %v", err)
			}
			if actual != want {
				t.Errorf("SQLite actual path = %q, want literal %q", actual, want)
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("literal database missing: %v", err)
			}
			if db.LockFilePath() != actual+".lock" {
				t.Errorf("lock %q does not guard actual database %q", db.LockFilePath(), actual)
			}
			second, err := Open(actual, Options{})
			if err == nil {
				second.Close()
				t.Fatal("second writer opened actual database while first writer still owns it")
			}
			if !strings.Contains(err.Error(), "another process already owns") {
				t.Errorf("second writer failed for unrelated reason: %v", err)
			}
		})
	}
}

func TestCanonicalPathMissingSuffixAndRelativeIdentity(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	path := filepath.Join("new", "nested", "usage.db")
	got, err := CanonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(realRoot, path)
	if got != want {
		t.Fatalf("canonical path = %q, want %q", got, want)
	}
	if _, err := os.Stat("new"); !os.IsNotExist(err) {
		t.Fatalf("CanonicalPath created directory or unexpected stat error: %v", err)
	}
	db, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Path() != want || mainDatabasePath(t, db) != want || db.LockFilePath() != want+".lock" {
		t.Fatal("relative path identities differ")
	}
	second, err := Open(want, Options{})
	if err == nil {
		second.Close()
		t.Fatal("absolute alias admitted a second writer")
	}
	if !strings.Contains(err.Error(), "another process already owns") {
		t.Fatal(err)
	}
}

func TestCanonicalPathMissingDirectoryThroughSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	path := filepath.Join(alias, "missing", "nested", "usage.db")
	wantDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(wantDir, "missing", "nested", "usage.db")
	got, err := CanonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("canonical path = %q, want %q", got, want)
	}
	db, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Path() != want || mainDatabasePath(t, db) != want {
		t.Fatal("new directory identity differs")
	}
}

func TestCanonicalPathRejectsEmptyAndDanglingSymlink(t *testing.T) {
	if _, err := CanonicalPath(" "); err == nil {
		t.Fatal("empty path accepted")
	}
	root := t.TempDir()
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "missing"), alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "usage.db")} {
		if _, err := CanonicalPath(path); err == nil {
			t.Errorf("dangling alias accepted: %q", path)
		}
	}
}

func TestDSNFileURL(t *testing.T) {
	paths := []string{"/tmp/a %23#? 中文.db"}
	if runtime.GOOS == "windows" {
		paths = append(paths, []string{
			`C:\data\a %23# 中文.db`,
			`\\server\share\a %23# 中文.db`,
		}...)
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			raw := dsn(path, 1234*time.Millisecond)
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.ToSlash(path)
			if runtime.GOOS == "windows" && !strings.HasPrefix(want, "/") {
				want = "/" + want
			}
			if u.Scheme != "file" || u.Host != "" || u.Opaque != "" || u.Fragment != "" || u.Path != want {
				t.Errorf("DSN %q parsed as %+v, want empty authority and literal path %q", raw, u, want)
			}
			if got := strings.Join(u.Query()["_pragma"], ","); got != "journal_mode(WAL),busy_timeout(1234),foreign_keys(ON),synchronous(NORMAL)" {
				t.Errorf("pragmas = %q", got)
			}
		})
	}
}

func TestOpenCanonicalSymlinkIdentity(t *testing.T) {
	for _, fileAlias := range []bool{false, true} {
		name := "directory"
		if fileAlias {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			realDir := filepath.Join(root, "real")
			if err := os.Mkdir(realDir, 0700); err != nil {
				t.Fatal(err)
			}
			realPath := filepath.Join(realDir, "shared.db")
			alias := filepath.Join(root, "alias")
			target := realDir
			aliasPath := filepath.Join(alias, "shared.db")
			if fileAlias {
				if err := os.WriteFile(realPath, nil, 0600); err != nil {
					t.Fatal(err)
				}
				target, aliasPath = realPath, alias
			}
			if err := os.Symlink(target, alias); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symlinks unavailable: %v", err)
				}
				t.Fatal(err)
			}
			db, err := Open(aliasPath, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			canonical, err := filepath.EvalSymlinks(realPath)
			if err != nil {
				t.Fatal(err)
			}
			if db.Path() != canonical {
				t.Errorf("Path = %q, want canonical %q", db.Path(), canonical)
			}
			if db.LockFilePath() != canonical+".lock" {
				t.Errorf("lock = %q, want canonical lock", db.LockFilePath())
			}
			if actual := mainDatabasePath(t, db); actual != canonical {
				t.Errorf("SQLite path = %q, want %q", actual, canonical)
			}
			second, err := Open(realPath, Options{})
			if err == nil {
				second.Close()
				t.Fatal("alias admitted second writer")
			}
			if !strings.Contains(err.Error(), "another process already owns") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
