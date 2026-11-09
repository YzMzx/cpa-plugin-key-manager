package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsCachePathAliasesDoNotTargetProtectedFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "live.db")
	if err := os.WriteFile(file, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if !settingsSamePath(filepath.Join(dir, "child", "..", "live.db"), file) {
		t.Fatal("cleaned alias bypass")
	}
	hard := filepath.Join(dir, "hard-link.db")
	if err := os.Link(file, hard); err == nil && !settingsSamePath(hard, file) {
		t.Fatal("hardlink bypass")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err == nil {
		if !settingsSamePath(filepath.Join(alias, "live.db"), file) {
			t.Fatal("symlink parent bypass")
		}
		if !settingsSamePath(filepath.Join(alias, "new-cache.db"), filepath.Join(dir, "new-cache.db")) {
			t.Fatal("missing file in aliased parent not canonicalized")
		}
	}
	if settingsSamePath(filepath.Join(dir, "safe-cache.json"), file) {
		t.Fatal("different targets treated equal")
	}
}
