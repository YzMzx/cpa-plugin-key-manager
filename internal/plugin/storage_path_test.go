package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRelativeStoragePathDoesNotAdoptAnotherInstancesFile(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	t.Setenv("CPA_DIR", root)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{filepath.Join("data", "key_usage.db"), filepath.Join("data", "models_dev.json")} {
		foreign := filepath.Join(other, relative)
		if err := os.MkdirAll(filepath.Dir(foreign), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(foreign, []byte("other-instance-data"), 0600); err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(root, relative)
		if got := ResolveStoragePath(relative); got != want {
			t.Fatalf("storage path adopted foreign file: %q want %q", got, want)
		}
		if got := ResolveStoragePath(foreign); got != foreign {
			t.Fatal("explicit absolute path changed")
		}
		actual, err := os.ReadFile(foreign)
		if err != nil || string(actual) != "other-instance-data" {
			t.Fatal("foreign file changed")
		}
	}
}
