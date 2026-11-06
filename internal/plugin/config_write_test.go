package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteHostConfigAPIKeysSkipsUnchanged pins item 4: the admin page calls the
// sync endpoint on every refresh, so an identical key list must not rewrite CPA's
// config.yaml (which would also reflow its comments and formatting).
func TestWriteHostConfigAPIKeysSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	original := "port: 8317\n# keep this comment\napi-keys:\n  - sk-a\n  - sk-b\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(cfgPath, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if err := WriteHostConfigAPIKeys(cfgPath, []string{"sk-a", " sk-b ", "sk-a"}); err != nil {
		t.Fatalf("write unchanged: %v", err)
	}
	raw, _ := os.ReadFile(cfgPath)
	if string(raw) != original {
		t.Fatalf("unchanged key list must not rewrite config.yaml:\n%s", string(raw))
	}
	if info, _ := os.Stat(cfgPath); !info.ModTime().Equal(old) {
		t.Fatalf("config.yaml mtime changed on a no-op write")
	}

	if err := WriteHostConfigAPIKeys(cfgPath, []string{"sk-a", "sk-b", "sk-c"}); err != nil {
		t.Fatalf("write changed: %v", err)
	}
	raw, _ = os.ReadFile(cfgPath)
	if !strings.Contains(string(raw), "sk-c") {
		t.Fatalf("changed key list was not written:\n%s", string(raw))
	}
}
