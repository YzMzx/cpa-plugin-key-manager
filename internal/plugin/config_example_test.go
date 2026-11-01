package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigExampleStaysMinimalAndParses pins the shape of config.example.yaml:
// only enablement plus the database path may live there. Everything else (keys,
// default policy, price overrides) is stored inside the SQLite database.
func TestConfigExampleStaysMinimalAndParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}
	text := string(raw)

	for _, forbidden := range []string{"usage_file:", "rules_file:", "flush_interval_seconds:", "default_policy:", "keys:", "allowed_models:", "priority:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("config.example.yaml must not contain %q any more", forbidden)
		}
	}
	for _, required := range []string{"plugins:", "cpa-plugin-key-manager:", "enabled: true", "usage_db_file:", "./data:/CLIProxyAPI/data"} {
		if !strings.Contains(text, required) {
			t.Fatalf("config.example.yaml is missing %q", required)
		}
	}

	cfg, err := ParseConfigYAML(raw)
	if err != nil {
		t.Fatalf("parse config.example.yaml: %v", err)
	}
	if !cfg.Enabled {
		t.Fatalf("example must enable the plugin")
	}
	dbPath := filepath.ToSlash(cfg.Storage.UsageDBFile)
	if !strings.HasSuffix(dbPath, "/data/key_usage.db") {
		t.Fatalf("empty usage_db_file must default to <cpa root>/data/key_usage.db, got %q", dbPath)
	}
	if len(cfg.Keys) != 0 {
		t.Fatalf("example must not seed key rules, got %d", len(cfg.Keys))
	}
}
