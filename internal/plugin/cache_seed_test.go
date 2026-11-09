package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSeedPricingCacheCannotOverwriteDatabaseOrHostConfiguration(t *testing.T) {
	for _, target := range []string{"database", "host-config", "database-wal", "database-lock"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("CPA_DIR", root)
			t.Setenv("CPA_KEY_MANAGER_USAGE_DB", "")
			config := filepath.Join(root, "config.yaml")
			original := []byte("server: {port: 8317}\n# protected host configuration\n")
			if err := os.WriteFile(config, original, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CPA_CONFIG_FILE", config)
			database := filepath.Join(root, "data", "live.db")
			cache := database
			switch target {
			case "host-config":
				cache = config
			case "database-wal":
				cache = database + "-wal"
			case "database-lock":
				cache = database + ".lock"
			}
			raw, err := yaml.Marshal(map[string]any{"enabled": true, "storage": map[string]any{"usage_db_file": database, "pricing_cache_file": cache}})
			if err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(lifecycleRequest{ConfigYAML: raw})
			manager := NewManager(nil)
			defer manager.Shutdown()
			if err := manager.Configure(request); err == nil {
				t.Fatal("unsafe initial pricing cache accepted")
			}
			actual, err := os.ReadFile(config)
			if err != nil || string(actual) != string(original) {
				t.Fatal("host configuration modified by rejected seed")
			}
			if _, err := os.Stat(database); !os.IsNotExist(err) {
				t.Fatal("unsafe seed opened/created live database before validation")
			}
		})
	}
}

func TestSeedPricingCacheCannotUseAliasedDatabaseParent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CPA_DIR", root)
	t.Setenv("CPA_KEY_MANAGER_USAGE_DB", "")
	live := filepath.Join(root, "data")
	if err := os.MkdirAll(live, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(live, alias); err != nil {
		t.Skip("symlink privileges unavailable")
	}
	cfg := DefaultConfig()
	cfg.Storage.UsageDBFile = filepath.Join(live, "live.db")
	cfg.Storage.PricingCacheFile = filepath.Join(alias, "live.db")
	cfg.Normalize()
	if err := validateConfig(cfg); err == nil {
		t.Fatal("seed cache aliased database path accepted")
	}
}
