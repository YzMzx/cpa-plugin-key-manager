package plugin

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHostKeyImportV8PresenceAndGroupedUpstreams(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      []string
	}{
		{"grouped", "config-version: 8\naccess: {api-keys: [client]}\napi-keys: {codex: [{keys: [{api-key: upstream}]}]}\n", []string{"client"}},
		{"new-wins", "api-keys: [old]\naccess: {api-keys: [new]}\n", []string{"new"}},
		{"empty-wins", "api-keys: [old]\naccess: {api-keys: []}\n", []string{}},
		{"legacy", "api-keys: [old]\n", []string{"old"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(p, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			got := ReadHostConfigAPIKeys(p)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestHostKeyParseErrorsAreNotEmptyAndReloadDoesNotReviveKeys(t *testing.T) {
	for _, raw := range []string{"access: {api-keys: secret}", "access: {api-keys: [123]}", "api-keys: [old]\napi-keys: [other]"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHostConfigAPIKeysChecked(path); err == nil {
			t.Fatalf("invalid key configuration accepted: %s", raw)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("diagnostic leaks raw YAML value")
		}
	}
	m := transactionManager(t)
	path := FindHostConfigFile("")
	if err := os.WriteFile(path, []byte("api-keys: [native]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	if _, listed := m.cfg.ResolveKeyRule("native"); !listed {
		t.Fatal("native key not imported")
	}
	if err := os.WriteFile(path, []byte("access: {api-keys: []}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(nil); err != nil {
		t.Fatal(err)
	}
	if _, listed := m.cfg.ResolveKeyRule("native"); listed {
		t.Fatal("empty current host list revived cached key")
	}
	revision := m.RulesRevision()
	if err := os.WriteFile(path, []byte("access: {api-keys: invalid}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(nil); err == nil {
		t.Fatal("malformed host config silently accepted")
	}
	if m.RulesRevision() != revision {
		t.Fatal("malformed host config changed revision")
	}
}
func TestInvalidHostConfigurationCannotCreateDatabase(t *testing.T) {
	isolateStateDirs(t)
	dir := t.TempDir()
	t.Setenv("CPA_DIR", dir)
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("CPA_CONFIG_FILE", path)
	if err := os.WriteFile(path, []byte("access: {api-keys: invalid}"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil)
	defer m.Shutdown()
	if err := m.Configure(nil); err == nil {
		t.Fatal("invalid host config accepted")
	}
	if m.usageStore.DB() != nil {
		t.Fatal("invalid host config opened database before validation")
	}
	if _, err := os.Stat(os.Getenv("CPA_KEY_MANAGER_USAGE_DB")); !os.IsNotExist(err) {
		t.Fatalf("invalid host config created database: %v", err)
	}
}
