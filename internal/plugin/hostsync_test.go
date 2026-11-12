package plugin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const compatMiniID = "openai-compatibility:minimax:c065c00535e8"
const compatVaraiID = "openai-compatibility:varai:e21f55dc402b"
const compatEnabledYAML = `openai-compatibility:
  - name: MiniMax
    base-url: https://mini.example/v1
    api-key-entries: [{api-key: mini-key}]
  - name: Varai
    base-url: https://varai.example/v1
    api-key-entries: [{api-key: varai-key, proxy-url: 'http://proxy.example:8080'}]
`

func credentialConfigFile(t *testing.T, raw string) func(string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("CPA_CONFIG_FILE", path)
	write := func(raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(raw)
	return write
}

func TestCredentialEnumerationCurrentCompatWithoutModelsProof(t *testing.T) {
	credentialConfigFile(t, compatEnabledYAML)
	// No path/runtime-only/source in host.auth.list for config credentials. Their
	// catalog may be empty: model registration is deliberately NOT enabled proof.
	m := NewManager(func(method string, payload []byte) ([]byte, error) {
		var req map[string]any
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Fatal(err)
		}
		if req["host_callback_id"] != "callback" {
			t.Fatalf("callback ID lost: %v", req)
		}
		switch method {
		case pluginabi.MethodHostAuthList:
			return okEnvelope(map[string]any{"files": []pluginapi.HostAuthFileEntry{{ID: "oauth.json", Provider: "claude", Status: "active"}}})
		case pluginabi.MethodHostAuthModels:
			return okEnvelope(pluginapi.HostAuthModelsResponse{Credentials: []pluginapi.HostAuthModels{
				{ID: compatMiniID, AuthIndex: "mini-index", Provider: "openai-compatible-minimax"},
				{ID: compatVaraiID, AuthIndex: "varai-index", Provider: "openai-compatible-varai", Models: []string{"a-model"}},
				{ID: "deleted.json", Provider: "claude", Models: []string{"still-registered"}},
			}})
		}
		return nil, errors.New("unexpected callback")
	})
	defer m.Shutdown()
	files, err := m.ListHostAuthFiles("callback")
	if err != nil || len(files) != 3 {
		t.Fatalf("files=%+v err=%v", files, err)
	}
	for _, f := range files {
		if f.ID == compatMiniID && (f.Status != "active" || f.AuthIndex != "mini-index") {
			t.Fatalf("normal models-only compat lost: %+v", f)
		}
		if f.ID == compatVaraiID && (f.Status != "active" || f.AuthIndex != "varai-index") {
			t.Fatalf("normal models-only compat lost: %+v", f)
		}
	}
}

func TestCredentialEnumerationDeletionDisableAndRotationDoNotReappear(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"deleted", "openai-compatibility: []\n"},
		{"disabled", strings.Replace(compatEnabledYAML, "name: MiniMax", "name: MiniMax\n    disabled: true", 1)},
		{"rotated key", strings.Replace(compatEnabledYAML, "mini-key", "rotated-key", 1)},
		{"changed base", strings.Replace(compatEnabledYAML, "https://mini.example/v1", "https://changed.example/v1", 1)},
		{"weight zero", strings.Replace(compatEnabledYAML, "api-key: mini-key", "api-key: mini-key, weight: 0", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write := credentialConfigFile(t, compatEnabledYAML)
			staleList := false
			m := NewManager(func(method string, _ []byte) ([]byte, error) {
				switch method {
				case pluginabi.MethodHostAuthList:
					files := []pluginapi.HostAuthFileEntry{}
					if staleList {
						files = append(files, pluginapi.HostAuthFileEntry{ID: compatMiniID, Provider: "openai-compatible-minimax", Status: "active"})
					}
					return okEnvelope(map[string]any{"files": files})
				case pluginabi.MethodHostAuthModels:
					return okEnvelope(pluginapi.HostAuthModelsResponse{Credentials: []pluginapi.HostAuthModels{{ID: compatMiniID, AuthIndex: "idx", Provider: "openai-compatible-minimax", Models: []string{"stale-model"}}}})
				}
				return okEnvelope(struct{}{})
			})
			defer m.Shutdown()
			// Previously observing a candidate must never make it an authorization source.
			raw, _ := json.Marshal(pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{{ID: compatMiniID, Provider: "openai-compatible-minimax", Status: "active"}, {ID: "removed.json", Provider: "claude", Status: "active"}}})
			if _, err := m.handleSchedulerPick(raw); err != nil {
				t.Fatal(err)
			}
			if files, err := m.ListHostAuthFiles(""); err != nil || len(files) != 1 {
				t.Fatalf("initial files=%+v err=%v", files, err)
			}
			if files := m.BuildAdminOverview("")["auth_files"].([]map[string]any); len(files) != 1 {
				t.Fatal(files)
			}
			write(tc.config)
			// A watcher-delayed host list and an indefinitely stale model registry must
			// not override config deletion/disable. No sleeps or TTL expiry required.
			staleList = true
			if files, err := m.ListHostAuthFiles(""); err != nil || len(files) != 0 {
				t.Fatalf("stale credentials returned: %+v err=%v", files, err)
			}
			if files := m.BuildAdminOverview("")["auth_files"].([]map[string]any); len(files) != 0 {
				t.Fatalf("overview replayed cache: %+v", files)
			}
		})
	}
}

func TestCredentialEnumerationPreservesCurrentFileState(t *testing.T) {
	m := NewManager(func(method string, _ []byte) ([]byte, error) {
		if method == pluginabi.MethodHostAuthList {
			return okEnvelope(map[string]any{"files": []pluginapi.HostAuthFileEntry{
				{ID: "disabled.json", Provider: "claude", Disabled: true, Status: "disabled"},
				{ID: "limited.json", Provider: "claude", Unavailable: true, Status: "error"},
			}})
		}
		return okEnvelope(pluginapi.HostAuthModelsResponse{Credentials: []pluginapi.HostAuthModels{{ID: "disabled.json", AuthIndex: "idx", Provider: "claude"}, {ID: "missing.json", Provider: "claude", Models: []string{"a-model"}}}})
	})
	defer m.Shutdown()
	files, err := m.ListHostAuthFiles("")
	if err != nil || len(files) != 2 {
		t.Fatalf("files=%+v err=%v", files, err)
	}
	if !files[0].Disabled || files[0].Status != "disabled" || files[0].AuthIndex != "idx" || !files[1].Unavailable {
		t.Fatalf("state overwritten by catalog: %+v", files)
	}
}

func TestCredentialEnumerationFailsClosedOnHostAndConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name               string
		listErr, modelsErr bool
		badConfig          string
	}{
		{name: "list failure", listErr: true}, {name: "models failure", modelsErr: true},
		{name: "invalid config", badConfig: "openai-compatibility: [TOP-SECRET-KEY"},
		{name: "missing config", badConfig: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write := credentialConfigFile(t, compatEnabledYAML)
			failed := false
			m := NewManager(func(method string, _ []byte) ([]byte, error) {
				if method == pluginabi.MethodHostAuthList {
					if failed && tc.listErr {
						return nil, errors.New("list offline")
					}
					return okEnvelope(map[string]any{"files": []pluginapi.HostAuthFileEntry{{ID: "oauth.json", Provider: "claude", Status: "active"}}})
				}
				if failed && tc.modelsErr {
					return nil, errors.New("models offline")
				}
				return okEnvelope(pluginapi.HostAuthModelsResponse{Credentials: []pluginapi.HostAuthModels{{ID: compatMiniID, AuthIndex: "idx", Provider: "openai-compatible-minimax"}}})
			})
			defer m.Shutdown()
			if files := m.BuildAdminOverview("")["auth_files"].([]map[string]any); len(files) != 2 {
				t.Fatal(files)
			}
			failed = true
			if tc.badConfig == "missing" {
				t.Setenv("CPA_CONFIG_FILE", filepath.Join(t.TempDir(), "absent.yaml"))
			} else if tc.badConfig != "" {
				write(tc.badConfig)
			}
			files, err := m.ListHostAuthFiles("")
			if err == nil || strings.Contains(err.Error(), "TOP-SECRET") {
				t.Fatalf("missing/unsafe diagnostic: %v", err)
			}
			want := 1
			if tc.listErr {
				want = 0
			}
			if len(files) != want {
				t.Fatalf("failed open: %+v", files)
			}
			for _, f := range files {
				if f.ID == compatMiniID {
					t.Fatalf("unverified active compat: %+v", f)
				}
			}
			overview := m.BuildAdminOverview("")
			if files := overview["auth_files"].([]map[string]any); len(files) != want {
				t.Fatalf("stale overview on failure: %+v", files)
			}
			if message, _ := overview["auth_files_error"].(string); message == "" || strings.Contains(message, "TOP-SECRET") {
				t.Fatalf("missing/unsafe overview diagnostic: %q", message)
			}
		})
	}
}

// Fixed IDs calculated using the host StableIDGenerator.Next algorithm. Cover
// distinctions that a provider-name-only or model-count check would miss.
func TestHostCompatIdentityFixtures(t *testing.T) {
	raw := compatEnabledYAML + `  - name: keyless
    base-url: https://keyless.example/v1
  - name: pooled
    base-url: https://pool.example/v1
    connection-pool: {enabled: true, idle-conn-timeout: 300s, max-idle-conns-per-host: 2}
    api-key-entries:
      - api-key: pool-key
        connection-pool: {max-idle-conns-per-host: 7}
      - api-key: pool-key
        connection-pool: {max-idle-conns-per-host: 7}
  - name: empty
    base-url: https://empty.example/v1
    api-key-entries: [{api-key: empty-key, connection-pool: {}}]
  - base-url: https://blank.example/v1
  - name: openai-compatible-custom
    base-url: https://custom.example/v1
`
	providers, err := parseHostCompatProviders([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := enabledHostCompatCredentials(providers)
	want := map[string]string{
		compatMiniID: "openai-compatible-minimax", compatVaraiID: "openai-compatible-varai",
		"openai-compatibility:keyless:80418cc7232c":                  "openai-compatible-keyless",
		"openai-compatibility:pooled:167974ebbf9d":                   "openai-compatible-pooled",
		"openai-compatibility:pooled:167974ebbf9d-1":                 "openai-compatible-pooled",
		"openai-compatibility:empty:e660054d8446":                    "openai-compatible-empty",
		"openai-compatibility:openai-compatibility:bf02d14d9f37":     "openai-compatibility",
		"openai-compatibility:openai-compatible-custom:55d8db23a4a5": "openai-compatible-custom",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("identities=%v want=%v", got, want)
	}
}

func TestHostCompatConfigLayoutsAndInvalidShape(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int
		invalid   bool
	}{
		{name: "v8", raw: `config-version: 8
api-keys:
  openai-compatibility:
    - name: MiniMax
      base-url: https://mini.example/v1
      keys: [{api-key: mini-key}]
`, want: 1},
		{name: "v8 empty overrides legacy", raw: compatEnabledYAML + "api-keys: {openai-compatibility: []}\n", want: 0},
		{name: "legacy client keys", raw: compatEnabledYAML + "api-keys: [client-key]\n", want: 2},
		{name: "v8 disabled", raw: `api-keys:
  openai-compatibility:
    - name: MiniMax
      disabled: true
      base-url: https://mini.example/v1
      keys: [{api-key: mini-key}]
`, want: 0},
		{name: "empty", raw: "", invalid: true}, {name: "scalar", raw: "no", invalid: true},
		{name: "groups mapping", raw: "api-keys: {openai-compatibility: {}}", invalid: true},
		{name: "missing keys", raw: "api-keys: {openai-compatibility: [{name: MiniMax}]}", invalid: true},
		{name: "duplicate disabled", raw: "openai-compatibility: [{name: MiniMax, disabled: false, disabled: true}]", invalid: true},
		{name: "bad disabled", raw: "openai-compatibility: [{disabled: maybe}]", invalid: true},
		{name: "unsupported version", raw: "config-version: 9", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			providers, err := parseHostCompatProviders([]byte(tc.raw))
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid config accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := enabledHostCompatCredentials(providers)
			if len(got) != tc.want {
				t.Fatalf("got=%v want %d", got, tc.want)
			}
			if tc.want == 1 && got[compatMiniID] != "openai-compatible-minimax" {
				t.Fatalf("v8 ID mismatch: %v", got)
			}
		})
	}
}

func TestHostCompatExplicitMissingConfigNeverFallsBack(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Neither enabled CWD nor environment config may replace a missing CLI path.
	oldConfig := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(oldConfig, []byte(compatEnabledYAML), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPA_CONFIG_FILE", oldConfig)
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	missing := filepath.Join(dir, "missing-host.yaml")
	for _, args := range [][]string{
		{"host", "-config", missing}, {"host", "--config", missing},
		{"host", "-config=" + missing}, {"host", "--config=" + missing},
		{"host", "-config"}, {"host", "--config="},
	} {
		os.Args = args
		files, err := readEnabledHostCompatCredentials()
		if err == nil || len(files) != 0 {
			t.Fatalf("explicit path fell back with args %v: files=%v err=%v", args, files, err)
		}
	}
	os.Args = []string{"host"}
	t.Setenv("CPA_CONFIG_FILE", missing)
	if files, err := readEnabledHostCompatCredentials(); err == nil || len(files) != 0 {
		t.Fatalf("missing env config fell back: files=%v err=%v", files, err)
	}
	t.Setenv("CPA_CONFIG_FILE", oldConfig)
	if files, err := readEnabledHostCompatCredentials(); err != nil || len(files) != 2 {
		t.Fatalf("existing explicit config was lost: files=%v err=%v", files, err)
	}
	t.Setenv("CPA_CONFIG_FILE", "")
	t.Setenv("CPA_DIR", filepath.Join(dir, "missing-host-dir"))
	if files, err := readEnabledHostCompatCredentials(); err == nil || len(files) != 0 {
		t.Fatalf("missing explicit directory fell back: files=%v err=%v", files, err)
	}
	t.Setenv("CPA_DIR", dir)
	if files, err := readEnabledHostCompatCredentials(); err != nil || len(files) != 2 {
		t.Fatalf("existing explicit directory was lost: files=%v err=%v", files, err)
	}
}
