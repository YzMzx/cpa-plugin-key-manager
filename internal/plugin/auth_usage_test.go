package plugin

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// TestAuthFilesCarryUsageCounters pins the fix for the credential table that always
// showed 0/0: the host list itself has no counters, so the plugin must merge the
// usage it recorded per credential.
func TestAuthFilesCarryUsageCounters(t *testing.T) {
	isolateStateDirs(t)
	tmpDir := t.TempDir()

	hostInvoker := func(method string, payload []byte) ([]byte, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return okEnvelope(map[string]any{
				"files": []pluginapi.HostAuthFileEntry{
					{ID: "claude-team.json", Name: "claude-team.json", Provider: "claude", Status: "active"},
					{ID: "unused.json", Name: "unused.json", Provider: "claude", Status: "active"},
				},
			})
		}
		return okEnvelope(struct{}{})
	}

	mgr := NewManager(hostInvoker)
	defer mgr.Shutdown()

	cfgYAML := `
enabled: true
storage:
  usage_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "usage.json")) + `"
  rules_file: "` + filepath.ToSlash(filepath.Join(tmpDir, "rules.json")) + `"
`
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(cfgYAML), SchemaVersion: pluginabi.SchemaVersion})
	if _, err := mgr.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Two successful calls and one failure for the claude credential.
	requestIDs := []string{"cred-a", "cred-b", "cred-c"}
	outcomes := []pluginapi.RequestCompletionOutcome{
		pluginapi.RequestCompletionSucceeded,
		pluginapi.RequestCompletionSucceeded,
		pluginapi.RequestCompletionFailed,
	}
	for i, id := range requestIDs {
		failed := outcomes[i] == pluginapi.RequestCompletionFailed
		if !failed {
			mgr.usageStore.BeginRequest(id, "sk-cred", "cred", "claude-sonnet-4-6", "claude-sonnet-4-6", "claude", false)
		}
		// The host reports the terminal state and the credential on the usage record.
		// For a failed call the record itself creates the tracker with Failed=true, which
		// is how the failed counter is attributed to the credential bucket.
		mgr.usageStore.ObserveHostUsageRecord(pluginapi.UsageRecord{
			RequestID: id,
			Provider:  "claude",
			AuthID:    "claude-team.json",
			Model:     "claude-sonnet-4-6",
			APIKey:    "sk-cred",
			Failed:    failed,
			Detail:    pluginapi.UsageDetail{InputTokens: 10, OutputTokens: 5, TotalTokens: 15},
		}, "cred")
		mgr.usageStore.CompleteRequest(pluginapi.RequestCompletion{
			RequestID: id,
			Model:     "claude-sonnet-4-6",
			Outcome:   outcomes[i],
		}, "sk-cred", "cred")
	}

	overview := mgr.BuildAdminOverview("")
	files, _ := overview["auth_files"].([]map[string]any)
	if len(files) != 2 {
		t.Fatalf("expected 2 credential rows, got %d", len(files))
	}

	byName := map[string]map[string]any{}
	for _, f := range files {
		name, _ := f["name"].(string)
		byName[name] = f
	}

	used := byName["claude-team.json"]
	if used == nil {
		t.Fatalf("used credential missing from overview: %+v", files)
	}
	if toInt(used["requests"]) != 3 {
		t.Fatalf("expected 3 distinct recorded requests, got %v", used["requests"])
	}
	if toInt(used["success"]) != 2 {
		t.Fatalf("expected 2 successes, got %v", used["success"])
	}
	if toInt(used["failed"]) != 1 {
		t.Fatalf("expected 1 failure, got %v", used["failed"])
	}
	if toInt(used["total_tokens"]) != 45 {
		t.Fatalf("expected all three requests to retain 45 observed tokens, got %v", used["total_tokens"])
	}

	unused := byName["unused.json"]
	if unused == nil {
		t.Fatalf("unused credential missing from overview")
	}
	if toInt(unused["success"]) != 0 {
		t.Fatalf("unused credential should report 0 successes, got %v", unused["success"])
	}
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return -1
}

// TestAccountUsageForMatchesFilenameAndIndex covers the lookup fallbacks used above.
func TestAccountUsageForMatchesFilenameAndIndex(t *testing.T) {
	store := usage.NewStore(nil)
	store.BeginRequest("r1", "sk-x", "n", "glm-5.3", "glm-5.3", "openai", false)
	store.ObserveHostUsageRecord(pluginapi.UsageRecord{
		RequestID: "r1",
		Provider:  "zhipu",
		AuthID:    "hash:abc123",
		Model:     "glm-5.3",
		APIKey:    "sk-x",
		Detail:    pluginapi.UsageDetail{InputTokens: 1, OutputTokens: 1, TotalTokens: 2},
	}, "n")

	if acct := store.AccountUsageFor("zhipu", "hash:abc123"); acct == nil || acct.Requests == 0 {
		t.Fatalf("lookup by raw credential id failed: %+v", acct)
	}
	if acct := store.AccountUsageFor("zhipu", "unknown.json", "hash:abc123"); acct == nil || acct.Requests == 0 {
		t.Fatalf("lookup should fall back to another identifier: %+v", acct)
	}
	if acct := store.AccountUsageFor("zhipu", "missing.json"); acct != nil {
		t.Fatalf("unexpected match for unknown credential: %+v", acct)
	}
}
