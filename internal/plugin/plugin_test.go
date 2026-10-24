package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/handler"
)

func decodeEnvelope[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var env pluginabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v (%s)", err, string(raw))
	}
	if !env.OK {
		t.Fatalf("envelope not OK: %+v", env.Error)
	}
	var out T
	if len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, &out); err != nil {
			t.Fatalf("unmarshal result: %v (%s)", err, string(env.Result))
		}
	}
	return out
}

func TestRestartPersistenceBugReproduction(t *testing.T) {
	tmpDir := t.TempDir()
	origWD, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWD) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	rulesFile := "./data/key_guard_rules.json"
	cpaConfigPath := "config.yaml"

	// Initial config.yaml as installed by install.ps1
	initialCPAConfig := `port: 8317
api-keys: []
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      priority: 100
      storage:
        usage_file: "./data/key_usage_stats.json"
        rules_file: "./data/key_guard_rules.json"
`
	if err := os.WriteFile(cpaConfigPath, []byte(initialCPAConfig), 0644); err != nil {
		t.Fatalf("failed to write initial config.yaml: %v", err)
	}

	pluginConfigYAML := `enabled: true
priority: 100
storage:
  usage_file: "./data/key_usage_stats.json"
  rules_file: "./data/key_guard_rules.json"
`
	regReq, _ := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte(pluginConfigYAML),
		SchemaVersion: pluginabi.SchemaVersion,
	})

	hostInvoker := func(method string, payload []byte) ([]byte, error) {
		return okEnvelope(struct{}{})
	}

	// Session 1: Manager starts
	mgr1 := NewManager(hostInvoker)
	if _, err := mgr1.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("mgr1 register failed: %v", err)
	}

	// User creates a key rule via Web UI (POST /v0/management/key-guard/keys)
	keyRuleJSON := []byte(`{
		"api_key": "sk-user-test-123",
		"name": "Production Key",
		"enabled": true,
		"max_concurrency": 2,
		"allowed_models": ["gpt-4o", "claude-sonnet-4-20250514"],
		"upstream_binding": {
			"strategy": "strict",
			"credentials": ["claude-team-1.json"]
		}
	}`)
	if _, err := mgr1.UpsertKeyRuleFromJSON(keyRuleJSON); err != nil {
		t.Fatalf("UpsertKeyRuleFromJSON failed: %v", err)
	}

	// User updates default policy via Web UI (POST /v0/management/key-guard/default-policy)
	dpJSON := []byte(`{
		"allow_unlisted_keys": false,
		"max_concurrency": 10,
		"allowed_models": ["gpt-4o"],
		"upstream_binding": {
			"strategy": "round-robin",
			"credentials": []
		}
	}`)
	if _, err := mgr1.SaveDefaultPolicyFromJSON(dpJSON); err != nil {
		t.Fatalf("SaveDefaultPolicyFromJSON failed: %v", err)
	}

	// Verify file content on disk before restart
	dataBefore, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatalf("failed to read rulesFile before restart: %v", err)
	}
	t.Logf("rulesFile before restart:\n%s", string(dataBefore))
	if !strings.Contains(string(dataBefore), "sk-user-test-123") {
		t.Fatalf("rulesFile missing sk-user-test-123 before restart")
	}

	// Simulate CLIProxyAPI shutdown
	mgr1.Shutdown()

	// ==========================================
	// Session 2: CLIProxyAPI Restarts!
	// ==========================================
	mgr2 := NewManager(hostInvoker)
	defer mgr2.Shutdown()

	// Plugin registers during host startup
	if _, err := mgr2.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("mgr2 register failed: %v", err)
	}

	// Browser opens Web UI and calls SyncHostAPIKeys with empty or existing CPA keys
	// Note: in CPA config.yaml, what was in api-keys?
	cpaKeys := ReadHostConfigAPIKeys(cpaConfigPath)
	t.Logf("CPA keys in config.yaml on restart: %v", cpaKeys)

	// Web UI calls sync
	if err := mgr2.SyncHostAPIKeys(cpaKeys); err != nil {
		t.Fatalf("SyncHostAPIKeys failed: %v", err)
	}

	// Web UI calls BuildAdminOverview
	overview := mgr2.BuildAdminOverview("")
	rawOv, _ := json.MarshalIndent(overview, "", "  ")
	t.Logf("Overview after restart:\n%s", string(rawOv))

	// Check if key is still present!
	keysList, ok := overview["keys"].([]KeyRuleConfig)
	if !ok || len(keysList) == 0 {
		t.Fatalf("CRITICAL BUG: keys disappeared after restart! overview keys = %+v", overview["keys"])
	}
	if keysList[0].APIKey != "sk-user-test-123" {
		t.Fatalf("expected sk-user-test-123, got %s", keysList[0].APIKey)
	}
	if keysList[0].Name != "Production Key" {
		t.Fatalf("expected Production Key, got %s", keysList[0].Name)
	}
	if keysList[0].MaxConcurrency != 2 {
		t.Fatalf("expected MaxConcurrency 2, got %d", keysList[0].MaxConcurrency)
	}

	// Check if default_policy is still present!
	dp, ok := overview["default_policy"].(DefaultPolicyConfig)
	if !ok {
		t.Fatalf("default_policy missing or wrong type")
	}
	if dp.AllowUnlistedKeys == nil || *dp.AllowUnlistedKeys != false {
		t.Fatalf("expected AllowUnlistedKeys=false, got %v", dp.AllowUnlistedKeys)
	}
	if dp.MaxConcurrency != 10 {
		t.Fatalf("expected MaxConcurrency=10, got %d", dp.MaxConcurrency)
	}
}

func TestWriteHostConfigAPIKeysFormatting(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	sampleYAML := `port: 8317
api-keys:
  - sk-old
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      priority: 100
      storage:
        usage_file: "./data/key_usage_stats.json"
        rules_file: "./data/key_guard_rules.json"
`
	if err := os.WriteFile(cfgPath, []byte(sampleYAML), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := WriteHostConfigAPIKeys(cfgPath, []string{"sk-new-1", "sk-new-2"}); err != nil {
		t.Fatalf("WriteHostConfigAPIKeys failed: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	t.Logf("Resulting config.yaml:\n%s", string(data))
	keys := ReadHostConfigAPIKeys(cfgPath)
	if len(keys) != 2 || keys[0] != "sk-new-1" || keys[1] != "sk-new-2" {
		t.Fatalf("unexpected keys: %v", keys)
	}
}

func TestWriteHostConfigStateFull(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	sampleYAML := `port: 8317
api-keys:
  - sk-old
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      priority: 100
      storage:
        usage_file: "./data/key_usage_stats.json"
        rules_file: "./data/key_guard_rules.json"
`
	if err := os.WriteFile(cfgPath, []byte(sampleYAML), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	enabled := true
	state := &DynamicRulesState{
		Version: 1,
		DefaultPolicy: &DefaultPolicyConfig{
			AllowUnlistedKeys: &enabled,
			MaxConcurrency:    12,
			AllowedModels:     []string{"gpt-4o", "gemini-3.8-flash-high"},
		},
		Keys: []KeyRuleConfig{
			{
				APIKey:         "sk-new-1",
				Name:           "Production Main",
				Enabled:        &enabled,
				MaxConcurrency: 5,
				AllowedModels:  []string{"gpt-4o"},
			},
		},
	}

	if err := WriteHostConfigState(cfgPath, []string{"sk-new-1"}, state); err != nil {
		t.Fatalf("WriteHostConfigState failed: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	t.Logf("Resulting YAML:\n%s", string(data))

	// Re-parse with ParseConfigYAML
	parsedCfg, err := ParseConfigYAML(data)
	if err != nil {
		t.Fatalf("ParseConfigYAML failed: %v", err)
	}
	if len(parsedCfg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(parsedCfg.Keys))
	}
	if parsedCfg.Keys[0].Name != "Production Main" {
		t.Fatalf("expected 'Production Main', got %s", parsedCfg.Keys[0].Name)
	}
	if len(parsedCfg.Keys[0].AllowedModels) != 1 || parsedCfg.Keys[0].AllowedModels[0] != "gpt-4o" {
		t.Fatalf("expected ['gpt-4o'], got %v", parsedCfg.Keys[0].AllowedModels)
	}
	if parsedCfg.DefaultPolicy.MaxConcurrency != 12 {
		t.Fatalf("expected DefaultPolicy.MaxConcurrency 12, got %d", parsedCfg.DefaultPolicy.MaxConcurrency)
	}
}

func TestFullPluginLifecycleAndGovernance(t *testing.T) {
	tmpDir := t.TempDir()
	usageFile := filepath.Join(tmpDir, "usage_stats.json")
	cacheFile := filepath.Join(tmpDir, "models_dev.json")

	mgr := NewManager(nil)
	defer mgr.Shutdown()

	cfgYAML := `
enabled: true
priority: 100
storage:
  usage_file: "` + filepath.ToSlash(usageFile) + `"
  flush_interval_seconds: 60
  pricing_cache_file: "` + filepath.ToSlash(cacheFile) + `"
pricing:
  sync_url: "http://127.0.0.1:1/offline-test"
  http_timeout_seconds: 1
  auto_inject_include_usage: true
  custom_prices:
    "claude-3-5-sonnet-*":
      input: 3.0
      output: 15.0
      cache_read: 0.3
      cache_write: 3.75
    "gpt-4o*":
      input: 2.5
      output: 10.0
      cache_read: 1.25
      cache_write: 0.0
keys:
  - api_key: "sk-key-alpha"
    name: "Tenant Alpha"
    max_concurrency: 1
    allowed_models:
      - "claude-3-5-*"
      - "gpt-4o*"
    upstream_binding:
      auth_ids:
        - "auth-alpha-*"
      strategy: "round-robin"
      strict: true
`
	regReq, _ := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte(cfgYAML),
		SchemaVersion: pluginabi.SchemaVersion,
	})
	rawReg, err := mgr.HandleRPC(pluginabi.MethodPluginRegister, regReq)
	if err != nil {
		t.Fatalf("plugin.register failed: %v", err)
	}
	regResp := decodeEnvelope[registrationResponse](t, rawReg)
	if !regResp.Capabilities.RequestInterceptor || !regResp.Capabilities.RequestLifecyclePlugin || !regResp.Capabilities.Scheduler {
		t.Fatalf("missing required capabilities: %+v", regResp.Capabilities)
	}

	// 1. Unauthorized model -> 403 Forbidden
	reqForbidden, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		RequestID:      "req-forbidden",
		SourceFormat:   "openai",
		Model:          "o1-pro",
		RequestedModel: "o1-pro",
		Headers:        http.Header{"Authorization": {"Bearer sk-key-alpha"}},
		Body:           []byte(`{"model":"o1-pro","messages":[{"role":"user","content":"hi"}]}`),
	})
	rawForb, err := mgr.HandleRPC(pluginabi.MethodRequestInterceptBefore, reqForbidden)
	if err != nil {
		t.Fatalf("intercept_before failed: %v", err)
	}
	respForb := decodeEnvelope[pluginapi.RequestInterceptResponse](t, rawForb)
	if !respForb.Terminate || respForb.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Terminate for unauthorized model o1-pro, got: %+v", respForb)
	}

	// 2. Authorized streaming request 1 -> acquires concurrency slot (1/1)
	reqStream1, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		RequestID:      "req-stream-1",
		SourceFormat:   "claude",
		Model:          "claude-3-5-sonnet-20241022",
		RequestedModel: "claude-3-5-sonnet-20241022",
		Stream:         true,
		Headers:        http.Header{"X-Api-Key": {"sk-key-alpha"}},
		Body:           []byte(`{"model":"claude-3-5-sonnet-20241022","stream":true}`),
	})
	rawS1, err := mgr.HandleRPC(pluginabi.MethodRequestInterceptBefore, reqStream1)
	if err != nil {
		t.Fatalf("intercept_before stream 1 failed: %v", err)
	}
	respS1 := decodeEnvelope[pluginapi.RequestInterceptResponse](t, rawS1)
	if respS1.Terminate {
		t.Fatalf("expected stream 1 to be allowed, got terminated: %+v", respS1)
	}
	// Verify stream_options was NOT injected into a "claude" protocol request!
	if strings.Contains(string(respS1.Body), "stream_options") {
		t.Fatalf("stream_options must NOT be injected into claude request: %s", string(respS1.Body))
	}

	// 3. Concurrent request 2 while stream 1 is still open -> 429 Too Many Requests
	reqConcurrent2, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		RequestID:      "req-concurrent-2",
		SourceFormat:   "openai",
		Model:          "gpt-4o-mini",
		RequestedModel: "gpt-4o-mini",
		Headers:        http.Header{"Authorization": {"Bearer sk-key-alpha"}},
		Body:           []byte(`{"model":"gpt-4o-mini"}`),
	})
	rawC2, err := mgr.HandleRPC(pluginabi.MethodRequestInterceptBefore, reqConcurrent2)
	if err != nil {
		t.Fatalf("intercept_before concurrent 2 failed: %v", err)
	}
	respC2 := decodeEnvelope[pluginapi.RequestInterceptResponse](t, rawC2)
	if !respC2.Terminate || respC2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests while stream 1 holds slot, got: %+v", respC2)
	}

	// 4. Test scheduler.pick via caller_scope metadata
	schedReq, _ := json.Marshal(pluginapi.SchedulerPickRequest{
		Model: "claude-3-5-sonnet-20241022",
		Options: pluginapi.SchedulerOptions{
			Metadata: map[string]any{
				"caller_scope": ComputeCallerScope("sk-key-alpha"),
			},
		},
		Candidates: []pluginapi.SchedulerAuthCandidate{
			{ID: "auth-other-1.json", Provider: "claude"},
			{ID: "auth-alpha-primary.json", Provider: "claude"},
		},
	})
	rawPick, err := mgr.HandleRPC(pluginabi.MethodSchedulerPick, schedReq)
	if err != nil {
		t.Fatalf("scheduler.pick failed: %v", err)
	}
	respPick := decodeEnvelope[pluginapi.SchedulerPickResponse](t, rawPick)
	if !respPick.Handled || respPick.AuthID != "auth-alpha-primary.json" {
		t.Fatalf("expected bound credential auth-alpha-primary.json, got: %+v", respPick)
	}

	// 5. Simulate SSE stream chunks for req-stream-1 (header-init chunk -1, then message_start, then message_delta)
	// Slot MUST remain occupied during chunks!
	chunkInit, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  "req-stream-1",
		Model:      "claude-3-5-sonnet-20241022",
		ChunkIndex: -1,
	})
	_, _ = mgr.HandleRPC(pluginabi.MethodResponseInterceptStreamChunk, chunkInit)

	chunkStart, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  "req-stream-1",
		Model:      "claude-3-5-sonnet-20241022",
		ChunkIndex: 0,
		Body:       []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-3-5-sonnet-20241022\",\"usage\":{\"input_tokens\":1000,\"cache_read_input_tokens\":2000,\"cache_creation_input_tokens\":500,\"output_tokens\":1}}}\n\n"),
	})
	_, _ = mgr.HandleRPC(pluginabi.MethodResponseInterceptStreamChunk, chunkStart)

	chunkDelta, _ := json.Marshal(pluginapi.StreamChunkInterceptRequest{
		RequestID:  "req-stream-1",
		Model:      "claude-3-5-sonnet-20241022",
		ChunkIndex: 1,
		Body:       []byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":300}}\n\n"),
	})
	_, _ = mgr.HandleRPC(pluginabi.MethodResponseInterceptStreamChunk, chunkDelta)

	// Hot-reload (`plugin.reconfigure`) WHILE stream 1 is still active: slot must still be held!
	if _, err := mgr.HandleRPC(pluginabi.MethodPluginReconfigure, regReq); err != nil {
		t.Fatalf("plugin.reconfigure failed: %v", err)
	}
	if active := mgr.limiter.ActiveCountForKey("sk-key-alpha"); active != 1 {
		t.Fatalf("expected active slot=1 preserved across reconfigure, got %d", active)
	}

	// 6. Stream 1 completes (`request.complete` on stream close / [DONE] / context.Canceled) -> releases slot and records billing!
	compReq, _ := json.Marshal(pluginapi.RequestCompletion{
		RequestID:      "req-stream-1",
		TraceID:        "trace-s1",
		SourceFormat:   "claude",
		Model:          "claude-3-5-sonnet-20241022",
		RequestedModel: "claude-3-5-sonnet-20241022",
		Stream:         true,
		Outcome:        pluginapi.RequestCompletionSucceeded,
		StatusCode:     http.StatusOK,
	})
	if _, err := mgr.HandleRPC(pluginabi.MethodRequestComplete, compReq); err != nil {
		t.Fatalf("request.complete failed: %v", err)
	}
	if active := mgr.limiter.ActiveCountForKey("sk-key-alpha"); active != 0 {
		t.Fatalf("expected active slot=0 after request.complete, got %d", active)
	}

	// 7. Query Management API to verify usage and USD cost
	mgmtReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    "/v0/management/key-guard/usage",
		Headers: http.Header{"Authorization": {"Bearer mgmt-secret"}},
		Query:   url.Values{"unmask": {"true"}},
	})
	rawMgmt, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, mgmtReq)
	if err != nil {
		t.Fatalf("management.handle failed: %v", err)
	}
	mgmtResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawMgmt)
	if mgmtResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from management API, got %d: %s", mgmtResp.StatusCode, string(mgmtResp.Body))
	}
	// Expected cost: (1000*3.0 + 300*15.0 + 2000*0.3 + 500*3.75) / 1e6 = (3000 + 4500 + 600 + 1875) / 1e6 = $0.009975
	if !strings.Contains(string(mgmtResp.Body), "$0.009975") {
		t.Fatalf("expected $0.009975 in management usage response, got: %s", string(mgmtResp.Body))
	}

	// 8. Query CLI flag `-key-usage`
	cliReq, _ := json.Marshal(pluginapi.CommandLineExecutionRequest{
		TriggeredFlags: map[string]pluginapi.CommandLineFlagValue{
			handler.FlagKeyUsage: {
				Name:  handler.FlagKeyUsage,
				Type:  "bool",
				Value: "true",
				Set:   true,
			},
		},
	})
	rawCLI, err := mgr.HandleRPC(pluginabi.MethodCommandLineExecute, cliReq)
	if err != nil {
		t.Fatalf("command_line.execute failed: %v", err)
	}
	cliResp := decodeEnvelope[pluginapi.CommandLineExecutionResponse](t, rawCLI)
	if cliResp.ExitCode != 0 || !strings.Contains(string(cliResp.Stdout), "TotalTokens=3800") {
		t.Fatalf("unexpected CLI output: exit=%d, stdout=%s", cliResp.ExitCode, string(cliResp.Stdout))
	}
}

func TestWebUIDynamicCRUDAndTokenTracking(t *testing.T) {
	tmpDir := t.TempDir()
	usageFile := filepath.Join(tmpDir, "usage_stats.json")
	rulesFile := filepath.Join(tmpDir, "key_guard_rules.json")
	cacheFile := filepath.Join(tmpDir, "models_dev.json")

	// Mock host callback returning upstream auth files and registered models
	hostInvoker := func(method string, payload []byte) ([]byte, error) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return okEnvelope(map[string]any{
				"files": []pluginapi.HostAuthFileEntry{
					{ID: "claude-team-1.json", Name: "claude-team-1.json", Provider: "claude", Status: "active"},
					{ID: "openai-tier5.json", Name: "openai-tier5.json", Provider: "openai", Status: "active"},
				},
			})
		case pluginabi.MethodHostAuthModels:
			return okEnvelope(map[string]any{
				"credentials": []pluginapi.HostAuthModels{
					{ID: "claude-team-1.json", Provider: "claude", Models: []string{"claude-sonnet-4-20250514", "claude-3-7-sonnet-20250219"}},
					{ID: "openai-tier5.json", Provider: "openai", Models: []string{"gpt-4o", "o3-mini"}},
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
  usage_file: "` + filepath.ToSlash(usageFile) + `"
  rules_file: "` + filepath.ToSlash(rulesFile) + `"
  pricing_cache_file: "` + filepath.ToSlash(cacheFile) + `"
`
	regReq, _ := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte(cfgYAML),
		SchemaVersion: pluginabi.SchemaVersion,
	})
	if _, err := mgr.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("plugin.register failed: %v", err)
	}

	// 1. Verify management.register exposes /ui with Menu "API Key 管控与用量"
	rawMgmtReg, err := mgr.HandleRPC(pluginabi.MethodManagementRegister, nil)
	if err != nil {
		t.Fatalf("management.register failed: %v", err)
	}
	mgmtReg := decodeEnvelope[managementRegistrationResponse](t, rawMgmtReg)
	foundUIMenu := false
	for _, r := range mgmtReg.Resources {
		if r.Path == "/ui" && r.Menu == "API Key 管控与用量" {
			foundUIMenu = true
			break
		}
	}
	if !foundUIMenu {
		t.Fatalf("expected /ui resource with Menu 'API Key 管控与用量', got: %+v", mgmtReg.Resources)
	}

	// 2. Verify GET /v0/resource/plugins/cpa-plugin-key-manager/ui renders embedded HTML SPA without Management Key prompt
	uiReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/cpa-plugin-key-manager/ui",
	})
	rawUI, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, uiReq)
	if err != nil {
		t.Fatalf("GET /ui failed: %v", err)
	}
	uiResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawUI)
	if uiResp.StatusCode != http.StatusOK || !strings.Contains(string(uiResp.Body), "API Key 管控与 Token 用量") {
		t.Fatalf("unexpected /ui HTML response: status=%d", uiResp.StatusCode)
	}

	// 2a. Verify unauthenticated access to /v0/resource/plugins/cpa-plugin-key-manager/ui?op=overview or /v0/management/key-guard/overview is rejected with 401
	unauthResReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/cpa-plugin-key-manager/ui",
		Query:  url.Values{"op": {"overview"}},
	})
	rawUnauthRes, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, unauthResReq)
	if err != nil {
		t.Fatalf("GET /ui?op=overview failed: %v", err)
	}
	unauthResResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawUnauthRes)
	if unauthResResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for /ui?op=overview, got %d: %s", unauthResResp.StatusCode, string(unauthResResp.Body))
	}

	unauthMgmtReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/management/key-guard/overview",
	})
	rawUnauthMgmt, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, unauthMgmtReq)
	if err != nil {
		t.Fatalf("GET /v0/management/key-guard/overview failed: %v", err)
	}
	unauthMgmtResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawUnauthMgmt)
	if unauthMgmtResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated management overview, got %d", unauthMgmtResp.StatusCode)
	}

	// 2b. Verify authenticated POST /v0/management/key-guard/keys/sync unifies CPA global api-keys with plugin
	authHeaders := http.Header{"Authorization": {"Bearer mgmt-secret"}}
	syncKeysReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    "/v0/management/key-guard/keys/sync",
		Headers: authHeaders,
		Body:    []byte(`{"keys":["sk-cpa-global-1","sk-cpa-global-2"]}`),
	})
	rawSyncKeys, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, syncKeysReq)
	if err != nil {
		t.Fatalf("POST /v0/management/key-guard/keys/sync failed: %v", err)
	}
	syncKeysResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawSyncKeys)
	if syncKeysResp.StatusCode != http.StatusOK || !strings.Contains(string(syncKeysResp.Body), "sk-cpa-global-1") || !strings.Contains(string(syncKeysResp.Body), "claude-sonnet-4-20250514") {
		t.Fatalf("unexpected /v0/management/key-guard/keys/sync response: status=%d body=%s", syncKeysResp.StatusCode, string(syncKeysResp.Body))
	}

	// 3. Dynamically create a new API Key rule via authenticated POST /v0/management/key-guard/keys
	keyCreateReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    "/v0/management/key-guard/keys",
		Headers: authHeaders,
		Body: []byte(`{
			"api_key": "sk-dynamic-user-1",
			"name": "Dynamic User 1",
			"enabled": true,
			"max_concurrency": 1,
			"allowed_models": ["gpt-4o"],
			"upstream_binding": {
				"strategy": "round-robin",
				"credentials": ["openai-tier5.json"]
			}
		}`),
	})
	rawKeyCreate, err := mgr.HandleRPC(pluginabi.MethodManagementHandle, keyCreateReq)
	if err != nil {
		t.Fatalf("POST /v0/management/key-guard/keys failed: %v", err)
	}
	keyCreateResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawKeyCreate)
	if keyCreateResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from POST /v0/management/key-guard/keys, got %d: %s", keyCreateResp.StatusCode, string(keyCreateResp.Body))
	}

	// 4. Execute a request with sk-dynamic-user-1 consuming 1000 input + 500 output = 1500 total tokens
	req1, _ := json.Marshal(pluginapi.RequestInterceptRequest{
		RequestID:      "dyn-req-1",
		SourceFormat:   "openai",
		Model:          "gpt-4o",
		RequestedModel: "gpt-4o",
		Headers:        http.Header{"Authorization": {"Bearer sk-dynamic-user-1"}},
		Body:           []byte(`{"model":"gpt-4o"}`),
	})
	rawInt1, _ := mgr.HandleRPC(pluginabi.MethodRequestInterceptBefore, req1)
	respInt1 := decodeEnvelope[pluginapi.RequestInterceptResponse](t, rawInt1)
	if respInt1.Terminate {
		t.Fatalf("expected first request to pass, got: %+v", respInt1)
	}

	respAfter1, _ := json.Marshal(pluginapi.ResponseInterceptRequest{
		RequestID:      "dyn-req-1",
		SourceFormat:   "openai",
		Model:          "gpt-4o",
		RequestedModel: "gpt-4o",
		Body:           []byte(`{"model":"gpt-4o","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`),
	})
	_, _ = mgr.HandleRPC(pluginabi.MethodResponseInterceptAfter, respAfter1)

	comp1, _ := json.Marshal(pluginapi.RequestCompletion{
		RequestID:      "dyn-req-1",
		Model:          "gpt-4o",
		RequestedModel: "gpt-4o",
		Outcome:        pluginapi.RequestCompletionSucceeded,
		StatusCode:     200,
	})
	_, _ = mgr.HandleRPC(pluginabi.MethodRequestComplete, comp1)

	// 5. Verify persistence across new Manager restart (loads key_guard_rules.json from disk) via authenticated /v0/management/key-guard/overview
	mgr2 := NewManager(hostInvoker)
	defer mgr2.Shutdown()
	if _, err := mgr2.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("mgr2 register failed: %v", err)
	}
	ovReq, _ := json.Marshal(pluginapi.ManagementRequest{
		Method:  http.MethodGet,
		Path:    "/v0/management/key-guard/overview",
		Headers: authHeaders,
	})
	rawOv, _ := mgr2.HandleRPC(pluginabi.MethodManagementHandle, ovReq)
	ovResp := decodeEnvelope[pluginapi.ManagementResponse](t, rawOv)
	if ovResp.StatusCode != http.StatusOK || !strings.Contains(string(ovResp.Body), "sk-dynamic-user-1") || !strings.Contains(string(ovResp.Body), "claude-team-1.json") {
		t.Fatalf("expected persisted dynamic key and host auth files in overview after restart, got: %s", string(ovResp.Body))
	}

	// 6. Verify Model List Filtering on Response Intercept (/v1/models) for restricted API keys
	modelCatalogRaw := []byte(`{
		"object": "list",
		"data": [
			{"id": "gpt-4o", "object": "model"},
			{"id": "claude-3-5-sonnet", "object": "model"},
			{"id": "gemini-2.0-flash", "object": "model"}
		]
	}`)

	modelsReq, _ := json.Marshal(pluginapi.ResponseInterceptRequest{
		RequestID:    "models-req-1",
		SourceFormat: "openai",
		RequestHeaders: http.Header{
			"Authorization": []string{"Bearer sk-dynamic-user-1"},
		},
		Body:       modelCatalogRaw,
		StatusCode: 200,
	})
	rawModelsResp, err := mgr.HandleRPC(pluginabi.MethodResponseInterceptAfter, modelsReq)
	if err != nil {
		t.Fatalf("handle models response intercept failed: %v", err)
	}
	modelsInterceptResp := decodeEnvelope[pluginapi.ResponseInterceptResponse](t, rawModelsResp)
	if len(modelsInterceptResp.Body) == 0 {
		t.Fatalf("expected filtered model catalog body to be returned")
	}
	var filteredCatalog struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(modelsInterceptResp.Body, &filteredCatalog); err != nil {
		t.Fatalf("unmarshal filtered model catalog failed: %v", err)
	}
	// sk-dynamic-user-1 was configured with allowed_models = ["gpt-4o"]
	if len(filteredCatalog.Data) != 1 || filteredCatalog.Data[0].ID != "gpt-4o" {
		t.Fatalf("expected only gpt-4o in filtered catalog, got: %+v", filteredCatalog.Data)
	}
}

func TestResolveStoragePathAndHostConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWD, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWD) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	// 1. When file exists in relative path
	rulesRel := "./data/key_guard_rules.json"
	if err := os.MkdirAll("./data", 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(rulesRel, []byte(`{"version":1}`), 0644); err != nil {
		t.Fatalf("write rulesRel failed: %v", err)
	}

	resolvedRules := ResolveStoragePath(rulesRel)
	if !filepath.IsAbs(resolvedRules) {
		t.Fatalf("expected absolute path, got %s", resolvedRules)
	}
	if _, err := os.Stat(resolvedRules); err != nil {
		t.Fatalf("expected resolved rules file to exist: %v", err)
	}

	// 2. FindHostConfigFile
	cfgRel := "config.yaml"
	if err := os.WriteFile(cfgRel, []byte("port: 8317\napi-keys: [sk-test]\n"), 0644); err != nil {
		t.Fatalf("write cfgRel failed: %v", err)
	}
	foundCfg := FindHostConfigFile("")
	if !filepath.IsAbs(foundCfg) {
		t.Fatalf("expected absolute path for found config, got %s", foundCfg)
	}
	keys := ReadHostConfigAPIKeys("")
	if len(keys) != 1 || keys[0] != "sk-test" {
		t.Fatalf("expected [sk-test], got %v", keys)
	}

	// 3. Test changing CWD to a different directory; ResolveStoragePath should keep working
	subDir := filepath.Join(tmpDir, "some-other-cwd")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir subDir failed: %v", err)
	}
	if err := os.Chdir(subDir); err != nil {
		t.Fatalf("chdir subDir failed: %v", err)
	}

	// With CPA_CONFIG_FILE set to absolute path
	t.Setenv("CPA_CONFIG_FILE", foundCfg)
	keysFromEnv := ReadHostConfigAPIKeys("")
	if len(keysFromEnv) != 1 || keysFromEnv[0] != "sk-test" {
		t.Fatalf("expected [sk-test] via CPA_CONFIG_FILE, got %v", keysFromEnv)
	}
}

func TestBuildAdminOverviewPreservesAllowedModelsWhenAuthModelsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "key_guard_rules.json")
	usageFile := filepath.Join(tmpDir, "key_usage_stats.json")

	mgr := NewManager(func(method string, payload []byte) ([]byte, error) {
		return okEnvelope(struct{}{})
	})
	defer mgr.Shutdown()

	regReq, _ := json.Marshal(lifecycleRequest{
		ConfigYAML: []byte(`
storage:
  rules_file: "` + filepath.ToSlash(rulesFile) + `"
  usage_file: "` + filepath.ToSlash(usageFile) + `"
default_policy:
  allowed_models: ["gpt-4o", "claude-3-5-sonnet"]
keys:
  - api_key: "sk-special"
    allowed_models: ["gemini-1.5-pro"]
`),
		SchemaVersion: pluginabi.SchemaVersion,
	})
	if _, err := mgr.HandleRPC(pluginabi.MethodPluginRegister, regReq); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// BuildAdminOverview when host has no auth files / models loaded yet (e.g. at startup)
	overview := mgr.BuildAdminOverview("")
	keysList, ok := overview["keys"].([]KeyRuleConfig)
	if !ok || len(keysList) == 0 {
		t.Fatalf("keys missing in overview")
	}
	if len(keysList[0].AllowedModels) != 1 || keysList[0].AllowedModels[0] != "gemini-1.5-pro" {
		t.Fatalf("allowed_models got erased! got %v", keysList[0].AllowedModels)
	}

	dp, ok := overview["default_policy"].(DefaultPolicyConfig)
	if !ok {
		t.Fatalf("default_policy missing")
	}
	if len(dp.AllowedModels) != 2 || dp.AllowedModels[0] != "gpt-4o" {
		t.Fatalf("default_policy allowed_models got erased! got %v", dp.AllowedModels)
	}
}
