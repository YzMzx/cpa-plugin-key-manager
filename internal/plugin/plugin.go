package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/handler"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/limiter"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	PluginID      = "cpa-plugin-key-manager"
	PluginVersion = "0.5.10"
	PluginAuthor  = "YzMzx"
	PluginRepo    = "https://github.com/YzMzx/cpa-plugin-key-manager"
	PluginLogoSVG = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%238b8680'/><path d='M24 22a10 10 0 1 0 9.5 13H42v5h6v-5h4v-6H33.5A10 10 0 0 0 24 22zm0 6a4 4 0 1 1 0 8 4 4 0 0 1 0-8z' fill='%23fff'/></svg>"
)

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registrationResponse struct {
	SchemaVersion uint32               `json:"schema_version"`
	Metadata      pluginapi.Metadata   `json:"metadata"`
	Capabilities  registrationCapFlags `json:"capabilities"`
}

type registrationCapFlags struct {
	FrontendAuthProvider      bool `json:"frontend_auth_provider"`
	Scheduler                 bool `json:"scheduler"`
	SchedulerAcrossPriorities bool `json:"scheduler_across_priorities,omitempty"`
	RequestInterceptor        bool `json:"request_interceptor"`
	RequestLifecyclePlugin    bool `json:"request_lifecycle_plugin"`
	ResponseInterceptor       bool `json:"response_interceptor"`
	StreamChunkInterceptor    bool `json:"response_stream_interceptor"`
	UsagePlugin               bool `json:"usage_plugin"`
	CommandLinePlugin         bool `json:"command_line_plugin"`
	ManagementAPI             bool `json:"management_api"`
}

type managementRegistrationResponse struct {
	Routes    []pluginapi.ManagementRoute `json:"routes,omitempty"`
	Resources []pluginapi.ResourceRoute   `json:"resources,omitempty"`
}

// Manager is the central runtime coordinator for cpa-plugin-key-manager.
// It is safe for concurrent use and preserves in-flight concurrency slots,
// dynamic Web UI rules, and accumulated usage across `plugin.reconfigure` hot-reloads.
type Manager struct {
	mu             sync.RWMutex
	seedCfg        Config
	dynamicState   *DynamicRulesState
	hostAPIKeys    []string
	cfg            Config
	lastSyncKey    string
	seenAuthFiles  map[string]pluginapi.HostAuthFileEntry
	seenModels     map[string]string
	host           *HostBridge
	scheduler      *authz.Scheduler
	limiter        *limiter.Limiter
	pricingEngine  *pricing.Engine
	pricingSyncer  *pricing.Syncer
	usageStore     *usage.Store
	lastConfigSync time.Time
}

// NewManager creates a new plugin Manager instance.
func NewManager(invoker HostInvoker) *Manager {
	hostBridge := NewHostBridge(invoker)
	pricingEng := pricing.NewEngine()
	syncer := pricing.NewSyncer(pricingEng, hostBridge.FetchURL, hostBridge.Log)
	store := usage.NewStore(pricingEng)
	defCfg := DefaultConfig()

	return &Manager{
		seedCfg:       defCfg,
		dynamicState:  &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)},
		cfg:           defCfg,
		seenAuthFiles: make(map[string]pluginapi.HostAuthFileEntry),
		seenModels:    make(map[string]string),
		host:          hostBridge,
		scheduler:     authz.NewScheduler(),
		limiter:       limiter.New(),
		pricingEngine: pricingEng,
		pricingSyncer: syncer,
		usageStore:    store,
	}
}

// SetHostInvoker updates the C ABI host callback function.
func (m *Manager) SetHostInvoker(invoker HostInvoker) {
	m.host.SetInvoker(invoker)
}

// HandleRPC dispatches a C ABI plugin method call and returns a JSON-serialized `pluginabi.Envelope`.
func (m *Manager) HandleRPC(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := m.Configure(request); err != nil {
			return nil, err
		}
		return okEnvelope(m.registrationPayload())

	case pluginabi.MethodPluginQuiesce:
		_ = m.usageStore.FlushIfDirty()
		return okEnvelope(struct{}{})

	case pluginabi.MethodPluginShutdown:
		m.Shutdown()
		return okEnvelope(struct{}{})

	case pluginabi.MethodFrontendAuthIdentifier:
		return okEnvelope(map[string]string{"identifier": PluginID})

	case pluginabi.MethodFrontendAuthAuthenticate:
		return m.handleFrontendAuth(request)

	case pluginabi.MethodSchedulerPick:
		return m.handleSchedulerPick(request)

	case pluginabi.MethodRequestInterceptBefore:
		return m.handleRequestInterceptBefore(request)

	case pluginabi.MethodRequestInterceptAfter:
		return m.handleRequestInterceptAfter(request)

	case pluginabi.MethodRequestComplete:
		return m.handleRequestComplete(request)

	case pluginabi.MethodResponseInterceptAfter:
		return m.handleResponseInterceptAfter(request)

	case pluginabi.MethodResponseInterceptStreamChunk:
		return m.handleStreamChunkIntercept(request)

	case pluginabi.MethodUsageHandle:
		return m.handleUsageRecord(request)

	case pluginabi.MethodManagementRegister:
		routes, resources := handler.RegisterManagementEndpoints()
		return okEnvelope(managementRegistrationResponse{
			Routes:    routes,
			Resources: resources,
		})

	case pluginabi.MethodManagementHandle:
		return m.handleManagement(request)

	case pluginabi.MethodCommandLineRegister:
		return okEnvelope(pluginapi.CommandLineRegistrationResponse{
			Flags: handler.RegisterCLIFlags(),
		})

	case pluginabi.MethodCommandLineExecute:
		return m.handleCommandLineExecute(request)

	default:
		return ErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// Configure parses and applies configuration from `plugin.register` or `plugin.reconfigure`.
// Hot-reloading preserves all active concurrency slots (`m.limiter`), dynamic rules (`key_guard_rules.json`),
// and accumulated billing data (`m.usageStore`).
func (m *Manager) Configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("decode lifecycle request: %w", err)
		}
	}

	seedCfg, err := ParseConfigYAML(req.ConfigYAML)
	if err != nil {
		return fmt.Errorf("parse plugin config YAML: %w", err)
	}

	dynState, errDyn := LoadDynamicRulesFile(seedCfg.Storage.RulesFile)
	if errDyn != nil {
		m.host.Log("warn", "failed to load dynamic rules file, using config.yaml seed", map[string]any{
			"file":  seedCfg.Storage.RulesFile,
			"error": errDyn.Error(),
		})
		dynState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}

	// 1. Seed synchronization: If the disk rules file has no keys, restore from
	// every other durable source (config.yaml seed, config.yaml plugin snapshot).
	if len(dynState.Keys) == 0 && len(seedCfg.Keys) > 0 {
		dynState.Keys = make([]KeyRuleConfig, len(seedCfg.Keys))
		for i, k := range seedCfg.Keys {
			dynState.Keys[i] = cloneKeyRule(k)
		}
	}
	if cfgSnapshot := ReadHostConfigPluginRules(""); cfgSnapshot != nil {
		if len(dynState.Keys) == 0 && len(cfgSnapshot.Keys) > 0 {
			dynState.Keys = make([]KeyRuleConfig, len(cfgSnapshot.Keys))
			for i, k := range cfgSnapshot.Keys {
				dynState.Keys[i] = cloneKeyRule(k)
			}
		}
		if dynState.DefaultPolicy == nil && cfgSnapshot.DefaultPolicy != nil {
			dp := *cfgSnapshot.DefaultPolicy
			dynState.DefaultPolicy = &dp
		}
		if len(cfgSnapshot.CustomPrices) > 0 && len(dynState.CustomPrices) == 0 {
			dynState.CustomPrices = cfgSnapshot.CustomPrices
		}
	}
	if len(dynState.Keys) > 0 || dynState.DefaultPolicy != nil {
		_ = SaveDynamicRulesFile(seedCfg.Storage.RulesFile, dynState)
	}
	// Remove plugin state files that older releases left in the auth directory as
	// `*.json`; CLIProxyAPI lists them as credentials that cannot be deleted.
	CleanupLegacyAuthMirrors()

	// 2. Hot-reload safety: If in-memory state already has dynamic rules (e.g. during plugin.reconfigure),
	// make sure we never erase in-flight rules that may not yet be on disk
	m.mu.RLock()
	existingDyn := m.dynamicState
	m.mu.RUnlock()
	if existingDyn != nil && len(existingDyn.Keys) > 0 {
		diskKeyMap := make(map[string]struct{}, len(dynState.Keys))
		for _, dk := range dynState.Keys {
			diskKeyMap[dk.APIKey] = struct{}{}
		}
		for _, ek := range existingDyn.Keys {
			if _, exists := diskKeyMap[ek.APIKey]; !exists {
				dynState.Keys = append(dynState.Keys, cloneKeyRule(ek))
			}
		}
		if dynState.DefaultPolicy == nil && existingDyn.DefaultPolicy != nil {
			dp := *existingDyn.DefaultPolicy
			dynState.DefaultPolicy = &dp
		}
	}

	hostKeys := ReadHostConfigAPIKeys("")
	m.mu.RLock()
	if len(hostKeys) == 0 && len(m.hostAPIKeys) > 0 {
		hostKeys = append([]string(nil), m.hostAPIKeys...)
	}
	m.mu.RUnlock()

	cfg := MergeDynamicState(seedCfg, dynState, hostKeys...)
	m.pricingEngine.SetCustomPrices(cfg.Pricing.CustomPrices, cfg.Pricing.DefaultPrice)

	flushDur := time.Duration(cfg.Storage.FlushIntervalSeconds) * time.Second
	// Durable usage mirrors keep billing history alive when the configured file
	// lives in an ephemeral directory such as a container's ./data.
	m.usageStore.SetMirrorFiles(UsageMirrorFiles(cfg.Storage.UsageFile))
	m.usageStore.SetLegacyMirrorFiles(LegacyUsageMirrorFiles(cfg.Storage.UsageFile))
	if errPersist := m.usageStore.ConfigurePersistence(cfg.Storage.UsageFile, flushDur); errPersist != nil {
		m.host.Log("warn", "failed to load previous usage snapshot from disk", map[string]any{
			"file":  cfg.Storage.UsageFile,
			"error": errPersist.Error(),
		})
	}

	syncKey := fmt.Sprintf("%s|%s|%d|%d",
		cfg.Pricing.SyncURL,
		cfg.Storage.PricingCacheFile,
		cfg.Pricing.SyncIntervalHours,
		cfg.Pricing.HTTPTimeoutSeconds,
	)

	m.mu.Lock()
	m.seedCfg = seedCfg
	m.dynamicState = dynState
	m.hostAPIKeys = hostKeys
	m.cfg = cfg
	m.lastSyncKey = syncKey
	m.mu.Unlock()

	// Repair the host config.yaml snapshot on every (re)configuration so that a
	// management save performed by CLIProxyAPI from a stale in-memory copy can
	// never permanently erase the administrator's remarks and model whitelists.
	if len(dynState.Keys) > 0 || dynState.DefaultPolicy != nil {
		allKeys := make([]string, 0, len(cfg.Keys))
		for _, k := range cfg.Keys {
			allKeys = append(allKeys, k.APIKey)
		}
		if len(allKeys) == 0 {
			allKeys = append(allKeys, hostKeys...)
		}
		if errHost := WriteHostConfigState("", allKeys, dynState); errHost != nil {
			m.host.Log("warn", "failed to mirror plugin rules into host config.yaml", map[string]any{
				"error": errHost.Error(),
			})
		}
	}

	return nil
}

// Shutdown stops background tasks and flushes usage statistics to disk.
func (m *Manager) Shutdown() {
	m.pricingSyncer.Stop()
	_ = m.usageStore.Close()
}

func (m *Manager) registrationPayload() registrationResponse {
	return registrationResponse{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             PluginID,
			Version:          PluginVersion,
			Author:           PluginAuthor,
			GitHubRepository: PluginRepo,
			Logo:             PluginLogoSVG,
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "storage",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Persistence paths for token usage statistics JSON and dynamic rules JSON.",
				},
				{
					Name:        "default_policy",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Default concurrency, model whitelist, and upstream credential binding policy for API keys.",
				},
				{
					Name:        "keys",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Per-API-Key rules (allowed_models, max_concurrency, upstream_binding).",
				},
			},
		},
		Capabilities: registrationCapFlags{
			FrontendAuthProvider:      true,
			Scheduler:                 true,
			SchedulerAcrossPriorities: true,
			RequestInterceptor:        true,
			RequestLifecyclePlugin:    true,
			ResponseInterceptor:       true,
			StreamChunkInterceptor:    true,
			UsagePlugin:               true,
			CommandLinePlugin:         true,
			ManagementAPI:             true,
		},
	}
}

func (m *Manager) handleFrontendAuth(raw []byte) ([]byte, error) {
	var req pluginapi.FrontendAuthRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	apiKey := ExtractAPIKeyFromHeadersAndQuery(req.Headers, req.Query)
	if apiKey == "" {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, listed := cfg.ResolveKeyRule(apiKey)
	if !listed || !rule.IsEnabled() {
		// Unlisted keys fall through to CLIProxyAPI's native config authenticator
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	return okEnvelope(pluginapi.FrontendAuthResponse{
		Authenticated: true,
		Principal:     apiKey,
		Metadata: map[string]string{
			"key_name": rule.Name,
		},
	})
}

func (m *Manager) handleRequestInterceptBefore(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	apiKey := cfg.ResolveAPIKeyFromContext(req.Headers, nil, req.Metadata)
	rule, _ := cfg.ResolveKeyRule(apiKey)

	// 1. Check whether API Key is enabled/allowed
	if !rule.IsEnabled() {
		return okEnvelope(authz.NewForbiddenKeyResponse("API key is not authorized or has been disabled"))
	}

	// 2. Check per-API-Key model whitelist (supports exact & wildcard matching against RequestedModel and Model)
	displayModel := strings.TrimSpace(req.RequestedModel)
	if displayModel == "" {
		displayModel = strings.TrimSpace(req.Model)
	}
	if !authz.AllowsModel(rule.AllowedModels, req.RequestedModel, req.Model) {
		return okEnvelope(authz.NewForbiddenModelResponse(displayModel))
	}

	// 3. Check per-API-Key cumulative USD quota limit (if quota_limit_usd > 0)
	if rule.QuotaLimitUSD > 0 {
		usedUSD := m.usageStore.GetKeyCostUSD(apiKey)
		if usedUSD >= rule.QuotaLimitUSD {
			return okEnvelope(authz.NewQuotaExceededResponse(usedUSD, rule.QuotaLimitUSD))
		}
	}

	// 4. Check and acquire per-API-Key concurrency slot (tracked by RequestID)
	acquired, _ := m.limiter.TryAcquire(limiter.SlotInfo{
		RequestID:      req.RequestID,
		APIKey:         apiKey,
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		SourceFormat:   req.SourceFormat,
		Stream:         req.Stream,
		AcquiredAt:     time.Now(),
	}, rule.MaxConcurrency)
	if !acquired {
		return okEnvelope(authz.NewConcurrencyLimitResponse(rule.MaxConcurrency))
	}

	// 5. Register in usage store for lifecycle tracking
	m.usageStore.BeginRequest(req.RequestID, apiKey, rule.Name, req.Model, req.RequestedModel, req.SourceFormat, req.Stream)

	// 6. Protocol-guarded auto-injection of `stream_options.include_usage = true` for OpenAI Chat Completions streams
	body := req.Body
	if req.Stream && cfg.ShouldAutoInjectIncludeUsage() {
		var reqPath string
		if req.Metadata != nil {
			if p, ok := req.Metadata["request_path"].(string); ok {
				reqPath = p
			}
		}
		if updatedBody, changed := usage.MaybeInjectStreamIncludeUsage(req.SourceFormat, reqPath, true, body); changed {
			body = updatedBody
		}
	}

	return okEnvelope(pluginapi.RequestInterceptResponse{
		Headers: req.Headers,
		Body:    body,
	})
}

func (m *Manager) handleRequestInterceptAfter(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return okEnvelope(pluginapi.RequestInterceptResponse{
		Headers: req.Headers,
		Body:    req.Body,
	})
}

func (m *Manager) handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	m.mu.Lock()
	cfg := m.cfg
	for _, cand := range req.Candidates {
		id := strings.TrimSpace(cand.ID)
		if id == "" {
			continue
		}
		name := id
		if fn := strings.TrimSpace(cand.Attributes["filename"]); fn != "" {
			name = fn
		}
		m.seenAuthFiles[id] = pluginapi.HostAuthFileEntry{
			ID:       id,
			Name:     name,
			Provider: cand.Provider,
			Status:   cand.Status,
			Priority: cand.Priority,
			Email:    cand.Attributes["email"],
			Account:  cand.Attributes["account"],
			Label:    cand.Attributes["label"],
		}
	}
	m.mu.Unlock()

	apiKey := cfg.ResolveAPIKeyFromContext(http.Header(req.Options.Headers), nil, req.Options.Metadata)
	rule, _ := cfg.ResolveKeyRule(apiKey)

	resp := m.scheduler.Pick(apiKey, rule.UpstreamBinding, req)
	return okEnvelope(resp)
}

func (m *Manager) handleResponseInterceptAfter(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if len(req.Body) > 0 {
		m.usageStore.ObserveResponse(req.RequestID, req.Model, req.RequestedModel, req.Body)
	}

	// If Model and RequestedModel are empty, this is a catalog/metadata response such as /v1/models.
	// Filter the returned model catalog so that clients only see models permitted by their API Key whitelist.
	if strings.TrimSpace(req.Model) == "" && strings.TrimSpace(req.RequestedModel) == "" && len(req.Body) > 0 {
		m.mu.RLock()
		cfg := m.cfg
		m.mu.RUnlock()

		apiKey := cfg.ResolveAPIKeyFromContext(req.RequestHeaders, nil, req.Metadata)
		rule, _ := cfg.ResolveKeyRule(apiKey)

		// Only filter if the key is restricted (i.e. not completely unrestricted `["*"]`)
		isUnrestricted := len(rule.AllowedModels) == 1 && strings.TrimSpace(rule.AllowedModels[0]) == "*"
		if !isUnrestricted {
			if filteredBody, changed := authz.FilterModelCatalogJSON(req.Body, rule.AllowedModels); changed {
				return okEnvelope(pluginapi.ResponseInterceptResponse{
					Body: filteredBody,
				})
			}
		}
	}

	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

func (m *Manager) handleStreamChunkIntercept(raw []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	// ChunkIndex == -1 is the header-init invocation; ChunkIndex >= 0 carries SSE payload chunks.
	if req.ChunkIndex >= 0 && len(req.Body) > 0 {
		m.usageStore.ObserveStreamChunk(req.RequestID, req.Model, req.RequestedModel, req.Body)
	}
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

func (m *Manager) handleRequestComplete(raw []byte) ([]byte, error) {
	var completion pluginapi.RequestCompletion
	if err := json.Unmarshal(raw, &completion); err != nil {
		return nil, err
	}

	// Priority 1: Always release the concurrency slot for RequestID first (idempotent, never underflows)
	releasedSlot, _ := m.limiter.Release(completion.RequestID)

	// Priority 2: Finalize request & token usage billing (deduplicated with usage.handle)
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	var apiKey string
	if releasedSlot != nil && releasedSlot.APIKey != "" && releasedSlot.APIKey != "__anonymous__" {
		apiKey = releasedSlot.APIKey
	} else {
		apiKey = cfg.ResolveAPIKeyFromContext(nil, nil, completion.Metadata)
	}
	rule, _ := cfg.ResolveKeyRule(apiKey)

	m.usageStore.CompleteRequest(completion, apiKey, rule.Name)
	return okEnvelope(struct{}{})
}

func (m *Manager) handleUsageRecord(raw []byte) ([]byte, error) {
	var rec pluginapi.UsageRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, _ := cfg.ResolveKeyRule(rec.APIKey)
	m.usageStore.ObserveHostUsageRecord(rec, rule.Name)
	return okEnvelope(struct{}{})
}

func (m *Manager) handleManagement(raw []byte) ([]byte, error) {
	var req struct {
		pluginapi.ManagementRequest
		HostCallbackID string `json:"host_callback_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	resp := handler.HandleManagementRequest(context.Background(), m, req.ManagementRequest, req.HostCallbackID)
	return okEnvelope(resp)
}

func (m *Manager) handleCommandLineExecute(raw []byte) ([]byte, error) {
	var req pluginapi.CommandLineExecutionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	flagVal := func(name string) string {
		if req.TriggeredFlags != nil {
			if v, ok := req.TriggeredFlags[name]; ok && v.Set {
				return v.Value
			}
		}
		if req.Flags != nil {
			if v, ok := req.Flags[name]; ok && v.Set {
				return v.Value
			}
		}
		return ""
	}

	showUsage := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsage))
	resetUsage := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsageReset))
	filterKey := strings.TrimSpace(flagVal(handler.FlagKeyUsageKey))
	asJSON := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsageJSON))

	if !showUsage && !resetUsage && filterKey == "" && !asJSON {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{ExitCode: 0})
	}

	if resetUsage {
		if err := m.ResetUsage(filterKey); err != nil {
			return okEnvelope(pluginapi.CommandLineExecutionResponse{
				ExitCode: 1,
				Stderr:   []byte(fmt.Sprintf("Failed to reset usage statistics: %v\n", err)),
			})
		}
		targetDesc := "all API keys"
		if filterKey != "" {
			targetDesc = usage.MaskAPIKey(filterKey)
		}
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			ExitCode: 0,
			Stdout:   []byte(fmt.Sprintf("Usage statistics reset successfully for %s.\n", targetDesc)),
		})
	}

	snap := m.BuildSnapshot(filterKey, "", true)
	out, err := handler.FormatUsageSnapshot(snap, asJSON)
	if err != nil {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			ExitCode: 1,
			Stderr:   []byte(fmt.Sprintf("Failed to format usage report: %v\n", err)),
		})
	}
	return okEnvelope(pluginapi.CommandLineExecutionResponse{
		ExitCode: 0,
		Stdout:   []byte(out),
	})
}

// --- handler.SnapshotProvider implementation ---

// BuildSnapshot returns a complete usage snapshot enriched with live concurrency counts and configured rules.
func (m *Manager) BuildSnapshot(filterAPIKey, filterModel string, maskKeys bool) usage.PersistedSnapshot {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	activeByKey := m.limiter.SnapshotByKey()
	maxConcByKey := make(map[string]int, len(cfg.Keys))
	keyNames := make(map[string]string, len(cfg.Keys))
	ruleByKey := make(map[string]KeyRuleConfig, len(cfg.Keys))
	for _, k := range cfg.Keys {
		maxConcByKey[k.APIKey] = k.MaxConcurrency
		if k.Name != "" {
			keyNames[k.APIKey] = k.Name
		}
		ruleByKey[k.APIKey] = k
	}

	snap := m.usageStore.Snapshot(filterAPIKey, filterModel, activeByKey, maxConcByKey, keyNames, maskKeys)
	for mapKey, ks := range snap.Keys {
		rawKey := ks.APIKey
		if rawKey == "" {
			rawKey = mapKey
		}
		if r, ok := ruleByKey[rawKey]; ok {
			ks.QuotaLimitUSD = r.QuotaLimitUSD
			enabled := r.IsEnabled()
			ks.Enabled = &enabled
			ks.AllowedModels = append([]string(nil), r.AllowedModels...)
		}
	}
	return snap
}

// ResetUsage clears accumulated usage statistics (for a single key or globally) and flushes to disk.
func (m *Manager) ResetUsage(apiKey string) error {
	return m.usageStore.Reset(apiKey)
}

// PricingStatus returns current models.dev sync diagnostics and custom price overrides.
func (m *Manager) PricingStatus() pricing.Status {
	return m.pricingEngine.Status()
}

// LookupModelPrice looks up the effective per-1M-token price for a given model name.
func (m *Manager) LookupModelPrice(model string) (pricing.ModelPrice, bool) {
	return m.pricingEngine.Lookup(model)
}

// SearchReferencePrices searches synced models.dev prices by substring query.
func (m *Manager) SearchReferencePrices(query string, limit int) []pricing.ReferenceModelEntry {
	return m.pricingEngine.SearchReferencePrices(query, limit)
}

// TriggerPricingSync runs an immediate synchronization with models.dev.
func (m *Manager) TriggerPricingSync(ctx context.Context) (int, error) {
	return m.pricingSyncer.SyncOnce(ctx)
}

// ExtractCallerAPIKey extracts the caller's API key from a self-service resource request and checks if it matches AdminToken.
func (m *Manager) ExtractCallerAPIKey(req pluginapi.ManagementRequest) (apiKey string, isAdmin bool) {
	m.mu.RLock()
	adminToken := strings.TrimSpace(m.cfg.AdminToken)
	m.mu.RUnlock()

	token := ExtractAPIKeyFromHeadersAndQuery(req.Headers, req.Query)
	if adminToken != "" && token == adminToken {
		return "", true
	}
	if adminToken == "" && token == "" {
		return "", true
	}
	return token, false
}

// ListHostAuthFiles calls `host.auth.list` and `host.auth.models`, merging any candidates observed during scheduling.
func (m *Manager) ListHostAuthFiles(hostCallbackID string) ([]pluginapi.HostAuthFileEntry, error) {
	hostFiles, err := m.host.ListAuthFiles(hostCallbackID)
	authModels, _ := m.host.ListAuthModels(hostCallbackID)

	byKey := make(map[string]pluginapi.HostAuthFileEntry)
	for _, f := range hostFiles {
		k := strings.TrimSpace(f.ID)
		if k == "" {
			k = strings.TrimSpace(f.Name)
		}
		if k == "" {
			k = strings.TrimSpace(f.AuthIndex)
		}
		if k != "" {
			byKey[k] = f
		}
	}
	for _, am := range authModels {
		k := strings.TrimSpace(am.ID)
		if k == "" {
			k = strings.TrimSpace(am.AuthIndex)
		}
		if k == "" {
			continue
		}
		if existing, ok := byKey[k]; ok {
			if existing.Provider == "" && am.Provider != "" {
				existing.Provider = am.Provider
			}
			if existing.AuthIndex == "" && am.AuthIndex != "" {
				existing.AuthIndex = am.AuthIndex
			}
			byKey[k] = existing
		} else {
			byKey[k] = pluginapi.HostAuthFileEntry{
				ID:        am.ID,
				AuthIndex: am.AuthIndex,
				Name:      am.ID,
				Provider:  am.Provider,
				Status:    "active",
			}
		}
	}

	m.mu.RLock()
	for id, f := range m.seenAuthFiles {
		if _, ok := byKey[id]; !ok {
			byKey[id] = f
		}
	}
	m.mu.RUnlock()

	out := make([]pluginapi.HostAuthFileEntry, 0, len(byKey))
	for _, f := range byKey {
		if strings.TrimSpace(f.Name) == "" {
			f.Name = f.ID
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, err
}

// AvailableModelOption represents a selectable model item in the Web UI checkbox list.
type AvailableModelOption struct {
	ID       string   `json:"id"`
	Provider string   `json:"provider"`
	Sources  []string `json:"sources,omitempty"`
}

func inferModelProvider(modelID string) string {
	low := strings.ToLower(strings.TrimSpace(modelID))
	switch {
	case strings.Contains(low, "claude"):
		return "claude"
	case strings.HasPrefix(low, "gpt-"), strings.HasPrefix(low, "o1"), strings.HasPrefix(low, "o3"), strings.HasPrefix(low, "o4"), strings.Contains(low, "codex"), strings.Contains(low, "chatgpt"):
		return "openai"
	case strings.Contains(low, "gemini"):
		return "gemini"
	case strings.Contains(low, "deepseek"):
		return "deepseek"
	case strings.Contains(low, "qwen"):
		return "qwen"
	case strings.Contains(low, "glm"):
		return "zhipu"
	case strings.Contains(low, "kimi"), strings.Contains(low, "moonshot"):
		return "kimi"
	case strings.Contains(low, "grok"):
		return "xai"
	default:
		return "other"
	}
}

// ListAvailableModels returns only existing models registered on active host credentials (`host.auth.models`),
// excluding any wildcards, sample models, or "unknown" placeholders.
func (m *Manager) ListAvailableModels(hostCallbackID string, snap usage.PersistedSnapshot) []AvailableModelOption {
	authModels, _ := m.host.ListAuthModels(hostCallbackID)
	byModel := make(map[string]*AvailableModelOption)

	addModel := func(id, provider, source string) {
		clean := strings.TrimSpace(id)
		if clean == "" || strings.EqualFold(clean, "unknown") || strings.ContainsAny(clean, "*?!") {
			return
		}
		prov := strings.ToLower(strings.TrimSpace(provider))
		if prov == "" {
			prov = inferModelProvider(clean)
		}
		item, exists := byModel[clean]
		if !exists {
			item = &AvailableModelOption{
				ID:       clean,
				Provider: prov,
			}
			byModel[clean] = item
		} else if (item.Provider == "" || item.Provider == "other") && prov != "" && prov != "other" {
			item.Provider = prov
		}
		if source != "" {
			hasSrc := false
			for _, s := range item.Sources {
				if s == source {
					hasSrc = true
					break
				}
			}
			if !hasSrc {
				item.Sources = append(item.Sources, source)
			}
		}
	}

	// Only models actually registered on active host credentials via host.auth.models
	for _, cred := range authModels {
		src := cred.ID
		if src == "" {
			src = cred.Provider
		}
		for _, mid := range cred.Models {
			addModel(mid, cred.Provider, src)
		}
	}

	// Fallback if host.auth.models returned no models (e.g. standalone mode): include real non-wildcard models observed in usage
	if len(byModel) == 0 {
		for _, ks := range snap.Keys {
			if ks == nil {
				continue
			}
			for mid := range ks.Models {
				addModel(mid, "", "usage")
			}
		}
	}

	out := make([]AvailableModelOption, 0, len(byModel))
	for _, item := range byModel {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func filterAllowedModelsToExisting(allowed []string, available []AvailableModelOption) []string {
	if len(allowed) == 0 {
		return []string{"*"}
	}
	for _, a := range allowed {
		if strings.TrimSpace(a) == "*" {
			return []string{"*"}
		}
	}
	if len(available) == 0 {
		out := make([]string, 0, len(allowed))
		for _, a := range allowed {
			clean := strings.TrimSpace(a)
			if clean != "" && !strings.EqualFold(clean, "unknown") && !strings.ContainsAny(clean, "*?!") {
				out = append(out, clean)
			}
		}
		if len(out) == 0 {
			return []string{"*"}
		}
		return out
	}

	out := make([]string, 0, len(available))
	for _, m := range available {
		if authz.AllowsModel(allowed, m.ID, m.ID) {
			out = append(out, m.ID)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

// SyncHostAPIKeys synchronizes the global API keys from CLIProxyAPI (`/v0/management/api-keys` or `config.yaml`)
// with the plugin's in-memory and persisted state so CPA and the plugin share a single unified set of API keys.
func (m *Manager) SyncHostAPIKeys(keys []string) error {
	cleaned := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, rawKey := range keys {
		k := strings.TrimSpace(rawKey)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			cleaned = append(cleaned, k)
		}
	}

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	m.hostAPIKeys = cleaned

	// Remove any key present in CPA's global api-keys from DeletedKeys
	if len(m.dynamicState.DeletedKeys) > 0 {
		filteredDel := make([]string, 0, len(m.dynamicState.DeletedKeys))
		for _, dk := range m.dynamicState.DeletedKeys {
			if _, inHost := seen[strings.TrimSpace(dk)]; !inHost {
				filteredDel = append(filteredDel, dk)
			}
		}
		m.dynamicState.DeletedKeys = filteredDel
	}

	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	if errSave != nil {
		m.host.Log("error", "failed to save dynamic rules file on sync host keys", map[string]any{
			"file":  rulesFile,
			"error": errSave.Error(),
		})
	}
	stateSnapshot := m.dynamicState
	allKeys := make([]string, 0, len(m.cfg.Keys))
	for _, k := range m.cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}
	m.mu.Unlock()

	if errHost := WriteHostConfigState("", allKeys, stateSnapshot); errHost != nil {
		m.host.Log("warn", "failed to mirror plugin rules into host config.yaml on sync", map[string]any{
			"error": errHost.Error(),
		})
	}
	return errSave
}

// repairHostConfigSnapshot re-mirrors the in-memory dynamic rules into the host
// config.yaml when that snapshot is missing or out of date. CLIProxyAPI saves its
// whole in-memory config on every management change; because that copy was loaded
// at startup it may not contain the plugin's `keys`/`default_policy` block, which
// would silently wipe the administrator's remarks and model whitelists.
func (m *Manager) repairHostConfigSnapshot() {
	m.mu.RLock()
	state := m.dynamicState
	cfg := m.cfg
	lastSync := m.lastConfigSync
	m.mu.RUnlock()

	if state == nil || (len(state.Keys) == 0 && state.DefaultPolicy == nil) {
		return
	}

	allKeys := make([]string, 0, len(cfg.Keys))
	for _, k := range cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}

	// Only rewrite when the snapshot actually lost data, at most once every 20s.
	configKeys := ReadHostConfigPluginKeys()
	needRepair := len(configKeys) < len(state.Keys)
	if !needRepair && state.DefaultPolicy != nil {
		if snap := ReadHostConfigPluginRules(""); snap == nil || snap.DefaultPolicy == nil {
			needRepair = true
		}
	}
	if !needRepair {
		return
	}
	if time.Since(lastSync) < 20*time.Second {
		return
	}

	if errHost := WriteHostConfigState("", allKeys, state); errHost != nil {
		m.host.Log("warn", "failed to repair host config.yaml plugin snapshot", map[string]any{
			"error": errHost.Error(),
		})
		return
	}
	m.mu.Lock()
	m.lastConfigSync = time.Now()
	m.mu.Unlock()
}

// BuildAdminOverview returns the complete state needed by the Admin Dashboard in a single call.
func (m *Manager) BuildAdminOverview(hostCallbackID string) map[string]any {
	diskKeys := ReadHostConfigAPIKeys("")
	if len(diskKeys) > 0 {
		m.mu.Lock()
		m.hostAPIKeys = diskKeys
		m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
		m.mu.Unlock()
	}
	m.repairHostConfigSnapshot()

	snap := m.BuildSnapshot("", "", false)
	authFiles, _ := m.ListHostAuthFiles(hostCallbackID)
	availableModels := m.ListAvailableModels(hostCallbackID, snap)
	pStatus := m.PricingStatus()

	m.mu.RLock()
	cfg := m.cfg
	keysCopy := make([]KeyRuleConfig, len(cfg.Keys))
	for i, k := range cfg.Keys {
		keysCopy[i] = cloneKeyRule(k)
	}
	dpCopy := cfg.DefaultPolicy
	m.mu.RUnlock()

	var totalCostNano int64
	var totalTokens, inTokens, outTokens, reasonTokens, readTokens, writeTokens int64
	var totalReq, okReq, errReq int64

	for _, ks := range snap.Keys {
		if ks == nil {
			continue
		}
		totalCostNano += ks.TotalCostNanoUSD
		totalTokens += ks.TotalTokens
		inTokens += ks.InputTokens
		outTokens += ks.OutputTokens
		reasonTokens += ks.ReasoningTokens
		readTokens += ks.CacheReadTokens
		writeTokens += ks.CacheWriteTokens
		totalReq += ks.TotalRequests
		okReq += ks.SuccessRequests
		errReq += ks.FailedRequests
	}

	summary := map[string]any{
		"total_cost_usd":       pricing.NanoToUSD(totalCostNano),
		"total_cost_formatted": pricing.FormatUSD(totalCostNano),
		"total_tokens":         totalTokens,
		"input_tokens":         inTokens,
		"output_tokens":        outTokens,
		"reasoning_tokens":     reasonTokens,
		"cache_read_tokens":    readTokens,
		"cache_write_tokens":   writeTokens,
		"total_requests":       totalReq,
		"success_requests":     okReq,
		"failed_requests":      errReq,
	}

	return map[string]any{
		"summary":          summary,
		"keys":             keysCopy,
		"default_policy":   dpCopy,
		"usage":            snap,
		"auth_files":       authFiles,
		"available_models": availableModels,
		"pricing_status":   pStatus,
		"rules_file":       cfg.Storage.RulesFile,
		"diagnostics":      m.BuildPersistenceDiagnostics(),
	}
}

// BuildPersistenceDiagnostics reports every persistence location the plugin
// inspected, so administrators can verify on a live host where the dynamic
// rules file actually lives and whether each mirror survived a restart.
func (m *Manager) BuildPersistenceDiagnostics() map[string]any {
	m.mu.RLock()
	rulesFile := m.cfg.Storage.RulesFile
	usageFile := m.cfg.Storage.UsageFile
	stateKeys := 0
	if m.dynamicState != nil {
		stateKeys = len(m.dynamicState.Keys)
	}
	m.mu.RUnlock()

	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	configFile := FindHostConfigFile("")

	rulesFileExists := false
	rulesFileSize := int64(0)
	if info, errStat := os.Stat(rulesFile); errStat == nil && !info.IsDir() {
		rulesFileExists = true
		rulesFileSize = info.Size()
	}

	return map[string]any{
		"rules_file":                rulesFile,
		"rules_file_exists":         rulesFileExists,
		"rules_file_size":           rulesFileSize,
		"rules_candidates":          DynamicRulesFileReport(rulesFile),
		"rules_keys_in_memory":      stateKeys,
		"usage_file":                usageFile,
		"usage_candidates":          UsageFileCandidates(usageFile),
		"usage_report":              UsageFileReport(usageFile),
		"config_file":               configFile,
		"config_plugin_keys_pinned": len(ReadHostConfigPluginKeys()) > 0,
		"auth_dirs":                 existingAuthDirs(),
		"state_dirs":                StateDirs(),
		"cwd":                       cwd,
		"home":                      home,
		"process_args":              os.Args,
	}
}

// ListKeyRulesAndDefaultPolicy returns all configured API key rules and default_policy.
func (m *Manager) ListKeyRulesAndDefaultPolicy() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keysCopy := make([]KeyRuleConfig, len(m.cfg.Keys))
	for i, k := range m.cfg.Keys {
		keysCopy[i] = cloneKeyRule(k)
	}
	return map[string]any{
		"keys":           keysCopy,
		"default_policy": m.cfg.DefaultPolicy,
		"rules_file":     m.cfg.Storage.RulesFile,
	}
}

// UpsertKeyRuleFromJSON creates or updates a KeyRuleConfig, hot-reloads in-memory rules, and persists to `key_guard_rules.json`.
func (m *Manager) UpsertKeyRuleFromJSON(rawBody []byte) (any, error) {
	var rule KeyRuleConfig
	if err := json.Unmarshal(rawBody, &rule); err != nil {
		return nil, fmt.Errorf("invalid key rule JSON: %w", err)
	}
	rule.APIKey = strings.TrimSpace(rule.APIKey)
	if rule.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if rule.MaxConcurrency < 0 {
		rule.MaxConcurrency = 0
	}
	if rule.QuotaLimitUSD < 0 {
		rule.QuotaLimitUSD = 0
	}
	if rule.Enabled == nil {
		v := true
		rule.Enabled = &v
	}
	if len(rule.AllowedModels) == 0 {
		rule.AllowedModels = []string{"*"}
	}
	nowStr := time.Now().UTC().Format(time.RFC3339)
	rule.UpdatedAt = nowStr

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	// Remove from DeletedKeys if previously deleted
	filteredDel := make([]string, 0, len(m.dynamicState.DeletedKeys))
	for _, dk := range m.dynamicState.DeletedKeys {
		if strings.TrimSpace(dk) != rule.APIKey {
			filteredDel = append(filteredDel, dk)
		}
	}
	m.dynamicState.DeletedKeys = filteredDel

	replaced := false
	for i := range m.dynamicState.Keys {
		if m.dynamicState.Keys[i].APIKey == rule.APIKey {
			if rule.CreatedAt == "" {
				rule.CreatedAt = m.dynamicState.Keys[i].CreatedAt
			}
			m.dynamicState.Keys[i] = cloneKeyRule(rule)
			replaced = true
			break
		}
	}
	if !replaced {
		if rule.CreatedAt == "" {
			rule.CreatedAt = nowStr
		}
		m.dynamicState.Keys = append(m.dynamicState.Keys, cloneKeyRule(rule))
	}

	hasInHost := false
	for _, hk := range m.hostAPIKeys {
		if hk == rule.APIKey {
			hasInHost = true
			break
		}
	}
	if !hasInHost {
		m.hostAPIKeys = append(m.hostAPIKeys, rule.APIKey)
	}

	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	allKeys := make([]string, 0, len(m.cfg.Keys))
	for _, k := range m.cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	if errSave != nil {
		m.host.Log("error", "failed to save dynamic rules file on upsert", map[string]any{
			"file":  rulesFile,
			"error": errSave.Error(),
		})
	}
	m.mu.Unlock()

	if errHost := WriteHostConfigState("", allKeys, m.dynamicState); errHost != nil {
		m.host.Log("warn", "failed to write host config api-keys and plugin state", map[string]any{
			"error": errHost.Error(),
		})
	}
	if errSave != nil {
		return nil, fmt.Errorf("failed to persist rules to %s: %w", rulesFile, errSave)
	}
	return rule, nil
}

// DeleteKeyRule removes a KeyRuleConfig, hot-reloads in-memory rules, and persists to `key_guard_rules.json`.
func (m *Manager) DeleteKeyRule(apiKey string) error {
	target := strings.TrimSpace(apiKey)
	if target == "" {
		return fmt.Errorf("api_key is required")
	}

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	nextKeys := make([]KeyRuleConfig, 0, len(m.dynamicState.Keys))
	for _, kr := range m.dynamicState.Keys {
		if kr.APIKey != target {
			nextKeys = append(nextKeys, kr)
		}
	}
	m.dynamicState.Keys = nextKeys

	nextHostKeys := make([]string, 0, len(m.hostAPIKeys))
	for _, hk := range m.hostAPIKeys {
		if hk != target {
			nextHostKeys = append(nextHostKeys, hk)
		}
	}
	m.hostAPIKeys = nextHostKeys

	alreadyDeleted := false
	for _, dk := range m.dynamicState.DeletedKeys {
		if dk == target {
			alreadyDeleted = true
			break
		}
	}
	if !alreadyDeleted {
		m.dynamicState.DeletedKeys = append(m.dynamicState.DeletedKeys, target)
	}

	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	allKeys := make([]string, 0, len(m.cfg.Keys))
	for _, k := range m.cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	if errSave != nil {
		m.host.Log("error", "failed to save dynamic rules file on delete", map[string]any{
			"file":  rulesFile,
			"error": errSave.Error(),
		})
	}
	m.mu.Unlock()

	if errHost := WriteHostConfigState("", allKeys, m.dynamicState); errHost != nil {
		m.host.Log("warn", "failed to write host config api-keys on delete", map[string]any{
			"error": errHost.Error(),
		})
	}
	return errSave
}

// SaveDefaultPolicyFromJSON updates the global DefaultPolicy, hot-reloads in-memory rules, and persists to `key_guard_rules.json`.
func (m *Manager) SaveDefaultPolicyFromJSON(rawBody []byte) (any, error) {
	var dp DefaultPolicyConfig
	if err := json.Unmarshal(rawBody, &dp); err != nil {
		return nil, fmt.Errorf("invalid default_policy JSON: %w", err)
	}
	if dp.AllowUnlistedKeys == nil {
		v := true
		dp.AllowUnlistedKeys = &v
	}
	if dp.MaxConcurrency < 0 {
		dp.MaxConcurrency = 0
	}
	if dp.QuotaLimitUSD < 0 {
		dp.QuotaLimitUSD = 0
	}
	if len(dp.AllowedModels) == 0 {
		dp.AllowedModels = []string{"*"}
	}

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	dpCopy := dp
	m.dynamicState.DefaultPolicy = &dpCopy
	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	if errSave != nil {
		m.host.Log("error", "failed to save dynamic rules file on save default policy", map[string]any{
			"file":  rulesFile,
			"error": errSave.Error(),
		})
	}
	allKeys := make([]string, 0, len(m.cfg.Keys))
	for _, k := range m.cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}
	m.mu.Unlock()

	if errHost := WriteHostConfigState("", allKeys, m.dynamicState); errHost != nil {
		m.host.Log("warn", "failed to write host config default policy", map[string]any{
			"error": errHost.Error(),
		})
	}

	if errSave != nil {
		return nil, errSave
	}
	return dp, nil
}

// UpsertCustomPrice adds or updates a custom model price override, hot-reloads the pricing engine, and persists to `key_guard_rules.json`.
func (m *Manager) UpsertCustomPrice(model string, price pricing.ModelPrice) error {
	norm := strings.ToLower(strings.TrimSpace(model))
	if norm == "" {
		return fmt.Errorf("model is required")
	}

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	if m.dynamicState.CustomPrices == nil {
		m.dynamicState.CustomPrices = make(map[string]pricing.ModelPrice)
	}

	if norm == "__default__" {
		cp := price
		m.dynamicState.DefaultPrice = &cp
	} else {
		m.dynamicState.CustomPrices[norm] = price
		filteredDel := make([]string, 0, len(m.dynamicState.DeletedPrices))
		for _, dp := range m.dynamicState.DeletedPrices {
			if strings.ToLower(strings.TrimSpace(dp)) != norm {
				filteredDel = append(filteredDel, dp)
			}
		}
		m.dynamicState.DeletedPrices = filteredDel
	}

	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	m.pricingEngine.SetCustomPrices(m.cfg.Pricing.CustomPrices, m.cfg.Pricing.DefaultPrice)
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	m.mu.Unlock()

	return errSave
}

// DeleteCustomPrice removes a custom model price override, hot-reloads the pricing engine, and persists to `key_guard_rules.json`.
func (m *Manager) DeleteCustomPrice(model string) error {
	norm := strings.ToLower(strings.TrimSpace(model))
	if norm == "" {
		return fmt.Errorf("model is required")
	}

	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	if m.dynamicState.CustomPrices != nil {
		delete(m.dynamicState.CustomPrices, norm)
	}
	alreadyDeleted := false
	for _, dp := range m.dynamicState.DeletedPrices {
		if strings.ToLower(strings.TrimSpace(dp)) == norm {
			alreadyDeleted = true
			break
		}
	}
	if !alreadyDeleted {
		m.dynamicState.DeletedPrices = append(m.dynamicState.DeletedPrices, norm)
	}

	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	m.pricingEngine.SetCustomPrices(m.cfg.Pricing.CustomPrices, m.cfg.Pricing.DefaultPrice)
	rulesFile := m.cfg.Storage.RulesFile
	errSave := SaveDynamicRulesFile(rulesFile, m.dynamicState)
	m.mu.Unlock()

	return errSave
}

// BuildSelfAccountView constructs the self-service response for a downstream user querying their own API Key (`#account`).
func (m *Manager) BuildSelfAccountView(apiKey string) (map[string]any, int, error) {
	k := strings.TrimSpace(apiKey)
	if k == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("API key is required")
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, listed := cfg.ResolveKeyRule(k)
	snap := m.BuildSnapshot(k, "", true)
	var ks *usage.KeyStats
	for _, item := range snap.Keys {
		ks = item
		break
	}
	if ks == nil {
		ks = &usage.KeyStats{
			MaskedKey:          usage.MaskAPIKey(k),
			KeyName:            rule.Name,
			ActiveConcurrency:  m.limiter.ActiveCountForKey(k),
			MaxConcurrency:     rule.MaxConcurrency,
			QuotaLimitUSD:      rule.QuotaLimitUSD,
			TotalCostFormatted: "$0.000000",
			Models:             make(map[string]*usage.ModelStats),
		}
	}

	if !listed && !cfg.AllowUnlisted() && ks.TotalRequests == 0 {
		return nil, http.StatusForbidden, fmt.Errorf("该 API Key 未在系统中授权或不存在")
	}

	usedUSD := ks.TotalCostUSD
	var remainingUSD float64
	if rule.QuotaLimitUSD > 0 {
		remainingUSD = rule.QuotaLimitUSD - usedUSD
		if remainingUSD < 0 {
			remainingUSD = 0
		}
	}

	selfAccount := map[string]any{
		"api_key_masked":      usage.MaskAPIKey(k),
		"key_name":            rule.Name,
		"listed":              listed,
		"enabled":             rule.IsEnabled(),
		"active_concurrency":  m.limiter.ActiveCountForKey(k),
		"max_concurrency":     rule.MaxConcurrency,
		"quota_limit_usd":     rule.QuotaLimitUSD,
		"used_cost_usd":       usedUSD,
		"used_cost_formatted": ks.TotalCostFormatted,
		"remaining_quota_usd": remainingUSD,
		"allowed_models":      rule.AllowedModels,
		"upstream_binding": map[string]any{
			"strategy":    rule.UpstreamBinding.Strategy,
			"credentials": append(append([]string(nil), rule.UpstreamBinding.AuthIDs...), rule.UpstreamBinding.Credentials...),
		},
		"stats": ks,
	}

	return map[string]any{
		"ok":           true,
		"self_account": selfAccount,
	}, http.StatusOK, nil
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pluginabi.Envelope{
		OK:     true,
		Result: raw,
	})
}

// ErrorEnvelope encodes an error into a `pluginabi.Envelope`.
func ErrorEnvelope(code, message string) []byte {
	raw, err := json.Marshal(pluginabi.Envelope{
		OK: false,
		Error: &pluginabi.Error{
			Code:    code,
			Message: message,
		},
	})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"failed to encode error envelope"}}`)
	}
	return raw
}
