package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/authz"
	"github.com/YzMzx/cpa-plugin-key/internal/handler"
	"github.com/YzMzx/cpa-plugin-key/internal/limiter"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key/internal/usage"
)

const (
	PluginID      = "cpa-plugin-key"
	PluginVersion = "0.1.0"
	PluginAuthor  = "YzMzx"
	PluginRepo    = "https://github.com/YzMzx/cpa-plugin-key"
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

// Manager is the central runtime coordinator for cpa-plugin-key.
// It is safe for concurrent use and preserves in-flight concurrency slots and
// accumulated usage across `plugin.reconfigure` hot-reloads.
type Manager struct {
	mu            sync.RWMutex
	cfg           Config
	lastSyncKey   string
	host          *HostBridge
	scheduler     *authz.Scheduler
	limiter       *limiter.Limiter
	pricingEngine *pricing.Engine
	pricingSyncer *pricing.Syncer
	usageStore    *usage.Store
}

// NewManager creates a new plugin Manager instance.
func NewManager(invoker HostInvoker) *Manager {
	hostBridge := NewHostBridge(invoker)
	pricingEng := pricing.NewEngine()
	syncer := pricing.NewSyncer(pricingEng, hostBridge.FetchURL, hostBridge.Log)
	store := usage.NewStore(pricingEng)

	return &Manager{
		cfg:           DefaultConfig(),
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
// Hot-reloading preserves all active concurrency slots (`m.limiter`) and accumulated billing data (`m.usageStore`).
func (m *Manager) Configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("decode lifecycle request: %w", err)
		}
	}

	cfg, err := ParseConfigYAML(req.ConfigYAML)
	if err != nil {
		return fmt.Errorf("parse plugin config YAML: %w", err)
	}

	m.pricingEngine.SetCustomPrices(cfg.Pricing.CustomPrices, cfg.Pricing.DefaultPrice)

	flushDur := time.Duration(cfg.Storage.FlushIntervalSeconds) * time.Second
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
	needRestartSync := m.lastSyncKey != syncKey
	m.cfg = cfg
	m.lastSyncKey = syncKey
	m.mu.Unlock()

	if needRestartSync {
		m.pricingSyncer.ConfigureAndStart(pricing.SyncConfig{
			SyncURL:      cfg.Pricing.SyncURL,
			CacheFile:    cfg.Storage.PricingCacheFile,
			SyncInterval: time.Duration(cfg.Pricing.SyncIntervalHours) * time.Hour,
			HTTPTimeout:  time.Duration(cfg.Pricing.HTTPTimeoutSeconds) * time.Second,
		})
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
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "storage",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Persistence paths for usage statistics JSON and models.dev pricing cache.",
				},
				{
					Name:        "pricing",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "models.dev sync interval and custom per-1M-token model price overrides.",
				},
				{
					Name:        "default_policy",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Default concurrency, model whitelist, and upstream binding policy for unlisted API keys.",
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

	// 3. Check and acquire per-API-Key concurrency slot (tracked by RequestID)
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

	// 4. Register in usage store for lifecycle tracking
	m.usageStore.BeginRequest(req.RequestID, apiKey, rule.Name, req.Model, req.RequestedModel, req.SourceFormat, req.Stream)

	// 5. Protocol-guarded auto-injection of `stream_options.include_usage = true` for OpenAI Chat Completions streams
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

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

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
	var req pluginapi.ManagementRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	resp := handler.HandleManagementRequest(context.Background(), m, req)
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
	for _, k := range cfg.Keys {
		maxConcByKey[k.APIKey] = k.MaxConcurrency
		if k.Name != "" {
			keyNames[k.APIKey] = k.Name
		}
	}

	return m.usageStore.Snapshot(filterAPIKey, filterModel, activeByKey, maxConcByKey, keyNames, maskKeys)
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
