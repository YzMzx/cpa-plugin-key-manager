package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	PluginVersion = "0.11.3-pre.2"
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
	// mutationMu orders configuration changes and durable rule commits.
	mutationMu         sync.Mutex
	managementMu       sync.Mutex
	admissionMu        sync.RWMutex
	hostSyncError      string
	hostSyncCode       string
	hostKeySync        func(context.Context, string, []string) error
	rejectedAuditSlots chan struct{}
	auditMu            sync.RWMutex
	auditRuntime       *auditRuntime
	auditCleanup       *auditCleanupRuntime
	mu                 sync.RWMutex
	seedCfg            Config
	dynamicState       *DynamicRulesState
	hostAPIKeys        []string
	cfg                Config
	lastSyncKey        string
	settingsApplyError string
	seenModels         map[string]string
	host               *HostBridge
	scheduler          *authz.Scheduler
	limiter            *limiter.Limiter
	pricingEngine      *pricing.Engine
	pricingSyncer      *pricing.Syncer
	usageStore         *usage.Store
	rulesRepo          *rulesRepository
}

// NewManager creates a new plugin Manager instance.
func NewManager(invoker HostInvoker) *Manager {
	hostBridge := NewHostBridge(invoker)
	pricingEng := pricing.NewEngine()
	syncer := pricing.NewSyncer(pricingEng, hostBridge.FetchURL, hostBridge.Log)
	store := usage.NewStore(pricingEng)
	defCfg := DefaultConfig()

	return &Manager{
		rejectedAuditSlots: make(chan struct{}, 16),
		seedCfg:            defCfg,
		dynamicState:       &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)},
		cfg:                defCfg,
		seenModels:         make(map[string]string),
		host:               hostBridge,
		scheduler:          authz.NewScheduler(),
		limiter:            limiter.New(),
		pricingEngine:      pricingEng,
		pricingSyncer:      syncer,
		usageStore:         store,
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
		if err := m.usageStore.FlushIfDirty(); err != nil {
			return nil, err
		}
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
// Hot-reloading preserves active concurrency slots and SQLite dynamic rules,
// and accumulated billing data (`m.usageStore`).
func (m *Manager) Configure(raw []byte) error {
	m.managementMu.Lock()
	defer m.managementMu.Unlock()
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
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

	if err := validateConfig(seedCfg); err != nil {
		return err
	}
	m.mu.RLock()
	currentDB := m.usageStore.SQLitePath()
	m.mu.RUnlock()
	if currentDB != "" && currentDB != seedCfg.Storage.UsageDBFile {
		return fmt.Errorf("changing storage.usage_db_file requires a restart")
	}

	// SQLite is the only persistence backend on this branch: open it before loading
	// the rules, because the rules repository lives in the very same database.
	seedFlush := time.Duration(seedCfg.Storage.FlushIntervalSeconds) * time.Second
	if errDB := m.usageStore.ConfigureSQLite(seedCfg.Storage.UsageDBFile, seedFlush); errDB != nil {
		return fmt.Errorf("configure plugin database: %w", errDB)
	}
	repo := newRulesRepository(m.usageStore.DB())
	if repo == nil {
		return fmt.Errorf("rules database is not configured")
	}
	dynState, err := m.loadRulesState(repo)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	// A reload never falls back to permissive seed rules on an unreadable store.
	if len(dynState.Keys) == 0 && len(dynState.DeletedKeys) == 0 && len(seedCfg.Keys) > 0 {
		for _, key := range seedCfg.Keys {
			dynState.Keys = append(dynState.Keys, cloneKeyRule(key))
		}
		rawState, err := json.Marshal(dynState)
		if err != nil {
			return err
		}
		if err := repo.Save(rawState); err != nil {
			return err
		}
	}

	hostKeys := ReadHostConfigAPIKeys("")
	m.mu.RLock()
	if len(hostKeys) == 0 && len(m.hostAPIKeys) > 0 {
		hostKeys = append([]string(nil), m.hostAPIKeys...)
	}
	m.mu.RUnlock()

	if dynState.Settings != nil {
		validated := *dynState.Settings
		if err := validateRuntimeSettings(&validated); err != nil {
			return err
		}
		dynState.Settings = &validated
	}
	cfg := MergeDynamicState(seedCfg, dynState, hostKeys...)
	if dynState.Settings != nil && settingsCacheConflicts(*dynState.Settings, cfg) {
		return ErrSettingsInvalid
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	// SQLite settings take precedence over seed scheduling on every restart/reload.
	if cfg.Storage.FlushIntervalSeconds != seedCfg.Storage.FlushIntervalSeconds {
		if err := m.usageStore.ConfigureSQLite(cfg.Storage.UsageDBFile, time.Duration(cfg.Storage.FlushIntervalSeconds)*time.Second); err != nil {
			return ErrSettingsPersistence
		}
	}
	if fingerprint := configFingerprint(cfg); dynState.ConfigFingerprint != fingerprint {
		dynState.Revision++
		dynState.ConfigFingerprint = fingerprint
		rawState, err := json.Marshal(dynState)
		if err != nil {
			return err
		}
		if err := repo.Save(rawState); err != nil {
			return fmt.Errorf("persist configured revision: %w", err)
		}
	}
	if err := m.pricingEngine.SetCustomPrices(cfg.Pricing.CustomPrices, cfg.Pricing.DefaultPrice); err != nil {
		return err
	}
	m.usageStore.SetLedgerRetention(cfg.Storage.LedgerRetentionDays)

	syncKey := fmt.Sprintf("%s|%s|%d|%d",
		cfg.Pricing.SyncURL,
		cfg.Storage.PricingCacheFile,
		cfg.Pricing.SyncIntervalHours,
		cfg.Pricing.HTTPTimeoutSeconds,
	)

	m.mu.Lock()
	prevSyncKey := m.lastSyncKey
	m.rulesRepo = repo
	m.seedCfg = seedCfg
	m.dynamicState = dynState
	m.hostAPIKeys = hostKeys
	m.cfg = cfg
	m.lastSyncKey = syncKey
	m.settingsApplyError = ""
	m.mu.Unlock()

	m.configureAudit(cfg.Audit)
	if prevSyncKey != syncKey {
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
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	m.stopAudit()
	m.pricingSyncer.Stop()
	if err := m.usageStore.Close(); err != nil {
		m.host.Log("error", "failed to flush usage on shutdown", map[string]any{"error": err.Error()})
	}
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
					Description: "SQLite storage path, retention, persistence interval and dashboard timezone.",
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

// isManagementPanelRequest reports whether a catalog request came from the
// browser-based management panel. That page lists the server's real catalog, so
// filtering it by the API Key saved in the panel made models look missing.
// API clients (SDKs, curl, the CLI) are still filtered per key.
func isManagementPanelRequest(headers http.Header) bool {
	if headers == nil {
		return false
	}
	// Explicit opt-out for scripts that need the full catalog.
	if strings.EqualFold(strings.TrimSpace(headers.Get("X-Key-Guard-Catalog")), "all") {
		return true
	}
	referer := strings.ToLower(strings.TrimSpace(headers.Get("Referer")))
	return strings.Contains(referer, "/management") || strings.Contains(referer, "management.html")
}

// --- handler.SnapshotProvider implementation ---

// AvailableModelOption represents a selectable model item in the Web UI checkbox list.
type AvailableModelOption struct {
	ID             string              `json:"id"`
	Provider       string              `json:"provider"`
	Sources        []string            `json:"sources,omitempty"`
	Price          pricing.ModelPrice  `json:"price"`
	ReferencePrice *pricing.ModelPrice `json:"reference_price,omitempty"`
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
