package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"gopkg.in/yaml.v3"
)

// Config represents the plugin configuration under `plugins.configs.cpa-plugin-key-manager` in CLIProxyAPI's config.yaml.
type Config struct {
	Enabled       bool                `yaml:"enabled" json:"enabled"`
	Priority      int                 `yaml:"priority" json:"priority"`
	Audit         AuditConfig         `yaml:"audit" json:"audit"`
	Storage       StorageConfig       `yaml:"storage" json:"storage"`
	Pricing       PricingConfig       `yaml:"pricing" json:"pricing"`
	DefaultPolicy DefaultPolicyConfig `yaml:"default_policy" json:"default_policy"`
	Keys          []KeyRuleConfig     `yaml:"keys" json:"keys"`

	// Precomputed lookup maps built by Normalize()
	byAPIKey      map[string]*KeyRuleConfig
	byCallerScope map[string]string
	deletedKeys   map[string]struct{}
}

// StorageConfig defines persistence file paths and intervals.
type StorageConfig struct {
	FlushIntervalSeconds int    `yaml:"flush_interval_seconds" json:"flush_interval_seconds"`
	PricingCacheFile     string `yaml:"pricing_cache_file" json:"pricing_cache_file"`
	// UsageDBFile is the SQLite database used as the authoritative usage store.
	UsageDBFile string `yaml:"usage_db_file" json:"usage_db_file"`
	// LedgerRetentionDays controls how long the overview ledger keeps hourly slices.
	LedgerRetentionDays int `yaml:"ledger_retention_days" json:"ledger_retention_days"`
	// Timezone is the IANA name used for overview bucketing/boundaries.
	// Defaults to Asia/Shanghai (UTC+8).
	Timezone string `yaml:"timezone" json:"timezone,omitempty"`
}

// PricingConfig defines models.dev synchronization and local price overrides.
type PricingConfig struct {
	SyncURL                string                        `yaml:"sync_url" json:"sync_url"`
	SyncIntervalHours      int                           `yaml:"sync_interval_hours" json:"sync_interval_hours"`
	HTTPTimeoutSeconds     int                           `yaml:"http_timeout_seconds" json:"http_timeout_seconds"`
	AutoInjectIncludeUsage *bool                         `yaml:"auto_inject_include_usage" json:"auto_inject_include_usage,omitempty"`
	DefaultPrice           *pricing.ModelPrice           `yaml:"default_price" json:"default_price,omitempty"`
	CustomPrices           map[string]pricing.ModelPrice `yaml:"custom_prices" json:"custom_prices,omitempty"`
}

// DefaultPolicyConfig defines fallback rules for API keys not explicitly listed in `keys`.
type DefaultPolicyConfig struct {
	AllowUnlistedKeys *bool                 `yaml:"allow_unlisted_keys" json:"allow_unlisted_keys,omitempty"`
	MaxConcurrency    int                   `yaml:"max_concurrency" json:"max_concurrency"`
	QuotaLimitUSD     float64               `yaml:"quota_limit_usd" json:"quota_limit_usd"`
	AllowedModels     []string              `yaml:"allowed_models" json:"allowed_models"`
	UpstreamBinding   authz.UpstreamBinding `yaml:"upstream_binding" json:"upstream_binding"`
}

// KeyRuleConfig defines governance, routing, quota, and concurrency policies for a specific API Key.
type KeyRuleConfig struct {
	APIKey         string  `yaml:"api_key" json:"api_key"`
	Name           string  `yaml:"name" json:"name,omitempty"`
	Enabled        *bool   `yaml:"enabled" json:"enabled,omitempty"`
	MaxConcurrency int     `yaml:"max_concurrency" json:"max_concurrency"`
	QuotaLimitUSD  float64 `yaml:"quota_limit_usd" json:"quota_limit_usd"`
	// QuotaUsedBaseUSD is the accumulated cost already written off by "重置额度".
	// The effective usage is (total cost - base), so resetting never touches billing history.
	QuotaUsedBaseUSD   float64               `yaml:"quota_used_base_usd,omitempty" json:"quota_used_base_usd,omitempty"`
	QuotaSourceKeys    []string              `yaml:"-" json:"quota_source_keys,omitempty"`
	QuotaSourceBaseUSD float64               `yaml:"-" json:"quota_source_base_usd,omitempty"`
	QuotaUsedUSD       *float64              `yaml:"-" json:"quota_used_usd,omitempty"`
	AllowedModels      []string              `yaml:"allowed_models" json:"allowed_models"`
	UpstreamBinding    authz.UpstreamBinding `yaml:"upstream_binding" json:"upstream_binding"`
	CreatedAt          string                `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt          string                `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
}

// DynamicRulesState is persisted atomically in SQLite rules_state.
// whenever rules, keys, or custom prices are modified via the Web UI / Management API.
type DynamicRulesState struct {
	Intercept         *contentguard.State  `json:"intercept,omitempty"`
	Version           int                  `json:"version"`
	UpdatedAt         string               `json:"updated_at"`
	Revision          uint64               `json:"revision,omitempty"`
	HostSyncPending   bool                 `json:"host_sync_pending,omitempty"`
	ConfigFingerprint string               `json:"config_fingerprint,omitempty"`
	Settings          *RuntimeSettings     `json:"settings,omitempty"`
	DefaultPolicy     *DefaultPolicyConfig `json:"default_policy,omitempty"`
	Keys              []KeyRuleConfig      `json:"keys"`
	// KeyOrder is the administrator-defined display order (drag & drop) of API keys.
	KeyOrder      []string                      `json:"key_order,omitempty"`
	DeletedKeys   []string                      `json:"deleted_keys,omitempty"`
	CustomPrices  map[string]pricing.ModelPrice `json:"custom_prices,omitempty"`
	DeletedPrices []string                      `json:"deleted_prices,omitempty"`
	DefaultPrice  *pricing.ModelPrice           `json:"default_price,omitempty"`
}

// applyKeyOrder stable-sorts merged keys following the persisted display order.
// Keys missing from the order list keep their original relative position at the end.
func applyKeyOrder(keys []KeyRuleConfig, order []string) []KeyRuleConfig {
	if len(order) == 0 || len(keys) < 2 {
		return keys
	}
	rank := make(map[string]int, len(order))
	for i, raw := range order {
		key := strings.TrimSpace(raw)
		if key == "" {
			continue
		}
		if _, exists := rank[key]; !exists {
			rank[key] = i
		}
	}
	if len(rank) == 0 {
		return keys
	}
	type ranked struct {
		rule KeyRuleConfig
		pos  int
		rank int
	}
	out := make([]ranked, 0, len(keys))
	for i, rule := range keys {
		r, ok := rank[strings.TrimSpace(rule.APIKey)]
		if !ok {
			r = len(rank) + i
		}
		out = append(out, ranked{rule: rule, pos: i, rank: r})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return out[i].pos < out[j].pos
	})
	sorted := make([]KeyRuleConfig, 0, len(out))
	for _, item := range out {
		sorted = append(sorted, item.rule)
	}
	return sorted
}

// IsEnabled returns true unless Enabled was explicitly set to false.
func (k KeyRuleConfig) IsEnabled() bool {
	if k.Enabled == nil {
		return true
	}
	return *k.Enabled
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	allowUnlisted := true
	autoInject := true
	return Config{
		Enabled:  true,
		Priority: 100,
		Storage: StorageConfig{
			UsageDBFile:          "./data/key_usage.db",
			FlushIntervalSeconds: 10,
			PricingCacheFile:     "./data/models_dev.json",
		},
		Pricing: PricingConfig{
			SyncURL:                "https://models.dev/api.json",
			SyncIntervalHours:      24,
			HTTPTimeoutSeconds:     30,
			AutoInjectIncludeUsage: &autoInject,
			CustomPrices:           make(map[string]pricing.ModelPrice),
		},
		DefaultPolicy: DefaultPolicyConfig{
			AllowUnlistedKeys: &allowUnlisted,
			MaxConcurrency:    0,
			AllowedModels:     []string{"*"},
		},
	}
}

// ParseConfigYAML parses YAML bytes into Config and normalizes defaults and lookup indexes.
// It supports both raw plugin instance YAML and full CLIProxyAPI config.yaml files.
func ParseConfigYAML(raw []byte) (Config, error) {
	cfg := DefaultConfig()
	cleaned := strings.TrimSpace(string(raw))
	if len(cleaned) > 0 {
		var root struct {
			Plugins struct {
				Configs map[string]yaml.Node `yaml:"configs"`
			} `yaml:"plugins"`
		}
		if errRoot := yaml.Unmarshal(raw, &root); errRoot == nil && root.Plugins.Configs != nil {
			if node, ok := root.Plugins.Configs[PluginID]; ok {
				var parsed Config
				if errDecode := node.Decode(&parsed); errDecode != nil {
					return Config{}, errDecode
				}
				parsed.Normalize()
				if err := validateConfig(parsed); err != nil {
					return Config{}, err
				}
				return parsed, nil
			}
		}

		var parsed Config
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return Config{}, err
		}
		cfg = parsed
	}
	cfg.Normalize()
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// FindCPARootDir discovers the root directory of the CLIProxyAPI installation by checking:
// 1. Explicit CPA_DIR environment variable
// 2. Directory containing config.yaml (found via FindHostConfigFile)
// 3. Directory of the host executable (os.Executable)
// 4. Fallback to process working directory (os.Getwd)
func FindCPARootDir() string {
	if envDir := strings.TrimSpace(os.Getenv("CPA_DIR")); envDir != "" {
		if abs, err := filepath.Abs(envDir); err == nil {
			return abs
		}
		return filepath.Clean(envDir)
	}

	// If config.yaml is found, its directory is the canonical CPA root
	cfgPath := FindHostConfigFile("")
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); err == nil {
			return filepath.Dir(cfgPath)
		}
	}

	if exe, errExe := os.Executable(); errExe == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(exeDir, "config.yaml")); err == nil {
			return exeDir
		}
		if _, err := os.Stat(filepath.Join(exeDir, "plugins")); err == nil {
			return exeDir
		}
		parentDir := filepath.Dir(exeDir)
		if _, err := os.Stat(filepath.Join(parentDir, "config.yaml")); err == nil {
			return parentDir
		}
		if _, err := os.Stat(filepath.Join(parentDir, "plugins")); err == nil {
			return parentDir
		}
	}

	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	return "."
}

// ResolveStoragePath resolves relative SQLite/cache paths only against the CPA
// root. Existing similarly named files in other locations are never adopted.
func ResolveStoragePath(rawPath string) string {
	cleaned := strings.TrimSpace(rawPath)
	if cleaned == "" {
		return ""
	}
	if filepath.IsAbs(cleaned) {
		return filepath.Clean(cleaned)
	}
	return filepath.Clean(filepath.Join(FindCPARootDir(), cleaned))
}

// FindHostConfigFile locates CLIProxyAPI's config.yaml on disk by checking:
// 1. Explicit path parameter (if non-empty)
// 2. Command-line arguments of current process (-config, --config, -config=..., --config=...)
// 3. CPA_CONFIG_FILE environment variable
// 4. CPA_DIR environment variable (filepath.Join(CPA_DIR, "config.yaml"))
// 5. Standard locations relative to CWD ("config.yaml", "../config.yaml")
// 6. Locations relative to the host executable directory
// 7. Common container/deployment locations ("/CLIProxyAPI/config.yaml")
func FindHostConfigFile(preferredPath string) string {
	if strings.TrimSpace(preferredPath) != "" {
		return preferredPath
	}

	// Check CLI flags from os.Args (-config or --config)
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-config" || arg == "--config" {
			if i+1 < len(os.Args) {
				candidate := strings.TrimSpace(os.Args[i+1])
				if candidate != "" {
					if _, err := os.Stat(candidate); err == nil {
						if abs, errAbs := filepath.Abs(candidate); errAbs == nil {
							return abs
						}
						return candidate
					}
				}
			}
		} else if strings.HasPrefix(arg, "-config=") || strings.HasPrefix(arg, "--config=") {
			candidate := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(arg, "--config="), "-config="))
			if candidate != "" {
				if _, err := os.Stat(candidate); err == nil {
					if abs, errAbs := filepath.Abs(candidate); errAbs == nil {
						return abs
					}
					return candidate
				}
			}
		}
	}

	if envPath := strings.TrimSpace(os.Getenv("CPA_CONFIG_FILE")); envPath != "" {
		return envPath
	}

	if envDir := strings.TrimSpace(os.Getenv("CPA_DIR")); envDir != "" {
		candidate := filepath.Join(envDir, "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			if abs, errAbs := filepath.Abs(candidate); errAbs == nil {
				return abs
			}
			return candidate
		}
	}

	candidates := []string{
		"config.yaml",
		"../config.yaml",
		"/CLIProxyAPI/config.yaml",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			if abs, errAbs := filepath.Abs(c); errAbs == nil {
				return abs
			}
			return c
		}
	}

	if exe, errExe := os.Executable(); errExe == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		exeCandidates := []string{
			filepath.Join(exeDir, "config.yaml"),
			filepath.Join(filepath.Dir(exeDir), "config.yaml"),
		}
		for _, c := range exeCandidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}

	// Default fallback to "config.yaml"
	if abs, errAbs := filepath.Abs("config.yaml"); errAbs == nil {
		return abs
	}
	return "config.yaml"
}

// Normalize fills in missing defaults and builds fast lookup maps.
func (c *Config) Normalize() {
	c.Audit.normalize()
	// SQLite only: the database is the single source of truth and lives in the CPA
	// root's `data` directory by default (explicit configuration always wins).
	// CPA_KEY_MANAGER_USAGE_DB pins it explicitly, which tests and multi-instance
	// deployments use to keep databases apart.
	if override := strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_USAGE_DB")); override != "" {
		c.Storage.UsageDBFile = ResolveStoragePath(override)
	}
	if strings.TrimSpace(c.Storage.UsageDBFile) == "" {
		c.Storage.UsageDBFile = filepath.Join(FindCPARootDir(), "data", "key_usage.db")
	}
	if c.Storage.FlushIntervalSeconds <= 0 {
		c.Storage.FlushIntervalSeconds = 10
	}
	if c.Storage.LedgerRetentionDays <= 0 {
		c.Storage.LedgerRetentionDays = 90
	}
	if strings.TrimSpace(c.Storage.Timezone) == "" {
		c.Storage.Timezone = usage.DefaultTimezone
	}
	if strings.TrimSpace(c.Storage.PricingCacheFile) == "" {
		c.Storage.PricingCacheFile = "./data/models_dev.json"
	}
	c.Storage.PricingCacheFile = ResolveStoragePath(c.Storage.PricingCacheFile)

	if strings.TrimSpace(c.Storage.UsageDBFile) != "" {
		c.Storage.UsageDBFile = ResolveStoragePath(c.Storage.UsageDBFile)
	}
	if strings.TrimSpace(c.Pricing.SyncURL) == "" {
		c.Pricing.SyncURL = "https://models.dev/api.json"
	}
	if c.Pricing.SyncIntervalHours <= 0 {
		c.Pricing.SyncIntervalHours = 24
	}
	if c.Pricing.HTTPTimeoutSeconds <= 0 {
		c.Pricing.HTTPTimeoutSeconds = 30
	}
	if c.Pricing.AutoInjectIncludeUsage == nil {
		v := true
		c.Pricing.AutoInjectIncludeUsage = &v
	}
	if c.Pricing.CustomPrices == nil {
		c.Pricing.CustomPrices = make(map[string]pricing.ModelPrice)
	}
	if c.DefaultPolicy.AllowUnlistedKeys == nil {
		v := true
		c.DefaultPolicy.AllowUnlistedKeys = &v
	}
	if len(c.DefaultPolicy.AllowedModels) == 0 {
		c.DefaultPolicy.AllowedModels = []string{"*"}
	}

	c.byAPIKey = make(map[string]*KeyRuleConfig, len(c.Keys))
	c.byCallerScope = make(map[string]string, len(c.Keys))
	for i := range c.Keys {
		k := strings.TrimSpace(c.Keys[i].APIKey)
		if k == "" {
			continue
		}
		c.Keys[i].APIKey = k
		if len(c.Keys[i].AllowedModels) == 0 {
			c.Keys[i].AllowedModels = []string{"*"}
		}
		c.byAPIKey[k] = &c.Keys[i]
		scope := ComputeCallerScope(k)
		if scope != "" {
			c.byCallerScope[scope] = k
		}
	}
	for deleted := range c.deletedKeys {
		if scope := ComputeCallerScope(deleted); scope != "" {
			c.byCallerScope[scope] = deleted
		}
	}
}

// ShouldAutoInjectIncludeUsage returns true if `stream_options.include_usage` auto-injection is enabled.
func (c *Config) ShouldAutoInjectIncludeUsage() bool {
	if c.Pricing.AutoInjectIncludeUsage == nil {
		return true
	}
	return *c.Pricing.AutoInjectIncludeUsage
}

// AllowUnlisted returns true if unlisted API keys are permitted under DefaultPolicy.
func (c *Config) AllowUnlisted() bool {
	if c.DefaultPolicy.AllowUnlistedKeys == nil {
		return true
	}
	return *c.DefaultPolicy.AllowUnlistedKeys
}

// ResolveKeyRule finds the configured KeyRuleConfig for an API key, or returns a synthesized rule from DefaultPolicy.
func (c *Config) ResolveKeyRule(apiKey string) (rule KeyRuleConfig, listed bool) {
	k := strings.TrimSpace(apiKey)
	if _, deleted := c.deletedKeys[k]; deleted {
		enabled := false
		return KeyRuleConfig{APIKey: k, Enabled: &enabled}, true
	}
	if k != "" && c.byAPIKey != nil {
		if found, ok := c.byAPIKey[k]; ok && found != nil {
			return *found, true
		}
	}
	enabled := c.AllowUnlisted()
	return KeyRuleConfig{
		APIKey:          k,
		Name:            "",
		Enabled:         &enabled,
		MaxConcurrency:  c.DefaultPolicy.MaxConcurrency,
		QuotaLimitUSD:   c.DefaultPolicy.QuotaLimitUSD,
		AllowedModels:   c.DefaultPolicy.AllowedModels,
		UpstreamBinding: c.DefaultPolicy.UpstreamBinding,
	}, false
}

// MergeDynamicState combines CPA's global `api-keys`, the base config.yaml seed, and dynamic Web UI changes from DynamicRulesState.
func MergeDynamicState(seed Config, state *DynamicRulesState, hostAPIKeys ...string) Config {
	out := seed
	if state == nil {
		state = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}

	if state.DefaultPolicy != nil {
		dp := *state.DefaultPolicy
		dp.AllowedModels = append([]string(nil), state.DefaultPolicy.AllowedModels...)
		dp.UpstreamBinding.AuthIDs = append([]string(nil), state.DefaultPolicy.UpstreamBinding.AuthIDs...)
		dp.UpstreamBinding.Credentials = append([]string(nil), state.DefaultPolicy.UpstreamBinding.Credentials...)
		out.DefaultPolicy = dp
	}

	deletedKeySet := make(map[string]struct{}, len(state.DeletedKeys))
	for _, dk := range state.DeletedKeys {
		k := strings.TrimSpace(dk)
		if k != "" {
			deletedKeySet[k] = struct{}{}
		}
	}

	keyOrder := make([]string, 0, len(hostAPIKeys)+len(seed.Keys)+len(state.Keys))
	keyMap := make(map[string]KeyRuleConfig, len(hostAPIKeys)+len(seed.Keys)+len(state.Keys))

	isSampleOrInvalidKey := func(k string) bool {
		v := strings.TrimSpace(k)
		if v == "" || v == "__anonymous__" || strings.EqualFold(v, "anonymous") {
			return true
		}
		return false
	}

	// 1. CPA Global `api-keys` (unified key source)
	for _, rawKey := range hostAPIKeys {
		k := strings.TrimSpace(rawKey)
		if isSampleOrInvalidKey(k) {
			continue
		}
		if _, deleted := deletedKeySet[k]; deleted {
			continue
		}
		if _, exists := keyMap[k]; !exists {
			keyOrder = append(keyOrder, k)
		}
		enabled := true
		keyMap[k] = KeyRuleConfig{
			APIKey:          k,
			Enabled:         &enabled,
			MaxConcurrency:  out.DefaultPolicy.MaxConcurrency,
			QuotaLimitUSD:   out.DefaultPolicy.QuotaLimitUSD,
			AllowedModels:   append([]string(nil), out.DefaultPolicy.AllowedModels...),
			UpstreamBinding: out.DefaultPolicy.UpstreamBinding,
		}
	}

	// 2. Plugin seed keys (if any)
	for _, kr := range seed.Keys {
		k := strings.TrimSpace(kr.APIKey)
		if isSampleOrInvalidKey(k) {
			continue
		}
		if _, deleted := deletedKeySet[k]; deleted {
			continue
		}
		if _, exists := keyMap[k]; !exists {
			keyOrder = append(keyOrder, k)
		}
		keyMap[k] = cloneKeyRule(kr)
	}

	// 3. Dynamic WebUI governance rules
	for _, kr := range state.Keys {
		k := strings.TrimSpace(kr.APIKey)
		if isSampleOrInvalidKey(k) {
			continue
		}
		if _, exists := keyMap[k]; !exists {
			keyOrder = append(keyOrder, k)
		}
		keyMap[k] = cloneKeyRule(kr)
	}

	mergedKeys := make([]KeyRuleConfig, 0, len(keyOrder))
	for _, k := range keyOrder {
		if r, ok := keyMap[k]; ok {
			mergedKeys = append(mergedKeys, r)
		}
	}
	out.Keys = applyKeyOrder(mergedKeys, state.KeyOrder)

	deletedPriceSet := make(map[string]struct{}, len(state.DeletedPrices))
	for _, dp := range state.DeletedPrices {
		p := strings.ToLower(strings.TrimSpace(dp))
		if p != "" {
			deletedPriceSet[p] = struct{}{}
		}
	}

	mergedPrices := make(map[string]pricing.ModelPrice, len(seed.Pricing.CustomPrices)+len(state.CustomPrices))
	for m, p := range seed.Pricing.CustomPrices {
		norm := strings.ToLower(strings.TrimSpace(m))
		if norm == "" {
			continue
		}
		if _, deleted := deletedPriceSet[norm]; deleted {
			continue
		}
		mergedPrices[norm] = p
	}
	for m, p := range state.CustomPrices {
		norm := strings.ToLower(strings.TrimSpace(m))
		if norm == "" {
			continue
		}
		mergedPrices[norm] = p
	}
	out.Pricing.CustomPrices = mergedPrices

	if state.DefaultPrice != nil {
		cp := *state.DefaultPrice
		out.Pricing.DefaultPrice = &cp
	}

	out.deletedKeys = deletedKeySet
	applySettingsConfig(&out, state.Settings)
	out.Normalize()
	return out
}

func cloneKeyRule(kr KeyRuleConfig) KeyRuleConfig {
	cp := kr
	if kr.Enabled != nil {
		b := *kr.Enabled
		cp.Enabled = &b
	}
	cp.QuotaSourceKeys = append([]string(nil), kr.QuotaSourceKeys...)
	cp.AllowedModels = append([]string(nil), kr.AllowedModels...)
	cp.UpstreamBinding.AuthIDs = append([]string(nil), kr.UpstreamBinding.AuthIDs...)
	cp.UpstreamBinding.Credentials = append([]string(nil), kr.UpstreamBinding.Credentials...)
	cp.UpstreamBinding.Providers = append([]string(nil), kr.UpstreamBinding.Providers...)
	if kr.UpstreamBinding.Strict != nil {
		strict := *kr.UpstreamBinding.Strict
		cp.UpstreamBinding.Strict = &strict
	}
	if kr.UpstreamBinding.Attributes != nil {
		cp.UpstreamBinding.Attributes = make(map[string]string, len(kr.UpstreamBinding.Attributes))
		for k, v := range kr.UpstreamBinding.Attributes {
			cp.UpstreamBinding.Attributes[k] = v
		}
	}
	return cp
}

// ResolveAPIKeyFromContext resolves the host-authenticated identity before looking
// at raw credential candidates. Unresolved/ambiguous identities never pick a key.
func (c *Config) ResolveAPIKeyFromContext(headers http.Header, query url.Values, metadata map[string]any) string {
	key, _ := c.resolveAuthenticatedKey(headers, query, metadata, "")
	return key
}

// ExtractAPIKeyFromHeadersAndQuery retains the legacy single-value extraction order
// for compatibility callers. It does not authenticate a key and must not be used
// to override host-authenticated identity (the host chooses a valid candidate):
//  1. Authorization: Bearer <token>
//  2. X-Goog-Api-Key
//  3. X-Api-Key
//  4. Query parameter `key`
//  5. Query parameter `auth_token`
//  6. Query parameter `api_key`
func ExtractAPIKeyFromHeadersAndQuery(headers http.Header, query url.Values) string {
	if headers != nil {
		if authHeader := strings.TrimSpace(headers.Get("Authorization")); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				if token := strings.TrimSpace(parts[1]); token != "" {
					return token
				}
			}
		}
		if googKey := strings.TrimSpace(headers.Get("X-Goog-Api-Key")); googKey != "" {
			return googKey
		}
		if apiKey := strings.TrimSpace(headers.Get("X-Api-Key")); apiKey != "" {
			return apiKey
		}
	}
	if query != nil {
		for _, qk := range []string{"key", "auth_token", "api_key"} {
			if v := strings.TrimSpace(query.Get(qk)); v != "" {
				return v
			}
		}
	}
	return ""
}

// ComputeCallerScope matches CLIProxyAPI's `session.CallerScope` (`SHA256("cli-proxy-api:caller-scope:v1\x00" + apiKey)`).
func ComputeCallerScope(apiKey string) string {
	val := strings.TrimSpace(apiKey)
	if val == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + val))
	return hex.EncodeToString(sum[:])
}
