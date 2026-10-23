package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key/internal/authz"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key/internal/usage"
	"gopkg.in/yaml.v3"
)

// Config represents the plugin configuration under `plugins.configs.cpa-plugin-key` in CLIProxyAPI's config.yaml.
type Config struct {
	Enabled       bool                `yaml:"enabled" json:"enabled"`
	Priority      int                 `yaml:"priority" json:"priority"`
	AdminToken    string              `yaml:"admin_token" json:"admin_token,omitempty"`
	Storage       StorageConfig       `yaml:"storage" json:"storage"`
	Pricing       PricingConfig       `yaml:"pricing" json:"pricing"`
	DefaultPolicy DefaultPolicyConfig `yaml:"default_policy" json:"default_policy"`
	Keys          []KeyRuleConfig     `yaml:"keys" json:"keys"`

	// Precomputed lookup maps built by Normalize()
	byAPIKey      map[string]*KeyRuleConfig
	byCallerScope map[string]string
}

// StorageConfig defines persistence file paths and intervals.
type StorageConfig struct {
	UsageFile            string `yaml:"usage_file" json:"usage_file"`
	FlushIntervalSeconds int    `yaml:"flush_interval_seconds" json:"flush_interval_seconds"`
	PricingCacheFile     string `yaml:"pricing_cache_file" json:"pricing_cache_file"`
	RulesFile            string `yaml:"rules_file" json:"rules_file"`
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
	APIKey          string                `yaml:"api_key" json:"api_key"`
	Name            string                `yaml:"name" json:"name,omitempty"`
	Enabled         *bool                 `yaml:"enabled" json:"enabled,omitempty"`
	MaxConcurrency  int                   `yaml:"max_concurrency" json:"max_concurrency"`
	QuotaLimitUSD   float64               `yaml:"quota_limit_usd" json:"quota_limit_usd"`
	AllowedModels   []string              `yaml:"allowed_models" json:"allowed_models"`
	UpstreamBinding authz.UpstreamBinding `yaml:"upstream_binding" json:"upstream_binding"`
	CreatedAt       string                `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt       string                `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
}

// DynamicRulesState is persisted to `storage.rules_file` (default `./data/key_guard_rules.json`)
// whenever rules, keys, or custom prices are modified via the Web UI / Management API.
type DynamicRulesState struct {
	Version       int                           `json:"version"`
	UpdatedAt     string                        `json:"updated_at"`
	DefaultPolicy *DefaultPolicyConfig          `json:"default_policy,omitempty"`
	Keys          []KeyRuleConfig               `json:"keys"`
	DeletedKeys   []string                      `json:"deleted_keys,omitempty"`
	CustomPrices  map[string]pricing.ModelPrice `json:"custom_prices,omitempty"`
	DeletedPrices []string                      `json:"deleted_prices,omitempty"`
	DefaultPrice  *pricing.ModelPrice           `json:"default_price,omitempty"`
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
	cfg := Config{
		Enabled:  true,
		Priority: 100,
		Storage: StorageConfig{
			UsageFile:            "./data/key_usage_stats.json",
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
	cfg.Normalize()
	return cfg
}

// ParseConfigYAML parses YAML bytes into Config and normalizes defaults and lookup indexes.
func ParseConfigYAML(raw []byte) (Config, error) {
	cfg := DefaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, err
		}
	}
	cfg.Normalize()
	return cfg, nil
}

// Normalize fills in missing defaults and builds fast lookup maps.
func (c *Config) Normalize() {
	if strings.TrimSpace(c.Storage.UsageFile) == "" {
		c.Storage.UsageFile = "./data/key_usage_stats.json"
	}
	if c.Storage.FlushIntervalSeconds <= 0 {
		c.Storage.FlushIntervalSeconds = 10
	}
	if strings.TrimSpace(c.Storage.PricingCacheFile) == "" {
		c.Storage.PricingCacheFile = "./data/models_dev.json"
	}
	if strings.TrimSpace(c.Storage.RulesFile) == "" {
		dir := filepath.Dir(filepath.Clean(c.Storage.UsageFile))
		if dir == "" || dir == "." {
			c.Storage.RulesFile = "./data/key_guard_rules.json"
		} else {
			c.Storage.RulesFile = filepath.Join(dir, "key_guard_rules.json")
		}
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

// LoadDynamicRulesFile loads the persisted DynamicRulesState from disk if it exists.
func LoadDynamicRulesFile(filePath string) (*DynamicRulesState, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}, nil
	}
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}, nil
	}
	var state DynamicRulesState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("unmarshal dynamic rules from %s: %w", cleanPath, err)
	}
	if state.Version == 0 {
		state.Version = 1
	}
	if state.CustomPrices == nil {
		state.CustomPrices = make(map[string]pricing.ModelPrice)
	}
	return &state, nil
}

// SaveDynamicRulesFile atomically writes DynamicRulesState to disk.
func SaveDynamicRulesFile(filePath string, state *DynamicRulesState) error {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" || state == nil {
		return nil
	}
	state.Version = 1
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return usage.WriteFileAtomically(cleanPath, raw)
}

// MergeDynamicState combines the base config.yaml seed with dynamic Web UI changes from DynamicRulesState.
func MergeDynamicState(seed Config, state *DynamicRulesState) Config {
	out := seed
	if state == nil {
		out.Normalize()
		return out
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

	keyOrder := make([]string, 0, len(seed.Keys)+len(state.Keys))
	keyMap := make(map[string]KeyRuleConfig, len(seed.Keys)+len(state.Keys))

	for _, kr := range seed.Keys {
		k := strings.TrimSpace(kr.APIKey)
		if k == "" {
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

	for _, kr := range state.Keys {
		k := strings.TrimSpace(kr.APIKey)
		if k == "" {
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
	out.Keys = mergedKeys

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

	out.Normalize()
	return out
}

func cloneKeyRule(kr KeyRuleConfig) KeyRuleConfig {
	cp := kr
	if kr.Enabled != nil {
		b := *kr.Enabled
		cp.Enabled = &b
	}
	cp.AllowedModels = append([]string(nil), kr.AllowedModels...)
	cp.UpstreamBinding.AuthIDs = append([]string(nil), kr.UpstreamBinding.AuthIDs...)
	cp.UpstreamBinding.Credentials = append([]string(nil), kr.UpstreamBinding.Credentials...)
	return cp
}

// ResolveAPIKeyFromContext extracts the client API key from HTTP headers, URL query, or CPA `caller_scope` metadata.
func (c *Config) ResolveAPIKeyFromContext(headers http.Header, query url.Values, metadata map[string]any) string {
	// 1. Check HTTP Headers (Authorization: Bearer, X-Api-Key, X-Goog-Api-Key)
	if key := ExtractAPIKeyFromHeadersAndQuery(headers, query); key != "" {
		return key
	}

	// 2. Check metadata["api_key"] or metadata["user_api_key"] if present
	if metadata != nil {
		for _, mk := range []string{"api_key", "user_api_key", "userApiKey"} {
			if v, ok := metadata[mk].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		// 3. Check CPA's `caller_scope` SHA256 fingerprint against configured keys
		if scope, ok := metadata["caller_scope"].(string); ok {
			scope = strings.TrimSpace(scope)
			if scope != "" && c.byCallerScope != nil {
				if apiKey, found := c.byCallerScope[scope]; found {
					return apiKey
				}
			}
		}
	}

	return ""
}

// ExtractAPIKeyFromHeadersAndQuery extracts the client API key using the exact same priority order
// as CLIProxyAPI's `internal/access/config_access/provider.go`:
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
