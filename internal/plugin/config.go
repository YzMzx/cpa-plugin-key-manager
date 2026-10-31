package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"gopkg.in/yaml.v3"
)

// Config represents the plugin configuration under `plugins.configs.cpa-plugin-key-manager` in CLIProxyAPI's config.yaml.
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
	// UsageDBFile is the SQLite database used as the authoritative usage store.
	UsageDBFile string `yaml:"usage_db_file" json:"usage_db_file"`
	// LegacyUsageDBFile is the database location earlier builds derived from
	// `usage_file`. It is imported once when the durable database does not exist yet.
	LegacyUsageDBFile string `yaml:"-" json:"legacy_usage_db_file,omitempty"`
	// LedgerRetentionDays controls how long the overview ledger keeps hourly slices.
	LedgerRetentionDays int `yaml:"ledger_retention_days" json:"ledger_retention_days"`
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
	QuotaUsedBaseUSD float64               `yaml:"quota_used_base_usd,omitempty" json:"quota_used_base_usd,omitempty"`
	AllowedModels    []string              `yaml:"allowed_models" json:"allowed_models"`
	UpstreamBinding  authz.UpstreamBinding `yaml:"upstream_binding" json:"upstream_binding"`
	CreatedAt        string                `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt        string                `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
}

// DynamicRulesState is persisted to `storage.rules_file` (default `./data/key_guard_rules.json`)
// whenever rules, keys, or custom prices are modified via the Web UI / Management API.
type DynamicRulesState struct {
	Version       int                  `json:"version"`
	UpdatedAt     string               `json:"updated_at"`
	DefaultPolicy *DefaultPolicyConfig `json:"default_policy,omitempty"`
	Keys          []KeyRuleConfig      `json:"keys"`
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
			UsageFile:            "./data/key_usage_stats.json",
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
				if errDecode := node.Decode(&parsed); errDecode == nil {
					parsed.Normalize()
					return parsed, nil
				}
			}
		}

		var parsed Config
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return Config{}, err
		}
		cfg = parsed
	}
	cfg.Normalize()
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

// ResolveStoragePath converts a configured relative path (e.g. "./data/key_guard_rules.json")
// to a robust absolute path. It anchors uncreated paths to the canonical CPA root directory,
// while also discovering existing files across potential CWD, exeDir, and container locations
// so that differences in CWD across CLIProxyAPI restarts never cause data loss.
// legacyUsageDBPath mirrors the database location earlier experimental builds
// derived from `usage_file`, so an upgrade can import the existing rows once.
func legacyUsageDBPath(usageFile string) string {
	clean := strings.TrimSpace(usageFile)
	if clean == "" {
		return ""
	}
	clean = filepath.Clean(clean)
	if strings.HasSuffix(strings.ToLower(clean), ".db") {
		return clean
	}
	return strings.TrimSuffix(clean, filepath.Ext(clean)) + ".db"
}
func ResolveStoragePath(rawPath string) string {
	cleaned := strings.TrimSpace(rawPath)
	if cleaned == "" {
		return ""
	}
	if filepath.IsAbs(cleaned) {
		return filepath.Clean(cleaned)
	}

	cpaRoot := FindCPARootDir()
	canonicalPath := filepath.Clean(filepath.Join(cpaRoot, cleaned))

	// 1. If it already exists at the canonical CPA root, use it immediately
	if _, err := os.Stat(canonicalPath); err == nil {
		return canonicalPath
	}

	// 2. Check candidate locations where previous runs may have stored it
	candidates := make([]string, 0, 8)

	// Relative to CWD
	if wd, err := os.Getwd(); err == nil && wd != "" {
		candidates = append(candidates, filepath.Clean(filepath.Join(wd, cleaned)))
	}

	// Relative to executable directory
	if exe, errExe := os.Executable(); errExe == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Clean(filepath.Join(exeDir, cleaned)))
		candidates = append(candidates, filepath.Clean(filepath.Join(filepath.Dir(exeDir), cleaned)))
	}

	// User home directory (.cli-proxy-api)
	if home, errHome := os.UserHomeDir(); errHome == nil && home != "" {
		candidates = append(candidates, filepath.Clean(filepath.Join(home, ".cli-proxy-api", cleaned)))
		candidates = append(candidates, filepath.Clean(filepath.Join(home, cleaned)))
	}

	// Common Unix container path
	candidates = append(candidates, filepath.Clean(filepath.Join("/CLIProxyAPI", cleaned)))

	for _, cand := range candidates {
		if cand == canonicalPath {
			continue
		}
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand
		}
	}

	// 3. File does not exist anywhere yet: ALWAYS anchor to canonical CPA root directory
	return canonicalPath
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
	if strings.TrimSpace(c.Storage.UsageFile) == "" {
		c.Storage.UsageFile = "./data/key_usage_stats.json"
	}
	c.Storage.UsageFile = ResolveStoragePath(c.Storage.UsageFile)

	// SQLite only: the database is the single source of truth, so it must live on a
	// durable volume rather than the ephemeral working directory a container recreates.
	// Priority: explicit config > first durable state dir > legacy snapshot directory.
	if strings.TrimSpace(c.Storage.UsageDBFile) == "" {
		if stateDirs := StateDirs(); len(stateDirs) > 0 {
			c.Storage.UsageDBFile = filepath.Join(stateDirs[0], "key_usage.db")
		} else {
			dir := filepath.Dir(filepath.Clean(c.Storage.UsageFile))
			base := strings.TrimSuffix(filepath.Base(filepath.Clean(c.Storage.UsageFile)), filepath.Ext(c.Storage.UsageFile))
			if dir == "" || dir == "." {
				c.Storage.UsageDBFile = "./" + base + ".db"
			} else {
				c.Storage.UsageDBFile = filepath.Join(dir, base+".db")
			}
		}
	}
	c.Storage.LegacyUsageDBFile = legacyUsageDBPath(c.Storage.UsageFile)

	if c.Storage.FlushIntervalSeconds <= 0 {
		c.Storage.FlushIntervalSeconds = 10
	}
	if c.Storage.LedgerRetentionDays <= 0 {
		c.Storage.LedgerRetentionDays = 90
	}
	if strings.TrimSpace(c.Storage.PricingCacheFile) == "" {
		c.Storage.PricingCacheFile = "./data/models_dev.json"
	}
	c.Storage.PricingCacheFile = ResolveStoragePath(c.Storage.PricingCacheFile)

	if strings.TrimSpace(c.Storage.RulesFile) == "" {
		dir := filepath.Dir(filepath.Clean(c.Storage.UsageFile))
		if dir == "" || dir == "." {
			c.Storage.RulesFile = "./data/key_guard_rules.json"
		} else {
			c.Storage.RulesFile = filepath.Join(dir, "key_guard_rules.json")
		}
	}
	c.Storage.RulesFile = ResolveStoragePath(c.Storage.RulesFile)
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

// AuthDirCandidates returns candidate CLIProxyAPI auth-token directories.
// These directories hold OAuth credentials, so they are guaranteed to be on a
// persistent volume that survives CLIProxyAPI restarts and container recreation.
func AuthDirCandidates() []string {
	out := make([]string, 0, 6)
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		if strings.HasPrefix(dir, "~/") || dir == "~" {
			home, errHome := os.UserHomeDir()
			if errHome != nil || home == "" {
				return
			}
			if dir == "~" {
				dir = home
			} else {
				dir = filepath.Join(home, strings.TrimPrefix(dir, "~/"))
			}
		}
		dir = filepath.Clean(dir)
		for _, existing := range out {
			if existing == dir {
				return
			}
		}
		out = append(out, dir)
	}

	for _, envName := range []string{"CPA_AUTH_DIR", "AUTH_DIR", "CLI_PROXY_AUTH_DIR"} {
		add(os.Getenv(envName))
	}
	if home, errHome := os.UserHomeDir(); errHome == nil && home != "" {
		add(filepath.Join(home, ".cli-proxy-api"))
		add(filepath.Join(home, ".cli-proxy-api", "auths"))
	}
	add("/root/.cli-proxy-api")
	add("/home/cliproxy/.cli-proxy-api")
	return out
}

// existingAuthDirs returns only the auth directory candidates that exist on disk.
func existingAuthDirs() []string {
	out := make([]string, 0, 4)
	for _, dir := range AuthDirCandidates() {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			out = append(out, dir)
		}
	}
	return out
}

// StateDirs returns the directories (in priority order) where the dynamic rules
// JSON may be persisted. Persistent auth directories come first so that state
// survives container recreation even when the working directory is ephemeral.
//
// Mirrors are stored in a dedicated `key-manager` subdirectory of the auth dir so
// CLIProxyAPI never mistakes them for OAuth credential files.
//
// The `CPA_KEY_MANAGER_STATE_DIRS` environment variable (comma separated) can be
// used to pin the mirror locations explicitly; those directories are always used
// and are created on demand.
func StateDirs() []string {
	out := make([]string, 0, 10)
	add := func(dir string, mustExist bool) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		dir = filepath.Clean(dir)
		if mustExist {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				return
			}
		}
		for _, existing := range out {
			if existing == dir {
				return
			}
		}
		out = append(out, dir)
	}

	if raw := strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_STATE_DIRS")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			add(part, false)
		}
		return out
	}

	for _, authDir := range existingAuthDirs() {
		add(filepath.Join(authDir, stateSubdirName), false)
	}
	if cfgPath := FindHostConfigFile(""); cfgPath != "" {
		if info, errStat := os.Stat(cfgPath); errStat == nil && !info.IsDir() {
			add(filepath.Dir(cfgPath), true)
		}
	}
	root := FindCPARootDir()
	add(filepath.Join(root, "data"), true)
	add(root, true)
	if wd, errWD := os.Getwd(); errWD == nil && wd != "" {
		add(wd, true)
	}
	if exe, errExe := os.Executable(); errExe == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		add(filepath.Join(exeDir, "data"), true)
	}
	return out
}

// stateSubdirName is the dedicated directory created inside CLIProxyAPI's auth
// directory for plugin state.
const stateSubdirName = "key-manager"

// stateFileExtension is used for mirrors that live inside CLIProxyAPI's auth
// directory. CLIProxyAPI walks that directory RECURSIVELY and treats every
// `*.json` file as an OAuth credential (and its ID then contains a path
// separator, which the management API refuses to delete). Mirrors therefore use
// a non-`.json` extension so they are invisible to the credential scanner.
const stateFileExtension = ".state"

// isInsideAuthDir reports whether dir is an CLIProxyAPI auth directory (or a
// subdirectory of one).
func isInsideAuthDir(dir string) bool {
	dir = filepath.Clean(dir)
	for _, authDir := range existingAuthDirs() {
		authDir = filepath.Clean(authDir)
		if dir == authDir || strings.HasPrefix(dir, authDir+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// mirrorNameInDir maps a JSON base name to the file name used inside dir: files
// placed under the auth directory must not end in `.json`.
func mirrorNameInDir(dir, baseName string) string {
	if !isInsideAuthDir(dir) {
		return baseName
	}
	return strings.TrimSuffix(baseName, ".json") + stateFileExtension
}

// legacyAuthMirrorPaths returns the mirror locations used by older releases
// (auth-dir root and the key-manager subdirectory, both ending in `.json`).
// They are still read once for migration but never written again.
func legacyAuthMirrorPaths(baseName string) []string {
	if strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_STATE_DIRS")) != "" {
		return nil
	}
	out := make([]string, 0, 8)
	for _, authDir := range existingAuthDirs() {
		out = append(out,
			filepath.Clean(filepath.Join(authDir, baseName)),
			filepath.Clean(filepath.Join(authDir, stateSubdirName, baseName)),
		)
	}
	return out
}

// RulesFileCandidates returns every path where the dynamic rules file may live,
// starting with the canonical primary path.
func RulesFileCandidates(primary string) []string {
	out := make([]string, 0, 12)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		for _, existing := range out {
			if existing == path {
				return
			}
		}
		out = append(out, path)
	}

	add(primary)
	baseName := "key_guard_rules.json"
	if strings.TrimSpace(primary) != "" {
		baseName = filepath.Base(filepath.Clean(primary))
	}
	for _, dir := range StateDirs() {
		add(filepath.Join(dir, mirrorNameInDir(dir, baseName)))
	}
	// Older releases wrote mirrors ending in `.json` into the auth directory.
	// They are still read so upgrades never lose the administrator's rules.
	for _, legacy := range legacyAuthMirrorPaths(baseName) {
		add(legacy)
	}
	return out
}

// isLegacyAuthMirror reports whether path is a stale mirror that lives inside the
// CLIProxyAPI auth directory and would be picked up as an OAuth credential file.
// Such files must never be written again and are removed after migration.
func isLegacyAuthMirror(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		return false
	}
	return isInsideAuthDir(filepath.Dir(path))
}

// readDynamicRulesFile reads and decodes a DynamicRulesState from an explicit path.
func readDynamicRulesFile(path string) (*DynamicRulesState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, io.EOF
	}
	var state DynamicRulesState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.Version == 0 {
		state.Version = 1
	}
	if state.CustomPrices == nil {
		state.CustomPrices = make(map[string]pricing.ModelPrice)
	}
	return &state, nil
}

// DynamicRulesFileReport describes one candidate rules-file location (used for live diagnostics).
func DynamicRulesFileReport(primary string) []map[string]any {
	reports := make([]map[string]any, 0, 8)
	for _, path := range RulesFileCandidates(primary) {
		entry := map[string]any{"path": path, "exists": false}
		info, errStat := os.Stat(path)
		if errStat != nil || info.IsDir() {
			reports = append(reports, entry)
			continue
		}
		entry["exists"] = true
		entry["size"] = info.Size()
		entry["mtime"] = info.ModTime().UTC().Format(time.RFC3339)
		if state, errRead := readDynamicRulesFile(path); errRead == nil && state != nil {
			entry["keys"] = len(state.Keys)
			entry["updated_at"] = state.UpdatedAt
			entry["has_default_policy"] = state.DefaultPolicy != nil
		} else if errRead != nil {
			entry["error"] = errRead.Error()
		}
		reports = append(reports, entry)
	}
	return reports
}

// LoadDynamicRulesFile loads the persisted DynamicRulesState from disk.
// It inspects every candidate location and adopts the most recently written
// non-empty state, so that an ephemeral `./data` directory (recreated by a
// container restart) can never wipe the administrator's configured rules.
func LoadDynamicRulesFile(filePath string) (*DynamicRulesState, error) {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		cleanPath = "key_guard_rules.json"
	}

	type candidateState struct {
		path  string
		state *DynamicRulesState
		score int
	}
	best := (*candidateState)(nil)
	var firstErr error

	for _, path := range RulesFileCandidates(cleanPath) {
		state, errRead := readDynamicRulesFile(path)
		if errRead != nil {
			if firstErr == nil && !os.IsNotExist(errRead) && !errors.Is(errRead, io.EOF) {
				firstErr = errRead
			}
			continue
		}
		score := len(state.Keys) * 1000
		if state.DefaultPolicy != nil {
			score++
		}
		cand := &candidateState{path: path, state: state, score: score}
		if best == nil {
			best = cand
			continue
		}
		if state.UpdatedAt != best.state.UpdatedAt {
			if state.UpdatedAt > best.state.UpdatedAt {
				best = cand
			}
			continue
		}
		if score > best.score {
			best = cand
		}
	}

	if best == nil {
		if firstErr != nil {
			return nil, firstErr
		}
		return &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}, nil
	}

	// Converge all candidate locations onto the winning state so that every
	// persistent location holds the same authoritative snapshot.
	_ = SaveDynamicRulesFile(cleanPath, best.state)
	return best.state, nil
}

// SaveDynamicRulesFile atomically writes DynamicRulesState to every candidate
// location (auth dir, config dir, CPA root data dir, ...). The primary path
// write is authoritative; mirror failures are tolerated.
func SaveDynamicRulesFile(filePath string, state *DynamicRulesState) error {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" || state == nil {
		return nil
	}
	state.Version = 1
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, errMarshal := json.MarshalIndent(state, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}

	var primaryErr error
	primaryClean := filepath.Clean(cleanPath)
	for _, path := range RulesFileCandidates(cleanPath) {
		if isLegacyAuthMirror(path) {
			// Legacy mirrors used a `.json` name inside the auth directory, which
			// CLIProxyAPI exposes as an undeletable credential. Write the new
			// mirror first, then drop the legacy file.
			if path == primaryClean {
				primaryErr = usage.WriteFileAtomically(path, raw)
				continue
			}
			_ = os.Remove(path)
			continue
		}
		errWrite := usage.WriteFileAtomically(path, raw)
		if path == primaryClean {
			primaryErr = errWrite
		}
	}
	return primaryErr
}

// UsageFileCandidates returns where a token-usage snapshot may live: the
// configured path first, then every durable mirror location.
func UsageFileCandidates(configured string) []string {
	out := make([]string, 0, 10)
	seen := make(map[string]struct{}, 10)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}

	add(configured)
	baseName := "key_usage_stats.json"
	if strings.TrimSpace(configured) != "" {
		baseName = filepath.Base(filepath.Clean(configured))
	}
	for _, dir := range StateDirs() {
		add(filepath.Join(dir, mirrorNameInDir(dir, baseName)))
	}
	for _, legacy := range legacyAuthMirrorPaths(baseName) {
		add(legacy)
	}
	return out
}

// UsageMirrorFiles returns the mirror paths that receive a copy of the usage
// snapshot after every flush (the configured file stays authoritative). Stale
// `.json` mirrors inside the auth directory are excluded because CLIProxyAPI
// would treat them as OAuth credential files.
func UsageMirrorFiles(configured string) []string {
	configuredClean := filepath.Clean(strings.TrimSpace(configured))
	out := make([]string, 0, 8)
	for _, path := range UsageFileCandidates(configured) {
		if path == configuredClean {
			continue
		}
		if isLegacyAuthMirror(path) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// LegacyUsageMirrorFiles returns read-only usage snapshot locations used by older
// releases. They are restored from and only removed after a successor snapshot has
// been written, so a migration can never destroy the only surviving copy.
func LegacyUsageMirrorFiles(configured string) []string {
	configuredClean := filepath.Clean(strings.TrimSpace(configured))
	out := make([]string, 0, 4)
	for _, path := range UsageFileCandidates(configured) {
		if path == configuredClean || !isLegacyAuthMirror(path) {
			continue
		}
		out = append(out, path)
	}
	return out
}

// UsageFileReport describes each usage-snapshot location for live diagnostics.
func UsageFileReport(configured string) []map[string]any {
	reports := make([]map[string]any, 0, 8)
	for _, path := range UsageFileCandidates(configured) {
		entry := map[string]any{"path": path, "exists": false}
		info, errStat := os.Stat(path)
		if errStat != nil || info.IsDir() {
			reports = append(reports, entry)
			continue
		}
		entry["exists"] = true
		entry["size"] = info.Size()
		entry["mtime"] = info.ModTime().UTC().Format(time.RFC3339)
		if raw, errRead := os.ReadFile(path); errRead == nil {
			var snap struct {
				UpdatedAt string                     `json:"updated_at"`
				Keys      map[string]json.RawMessage `json:"keys"`
			}
			if errUnmarshal := json.Unmarshal(raw, &snap); errUnmarshal == nil {
				entry["keys"] = len(snap.Keys)
				entry["updated_at"] = snap.UpdatedAt
			}
		}
		entry["legacy"] = isLegacyAuthMirror(path)
		reports = append(reports, entry)
	}
	return reports
}

// CleanupLegacyAuthMirrors removes the rules mirror files that older releases left
// inside CLIProxyAPI's auth directory as `*.json`. CLIProxyAPI lists them as
// credentials whose ID contains a path separator, so they cannot be deleted from
// the dashboard. Usage mirrors are cleaned by the usage store after a successful
// snapshot write (see Store.SetLegacyMirrorFiles).
func CleanupLegacyAuthMirrors() {
	for _, legacy := range legacyAuthMirrorPaths("key_guard_rules.json") {
		if info, errStat := os.Stat(legacy); errStat == nil && !info.IsDir() {
			_ = os.Remove(legacy)
		}
	}
}

// ReadHostConfigAPIKeys reads global client `api-keys` (or `access.api-keys`) from CLIProxyAPI's config.yaml on disk.
func ReadHostConfigAPIKeys(configPath string) []string {
	resolvedPath := FindHostConfigFile(configPath)
	raw, err := os.ReadFile(resolvedPath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var root struct {
		APIKeys []string `yaml:"api-keys"`
		Access  struct {
			APIKeys []string `yaml:"api-keys"`
		} `yaml:"access"`
	}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(root.APIKeys)+len(root.Access.APIKeys))
	for _, list := range [][]string{root.APIKeys, root.Access.APIKeys} {
		for _, item := range list {
			k := strings.TrimSpace(item)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				out = append(out, k)
			}
		}
	}
	return out
}

// WriteHostConfigAPIKeys updates the global `api-keys` list in CLIProxyAPI's config.yaml on disk
// while preserving all other YAML nodes and comments.
//
// Note: the plugin deliberately does NOT mirror its rule state (remarks, model
// whitelists, default policy) into config.yaml. CLIProxyAPI rewrites that file
// from its own in-memory copy on every management save, so such a snapshot is
// silently lost; the durable mirrors written by SaveDynamicRulesFile are the
// only supported persistence mechanism.
func WriteHostConfigAPIKeys(configPath string, keys []string) error {
	resolvedPath := FindHostConfigFile(configPath)
	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	rootMap := doc.Content[0]

	seqNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	seen := make(map[string]struct{}, len(keys))
	for _, rawKey := range keys {
		k := strings.TrimSpace(rawKey)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: k,
		})
	}

	updated := false
	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		kNode := rootMap.Content[i]
		vNode := rootMap.Content[i+1]
		if kNode.Value == "api-keys" && (vNode.Kind == yaml.SequenceNode || vNode.Tag == "!!null") {
			rootMap.Content[i+1] = seqNode
			updated = true
			break
		}
		if kNode.Value == "access" && vNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(vNode.Content); j += 2 {
				if vNode.Content[j].Value == "api-keys" {
					vNode.Content[j+1] = seqNode
					updated = true
					break
				}
			}
		}
	}
	if !updated {
		rootMap.Content = append(rootMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "api-keys"},
			seqNode,
		)
	}

	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		_ = enc.Close()
		return err
	}
	_ = enc.Close()
	return usage.WriteFileAtomically(resolvedPath, []byte(buf.String()))
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
		if v == "sk-tenant-alpha-prod" || v == "sk-tenant-beta-dev" {
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
