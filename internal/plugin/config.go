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
	return Config{
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

	if c.Storage.FlushIntervalSeconds <= 0 {
		c.Storage.FlushIntervalSeconds = 10
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
// directory. Keeping mirrors in a subdirectory prevents CLIProxyAPI from listing
// them as (broken) OAuth credential files.
const stateSubdirName = "key-manager"

// legacyAuthMirrorPaths returns the pre-0.5.8 mirror locations directly inside the
// auth directory. They are still read once for migration but never written again.
func legacyAuthMirrorPaths(baseName string) []string {
	if strings.TrimSpace(os.Getenv("CPA_KEY_MANAGER_STATE_DIRS")) != "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, authDir := range existingAuthDirs() {
		out = append(out, filepath.Clean(filepath.Join(authDir, baseName)))
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
		add(filepath.Join(dir, baseName))
	}
	// Pre-0.5.8 mirrors written directly into the auth directory are still read
	// so that upgrades never lose the administrator's rules.
	for _, legacy := range legacyAuthMirrorPaths(baseName) {
		add(legacy)
	}
	return out
}

// isLegacyAuthMirror reports whether path is a mirror written directly inside the
// CLIProxyAPI auth directory (pre-0.5.8 layout). Such files must never be written
// again because CLIProxyAPI would list them as credential files.
func isLegacyAuthMirror(path string) bool {
	parent := filepath.Clean(filepath.Dir(path))
	for _, authDir := range existingAuthDirs() {
		if parent == filepath.Clean(authDir) {
			return true
		}
	}
	return false
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
			// migrate away from the pre-0.5.8 layout so CLIProxyAPI stops
			// listing the mirror as a credential file
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
		add(filepath.Join(dir, baseName))
	}
	for _, legacy := range legacyAuthMirrorPaths(baseName) {
		add(legacy)
	}
	return out
}

// UsageMirrorFiles returns the mirror paths that receive a copy of the usage
// snapshot after every flush (the configured file stays authoritative).
func UsageMirrorFiles(configured string) []string {
	configuredClean := filepath.Clean(strings.TrimSpace(configured))
	out := make([]string, 0, 8)
	for _, path := range UsageFileCandidates(configured) {
		if path == configuredClean {
			continue
		}
		out = append(out, path)
	}
	return out
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

// ReadHostConfigPluginRules reads the plugin rule snapshot that is mirrored into
// CLIProxyAPI's config.yaml under `plugins.configs.<plugin id>`. It returns the
// decoded DynamicRulesState when present, so that a wiped `data/` directory can
// always be rebuilt from the host's persistent config file.
func ReadHostConfigPluginRules(configPath string) *DynamicRulesState {
	resolvedPath := FindHostConfigFile(configPath)
	raw, err := os.ReadFile(resolvedPath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var root struct {
		Plugins struct {
			Configs map[string]yaml.Node `yaml:"configs"`
		} `yaml:"plugins"`
	}
	if errUnmarshal := yaml.Unmarshal(raw, &root); errUnmarshal != nil {
		return nil
	}
	node, ok := root.Plugins.Configs[PluginID]
	if !ok {
		return nil
	}
	var snapshot struct {
		DefaultPolicy *DefaultPolicyConfig `yaml:"default_policy"`
		Keys          []KeyRuleConfig      `yaml:"keys"`
	}
	if errDecode := node.Decode(&snapshot); errDecode != nil {
		return nil
	}
	if snapshot.DefaultPolicy == nil && len(snapshot.Keys) == 0 {
		return nil
	}
	state := &DynamicRulesState{
		Version:       1,
		DefaultPolicy: snapshot.DefaultPolicy,
		Keys:          snapshot.Keys,
		CustomPrices:  make(map[string]pricing.ModelPrice),
	}
	return state
}

// ReadHostConfigPluginKeys returns just the API keys of the plugin rule snapshot
// mirrored inside CLIProxyAPI's config.yaml (used for live diagnostics).
func ReadHostConfigPluginKeys() []string {
	state := ReadHostConfigPluginRules("")
	if state == nil {
		return nil
	}
	out := make([]string, 0, len(state.Keys))
	for _, rule := range state.Keys {
		if key := strings.TrimSpace(rule.APIKey); key != "" {
			out = append(out, key)
		}
	}
	return out
}

func valueToYAMLNode(v any) (*yaml.Node, error) {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, errors.New("empty yaml node")
	}
	return doc.Content[0], nil
}

// WriteHostConfigAPIKeys updates the global `api-keys` list in CLIProxyAPI's config.yaml on disk
// while preserving all other YAML nodes and comments.
func WriteHostConfigAPIKeys(configPath string, keys []string) error {
	return WriteHostConfigState(configPath, keys, nil)
}

// WriteHostConfigState synchronizes global `api-keys`, `default_policy`, and `keys` into CLIProxyAPI's config.yaml.
// This guarantees that even if `key_guard_rules.json` is missing or cleared across container restarts,
// CLIProxyAPI and the plugin will ALWAYS restore the exact remarks, model whitelists, and default policies on startup.
func WriteHostConfigState(configPath string, keys []string, state *DynamicRulesState) error {
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

	// 1. Update api-keys list
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

	// 2. Synchronize plugins.configs.cpa-plugin-key-manager
	if state != nil {
		var pluginsMap *yaml.Node
		for i := 0; i+1 < len(rootMap.Content); i += 2 {
			if rootMap.Content[i].Value == "plugins" && rootMap.Content[i+1].Kind == yaml.MappingNode {
				pluginsMap = rootMap.Content[i+1]
				break
			}
		}
		if pluginsMap == nil {
			pluginsMap = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			rootMap.Content = append(rootMap.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "plugins"},
				pluginsMap,
			)
		}

		var configsMap *yaml.Node
		for i := 0; i+1 < len(pluginsMap.Content); i += 2 {
			if pluginsMap.Content[i].Value == "configs" && pluginsMap.Content[i+1].Kind == yaml.MappingNode {
				configsMap = pluginsMap.Content[i+1]
				break
			}
		}
		if configsMap == nil {
			configsMap = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			pluginsMap.Content = append(pluginsMap.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "configs"},
				configsMap,
			)
		}

		var pluginConfigMap *yaml.Node
		for i := 0; i+1 < len(configsMap.Content); i += 2 {
			if configsMap.Content[i].Value == PluginID && configsMap.Content[i+1].Kind == yaml.MappingNode {
				pluginConfigMap = configsMap.Content[i+1]
				break
			}
		}
		if pluginConfigMap == nil {
			pluginConfigMap = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			configsMap.Content = append(configsMap.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: PluginID},
				pluginConfigMap,
			)
		}

		// Ensure enabled: true
		hasEnabled := false
		for i := 0; i+1 < len(pluginConfigMap.Content); i += 2 {
			if pluginConfigMap.Content[i].Value == "enabled" {
				hasEnabled = true
				break
			}
		}
		if !hasEnabled {
			pluginConfigMap.Content = append(pluginConfigMap.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
			)
		}

		// Update default_policy
		if state.DefaultPolicy != nil {
			if dpVal, errDP := valueToYAMLNode(state.DefaultPolicy); errDP == nil && dpVal != nil {
				updatedDP := false
				for i := 0; i+1 < len(pluginConfigMap.Content); i += 2 {
					if pluginConfigMap.Content[i].Value == "default_policy" {
						pluginConfigMap.Content[i+1] = dpVal
						updatedDP = true
						break
					}
				}
				if !updatedDP {
					pluginConfigMap.Content = append(pluginConfigMap.Content,
						&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "default_policy"},
						dpVal,
					)
				}
			}
		}

		// Update keys
		if len(state.Keys) > 0 {
			if keysVal, errKeys := valueToYAMLNode(state.Keys); errKeys == nil && keysVal != nil {
				updatedKeyList := false
				for i := 0; i+1 < len(pluginConfigMap.Content); i += 2 {
					if pluginConfigMap.Content[i].Value == "keys" {
						pluginConfigMap.Content[i+1] = keysVal
						updatedKeyList = true
						break
					}
				}
				if !updatedKeyList {
					pluginConfigMap.Content = append(pluginConfigMap.Content,
						&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "keys"},
						keysVal,
					)
				}
			}
		}
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
