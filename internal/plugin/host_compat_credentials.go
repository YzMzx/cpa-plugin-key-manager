package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type hostCompatPool struct {
	Enabled             *bool  `yaml:"enabled"`
	IdleConnTimeout     string `yaml:"idle-conn-timeout"`
	MaxIdleConnsPerHost *int   `yaml:"max-idle-conns-per-host"`
}
type hostCompatKey struct {
	APIKey         string          `yaml:"api-key"`
	ProxyURL       string          `yaml:"proxy-url"`
	Weight         *int            `yaml:"weight"`
	ConnectionPool *hostCompatPool `yaml:"connection-pool"`
}
type hostCompatProvider struct {
	Name           string          `yaml:"name"`
	Disabled       bool            `yaml:"disabled"`
	BaseURL        string          `yaml:"base-url"`
	APIKeyEntries  []hostCompatKey `yaml:"api-key-entries"`
	ConnectionPool *hostCompatPool `yaml:"connection-pool"`
}

// There is no host.config RPC and HostConfigSummary has no API-key providers.
// Read only the relevant fields from disk, supporting the same legacy/v8
// precedence as the host. Never return YAML errors that may quote secrets.
func readEnabledHostCompatCredentials() (map[string]string, error) {
	raw, err := os.ReadFile(hostCompatConfigFile())
	if err != nil {
		return nil, errors.New("current host credential configuration is unavailable")
	}
	providers, err := parseHostCompatProviders(raw)
	if err != nil {
		return nil, errors.New("current host credential configuration is invalid")
	}
	return enabledHostCompatCredentials(providers), nil
}

// An explicitly selected host file is authoritative even when missing. The
// general discovery helper skips missing CLI paths, which is unsafe here: a
// different config.yaml must never authorize a removed credential.
func hostCompatConfigFile() string {
	for i, arg := range os.Args[1:] {
		if arg == "-config" || arg == "--config" {
			if i+2 < len(os.Args) {
				return strings.TrimSpace(os.Args[i+2])
			}
			return ""
		}
		if strings.HasPrefix(arg, "-config=") {
			return strings.TrimSpace(strings.TrimPrefix(arg, "-config="))
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
		}
	}
	if path := strings.TrimSpace(os.Getenv("CPA_CONFIG_FILE")); path != "" {
		return path
	}
	if dir := strings.TrimSpace(os.Getenv("CPA_DIR")); dir != "" {
		return filepath.Join(dir, "config.yaml")
	}
	return FindHostConfigFile("")
}

func parseHostCompatProviders(raw []byte) ([]hostCompatProvider, error) {
	var root map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, errors.New("host config must be a mapping")
	}
	// Also reject duplicate fields inside subtrees, including overridden ones.
	var shape map[string]any
	if err := yaml.Unmarshal(raw, &shape); err != nil {
		return nil, err
	}
	if version, ok := root["config-version"]; ok && (version.Tag != "!!int" || version.Value != "8") {
		return nil, errors.New("unsupported config version")
	}
	var groups *yaml.Node
	if keys, ok := root["api-keys"]; ok && keys.Kind == yaml.MappingNode {
		var families map[string]yaml.Node
		if err := keys.Decode(&families); err != nil {
			return nil, err
		}
		if current, ok := families["openai-compatibility"]; ok {
			groups = &current
		}
	}
	if groups != nil {
		if groups.Kind != yaml.SequenceNode {
			return nil, errors.New("compat groups must be a sequence")
		}
		providers := make([]hostCompatProvider, 0, len(groups.Content))
		for _, node := range groups.Content {
			var fields map[string]yaml.Node
			if err := node.Decode(&fields); err != nil {
				return nil, err
			}
			keys, ok := fields["keys"]
			if !ok || keys.Kind != yaml.SequenceNode {
				return nil, errors.New("compat keys must be a sequence")
			}
			var provider hostCompatProvider
			if err := node.Decode(&provider); err != nil {
				return nil, err
			}
			if err := keys.Decode(&provider.APIKeyEntries); err != nil {
				return nil, err
			}
			providers = append(providers, provider)
		}
		return providers, nil
	}
	var providers []hostCompatProvider
	if legacy, ok := root["openai-compatibility"]; ok {
		if err := legacy.Decode(&providers); err != nil {
			return nil, err
		}
	}
	return providers, nil
}

// The host synthesizer's StableIDGenerator is internal, not an SDK API. Match
// its exact identity (key/base/proxy/effective pool and duplicate counters), not
// just a provider name; an old key must not borrow a current provider's status.
func enabledHostCompatCredentials(providers []hostCompatProvider) map[string]string {
	out := make(map[string]string)
	counters := make(map[string]int)
	next := func(kind string, parts ...string) string {
		h := sha256.New()
		_, _ = h.Write([]byte(kind))
		for _, part := range parts {
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(strings.TrimSpace(part)))
		}
		id := kind + ":" + hex.EncodeToString(h.Sum(nil))[:12]
		n := counters[id]
		counters[id] = n + 1
		if n > 0 {
			return fmt.Sprintf("%s-%d", id, n)
		}
		return id
	}
	for _, provider := range providers {
		if provider.Disabled || strings.TrimSpace(provider.BaseURL) == "" {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(provider.Name))
		if name == "" {
			name = "openai-compatibility"
		}
		kind := "openai-compatibility:" + name
		providerKey := name
		if name != "openai-compatibility" && !strings.HasPrefix(name, "openai-compatible-") {
			providerKey = "openai-compatible-" + name
		}
		add := func(entry *hostCompatKey) {
			parts := []string{strings.TrimSpace(provider.BaseURL)}
			pool := provider.ConnectionPool
			if entry != nil {
				parts = []string{strings.TrimSpace(entry.APIKey), strings.TrimSpace(provider.BaseURL), strings.TrimSpace(entry.ProxyURL)}
				if entry.ConnectionPool != nil {
					merged := *entry.ConnectionPool
					if pool != nil {
						if merged.Enabled == nil {
							merged.Enabled = pool.Enabled
						}
						if strings.TrimSpace(merged.IdleConnTimeout) == "" {
							merged.IdleConnTimeout = pool.IdleConnTimeout
						}
						if merged.MaxIdleConnsPerHost == nil {
							merged.MaxIdleConnsPerHost = pool.MaxIdleConnsPerHost
						}
					}
					pool = &merged
				}
			}
			if pool != nil {
				enabled, maxIdle := "", ""
				if pool.Enabled != nil {
					enabled = strconv.FormatBool(*pool.Enabled)
				}
				if pool.MaxIdleConnsPerHost != nil {
					maxIdle = strconv.Itoa(*pool.MaxIdleConnsPerHost)
				}
				parts = append(parts, strings.Join([]string{"pool:" + enabled, strings.TrimSpace(pool.IdleConnTimeout), maxIdle}, string(rune(0))))
			}
			id := next(kind, parts...)
			// Weight zero excludes routing, but still consumes the host ID counter.
			if entry == nil || entry.Weight == nil || *entry.Weight > 0 {
				out[id] = providerKey
			}
		}
		if len(provider.APIKeyEntries) == 0 {
			add(nil)
		} else {
			for i := range provider.APIKeyEntries {
				add(&provider.APIKeyEntries[i])
			}
		}
	}
	return out
}
