package plugin

import (
	"errors"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// ListHostAuthFiles lists current credentials, never historical scheduling candidates.
// host.auth.models carries identity/catalog data, not enabled state. Only config-
// backed compatibility identities independently verified against current host YAML
// may supplement host.auth.list (which omits pathless config credentials).
func (m *Manager) ListHostAuthFiles(hostCallbackID string) ([]pluginapi.HostAuthFileEntry, error) {
	hostFiles, err := m.host.ListAuthFiles(hostCallbackID)
	if err != nil {
		return []pluginapi.HostAuthFileEntry{}, errors.New("current host credential list is unavailable")
	}
	authModels, modelsErr := m.host.ListAuthModels(hostCallbackID)
	if modelsErr != nil {
		modelsErr = errors.New("current host credential catalog is unavailable")
	}
	var configErr error
	var compat map[string]string
	configRead := false
	verifyCompat := func(id, provider string) bool {
		if !configRead {
			compat, configErr = readEnabledHostCompatCredentials()
			configRead = true
		}
		expected, ok := compat[id]
		return ok && (strings.TrimSpace(provider) == "" || strings.EqualFold(expected, strings.TrimSpace(provider)))
	}
	byKey := make(map[string]pluginapi.HostAuthFileEntry)
	for _, f := range hostFiles {
		k := strings.TrimSpace(f.ID)
		if k == "" {
			k = strings.TrimSpace(f.Name)
		}
		if k == "" {
			k = strings.TrimSpace(f.AuthIndex)
		}
		if k == "" {
			continue
		}
		if isHostCompatCredential(k, f.Provider) && !verifyCompat(k, f.Provider) {
			continue
		}
		byKey[k] = f
	}
	for _, am := range authModels {
		k := strings.TrimSpace(am.ID)
		if k == "" {
			continue
		}
		if existing, ok := byKey[k]; ok {
			if existing.Provider == "" {
				existing.Provider = am.Provider
			}
			if existing.AuthIndex == "" {
				existing.AuthIndex = am.AuthIndex
			}
			byKey[k] = existing
		} else if isHostCompatCredential(k, am.Provider) && verifyCompat(k, am.Provider) {
			// This is configured/enabled, not a claim about model health or cooldown.
			byKey[k] = pluginapi.HostAuthFileEntry{ID: am.ID, AuthIndex: am.AuthIndex, Name: am.ID, Provider: compat[k], Status: "active"}
		}
	}
	out := make([]pluginapi.HostAuthFileEntry, 0, len(byKey))
	for _, f := range byKey {
		if strings.TrimSpace(f.Name) == "" {
			f.Name = f.ID
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, errors.Join(modelsErr, configErr)
}

func isHostCompatCredential(id, provider string) bool {
	return strings.HasPrefix(strings.ToLower(id), "openai-compatibility:") || strings.HasPrefix(strings.ToLower(provider), "openai-compatible-") || strings.EqualFold(provider, "openai-compatibility")
}

// SyncHostAPIKeys explicitly imports new native keys without reviving tombstones.
func (m *Manager) SyncHostAPIKeys(keys []string) error {
	cleaned := dedupeKeys(keys)
	return m.mutateRules(ruleMutation{op: "host key import", syncHostKeys: true}, func(state *DynamicRulesState) error {
		for _, key := range cleaned {
			deleted := false
			for _, tombstone := range state.DeletedKeys {
				if key == tombstone {
					deleted = true
					break
				}
			}
			if deleted {
				continue
			}
			exists := false
			for _, rule := range state.Keys {
				if key == rule.APIKey {
					exists = true
					break
				}
			}
			if !exists {
				rule, _ := m.cfg.ResolveKeyRule(key)
				rule.APIKey = key
				state.Keys = append(state.Keys, cloneKeyRule(rule))
			}
		}
		return nil
	})
}
