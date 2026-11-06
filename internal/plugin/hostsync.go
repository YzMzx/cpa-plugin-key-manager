package plugin

import (
	"sort"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// authListCacheTTL bounds how stale the credential list in the overview may be.
const authListCacheTTL = 5 * time.Second

// cachedHostAuthFiles returns the host credential list, reusing a recent result.
func (m *Manager) cachedHostAuthFiles(hostCallbackID string) []pluginapi.HostAuthFileEntry {
	m.authListMu.Lock()
	if m.authListCache != nil && time.Since(m.authListFetched) < authListCacheTTL {
		cached := append([]pluginapi.HostAuthFileEntry(nil), m.authListCache...)
		m.authListMu.Unlock()
		return cached
	}
	m.authListMu.Unlock()

	files, err := m.ListHostAuthFiles(hostCallbackID)
	if err != nil && len(files) == 0 {
		m.authListMu.Lock()
		stale := append([]pluginapi.HostAuthFileEntry(nil), m.authListCache...)
		m.authListMu.Unlock()
		return stale
	}
	m.authListMu.Lock()
	m.authListCache = append([]pluginapi.HostAuthFileEntry(nil), files...)
	m.authListFetched = time.Now()
	m.authListMu.Unlock()
	return files
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
	prevKeys := configuredKeyList(m.cfg.Keys)
	prevDeleted := len(m.dynamicState.DeletedKeys)
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

	// The admin page calls this on every load and refresh. When neither the
	// merged key set nor the tombstones changed there is nothing to persist, so
	// skip both the rules upsert and the config.yaml rewrite.
	if keysEqual(prevKeys, configuredKeyList(m.cfg.Keys)) && prevDeleted == len(m.dynamicState.DeletedKeys) {
		m.mu.Unlock()
		return nil
	}
	errSave := m.persistRules()
	if errSave != nil {
		m.host.Log("error", "failed to save dynamic rules file on sync host keys", map[string]any{
			"file":  m.rulesLocation(),
			"error": errSave.Error(),
		})
	}
	allKeys := make([]string, 0, len(m.cfg.Keys))
	for _, k := range m.cfg.Keys {
		allKeys = append(allKeys, k.APIKey)
	}
	m.mu.Unlock()

	if errHost := WriteHostConfigAPIKeys("", allKeys); errHost != nil {
		m.host.Log("warn", "failed to sync host config api-keys", map[string]any{
			"error": errHost.Error(),
		})
	}
	return errSave
}
