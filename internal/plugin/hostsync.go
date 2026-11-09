package plugin

import (
	"sort"
	"strings"
	"time"

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
