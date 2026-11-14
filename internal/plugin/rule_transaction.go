package plugin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// cloneRulesState makes the mutation candidate independent from live readers.
func cloneRulesState(state *DynamicRulesState) (*DynamicRulesState, error) {
	if state == nil {
		state = &DynamicRulesState{Version: 1}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var next DynamicRulesState
	if err := json.Unmarshal(raw, &next); err != nil {
		return nil, err
	}
	normalizeRulesState(&next)
	return &next, nil
}

func removeKeyFromState(state *DynamicRulesState, key string) {
	next := make([]KeyRuleConfig, 0, len(state.Keys))
	for _, rule := range state.Keys {
		if rule.APIKey != key {
			next = append(next, rule)
		}
	}
	state.Keys = next
	state.KeyOrder = removeString(state.KeyOrder, key, false)
}

// mutateRules prepares a copy, commits it durably, then publishes it. The slow
// database write never holds the runtime read lock. Host synchronization is an
// explicit, retryable side effect; a committed rule is never silently rolled back.
func (m *Manager) mutateRules(opts ruleMutation, fn func(*DynamicRulesState) error) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	m.mu.RLock()
	next, err := cloneRulesState(m.dynamicState)
	previousSettings := m.dynamicState
	seed, repo := m.seedCfg, m.rulesRepo
	hostKeys := append([]string(nil), m.hostAPIKeys...)
	m.mu.RUnlock()
	if err != nil {
		return err
	}
	if repo == nil {
		return fmt.Errorf("rules database is not configured")
	}
	// Callbacks may consult the immutable current config, but mutate only next.
	if err := fn(next); err != nil {
		return err
	}
	next.Revision++
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	nextCfg := MergeDynamicState(seed, next, hostKeys...)
	if err := validateConfig(nextCfg); err != nil {
		return err
	}
	if opts.syncHostKeys {
		next.HostSyncPending = true
	}
	settingsChanged := previousSettings == nil && next.Settings != nil || previousSettings != nil && !reflect.DeepEqual(previousSettings.Settings, next.Settings)
	if settingsChanged {
		if next.Settings != nil {
			validated := *next.Settings
			if err := validateRuntimeSettings(&validated); err != nil {
				return err
			}
		}
		if err := m.usageStore.FlushNow(); err != nil {
			return ErrSettingsPersistence
		}
	}
	next.ConfigFingerprint = configFingerprint(nextCfg)
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := repo.Save(raw); err != nil {
		return fmt.Errorf("persist rules: %w", err)
	}
	m.mu.Lock()
	m.dynamicState, m.cfg = next, nextCfg
	m.hostAPIKeys = configuredKeyList(nextCfg.Keys)
	m.mu.Unlock()
	if settingsChanged {
		if err := m.applyRuntimeSettings(nextCfg); err != nil {
			return err
		}
	}
	if opts.refreshPricing {
		if err := m.pricingEngine.SetCustomPrices(nextCfg.Pricing.CustomPrices, nextCfg.Pricing.DefaultPrice); err != nil {
			return err
		}
	}
	if opts.syncHostKeys {
		m.mu.Lock()
		m.hostSyncError, m.hostSyncCode = "宿主同步等待重试", "pending"
		m.mu.Unlock()
	}
	return nil
}

// RulesRevision is a stable optimistic-concurrency token, persisted with rules.
func (m *Manager) RulesRevision() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dynamicState == nil {
		return 0
	}
	return m.dynamicState.Revision
}
