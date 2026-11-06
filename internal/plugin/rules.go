package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

// errRuleNotFound aborts a mutation without persisting anything.
var errRuleNotFound = errors.New("api key not found")

// ruleMutation describes the side effects one rule change needs besides
// persisting the dynamic state.
type ruleMutation struct {
	// op names the change in error logs.
	op string
	// syncHostKeys rewrites CPA's config.yaml api-keys list after the change.
	syncHostKeys bool
	// refreshPricing pushes the merged price overrides into the pricing engine.
	refreshPricing bool
}

// mutateRules is the single write path for the dynamic rules: it locks the
// manager, applies fn to the dynamic state, re-merges the effective config,
// persists the state to SQLite and optionally refreshes pricing / the host
// api-keys list. Returning an error from fn aborts without persisting.
func (m *Manager) mutateRules(opts ruleMutation, fn func(state *DynamicRulesState) error) error {
	m.mu.Lock()
	if m.dynamicState == nil {
		m.dynamicState = &DynamicRulesState{Version: 1, CustomPrices: make(map[string]pricing.ModelPrice)}
	}
	if m.dynamicState.CustomPrices == nil {
		m.dynamicState.CustomPrices = make(map[string]pricing.ModelPrice)
	}
	if err := fn(m.dynamicState); err != nil {
		m.mu.Unlock()
		return err
	}
	m.cfg = MergeDynamicState(m.seedCfg, m.dynamicState, m.hostAPIKeys...)
	if opts.refreshPricing {
		m.pricingEngine.SetCustomPrices(m.cfg.Pricing.CustomPrices, m.cfg.Pricing.DefaultPrice)
	}
	errSave := m.persistRules()
	if errSave != nil {
		m.host.Log("error", "failed to persist rules on "+opts.op, map[string]any{
			"file":  m.rulesLocation(),
			"error": errSave.Error(),
		})
	}
	var hostKeys []string
	if opts.syncHostKeys {
		hostKeys = configuredKeyList(m.cfg.Keys)
	}
	m.mu.Unlock()

	if opts.syncHostKeys {
		if errHost := WriteHostConfigAPIKeys("", hostKeys); errHost != nil {
			m.host.Log("warn", "failed to write host config api-keys on "+opts.op, map[string]any{
				"error": errHost.Error(),
			})
		}
	}
	return errSave
}

// removeString returns list without any element equal to target (after trimming).
func removeString(list []string, target string, fold bool) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		v := strings.TrimSpace(item)
		if (fold && strings.EqualFold(v, target)) || (!fold && v == target) {
			continue
		}
		out = append(out, item)
	}
	return out
}

// appendUnique appends value unless list already contains it.
func appendUnique(list []string, value string, fold bool) []string {
	for _, item := range list {
		v := strings.TrimSpace(item)
		if (fold && strings.EqualFold(v, value)) || (!fold && v == value) {
			return list
		}
	}
	return append(list, value)
}

// ListKeyRulesAndDefaultPolicy returns all configured API key rules and default_policy.
func (m *Manager) ListKeyRulesAndDefaultPolicy() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keysCopy := make([]KeyRuleConfig, len(m.cfg.Keys))
	for i, k := range m.cfg.Keys {
		keysCopy[i] = cloneKeyRule(k)
	}
	return map[string]any{
		"keys":           keysCopy,
		"default_policy": m.cfg.DefaultPolicy,
		"rules_file":     m.cfg.Storage.RulesFile,
	}
}

// ResetKeyQuota writes off the quota already consumed by one API key by moving its
// baseline to the current accumulated cost. Billing history is left untouched.
func (m *Manager) ResetKeyQuota(apiKey string) (float64, error) {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return 0, fmt.Errorf("api_key is required")
	}
	used := m.usageStore.GetKeyCostUSD(key)
	err := m.mutateRules(ruleMutation{op: "quota reset"}, func(state *DynamicRulesState) error {
		for i := range state.Keys {
			if state.Keys[i].APIKey == key {
				state.Keys[i].QuotaUsedBaseUSD = used
				state.Keys[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				return nil
			}
		}
		return errRuleNotFound
	})
	if err != nil {
		return 0, err
	}
	return used, nil
}

// GetKeyQuota reports the configured limit and the usage counted since the last reset.
func (m *Manager) GetKeyQuota(apiKey string) (limitUSD, usedUSD, remainingUSD float64, unlimited bool) {
	m.mu.RLock()
	rule, _ := m.cfg.ResolveKeyRule(apiKey)
	m.mu.RUnlock()

	limitUSD = rule.QuotaLimitUSD
	usedUSD = m.usageStore.GetKeyCostUSD(strings.TrimSpace(apiKey)) - rule.QuotaUsedBaseUSD
	if usedUSD < 0 {
		usedUSD = 0
	}
	if limitUSD <= 0 {
		return 0, usedUSD, 0, true
	}
	remainingUSD = limitUSD - usedUSD
	if remainingUSD < 0 {
		remainingUSD = 0
	}
	return limitUSD, usedUSD, remainingUSD, false
}

// UpsertKeyRuleFromJSON creates or updates a KeyRuleConfig, hot-reloads the rules
// and persists them.
func (m *Manager) UpsertKeyRuleFromJSON(rawBody []byte) (any, error) {
	var rule KeyRuleConfig
	if err := json.Unmarshal(rawBody, &rule); err != nil {
		return nil, fmt.Errorf("invalid key rule JSON: %w", err)
	}
	rule.APIKey = strings.TrimSpace(rule.APIKey)
	if rule.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if rule.MaxConcurrency < 0 {
		rule.MaxConcurrency = 0
	}
	if rule.QuotaLimitUSD < 0 {
		rule.QuotaLimitUSD = 0
	}
	if rule.Enabled == nil {
		v := true
		rule.Enabled = &v
	}
	if len(rule.AllowedModels) == 0 {
		rule.AllowedModels = []string{"*"}
	}
	nowStr := time.Now().UTC().Format(time.RFC3339)
	rule.UpdatedAt = nowStr

	err := m.mutateRules(ruleMutation{op: "upsert", syncHostKeys: true}, func(state *DynamicRulesState) error {
		state.DeletedKeys = removeString(state.DeletedKeys, rule.APIKey, false)

		replaced := false
		for i := range state.Keys {
			if state.Keys[i].APIKey != rule.APIKey {
				continue
			}
			if rule.CreatedAt == "" {
				rule.CreatedAt = state.Keys[i].CreatedAt
			}
			// The quota baseline is owned by "重置额度" only, so editing a rule never
			// silently restores spent quota.
			rule.QuotaUsedBaseUSD = state.Keys[i].QuotaUsedBaseUSD
			state.Keys[i] = cloneKeyRule(rule)
			replaced = true
			break
		}
		if !replaced {
			if rule.CreatedAt == "" {
				rule.CreatedAt = nowStr
			}
			state.Keys = append(state.Keys, cloneKeyRule(rule))
		}
		m.hostAPIKeys = appendUnique(m.hostAPIKeys, rule.APIKey, false)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to persist rules to %s: %w", m.rulesLocation(), err)
	}
	return rule, nil
}

// DeleteKeyRule removes a KeyRuleConfig, hot-reloads the rules and persists them.
func (m *Manager) DeleteKeyRule(apiKey string) error {
	target := strings.TrimSpace(apiKey)
	if target == "" {
		return fmt.Errorf("api_key is required")
	}
	return m.mutateRules(ruleMutation{op: "delete", syncHostKeys: true}, func(state *DynamicRulesState) error {
		nextKeys := make([]KeyRuleConfig, 0, len(state.Keys))
		for _, kr := range state.Keys {
			if kr.APIKey != target {
				nextKeys = append(nextKeys, kr)
			}
		}
		state.Keys = nextKeys
		m.hostAPIKeys = removeString(m.hostAPIKeys, target, false)
		// Keep the drag & drop display order in sync with the surviving keys.
		if len(state.KeyOrder) > 0 {
			state.KeyOrder = removeString(state.KeyOrder, target, false)
		}
		state.DeletedKeys = appendUnique(state.DeletedKeys, target, false)
		return nil
	})
}

// ReorderKeys persists the administrator-defined display order of API keys
// (drag & drop in the Web UI) and hot-reloads the in-memory rule list.
func (m *Manager) ReorderKeys(keys []string) error {
	cleaned := dedupeKeys(keys)
	if len(cleaned) == 0 {
		return fmt.Errorf("keys list is required")
	}
	return m.mutateRules(ruleMutation{op: "reorder"}, func(state *DynamicRulesState) error {
		state.KeyOrder = cleaned
		return nil
	})
}

// SaveDefaultPolicyFromJSON updates the global DefaultPolicy, hot-reloads the rules
// and persists them.
func (m *Manager) SaveDefaultPolicyFromJSON(rawBody []byte) (any, error) {
	var dp DefaultPolicyConfig
	if err := json.Unmarshal(rawBody, &dp); err != nil {
		return nil, fmt.Errorf("invalid default_policy JSON: %w", err)
	}
	if dp.AllowUnlistedKeys == nil {
		v := true
		dp.AllowUnlistedKeys = &v
	}
	if dp.MaxConcurrency < 0 {
		dp.MaxConcurrency = 0
	}
	if dp.QuotaLimitUSD < 0 {
		dp.QuotaLimitUSD = 0
	}
	if len(dp.AllowedModels) == 0 {
		dp.AllowedModels = []string{"*"}
	}
	err := m.mutateRules(ruleMutation{op: "default policy"}, func(state *DynamicRulesState) error {
		dpCopy := dp
		state.DefaultPolicy = &dpCopy
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dp, nil
}

// UpsertCustomPrice adds or updates a custom model price override and hot-reloads
// the pricing engine.
func (m *Manager) UpsertCustomPrice(model string, price pricing.ModelPrice) error {
	norm := strings.ToLower(strings.TrimSpace(model))
	if norm == "" {
		return fmt.Errorf("model is required")
	}
	return m.mutateRules(ruleMutation{op: "price upsert", refreshPricing: true}, func(state *DynamicRulesState) error {
		if norm == "__default__" {
			cp := price
			state.DefaultPrice = &cp
			return nil
		}
		state.CustomPrices[norm] = price
		state.DeletedPrices = removeString(state.DeletedPrices, norm, true)
		return nil
	})
}

// DeleteCustomPrice removes a custom model price override and hot-reloads the
// pricing engine.
func (m *Manager) DeleteCustomPrice(model string) error {
	norm := strings.ToLower(strings.TrimSpace(model))
	if norm == "" {
		return fmt.Errorf("model is required")
	}
	return m.mutateRules(ruleMutation{op: "price delete", refreshPricing: true}, func(state *DynamicRulesState) error {
		if norm == "__default__" {
			state.DefaultPrice = nil
			return nil
		}
		delete(state.CustomPrices, norm)
		state.DeletedPrices = appendUnique(state.DeletedPrices, norm, true)
		return nil
	})
}
