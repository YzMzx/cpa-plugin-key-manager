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
	}
}

// ResetKeyQuota writes off the quota already consumed by one API key by moving its
// baseline to the current accumulated cost. Billing history is left untouched.
func (m *Manager) ResetKeyQuota(apiKey string) (float64, error) {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return 0, fmt.Errorf("api_key is required")
	}
	m.mu.RLock()
	resetRule, _ := m.cfg.ResolveKeyRule(key)
	m.mu.RUnlock()
	used := m.quotaCostUSD(resetRule)
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
	usedUSD = m.quotaCostUSD(rule) - rule.QuotaUsedBaseUSD
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
	rule.QuotaUsedUSD = nil
	rule.APIKey = strings.TrimSpace(rule.APIKey)
	if rule.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if rule.MaxConcurrency < 0 {
		rule.MaxConcurrency = 0
	}
	if err := validateQuota(rule.QuotaLimitUSD); err != nil {
		return nil, err
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

	var request struct {
		OrigKey string `json:"orig_key"`
	}
	if err := json.Unmarshal(rawBody, &request); err != nil {
		return nil, err
	}
	origKey := strings.TrimSpace(request.OrigKey)
	if origKey != "" && origKey != rule.APIKey {
		m.admissionMu.Lock()
		defer m.admissionMu.Unlock()
		if m.limiter.ActiveCountForKey(origKey) > 0 {
			return nil, fmt.Errorf("cannot rename a key with active requests; wait for completion")
		}
	}
	err := m.mutateRules(ruleMutation{op: "upsert", syncHostKeys: true}, func(state *DynamicRulesState) error {
		// A retired key remains a billing source for late callbacks. Recreating it as
		// an independent key would charge its new requests to the renamed key too.
		// A rename back is safe only for the owner of that same lineage; its source
		// list removes the new current key below. Other owners must still block it.
		for _, owner := range m.cfg.Keys {
			for _, source := range owner.QuotaSourceKeys {
				if source == rule.APIKey && !(origKey != "" && origKey != rule.APIKey && owner.APIKey == origKey) {
					return fmt.Errorf("api key is retained as a quota source; rename its current owner instead")
				}
			}
		}
		if origKey != "" && origKey != rule.APIKey {
			for _, existing := range m.cfg.Keys {
				if existing.APIKey == rule.APIKey {
					return fmt.Errorf("target api key already exists")
				}
			}
			found := false
			for _, existing := range m.cfg.Keys {
				if existing.APIKey == origKey {
					found = true
					spent := m.quotaCostUSD(existing) - existing.QuotaUsedBaseUSD
					if spent < 0 {
						spent = 0
					}
					// A possibly negative baseline carries consumed quota without rewriting history.
					rule.QuotaUsedBaseUSD = m.usageStore.GetKeyCostUSD(rule.APIKey) - spent
					rule.QuotaSourceKeys = removeString(appendUnique(append([]string(nil), existing.QuotaSourceKeys...), origKey, false), rule.APIKey, false)
					rule.QuotaSourceBaseUSD = 0
					for _, source := range rule.QuotaSourceKeys {
						rule.QuotaSourceBaseUSD += m.usageStore.GetKeyCostUSD(source)
					}
					if rule.CreatedAt == "" {
						rule.CreatedAt = existing.CreatedAt
					}
				}
			}
			if !found {
				return errRuleNotFound
			}
			removeKeyFromState(state, origKey)
			state.DeletedKeys = appendUnique(state.DeletedKeys, origKey, false)
		}
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
			rule.QuotaSourceKeys = append([]string(nil), state.Keys[i].QuotaSourceKeys...)
			rule.QuotaSourceBaseUSD = state.Keys[i].QuotaSourceBaseUSD
			state.Keys[i] = cloneKeyRule(rule)
			replaced = true
			break
		}
		if !replaced {
			if origKey == "" || origKey == rule.APIKey {
				rule.QuotaSourceKeys = nil
				rule.QuotaSourceBaseUSD = 0
				rule.QuotaUsedBaseUSD = 0
			}
			if rule.CreatedAt == "" {
				rule.CreatedAt = nowStr
			}
			state.Keys = append(state.Keys, cloneKeyRule(rule))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("key rule change was not committed: %w", err)
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
	if err := validateQuota(dp.QuotaLimitUSD); err != nil {
		return nil, err
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
	if err := pricing.ValidatePrice(price); err != nil {
		return err
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

// quotaCostUSD carries late usage on retired keys without rewriting billing history.
func (m *Manager) quotaCostUSD(rule KeyRuleConfig) float64 {
	total := m.usageStore.GetKeyCostUSD(rule.APIKey)
	for _, source := range rule.QuotaSourceKeys {
		total += m.usageStore.GetKeyCostUSD(source)
	}
	return total - rule.QuotaSourceBaseUSD
}
