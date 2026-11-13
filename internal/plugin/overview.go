package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// authFilesWithUsage turns the host credential list into JSON objects enriched with
// the usage counters this plugin recorded for each credential. The host itself does
// not report success/failed, so without this the admin table would always show 0/0.
func (m *Manager) authFilesWithUsage(files []pluginapi.HostAuthFileEntry) []map[string]any {
	queries := make([]usage.AccountUsageQuery, len(files))
	for i, f := range files {
		queries[i] = usage.AccountUsageQuery{Provider: f.Provider, Identifiers: []string{f.Name, f.ID, f.AuthIndex}}
	}
	usageByFile := m.usageStore.AccountUsageLookup(queries)

	out := make([]map[string]any, 0, len(files))
	for idx, f := range files {
		item := make(map[string]any, 16)
		if raw, errMarshal := json.Marshal(f); errMarshal == nil {
			_ = json.Unmarshal(raw, &item)
		}
		if item == nil {
			item = make(map[string]any, 16)
		}
		if _, ok := item["name"]; !ok && f.Name != "" {
			item["name"] = f.Name
		}
		if _, ok := item["id"]; !ok && f.ID != "" {
			item["id"] = f.ID
		}

		acct := usageByFile[idx]
		if acct != nil {
			item["requests"] = acct.Requests
			item["success"] = acct.SuccessRequests
			item["failed"] = acct.FailedRequests
			item["input_tokens"] = acct.InputTokens
			item["output_tokens"] = acct.OutputTokens
			item["total_tokens"] = acct.TotalTokens
			item["last_model"] = acct.LastModel
			item["last_request_at"] = acct.LastRequestAt
		} else {
			item["requests"] = 0
			item["success"] = 0
			item["failed"] = 0
		}
		out = append(out, item)
	}
	return out
}

// BuildAdminOverview returns the complete state needed by the Admin Dashboard in a single call.
func (m *Manager) BuildAdminOverview(hostCallbackID string) map[string]any {
	snap := m.BuildSnapshot("", "", false)
	// Do not cache authorization state or replay stale active entries on errors.
	rawAuthFiles, authErr := m.ListHostAuthFiles(hostCallbackID)
	authFilesError := ""
	if authErr != nil {
		authFilesError = "上游凭证状态读取不完整，未确认的凭证已隐藏；请稍后刷新，勿据此清除已有绑定"
	}
	authFiles := m.authFilesWithUsage(rawAuthFiles)
	availableModels := m.ListAvailableModels(hostCallbackID, snap)
	pStatus := m.PricingStatus()

	m.mu.RLock()
	cfg := m.cfg
	keysCopy := make([]KeyRuleConfig, len(cfg.Keys))
	for i, k := range cfg.Keys {
		keysCopy[i] = cloneKeyRule(k)
	}
	dpCopy := cfg.DefaultPolicy
	m.mu.RUnlock()
	for i := range keysCopy {
		used := m.quotaCostUSD(keysCopy[i]) - keysCopy[i].QuotaUsedBaseUSD
		if used < 0 {
			used = 0
		}
		keysCopy[i].QuotaUsedUSD = &used
	}

	var totalTokens, inTokens, outTokens, reasonTokens, readTokens, writeTokens int64
	var totalReq, okReq, errReq int64
	var totalCostNano int64
	accountingError := ""
	add := func(dst *int64, value int64) {
		if !usage.SaturatingAdd(dst, value) {
			accountingError = "overview aggregate exceeds supported range; affected counters are saturated"
		}
	}

	for _, ks := range snap.Keys {
		if ks == nil {
			continue
		}
		add(&totalTokens, ks.TotalTokens)
		add(&inTokens, ks.InputTokens)
		add(&outTokens, ks.OutputTokens)
		add(&reasonTokens, ks.ReasoningTokens)
		add(&readTokens, ks.CacheReadTokens)
		add(&writeTokens, ks.CacheWriteTokens)
		add(&totalReq, ks.TotalRequests)
		add(&okReq, ks.SuccessRequests)
		add(&errReq, ks.FailedRequests)
		add(&totalCostNano, ks.TotalCostNanoUSD)
	}

	summary := map[string]any{
		"total_tokens":         totalTokens,
		"input_tokens":         inTokens,
		"output_tokens":        outTokens,
		"reasoning_tokens":     reasonTokens,
		"cache_read_tokens":    readTokens,
		"cache_write_tokens":   writeTokens,
		"total_requests":       totalReq,
		"success_requests":     okReq,
		"failed_requests":      errReq,
		"total_cost_nano_usd":  totalCostNano,
		"total_cost_usd":       pricing.NanoToUSD(totalCostNano),
		"total_cost_formatted": pricing.FormatUSD(totalCostNano),
	}

	if accountingError != "" {
		summary["accounting_error"] = accountingError
	}
	return map[string]any{
		"timezone":          cfg.Storage.Timezone,
		"rules_revision":    m.RulesRevision(),
		"host_sync":         m.HostSyncStatus(),
		"summary":           summary,
		"keys":              keysCopy,
		"default_policy":    dpCopy,
		"usage":             snap,
		"auth_files":        authFiles,
		"auth_files_error":  authFilesError,
		"available_models":  availableModels,
		"pricing_status":    pStatus,
		"diagnostics":       m.BuildPersistenceDiagnostics(),
		"audit_status":      m.AuditStatus(),
		"audit_key_options": m.AuditKeyOptions(),
	}
}

// BuildPersistenceDiagnostics reports where the SQLite database lives and whether
// it exists, so administrators can verify persistence on a live host.
func (m *Manager) BuildPersistenceDiagnostics() map[string]any {
	m.mu.RLock()
	stateKeys := 0
	if m.dynamicState != nil {
		stateKeys = len(m.dynamicState.Keys)
	}
	m.mu.RUnlock()

	usageDBFile := ""
	usageDBExists := false
	usageDBSize := int64(0)
	m.mu.RLock()
	if m.cfg.Storage.UsageDBFile != "" {
		usageDBFile = m.cfg.Storage.UsageDBFile
	}
	m.mu.RUnlock()
	if usageDBFile == "" {
		usageDBFile = m.usageStore.SQLitePath()
	}
	if usageDBFile != "" {
		if info, errStat := os.Stat(usageDBFile); errStat == nil && !info.IsDir() {
			usageDBExists = true
			usageDBSize = info.Size()
		}
	}

	return map[string]any{
		"persistence":          m.usageStore.PersistenceStatus(),
		"rules_keys_in_memory": stateKeys,
		"usage_db_file":        usageDBFile,
		"usage_db_exists":      usageDBExists,
		"usage_db_size":        usageDBSize,
		"usage_db_lock_file":   m.usageStore.SQLiteLockPath(),
	}
}

// BuildSnapshot returns a complete usage snapshot enriched with live concurrency counts and configured rules.
func (m *Manager) BuildSnapshot(filterAPIKey, filterModel string, maskKeys bool) usage.PersistedSnapshot {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	activeByKey := m.limiter.SnapshotByKey()
	maxConcByKey := make(map[string]int, len(cfg.Keys))
	keyNames := make(map[string]string, len(cfg.Keys))
	ruleByKey := make(map[string]KeyRuleConfig, len(cfg.Keys))
	for _, k := range cfg.Keys {
		maxConcByKey[k.APIKey] = k.MaxConcurrency
		if k.Name != "" {
			keyNames[k.APIKey] = k.Name
		}
		ruleByKey[k.APIKey] = k
	}

	snap := m.usageStore.Snapshot(filterAPIKey, filterModel, activeByKey, maxConcByKey, keyNames, maskKeys)
	for mapKey, ks := range snap.Keys {
		rawKey := ks.APIKey
		if rawKey == "" {
			rawKey = mapKey
		}
		if r, ok := ruleByKey[rawKey]; ok {
			ks.QuotaLimitUSD = r.QuotaLimitUSD
			enabled := r.IsEnabled()
			ks.Enabled = &enabled
			ks.AllowedModels = append([]string(nil), r.AllowedModels...)
		}
	}
	return snap
}

// BuildSelfAccountView constructs the self-service response for a downstream user querying their own API Key (`#account`).
func (m *Manager) BuildSelfAccountView(apiKey string) (map[string]any, int, error) {
	k := strings.TrimSpace(apiKey)
	if k == "" {
		return nil, http.StatusUnauthorized, fmt.Errorf("API key is required")
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, listed := cfg.ResolveKeyRule(k)
	snap := m.BuildSnapshot(k, "", true)
	var ks *usage.KeyStats
	for _, item := range snap.Keys {
		ks = item
		break
	}
	if ks == nil {
		ks = &usage.KeyStats{
			MaskedKey:          usage.MaskAPIKey(k),
			KeyName:            rule.Name,
			ActiveConcurrency:  m.limiter.ActiveCountForKey(k),
			MaxConcurrency:     rule.MaxConcurrency,
			QuotaLimitUSD:      rule.QuotaLimitUSD,
			TotalCostFormatted: "$0.000000",
			Models:             make(map[string]*usage.ModelStats),
		}
	}

	if !listed && !cfg.AllowUnlisted() && ks.TotalRequests == 0 {
		return nil, http.StatusForbidden, fmt.Errorf("该 API Key 未在系统中授权或不存在")
	}

	usedUSD := ks.TotalCostUSD
	var remainingUSD float64
	if rule.QuotaLimitUSD > 0 {
		remainingUSD = rule.QuotaLimitUSD - usedUSD
		if remainingUSD < 0 {
			remainingUSD = 0
		}
	}

	selfAccount := map[string]any{
		"api_key_masked":      usage.MaskAPIKey(k),
		"key_name":            rule.Name,
		"listed":              listed,
		"enabled":             rule.IsEnabled(),
		"active_concurrency":  m.limiter.ActiveCountForKey(k),
		"max_concurrency":     rule.MaxConcurrency,
		"quota_limit_usd":     rule.QuotaLimitUSD,
		"used_cost_usd":       usedUSD,
		"used_cost_formatted": ks.TotalCostFormatted,
		"remaining_quota_usd": remainingUSD,
		"allowed_models":      rule.AllowedModels,
		"upstream_binding": map[string]any{
			"strategy":    rule.UpstreamBinding.Strategy,
			"credentials": append(append([]string(nil), rule.UpstreamBinding.AuthIDs...), rule.UpstreamBinding.Credentials...),
		},
		"stats": ks,
	}

	return map[string]any{
		"ok":           true,
		"self_account": selfAccount,
	}, http.StatusOK, nil
}

// ListAvailableModels returns only existing models registered on active host credentials (`host.auth.models`),
// excluding any wildcards, sample models, or "unknown" placeholders.
func (m *Manager) ListAvailableModels(hostCallbackID string, snap usage.PersistedSnapshot) []AvailableModelOption {
	authModels, _ := m.host.ListAuthModels(hostCallbackID)
	byModel := make(map[string]*AvailableModelOption)

	addModel := func(id, provider, source string) {
		clean := strings.TrimSpace(id)
		if clean == "" || strings.EqualFold(clean, "unknown") || strings.ContainsAny(clean, "*?!") {
			return
		}
		prov := strings.ToLower(strings.TrimSpace(provider))
		if prov == "" {
			prov = inferModelProvider(clean)
		}
		item, exists := byModel[clean]
		if !exists {
			item = &AvailableModelOption{
				ID:       clean,
				Provider: prov,
			}
			byModel[clean] = item
		} else if (item.Provider == "" || item.Provider == "other") && prov != "" && prov != "other" {
			item.Provider = prov
		}
		if source != "" {
			hasSrc := false
			for _, s := range item.Sources {
				if s == source {
					hasSrc = true
					break
				}
			}
			if !hasSrc {
				item.Sources = append(item.Sources, source)
			}
		}
	}

	// Only models actually registered on active host credentials via host.auth.models
	for _, cred := range authModels {
		src := cred.ID
		if src == "" {
			src = cred.Provider
		}
		for _, mid := range cred.Models {
			addModel(mid, cred.Provider, src)
		}
	}

	// Fallback if host.auth.models returned no models (e.g. standalone mode): include real non-wildcard models observed in usage
	if len(byModel) == 0 {
		for _, ks := range snap.Keys {
			if ks == nil {
				continue
			}
			for mid := range ks.Models {
				addModel(mid, "", "usage")
			}
		}
	}

	out := make([]AvailableModelOption, 0, len(byModel))
	for _, item := range byModel {
		p, _ := m.pricingEngine.Lookup(item.ID)
		item.Price = p
		if refP, okRef := m.pricingEngine.LookupReference(item.ID); okRef {
			cp := refP
			item.ReferencePrice = &cp
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// QueryLedger aggregates the retained hourly ledger according to the overview filters.
// The key counters come from the configured rules (not from usage buckets), so the
// overview shows "总密钥 / 可用密钥" immediately instead of only after the first call.
func (m *Manager) QueryLedger(q usage.LedgerQuery) usage.LedgerResult {
	if strings.TrimSpace(q.Timezone) == "" {
		m.mu.RLock()
		q.Timezone = m.cfg.Storage.Timezone
		m.mu.RUnlock()
	}
	result := m.usageStore.QueryLedger(q)

	m.mu.RLock()
	total := 0
	available := 0
	seen := make(map[string]struct{}, len(m.cfg.Keys))
	for _, rule := range m.cfg.Keys {
		key := strings.TrimSpace(rule.APIKey)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		total++
		if rule.IsEnabled() {
			available++
		}
	}
	m.mu.RUnlock()

	if total > 0 {
		result.KeysTotal = total
		result.KeysAvailable = available
	}
	return result
}

// ResetUsage clears accumulated usage statistics (for a single key or globally) and flushes to disk.
func (m *Manager) ResetUsage(apiKey string) error {
	return m.usageStore.Reset(apiKey)
}

// PricingStatus returns current models.dev sync diagnostics and custom price overrides.
func (m *Manager) PricingStatus() pricing.Status {
	return m.pricingEngine.Status()
}

// LookupModelPrice looks up the effective per-1M-token price for a given model name.
func (m *Manager) LookupModelPrice(model string) (pricing.ModelPrice, bool) {
	return m.pricingEngine.Lookup(model)
}

// SearchReferencePrices searches synced models.dev prices by substring query.
func (m *Manager) SearchReferencePrices(query string, limit int) []pricing.ReferenceModelEntry {
	return m.pricingEngine.SearchReferencePrices(query, limit)
}

// TriggerPricingSync runs an immediate synchronization with models.dev.
func (m *Manager) TriggerPricingSync(ctx context.Context) (int, error) {
	return m.pricingSyncer.SyncOnce(ctx)
}
