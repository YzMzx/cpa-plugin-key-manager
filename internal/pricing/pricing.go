package pricing

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
)

// NanoUSDPerUSD represents 1 USD in nano-dollars (10^9), providing exact integer arithmetic
// for per-token cost accumulation without floating-point drift.
const NanoUSDPerUSD int64 = 1_000_000_000

// ModelPrice holds reference prices in USD per 1,000,000 (1M) tokens.
type ModelPrice struct {
	Input      float64 `yaml:"input" json:"input"`
	Output     float64 `yaml:"output" json:"output"`
	CacheRead  float64 `yaml:"cache_read" json:"cache_read"`
	CacheWrite float64 `yaml:"cache_write" json:"cache_write"`
	Source     string  `yaml:"-" json:"source,omitempty"`
}

// CostBreakdown holds the calculated cost for a single request in both nano-USD and USD float64.
type CostBreakdown struct {
	NanoUSD    int64      `json:"nano_usd"`
	USD        float64    `json:"usd"`
	Formatted  string     `json:"formatted"`
	UnitPrice  ModelPrice `json:"unit_price"`
	PriceFound bool       `json:"price_found"`
}

// NanoToUSD converts nano-USD (10^-9 USD) to standard USD float64 rounded to 6 decimal places (micro-USD precision).
func NanoToUSD(nano int64) float64 {
	usd := float64(nano) / float64(NanoUSDPerUSD)
	return math.Round(usd*1_000_000) / 1_000_000
}

// FormatUSD formats a nano-USD amount as a USD string with 6 decimal places (e.g. "$0.014250").
func FormatUSD(nano int64) string {
	return fmt.Sprintf("$%.6f", float64(nano)/float64(NanoUSDPerUSD))
}

type customRule struct {
	pattern string
	price   ModelPrice
}

// Engine manages model pricing from local custom overrides, models.dev remote sync, and local disk cache.
type Engine struct {
	mu            sync.RWMutex
	customExact   map[string]ModelPrice
	customRules   []customRule
	modelsDevMap  map[string]ModelPrice
	defaultPrice  *ModelPrice
	lastSyncAt    time.Time
	lastSyncError string
	syncSource    string
}

// NewEngine creates a new pricing Engine.
func NewEngine() *Engine {
	return &Engine{
		customExact:  make(map[string]ModelPrice),
		modelsDevMap: make(map[string]ModelPrice),
	}
}

// SetCustomPrices updates the user-configured price overrides and optional default fallback price.
// Safe for hot-reload without losing synced models.dev prices.
func (e *Engine) SetCustomPrices(custom map[string]ModelPrice, defaultPrice *ModelPrice) error {
	// Validate the complete candidate before publishing any part of it. A bad
	// override must not erase a previously valid set during hot reload.
	for model, price := range custom {
		if err := ValidatePrice(price); err != nil {
			return fmt.Errorf("custom price %q: %w", model, err)
		}
	}
	if defaultPrice != nil {
		if err := ValidatePrice(*defaultPrice); err != nil {
			return fmt.Errorf("default price: %w", err)
		}
	}
	exact := make(map[string]ModelPrice, len(custom))
	rules := make([]customRule, 0, len(custom))

	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	// Sort longer/more specific patterns first
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})

	for _, rawPattern := range keys {
		pat := strings.ToLower(strings.TrimSpace(rawPattern))
		if pat == "" {
			continue
		}
		p := custom[rawPattern]
		p.Source = "custom_override"
		if strings.ContainsAny(pat, "*?") {
			rules = append(rules, customRule{
				pattern: pat,
				price:   p,
			})
		} else {
			exact[pat] = p
		}
	}

	var defCopy *ModelPrice
	if defaultPrice != nil {
		cp := *defaultPrice
		cp.Source = "default_fallback"
		defCopy = &cp
	}

	e.mu.Lock()
	e.customExact = exact
	e.customRules = rules
	e.defaultPrice = defCopy
	e.mu.Unlock()
	return nil
}

// normalizeModelVariants flattens the candidate names into unique lowercase variants.
func normalizeModelVariants(modelCandidates []string) []string {
	variants := make([]string, 0, len(modelCandidates)*3)
	seen := make(map[string]struct{}, len(modelCandidates)*3)
	for _, cand := range modelCandidates {
		for _, v := range authz.NormalizeModelVariants(cand) {
			if _, ok := seen[v]; !ok {
				seen[v] = struct{}{}
				variants = append(variants, v)
			}
		}
	}
	return variants
}

// modelPrefixLadder returns progressively shorter prefixes of a model id, each still
// containing at least two dash-separated segments.
//
//	gemini-3.8-flash-high -> [gemini-3.8-flash gemini-3.8]
//	claude-sonnet-4-6     -> [claude-sonnet-4 claude-sonnet]
func modelPrefixLadder(model string) []string {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" {
		return nil
	}
	segments := strings.Split(model, "-")
	out := make([]string, 0, len(segments))
	for n := len(segments) - 1; n >= 2; n-- {
		prefix := strings.Join(segments[:n], "-")
		if prefix != model {
			out = append(out, prefix)
		}
	}
	return out
}

// bestPrefixMatchLocked accepts only a published ancestor of the requested ID.
// A longer descendant (for example family-preview) is not evidence that its
// price applies to an unknown sibling. An exact base always wins.
func (e *Engine) bestPrefixMatchLocked(base string) (string, ModelPrice, bool) {
	price, ok := e.modelsDevMap[base]
	return base, price, ok
}

// lookupModelsDevLocked resolves a models.dev price: exact variant first, then a
// exact-ancestor fallback (gemini-3.8-flash-high -> gemini-3.8-flash -> gemini-3.8).
func (e *Engine) lookupModelsDevLocked(variants []string) (ModelPrice, bool) {
	for _, v := range variants {
		if p, ok := e.modelsDevMap[v]; ok {
			return p, true
		}
	}
	for _, v := range variants {
		for _, prefix := range modelPrefixLadder(v) {
			if key, price, ok := e.bestPrefixMatchLocked(prefix); ok {
				price.Source = "models.dev(prefix:" + key + ")"
				return price, true
			}
		}
	}
	return ModelPrice{}, false
}

// Lookup resolves candidates in caller priority order: requested model first,
// then served model. Each candidate completes custom exact -> custom wildcard ->
// reference lookup before the next candidate is considered. A global default is
// used only when no candidate has a price. A served-model override therefore
// cannot supersede a known price for the client-requested product.
func (e *Engine) Lookup(modelCandidates ...string) (ModelPrice, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, candidate := range modelCandidates {
		variants := normalizeModelVariants([]string{candidate})
		for _, v := range variants {
			if p, ok := e.customExact[v]; ok {
				return p, true
			}
		}
		for _, rule := range e.customRules {
			for _, v := range variants {
				if authz.MatchWildcard(rule.pattern, v) {
					return rule.price, true
				}
			}
		}
		if p, ok := e.lookupModelsDevLocked(variants); ok {
			return p, true
		}
	}
	if e.defaultPrice != nil {
		return *e.defaultPrice, true
	}
	return ModelPrice{Source: "unmatched"}, false
}

// LookupReference resolves the models.dev reference price for the given model, ignoring custom overrides and default fallback.
func (e *Engine) LookupReference(modelCandidates ...string) (ModelPrice, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, candidate := range modelCandidates {
		if p, ok := e.lookupModelsDevLocked(normalizeModelVariants([]string{candidate})); ok {
			return p, true
		}
	}
	return ModelPrice{Source: "unmatched"}, false
}

// Calculate computes the CostBreakdown for the given model and orthogonal token counts.
func (e *Engine) Calculate(uncachedInput, output, cacheRead, cacheWrite int64, modelCandidates ...string) (CostBreakdown, error) {
	price, found := e.Lookup(modelCandidates...)
	nano, err := CalculateCostNanoUSD(uncachedInput, output, cacheRead, cacheWrite, price)
	if err != nil {
		return CostBreakdown{UnitPrice: price, PriceFound: found}, err
	}
	return CostBreakdown{
		NanoUSD:    nano,
		USD:        NanoToUSD(nano),
		Formatted:  FormatUSD(nano),
		UnitPrice:  price,
		PriceFound: found,
	}, nil
}

// ParseAndLoadModelsDevJSON parses the raw JSON payload from https://models.dev/api.json
// and updates the in-memory models.dev pricing table.
func (e *Engine) ParseAndLoadModelsDevJSON(rawJSON []byte, source string) (int, error) {
	if len(rawJSON) == 0 {
		return 0, fmt.Errorf("empty models.dev JSON payload")
	}

	var root map[string]modelsDevProvider
	if err := json.Unmarshal(rawJSON, &root); err != nil {
		return 0, fmt.Errorf("unmarshal models.dev JSON: %w", err)
	}
	if len(root) == 0 {
		return 0, fmt.Errorf("models.dev JSON contained no providers")
	}

	parsed := make(map[string]ModelPrice, 1024)
	// Preferred providers have priority when bare model IDs collide across providers
	preferredProviders := map[string]int{
		"anthropic":     100,
		"openai":        100,
		"google":        100,
		"google-vertex": 95,
		"deepseek":      95,
		"xai":           95,
		"mistral":       90,
		"cohere":        90,
		"alibaba":       85,
		"moonshotai":    85,
		"zhipuai":       85,
	}
	priorityByKey := make(map[string]int, 1024)

	putWithPriority := func(key string, price ModelPrice, prio int) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		if existingPrio, exists := priorityByKey[key]; !exists || prio > existingPrio {
			parsed[key] = price
			priorityByKey[key] = prio
		}
	}

	// Stable provider and model order also defines the tie-break at equal priority.
	providerKeys := make([]string, 0, len(root))
	for key := range root {
		providerKeys = append(providerKeys, key)
	}
	sort.Strings(providerKeys)
	for _, provKey := range providerKeys {
		prov := root[provKey]
		provID := strings.ToLower(strings.TrimSpace(prov.ID))
		if provID == "" {
			provID = strings.ToLower(strings.TrimSpace(provKey))
		}
		basePrio := preferredProviders[provID]
		if basePrio == 0 {
			basePrio = 50
		}

		modelKeys := make([]string, 0, len(prov.Models))
		for key := range prov.Models {
			modelKeys = append(modelKeys, key)
		}
		sort.Strings(modelKeys)
		for _, modelKey := range modelKeys {
			m := prov.Models[modelKey]
			if m.Cost == nil {
				continue
			}
			// Skip zero-cost entries if a paid canonical entry exists, unless it's the only one
			p := ModelPrice{
				Input:      m.Cost.Input,
				Output:     m.Cost.Output,
				CacheRead:  m.Cost.CacheRead,
				CacheWrite: m.Cost.CacheWrite,
				Source:     source,
			}
			if err := ValidatePrice(p); err != nil {
				return 0, fmt.Errorf("models.dev provider %q model %q: %w", provKey, modelKey, err)
			}
			prio := basePrio
			if p.Input == 0 && p.Output == 0 {
				prio -= 20
			}

			modelID := strings.ToLower(strings.TrimSpace(m.ID))
			if modelID == "" {
				modelID = strings.ToLower(strings.TrimSpace(modelKey))
			}

			// Index 1: <provider>/<model_id>
			if provID != "" && modelID != "" {
				putWithPriority(provID+"/"+modelID, p, prio+10)
			}
			// Index 2: canonical_model_id (e.g. "anthropic/claude-3-5-sonnet")
			if canon := strings.ToLower(strings.TrimSpace(m.CanonicalModelID)); canon != "" {
				putWithPriority(canon, p, prio+5)
				if idx := strings.LastIndex(canon, "/"); idx >= 0 && idx+1 < len(canon) {
					putWithPriority(canon[idx+1:], p, prio)
				}
			}
			// Index 3: direct modelID and bare name without provider prefix
			putWithPriority(modelID, p, prio)
			if idx := strings.LastIndex(modelID, "/"); idx >= 0 && idx+1 < len(modelID) {
				putWithPriority(modelID[idx+1:], p, prio-1)
			}
			// Index 4: map key from models map
			if mk := strings.ToLower(strings.TrimSpace(modelKey)); mk != "" && mk != modelID {
				putWithPriority(mk, p, prio)
			}
		}
	}

	if len(parsed) == 0 {
		return 0, fmt.Errorf("no valid model cost entries found in models.dev JSON")
	}

	e.mu.Lock()
	e.modelsDevMap = parsed
	e.lastSyncAt = time.Now()
	e.lastSyncError = ""
	e.syncSource = source
	e.mu.Unlock()

	return len(parsed), nil
}

// RecordSyncError records the last synchronization error without clearing existing cached prices.
func (e *Engine) RecordSyncError(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.lastSyncError = err.Error()
	e.mu.Unlock()
}

// Status returns current pricing engine diagnostics for Management API & CLI queries.
type Status struct {
	SyncedModelKeys  int                   `json:"synced_model_keys"`
	CustomExactCount int                   `json:"custom_exact_count"`
	CustomRuleCount  int                   `json:"custom_wildcard_count"`
	LastSyncAt       string                `json:"last_sync_at,omitempty"`
	LastSyncError    string                `json:"last_sync_error,omitempty"`
	SyncSource       string                `json:"sync_source,omitempty"`
	CustomPrices     map[string]ModelPrice `json:"custom_prices,omitempty"`
	DefaultPrice     *ModelPrice           `json:"default_price,omitempty"`
}

// ReferenceModelEntry represents a single model price entry in the synced models.dev catalog.
type ReferenceModelEntry struct {
	Model string     `json:"model"`
	Price ModelPrice `json:"price"`
}

// Status returns a snapshot of the pricing engine status.
func (e *Engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()

	customAll := make(map[string]ModelPrice, len(e.customExact)+len(e.customRules))
	for k, v := range e.customExact {
		customAll[k] = v
	}
	for _, r := range e.customRules {
		customAll[r.pattern] = r.price
	}
	var lastSync string
	if !e.lastSyncAt.IsZero() {
		lastSync = e.lastSyncAt.UTC().Format(time.RFC3339)
	}
	var defPrice *ModelPrice
	if e.defaultPrice != nil {
		cp := *e.defaultPrice
		defPrice = &cp
	}
	return Status{
		SyncedModelKeys:  len(e.modelsDevMap),
		CustomExactCount: len(e.customExact),
		CustomRuleCount:  len(e.customRules),
		LastSyncAt:       lastSync,
		LastSyncError:    e.lastSyncError,
		SyncSource:       e.syncSource,
		CustomPrices:     customAll,
		DefaultPrice:     defPrice,
	}
}

// SearchReferencePrices searches synced models.dev prices by substring query and returns up to limit sorted entries.
func (e *Engine) SearchReferencePrices(query string, limit int) []ReferenceModelEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if limit <= 0 {
		limit = 200
	}

	e.mu.RLock()
	keys := make([]string, 0, len(e.modelsDevMap))
	for k := range e.modelsDevMap {
		if q == "" || strings.Contains(k, q) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	out := make([]ReferenceModelEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, ReferenceModelEntry{
			Model: k,
			Price: e.modelsDevMap[k],
		})
	}
	e.mu.RUnlock()
	return out
}

type modelsDevProvider struct {
	ID     string                    `json:"id"`
	Name   string                    `json:"name"`
	Models map[string]modelsDevModel `json:"models"`
}

type modelsDevModel struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	CanonicalModelID string         `json:"canonical_model_id"`
	Cost             *modelsDevCost `json:"cost"`
}

type modelsDevCost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
}
