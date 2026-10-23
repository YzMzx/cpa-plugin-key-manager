package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
)

// ModelStats stores cumulative usage and USD billing statistics for a single model under an API Key.
type ModelStats struct {
	Model            string             `json:"model"`
	Requests         int64              `json:"requests"`
	SuccessRequests  int64              `json:"success_requests"`
	FailedRequests   int64              `json:"failed_requests"`
	InputTokens      int64              `json:"input_tokens"`
	OutputTokens     int64              `json:"output_tokens"`
	ReasoningTokens  int64              `json:"reasoning_tokens"`
	CacheReadTokens  int64              `json:"cache_read_tokens"`
	CacheWriteTokens int64              `json:"cache_write_tokens"`
	TotalTokens      int64              `json:"total_tokens"`
	CostNanoUSD      int64              `json:"cost_nano_usd"`
	CostUSD          float64            `json:"cost_usd"`
	CostFormatted    string             `json:"cost_formatted"`
	UnitPricePer1M   pricing.ModelPrice `json:"unit_price_per_1m"`
	LastUsedAt       string             `json:"last_used_at,omitempty"`
}

// KeyStats stores cumulative usage and USD billing statistics for a single API Key across all models.
type KeyStats struct {
	APIKey             string                 `json:"api_key,omitempty"`
	MaskedKey          string                 `json:"masked_key"`
	KeyName            string                 `json:"key_name,omitempty"`
	Enabled            *bool                  `json:"enabled,omitempty"`
	ActiveConcurrency  int                    `json:"active_concurrency"`
	MaxConcurrency     int                    `json:"max_concurrency"`
	QuotaLimitUSD      float64                `json:"quota_limit_usd,omitempty"`
	AllowedModels      []string               `json:"allowed_models,omitempty"`
	TotalRequests      int64                  `json:"total_requests"`
	SuccessRequests    int64                  `json:"success_requests"`
	FailedRequests     int64                  `json:"failed_requests"`
	InputTokens        int64                  `json:"input_tokens"`
	OutputTokens       int64                  `json:"output_tokens"`
	ReasoningTokens    int64                  `json:"reasoning_tokens"`
	CacheReadTokens    int64                  `json:"cache_read_tokens"`
	CacheWriteTokens   int64                  `json:"cache_write_tokens"`
	TotalTokens        int64                  `json:"total_tokens"`
	TotalCostNanoUSD   int64                  `json:"total_cost_nano_usd"`
	TotalCostUSD       float64                `json:"total_cost_usd"`
	TotalCostFormatted string                 `json:"total_cost_formatted"`
	LastRequestAt      string                 `json:"last_request_at,omitempty"`
	Models             map[string]*ModelStats `json:"models"`
}

// PersistedSnapshot is the root JSON structure persisted to disk.
type PersistedSnapshot struct {
	Version   int                  `json:"version"`
	UpdatedAt string               `json:"updated_at"`
	Keys      map[string]*KeyStats `json:"keys"`
}

// TrackedRequest holds in-flight and recently completed request state for deduplicating
// and reconciling usage between response/stream interceptors (`request.complete`) and `usage.handle`.
type TrackedRequest struct {
	RequestID      string
	TraceID        string
	APIKey         string
	KeyName        string
	Model          string
	RequestedModel string
	SourceFormat   string
	Stream         bool
	StartedAt      time.Time
	CompletedAt    time.Time

	ExtractedUsage NormalizedUsage
	BilledUsage    NormalizedUsage
	BilledModel    string
	CountedRequest bool
	Failed         bool
}

// Store manages in-memory usage accounting, request deduplication, and atomic JSON persistence.
type Store struct {
	mu      sync.Mutex
	pricing *pricing.Engine
	keys    map[string]*KeyStats

	// Active & recently completed request trackers (for coordinating request.complete and usage.handle)
	byRequestID   map[string]*TrackedRequest
	byTraceID     map[string]*TrackedRequest
	seenHostReqID map[string]time.Time

	storageFile   string
	dirty         bool
	flushInterval time.Duration
	stopFlushCh   chan struct{}
	flushStopped  chan struct{}
}

// NewStore creates a new usage Store backed by the given pricing Engine.
func NewStore(pricingEngine *pricing.Engine) *Store {
	if pricingEngine == nil {
		pricingEngine = pricing.NewEngine()
	}
	return &Store{
		pricing:       pricingEngine,
		keys:          make(map[string]*KeyStats),
		byRequestID:   make(map[string]*TrackedRequest),
		byTraceID:     make(map[string]*TrackedRequest),
		seenHostReqID: make(map[string]time.Time),
	}
}

// ConfigurePersistence sets the persistence file path and periodic flush interval.
// Calling ConfigurePersistence during hot-reload (`plugin.reconfigure`) preserves all in-memory
// usage statistics while loading any existing disk history on initial startup.
func (s *Store) ConfigurePersistence(filePath string, flushInterval time.Duration) error {
	s.stopFlusher()

	cleanPath := strings.TrimSpace(filePath)
	if cleanPath != "" {
		cleanPath = filepath.Clean(cleanPath)
	}
	if flushInterval <= 0 {
		flushInterval = 10 * time.Second
	}

	s.mu.Lock()
	wasEmpty := len(s.keys) == 0
	s.storageFile = cleanPath
	s.flushInterval = flushInterval
	s.mu.Unlock()

	var loadErr error
	if cleanPath != "" && wasEmpty {
		loadErr = s.loadFromDisk(cleanPath)
	}

	if cleanPath != "" {
		stopCh := make(chan struct{})
		stoppedCh := make(chan struct{})
		s.mu.Lock()
		s.stopFlushCh = stopCh
		s.flushStopped = stoppedCh
		s.mu.Unlock()
		go s.flushLoop(stopCh, stoppedCh, flushInterval)
	}

	return loadErr
}

// Close stops the periodic flusher and performs a final synchronous atomic flush to disk.
func (s *Store) Close() error {
	s.stopFlusher()
	return s.FlushNow()
}

func (s *Store) stopFlusher() {
	s.mu.Lock()
	stopCh := s.stopFlushCh
	stoppedCh := s.flushStopped
	s.stopFlushCh = nil
	s.flushStopped = nil
	s.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if stoppedCh != nil {
		<-stoppedCh
	}
}

func (s *Store) flushLoop(stopCh <-chan struct{}, stoppedCh chan<- struct{}, interval time.Duration) {
	defer close(stoppedCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			s.evictOldTrackers(15 * time.Minute)
			_ = s.FlushIfDirty()
		}
	}
}

// BeginRequest registers a request when `request.intercept_before` allows it through.
func (s *Store) BeginRequest(requestID, apiKey, keyName, model, requestedModel, sourceFormat string, stream bool) {
	reqID := strings.TrimSpace(requestID)
	if reqID == "" {
		return
	}
	apiKey = normalizeAPIKey(apiKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.byRequestID[reqID]; ok {
		if apiKey != "__anonymous__" {
			existing.APIKey = apiKey
		}
		if keyName != "" {
			existing.KeyName = keyName
		}
		if model != "" {
			existing.Model = model
		}
		if requestedModel != "" {
			existing.RequestedModel = requestedModel
		}
		return
	}

	s.byRequestID[reqID] = &TrackedRequest{
		RequestID:      reqID,
		APIKey:         apiKey,
		KeyName:        keyName,
		Model:          strings.TrimSpace(model),
		RequestedModel: strings.TrimSpace(requestedModel),
		SourceFormat:   strings.TrimSpace(sourceFormat),
		Stream:         stream,
		StartedAt:      time.Now(),
	}
}

// LookupRequest returns tracked metadata for a RequestID if present.
func (s *Store) LookupRequest(requestID string) (TrackedRequest, bool) {
	reqID := strings.TrimSpace(requestID)
	if reqID == "" {
		return TrackedRequest{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tr, ok := s.byRequestID[reqID]
	if !ok {
		return TrackedRequest{}, false
	}
	return *tr, true
}

// ObserveResponse extracts and merges non-streaming usage from `response.intercept_after`.
func (s *Store) ObserveResponse(requestID, model, requestedModel string, body []byte) NormalizedUsage {
	reqID := strings.TrimSpace(requestID)
	s.mu.Lock()
	var sourceFormat string
	if tr, ok := s.byRequestID[reqID]; ok {
		sourceFormat = tr.SourceFormat
	}
	s.mu.Unlock()

	extracted := ExtractResponseUsage(sourceFormat, body)
	if !extracted.HasUsage && extracted.ResponseModel == "" {
		return extracted
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tr := s.ensureTrackerLocked(reqID, "", model, requestedModel, sourceFormat, false)
	tr.ExtractedUsage = MergeUsage(tr.ExtractedUsage, extracted)
	if tr.CountedRequest {
		s.reconcileTrackerDeltaLocked(tr)
	}
	return tr.ExtractedUsage
}

// ObserveStreamChunk extracts and incrementally merges SSE streaming usage from `response.intercept_stream_chunk`.
func (s *Store) ObserveStreamChunk(requestID, model, requestedModel string, chunk []byte) NormalizedUsage {
	reqID := strings.TrimSpace(requestID)
	s.mu.Lock()
	var sourceFormat string
	var current NormalizedUsage
	if tr, ok := s.byRequestID[reqID]; ok {
		sourceFormat = tr.SourceFormat
		current = tr.ExtractedUsage
	}
	s.mu.Unlock()

	updated := ObserveStreamChunkUsage(sourceFormat, chunk, current)
	if !updated.HasUsage && updated.ResponseModel == "" {
		return current
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tr := s.ensureTrackerLocked(reqID, "", model, requestedModel, sourceFormat, true)
	tr.ExtractedUsage = MergeUsage(tr.ExtractedUsage, updated)
	if tr.CountedRequest {
		s.reconcileTrackerDeltaLocked(tr)
	}
	return tr.ExtractedUsage
}

// CompleteRequest finalizes accounting for `request.complete` and reconciles any usage
// already observed via interceptors or `usage.handle`.
func (s *Store) CompleteRequest(completion pluginapi.RequestCompletion, fallbackAPIKey, fallbackKeyName string) {
	reqID := strings.TrimSpace(completion.RequestID)
	traceID := strings.TrimSpace(completion.TraceID)
	failed := completion.Outcome != pluginapi.RequestCompletionSucceeded &&
		!(completion.StatusCode >= 200 && completion.StatusCode < 300 && completion.Outcome == "")

	s.mu.Lock()
	defer s.mu.Unlock()

	var tr *TrackedRequest
	if reqID != "" {
		tr = s.byRequestID[reqID]
	}
	if tr == nil && traceID != "" {
		if byTrace, ok := s.byTraceID[traceID]; ok {
			tr = byTrace
			if reqID != "" {
				tr.RequestID = reqID
				s.byRequestID[reqID] = tr
			}
		}
	}
	if tr == nil {
		tr = s.ensureTrackerLocked(reqID, fallbackAPIKey, completion.Model, completion.RequestedModel, completion.SourceFormat, completion.Stream)
	}

	if fallbackAPIKey != "" && (tr.APIKey == "" || tr.APIKey == "__anonymous__") {
		tr.APIKey = normalizeAPIKey(fallbackAPIKey)
	}
	if fallbackKeyName != "" && tr.KeyName == "" {
		tr.KeyName = fallbackKeyName
	}
	if completion.Model != "" && tr.Model == "" {
		tr.Model = strings.TrimSpace(completion.Model)
	}
	if completion.RequestedModel != "" && tr.RequestedModel == "" {
		tr.RequestedModel = strings.TrimSpace(completion.RequestedModel)
	}
	if traceID != "" {
		tr.TraceID = traceID
		// If usage.handle already created a trace entry before CompleteRequest knew the TraceID, merge them!
		if existingTrace, ok := s.byTraceID[traceID]; ok && existingTrace != tr {
			tr.ExtractedUsage = MergeMaxUsage(tr.ExtractedUsage, existingTrace.ExtractedUsage)
			if existingTrace.APIKey != "" && existingTrace.APIKey != "__anonymous__" && (tr.APIKey == "" || tr.APIKey == "__anonymous__") {
				tr.APIKey = existingTrace.APIKey
			}
			if existingTrace.KeyName != "" && tr.KeyName == "" {
				tr.KeyName = existingTrace.KeyName
			}
			if existingTrace.CountedRequest {
				tr.CountedRequest = true
				tr.BilledUsage = existingTrace.BilledUsage
				tr.BilledModel = existingTrace.BilledModel
				tr.Failed = existingTrace.Failed
			}
		}
		s.byTraceID[traceID] = tr
	}

	tr.CompletedAt = time.Now()
	tr.Failed = failed
	s.reconcileTrackerDeltaLocked(tr)
}

// ObserveHostUsageRecord processes a `pluginapi.UsageRecord` from `usage.handle`.
// It coordinates with `TrackedRequest` so the same request is never double-billed, while
// ensuring any additional token fields provided by the host (e.g. after upstream protocol conversion)
// are merged and accounted for.
func (s *Store) ObserveHostUsageRecord(rec pluginapi.UsageRecord, keyName string) {
	hostReqID := strings.TrimSpace(rec.RequestID)
	traceID := strings.TrimSpace(rec.TraceID)
	apiKey := normalizeAPIKey(rec.APIKey)
	hostUsage := NormalizeFromHostDetail(rec.Provider, rec.Detail)
	if rec.ResponseModel != "" && hostUsage.ResponseModel == "" {
		hostUsage.ResponseModel = strings.TrimSpace(rec.ResponseModel)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if hostReqID != "" {
		if _, seen := s.seenHostReqID[hostReqID]; seen {
			return
		}
		s.seenHostReqID[hostReqID] = time.Now()
	}

	// 1. Try matching by TraceID
	var tr *TrackedRequest
	if traceID != "" {
		tr = s.byTraceID[traceID]
	}
	// 2. Try matching by RequestID
	if tr == nil && hostReqID != "" {
		tr = s.byRequestID[hostReqID]
	}
	// 3. Try matching an active/recent tracker for the same APIKey & Model that hasn't bound a TraceID yet
	if tr == nil && apiKey != "__anonymous__" {
		var best *TrackedRequest
		for _, candidate := range s.byRequestID {
			if candidate.APIKey != apiKey {
				continue
			}
			if traceID != "" && candidate.TraceID != "" && candidate.TraceID != traceID {
				continue
			}
			if best == nil || candidate.StartedAt.After(best.StartedAt) {
				best = candidate
			}
		}
		if best != nil && time.Since(best.StartedAt) < 10*time.Minute {
			tr = best
		}
	}

	if tr == nil {
		id := hostReqID
		if id == "" {
			id = traceID
		}
		if id == "" {
			id = fmt.Sprintf("host-%d", time.Now().UnixNano())
		}
		tr = &TrackedRequest{
			RequestID:      id,
			TraceID:        traceID,
			APIKey:         apiKey,
			KeyName:        keyName,
			Model:          strings.TrimSpace(rec.Model),
			RequestedModel: strings.TrimSpace(rec.Alias),
			Stream:         rec.Stream,
			StartedAt:      rec.RequestedAt,
			CompletedAt:    time.Now(),
			Failed:         rec.Failed,
		}
		if tr.StartedAt.IsZero() {
			tr.StartedAt = time.Now()
		}
		s.byRequestID[id] = tr
	}

	if traceID != "" {
		tr.TraceID = traceID
		s.byTraceID[traceID] = tr
	}
	if apiKey != "__anonymous__" && (tr.APIKey == "" || tr.APIKey == "__anonymous__") {
		tr.APIKey = apiKey
	}
	if keyName != "" && tr.KeyName == "" {
		tr.KeyName = keyName
	}
	if rec.Model != "" && tr.Model == "" {
		tr.Model = strings.TrimSpace(rec.Model)
	}
	if rec.Alias != "" && tr.RequestedModel == "" {
		tr.RequestedModel = strings.TrimSpace(rec.Alias)
	}

	// Merge host usage with interceptor usage (taking the more complete value per bucket)
	tr.ExtractedUsage = MergeMaxUsage(tr.ExtractedUsage, hostUsage)
	s.reconcileTrackerDeltaLocked(tr)
}

func (s *Store) ensureTrackerLocked(reqID, apiKey, model, requestedModel, sourceFormat string, stream bool) *TrackedRequest {
	if reqID != "" {
		if existing, ok := s.byRequestID[reqID]; ok {
			return existing
		}
	} else {
		reqID = fmt.Sprintf("anon-%d", time.Now().UnixNano())
	}
	tr := &TrackedRequest{
		RequestID:      reqID,
		APIKey:         normalizeAPIKey(apiKey),
		Model:          strings.TrimSpace(model),
		RequestedModel: strings.TrimSpace(requestedModel),
		SourceFormat:   strings.TrimSpace(sourceFormat),
		Stream:         stream,
		StartedAt:      time.Now(),
	}
	s.byRequestID[reqID] = tr
	return tr
}

func isInvalidKeyID(k string) bool {
	v := strings.TrimSpace(k)
	if v == "" || v == "__anonymous__" || strings.EqualFold(v, "anonymous") {
		return true
	}
	if v == "sk-tenant-alpha-prod" || v == "sk-tenant-beta-dev" {
		return true
	}
	return false
}

func isInvalidModelID(m string) bool {
	v := strings.TrimSpace(m)
	return v == "" || strings.EqualFold(v, "unknown")
}

// reconcileTrackerDeltaLocked applies the request count (at most once) and any newly discovered
// token deltas for `tr` to the cumulative key/model statistics.
func (s *Store) reconcileTrackerDeltaLocked(tr *TrackedRequest) {
	apiKey := normalizeAPIKey(tr.APIKey)
	if isInvalidKeyID(apiKey) {
		return
	}
	model := s.canonicalBillingModel(tr)
	if tr.BilledModel != "" && !isInvalidModelID(tr.BilledModel) {
		model = tr.BilledModel
	} else if !isInvalidModelID(model) {
		tr.BilledModel = model
	}
	if isInvalidModelID(model) {
		return
	}

	ks := s.getOrCreateKeyStatsLocked(apiKey, tr.KeyName)
	ms := s.getOrCreateModelStatsLocked(ks, model)
	nowStr := time.Now().UTC().Format(time.RFC3339)

	// 1. Apply request count once
	if !tr.CountedRequest {
		tr.CountedRequest = true
		ks.TotalRequests++
		ms.Requests++
		if tr.Failed {
			ks.FailedRequests++
			ms.FailedRequests++
		} else {
			ks.SuccessRequests++
			ms.SuccessRequests++
		}
		ks.LastRequestAt = nowStr
		ms.LastUsedAt = nowStr
		s.dirty = true
	}

	// 2. Compute token deltas between ExtractedUsage and already BilledUsage
	target := MergeMaxUsage(tr.BilledUsage, tr.ExtractedUsage)
	dIn := target.UncachedInputTokens - tr.BilledUsage.UncachedInputTokens
	dOut := target.OutputTokens - tr.BilledUsage.OutputTokens
	dReason := target.ReasoningTokens - tr.BilledUsage.ReasoningTokens
	dRead := target.CacheReadTokens - tr.BilledUsage.CacheReadTokens
	dWrite := target.CacheWriteTokens - tr.BilledUsage.CacheWriteTokens

	if dIn <= 0 && dOut <= 0 && dReason <= 0 && dRead <= 0 && dWrite <= 0 {
		// Refresh unit price display even if 0 tokens
		if ms.UnitPricePer1M.Source == "" {
			if p, ok := s.pricing.Lookup(tr.ExtractedUsage.ResponseModel, tr.Model, tr.RequestedModel, model); ok {
				ms.UnitPricePer1M = p
			}
		}
		return
	}

	if dIn < 0 {
		dIn = 0
	}
	if dOut < 0 {
		dOut = 0
	}
	if dReason < 0 {
		dReason = 0
	}
	if dRead < 0 {
		dRead = 0
	}
	if dWrite < 0 {
		dWrite = 0
	}
	dTotal := dIn + dOut + dRead + dWrite

	costBreakdown := s.pricing.Calculate(dIn, dOut, dRead, dWrite, tr.ExtractedUsage.ResponseModel, tr.Model, tr.RequestedModel, model)
	tr.BilledUsage = target

	// Update ModelStats
	ms.InputTokens += dIn
	ms.OutputTokens += dOut
	ms.ReasoningTokens += dReason
	ms.CacheReadTokens += dRead
	ms.CacheWriteTokens += dWrite
	ms.TotalTokens += dTotal
	ms.CostNanoUSD += costBreakdown.NanoUSD
	ms.CostUSD = pricing.NanoToUSD(ms.CostNanoUSD)
	ms.CostFormatted = pricing.FormatUSD(ms.CostNanoUSD)
	ms.UnitPricePer1M = costBreakdown.UnitPrice
	ms.LastUsedAt = nowStr

	// Update KeyStats
	ks.InputTokens += dIn
	ks.OutputTokens += dOut
	ks.ReasoningTokens += dReason
	ks.CacheReadTokens += dRead
	ks.CacheWriteTokens += dWrite
	ks.TotalTokens += dTotal
	ks.TotalCostNanoUSD += costBreakdown.NanoUSD
	ks.TotalCostUSD = pricing.NanoToUSD(ks.TotalCostNanoUSD)
	ks.TotalCostFormatted = pricing.FormatUSD(ks.TotalCostNanoUSD)
	ks.LastRequestAt = nowStr

	s.dirty = true
}

func (s *Store) canonicalBillingModel(tr *TrackedRequest) string {
	for _, cand := range []string{tr.Model, tr.RequestedModel, tr.ExtractedUsage.ResponseModel} {
		cand = strings.TrimSpace(cand)
		if !isInvalidModelID(cand) {
			return cand
		}
	}
	return ""
}

func (s *Store) getOrCreateKeyStatsLocked(apiKey, keyName string) *KeyStats {
	ks, ok := s.keys[apiKey]
	if !ok {
		ks = &KeyStats{
			APIKey:             apiKey,
			MaskedKey:          MaskAPIKey(apiKey),
			KeyName:            keyName,
			TotalCostFormatted: "$0.000000",
			Models:             make(map[string]*ModelStats),
		}
		s.keys[apiKey] = ks
	} else if keyName != "" && ks.KeyName == "" {
		ks.KeyName = keyName
	}
	return ks
}

func (s *Store) getOrCreateModelStatsLocked(ks *KeyStats, model string) *ModelStats {
	if ks.Models == nil {
		ks.Models = make(map[string]*ModelStats)
	}
	ms, ok := ks.Models[model]
	if !ok {
		ms = &ModelStats{
			Model:         model,
			CostFormatted: "$0.000000",
		}
		ks.Models[model] = ms
	}
	return ms
}

// Snapshot returns a deep copy of current usage stats enriched with live active concurrency counts.
func (s *Store) Snapshot(filterAPIKey, filterModel string, activeByKey map[string]int, maxConcByKey map[string]int, keyNames map[string]string, maskKeys bool) PersistedSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	filterKey := strings.TrimSpace(filterAPIKey)
	filterMod := strings.ToLower(strings.TrimSpace(filterModel))

	// Include all configured keys or valid keys with stats
	allKeyIDs := make(map[string]struct{}, len(s.keys)+len(keyNames)+len(maxConcByKey))
	for k := range s.keys {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}
	for k := range keyNames {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}
	for k := range maxConcByKey {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}

	outKeys := make(map[string]*KeyStats, len(allKeyIDs))
	for k := range allKeyIDs {
		if isInvalidKeyID(k) {
			continue
		}
		if filterKey != "" && k != filterKey && MaskAPIKey(k) != filterKey {
			continue
		}
		src, exists := s.keys[k]
		var cpKey KeyStats
		if exists {
			cpKey = *src
		} else {
			cpKey = KeyStats{
				APIKey:             k,
				MaskedKey:          MaskAPIKey(k),
				KeyName:            keyNames[k],
				TotalCostFormatted: "$0.000000",
			}
		}
		if name, ok := keyNames[k]; ok && name != "" {
			cpKey.KeyName = name
		}
		if activeByKey != nil {
			cpKey.ActiveConcurrency = activeByKey[k]
		}
		if maxConcByKey != nil {
			cpKey.MaxConcurrency = maxConcByKey[k]
		}
		if maskKeys {
			cpKey.APIKey = ""
		}

		cpModels := make(map[string]*ModelStats)
		var sumReq, sumOk, sumFail, sumIn, sumOut, sumReason, sumRead, sumWrite, sumTotal, sumNano int64
		if exists && src.Models != nil {
			for mName, mStat := range src.Models {
				if mStat == nil || isInvalidModelID(mName) || isInvalidModelID(mStat.Model) {
					continue
				}
				if filterMod != "" && !strings.Contains(strings.ToLower(mName), filterMod) {
					continue
				}
				mCopy := *mStat
				mCopy.CostUSD = pricing.NanoToUSD(mCopy.CostNanoUSD)
				mCopy.CostFormatted = pricing.FormatUSD(mCopy.CostNanoUSD)
				cpModels[mName] = &mCopy

				sumReq += mCopy.Requests
				sumOk += mCopy.SuccessRequests
				sumFail += mCopy.FailedRequests
				sumIn += mCopy.InputTokens
				sumOut += mCopy.OutputTokens
				sumReason += mCopy.ReasoningTokens
				sumRead += mCopy.CacheReadTokens
				sumWrite += mCopy.CacheWriteTokens
				sumTotal += mCopy.TotalTokens
				sumNano += mCopy.CostNanoUSD
			}
		}
		cpKey.Models = cpModels
		if filterMod == "" && exists {
			cpKey.TotalRequests = sumReq
			cpKey.SuccessRequests = sumOk
			cpKey.FailedRequests = sumFail
			cpKey.InputTokens = sumIn
			cpKey.OutputTokens = sumOut
			cpKey.ReasoningTokens = sumReason
			cpKey.CacheReadTokens = sumRead
			cpKey.CacheWriteTokens = sumWrite
			cpKey.TotalTokens = sumTotal
			cpKey.TotalCostNanoUSD = sumNano
		}
		cpKey.TotalCostUSD = pricing.NanoToUSD(cpKey.TotalCostNanoUSD)
		cpKey.TotalCostFormatted = pricing.FormatUSD(cpKey.TotalCostNanoUSD)

		mapKey := k
		if maskKeys {
			mapKey = MaskAPIKey(k)
		}
		outKeys[mapKey] = &cpKey
	}

	return PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      outKeys,
	}
}

// Reset clears statistics either for a specific API Key or globally (when apiKey is empty).
func (s *Store) Reset(apiKey string) error {
	target := strings.TrimSpace(apiKey)
	s.mu.Lock()
	if target == "" {
		s.keys = make(map[string]*KeyStats)
		s.byRequestID = make(map[string]*TrackedRequest)
		s.byTraceID = make(map[string]*TrackedRequest)
		s.seenHostReqID = make(map[string]time.Time)
	} else {
		delete(s.keys, target)
	}
	s.dirty = true
	s.mu.Unlock()
	return s.FlushNow()
}

// FlushIfDirty writes the snapshot to disk only if new usage has been recorded since the last flush.
func (s *Store) FlushIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.storageFile == "" {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.FlushNow()
}

// FlushNow atomically writes the full usage statistics snapshot to `storageFile`.
func (s *Store) FlushNow() error {
	s.mu.Lock()
	targetFile := s.storageFile
	if targetFile == "" {
		s.mu.Unlock()
		return nil
	}
	snap := PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      make(map[string]*KeyStats, len(s.keys)),
	}
	for k, v := range s.keys {
		cp := *v
		cp.TotalCostUSD = pricing.NanoToUSD(cp.TotalCostNanoUSD)
		cp.TotalCostFormatted = pricing.FormatUSD(cp.TotalCostNanoUSD)
		cp.Models = make(map[string]*ModelStats, len(v.Models))
		for mk, mv := range v.Models {
			mcp := *mv
			mcp.CostUSD = pricing.NanoToUSD(mcp.CostNanoUSD)
			mcp.CostFormatted = pricing.FormatUSD(mcp.CostNanoUSD)
			cp.Models[mk] = &mcp
		}
		snap.Keys[k] = &cp
	}
	s.dirty = false
	s.mu.Unlock()

	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomicallyWindowsSafe(targetFile, raw)
}

func (s *Store) loadFromDisk(filePath string) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var snap PersistedSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("unmarshal usage stats from %s: %w", filePath, err)
	}

	s.mu.Lock()
	if s.keys == nil {
		s.keys = make(map[string]*KeyStats)
	}
	cleanedDisk := false
	for k, ks := range snap.Keys {
		if ks == nil {
			cleanedDisk = true
			continue
		}
		if ks.APIKey == "" {
			ks.APIKey = k
		}
		if isInvalidKeyID(k) || isInvalidKeyID(ks.APIKey) {
			cleanedDisk = true
			continue
		}
		ks.MaskedKey = MaskAPIKey(ks.APIKey)
		validModels := make(map[string]*ModelStats)
		var sumReq, sumOk, sumFail, sumIn, sumOut, sumReason, sumRead, sumWrite, sumTotal, sumNano int64
		for mk, ms := range ks.Models {
			if ms == nil {
				cleanedDisk = true
				continue
			}
			if ms.Model == "" {
				ms.Model = mk
			}
			if isInvalidModelID(mk) || isInvalidModelID(ms.Model) {
				cleanedDisk = true
				continue
			}
			if ms.CostNanoUSD == 0 && ms.CostUSD > 0 {
				ms.CostNanoUSD = int64(ms.CostUSD * float64(pricing.NanoUSDPerUSD))
			}
			ms.CostUSD = pricing.NanoToUSD(ms.CostNanoUSD)
			ms.CostFormatted = pricing.FormatUSD(ms.CostNanoUSD)
			validModels[ms.Model] = ms

			sumReq += ms.Requests
			sumOk += ms.SuccessRequests
			sumFail += ms.FailedRequests
			sumIn += ms.InputTokens
			sumOut += ms.OutputTokens
			sumReason += ms.ReasoningTokens
			sumRead += ms.CacheReadTokens
			sumWrite += ms.CacheWriteTokens
			sumTotal += ms.TotalTokens
			sumNano += ms.CostNanoUSD
		}
		if len(validModels) == 0 {
			cleanedDisk = true
			continue
		}
		ks.Models = validModels
		ks.TotalRequests = sumReq
		ks.SuccessRequests = sumOk
		ks.FailedRequests = sumFail
		ks.InputTokens = sumIn
		ks.OutputTokens = sumOut
		ks.ReasoningTokens = sumReason
		ks.CacheReadTokens = sumRead
		ks.CacheWriteTokens = sumWrite
		ks.TotalTokens = sumTotal
		ks.TotalCostNanoUSD = sumNano
		ks.TotalCostUSD = pricing.NanoToUSD(ks.TotalCostNanoUSD)
		ks.TotalCostFormatted = pricing.FormatUSD(ks.TotalCostNanoUSD)
		s.keys[ks.APIKey] = ks
	}
	if cleanedDisk {
		s.dirty = true
	}
	s.mu.Unlock()
	if cleanedDisk {
		_ = s.FlushIfDirty()
	}
	return nil
}

func (s *Store) evictOldTrackers(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, tr := range s.byRequestID {
		refTime := tr.CompletedAt
		if refTime.IsZero() {
			refTime = tr.StartedAt
		}
		if refTime.Before(cutoff) {
			delete(s.byRequestID, id)
			if tr.TraceID != "" {
				delete(s.byTraceID, tr.TraceID)
			}
		}
	}
	for id, ts := range s.seenHostReqID {
		if ts.Before(cutoff) {
			delete(s.seenHostReqID, id)
		}
	}
}

func normalizeAPIKey(apiKey string) string {
	k := strings.TrimSpace(apiKey)
	if k == "" {
		return "__anonymous__"
	}
	return k
}

// MaskAPIKey masks an API key for safe display (e.g. "sk-tenant-alpha-001" -> "sk-tena...a-001").
func MaskAPIKey(key string) string {
	k := strings.TrimSpace(key)
	if k == "" || k == "__anonymous__" {
		return "anonymous"
	}
	if len(k) <= 8 {
		return k[:2] + "***"
	}
	if len(k) <= 14 {
		return k[:4] + "..." + k[len(k)-3:]
	}
	return k[:7] + "..." + k[len(k)-5:]
}

// SortedKeyIDs returns sorted keys from a PersistedSnapshot map.
func SortedKeyIDs(m map[string]*KeyStats) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GetKeyCostUSD returns the accumulated USD cost for a given API key in O(1) time.
func (s *Store) GetKeyCostUSD(apiKey string) float64 {
	k := normalizeAPIKey(apiKey)
	s.mu.Lock()
	ks, ok := s.keys[k]
	var nano int64
	if ok && ks != nil {
		nano = ks.TotalCostNanoUSD
	}
	s.mu.Unlock()
	if nano <= 0 {
		return 0
	}
	return pricing.NanoToUSD(nano)
}

// WriteFileAtomically writes data to a temporary file, syncs it, and renames it over targetPath
// with a lightweight retry loop (3 retries, 20ms sleep each) to prevent transient Windows file lock errors.
func WriteFileAtomically(targetPath string, data []byte) error {
	return writeFileAtomicallyWindowsSafe(targetPath, data)
}

// writeFileAtomicallyWindowsSafe writes data to a temporary file, syncs it, and renames it over targetPath
// with a lightweight retry loop (3 retries, 20ms sleep each) to prevent transient Windows file lock errors.
func writeFileAtomicallyWindowsSafe(targetPath string, data []byte) error {
	cleanPath := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", cleanPath, time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		if err := os.Rename(tmpPath, cleanPath); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	_ = os.Remove(tmpPath)
	return lastErr
}
