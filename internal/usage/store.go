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

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// tupleSeparator joins the requested and served model into one stable map key.
// It is only an internal index: readers always use the struct fields.
const tupleSeparator = " -> "

// ModelStats stores cumulative usage for one (requested model, served model) pair.
// Every request belongs to exactly one pair, so "client asked for A, upstream
// served B" is measured precisely instead of being inferred from a shared bucket.
type ModelStats struct {
	RequestedModel   string             `json:"requested_model"`
	ServedModel      string             `json:"served_model"`
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

// IsSubstituted reports whether the upstream served a different model name.
func (m *ModelStats) IsSubstituted() bool {
	if m == nil {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(m.RequestedModel), strings.TrimSpace(m.ServedModel))
}

// tupleKey builds the map key for one (requested, served) pair. When the upstream
// served what was asked for, the key is just the model name.
func tupleKey(requested, served string) string {
	requested = strings.TrimSpace(requested)
	served = strings.TrimSpace(served)
	if served == "" {
		served = requested
	}
	if requested == "" || strings.EqualFold(requested, served) {
		return served
	}
	return requested + tupleSeparator + served
}

// KeyStats stores cumulative usage for a single API Key.
type KeyStats struct {
	APIKey             string   `json:"api_key,omitempty"`
	MaskedKey          string   `json:"masked_key"`
	KeyName            string   `json:"key_name,omitempty"`
	Enabled            *bool    `json:"enabled,omitempty"`
	ActiveConcurrency  int      `json:"-"`
	MaxConcurrency     int      `json:"max_concurrency"`
	QuotaLimitUSD      float64  `json:"quota_limit_usd,omitempty"`
	AllowedModels      []string `json:"allowed_models,omitempty"`
	TotalRequests      int64    `json:"total_requests"`
	SuccessRequests    int64    `json:"success_requests"`
	FailedRequests     int64    `json:"failed_requests"`
	InputTokens        int64    `json:"input_tokens"`
	OutputTokens       int64    `json:"output_tokens"`
	ReasoningTokens    int64    `json:"reasoning_tokens"`
	CacheReadTokens    int64    `json:"cache_read_tokens"`
	CacheWriteTokens   int64    `json:"cache_write_tokens"`
	TotalTokens        int64    `json:"total_tokens"`
	TotalCostNanoUSD   int64    `json:"total_cost_nano_usd"`
	TotalCostUSD       float64  `json:"total_cost_usd"`
	TotalCostFormatted string   `json:"total_cost_formatted"`
	LastRequestAt      string   `json:"last_request_at,omitempty"`
	// Models is keyed by tupleKey(requested, served); each value carries both names.
	Models map[string]*ModelStats `json:"models"`
}

// AccountStats aggregates usage for one upstream account (provider + credential identity).
type AccountStats struct {
	Provider string `json:"provider"`
	// AuthID is the normalized account identity (a trailing credential hash is
	// stripped so several hashed keys of one provider share a single row).
	AuthID    string `json:"auth_id,omitempty"`
	AuthIndex string `json:"auth_index,omitempty"`
	AuthType  string `json:"auth_type,omitempty"`
	// AuthIDs lists the raw credential ids that were folded into this account.
	AuthIDs          []string `json:"auth_ids,omitempty"`
	Requests         int64    `json:"requests"`
	SuccessRequests  int64    `json:"success_requests"`
	FailedRequests   int64    `json:"failed_requests"`
	InputTokens      int64    `json:"input_tokens"`
	OutputTokens     int64    `json:"output_tokens"`
	ReasoningTokens  int64    `json:"reasoning_tokens"`
	CacheReadTokens  int64    `json:"cache_read_tokens"`
	CacheWriteTokens int64    `json:"cache_write_tokens"`
	TotalTokens      int64    `json:"total_tokens"`
	LastModel        string   `json:"last_model,omitempty"`
	LastRequestAt    string   `json:"last_request_at,omitempty"`
	// Models is keyed by tupleKey(requested, served) for this credential.
	Models map[string]*ModelStats `json:"models,omitempty"`
}

// PersistedSnapshot is the root JSON structure persisted to disk.
type PersistedSnapshot struct {
	Version   int                      `json:"version"`
	UpdatedAt string                   `json:"updated_at"`
	Keys      map[string]*KeyStats     `json:"keys"`
	Accounts  map[string]*AccountStats `json:"accounts,omitempty"`
	// Ledger keeps hourly usage slices that power the overview dashboard.
	Ledger []*LedgerEntry `json:"ledger,omitempty"`
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
	// BilledKey is the tuple bucket already billed for this request, if any.
	BilledKey      string
	CountedRequest bool
	Failed         bool

	// Upstream credential that actually served this request (from `usage.handle`).
	Provider  string
	AuthID    string
	AuthIndex string
	AuthType  string
}

// Store manages in-memory usage accounting, request deduplication, and atomic JSON persistence.
type Store struct {
	mu       sync.Mutex
	pricing  *pricing.Engine
	keys     map[string]*KeyStats
	accounts map[string]*AccountStats

	// Active & recently completed request trackers (for coordinating request.complete and usage.handle)
	byRequestID   map[string]*TrackedRequest
	byTraceID     map[string]*TrackedRequest
	seenHostReqID map[string]time.Time

	storageFile       string
	mirrorFiles       []string
	legacyMirrorFiles []string
	dirty             bool
	flushInterval     time.Duration
	stopFlushCh       chan struct{}
	flushStopped      chan struct{}

	// ledger holds hourly aggregated usage slices for the overview dashboard.
	ledger          map[string]*LedgerEntry
	ledgerRetention time.Duration
}

// NewStore creates a new usage Store backed by the given pricing Engine.
func NewStore(pricingEngine *pricing.Engine) *Store {
	if pricingEngine == nil {
		pricingEngine = pricing.NewEngine()
	}
	return &Store{
		pricing:         pricingEngine,
		keys:            make(map[string]*KeyStats),
		accounts:        make(map[string]*AccountStats),
		ledger:          make(map[string]*LedgerEntry),
		ledgerRetention: 90 * 24 * time.Hour,
		byRequestID:     make(map[string]*TrackedRequest),
		byTraceID:       make(map[string]*TrackedRequest),
		seenHostReqID:   make(map[string]time.Time),
	}
}

// SetMirrorFiles registers extra paths that receive a copy of the usage snapshot
// after every flush. This keeps billing history alive when the configured file
// lives in an ephemeral directory (e.g. a container's ./data).
func (s *Store) SetMirrorFiles(paths []string) {
	cleaned := cleanPathList(paths)
	s.mu.Lock()
	s.mirrorFiles = cleaned
	s.mu.Unlock()
}

// SetLegacyMirrorFiles registers older, read-only snapshot locations (for example
// `*.json` files that a previous release wrote into CLIProxyAPI's auth dir). They
// are used to restore history and are removed only after the successor snapshot
// has been durably written.
func (s *Store) SetLegacyMirrorFiles(paths []string) {
	cleaned := cleanPathList(paths)
	s.mu.Lock()
	s.legacyMirrorFiles = cleaned
	s.mu.Unlock()
}

func cleanPathList(paths []string) []string {
	cleaned := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		cleaned = append(cleaned, path)
	}
	return cleaned
}

// restoreCandidates returns every path that may hold an older snapshot: live
// mirrors first, then the read-only legacy locations.
func (s *Store) restoreCandidates() (mirrors []string, legacy []string) {
	s.mu.Lock()
	mirrors = append([]string(nil), s.mirrorFiles...)
	legacy = append([]string(nil), s.legacyMirrorFiles...)
	s.mu.Unlock()
	return mirrors, legacy
}

// adoptMirrorIfEmpty restores the configured snapshot from the newest non-empty
// mirror when the configured file is missing or empty (e.g. after the container
// recreated its ./data directory). Legacy locations participate so that an
// upgrade never drops history before it has been migrated.
func (s *Store) adoptMirrorIfEmpty(target string) {
	if target == "" {
		return
	}
	// Keep the configured snapshot when it already carries history; only replace a
	// missing or history-less file (e.g. the empty skeleton a fresh container writes).
	if raw, errRead := os.ReadFile(target); errRead == nil && len(strings.TrimSpace(string(raw))) > 0 {
		var existing PersistedSnapshot
		if errUnmarshal := json.Unmarshal(raw, &existing); errUnmarshal == nil && len(existing.Keys) > 0 {
			return
		}
	}

	mirrors, legacy := s.restoreCandidates()
	candidates := append(append([]string(nil), mirrors...), legacy...)
	if len(candidates) == 0 {
		return
	}

	bestPath := ""
	var bestSnap *PersistedSnapshot
	for _, candidate := range candidates {
		if filepath.Clean(candidate) == filepath.Clean(target) {
			continue
		}
		raw, errRead := os.ReadFile(candidate)
		if errRead != nil || len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var snap PersistedSnapshot
		if errUnmarshal := json.Unmarshal(raw, &snap); errUnmarshal != nil {
			continue
		}
		if bestSnap == nil || snap.UpdatedAt > bestSnap.UpdatedAt {
			cp := snap
			bestSnap = &cp
			bestPath = candidate
		}
	}
	if bestSnap == nil || bestPath == "" || len(bestSnap.Keys) == 0 {
		return
	}
	raw, errRead := os.ReadFile(bestPath)
	if errRead != nil {
		return
	}
	_ = writeFileAtomicallyWindowsSafe(target, raw)
}

// cleanupLegacyMirrors removes legacy snapshot files once the successor locations
// hold a snapshot, so migration can never delete the only surviving copy.
func (s *Store) cleanupLegacyMirrors() {
	s.mu.Lock()
	legacy := append([]string(nil), s.legacyMirrorFiles...)
	target := s.storageFile
	s.mu.Unlock()
	if len(legacy) == 0 || target == "" {
		return
	}
	if info, errStat := os.Stat(target); errStat != nil || info.Size() == 0 {
		return
	}
	for _, path := range legacy {
		if filepath.Clean(path) == filepath.Clean(target) {
			continue
		}
		if info, errStat := os.Stat(path); errStat == nil && !info.IsDir() {
			_ = os.Remove(path)
		}
	}
	s.mu.Lock()
	s.legacyMirrorFiles = nil
	s.mu.Unlock()
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

	s.adoptMirrorIfEmpty(cleanPath)

	s.mu.Lock()
	wasEmpty := len(s.keys) == 0
	s.storageFile = cleanPath
	s.flushInterval = flushInterval
	s.mu.Unlock()

	var loadErr error
	if cleanPath != "" && wasEmpty {
		loadErr = s.loadFromDisk(cleanPath)
	}

	// Write the migrated snapshot everywhere immediately so legacy files can be
	// dropped without risking the only copy.
	if cleanPath != "" {
		s.mu.Lock()
		hasHistory := len(s.keys) > 0
		legacyPending := len(s.legacyMirrorFiles) > 0
		s.mu.Unlock()
		if hasHistory || legacyPending {
			_ = s.FlushNow()
			s.cleanupLegacyMirrors()
		}
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
				tr.BilledKey = existingTrace.BilledKey
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
			Provider:       strings.TrimSpace(rec.Provider),
			AuthID:         strings.TrimSpace(rec.AuthID),
			AuthIndex:      strings.TrimSpace(rec.AuthIndex),
			AuthType:       strings.TrimSpace(rec.AuthType),
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
	if provider := strings.TrimSpace(rec.Provider); provider != "" {
		tr.Provider = provider
	}
	if authID := strings.TrimSpace(rec.AuthID); authID != "" {
		tr.AuthID = authID
	}
	if authIndex := strings.TrimSpace(rec.AuthIndex); authIndex != "" {
		tr.AuthIndex = authIndex
	}
	if authType := strings.TrimSpace(rec.AuthType); authType != "" {
		tr.AuthType = authType
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

// reconcileTrackerDeltaLocked applies the request count (at most once) and any newly
// discovered token deltas to the (requested model, served model) tuple buckets of the
// key and of the upstream account.
func (s *Store) reconcileTrackerDeltaLocked(tr *TrackedRequest) {
	apiKey := normalizeAPIKey(tr.APIKey)
	if isInvalidKeyID(apiKey) {
		return
	}
	requested := requestedModelOf(tr)
	if requested == "" {
		return
	}
	served := servedModelOf(tr, requested)
	key := tupleKey(requested, served)

	ks := s.getOrCreateKeyStatsLocked(apiKey, tr.KeyName)
	acct := s.getOrCreateAccountStatsLocked(tr)

	// The served model can only be learned mid-flight for a streaming response, so
	// move the slice already billed for the previous tuple onto the new one.
	if prev := strings.TrimSpace(tr.BilledKey); prev != "" && prev != key {
		migrateTupleBucket(ks.Models, prev, key, requested, served)
		if acct != nil {
			migrateTupleBucket(acct.Models, prev, key, requested, served)
		}
	}
	tr.BilledKey = key

	// 1. Compute token deltas between ExtractedUsage and already BilledUsage
	target := MergeMaxUsage(tr.BilledUsage, tr.ExtractedUsage)
	dIn := target.UncachedInputTokens - tr.BilledUsage.UncachedInputTokens
	dOut := target.OutputTokens - tr.BilledUsage.OutputTokens
	dReason := target.ReasoningTokens - tr.BilledUsage.ReasoningTokens
	dRead := target.CacheReadTokens - tr.BilledUsage.CacheReadTokens
	dWrite := target.CacheWriteTokens - tr.BilledUsage.CacheWriteTokens
	hasDelta := dIn > 0 || dOut > 0 || dReason > 0 || dRead > 0 || dWrite > 0

	// Nothing left to record (request already counted and no new tokens): return
	// before creating buckets, otherwise an idle reconcile would materialise an
	// empty tuple row with 0 requests and 0 tokens.
	if tr.CountedRequest && !hasDelta {
		if existing, ok := ks.Models[key]; ok && existing != nil && existing.UnitPricePer1M.Source == "" {
			if p, found := s.pricing.Lookup(requested, served); found {
				existing.UnitPricePer1M = p
				s.dirty = true
			}
		}
		return
	}

	ms := getOrCreateTupleStats(ks, key, requested, served)
	ams := getOrCreateAccountTupleStats(acct, key, requested, served)
	now := time.Now()
	nowStr := now.UTC().Format(time.RFC3339)

	// Ledger dimensions: bill by the client-requested (catalog) model, never by the
	// substituted upstream name, so usage history matches the model catalog.
	ledgerAccount, ledgerProvider := "", ""
	if acct != nil {
		ledgerAccount = acct.AuthID
		ledgerProvider = acct.Provider
	}
	recordLedger := func(requests, in, out, read, write, total, costNano int64) {
		s.recordLedgerLocked(now, apiKey, tr.KeyName, ledgerAccount, ledgerProvider,
			requested, served, tr.SourceFormat, requests, in, out, read, write, total, costNano)
	}

	// 2. Apply request count once
	if !tr.CountedRequest {
		tr.CountedRequest = true
		ks.TotalRequests++
		ms.Requests++
		if tr.Failed {
			ks.FailedRequests++
			ms.FailedRequests++
			if acct != nil {
				acct.FailedRequests++
			}
			if ams != nil {
				ams.FailedRequests++
			}
		} else {
			ks.SuccessRequests++
			ms.SuccessRequests++
			if acct != nil {
				acct.SuccessRequests++
			}
			if ams != nil {
				ams.SuccessRequests++
			}
		}
		if acct != nil {
			acct.Requests++
			acct.LastRequestAt = nowStr
			acct.LastModel = served
		}
		if ams != nil {
			ams.Requests++
			ams.LastUsedAt = nowStr
		}
		ks.LastRequestAt = nowStr
		ms.LastUsedAt = nowStr
		recordLedger(1, 0, 0, 0, 0, 0, 0)
		s.dirty = true
	}

	if !hasDelta {
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

	// Cost is priced from the client-requested model: upstream variant names rarely
	// have a published price, while the requested name identifies the real product.
	costBreakdown := s.pricing.Calculate(dIn, dOut, dRead, dWrite, requested, served)
	tr.BilledUsage = target

	// Update the tuple statistics
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

	// Update AccountStats (upstream credential + provider dimension)
	if acct != nil {
		acct.InputTokens += dIn
		acct.OutputTokens += dOut
		acct.ReasoningTokens += dReason
		acct.CacheReadTokens += dRead
		acct.CacheWriteTokens += dWrite
		acct.TotalTokens += dTotal
		acct.LastModel = served
		acct.LastRequestAt = nowStr
	}
	if ams != nil {
		ams.InputTokens += dIn
		ams.OutputTokens += dOut
		ams.ReasoningTokens += dReason
		ams.CacheReadTokens += dRead
		ams.CacheWriteTokens += dWrite
		ams.TotalTokens += dTotal
		ams.CostNanoUSD += costBreakdown.NanoUSD
		ams.CostUSD = pricing.NanoToUSD(ams.CostNanoUSD)
		ams.CostFormatted = pricing.FormatUSD(ams.CostNanoUSD)
		ams.LastUsedAt = nowStr
	}

	recordLedger(0, dIn, dOut, dRead, dWrite, dTotal, costBreakdown.NanoUSD)

	s.dirty = true
}

// requestedModelOf resolves the client-requested model of a tracked request.
func requestedModelOf(tr *TrackedRequest) string {
	for _, candidate := range []string{tr.RequestedModel, tr.Model} {
		if value := strings.TrimSpace(candidate); !isInvalidModelID(value) {
			return value
		}
	}
	return ""
}

// servedModelOf resolves the model the upstream actually served, defaulting to the
// requested model when the provider did not report one.
func servedModelOf(tr *TrackedRequest, requested string) string {
	if value := strings.TrimSpace(tr.ExtractedUsage.ResponseModel); !isInvalidModelID(value) {
		return value
	}
	return requested
}

// getOrCreateTupleStats returns the (requested, served) bucket of a key, creating it
// when needed.
func getOrCreateTupleStats(ks *KeyStats, key, requested, served string) *ModelStats {
	if ks.Models == nil {
		ks.Models = make(map[string]*ModelStats)
	}
	stats, ok := ks.Models[key]
	if !ok || stats == nil {
		stats = &ModelStats{RequestedModel: requested, ServedModel: served}
		ks.Models[key] = stats
	}
	if stats.RequestedModel == "" {
		stats.RequestedModel = requested
	}
	if stats.ServedModel == "" {
		stats.ServedModel = served
	}
	return stats
}

// getOrCreateAccountTupleStats is the account-level counterpart, nil-safe for
// requests that did not report a credential.
func getOrCreateAccountTupleStats(acct *AccountStats, key, requested, served string) *ModelStats {
	if acct == nil {
		return nil
	}
	if acct.Models == nil {
		acct.Models = make(map[string]*ModelStats)
	}
	stats, ok := acct.Models[key]
	if !ok || stats == nil {
		stats = &ModelStats{RequestedModel: requested, ServedModel: served}
		acct.Models[key] = stats
	}
	if stats.RequestedModel == "" {
		stats.RequestedModel = requested
	}
	if stats.ServedModel == "" {
		stats.ServedModel = served
	}
	return stats
}

// mergeTupleStats folds src into dst when two entries describe the same tuple.
func mergeTupleStats(dst, src *ModelStats) {
	if dst == nil || src == nil {
		return
	}
	dst.Requests += src.Requests
	dst.SuccessRequests += src.SuccessRequests
	dst.FailedRequests += src.FailedRequests
	dst.InputTokens += src.InputTokens
	dst.OutputTokens += src.OutputTokens
	dst.ReasoningTokens += src.ReasoningTokens
	dst.CacheReadTokens += src.CacheReadTokens
	dst.CacheWriteTokens += src.CacheWriteTokens
	dst.TotalTokens += src.TotalTokens
	dst.CostNanoUSD += src.CostNanoUSD
	dst.CostUSD = pricing.NanoToUSD(dst.CostNanoUSD)
	dst.CostFormatted = pricing.FormatUSD(dst.CostNanoUSD)
	if dst.UnitPricePer1M.Source == "" {
		dst.UnitPricePer1M = src.UnitPricePer1M
	}
	if src.LastUsedAt > dst.LastUsedAt {
		dst.LastUsedAt = src.LastUsedAt
	}
}

// migrateTupleBucket moves an already billed tuple onto the tuple that just became
// known (a streaming response reveals the served model mid-flight), merging when the
// destination already exists.
func migrateTupleBucket(models map[string]*ModelStats, from, to, requested, served string) {
	if models == nil || from == "" || to == "" || from == to {
		return
	}
	src, ok := models[from]
	if !ok || src == nil {
		return
	}
	dst, exists := models[to]
	if !exists || dst == nil {
		src.RequestedModel = requested
		src.ServedModel = served
		models[to] = src
		delete(models, from)
		return
	}
	dst.Requests += src.Requests
	dst.SuccessRequests += src.SuccessRequests
	dst.FailedRequests += src.FailedRequests
	dst.InputTokens += src.InputTokens
	dst.OutputTokens += src.OutputTokens
	dst.ReasoningTokens += src.ReasoningTokens
	dst.CacheReadTokens += src.CacheReadTokens
	dst.CacheWriteTokens += src.CacheWriteTokens
	dst.TotalTokens += src.TotalTokens
	dst.CostNanoUSD += src.CostNanoUSD
	dst.CostUSD = pricing.NanoToUSD(dst.CostNanoUSD)
	dst.CostFormatted = pricing.FormatUSD(dst.CostNanoUSD)
	if dst.UnitPricePer1M.Source == "" {
		dst.UnitPricePer1M = src.UnitPricePer1M
	}
	if src.LastUsedAt > dst.LastUsedAt {
		dst.LastUsedAt = src.LastUsedAt
	}
	delete(models, from)
}

// normalizeAccountIdentity collapses credential ids that differ only by a
// trailing hash into a single account identity. CLIProxyAPI names inline
// openai-compatibility credentials as `<provider>:<name>:<hash>`, so several
// hashed keys of the same configured provider must share a single row:
//
//	openai-compatibility:上海人工智能实验室:5dfdf0f0b3d3 -> openai-compatibility:上海人工智能实验室
//	antigravity-sly538876@gmail.com.json              -> unchanged
func normalizeAccountIdentity(authID string) string {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ""
	}
	if !strings.Contains(authID, ":") {
		return authID
	}
	parts := strings.Split(authID, ":")
	if len(parts) < 2 {
		return authID
	}
	last := strings.TrimSpace(parts[len(parts)-1])
	if !looksLikeCredentialHash(last) {
		return authID
	}
	return strings.Join(parts[:len(parts)-1], ":")
}

// looksLikeCredentialHash reports whether a trailing segment is an opaque hex
// hash rather than a meaningful account name.
func looksLikeCredentialHash(segment string) bool {
	if len(segment) < 6 || len(segment) > 64 {
		return false
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

// accountBucketKey builds the stable identifier for one upstream account. The
// identity is the normalized credential id, so one configured provider with
// several hashed credentials produces a single aggregated row; requests without
// a credential id fall back to the provider name.
func accountBucketKey(provider, authID, authIndex string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	identity := normalizeAccountIdentity(authID)
	if identity == "" {
		identity = normalizeAccountIdentity(authIndex)
	}
	if identity != "" {
		return "account::" + identity
	}
	if provider == "" {
		return ""
	}
	return "provider::" + provider
}

// getOrCreateAccountStatsLocked returns the account bucket for a tracked request,
// or nil when the host did not report which credential served it.
func (s *Store) getOrCreateAccountStatsLocked(tr *TrackedRequest) *AccountStats {
	key := accountBucketKey(tr.Provider, tr.AuthID, tr.AuthIndex)
	if key == "" {
		return nil
	}
	if s.accounts == nil {
		s.accounts = make(map[string]*AccountStats)
	}
	displayID := normalizeAccountIdentity(tr.AuthID)
	if displayID == "" {
		displayID = normalizeAccountIdentity(tr.AuthIndex)
	}
	provider := strings.TrimSpace(tr.Provider)
	acct, ok := s.accounts[key]
	if !ok || acct == nil {
		acct = &AccountStats{
			Provider:  provider,
			AuthID:    displayID,
			AuthIndex: strings.TrimSpace(tr.AuthIndex),
			AuthType:  strings.TrimSpace(tr.AuthType),
			Models:    make(map[string]*ModelStats),
		}
		s.accounts[key] = acct
	} else if provider != "" {
		// Several credentials (or providers) can feed one account identity; expose
		// that aggregate as "mixed" instead of silently picking the first one.
		if acct.Provider == "" {
			acct.Provider = provider
		} else if !strings.EqualFold(acct.Provider, provider) {
			acct.Provider = "mixed"
		}
	}
	if rawID := strings.TrimSpace(tr.AuthID); rawID != "" && rawID != displayID {
		acct.AuthIDs = appendUniqueAccountID(acct.AuthIDs, rawID)
	}
	if acct.AuthIndex == "" && tr.AuthIndex != "" {
		acct.AuthIndex = strings.TrimSpace(tr.AuthIndex)
	}
	if acct.AuthType == "" && tr.AuthType != "" {
		acct.AuthType = strings.TrimSpace(tr.AuthType)
	}
	return acct
}

// mergeAccountStats folds src into dst (used when legacy snapshots are re-keyed
// onto the same normalized account identity).
func mergeAccountStats(dst, src *AccountStats) {
	if dst == nil || src == nil {
		return
	}
	dst.Requests += src.Requests
	dst.SuccessRequests += src.SuccessRequests
	dst.FailedRequests += src.FailedRequests
	dst.InputTokens += src.InputTokens
	dst.OutputTokens += src.OutputTokens
	dst.ReasoningTokens += src.ReasoningTokens
	dst.CacheReadTokens += src.CacheReadTokens
	dst.CacheWriteTokens += src.CacheWriteTokens
	dst.TotalTokens += src.TotalTokens
	if src.LastRequestAt > dst.LastRequestAt {
		dst.LastRequestAt = src.LastRequestAt
	}
	if src.LastModel != "" {
		dst.LastModel = src.LastModel
	}
	if dst.AuthIndex == "" {
		dst.AuthIndex = src.AuthIndex
	}
	if dst.AuthType == "" {
		dst.AuthType = src.AuthType
	}
	if dst.AuthID == "" {
		dst.AuthID = src.AuthID
	}
	if dst.Provider == "" {
		dst.Provider = src.Provider
	} else if src.Provider != "" && !strings.EqualFold(dst.Provider, src.Provider) {
		dst.Provider = "mixed"
	}
	for _, id := range src.AuthIDs {
		dst.AuthIDs = appendUniqueAccountID(dst.AuthIDs, id)
	}
	if len(src.Models) > 0 {
		if dst.Models == nil {
			dst.Models = make(map[string]*ModelStats)
		}
		for model, stats := range src.Models {
			if stats == nil {
				continue
			}
			existing, ok := dst.Models[model]
			if !ok || existing == nil {
				dst.Models[model] = stats
				continue
			}
			existing.Requests += stats.Requests
			existing.SuccessRequests += stats.SuccessRequests
			existing.FailedRequests += stats.FailedRequests
			existing.InputTokens += stats.InputTokens
			existing.OutputTokens += stats.OutputTokens
			existing.ReasoningTokens += stats.ReasoningTokens
			existing.CacheReadTokens += stats.CacheReadTokens
			existing.CacheWriteTokens += stats.CacheWriteTokens
			existing.TotalTokens += stats.TotalTokens
			existing.CostNanoUSD += stats.CostNanoUSD
			existing.CostUSD = pricing.NanoToUSD(existing.CostNanoUSD)
			existing.CostFormatted = pricing.FormatUSD(existing.CostNanoUSD)
			if stats.LastUsedAt > existing.LastUsedAt {
				existing.LastUsedAt = stats.LastUsedAt
			}
		}
	}
}

// appendUniqueAccountID records a raw credential id that was folded into a
// normalized account bucket (capped so a pathological config cannot bloat the file).
func appendUniqueAccountID(ids []string, rawID string) []string {
	rawID = strings.TrimSpace(rawID)
	if rawID == "" {
		return ids
	}
	for _, existing := range ids {
		if existing == rawID {
			return ids
		}
	}
	if len(ids) >= 16 {
		return ids
	}
	return append(ids, rawID)
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
			for tuple, mStat := range src.Models {
				if mStat == nil {
					continue
				}
				// A filter matches either side of the tuple so searching the requested
				// name and the served name both work.
				if filterMod != "" &&
					!strings.Contains(strings.ToLower(mStat.RequestedModel), filterMod) &&
					!strings.Contains(strings.ToLower(mStat.ServedModel), filterMod) {
					continue
				}
				mCopy := *mStat
				mCopy.CostUSD = pricing.NanoToUSD(mCopy.CostNanoUSD)
				mCopy.CostFormatted = pricing.FormatUSD(mCopy.CostNanoUSD)
				cpModels[tuple] = &mCopy

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
		Accounts:  s.snapshotAccountsLocked(),
	}
}

// snapshotAccountsLocked copies the account buckets for read-only delivery.
func (s *Store) snapshotAccountsLocked() map[string]*AccountStats {
	if len(s.accounts) == 0 {
		return nil
	}
	out := make(map[string]*AccountStats, len(s.accounts))
	for k, v := range s.accounts {
		if v == nil {
			continue
		}
		cp := *v
		if len(v.Models) > 0 {
			cp.Models = make(map[string]*ModelStats, len(v.Models))
			for mk, mv := range v.Models {
				if mv == nil {
					continue
				}
				mcp := *mv
				mcp.CostUSD = pricing.NanoToUSD(mcp.CostNanoUSD)
				mcp.CostFormatted = pricing.FormatUSD(mcp.CostNanoUSD)
				cp.Models[mk] = &mcp
			}
		}
		out[k] = &cp
	}
	return out
}

// Reset clears statistics either for a specific API Key or globally (when apiKey is empty).
func (s *Store) Reset(apiKey string) error {
	target := strings.TrimSpace(apiKey)
	s.mu.Lock()
	if target == "" {
		s.keys = make(map[string]*KeyStats)
		s.accounts = make(map[string]*AccountStats)
		s.ledger = make(map[string]*LedgerEntry)
		s.byRequestID = make(map[string]*TrackedRequest)
		s.byTraceID = make(map[string]*TrackedRequest)
		s.seenHostReqID = make(map[string]time.Time)
	} else {
		delete(s.keys, target)
		for key, entry := range s.ledger {
			if entry != nil && entry.APIKey == target {
				delete(s.ledger, key)
			}
		}
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
	mirrors := append([]string(nil), s.mirrorFiles...)
	if targetFile == "" {
		s.mu.Unlock()
		return nil
	}
	snap := PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      make(map[string]*KeyStats, len(s.keys)),
		Accounts:  make(map[string]*AccountStats, len(s.accounts)),
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
	for k, v := range s.accounts {
		if v == nil {
			continue
		}
		acp := *v
		if len(v.Models) > 0 {
			acp.Models = make(map[string]*ModelStats, len(v.Models))
			for mk, mv := range v.Models {
				if mv == nil {
					continue
				}
				mcp := *mv
				mcp.CostUSD = pricing.NanoToUSD(mcp.CostNanoUSD)
				mcp.CostFormatted = pricing.FormatUSD(mcp.CostNanoUSD)
				acp.Models[mk] = &mcp
			}
		}
		snap.Accounts[k] = &acp
	}
	s.pruneLedgerLocked(time.Now())
	if len(s.ledger) > 0 {
		snap.Ledger = make([]*LedgerEntry, 0, len(s.ledger))
		for _, entry := range s.ledger {
			if entry == nil {
				continue
			}
			cp := *entry
			snap.Ledger = append(snap.Ledger, &cp)
		}
		sort.Slice(snap.Ledger, func(i, j int) bool {
			if snap.Ledger[i].Hour != snap.Ledger[j].Hour {
				return snap.Ledger[i].Hour < snap.Ledger[j].Hour
			}
			return snap.Ledger[i].Model < snap.Ledger[j].Model
		})
	}
	s.dirty = false
	s.mu.Unlock()

	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	errWrite := writeFileAtomicallyWindowsSafe(targetFile, raw)
	for _, mirror := range mirrors {
		if mirror == targetFile {
			continue
		}
		_ = writeFileAtomicallyWindowsSafe(mirror, raw)
	}
	return errWrite
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
	if s.ledger == nil {
		s.ledger = make(map[string]*LedgerEntry)
	}
	for _, entry := range snap.Ledger {
		if entry == nil || entry.Hour <= 0 || strings.TrimSpace(entry.Model) == "" {
			continue
		}
		s.ledger[ledgerEntryKey(entry.Hour, entry.APIKey, entry.Account, entry.Model, entry.Source)] = entry
	}
	s.pruneLedgerLocked(time.Now())
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
		for tuple, ms := range ks.Models {
			if ms == nil {
				cleanedDisk = true
				continue
			}
			if ms.ServedModel == "" || isInvalidModelID(ms.ServedModel) {
				// Entries written before the tuple rewrite carry only a served name;
				// treat them as "requested == served" so the values stay usable.
				if !isInvalidModelID(tuple) {
					ms.ServedModel = tuple
					if ms.RequestedModel == "" {
						ms.RequestedModel = tuple
					}
					cleanedDisk = true
				}
			}
			if ms.RequestedModel == "" {
				ms.RequestedModel = ms.ServedModel
			}
			if isInvalidModelID(ms.ServedModel) || isInvalidModelID(ms.RequestedModel) {
				cleanedDisk = true
				continue
			}
			// Drop tuples that never recorded anything.
			if ms.Requests == 0 && ms.TotalTokens == 0 && ms.CostNanoUSD == 0 {
				cleanedDisk = true
				continue
			}
			if ms.CostNanoUSD == 0 && ms.CostUSD > 0 {
				ms.CostNanoUSD = int64(ms.CostUSD * float64(pricing.NanoUSDPerUSD))
			}
			ms.CostUSD = pricing.NanoToUSD(ms.CostNanoUSD)
			ms.CostFormatted = pricing.FormatUSD(ms.CostNanoUSD)
			normalizedKey := tupleKey(ms.RequestedModel, ms.ServedModel)
			if normalizedKey != tuple {
				cleanedDisk = true
				if existing, ok := validModels[normalizedKey]; ok && existing != nil {
					mergeTupleStats(existing, ms)
					continue
				}
			}
			validModels[normalizedKey] = ms

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
	if s.accounts == nil {
		s.accounts = make(map[string]*AccountStats)
	}
	for _, acct := range snap.Accounts {
		if acct == nil {
			cleanedDisk = true
			continue
		}
		// Re-key on load so snapshots written before account identities were
		// normalized collapse into one row instead of producing duplicates.
		key := accountBucketKey(acct.Provider, acct.AuthID, acct.AuthIndex)
		if key == "" {
			cleanedDisk = true
			continue
		}
		if rawID := strings.TrimSpace(acct.AuthID); rawID != "" {
			if normalized := normalizeAccountIdentity(rawID); normalized != rawID {
				acct.AuthIDs = appendUniqueAccountID(acct.AuthIDs, rawID)
				acct.AuthID = normalized
				cleanedDisk = true
			}
		}
		if acct.AuthID == "" {
			acct.AuthID = normalizeAccountIdentity(acct.AuthIndex)
		}
		if acct.Models == nil {
			acct.Models = make(map[string]*ModelStats)
		}
		for tuple, mv := range acct.Models {
			if mv == nil {
				delete(acct.Models, tuple)
				cleanedDisk = true
				continue
			}
			if mv.ServedModel == "" || isInvalidModelID(mv.ServedModel) {
				if !isInvalidModelID(tuple) {
					mv.ServedModel = tuple
					if mv.RequestedModel == "" {
						mv.RequestedModel = tuple
					}
					cleanedDisk = true
				}
			}
			if mv.RequestedModel == "" {
				mv.RequestedModel = mv.ServedModel
			}
			if isInvalidModelID(mv.ServedModel) || isInvalidModelID(mv.RequestedModel) {
				delete(acct.Models, tuple)
				cleanedDisk = true
				continue
			}
			if mv.Requests == 0 && mv.TotalTokens == 0 && mv.CostNanoUSD == 0 {
				delete(acct.Models, tuple)
				cleanedDisk = true
				continue
			}
			mv.CostUSD = pricing.NanoToUSD(mv.CostNanoUSD)
			mv.CostFormatted = pricing.FormatUSD(mv.CostNanoUSD)
			normalizedKey := tupleKey(mv.RequestedModel, mv.ServedModel)
			if normalizedKey != tuple {
				delete(acct.Models, tuple)
				cleanedDisk = true
				if existing, ok := acct.Models[normalizedKey]; ok && existing != nil {
					mergeTupleStats(existing, mv)
					continue
				}
				acct.Models[normalizedKey] = mv
			}
		}
		// Drop account buckets that hold no data at all.
		if acct.Requests == 0 && acct.TotalTokens == 0 && len(acct.Models) == 0 {
			cleanedDisk = true
			continue
		}
		if existing, ok := s.accounts[key]; ok && existing != nil {
			mergeAccountStats(existing, acct)
		} else {
			s.accounts[key] = acct
		}
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
