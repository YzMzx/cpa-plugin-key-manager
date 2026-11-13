package usage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
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

// PersistedSnapshot is the public usage snapshot assembled from live SQLite-backed state.
type PersistedSnapshot struct {
	Version   int                      `json:"version"`
	UpdatedAt string                   `json:"updated_at"`
	Keys      map[string]*KeyStats     `json:"keys"`
	Accounts  map[string]*AccountStats `json:"accounts,omitempty"`
	// Ledger keeps hourly usage slices that power the overview dashboard.
	Ledger []*LedgerEntry `json:"ledger,omitempty"`
}

// ledgerStamp records exactly what one request contributed to the ledger so a late
// failure can be undone again.
type ledgerStamp struct {
	hour                           int64
	apiKey, account, model, source string
	requests, in, out, read, write int64
	total, cost                    int64
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

	ExtractedUsage       NormalizedUsage
	BilledUsage          NormalizedUsage
	billedStats          ModelStats
	billedAccountKey     string
	billedPrice          pricing.ModelPrice
	billedPriceFound     bool
	billedPriceRank      int
	billedPriceRequested string
	billedPriceServed    string
	billedQuotaCost      int64
	displayReset         bool
	// BilledKey is the tuple bucket already billed for this request, if any.
	BilledKey         string
	CountedRequest    bool
	Failed            bool
	HostRequestID     string
	HostUsageRecorded bool
	LogicalRequest    bool
	CompletionKnown   bool

	// ledgerStamps are the ledger slices this request already contributed; they are
	// subtracted when the request is later reported as failed.
	ledgerStamps []ledgerStamp

	// Upstream credential that actually served this request (from `usage.handle`).
	Provider  string
	AuthID    string
	AuthIndex string
	AuthType  string
}

// Store manages in-memory usage accounting, request deduplication, and SQLite persistence.
type Store struct {
	// Lock order: lifecycleMu -> flushMu -> mu. Request accounting only takes mu.
	lifecycleMu            sync.Mutex
	flushMu                sync.Mutex
	lastPersistenceSuccess time.Time
	lastPersistenceError   string
	lastAccountingError    string
	flushInProgress        bool
	closing                bool
	mu                     sync.Mutex
	pricing                *pricing.Engine
	keys                   map[string]*KeyStats
	quotaCosts             map[string]int64
	dirtyQuota             map[string]struct{}
	accounts               map[string]*AccountStats

	// Active & recently completed request trackers (for coordinating request.complete and usage.handle)
	byRequestID   map[string]*TrackedRequest
	byTraceID     map[string]*TrackedRequest
	seenHostReqID map[string]time.Time

	dirty         bool
	flushInterval time.Duration
	stopFlushCh   chan struct{}
	flushStopped  chan struct{}

	// ledger holds hourly aggregated usage slices for the overview dashboard.
	ledger          map[string]*LedgerEntry
	ledgerByHour    map[int64]map[string]*LedgerEntry
	ledgerRetention time.Duration

	// db is the SQLite database; it is the only persistence backend on this branch.
	db *sqlitestore.DB

	// Incremental flush bookkeeping: only rows touched since the last flush are
	// rewritten, and removals are deleted explicitly.
	dirtyKeys         map[string]struct{}
	dirtyAccounts     map[string]struct{}
	dirtyLedger       map[string]struct{}
	deletedLedger     map[ledgerRef]struct{}
	deletedKeys       map[string]struct{}
	ledgerPruneBefore int64
	resetAll          bool
}

// ledgerRef identifies one hourly ledger row for deletion bookkeeping.
type ledgerRef struct {
	hour    int64
	apiKey  string
	account string
	model   string
	source  string
}

// NewStore creates a new usage Store backed by the given pricing Engine.
func NewStore(pricingEngine *pricing.Engine) *Store {
	if pricingEngine == nil {
		pricingEngine = pricing.NewEngine()
	}
	return &Store{
		pricing:         pricingEngine,
		keys:            make(map[string]*KeyStats),
		quotaCosts:      make(map[string]int64),
		dirtyQuota:      make(map[string]struct{}),
		accounts:        make(map[string]*AccountStats),
		ledger:          make(map[string]*LedgerEntry),
		ledgerByHour:    make(map[int64]map[string]*LedgerEntry),
		ledgerRetention: 90 * 24 * time.Hour,
		byRequestID:     make(map[string]*TrackedRequest),
		byTraceID:       make(map[string]*TrackedRequest),
		seenHostReqID:   make(map[string]time.Time),
		dirtyKeys:       make(map[string]struct{}),
		dirtyAccounts:   make(map[string]struct{}),
		dirtyLedger:     make(map[string]struct{}),
		deletedLedger:   make(map[ledgerRef]struct{}),
		deletedKeys:     make(map[string]struct{}),
	}
}

// ConfigureSQLite applies persistence configuration without reloading a live database.
// A failed flush or candidate open leaves the old handle, state and flusher intact.
func (s *Store) ConfigureSQLite(dbPath string, flushInterval time.Duration) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	closePending := s.closing && s.db != nil
	s.mu.Unlock()
	if closePending {
		return fmt.Errorf("usage store shutdown is still in progress")
	}
	if flushInterval <= 0 {
		flushInterval = 10 * time.Second
	}
	s.stopFlusher()
	s.flushMu.Lock()
	err := s.configureSQLiteSerialized(dbPath)
	s.flushMu.Unlock()
	s.mu.Lock()
	interval := s.flushInterval
	if err == nil {
		s.closing = false
		interval = flushInterval
		s.flushInterval = interval
	}
	configured := s.db != nil
	s.mu.Unlock()
	if configured {
		s.startFlusher(interval)
	}
	return err
}

// Close stops the flusher and flushes before releasing the database. On failure
// pre-close flush failure keeps dirty state retryable. Once driver shutdown starts,
// later accounting is rejected and Close retries only driver drain/lock release.
func (s *Store) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.stopFlusher()
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	// Keep accounting excluded between the final snapshot and handle release.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	if !s.closing {
		s.pruneLedgerLocked(time.Now())
		batch := s.takeFlushBatchLocked()
		if !batch.empty() {
			if err := writeFlushBatch(s.db.Conn(), batch); err != nil {
				s.restoreFlushBatchLocked(batch)
				s.lastPersistenceError = err.Error()
				return err
			}
			s.lastPersistenceSuccess, s.lastPersistenceError = time.Now().UTC(), ""
		}
		s.closing = true
	}
	if err := s.db.Close(); err != nil {
		s.lastPersistenceError = err.Error()
		return err
	}
	s.db = nil
	return nil
}

func (s *Store) startFlusher(interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	s.mu.Lock()
	stopCh, stoppedCh := make(chan struct{}), make(chan struct{})
	s.stopFlushCh, s.flushStopped = stopCh, stoppedCh
	s.mu.Unlock()
	go s.flushLoop(stopCh, stoppedCh, interval)
}

// DB exposes the shared database handle so other layers (for example the rule
// store in the plugin package) can use the very same connection and writer lock.
func (s *Store) DB() *sqlitestore.DB {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db
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
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return
	}

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
		LogicalRequest: true,
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
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return extracted
	}
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
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return current
	}
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
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return
	}

	var tr *TrackedRequest
	if reqID != "" {
		tr = s.byRequestID[reqID]
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
	tr.LogicalRequest = true
	if traceID != "" {
		tr.TraceID = traceID
		if tr.HostRequestID == "" {
			var candidate *TrackedRequest
			for _, attempt := range s.byRequestID {
				if attempt == tr || !attempt.HostUsageRecorded || attempt.LogicalRequest || attempt.TraceID != traceID || attempt.Failed != failed || attempt.APIKey != tr.APIKey {
					continue
				}
				if candidate == nil || attempt.CompletedAt.After(candidate.CompletedAt) {
					candidate = attempt
				}
			}
			if candidate != nil {
				if !s.mergeTrackedRequestLocked(tr, candidate) {
					return
				}
				tr.HostRequestID = candidate.HostRequestID
				tr.HostUsageRecorded = true
			}
		}
		s.byTraceID[traceID] = tr
	}
	tr.CompletionKnown = true

	tr.CompletedAt = time.Now()
	if !tr.HostUsageRecorded || reqID == tr.HostRequestID {
		tr.Failed = failed
	}
	if tr.Failed {
		// A stream may already have contributed tokens before the failure was known.
		s.rollbackLedgerStampsLocked(tr)
	}
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
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return
	}

	if hostReqID != "" {
		if _, seen := s.seenHostReqID[hostReqID]; seen {
			return
		}
		s.seenHostReqID[hostReqID] = time.Now()
	}

	// A TraceID identifies an incoming request, not one upstream execution.
	var tr *TrackedRequest
	if hostReqID != "" {
		tr = s.byRequestID[hostReqID]
	}
	if tr == nil && traceID != "" {
		candidate := s.byTraceID[traceID]
		if candidate != nil && candidate.APIKey == apiKey && candidate.HostRequestID == "" && (!candidate.CompletionKnown && !rec.Failed || candidate.CompletionKnown && candidate.Failed == rec.Failed) {
			tr = candidate
		}
	}
	// Only records without an explicit request identity may use a conservative
	// fallback: one uncompleted, model-matching tracker, never "the latest".
	if tr == nil && hostReqID == "" && apiKey != "__anonymous__" {
		var match *TrackedRequest
		ambiguous := false
		for _, candidate := range s.byRequestID {
			if candidate.APIKey != apiKey || !candidate.CompletedAt.IsZero() || time.Since(candidate.StartedAt) >= 10*time.Minute {
				continue
			}
			if traceID != "" && candidate.TraceID != "" && candidate.TraceID != traceID {
				continue
			}
			if strings.TrimSpace(rec.Model) == "" || !strings.EqualFold(strings.TrimSpace(candidate.Model), strings.TrimSpace(rec.Model)) {
				continue
			}
			if match != nil && match != candidate {
				ambiguous = true
				break
			}
			match = candidate
		}
		if !ambiguous {
			tr = match
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

	if hostReqID != "" {
		s.byRequestID[hostReqID] = tr
		tr.HostRequestID = hostReqID
	}
	tr.HostUsageRecorded = true
	if traceID != "" {
		tr.TraceID = traceID
		if existing := s.byTraceID[traceID]; existing == nil || !existing.LogicalRequest {
			s.byTraceID[traceID] = tr
		}
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

	tr.Failed = rec.Failed
	if rec.Failed {
		s.rollbackLedgerStampsLocked(tr)
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
	return false
}

func isInvalidModelID(m string) bool {
	v := strings.TrimSpace(m)
	return v == "" || strings.EqualFold(v, "unknown")
}

// markKeyDirtyLocked schedules one API key (with its model tuples) for the next flush.
func (s *Store) markKeyDirtyLocked(apiKey string) {
	if apiKey == "" || s.dirtyKeys == nil {
		return
	}
	s.dirtyKeys[apiKey] = struct{}{}
}

// markAccountDirtyLocked schedules the account bucket of a tracked request.
func (s *Store) markAccountDirtyLocked(tr *TrackedRequest) {
	if s.dirtyAccounts == nil || tr == nil {
		return
	}
	if key := accountBucketKey(tr.Provider, tr.AuthID, tr.AuthIndex); key != "" {
		s.dirtyAccounts[key] = struct{}{}
	}
}

// markLedgerDirtyLocked schedules one hourly ledger row for the next flush.
func (s *Store) markLedgerDirtyLocked(key string) {
	if key == "" || s.dirtyLedger == nil {
		return
	}
	s.dirtyLedger[key] = struct{}{}
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

// AccountUsageQuery names one upstream credential by every identifier the host
// exposes (filename, credential id, auth index).
type AccountUsageQuery struct {
	Provider    string
	Identifiers []string
}

// AccountUsageLookup resolves many credentials in a single locked pass: it builds
// one case-insensitive identifier index over the accounts and returns value copies,
// so callers never hold pointers into the live statistics. Results line up with the
// queries; a nil entry means the credential has no recorded usage.
func (s *Store) AccountUsageLookup(queries []AccountUsageQuery) []*AccountStats {
	out := make([]*AccountStats, len(queries))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.accounts) == 0 {
		return out
	}
	byIdent := make(map[string]*AccountStats, len(s.accounts)*2)
	for _, acct := range s.accounts {
		if acct == nil {
			continue
		}
		for _, id := range []string{acct.AuthID, acct.AuthIndex} {
			if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
				if _, exists := byIdent[id]; !exists {
					byIdent[id] = acct
				}
			}
		}
	}
	for i, q := range queries {
		var hit *AccountStats
		for _, id := range q.Identifiers {
			if strings.TrimSpace(id) == "" {
				continue
			}
			if key := accountBucketKey(q.Provider, id, ""); key != "" {
				if acct, ok := s.accounts[key]; ok && acct != nil {
					hit = acct
					break
				}
			}
			if acct, ok := byIdent[strings.ToLower(normalizeAccountIdentity(id))]; ok {
				hit = acct
				break
			}
			if acct, ok := byIdent[strings.ToLower(strings.TrimSpace(id))]; ok {
				hit = acct
				break
			}
		}
		if hit != nil {
			cp := *hit
			cp.Models = nil
			out[i] = &cp
		}
	}
	return out
}

// AccountUsageFor resolves the aggregated usage of one upstream credential. It is a
// convenience wrapper around AccountUsageLookup and returns a value copy.
func (s *Store) AccountUsageFor(provider string, identifiers ...string) *AccountStats {
	return s.AccountUsageLookup([]AccountUsageQuery{{Provider: provider, Identifiers: identifiers}})[0]
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

// appendUniqueAccountID records a raw credential id folded into one account bucket.
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
		ks = &KeyStats{APIKey: apiKey, MaskedKey: MaskAPIKey(apiKey), KeyName: keyName, TotalCostFormatted: "$0.000000", Models: make(map[string]*ModelStats)}
		s.keys[apiKey] = ks
	} else if keyName != "" && ks.KeyName == "" {
		ks.KeyName = keyName
	}
	return ks
}

// FlushIfDirty writes the snapshot to disk only if new usage has been recorded since the last flush.
func (s *Store) FlushIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.db == nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.FlushNow()
}

// FlushNow persists every row touched since the previous flush.
func (s *Store) FlushNow() error {
	return s.flushToDB()
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
	if len([]rune(k)) <= 2 {
		return "***"
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
	nano := s.quotaCosts[k]
	s.mu.Unlock()
	if nano <= 0 {
		return 0
	}
	return pricing.NanoToUSD(nano)
}

// WriteFileAtomically writes data to a temporary file, syncs it, and renames it over targetPath
// with a lightweight retry loop (3 retries, 20ms sleep each) to prevent transient Windows file lock errors.
func WriteFileAtomically(targetPath string, data []byte) error {
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
