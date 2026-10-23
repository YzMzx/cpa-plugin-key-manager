package limiter

import (
	"strings"
	"sync"
	"time"
)

// SlotInfo captures metadata for an active in-flight request occupying a concurrency slot.
type SlotInfo struct {
	RequestID      string    `json:"request_id"`
	TraceID        string    `json:"trace_id,omitempty"`
	APIKey         string    `json:"api_key"`
	Model          string    `json:"model"`
	RequestedModel string    `json:"requested_model,omitempty"`
	SourceFormat   string    `json:"source_format,omitempty"`
	Stream         bool      `json:"stream"`
	AcquiredAt     time.Time `json:"acquired_at"`
}

// Limiter tracks in-flight requests per API Key and RequestID.
// It is safe for concurrent use and preserves active slots across hot-reloads (reconfigure).
type Limiter struct {
	mu          sync.Mutex
	byRequestID map[string]*SlotInfo
	byAPIKey    map[string]map[string]*SlotInfo
}

// New creates a new concurrency Limiter.
func New() *Limiter {
	return &Limiter{
		byRequestID: make(map[string]*SlotInfo),
		byAPIKey:    make(map[string]map[string]*SlotInfo),
	}
}

// TryAcquire attempts to acquire a concurrency slot for the given request.
//   - If the same RequestID already holds a slot, it is treated idempotently and returns (true, currentCount).
//   - If maxConcurrency <= 0, concurrency is unlimited for this API Key, but the active request is still tracked.
//   - If current active count for apiKey >= maxConcurrency, it returns (false, currentCount) without modifying state.
func (l *Limiter) TryAcquire(slot SlotInfo, maxConcurrency int) (acquired bool, activeCount int) {
	reqID := strings.TrimSpace(slot.RequestID)
	apiKey := strings.TrimSpace(slot.APIKey)
	if reqID == "" {
		return true, 0
	}
	if apiKey == "" {
		apiKey = "__anonymous__"
		slot.APIKey = apiKey
	}
	if slot.AcquiredAt.IsZero() {
		slot.AcquiredAt = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.byRequestID[reqID]; ok {
		return true, len(l.byAPIKey[existing.APIKey])
	}

	keySlots := l.byAPIKey[apiKey]
	current := len(keySlots)
	if maxConcurrency > 0 && current >= maxConcurrency {
		return false, current
	}

	if keySlots == nil {
		keySlots = make(map[string]*SlotInfo)
		l.byAPIKey[apiKey] = keySlots
	}
	info := slot
	l.byRequestID[reqID] = &info
	keySlots[reqID] = &info
	return true, len(keySlots)
}

// Release releases the concurrency slot associated with requestID.
// It is idempotent: calling Release multiple times for the same requestID is a safe no-op
// and never causes active counts to underflow below zero.
// Returns the released SlotInfo and true if a slot was active, or (nil, false) if already released/unknown.
func (l *Limiter) Release(requestID string) (*SlotInfo, bool) {
	reqID := strings.TrimSpace(requestID)
	if reqID == "" {
		return nil, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	info, exists := l.byRequestID[reqID]
	if !exists {
		return nil, false
	}
	delete(l.byRequestID, reqID)

	if keySlots, ok := l.byAPIKey[info.APIKey]; ok {
		delete(keySlots, reqID)
		if len(keySlots) == 0 {
			delete(l.byAPIKey, info.APIKey)
		}
	}
	cp := *info
	return &cp, true
}

// Lookup returns a copy of the active SlotInfo for requestID without releasing it.
func (l *Limiter) Lookup(requestID string) (*SlotInfo, bool) {
	reqID := strings.TrimSpace(requestID)
	if reqID == "" {
		return nil, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	info, exists := l.byRequestID[reqID]
	if !exists {
		return nil, false
	}
	cp := *info
	return &cp, true
}

// ActiveCountForKey returns the number of currently active in-flight requests for apiKey.
func (l *Limiter) ActiveCountForKey(apiKey string) int {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		key = "__anonymous__"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byAPIKey[key])
}

// TotalActive returns the total number of in-flight requests across all API keys.
func (l *Limiter) TotalActive() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byRequestID)
}

// SnapshotByKey returns a map of apiKey -> active request count.
func (l *Limiter) SnapshotByKey() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make(map[string]int, len(l.byAPIKey))
	for k, slots := range l.byAPIKey {
		if len(slots) > 0 {
			out[k] = len(slots)
		}
	}
	return out
}

// EvictStale releases any slots that have been held longer than maxAge (safety net against unexpected host panic).
func (l *Limiter) EvictStale(maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-maxAge)

	l.mu.Lock()
	defer l.mu.Unlock()

	evicted := 0
	for reqID, info := range l.byRequestID {
		if info.AcquiredAt.Before(cutoff) {
			delete(l.byRequestID, reqID)
			if keySlots, ok := l.byAPIKey[info.APIKey]; ok {
				delete(keySlots, reqID)
				if len(keySlots) == 0 {
					delete(l.byAPIKey, info.APIKey)
				}
			}
			evicted++
		}
	}
	return evicted
}
