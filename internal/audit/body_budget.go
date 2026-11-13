package audit

import (
	"sync/atomic"
	"time"
)

const (
	bodyCaptureSlots = 4
	bodyCaptureUnits = 20 // MiB of input; each capture reserves at least one unit.
	bodyCaptureUnit  = 1 << 20
	bodyCaptureTime  = 500 * time.Millisecond
)

// BodyCaptureBudget bounds concurrent preparation, not storage. Its zero value is
// ready for use. Keep it with the manager, not a replaceable audit generation.
// It must not be copied after first use and retains no request data.
type BodyCaptureBudget struct {
	used atomic.Uint64
	now  func() time.Time
}

// NewBodyCaptureBudgetWithClock supplies a deterministic clock for isolated
// integration fixtures. Production uses the zero value and time.Now. The clock
// must be concurrency safe and must not be changed after captures start.
func NewBodyCaptureBudgetWithClock(now func() time.Time) BodyCaptureBudget {
	return BodyCaptureBudget{now: now}
}

func (b *BodyCaptureBudget) acquire(size int) (uint64, bool) {
	units := max(1, (size+bodyCaptureUnit-1)/bodyCaptureUnit)
	if units > bodyCaptureUnits {
		return 0, false
	}
	weight := uint64(1)<<32 | uint64(units)
	// Bound CAS retries too: contention must not turn capture into a wait loop.
	for attempts := 0; attempts < 8; attempts++ {
		old := b.used.Load()
		if old>>32 >= bodyCaptureSlots || uint64(uint32(old))+uint64(units) > bodyCaptureUnits {
			return 0, false
		}
		if b.used.CompareAndSwap(old, old+weight) {
			return weight, true
		}
	}
	return 0, false
}

// Capture returns immediately without inspecting the body when capacity is full.
// Releasing in a defer also covers malformed JSON and processing-budget exits.
func (b *BodyCaptureBudget) Capture(body []byte, contentType, encoding string, maxBytes int) BodyResult {
	if len(body) == 0 || maxBytes <= 0 || len(body) > min(maxBytes, MaxRequestBodyBytes) {
		return CaptureRawJSON(body, contentType, encoding, maxBytes)
	}
	weight, ok := b.acquire(len(body))
	if !ok {
		return BodyResult{State: "omitted_busy"}
	}
	defer b.used.Add(^weight + 1)
	now := b.now
	if now == nil {
		now = time.Now
	}
	budget := newBodyWorkBudget()
	budget.now, budget.deadline = now, now().Add(bodyCaptureTime)
	return captureRawJSON(body, contentType, encoding, maxBytes, budget)
}

// Work units count visited bytes (including rescans and decoded strings), not
// JSON elements. The deadline is cooperative, with checks every 4096 units.
// The deadline is approximate: bounded standard-library validation, decoding,
// copies and hashing cannot be preempted. No watchdog goroutine continues
// processing after a request is omitted.
type bodyWorkBudget struct {
	remaining  int
	untilCheck int
	deadline   time.Time
	now        func() time.Time
}
type bodyBudgetExceeded struct{}

func newBodyWorkBudget() *bodyWorkBudget {
	return &bodyWorkBudget{remaining: 128 << 20}
}
func (b *bodyWorkBudget) checkDeadline() {
	if b == nil || b.deadline.IsZero() {
		return
	}
	now := b.now
	if now == nil {
		now = time.Now
	}
	if now().After(b.deadline) {
		panic(bodyBudgetExceeded{})
	}
}

func (b *bodyWorkBudget) spend(n int) {
	if b == nil {
		return
	}
	b.remaining -= n
	b.untilCheck -= n
	if b.remaining < 0 {
		panic(bodyBudgetExceeded{})
	}
	if b.untilCheck <= 0 {
		b.untilCheck = 4096
		b.checkDeadline()
	}
}
