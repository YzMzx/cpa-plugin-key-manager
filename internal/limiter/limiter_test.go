package limiter

import (
	"fmt"
	"sync"
	"testing"
)

func TestLimiterConcurrencyAndIdempotentRelease(t *testing.T) {
	lim := New()
	maxConc := 2

	ok1, c1 := lim.TryAcquire(SlotInfo{RequestID: "req-1", APIKey: "sk-1", Model: "gpt-4o", Stream: true}, maxConc)
	if !ok1 || c1 != 1 {
		t.Fatalf("req-1 acquire failed: ok=%v, count=%d", ok1, c1)
	}

	// Idempotent re-acquire for the same RequestID
	ok1Dup, c1Dup := lim.TryAcquire(SlotInfo{RequestID: "req-1", APIKey: "sk-1", Model: "gpt-4o", Stream: true}, maxConc)
	if !ok1Dup || c1Dup != 1 {
		t.Fatalf("req-1 duplicate acquire should be idempotent: ok=%v, count=%d", ok1Dup, c1Dup)
	}

	ok2, c2 := lim.TryAcquire(SlotInfo{RequestID: "req-2", APIKey: "sk-1", Model: "gpt-4o", Stream: false}, maxConc)
	if !ok2 || c2 != 2 {
		t.Fatalf("req-2 acquire failed: ok=%v, count=%d", ok2, c2)
	}

	// 3rd concurrent request for sk-1 must be rejected with 429
	ok3, c3 := lim.TryAcquire(SlotInfo{RequestID: "req-3", APIKey: "sk-1", Model: "gpt-4o", Stream: true}, maxConc)
	if ok3 || c3 != 2 {
		t.Fatalf("req-3 should be rejected at maxConcurrency=2: ok=%v, count=%d", ok3, c3)
	}

	// Another key sk-2 has independent concurrency slots
	okOther, cOther := lim.TryAcquire(SlotInfo{RequestID: "req-other", APIKey: "sk-2", Model: "claude-3-5-sonnet"}, 1)
	if !okOther || cOther != 1 {
		t.Fatalf("sk-2 acquire failed: ok=%v, count=%d", okOther, cOther)
	}

	// Release req-1 (e.g. stream finished or client disconnected)
	released, existed := lim.Release("req-1")
	if !existed || released == nil || released.APIKey != "sk-1" {
		t.Fatalf("expected req-1 to be released, got existed=%v, info=%+v", existed, released)
	}
	// Duplicate release must be a safe no-op (never underflow)
	if _, existedAgain := lim.Release("req-1"); existedAgain {
		t.Fatalf("duplicate release of req-1 should return false")
	}
	if got := lim.ActiveCountForKey("sk-1"); got != 1 {
		t.Fatalf("active count for sk-1 = %d, want 1", got)
	}

	// Now req-3 can acquire a slot
	ok3Retry, c3Retry := lim.TryAcquire(SlotInfo{RequestID: "req-3", APIKey: "sk-1", Model: "gpt-4o"}, maxConc)
	if !ok3Retry || c3Retry != 2 {
		t.Fatalf("req-3 retry after release failed: ok=%v, count=%d", ok3Retry, c3Retry)
	}
}

func TestLimiterParallelStress(t *testing.T) {
	lim := New()
	const workers = 50
	const maxConc = 5
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			reqID := fmt.Sprintf("req-%d", id)
			ok, count := lim.TryAcquire(SlotInfo{RequestID: reqID, APIKey: "sk-stress"}, maxConc)
			if ok {
				if count > maxConc {
					t.Errorf("observed active count %d > maxConc %d", count, maxConc)
				}
				lim.Release(reqID)
				lim.Release(reqID) // test idempotent double-release under race
			}
		}(i)
	}
	wg.Wait()

	if got := lim.ActiveCountForKey("sk-stress"); got != 0 {
		t.Fatalf("active count after all goroutines exited = %d, want 0", got)
	}
}
