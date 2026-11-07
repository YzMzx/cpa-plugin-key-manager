package usage

import (
	"strings"
	"testing"
	"time"
)

// TestLedgerDefaultsToUTCPlus8 pins the plugin default timezone: with no
// timezone configured, day buckets and labels are rendered in UTC+8, so a
// request at 2026-01-01 16:30 UTC (2026-01-02 00:30 in UTC+8) belongs to
// the 2026-01-02 day bucket — not 2026-01-01 as it would under UTC.
func TestLedgerDefaultsToUTCPlus8(t *testing.T) {
	store, _ := ledgerTestStore(t)

	// 2026-01-01 16:30:00 UTC == 2026-01-02 00:30:00 UTC+8.
	at := time.Date(2026, 1, 1, 16, 30, 0, 0, time.UTC)
	store.mu.Lock()
	store.applyLedgerLocked(at, "sk-tz", "时区", "openai:zhipu:glm.json", "openai", "glm-5.3", "", "zhipu", 1, 10, 2, 0, 0, 12, 0)
	store.mu.Unlock()

	result := store.QueryLedger(LedgerQuery{
		From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
	})
	if result.Timezone != "Asia/Shanghai" {
		t.Fatalf("default timezone = %q, want Asia/Shanghai (UTC+8)", result.Timezone)
	}
	if len(result.Series) != 1 {
		t.Fatalf("series buckets = %d, want 1: %+v", len(result.Series), result.Series)
	}
	if result.Series[0].Label != "2026-01-02" {
		t.Fatalf("day bucket label = %q, want 2026-01-02 (UTC+8 date)", result.Series[0].Label)
	}
	if !strings.Contains(result.From, "+08:00") {
		t.Fatalf("from echo = %q, want +08:00 offset", result.From)
	}

	// Explicit UTC must still work for callers that ask for it.
	utc := store.QueryLedger(LedgerQuery{
		From:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		To:       time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		Timezone: "UTC",
	})
	if len(utc.Series) != 1 || utc.Series[0].Label != "2026-01-01" {
		t.Fatalf("UTC override bucket = %+v, want label 2026-01-01", utc.Series)
	}
}
