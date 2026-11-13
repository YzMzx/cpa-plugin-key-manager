package audit

import "testing"

func TestCleanupBatchStoreConfigLegacyDefaultsAndExplicitBounds(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{CleanupBatchMaxRecords: MinCleanupBatchRecords, CleanupBatchMaxBytes: MinCleanupBatchBytes},
		{CleanupBatchMaxRecords: MaxCleanupBatchRecords, CleanupBatchMaxBytes: MaxCleanupBatchBytes},
		{CleanupBatchMaxRecords: 87},
		{CleanupBatchMaxBytes: 48 << 20},
	} {
		s := NewStore(nil, cfg)
		want := (CleanupBatchLimits{MaxRecords: cfg.CleanupBatchMaxRecords, MaxBytes: cfg.CleanupBatchMaxBytes}).Normalized()
		got := CleanupBatchLimits{MaxRecords: s.cfg.CleanupBatchMaxRecords, MaxBytes: s.cfg.CleanupBatchMaxBytes}
		if got != want {
			t.Fatalf("configuration changed: got %+v want %+v", got, want)
		}
		if err := got.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
