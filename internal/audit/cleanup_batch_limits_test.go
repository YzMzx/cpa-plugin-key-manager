package audit

import "testing"

func TestCleanupBatchLimitsDefaultsAndBoundaries(t *testing.T) {
	defaults := (CleanupBatchLimits{}).Normalized()
	if defaults.MaxRecords != 1000 || defaults.MaxBytes != 32<<20 {
		t.Fatalf("unexpected defaults: %+v", defaults)
	}
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []CleanupBatchLimits{
		{MaxRecords: MinCleanupBatchRecords, MaxBytes: MinCleanupBatchBytes},
		{MaxRecords: MaxCleanupBatchRecords, MaxBytes: MaxCleanupBatchBytes},
	} {
		if err := limits.Validate(); err != nil {
			t.Fatalf("valid boundary %+v: %v", limits, err)
		}
		if got := limits.Normalized(); got != limits {
			t.Fatalf("changed valid limits: %+v", got)
		}
	}
	for _, limits := range []CleanupBatchLimits{
		{MaxRecords: 0, MaxBytes: DefaultCleanupBatchBytes},
		{MaxRecords: -1, MaxBytes: DefaultCleanupBatchBytes},
		{MaxRecords: MaxCleanupBatchRecords + 1, MaxBytes: DefaultCleanupBatchBytes},
		{MaxRecords: DefaultCleanupBatchRecords, MaxBytes: 0},
		{MaxRecords: DefaultCleanupBatchRecords, MaxBytes: MinCleanupBatchBytes - 1},
		{MaxRecords: DefaultCleanupBatchRecords, MaxBytes: MaxCleanupBatchBytes + 1},
	} {
		if err := limits.Validate(); err == nil {
			t.Fatalf("accepted invalid limits: %+v", limits)
		}
		if limits.MaxRecords != 0 && limits.MaxBytes != 0 && limits.Normalized() != limits {
			t.Fatalf("normalization concealed invalid nonzero limits: %+v", limits)
		}
	}
}
