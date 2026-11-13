package audit

import "fmt"

const (
	DefaultCleanupBatchRecords       = 1000
	MinCleanupBatchRecords           = 1
	MaxCleanupBatchRecords           = 5000
	DefaultCleanupBatchBytes   int64 = 32 << 20
	MinCleanupBatchBytes       int64 = 16 << 20
	MaxCleanupBatchBytes       int64 = 128 << 20
)

// CleanupBatchLimits bounds one cleanup execution, not the retained audit range.
// Preview captures its own limits; execution may lower but must not raise them.
type CleanupBatchLimits struct {
	MaxRecords int   `json:"max_records"`
	MaxBytes   int64 `json:"max_bytes"`
}

// Validate rejects zero as well as out-of-range explicit settings. Call Normalized
// only at legacy/optional configuration boundaries, never after decoding a PUT.
func (l CleanupBatchLimits) Validate() error {
	if l.MaxRecords < MinCleanupBatchRecords || l.MaxRecords > MaxCleanupBatchRecords {
		return fmt.Errorf("audit.cleanup_batch_max_records must be between %d and %d", MinCleanupBatchRecords, MaxCleanupBatchRecords)
	}
	if l.MaxBytes < MinCleanupBatchBytes || l.MaxBytes > MaxCleanupBatchBytes {
		return fmt.Errorf("audit.cleanup_batch_max_bytes must be between %d and %d bytes", MinCleanupBatchBytes, MaxCleanupBatchBytes)
	}
	return nil
}

// Normalized supplies defaults only for absent (zero) legacy fields. Nonzero
// invalid values are retained so Validate cannot silently accept them.
func (l CleanupBatchLimits) Normalized() CleanupBatchLimits {
	if l.MaxRecords == 0 {
		l.MaxRecords = DefaultCleanupBatchRecords
	}
	if l.MaxBytes == 0 {
		l.MaxBytes = DefaultCleanupBatchBytes
	}
	return l
}
