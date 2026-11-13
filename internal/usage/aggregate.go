package usage

import "math"

// SaturatingAdd preserves the numeric API shape without wrapping or reporting a
// fabricated zero. Callers MUST expose the accompanying overflow diagnostic.
func SaturatingAdd(total *int64, value int64) bool {
	if value < 0 || *total < 0 || value > math.MaxInt64-*total {
		*total = math.MaxInt64
		return false
	}
	*total += value
	return true
}
