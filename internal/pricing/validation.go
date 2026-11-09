package pricing

import (
	"fmt"
	"math"
)

// MaxPriceUSDPerMillion is a defensive ceiling in USD per million tokens.
// It deliberately exceeds ordinary token prices while rejecting configuration
// mistakes (for example, an amount expressed in nano-USD instead of USD).
const MaxPriceUSDPerMillion = 1_000_000.0

// ValidatePrice rejects rates that cannot safely participate in billing.
// Zero is a valid, explicitly free rate; Source is descriptive metadata only.
func ValidatePrice(price ModelPrice) error {
	for _, field := range []struct {
		name  string
		value float64
	}{
		{"input", price.Input},
		{"output", price.Output},
		{"cache_read", price.CacheRead},
		{"cache_write", price.CacheWrite},
	} {
		if math.IsNaN(field.value) || math.IsInf(field.value, 0) || field.value < 0 || field.value > MaxPriceUSDPerMillion {
			return fmt.Errorf("price %s must be finite and between 0 and %g USD per million tokens", field.name, MaxPriceUSDPerMillion)
		}
	}
	return nil
}
