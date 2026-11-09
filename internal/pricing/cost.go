package pricing

import (
	"fmt"
	"math/big"
	"strconv"
)

// CalculateCostNanoUSD returns a checked cost in nano-USD. Rates are interpreted
// as their shortest round-trip decimal representation, not an inexact binary
// float product. The four token components are summed before rounding once to
// the nearest nano-USD; an exact half nano-USD rounds up. Negative counts, invalid
// prices and a rounded result outside int64 are errors, never zero-cost fallbacks.
//
// For incremental usage, calculate each cumulative total and bill the difference
// between rounded cumulative costs. Rounding each individual chunk loses sub-nano
// fractions; this function intentionally does not impose a minimum chunk charge.
func CalculateCostNanoUSD(uncachedInput, output, cacheRead, cacheWrite int64, price ModelPrice) (int64, error) {
	if err := ValidatePrice(price); err != nil {
		return 0, err
	}
	counts := [...]int64{uncachedInput, output, cacheRead, cacheWrite}
	rates := [...]float64{price.Input, price.Output, price.CacheRead, price.CacheWrite}
	names := [...]string{"input", "output", "cache_read", "cache_write"}
	total := new(big.Rat)
	for i, count := range counts {
		if count < 0 {
			return 0, fmt.Errorf("%s token count must be non-negative", names[i])
		}
		if count == 0 || rates[i] == 0 {
			continue
		}
		rate, ok := new(big.Rat).SetString(strconv.FormatFloat(rates[i], 'g', -1, 64))
		if !ok {
			return 0, fmt.Errorf("cannot represent %s price", names[i])
		}
		// USD per million tokens * 1000 = nano-USD per token.
		factor := new(big.Int).Mul(big.NewInt(count), big.NewInt(1000))
		total.Add(total, rate.Mul(rate, new(big.Rat).SetInt(factor)))
	}
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(total.Num(), total.Denom(), remainder)
	if remainder.Lsh(remainder, 1).Cmp(total.Denom()) >= 0 {
		whole.Add(whole, big.NewInt(1))
	}
	if !whole.IsInt64() {
		return 0, fmt.Errorf("calculated nano-USD cost exceeds int64 range")
	}
	return whole.Int64(), nil
}
