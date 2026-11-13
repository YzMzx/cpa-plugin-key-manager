package usage

import (
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
)

// Parse the original decimal lexeme, never a rounded float64 or gjson.Int's
// unchecked conversion. Missing values are absent; negative integers retain the
// historical clamp-to-zero policy, including magnitudes outside int64.
func strictTokenInteger(n gjson.Result, invalid *bool) int64 {
	if !n.Exists() {
		return 0
	}
	raw := n.Raw
	if n.Type != gjson.Number {
		*invalid = true
		return 0
	}
	digits := strings.TrimPrefix(raw, "-")
	if digits == "" {
		*invalid = true
		return 0
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			*invalid = true
			return 0
		}
	}
	if strings.HasPrefix(raw, "-") {
		return 0
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		*invalid = true
		return 0
	}
	return v
}

func mergeInputEvidence(out *NormalizedUsage, a, b NormalizedUsage) {
	out.cacheReadPresent = a.cacheReadPresent || b.cacheReadPresent
	out.cacheWritePresent = a.cacheWritePresent || b.cacheWritePresent
	out.cacheWriteInclusive = a.cacheWriteInclusive || b.cacheWriteInclusive
	// Cumulative snapshots can arrive out of order. Keep the largest raw total,
	// while retaining the strongest available cache decomposition independently.
	out.CacheReadTokens = maxInt64(a.CacheReadTokens, b.CacheReadTokens)
	out.CacheWriteTokens = maxInt64(a.CacheWriteTokens, b.CacheWriteTokens)
	// Native independent input (Anthropic) is stronger evidence than a lossy
	// translated inclusive total. Do not subtract native cache writes twice.
	if a.inputPresent && !a.inputInclusive || b.inputPresent && !b.inputInclusive {
		var input int64
		for _, u := range []NormalizedUsage{a, b} {
			if u.inputPresent && !u.inputInclusive {
				input = maxInt64(input, u.inputTotal)
				out.inputSource = u.inputSource
			}
		}
		out.inputPresent, out.inputInclusive, out.inputTotal = true, false, input
		out.UncachedInputTokens = input
	} else if a.inputPresent && a.inputInclusive || b.inputPresent && b.inputInclusive {
		total := int64(0)
		for _, u := range []NormalizedUsage{a, b} {
			if u.inputPresent && u.inputInclusive {
				total = maxInt64(total, u.inputTotal)
			}
		}
		out.inputPresent, out.inputInclusive, out.inputTotal = true, true, total
		if b.inputPresent && b.inputInclusive {
			out.inputSource = b.inputSource
		}
		uncached := total
		if out.CacheReadTokens <= uncached {
			uncached -= out.CacheReadTokens
		} else {
			uncached = 0
		}
		if out.cacheWriteInclusive {
			if out.CacheWriteTokens <= uncached {
				uncached -= out.CacheWriteTokens
			} else {
				uncached = 0
			}
		}
		out.UncachedInputTokens = uncached
	} else {
		out.inputPresent = a.inputPresent || b.inputPresent
		out.inputTotal = maxInt64(a.inputTotal, b.inputTotal)
		out.UncachedInputTokens = maxInt64(a.UncachedInputTokens, b.UncachedInputTokens)
		if b.inputSource != "" {
			out.inputSource = b.inputSource
		}
	}
}
