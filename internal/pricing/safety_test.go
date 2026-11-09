package pricing

import (
	"math"
	"testing"
)

func TestValidatePriceRejectsInvalidRates(t *testing.T) {
	for _, value := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1), MaxPriceUSDPerMillion + 1} {
		for field := 0; field < 4; field++ {
			price := ModelPrice{}
			switch field {
			case 0:
				price.Input = value
			case 1:
				price.Output = value
			case 2:
				price.CacheRead = value
			case 3:
				price.CacheWrite = value
			}
			if err := ValidatePrice(price); err == nil {
				t.Fatalf("field %d accepted invalid rate %v", field, value)
			}
		}
	}
	for _, price := range []ModelPrice{{}, {Input: MaxPriceUSDPerMillion}, {Input: math.SmallestNonzeroFloat64}} {
		if err := ValidatePrice(price); err != nil {
			t.Fatalf("valid price rejected: %v", err)
		}
	}
}

func TestSetCustomPricesRejectsWholeInvalidUpdate(t *testing.T) {
	engine := NewEngine()
	if err := engine.SetCustomPrices(map[string]ModelPrice{"valid": {Input: 2}}, &ModelPrice{Input: 3}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1), MaxPriceUSDPerMillion + 1} {
		if err := engine.SetCustomPrices(map[string]ModelPrice{"valid": {Input: 5}, "bad": {Output: bad}}, nil); err == nil {
			t.Fatalf("accepted %v", bad)
		}
		if price, ok := engine.Lookup("valid"); !ok || price.Input != 2 {
			t.Fatalf("valid overrides replaced: %+v", price)
		}
		if price, ok := engine.Lookup("unknown"); !ok || price.Input != 3 {
			t.Fatalf("default replaced: %+v", price)
		}
	}
	if err := engine.SetCustomPrices(nil, &ModelPrice{CacheRead: -1}); err == nil {
		t.Fatal("invalid default accepted")
	}
}

func TestRemoteBadPriceKeepsPreviousCatalog(t *testing.T) {
	engine := NewEngine()
	if _, err := engine.ParseAndLoadModelsDevJSON([]byte(sampleModelsDevJSON), "good"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"bad":{"models":{"model":{"cost":{"input":-1}}}}}`,
		`{"bad":{"models":{"model":{"cost":{"output":1000001}}}}}`,
		`{"bad":{"models":{"model":{"cost":{"input":1e309}}}}}`,
	} {
		if _, err := engine.ParseAndLoadModelsDevJSON([]byte(raw), "bad"); err == nil {
			t.Fatalf("bad catalog accepted: %s", raw)
		}
		if price, ok := engine.Lookup("gpt-4o"); !ok || price.Input != 2.5 || price.Source != "good" {
			t.Fatalf("old catalog lost: %+v", price)
		}
	}
}

func TestCheckedCostRoundingAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		in, out, read, write int64
		price                ModelPrice
		want                 int64
		invalid              bool
	}{
		{"normal", 1000, 500, 2000, 1000, ModelPrice{Input: 3, Output: 15, CacheRead: .3, CacheWrite: 3.75}, 14850000, false},
		{"free", math.MaxInt64, math.MaxInt64, 0, 0, ModelPrice{}, 0, false},
		{"exact max", math.MaxInt64, 0, 0, 0, ModelPrice{Input: .001}, math.MaxInt64, false},
		{"overflow", math.MaxInt64, 0, 0, 0, ModelPrice{Input: .002}, 0, true},
		{"sum overflow", math.MaxInt64, 1, 0, 0, ModelPrice{Input: .001, Output: .001}, 0, true},
		{"rounding overflow", math.MaxInt64, 1, 0, 0, ModelPrice{Input: .001, Output: .0005}, 0, true},
		{"negative tokens", -1, 0, 0, 0, ModelPrice{Input: 1}, 0, true},
		{"negative price", 1, 0, 0, 0, ModelPrice{Input: -1}, 0, true},
		{"below half", 1, 0, 0, 0, ModelPrice{Input: .00049}, 0, false},
		{"half up", 1, 0, 0, 0, ModelPrice{Input: .0005}, 1, false},
		{"sum before round", 1, 1, 0, 0, ModelPrice{Input: .0003, Output: .0003}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CalculateCostNanoUSD(tc.in, tc.out, tc.read, tc.write, tc.price)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.want) {
				t.Fatalf("got (%d,%v), want %d invalid=%v", got, err, tc.want, tc.invalid)
			}
		})
	}
	// A 0.3-nano token rounds to zero alone, but cumulative-difference billing
	// collects the fractions rather than imposing a one-nano minimum per chunk.
	var previous, charged int64
	for count := int64(1); count <= 10; count++ {
		total, err := CalculateCostNanoUSD(count, 0, 0, 0, ModelPrice{Input: .0003})
		if err != nil {
			t.Fatal(err)
		}
		charged += total - previous
		previous = total
	}
	if charged != 3 {
		t.Fatalf("cumulative rounding cost=%d want 3", charged)
	}
}

func TestEngineCalculateReturnsOverflowError(t *testing.T) {
	engine := NewEngine()
	if err := engine.SetCustomPrices(map[string]ModelPrice{"costly": {Input: MaxPriceUSDPerMillion}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Calculate(math.MaxInt64, 0, 0, 0, "costly"); err == nil {
		t.Fatal("overflow must not become a successful zero-cost result")
	}
}
