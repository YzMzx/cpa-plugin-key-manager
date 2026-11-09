package pricing

import "testing"

func TestPrefixBaseWinsAndUnknownSiblingDoesNotMatch(t *testing.T) {
	engine := NewEngine()
	raw := `{"vendor":{"models":{
	 "family-model":{"cost":{"input":2}},
	 "family-model-preview-long":{"cost":{"input":9}},
	 "other-family-preview":{"cost":{"input":7}},
	 "other-family-fast":{"cost":{"input":4}},
	 "single-family-preview":{"cost":{"input":8}}
	}}}`
	if _, err := engine.ParseAndLoadModelsDevJSON([]byte(raw), "reference"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"family-model-high", "family-model-extra-unknown"} {
		price, ok := engine.Lookup(id)
		if !ok || price.Input != 2 || price.Source != "models.dev(prefix:family-model)" {
			t.Fatalf("%s: %+v ok=%v", id, price, ok)
		}
	}
	for _, id := range []string{"other-family-unknown", "single-family-unknown", "unrelated-model"} {
		if price, ok := engine.Lookup(id); ok {
			t.Fatalf("unknown sibling %s guessed price %+v", id, price)
		}
	}
}

func TestModelCandidatesRespectRequestedPriority(t *testing.T) {
	engine := NewEngine()
	if _, err := engine.ParseAndLoadModelsDevJSON([]byte(sampleModelsDevJSON), "reference"); err != nil {
		t.Fatal(err)
	}
	if err := engine.SetCustomPrices(map[string]ModelPrice{"served-model": {Input: 99}, "requested-custom": {Input: 4}}, &ModelPrice{Input: 10}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		requested, served string
		want              float64
	}{
		{"gpt-4o", "served-model", 2.5},
		{"requested-custom", "gpt-4o", 4},
		{"gpt-4o-high", "served-model", 2.5},
		{"unknown-request", "served-model", 99},
		{"unknown-request", "unknown-response", 10},
	} {
		price, ok := engine.Lookup(tc.requested, tc.served)
		if !ok || price.Input != tc.want {
			t.Fatalf("%s/%s got %+v want %v", tc.requested, tc.served, price, tc.want)
		}
	}
	price, ok := engine.LookupReference("gpt-4o-high", "claude-3-5-sonnet-20241022")
	if !ok || price.Input != 2.5 {
		t.Fatalf("requested reference must precede served exact: %+v", price)
	}
}

func TestAliasConflictsUseStableProviderAndModelOrder(t *testing.T) {
	raw := `{
	 "z-provider":{"models":{"z-model":{"id":"shared","cost":{"input":9}}}},
	 "a-provider":{"models":{
	   "z-model":{"id":"shared","cost":{"input":6}},
	   "a-model":{"id":"shared","cost":{"input":2}}
	 }}
	}`
	engine := NewEngine()
	for i := 0; i < 100; i++ {
		if _, err := engine.ParseAndLoadModelsDevJSON([]byte(raw), "reference"); err != nil {
			t.Fatal(err)
		}
		price, ok := engine.Lookup("shared")
		if !ok || price.Input != 2 {
			t.Fatalf("iteration %d unstable alias: %+v", i, price)
		}
		price, ok = engine.Lookup("z-provider/shared")
		if !ok || price.Input != 9 {
			t.Fatalf("qualified alias lost: %+v", price)
		}
	}
}
