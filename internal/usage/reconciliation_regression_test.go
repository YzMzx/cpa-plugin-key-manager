package usage

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func regressionStore(t *testing.T) *Store {
	t.Helper()
	e := pricing.NewEngine()
	if err := e.SetCustomPrices(map[string]pricing.ModelPrice{"m": {Input: 1, CacheRead: .1}}, &pricing.ModelPrice{Input: 1}); err != nil {
		t.Fatal(err)
	}
	return NewStore(e)
}
func regressionBill(s *Store, id, key string, n int64) {
	s.BeginRequest(id, key, "", "m", "m", "openai", false)
	s.ObserveResponse(id, "m", "m", []byte(fmt.Sprintf(`{"usage":{"prompt_tokens":%d}}`, n)))
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: id, Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, key, "")
}
func TestRegressionLateCacheReclassification(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			s := regressionStore(t)
			s.BeginRequest("r", "k", "", "m", "m", "openai", false)
			initial := []byte(`{"usage":{"prompt_tokens":100}}`)
			cached := []byte(`{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":60}}}`)
			if reverse {
				initial, cached = cached, initial
			}
			s.ObserveResponse("r", "m", "m", initial)
			s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "r", Model: "m", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
			s.ObserveResponse("r", "m", "m", cached)
			k := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"]
			if k.TotalTokens != 100 || k.TotalCostNanoUSD != 46000 {
				t.Fatalf("reclassification double billed: %+v", k)
			}
		})
	}
}
func TestRegressionDefaultPriceUpgradesOnce(t *testing.T) {
	s := regressionStore(t)
	if err := s.pricing.SetCustomPrices(map[string]pricing.ModelPrice{"served": {Input: 2}}, &pricing.ModelPrice{Input: 1}); err != nil {
		t.Fatal(err)
	}
	s.BeginRequest("r", "k", "", "unpriced-product", "unpriced-product", "openai", false)
	s.CompleteRequest(pluginapi.RequestCompletion{RequestID: "r", Model: "unpriced-product", Outcome: pluginapi.RequestCompletionSucceeded}, "k", "")
	s.ObserveResponse("r", "unpriced-product", "unpriced-product", []byte(`{"model":"served","usage":{"prompt_tokens":100}}`))
	if got := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"].TotalCostNanoUSD; got != 200000 {
		t.Fatalf("late exact price=%d", got)
	}
	if err := s.pricing.SetCustomPrices(map[string]pricing.ModelPrice{"served": {Input: 9}}, nil); err != nil {
		t.Fatal(err)
	}
	s.ObserveResponse("r", "unpriced-product", "unpriced-product", []byte(`{"model":"served","usage":{"prompt_tokens":101}}`))
	if got := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"].TotalCostNanoUSD; got != 202000 {
		t.Fatalf("snapshot price changed=%d", got)
	}
}
func TestRegressionStrictTokenIntegerRange(t *testing.T) {
	for _, template := range []string{
		`{"usage":{"prompt_tokens":%s}}`,
		`{"response":{"usage":{"input_tokens":%s}}}`,
		`{"type":"message","usage":{"input_tokens":%s}}`,
		`{"usageMetadata":{"promptTokenCount":%s}}`,
	} {
		for _, value := range []string{"18446744073709551616", "9223372036854775808", "1.5", "1e100"} {
			u := ExtractResponseUsage("", []byte(fmt.Sprintf(template, value)))
			if !u.Invalid {
				t.Errorf("accepted invalid token %s: %+v", fmt.Sprintf(template, value), u)
			}
		}
	}
}
func TestRegressionResetPreservesQuotaAndRollsBack(t *testing.T) {
	for _, target := range []string{"k", ""} {
		t.Run("target="+target, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "usage.db")
			s := regressionStore(t)
			if err := s.ConfigureSQLite(path, time.Hour); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			regressionBill(s, "r", "k", 100)
			before := s.GetKeyCostUSD("k")
			if err := s.FlushNow(); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB().Conn().Exec(`CREATE TRIGGER fail_reset BEFORE DELETE ON key_usage BEGIN SELECT RAISE(ABORT, 'fixture'); END`); err != nil {
				t.Fatal(err)
			}
			if err := s.Reset(target); err == nil {
				t.Fatal("expected reset failure")
			}
			if k := s.Snapshot("k", "", nil, nil, nil, false).Keys["k"]; k == nil || k.TotalTokens != 100 {
				t.Fatal("failed reset changed live stats")
			}
			if _, err := s.DB().Conn().Exec("DROP TRIGGER fail_reset"); err != nil {
				t.Fatal(err)
			}
			if err := s.Reset(target); err != nil {
				t.Fatal(err)
			}
			if got := s.GetKeyCostUSD("k"); got != before {
				t.Fatalf("reset erased quota: %g != %g", got, before)
			}
			s.ObserveResponse("r", "m", "m", []byte(`{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":60}}}`))
			if got := s.GetKeyCostUSD("k"); got != .000046 {
				t.Fatalf("late quota correction=%g", got)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = regressionStore(t)
			if err := s.ConfigureSQLite(path, time.Hour); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if got := s.GetKeyCostUSD("k"); got != .000046 {
				t.Fatalf("restarted quota=%g", got)
			}
		})
	}
}
func TestRegressionLedgerCrossKeyOverflowDiagnostic(t *testing.T) {
	s := NewStore(nil)
	hour := time.Now().UTC().Truncate(time.Hour).Unix()
	for _, key := range []string{"a", "b"} {
		s.ledgerPutLocked(key, &LedgerEntry{Hour: hour, APIKey: key, Model: "m", TotalTokens: math.MaxInt64, InputTokens: math.MaxInt64, CostNanoUSD: math.MaxInt64})
	}
	r := s.QueryLedger(LedgerQuery{From: time.Unix(hour, 0), To: time.Unix(hour+3600, 0)})
	b, _ := json.Marshal(r)
	var decoded map[string]any
	_ = json.Unmarshal(b, &decoded)
	if r.TotalTokens < 0 || decoded["accounting_error"] == nil {
		t.Fatalf("overflow without diagnostic: %s", b)
	}
}
