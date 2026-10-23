package pricing

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

const sampleModelsDevJSON = `{
  "anthropic": {
    "id": "anthropic",
    "name": "Anthropic",
    "models": {
      "claude-3-5-sonnet-20241022": {
        "id": "claude-3-5-sonnet-20241022",
        "name": "Claude 3.5 Sonnet",
        "canonical_model_id": "anthropic/claude-3-5-sonnet",
        "cost": {
          "input": 3.0,
          "output": 15.0,
          "cache_read": 0.3,
          "cache_write": 3.75
        }
      }
    }
  },
  "openai": {
    "id": "openai",
    "name": "OpenAI",
    "models": {
      "gpt-4o": {
        "id": "gpt-4o",
        "name": "GPT-4o",
        "canonical_model_id": "openai/gpt-4o",
        "cost": {
          "input": 2.5,
          "output": 10.0,
          "cache_read": 1.25
        }
      }
    }
  }
}`

func TestPricingEngineResolutionAndOverrides(t *testing.T) {
	eng := NewEngine()
	count, err := eng.ParseAndLoadModelsDevJSON([]byte(sampleModelsDevJSON), "models.dev")
	if err != nil {
		t.Fatalf("ParseAndLoadModelsDevJSON failed: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected non-zero indexed model keys")
	}

	// 1. Lookup model from models.dev with thinking suffix
	p, ok := eng.Lookup("claude-3-5-sonnet-20241022(high)")
	if !ok {
		t.Fatalf("expected claude-3-5-sonnet-20241022(high) to match")
	}
	if p.Input != 3.0 || p.Output != 15.0 || p.CacheRead != 0.3 || p.CacheWrite != 3.75 {
		t.Fatalf("unexpected claude price: %+v", p)
	}

	// 2. Configure custom exact and wildcard overrides (must take priority over models.dev)
	eng.SetCustomPrices(map[string]ModelPrice{
		"gpt-4o": {
			Input:      2.0,
			Output:     8.0,
			CacheRead:  1.0,
			CacheWrite: 0,
		},
		"custom-internal-*": {
			Input:      0.5,
			Output:     1.5,
			CacheRead:  0.05,
			CacheWrite: 0.1,
		},
	}, nil)

	pGPT, ok := eng.Lookup("gpt-4o")
	if !ok || pGPT.Input != 2.0 || pGPT.Source != "custom_override" {
		t.Fatalf("expected custom override for gpt-4o, got ok=%v, price=%+v", ok, pGPT)
	}

	pCustom, ok := eng.Lookup("custom-internal-v2")
	if !ok || pCustom.Input != 0.5 || pCustom.Output != 1.5 {
		t.Fatalf("expected wildcard custom override for custom-internal-v2, got ok=%v, price=%+v", ok, pCustom)
	}

	// 3. Verify high-precision USD calculation (6 decimal places)
	// 1,000 uncached input ($3/1M = $0.003000)
	// + 500 output ($15/1M = $0.007500)
	// + 2,000 cache read ($0.3/1M = $0.000600)
	// + 1,000 cache write ($3.75/1M = $0.003750)
	// Total = $0.014850 = 14,850,000 nano-USD
	breakdown := eng.Calculate(1000, 500, 2000, 1000, "claude-3-5-sonnet-20241022")
	if !breakdown.PriceFound {
		t.Fatalf("expected price found")
	}
	if breakdown.NanoUSD != 14_850_000 {
		t.Fatalf("NanoUSD = %d, want 14850000", breakdown.NanoUSD)
	}
	if breakdown.Formatted != "$0.014850" {
		t.Fatalf("Formatted = %q, want $0.014850", breakdown.Formatted)
	}
}

func TestSyncerCacheAndGracefulDegradation(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "models_dev_cache.json")

	eng := NewEngine()
	fetchShouldFail := false
	fetcher := func(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
		if fetchShouldFail {
			return nil, errors.New("simulated network timeout")
		}
		return []byte(sampleModelsDevJSON), nil
	}

	var warnLogs int
	syncer := NewSyncer(eng, fetcher, func(level, message string, fields map[string]any) {
		if level == "warn" {
			warnLogs++
		}
	})

	syncer.ConfigureAndStart(SyncConfig{
		SyncURL:      "https://models.dev/api.json",
		CacheFile:    cacheFile,
		SyncInterval: time.Hour,
		HTTPTimeout:  5 * time.Second,
	})
	defer syncer.Stop()
	syncer.WaitInitialSync(2 * time.Second)

	if _, ok := eng.Lookup("gpt-4o"); !ok {
		t.Fatalf("expected gpt-4o in engine after initial sync")
	}

	// Now simulate network failure on a new Engine that boots from the saved disk cache
	eng2 := NewEngine()
	fetchShouldFail = true
	syncer2 := NewSyncer(eng2, fetcher, func(level, message string, fields map[string]any) {
		if level == "warn" {
			warnLogs++
		}
	})
	syncer2.ConfigureAndStart(SyncConfig{
		SyncURL:      "https://models.dev/api.json",
		CacheFile:    cacheFile,
		SyncInterval: time.Hour,
		HTTPTimeout:  5 * time.Second,
	})
	defer syncer2.Stop()
	syncer2.WaitInitialSync(2 * time.Second)

	// Even though remote fetch failed, eng2 must still serve prices from the disk cache!
	p2, ok := eng2.Lookup("claude-3-5-sonnet-20241022")
	if !ok || p2.Input != 3.0 {
		t.Fatalf("expected disk cache fallback to work when network fails, got ok=%v, price=%+v", ok, p2)
	}
	if warnLogs == 0 {
		t.Fatalf("expected warn log when remote sync fails")
	}
}
