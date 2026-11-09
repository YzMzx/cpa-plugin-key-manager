package usage

import (
	"fmt"
	"testing"
	"time"
)

func benchmarkFixture(rows int) *Store {
	s := NewStore(nil)
	now := time.Now().UTC().Truncate(time.Hour)
	for i := 0; i < rows; i++ {
		key := fmt.Sprintf("sk-bench-%d", i%1000)
		model := fmt.Sprintf("model-%d", i/1000)
		ks := s.getOrCreateKeyStatsLocked(key, "")
		if ks.Models == nil {
			ks.Models = make(map[string]*ModelStats)
		}
		ks.Models[model] = &ModelStats{RequestedModel: model, ServedModel: model, Requests: 1, SuccessRequests: 1, InputTokens: 10, TotalTokens: 10, CostNanoUSD: 1000}
		ks.TotalRequests++
		ks.SuccessRequests++
		ks.TotalTokens += 10
		ks.InputTokens += 10
		ks.TotalCostNanoUSD += 1000
		hour := now.Add(-time.Duration(i%720) * time.Hour).Unix()
		entry := &LedgerEntry{Hour: hour, APIKey: key, Model: model, Source: "openai", Requests: 1, InputTokens: 10, TotalTokens: 10, CostNanoUSD: 1000}
		s.ledgerPutLocked(ledgerEntryKey(hour, key, "", model, "openai"), entry)
	}
	return s
}

func BenchmarkSnapshot(b *testing.B) {
	for _, rows := range []int{10000, 100000} {
		b.Run(fmt.Sprintf("rows-%d", rows), func(b *testing.B) {
			s := benchmarkFixture(rows)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Snapshot("", "", nil, nil, nil, false)
			}
		})
	}
}

func BenchmarkQueryLedger(b *testing.B) {
	for _, rows := range []int{10000, 100000} {
		s := benchmarkFixture(rows)
		for _, filter := range []struct{ name, key string }{{"all", ""}, {"narrow-key", "sk-bench-999"}} {
			b.Run(fmt.Sprintf("rows-%d/%s", rows, filter.name), func(b *testing.B) {
				q := LedgerQuery{From: time.Now().Add(-30 * 24 * time.Hour), To: time.Now(), Timezone: "Asia/Shanghai", Granularity: "day", Key: filter.key}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					s.QueryLedger(q)
				}
			})
		}
	}
}
