package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func filterStore(t *testing.T) *Store {
	t.Helper()
	db, _ := openAuditDB(t)
	s := NewStore(db, Config{Enabled: true})
	base := time.Now().Add(-time.Hour).UnixMilli()
	for i, rec := range []struct{ id, label, requested, served, fingerprint, ip, outcome string }{
		{"filter-first", "生产 Alpha 团队", "GPT-4.1-Mini", "Upstream-Preview", strings.Repeat("a", 64), "203.0.113.10", "succeeded"},
		{"filter-second", "测试 beta 团队", "gpt-4.1-large", "claude-Other", strings.Repeat("b", 64), "203.0.113.11", "failed"},
		{"filter-literal", "Literal %_ ' OR 1=1 --", "model-%_literal", "served-%_special", strings.Repeat("a", 64), "203.0.113.10", "rejected"},
	} {
		r := auditRecord(rec.id)
		r.KeyLabel = rec.label
		r.RequestedModel = rec.requested
		r.ServedModel = rec.served
		r.KeyFingerprint = rec.fingerprint
		r.ClientIP = rec.ip
		r.Outcome = rec.outcome
		r.StartedAt = base + int64(i)
		mustBegin(t, s, r)
	}
	return s
}

func TestAuditFourFiltersMatchDocumentedSemantics(t *testing.T) {
	s := filterStore(t)
	for _, tc := range []struct {
		name string
		q    Query
		ids  []string
	}{
		{"opaque-key-exact", Query{KeyFingerprint: strings.Repeat("a", 64)}, []string{"filter-literal", "filter-first"}},
		{"opaque-key-case-normalized", Query{KeyFingerprint: strings.Repeat("A", 64)}, []string{"filter-literal", "filter-first"}},
		{"remark-Chinese-substring", Query{KeyLabel: "生产"}, []string{"filter-first"}},
		{"remark-ascii-case-insensitive", Query{KeyLabel: "ALPHA"}, []string{"filter-first"}},
		{"requested-model-substring", Query{Model: "4.1-MI"}, []string{"filter-first"}},
		{"served-model-substring", Query{Model: "preview"}, []string{"filter-first"}},
		{"model-both-columns", Query{Model: "GPT"}, []string{"filter-second", "filter-first"}},
		{"outcome-exact", Query{Outcome: "failed"}, []string{"filter-second"}},
		{"outcome-not-prefix", Query{Outcome: "fail"}, nil},
		{"combined-and", Query{KeyFingerprint: strings.Repeat("a", 64), KeyLabel: "ALPHA", Model: "mini", Outcome: "succeeded"}, []string{"filter-first"}},
		{"combined-mismatch", Query{KeyLabel: "生产", Model: "Other"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := s.List(context.Background(), tc.q)
			if err != nil {
				t.Fatal(err)
			}
			if result.Total != len(tc.ids) || len(result.Records) != len(tc.ids) {
				t.Fatalf("got total=%d records=%v want %v", result.Total, result.Records, tc.ids)
			}
			for i, id := range tc.ids {
				if result.Records[i].RequestID != id {
					t.Fatalf("order/selection=%v want=%v", result.Records, tc.ids)
				}
				if result.Records[i].RequestBody != "" {
					t.Fatal("filter list leaked body")
				}
			}
		})
	}
}

func TestAuditSubstringFiltersTreatWildcardAndSQLTextLiterally(t *testing.T) {
	s := filterStore(t)
	for _, q := range []Query{{KeyLabel: "%_"}, {Model: "%_"}, {KeyLabel: "' OR 1=1 --"}, {Model: "%_special"}} {
		got, err := s.List(context.Background(), q)
		if err != nil || got.Total != 1 || got.Records[0].RequestID != "filter-literal" {
			t.Fatalf("literal filter %+v matched %+v err=%v", q, got, err)
		}
	}
	for _, q := range []Query{{Model: "' OR 1=1 --"}, {KeyLabel: "%does-not-exist"}, {Outcome: "failed' OR 1=1 --"}} {
		got, err := s.List(context.Background(), q)
		if err != nil || got.Total != 0 {
			t.Fatalf("query not literal %+v => %+v err=%v", q, got, err)
		}
	}
}

func TestAuditFilterGuardsAndLegacyQueriesRemainCompatible(t *testing.T) {
	s := filterStore(t)
	for _, q := range []Query{{IP:"203.0.113.10"}, {KeyLabel: strings.Repeat("x", 1025)}, {KeyLabel: "x" + string(rune(0)) + "y"}, {Model: strings.Repeat("x", 1025)}, {KeyFingerprint: "raw-private-key"}} {
		if _, err := s.List(context.Background(), q); !errors.Is(err, ErrInvalidQuery) {
			t.Fatalf("invalid filter accepted %+v err=%v", q, err)
		}
	}
	got, err := s.List(context.Background(), Query{RequestID: "filter-first", TraceID: "trace-filter-first", From: time.Now().Add(-2 * time.Hour).UnixMilli(), To: time.Now().UnixMilli(), KeyLabel: "Alpha", Limit: 1, Offset: 0})
	if err != nil || got.Total != 1 || len(got.Records) != 1 {
		t.Fatalf("legacy filters failed: %+v %v", got, err)
	}
	paged, err := s.List(context.Background(), Query{KeyFingerprint: strings.Repeat("a", 64), Limit: 1, Offset: 1})
	if err != nil || paged.Total != 2 || len(paged.Records) != 1 || paged.Records[0].RequestID != "filter-first" {
		t.Fatalf("filtered pagination failed: %+v %v", paged, err)
	}
}
