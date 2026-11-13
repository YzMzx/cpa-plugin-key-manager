package usage

import (
	"fmt"
	"strings"
	"time"
)

// Reset clears display statistics, never the lifetime quota counter. Keep recent
// execution identities so late callbacks correct quota rather than billing twice.
// Lock order matches Close: flushMu -> mu; publication follows SQLite commit.
func (s *Store) Reset(apiKey string) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return fmt.Errorf("usage store is shutting down")
	}
	target := strings.TrimSpace(apiKey)
	batch := s.takeFlushBatchLocked()
	original := *batch
	batch.deletedKeys = append([]string(nil), batch.deletedKeys...)
	batch.deletedLedger = append([]ledgerRef(nil), batch.deletedLedger...)
	if target == "" {
		batch.resetAll = true
		batch.keys = nil
		batch.accounts = nil
		batch.ledger = nil
	} else {
		batch.deletedKeys = append(batch.deletedKeys, target)
		keys := make([]KeyStats, 0, len(batch.keys))
		for _, k := range batch.keys {
			if k.APIKey != target {
				keys = append(keys, k)
			}
		}
		batch.keys = keys
		ledger := make([]LedgerEntry, 0, len(batch.ledger))
		for _, e := range batch.ledger {
			if e.APIKey != target {
				ledger = append(ledger, e)
			}
		}
		batch.ledger = ledger
		for _, e := range s.ledger {
			if e.APIKey == target {
				batch.deletedLedger = append(batch.deletedLedger, ledgerRef{hour: e.Hour, apiKey: e.APIKey, account: e.Account, model: e.Model, source: e.Source})
			}
		}
	}
	if s.db != nil {
		if err := writeFlushBatch(s.db.Conn(), batch); err != nil {
			// Restore only the original dirty work, NOT the failed reset command.
			s.restoreFlushBatchLocked(&original)
			s.lastPersistenceError = err.Error()
			return err
		}
		s.lastPersistenceSuccess, s.lastPersistenceError = time.Now().UTC(), ""
	}
	if target == "" {
		s.keys = make(map[string]*KeyStats)
		s.accounts = make(map[string]*AccountStats)
		s.ledgerResetLocked()
	} else {
		delete(s.keys, target)
		for key, e := range s.ledger {
			if e.APIKey == target {
				s.ledgerDeleteLocked(key)
			}
		}
	}
	for _, tr := range s.byRequestID {
		if target == "" || tr.APIKey == target {
			tr.displayReset = tr.CountedRequest
			tr.ledgerStamps = nil
		}
	}
	return nil
}

func (s *Store) replaceQuotaContributionLocked(tr *TrackedRequest, cost int64) {
	s.quotaCosts[tr.APIKey] = s.quotaCosts[tr.APIKey] - tr.billedQuotaCost + cost
	tr.billedQuotaCost = cost
	s.dirtyQuota[tr.APIKey] = struct{}{}
	s.dirty = true
}
