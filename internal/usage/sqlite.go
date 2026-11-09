package usage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// loadSnapshotFromDB rebuilds the in-memory state from SQLite.
func loadSnapshotFromDB(db *sqlitestore.DB) (PersistedSnapshot, error) {
	snap := PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      make(map[string]*KeyStats),
		Accounts:  make(map[string]*AccountStats),
	}
	conn := db.Conn()

	rows, err := conn.Query(`SELECT api_key, masked_key, key_name, total_requests, success_requests, failed_requests,
		input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens, total_tokens,
		total_cost_nano_usd, last_request_at FROM key_usage`)
	if err != nil {
		return snap, fmt.Errorf("sqlite: load key usage: %w", err)
	}
	for rows.Next() {
		ks := &KeyStats{Models: make(map[string]*ModelStats)}
		if errScan := rows.Scan(&ks.APIKey, &ks.MaskedKey, &ks.KeyName, &ks.TotalRequests, &ks.SuccessRequests,
			&ks.FailedRequests, &ks.InputTokens, &ks.OutputTokens, &ks.ReasoningTokens, &ks.CacheReadTokens,
			&ks.CacheWriteTokens, &ks.TotalTokens, &ks.TotalCostNanoUSD, &ks.LastRequestAt); errScan != nil {
			_ = rows.Close()
			return snap, fmt.Errorf("sqlite: scan key usage: %w", errScan)
		}
		snap.Keys[ks.APIKey] = ks
	}
	if errRows := rows.Err(); errRows != nil {
		_ = rows.Close()
		return snap, errRows
	}
	_ = rows.Close()

	modelRows, err := conn.Query(`SELECT api_key, requested_model, served_model, requests, success_requests, failed_requests,
		input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens, total_tokens,
		cost_nano_usd, unit_input, unit_output, unit_cache_read, unit_cache_write, unit_source, last_used_at
		FROM key_model_usage`)
	if err != nil {
		return snap, fmt.Errorf("sqlite: load key model usage: %w", err)
	}
	for modelRows.Next() {
		ms := &ModelStats{}
		var apiKey string
		var unitInput, unitOutput, unitCacheRead, unitCacheWrite float64
		var unitSource string
		if errScan := modelRows.Scan(&apiKey, &ms.RequestedModel, &ms.ServedModel, &ms.Requests, &ms.SuccessRequests,
			&ms.FailedRequests, &ms.InputTokens, &ms.OutputTokens, &ms.ReasoningTokens, &ms.CacheReadTokens,
			&ms.CacheWriteTokens, &ms.TotalTokens, &ms.CostNanoUSD, &unitInput, &unitOutput, &unitCacheRead,
			&unitCacheWrite, &unitSource, &ms.LastUsedAt); errScan != nil {
			_ = modelRows.Close()
			return snap, fmt.Errorf("sqlite: scan key model usage: %w", errScan)
		}
		ms.UnitPricePer1M = pricing.ModelPrice{
			Input: unitInput, Output: unitOutput, CacheRead: unitCacheRead, CacheWrite: unitCacheWrite, Source: unitSource,
		}
		ks := snap.Keys[apiKey]
		if ks == nil {
			ks = &KeyStats{APIKey: apiKey, MaskedKey: MaskAPIKey(apiKey), Models: make(map[string]*ModelStats)}
			snap.Keys[apiKey] = ks
		}
		ks.Models[tupleKey(ms.RequestedModel, ms.ServedModel)] = ms
	}
	if errRows := modelRows.Err(); errRows != nil {
		_ = modelRows.Close()
		return snap, errRows
	}
	_ = modelRows.Close()

	acctRows, err := conn.Query(`SELECT account_key, provider, auth_id, auth_index, auth_type, requests, success_requests,
		failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens,
		total_tokens, last_model, last_request_at FROM account_usage`)
	if err != nil {
		return snap, fmt.Errorf("sqlite: load account usage: %w", err)
	}
	for acctRows.Next() {
		acct := &AccountStats{Models: make(map[string]*ModelStats)}
		var accountKey string
		if errScan := acctRows.Scan(&accountKey, &acct.Provider, &acct.AuthID, &acct.AuthIndex, &acct.AuthType,
			&acct.Requests, &acct.SuccessRequests, &acct.FailedRequests, &acct.InputTokens, &acct.OutputTokens,
			&acct.ReasoningTokens, &acct.CacheReadTokens, &acct.CacheWriteTokens, &acct.TotalTokens,
			&acct.LastModel, &acct.LastRequestAt); errScan != nil {
			_ = acctRows.Close()
			return snap, fmt.Errorf("sqlite: scan account usage: %w", errScan)
		}
		snap.Accounts[accountKey] = acct
	}
	if errRows := acctRows.Err(); errRows != nil {
		_ = acctRows.Close()
		return snap, errRows
	}
	_ = acctRows.Close()

	acctModelRows, err := conn.Query(`SELECT account_key, requested_model, served_model, requests, success_requests,
		failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens,
		total_tokens, cost_nano_usd, last_used_at FROM account_model_usage`)
	if err != nil {
		return snap, fmt.Errorf("sqlite: load account model usage: %w", err)
	}
	for acctModelRows.Next() {
		ms := &ModelStats{}
		var accountKey string
		if errScan := acctModelRows.Scan(&accountKey, &ms.RequestedModel, &ms.ServedModel, &ms.Requests,
			&ms.SuccessRequests, &ms.FailedRequests, &ms.InputTokens, &ms.OutputTokens, &ms.ReasoningTokens,
			&ms.CacheReadTokens, &ms.CacheWriteTokens, &ms.TotalTokens, &ms.CostNanoUSD, &ms.LastUsedAt); errScan != nil {
			_ = acctModelRows.Close()
			return snap, fmt.Errorf("sqlite: scan account model usage: %w", errScan)
		}
		acct := snap.Accounts[accountKey]
		if acct == nil {
			acct = &AccountStats{Models: make(map[string]*ModelStats)}
			snap.Accounts[accountKey] = acct
		}
		acct.Models[tupleKey(ms.RequestedModel, ms.ServedModel)] = ms
	}
	if errRows := acctModelRows.Err(); errRows != nil {
		_ = acctModelRows.Close()
		return snap, errRows
	}
	_ = acctModelRows.Close()

	ledgerRows, err := conn.Query(`SELECT hour, api_key, account, model, source, key_name, provider, served_model,
		requests, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens, cost_nano_usd
		FROM usage_ledger`)
	if err != nil {
		return snap, fmt.Errorf("sqlite: load ledger: %w", err)
	}
	for ledgerRows.Next() {
		entry := &LedgerEntry{}
		if errScan := ledgerRows.Scan(&entry.Hour, &entry.APIKey, &entry.Account, &entry.Model, &entry.Source,
			&entry.KeyName, &entry.Provider, &entry.ServedModel, &entry.Requests, &entry.InputTokens,
			&entry.OutputTokens, &entry.CacheReadTokens, &entry.CacheWriteTokens, &entry.TotalTokens,
			&entry.CostNanoUSD); errScan != nil {
			_ = ledgerRows.Close()
			return snap, fmt.Errorf("sqlite: scan ledger: %w", errScan)
		}
		snap.Ledger = append(snap.Ledger, entry)
	}
	if errRows := ledgerRows.Err(); errRows != nil {
		_ = ledgerRows.Close()
		return snap, errRows
	}
	_ = ledgerRows.Close()

	return snap, nil
}

// flushBatch is a value snapshot of everything one flush must persist. It is
// captured under s.mu so request goroutines can keep mutating the live maps while
// the database transaction runs without the lock.
type flushBatch struct {
	keys          []KeyStats
	accounts      map[string]AccountStats
	ledger        []LedgerEntry
	deletedLedger []ledgerRef
	deletedKeys   []string
	pruneBefore   int64
	resetAll      bool

	// Raw dirty markers, restored when the transaction fails so nothing is lost.
	dirtyKeyIDs     []string
	dirtyAccountIDs []string
	dirtyLedgerIDs  []string
}

func (b *flushBatch) empty() bool {
	return !b.resetAll && len(b.keys) == 0 && len(b.accounts) == 0 && len(b.ledger) == 0 &&
		len(b.deletedLedger) == 0 && len(b.deletedKeys) == 0 && b.pruneBefore == 0
}

// cloneModels deep-copies a tuple map so the batch never shares pointers with the
// live statistics.
func cloneModels(src map[string]*ModelStats) map[string]*ModelStats {
	out := make(map[string]*ModelStats, len(src))
	for k, ms := range src {
		if ms == nil {
			continue
		}
		cp := *ms
		out[k] = &cp
	}
	return out
}

// takeFlushBatchLocked moves the pending changes into a value batch and clears the
// dirty markers. Callers must hold s.mu.
func (s *Store) takeFlushBatchLocked() *flushBatch {
	b := &flushBatch{
		accounts:    make(map[string]AccountStats, len(s.dirtyAccounts)),
		pruneBefore: s.ledgerPruneBefore,
		resetAll:    s.resetAll,
	}
	for apiKey := range s.dirtyKeys {
		b.dirtyKeyIDs = append(b.dirtyKeyIDs, apiKey)
		if ks := s.keys[apiKey]; ks != nil {
			cp := *ks
			cp.APIKey = apiKey
			cp.Models = cloneModels(ks.Models)
			b.keys = append(b.keys, cp)
		}
	}
	for accountKey := range s.dirtyAccounts {
		b.dirtyAccountIDs = append(b.dirtyAccountIDs, accountKey)
		if acct := s.accounts[accountKey]; acct != nil {
			cp := *acct
			cp.Models = cloneModels(acct.Models)
			b.accounts[accountKey] = cp
		}
	}
	for key := range s.dirtyLedger {
		b.dirtyLedgerIDs = append(b.dirtyLedgerIDs, key)
		if entry := s.ledger[key]; entry != nil {
			b.ledger = append(b.ledger, *entry)
		}
	}
	for ref := range s.deletedLedger {
		b.deletedLedger = append(b.deletedLedger, ref)
	}
	for key := range s.deletedKeys {
		b.deletedKeys = append(b.deletedKeys, key)
	}

	s.dirtyKeys = make(map[string]struct{})
	s.dirtyAccounts = make(map[string]struct{})
	s.dirtyLedger = make(map[string]struct{})
	s.deletedLedger = make(map[ledgerRef]struct{})
	s.deletedKeys = make(map[string]struct{})
	s.ledgerPruneBefore = 0
	s.resetAll = false
	s.dirty = false
	return b
}

// restoreFlushBatchLocked re-queues a batch whose transaction failed, so the next
// flush retries it. Newer markers set in the meantime are preserved.
func (s *Store) restoreFlushBatchLocked(b *flushBatch) {
	for _, id := range b.dirtyKeyIDs {
		s.dirtyKeys[id] = struct{}{}
	}
	for _, id := range b.dirtyAccountIDs {
		s.dirtyAccounts[id] = struct{}{}
	}
	for _, id := range b.dirtyLedgerIDs {
		s.dirtyLedger[id] = struct{}{}
	}
	for _, ref := range b.deletedLedger {
		s.deletedLedger[ref] = struct{}{}
	}
	for _, key := range b.deletedKeys {
		s.deletedKeys[key] = struct{}{}
	}
	if b.pruneBefore > s.ledgerPruneBefore {
		s.ledgerPruneBefore = b.pruneBefore
	}
	if b.resetAll {
		s.resetAll = true
	}
	s.dirty = true
}

const (
	sqlUpsertKey = `INSERT INTO key_usage (api_key, masked_key, key_name, total_requests, success_requests,
		failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens,
		total_tokens, total_cost_nano_usd, last_request_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(api_key) DO UPDATE SET masked_key=excluded.masked_key, key_name=excluded.key_name,
		total_requests=excluded.total_requests, success_requests=excluded.success_requests,
		failed_requests=excluded.failed_requests, input_tokens=excluded.input_tokens,
		output_tokens=excluded.output_tokens, reasoning_tokens=excluded.reasoning_tokens,
		cache_read_tokens=excluded.cache_read_tokens, cache_write_tokens=excluded.cache_write_tokens,
		total_tokens=excluded.total_tokens, total_cost_nano_usd=excluded.total_cost_nano_usd,
		last_request_at=excluded.last_request_at`
	sqlInsertKeyTuple = `INSERT INTO key_model_usage (api_key, requested_model, served_model, requests,
		success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
		cache_write_tokens, total_tokens, cost_nano_usd, unit_input, unit_output, unit_cache_read,
		unit_cache_write, unit_source, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	sqlUpsertAccount = `INSERT INTO account_usage (account_key, provider, auth_id, auth_index, auth_type,
		requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens,
		cache_read_tokens, cache_write_tokens, total_tokens, last_model, last_request_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(account_key) DO UPDATE SET provider=excluded.provider, auth_id=excluded.auth_id,
		auth_index=excluded.auth_index, auth_type=excluded.auth_type, requests=excluded.requests,
		success_requests=excluded.success_requests, failed_requests=excluded.failed_requests,
		input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
		reasoning_tokens=excluded.reasoning_tokens, cache_read_tokens=excluded.cache_read_tokens,
		cache_write_tokens=excluded.cache_write_tokens, total_tokens=excluded.total_tokens,
		last_model=excluded.last_model, last_request_at=excluded.last_request_at`
	sqlInsertAccountTuple = `INSERT INTO account_model_usage (account_key, requested_model, served_model,
		requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens,
		cache_read_tokens, cache_write_tokens, total_tokens, cost_nano_usd, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	sqlUpsertLedger = `INSERT INTO usage_ledger (hour, api_key, account, model, source, key_name, provider,
		served_model, requests, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
		total_tokens, cost_nano_usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hour, api_key, account, model, source) DO UPDATE SET key_name=excluded.key_name,
		provider=excluded.provider, served_model=excluded.served_model, requests=excluded.requests,
		input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
		cache_read_tokens=excluded.cache_read_tokens, cache_write_tokens=excluded.cache_write_tokens,
		total_tokens=excluded.total_tokens, cost_nano_usd=excluded.cost_nano_usd`
	sqlDeleteLedgerRow = `DELETE FROM usage_ledger WHERE hour = ? AND api_key = ? AND account = ? AND model = ? AND source = ?`
)

// flushToDB writes only the rows touched since the previous flush. The batch is a
// value copy taken under the lock, the whole write is one transaction, and a failed
// transaction re-queues its markers so the next flush retries instead of losing data.
func (s *Store) flushToDB() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	return s.flushToDBSerialized()
}

// flushToDBSerialized holds flushMu from snapshot capture through commit/restore.
func (s *Store) flushToDBSerialized() error {
	s.mu.Lock()
	s.pruneLedgerLocked(time.Now())
	db := s.db
	if db == nil {
		s.mu.Unlock()
		return nil
	}
	batch := s.takeFlushBatchLocked()
	s.flushInProgress = !batch.empty()
	s.mu.Unlock()

	if batch.empty() {
		return nil
	}
	if err := writeFlushBatch(db.Conn(), batch); err != nil {
		s.mu.Lock()
		s.restoreFlushBatchLocked(batch)
		s.lastPersistenceError = err.Error()
		s.flushInProgress = false
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.lastPersistenceSuccess = time.Now().UTC()
	s.lastPersistenceError = ""
	s.flushInProgress = false
	s.mu.Unlock()
	return nil
}

func writeFlushBatch(conn *sql.DB, b *flushBatch) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if b.resetAll {
		for _, table := range []string{"key_model_usage", "key_usage", "account_model_usage", "account_usage", "usage_ledger"} {
			if _, err := tx.Exec("DELETE FROM " + table); err != nil {
				return fmt.Errorf("sqlite: clear %s: %w", table, err)
			}
		}
	}

	prepare := func(query string) (*sql.Stmt, error) { return tx.Prepare(query) }
	stmtKey, err := prepare(sqlUpsertKey)
	if err != nil {
		return fmt.Errorf("sqlite: prepare key upsert: %w", err)
	}
	defer stmtKey.Close()
	stmtKeyTuple, err := prepare(sqlInsertKeyTuple)
	if err != nil {
		return fmt.Errorf("sqlite: prepare key tuple: %w", err)
	}
	defer stmtKeyTuple.Close()
	stmtAcct, err := prepare(sqlUpsertAccount)
	if err != nil {
		return fmt.Errorf("sqlite: prepare account upsert: %w", err)
	}
	defer stmtAcct.Close()
	stmtAcctTuple, err := prepare(sqlInsertAccountTuple)
	if err != nil {
		return fmt.Errorf("sqlite: prepare account tuple: %w", err)
	}
	defer stmtAcctTuple.Close()
	stmtLedger, err := prepare(sqlUpsertLedger)
	if err != nil {
		return fmt.Errorf("sqlite: prepare ledger upsert: %w", err)
	}
	defer stmtLedger.Close()
	stmtLedgerDel, err := prepare(sqlDeleteLedgerRow)
	if err != nil {
		return fmt.Errorf("sqlite: prepare ledger delete: %w", err)
	}
	defer stmtLedgerDel.Close()

	for _, apiKey := range b.deletedKeys {
		if _, err := tx.Exec(`DELETE FROM key_model_usage WHERE api_key = ?`, apiKey); err != nil {
			return fmt.Errorf("sqlite: delete key models: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM key_usage WHERE api_key = ?`, apiKey); err != nil {
			return fmt.Errorf("sqlite: delete key: %w", err)
		}
	}

	for i := range b.keys {
		ks := &b.keys[i]
		if _, err := stmtKey.Exec(ks.APIKey, ks.MaskedKey, ks.KeyName, ks.TotalRequests, ks.SuccessRequests,
			ks.FailedRequests, ks.InputTokens, ks.OutputTokens, ks.ReasoningTokens, ks.CacheReadTokens,
			ks.CacheWriteTokens, ks.TotalTokens, ks.TotalCostNanoUSD, ks.LastRequestAt); err != nil {
			return fmt.Errorf("sqlite: upsert key: %w", err)
		}
		// Tuples are few per key, so replace this key's tuple set atomically.
		if _, err := tx.Exec(`DELETE FROM key_model_usage WHERE api_key = ?`, ks.APIKey); err != nil {
			return fmt.Errorf("sqlite: reset key tuples: %w", err)
		}
		for _, ms := range ks.Models {
			if _, err := stmtKeyTuple.Exec(ks.APIKey, ms.RequestedModel, ms.ServedModel, ms.Requests,
				ms.SuccessRequests, ms.FailedRequests, ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens,
				ms.CacheReadTokens, ms.CacheWriteTokens, ms.TotalTokens, ms.CostNanoUSD,
				ms.UnitPricePer1M.Input, ms.UnitPricePer1M.Output, ms.UnitPricePer1M.CacheRead,
				ms.UnitPricePer1M.CacheWrite, ms.UnitPricePer1M.Source, ms.LastUsedAt); err != nil {
				return fmt.Errorf("sqlite: upsert key tuple: %w", err)
			}
		}
	}

	for accountKey, acct := range b.accounts {
		if _, err := stmtAcct.Exec(accountKey, acct.Provider, acct.AuthID, acct.AuthIndex, acct.AuthType,
			acct.Requests, acct.SuccessRequests, acct.FailedRequests, acct.InputTokens, acct.OutputTokens,
			acct.ReasoningTokens, acct.CacheReadTokens, acct.CacheWriteTokens, acct.TotalTokens,
			acct.LastModel, acct.LastRequestAt); err != nil {
			return fmt.Errorf("sqlite: upsert account %s: %w", accountKey, err)
		}
		if _, err := tx.Exec(`DELETE FROM account_model_usage WHERE account_key = ?`, accountKey); err != nil {
			return fmt.Errorf("sqlite: reset account tuples: %w", err)
		}
		for _, ms := range acct.Models {
			if _, err := stmtAcctTuple.Exec(accountKey, ms.RequestedModel, ms.ServedModel, ms.Requests,
				ms.SuccessRequests, ms.FailedRequests, ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens,
				ms.CacheReadTokens, ms.CacheWriteTokens, ms.TotalTokens, ms.CostNanoUSD, ms.LastUsedAt); err != nil {
				return fmt.Errorf("sqlite: upsert account tuple %s/%s: %w", accountKey, ms.ServedModel, err)
			}
		}
	}

	for _, ref := range b.deletedLedger {
		if _, err := stmtLedgerDel.Exec(ref.hour, ref.apiKey, ref.account, ref.model, ref.source); err != nil {
			return fmt.Errorf("sqlite: delete ledger row: %w", err)
		}
	}
	for i := range b.ledger {
		e := &b.ledger[i]
		if _, err := stmtLedger.Exec(e.Hour, e.APIKey, e.Account, e.Model, e.Source, e.KeyName, e.Provider,
			e.ServedModel, e.Requests, e.InputTokens, e.OutputTokens, e.CacheReadTokens, e.CacheWriteTokens,
			e.TotalTokens, e.CostNanoUSD); err != nil {
			return fmt.Errorf("sqlite: upsert ledger %d/%s: %w", e.Hour, e.Model, err)
		}
	}

	if b.pruneBefore > 0 {
		if _, err := tx.Exec(`DELETE FROM usage_ledger WHERE hour < ?`, b.pruneBefore); err != nil {
			return fmt.Errorf("sqlite: prune ledger: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit flush: %w", err)
	}
	return nil
}

// ImportLegacySnapshotCandidates loads the newest JSON snapshot among the given
// paths into memory so the following SQLite flush can persist it. This is the
// upgrade path from v0.8.x (JSON) to v0.9.x (SQLite): usage history is imported
// once, when the database does not exist yet.
func (s *Store) ImportLegacySnapshotCandidates(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	s.mu.Lock()
	empty := len(s.keys) == 0 && len(s.accounts) == 0 && len(s.ledger) == 0
	s.mu.Unlock()
	if !empty {
		return nil
	}

	bestPath := ""
	bestUpdated := ""
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		rawBytes, errRead := os.ReadFile(path)
		if errRead != nil || len(strings.TrimSpace(string(rawBytes))) == 0 {
			continue
		}
		var snap PersistedSnapshot
		if errUnmarshal := json.Unmarshal(rawBytes, &snap); errUnmarshal != nil {
			continue
		}
		if len(snap.Keys) == 0 && len(snap.Ledger) == 0 {
			continue
		}
		if bestPath == "" || snap.UpdatedAt > bestUpdated {
			bestPath = path
			bestUpdated = snap.UpdatedAt
		}
	}
	if bestPath == "" {
		return nil
	}
	return s.loadFromDisk(bestPath)
}

// EnableSQLite is a compatibility entry point using the same safe lifecycle path.
func (s *Store) EnableSQLite(dbPath string) error {
	return s.ConfigureSQLite(dbPath, 10*time.Second)
}

// configureSQLiteSerialized requires flushMu; only a complete candidate is
// published. Holding mu during this uncommon switch prevents overwriting usage
// arriving between the final old-database flush and snapshot adoption.
func (s *Store) configureSQLiteSerialized(dbPath string) error {
	s.mu.Lock()
	previous := s.db
	if previous != nil && filepath.Clean(previous.Path()) == filepath.Clean(dbPath) {
		s.mu.Unlock()
		return s.flushToDBSerialized()
	}
	s.mu.Unlock()
	candidate, err := sqlitestore.Open(dbPath, sqlitestore.Options{})
	if err != nil {
		s.mu.Lock()
		s.lastPersistenceError = err.Error()
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(err error) error {
		_ = candidate.Close()
		s.lastPersistenceError = err.Error()
		return err
	}
	if previous != nil {
		batch := s.takeFlushBatchLocked()
		if !batch.empty() {
			if err := writeFlushBatch(previous.Conn(), batch); err != nil {
				s.restoreFlushBatchLocked(batch)
				return fail(err)
			}
			s.lastPersistenceSuccess = time.Now().UTC()
		}
	}
	snap, err := loadSnapshotFromDB(candidate)
	if err != nil {
		return fail(err)
	}
	hasExisting := len(snap.Keys) > 0 || len(snap.Accounts) > 0 || len(snap.Ledger) > 0
	if !hasExisting {
		// Seed a new database without clearing live dirty markers until it commits.
		for key := range s.keys {
			s.dirtyKeys[key] = struct{}{}
		}
		for key := range s.accounts {
			s.dirtyAccounts[key] = struct{}{}
		}
		for key := range s.ledger {
			s.dirtyLedger[key] = struct{}{}
		}
		batch := s.takeFlushBatchLocked()
		if !batch.empty() {
			if err := writeFlushBatch(candidate.Conn(), batch); err != nil {
				s.restoreFlushBatchLocked(batch)
				return fail(err)
			}
		}
	} else {
		s.keys, s.accounts = snap.Keys, snap.Accounts
		s.ledgerResetLocked()
		for _, entry := range snap.Ledger {
			if entry != nil {
				s.ledgerPutLocked(ledgerEntryKey(entry.Hour, entry.APIKey, entry.Account, entry.Model, entry.Source), entry)
			}
		}
	}
	s.db = candidate
	s.lastPersistenceSuccess, s.lastPersistenceError = time.Now().UTC(), ""
	if previous != nil {
		if err := previous.Close(); err != nil {
			s.lastPersistenceError = err.Error()
		}
	}
	return nil
}

// SQLitePath reports the database file (empty when SQLite is not enabled).
func (s *Store) SQLitePath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sqlitePathLocked()
}

// sqlitePathLocked is the variant used by callers that already hold s.mu.
func (s *Store) sqlitePathLocked() string {
	if s.db == nil {
		return ""
	}
	return s.db.Path()
}

// SQLiteLockPath reports the cross-process writer lock file.
func (s *Store) SQLiteLockPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ""
	}
	return s.db.LockFilePath()
}
