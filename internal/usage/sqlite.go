package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// loadSnapshotFromDB rebuilds the in-memory state from SQLite.
func (s *Store) loadSnapshotFromDB() (PersistedSnapshot, error) {
	snap := PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      make(map[string]*KeyStats),
		Accounts:  make(map[string]*AccountStats),
	}
	conn := s.db.Conn()

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

// flushToDB writes only the rows touched since the previous flush: dirty keys and
// accounts are rewritten together with their model tuples, dirty ledger slices are
// upserted, and removed slices are deleted.
func (s *Store) flushToDB() error {
	s.mu.Lock()
	db := s.db
	if db == nil {
		s.mu.Unlock()
		return nil
	}
	keys := make(map[string]*KeyStats, len(s.dirtyKeys))
	for apiKey := range s.dirtyKeys {
		if ks := s.keys[apiKey]; ks != nil {
			keys[apiKey] = ks
		}
	}
	accounts := make(map[string]*AccountStats, len(s.dirtyAccounts))
	for accountKey := range s.dirtyAccounts {
		if acct := s.accounts[accountKey]; acct != nil {
			accounts[accountKey] = acct
		}
	}
	ledger := make([]*LedgerEntry, 0, len(s.dirtyLedger))
	for key := range s.dirtyLedger {
		if entry := s.ledger[key]; entry != nil {
			cp := *entry
			ledger = append(ledger, &cp)
		}
	}
	deletedLedger := make([]ledgerRef, 0, len(s.deletedLedger))
	for key := range s.deletedLedger {
		deletedLedger = append(deletedLedger, key)
	}
	deletedKeys := make([]string, 0, len(s.deletedKeys))
	for key := range s.deletedKeys {
		deletedKeys = append(deletedKeys, key)
	}
	pruneBefore := s.ledgerPruneBefore
	resetAll := s.resetAll

	s.dirtyKeys = make(map[string]struct{})
	s.dirtyAccounts = make(map[string]struct{})
	s.dirtyLedger = make(map[string]struct{})
	s.deletedLedger = make(map[ledgerRef]struct{})
	s.deletedKeys = make(map[string]struct{})
	s.ledgerPruneBefore = 0
	s.resetAll = false
	s.dirty = false
	s.mu.Unlock()

	if resetAll {
		if _, err := db.Conn().Exec(`DELETE FROM key_model_usage`); err != nil {
			return fmt.Errorf("sqlite: clear key models: %w", err)
		}
		if _, err := db.Conn().Exec(`DELETE FROM key_usage`); err != nil {
			return fmt.Errorf("sqlite: clear keys: %w", err)
		}
		if _, err := db.Conn().Exec(`DELETE FROM account_model_usage`); err != nil {
			return fmt.Errorf("sqlite: clear account models: %w", err)
		}
		if _, err := db.Conn().Exec(`DELETE FROM account_usage`); err != nil {
			return fmt.Errorf("sqlite: clear accounts: %w", err)
		}
		if _, err := db.Conn().Exec(`DELETE FROM usage_ledger`); err != nil {
			return fmt.Errorf("sqlite: clear ledger: %w", err)
		}
		return nil
	}

	tx, err := db.Conn().Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, apiKey := range deletedKeys {
		if _, err := tx.Exec(`DELETE FROM key_model_usage WHERE api_key = ?`, apiKey); err != nil {
			return fmt.Errorf("sqlite: delete key models: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM key_usage WHERE api_key = ?`, apiKey); err != nil {
			return fmt.Errorf("sqlite: delete key: %w", err)
		}
	}

	for apiKey, ks := range keys {
		if _, err := tx.Exec(`INSERT INTO key_usage (api_key, masked_key, key_name, total_requests, success_requests,
			failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens,
			total_tokens, total_cost_nano_usd, last_request_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(api_key) DO UPDATE SET masked_key=excluded.masked_key, key_name=excluded.key_name,
			total_requests=excluded.total_requests, success_requests=excluded.success_requests,
			failed_requests=excluded.failed_requests, input_tokens=excluded.input_tokens,
			output_tokens=excluded.output_tokens, reasoning_tokens=excluded.reasoning_tokens,
			cache_read_tokens=excluded.cache_read_tokens, cache_write_tokens=excluded.cache_write_tokens,
			total_tokens=excluded.total_tokens, total_cost_nano_usd=excluded.total_cost_nano_usd,
			last_request_at=excluded.last_request_at`,
			apiKey, ks.MaskedKey, ks.KeyName, ks.TotalRequests, ks.SuccessRequests, ks.FailedRequests,
			ks.InputTokens, ks.OutputTokens, ks.ReasoningTokens, ks.CacheReadTokens, ks.CacheWriteTokens,
			ks.TotalTokens, ks.TotalCostNanoUSD, ks.LastRequestAt); err != nil {
			return fmt.Errorf("sqlite: upsert key %s: %w", apiKey, err)
		}
		// Tuples are few per key, so replace this key's tuple set atomically.
		if _, err := tx.Exec(`DELETE FROM key_model_usage WHERE api_key = ?`, apiKey); err != nil {
			return fmt.Errorf("sqlite: reset key tuples: %w", err)
		}
		for _, ms := range ks.Models {
			if ms == nil {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO key_model_usage (api_key, requested_model, served_model, requests,
				success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
				cache_write_tokens, total_tokens, cost_nano_usd, unit_input, unit_output, unit_cache_read,
				unit_cache_write, unit_source, last_used_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				apiKey, ms.RequestedModel, ms.ServedModel, ms.Requests, ms.SuccessRequests, ms.FailedRequests,
				ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens, ms.CacheReadTokens, ms.CacheWriteTokens,
				ms.TotalTokens, ms.CostNanoUSD, ms.UnitPricePer1M.Input, ms.UnitPricePer1M.Output,
				ms.UnitPricePer1M.CacheRead, ms.UnitPricePer1M.CacheWrite, ms.UnitPricePer1M.Source,
				ms.LastUsedAt); err != nil {
				return fmt.Errorf("sqlite: upsert key tuple %s/%s: %w", apiKey, ms.ServedModel, err)
			}
		}
	}

	for accountKey, acct := range accounts {
		if _, err := tx.Exec(`INSERT INTO account_usage (account_key, provider, auth_id, auth_index, auth_type,
			requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens,
			cache_read_tokens, cache_write_tokens, total_tokens, last_model, last_request_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(account_key) DO UPDATE SET provider=excluded.provider, auth_id=excluded.auth_id,
			auth_index=excluded.auth_index, auth_type=excluded.auth_type, requests=excluded.requests,
			success_requests=excluded.success_requests, failed_requests=excluded.failed_requests,
			input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
			reasoning_tokens=excluded.reasoning_tokens, cache_read_tokens=excluded.cache_read_tokens,
			cache_write_tokens=excluded.cache_write_tokens, total_tokens=excluded.total_tokens,
			last_model=excluded.last_model, last_request_at=excluded.last_request_at`,
			accountKey, acct.Provider, acct.AuthID, acct.AuthIndex, acct.AuthType, acct.Requests,
			acct.SuccessRequests, acct.FailedRequests, acct.InputTokens, acct.OutputTokens, acct.ReasoningTokens,
			acct.CacheReadTokens, acct.CacheWriteTokens, acct.TotalTokens, acct.LastModel, acct.LastRequestAt); err != nil {
			return fmt.Errorf("sqlite: upsert account %s: %w", accountKey, err)
		}
		if _, err := tx.Exec(`DELETE FROM account_model_usage WHERE account_key = ?`, accountKey); err != nil {
			return fmt.Errorf("sqlite: reset account tuples: %w", err)
		}
		for _, ms := range acct.Models {
			if ms == nil {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO account_model_usage (account_key, requested_model, served_model,
				requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens,
				cache_read_tokens, cache_write_tokens, total_tokens, cost_nano_usd, last_used_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				accountKey, ms.RequestedModel, ms.ServedModel, ms.Requests, ms.SuccessRequests, ms.FailedRequests,
				ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens, ms.CacheReadTokens, ms.CacheWriteTokens,
				ms.TotalTokens, ms.CostNanoUSD, ms.LastUsedAt); err != nil {
				return fmt.Errorf("sqlite: upsert account tuple %s/%s: %w", accountKey, ms.ServedModel, err)
			}
		}
	}

	for _, ref := range deletedLedger {
		if _, err := tx.Exec(`DELETE FROM usage_ledger WHERE hour = ? AND api_key = ? AND account = ? AND model = ? AND source = ?`,
			ref.hour, ref.apiKey, ref.account, ref.model, ref.source); err != nil {
			return fmt.Errorf("sqlite: delete ledger row: %w", err)
		}
	}
	for _, entry := range ledger {
		if entry == nil {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO usage_ledger (hour, api_key, account, model, source, key_name, provider,
			served_model, requests, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
			total_tokens, cost_nano_usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(hour, api_key, account, model, source) DO UPDATE SET key_name=excluded.key_name,
			provider=excluded.provider, served_model=excluded.served_model, requests=excluded.requests,
			input_tokens=excluded.input_tokens, output_tokens=excluded.output_tokens,
			cache_read_tokens=excluded.cache_read_tokens, cache_write_tokens=excluded.cache_write_tokens,
			total_tokens=excluded.total_tokens, cost_nano_usd=excluded.cost_nano_usd`,
			entry.Hour, entry.APIKey, entry.Account, entry.Model, entry.Source, entry.KeyName, entry.Provider,
			entry.ServedModel, entry.Requests, entry.InputTokens, entry.OutputTokens, entry.CacheReadTokens,
			entry.CacheWriteTokens, entry.TotalTokens, entry.CostNanoUSD); err != nil {
			return fmt.Errorf("sqlite: upsert ledger %d/%s: %w", entry.Hour, entry.Model, err)
		}
	}

	if pruneBefore > 0 {
		if _, err := tx.Exec(`DELETE FROM usage_ledger WHERE hour < ?`, pruneBefore); err != nil {
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

// EnableSQLite opens the database, loads existing rows and marks SQLite as the only backend.
func (s *Store) EnableSQLite(dbPath string) error {
	db, err := sqlitestore.Open(dbPath, sqlitestore.Options{})
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.db = db
	s.mu.Unlock()

	snap, errLoad := s.loadSnapshotFromDB()
	if errLoad != nil {
		_ = db.Close()
		s.mu.Lock()
		s.db = nil
		s.mu.Unlock()
		return errLoad
	}

	hasExisting := len(snap.Keys) > 0 || len(snap.Accounts) > 0 || len(snap.Ledger) > 0
	s.mu.Lock()
	if hasExisting {
		s.keys = snap.Keys
		s.accounts = snap.Accounts
		s.ledger = make(map[string]*LedgerEntry, len(snap.Ledger))
		for _, entry := range snap.Ledger {
			if entry == nil {
				continue
			}
			s.ledger[ledgerEntryKey(entry.Hour, entry.APIKey, entry.Account, entry.Model, entry.Source)] = entry
		}
	} else {
		// Import whatever is currently in memory (e.g. migrated JSON history).
		for apiKey := range s.keys {
			s.dirtyKeys[apiKey] = struct{}{}
		}
		for accountKey := range s.accounts {
			s.dirtyAccounts[accountKey] = struct{}{}
		}
		for key := range s.ledger {
			s.dirtyLedger[key] = struct{}{}
		}
	}
	s.mu.Unlock()

	if !hasExisting {
		return s.flushToDB()
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

// sortedKeys is a small helper kept for deterministic diagnostics.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
