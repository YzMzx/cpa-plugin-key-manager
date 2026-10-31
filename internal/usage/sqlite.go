package usage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	_ "modernc.org/sqlite"
)

// sqliteSchemaVersion is the current schema revision. Each entry in
// sqliteMigrations is applied at most once and recorded in schema_migrations.
const sqliteSchemaVersion = 1

type sqliteMigration struct {
	version int
	name    string
	stmts   []string
}

var sqliteMigrations = []sqliteMigration{
	{
		version: 1,
		name:    "usage aggregates and hourly ledger",
		stmts: []string{
			`CREATE TABLE IF NOT EXISTS schema_migrations (
				version INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at_unix_ms INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS key_usage (
				api_key TEXT PRIMARY KEY,
				masked_key TEXT NOT NULL DEFAULT '',
				key_name TEXT NOT NULL DEFAULT '',
				total_requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				failed_requests INTEGER NOT NULL DEFAULT 0,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				reasoning_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cache_write_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				total_cost_nano_usd INTEGER NOT NULL DEFAULT 0,
				last_request_at TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE IF NOT EXISTS key_model_usage (
				api_key TEXT NOT NULL,
				requested_model TEXT NOT NULL,
				served_model TEXT NOT NULL,
				requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				failed_requests INTEGER NOT NULL DEFAULT 0,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				reasoning_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cache_write_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				cost_nano_usd INTEGER NOT NULL DEFAULT 0,
				unit_input REAL NOT NULL DEFAULT 0,
				unit_output REAL NOT NULL DEFAULT 0,
				unit_cache_read REAL NOT NULL DEFAULT 0,
				unit_cache_write REAL NOT NULL DEFAULT 0,
				unit_source TEXT NOT NULL DEFAULT '',
				last_used_at TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (api_key, requested_model, served_model)
			)`,
			`CREATE TABLE IF NOT EXISTS account_usage (
				account_key TEXT PRIMARY KEY,
				provider TEXT NOT NULL DEFAULT '',
				auth_id TEXT NOT NULL DEFAULT '',
				auth_index TEXT NOT NULL DEFAULT '',
				auth_type TEXT NOT NULL DEFAULT '',
				requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				failed_requests INTEGER NOT NULL DEFAULT 0,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				reasoning_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cache_write_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				last_model TEXT NOT NULL DEFAULT '',
				last_request_at TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE IF NOT EXISTS account_model_usage (
				account_key TEXT NOT NULL,
				requested_model TEXT NOT NULL,
				served_model TEXT NOT NULL,
				requests INTEGER NOT NULL DEFAULT 0,
				success_requests INTEGER NOT NULL DEFAULT 0,
				failed_requests INTEGER NOT NULL DEFAULT 0,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				reasoning_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cache_write_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				cost_nano_usd INTEGER NOT NULL DEFAULT 0,
				last_used_at TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (account_key, requested_model, served_model)
			)`,
			`CREATE TABLE IF NOT EXISTS usage_ledger (
				hour INTEGER NOT NULL,
				api_key TEXT NOT NULL,
				account TEXT NOT NULL DEFAULT '',
				model TEXT NOT NULL,
				source TEXT NOT NULL DEFAULT '',
				key_name TEXT NOT NULL DEFAULT '',
				provider TEXT NOT NULL DEFAULT '',
				served_model TEXT NOT NULL DEFAULT '',
				requests INTEGER NOT NULL DEFAULT 0,
				input_tokens INTEGER NOT NULL DEFAULT 0,
				output_tokens INTEGER NOT NULL DEFAULT 0,
				cache_read_tokens INTEGER NOT NULL DEFAULT 0,
				cache_write_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0,
				cost_nano_usd INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (hour, api_key, account, model, source)
			)`,
			`CREATE INDEX IF NOT EXISTS usage_ledger_hour_idx ON usage_ledger (hour)`,
			`CREATE INDEX IF NOT EXISTS usage_ledger_model_idx ON usage_ledger (model, hour)`,
		},
	},
}

// sqliteStore owns the SQLite connection. MaxOpenConns is pinned to 1 because the
// driver serialises writes anyway and this keeps flush transactions simple.
type sqliteStore struct {
	db   *sql.DB
	path string
}

func openSQLiteStore(path string) (*sqliteStore, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "" || clean == "." {
		return nil, fmt.Errorf("sqlite: empty database path")
	}
	if dir := filepath.Dir(clean); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("sqlite: create directory: %w", err)
		}
	}
	dsn := "file:" + filepath.ToSlash(clean) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if errPing := db.Ping(); errPing != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", errPing)
	}
	store := &sqliteStore{db: db, path: clean}
	if errMigrate := store.migrate(); errMigrate != nil {
		_ = db.Close()
		return nil, errMigrate
	}
	return store, nil
}

func (s *sqliteStore) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at_unix_ms INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("sqlite: ensure schema_migrations: %w", err)
	}
	for _, m := range sqliteMigrations {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, m.version).Scan(&count); err != nil {
			return fmt.Errorf("sqlite: check migration %d: %w", m.version, err)
		}
		if count > 0 {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("sqlite: begin migration %d: %w", m.version, err)
		}
		for _, stmt := range m.stmts {
			if _, errExec := tx.Exec(stmt); errExec != nil {
				_ = tx.Rollback()
				return fmt.Errorf("sqlite: migration %d (%s): %w", m.version, m.name, errExec)
			}
		}
		if _, errIns := tx.Exec(
			`INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?, ?, ?)`,
			m.version, m.name, time.Now().UnixMilli()); errIns != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite: record migration %d: %w", m.version, errIns)
		}
		if errCommit := tx.Commit(); errCommit != nil {
			return fmt.Errorf("sqlite: commit migration %d: %w", m.version, errCommit)
		}
	}
	return nil
}

func (s *sqliteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// loadSnapshot rebuilds a PersistedSnapshot from the database.
func (s *sqliteStore) loadSnapshot() (PersistedSnapshot, error) {
	snap := PersistedSnapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Keys:      make(map[string]*KeyStats),
		Accounts:  make(map[string]*AccountStats),
	}

	rows, err := s.db.Query(`SELECT api_key, masked_key, key_name, total_requests, success_requests, failed_requests,
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

	modelRows, err := s.db.Query(`SELECT api_key, requested_model, served_model, requests, success_requests, failed_requests,
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
		ms.UnitPricePer1M = priceFromColumns(unitInput, unitOutput, unitCacheRead, unitCacheWrite, unitSource)
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

	acctRows, err := s.db.Query(`SELECT account_key, provider, auth_id, auth_index, auth_type, requests, success_requests,
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

	acctModelRows, err := s.db.Query(`SELECT account_key, requested_model, served_model, requests, success_requests,
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

	ledgerRows, err := s.db.Query(`SELECT hour, api_key, account, model, source, key_name, provider, served_model,
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

// saveSnapshot rewrites every aggregate table inside one transaction. The data set is
// small (keys x model tuples plus hourly ledger slices), so a full rewrite is both
// simpler and safer than tracking deltas.
func (s *sqliteStore) saveSnapshot(snap PersistedSnapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, table := range []string{"key_model_usage", "key_usage", "account_model_usage", "account_usage", "usage_ledger"} {
		if _, errDel := tx.Exec("DELETE FROM " + table); errDel != nil {
			return fmt.Errorf("sqlite: clear %s: %w", table, errDel)
		}
	}

	keyStmt, err := tx.Prepare(`INSERT INTO key_usage (api_key, masked_key, key_name, total_requests,
		success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
		cache_write_tokens, total_tokens, total_cost_nano_usd, last_request_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare key insert: %w", err)
	}
	modelStmt, err := tx.Prepare(`INSERT INTO key_model_usage (api_key, requested_model, served_model, requests,
		success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
		cache_write_tokens, total_tokens, cost_nano_usd, unit_input, unit_output, unit_cache_read, unit_cache_write,
		unit_source, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare model insert: %w", err)
	}
	acctStmt, err := tx.Prepare(`INSERT INTO account_usage (account_key, provider, auth_id, auth_index, auth_type,
		requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
		cache_write_tokens, total_tokens, last_model, last_request_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare account insert: %w", err)
	}
	acctModelStmt, err := tx.Prepare(`INSERT INTO account_model_usage (account_key, requested_model, served_model,
		requests, success_requests, failed_requests, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens,
		cache_write_tokens, total_tokens, cost_nano_usd, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare account model insert: %w", err)
	}
	ledgerStmt, err := tx.Prepare(`INSERT INTO usage_ledger (hour, api_key, account, model, source, key_name, provider,
		served_model, requests, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens,
		cost_nano_usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("sqlite: prepare ledger insert: %w", err)
	}

	for apiKey, ks := range snap.Keys {
		if ks == nil {
			continue
		}
		if _, errIns := keyStmt.Exec(apiKey, ks.MaskedKey, ks.KeyName, ks.TotalRequests, ks.SuccessRequests,
			ks.FailedRequests, ks.InputTokens, ks.OutputTokens, ks.ReasoningTokens, ks.CacheReadTokens,
			ks.CacheWriteTokens, ks.TotalTokens, ks.TotalCostNanoUSD, ks.LastRequestAt); errIns != nil {
			return fmt.Errorf("sqlite: insert key %s: %w", apiKey, errIns)
		}
		for _, ms := range ks.Models {
			if ms == nil {
				continue
			}
			if _, errIns := modelStmt.Exec(apiKey, ms.RequestedModel, ms.ServedModel, ms.Requests, ms.SuccessRequests,
				ms.FailedRequests, ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens, ms.CacheReadTokens,
				ms.CacheWriteTokens, ms.TotalTokens, ms.CostNanoUSD, ms.UnitPricePer1M.Input, ms.UnitPricePer1M.Output,
				ms.UnitPricePer1M.CacheRead, ms.UnitPricePer1M.CacheWrite, ms.UnitPricePer1M.Source,
				ms.LastUsedAt); errIns != nil {
				return fmt.Errorf("sqlite: insert key model %s/%s: %w", apiKey, ms.ServedModel, errIns)
			}
		}
	}

	for accountKey, acct := range snap.Accounts {
		if acct == nil {
			continue
		}
		if _, errIns := acctStmt.Exec(accountKey, acct.Provider, acct.AuthID, acct.AuthIndex, acct.AuthType,
			acct.Requests, acct.SuccessRequests, acct.FailedRequests, acct.InputTokens, acct.OutputTokens,
			acct.ReasoningTokens, acct.CacheReadTokens, acct.CacheWriteTokens, acct.TotalTokens, acct.LastModel,
			acct.LastRequestAt); errIns != nil {
			return fmt.Errorf("sqlite: insert account %s: %w", accountKey, errIns)
		}
		for _, ms := range acct.Models {
			if ms == nil {
				continue
			}
			if _, errIns := acctModelStmt.Exec(accountKey, ms.RequestedModel, ms.ServedModel, ms.Requests,
				ms.SuccessRequests, ms.FailedRequests, ms.InputTokens, ms.OutputTokens, ms.ReasoningTokens,
				ms.CacheReadTokens, ms.CacheWriteTokens, ms.TotalTokens, ms.CostNanoUSD, ms.LastUsedAt); errIns != nil {
				return fmt.Errorf("sqlite: insert account model %s/%s: %w", accountKey, ms.ServedModel, errIns)
			}
		}
	}

	ledger := append([]*LedgerEntry(nil), snap.Ledger...)
	sort.Slice(ledger, func(i, j int) bool { return ledger[i].Hour < ledger[j].Hour })
	for _, entry := range ledger {
		if entry == nil {
			continue
		}
		if _, errIns := ledgerStmt.Exec(entry.Hour, entry.APIKey, entry.Account, entry.Model, entry.Source,
			entry.KeyName, entry.Provider, entry.ServedModel, entry.Requests, entry.InputTokens, entry.OutputTokens,
			entry.CacheReadTokens, entry.CacheWriteTokens, entry.TotalTokens, entry.CostNanoUSD); errIns != nil {
			return fmt.Errorf("sqlite: insert ledger %d/%s: %w", entry.Hour, entry.Model, errIns)
		}
	}

	for _, stmt := range []*sql.Stmt{keyStmt, modelStmt, acctStmt, acctModelStmt, ledgerStmt} {
		_ = stmt.Close()
	}
	if errCommit := tx.Commit(); errCommit != nil {
		return fmt.Errorf("sqlite: commit save: %w", errCommit)
	}
	return nil
}

func priceFromColumns(in, out, read, write float64, source string) pricing.ModelPrice {
	return pricing.ModelPrice{
		Input:      in,
		Output:     out,
		CacheRead:  read,
		CacheWrite: write,
		Source:     source,
	}
}
