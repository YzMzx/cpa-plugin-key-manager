package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	name    string
	stmts   []string
}

// migrations is append-only: never edit an applied migration, add a new one.
var migrations = []migration{
	{
		version: 1,
		name:    "usage aggregates, hourly ledger and plugin rules",
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
			// Rules, key order, default policy and price overrides live in a single
			// row so every rule mutation is one atomic upsert.
			`CREATE TABLE IF NOT EXISTS rules_state (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				payload TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
		},
	},
}

// Migrate applies every pending migration inside its own transaction.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at_unix_ms INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("sqlitestore: ensure schema_migrations: %w", err)
	}
	for _, m := range migrations {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, m.version).Scan(&count); err != nil {
			return fmt.Errorf("sqlitestore: check migration %d: %w", m.version, err)
		}
		if count > 0 {
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("sqlitestore: begin migration %d: %w", m.version, err)
		}
		for _, stmt := range m.stmts {
			if _, errExec := tx.ExecContext(ctx, stmt); errExec != nil {
				_ = tx.Rollback()
				return fmt.Errorf("sqlitestore: migration %d (%s): %w", m.version, m.name, errExec)
			}
		}
		if _, errIns := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?, ?, ?)`,
			m.version, m.name, timeNowMillis()); errIns != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlitestore: record migration %d: %w", m.version, errIns)
		}
		if errCommit := tx.Commit(); errCommit != nil {
			return fmt.Errorf("sqlitestore: commit migration %d: %w", m.version, errCommit)
		}
	}
	return nil
}
