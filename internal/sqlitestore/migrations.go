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
	{
		version: 2,
		name:    "bounded client request audit",
		stmts: []string{
			`CREATE TABLE IF NOT EXISTS client_request_audit (
				id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, trace_id TEXT NOT NULL DEFAULT '',
				started_at INTEGER NOT NULL, completed_at INTEGER NOT NULL DEFAULT 0,
				method TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
				client_ip TEXT NOT NULL DEFAULT '', peer_ip TEXT NOT NULL DEFAULT '',
				ip_source TEXT NOT NULL DEFAULT '', ip_note TEXT NOT NULL DEFAULT '',
				key_label TEXT NOT NULL DEFAULT '', key_fingerprint TEXT NOT NULL DEFAULT '',
				requested_model TEXT NOT NULL DEFAULT '', served_model TEXT NOT NULL DEFAULT '',
				protocol TEXT NOT NULL DEFAULT '', stream INTEGER NOT NULL DEFAULT 0,
				outcome TEXT NOT NULL DEFAULT 'pending', status_code INTEGER NOT NULL DEFAULT 0,
				duration_ms INTEGER NOT NULL DEFAULT 0,
				body_state TEXT NOT NULL DEFAULT 'not_captured', body_truncated INTEGER NOT NULL DEFAULT 0,
				request_body TEXT NOT NULL DEFAULT '', body_sha256 TEXT NOT NULL DEFAULT '',
				input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
				total_tokens INTEGER NOT NULL DEFAULT 0, logical_bytes INTEGER NOT NULL CHECK(logical_bytes >= 0)
			)`,
			`CREATE INDEX IF NOT EXISTS client_request_audit_started_idx ON client_request_audit(started_at, id)`,
			`CREATE INDEX IF NOT EXISTS client_request_audit_trace_idx ON client_request_audit(trace_id, started_at)`,
			`CREATE INDEX IF NOT EXISTS client_request_audit_key_idx ON client_request_audit(key_fingerprint, started_at)`,
			`CREATE INDEX IF NOT EXISTS client_request_audit_model_idx ON client_request_audit(requested_model, started_at)`,
			`CREATE INDEX IF NOT EXISTS client_request_audit_ip_idx ON client_request_audit(client_ip, started_at)`,
		},
	},
	{
		version: 3,
		name:    "remove request audit network monitoring",
		stmts: []string{
			// Preserve compatibility columns, but remove every historical network value.
			// SQLite length(TEXT) counts characters, while logical_bytes counts UTF-8 bytes.
			`UPDATE client_request_audit SET
			 logical_bytes = max(0, logical_bytes - length(CAST(client_ip AS BLOB)) - length(CAST(peer_ip AS BLOB)) - length(CAST(ip_source AS BLOB)) - length(CAST(ip_note AS BLOB))),
			 client_ip = '', peer_ip = '', ip_source = '', ip_note = ''`,
			`DROP INDEX IF EXISTS client_request_audit_ip_idx`,
		},
	},
	{
		version: 4,
		name:    "audit storage metadata index",
		stmts: []string{
			// Cache UTF-8 body lengths in an expression index. Storage statistics and
			// cleanup previews must not read up to 1 GiB of retained request bodies.
			`CREATE INDEX IF NOT EXISTS client_request_audit_storage_idx ON client_request_audit(started_at, id, logical_bytes, length(CAST(request_body AS BLOB)))`,
		},
	},
	{
		version: 5,
		name:    "durable quota totals independent of display resets",
		stmts: []string{
			`CREATE TABLE quota_usage (api_key TEXT PRIMARY KEY, total_cost_nano_usd INTEGER NOT NULL DEFAULT 0 CHECK(total_cost_nano_usd >= 0))`,
			`INSERT INTO quota_usage(api_key, total_cost_nano_usd) SELECT api_key, max(0, total_cost_nano_usd) FROM key_usage`,
		},
	},
	{
		version: 6,
		name:    "durable audit cleanup snapshots and jobs",
		stmts: []string{
			// Only opaque IDs, owner/token hashes and byte counts are retained here.
			`CREATE TABLE audit_cleanup_previews (
			 token_hash TEXT PRIMARY KEY, principal_hash TEXT NOT NULL,
			 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
			 scope TEXT NOT NULL, before_value TEXT NOT NULL,
			 records INTEGER NOT NULL, logical_bytes INTEGER NOT NULL, body_bytes INTEGER NOT NULL,
			 batch_max_records INTEGER NOT NULL, batch_max_bytes INTEGER NOT NULL
			)`,
			`CREATE TABLE audit_cleanup_jobs (
			 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, principal_hash TEXT NOT NULL,
			 state TEXT NOT NULL CHECK(state IN ('queued','running','completed','canceled','failed')),
			 total_records INTEGER NOT NULL, processed_records INTEGER NOT NULL DEFAULT 0,
			 deleted_records INTEGER NOT NULL DEFAULT 0, skipped_records INTEGER NOT NULL DEFAULT 0,
			 remaining_records INTEGER NOT NULL, deleted_logical_bytes INTEGER NOT NULL DEFAULT 0,
			 deleted_body_bytes INTEGER NOT NULL DEFAULT 0, batches INTEGER NOT NULL DEFAULT 0,
			 batch_max_records INTEGER NOT NULL, batch_max_bytes INTEGER NOT NULL,
			 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
			 error_code TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE UNIQUE INDEX audit_cleanup_one_active_idx ON audit_cleanup_jobs((1)) WHERE state IN ('queued','running')`,
			`CREATE INDEX audit_cleanup_jobs_owner_idx ON audit_cleanup_jobs(principal_hash,created_at,id)`,
			`CREATE TABLE audit_cleanup_items (
			 snapshot_hash TEXT NOT NULL, record_id TEXT NOT NULL,
			 started_at INTEGER NOT NULL, logical_bytes INTEGER NOT NULL, body_bytes INTEGER NOT NULL,
			 PRIMARY KEY(snapshot_hash,record_id)
			) WITHOUT ROWID`,
			`CREATE INDEX audit_cleanup_items_order_idx ON audit_cleanup_items(snapshot_hash,started_at,record_id)`,
			// Per-ID current byte checks must also be covered; the earlier index starts
			// with started_at and would otherwise rescan the whole audit each batch.
			`CREATE INDEX client_request_audit_cleanup_metadata_idx ON client_request_audit(id,logical_bytes,length(CAST(request_body AS BLOB)))`,
		},
	},
	{
		version: 7,
		name:    "content intercept forensic events",
		stmts: []string{
			// Key identity is stored only as name, masked form and fingerprint.
			// Optional evidence is filtered plaintext, not general secret redaction.
			`CREATE TABLE key_guard_intercept_events (
			 id TEXT PRIMARY KEY, created_at INTEGER NOT NULL,
			 request_id TEXT NOT NULL DEFAULT '', trace_id TEXT NOT NULL DEFAULT '',
			 path TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL DEFAULT '',
			 requested_model TEXT NOT NULL DEFAULT '', served_model TEXT NOT NULL DEFAULT '',
			 stream INTEGER NOT NULL DEFAULT 0,
			 key_name TEXT NOT NULL DEFAULT '', key_masked TEXT NOT NULL DEFAULT '', key_fingerprint TEXT NOT NULL DEFAULT '',
			 action TEXT NOT NULL, mode TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '',
			 rule_names TEXT NOT NULL DEFAULT '', matches_json TEXT NOT NULL DEFAULT '', classifier_json TEXT NOT NULL DEFAULT '',
			 body TEXT NOT NULL DEFAULT '', body_state TEXT NOT NULL DEFAULT '', body_truncated INTEGER NOT NULL DEFAULT 0,
			 body_bytes INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT NOT NULL DEFAULT '', scan_truncated INTEGER NOT NULL DEFAULT 0,
			 auto_disabled TEXT NOT NULL DEFAULT '',
			 review_status TEXT NOT NULL DEFAULT 'pending', review_note TEXT NOT NULL DEFAULT '', reviewed_at INTEGER NOT NULL DEFAULT 0,
			 logical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(logical_bytes >= 0)
			)`,
			`CREATE INDEX key_guard_intercept_created_idx ON key_guard_intercept_events(created_at, id)`,
			`CREATE INDEX key_guard_intercept_key_idx ON key_guard_intercept_events(key_fingerprint, created_at)`,
			`CREATE INDEX key_guard_intercept_action_idx ON key_guard_intercept_events(action, created_at)`,
		},
	},
	{
		version: 8,
		name:    "content intercept original body digest",
		stmts:   []string{`ALTER TABLE key_guard_intercept_events ADD COLUMN original_sha256 TEXT NOT NULL DEFAULT ''`, `ALTER TABLE key_guard_intercept_events ADD COLUMN original_bytes INTEGER NOT NULL DEFAULT 0 CHECK(original_bytes >= 0)`},
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
