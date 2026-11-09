package audit

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

var ErrInvalidCleanup = errors.New("invalid audit cleanup scope or time")

const maxCleanupRecords = 100000

// StorageUsage separates audit logical payload from the shared SQLite file size.
type StorageUsage struct {
	Records            int64   `json:"records"`
	ActiveRecords      int64   `json:"active_records"`
	ExpiredRecords     int64   `json:"expired_records"`
	LogicalBytes       int64   `json:"logical_bytes"`
	RequestBodyBytes   int64   `json:"request_body_bytes"`
	MaxTotalBytes      int64   `json:"max_total_bytes"`
	UtilizationPercent float64 `json:"utilization_percent"`
	DBFileBytes        int64   `json:"db_file_bytes"`
	WALFileBytes       int64   `json:"wal_file_bytes"`
	RetentionDays      int     `json:"retention_days"`
	CapacityMode       string  `json:"capacity_mode"`
	PhysicalSizeScope  string  `json:"physical_size_scope"`
	Warning            string  `json:"warning"`
}

type CleanupPlan struct {
	IDs             []string `json:"-"`
	Scope           string   `json:"scope"`
	BeforeUnixMilli int64    `json:"before_unix_milli,omitempty"`
	Records         int64    `json:"records"`
	LogicalBytes    int64    `json:"logical_bytes"`
	BodyBytes       int64    `json:"request_body_bytes"`
}
type CleanupResult struct {
	Records      int64 `json:"records"`
	LogicalBytes int64 `json:"logical_bytes"`
	BodyBytes    int64 `json:"request_body_bytes"`
}

func safeExpireNow() time.Time { return time.Now().UTC() }

func (s *Store) Storage(ctx context.Context) (StorageUsage, error) {
	usage := StorageUsage{CapacityMode: "logical_payload_not_physical_file", PhysicalSizeScope: "shared_sqlite_database_and_wal", Warning: "Audit logical deletion may not shrink the shared SQLite/WAL files and does not guarantee secure erasure."}
	if err := s.ready(); err != nil {
		return usage, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	usage.MaxTotalBytes = s.cfg.MaxTotalBytes
	usage.RetentionDays = s.cfg.RetentionDays
	cutoff := s.cutoff(safeExpireNow())
	err := s.db.Conn().QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN started_at>=? THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN started_at<? THEN 1 ELSE 0 END),0),COALESCE(SUM(logical_bytes),0),COALESCE(SUM(length(CAST(request_body AS BLOB))),0) FROM client_request_audit`, cutoff, cutoff).Scan(&usage.Records, &usage.ActiveRecords, &usage.ExpiredRecords, &usage.LogicalBytes, &usage.RequestBodyBytes)
	if err != nil {
		return StorageUsage{}, s.fail(ErrUnavailable)
	}
	if usage.MaxTotalBytes > 0 {
		usage.UtilizationPercent = 100 * float64(usage.LogicalBytes) / float64(usage.MaxTotalBytes)
	}
	for _, entry := range []struct {
		suffix string
		target *int64
	}{{"", &usage.DBFileBytes}, {"-wal", &usage.WALFileBytes}} {
		info, err := os.Stat(s.db.Path() + entry.suffix)
		if err == nil && !info.IsDir() {
			*entry.target = info.Size()
		} else if err != nil && !os.IsNotExist(err) {
			return StorageUsage{}, s.fail(ErrUnavailable)
		}
	}
	return usage, nil
}

// PreviewCleanup snapshots opaque record IDs. It never mutates audit or other tables.
func (s *Store) PreviewCleanup(ctx context.Context, scope string, before time.Time) (CleanupPlan, error) {
	var plan CleanupPlan
	if err := s.ready(); err != nil {
		return plan, err
	}
	now := safeExpireNow()
	plan.Scope = scope
	where := "1=1"
	var args []any
	switch scope {
	case "expired":
		if !before.IsZero() {
			return plan, ErrInvalidCleanup
		}
		plan.BeforeUnixMilli = s.cutoff(now)
		where = "started_at<?"
		args = []any{plan.BeforeUnixMilli}
	case "before":
		if before.IsZero() || before.After(now) || before.UnixMilli() < 0 {
			return plan, ErrInvalidCleanup
		}
		plan.BeforeUnixMilli = before.UTC().UnixMilli()
		where = "started_at<?"
		args = []any{plan.BeforeUnixMilli}
	case "all":
		if !before.IsZero() {
			return plan, ErrInvalidCleanup
		}
	default:
		return plan, ErrInvalidCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	args = append(args, maxCleanupRecords+1)
	rows, err := s.db.Conn().QueryContext(ctx, "SELECT id,logical_bytes,length(CAST(request_body AS BLOB)) FROM client_request_audit WHERE "+where+" ORDER BY started_at,id LIMIT ?", args...)
	if err != nil {
		return CleanupPlan{}, s.fail(ErrUnavailable)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var logical, body int64
		if err := rows.Scan(&id, &logical, &body); err != nil {
			return CleanupPlan{}, s.fail(ErrUnavailable)
		}
		if !validID(id) || logical < 0 || body < 0 || len(plan.IDs) >= maxCleanupRecords {
			return CleanupPlan{}, s.fail(ErrUnavailable)
		}
		plan.IDs = append(plan.IDs, id)
		plan.Records++
		plan.LogicalBytes += logical
		plan.BodyBytes += body
	}
	if rows.Err() != nil {
		return CleanupPlan{}, s.fail(ErrUnavailable)
	}
	return plan, nil
}

// ApplyCleanup only uses a server-owned preview snapshot, never a client WHERE.
// Re-read metadata in each batch so counts reflect rows still present at apply.
func (s *Store) ApplyCleanup(ctx context.Context, plan CleanupPlan) (CleanupResult, error) {
	var result CleanupResult
	if err := s.ready(); err != nil {
		return result, err
	}
	if (plan.Scope != "all" && plan.Scope != "before" && plan.Scope != "expired") || len(plan.IDs) > maxCleanupRecords {
		return result, ErrInvalidCleanup
	}
	seen := make(map[string]struct{}, len(plan.IDs))
	for _, id := range plan.IDs {
		if !validID(id) {
			return result, ErrInvalidCleanup
		}
		if _, ok := seen[id]; ok {
			return result, ErrInvalidCleanup
		}
		seen[id] = struct{}{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.db.Conn().BeginTx(ctx, nil)
	if err != nil {
		return result, s.fail(ErrUnavailable)
	}
	defer tx.Rollback()
	for start := 0; start < len(plan.IDs); start += 200 {
		end := min(start+200, len(plan.IDs))
		args := make([]any, end-start)
		for i, id := range plan.IDs[start:end] {
			args[i] = id
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
		var count, logical, body int64
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(logical_bytes),0),COALESCE(SUM(length(CAST(request_body AS BLOB))),0) FROM client_request_audit WHERE id IN ("+placeholders+")", args...).Scan(&count, &logical, &body)
		if err != nil {
			return CleanupResult{}, s.fail(ErrUnavailable)
		}
		deleted, err := tx.ExecContext(ctx, "DELETE FROM client_request_audit WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			return CleanupResult{}, s.fail(ErrUnavailable)
		}
		actual, err := deleted.RowsAffected()
		if err != nil || actual != count {
			return CleanupResult{}, s.fail(ErrUnavailable)
		}
		result.Records += count
		result.LogicalBytes += logical
		result.BodyBytes += body
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, s.fail(ErrUnavailable)
	}
	return result, nil
}
