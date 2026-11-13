package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrCleanupPreviewExpired = errors.New("audit cleanup preview expired")
	ErrCleanupBusy           = errors.New("audit cleanup already active or preview capacity reached")
	ErrCleanupJobState       = errors.New("invalid audit cleanup job state")
	ErrCleanupTooLarge       = errors.New("audit cleanup snapshot or record exceeds budget")
)

const cleanupPreviewTTL = 5 * time.Minute
const cleanupHistoryLimit = 100

// CleanupJobPreview confirms the whole immutable ID snapshot, not just its first batch.
// Tokens are returned only here; the database retains only a SHA-256 digest.
type CleanupJobPreview struct {
	Token            string    `json:"token"`
	ExpiresAt        time.Time `json:"expires_at"`
	Records          int64     `json:"records"`
	LogicalBytes     int64     `json:"logical_bytes"`
	RequestBodyBytes int64     `json:"request_body_bytes"`
	BatchMaxRecords  int       `json:"batch_max_records"`
	BatchMaxBytes    int64     `json:"batch_max_bytes"`
	Scope            string    `json:"scope"`
	Before           string    `json:"before"`
}

type CleanupJob struct {
	ID                  string    `json:"id"`
	State               string    `json:"state"`
	TotalRecords        int64     `json:"total_records"`
	ProcessedRecords    int64     `json:"processed_records"`
	DeletedRecords      int64     `json:"deleted_records"`
	SkippedRecords      int64     `json:"skipped_records"`
	RemainingRecords    int64     `json:"remaining_records"`
	DeletedLogicalBytes int64     `json:"deleted_logical_bytes"`
	DeletedBodyBytes    int64     `json:"deleted_body_bytes"`
	Batches             int64     `json:"batches"`
	BatchMaxRecords     int       `json:"batch_max_records"`
	BatchMaxBytes       int64     `json:"batch_max_bytes"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	ErrorCode           string    `json:"error_code"`
	tokenHash           string
}

const cleanupJobColumns = "id,state,total_records,processed_records,deleted_records,skipped_records,remaining_records,deleted_logical_bytes,deleted_body_bytes,batches,batch_max_records,batch_max_bytes,created_at,updated_at,error_code,token_hash"

type cleanupScanner interface{ Scan(...any) error }

func scanCleanupJob(row cleanupScanner) (CleanupJob, error) {
	var job CleanupJob
	var created, updated int64
	err := row.Scan(&job.ID, &job.State, &job.TotalRecords, &job.ProcessedRecords, &job.DeletedRecords, &job.SkippedRecords, &job.RemainingRecords, &job.DeletedLogicalBytes, &job.DeletedBodyBytes, &job.Batches, &job.BatchMaxRecords, &job.BatchMaxBytes, &created, &updated, &job.ErrorCode, &job.tokenHash)
	job.CreatedAt = time.UnixMilli(created).UTC()
	job.UpdatedAt = time.UnixMilli(updated).UTC()
	if errors.Is(err, sql.ErrNoRows) {
		return CleanupJob{}, ErrNotFound
	}
	if err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	return job, nil
}
func cleanupDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// cleanupTransaction retains a borrowed connection through rollback, including
// database/sql's asynchronous rollback after context cancellation.
func (s *Store) cleanupTransaction(ctx context.Context) (*sql.Conn, *sql.Tx, error) {
	if err := s.ready(); err != nil {
		return nil, nil, err
	}
	conn, err := s.db.Conn().Conn(ctx)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		conn.Close()
		return nil, nil, ErrUnavailable
	}
	return conn, tx, nil
}

// cleanupGC never removes active work. Unstarted snapshots expire in five minutes;
// terminal metadata (and failed resumable snapshots) has a seven-day/100-job cap.
func cleanupGC(ctx context.Context, tx *sql.Tx, now int64) error {
	doomed := `SELECT token_hash FROM audit_cleanup_jobs WHERE state NOT IN ('queued','running') AND (updated_at<? OR id NOT IN (SELECT id FROM audit_cleanup_jobs WHERE state NOT IN ('queued','running') ORDER BY updated_at DESC,id DESC LIMIT ?))`
	cutoff := now - int64((7*24*time.Hour)/time.Millisecond)
	// Once collection begins, a failed snapshot must never become resumable.
	// Keep its descriptor until the last item is gone, without resetting age.
	if _, err := tx.ExecContext(ctx, "UPDATE audit_cleanup_jobs SET error_code='snapshot_expired' WHERE state='failed' AND token_hash IN ("+doomed+")", cutoff, cleanupHistoryLimit); err != nil {
		return err
	}
	// Limit physical metadata work per call; repeated idle ticks drain backlogs.
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_items WHERE (snapshot_hash,record_id) IN (SELECT snapshot_hash,record_id FROM audit_cleanup_items WHERE snapshot_hash IN (SELECT token_hash FROM audit_cleanup_previews WHERE expires_at<=?) OR snapshot_hash IN ("+doomed+") ORDER BY snapshot_hash,record_id LIMIT 5000)", now, cutoff, cleanupHistoryLimit); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_previews WHERE expires_at<=? AND NOT EXISTS(SELECT 1 FROM audit_cleanup_items WHERE snapshot_hash=audit_cleanup_previews.token_hash)", now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_jobs WHERE token_hash IN ("+doomed+") AND NOT EXISTS(SELECT 1 FROM audit_cleanup_items WHERE snapshot_hash=audit_cleanup_jobs.token_hash)", cutoff, cleanupHistoryLimit)
	return err
}

const cleanupPreviewTotalsQuery = `SELECT COUNT(*),COALESCE(SUM(logical_bytes),0),COALESCE(SUM(body_bytes),0),COALESCE(SUM(CASE WHEN length(id)!=64 OR id GLOB '*[^0-9a-fA-F]*' OR logical_bytes<0 OR body_bytes<0 THEN 1 ELSE 0 END),0)`

// PreviewCleanupJob captures metadata via a covering index in a bounded, durable
// transaction. No credentials, body contents or raw management tokens are copied.
func (s *Store) PreviewCleanupJob(ctx context.Context, scope, before, principalHash string, limits CleanupBatchLimits) (CleanupJobPreview, error) {
	return s.previewCleanupJob(ctx, scope, before, principalHash, limits, maxCleanupRecords)
}

// The snapshot bound is parameterized only for small, exhaustive boundary tests.
// The public entry always uses maxCleanupRecords; its five-second deadline is
// identical here and in the separately executed 100,000-row capacity benchmark.
func (s *Store) previewCleanupJob(ctx context.Context, scope, before, principalHash string, limits CleanupBatchLimits, snapshotMaxRecords int) (CleanupJobPreview, error) {
	var preview CleanupJobPreview
	if !validID(principalHash) {
		return preview, ErrInvalidCleanup
	}
	limits = limits.Normalized()
	if limits.Validate() != nil {
		return preview, ErrInvalidCleanup
	}
	now := safeExpireNow()
	where := "1=1"
	var args []any
	switch scope {
	case "all":
		if before != "" {
			return preview, ErrInvalidCleanup
		}
	case "expired":
		if before != "" {
			return preview, ErrInvalidCleanup
		}
		if err := s.ready(); err != nil {
			return preview, err
		}
		cutoff := s.cutoff(now)
		where = "started_at<?"
		args = []any{cutoff}
		before = time.UnixMilli(cutoff).UTC().Format(time.RFC3339Nano)
	case "before":
		parsed, err := time.Parse(time.RFC3339Nano, before)
		if err != nil || parsed.After(now) || parsed.UnixMilli() < 0 {
			return preview, ErrInvalidCleanup
		}
		before = parsed.UTC().Format(time.RFC3339Nano)
		where = "started_at<?"
		args = []any{parsed.UnixMilli()}
	default:
		return preview, ErrInvalidCleanup
	}
	token, err := randomID()
	if err != nil {
		return preview, err
	}
	hash := cleanupDigest(token)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, tx, err := s.cleanupTransaction(ctx)
	if err != nil {
		return preview, err
	}
	defer conn.Close()
	defer tx.Rollback()
	if err := cleanupGC(ctx, tx, now.UnixMilli()); err != nil {
		return preview, ErrUnavailable
	}
	if err := checkCleanupPreviewCapacity(ctx, tx, now.UnixMilli()); err != nil {
		return preview, err
	}
	// Preflight only covering-index metadata before writing a potentially large
	// snapshot. Exact-bound+1 rejection needs no 100,001-item insert/rollback.
	// The same transaction protects the count and the subsequent ID copy.
	metadataArgs := append([]any(nil), args...)
	metadataArgs = append(metadataArgs, snapshotMaxRecords+1)
	var invalid int
	err = tx.QueryRowContext(ctx, cleanupPreviewTotalsQuery+" FROM (SELECT id,logical_bytes,length(CAST(request_body AS BLOB)) AS body_bytes FROM "+auditStorageMetadata+" WHERE "+where+" ORDER BY started_at,id LIMIT ?)", metadataArgs...).Scan(&preview.Records, &preview.LogicalBytes, &preview.RequestBodyBytes, &invalid)
	if err != nil || invalid != 0 {
		return CleanupJobPreview{}, ErrUnavailable
	}
	if preview.Records > int64(snapshotMaxRecords) {
		return CleanupJobPreview{}, ErrCleanupTooLarge
	}
	insertArgs := []any{hash}
	insertArgs = append(insertArgs, args...)
	insertArgs = append(insertArgs, snapshotMaxRecords)
	_, err = tx.ExecContext(ctx, "INSERT INTO audit_cleanup_items(snapshot_hash,record_id,started_at,logical_bytes,body_bytes) SELECT ?,id,started_at,logical_bytes,length(CAST(request_body AS BLOB)) FROM "+auditStorageMetadata+" WHERE "+where+" ORDER BY started_at,id LIMIT ?", insertArgs...)
	if err != nil {
		return CleanupJobPreview{}, ErrUnavailable
	}
	preview.Token = token
	preview.Scope = scope
	preview.Before = before
	preview.ExpiresAt = now.Add(cleanupPreviewTTL)
	preview.BatchMaxRecords = limits.MaxRecords
	preview.BatchMaxBytes = limits.MaxBytes
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_cleanup_previews(token_hash,principal_hash,created_at,expires_at,scope,before_value,records,logical_bytes,body_bytes,batch_max_records,batch_max_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, hash, principalHash, now.UnixMilli(), preview.ExpiresAt.UnixMilli(), scope, before, preview.Records, preview.LogicalBytes, preview.RequestBodyBytes, limits.MaxRecords, limits.MaxBytes)
	if err != nil {
		return CleanupJobPreview{}, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return CleanupJobPreview{}, ErrUnavailable
	}
	return preview, nil
}

func (s *Store) StartCleanupJob(ctx context.Context, token, principalHash string) (CleanupJob, error) {
	if !validID(token) || !validID(principalHash) {
		return CleanupJob{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, tx, err := s.cleanupTransaction(ctx)
	if err != nil {
		return CleanupJob{}, err
	}
	defer conn.Close()
	defer tx.Rollback()
	hash := cleanupDigest(token)
	// Idempotency intentionally precedes TTL and active-job checks.
	existing, err := scanCleanupJob(tx.QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE token_hash=? AND principal_hash=?", hash, principalHash))
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return CleanupJob{}, err
	}
	var records, expires, bytes int64
	var maxRecords int
	err = tx.QueryRowContext(ctx, "SELECT records,expires_at,batch_max_records,batch_max_bytes FROM audit_cleanup_previews WHERE token_hash=? AND principal_hash=?", hash, principalHash).Scan(&records, &expires, &maxRecords, &bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return CleanupJob{}, ErrNotFound
	}
	if err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	now := safeExpireNow().UnixMilli()
	if expires <= now {
		return CleanupJob{}, ErrCleanupPreviewExpired
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_cleanup_jobs WHERE state IN ('queued','running')").Scan(&active); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	if active != 0 {
		return CleanupJob{}, ErrCleanupBusy
	}
	id, err := randomID()
	if err != nil {
		return CleanupJob{}, err
	}
	state := "queued"
	if records == 0 {
		state = "completed"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_cleanup_jobs(id,token_hash,principal_hash,state,total_records,remaining_records,batch_max_records,batch_max_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, hash, principalHash, state, records, records, maxRecords, bytes, now, now)
	if err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	// Items remain under their token digest: ownership transfers atomically with
	// deleting the preview; no second snapshot or range query can expand it.
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_previews WHERE token_hash=?", hash); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	if err := cleanupGC(ctx, tx, now); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	job, err := scanCleanupJob(tx.QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE id=?", id))
	if err != nil {
		return CleanupJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	return job, nil
}

func (s *Store) ListCleanupJobs(ctx context.Context, principalHash string) ([]CleanupJob, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if !validID(principalHash) {
		return nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.Conn().QueryContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE principal_hash=? ORDER BY CASE state WHEN 'queued' THEN 0 WHEN 'running' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END,created_at DESC,id DESC LIMIT ?", principalHash, cleanupHistoryLimit+1)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	jobs := make([]CleanupJob, 0)
	for rows.Next() {
		job, err := scanCleanupJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return jobs, nil
}
func (s *Store) GetCleanupJob(ctx context.Context, id, principalHash string) (CleanupJob, error) {
	if err := s.ready(); err != nil {
		return CleanupJob{}, err
	}
	if !validID(id) || !validID(principalHash) {
		return CleanupJob{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return scanCleanupJob(s.db.Conn().QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE id=? AND principal_hash=?", id, principalHash))
}
func (s *Store) CancelCleanupJob(ctx context.Context, id, principalHash string) (CleanupJob, error) {
	return s.changeCleanupJobState(ctx, id, principalHash, false)
}
func (s *Store) ResumeCleanupJob(ctx context.Context, id, principalHash string) (CleanupJob, error) {
	return s.changeCleanupJobState(ctx, id, principalHash, true)
}
func (s *Store) changeCleanupJobState(ctx context.Context, id, principalHash string, resume bool) (CleanupJob, error) {
	if !validID(id) || !validID(principalHash) {
		return CleanupJob{}, ErrNotFound
	}
	// Cancellation waits for the currently borrowed 10-second batch connection;
	// it stops subsequent transactions, never rolls back a committed batch.
	timeout := 5 * time.Second
	if !resume {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, tx, err := s.cleanupTransaction(ctx)
	if err != nil {
		return CleanupJob{}, err
	}
	defer conn.Close()
	defer tx.Rollback()
	job, err := scanCleanupJob(tx.QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE id=? AND principal_hash=?", id, principalHash))
	if err != nil {
		return CleanupJob{}, err
	}
	target := "canceled"
	if resume {
		if job.State != "failed" || job.ErrorCode == "snapshot_expired" || job.UpdatedAt.Before(safeExpireNow().Add(-7*24*time.Hour)) {
			return CleanupJob{}, ErrCleanupJobState
		}
		var active int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_cleanup_jobs WHERE state IN ('queued','running')").Scan(&active); err != nil {
			return CleanupJob{}, ErrUnavailable
		}
		if active != 0 {
			return CleanupJob{}, ErrCleanupBusy
		}
		target = "queued"
	} else {
		if job.State == "canceled" {
			return job, nil
		}
		if job.State != "queued" && job.State != "running" && job.State != "failed" {
			return CleanupJob{}, ErrCleanupJobState
		}
	}
	now := safeExpireNow().UnixMilli()
	result, err := tx.ExecContext(ctx, "UPDATE audit_cleanup_jobs SET state=?,updated_at=?,error_code='' WHERE id=? AND state=?", target, now, id, job.State)
	if err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return CleanupJob{}, ErrCleanupJobState
	}
	if !resume {
		if _, err := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_items WHERE snapshot_hash=?", job.tokenHash); err != nil {
			return CleanupJob{}, ErrUnavailable
		}
	}
	if err := cleanupGC(ctx, tx, now); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	job, err = scanCleanupJob(tx.QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE id=?", id))
	if err != nil {
		return CleanupJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return CleanupJob{}, ErrUnavailable
	}
	return job, nil
}

const cleanupCurrentItemsQuery = `SELECT record_id FROM audit_cleanup_items INDEXED BY audit_cleanup_items_order_idx WHERE snapshot_hash=? ORDER BY started_at,record_id LIMIT ?`
const cleanupCurrentMetadataQuery = `SELECT id,logical_bytes,length(CAST(request_body AS BLOB)) FROM client_request_audit INDEXED BY client_request_audit_cleanup_metadata_idx WHERE id IN (`

// RunCleanupJobBatch processes the one active job, preserving the preview's budget
// when configuration increases and immediately honoring a lower current budget.
// Each DELETE chunk, item consumption and progress update commits in ONE transaction.
func (s *Store) RunCleanupJobBatch(ctx context.Context, limits CleanupBatchLimits) (worked bool, err error) {
	limits = limits.Normalized()
	if limits.Validate() != nil {
		return false, ErrInvalidCleanup
	}
	ctx, cancel := context.WithTimeout(ctx, CleanupApplyTimeout)
	defer cancel()
	conn, tx, err := s.cleanupTransaction(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	var job CleanupJob
	defer func() {
		_ = tx.Rollback()
		if err == nil || job.ID == "" || errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		code := "storage_unavailable"
		if errors.Is(err, ErrCleanupTooLarge) {
			code = "record_exceeds_batch_budget"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = "batch_timeout"
		}
		// Persist failure outside the rolled-back batch. If storage is still broken,
		// leaving queued/running is intentional: the durable task will be retried.
		failCtx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		_, _ = conn.ExecContext(failCtx, "UPDATE audit_cleanup_jobs SET state='failed',error_code=?,updated_at=? WHERE id=? AND state IN ('queued','running')", code, safeExpireNow().UnixMilli(), job.ID)
	}()
	job, err = scanCleanupJob(tx.QueryRowContext(ctx, "SELECT "+cleanupJobColumns+" FROM audit_cleanup_jobs WHERE state IN ('queued','running') LIMIT 1"))
	if errors.Is(err, ErrNotFound) {
		// Idle workers reclaim expired metadata too, without taking a write lock
		// on every poll when there is nothing to collect.
		now := safeExpireNow().UnixMilli()
		var needed bool
		gcQuery := `SELECT EXISTS(SELECT 1 FROM audit_cleanup_previews WHERE expires_at<=?) OR EXISTS(SELECT 1 FROM audit_cleanup_jobs WHERE state NOT IN ('queued','running') AND updated_at<?) OR EXISTS(SELECT 1 FROM audit_cleanup_jobs WHERE state NOT IN ('queued','running') LIMIT 1 OFFSET ?)`
		if tx.QueryRowContext(ctx, gcQuery, now, now-int64((7*24*time.Hour)/time.Millisecond), cleanupHistoryLimit).Scan(&needed) != nil {
			return false, ErrUnavailable
		}
		if !needed {
			return false, nil
		}
		if cleanupGC(ctx, tx, now) != nil {
			return false, ErrUnavailable
		}
		if tx.Commit() != nil {
			return false, ErrUnavailable
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	worked = true
	maxRecords := min(job.BatchMaxRecords, limits.MaxRecords)
	maxBytes := min(job.BatchMaxBytes, limits.MaxBytes)
	rows, queryErr := tx.QueryContext(ctx, cleanupCurrentItemsQuery, job.tokenHash, maxRecords)
	if queryErr != nil {
		return true, ErrUnavailable
	}
	candidates := make([]string, 0, maxRecords)
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !validID(id) {
			rows.Close()
			return true, ErrUnavailable
		}
		candidates = append(candidates, id)
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return true, ErrUnavailable
	}
	// LEFT JOIN prevents SQLite's expression-index substitution and reads body
	// payloads. Read only the selected IDs from the covering index in chunks.
	type currentMetadata struct{ logical, body int64 }
	metadata := make(map[string]currentMetadata, len(candidates))
	for start := 0; start < len(candidates); start += 200 {
		end := min(start+200, len(candidates))
		args := make([]any, end-start)
		for i, id := range candidates[start:end] {
			args[i] = id
		}
		currentRows, queryErr := tx.QueryContext(ctx, cleanupCurrentMetadataQuery+cleanupPlaceholders(len(args))+")", args...)
		if queryErr != nil {
			return true, ErrUnavailable
		}
		for currentRows.Next() {
			var id string
			var current currentMetadata
			if currentRows.Scan(&id, &current.logical, &current.body) != nil || current.logical < 0 || current.body < 0 {
				currentRows.Close()
				return true, ErrUnavailable
			}
			metadata[id] = current
		}
		readErr := currentRows.Err()
		currentRows.Close()
		if readErr != nil {
			return true, ErrUnavailable
		}
	}
	ids := make([]string, 0, len(candidates))
	present := make([]string, 0, len(candidates))
	var used, logicalTotal, bodyTotal int64
	for _, id := range candidates {
		if current, exists := metadata[id]; exists {
			cost := max(current.logical, current.body)
			if cost > maxBytes-used {
				if len(ids) == 0 {
					return true, ErrCleanupTooLarge
				}
				break
			}
			used += cost
			logicalTotal += current.logical
			bodyTotal += current.body
			present = append(present, id)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 && job.RemainingRecords != 0 {
		return true, ErrUnavailable
	}
	for start := 0; start < len(present); start += 200 {
		end := min(start+200, len(present))
		args := make([]any, end-start)
		for i, id := range present[start:end] {
			args[i] = id
		}
		result, deleteErr := tx.ExecContext(ctx, "DELETE FROM client_request_audit WHERE id IN ("+cleanupPlaceholders(len(args))+")", args...)
		if deleteErr != nil {
			return true, ErrUnavailable
		}
		if changed, countErr := result.RowsAffected(); countErr != nil || changed != int64(len(args)) {
			return true, ErrUnavailable
		}
	}
	for start := 0; start < len(ids); start += 200 {
		end := min(start+200, len(ids))
		args := []any{job.tokenHash}
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		result, consumeErr := tx.ExecContext(ctx, "DELETE FROM audit_cleanup_items WHERE snapshot_hash=? AND record_id IN ("+cleanupPlaceholders(end-start)+")", args...)
		if consumeErr != nil {
			return true, ErrUnavailable
		}
		if changed, countErr := result.RowsAffected(); countErr != nil || changed != int64(end-start) {
			return true, ErrUnavailable
		}
	}
	remaining := job.RemainingRecords - int64(len(ids))
	if remaining < 0 {
		return true, ErrUnavailable
	}
	state := "running"
	if remaining == 0 {
		state = "completed"
	}
	now := safeExpireNow().UnixMilli()
	_, err = tx.ExecContext(ctx, `UPDATE audit_cleanup_jobs SET state=?,processed_records=processed_records+?,deleted_records=deleted_records+?,skipped_records=skipped_records+?,remaining_records=?,deleted_logical_bytes=deleted_logical_bytes+?,deleted_body_bytes=deleted_body_bytes+?,batches=batches+1,updated_at=?,error_code='' WHERE id=? AND state IN ('queued','running')`, state, len(ids), len(present), len(ids)-len(present), remaining, logicalTotal, bodyTotal, now, job.ID)
	if err != nil {
		return true, ErrUnavailable
	}
	if state == "completed" {
		if err := cleanupGC(ctx, tx, now); err != nil {
			return true, ErrUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return true, ErrUnavailable
	}
	return true, nil
}
func cleanupPlaceholders(count int) string {
	return strings.TrimSuffix(strings.Repeat("?,", count), ",")
}

// Capacity validation is independent of collection throughput. An expired
// descriptor may still have items awaiting bounded GC, but consumes only the
// retained-descriptor cap, not one of the eight live confirmation slots.
func checkCleanupPreviewCapacity(ctx context.Context, tx *sql.Tx, now int64) error {
	var live, retained int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN expires_at>? THEN 1 ELSE 0 END),0) FROM audit_cleanup_previews", now).Scan(&retained, &live); err != nil {
		return ErrUnavailable
	}
	if live >= 8 || retained >= 16 {
		return ErrCleanupBusy
	}
	return nil
}
