package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// Store borrows the owner's database. It never opens or closes a connection.
type Store struct {
	db             *sqlitestore.DB
	cfg            Config
	mu             sync.Mutex
	lastError      string
	droppedRecords uint64
}

func NewStore(db *sqlitestore.DB, cfg Config) *Store {
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = DefaultRetentionDays
	}
	if cfg.RetentionDays > 3650 {
		cfg.RetentionDays = 3650
	}
	if cfg.MaxRecords <= 0 {
		cfg.MaxRecords = DefaultMaxRecords
	}
	if cfg.MaxRecords > 100000 {
		cfg.MaxRecords = 100000
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxBodyBytes > MaxRequestBodyBytes {
		cfg.MaxBodyBytes = MaxRequestBodyBytes
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if cfg.MaxTotalBytes > MaxTotalBytes {
		cfg.MaxTotalBytes = MaxTotalBytes
	}
	return &Store{db: db, cfg: cfg}
}

func (s *Store) fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastError = err.Error()
	} else {
		s.lastError = ""
	}
	return err
}
func (s *Store) ready() error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) cutoff(now time.Time) int64 {
	return now.UTC().Add(-time.Duration(s.cfg.RetentionDays) * 24 * time.Hour).UnixMilli()
}
func randomID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(raw[:]), nil
}
func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 32
}
func validText(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
func safeOutcome(value string) bool {
	switch value {
	case "pending", "running", "unknown", "success", "succeeded", "failed", "rejected", "cancelled", "canceled", "aborted":
		return true
	}
	return false
}

func (s *Store) normalize(r Record, now time.Time) (Record, int64, error) {
	// Discard legacy network fields before validation, sizing or persistence.
	r.ClientIP, r.PeerIP, r.IPSource, r.IPNote = "", "", "", ""
	if strings.TrimSpace(r.RequestID) == "" || !validText(r.RequestID, 256) || !validText(r.TraceID, 256) {
		return r, 0, ErrInvalidRecord
	}
	var idErr error
	r.ID, idErr = randomID()
	if idErr != nil {
		return r, 0, idErr
	}
	if r.StartedAt == 0 {
		r.StartedAt = now.UnixMilli()
	}
	if r.StartedAt < 0 || r.StartedAt > now.Add(5*time.Minute).UnixMilli() {
		return r, 0, ErrInvalidRecord
	}
	if r.CompletedAt < 0 || (r.CompletedAt != 0 && (r.CompletedAt < r.StartedAt || r.CompletedAt > now.Add(5*time.Minute).UnixMilli())) || r.DurationMS < 0 || r.InputTokens < 0 || r.OutputTokens < 0 || r.TotalTokens < 0 || r.StatusCode < 0 || r.StatusCode > 599 {
		return r, 0, ErrInvalidRecord
	}
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
		return r, 0, ErrInvalidRecord
	}
	// Query strings and fragments can contain API keys. Only the route is retained.
	if i := strings.IndexAny(r.Path, "?#"); i >= 0 {
		r.Path = r.Path[:i]
	}
	if r.Outcome == "" {
		r.Outcome = "pending"
	}
	if !safeOutcome(r.Outcome) {
		return r, 0, ErrInvalidRecord
	}
	for _, value := range []string{r.Method, r.Path, r.KeyLabel, r.KeyFingerprint, r.RequestedModel, r.ServedModel, r.Protocol, r.BodyState} {
		if !validText(value, 1024) {
			return r, 0, ErrInvalidRecord
		}
	}
	if len(r.Method) > 32 || (r.KeyFingerprint != "" && !validID(r.KeyFingerprint)) {
		return r, 0, ErrInvalidRecord
	}
	r.KeyFingerprint = strings.ToLower(r.KeyFingerprint)
	capture := r.BodyState == "stored_raw_system_filtered" || r.BodyState == "stored_raw_system_media_filtered" || r.BodyState == "stored_raw_media_filtered" || r.BodyState == "stored_raw" || r.BodyState == "stored_partial" || r.BodyState == "stored" || r.BodyState == "sanitized" || r.BodyState == "truncated"
	if !capture || (r.BodyState != "stored_raw" && r.BodyState != "stored_raw_media_filtered" && r.BodyState != "stored_raw_system_filtered" && r.BodyState != "stored_raw_system_media_filtered" && !knownProtocol(r.Protocol)) {
		r.RequestBody = ""
		r.BodySHA256 = ""
		if r.BodyState == "" || capture {
			r.BodyState = "not_captured"
		}
	}
	if r.BodyState == "stored_raw" || r.BodyState == "stored_raw_media_filtered" || r.BodyState == "stored_raw_system_filtered" || r.BodyState == "stored_raw_system_media_filtered" {
		r.BodyTruncated = false
	}
	if r.RequestBody != "" {
		if len(r.RequestBody) > s.cfg.MaxBodyBytes {
			r.RequestBody = ""
			r.BodySHA256 = ""
			r.BodyState = "omitted_size"
			r.BodyTruncated = true
		} else if !json.Valid([]byte(r.RequestBody)) || !validID(r.BodySHA256) || !utf8.ValidString(r.RequestBody) || (!strings.HasPrefix(strings.TrimSpace(r.RequestBody), "{") && !strings.HasPrefix(strings.TrimSpace(r.RequestBody), "[")) {
			r.RequestBody = ""
			r.BodySHA256 = ""
			r.BodyState = "not_captured"
		} else {
			hash := sha256.Sum256([]byte(r.RequestBody))
			expected := hex.EncodeToString(hash[:])
			if !strings.EqualFold(r.BodySHA256, expected) {
				r.RequestBody = ""
				r.BodySHA256 = ""
				r.BodyState = "not_captured"
			} else {
				r.BodySHA256 = expected
			}
		}
	} else {
		r.BodySHA256 = ""
	}
	return r, logicalBytes(r), nil
}
func knownProtocol(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "openai", "openai-chat", "openai_chat", "openai-chat-completions", "openai-responses", "openai_responses", "responses", "anthropic", "claude", "gemini", "google-gemini":
		return true
	}
	return false
}
func logicalBytes(r Record) int64 {
	n := int64(256)
	for _, value := range []string{r.ID, r.RequestID, r.TraceID, r.Method, r.Path, r.KeyLabel, r.KeyFingerprint, r.RequestedModel, r.ServedModel, r.Protocol, r.Outcome, r.BodyState, r.RequestBody, r.BodySHA256} {
		n += int64(len(value))
	}
	return n
}

const columns = "id,request_id,trace_id,started_at,completed_at,method,path,client_ip,peer_ip,ip_source,ip_note,key_label,key_fingerprint,requested_model,served_model,protocol,stream,outcome,status_code,duration_ms,body_state,body_truncated,request_body,body_sha256,input_tokens,output_tokens,total_tokens"
const detailColumns = "id,request_id,trace_id,started_at,completed_at,method,path,'' AS client_ip,'' AS peer_ip,'' AS ip_source,'' AS ip_note,key_label,key_fingerprint,requested_model,served_model,protocol,stream,outcome,status_code,duration_ms,body_state,body_truncated,request_body,body_sha256,input_tokens,output_tokens,total_tokens"
const listColumns = "id,request_id,trace_id,started_at,completed_at,method,path,'' AS client_ip,'' AS peer_ip,'' AS ip_source,'' AS ip_note,key_label,key_fingerprint,requested_model,served_model,protocol,stream,outcome,status_code,duration_ms,body_state,body_truncated,'' AS request_body,body_sha256,input_tokens,output_tokens,total_tokens"

func recordArgs(r Record) []any {
	return []any{r.ID, r.RequestID, r.TraceID, r.StartedAt, r.CompletedAt, r.Method, r.Path, "", "", "", "", r.KeyLabel, r.KeyFingerprint, r.RequestedModel, r.ServedModel, r.Protocol, r.Stream, r.Outcome, r.StatusCode, r.DurationMS, r.BodyState, r.BodyTruncated, r.RequestBody, r.BodySHA256, r.InputTokens, r.OutputTokens, r.TotalTokens}
}
func scanRecord(scanner interface{ Scan(...any) error }, extra ...any) (Record, error) {
	var r Record
	targets := []any{&r.ID, &r.RequestID, &r.TraceID, &r.StartedAt, &r.CompletedAt, &r.Method, &r.Path, &r.ClientIP, &r.PeerIP, &r.IPSource, &r.IPNote, &r.KeyLabel, &r.KeyFingerprint, &r.RequestedModel, &r.ServedModel, &r.Protocol, &r.Stream, &r.Outcome, &r.StatusCode, &r.DurationMS, &r.BodyState, &r.BodyTruncated, &r.RequestBody, &r.BodySHA256, &r.InputTokens, &r.OutputTokens, &r.TotalTokens}
	err := scanner.Scan(append(targets, extra...)...)
	r.ClientIP, r.PeerIP, r.IPSource, r.IPNote = "", "", "", ""
	return r, err
}

func (s *Store) Begin(ctx context.Context, record Record) error {
	if s != nil && !s.cfg.Enabled {
		return ErrDisabled
	}
	if err := s.ready(); err != nil {
		return err
	}
	now := time.Now().UTC()
	r, size, err := s.normalize(record, now)
	if err != nil {
		return s.fail(err)
	}
	tx, err := s.db.Conn().BeginTx(ctx, nil)
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	defer tx.Rollback()
	// Insertion and enforcement share one transaction; uniqueness never rewrites a body.
	if r.StartedAt >= s.cutoff(now) && size <= s.cfg.MaxTotalBytes {
		args := append(recordArgs(r), size)
		_, err = tx.ExecContext(ctx, "INSERT INTO client_request_audit ("+columns+",logical_bytes) VALUES ("+strings.TrimSuffix(strings.Repeat("?,", 28), ",")+") ON CONFLICT(request_id) DO NOTHING", args...)
		if err != nil {
			return s.fail(ErrUnavailable)
		}
	}
	if err := s.pruneTx(ctx, tx, now); err != nil {
		return s.fail(err)
	}
	if err := tx.Commit(); err != nil {
		return s.fail(ErrUnavailable)
	}
	if size > s.cfg.MaxTotalBytes {
		s.mu.Lock()
		s.droppedRecords++
		s.mu.Unlock()
		return s.fail(ErrCapacity)
	}
	return s.fail(nil)
}

func (s *Store) Complete(ctx context.Context, c Completion) error {
	if s != nil && !s.cfg.Enabled {
		return ErrDisabled
	}
	if err := s.ready(); err != nil {
		return err
	}
	if c.RequestID == "" || !validText(c.RequestID, 256) || !validText(c.TraceID, 256) || !validText(c.ServedModel, 1024) || (c.Outcome != "" && !safeOutcome(c.Outcome)) || c.Outcome == "pending" || c.Outcome == "running" || c.CompletedAt < 0 || c.DurationMS < 0 || c.StatusCode < 0 || c.StatusCode > 599 || c.InputTokens < 0 || c.OutputTokens < 0 || c.TotalTokens < 0 {
		return s.fail(ErrInvalidRecord)
	}
	now := time.Now().UTC()
	if c.CompletedAt > now.Add(5*time.Minute).UnixMilli() {
		return s.fail(ErrInvalidRecord)
	}
	if c.Outcome != "" && c.CompletedAt == 0 {
		c.CompletedAt = now.UnixMilli()
	}
	tx, err := s.db.Conn().BeginTx(ctx, nil)
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	defer tx.Rollback()
	var storedLogicalBytes int64
	r, err := scanRecord(tx.QueryRowContext(ctx, "SELECT "+listColumns+",logical_bytes FROM client_request_audit WHERE request_id=? AND started_at>=?", c.RequestID, s.cutoff(now)), &storedLogicalBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	previousMetadataBytes := logicalBytes(r)
	if c.Outcome != "" {
		if r.CompletedAt != 0 || r.Outcome == "rejected" {
			return nil
		}
		if c.CompletedAt < r.StartedAt {
			c.CompletedAt = r.StartedAt
		}
		r.CompletedAt = c.CompletedAt
		if c.DurationMS == 0 {
			c.DurationMS = c.CompletedAt - r.StartedAt
		}
		r.DurationMS = c.DurationMS
		r.Outcome, r.StatusCode = c.Outcome, c.StatusCode
	}
	if r.TraceID == "" {
		r.TraceID = c.TraceID
	}
	if c.ServedModel != "" {
		r.ServedModel = c.ServedModel
	}
	if c.InputTokens > r.InputTokens {
		r.InputTokens = c.InputTokens
	}
	if c.OutputTokens > r.OutputTokens {
		r.OutputTokens = c.OutputTokens
	}
	if c.TotalTokens > r.TotalTokens {
		r.TotalTokens = c.TotalTokens
	}

	_, err = tx.ExecContext(ctx, "UPDATE client_request_audit SET trace_id=?,completed_at=?,served_model=?,outcome=?,status_code=?,duration_ms=?,input_tokens=?,output_tokens=?,total_tokens=?,logical_bytes=? WHERE id=?", r.TraceID, r.CompletedAt, r.ServedModel, r.Outcome, r.StatusCode, r.DurationMS, r.InputTokens, r.OutputTokens, r.TotalTokens, storedLogicalBytes+logicalBytes(r)-previousMetadataBytes, r.ID)
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	if err := s.pruneTx(ctx, tx, now); err != nil {
		return s.fail(err)
	}
	if err := tx.Commit(); err != nil {
		return s.fail(ErrUnavailable)
	}
	return s.fail(nil)
}

func (s *Store) Prune(ctx context.Context, now time.Time) error {
	if err := s.ready(); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// An explicit connection lease waits for database/sql automatic rollback on
	// context cancellation before returning. Otherwise Close may finish while a
	// cancelled cleanup still owns a driver handle (notably visible on Windows).
	connection, err := s.db.Conn().Conn(ctx)
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	defer connection.Close()
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return s.fail(ErrUnavailable)
	}
	defer tx.Rollback()
	if err := s.pruneTx(ctx, tx, now); err != nil {
		return s.fail(err)
	}
	if err := tx.Commit(); err != nil {
		return s.fail(ErrUnavailable)
	}
	return nil
}
func (s *Store) pruneTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM client_request_audit WHERE started_at<?", s.cutoff(now)); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM client_request_audit WHERE id IN (SELECT id FROM client_request_audit ORDER BY started_at DESC,id DESC LIMIT -1 OFFSET ?)", s.cfg.MaxRecords); err != nil {
		return ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,logical_bytes FROM client_request_audit ORDER BY started_at DESC,id DESC LIMIT ?", s.cfg.MaxRecords)
	if err != nil {
		return ErrUnavailable
	}
	var remove []string
	var total int64
	exhausted := false
	for rows.Next() {
		var id string
		var size int64
		if err := rows.Scan(&id, &size); err != nil {
			rows.Close()
			return ErrUnavailable
		}
		if exhausted || size < 0 || size > s.cfg.MaxTotalBytes-total {
			exhausted = true
			remove = append(remove, id)
		} else {
			total += size
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrUnavailable
	}
	for start := 0; start < len(remove); start += 200 {
		end := start + 200
		if end > len(remove) {
			end = len(remove)
		}
		args := make([]any, end-start)
		for i, id := range remove[start:end] {
			args[i] = id
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM client_request_audit WHERE id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func (s *Store) List(ctx context.Context, q Query) (ListResult, error) {
	result := ListResult{Records: []Record{}, Limit: q.Limit, Offset: q.Offset}
	if err := s.ready(); err != nil {
		return result, err
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > MaxQueryLimit {
		q.Limit = MaxQueryLimit
	}
	result.Limit = q.Limit
	if q.IP != "" || q.Offset < 0 || q.Offset > MaxQueryOffset || q.From < 0 || q.To < 0 || (q.From != 0 && q.To != 0 && q.To < q.From) {
		return result, ErrInvalidQuery
	}
	if q.KeyFingerprint != "" {
		if !validID(q.KeyFingerprint) {
			return result, ErrInvalidQuery
		}
		q.KeyFingerprint = strings.ToLower(q.KeyFingerprint)
	}
	where := "started_at>=?"
	args := []any{s.cutoff(time.Now().UTC())}
	for _, f := range []struct{ column, value string }{{"request_id", q.RequestID}, {"trace_id", q.TraceID}, {"key_fingerprint", q.KeyFingerprint}, {"outcome", q.Outcome}} {
		if f.value != "" {
			if !validText(f.value, 1024) {
				return result, ErrInvalidQuery
			}
			where += " AND " + f.column + "=?"
			args = append(args, f.value)
		}
	}
	if q.KeyLabel != "" {
		if !validText(q.KeyLabel, 1024) {
			return result, ErrInvalidQuery
		}
		where += " AND instr(lower(key_label),lower(?))>0"
		args = append(args, q.KeyLabel)
	}
	if q.Model != "" {
		if !validText(q.Model, 1024) {
			return result, ErrInvalidQuery
		}
		// instr treats %, _ and SQL-looking input as literal text, not patterns.
		where += " AND (instr(lower(requested_model),lower(?))>0 OR instr(lower(served_model),lower(?))>0)"
		args = append(args, q.Model, q.Model)
	}
	if q.From > 0 {
		where += " AND started_at>=?"
		args = append(args, q.From)
	}
	if q.To > 0 {
		where += " AND started_at<=?"
		args = append(args, q.To)
	}
	tx, err := s.db.Conn().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, s.fail(ErrUnavailable)
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM client_request_audit WHERE "+where, args...).Scan(&result.Total); err != nil {
		return result, s.fail(ErrUnavailable)
	}
	args = append(args, q.Limit, q.Offset)
	rows, err := tx.QueryContext(ctx, "SELECT "+listColumns+" FROM client_request_audit WHERE "+where+" ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return result, s.fail(ErrUnavailable)
	}
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return result, s.fail(ErrUnavailable)
		}
		result.Records = append(result.Records, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, s.fail(ErrUnavailable)
	}
	if err := tx.Commit(); err != nil {
		return result, s.fail(ErrUnavailable)
	}
	return result, nil
}
func (s *Store) Detail(ctx context.Context, id string) (Record, error) {
	var result Record
	if err := s.ready(); err != nil {
		return result, err
	}
	if !validID(id) {
		return result, ErrNotFound
	}
	result, err := scanRecord(s.db.Conn().QueryRowContext(ctx, "SELECT "+detailColumns+" FROM client_request_audit WHERE id=? AND started_at>=?", id, s.cutoff(time.Now().UTC())))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, s.fail(ErrUnavailable)
	}
	return result, nil
}
func (s *Store) Status() Status {
	if s == nil {
		return Status{CapacityMode: "logical_payload_not_physical_file"}
	}
	status := Status{Enabled: s.cfg.Enabled, Configured: s.db != nil, RetentionDays: s.cfg.RetentionDays, MaxRecords: s.cfg.MaxRecords, MaxBodyBytes: s.cfg.MaxBodyBytes, MaxTotalBytes: s.cfg.MaxTotalBytes, CapacityMode: "logical_payload_not_physical_file"}
	s.mu.Lock()
	status.LastError = s.lastError
	status.DroppedRecords = s.droppedRecords
	s.mu.Unlock()
	if s.db == nil {
		return status
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.db.Conn().QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(logical_bytes),0) FROM (SELECT logical_bytes FROM client_request_audit WHERE started_at>=? ORDER BY started_at DESC,id DESC LIMIT ?)", s.cutoff(time.Now().UTC()), s.cfg.MaxRecords+1).Scan(&status.Records, &status.LogicalBytes)
	if err != nil {
		status.LastError = ErrUnavailable.Error()
	}
	return status
}
