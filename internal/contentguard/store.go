package contentguard

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// Event is one persisted interception or flag. Body is filtered plaintext and
// is only returned by Detail/Export, never by List.
type Event struct {
	ID             string            `json:"id"`
	CreatedAt      int64             `json:"-"`
	RequestID      string            `json:"request_id"`
	TraceID        string            `json:"trace_id"`
	Path           string            `json:"path"`
	Protocol       string            `json:"protocol"`
	RequestedModel string            `json:"requested_model"`
	ServedModel    string            `json:"served_model"`
	Stream         bool              `json:"stream"`
	KeyName        string            `json:"key_name"`
	KeyMasked      string            `json:"key_masked"`
	KeyFingerprint string            `json:"key_fingerprint"`
	Action         string            `json:"action"`
	Mode           string            `json:"mode"`
	Severity       string            `json:"severity"`
	RuleNames      []string          `json:"rule_names"`
	Matches        []Match           `json:"matches,omitempty"`
	Classifier     *ClassifierRecord `json:"classifier,omitempty"`
	Body           string            `json:"body,omitempty"`
	BodyState      string            `json:"body_state"`
	BodyTruncated  bool              `json:"body_truncated"`
	BodyBytes      int               `json:"body_bytes"`
	BodySHA256     string            `json:"body_sha256"`               // SHA-256 of exact stored Body bytes
	OriginalBytes  int               `json:"original_bytes"`            // Complete input size; not retained bytes
	OriginalSHA256 string            `json:"original_sha256,omitempty"` // SHA-256 of complete validated original bytes
	ScanTruncated  bool              `json:"scan_truncated"`
	AutoDisabled   string            `json:"auto_disabled"` // "", "disabled", "skipped", "failed"
	ReviewStatus   string            `json:"review_status"`
	ReviewNote     string            `json:"review_note"`
	ReviewedAt     int64             `json:"-"`
	LogicalBytes   int64             `json:"logical_bytes"`
}

// ClassifierRecord keeps the moderation verdict or failure code.
type ClassifierRecord struct {
	Flagged  bool    `json:"flagged"`
	Score    float64 `json:"score,omitempty"`
	Category string  `json:"category,omitempty"`
	Reason   string  `json:"reason,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// Review statuses.
const (
	ReviewPending   = "pending"
	ReviewConfirmed = "confirmed"
	ReviewFalse     = "false_positive"
	ReviewResolved  = "resolved"
)

// ValidReview reports whether status is a known review state.
func ValidReview(status string) bool {
	return oneOf(status, ReviewPending, ReviewConfirmed, ReviewFalse, ReviewResolved)
}

// Store persists events in the shared plugin SQLite database. It borrows the
// connection and never opens or closes it.
type Store struct{ db *sqlitestore.DB }

// NewStore returns nil when no database is configured.
func NewStore(db *sqlitestore.DB) *Store {
	if db == nil {
		return nil
	}
	return &Store{db: db}
}

func (s *Store) conn() (*sql.DB, error) {
	if s == nil || s.db == nil || s.db.Conn() == nil {
		return nil, ErrUnavailable
	}
	return s.db.Conn(), nil
}

func newEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(raw[:]), nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func logicalSize(e Event, matches, classifier string) int64 {
	// Reserve the full review-note budget so later review updates cannot grow
	// beyond the capacity admitted at insertion.
	n := int64(256 + 2000)
	for _, value := range []string{e.ID, e.RequestID, e.TraceID, e.Path, e.Protocol, e.RequestedModel, e.ServedModel, e.KeyName, e.KeyMasked, e.KeyFingerprint, e.Action, e.Mode, e.Severity, strings.Join(e.RuleNames, "\n"), matches, classifier, e.Body, e.BodyState, e.BodySHA256, e.OriginalSHA256} {
		n += int64(len(value))
	}
	return n
}

// Insert stores one event and returns its generated ID.
func (s *Store) Insert(ctx context.Context, e Event) (string, error) {
	return s.InsertBounded(ctx, e, DefaultSettings())
}

// InsertBounded atomically inserts and prunes within validated capacity limits.
func (s *Store) InsertBounded(ctx context.Context, e Event, settings Settings) (string, error) {
	if err := settings.Validate(); err != nil {
		return "", err
	}
	if err := validateEvent(e); err != nil {
		return "", err
	}
	// Defense in depth: current capture policy also applies at the storage boundary.
	e.Matches = FilterEvidenceMatches(e.Matches, settings.CaptureBody, settings.EvidenceIncludeSystem)
	if e.Classifier != nil && (!settings.CaptureBody || !settings.EvidenceIncludeSystem) {
		record := *e.Classifier
		record.Reason = ""
		record.Category = ""
		e.Classifier = &record
	}
	if !settings.CaptureBody {
		e.Body, e.BodySHA256, e.OriginalSHA256 = "", "", ""
		e.BodyBytes, e.BodyState = 0, "omitted_disabled"
	} else if e.Body != "" {
		filtered := CaptureEvidence([]byte(e.Body), settings.EvidenceIncludeSystem, settings.MaxEvidenceBytes)
		e.Body, e.BodyState, e.BodySHA256 = filtered.Text, filtered.State, filtered.SHA256
		e.BodyBytes = len(e.Body)
		e.BodyTruncated = e.BodyTruncated || filtered.Truncated
	}
	db, err := s.conn()
	if err != nil {
		return "", err
	}
	if e.ID, err = newEventID(); err != nil {
		return "", err
	}
	if e.CreatedAt <= 0 {
		e.CreatedAt = time.Now().UTC().UnixMilli()
	}
	if e.ReviewStatus == "" {
		e.ReviewStatus = ReviewPending
	}
	matches, err := json.Marshal(e.Matches)
	if len(matches) > 1<<20 {
		return "", ErrInvalid
	}
	if err != nil {
		return "", ErrInvalid
	}
	classifier := ""
	if e.Classifier != nil {
		raw, marshalErr := json.Marshal(e.Classifier)
		if marshalErr != nil {
			return "", ErrInvalid
		}
		classifier = string(raw)
	}
	e.LogicalBytes = logicalSize(e, string(matches), classifier)
	if e.LogicalBytes > settings.MaxTotalBytes {
		return "", ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO key_guard_intercept_events(
		id,created_at,request_id,trace_id,path,protocol,requested_model,served_model,stream,
		key_name,key_masked,key_fingerprint,action,mode,severity,rule_names,matches_json,classifier_json,
		body,body_state,body_truncated,body_bytes,body_sha256,scan_truncated,auto_disabled,
		review_status,review_note,reviewed_at,logical_bytes,original_sha256,original_bytes)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.CreatedAt, e.RequestID, e.TraceID, e.Path, e.Protocol, e.RequestedModel, e.ServedModel, boolInt(e.Stream),
		e.KeyName, e.KeyMasked, e.KeyFingerprint, e.Action, e.Mode, e.Severity, "\n"+strings.Join(e.RuleNames, "\n")+"\n", string(matches), classifier,
		e.Body, e.BodyState, boolInt(e.BodyTruncated), e.BodyBytes, e.BodySHA256, boolInt(e.ScanTruncated), e.AutoDisabled,
		e.ReviewStatus, e.ReviewNote, e.ReviewedAt, e.LogicalBytes, e.OriginalSHA256, e.OriginalBytes)
	if err != nil {
		return "", err
	}
	if _, err = pruneTx(ctx, tx, time.Now(), settings); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return e.ID, nil
}

// SetAutoDisabled records the automatic-disable outcome on an existing event.
func (s *Store) SetAutoDisabled(ctx context.Context, id, outcome string) error {
	if !validEventID(id) || !oneOf(outcome, "", "disabled", "skipped", "failed") {
		return ErrInvalidQuery
	}
	db, err := s.conn()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE key_guard_intercept_events SET auto_disabled=? WHERE id=?`, outcome, id)
	return err
}

// Query filters the event list. KeyFingerprint must be a full digest.
type Query struct {
	From, To       int64
	KeyFingerprint string
	Action         string
	Severity       string
	Review         string
	Rule           string
	Model          string
	RequestID      string
	Limit, Offset  int
}

const (
	MaxQueryLimit  = 100
	MaxQueryOffset = 100000
)

func (q Query) where() (string, []any, error) {
	if q.From < 0 || q.To < 0 || (q.To > 0 && q.From > q.To) {
		return "", nil, ErrInvalidQuery
	}
	clauses := []string{"1=1"}
	var args []any
	if q.From > 0 {
		clauses, args = append(clauses, "created_at >= ?"), append(args, q.From)
	}
	if q.To > 0 {
		clauses, args = append(clauses, "created_at <= ?"), append(args, q.To)
	}
	if q.KeyFingerprint != "" {
		if !ValidFingerprint(q.KeyFingerprint) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "key_fingerprint = ?"), append(args, q.KeyFingerprint)
	}
	if q.Action != "" {
		if !oneOf(q.Action, EventBlocked, EventFlagged) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "action = ?"), append(args, q.Action)
	}
	if q.Severity != "" {
		if SeverityRank(q.Severity) == 0 {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "severity = ?"), append(args, q.Severity)
	}
	if q.Review != "" {
		if !ValidReview(q.Review) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "review_status = ?"), append(args, q.Review)
	}
	if q.Rule != "" {
		if !safeText(q.Rule, 320) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "instr(lower(rule_names), lower(?)) > 0"), append(args, q.Rule)
	}
	if q.Model != "" {
		if !safeText(q.Model, 320) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "(instr(lower(requested_model), lower(?)) > 0 OR instr(lower(served_model), lower(?)) > 0)"), append(args, q.Model, q.Model)
	}
	if q.RequestID != "" {
		if !safeText(q.RequestID, 256) {
			return "", nil, ErrInvalidQuery
		}
		clauses, args = append(clauses, "(request_id = ? OR trace_id = ?)"), append(args, q.RequestID, q.RequestID)
	}
	return strings.Join(clauses, " AND "), args, nil
}

const listColumns = `id,created_at,request_id,trace_id,path,protocol,requested_model,served_model,stream,key_name,key_masked,key_fingerprint,action,mode,severity,rule_names,'' AS matches_json,'' AS classifier_json,'' AS body,body_state,body_truncated,body_bytes,body_sha256,scan_truncated,auto_disabled,review_status,review_note,reviewed_at,logical_bytes,original_sha256,original_bytes`
const detailColumns = `id,created_at,request_id,trace_id,path,protocol,requested_model,served_model,stream,key_name,key_masked,key_fingerprint,action,mode,severity,rule_names,matches_json,classifier_json,body,body_state,body_truncated,body_bytes,body_sha256,scan_truncated,auto_disabled,review_status,review_note,reviewed_at,logical_bytes,original_sha256,original_bytes`

type scanner interface{ Scan(...any) error }

func scanEvent(row scanner) (Event, error) {
	var e Event
	var stream, bodyTruncated, scanTruncated int
	var rules, matches, classifier string
	err := row.Scan(&e.ID, &e.CreatedAt, &e.RequestID, &e.TraceID, &e.Path, &e.Protocol, &e.RequestedModel, &e.ServedModel, &stream,
		&e.KeyName, &e.KeyMasked, &e.KeyFingerprint, &e.Action, &e.Mode, &e.Severity, &rules, &matches, &classifier,
		&e.Body, &e.BodyState, &bodyTruncated, &e.BodyBytes, &e.BodySHA256, &scanTruncated, &e.AutoDisabled,
		&e.ReviewStatus, &e.ReviewNote, &e.ReviewedAt, &e.LogicalBytes, &e.OriginalSHA256, &e.OriginalBytes)
	if err != nil {
		return e, err
	}
	e.Stream, e.BodyTruncated, e.ScanTruncated = stream != 0, bodyTruncated != 0, scanTruncated != 0
	e.RuleNames = []string{}
	for _, name := range strings.Split(rules, "\n") {
		if name != "" {
			e.RuleNames = append(e.RuleNames, name)
		}
	}
	if matches != "" {
		if len(matches) > 1<<20 || json.Unmarshal([]byte(matches), &e.Matches) != nil {
			return Event{}, ErrInvalid
		}
	}
	if classifier != "" {
		var record ClassifierRecord
		if len(classifier) > 4096 || json.Unmarshal([]byte(classifier), &record) != nil {
			return Event{}, ErrInvalid
		}
		e.Classifier = &record
	}
	return e, nil
}

// List returns metadata only, newest first.
func (s *Store) List(ctx context.Context, q Query) ([]Event, int, error) {
	db, err := s.conn()
	if err != nil {
		return nil, 0, err
	}
	if q.Limit < 1 || q.Limit > MaxQueryLimit || q.Offset < 0 || q.Offset > MaxQueryOffset {
		return nil, 0, ErrInvalidQuery
	}
	where, args, err := q.where()
	if err != nil {
		return nil, 0, err
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(1) FROM key_guard_intercept_events WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(ctx, "SELECT "+listColumns+" FROM key_guard_intercept_events WHERE "+where+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

func validEventID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Detail returns one complete event, including body and matches.
func (s *Store) Detail(ctx context.Context, id string) (Event, error) {
	db, err := s.conn()
	if err != nil {
		return Event{}, err
	}
	if !validEventID(id) {
		return Event{}, ErrNotFound
	}
	e, err := scanEvent(db.QueryRowContext(ctx, "SELECT "+detailColumns+" FROM key_guard_intercept_events WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	if err == nil {
		err = validateEvent(e)
	}
	if err != nil {
		return Event{}, err
	}
	return e, nil
}

// MaxExport bounds one forensic export request.
const MaxExport = 100
const MaxExportBytes = 8 << 20

// Export returns complete events for the given IDs in request order.
func (s *Store) Export(ctx context.Context, ids []string) ([]Event, error) {
	if len(ids) == 0 || len(ids) > MaxExport {
		return nil, ErrInvalidQuery
	}
	out := make([]Event, 0, len(ids))
	seen := map[string]bool{}
	totalBytes := int64(0)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		e, err := s.Detail(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		totalBytes += e.LogicalBytes
		if totalBytes > MaxExportBytes {
			return nil, ErrInvalidQuery
		}
		out = append(out, e)
	}
	return out, nil
}

// Review updates the administrator disposition of an event.
func (s *Store) Review(ctx context.Context, id, status, note string) (Event, error) {
	db, err := s.conn()
	if err != nil {
		return Event{}, err
	}
	note = strings.TrimSpace(note)
	if !validEventID(id) || !ValidReview(status) || len(note) > 2000 || !utf8.ValidString(note) || strings.ContainsRune(note, 0) {
		return Event{}, ErrInvalidQuery
	}
	result, err := db.ExecContext(ctx, `UPDATE key_guard_intercept_events SET review_status=?, review_note=?, reviewed_at=? WHERE id=?`, status, note, time.Now().UTC().UnixMilli(), id)
	if err != nil {
		return Event{}, err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return Event{}, ErrNotFound
	}
	return s.Detail(ctx, id)
}

// Stats summarizes events since a timestamp.
type Stats struct {
	Total        int              `json:"total"`
	Blocked      int              `json:"blocked"`
	Flagged      int              `json:"flagged"`
	Pending      int              `json:"pending_review"`
	AutoDisabled int              `json:"auto_disabled"`
	TopKeys      []map[string]any `json:"top_keys"`
	TopRules     []map[string]any `json:"top_rules"`
	Records      int              `json:"records"`
	LogicalBytes int64            `json:"logical_bytes"`
}

// Stats aggregates counts since the given time.
func (s *Store) Stats(ctx context.Context, since int64) (Stats, error) {
	db, err := s.conn()
	if err != nil {
		return Stats{}, err
	}
	var out Stats
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1), COALESCE(SUM(action='blocked'),0), COALESCE(SUM(action='flagged'),0), COALESCE(SUM(review_status='pending'),0), COALESCE(SUM(auto_disabled='disabled'),0) FROM key_guard_intercept_events WHERE created_at >= ?`, since).Scan(&out.Total, &out.Blocked, &out.Flagged, &out.Pending, &out.AutoDisabled); err != nil {
		return Stats{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1), COALESCE(SUM(logical_bytes),0) FROM key_guard_intercept_events`).Scan(&out.Records, &out.LogicalBytes); err != nil {
		return Stats{}, err
	}
	rows, err := db.QueryContext(ctx, `SELECT key_fingerprint, MAX(key_name), MAX(key_masked), COUNT(1), COALESCE(SUM(action='blocked'),0) FROM key_guard_intercept_events WHERE created_at >= ? GROUP BY key_fingerprint ORDER BY COUNT(1) DESC LIMIT 5`, since)
	if err != nil {
		return Stats{}, err
	}
	out.TopKeys = []map[string]any{}
	for rows.Next() {
		var fp, name, masked string
		var count, blocked int
		if err := rows.Scan(&fp, &name, &masked, &count, &blocked); err != nil {
			rows.Close()
			return Stats{}, err
		}
		out.TopKeys = append(out.TopKeys, map[string]any{"key_fingerprint": fp, "key_name": name, "key_masked": masked, "count": count, "blocked": blocked})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Stats{}, err
	}
	rows.Close()
	ruleRows, err := db.QueryContext(ctx, `SELECT rule_names FROM key_guard_intercept_events WHERE created_at >= ? ORDER BY created_at DESC LIMIT 5000`, since)
	if err != nil {
		return Stats{}, err
	}
	counts := map[string]int{}
	for ruleRows.Next() {
		var names string
		if err := ruleRows.Scan(&names); err != nil {
			ruleRows.Close()
			return Stats{}, err
		}
		for _, name := range strings.Split(names, "\n") {
			if name != "" {
				counts[name]++
			}
		}
	}
	if err := ruleRows.Err(); err != nil {
		ruleRows.Close()
		return Stats{}, err
	}
	ruleRows.Close()
	out.TopRules = []map[string]any{}
	for len(out.TopRules) < 5 && len(counts) > 0 {
		best, bestCount := "", -1
		for name, count := range counts {
			if count > bestCount || (count == bestCount && name < best) {
				best, bestCount = name, count
			}
		}
		out.TopRules = append(out.TopRules, map[string]any{"rule_name": best, "count": bestCount})
		delete(counts, best)
	}
	return out, nil
}

// Prune enforces retention days, record count and total logical size.
func (s *Store) Prune(ctx context.Context, now time.Time, settings Settings) (int64, error) {
	if err := settings.Validate(); err != nil {
		return 0, err
	}
	db, err := s.conn()
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	deleted, err := pruneTx(ctx, tx, now, settings)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// Window totals are O(n log n), unlike repeated whole-table SUM/delete passes.
// The table remains bounded by MaxRecords after every insertion.
func pruneTx(ctx context.Context, tx *sql.Tx, now time.Time, settings Settings) (int64, error) {
	cutoff := now.UTC().Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour).UnixMilli()
	result, err := tx.ExecContext(ctx,
		`DELETE FROM key_guard_intercept_events WHERE id IN (
   SELECT id FROM (
    SELECT id,created_at,ROW_NUMBER() OVER (ORDER BY created_at DESC,id DESC) AS rn,
     SUM(logical_bytes) OVER (ORDER BY created_at DESC,id DESC ROWS UNBOUNDED PRECEDING) AS cumulative
    FROM key_guard_intercept_events
   ) WHERE created_at < ? OR rn > ? OR cumulative > ?
  )`, cutoff, settings.MaxRecords, settings.MaxTotalBytes)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
