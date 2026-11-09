// Package audit stores bounded, sanitized request audit records in the shared database.
package audit

import "errors"

const (
	DefaultRetentionDays = 7
	DefaultMaxRecords    = 10000
	// MaxRequestBodyBytes bounds decoded input, retained JSON and string values.
	MaxRequestBodyBytes        = 10 * 1024 * 1024
	DefaultMaxBodyBytes        = MaxRequestBodyBytes
	DefaultMaxTotalBytes int64 = 64 * 1024 * 1024
	MaxQueryLimit              = 100
	MaxQueryOffset             = 100000
)

var (
	ErrUnavailable   = errors.New("audit storage unavailable")
	ErrInvalidRecord = errors.New("invalid audit record")
	ErrInvalidQuery  = errors.New("invalid audit query")
	ErrNotFound      = errors.New("audit record not found")
	ErrDisabled      = errors.New("request audit is disabled")
	ErrCapacity      = errors.New("audit record exceeds logical capacity")
)

// Config is normalized by the owner; NewStore also supplies safe positive defaults.
// Enabled has no implicit true value: collection must be explicitly enabled.
type Config struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	RetentionDays  int      `yaml:"retention_days" json:"retention_days"`
	MaxRecords     int      `yaml:"max_records" json:"max_records"`
	MaxBodyBytes   int      `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxTotalBytes  int64    `yaml:"max_total_bytes" json:"max_total_bytes"`
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies,omitempty"`
}

// Record deliberately has no API key, headers or upstream error body fields.
// RequestBody must already have passed the audit sanitizer. Unknown schemas must
// use a non-captured BodyState and an empty RequestBody. Dates are UTC Unix millis.
type Record struct {
	ID             string `json:"id"`
	RequestID      string `json:"request_id"`
	TraceID        string `json:"trace_id,omitempty"`
	StartedAt      int64  `json:"started_at"`
	CompletedAt    int64  `json:"completed_at,omitempty"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	ClientIP       string `json:"client_ip,omitempty"`
	PeerIP         string `json:"peer_ip,omitempty"`
	IPSource       string `json:"ip_source,omitempty"`
	IPNote         string `json:"ip_note,omitempty"`
	KeyLabel       string `json:"key_label,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	RequestedModel string `json:"requested_model,omitempty"`
	ServedModel    string `json:"served_model,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Stream         bool   `json:"stream"`
	Outcome        string `json:"outcome"`
	StatusCode     int    `json:"status_code,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
	BodyState      string `json:"body_state"`
	BodyTruncated  bool   `json:"body_truncated"`
	RequestBody    string `json:"request_body,omitempty"`
	BodySHA256     string `json:"body_sha256,omitempty"`
	InputTokens    int64  `json:"input_tokens,omitempty"`
	OutputTokens   int64  `json:"output_tokens,omitempty"`
	TotalTokens    int64  `json:"total_tokens,omitempty"`
}

// Completion never creates a record. Repeated terminal updates are idempotent,
// and a locally rejected record cannot be rewritten as a successful request.
type Completion struct {
	RequestID    string
	TraceID      string
	CompletedAt  int64
	ServedModel  string
	Outcome      string
	StatusCode   int
	DurationMS   int64
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

type Query struct {
	RequestID      string
	TraceID        string
	KeyFingerprint string
	KeyLabel       string
	Model          string
	IP             string
	Outcome        string
	From           int64
	To             int64
	Limit          int
	Offset         int
}

// ListResult contains metadata only; RequestBody is always absent from Records.
type ListResult struct {
	Records []Record `json:"records"`
	Total   int      `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
}

type Status struct {
	Enabled        bool   `json:"enabled"`
	Configured     bool   `json:"configured"`
	RetentionDays  int    `json:"retention_days"`
	MaxRecords     int    `json:"max_records"`
	MaxBodyBytes   int    `json:"max_body_bytes"`
	MaxTotalBytes  int64  `json:"max_total_bytes"`
	Records        int    `json:"records"`
	LogicalBytes   int64  `json:"logical_bytes"`
	CapacityMode   string `json:"capacity_mode"`
	LastError      string `json:"last_error,omitempty"`
	DroppedRecords uint64 `json:"dropped_records"`
}
