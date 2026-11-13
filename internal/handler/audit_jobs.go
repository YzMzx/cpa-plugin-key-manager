package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementAuditCleanupJobs = "/key-guard/audit/cleanup/jobs"
	RouteManagementAuditJobPreview  = RouteManagementAuditCleanupJobs + "/preview"
	RouteManagementAuditJobDetail   = RouteManagementAuditCleanupJobs + "/detail"
	RouteManagementAuditJobCancel   = RouteManagementAuditCleanupJobs + "/cancel"
	RouteManagementAuditJobResume   = RouteManagementAuditCleanupJobs + "/resume"
)

type auditCleanupJobProvider interface {
	PreviewAuditCleanupJob(context.Context, string, time.Time, string) (map[string]any, error)
	StartAuditCleanupJob(context.Context, string, string) (map[string]any, error)
	ListAuditCleanupJobs(context.Context, string) (map[string]any, error)
	GetAuditCleanupJob(context.Context, string, string) (map[string]any, error)
	CancelAuditCleanupJob(context.Context, string, string) (map[string]any, error)
	ResumeAuditCleanupJob(context.Context, string, string) (map[string]any, error)
}

func isAuditCleanupJobPath(path string) bool {
	switch path {
	case "/v0/management" + RouteManagementAuditCleanupJobs,
		"/v0/management" + RouteManagementAuditJobPreview,
		"/v0/management" + RouteManagementAuditJobDetail,
		"/v0/management" + RouteManagementAuditJobCancel,
		"/v0/management" + RouteManagementAuditJobResume:
		return true
	default:
		return false
	}
}

// HandleAuditCleanupJobsRequest is only for native management dispatch. The host
// middleware verifies credentials; their presence here is not authentication.
// No endpoint invokes synchronous cleanup or performs physical database deletion.
func HandleAuditCleanupJobsRequest(ctx context.Context, provider any, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if !isAuditCleanupJobPath(req.Path) {
		return jsonError(http.StatusNotFound, "unknown audit cleanup job endpoint")
	}
	if !hasManagementCredential(req) {
		return jsonError(http.StatusUnauthorized, "management authentication required")
	}
	// Match legacy cleanup's extraction and precedence. Never persist or return it.
	principal := strings.TrimSpace(req.Headers.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(principal), "bearer ") {
		principal = strings.TrimSpace(principal[7:])
	}
	if principal == "" {
		principal = strings.TrimSpace(req.Headers.Get("X-Management-Key"))
	}
	if principal == "" {
		return jsonError(http.StatusUnauthorized, "management authentication required")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	read := req.Path == "/v0/management"+RouteManagementAuditJobDetail ||
		(req.Path == "/v0/management"+RouteManagementAuditCleanupJobs && method == http.MethodGet)
	if (read && method != http.MethodGet) || (!read && method != http.MethodPost) {
		return jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
	source, ok := provider.(auditCleanupJobProvider)
	if !ok {
		return jsonError(http.StatusServiceUnavailable, "audit cleanup jobs unavailable")
	}
	timeout := 5 * time.Second
	if req.Path == "/v0/management"+RouteManagementAuditJobCancel {
		// Cancellation may wait for the current bounded 10s batch to release
		// the shared connection; it never performs that batch itself.
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var value map[string]any
	var err error
	status := http.StatusOK
	switch req.Path {
	case "/v0/management" + RouteManagementAuditJobPreview:
		var body struct {
			Scope  string `json:"scope"`
			Before string `json:"before"`
		}
		if !decodeAuditJobBody(req.Body, &body, "scope", "before") {
			return jsonError(http.StatusBadRequest, "invalid cleanup job JSON body")
		}
		var before time.Time
		switch body.Scope {
		case "expired", "all":
			if body.Before != "" {
				return jsonError(http.StatusBadRequest, "before is only valid for before scope")
			}
		case "before":
			before, err = time.Parse(time.RFC3339Nano, body.Before)
			if err != nil || before.After(time.Now().UTC()) || before.UnixMilli() < 0 {
				return jsonError(http.StatusBadRequest, "before must be a non-future RFC3339 timestamp with timezone")
			}
		default:
			return jsonError(http.StatusBadRequest, "scope must be expired, before or all")
		}
		value, err = source.PreviewAuditCleanupJob(ctx, body.Scope, before, principal)
	case "/v0/management" + RouteManagementAuditCleanupJobs:
		if method == http.MethodGet {
			value, err = source.ListAuditCleanupJobs(ctx, principal)
			break
		}
		var body struct {
			Token   string `json:"token"`
			Confirm bool   `json:"confirm"`
		}
		if !decodeAuditJobBody(req.Body, &body, "token", "confirm") || !body.Confirm || !validAuditJobID(body.Token) {
			return jsonError(http.StatusBadRequest, "cleanup job requires a 64hex preview token and confirm=true")
		}
		value, err = source.StartAuditCleanupJob(ctx, body.Token, principal)
		status = http.StatusAccepted
	case "/v0/management" + RouteManagementAuditJobDetail:
		ids := req.Query["id"]
		if len(ids) != 1 || !validAuditJobID(ids[0]) {
			return jsonError(http.StatusBadRequest, "cleanup job id must be 64hex")
		}
		value, err = source.GetAuditCleanupJob(ctx, ids[0], principal)
	case "/v0/management" + RouteManagementAuditJobCancel, "/v0/management" + RouteManagementAuditJobResume:
		var body struct {
			ID string `json:"id"`
		}
		if !decodeAuditJobBody(req.Body, &body, "id") || !validAuditJobID(body.ID) {
			return jsonError(http.StatusBadRequest, "cleanup job requires a 64hex id")
		}
		if req.Path == "/v0/management"+RouteManagementAuditJobCancel {
			value, err = source.CancelAuditCleanupJob(ctx, body.ID, principal)
		} else {
			value, err = source.ResumeAuditCleanupJob(ctx, body.ID, principal)
		}
	}
	if err != nil {
		return auditCleanupJobResponseError(err)
	}
	return jsonResponse(status, value)
}

func validAuditJobID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Accept only one bounded JSON object with exact field names and non-null
// primitive values. Check keys before decoding so duplicates cannot be hidden by
// encoding/json's last-wins or case-insensitive struct-field matching.
func decodeAuditJobBody(raw []byte, target any, fields ...string) bool {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) {
		return false
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return false
	}
	return json.Unmarshal(raw, target) == nil
}

func auditCleanupJobResponseError(err error) pluginapi.ManagementResponse {
	switch {
	case errors.Is(err, audit.ErrCleanupPreviewExpired), errors.Is(err, audit.ErrCleanupBusy), errors.Is(err, audit.ErrCleanupJobState):
		return jsonError(http.StatusConflict, "audit cleanup preview expired or job state conflicts; refresh before retrying")
	case errors.Is(err, audit.ErrCleanupTooLarge):
		return jsonError(http.StatusRequestEntityTooLarge, "audit cleanup selection is too large")
	case errors.Is(err, audit.ErrNotFound):
		return jsonError(http.StatusNotFound, "audit cleanup job not found")
	case errors.Is(err, audit.ErrInvalidCleanup):
		return jsonError(http.StatusBadRequest, "invalid audit cleanup request")
	default:
		// Includes unavailable, cancellation, deadlines and unknown provider errors.
		// Never expose SQL, paths, credentials or ownership diagnostics.
		return jsonError(http.StatusServiceUnavailable, "audit cleanup jobs temporarily unavailable; refresh before retrying")
	}
}
