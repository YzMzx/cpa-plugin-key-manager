package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementAuditStorage        = "/key-guard/audit/storage"
	RouteManagementAuditCleanupPreview = "/key-guard/audit/cleanup/preview"
	RouteManagementAuditCleanup        = "/key-guard/audit/cleanup"
)

type auditCleanupProvider interface {
	AuditStorage(context.Context) (map[string]any, error)
	PreviewAuditCleanup(context.Context, string, time.Time, string) (map[string]any, error)
	CleanupAudit(context.Context, string, string) (map[string]any, error)
}

// HandleAuditCleanupRequest must be dispatched only from native management paths.
// Actual credential verification remains the host middleware's responsibility.
func HandleAuditCleanupRequest(ctx context.Context, provider any, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	path := strings.TrimSpace(req.Path)
	if path != "/v0/management"+RouteManagementAuditStorage && path != "/v0/management"+RouteManagementAuditCleanupPreview && path != "/v0/management"+RouteManagementAuditCleanup {
		return jsonError(http.StatusNotFound, "unknown audit maintenance endpoint")
	}
	if !hasManagementCredential(req) {
		return jsonError(http.StatusUnauthorized, "management authentication required")
	}
	source, ok := provider.(auditCleanupProvider)
	if !ok {
		return jsonError(http.StatusServiceUnavailable, "audit maintenance unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if path == "/v0/management"+RouteManagementAuditStorage {
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		value, err := source.AuditStorage(ctx)
		if err != nil {
			return auditCleanupResponseError(err)
		}
		return jsonResponse(http.StatusOK, value)
	}
	if method != http.MethodPost {
		return jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
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
	if path == "/v0/management"+RouteManagementAuditCleanupPreview {
		var body struct {
			Scope  string `json:"scope"`
			Before string `json:"before"`
		}
		if !decodeAuditCleanupBody(req.Body, &body) {
			return jsonError(http.StatusBadRequest, "invalid cleanup JSON body")
		}
		var before time.Time
		switch body.Scope {
		case "expired", "all":
			if body.Before != "" {
				return jsonError(http.StatusBadRequest, "before is only valid for before scope")
			}
		case "before":
			var err error
			before, err = time.Parse(time.RFC3339Nano, body.Before)
			if err != nil || before.After(time.Now().UTC()) || before.UnixMilli() < 0 {
				return jsonError(http.StatusBadRequest, "before must be a non-future RFC3339 timestamp with timezone")
			}
		default:
			return jsonError(http.StatusBadRequest, "scope must be expired, before or all")
		}
		value, err := source.PreviewAuditCleanup(ctx, body.Scope, before, principal)
		if err != nil {
			return auditCleanupResponseError(err)
		}
		return jsonResponse(http.StatusOK, value)
	}
	var body struct {
		Token   string `json:"token"`
		Confirm bool   `json:"confirm"`
	}
	if !decodeAuditCleanupBody(req.Body, &body) || !body.Confirm || body.Token == "" {
		return jsonError(http.StatusBadRequest, "cleanup requires preview token and confirm=true")
	}
	value, err := source.CleanupAudit(ctx, body.Token, principal)
	if err != nil {
		return auditCleanupResponseError(err)
	}
	return jsonResponse(http.StatusOK, value)
}
func decodeAuditCleanupBody(raw []byte, target any) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(raw) > 4096 || trimmed[0] != '{' {
		return false
	}
	// Duplicate keys are ambiguous for destructive actions: reject rather than last-wins.
	check := json.NewDecoder(bytes.NewReader(trimmed))
	if token, err := check.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for check.More() {
		token, err := check.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || seen[strings.ToLower(key)] {
			return false
		}
		seen[strings.ToLower(key)] = true
		var value json.RawMessage
		if check.Decode(&value) != nil {
			return false
		}
	}
	if _, err := check.Token(); err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}
func auditCleanupResponseError(err error) pluginapi.ManagementResponse {
	var code interface{ AuditCleanupCode() string }
	if errors.As(err, &code) {
		if code.AuditCleanupCode() == "preview_limit" {
			return jsonError(http.StatusTooManyRequests, "too many pending previews; wait for expiry")
		}
		return jsonError(http.StatusConflict, "cleanup preview is invalid, used or expired; preview again")
	}
	if errors.Is(err, audit.ErrInvalidCleanup) {
		return jsonError(http.StatusBadRequest, "invalid audit cleanup scope or time")
	}
	return jsonError(http.StatusServiceUnavailable, "audit maintenance temporarily unavailable; refresh before retrying")
}
