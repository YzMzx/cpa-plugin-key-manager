package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementAudit       = "/key-guard/audit"
	RouteManagementAuditDetail = "/key-guard/audit/detail"
	RouteManagementAuditStatus = "/key-guard/audit/status"
)

type auditProvider interface {
	QueryAudit(context.Context, audit.Query) (map[string]any, error)
	AuditDetail(context.Context, string) (map[string]any, error)
	AuditStatus() map[string]any
}

func handleAuditRequest(ctx context.Context, provider any, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	// The native host middleware verifies the credential. This extra guard prevents
	// public resource routes from ever reaching audit data.
	if !strings.HasPrefix(req.Path, "/v0/management/key-guard/") || !hasManagementCredential(req) {
		return jsonError(http.StatusUnauthorized, "management authentication required")
	}
	if strings.ToUpper(req.Method) != http.MethodGet {
		return jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
	source, ok := provider.(auditProvider)
	if !ok {
		return jsonError(http.StatusServiceUnavailable, "audit is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	path := strings.TrimSpace(req.Path)
	if path == "/v0/management"+RouteManagementAuditStatus {
		return jsonResponse(http.StatusOK, map[string]any{"status": source.AuditStatus()})
	}
	if path == "/v0/management"+RouteManagementAuditDetail {
		value, err := source.AuditDetail(ctx, queryValue(req, "id"))
		if err != nil {
			return auditError(err)
		}
		return jsonResponse(http.StatusOK, value)
	}
	if path != "/v0/management"+RouteManagementAudit {
		return jsonError(http.StatusNotFound, "unknown audit endpoint")
	}
	q := audit.Query{RequestID: queryValue(req, "request_id"), TraceID: queryValue(req, "trace_id"), KeyFingerprint: queryValue(req, "key_fingerprint"), Model: queryValue(req, "model"), IP: queryValue(req, "ip"), Outcome: queryValue(req, "outcome"), Limit: 50}
	var err error
	if value := queryValue(req, "limit"); value != "" {
		q.Limit, err = strconv.Atoi(value)
		if err != nil || q.Limit < 1 || q.Limit > audit.MaxQueryLimit {
			return jsonError(400, "limit must be between 1 and 100")
		}
	}
	if value := queryValue(req, "offset"); value != "" {
		q.Offset, err = strconv.Atoi(value)
		if err != nil || q.Offset < 0 || q.Offset > audit.MaxQueryOffset {
			return jsonError(400, "invalid pagination offset")
		}
	}
	zone := ""
	if cfg, ok := provider.(interface{ ConfiguredTimezone() string }); ok {
		zone = cfg.ConfiguredTimezone()
	}
	if value := queryValue(req, "from"); value != "" {
		parsed, e := parseTimeParamInZone(value, zone)
		if e != nil {
			return jsonError(400, "invalid from time")
		}
		q.From = parsed.UnixMilli()
	}
	if value := queryValue(req, "to"); value != "" {
		parsed, e := parseTimeParamInZone(value, zone)
		if e != nil {
			return jsonError(400, "invalid to time")
		}
		q.To = parsed.UnixMilli()
	}
	if q.From > 0 && q.To > 0 && q.To < q.From {
		return jsonError(400, "to must not precede from")
	}
	value, err := source.QueryAudit(ctx, q)
	if err != nil {
		return auditError(err)
	}
	return jsonResponse(200, value)
}
func auditError(err error) pluginapi.ManagementResponse {
	switch {
	case errors.Is(err, audit.ErrNotFound):
		return jsonError(404, "audit record not found or expired")
	case errors.Is(err, audit.ErrInvalidQuery), errors.Is(err, audit.ErrInvalidRecord):
		return jsonError(400, "invalid audit query")
	default:
		return jsonError(503, "audit storage is temporarily unavailable")
	}
}
