package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// beginAudit preserves only the pre-modification request at the execution boundary.
func (m *Manager) beginAudit(req pluginapi.RequestInterceptRequest, apiKey, keyLabel string) {
	store, cfg := m.auditSnapshot()
	if store == nil || !cfg.isEnabled() || strings.TrimSpace(req.RequestID) == "" {
		return
	}
	m.mu.RLock()
	adminToken := m.cfg.AdminToken
	m.mu.RUnlock()
	contentType := req.Headers.Get("Content-Type")
	// Model executors may omit client headers; known JSON protocols can still be
	// parsed safely without guessing media/binary formats.
	if contentType == "" {
		switch strings.ToLower(req.SourceFormat) {
		case "openai", "openai-responses", "claude", "anthropic", "gemini":
			contentType = "application/json"
		}
	}
	network := audit.ResolveClientIP(req.Metadata, req.Headers, cfg.TrustedProxies)
	path := ""
	if value, ok := req.Metadata["request_path"].(string); ok {
		if parsed, err := url.Parse(value); err == nil {
			path = parsed.Path
		}
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		path = ""
	}
	body := audit.BodyResult{State: "omitted_busy"}
	// Large JSON sanitization allocates multiple working representations. Do not
	// let a burst of requests multiply that cost or queue raw sensitive payloads.
	allowed := auditRequestSchemaField(req.SourceFormat, path) != ""
	if !allowed {
		body = audit.BodyResult{State: "omitted_unknown_schema"}
	}
	if allowed && len(req.Body) > 256<<10 && len(req.Body) <= audit.MaxRequestBodyBytes {
		select {
		case m.auditLargeCapture <- struct{}{}:
			defer func() { <-m.auditLargeCapture }()
		default:
			allowed = false
		}
	}
	if allowed {
		body = audit.SanitizeBody(req.Body, contentType, req.Headers.Get("Content-Encoding"), cfg.MaxBodyBytes, apiKey, adminToken)
	}
	method := ""
	if value, ok := req.Metadata["request_method"].(string); ok {
		switch strings.ToUpper(value) {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			method = strings.ToUpper(value)
		}
	}
	if body.State == "stored" && !auditKnownRequestSchema(req.SourceFormat, path, body.Body) {
		body = audit.BodyResult{State: "omitted_unknown_schema"}
	}
	fingerprint := ""
	if apiKey != "" {
		sum := sha256.Sum256([]byte(apiKey))
		fingerprint = hex.EncodeToString(sum[:])
	}
	rec := audit.Record{RequestID: auditCorrelationID(req.RequestID), TraceID: auditCorrelationID(req.TraceID), StartedAt: time.Now().UTC().UnixMilli(), Method: method, Path: auditSafeLabel(path, apiKey, adminToken), ClientIP: network.ClientIP, PeerIP: network.PeerIP, IPSource: network.Source, IPNote: network.Note, KeyLabel: auditSafeLabel(keyLabel, apiKey, adminToken), KeyFingerprint: fingerprint, RequestedModel: auditSafeLabel(req.RequestedModel, apiKey, adminToken), ServedModel: auditSafeLabel(req.Model, apiKey, adminToken), Protocol: auditSafeLabel(req.SourceFormat), Stream: req.Stream, Outcome: "running", BodyState: body.State, BodyTruncated: body.Truncated, RequestBody: body.Body, BodySHA256: body.SHA256}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := store.Begin(ctx, rec); err != nil {
		m.recordAuditCaptureFailure()
	}
}
func (m *Manager) rejectAudit(requestID string, status int) {
	m.completeAudit(audit.Completion{RequestID: requestID, CompletedAt: time.Now().UTC().UnixMilli(), Outcome: "rejected", StatusCode: status})
}
func (m *Manager) completeAudit(completion audit.Completion) {
	store, cfg := m.auditSnapshot()
	if !cfg.isEnabled() {
		return
	}
	completion.RequestID = auditCorrelationID(completion.RequestID)
	completion.TraceID = auditCorrelationID(completion.TraceID)
	if store == nil || completion.RequestID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := store.Complete(ctx, completion); err != nil {
		m.recordAuditCaptureFailure()
	}
}
func (m *Manager) completeRequestAudit(completion pluginapi.RequestCompletion, apiKey string) {
	m.mu.RLock()
	adminToken := m.cfg.AdminToken
	m.mu.RUnlock()
	finished := completion.CompletedAt
	if finished.IsZero() {
		finished = time.Now().UTC()
	}
	duration := int64(0)
	if !completion.StartedAt.IsZero() && finished.After(completion.StartedAt) {
		duration = finished.Sub(completion.StartedAt).Milliseconds()
	}
	outcome := string(completion.Outcome)
	switch outcome {
	case "succeeded", "failed", "rejected", "canceled":
	default:
		outcome = "unknown"
	}
	m.completeAudit(audit.Completion{RequestID: completion.RequestID, TraceID: completion.TraceID, CompletedAt: finished.UnixMilli(), ServedModel: auditSafeLabel(completion.Model, apiKey, adminToken), Outcome: outcome, StatusCode: completion.StatusCode, DurationMS: duration})
}
func (m *Manager) auditUsage(rec pluginapi.UsageRecord) {
	m.mu.RLock()
	adminToken := m.cfg.AdminToken
	m.mu.RUnlock()
	m.completeAudit(audit.Completion{RequestID: rec.RequestID, TraceID: rec.TraceID, ServedModel: auditSafeLabel(rec.ResponseModel, rec.APIKey, adminToken), InputTokens: rec.Detail.InputTokens, OutputTokens: rec.Detail.OutputTokens, TotalTokens: rec.Detail.TotalTokens})
}
