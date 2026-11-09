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

// Local rejections must not do full-body parsing/formatting or block their 429/403
// response on SQLite. Only bounded metadata-only work is admitted, never raw body
// bytes or authentication headers. Saturation is observable via failure counts.
func (m *Manager) beginRejectedAudit(req pluginapi.RequestInterceptRequest, apiKey, keyLabel string, status int) {
	store, cfg := m.auditSnapshot()
	if store == nil || !cfg.isEnabled() || req.RequestID == "" {
		return
	}
	select {
	case m.rejectedAuditSlots <- struct{}{}:
	default:
		m.recordAuditCaptureFailure()
		return
	}
	now := time.Now().UTC().UnixMilli()
	fingerprint := ""
	if apiKey != "" {
		sum := sha256.Sum256([]byte(apiKey))
		fingerprint = hex.EncodeToString(sum[:])
	}
	path := ""
	if value, ok := req.Metadata["request_path"].(string); ok {
		if parsed, err := url.Parse(value); err == nil && strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//") {
			path = parsed.Path
		}
	}
	rec := audit.Record{RequestID: auditCorrelationID(req.RequestID), TraceID: auditCorrelationID(req.TraceID), StartedAt: now, CompletedAt: now, Path: auditSafeLabel(path, apiKey), KeyLabel: auditSafeLabel(keyLabel, apiKey), KeyFingerprint: fingerprint, RequestedModel: auditSafeLabel(req.RequestedModel, apiKey), ServedModel: auditSafeLabel(req.Model, apiKey), Protocol: auditSafeLabel(req.SourceFormat), Stream: req.Stream, Outcome: "rejected", StatusCode: status, BodyState: "omitted_rejected"}
	go func() {
		defer func() { <-m.rejectedAuditSlots }()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		m.writeCurrentAudit(store, func(current *audit.Store) error { return current.Begin(ctx, rec) })
	}()
}
