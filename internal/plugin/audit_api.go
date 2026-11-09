package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
)

func auditRecordView(record audit.Record, detail bool) map[string]any {
	raw, _ := json.Marshal(record)
	view := map[string]any{}
	_ = json.Unmarshal(raw, &view)
	view["started_at"] = auditTime(record.StartedAt)
	view["completed_at"] = auditTime(record.CompletedAt)
	if !detail {
		delete(view, "request_body")
	}
	return view
}
func auditTime(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}
func (m *Manager) QueryAudit(ctx context.Context, q audit.Query) (map[string]any, error) {
	store, _ := m.auditSnapshot()
	if store == nil {
		return nil, audit.ErrUnavailable
	}
	q.RequestID = auditCorrelationID(q.RequestID)
	q.TraceID = auditCorrelationID(q.TraceID)
	result, err := store.List(ctx, q)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(result.Records))
	for _, record := range result.Records {
		items = append(items, auditRecordView(record, false))
	}
	return map[string]any{"items": items, "total": result.Total, "limit": result.Limit, "offset": result.Offset, "status": m.AuditStatus()}, nil
}
func (m *Manager) AuditDetail(ctx context.Context, id string) (map[string]any, error) {
	store, _ := m.auditSnapshot()
	if store == nil {
		return nil, audit.ErrUnavailable
	}
	record, err := store.Detail(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"record": auditRecordView(record, true), "status": m.AuditStatus()}, nil
}

// AuditKeyOptions exposes current configured keys only as irreversible selector
// values and masked labels. Retained deleted-key options can be derived from audit
// list metadata by the page without reintroducing raw API keys into URLs.
func (m *Manager) AuditKeyOptions() []map[string]string {
	type optionKey struct{ key, name string }
	m.mu.RLock()
	keys := make([]optionKey, 0, len(m.cfg.Keys))
	for _, rule := range m.cfg.Keys {
		keys = append(keys, optionKey{key: rule.APIKey, name: rule.Name})
	}
	adminToken := m.cfg.AdminToken
	m.mu.RUnlock()
	options := make([]map[string]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, item := range keys {
		key := strings.TrimSpace(item.key)
		if key == "" {
			continue
		}
		digest := sha256.Sum256([]byte(key))
		value := hex.EncodeToString(digest[:])
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		masked := "***"
		if len(key) > 2 {
			masked = usage.MaskAPIKey(key)
		}
		name := auditSafeLabel(item.name, key, adminToken)
		label := masked
		if name != "" {
			label = name + " · " + masked
		}
		options = append(options, map[string]string{"value": value, "label": label})
	}
	return options
}
