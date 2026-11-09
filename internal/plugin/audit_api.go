package plugin

import (
	"context"
	"encoding/json"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
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
