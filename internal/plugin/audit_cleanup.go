package plugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

type auditCleanupError string

func (e auditCleanupError) Error() string { return string(e) }
func (e auditCleanupError) AuditCleanupCode() string {
	if e == ErrAuditCleanupLimit {
		return "preview_limit"
	}
	return "preview_token"
}

const (
	ErrAuditCleanupToken auditCleanupError = "audit cleanup preview is invalid or expired"
	ErrAuditCleanupLimit auditCleanupError = "too many pending audit cleanup previews"
)
const auditCleanupTTL = 5 * time.Minute
const auditCleanupMaxPlans = 8

type auditCleanupRuntime struct {
	mu    sync.Mutex
	plans map[string]auditCleanupPending
	now   func() time.Time
}
type auditCleanupPending struct {
	plan      audit.CleanupPlan
	principal [32]byte
	expires   time.Time
	store     *audit.Store
}

func (m *Manager) cleanupRuntime() *auditCleanupRuntime {
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	if m.auditCleanup == nil {
		m.auditCleanup = &auditCleanupRuntime{plans: make(map[string]auditCleanupPending)}
	}
	return m.auditCleanup
}

// clearAuditCleanup is called on audit reconfigure/shutdown, outside auditMu.
func (m *Manager) clearAuditCleanup() {
	m.auditMu.Lock()
	runtime := m.auditCleanup
	m.auditCleanup = nil
	m.auditMu.Unlock()
	if runtime != nil {
		runtime.mu.Lock()
		clear(runtime.plans)
		runtime.mu.Unlock()
	}
}
func cleanupClock(runtime *auditCleanupRuntime) time.Time {
	if runtime.now != nil {
		return runtime.now().UTC()
	}
	return time.Now().UTC()
}
func cleanupPrincipal(value string) ([32]byte, error) {
	if value == "" {
		return [32]byte{}, ErrAuditCleanupToken
	}
	return sha256.Sum256([]byte(value)), nil
}
func storageMap(value audit.StorageUsage) map[string]any {
	return map[string]any{"records": value.Records, "active_records": value.ActiveRecords, "expired_records": value.ExpiredRecords, "logical_bytes": value.LogicalBytes, "request_body_bytes": value.RequestBodyBytes, "max_total_bytes": value.MaxTotalBytes, "utilization_percent": value.UtilizationPercent, "db_file_bytes": value.DBFileBytes, "wal_file_bytes": value.WALFileBytes, "retention_days": value.RetentionDays, "capacity_mode": value.CapacityMode, "physical_size_scope": value.PhysicalSizeScope, "warning": value.Warning}
}
func (m *Manager) AuditStorage(ctx context.Context) (map[string]any, error) {
	store, _ := m.auditSnapshot()
	if store == nil {
		return nil, audit.ErrUnavailable
	}
	value, err := store.Storage(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"storage": storageMap(value)}, nil
}
func (m *Manager) PreviewAuditCleanup(ctx context.Context, scope string, before time.Time, principal string) (map[string]any, error) {
	identity, err := cleanupPrincipal(principal)
	if err != nil {
		return nil, err
	}
	store, _ := m.auditSnapshot()
	if store == nil {
		return nil, audit.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	plan, err := store.PreviewCleanup(ctx, scope, before)
	if err != nil {
		return nil, err
	}
	storage, err := store.Storage(ctx)
	if err != nil {
		return nil, err
	}
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return nil, audit.ErrUnavailable
	}
	token := hex.EncodeToString(bytes[:])
	runtime := m.cleanupRuntime()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now := cleanupClock(runtime)
	for key, value := range runtime.plans {
		if !value.expires.After(now) {
			delete(runtime.plans, key)
		}
	}
	if len(runtime.plans) >= auditCleanupMaxPlans {
		return nil, ErrAuditCleanupLimit
	}
	expires := now.Add(auditCleanupTTL)
	runtime.plans[token] = auditCleanupPending{plan: plan, principal: identity, expires: expires, store: store}
	return map[string]any{"ok": true, "preview": map[string]any{"token": token, "scope": plan.Scope, "before": auditTime(plan.BeforeUnixMilli), "records": plan.Records, "logical_bytes": plan.LogicalBytes, "request_body_bytes": plan.BodyBytes, "expires_at": expires.Format(time.RFC3339Nano)}, "storage": storageMap(storage)}, nil
}
func (m *Manager) CleanupAudit(ctx context.Context, token, principal string) (map[string]any, error) {
	identity, err := cleanupPrincipal(principal)
	if err != nil {
		return nil, err
	}
	if len(token) != 64 {
		return nil, ErrAuditCleanupToken
	}
	if _, err := hex.DecodeString(token); err != nil {
		return nil, ErrAuditCleanupToken
	}
	runtime := m.cleanupRuntime()
	runtime.mu.Lock()
	pending, ok := runtime.plans[token]
	if !ok {
		runtime.mu.Unlock()
		return nil, ErrAuditCleanupToken
	}
	if !pending.expires.After(cleanupClock(runtime)) {
		delete(runtime.plans, token)
		runtime.mu.Unlock()
		return nil, ErrAuditCleanupToken
	}
	if subtle.ConstantTimeCompare(pending.principal[:], identity[:]) != 1 {
		runtime.mu.Unlock()
		return nil, ErrAuditCleanupToken
	}
	// Consume before SQL even on failure. The outcome may be unknown to a timed-out client.
	delete(runtime.plans, token)
	runtime.mu.Unlock()
	store, _ := m.auditSnapshot()
	if store == nil || store != pending.store {
		return nil, ErrAuditCleanupToken
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	deleted, err := store.ApplyCleanup(ctx, pending.plan)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"ok": true, "deleted": map[string]any{"records": deleted.Records, "logical_bytes": deleted.LogicalBytes, "request_body_bytes": deleted.BodyBytes}}
	storage, err := store.Storage(ctx)
	if err != nil {
		result["warning"] = "Audit records were deleted; refresh storage statistics."
	} else {
		result["storage"] = storageMap(storage)
	}
	return result, nil
}
