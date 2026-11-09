package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

// auditRuntime owns cleanup only; the shared SQLite handle remains usageStore-owned.
type auditRuntime struct {
	store       *audit.Store
	cfg         AuditConfig
	cancel      context.CancelFunc
	done        chan struct{}
	dropped     atomic.Uint64
	lastFailure atomic.Int64
}

func (m *Manager) configureAudit(cfg AuditConfig) {
	m.stopAudit()
	store := audit.NewStore(m.usageStore.DB(), audit.Config{Enabled: cfg.isEnabled(), RetentionDays: cfg.RetentionDays, MaxRecords: cfg.MaxRecords, MaxBodyBytes: cfg.MaxBodyBytes, MaxTotalBytes: cfg.MaxTotalBytes, TrustedProxies: append([]string(nil), cfg.TrustedProxies...)})
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &auditRuntime{store: store, cfg: cfg, cancel: cancel, done: make(chan struct{})}
	m.auditMu.Lock()
	m.auditRuntime = runtime
	m.auditMu.Unlock()
	go func() {
		defer close(runtime.done)
		cleanup := func() {
			work, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			_ = store.Prune(work, time.Now())
		}
		cleanup()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup()
			}
		}
	}()
}
func (m *Manager) stopAudit() {
	m.auditMu.Lock()
	runtime := m.auditRuntime
	m.auditRuntime = nil
	m.auditMu.Unlock()
	if runtime != nil {
		runtime.cancel()
		<-runtime.done
	}
}
func (m *Manager) auditSnapshot() (*audit.Store, AuditConfig) {
	m.auditMu.RLock()
	defer m.auditMu.RUnlock()
	if m.auditRuntime == nil {
		return nil, AuditConfig{}
	}
	return m.auditRuntime.store, m.auditRuntime.cfg
}
func (m *Manager) AuditStatus() map[string]any {
	store, _ := m.auditSnapshot()
	status := map[string]any{"enabled": false, "warning": "当前宿主插件接口未提供已验证的客户端网络元数据，IP 缺失时显示未知；不会信任任意转发头"}
	if store != nil {
		raw, _ := json.Marshal(store.Status())
		_ = json.Unmarshal(raw, &status)
	}
	m.auditMu.RLock()
	runtime := m.auditRuntime
	if runtime != nil {
		status["capture_failures"] = runtime.dropped.Load()
		if at := runtime.lastFailure.Load(); at > 0 {
			status["last_capture_failure_at"] = auditTime(at)
		}
	}
	m.auditMu.RUnlock()
	return status
}
func auditSafeLabel(raw string, secrets ...string) string {
	return audit.SanitizeText(strings.TrimSpace(raw), 160, secrets...)
}

func (m *Manager) recordAuditCaptureFailure() {
	m.auditMu.RLock()
	defer m.auditMu.RUnlock()
	if runtime := m.auditRuntime; runtime != nil {
		runtime.dropped.Add(1)
		runtime.lastFailure.Store(time.Now().UTC().UnixMilli())
	}
}
