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
	store := audit.NewStore(m.usageStore.DB(), audit.Config{Enabled: cfg.isEnabled(), RetentionDays: cfg.RetentionDays, MaxRecords: cfg.MaxRecords, MaxBodyBytes: cfg.MaxBodyBytes, MaxTotalBytes: cfg.MaxTotalBytes})
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &auditRuntime{store: store, cfg: cfg, cancel: cancel, done: make(chan struct{})}
	m.auditMu.Lock()
	m.auditRuntime = runtime
	m.auditMu.Unlock()
	go func() {
		defer close(runtime.done)
		cleanup := func() {
			// Stop wakes the loop but lets an active cleanup finish within its own
			// deadline. Cancelling its transaction mid-commit can leave database/sql
			// asynchronous rollback still closing the shared driver during shutdown.
			work, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	m.clearAuditCleanup()
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
	status := map[string]any{"enabled": false, "body_capture_mode": "plaintext_json", "ip_monitoring": false}
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

// writeCurrentAudit acquires a generation lease after CPU-only body preparation.
// A runtime swap waits for in-flight SQL writes, and a prepared old-generation
// capture cannot write after a disabling or tighter configuration has applied.
// Do not call recordAuditCaptureFailure inside this lease: a nested RLock could
// deadlock with a writer already waiting to reconfigure the runtime.
func (m *Manager) writeCurrentAudit(expected *audit.Store, write func(*audit.Store) error) bool {
	m.auditMu.RLock()
	defer m.auditMu.RUnlock()
	current := m.auditRuntime
	if expected == nil || current == nil || current.store != expected || !current.cfg.isEnabled() {
		return false
	}
	if err := write(current.store); err != nil {
		current.dropped.Add(1)
		current.lastFailure.Store(time.Now().UTC().UnixMilli())
	}
	return true
}
