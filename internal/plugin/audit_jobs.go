package plugin

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

// These APIs authorize a durable snapshot, not an unbounded SQL request. The host
// verifies management credentials; only their irreversible identity hash is stored.
func cleanupJobIdentity(principal string) (string, error) {
	hash, err := cleanupPrincipal(principal)
	if err != nil {
		return "", ErrAuditCleanupToken
	}
	return hex.EncodeToString(hash[:]), nil
}
func (m *Manager) PreviewAuditCleanupJob(ctx context.Context, scope string, before time.Time, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, cfg, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	cutoff := ""
	if !before.IsZero() {
		cutoff = before.UTC().Format(time.RFC3339Nano)
	}
	preview, err := store.PreviewCleanupJob(ctx, scope, cutoff, owner, audit.CleanupBatchLimits{MaxRecords: cfg.CleanupBatchMaxRecords, MaxBytes: cfg.CleanupBatchMaxBytes})
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "preview": preview}, nil
}
func (m *Manager) StartAuditCleanupJob(ctx context.Context, token, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, _, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	job, err := store.StartCleanupJob(ctx, token, owner)
	if err != nil {
		return nil, err
	}
	release()
	m.wakeAuditCleanupJobs()
	return map[string]any{"ok": true, "job": job}, nil
}
func (m *Manager) ListAuditCleanupJobs(ctx context.Context, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, _, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	jobs, err := store.ListCleanupJobs(ctx, owner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"jobs": jobs}, nil
}
func (m *Manager) GetAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, _, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	job, err := store.GetCleanupJob(ctx, id, owner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"job": job}, nil
}
func (m *Manager) CancelAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, _, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	job, err := store.CancelCleanupJob(ctx, id, owner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "job": job}, nil
}
func (m *Manager) ResumeAuditCleanupJob(ctx context.Context, id, principal string) (map[string]any, error) {
	owner, err := cleanupJobIdentity(principal)
	if err != nil {
		return nil, err
	}
	store, _, release, err := m.auditJobLease()
	if err != nil {
		return nil, err
	}
	defer release()
	job, err := store.ResumeCleanupJob(ctx, id, owner)
	if err != nil {
		return nil, err
	}
	release()
	m.wakeAuditCleanupJobs()
	return map[string]any{"ok": true, "job": job}, nil
}
func (m *Manager) wakeAuditCleanupJobs() {
	m.auditMu.RLock()
	defer m.auditMu.RUnlock()
	if current := m.auditRuntime; current != nil {
		select {
		case current.jobsWake <- struct{}{}:
		default:
		}
	}
}

// A worker owns no database handle. Each batch leases the shared connection for
// at most the existing ten-second budget, commits progress atomically, then yields.
// Shutdown wakes the loop but lets an active batch finish before the owner closes DB.
func runAuditCleanupJobs(ctx context.Context, current *auditRuntime) {
	for {
		if ctx.Err() != nil {
			return
		}
		work, cancel := context.WithTimeout(context.Background(), audit.CleanupApplyTimeout)
		worked, err := current.store.RunCleanupJobBatch(work, audit.CleanupBatchLimits{MaxRecords: current.cfg.CleanupBatchMaxRecords, MaxBytes: current.cfg.CleanupBatchMaxBytes})
		cancel()
		wait := time.Second
		if worked && err == nil {
			wait = 250 * time.Millisecond
		}
		timer := time.NewTimer(wait)
		if worked {
			// Even a repeated idempotent start must not bypass the inter-batch yield.
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-current.jobsWake:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

// Task status/control must never retry unrelated host-key synchronization or
// wait on its network timeout after a task has already been persisted.
func isAuditCleanupJobPath(path string) bool {
	const base = "/v0/management/key-guard/audit/cleanup/jobs"
	return path == base || path == base+"/preview" || path == base+"/detail" || path == base+"/cancel" || path == base+"/resume"
}

// A read lease fences API storage operations against runtime teardown and DB close.
// It is released before wake, never reacquired recursively while a writer waits.
func (m *Manager) auditJobLease() (*audit.Store, AuditConfig, func(), error) {
	m.auditMu.RLock()
	current := m.auditRuntime
	if current == nil {
		m.auditMu.RUnlock()
		return nil, AuditConfig{}, nil, audit.ErrUnavailable
	}
	var once sync.Once
	return current.store, current.cfg, func() { once.Do(m.auditMu.RUnlock) }, nil
}
