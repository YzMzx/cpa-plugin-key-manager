package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func durablePreview(t *testing.T, m *Manager) string {
	t.Helper()
	value, err := m.PreviewAuditCleanupJob(context.Background(), "all", time.Time{}, "manager")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value["preview"])
	var preview struct{ Token string }
	if err := json.Unmarshal(raw, &preview); err != nil {
		t.Fatal(err)
	}
	return preview.Token
}
func durableJob(t *testing.T, value map[string]any) audit.CleanupJob {
	t.Helper()
	raw, _ := json.Marshal(value["job"])
	var job audit.CleanupJob
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	return job
}
func awaitDurableJob(t *testing.T, m *Manager, id string) audit.CleanupJob {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		value, err := m.GetAuditCleanupJob(context.Background(), id, "manager")
		if err != nil {
			t.Fatal(err)
		}
		job := durableJob(t, value)
		if job.State == "completed" || job.State == "failed" || job.State == "canceled" {
			return job
		}
		select {
		case <-deadline.C:
			t.Fatal("cleanup worker did not finish")
		case <-ticker.C:
		}
	}
}
func TestDurableCleanupWorkerFullSnapshotAndReplay(t *testing.T) {
	m := transactionManager(t)
	store, cfg := m.auditSnapshot()
	// Seed synthetic logical weights without creating production-sized payloads.
	tx, err := m.usageStore.DB().Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := tx.Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,?,?)", fmt.Sprintf("%064x", i+1), fmt.Sprint(i), time.Now().UnixMilli(), 10<<20); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	token := durablePreview(t, m)
	if err := store.Begin(context.Background(), audit.Record{RequestID: "new-after-preview", StartedAt: time.Now().Add(-time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	value, err := m.StartAuditCleanupJob(context.Background(), token, "manager")
	if err != nil {
		t.Fatal(err)
	}
	job := durableJob(t, value)
	again, err := m.StartAuditCleanupJob(context.Background(), token, "manager")
	if err != nil || durableJob(t, again).ID != job.ID {
		t.Fatalf("duplicate task: %v", err)
	}
	finished := awaitDurableJob(t, m, job.ID)
	if finished.State != "completed" || finished.DeletedRecords != 4 || finished.Batches < 2 {
		t.Fatalf("not full bounded cleanup: %+v", finished)
	}
	records := auditRecords(t, m)
	if len(records) != 1 || records[0].RequestID != "new-after-preview" {
		t.Fatal("new record included in snapshot")
	}
	if _, err := m.GetAuditCleanupJob(context.Background(), job.ID, "other"); err == nil {
		t.Fatal("cross-owner read")
	}
	m.configureAudit(cfg)
	after, err := m.GetAuditCleanupJob(context.Background(), job.ID, "manager")
	if err != nil || durableJob(t, after).State != "completed" {
		t.Fatal("hot reconfigure lost task")
	}
}
func TestDurableCleanupWorkerRestartsWithoutManagementRequest(t *testing.T) {
	m := transactionManager(t)
	store, cfg := m.auditSnapshot()
	m.stopAudit()
	// Persist through the borrowed store while no worker runs, then emulate restart.
	if err := store.Begin(context.Background(), audit.Record{RequestID: "restart-job", StartedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	owner, _ := cleanupJobIdentity("manager")
	preview, err := store.PreviewCleanupJob(context.Background(), "all", "", owner, audit.CleanupBatchLimits{MaxRecords: 1000, MaxBytes: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.StartCleanupJob(context.Background(), preview.Token, owner)
	if err != nil {
		t.Fatal(err)
	}
	m.configureAudit(cfg)
	if result := awaitDurableJob(t, m, job.ID); result.State != "completed" || result.DeletedRecords != 1 {
		t.Fatalf("failed recovery: %+v", result)
	}
}
func TestCleanupJobManagementDoesNotRetryHostSync(t *testing.T) {
	m := transactionManager(t)
	calls := 0
	m.hostKeySync = func(context.Context, string, []string) error { calls++; return nil }
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"sync-pending"}`)); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/key-guard/audit/cleanup/jobs", Headers: http.Header{"Authorization": {"Bearer manager"}}})
	out, err := m.handleManagement(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeEnvelope[pluginapi.ManagementResponse](t, out)
	if resp.StatusCode != 200 || calls != 0 {
		t.Fatalf("task endpoint blocked by unrelated sync: status=%d calls=%d", resp.StatusCode, calls)
	}
}
func TestCleanupJobLeaseFencesTeardown(t *testing.T) {
	m := transactionManager(t)
	_, _, release, err := m.auditJobLease()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { m.stopAudit(); close(done) }()
	select {
	case <-done:
		t.Fatal("runtime stopped while task storage lease active")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	release()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop after task lease release")
	}
	if _, err := m.ListAuditCleanupJobs(context.Background(), "manager"); err != audit.ErrUnavailable {
		t.Fatalf("stopped runtime accepted task API: %v", err)
	}
}
func TestCleanupJobPersistsAcrossActualManagerRestart(t *testing.T) {
	m := transactionManager(t)
	store, _ := m.auditSnapshot()
	m.stopAudit()
	owner, _ := cleanupJobIdentity("manager")
	if err := store.Begin(context.Background(), audit.Record{RequestID: "full-restart", StartedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	p, err := store.PreviewCleanupJob(context.Background(), "all", "", owner, audit.CleanupBatchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.StartCleanupJob(context.Background(), p.Token, owner)
	if err != nil {
		t.Fatal(err)
	}
	m.Shutdown()
	next := NewManager(nil)
	defer next.Shutdown()
	// Skip reference-price fetching, unrelated to this isolated recovery test.
	next.lastSyncKey = m.lastSyncKey
	if err := next.Configure(nil); err != nil {
		t.Fatal(err)
	}
	if result := awaitDurableJob(t, next, job.ID); result.State != "completed" || result.DeletedRecords != 1 {
		t.Fatalf("manager restart lost task: %+v", result)
	}
}
func TestCleanupJobControlDoesNotUseUnrelatedRulesRevision(t *testing.T) {
	m := transactionManager(t)
	raw, _ := json.Marshal(pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/v0/management/key-guard/audit/cleanup/jobs/preview", Headers: http.Header{"Authorization": {"Bearer manager"}, "X-Key-Guard-Revision": {"18446744073709551615"}}, Body: []byte(`{"scope":"all"}`)})
	out, err := m.handleManagement(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeEnvelope[pluginapi.ManagementResponse](t, out)
	if resp.StatusCode != 200 {
		t.Fatalf("unrelated rule revision blocked job preview: %d %s", resp.StatusCode, resp.Body)
	}
}
