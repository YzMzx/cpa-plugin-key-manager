package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

func cleanupPreviewToken(t *testing.T, m *Manager, scope, principal string) string {
	t.Helper()
	value, err := m.PreviewAuditCleanup(context.Background(), scope, time.Time{}, principal)
	if err != nil {
		t.Fatal(err)
	}
	return value["preview"].(map[string]any)["token"].(string)
}
func TestAuditCleanupPreviewExposesBatchLimits(t *testing.T) {
	m := transactionManager(t)
	db := m.usageStore.DB().Conn()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 4; i++ {
		if _, err := tx.Exec("INSERT INTO client_request_audit(id,request_id,started_at,logical_bytes) VALUES(?,?,?,?)", fmt.Sprintf("%064x", i), fmt.Sprint(i), time.Now().UnixMilli(), 10<<20); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	value, err := m.PreviewAuditCleanup(context.Background(), "all", time.Time{}, "manager")
	if err != nil {
		t.Fatal(err)
	}
	preview := value["preview"].(map[string]any)
	if preview["limited"] != true || preview["remaining_records"] != int64(1) || preview["records"] != int64(3) {
		t.Fatalf("missing batch limits: %v", preview)
	}
}

func TestAuditCleanupTokenIdentitySingleUseAndSnapshot(t *testing.T) {
	m := transactionManager(t)
	auditRequest(t, m, "cleanup-one")
	token := cleanupPreviewToken(t, m, "all", "management-one")
	if len(token) != 64 || strings.Contains(token, "management") {
		t.Fatal("unsafe token")
	}
	if _, err := m.CleanupAudit(context.Background(), token, "management-two"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("identity mismatch accepted")
	}
	auditRequest(t, m, "cleanup-after-preview")
	result, err := m.CleanupAudit(context.Background(), token, "management-one")
	if err != nil {
		t.Fatal(err)
	}
	if result["deleted"].(map[string]any)["records"] != int64(1) {
		t.Fatalf("wrong actual delete %v", result)
	}
	records := auditRecords(t, m)
	if len(records) != 1 || records[0].RequestID != auditCorrelationID("cleanup-after-preview") {
		t.Fatal("deleted request added after preview")
	}
	if _, err := m.CleanupAudit(context.Background(), token, "management-one"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("token replay accepted")
	}
	if _, err := m.CleanupAudit(context.Background(), "bad-token", "management-one"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("invalid token accepted")
	}
}
func TestAuditCleanupExpiryLimitAndReset(t *testing.T) {
	m := transactionManager(t)
	token := cleanupPreviewToken(t, m, "all", "manager")
	runtime := m.cleanupRuntime()
	runtime.mu.Lock()
	clock := time.Now().UTC()
	runtime.now = func() time.Time { return clock.Add(6 * time.Minute) }
	runtime.mu.Unlock()
	if _, err := m.CleanupAudit(context.Background(), token, "manager"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("expired token accepted")
	}
	runtime.mu.Lock()
	runtime.now = nil
	runtime.mu.Unlock()
	for i := 0; i < auditCleanupMaxPlans; i++ {
		cleanupPreviewToken(t, m, "all", "manager")
	}
	if _, err := m.PreviewAuditCleanup(context.Background(), "all", time.Time{}, "manager"); !errors.Is(err, ErrAuditCleanupLimit) {
		t.Fatal("unbounded pending previews")
	}
	m.clearAuditCleanup()
	token = cleanupPreviewToken(t, m, "all", "manager")
	m.clearAuditCleanup()
	if _, err := m.CleanupAudit(context.Background(), token, "manager"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("reset retained token")
	}
}
func TestAuditCleanupFailureConsumesTokenAndNeverTouchesRules(t *testing.T) {
	m := transactionManager(t)
	auditRequest(t, m, "cleanup-cancel")
	token := cleanupPreviewToken(t, m, "all", "manager")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.CleanupAudit(ctx, token, "manager"); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("unexpected canceled outcome %v", err)
	}
	if _, err := m.CleanupAudit(context.Background(), token, "manager"); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("failed token retry accepted")
	}
	if records := auditRecords(t, m); len(records) != 1 {
		t.Fatal("canceled cleanup mutated audit")
	}
	var rules int
	if err := m.usageStore.DB().Conn().QueryRow("SELECT COUNT(*) FROM rules_state").Scan(&rules); err != nil || rules != 1 {
		t.Fatal("rules affected")
	}
	if _, err := m.PreviewAuditCleanup(context.Background(), "all", time.Time{}, ""); !errors.Is(err, ErrAuditCleanupToken) {
		t.Fatal("empty principal accepted")
	}
}
