package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAuditBodyDeadlineKeepsMetadataAndGeneration(t *testing.T) {
	m := transactionManager(t)
	now := time.Now()
	m.auditBodies = audit.NewBodyCaptureBudgetWithClock(func() time.Time { now = now.Add(time.Second); return now })
	// Runtime replacement must not reset the manager-owned preparation budget.
	_, cfg := m.auditSnapshot()
	m.configureAudit(cfg)
	m.beginAudit(pluginapi.RequestInterceptRequest{RequestID: "body-deadline", SourceFormat: "openai", Body: []byte(`{"text":"private body"}`)}, "", "")
	records := auditRecords(t, m)
	if len(records) != 1 {
		t.Fatal("deadline omission lost request metadata")
	}
	store, _ := m.auditSnapshot()
	detail, err := store.Detail(context.Background(), records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.BodyState != "omitted_processing_limit" || detail.RequestBody != "" || detail.BodySHA256 != "" {
		t.Fatalf("deadline retained body: %+v", detail)
	}
}
