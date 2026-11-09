package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

func TestAuditPreparedOldGenerationCannotWriteAfterDisableOrLimitChange(t *testing.T) {
	m := transactionManager(t)
	old, cfg := m.auditSnapshot()
	disabled := false
	next := cfg
	next.Enabled = &disabled
	m.configureAudit(next)
	called := false
	if m.writeCurrentAudit(old, func(*audit.Store) error { called = true; return nil }) || called {
		t.Fatal("old generation wrote after disable")
	}
	enabled := true
	next.Enabled = &enabled
	next.MaxRecords = 1
	m.configureAudit(next)
	if m.writeCurrentAudit(old, func(*audit.Store) error { called = true; return nil }) || called {
		t.Fatal("old generation wrote after tighter limit applied")
	}
	current, _ := m.auditSnapshot()
	if !m.writeCurrentAudit(current, func(*audit.Store) error { called = true; return nil }) || !called {
		t.Fatal("current enabled generation did not write")
	}
}

func TestAuditReconfigureWaitsForLeasedWriteThenRejectsOldCompletion(t *testing.T) {
	m := transactionManager(t)
	old, cfg := m.auditSnapshot()
	entered := make(chan struct{})
	release := make(chan struct{})
	written := make(chan struct{})
	go func() {
		defer close(written)
		m.writeCurrentAudit(old, func(store *audit.Store) error {
			close(entered)
			<-release
			return store.Begin(context.Background(), audit.Record{RequestID: "leased-before-disable", Outcome: "running"})
		})
	}()
	<-entered
	disabled := false
	cfg.Enabled = &disabled
	updated := make(chan struct{})
	started := make(chan struct{})
	go func() { close(started); m.configureAudit(cfg); close(updated) }()
	<-started
	select {
	case <-updated:
		t.Fatal("runtime swapped before leased write completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-written
	select {
	case <-updated:
	case <-time.After(3 * time.Second):
		t.Fatal("reconfigure deadlocked waiting for write lease")
	}
	executed := false
	if m.writeCurrentAudit(old, func(store *audit.Store) error {
		executed = true
		return store.Complete(context.Background(), audit.Completion{RequestID: "leased-before-disable", Outcome: "succeeded"})
	}) || executed {
		t.Fatal("old completion wrote after disable")
	}
	current, _ := m.auditSnapshot()
	records, err := current.List(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(records.Records) != 1 || records.Records[0].Outcome != "running" {
		t.Fatal("old terminal callback changed record after disable")
	}
}

func TestAuditLeasedFailureDoesNotDeadlockOrDisappearFromItsGeneration(t *testing.T) {
	m := transactionManager(t)
	store, _ := m.auditSnapshot()
	if !m.writeCurrentAudit(store, func(*audit.Store) error { return audit.ErrUnavailable }) {
		t.Fatal("current write not attempted")
	}
	status := m.AuditStatus()
	if status["capture_failures"].(uint64) != 1 {
		t.Fatal("leased error was not recorded")
	}
}
