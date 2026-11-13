package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

func TestCleanupBudgetConfigDefaultsAndBounds(t *testing.T) {
	isolateStateDirs(t)
	for _, raw := range []string{"", "audit:\n  retention_days: 14\n"} {
		cfg, err := ParseConfigYAML([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Audit.CleanupBatchMaxRecords != 1000 || cfg.Audit.CleanupBatchMaxBytes != 32<<20 {
			t.Fatalf("old configuration missing cleanup defaults: %+v", cfg.Audit)
		}
	}
	for _, tc := range []struct {
		records int
		bytes   int64
		valid   bool
	}{
		{1, 16 << 20, true}, {5000, 128 << 20, true},
		{-1, 32 << 20, false}, {5001, 32 << 20, false},
		{1000, (16 << 20) - 1, false}, {1000, (128 << 20) + 1, false},
	} {
		cfg := DefaultConfig()
		cfg.Normalize()
		cfg.Audit.CleanupBatchMaxRecords, cfg.Audit.CleanupBatchMaxBytes = tc.records, tc.bytes
		if err := cfg.Audit.validate(); (err == nil) != tc.valid {
			t.Fatalf("limits %+v: %v", tc, err)
		}
	}
	cfg, err := ParseConfigYAML([]byte("audit:\n  cleanup_batch_max_records: 7\n  cleanup_batch_max_bytes: 16777217\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.CleanupBatchMaxRecords != 7 || cfg.Audit.CleanupBatchMaxBytes != 16777217 {
		t.Fatalf("explicit YAML budget lost: %+v", cfg.Audit)
	}
	for _, raw := range []string{
		"audit:\n  cleanup_batch_max_bytes: 16777216.5\n",
		"audit:\n  cleanup_batch_max_records: 1.5\n",
		"audit:\n  cleanup_batch_max_bytes: \"33554432\"\n",
		"audit:\n  cleanup_batch_max_bytes: null\n",
		"defaults: &budget\n  cleanup_batch_max_bytes: 16777216.5\naudit:\n  <<: *budget\n",
	} {
		if _, err := ParseConfigYAML([]byte(raw)); err == nil {
			t.Fatalf("non-integer YAML budget accepted: %s", raw)
		}
	}
}

func TestCleanupBudgetRuntimeSettingsNormalizeOnlyLegacyDefaults(t *testing.T) {
	isolateStateDirs(t)
	cfg := DefaultConfig()
	cfg.Normalize()
	settings := runtimeSettingsFromConfig(cfg)
	settings.Audit.CleanupBatchMaxRecords, settings.Audit.CleanupBatchMaxBytes = 0, 0
	normalizeRuntimeSettings(&settings)
	if settings.Audit.CleanupBatchMaxRecords != audit.DefaultCleanupBatchRecords || settings.Audit.CleanupBatchMaxBytes != audit.DefaultCleanupBatchBytes {
		t.Fatalf("legacy defaults missing: %+v", settings.Audit)
	}
	if err := validateRuntimeSettings(&settings); err != nil {
		t.Fatal(err)
	}
	settings.Audit.CleanupBatchMaxRecords = -1
	normalizeRuntimeSettings(&settings)
	if err := validateRuntimeSettings(&settings); !errors.Is(err, ErrSettingsInvalid) {
		t.Fatalf("invalid persisted limits concealed: %v", err)
	}
	normalizeRuntimeSettings(nil)
}

func TestCleanupBudgetSettingsStrictValidationAndMetadata(t *testing.T) {
	m := transactionManager(t)
	revision := m.RulesRevision()
	for _, patch := range []string{
		`{"cleanup_batch_max_records":0}`, `{"cleanup_batch_max_records":-1}`, `{"cleanup_batch_max_records":5001}`,
		`{"cleanup_batch_max_records":1.5}`, `{"cleanup_batch_max_records":null}`,
		`{"cleanup_batch_max_bytes":0}`, `{"cleanup_batch_max_bytes":16777215}`, `{"cleanup_batch_max_bytes":134217729}`,
		`{"cleanup_batch_max_bytes":16777216.5}`, `{"cleanup_batch_max_bytes":9223372036854775808}`,
		`{"cleanup_batch_max_bytes":"33554432"}`, `{"cleanup_batch_max_bytes":null}`,
	} {
		raw := []byte(`{"settings":{"audit":` + patch + `},"expected_revision":` + jsonNumber(revision) + `}`)
		if _, err := m.SaveRuntimeSettings(raw); !errors.Is(err, ErrSettingsInvalid) {
			t.Fatalf("invalid budget accepted %s: %v", patch, err)
		}
		if m.RulesRevision() != revision {
			t.Fatal("invalid budget changed revision")
		}
	}
	limits := m.GetRuntimeSettings()["limits"].(map[string]any)["audit"].(map[string]any)
	if !reflect.DeepEqual(limits["cleanup_batch_max_records"], []int{1, 5000}) || !reflect.DeepEqual(limits["cleanup_batch_max_bytes"], []int64{16 << 20, 128 << 20}) {
		t.Fatalf("budget limits absent: %+v", limits)
	}
	for _, tc := range []struct {
		records int
		bytes   int64
	}{{1, 16 << 20}, {5000, 128 << 20}} {
		patch := map[string]any{"audit": map[string]any{"cleanup_batch_max_records": tc.records, "cleanup_batch_max_bytes": tc.bytes}}
		if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, patch, false)); err != nil {
			t.Fatalf("valid budget requires no ack_prune: %v", err)
		}
	}
}

func TestCleanupBudgetSettingsSQLiteRestartPartialPatchAndHotApply(t *testing.T) {
	m := transactionManager(t)
	db := m.usageStore.DB()
	patch := map[string]any{"audit": map[string]any{"cleanup_batch_max_records": 321, "cleanup_batch_max_bytes": int64(48 << 20)}}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, patch, false)); err != nil {
		t.Fatal(err)
	}
	if m.usageStore.DB() != db {
		t.Fatal("cleanup budget reopened database")
	}
	_, live := m.auditSnapshot()
	if live.CleanupBatchMaxRecords != 321 || live.CleanupBatchMaxBytes != 48<<20 {
		t.Fatalf("budget not hot applied: %+v", live)
	}
	previewResult, err := m.PreviewAuditCleanupJob(context.Background(), "all", time.Time{}, "budget-test-principal")
	if err != nil {
		t.Fatal(err)
	}
	preview := previewResult["preview"].(audit.CleanupJobPreview)
	if preview.BatchMaxRecords != 321 || preview.BatchMaxBytes != 48<<20 {
		t.Fatalf("hot runtime store did not capture current budget: %+v", preview)
	}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"audit": map[string]any{"max_body_bytes": 2048}}, false)); err != nil {
		t.Fatal(err)
	}
	if m.cfg.Audit.CleanupBatchMaxRecords != 321 || m.cfg.Audit.CleanupBatchMaxBytes != 48<<20 {
		t.Fatal("old partial patch cleared budget")
	}
	payload, _, err := m.rulesRepo.Load()
	if err != nil {
		t.Fatal(err)
	}
	var state DynamicRulesState
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	if state.Settings == nil || state.Settings.Audit.CleanupBatchMaxRecords != 321 || state.Settings.Audit.CleanupBatchMaxBytes != 48<<20 {
		t.Fatal("SQLite did not persist budget")
	}
	m.Shutdown()
	request, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("audit:\n  cleanup_batch_max_records: 4999\n  cleanup_batch_max_bytes: 134217728\n")})
	if err := m.Configure(request); err != nil {
		t.Fatal(err)
	}
	if m.cfg.Audit.CleanupBatchMaxRecords != 321 || m.cfg.Audit.CleanupBatchMaxBytes != 48<<20 || m.cfg.Audit.MaxBodyBytes != 2048 {
		t.Fatalf("YAML seed overrode SQLite settings: %+v", m.cfg.Audit)
	}
}

func TestCleanupBudgetLegacySQLiteSettingsNormalizeBeforeValidation(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"audit": map[string]any{"max_records": 12345}}, false)); err != nil {
		t.Fatal(err)
	}
	payload, _, err := m.rulesRepo.Load()
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	oldAudit := state["settings"].(map[string]any)["audit"].(map[string]any)
	delete(oldAudit, "cleanup_batch_max_records")
	delete(oldAudit, "cleanup_batch_max_bytes")
	payload, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.rulesRepo.Save(payload); err != nil {
		t.Fatal(err)
	}
	m.Shutdown()
	request, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("audit:\n  max_records: 54321\n  cleanup_batch_max_records: 5000\n  cleanup_batch_max_bytes: 134217728\n")})
	if err := m.Configure(request); err != nil {
		t.Fatalf("legacy SQLite settings rejected: %v", err)
	}
	if m.cfg.Audit.CleanupBatchMaxRecords != 1000 || m.cfg.Audit.CleanupBatchMaxBytes != 32<<20 || m.cfg.Audit.MaxRecords != 12345 {
		t.Fatalf("legacy SQLite defaults or precedence broken: %+v", m.cfg.Audit)
	}
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{"audit": map[string]any{"max_body_bytes": 2048}}, false)); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupBudgetInvalidSQLiteDoesNotFallBackToSeed(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.SaveRuntimeSettings(settingsRequest(t, m, map[string]any{}, false)); err != nil {
		t.Fatal(err)
	}
	payload, _, err := m.rulesRepo.Load()
	if err != nil {
		t.Fatal(err)
	}
	var state DynamicRulesState
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	state.Settings.Audit.CleanupBatchMaxBytes = audit.MaxCleanupBatchBytes + 1
	payload, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.rulesRepo.Save(payload); err != nil {
		t.Fatal(err)
	}
	m.Shutdown()
	if err := m.Configure(nil); !errors.Is(err, ErrSettingsInvalid) {
		t.Fatalf("invalid SQLite budget fell back to seed: %v", err)
	}
}

func TestCleanupBudgetMergeKeepsSeedOnlyWithoutRuntimeSettings(t *testing.T) {
	isolateStateDirs(t)
	seed, err := ParseConfigYAML([]byte("audit:\n  cleanup_batch_max_records: 87\n  cleanup_batch_max_bytes: 50331648\n"))
	if err != nil {
		t.Fatal(err)
	}
	withoutSettings := MergeDynamicState(seed, &DynamicRulesState{Version: 1})
	if withoutSettings.Audit.CleanupBatchMaxRecords != 87 || withoutSettings.Audit.CleanupBatchMaxBytes != 48<<20 {
		t.Fatal("migration seed budget lost without SQLite settings")
	}
	settings := runtimeSettingsFromConfig(seed)
	settings.Audit.CleanupBatchMaxRecords, settings.Audit.CleanupBatchMaxBytes = 0, 0
	withLegacySettings := MergeDynamicState(seed, &DynamicRulesState{Version: 1, Settings: &settings})
	if withLegacySettings.Audit.CleanupBatchMaxRecords != audit.DefaultCleanupBatchRecords || withLegacySettings.Audit.CleanupBatchMaxBytes != audit.DefaultCleanupBatchBytes {
		t.Fatal("YAML seed overwrote legacy SQLite defaults")
	}
	if settings.Audit.CleanupBatchMaxRecords != 0 || settings.Audit.CleanupBatchMaxBytes != 0 {
		t.Fatal("merge mutated caller's runtime settings")
	}
}
