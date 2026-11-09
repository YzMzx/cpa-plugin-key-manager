package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

var errSettingsUnchanged = errors.New("runtime settings unchanged")

type settingsApplyFailure struct{}

func (*settingsApplyFailure) Error() string {
	return "settings saved but runtime application needs retry"
}

// GetRuntimeSettings never returns Config itself: credentials, key arrays, policy
// and price overrides are outside this deliberately small response surface.
func (m *Manager) GetRuntimeSettings() map[string]any {
	m.mu.RLock()
	cfg := m.cfg
	revision := uint64(0)
	if m.dynamicState != nil {
		revision = m.dynamicState.Revision
	}
	applyError := m.settingsApplyError
	m.mu.RUnlock()
	current := runtimeSettingsFromConfig(cfg)
	if parsed, err := url.Parse(current.Pricing.SyncURL); err == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		current.Pricing.SyncURL = parsed.String()
	} else {
		current.Pricing.SyncURL = ""
	}
	return map[string]any{
		"settings": current, "rules_revision": revision,
		"readonly": map[string]any{"bootstrap": map[string]any{"enabled": cfg.Enabled, "priority": cfg.Priority, "usage_db_file": cfg.Storage.UsageDBFile}, "needs_restart": []string{"enabled", "priority", "storage.usage_db_file"}, "management_credentials": "managed by CPA; never returned or changed here"},
		"capture":  map[string]any{"mode": "plaintext_json_without_media", "credentials_in_body_may_be_retained": true},
		"limits":   settingsLimits(), "apply_status": map[string]any{"ok": applyError == "", "error": applyError},
	}
}
func settingsLimits() map[string]any {
	return map[string]any{
		"audit":   map[string]any{"retention_days": []int{1, 90}, "max_records": []int{1, 100000}, "max_body_bytes": []int{256, 10485760}, "max_total_bytes": []int64{1 << 20, 1 << 30}},
		"storage": map[string]any{"flush_interval_seconds": []int{1, 3600}, "ledger_retention_days": []int{1, 3650}, "timezone": "IANA timezone", "pricing_cache_file_max_length": 4096},
		"pricing": map[string]any{"sync_interval_hours": []int{1, 720}, "http_timeout_seconds": []int{1, 300}, "sync_url_max_length": 2048, "schemes": []string{"http", "https"}},
	}
}

// SaveRuntimeSettings requires a body-level compare-and-swap token. It accepts
// partial groups/fields but never silently ignores unknown, duplicate or null fields.
func (m *Manager) SaveRuntimeSettings(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 32768 || !settingsUniqueObject(raw) {
		return nil, ErrSettingsInvalid
	}
	var req struct {
		Settings         json.RawMessage `json:"settings"`
		ExpectedRevision *uint64         `json:"expected_revision"`
		AckPrune         bool            `json:"ack_prune"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil {
		return nil, ErrSettingsInvalid
	}
	if req.ExpectedRevision == nil {
		return nil, ErrSettingsRevision
	}
	if len(req.Settings) == 0 || bytes.Equal(bytes.TrimSpace(req.Settings), []byte("null")) {
		return nil, ErrSettingsInvalid
	}
	expected := *req.ExpectedRevision
	err := m.mutateRules(ruleMutation{op: "runtime settings"}, func(state *DynamicRulesState) error {
		if state.Revision != expected {
			return ErrSettingsRevision
		}
		current := runtimeSettingsFromConfig(m.cfg)
		next := current
		patch := json.NewDecoder(bytes.NewReader(req.Settings))
		patch.DisallowUnknownFields()
		if patch.Decode(&next) != nil {
			return ErrSettingsInvalid
		}
		if err := validateRuntimeSettings(&next); err != nil {
			return err
		}
		if settingsCacheConflicts(next, m.cfg) {
			return ErrSettingsInvalid
		}
		if settingsMayPrune(current, next) && !req.AckPrune {
			return ErrSettingsPruneConfirmation
		}
		if reflect.DeepEqual(next, current) && state.Settings != nil {
			if m.settingsApplyError != "" {
				if err := m.applyRuntimeSettings(m.cfg); err != nil {
					return err
				}
			}
			return errSettingsUnchanged
		}
		state.Settings = &next
		return nil
	})
	if err != nil && !errors.Is(err, errSettingsUnchanged) {
		var applied *settingsApplyFailure
		if !errors.As(err, &applied) {
			if errors.Is(err, ErrSettingsRevision) || errors.Is(err, ErrSettingsInvalid) || errors.Is(err, ErrSettingsPersistence) || errors.Is(err, ErrSettingsPruneConfirmation) {
				return nil, err
			}
			return nil, ErrSettingsPersistence
		}
	}
	result := m.GetRuntimeSettings()
	result["ok"] = true
	m.mu.RLock()
	pending := m.settingsApplyError
	m.mu.RUnlock()
	if pending != "" {
		result["warning"] = "设置已保存，但热应用未完成；请重试保存或重新加载插件"
	}
	return result, nil
}

func validateRuntimeSettings(settings *RuntimeSettings) error {
	a := settings.Audit
	enabled := a.Enabled
	if err := (AuditConfig{Enabled: &enabled, RetentionDays: a.RetentionDays, MaxRecords: a.MaxRecords, MaxBodyBytes: a.MaxBodyBytes, MaxTotalBytes: a.MaxTotalBytes}).validate(); err != nil {
		return ErrSettingsInvalid
	}
	s := &settings.Storage
	if s.FlushIntervalSeconds < 1 || s.FlushIntervalSeconds > 3600 || s.LedgerRetentionDays < 1 || s.LedgerRetentionDays > 3650 {
		return ErrSettingsInvalid
	}
	if len(s.Timezone) > 128 || strings.TrimSpace(s.Timezone) != s.Timezone {
		return ErrSettingsInvalid
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil {
		return ErrSettingsInvalid
	}
	if strings.TrimSpace(s.PricingCacheFile) == "" || strings.Contains(s.PricingCacheFile, "://") || len(s.PricingCacheFile) > 4096 || strings.IndexFunc(s.PricingCacheFile, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return ErrSettingsInvalid
	}
	s.PricingCacheFile = filepath.Clean(ResolveStoragePath(strings.TrimSpace(s.PricingCacheFile)))
	p := &settings.Pricing
	if p.SyncIntervalHours < 1 || p.SyncIntervalHours > 720 || p.HTTPTimeoutSeconds < 1 || p.HTTPTimeoutSeconds > 300 || len(p.SyncURL) > 2048 {
		return ErrSettingsInvalid
	}
	parsed, err := url.Parse(p.SyncURL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return ErrSettingsInvalid
	}
	if strings.IndexFunc(p.SyncURL, unicode.IsControl) >= 0 {
		return ErrSettingsInvalid
	}
	if parsed.Port() != "" { // url.Parse validates syntax, not the permitted port range.
		var port int
		if _, err := fmt.Sscanf(parsed.Port(), "%d", &port); err != nil || port < 1 || port > 65535 {
			return ErrSettingsInvalid
		}
	}
	return nil
}

// settingsUniqueObject bounds nesting and rejects null/duplicate keys before
// struct decoding so a UI never appears to save a field that was ignored.
func settingsUniqueObject(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int, bool) bool
	walk = func(depth int, root bool) bool {
		if depth > 8 {
			return false
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return false
		}
		delimiter, isDelimiter := token.(json.Delim)
		if root && (!isDelimiter || delimiter != '{') {
			return false
		}
		if !isDelimiter {
			return true
		}
		if delimiter != '{' {
			return false
		}
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[strings.ToLower(key)] {
				return false
			}
			seen[strings.ToLower(key)] = true
			if !walk(depth+1, false) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	}
	if !walk(0, true) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func (m *Manager) applyRuntimeSettings(cfg Config) error {
	if err := m.usageStore.ConfigureSQLite(cfg.Storage.UsageDBFile, time.Duration(cfg.Storage.FlushIntervalSeconds)*time.Second); err != nil {
		m.mu.Lock()
		m.settingsApplyError = "usage flush scheduling failed; settings remain saved"
		m.mu.Unlock()
		return &settingsApplyFailure{}
	}
	m.usageStore.SetLedgerRetention(cfg.Storage.LedgerRetentionDays)
	m.configureAudit(cfg.Audit)
	if store, _ := m.auditSnapshot(); store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := store.Prune(ctx, time.Now())
		cancel()
		if err != nil {
			m.mu.Lock()
			m.settingsApplyError = "audit retention application failed; settings remain saved"
			m.mu.Unlock()
			return &settingsApplyFailure{}
		}
	}
	syncKey := fmt.Sprintf("%s|%s|%d|%d", cfg.Pricing.SyncURL, cfg.Storage.PricingCacheFile, cfg.Pricing.SyncIntervalHours, cfg.Pricing.HTTPTimeoutSeconds)
	m.mu.RLock()
	oldKey := m.lastSyncKey
	m.mu.RUnlock()
	if syncKey != oldKey {
		m.pricingSyncer.ConfigureAndStart(pricing.SyncConfig{SyncURL: cfg.Pricing.SyncURL, CacheFile: cfg.Storage.PricingCacheFile, SyncInterval: time.Duration(cfg.Pricing.SyncIntervalHours) * time.Hour, HTTPTimeout: time.Duration(cfg.Pricing.HTTPTimeoutSeconds) * time.Second})
	}
	m.mu.Lock()
	m.lastSyncKey = syncKey
	m.settingsApplyError = ""
	m.mu.Unlock()
	return nil
}

func settingsMayPrune(old, next RuntimeSettings) bool {
	return next.Audit.RetentionDays < old.Audit.RetentionDays || next.Audit.MaxRecords < old.Audit.MaxRecords || next.Audit.MaxTotalBytes < old.Audit.MaxTotalBytes || next.Storage.LedgerRetentionDays < old.Storage.LedgerRetentionDays
}

func settingsCacheConflicts(settings RuntimeSettings, cfg Config) bool {
	path := filepath.Clean(settings.Storage.PricingCacheFile)
	for _, protected := range []string{cfg.Storage.UsageDBFile, cfg.Storage.UsageDBFile + "-wal", cfg.Storage.UsageDBFile + "-shm", cfg.Storage.UsageDBFile + ".lock", FindHostConfigFile("")} {
		if protected != "" && settingsSamePath(path, protected) {
			return true
		}
	}
	return false
}
