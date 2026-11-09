package plugin

type settingsError string

func (e settingsError) Error() string { return string(e) }
func (e settingsError) SettingsCode() string {
	switch e {
	case ErrSettingsRevision:
		return "revision"
	case ErrSettingsPruneConfirmation:
		return "ack_prune"
	case ErrSettingsInvalid:
		return "invalid"
	default:
		return "persistence"
	}
}

const (
	ErrSettingsRevision          settingsError = "settings revision is required or stale"
	ErrSettingsInvalid           settingsError = "invalid runtime settings"
	ErrSettingsPersistence       settingsError = "runtime settings could not be persisted"
	ErrSettingsPruneConfirmation settingsError = "lower retention or capacity requires ack_prune=true"
)

// RuntimeSettings is the complete SQLite-owned hot-reload surface. Bootstrap
// identity, credentials, key rules and custom prices deliberately do not appear.
type RuntimeSettings struct {
	Audit   RuntimeAuditSettings   `json:"audit"`
	Storage RuntimeStorageSettings `json:"storage"`
	Pricing RuntimePricingSettings `json:"pricing"`
}
type RuntimeAuditSettings struct {
	Enabled       bool  `json:"enabled"`
	RetentionDays int   `json:"retention_days"`
	MaxRecords    int   `json:"max_records"`
	MaxBodyBytes  int   `json:"max_body_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
}
type RuntimeStorageSettings struct {
	FlushIntervalSeconds int    `json:"flush_interval_seconds"`
	LedgerRetentionDays  int    `json:"ledger_retention_days"`
	Timezone             string `json:"timezone"`
	PricingCacheFile     string `json:"pricing_cache_file"`
}
type RuntimePricingSettings struct {
	SyncURL                string `json:"sync_url"`
	SyncIntervalHours      int    `json:"sync_interval_hours"`
	HTTPTimeoutSeconds     int    `json:"http_timeout_seconds"`
	AutoInjectIncludeUsage bool   `json:"auto_inject_include_usage"`
}

func runtimeSettingsFromConfig(cfg Config) RuntimeSettings {
	return RuntimeSettings{
		Audit:   RuntimeAuditSettings{Enabled: cfg.Audit.isEnabled(), RetentionDays: cfg.Audit.RetentionDays, MaxRecords: cfg.Audit.MaxRecords, MaxBodyBytes: cfg.Audit.MaxBodyBytes, MaxTotalBytes: cfg.Audit.MaxTotalBytes},
		Storage: RuntimeStorageSettings{FlushIntervalSeconds: cfg.Storage.FlushIntervalSeconds, LedgerRetentionDays: cfg.Storage.LedgerRetentionDays, Timezone: cfg.Storage.Timezone, PricingCacheFile: cfg.Storage.PricingCacheFile},
		Pricing: RuntimePricingSettings{SyncURL: cfg.Pricing.SyncURL, SyncIntervalHours: cfg.Pricing.SyncIntervalHours, HTTPTimeoutSeconds: cfg.Pricing.HTTPTimeoutSeconds, AutoInjectIncludeUsage: cfg.ShouldAutoInjectIncludeUsage()},
	}
}
func applySettingsConfig(cfg *Config, settings *RuntimeSettings) {
	if settings == nil {
		return
	}
	enabled, inject := settings.Audit.Enabled, settings.Pricing.AutoInjectIncludeUsage
	cfg.Audit = AuditConfig{Enabled: &enabled, RetentionDays: settings.Audit.RetentionDays, MaxRecords: settings.Audit.MaxRecords, MaxBodyBytes: settings.Audit.MaxBodyBytes, MaxTotalBytes: settings.Audit.MaxTotalBytes}
	cfg.Storage.FlushIntervalSeconds = settings.Storage.FlushIntervalSeconds
	cfg.Storage.LedgerRetentionDays = settings.Storage.LedgerRetentionDays
	cfg.Storage.Timezone = settings.Storage.Timezone
	cfg.Storage.PricingCacheFile = settings.Storage.PricingCacheFile
	cfg.Pricing.SyncURL = settings.Pricing.SyncURL
	cfg.Pricing.SyncIntervalHours = settings.Pricing.SyncIntervalHours
	cfg.Pricing.HTTPTimeoutSeconds = settings.Pricing.HTTPTimeoutSeconds
	cfg.Pricing.AutoInjectIncludeUsage = &inject
}
