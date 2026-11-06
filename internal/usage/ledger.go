package usage

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	// Embed the IANA timezone database so bucket labels stay correct inside slim
	// container images that do not ship /usr/share/zoneinfo.
	_ "time/tzdata"
)

// LedgerEntry is one aggregated slice of billable usage. Entries are keyed by
// (hour, api key, account, billed model, source channel) so the overview can be
// filtered and re-bucketed without keeping every raw request in memory.
//
// Model is always the model the request was billed for (the client-requested /
// catalog model). ServedModel only records what the upstream reported, so an
// upstream substitution never changes the billed model.
type LedgerEntry struct {
	Hour        int64  `json:"hour"` // unix seconds, truncated to the hour
	APIKey      string `json:"api_key,omitempty"`
	KeyName     string `json:"key_name,omitempty"`
	Account     string `json:"account,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Model       string `json:"model"`
	ServedModel string `json:"served_model,omitempty"`
	Source      string `json:"source,omitempty"`

	Requests         int64 `json:"requests"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
	CostNanoUSD      int64 `json:"cost_nano_usd"`
}

const ledgerKeySeparator = "\x1f"

// ledgerEntryKey builds the in-memory key of one aggregated slice.
func ledgerEntryKey(hour int64, apiKey, account, model, source string) string {
	return fmt.Sprintf("%d%s%s%s%s%s%s%s%s", hour,
		ledgerKeySeparator, apiKey,
		ledgerKeySeparator, account,
		ledgerKeySeparator, model,
		ledgerKeySeparator, source)
}

// The ledger is indexed twice: by its full key (s.ledger) and by hour
// (s.ledgerByHour), so QueryLedger only touches the hours inside its window instead
// of scanning the whole retention period. Every mutation goes through these helpers
// to keep both views consistent.

func (s *Store) ledgerPutLocked(key string, entry *LedgerEntry) {
	if s.ledger == nil {
		s.ledger = make(map[string]*LedgerEntry)
	}
	s.ledger[key] = entry
	if s.ledgerByHour == nil {
		s.ledgerByHour = make(map[int64]map[string]*LedgerEntry)
	}
	bucket := s.ledgerByHour[entry.Hour]
	if bucket == nil {
		bucket = make(map[string]*LedgerEntry)
		s.ledgerByHour[entry.Hour] = bucket
	}
	bucket[key] = entry
}

func (s *Store) ledgerDeleteLocked(key string) {
	entry := s.ledger[key]
	delete(s.ledger, key)
	if entry == nil || s.ledgerByHour == nil {
		return
	}
	if bucket := s.ledgerByHour[entry.Hour]; bucket != nil {
		delete(bucket, key)
		if len(bucket) == 0 {
			delete(s.ledgerByHour, entry.Hour)
		}
	}
}

func (s *Store) ledgerResetLocked() {
	s.ledger = make(map[string]*LedgerEntry)
	s.ledgerByHour = make(map[int64]map[string]*LedgerEntry)
}

// tzCache memoises time.LoadLocation, which reads the embedded tz database.
var tzCache sync.Map

func loadLocationCached(name string) *time.Location {
	name = strings.TrimSpace(name)
	if name == "" {
		return time.UTC
	}
	if cached, ok := tzCache.Load(name); ok {
		return cached.(*time.Location)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	tzCache.Store(name, loc)
	return loc
}

// applyLedgerLocked accumulates one slice of usage into the hourly ledger and returns
// the applied stamp, so a later failure of the same request can be rolled back.
func (s *Store) applyLedgerLocked(at time.Time, apiKey, keyName, account, provider, model, served, source string,
	requests, in, out, read, write, total, costNano int64) ledgerStamp {
	stamp := ledgerStamp{
		apiKey: apiKey, account: account, model: model, source: source,
		requests: requests, in: in, out: out, read: read, write: write, total: total, cost: costNano,
	}
	if s.ledger == nil || strings.TrimSpace(model) == "" {
		return stamp
	}
	hour := at.UTC().Truncate(time.Hour).Unix()
	stamp.hour = hour
	key := ledgerEntryKey(hour, apiKey, account, model, source)
	entry := s.ledger[key]
	if entry == nil {
		entry = &LedgerEntry{
			Hour:     hour,
			APIKey:   apiKey,
			KeyName:  keyName,
			Account:  account,
			Provider: provider,
			Model:    model,
			Source:   source,
		}
		s.ledgerPutLocked(key, entry)
	}
	if entry.ServedModel == "" && served != "" && !strings.EqualFold(served, model) {
		entry.ServedModel = served
	}
	entry.Requests += requests
	entry.InputTokens += in
	entry.OutputTokens += out
	entry.CacheReadTokens += read
	entry.CacheWriteTokens += write
	entry.TotalTokens += total
	entry.CostNanoUSD += costNano
	s.markLedgerDirtyLocked(key)
	return stamp
}

// rollbackLedgerStampsLocked removes everything a failed request contributed to the ledger.
func (s *Store) rollbackLedgerStampsLocked(tr *TrackedRequest) {
	if tr == nil || len(tr.ledgerStamps) == 0 {
		return
	}
	for _, stamp := range tr.ledgerStamps {
		key := ledgerEntryKey(stamp.hour, stamp.apiKey, stamp.account, stamp.model, stamp.source)
		entry := s.ledger[key]
		if entry == nil {
			continue
		}
		entry.Requests -= stamp.requests
		entry.InputTokens -= stamp.in
		entry.OutputTokens -= stamp.out
		entry.CacheReadTokens -= stamp.read
		entry.CacheWriteTokens -= stamp.write
		entry.TotalTokens -= stamp.total
		entry.CostNanoUSD -= stamp.cost
		if entry.Requests <= 0 && entry.TotalTokens <= 0 && entry.CostNanoUSD <= 0 {
			s.ledgerDeleteLocked(key)
			s.deletedLedger[ledgerRef{
				hour: stamp.hour, apiKey: stamp.apiKey, account: stamp.account,
				model: stamp.model, source: stamp.source,
			}] = struct{}{}
			continue
		}
		s.markLedgerDirtyLocked(key)
	}
	tr.ledgerStamps = nil
}

// pruneLedgerLocked drops entries older than the retention window.
func (s *Store) pruneLedgerLocked(now time.Time) {
	if len(s.ledger) == 0 {
		return
	}
	retention := s.ledgerRetention
	if retention <= 0 {
		retention = 90 * 24 * time.Hour
	}
	cutoff := now.UTC().Add(-retention).Truncate(time.Hour).Unix()
	for key, entry := range s.ledger {
		if entry == nil || entry.Hour < cutoff {
			s.ledgerDeleteLocked(key)
		}
	}
	if s.ledgerPruneBefore < cutoff {
		s.ledgerPruneBefore = cutoff
	}
}

// SetLedgerRetention configures how long hourly ledger slices are kept.
func (s *Store) SetLedgerRetention(days int) {
	s.mu.Lock()
	if days <= 0 {
		days = 90
	}
	s.ledgerRetention = time.Duration(days) * 24 * time.Hour
	s.mu.Unlock()
}

// LedgerStatus summarizes the state of the local ledger for the overview page.
type LedgerStatus struct {
	Enabled       bool   `json:"enabled"`
	Entries       int    `json:"entries"`
	RetentionDays int    `json:"retention_days"`
	OldestAt      string `json:"oldest_at,omitempty"`
	NewestAt      string `json:"newest_at,omitempty"`
	Storage       string `json:"storage,omitempty"`
}

// LedgerStatus reports ledger health and coverage.
func (s *Store) LedgerStatus() LedgerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := LedgerStatus{
		Enabled:       true,
		Entries:       len(s.ledger),
		RetentionDays: int(s.ledgerRetention.Hours() / 24),
		Storage:       s.sqlitePathLocked(),
	}
	if status.RetentionDays <= 0 {
		status.RetentionDays = 90
	}
	var oldest, newest int64
	for _, entry := range s.ledger {
		if entry == nil {
			continue
		}
		if oldest == 0 || entry.Hour < oldest {
			oldest = entry.Hour
		}
		if entry.Hour > newest {
			newest = entry.Hour
		}
	}
	if oldest > 0 {
		status.OldestAt = time.Unix(oldest, 0).UTC().Format(time.RFC3339)
	}
	if newest > 0 {
		status.NewestAt = time.Unix(newest, 0).UTC().Format(time.RFC3339)
	}
	return status
}

// LedgerQuery describes the overview filters.
type LedgerQuery struct {
	From        time.Time
	To          time.Time
	Granularity string // hour | day | month
	Key         string // substring match on api key or key name
	Account     string // substring match on account id/provider
	Model       string // exact billed model
	Source      string // exact source channel
	Timezone    string // IANA name; buckets are rendered in this zone
}

// LedgerBucket is one point of the trend series.
type LedgerBucket struct {
	Label            string  `json:"label"`
	Start            string  `json:"start"`
	Requests         int64   `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostNanoUSD      int64   `json:"cost_nano_usd"`
	CacheHitRate     float64 `json:"cache_hit_rate"`
}

// LedgerModelRow is one slice of the model distribution chart.
type LedgerModelRow struct {
	Model            string  `json:"model"`
	Requests         int64   `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostNanoUSD      int64   `json:"cost_nano_usd"`
	Share            float64 `json:"share"`
}

// LedgerKeyRow aggregates one API key and carries its per-model breakdown.
type LedgerKeyRow struct {
	APIKey           string           `json:"api_key"`
	KeyName          string           `json:"key_name,omitempty"`
	Requests         int64            `json:"requests"`
	InputTokens      int64            `json:"input_tokens"`
	OutputTokens     int64            `json:"output_tokens"`
	CacheReadTokens  int64            `json:"cache_read_tokens"`
	CacheWriteTokens int64            `json:"cache_write_tokens"`
	TotalTokens      int64            `json:"total_tokens"`
	CostNanoUSD      int64            `json:"cost_nano_usd"`
	Share            float64          `json:"share"`
	Models           []LedgerModelRow `json:"models"`
}

// LedgerResult is the full payload returned to the overview tab.
type LedgerResult struct {
	From             string           `json:"from"`
	To               string           `json:"to"`
	Timezone         string           `json:"timezone"`
	Granularity      string           `json:"granularity"`
	Requests         int64            `json:"requests"`
	InputTokens      int64            `json:"input_tokens"`
	OutputTokens     int64            `json:"output_tokens"`
	CacheReadTokens  int64            `json:"cache_read_tokens"`
	CacheWriteTokens int64            `json:"cache_write_tokens"`
	TotalTokens      int64            `json:"total_tokens"`
	CostNanoUSD      int64            `json:"cost_nano_usd"`
	ModelCount       int              `json:"model_count"`
	ActiveDays       int              `json:"active_days"`
	KeysTotal        int              `json:"keys_total"`
	KeysAvailable    int              `json:"keys_available"`
	Series           []LedgerBucket   `json:"series"`
	Models           []LedgerModelRow `json:"models"`
	KeyRows          []LedgerKeyRow   `json:"key_rows"`
	UsedModels       []string         `json:"used_models"`
	UsedSources      []string         `json:"used_sources"`
	Status           LedgerStatus     `json:"status"`
}

func ledgerGranularity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "hour", "小时", "时":
		return "hour"
	case "month", "月":
		return "month"
	case "day", "日", "天":
		return "day"
	default:
		return "day"
	}
}

// bucketLabel renders the bucket start in the requested timezone.
func bucketLabel(t time.Time, granularity string, loc *time.Location) (string, string) {
	local := t.In(loc)
	switch granularity {
	case "hour":
		return local.Format("01-02 15:00"), local.Format(time.RFC3339)
	case "month":
		return local.Format("2006-01"), local.Format("2006-01-02")
	default:
		return local.Format("2006-01-02"), local.Format("2006-01-02")
	}
}

// QueryLedger aggregates the retained ledger according to the query filters.
func (s *Store) QueryLedger(q LedgerQuery) LedgerResult {
	loc := loadLocationCached(q.Timezone)
	granularity := ledgerGranularity(q.Granularity)
	from := q.From.UTC()
	to := q.To.UTC()
	if from.IsZero() || to.IsZero() || !to.After(from) {
		to = time.Now().UTC()
		from = to.Add(-24 * time.Hour)
	}

	s.mu.Lock()
	// Walk only the hours inside the window via the hour index instead of scanning
	// the whole retention period.
	fromHour := from.Truncate(time.Hour).Unix()
	toUnix := to.Unix()
	entries := make([]LedgerEntry, 0, 256)
	if span := (toUnix - fromHour) / 3600; span >= 0 && span <= int64(len(s.ledgerByHour)) {
		for hour := fromHour; hour <= toUnix; hour += 3600 {
			for _, entry := range s.ledgerByHour[hour] {
				if entry != nil {
					entries = append(entries, *entry)
				}
			}
		}
	} else {
		// The window is wider than the number of populated hours: iterating the
		// populated buckets is cheaper than stepping through empty hours.
		for hour, bucket := range s.ledgerByHour {
			if hour < fromHour || hour > toUnix {
				continue
			}
			for _, entry := range bucket {
				if entry != nil {
					entries = append(entries, *entry)
				}
			}
		}
	}
	keysTotal := 0
	keysAvailable := 0
	for _, ks := range s.keys {
		if ks == nil {
			continue
		}
		keysTotal++
		if ks.Enabled == nil || *ks.Enabled {
			keysAvailable++
		}
	}
	status := LedgerStatus{Enabled: true, Entries: len(s.ledger), Storage: s.sqlitePathLocked()}
	if status.RetentionDays = int(s.ledgerRetention.Hours() / 24); status.RetentionDays <= 0 {
		status.RetentionDays = 90
	}
	s.mu.Unlock()

	keyFilter := strings.ToLower(strings.TrimSpace(q.Key))
	accountFilter := strings.ToLower(strings.TrimSpace(q.Account))
	modelFilter := strings.ToLower(strings.TrimSpace(q.Model))
	sourceFilter := strings.ToLower(strings.TrimSpace(q.Source))

	result := LedgerResult{
		From:          from.In(loc).Format(time.RFC3339),
		To:            to.In(loc).Format(time.RFC3339),
		Timezone:      loc.String(),
		Granularity:   granularity,
		KeysTotal:     keysTotal,
		KeysAvailable: keysAvailable,
		Series:        []LedgerBucket{},
		Models:        []LedgerModelRow{},
		Status:        status,
	}

	buckets := make(map[string]*LedgerBucket)
	modelAgg := make(map[string]*LedgerModelRow)
	keyAgg := make(map[string]*LedgerKeyRow)
	keyModelAgg := make(map[string]map[string]*LedgerModelRow)
	activeDays := make(map[string]struct{})
	usedModels := make(map[string]struct{})
	usedSources := make(map[string]struct{})

	for _, entry := range entries {
		at := time.Unix(entry.Hour, 0).UTC()
		if at.Before(from) || at.After(to) {
			continue
		}
		if keyFilter != "" &&
			!strings.Contains(strings.ToLower(entry.APIKey), keyFilter) &&
			!strings.Contains(strings.ToLower(entry.KeyName), keyFilter) {
			continue
		}
		if accountFilter != "" &&
			!strings.Contains(strings.ToLower(entry.Account), accountFilter) &&
			!strings.Contains(strings.ToLower(entry.Provider), accountFilter) {
			continue
		}
		if modelFilter != "" && !strings.EqualFold(entry.Model, modelFilter) {
			continue
		}
		if sourceFilter != "" && !strings.EqualFold(entry.Source, sourceFilter) {
			continue
		}

		result.Requests += entry.Requests
		result.InputTokens += entry.InputTokens
		result.OutputTokens += entry.OutputTokens
		result.CacheReadTokens += entry.CacheReadTokens
		result.CacheWriteTokens += entry.CacheWriteTokens
		result.TotalTokens += entry.TotalTokens
		result.CostNanoUSD += entry.CostNanoUSD
		if entry.Model != "" {
			usedModels[entry.Model] = struct{}{}
		}
		if entry.Source != "" {
			usedSources[entry.Source] = struct{}{}
		}
		activeDays[at.In(loc).Format("2006-01-02")] = struct{}{}

		label, start := bucketLabel(at, granularity, loc)
		bucket := buckets[label]
		if bucket == nil {
			bucket = &LedgerBucket{Label: label, Start: start}
			buckets[label] = bucket
		}
		bucket.Requests += entry.Requests
		bucket.InputTokens += entry.InputTokens
		bucket.OutputTokens += entry.OutputTokens
		bucket.CacheReadTokens += entry.CacheReadTokens
		bucket.CacheWriteTokens += entry.CacheWriteTokens
		bucket.TotalTokens += entry.TotalTokens
		bucket.CostNanoUSD += entry.CostNanoUSD

		row := modelAgg[entry.Model]
		if row == nil {
			row = &LedgerModelRow{Model: entry.Model}
			modelAgg[entry.Model] = row
		}
		row.Requests += entry.Requests
		row.InputTokens += entry.InputTokens
		row.OutputTokens += entry.OutputTokens
		row.CacheReadTokens += entry.CacheReadTokens
		row.CacheWriteTokens += entry.CacheWriteTokens
		row.TotalTokens += entry.TotalTokens
		row.CostNanoUSD += entry.CostNanoUSD

		// Per-key aggregation with its own per-model breakdown.
		keyRow := keyAgg[entry.APIKey]
		if keyRow == nil {
			keyRow = &LedgerKeyRow{APIKey: entry.APIKey, KeyName: entry.KeyName}
			keyAgg[entry.APIKey] = keyRow
		}
		if keyRow.KeyName == "" && entry.KeyName != "" {
			keyRow.KeyName = entry.KeyName
		}
		keyRow.Requests += entry.Requests
		keyRow.InputTokens += entry.InputTokens
		keyRow.OutputTokens += entry.OutputTokens
		keyRow.CacheReadTokens += entry.CacheReadTokens
		keyRow.CacheWriteTokens += entry.CacheWriteTokens
		keyRow.TotalTokens += entry.TotalTokens
		keyRow.CostNanoUSD += entry.CostNanoUSD

		perModel := keyModelAgg[entry.APIKey]
		if perModel == nil {
			perModel = make(map[string]*LedgerModelRow)
			keyModelAgg[entry.APIKey] = perModel
		}
		km := perModel[entry.Model]
		if km == nil {
			km = &LedgerModelRow{Model: entry.Model}
			perModel[entry.Model] = km
		}
		km.Requests += entry.Requests
		km.InputTokens += entry.InputTokens
		km.OutputTokens += entry.OutputTokens
		km.CacheReadTokens += entry.CacheReadTokens
		km.CacheWriteTokens += entry.CacheWriteTokens
		km.TotalTokens += entry.TotalTokens
		km.CostNanoUSD += entry.CostNanoUSD
	}

	labels := make([]string, 0, len(buckets))
	for label := range buckets {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		bucket := buckets[label]
		denominator := bucket.InputTokens + bucket.CacheReadTokens
		if denominator > 0 {
			bucket.CacheHitRate = float64(bucket.CacheReadTokens) / float64(denominator) * 100
		}
		result.Series = append(result.Series, *bucket)
	}

	rows := make([]LedgerModelRow, 0, len(modelAgg))
	for _, row := range modelAgg {
		rows = append(rows, *row)
	}
	rows = fillModelShare(rows, result.TotalTokens)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalTokens != rows[j].TotalTokens {
			return rows[i].TotalTokens > rows[j].TotalTokens
		}
		return rows[i].Model < rows[j].Model
	})
	result.Models = rows
	result.ModelCount = len(rows)
	result.ActiveDays = len(activeDays)

	// Per-key rows with nested per-model breakdown, largest consumers first.
	keyRows := make([]LedgerKeyRow, 0, len(keyAgg))
	for apiKey, keyRow := range keyAgg {
		if keyRow == nil {
			continue
		}
		if keyRow.TotalTokens > 0 {
			keyRow.Share = float64(keyRow.TotalTokens) / float64(result.TotalTokens) * 100
		}
		perModel := make([]LedgerModelRow, 0, len(keyModelAgg[apiKey]))
		for _, km := range keyModelAgg[apiKey] {
			if km == nil {
				continue
			}
			km.Share = 0
			if keyRow.TotalTokens > 0 {
				km.Share = float64(km.TotalTokens) / float64(keyRow.TotalTokens) * 100
			}
			perModel = append(perModel, *km)
		}
		sort.Slice(perModel, func(i, j int) bool {
			if perModel[i].CostNanoUSD != perModel[j].CostNanoUSD {
				return perModel[i].CostNanoUSD > perModel[j].CostNanoUSD
			}
			if perModel[i].TotalTokens != perModel[j].TotalTokens {
				return perModel[i].TotalTokens > perModel[j].TotalTokens
			}
			return perModel[i].Model < perModel[j].Model
		})
		keyRow.Models = perModel
		keyRows = append(keyRows, *keyRow)
	}
	// Highest cost first: the overview list is read as a spend ranking.
	sort.Slice(keyRows, func(i, j int) bool {
		if keyRows[i].CostNanoUSD != keyRows[j].CostNanoUSD {
			return keyRows[i].CostNanoUSD > keyRows[j].CostNanoUSD
		}
		if keyRows[i].TotalTokens != keyRows[j].TotalTokens {
			return keyRows[i].TotalTokens > keyRows[j].TotalTokens
		}
		return keyRows[i].APIKey < keyRows[j].APIKey
	})
	result.KeyRows = keyRows

	for model := range usedModels {
		result.UsedModels = append(result.UsedModels, model)
	}
	sort.Strings(result.UsedModels)
	for source := range usedSources {
		result.UsedSources = append(result.UsedSources, source)
	}
	sort.Strings(result.UsedSources)
	return result
}

// fillModelShare computes the token share of each model row.
func fillModelShare(rows []LedgerModelRow, total int64) []LedgerModelRow {
	if total <= 0 {
		for i := range rows {
			rows[i].Share = 0
		}
		return rows
	}
	for i := range rows {
		rows[i].Share = float64(rows[i].TotalTokens) / float64(total) * 100
	}
	return rows
}
