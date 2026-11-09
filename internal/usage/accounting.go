package usage

import (
	"math"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

// reconcileTrackerDeltaLocked replaces only this request's contribution. A late
// served model, credential or terminal outcome must never move a shared bucket.
func (s *Store) reconcileTrackerDeltaLocked(tr *TrackedRequest) {
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return
	}
	if tr.ExtractedUsage.Invalid || tr.BilledUsage.Invalid {
		s.lastAccountingError = "usage token normalization exceeds supported range"
		return
	}
	apiKey := normalizeAPIKey(tr.APIKey)
	requested := requestedModelOf(tr)
	if isInvalidKeyID(apiKey) || requested == "" {
		return
	}
	served := servedModelOf(tr, requested)
	target := MergeMaxUsage(tr.BilledUsage, tr.ExtractedUsage)
	total, ok := checkedTokenSum(target.UncachedInputTokens, target.OutputTokens, target.CacheReadTokens, target.CacheWriteTokens)
	if !ok {
		s.lastAccountingError = "usage token total exceeds supported range"
		return
	}
	price, found := tr.billedPrice, tr.billedPriceFound
	if !found {
		price, found = s.pricing.Lookup(requested, served)
	}
	cost, err := pricing.CalculateCostNanoUSD(target.UncachedInputTokens, target.OutputTokens, target.CacheReadTokens, target.CacheWriteTokens, price)
	if err != nil {
		s.lastAccountingError = "usage cost calculation failed: " + err.Error()
		return
	}
	next := ModelStats{RequestedModel: requested, ServedModel: served, Requests: 1, InputTokens: target.UncachedInputTokens, OutputTokens: target.OutputTokens, ReasoningTokens: target.ReasoningTokens, CacheReadTokens: target.CacheReadTokens, CacheWriteTokens: target.CacheWriteTokens, TotalTokens: total, CostNanoUSD: cost, UnitPricePer1M: price, LastUsedAt: time.Now().UTC().Format(time.RFC3339)}
	if tr.Failed {
		next.FailedRequests = 1
	} else {
		next.SuccessRequests = 1
	}
	ks := s.getOrCreateKeyStatsLocked(apiKey, tr.KeyName)
	if !canReplaceKeyContribution(ks, tr.billedStats, next) {
		s.lastAccountingError = "usage aggregate exceeds supported range"
		return
	}
	acct := s.getOrCreateAccountStatsLocked(tr)
	accountKey := accountBucketKey(tr.Provider, tr.AuthID, tr.AuthIndex)
	if acct != nil && !canReplaceAccountContribution(acct, func() ModelStats {
		if accountKey == tr.billedAccountKey {
			return tr.billedStats
		}
		return ModelStats{}
	}(), next) {
		s.lastAccountingError = "account usage aggregate exceeds supported range"
		return
	}
	key := tupleKey(requested, served)
	old := tr.billedStats
	oldTuple := ModelStats{}
	if key == tr.BilledKey {
		oldTuple = old
	}
	if !canReplaceModelContribution(ks.Models[key], oldTuple, next) {
		s.lastAccountingError = "model usage aggregate exceeds supported range"
		return
	}
	if acct != nil {
		prior := ModelStats{}
		if key == tr.BilledKey && accountKey == tr.billedAccountKey {
			prior = old
		}
		if !canReplaceModelContribution(acct.Models[key], prior, next) {
			s.lastAccountingError = "account model aggregate exceeds supported range"
			return
		}
	}
	if !s.canReplaceLedgerContributionLocked(tr, apiKey, requested, acct, next) {
		s.lastAccountingError = "ledger usage aggregate exceeds supported range"
		return
	}
	if old.Requests > 0 {
		replaceTupleContribution(ks.Models, tr.BilledKey, old, ModelStats{})
		applyKeyContribution(ks, old, -1)
		if previous := s.accounts[tr.billedAccountKey]; previous != nil {
			replaceTupleContribution(previous.Models, tr.BilledKey, old, ModelStats{})
			applyAccountContribution(previous, old, -1)
			s.dirtyAccounts[tr.billedAccountKey] = struct{}{}
		}
	}
	if ks.Models == nil {
		ks.Models = make(map[string]*ModelStats)
	}
	replaceTupleContribution(ks.Models, key, ModelStats{}, next)
	applyKeyContribution(ks, next, 1)
	ks.LastRequestAt = next.LastUsedAt
	if acct != nil {
		if acct.Models == nil {
			acct.Models = make(map[string]*ModelStats)
		}
		replaceTupleContribution(acct.Models, key, ModelStats{}, next)
		applyAccountContribution(acct, next, 1)
		acct.LastModel, acct.LastRequestAt = served, next.LastUsedAt
		s.markAccountDirtyLocked(tr)
	}
	// Rebuild this request's ledger stamps, preserving every other request.
	s.rollbackLedgerStampsLocked(tr)
	if !tr.Failed {
		at := tr.StartedAt
		if at.IsZero() {
			at = time.Now()
		}
		identity, provider := "", ""
		if acct != nil {
			identity, provider = acct.AuthID, acct.Provider
		}
		tr.ledgerStamps = []ledgerStamp{s.applyLedgerLocked(at, apiKey, tr.KeyName, identity, provider, requested, served, tr.SourceFormat, 1, next.InputTokens, next.OutputTokens, next.CacheReadTokens, next.CacheWriteTokens, next.TotalTokens, next.CostNanoUSD)}
	}
	tr.BilledKey, tr.BilledUsage, tr.CountedRequest = key, target, true
	tr.billedStats, tr.billedAccountKey = next, accountKey
	tr.billedPrice, tr.billedPriceFound = price, found
	s.markKeyDirtyLocked(apiKey)
	s.dirty = true
}

// mergeTrackedRequestLocked removes the duplicate tracker contribution before
// transferring its observed data to a tracker sharing an explicit TraceID.
func (s *Store) mergeTrackedRequestLocked(dst, src *TrackedRequest) {
	if src.HostUsageRecorded {
		dst.HostRequestID = src.HostRequestID
		dst.HostUsageRecorded = true
		dst.Failed = src.Failed
	}
	if dst.APIKey == "" || dst.APIKey == "__anonymous__" {
		dst.APIKey = src.APIKey
	}
	if dst.KeyName == "" {
		dst.KeyName = src.KeyName
	}
	dst.ExtractedUsage = MergeMaxUsage(dst.ExtractedUsage, src.ExtractedUsage)
	if dst.Provider == "" {
		dst.Provider = src.Provider
	}
	if dst.AuthID == "" {
		dst.AuthID = src.AuthID
	}
	if dst.AuthIndex == "" {
		dst.AuthIndex = src.AuthIndex
	}
	if dst.AuthType == "" {
		dst.AuthType = src.AuthType
	}
	old := src.billedStats
	if old.Requests > 0 {
		if ks := s.keys[src.APIKey]; ks != nil {
			replaceTupleContribution(ks.Models, src.BilledKey, old, ModelStats{})
			applyKeyContribution(ks, old, -1)
			s.markKeyDirtyLocked(src.APIKey)
		}
		if acct := s.accounts[src.billedAccountKey]; acct != nil {
			replaceTupleContribution(acct.Models, src.BilledKey, old, ModelStats{})
			applyAccountContribution(acct, old, -1)
			s.dirtyAccounts[src.billedAccountKey] = struct{}{}
		}
		s.rollbackLedgerStampsLocked(src)
	}
	for id, tr := range s.byRequestID {
		if tr == src {
			s.byRequestID[id] = dst
		}
	}
	for id, tr := range s.byTraceID {
		if tr == src {
			s.byTraceID[id] = dst
		}
	}
}

func checkedTokenSum(values ...int64) (int64, bool) {
	var total int64
	for _, value := range values {
		if value < 0 || value > math.MaxInt64-total {
			return 0, false
		}
		total += value
	}
	return total, true
}

func canReplaceValue(current, old, next int64) bool {
	return current >= old && next >= 0 && next <= math.MaxInt64-(current-old)
}
func canReplaceModelContribution(current *ModelStats, old, next ModelStats) bool {
	value := ModelStats{}
	if current != nil {
		value = *current
	}
	return canReplaceValue(value.Requests, old.Requests, next.Requests) && canReplaceValue(value.SuccessRequests, old.SuccessRequests, next.SuccessRequests) && canReplaceValue(value.FailedRequests, old.FailedRequests, next.FailedRequests) && canReplaceValue(value.InputTokens, old.InputTokens, next.InputTokens) && canReplaceValue(value.OutputTokens, old.OutputTokens, next.OutputTokens) && canReplaceValue(value.ReasoningTokens, old.ReasoningTokens, next.ReasoningTokens) && canReplaceValue(value.CacheReadTokens, old.CacheReadTokens, next.CacheReadTokens) && canReplaceValue(value.CacheWriteTokens, old.CacheWriteTokens, next.CacheWriteTokens) && canReplaceValue(value.TotalTokens, old.TotalTokens, next.TotalTokens) && canReplaceValue(value.CostNanoUSD, old.CostNanoUSD, next.CostNanoUSD)
}

func (s *Store) canReplaceLedgerContributionLocked(tr *TrackedRequest, apiKey, requested string, acct *AccountStats, next ModelStats) bool {
	if tr.Failed {
		return true
	}
	at := tr.StartedAt
	if at.IsZero() {
		at = time.Now()
	}
	hour := at.UTC().Truncate(time.Hour).Unix()
	account := ""
	if acct != nil {
		account = acct.AuthID
	}
	key := ledgerEntryKey(hour, apiKey, account, requested, tr.SourceFormat)
	entry := s.ledger[key]
	if entry == nil {
		return true
	}
	old := ModelStats{}
	for _, stamp := range tr.ledgerStamps {
		if ledgerEntryKey(stamp.hour, stamp.apiKey, stamp.account, stamp.model, stamp.source) == key {
			old.Requests += stamp.requests
			old.InputTokens += stamp.in
			old.OutputTokens += stamp.out
			old.CacheReadTokens += stamp.read
			old.CacheWriteTokens += stamp.write
			old.TotalTokens += stamp.total
			old.CostNanoUSD += stamp.cost
		}
	}
	value := ModelStats{Requests: entry.Requests, InputTokens: entry.InputTokens, OutputTokens: entry.OutputTokens, CacheReadTokens: entry.CacheReadTokens, CacheWriteTokens: entry.CacheWriteTokens, TotalTokens: entry.TotalTokens, CostNanoUSD: entry.CostNanoUSD}
	next.SuccessRequests, next.FailedRequests, next.ReasoningTokens = 0, 0, 0
	return canReplaceModelContribution(&value, old, next)
}

func canReplaceKeyContribution(k *KeyStats, o, n ModelStats) bool {
	return canReplaceValue(k.TotalRequests, o.Requests, n.Requests) && canReplaceValue(k.InputTokens, o.InputTokens, n.InputTokens) && canReplaceValue(k.OutputTokens, o.OutputTokens, n.OutputTokens) && canReplaceValue(k.ReasoningTokens, o.ReasoningTokens, n.ReasoningTokens) && canReplaceValue(k.CacheReadTokens, o.CacheReadTokens, n.CacheReadTokens) && canReplaceValue(k.CacheWriteTokens, o.CacheWriteTokens, n.CacheWriteTokens) && canReplaceValue(k.TotalTokens, o.TotalTokens, n.TotalTokens) && canReplaceValue(k.TotalCostNanoUSD, o.CostNanoUSD, n.CostNanoUSD)
}
func canReplaceAccountContribution(k *AccountStats, o, n ModelStats) bool {
	return canReplaceValue(k.Requests, o.Requests, n.Requests) && canReplaceValue(k.InputTokens, o.InputTokens, n.InputTokens) && canReplaceValue(k.OutputTokens, o.OutputTokens, n.OutputTokens) && canReplaceValue(k.ReasoningTokens, o.ReasoningTokens, n.ReasoningTokens) && canReplaceValue(k.CacheReadTokens, o.CacheReadTokens, n.CacheReadTokens) && canReplaceValue(k.CacheWriteTokens, o.CacheWriteTokens, n.CacheWriteTokens) && canReplaceValue(k.TotalTokens, o.TotalTokens, n.TotalTokens)
}
func applyModelContribution(dst *ModelStats, src ModelStats, sign int64) {
	dst.Requests += sign * src.Requests
	dst.SuccessRequests += sign * src.SuccessRequests
	dst.FailedRequests += sign * src.FailedRequests
	dst.InputTokens += sign * src.InputTokens
	dst.OutputTokens += sign * src.OutputTokens
	dst.ReasoningTokens += sign * src.ReasoningTokens
	dst.CacheReadTokens += sign * src.CacheReadTokens
	dst.CacheWriteTokens += sign * src.CacheWriteTokens
	dst.TotalTokens += sign * src.TotalTokens
	dst.CostNanoUSD += sign * src.CostNanoUSD
	dst.CostUSD = pricing.NanoToUSD(dst.CostNanoUSD)
	dst.CostFormatted = pricing.FormatUSD(dst.CostNanoUSD)
}
func replaceTupleContribution(models map[string]*ModelStats, key string, old, next ModelStats) {
	if strings.TrimSpace(key) == "" {
		return
	}
	dst := models[key]
	if dst == nil {
		if next.Requests == 0 {
			return
		}
		dst = &ModelStats{}
		models[key] = dst
	}
	applyModelContribution(dst, old, -1)
	applyModelContribution(dst, next, 1)
	if dst.Requests == 0 && dst.TotalTokens == 0 && dst.CostNanoUSD == 0 {
		delete(models, key)
		return
	}
	if next.Requests > 0 {
		dst.RequestedModel = next.RequestedModel
		dst.ServedModel = next.ServedModel
		dst.UnitPricePer1M = next.UnitPricePer1M
		dst.LastUsedAt = next.LastUsedAt
	}
}
func applyKeyContribution(k *KeyStats, v ModelStats, sign int64) {
	k.TotalRequests += sign * v.Requests
	k.SuccessRequests += sign * v.SuccessRequests
	k.FailedRequests += sign * v.FailedRequests
	k.InputTokens += sign * v.InputTokens
	k.OutputTokens += sign * v.OutputTokens
	k.ReasoningTokens += sign * v.ReasoningTokens
	k.CacheReadTokens += sign * v.CacheReadTokens
	k.CacheWriteTokens += sign * v.CacheWriteTokens
	k.TotalTokens += sign * v.TotalTokens
	k.TotalCostNanoUSD += sign * v.CostNanoUSD
	k.TotalCostUSD = pricing.NanoToUSD(k.TotalCostNanoUSD)
	k.TotalCostFormatted = pricing.FormatUSD(k.TotalCostNanoUSD)
}
func applyAccountContribution(k *AccountStats, v ModelStats, sign int64) {
	k.Requests += sign * v.Requests
	k.SuccessRequests += sign * v.SuccessRequests
	k.FailedRequests += sign * v.FailedRequests
	k.InputTokens += sign * v.InputTokens
	k.OutputTokens += sign * v.OutputTokens
	k.ReasoningTokens += sign * v.ReasoningTokens
	k.CacheReadTokens += sign * v.CacheReadTokens
	k.CacheWriteTokens += sign * v.CacheWriteTokens
	k.TotalTokens += sign * v.TotalTokens
}
