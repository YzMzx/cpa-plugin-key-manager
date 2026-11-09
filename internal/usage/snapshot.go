package usage

import (
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

// Snapshot returns a deep copy of current usage stats enriched with live active concurrency counts.
func (s *Store) Snapshot(filterAPIKey, filterModel string, activeByKey map[string]int, maxConcByKey map[string]int, keyNames map[string]string, maskKeys bool) PersistedSnapshot {
	s.mu.Lock()

	filterKey := strings.TrimSpace(filterAPIKey)
	filterMod := strings.ToLower(strings.TrimSpace(filterModel))

	// Include all configured keys or valid keys with stats
	allKeyIDs := make(map[string]struct{}, len(s.keys)+len(keyNames)+len(maxConcByKey))
	for k := range s.keys {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}
	for k := range keyNames {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}
	for k := range maxConcByKey {
		if !isInvalidKeyID(k) {
			allKeyIDs[k] = struct{}{}
		}
	}

	outKeys := make(map[string]*KeyStats, len(allKeyIDs))
	for k := range allKeyIDs {
		if isInvalidKeyID(k) {
			continue
		}
		if filterKey != "" && k != filterKey && MaskAPIKey(k) != filterKey {
			continue
		}
		src, exists := s.keys[k]
		var cpKey KeyStats
		if exists {
			cpKey = *src
		} else {
			cpKey = KeyStats{
				APIKey:             k,
				MaskedKey:          MaskAPIKey(k),
				KeyName:            keyNames[k],
				TotalCostFormatted: "$0.000000",
			}
		}
		if name, ok := keyNames[k]; ok && name != "" {
			cpKey.KeyName = name
		}
		if activeByKey != nil {
			cpKey.ActiveConcurrency = activeByKey[k]
		}
		if maxConcByKey != nil {
			cpKey.MaxConcurrency = maxConcByKey[k]
		}
		if maskKeys {
			cpKey.APIKey = ""
		}

		cpModels := make(map[string]*ModelStats)
		var sumReq, sumOk, sumFail, sumIn, sumOut, sumReason, sumRead, sumWrite, sumTotal, sumNano int64
		if exists && src.Models != nil {
			for tuple, mStat := range src.Models {
				if mStat == nil {
					continue
				}
				// A filter matches either side of the tuple so searching the requested
				// name and the served name both work.
				if filterMod != "" &&
					!strings.Contains(strings.ToLower(mStat.RequestedModel), filterMod) &&
					!strings.Contains(strings.ToLower(mStat.ServedModel), filterMod) {
					continue
				}
				mCopy := *mStat
				cpModels[tuple] = &mCopy

				sumReq += mCopy.Requests
				sumOk += mCopy.SuccessRequests
				sumFail += mCopy.FailedRequests
				sumIn += mCopy.InputTokens
				sumOut += mCopy.OutputTokens
				sumReason += mCopy.ReasoningTokens
				sumRead += mCopy.CacheReadTokens
				sumWrite += mCopy.CacheWriteTokens
				sumTotal += mCopy.TotalTokens
				sumNano += mCopy.CostNanoUSD
			}
		}
		cpKey.Models = cpModels
		if filterMod == "" && exists {
			cpKey.TotalRequests = sumReq
			cpKey.SuccessRequests = sumOk
			cpKey.FailedRequests = sumFail
			cpKey.InputTokens = sumIn
			cpKey.OutputTokens = sumOut
			cpKey.ReasoningTokens = sumReason
			cpKey.CacheReadTokens = sumRead
			cpKey.CacheWriteTokens = sumWrite
			cpKey.TotalTokens = sumTotal
			cpKey.TotalCostNanoUSD = sumNano
		}

		mapKey := k
		if maskKeys {
			mapKey = MaskAPIKey(k)
		}
		outKeys[mapKey] = &cpKey
	}

	accounts := s.snapshotAccountsLocked()
	s.mu.Unlock()
	// Formatting is CPU-only and operates exclusively on detached value copies.
	for _, ks := range outKeys {
		ks.TotalCostUSD = pricing.NanoToUSD(ks.TotalCostNanoUSD)
		ks.TotalCostFormatted = pricing.FormatUSD(ks.TotalCostNanoUSD)
		formatSnapshotModels(ks.Models)
	}
	for _, acct := range accounts {
		formatSnapshotModels(acct.Models)
	}
	return PersistedSnapshot{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Keys: outKeys, Accounts: accounts}
}

func formatSnapshotModels(models map[string]*ModelStats) {
	for _, ms := range models {
		ms.CostUSD = pricing.NanoToUSD(ms.CostNanoUSD)
		ms.CostFormatted = pricing.FormatUSD(ms.CostNanoUSD)
	}
}

// snapshotAccountsLocked copies the account buckets for read-only delivery.
func (s *Store) snapshotAccountsLocked() map[string]*AccountStats {
	if len(s.accounts) == 0 {
		return nil
	}
	out := make(map[string]*AccountStats, len(s.accounts))
	for k, v := range s.accounts {
		if v == nil {
			continue
		}
		cp := *v
		cp.AuthIDs = append([]string(nil), v.AuthIDs...)
		if len(v.Models) > 0 {
			cp.Models = make(map[string]*ModelStats, len(v.Models))
			for mk, mv := range v.Models {
				if mv == nil {
					continue
				}
				mcp := *mv
				cp.Models[mk] = &mcp
			}
		}
		out[k] = &cp
	}
	return out
}
