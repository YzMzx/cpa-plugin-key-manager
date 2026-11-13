package usage

// An explicit trace may unite an already billed host execution with its logical
// request. Validate the replacement against detached aggregates before removing
// any live contribution. This uncommon path must not turn invalid late evidence
// into a refund of valid, previously committed usage.
func (s *Store) mergeTrackedRequestLocked(dst, src *TrackedRequest) bool {
	if s.closing {
		s.lastAccountingError = "usage store is shutting down; late accounting was rejected"
		return false
	}
	candidate := NewStore(s.pricing)
	// Only the two request keys and account buckets can be changed by reconciliation.
	for _, key := range []string{dst.APIKey, src.APIKey} {
		if k := s.keys[key]; k != nil {
			cp := *k
			cp.Models = cloneModels(k.Models)
			candidate.keys[key] = &cp
		}
		candidate.quotaCosts[key] = s.quotaCosts[key]
	}
	identity := *dst
	if identity.Provider == "" {
		identity.Provider = src.Provider
	}
	if identity.AuthID == "" {
		identity.AuthID = src.AuthID
	}
	if identity.AuthIndex == "" {
		identity.AuthIndex = src.AuthIndex
	}
	accountIDs := []string{dst.billedAccountKey, src.billedAccountKey, accountBucketKey(identity.Provider, identity.AuthID, identity.AuthIndex)}
	for _, key := range accountIDs {
		if a := s.accounts[key]; a != nil {
			cp := *a
			cp.Models = cloneModels(a.Models)
			cp.AuthIDs = append([]string(nil), a.AuthIDs...)
			candidate.accounts[key] = &cp
		}
	}
	// Ledger mutations are limited to these API keys. Copy their slices only.
	for key, e := range s.ledger {
		if e.APIKey == dst.APIKey || e.APIKey == src.APIKey {
			cp := *e
			candidate.ledgerPutLocked(key, &cp)
		}
	}
	d, c := *dst, *src
	d.ledgerStamps = append([]ledgerStamp(nil), dst.ledgerStamps...)
	c.ledgerStamps = append([]ledgerStamp(nil), src.ledgerStamps...)
	candidate.mergeTrackedRequestUnchecked(&d, &c)
	if !candidate.reconcileTrackerDeltaLocked(&d) {
		s.lastAccountingError = candidate.lastAccountingError
		if s.lastAccountingError == "" {
			s.lastAccountingError = "trace merge rejected incomplete billing identity"
		}
		return false
	}
	// All mutations below publish the validated candidate while mu remains held.
	for key, k := range candidate.keys {
		s.keys[key] = k
	}
	for key, a := range candidate.accounts {
		s.accounts[key] = a
	}
	for key, cost := range candidate.quotaCosts {
		s.quotaCosts[key] = cost
	}
	for key := range candidate.dirtyKeys {
		s.dirtyKeys[key] = struct{}{}
	}
	for key := range candidate.dirtyAccounts {
		s.dirtyAccounts[key] = struct{}{}
	}
	for key := range candidate.dirtyQuota {
		s.dirtyQuota[key] = struct{}{}
	}
	for key, e := range s.ledger {
		if e.APIKey == dst.APIKey || e.APIKey == src.APIKey {
			s.ledgerDeleteLocked(key)
		}
	}
	for key, e := range candidate.ledger {
		s.ledgerPutLocked(key, e)
	}
	for key := range candidate.dirtyLedger {
		s.dirtyLedger[key] = struct{}{}
	}
	for ref := range candidate.deletedLedger {
		s.deletedLedger[ref] = struct{}{}
	}
	*dst = d
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
	s.dirty = true
	return true
}
