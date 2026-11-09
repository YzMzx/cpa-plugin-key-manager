package usage

// PersistenceStatus is a credential-free view of the last completed persistence
// operation. Dirty remains true while a batch is in flight or awaiting retry.
type PersistenceStatus struct {
	Configured      bool   `json:"configured"`
	Dirty           bool   `json:"dirty"`
	Flushing        bool   `json:"flushing"`
	LastSuccessAt   string `json:"last_success_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	DirtyKeys       int    `json:"dirty_keys"`
	DirtyAccounts   int    `json:"dirty_accounts"`
	DirtyLedger     int    `json:"dirty_ledger"`
	AccountingError string `json:"accounting_error,omitempty"`
}

func (s *Store) PersistenceStatus() PersistenceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := PersistenceStatus{Configured: s.db != nil, Dirty: s.dirty || s.flushInProgress, Flushing: s.flushInProgress, LastError: s.lastPersistenceError, DirtyKeys: len(s.dirtyKeys), DirtyAccounts: len(s.dirtyAccounts), DirtyLedger: len(s.dirtyLedger), AccountingError: s.lastAccountingError}
	if !s.lastPersistenceSuccess.IsZero() {
		status.LastSuccessAt = s.lastPersistenceSuccess.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	return status
}
