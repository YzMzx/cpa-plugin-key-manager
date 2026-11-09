package plugin

// ConfiguredTimezone is the shared calendar boundary for API and UI queries.
func (m *Manager) ConfiguredTimezone() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Storage.Timezone
}
