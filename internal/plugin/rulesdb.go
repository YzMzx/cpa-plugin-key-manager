package plugin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// rulesRepository stores the whole DynamicRulesState (keys, key order, default
// policy, price overrides) as one row so every mutation is a single atomic upsert.
type rulesRepository struct {
	db *sqlitestore.DB
}

func newRulesRepository(db *sqlitestore.DB) *rulesRepository {
	if db == nil {
		return nil
	}
	return &rulesRepository{db: db}
}

// Load returns the persisted payload and its timestamp; a nil payload means the
// database has not been written yet.
func (r *rulesRepository) Load() ([]byte, string, error) {
	if r == nil || r.db == nil {
		return nil, "", nil
	}
	var payload string
	var updatedAt string
	err := r.db.Conn().QueryRow(`SELECT payload, updated_at FROM rules_state WHERE id = 1`).Scan(&payload, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("rules db: load: %w", err)
	}
	return []byte(payload), updatedAt, nil
}

// Save upserts the serialised state.
func (r *rulesRepository) Save(payload []byte) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("rules db: not configured")
	}
	if len(payload) == 0 {
		return fmt.Errorf("rules db: empty payload")
	}
	_, err := r.db.Conn().Exec(`INSERT INTO rules_state (id, payload, updated_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`,
		string(payload), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("rules db: save: %w", err)
	}
	return nil
}

// loadRulesState prefers the database and falls back to a one-time import from the
// legacy JSON file so upgrades never lose the configured rules.
func (m *Manager) loadRulesState(repo *rulesRepository, legacyJSONPath string) (*DynamicRulesState, error) {
	if payload, _, err := repo.Load(); err != nil {
		return nil, err
	} else if len(payload) > 0 {
		var state DynamicRulesState
		if errUnmarshal := json.Unmarshal(payload, &state); errUnmarshal != nil {
			return nil, fmt.Errorf("rules db: decode: %w", errUnmarshal)
		}
		normalizeRulesState(&state)
		return &state, nil
	}

	// No row yet: import the legacy JSON rules (if any) and persist them.
	legacy, errLegacy := LoadDynamicRulesFile(legacyJSONPath)
	if errLegacy != nil {
		return nil, errLegacy
	}
	if legacy == nil {
		legacy = &DynamicRulesState{Version: 1, CustomPrices: map[string]pricing.ModelPrice{}}
	}
	normalizeRulesState(legacy)
	if raw, errMarshal := json.Marshal(legacy); errMarshal == nil {
		_ = repo.Save(raw)
	}
	return legacy, nil
}

// persistRules writes the in-memory dynamic state through the repository. The
// caller must hold m.mu (every call site mutates the state under the write lock).
func (m *Manager) persistRules() error {
	state := m.dynamicState
	repo := m.rulesRepo
	if state == nil {
		return nil
	}
	if repo == nil {
		return fmt.Errorf("rules db: not configured")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return repo.Save(raw)
}

// rulesLocation describes where rules are stored (used in logs and errors). It is
// intentionally lock free because it is called while holding m.mu.
func (m *Manager) rulesLocation() string {
	if m.rulesRepo != nil && m.rulesRepo.db != nil {
		return m.rulesRepo.db.Path() + " (rules_state)"
	}
	return m.cfg.Storage.RulesFile
}

func normalizeRulesState(state *DynamicRulesState) {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.CustomPrices == nil {
		state.CustomPrices = map[string]pricing.ModelPrice{}
	}
}
