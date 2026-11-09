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

// loadRulesState reads only the configured SQLite database. A missing row is a
// new empty state; no external JSON files or experimental databases are scanned.
func (m *Manager) loadRulesState(repo *rulesRepository) (*DynamicRulesState, error) {
	payload, _, err := repo.Load()
	if err != nil {
		return nil, err
	}
	state := &DynamicRulesState{Version: 1}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, state); err != nil {
			return nil, fmt.Errorf("rules db: decode: %w", err)
		}
	}
	normalizeRulesState(state)
	return state, nil
}

func normalizeRulesState(state *DynamicRulesState) {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.CustomPrices == nil {
		state.CustomPrices = map[string]pricing.ModelPrice{}
	}
}
