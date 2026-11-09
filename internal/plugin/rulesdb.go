package plugin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

// rulesRepository stores the whole DynamicRulesState (keys, key order, default
// policy, price overrides) as one row so every mutation is a single atomic upsert.
type rulesRepository struct {
	db *sqlitestore.DB
}

// importLegacyUsageDB copies a database written by an earlier build (derived from
// `usage_file`) into the durable location when the durable file does not exist yet.
// The SQLite side files are copied too so WAL content is preserved.
func importLegacyUsageDB(legacyPath, targetPath string) (bool, error) {
	legacyPath = strings.TrimSpace(legacyPath)
	targetPath = strings.TrimSpace(targetPath)
	if legacyPath == "" || targetPath == "" || filepath.Clean(legacyPath) == filepath.Clean(targetPath) {
		return false, nil
	}
	if info, err := os.Stat(legacyPath); err != nil || info.IsDir() || info.Size() == 0 {
		return false, nil
	}
	if info, err := os.Stat(targetPath); err == nil && !info.IsDir() && info.Size() > 0 {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return false, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := legacyPath + suffix
		raw, errRead := os.ReadFile(src)
		if errRead != nil {
			if suffix == "" {
				return false, errRead
			}
			continue
		}
		if errWrite := os.WriteFile(targetPath+suffix, raw, 0o644); errWrite != nil {
			return false, errWrite
		}
	}
	return true, nil
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
	raw, errMarshal := json.Marshal(legacy)
	if errMarshal != nil {
		return nil, errMarshal
	}
	if err := repo.Save(raw); err != nil {
		return nil, err
	}
	return legacy, nil
}

func normalizeRulesState(state *DynamicRulesState) {
	if state.Version == 0 {
		state.Version = 1
	}
	if state.CustomPrices == nil {
		state.CustomPrices = map[string]pricing.ModelPrice{}
	}
}
