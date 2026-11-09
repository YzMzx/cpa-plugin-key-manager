package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"
	_ "time/tzdata"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
)

func validateConfig(cfg Config) error {
	if settingsCacheConflicts(runtimeSettingsFromConfig(cfg), cfg) {
		return fmt.Errorf("pricing cache path conflicts with protected storage")
	}
	if err := cfg.Audit.validate(); err != nil {
		return err
	}
	if _, err := time.LoadLocation(cfg.Storage.Timezone); err != nil {
		return fmt.Errorf("invalid storage.timezone: %w", err)
	}
	for _, price := range cfg.Pricing.CustomPrices {
		if err := pricing.ValidatePrice(price); err != nil {
			return fmt.Errorf("invalid custom price: %w", err)
		}
	}
	if cfg.Pricing.DefaultPrice != nil {
		if err := pricing.ValidatePrice(*cfg.Pricing.DefaultPrice); err != nil {
			return fmt.Errorf("invalid default price: %w", err)
		}
	}
	if err := validateQuota(cfg.DefaultPolicy.QuotaLimitUSD); err != nil {
		return err
	}
	for _, rule := range cfg.Keys {
		if err := validateQuota(rule.QuotaLimitUSD); err != nil {
			return err
		}
	}
	return nil
}

func validateQuota(value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return fmt.Errorf("quota must be a finite non-negative number")
	}
	return nil
}

func configFingerprint(cfg Config) string {
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
