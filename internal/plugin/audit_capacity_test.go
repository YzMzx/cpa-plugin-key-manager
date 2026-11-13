package plugin

import (
	"fmt"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
)

func TestAuditCapacityTenGiBBoundsAndDefault(t *testing.T) {
	for _, tc := range []struct {
		size  int64
		valid bool
	}{
		{1 << 20, true}, {1 << 30, true}, {10 << 30, true}, {(10 << 30) + 1, false}, {(1 << 20) - 1, false},
	} {
		t.Run(fmt.Sprint(tc.size), func(t *testing.T) {
			cfg, err := ParseConfigYAML([]byte(fmt.Sprintf("audit:\n  max_total_bytes: %d\n", tc.size)))
			if (err == nil) != tc.valid {
				t.Fatalf("size=%d err=%v", tc.size, err)
			}
			if err == nil && cfg.Audit.MaxTotalBytes != tc.size {
				t.Fatalf("capacity clamped: %d", cfg.Audit.MaxTotalBytes)
			}
		})
	}
	cfg, err := ParseConfigYAML(nil)
	if err != nil || cfg.Audit.MaxTotalBytes != audit.DefaultMaxTotalBytes {
		t.Fatalf("changed default: %d %v", cfg.Audit.MaxTotalBytes, err)
	}
	bounds := settingsLimits()["audit"].(map[string]any)["max_total_bytes"].([]int64)
	if bounds[0] != 1<<20 || bounds[1] != 10<<30 {
		t.Fatalf("wrong advertised bounds: %v", bounds)
	}
}
