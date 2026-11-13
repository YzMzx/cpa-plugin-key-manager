package plugin

import (
	"fmt"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/audit"
	"gopkg.in/yaml.v3"
)

// AuditConfig bounds plaintext JSON request retention; responses, IP monitoring
// and authentication headers are excluded.
type AuditConfig struct {
	Enabled                *bool `yaml:"enabled" json:"enabled,omitempty"`
	RetentionDays          int   `yaml:"retention_days" json:"retention_days"`
	MaxRecords             int   `yaml:"max_records" json:"max_records"`
	MaxBodyBytes           int   `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxTotalBytes          int64 `yaml:"max_total_bytes" json:"max_total_bytes"`
	CleanupBatchMaxRecords int   `yaml:"cleanup_batch_max_records" json:"cleanup_batch_max_records"`
	CleanupBatchMaxBytes   int64 `yaml:"cleanup_batch_max_bytes" json:"cleanup_batch_max_bytes"`
}

// UnmarshalYAML keeps cleanup budgets as integer settings. yaml.v3 otherwise
// converts a floating-point scalar to int/int64 by truncating its fractional part.
func (c *AuditConfig) UnmarshalYAML(node *yaml.Node) error {
	// Decode the effective mapping so YAML anchors/merges cannot bypass the
	// integer requirement, while an explicit override keeps YAML precedence.
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	for _, key := range []string{"cleanup_batch_max_records", "cleanup_batch_max_bytes"} {
		if value, ok := fields[key]; ok && (value.Kind != yaml.ScalarNode || value.Tag != "!!int") {
			return fmt.Errorf("audit.%s must be an integer", key)
		}
	}
	type plainAuditConfig AuditConfig
	return node.Decode((*plainAuditConfig)(c))
}

func (c *AuditConfig) normalize() {
	if c.Enabled == nil {
		enabled := true
		c.Enabled = &enabled
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 7
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = 10000
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = audit.DefaultMaxBodyBytes
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = 64 << 20
	}
	limits := (audit.CleanupBatchLimits{MaxRecords: c.CleanupBatchMaxRecords, MaxBytes: c.CleanupBatchMaxBytes}).Normalized()
	c.CleanupBatchMaxRecords, c.CleanupBatchMaxBytes = limits.MaxRecords, limits.MaxBytes
}
func (c AuditConfig) isEnabled() bool { return c.Enabled == nil || *c.Enabled }
func (c AuditConfig) validate() error {
	if c.RetentionDays < 1 || c.RetentionDays > 90 {
		return fmt.Errorf("audit.retention_days must be between 1 and 90")
	}
	if c.MaxRecords < 1 || c.MaxRecords > 100000 {
		return fmt.Errorf("audit.max_records must be between 1 and 100000")
	}
	if c.MaxBodyBytes < 256 || c.MaxBodyBytes > audit.MaxRequestBodyBytes {
		return fmt.Errorf("audit.max_body_bytes must be between 256 and 10485760 (10 MiB)")
	}
	if c.MaxTotalBytes < 1<<20 || c.MaxTotalBytes > audit.MaxTotalBytes {
		return fmt.Errorf("audit.max_total_bytes must be between 1 MiB and 10 GiB")
	}
	return (audit.CleanupBatchLimits{MaxRecords: c.CleanupBatchMaxRecords, MaxBytes: c.CleanupBatchMaxBytes}).Validate()
}
