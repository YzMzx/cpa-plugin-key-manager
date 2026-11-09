package plugin

import (
	"fmt"
	"net/netip"
	"strings"
)

// AuditConfig bounds redacted request retention; responses and auth headers are excluded.
type AuditConfig struct {
	Enabled        *bool    `yaml:"enabled" json:"enabled,omitempty"`
	RetentionDays  int      `yaml:"retention_days" json:"retention_days"`
	MaxRecords     int      `yaml:"max_records" json:"max_records"`
	MaxBodyBytes   int      `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxTotalBytes  int64    `yaml:"max_total_bytes" json:"max_total_bytes"`
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies,omitempty"`
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
		c.MaxBodyBytes = 32768
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = 64 << 20
	}
}
func (c AuditConfig) isEnabled() bool { return c.Enabled == nil || *c.Enabled }
func (c AuditConfig) validate() error {
	if c.RetentionDays < 1 || c.RetentionDays > 90 {
		return fmt.Errorf("audit.retention_days must be between 1 and 90")
	}
	if c.MaxRecords < 1 || c.MaxRecords > 100000 {
		return fmt.Errorf("audit.max_records must be between 1 and 100000")
	}
	if c.MaxBodyBytes < 256 || c.MaxBodyBytes > 32768 {
		return fmt.Errorf("audit.max_body_bytes must be between 256 and 32768")
	}
	if c.MaxTotalBytes < 1<<20 || c.MaxTotalBytes > 1<<30 {
		return fmt.Errorf("audit.max_total_bytes must be between 1 MiB and 1 GiB")
	}
	if len(c.TrustedProxies) > 256 {
		return fmt.Errorf("audit.trusted_proxies may contain at most 256 CIDRs")
	}
	for _, prefix := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(strings.TrimSpace(prefix)); err != nil {
			return fmt.Errorf("audit.trusted_proxies must contain valid CIDRs")
		}
	}
	return nil
}
