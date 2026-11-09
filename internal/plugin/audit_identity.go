package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Correlation IDs must survive every callback unchanged. Canonical host UUIDs
// and hex traces remain readable; other identifiers become opaque digests.
func auditCorrelationID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "id-sha256:") && len(raw) == 74 {
		if _, err := hex.DecodeString(strings.TrimPrefix(raw, "id-sha256:")); err == nil {
			return raw
		}
	}
	value := strings.ReplaceAll(raw, "-", "")
	canonical := len(raw) == 36 && raw[8] == '-' && raw[13] == '-' && raw[18] == '-' && raw[23] == '-' && len(value) == 32
	hexTrace := !strings.Contains(raw, "-") && (len(raw) == 8 || len(raw) == 16 || len(raw) == 32 || len(raw) == 64)
	if canonical || hexTrace {
		if _, err := hex.DecodeString(value); err == nil {
			return raw
		}
	}
	sum := sha256.Sum256([]byte(raw))
	return "id-sha256:" + hex.EncodeToString(sum[:])
}
