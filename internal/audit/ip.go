package audit

import "net/http"

// IPInfo is retained only for source compatibility. Audit no longer collects,
// resolves, stores or returns network identity. Every field is JSON-invisible.
// Deprecated: network monitoring has been removed.
type IPInfo struct {
	ClientIP string `json:"-"`
	PeerIP   string `json:"-"`
	Source   string `json:"-"`
	Note     string `json:"-"`
}

// ResolveClientIP ignores all input. It does not parse proxy headers or metadata.
// Deprecated: callers should stop providing network metadata.
func ResolveClientIP(_ map[string]any, _ http.Header, _ []string) IPInfo { return IPInfo{} }
