package audit

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestResolveClientIPDeprecatedNoOp(t *testing.T) {
	metadata := map[string]any{"host_audit": map[string]any{"schema": "cpa.audit.network.v1", "peer_validated": true, "peer_ip": "192.0.2.1", "resolved_validated": true, "resolved_client_ip": "203.0.113.1"}, "client_ip": "198.51.100.1"}
	info := ResolveClientIP(metadata, http.Header{"X-Forwarded-For": {"203.0.113.9"}, "Authorization": {"Bearer secret"}}, []string{"0.0.0.0/0"})
	if info != (IPInfo{}) {
		t.Fatalf("deprecated resolver collected metadata: %+v", info)
	}
	raw, err := json.Marshal(IPInfo{ClientIP: "private", PeerIP: "private", Source: "source", Note: "note"})
	if err != nil || string(raw) != "{}" {
		t.Fatalf("network fields exposed: %s %v", raw, err)
	}
}
