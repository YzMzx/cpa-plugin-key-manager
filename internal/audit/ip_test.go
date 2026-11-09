package audit

import (
	"net/http"
	"strings"
	"testing"
)

func networkMetadata(peer string) map[string]any {
	return map[string]any{"host_audit": map[string]any{"schema": "cpa.audit.network.v1", "peer_validated": true, "peer_ip": peer}}
}

func TestResolveIPUnknownWithoutProvenHostMetadata(t *testing.T) {
	forged := http.Header{"X-Forwarded-For": {"203.0.113.1"}, "X-Real-Ip": {"203.0.113.2"}, "Forwarded": {"for=203.0.113.3"}}
	for _, metadata := range []map[string]any{nil, {"client_ip": "203.0.113.4", "remote_addr": "127.0.0.1:42"}, {"host_audit": map[string]any{"peer_ip": "127.0.0.1", "peer_validated": true}}, {"host_audit": map[string]any{"schema": "cpa.audit.network.v1", "peer_ip": "127.0.0.1", "peer_validated": "true"}}} {
		got := ResolveClientIP(metadata, forged, []string{"0.0.0.0/0"})
		if got.Source != "unknown" || got.ClientIP != "" || got.PeerIP != "" {
			t.Fatalf("forged provenance accepted: %+v", got)
		}
	}
}

func TestResolveIPTrustedChainRightToLeft(t *testing.T) {
	cases := []struct {
		name, peer, xff, want, source string
		trust                         []string
	}{
		{"direct-untrusted", "198.51.100.7:1234", "203.0.113.99", "198.51.100.7", "host_peer", []string{"10.0.0.0/8"}},
		{"no-trust", "10.0.0.1", "203.0.113.99", "10.0.0.1", "host_peer", nil},
		{"trusted-tail", "10.0.0.1", "forged-left, 198.51.100.8, 10.0.0.2", "10.0.0.1", "host_peer", []string{"10.0.0.0/8"}},
		{"right-boundary", "10.0.0.1", "203.0.113.99, 198.51.100.8, 10.0.0.2", "198.51.100.8", "trusted_proxy_chain", []string{"10.0.0.0/8"}},
		{"ipv6", "[2001:db8::1]:443", "2001:db9::9, 2001:db8::2", "2001:db9::9", "trusted_proxy_chain", []string{"2001:db8::/32"}},
		{"invalid-cidr", "10.0.0.1", "203.0.113.99", "10.0.0.1", "host_peer", []string{"not-a-cidr"}},
		{"mapped-peer", "::ffff:192.0.2.1", "203.0.113.99", "203.0.113.99", "trusted_proxy_chain", []string{"192.0.2.0/24"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveClientIP(networkMetadata(tc.peer), http.Header{"X-Forwarded-For": {tc.xff}}, tc.trust)
			if got.ClientIP != tc.want || got.Source != tc.source {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestResolveIPExplicitHostResolvedAndMalformedChain(t *testing.T) {
	metadata := networkMetadata("192.0.2.1")
	host := metadata["host_audit"].(map[string]any)
	host["resolved_client_ip"] = "203.0.113.4"
	host["resolved_validated"] = true
	got := ResolveClientIP(metadata, http.Header{"X-Forwarded-For": {"attacker"}}, nil)
	if got.ClientIP != "203.0.113.4" || got.Source != "host_resolved" || got.PeerIP != "192.0.2.1" {
		t.Fatal(got)
	}
	host["resolved_client_ip"] = "not-an-ip"
	got = ResolveClientIP(metadata, nil, nil)
	if got.ClientIP != "192.0.2.1" || got.Source != "host_peer" {
		t.Fatal(got)
	}
	for _, xff := range []string{"unknown", "198.51.100.2,,10.0.0.3", "198.51.100.2,for=secret", strings.Repeat("1", 4097), strings.Repeat("1.1.1.1,", 33)} {
		got := ResolveClientIP(networkMetadata("10.0.0.1"), http.Header{"X-Forwarded-For": {xff}}, []string{"10.0.0.0/8"})
		if got.Source != "host_peer" || got.ClientIP != "10.0.0.1" || strings.Contains(got.Note, "secret") {
			t.Fatal(got)
		}
	}
}

func TestResolveIPRejectsMalformedPeerAndNeverPersistsHeaders(t *testing.T) {
	for _, peer := range []string{"", "host.example", "0.0.0.0", "[::]:123", "127.0.0.1%secret", "secret\n127.0.0.1"} {
		got := ResolveClientIP(networkMetadata(peer), http.Header{"Authorization": {"Bearer raw-secret"}}, []string{"0.0.0.0/0"})
		if got.Source != "unknown" || got.ClientIP != "" || strings.Contains(got.Note, "raw-secret") {
			t.Fatal(got)
		}
	}
}
