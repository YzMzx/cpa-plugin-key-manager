package audit

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// IPInfo states the provenance explicitly; unknown is not inferred from headers.
type IPInfo struct {
	ClientIP string `json:"client_ip"`
	PeerIP   string `json:"peer_ip"`
	Source   string `json:"source"`
	Note     string `json:"note"`
}

// ResolveClientIP accepts only a reserved, host-produced future metadata contract:
// host_audit: {schema:"cpa.audit.network.v1", peer_validated:true, peer_ip:"IP",
// resolved_validated:true, resolved_client_ip:"IP"}. remote_addr may replace
// peer_ip. The host must populate this namespace itself, never from client input.
// Current CPA intercept/RPC metadata does not publish this contract: ordinary
// client_ip/remote_addr fields and forwarded headers alone therefore stay unknown.
func ResolveClientIP(metadata map[string]any, headers http.Header, trustedProxies []string) IPInfo {
	unknown := IPInfo{Source: "unknown", Note: "Host did not provide validated network metadata; forwarded headers are not evidence of client IP."}
	host, ok := metadata["host_audit"].(map[string]any)
	if !ok {
		return unknown
	}
	schema, _ := host["schema"].(string)
	if schema != "cpa.audit.network.v1" {
		return unknown
	}
	peerValidated, _ := host["peer_validated"].(bool)
	if !peerValidated {
		return unknown
	}
	raw, _ := host["peer_ip"].(string)
	if raw == "" {
		raw, _ = host["remote_addr"].(string)
	}
	peer, ok := parseAuditIP(raw)
	if !ok {
		unknown.Note = "Host network metadata contained an invalid peer address."
		return unknown
	}
	result := IPInfo{ClientIP: peer.String(), PeerIP: peer.String(), Source: "host_peer", Note: "Direct peer supplied by validated host metadata; proxy headers ignored."}
	if validated, _ := host["resolved_validated"].(bool); validated {
		raw, _ := host["resolved_client_ip"].(string)
		if resolved, valid := parseAuditIP(raw); valid {
			result.ClientIP = resolved.String()
			result.Source = "host_resolved"
			result.Note = "Client IP resolved and explicitly validated by the host."
			return result
		}
		result.Note = "Host resolved address was invalid; only the validated direct peer is recorded."
		return result
	}
	if len(trustedProxies) > 256 {
		result.Note = "Trusted proxy configuration exceeds the safety limit; only direct peer recorded."
		return result
	}
	trusted := make([]netip.Prefix, 0, len(trustedProxies))
	for _, raw := range trustedProxies {
		if len(raw) > 256 {
			continue
		}
		raw = strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			trusted = append(trusted, prefix.Masked())
			continue
		}
		if ip, valid := parseAuditIP(raw); valid {
			bits := 128
			if ip.Is4() {
				bits = 32
			}
			trusted = append(trusted, netip.PrefixFrom(ip, bits))
		}
	}
	isTrusted := func(ip netip.Addr) bool {
		for _, prefix := range trusted {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return result
	}
	values := headers.Values("X-Forwarded-For")
	if len(values) == 0 {
		return result
	}
	if len(values) > 16 {
		result.Note = "Forwarded chain exceeds the safety limit; only direct peer recorded."
		return result
	}
	length := 0
	for _, value := range values {
		if len(value) > 4096-length {
			result.Note = "Forwarded chain exceeds the safety limit; only direct peer recorded."
			return result
		}
		length += len(value)
	}
	if length > 4096 {
		result.Note = "Forwarded chain exceeds the safety limit; only direct peer recorded."
		return result
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	if len(parts) > 32 {
		result.Note = "Forwarded chain exceeds the safety limit; only direct peer recorded."
		return result
	}
	chain := make([]netip.Addr, len(parts))
	for i, part := range parts {
		ip, valid := parseAuditIP(part)
		if !valid {
			result.Note = "Invalid forwarded chain ignored; only direct peer recorded."
			return result
		}
		chain[i] = ip
	}
	candidate := peer
	for i := len(chain) - 1; i >= 0; i-- {
		if !isTrusted(candidate) {
			break
		}
		candidate = chain[i]
	}
	result.ClientIP = candidate.String()
	result.Source = "trusted_proxy_chain"
	result.Note = "Forwarded chain parsed right-to-left from a host-validated trusted peer."
	return result
}

func parseAuditIP(raw string) (netip.Addr, bool) {
	if len(raw) > 256 {
		return netip.Addr{}, false
	}
	raw = strings.TrimSpace(raw)
	if ip, err := netip.ParseAddr(raw); err == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		return ip, ip.IsValid() && !ip.IsUnspecified()
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || port == "" {
		return netip.Addr{}, false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	return ip, ip.IsValid() && !ip.IsUnspecified()
}
