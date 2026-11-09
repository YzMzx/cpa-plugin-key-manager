package plugin

import (
	"strings"
	"testing"
)

func TestHostListenerConfigLayoutsAndPresencePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, raw, host, cert string
		port                  int
		tls                   bool
	}{
		{name: "legacy", raw: "host: 127.0.0.1\nport: 8317\ntls: {enable: true, cert: old.pem}\n", host: "127.0.0.1", port: 8317, tls: true, cert: "old.pem"},
		{name: "v8", raw: "config-version: 8\nserver: {host: localhost, port: 8420, tls: {enable: true, cert: new.pem}}\n", host: "localhost", port: 8420, tls: true, cert: "new.pem"},
		{name: "canonical-explicit-empty-false", raw: "host: bad.invalid\nport: 8317\ntls: {enable: true, cert: old.pem}\nserver: {host: '', port: 8420, tls: {enable: false, cert: ''}}\n", host: "", port: 8420, tls: false, cert: ""},
		{name: "partial-fallback", raw: "host: localhost\nport: 8317\ntls: {enable: true, cert: old.pem}\nserver: {port: 8420}\n", host: "localhost", port: 8420, tls: true, cert: "old.pem"},
		{name: "tls-cert-leaf", raw: "port: 8317\ntls: {enable: true, cert: old.pem}\nserver: {port: 8420, tls: {cert: new.pem}}\n", port: 8420, tls: true, cert: "new.pem"},
		{name: "tls-enable-leaf", raw: "port: 8317\ntls: {enable: false, cert: old.pem}\nserver: {tls: {enable: true}}\n", port: 8317, tls: true, cert: "old.pem"},
		{name: "tls-disable-leaf", raw: "port: 8317\ntls: {enable: true, cert: old.pem}\nserver: {tls: {enable: false}}\n", port: 8317, tls: false, cert: "old.pem"},
		{name: "ipv6", raw: "server: {host: '::1', port: 8317}\n", host: "::1", port: 8317},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseHostListenerConfig([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Host != tc.host || cfg.Port != tc.port || cfg.TLS.Enable != tc.tls || cfg.TLS.Cert != tc.cert {
				t.Fatalf("parsed listener mismatch: %+v", cfg)
			}
		})
	}
}

func TestHostListenerRejectsMalformedConfigurationWithoutLeakingValues(t *testing.T) {
	for _, raw := range []string{
		"server: true\n", "server: {port: secret-value}\n", "server: {port: 0}\nport: 8317\n",
		"server: {port: 65536}\n", "port: -1\n", "server: {port: null}\nport: 8317\n",
		"server: {port: 8317, tls: secret-value}\n", "[secret-value]", "server: [secret-value", "server: {host: [], port: 8317}",
	} {
		_, err := parseHostListenerConfig([]byte(raw))
		if err == nil {
			t.Fatalf("accepted malformed input %q", raw)
		}
		code, message := hostSyncDiagnostic(err)
		if code == "" || message == "" || strings.Contains(message, "secret-value") {
			t.Fatalf("unsafe diagnosis: %q %q", code, message)
		}
	}
}
