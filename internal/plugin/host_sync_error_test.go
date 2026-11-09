package plugin

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHostSyncFailureClassificationNeverLeaksSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		err        error
	}{
		{"timeout", "timeout", context.DeadlineExceeded},
		{"cancel", "cancelled", context.Canceled},
		{"dns", "dns", &net.DNSError{Err: "secret-value", Name: "secret-host"}},
		{"refused", "connection_refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
		{"tls", "tls_verify", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "secret-host"}},
		{"unknown", "connection_failed", errors.New("Bearer secret-value https://host/?value=private-api-key")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, message := hostSyncDiagnostic(hostSyncTransportFailure(tc.err))
			if code != tc.code {
				t.Fatalf("code=%q want %q", code, tc.code)
			}
			for _, secret := range []string{"secret-value", "secret-host", "private-api-key"} {
				if strings.Contains(message, secret) {
					t.Fatal("diagnosis leaked secret")
				}
			}
		})
	}
	code, message := hostSyncDiagnostic(errors.New("secret-value"))
	if code != "sync_failed" || strings.Contains(message, "secret-value") {
		t.Fatal("arbitrary error leaked")
	}
}

func TestHostSyncHTTPDiagnosticsKeepStatusAndHideResponseBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{401, "authorization"}, {403, "authorization"}, {404, "endpoint_missing"}, {405, "method_unsupported"}, {500, "http_status"}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("secret-response-body"))
			}))
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := "server:\n  host: " + parsed.Hostname() + "\n  port: " + parsed.Port() + "\n"
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CPA_CONFIG_FILE", path)
			err := syncHostRuntimeDelta(context.Background(), "secret-token", nil, nil)
			code, message := hostSyncDiagnostic(err)
			if code != tc.code {
				t.Fatalf("code=%q want %q", code, tc.code)
			}
			if !strings.Contains(message, http.StatusText(tc.status)) && tc.status != 404 && tc.status != 405 {
				t.Fatalf("status missing: %s", message)
			}
			for _, secret := range []string{"secret-response-body", "secret-token"} {
				if strings.Contains(message, secret) {
					t.Fatal("HTTP diagnosis leaked secret")
				}
			}
		})
	}
}

func TestHostSyncStatusExposesSafeReasonAndClearsOnRetry(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"pending-key"}`)); err != nil {
		t.Fatal(err)
	}
	m.hostKeySync = func(context.Context, string, []string) error {
		return newHostSyncFailure("config_port", "请检查 server.port")
	}
	m.syncPendingHost(context.Background(), "secret-token")
	status := m.HostSyncStatus()
	if status["pending"] != true || status["error_code"] != "config_port" || !strings.Contains(status["error"].(string), "server.port") {
		t.Fatalf("missing useful sync state: %v", status)
	}
	m.hostKeySync = func(context.Context, string, []string) error { return nil }
	m.syncPendingHost(context.Background(), "secret-token")
	status = m.HostSyncStatus()
	if status["pending"] != false || status["error_code"] != "" || status["error"] != "" {
		t.Fatalf("retry did not clear diagnostic: %v", status)
	}
}
