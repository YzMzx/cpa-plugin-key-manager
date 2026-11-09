package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HostSyncStatus exposes partial success without retaining management credentials.
func (m *Manager) HostSyncStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pending := m.dynamicState != nil && m.dynamicState.HostSyncPending
	return map[string]any{"pending": pending, "error": m.hostSyncError}
}

// syncPendingHost retries the durable intent using the credential of this request.
// managementMu serializes clients; mutationMu keeps the committed key set stable.
func (m *Manager) syncPendingHost(ctx context.Context, credential string) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	m.mu.RLock()
	pending := m.dynamicState != nil && m.dynamicState.HostSyncPending
	keys := configuredKeyList(m.cfg.Keys)
	var deleted []string
	if m.dynamicState != nil {
		deleted = append([]string(nil), m.dynamicState.DeletedKeys...)
	}
	syncHost := m.hostKeySync
	m.mu.RUnlock()
	if !pending {
		return
	}
	var err error
	if syncHost != nil {
		err = syncHost(ctx, credential, keys)
	} else {
		err = syncHostRuntimeDelta(ctx, credential, keys, deleted)
	}
	if err != nil {
		m.mu.Lock()
		m.hostSyncError = "Rules saved; CPA synchronization failed. Refresh to retry."
		m.mu.Unlock()
		return
	}
	m.mu.RLock()
	next, cloneErr := cloneRulesState(m.dynamicState)
	repo := m.rulesRepo
	m.mu.RUnlock()
	if cloneErr == nil {
		next.HostSyncPending = false
		raw, marshalErr := json.Marshal(next)
		if marshalErr == nil {
			cloneErr = repo.Save(raw)
		} else {
			cloneErr = marshalErr
		}
	}
	m.mu.Lock()
	if cloneErr != nil {
		m.hostSyncError = "CPA synchronized; persisting synchronization status failed. Refresh to retry."
	} else {
		m.dynamicState = next
		m.hostSyncError = ""
	}
	m.mu.Unlock()
}

// Native PATCH/DELETE modify one entity under the host lock. Unlike whole-list
// PUT this cannot overwrite keys created concurrently in the host admin panel.
func syncHostRuntimeDelta(ctx context.Context, credential string, keys, deleted []string) error {
	if strings.TrimSpace(credential) == "" {
		return fmt.Errorf("management credential is required")
	}
	raw, err := os.ReadFile(FindHostConfigFile(""))
	if err != nil {
		return fmt.Errorf("host config is unavailable")
	}
	var cfg struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		TLS  struct {
			Enable bool   `yaml:"enable"`
			Cert   string `yaml:"cert"`
		} `yaml:"tls"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil || cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("host management port is invalid")
	}
	scheme := "http"
	if cfg.TLS.Enable {
		scheme = "https"
	}
	host := strings.Trim(strings.TrimSpace(cfg.Host), "[]")
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	endpoint := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(cfg.Port)) + "/v0/management/api-keys"
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if cfg.TLS.Enable && cfg.TLS.Cert != "" {
		certFile := cfg.TLS.Cert
		if !filepath.IsAbs(certFile) {
			certFile = filepath.Join(filepath.Dir(FindHostConfigFile("")), certFile)
		}
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("host TLS certificate is unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certPEM) {
			return fmt.Errorf("invalid host TLS certificate")
		}
		serverName := host
		if block, _ := pem.Decode(certPEM); block != nil {
			if certificate, err := x509.ParseCertificate(block.Bytes); err == nil && certificate.VerifyHostname(host) != nil && len(certificate.DNSNames) > 0 {
				serverName = certificate.DNSNames[0]
			}
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, target string, payload []byte, output any) error {
		req, err := http.NewRequestWithContext(requestCtx, method, target, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("build host management request")
		}
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("host management request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("host management returned HTTP %d", resp.StatusCode)
		}
		if output != nil {
			if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(output); err != nil {
				return fmt.Errorf("invalid host management response")
			}
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		}
		return nil
	}
	var current struct {
		Keys []string `json:"api-keys"`
	}
	if err := call(http.MethodGet, endpoint, nil, &current); err != nil {
		return err
	}
	present := make(map[string]bool, len(current.Keys))
	for _, key := range current.Keys {
		present[key] = true
	}
	for _, key := range keys {
		if present[key] {
			continue
		}
		// old == new is idempotent if a concurrent writer already inserted it.
		payload, _ := json.Marshal(map[string]string{"old": key, "new": key})
		if err := call(http.MethodPatch, endpoint, payload, nil); err != nil {
			return err
		}
	}
	for _, key := range deleted {
		if present[key] {
			if err := call(http.MethodDelete, endpoint+"?value="+url.QueryEscape(key), nil, nil); err != nil {
				return err
			}
		}
	}
	invalidateHostConfigCache()
	return nil
}
