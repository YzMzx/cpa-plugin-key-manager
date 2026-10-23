package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
)

// HostInvoker invokes a method on the CLIProxyAPI host C ABI (`host.log`, `host.http.do`, etc.).
type HostInvoker func(method string, payload []byte) ([]byte, error)

// HostBridge wraps host callbacks with graceful fallback when running outside a host callback context.
type HostBridge struct {
	mu      sync.RWMutex
	invoker HostInvoker
}

// NewHostBridge creates a new HostBridge.
func NewHostBridge(invoker HostInvoker) *HostBridge {
	return &HostBridge{invoker: invoker}
}

// SetInvoker sets or updates the underlying C ABI host callback function.
func (b *HostBridge) SetInvoker(invoker HostInvoker) {
	b.mu.Lock()
	b.invoker = invoker
	b.mu.Unlock()
}

type hostLogPayload struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type hostHTTPDoPayload struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers http.Header `json:"headers,omitempty"`
}

// Log sends a structured log entry to CLIProxyAPI via `host.log`.
func (b *HostBridge) Log(level, message string, fields map[string]any) {
	b.mu.RLock()
	inv := b.invoker
	b.mu.RUnlock()
	if inv == nil {
		return
	}
	req := hostLogPayload{
		Level:   level,
		Message: message,
		Fields:  fields,
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return
	}
	_, _ = inv(pluginabi.MethodHostLog, raw)
}

// FetchURL fetches an HTTP URL, attempting `host.http.do` first and gracefully falling back to standard `net/http`.
func (b *HostBridge) FetchURL(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	b.mu.RLock()
	inv := b.invoker
	b.mu.RUnlock()

	if inv != nil {
		req := hostHTTPDoPayload{
			Method: http.MethodGet,
			URL:    url,
			Headers: http.Header{
				"Accept":     {"application/json"},
				"User-Agent": {"CLIProxyAPI-Plugin-KeyGuard/1.0"},
			},
		}
		if rawReq, errMarshal := json.Marshal(req); errMarshal == nil {
			if rawResp, errCall := inv(pluginabi.MethodHostHTTPDo, rawReq); errCall == nil && len(rawResp) > 0 {
				var env pluginabi.Envelope
				if errEnv := json.Unmarshal(rawResp, &env); errEnv == nil && env.OK && len(env.Result) > 0 {
					var httpResp pluginapi.ExecutorHTTPResponse
					if errDec := json.Unmarshal(env.Result, &httpResp); errDec == nil {
						if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 && len(httpResp.Body) > 0 {
							return httpResp.Body, nil
						}
						return nil, fmt.Errorf("host.http.do returned status %d", httpResp.StatusCode)
					}
				}
			}
		}
	}

	// Fallback to standard Go net/http client (e.g. when called from a background goroutine without active host_callback_id)
	return pricing.DefaultHTTPFetcher(ctx, url, timeout)
}

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

// ListAuthFiles calls `host.auth.list` on the CLIProxyAPI host to retrieve all available upstream credentials.
func (b *HostBridge) ListAuthFiles(hostCallbackID string) ([]pluginapi.HostAuthFileEntry, error) {
	b.mu.RLock()
	inv := b.invoker
	b.mu.RUnlock()
	if inv == nil {
		return []pluginapi.HostAuthFileEntry{}, nil
	}

	payload := map[string]any{}
	if hostCallbackID != "" {
		payload["host_callback_id"] = hostCallbackID
	}
	rawReq, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rawResp, errCall := inv(pluginabi.MethodHostAuthList, rawReq)
	if errCall != nil {
		return nil, errCall
	}
	if len(rawResp) == 0 {
		return []pluginapi.HostAuthFileEntry{}, nil
	}
	var env pluginabi.Envelope
	if errEnv := json.Unmarshal(rawResp, &env); errEnv != nil {
		return nil, errEnv
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host.auth.list failed")
	}
	var resp hostAuthListResponse
	if len(env.Result) > 0 {
		if errDec := json.Unmarshal(env.Result, &resp); errDec != nil {
			return nil, errDec
		}
	}
	if resp.Files == nil {
		resp.Files = []pluginapi.HostAuthFileEntry{}
	}
	return resp.Files, nil
}
