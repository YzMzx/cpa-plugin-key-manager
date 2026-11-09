package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
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

// FetchURL uses a bounded, cancellable HTTP transport for public price catalogs.
// A synchronous host C callback cannot carry this context/deadline, so it must not
// be used here: a hung host call would otherwise stall Stop/reconfiguration.
func (b *HostBridge) FetchURL(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
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

// ListAuthModels calls `host.auth.models` on the CLIProxyAPI host to retrieve all credentials and their registered models.
func (b *HostBridge) ListAuthModels(hostCallbackID string) ([]pluginapi.HostAuthModels, error) {
	b.mu.RLock()
	inv := b.invoker
	b.mu.RUnlock()
	if inv == nil {
		return []pluginapi.HostAuthModels{}, nil
	}

	payload := map[string]any{}
	if hostCallbackID != "" {
		payload["host_callback_id"] = hostCallbackID
	}
	rawReq, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rawResp, errCall := inv(pluginabi.MethodHostAuthModels, rawReq)
	if errCall != nil {
		return nil, errCall
	}
	if len(rawResp) == 0 {
		return []pluginapi.HostAuthModels{}, nil
	}
	var env pluginabi.Envelope
	if errEnv := json.Unmarshal(rawResp, &env); errEnv != nil {
		return nil, errEnv
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host.auth.models failed")
	}
	var resp pluginapi.HostAuthModelsResponse
	if len(env.Result) > 0 {
		if errDec := json.Unmarshal(env.Result, &resp); errDec != nil {
			return nil, errDec
		}
	}
	if resp.Credentials == nil {
		resp.Credentials = []pluginapi.HostAuthModels{}
	}
	return resp.Credentials, nil
}
