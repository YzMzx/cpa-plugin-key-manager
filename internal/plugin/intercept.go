package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/handler"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/limiter"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func (m *Manager) handleFrontendAuth(raw []byte) ([]byte, error) {
	var req pluginapi.FrontendAuthRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	apiKey := ExtractAPIKeyFromHeadersAndQuery(req.Headers, req.Query)
	if apiKey == "" {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, listed := cfg.ResolveKeyRule(apiKey)
	if !listed || !rule.IsEnabled() {
		// Unlisted keys fall through to CLIProxyAPI's native config authenticator
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	return okEnvelope(pluginapi.FrontendAuthResponse{
		Authenticated: true,
		Principal:     apiKey,
		Metadata: map[string]string{
			"key_name": rule.Name,
		},
	})
}

func (m *Manager) handleRequestInterceptBefore(raw []byte) ([]byte, error) {
	m.admissionMu.RLock()
	defer m.admissionMu.RUnlock()
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	apiKey := cfg.ResolveAPIKeyFromContext(req.Headers, nil, req.Metadata)
	rule, _ := cfg.ResolveKeyRule(apiKey)
	m.beginAudit(req, apiKey, rule.Name)

	// 1. Check whether API Key is enabled/allowed
	if !rule.IsEnabled() {
		m.rejectAudit(req.RequestID, http.StatusForbidden)
		return okEnvelope(authz.NewForbiddenKeyResponse("API key is not authorized or has been disabled"))
	}

	// 2. Check per-API-Key model whitelist (supports exact & wildcard matching against RequestedModel and Model)
	displayModel := strings.TrimSpace(req.RequestedModel)
	if displayModel == "" {
		displayModel = strings.TrimSpace(req.Model)
	}
	if !authz.AllowsModel(rule.AllowedModels, req.RequestedModel, req.Model) {
		m.rejectAudit(req.RequestID, http.StatusForbidden)
		return okEnvelope(authz.NewForbiddenModelResponse(displayModel))
	}

	// 3. Check per-API-Key cumulative USD quota limit (if quota_limit_usd > 0).
	//    The quota counts usage since the last "重置额度", not the lifetime total.
	if rule.QuotaLimitUSD > 0 {
		usedUSD := m.quotaCostUSD(rule) - rule.QuotaUsedBaseUSD
		if usedUSD < 0 {
			usedUSD = 0
		}
		if usedUSD >= rule.QuotaLimitUSD {
			m.rejectAudit(req.RequestID, http.StatusTooManyRequests)
			return okEnvelope(authz.NewQuotaExceededResponse(usedUSD, rule.QuotaLimitUSD))
		}
	}

	// 4. Check and acquire per-API-Key concurrency slot (tracked by RequestID)
	acquired, _ := m.limiter.TryAcquire(limiter.SlotInfo{
		RequestID:      req.RequestID,
		APIKey:         apiKey,
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		SourceFormat:   req.SourceFormat,
		Stream:         req.Stream,
		AcquiredAt:     time.Now(),
	}, rule.MaxConcurrency)
	if !acquired {
		m.rejectAudit(req.RequestID, http.StatusTooManyRequests)
		return okEnvelope(authz.NewConcurrencyLimitResponse(rule.MaxConcurrency))
	}

	// 5. Register in usage store for lifecycle tracking
	m.usageStore.BeginRequest(req.RequestID, apiKey, rule.Name, req.Model, req.RequestedModel, req.SourceFormat, req.Stream)

	// 6. Protocol-guarded auto-injection of `stream_options.include_usage = true` for OpenAI Chat Completions streams
	body := req.Body
	if req.Stream && cfg.ShouldAutoInjectIncludeUsage() {
		var reqPath string
		if req.Metadata != nil {
			if p, ok := req.Metadata["request_path"].(string); ok {
				reqPath = p
			}
		}
		if updatedBody, changed := usage.MaybeInjectStreamIncludeUsage(req.SourceFormat, reqPath, true, body); changed {
			body = updatedBody
		}
	}

	return okEnvelope(pluginapi.RequestInterceptResponse{
		Headers: req.Headers,
		Body:    body,
	})
}

func (m *Manager) handleRequestInterceptAfter(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return okEnvelope(pluginapi.RequestInterceptResponse{
		Headers: req.Headers,
		Body:    req.Body,
	})
}

func (m *Manager) handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	m.mu.Lock()
	cfg := m.cfg
	for _, cand := range req.Candidates {
		id := strings.TrimSpace(cand.ID)
		if id == "" {
			continue
		}
		name := id
		if fn := strings.TrimSpace(cand.Attributes["filename"]); fn != "" {
			name = fn
		}
		m.seenAuthFiles[id] = pluginapi.HostAuthFileEntry{
			ID:       id,
			Name:     name,
			Provider: cand.Provider,
			Status:   cand.Status,
			Priority: cand.Priority,
			Email:    cand.Attributes["email"],
			Account:  cand.Attributes["account"],
			Label:    cand.Attributes["label"],
		}
	}
	m.mu.Unlock()

	apiKey := cfg.ResolveAPIKeyFromContext(http.Header(req.Options.Headers), nil, req.Options.Metadata)
	rule, _ := cfg.ResolveKeyRule(apiKey)

	resp := m.scheduler.Pick(apiKey, rule.UpstreamBinding, req)
	return okEnvelope(resp)
}

func (m *Manager) handleResponseInterceptAfter(raw []byte) ([]byte, error) {
	m.admissionMu.RLock()
	defer m.admissionMu.RUnlock()
	var req pluginapi.ResponseInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if len(req.Body) > 0 {
		m.usageStore.ObserveResponse(req.RequestID, req.Model, req.RequestedModel, req.Body)
	}

	// If Model and RequestedModel are empty, this is a catalog/metadata response such as /v1/models.
	// Filter the returned model catalog so that clients only see models permitted by their API Key whitelist.
	if strings.TrimSpace(req.Model) == "" && strings.TrimSpace(req.RequestedModel) == "" && len(req.Body) > 0 &&
		!isManagementPanelRequest(req.RequestHeaders) {
		m.mu.RLock()
		cfg := m.cfg
		m.mu.RUnlock()

		apiKey := cfg.ResolveAPIKeyFromContext(req.RequestHeaders, nil, req.Metadata)
		rule, _ := cfg.ResolveKeyRule(apiKey)

		// Only filter if the key is restricted (i.e. not completely unrestricted `["*"]`)
		isUnrestricted := len(rule.AllowedModels) == 1 && strings.TrimSpace(rule.AllowedModels[0]) == "*"
		if !isUnrestricted {
			if filteredBody, changed := authz.FilterModelCatalogJSON(req.Body, rule.AllowedModels); changed {
				return okEnvelope(pluginapi.ResponseInterceptResponse{
					Body: filteredBody,
				})
			}
		}
	}

	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

func (m *Manager) handleStreamChunkIntercept(raw []byte) ([]byte, error) {
	m.admissionMu.RLock()
	defer m.admissionMu.RUnlock()
	var req pluginapi.StreamChunkInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	// ChunkIndex == -1 is the header-init invocation; ChunkIndex >= 0 carries SSE payload chunks.
	if req.ChunkIndex >= 0 && len(req.Body) > 0 {
		m.usageStore.ObserveStreamChunk(req.RequestID, req.Model, req.RequestedModel, req.Body)
	}
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

func (m *Manager) handleRequestComplete(raw []byte) ([]byte, error) {
	m.admissionMu.RLock()
	defer m.admissionMu.RUnlock()
	var completion pluginapi.RequestCompletion
	if err := json.Unmarshal(raw, &completion); err != nil {
		return nil, err
	}

	// Priority 1: Always release the concurrency slot for RequestID first (idempotent, never underflows)
	releasedSlot, _ := m.limiter.Release(completion.RequestID)

	// Priority 2: Finalize request & token usage billing (deduplicated with usage.handle)
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	var apiKey string
	if releasedSlot != nil && releasedSlot.APIKey != "" && releasedSlot.APIKey != "__anonymous__" {
		apiKey = releasedSlot.APIKey
	} else {
		apiKey = cfg.ResolveAPIKeyFromContext(nil, nil, completion.Metadata)
	}
	rule, _ := cfg.ResolveKeyRule(apiKey)

	m.usageStore.CompleteRequest(completion, apiKey, rule.Name)
	m.completeRequestAudit(completion, apiKey)
	return okEnvelope(struct{}{})
}

func (m *Manager) handleUsageRecord(raw []byte) ([]byte, error) {
	m.admissionMu.RLock()
	defer m.admissionMu.RUnlock()
	var rec pluginapi.UsageRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}

	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	rule, _ := cfg.ResolveKeyRule(rec.APIKey)
	m.usageStore.ObserveHostUsageRecord(rec, rule.Name)
	m.auditUsage(rec)
	return okEnvelope(struct{}{})
}

func (m *Manager) handleManagement(raw []byte) ([]byte, error) {
	var req struct {
		pluginapi.ManagementRequest
		HostCallbackID string `json:"host_callback_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	m.managementMu.Lock()
	defer m.managementMu.Unlock()
	method := strings.ToUpper(req.Method)
	if method != http.MethodGet && method != http.MethodHead && req.Path != "/v0/management/key-guard/settings/bootstrap" {
		if value := req.Headers.Get("X-Key-Guard-Revision"); value != "" {
			revision, err := strconv.ParseUint(value, 10, 64)
			if err != nil || revision != m.RulesRevision() {
				return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusConflict, Headers: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"error":{"message":"Rules changed in another session. Refresh and retry."}}`)})
			}
		}
	}
	resp := handler.HandleManagementRequest(context.Background(), m, req.ManagementRequest, req.HostCallbackID)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.HasPrefix(req.Path, "/v0/management/key-guard/") {
		credential := strings.TrimSpace(req.Headers.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(credential), "bearer ") {
			credential = strings.TrimSpace(credential[7:])
		}
		if credential == "" {
			credential = strings.TrimSpace(req.Headers.Get("X-Management-Key"))
		}
		m.syncPendingHost(context.Background(), credential)
		var payload map[string]any
		if json.Unmarshal(resp.Body, &payload) == nil && payload != nil {
			payload["host_sync"] = m.HostSyncStatus()
			payload["rules_revision"] = m.RulesRevision()
			if nested, ok := payload["overview"].(map[string]any); ok {
				nested["host_sync"] = payload["host_sync"]
				nested["rules_revision"] = payload["rules_revision"]
			}
			resp.Body, _ = json.Marshal(payload)
		}
	}
	return okEnvelope(resp)
}

func (m *Manager) handleCommandLineExecute(raw []byte) ([]byte, error) {
	var req pluginapi.CommandLineExecutionRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}

	flagVal := func(name string) string {
		if req.TriggeredFlags != nil {
			if v, ok := req.TriggeredFlags[name]; ok && v.Set {
				return v.Value
			}
		}
		if req.Flags != nil {
			if v, ok := req.Flags[name]; ok && v.Set {
				return v.Value
			}
		}
		return ""
	}

	showUsage := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsage))
	resetUsage := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsageReset))
	filterKey := strings.TrimSpace(flagVal(handler.FlagKeyUsageKey))
	asJSON := handler.ParseBoolFlag(flagVal(handler.FlagKeyUsageJSON))

	if !showUsage && !resetUsage && filterKey == "" && !asJSON {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{ExitCode: 0})
	}

	if resetUsage {
		if err := m.ResetUsage(filterKey); err != nil {
			return okEnvelope(pluginapi.CommandLineExecutionResponse{
				ExitCode: 1,
				Stderr:   []byte(fmt.Sprintf("Failed to reset usage statistics: %v\n", err)),
			})
		}
		targetDesc := "all API keys"
		if filterKey != "" {
			targetDesc = usage.MaskAPIKey(filterKey)
		}
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			ExitCode: 0,
			Stdout:   []byte(fmt.Sprintf("Usage statistics reset successfully for %s.\n", targetDesc)),
		})
	}

	snap := m.BuildSnapshot(filterKey, "", true)
	out, err := handler.FormatUsageSnapshot(snap, asJSON)
	if err != nil {
		return okEnvelope(pluginapi.CommandLineExecutionResponse{
			ExitCode: 1,
			Stderr:   []byte(fmt.Sprintf("Failed to format usage report: %v\n", err)),
		})
	}
	return okEnvelope(pluginapi.CommandLineExecutionResponse{
		ExitCode: 0,
		Stdout:   []byte(out),
	})
}

// ExtractCallerAPIKey extracts the caller's API key from a self-service resource request and checks if it matches AdminToken.
func (m *Manager) ExtractCallerAPIKey(req pluginapi.ManagementRequest) (apiKey string, isAdmin bool) {
	m.mu.RLock()
	adminToken := strings.TrimSpace(m.cfg.AdminToken)
	m.mu.RUnlock()

	token := ExtractAPIKeyFromHeadersAndQuery(req.Headers, req.Query)
	if adminToken != "" && token == adminToken {
		return "", true
	}
	if adminToken == "" && token == "" {
		return "", true
	}
	return token, false
}
