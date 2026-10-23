package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key/internal/usage"
	"github.com/YzMzx/cpa-plugin-key/web"
)

const (
	RouteManagementOverview      = "/key-guard/overview"
	RouteManagementKeys          = "/key-guard/keys"
	RouteManagementKeysSync      = "/key-guard/keys/sync"
	RouteManagementDefaultPolicy = "/key-guard/default-policy"
	RouteManagementAuthFiles     = "/key-guard/auth-files"
	RouteManagementUsage         = "/key-guard/usage"
	RouteManagementReset         = "/key-guard/usage/reset"
	RouteManagementPricing       = "/key-guard/pricing"
	RouteManagementPriceSync     = "/key-guard/pricing/sync"
	RouteManagementPriceCustom   = "/key-guard/pricing/custom"

	ResourcePathUI    = "/ui"
	ResourcePathUsage = "/usage"
)

// RegisterManagementEndpoints returns the management routes (`/v0/management/...`) and
// self-service/dashboard resource routes (`/v0/resource/plugins/cpa-plugin-key/...`).
func RegisterManagementEndpoints() ([]pluginapi.ManagementRoute, []pluginapi.ResourceRoute) {
	routes := []pluginapi.ManagementRoute{
		{
			Method:      http.MethodGet,
			Path:        RouteManagementOverview,
			Description: "Return complete admin dashboard state (KPI summary, keys, default_policy, usage, host auth files, available models, pricing status).",
		},
		{
			Method:      http.MethodGet,
			Path:        RouteManagementKeys,
			Description: "List all configured API key rules and default policy.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementKeys,
			Description: "Create or update an API key rule and persist to key_guard_rules.json.",
		},
		{
			Method:      http.MethodDelete,
			Path:        RouteManagementKeys,
			Description: "Delete an API key rule and persist to key_guard_rules.json.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementKeysSync,
			Description: "Synchronize global API keys from CLIProxyAPI config.yaml (/v0/management/api-keys) with plugin governance rules.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementDefaultPolicy,
			Description: "Update global default policy for unlisted API keys and persist to key_guard_rules.json.",
		},
		{
			Method:      http.MethodGet,
			Path:        RouteManagementAuthFiles,
			Description: "Query available upstream credentials from CLIProxyAPI host via host.auth.list.",
		},
		{
			Method:      http.MethodGet,
			Path:        RouteManagementUsage,
			Description: "Query per-API-Key and per-Model token usage, active concurrency, and USD cost statistics.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementReset,
			Description: "Reset accumulated token usage and USD cost statistics (globally or for a specific api_key).",
		},
		{
			Method:      http.MethodGet,
			Path:        RouteManagementPricing,
			Description: "Inspect models.dev pricing sync status, search reference prices, and view custom model price overrides.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementPriceSync,
			Description: "Trigger an immediate models.dev reference pricing synchronization.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementPriceCustom,
			Description: "Create or update a custom model price override and persist to key_guard_rules.json.",
		},
		{
			Method:      http.MethodDelete,
			Path:        RouteManagementPriceCustom,
			Description: "Delete a custom model price override and persist to key_guard_rules.json.",
		},
	}

	resources := []pluginapi.ResourceRoute{
		{
			Path:        ResourcePathUI,
			Menu:        "API Key 计费与管控",
			Description: "可视化管理下游 API Key、并发限流、配额上限、模型白名单、上游凭证绑定及 Token/USD 实时账单（支持 #account 用户自查模式）。",
		},
		{
			Path:        ResourcePathUsage,
			Description: "API Key 实时并发、配额与 Token/USD 账单自查接口 (支持 ?format=json 或 #account 自查)。",
		},
	}
	return routes, resources
}

// SnapshotProvider supplies current snapshots and CRUD operations to the HTTP management handler.
type SnapshotProvider interface {
	BuildSnapshot(filterAPIKey, filterModel string, maskKeys bool) usage.PersistedSnapshot
	ResetUsage(apiKey string) error
	PricingStatus() pricing.Status
	LookupModelPrice(model string) (pricing.ModelPrice, bool)
	SearchReferencePrices(query string, limit int) []pricing.ReferenceModelEntry
	TriggerPricingSync(ctx context.Context) (int, error)
	ExtractCallerAPIKey(req pluginapi.ManagementRequest) (apiKey string, isAdmin bool)

	BuildAdminOverview(hostCallbackID string) map[string]any
	ListKeyRulesAndDefaultPolicy() map[string]any
	SyncHostAPIKeys(keys []string) error
	UpsertKeyRuleFromJSON(rawBody []byte) (any, error)
	DeleteKeyRule(apiKey string) error
	SaveDefaultPolicyFromJSON(rawBody []byte) (any, error)
	ListHostAuthFiles(hostCallbackID string) ([]pluginapi.HostAuthFileEntry, error)
	UpsertCustomPrice(model string, price pricing.ModelPrice) error
	DeleteCustomPrice(model string) error
	BuildSelfAccountView(apiKey string) (map[string]any, int, error)
}

// HandleManagementRequest dispatches incoming HTTP requests from `management.handle`.
func HandleManagementRequest(ctx context.Context, provider SnapshotProvider, req pluginapi.ManagementRequest, hostCallbackID string) pluginapi.ManagementResponse {
	path := strings.TrimSpace(req.Path)
	method := strings.ToUpper(strings.TrimSpace(req.Method))

	switch {
	case strings.HasSuffix(path, ResourcePathUI):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		return textResponse(http.StatusOK, "text/html; charset=utf-8", web.DashboardHTML())

	case strings.HasSuffix(path, RouteManagementOverview):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		return jsonResponse(http.StatusOK, provider.BuildAdminOverview(hostCallbackID))

	case strings.HasSuffix(path, RouteManagementKeysSync):
		if method != http.MethodPost && method != http.MethodPut {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		var body struct {
			Keys []string `json:"keys"`
		}
		if len(req.Body) > 0 {
			if err := json.Unmarshal(req.Body, &body); err != nil {
				return jsonError(http.StatusBadRequest, "invalid JSON body: "+err.Error())
			}
		}
		if err := provider.SyncHostAPIKeys(body.Keys); err != nil {
			return jsonError(http.StatusInternalServerError, err.Error())
		}
		return jsonResponse(http.StatusOK, provider.BuildAdminOverview(hostCallbackID))

	case strings.HasSuffix(path, RouteManagementKeys):
		switch method {
		case http.MethodGet:
			return jsonResponse(http.StatusOK, provider.ListKeyRulesAndDefaultPolicy())
		case http.MethodPost, http.MethodPut:
			rule, err := provider.UpsertKeyRuleFromJSON(req.Body)
			if err != nil {
				return jsonError(http.StatusBadRequest, err.Error())
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"ok":   true,
				"rule": rule,
			})
		case http.MethodDelete:
			targetKey := queryValue(req, "api_key")
			if targetKey == "" && len(req.Body) > 0 {
				var body struct {
					APIKey string `json:"api_key"`
				}
				_ = json.Unmarshal(req.Body, &body)
				targetKey = strings.TrimSpace(body.APIKey)
			}
			if targetKey == "" {
				return jsonError(http.StatusBadRequest, "api_key is required")
			}
			if err := provider.DeleteKeyRule(targetKey); err != nil {
				return jsonError(http.StatusInternalServerError, err.Error())
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"ok":      true,
				"deleted": usage.MaskAPIKey(targetKey),
			})
		default:
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}

	case strings.HasSuffix(path, RouteManagementDefaultPolicy):
		if method != http.MethodPost && method != http.MethodPut {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		policy, err := provider.SaveDefaultPolicyFromJSON(req.Body)
		if err != nil {
			return jsonError(http.StatusBadRequest, err.Error())
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"ok":             true,
			"default_policy": policy,
		})

	case strings.HasSuffix(path, RouteManagementAuthFiles):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		files, err := provider.ListHostAuthFiles(hostCallbackID)
		if err != nil {
			return jsonResponse(http.StatusOK, map[string]any{
				"files":   files,
				"warning": err.Error(),
			})
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"files": files,
		})

	case strings.HasSuffix(path, RouteManagementUsage):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		filterKey := queryValue(req, "api_key")
		filterModel := queryValue(req, "model")
		maskKeys := queryValue(req, "unmask") != "true"
		format := strings.ToLower(queryValue(req, "format"))
		snap := provider.BuildSnapshot(filterKey, filterModel, maskKeys)
		if format == "table" || format == "text" {
			return textResponse(http.StatusOK, "text/plain; charset=utf-8", RenderUsageTable(snap))
		}
		return jsonResponse(http.StatusOK, snap)

	case strings.HasSuffix(path, RouteManagementReset):
		if method != http.MethodPost && method != http.MethodDelete {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		targetKey := queryValue(req, "api_key")
		if targetKey == "" && len(req.Body) > 0 {
			var body struct {
				APIKey string `json:"api_key"`
			}
			_ = json.Unmarshal(req.Body, &body)
			targetKey = strings.TrimSpace(body.APIKey)
		}
		if err := provider.ResetUsage(targetKey); err != nil {
			return jsonError(http.StatusInternalServerError, err.Error())
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"ok":      true,
			"message": "usage statistics reset successfully",
			"api_key": usage.MaskAPIKey(targetKey),
		})

	case strings.HasSuffix(path, RouteManagementPriceCustom):
		switch method {
		case http.MethodPost, http.MethodPut:
			var body struct {
				Model string             `json:"model"`
				Price pricing.ModelPrice `json:"price"`
			}
			if err := json.Unmarshal(req.Body, &body); err != nil {
				return jsonError(http.StatusBadRequest, "invalid JSON body: "+err.Error())
			}
			if strings.TrimSpace(body.Model) == "" {
				return jsonError(http.StatusBadRequest, "model is required")
			}
			if err := provider.UpsertCustomPrice(body.Model, body.Price); err != nil {
				return jsonError(http.StatusInternalServerError, err.Error())
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"ok":     true,
				"model":  strings.ToLower(strings.TrimSpace(body.Model)),
				"price":  body.Price,
				"status": provider.PricingStatus(),
			})
		case http.MethodDelete:
			targetModel := queryValue(req, "model")
			if targetModel == "" && len(req.Body) > 0 {
				var body struct {
					Model string `json:"model"`
				}
				_ = json.Unmarshal(req.Body, &body)
				targetModel = strings.TrimSpace(body.Model)
			}
			if targetModel == "" {
				return jsonError(http.StatusBadRequest, "model is required")
			}
			if err := provider.DeleteCustomPrice(targetModel); err != nil {
				return jsonError(http.StatusInternalServerError, err.Error())
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"ok":      true,
				"deleted": strings.ToLower(strings.TrimSpace(targetModel)),
				"status":  provider.PricingStatus(),
			})
		default:
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}

	case strings.HasSuffix(path, RouteManagementPricing):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		status := provider.PricingStatus()
		modelQuery := queryValue(req, "model")
		if modelQuery != "" {
			price, found := provider.LookupModelPrice(modelQuery)
			return jsonResponse(http.StatusOK, map[string]any{
				"status": status,
				"query": map[string]any{
					"model": modelQuery,
					"found": found,
					"price": price,
				},
			})
		}
		if req.Query != nil && req.Query.Has("search") {
			searchQuery := queryValue(req, "search")
			limit := 100
			if rawLim := queryValue(req, "limit"); rawLim != "" {
				if parsed, err := strconv.Atoi(rawLim); err == nil && parsed > 0 {
					limit = parsed
				}
			}
			refModels := provider.SearchReferencePrices(searchQuery, limit)
			return jsonResponse(http.StatusOK, map[string]any{
				"status":           status,
				"reference_models": refModels,
			})
		}
		return jsonResponse(http.StatusOK, status)

	case strings.HasSuffix(path, RouteManagementPriceSync):
		if method != http.MethodPost {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		count, err := provider.TriggerPricingSync(ctx)
		if err != nil {
			return jsonResponse(http.StatusBadGateway, map[string]any{
				"ok":     false,
				"error":  err.Error(),
				"status": provider.PricingStatus(),
			})
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"ok":            true,
			"synced_models": count,
			"status":        provider.PricingStatus(),
		})

	case strings.HasSuffix(path, ResourcePathUsage):
		callerKey, isAdmin := provider.ExtractCallerAPIKey(req)
		mode := strings.ToLower(queryValue(req, "mode"))
		if mode == "account" && strings.TrimSpace(callerKey) == "" {
			return jsonError(http.StatusUnauthorized, "请输入有效的下游 API Key")
		}
		if mode == "account" {
			selfView, status, err := provider.BuildSelfAccountView(callerKey)
			if err != nil {
				return jsonError(status, err.Error())
			}
			return jsonResponse(http.StatusOK, selfView)
		}

		filterModel := queryValue(req, "model")
		filterKey := callerKey
		if isAdmin {
			filterKey = queryValue(req, "api_key")
		}
		snap := provider.BuildSnapshot(filterKey, filterModel, true)
		format := strings.ToLower(queryValue(req, "format"))
		accept := ""
		if req.Headers != nil {
			accept = strings.ToLower(req.Headers.Get("Accept"))
		}
		if format == "json" || strings.Contains(accept, "application/json") {
			if callerKey != "" && !isAdmin {
				if selfView, status, err := provider.BuildSelfAccountView(callerKey); err == nil && status == http.StatusOK {
					selfView["version"] = snap.Version
					selfView["updated_at"] = snap.UpdatedAt
					selfView["keys"] = snap.Keys
					return jsonResponse(http.StatusOK, selfView)
				}
			}
			return jsonResponse(http.StatusOK, snap)
		}
		if format == "table" || format == "text" {
			return textResponse(http.StatusOK, "text/plain; charset=utf-8", RenderUsageTable(snap))
		}
		return textResponse(http.StatusOK, "text/html; charset=utf-8", web.DashboardHTML())

	default:
		return jsonError(http.StatusNotFound, "unknown endpoint: "+path)
	}
}

func queryValue(req pluginapi.ManagementRequest, key string) string {
	if req.Query == nil {
		return ""
	}
	return strings.TrimSpace(req.Query.Get(key))
}

func jsonResponse(statusCode int, payload any) pluginapi.ManagementResponse {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		raw = []byte(`{"error":"failed to encode response"}`)
		statusCode = http.StatusInternalServerError
	}
	return pluginapi.ManagementResponse{
		StatusCode: statusCode,
		Headers: http.Header{
			"Content-Type": {"application/json; charset=utf-8"},
		},
		Body: raw,
	}
}

func jsonError(statusCode int, message string) pluginapi.ManagementResponse {
	return jsonResponse(statusCode, map[string]any{
		"error": map[string]any{
			"message": message,
			"status":  statusCode,
		},
	})
}

func textResponse(statusCode int, contentType, body string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: statusCode,
		Headers: http.Header{
			"Content-Type": {contentType},
		},
		Body: []byte(body),
	}
}
