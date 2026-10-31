package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/YzMzx/cpa-plugin-key-manager/web"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementOverview      = "/key-guard/overview"
	RouteManagementKeys          = "/key-guard/keys"
	RouteManagementKeysSync      = "/key-guard/keys/sync"
	RouteManagementKeysReorder   = "/key-guard/keys/reorder"
	RouteManagementDefaultPolicy = "/key-guard/default-policy"
	RouteManagementAuthFiles     = "/key-guard/auth-files"
	RouteManagementUsage         = "/key-guard/usage"
	RouteManagementReset         = "/key-guard/usage/reset"
	RouteManagementPricing       = "/key-guard/pricing"
	RouteManagementPriceSync     = "/key-guard/pricing/sync"
	RouteManagementPriceCustom   = "/key-guard/pricing/custom"
	RouteManagementLedger        = "/key-guard/ledger"

	ResourcePathUI    = "/ui"
	ResourcePathUsage = "/usage"
)

// RegisterManagementEndpoints returns the management routes (`/v0/management/...`) and
// self-service/dashboard resource routes (`/v0/resource/plugins/cpa-plugin-key-manager/...`).
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
			Path:        RouteManagementKeysReorder,
			Description: "Persist the drag & drop display order of API keys.",
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
		{
			Method:      http.MethodGet,
			Path:        RouteManagementLedger,
			Description: "Query the hourly usage ledger for the overview dashboard (time range, key, account, model and source filters).",
		},
	}

	resources := []pluginapi.ResourceRoute{
		{
			Path:        ResourcePathUI,
			Menu:        "API Key 管控与用量",
			Description: "统一管理 CPA 全局 API Key、并发限流、模型白名单、上游凭证绑定及 Token 用量统计。",
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
	ReorderKeys(keys []string) error
	UpsertKeyRuleFromJSON(rawBody []byte) (any, error)
	DeleteKeyRule(apiKey string) error
	SaveDefaultPolicyFromJSON(rawBody []byte) (any, error)
	ListHostAuthFiles(hostCallbackID string) ([]pluginapi.HostAuthFileEntry, error)
	UpsertCustomPrice(model string, price pricing.ModelPrice) error
	DeleteCustomPrice(model string) error
	QueryLedger(q usage.LedgerQuery) usage.LedgerResult
	BuildSelfAccountView(apiKey string) (map[string]any, int, error)
}

// HandleManagementRequest dispatches incoming HTTP requests from `management.handle`.
func HandleManagementRequest(ctx context.Context, provider SnapshotProvider, req pluginapi.ManagementRequest, hostCallbackID string) pluginapi.ManagementResponse {
	path := strings.TrimSpace(req.Path)
	method := strings.ToUpper(strings.TrimSpace(req.Method))

	if strings.HasSuffix(path, ResourcePathUI) {
		if method != http.MethodGet && method != http.MethodHead {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		if queryValue(req, "op") != "" {
			return jsonError(http.StatusUnauthorized, "unauthorized: management authentication required via /v0/management/key-guard/*")
		}
		return htmlShellResponse(web.DashboardHTML())
	}

	if !hasManagementCredential(req) {
		return jsonError(http.StatusUnauthorized, "unauthorized: valid CLIProxyAPI Management Key is required")
	}

	switch {
	case strings.HasSuffix(path, RouteManagementOverview):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		return jsonResponse(http.StatusOK, provider.BuildAdminOverview(hostCallbackID))

	case strings.HasSuffix(path, RouteManagementKeysReorder):
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
		if err := provider.ReorderKeys(body.Keys); err != nil {
			return jsonError(http.StatusBadRequest, err.Error())
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
			origKey := queryValue(req, "orig_key")
			var tmp struct {
				OrigKey string `json:"orig_key"`
				APIKey  string `json:"api_key"`
			}
			_ = json.Unmarshal(req.Body, &tmp)
			if origKey == "" {
				origKey = strings.TrimSpace(tmp.OrigKey)
			}
			if origKey != "" && strings.TrimSpace(tmp.APIKey) != "" && strings.TrimSpace(tmp.APIKey) != origKey {
				_ = provider.DeleteKeyRule(origKey)
			}
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

	case strings.HasSuffix(path, RouteManagementLedger):
		if method != http.MethodGet {
			return jsonError(http.StatusMethodNotAllowed, "method not allowed")
		}
		q := usage.LedgerQuery{
			From:        parseTimeParam(queryValue(req, "from")),
			To:          parseTimeParam(queryValue(req, "to")),
			Granularity: queryValue(req, "granularity"),
			Key:         queryValue(req, "key"),
			Account:     queryValue(req, "account"),
			Model:       queryValue(req, "model"),
			Source:      queryValue(req, "source"),
			Timezone:    queryValue(req, "tz"),
		}
		if q.Timezone == "" {
			q.Timezone = "Local"
		}
		return jsonResponse(http.StatusOK, provider.QueryLedger(q))

	default:
		return jsonError(http.StatusNotFound, "unknown endpoint: "+path)
	}
}

func hasManagementCredential(req pluginapi.ManagementRequest) bool {
	if strings.HasPrefix(strings.TrimSpace(req.Path), "/v0/resource/") {
		return false
	}
	if req.Headers == nil {
		return false
	}
	auth := strings.TrimSpace(req.Headers.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		auth = strings.TrimSpace(auth[7:])
	}
	if auth != "" {
		return true
	}
	return strings.TrimSpace(req.Headers.Get("X-Management-Key")) != ""
}

func queryValue(req pluginapi.ManagementRequest, key string) string {
	if req.Query == nil {
		return ""
	}
	return strings.TrimSpace(req.Query.Get(key))
}

// parseTimeParam accepts RFC3339, a plain date (YYYY-MM-DD) or unix seconds.
func parseTimeParam(raw string) time.Time {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed
	}
	if parsed, err := time.ParseInLocation("2006-01-02", value, time.Local); err == nil {
		return parsed
	}
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(secs, 0)
	}
	return time.Time{}
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
			"Content-Type":  {"application/json; charset=utf-8"},
			"Cache-Control": {"no-store"},
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
			"Content-Type":  {contentType},
			"Cache-Control": {"no-store"},
		},
		Body: []byte(body),
	}
}

func htmlShellResponse(body string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Cache-Control":           {"no-store, no-cache, must-revalidate"},
			"Pragma":                  {"no-cache"},
			"X-Content-Type-Options":  {"nosniff"},
			"X-Frame-Options":         {"SAMEORIGIN"},
			"Content-Security-Policy": {"frame-ancestors 'self'"},
		},
		Body: []byte(body),
	}
}
