package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/pricing"
	"github.com/YzMzx/cpa-plugin-key/internal/usage"
)

const (
	RouteManagementUsage     = "/key-guard/usage"
	RouteManagementReset     = "/key-guard/usage/reset"
	RouteManagementPricing   = "/key-guard/pricing"
	RouteManagementPriceSync = "/key-guard/pricing/sync"
	ResourcePathUsage        = "/usage"
)

// RegisterManagementEndpoints returns the management routes (`/v0/management/...`) and
// self-service/dashboard resource routes (`/v0/resource/plugins/cpa-plugin-key/...`).
func RegisterManagementEndpoints() ([]pluginapi.ManagementRoute, []pluginapi.ResourceRoute) {
	routes := []pluginapi.ManagementRoute{
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
			Description: "Inspect models.dev pricing sync status and configured custom model price overrides.",
		},
		{
			Method:      http.MethodPost,
			Path:        RouteManagementPriceSync,
			Description: "Trigger an immediate models.dev reference pricing synchronization.",
		},
	}

	resources := []pluginapi.ResourceRoute{
		{
			Path:        ResourcePathUsage,
			Menu:        "API Key Billing & Governance",
			Description: "View per-API-Key concurrency, token usage, and USD billing dashboard (supports ?format=json or ?api_key=...).",
		},
	}
	return routes, resources
}

// SnapshotProvider supplies current snapshots and operations to the HTTP management handler.
type SnapshotProvider interface {
	BuildSnapshot(filterAPIKey, filterModel string, maskKeys bool) usage.PersistedSnapshot
	ResetUsage(apiKey string) error
	PricingStatus() pricing.Status
	LookupModelPrice(model string) (pricing.ModelPrice, bool)
	TriggerPricingSync(ctx context.Context) (int, error)
	ExtractCallerAPIKey(req pluginapi.ManagementRequest) (apiKey string, isAdmin bool)
}

// HandleManagementRequest dispatches incoming HTTP requests from `management.handle`.
func HandleManagementRequest(ctx context.Context, provider SnapshotProvider, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	path := strings.TrimSpace(req.Path)
	method := strings.ToUpper(strings.TrimSpace(req.Method))

	switch {
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
		filterModel := queryValue(req, "model")
		filterKey := callerKey
		if isAdmin {
			// Admin can query all keys or filter by ?api_key=
			filterKey = queryValue(req, "api_key")
		}
		snap := provider.BuildSnapshot(filterKey, filterModel, true)
		format := strings.ToLower(queryValue(req, "format"))
		accept := ""
		if req.Headers != nil {
			accept = strings.ToLower(req.Headers.Get("Accept"))
		}
		if format == "json" || strings.Contains(accept, "application/json") {
			return jsonResponse(http.StatusOK, snap)
		}
		if format == "table" || format == "text" {
			return textResponse(http.StatusOK, "text/plain; charset=utf-8", RenderUsageTable(snap))
		}
		return textResponse(http.StatusOK, "text/html; charset=utf-8", renderHTMLDashboard(snap, provider.PricingStatus()))

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

func renderHTMLDashboard(snap usage.PersistedSnapshot, pStatus pricing.Status) string {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>API Key Governance & Billing</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }
  h1 { font-size: 20px; margin-bottom: 6px; color: #f8fafc; }
  .meta { font-size: 13px; color: #94a3b8; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }
  th { background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .model-row td { color: #cbd5e1; background: #172033; padding-left: 28px; font-size: 12px; }
  .cost { color: #38bdf8; font-weight: 600; font-family: monospace; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #334155; font-size: 12px; }
</style>
</head>
<body>
<h1>CLIProxyAPI - API Key Governance & Billing</h1>
`)
	fmt.Fprintf(&b, `<div class="meta">Updated: %s | models.dev Synced Keys: %d | Last Sync: %s</div>`,
		html.EscapeString(snap.UpdatedAt),
		pStatus.SyncedModelKeys,
		html.EscapeString(pStatus.LastSyncAt),
	)
	b.WriteString(`<table>
<thead>
  <tr>
    <th>API Key / Model</th>
    <th>Name</th>
    <th>Concurrency</th>
    <th>Requests (OK / Err)</th>
    <th>Input Tokens</th>
    <th>Output Tokens</th>
    <th>Cache (Read / Write)</th>
    <th>Total Tokens</th>
    <th>Cost (USD)</th>
  </tr>
</thead>
<tbody>
`)
	keyIDs := usage.SortedKeyIDs(snap.Keys)
	if len(keyIDs) == 0 {
		b.WriteString(`<tr><td colspan="9">No API Key usage records yet.</td></tr>`)
	}
	for _, k := range keyIDs {
		ks := snap.Keys[k]
		if ks == nil {
			continue
		}
		conc := fmt.Sprintf("%d / ∞", ks.ActiveConcurrency)
		if ks.MaxConcurrency > 0 {
			conc = fmt.Sprintf("%d / %d", ks.ActiveConcurrency, ks.MaxConcurrency)
		}
		fmt.Fprintf(&b, `<tr>
  <td><strong>%s</strong></td>
  <td>%s</td>
  <td><span class="badge">%s</span></td>
  <td>%d (%d / %d)</td>
  <td>%d</td>
  <td>%d</td>
  <td>%d / %d</td>
  <td>%d</td>
  <td class="cost">%s</td>
</tr>`,
			html.EscapeString(ks.MaskedKey),
			html.EscapeString(ks.KeyName),
			html.EscapeString(conc),
			ks.TotalRequests, ks.SuccessRequests, ks.FailedRequests,
			ks.InputTokens, ks.OutputTokens,
			ks.CacheReadTokens, ks.CacheWriteTokens,
			ks.TotalTokens,
			html.EscapeString(ks.TotalCostFormatted),
		)

		if len(ks.Models) > 0 {
			models := make([]string, 0, len(ks.Models))
			for m := range ks.Models {
				models = append(models, m)
			}
			sort.Strings(models)
			for _, m := range models {
				ms := ks.Models[m]
				fmt.Fprintf(&b, `<tr class="model-row">
  <td>↳ %s</td>
  <td><small>price: $%.2f/$%.2f (%s)</small></td>
  <td>-</td>
  <td>%d (%d / %d)</td>
  <td>%d</td>
  <td>%d</td>
  <td>%d / %d</td>
  <td>%d</td>
  <td class="cost">%s</td>
</tr>`,
					html.EscapeString(ms.Model),
					ms.UnitPricePer1M.Input, ms.UnitPricePer1M.Output, html.EscapeString(ms.UnitPricePer1M.Source),
					ms.Requests, ms.SuccessRequests, ms.FailedRequests,
					ms.InputTokens, ms.OutputTokens,
					ms.CacheReadTokens, ms.CacheWriteTokens,
					ms.TotalTokens,
					html.EscapeString(ms.CostFormatted),
				)
			}
		}
	}
	b.WriteString(`</tbody></table></body></html>`)
	return b.String()
}
