package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementSettings          = "/key-guard/settings"
	RouteManagementSettingsBootstrap = "/key-guard/settings/bootstrap"
)

type settingsProvider interface {
	GetRuntimeSettings() map[string]any
	SaveRuntimeSettings([]byte) (map[string]any, error)
	BootstrapSettings() map[string]any
	SaveBootstrapSettings([]byte) (map[string]any, error)
}

// Settings share the native management authentication boundary. Public resources
// and self-service credentials can never reach these writes.
func handleSettingsRequest(ctx context.Context, provider any, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	path := strings.TrimSpace(req.Path)
	if path != "/v0/management"+RouteManagementSettings && path != "/v0/management"+RouteManagementSettingsBootstrap {
		return jsonError(404, "unknown settings endpoint")
	}
	if !hasManagementCredential(req) {
		return jsonError(401, "management authentication required")
	}
	source, ok := provider.(settingsProvider)
	if !ok {
		return jsonError(503, "settings are unavailable")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if path == "/v0/management"+RouteManagementSettings {
		if method == http.MethodGet {
			payload := source.GetRuntimeSettings()
			payload["bootstrap"] = source.BootstrapSettings()
			return jsonResponse(200, payload)
		}
		if method != http.MethodPut {
			return jsonError(405, "method not allowed")
		}
		if len(req.Body) == 0 || len(req.Body) > 65536 {
			return jsonError(400, "invalid settings request size")
		}
		payload, err := source.SaveRuntimeSettings(req.Body)
		if err != nil {
			return settingsError(err)
		}
		payload["bootstrap"] = source.BootstrapSettings()
		return jsonResponse(200, payload)
	}
	if method == http.MethodGet {
		return jsonResponse(200, map[string]any{"bootstrap": source.BootstrapSettings()})
	}
	if method != http.MethodPut {
		return jsonError(405, "method not allowed")
	}
	if len(req.Body) == 0 || len(req.Body) > 16384 {
		return jsonError(400, "invalid bootstrap request size")
	}
	payload, err := source.SaveBootstrapSettings(req.Body)
	if err != nil {
		return settingsError(err)
	}
	return jsonResponse(200, payload)
}
func settingsError(err error) pluginapi.ManagementResponse {
	var bootstrap interface{ SettingsBootstrapCode() string }
	var runtime interface{ SettingsCode() string }
	code := "unavailable"
	if errors.As(err, &bootstrap) {
		code = bootstrap.SettingsBootstrapCode()
	} else if errors.As(err, &runtime) {
		code = runtime.SettingsCode()
	}
	switch code {
	case "conflict", "revision":
		return jsonError(409, "settings changed; reload before saving")
	case "invalid", "confirmation", "ack_prune":
		return jsonError(400, "invalid settings or required confirmation is missing")
	default:
		return jsonError(503, "settings were not applied; check persistence and retry")
	}
}
