package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	RouteManagementIntercept       = "/key-guard/intercept"
	RouteManagementInterceptConfig = RouteManagementIntercept + "/config"
	RouteManagementInterceptEvents = RouteManagementIntercept + "/events"
	RouteManagementInterceptDetail = RouteManagementInterceptEvents + "/detail"
	RouteManagementInterceptReview = RouteManagementInterceptEvents + "/review"
	RouteManagementInterceptExport = RouteManagementInterceptEvents + "/export"
	RouteManagementInterceptTest   = RouteManagementIntercept + "/test"
	RouteManagementInterceptStatus = RouteManagementIntercept + "/status"
)

type interceptProvider interface {
	GetInterceptConfig() map[string]any
	SaveInterceptConfig([]byte) (map[string]any, error)
	TestInterceptRules(context.Context, []byte) (map[string]any, error)
	InterceptStatus(context.Context) (map[string]any, error)
	QueryInterceptEvents(context.Context, contentguard.Query) (map[string]any, error)
	InterceptEventDetail(context.Context, string) (map[string]any, error)
	ReviewInterceptEvent(context.Context, []byte) (map[string]any, error)
	ExportInterceptEvents(context.Context, []byte) (map[string]any, error)
}

// Routes are registered only with the host's native management middleware.
// Credential presence here is a boundary check, never a secret verifier.
func handleInterceptRequest(ctx context.Context, provider any, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var method string
	var allowed []string
	switch req.Path {
	case "/v0/management" + RouteManagementInterceptConfig:
		method = http.MethodGet + "," + http.MethodPut
	case "/v0/management" + RouteManagementInterceptEvents:
		method = http.MethodGet
		allowed = []string{"limit", "offset", "from", "to", "key_fingerprint", "action", "severity", "review", "rule", "model", "request_id"}
	case "/v0/management" + RouteManagementInterceptDetail:
		method, allowed = http.MethodGet, []string{"id"}
	case "/v0/management" + RouteManagementInterceptReview, "/v0/management" + RouteManagementInterceptExport, "/v0/management" + RouteManagementInterceptTest:
		method = http.MethodPost
	case "/v0/management" + RouteManagementInterceptStatus:
		method = http.MethodGet
	default:
		return jsonError(http.StatusNotFound, "unknown intercept endpoint")
	}
	if !hasManagementCredential(req) {
		return jsonError(http.StatusUnauthorized, "management authentication required")
	}
	methodAllowed := false
	for _, candidate := range strings.Split(method, ",") {
		if req.Method == candidate {
			methodAllowed = true
		}
	}
	if !methodAllowed {
		return jsonError(http.StatusMethodNotAllowed, "method not allowed")
	}
	for key, values := range req.Query {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found || len(values) != 1 || len(values[0]) > 1024 || strings.TrimSpace(values[0]) == "" {
			return jsonError(400, "invalid intercept query")
		}
	}
	if req.Method == http.MethodGet && len(req.Body) != 0 {
		return jsonError(400, "unexpected request body")
	}
	if req.Method != http.MethodGet {
		maximum := 16 << 10
		if req.Path == "/v0/management"+RouteManagementInterceptConfig {
			maximum = 2 << 20
		}
		if req.Path == "/v0/management"+RouteManagementInterceptTest {
			maximum = 12 << 20
		}
		if len(req.Body) == 0 || len(req.Body) > maximum {
			return jsonError(400, "invalid intercept request size")
		}
	}
	source, ok := provider.(interceptProvider)
	if !ok {
		return jsonError(503, "intercept is unavailable")
	}
	timeout := 5 * time.Second
	if req.Path == "/v0/management"+RouteManagementInterceptTest {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var value map[string]any
	var err error
	switch req.Path {
	case "/v0/management" + RouteManagementInterceptConfig:
		if req.Method == http.MethodGet {
			value = source.GetInterceptConfig()
		} else {
			value, err = source.SaveInterceptConfig(req.Body)
		}
	case "/v0/management" + RouteManagementInterceptStatus:
		value, err = source.InterceptStatus(ctx)
	case "/v0/management" + RouteManagementInterceptTest:
		value, err = source.TestInterceptRules(ctx, req.Body)
	case "/v0/management" + RouteManagementInterceptDetail:
		id := queryValue(req, "id")
		if id == "" {
			return jsonError(400, "event id is required")
		}
		value, err = source.InterceptEventDetail(ctx, id)
	case "/v0/management" + RouteManagementInterceptReview:
		value, err = source.ReviewInterceptEvent(ctx, req.Body)
	case "/v0/management" + RouteManagementInterceptExport:
		value, err = source.ExportInterceptEvents(ctx, req.Body)
	case "/v0/management" + RouteManagementInterceptEvents:
		q := contentguard.Query{Limit: 50, KeyFingerprint: queryValue(req, "key_fingerprint"), Action: queryValue(req, "action"), Severity: queryValue(req, "severity"), Review: queryValue(req, "review"), Rule: queryValue(req, "rule"), Model: queryValue(req, "model"), RequestID: queryValue(req, "request_id")}
		if raw := queryValue(req, "limit"); raw != "" {
			q.Limit, err = strconv.Atoi(raw)
			if err != nil || q.Limit < 1 || q.Limit > contentguard.MaxQueryLimit {
				return jsonError(400, "invalid pagination limit")
			}
		}
		if raw := queryValue(req, "offset"); raw != "" {
			q.Offset, err = strconv.Atoi(raw)
			if err != nil || q.Offset < 0 || q.Offset > contentguard.MaxQueryOffset {
				return jsonError(400, "invalid pagination offset")
			}
		}
		zone := ""
		if cfg, ok := provider.(interface{ ConfiguredTimezone() string }); ok {
			zone = cfg.ConfiguredTimezone()
		}
		for _, key := range []string{"from", "to"} {
			if raw := queryValue(req, key); raw != "" {
				parsed, e := parseTimeParamInZone(raw, zone)
				if e != nil || parsed.UnixMilli() <= 0 {
					return jsonError(400, "invalid event time")
				}
				if key == "from" {
					q.From = parsed.UnixMilli()
				} else {
					q.To = parsed.UnixMilli()
				}
			}
		}
		if q.From > 0 && q.To > 0 && q.From > q.To {
			return jsonError(400, "invalid event time range")
		}
		value, err = source.QueryInterceptEvents(ctx, q)
	}
	if err != nil {
		return interceptError(err)
	}
	return jsonResponse(http.StatusOK, value)
}

func interceptError(err error) pluginapi.ManagementResponse {
	var coded interface{ InterceptCode() string }
	if errors.As(err, &coded) {
		switch coded.InterceptCode() {
		case "revision":
			return jsonError(409, "intercept configuration changed; reload before saving")
		case "ack_prune":
			return jsonError(400, "confirmation is required before reducing retention or capacity")
		case "invalid":
			return jsonError(400, "invalid intercept request")
		}
	}
	switch {
	case errors.Is(err, contentguard.ErrNotFound):
		return jsonError(404, "intercept event not found")
	case errors.Is(err, contentguard.ErrInvalid), errors.Is(err, contentguard.ErrInvalidQuery):
		return jsonError(400, "invalid intercept request")
	default:
		return jsonError(503, "intercept is unavailable; retry later")
	}
}
