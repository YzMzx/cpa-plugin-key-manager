package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// ErrorPayload represents a dual-compatible (OpenAI + Anthropic Claude) error response body.
//   - OpenAI clients read: root.error.{message, type, code, param}
//   - Anthropic clients read: root.type == "error" and root.error.{type, message}
type ErrorPayload struct {
	Type  string      `json:"type"`
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries structured error fields compatible with OpenAI and Anthropic SDKs.
type ErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Param   any    `json:"param,omitempty"`
}

// BuildErrorBody constructs a JSON byte slice compatible with both OpenAI and Anthropic error formats.
func BuildErrorBody(statusCode int, errType, code, message string) []byte {
	if strings.TrimSpace(errType) == "" {
		switch statusCode {
		case http.StatusUnauthorized:
			errType = "authentication_error"
		case http.StatusForbidden:
			errType = "permission_error"
		case http.StatusTooManyRequests:
			errType = "rate_limit_error"
		default:
			errType = "invalid_request_error"
		}
	}
	if strings.TrimSpace(code) == "" {
		switch statusCode {
		case http.StatusUnauthorized:
			code = "invalid_api_key"
		case http.StatusForbidden:
			code = "model_not_allowed"
		case http.StatusTooManyRequests:
			code = "concurrency_limit_exceeded"
		default:
			code = "request_rejected"
		}
	}
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(statusCode)
	}

	payload := ErrorPayload{
		Type: "error",
		Error: ErrorDetail{
			Message: message,
			Type:    errType,
			Code:    code,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return []byte(fmt.Sprintf(`{"type":"error","error":{"type":%q,"code":%q,"message":%q}}`, errType, code, message))
	}
	return raw
}

// NewForbiddenModelResponse returns a terminated RequestInterceptResponse with HTTP 403 Forbidden.
func NewForbiddenModelResponse(model string) pluginapi.RequestInterceptResponse {
	msg := fmt.Sprintf("API key is not authorized to access model %q", model)
	if strings.TrimSpace(model) == "" {
		msg = "API key is not authorized to access the requested model"
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: headers,
		ResponseBody:    BuildErrorBody(http.StatusForbidden, "permission_error", "model_not_allowed", msg),
	}
}

// NewForbiddenKeyResponse returns a terminated RequestInterceptResponse with HTTP 403 Forbidden for disabled/unauthorized keys.
func NewForbiddenKeyResponse(reason string) pluginapi.RequestInterceptResponse {
	if strings.TrimSpace(reason) == "" {
		reason = "API key is disabled or not authorized"
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: headers,
		ResponseBody:    BuildErrorBody(http.StatusForbidden, "permission_error", "api_key_forbidden", reason),
	}
}

// NewConcurrencyLimitResponse returns a terminated RequestInterceptResponse with HTTP 429 Too Many Requests.
func NewConcurrencyLimitResponse(maxConcurrency int) pluginapi.RequestInterceptResponse {
	msg := fmt.Sprintf("API key concurrency limit reached (max_concurrency=%d). Please retry after current requests complete.", maxConcurrency)
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	headers.Set("Retry-After", "1")
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusTooManyRequests,
		ResponseHeaders: headers,
		ResponseBody:    BuildErrorBody(http.StatusTooManyRequests, "rate_limit_error", "rate_limit_exceeded", msg),
	}
}
