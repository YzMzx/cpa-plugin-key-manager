package contentguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// ClassifierResult is the normalized verdict of an external moderation call.
type ClassifierResult struct {
	Flagged  bool
	Score    float64
	Category string
	Reason   string
}

// ClassifierError carries a stable, secret-free failure code.
type ClassifierError struct{ Code string }

func (e *ClassifierError) Error() string { return "classifier " + e.Code }

func classifierFailure(code string) error { return &ClassifierError{Code: code} }

// ClassifierFailureCode extracts a safe code for diagnostics.
func ClassifierFailureCode(err error) string {
	var failure *ClassifierError
	if errors.As(err, &failure) {
		return failure.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "unavailable"
}

// Classifier calls an administrator-configured moderation endpoint. It is a
// reserved extension point: the OpenAI moderation format and a generic
// {"flagged","score","category","reason"} JSON contract are supported.
// ModerationClassifier is the reserved opt-in extension contract. Implementations
// receive only explicitly authorized text, never automatic raw request copies.
type ModerationClassifier interface {
	Classify(context.Context, ClassifierSettings, string) (ClassifierResult, error)
}

type Classifier struct {
	client *http.Client
	slots  chan struct{}
}

// NewClassifier bounds concurrent outbound calls; saturation is a failure that
// follows the configured failure policy rather than queueing requests.
func NewClassifier(maxConcurrent int) *Classifier {
	if maxConcurrent <= 0 {
		maxConcurrent = 32
	}
	maxConcurrent = min(maxConcurrent, 64)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = maxConcurrent
	return &Classifier{
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		slots:  make(chan struct{}, maxConcurrent),
	}
}

// BuildClassifierText joins segments (role-labelled) and caps the rune count.
func BuildClassifierText(segments []Segment, maxChars int) string {
	maxChars = max(0, min(maxChars, 200000))
	var out strings.Builder
	remaining := maxChars
	appendText := func(text string) {
		for _, r := range text {
			if remaining <= 0 {
				break
			}
			out.WriteRune(r)
			remaining--
		}
	}
	for i, segment := range segments {
		if remaining <= 0 || i >= MaxSegments {
			break
		}
		if out.Len() > 0 {
			appendText("\n\n")
		}
		role := segment.Role
		if !oneOf(role, RoleUser, RoleSystem, RoleTool, RoleAssistant) {
			role = RoleUser
		}
		appendText("[" + role + "] ")
		appendText(segment.Text)
	}
	return out.String()
}

// Classify performs one bounded call. The API key is sent only as a bearer
// header and never appears in errors or logs.
func (c *Classifier) Classify(ctx context.Context, settings ClassifierSettings, text string) (ClassifierResult, error) {
	if c == nil || !settings.Enabled || settings.URL == "" {
		return ClassifierResult{}, classifierFailure("disabled")
	}
	validated := DefaultSettings()
	validated.Classifier = settings
	if validated.Validate() != nil {
		return ClassifierResult{}, classifierFailure("settings_invalid")
	}
	if len(text) > 4*settings.MaxChars || !utf8.ValidString(text) || utf8.RuneCountInString(text) > settings.MaxChars {
		return ClassifierResult{}, classifierFailure("input_too_large")
	}
	if ctx.Err() != nil {
		return ClassifierResult{}, classifierFailure("canceled")
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return ClassifierResult{}, classifierFailure("busy")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(settings.TimeoutMS)*time.Millisecond)
	defer cancel()
	payload := map[string]any{"input": text}
	if settings.Model != "" {
		payload["model"] = settings.Model
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ClassifierResult{}, classifierFailure("encode")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.URL, bytes.NewReader(raw))
	if err != nil {
		return ClassifierResult{}, classifierFailure("request_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if settings.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+settings.APIKey)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ClassifierResult{}, classifierFailure("timeout")
		}
		return ClassifierResult{}, classifierFailure("transport")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return ClassifierResult{}, classifierFailure("read")
	}
	if len(body) > 1<<20 {
		return ClassifierResult{}, classifierFailure("response_too_large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ClassifierResult{}, classifierFailure("http_" + http.StatusText(resp.StatusCode))
	}
	return parseClassifierResponse(settings, body)
}

func parseClassifierResponse(settings ClassifierSettings, body []byte) (ClassifierResult, error) {
	root, err := decodeJSON(body, 1<<20)
	if err != nil {
		return ClassifierResult{}, classifierFailure("response_invalid")
	}
	switch settings.Format {
	case FormatOpenAIModeration:
		object, ok := root.(map[string]any)
		if !ok {
			return ClassifierResult{}, classifierFailure("response_invalid")
		}
		items, ok := object["results"].([]any)
		if !ok || len(items) == 0 || len(items) > 32 {
			return ClassifierResult{}, classifierFailure("response_invalid")
		}
		for _, item := range items {
			row, ok := item.(map[string]any)
			if !ok {
				return ClassifierResult{}, classifierFailure("response_invalid")
			}
			for _, key := range []string{"categories", "category_scores"} {
				values, ok := row[key].(map[string]any)
				if !ok || len(values) > 256 {
					return ClassifierResult{}, classifierFailure("response_invalid")
				}
				for category, value := range values {
					if !safeText(category, 80) {
						return ClassifierResult{}, classifierFailure("response_invalid")
					}
					if key == "categories" {
						if _, ok := value.(bool); !ok {
							return ClassifierResult{}, classifierFailure("response_invalid")
						}
					} else {
						if _, ok := value.(json.Number); !ok {
							return ClassifierResult{}, classifierFailure("response_invalid")
						}
					}
				}
			}
		}
		var parsed struct {
			Results []struct {
				Flagged        *bool              `json:"flagged"`
				Categories     map[string]bool    `json:"categories"`
				CategoryScores map[string]float64 `json:"category_scores"`
			} `json:"results"`
		}
		if json.Unmarshal(body, &parsed) != nil || len(parsed.Results) == 0 {
			return ClassifierResult{}, classifierFailure("response_invalid")
		}
		result := ClassifierResult{}
		for _, item := range parsed.Results {
			if item.Flagged == nil || item.Categories == nil || item.CategoryScores == nil {
				return ClassifierResult{}, classifierFailure("response_invalid")
			}
			if *item.Flagged {
				result.Flagged = true
			}
			for category, score := range item.CategoryScores {
				if !validScore(score) || !safeText(category, 80) {
					return ClassifierResult{}, classifierFailure("response_invalid")
				}
				if score > result.Score || (score == result.Score && category < result.Category) {
					result.Score, result.Category = score, category
				}
			}
			{
				for category, on := range item.Categories {
					if !safeText(category, 80) {
						return ClassifierResult{}, classifierFailure("response_invalid")
					}
					if on && result.Score == 0 && (result.Category == "" || category < result.Category) {
						result.Category = category
					}
				}
			}
		}
		if settings.ScoreThreshold > 0 && result.Score >= settings.ScoreThreshold {
			result.Flagged = true
		}
		return result, nil
	case FormatGeneric:
		var parsed struct {
			Flagged  *bool    `json:"flagged"`
			Score    *float64 `json:"score"`
			Category string   `json:"category"`
			Reason   string   `json:"reason"`
		}
		if json.Unmarshal(body, &parsed) != nil || parsed.Flagged == nil || parsed.Score == nil || !validScore(*parsed.Score) {
			return ClassifierResult{}, classifierFailure("response_invalid")
		}
		result := ClassifierResult{Flagged: *parsed.Flagged, Score: *parsed.Score, Category: clip(parsed.Category, 80), Reason: clip(parsed.Reason, 300)}
		if settings.ScoreThreshold > 0 && result.Score >= settings.ScoreThreshold {
			result.Flagged = true
		}
		return result, nil
	}
	return ClassifierResult{}, classifierFailure("format")
}

func clip(value string, max int) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "")
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
func validScore(score float64) bool {
	return !math.IsNaN(score) && !math.IsInf(score, 0) && score >= 0 && score <= 1
}
