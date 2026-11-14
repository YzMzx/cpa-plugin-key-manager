package plugin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
)

const maxInterceptConfigBody = 2 << 20
const maxInterceptTestBody = 12 << 20

type interceptAPIError string

func (e interceptAPIError) Error() string         { return "intercept request " + string(e) }
func (e interceptAPIError) InterceptCode() string { return string(e) }

const (
	errInterceptInvalid  interceptAPIError = "invalid"
	errInterceptRevision interceptAPIError = "revision"
	errInterceptPrune    interceptAPIError = "ack_prune"
)

var errInterceptUnchanged = errors.New("intercept configuration unchanged")

// Intercept configuration has its own mandatory body CAS. Event operations and
// previews must not be rejected by an unrelated global rules revision header.
func isInterceptUnversionedPath(path string) bool {
	switch path {
	case "/v0/management/key-guard/intercept/config", "/v0/management/key-guard/intercept/events", "/v0/management/key-guard/intercept/events/detail", "/v0/management/key-guard/intercept/events/review", "/v0/management/key-guard/intercept/events/export", "/v0/management/key-guard/intercept/test", "/v0/management/key-guard/intercept/status":
		return true
	}
	return false
}

// Read contents and their CAS token under the same lock, not two independent
// runtime/revision snapshots. Immutable state is cloned before releasing it.
func (m *Manager) interceptConfigSnapshot() (contentguard.State, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, revision := contentguard.DefaultState(), uint64(0)
	if m.dynamicState != nil {
		revision = m.dynamicState.Revision
		if m.dynamicState.Intercept != nil {
			state = m.dynamicState.Intercept.Clone()
		}
	}
	return state, revision
}

func (m *Manager) GetInterceptConfig() map[string]any {
	state, revision := m.interceptConfigSnapshot()
	configured := state.Settings.Classifier.APIKey != ""
	state.Settings.Classifier.APIKey = ""
	raw, _ := json.Marshal(state.Settings)
	settings := map[string]any{}
	_ = json.Unmarshal(raw, &settings)
	classifier := settings["classifier"].(map[string]any)
	delete(classifier, "api_key")
	classifier["api_key_configured"] = configured
	return map[string]any{"settings": settings, "rules": state.Rules, "rules_revision": revision, "limits": contentguard.Limits(), "key_options": m.AuditKeyOptions(), "host_sync": m.HostSyncStatus()}
}

// interceptDecode rejects ambiguous JSON before typed decoding: duplicate keys
// (including case aliases), nulls, unknown fields, excessive nesting and tails.
func interceptDecode(raw []byte, maximum int, target any) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return errInterceptInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int, bool) bool
	walk = func(depth int, root bool) bool {
		if depth > 16 {
			return false
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return false
		}
		delim, isDelim := token.(json.Delim)
		if root && (!isDelim || delim != '{') {
			return false
		}
		if !isDelim {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				t, e := decoder.Token()
				key, ok := t.(string)
				if e != nil || !ok || key != strings.ToLower(key) || seen[key] {
					return false
				}
				seen[key] = true
				if !walk(depth+1, false) {
					return false
				}
			}
			end, e := decoder.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !walk(depth+1, false) {
					return false
				}
			}
			end, e := decoder.Token()
			return e == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !walk(0, true) {
		return errInterceptInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInterceptInvalid
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errInterceptInvalid
	}
	return nil
}

// A supplied settings object must contain every writable non-secret field;
// omission of the entire object preserves the complete current group.
func completeInterceptSettings(raw json.RawMessage, typ reflect.Type) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "api_key" {
			continue
		}
		value, ok := object[name]
		if !ok {
			return false
		}
		if field.Type.Kind() == reflect.Struct && !completeInterceptSettings(value, field.Type) {
			return false
		}
	}
	return true
}

func (m *Manager) SaveInterceptConfig(raw []byte) (map[string]any, error) {
	var request struct {
		ExpectedRevision      *uint64              `json:"expected_revision"`
		Settings              json.RawMessage      `json:"settings"`
		Rules                 *[]contentguard.Rule `json:"rules"`
		AckPrune              bool                 `json:"ack_prune"`
		ClearClassifierAPIKey bool                 `json:"clear_classifier_api_key"`
	}
	if err := interceptDecode(raw, maxInterceptConfigBody, &request); err != nil {
		return nil, err
	}
	if request.ExpectedRevision == nil {
		return nil, errInterceptRevision
	}
	if len(request.Settings) == 0 && request.Rules == nil && !request.ClearClassifierAPIKey {
		return nil, errInterceptInvalid
	}
	err := m.mutateRules(ruleMutation{op: "intercept configuration"}, func(state *DynamicRulesState) error {
		if state.Revision != *request.ExpectedRevision {
			return errInterceptRevision
		}
		current, err := normalizedInterceptState(state.Intercept)
		if err != nil {
			return errInterceptInvalid
		}
		next := current.Clone()
		if len(request.Settings) > 0 {
			if !completeInterceptSettings(request.Settings, reflect.TypeOf(contentguard.Settings{})) {
				return errInterceptInvalid
			}
			// api_key_configured is a response-only hint; accept a boolean when a UI
			// round-trips the settings group, but never use it as a credential.
			var obj map[string]json.RawMessage
			if json.Unmarshal(request.Settings, &obj) != nil {
				return errInterceptInvalid
			}
			var classifier map[string]json.RawMessage
			if json.Unmarshal(obj["classifier"], &classifier) != nil {
				return errInterceptInvalid
			}
			if hint, present := classifier["api_key_configured"]; present {
				var configured bool
				if json.Unmarshal(hint, &configured) != nil {
					return errInterceptInvalid
				}
				delete(classifier, "api_key_configured")
			}
			obj["classifier"], _ = json.Marshal(classifier)
			settingsRaw, _ := json.Marshal(obj)
			var settings contentguard.Settings
			if err := interceptDecode(settingsRaw, maxInterceptConfigBody, &settings); err != nil {
				return err
			}
			if settings.Classifier.APIKey == "" {
				settings.Classifier.APIKey = current.Settings.Classifier.APIKey
			}
			next.Settings = settings
		}
		if request.ClearClassifierAPIKey {
			if len(request.Settings) > 0 {
				var obj struct {
					Classifier struct {
						APIKey string `json:"api_key"`
					} `json:"classifier"`
				}
				_ = json.Unmarshal(request.Settings, &obj)
				if obj.Classifier.APIKey != "" {
					return errInterceptInvalid
				}
			}
			next.Settings.Classifier.APIKey = ""
		}
		if request.Rules != nil {
			next.Rules = *request.Rules
		}
		if next.Settings.Validate() != nil {
			return errInterceptInvalid
		}
		next.Rules, err = contentguard.ValidateRules(next.Rules)
		if err != nil {
			return errInterceptInvalid
		}
		if contentguard.MayPrune(current.Settings, next.Settings) && !request.AckPrune {
			return errInterceptPrune
		}
		if reflect.DeepEqual(current, next) && state.Intercept != nil {
			return errInterceptUnchanged
		}
		state.Intercept = &next
		return nil
	})
	if err != nil && !errors.Is(err, errInterceptUnchanged) {
		var apiError interceptAPIError
		if errors.As(err, &apiError) {
			return nil, err
		}
		return nil, contentguard.ErrUnavailable
	}
	result := m.GetInterceptConfig()
	result["ok"] = true
	return result, nil
}

// Never surface arbitrary classifier response strings in previews: a remote
// service can echo its Authorization header or hidden system text in any field.
func safeInterceptMatches(matches []contentguard.Match, settings contentguard.Settings) []contentguard.Match {
	out := contentguard.FilterEvidenceMatches(matches, settings.CaptureBody, settings.EvidenceIncludeSystem)
	if out == nil {
		return []contentguard.Match{}
	}
	return out
}

func (m *Manager) TestInterceptRules(ctx context.Context, raw []byte) (map[string]any, error) {
	var request struct {
		Text           *string              `json:"text"`
		Rules          *[]contentguard.Rule `json:"rules"`
		KeyFingerprint string               `json:"key_fingerprint"`
		Classifier     bool                 `json:"classifier"`
	}
	if err := interceptDecode(raw, maxInterceptTestBody, &request); err != nil {
		return nil, err
	}
	if request.Text == nil || !utf8.ValidString(*request.Text) || (request.KeyFingerprint != "" && !contentguard.ValidFingerprint(request.KeyFingerprint)) {
		return nil, errInterceptInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, _ := m.interceptConfigSnapshot()
	if len(*request.Text) > state.Settings.MaxScanBytes || len(*request.Text) > contentguard.MaxInputBytes {
		return nil, errInterceptInvalid
	}
	if request.Rules != nil {
		state.Rules = *request.Rules
	}
	rules, err := contentguard.ValidateRules(state.Rules)
	if err != nil {
		return nil, errInterceptInvalid
	}
	engine, err := contentguard.NewEngine(rules)
	if err != nil {
		return nil, errInterceptInvalid
	}
	segments, parsed := contentguard.Extract([]byte(*request.Text), state.Settings.MaxScanBytes)
	if !parsed {
		trimmed := strings.TrimSpace(*request.Text)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || json.Valid([]byte(trimmed)) {
			return nil, errInterceptInvalid
		}
		segments = []contentguard.Segment{{Role: contentguard.RoleUser, Path: "text", Text: *request.Text}}
	}
	matches, err := engine.ScanChecked(ctx, segments, request.KeyFingerprint, state.Settings.SnippetContext)
	if err != nil {
		if errors.Is(err, contentguard.ErrScanBudget) {
			return nil, errInterceptInvalid
		}
		return nil, err
	}
	var classifier *contentguard.ClassifierRecord
	if request.Classifier {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cfg := state.Settings.Classifier
		verdict, err := m.classifier.Classify(ctx, cfg, contentguard.BuildClassifierText(segments, cfg.MaxChars))
		classifier = &contentguard.ClassifierRecord{}
		if err != nil {
			classifier.Error = contentguard.ClassifierFailureCode(err)
			if cfg.Enabled {
				m.classifierFailures.Add(1)
			}
			if cfg.Enabled && cfg.FailurePolicy == contentguard.PolicyDeny {
				matches = append(matches, contentguard.Match{Source: "classifier", RuleName: "外部分类不可用", Action: contentguard.ActionBlock, Severity: cfg.Severity})
			}
		} else {
			classifier.Flagged, classifier.Score = verdict.Flagged, verdict.Score
			if verdict.Flagged {
				matches = append(matches, contentguard.Match{Source: "classifier", RuleName: "外部内容分类", Action: cfg.Action, Severity: cfg.Severity, Score: verdict.Score})
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blocked, severity := contentguard.Decide(state.Settings.Mode, matches)
	views := make([]map[string]any, 0, len(segments))
	for _, segment := range segments {
		item := map[string]any{"role": segment.Role}
		if state.Settings.CaptureBody && (state.Settings.EvidenceIncludeSystem || (segment.Role != contentguard.RoleSystem && segment.Role != contentguard.RoleTool)) {
			item["path"], item["text"] = segment.Path, segment.Text
		}
		views = append(views, item)
	}
	result := map[string]any{"ok": true, "parsed_json": parsed, "segments": views, "matches": safeInterceptMatches(matches, state.Settings), "would_block": blocked, "severity": severity}
	if classifier != nil {
		result["classifier"] = classifier
	}
	return scrubInterceptSecret(result, state.Settings.Classifier.APIKey), nil
}

// Secret replacement is a defense-in-depth presentation boundary, including
// administrator test text or remote evidence containing the configured secret.
func scrubInterceptSecret(value map[string]any, secret string) map[string]any {
	if secret == "" {
		return value
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return value
	}
	var scrub func(any) any
	scrub = func(v any) any {
		switch item := v.(type) {
		case string:
			return strings.ReplaceAll(item, secret, "[redacted]")
		case []any:
			for i := range item {
				item[i] = scrub(item[i])
			}
		case map[string]any:
			for key, entry := range item {
				item[key] = scrub(entry)
			}
		}
		return v
	}
	scrub(out)
	return out
}

func interceptEventView(event contentguard.Event, detail bool, settings contentguard.Settings) map[string]any {
	event.Matches = safeInterceptMatches(event.Matches, settings)
	if event.Classifier != nil {
		copy := *event.Classifier
		copy.Reason, copy.Category = "", ""
		event.Classifier = &copy
	}
	if !detail || !settings.CaptureBody {
		event.Body = ""
		if !settings.CaptureBody {
			event.BodyState = "omitted_disabled"
			event.BodyBytes = 0
			event.BodySHA256 = ""
			event.OriginalSHA256 = ""
		}
	} else if !settings.EvidenceIncludeSystem && event.Body != "" {
		// A truncated JSON prefix cannot be reliably role-filtered; omit it rather
		// than treating it as plain text and exposing a previous system capture.
		if !json.Valid([]byte(event.Body)) {
			event.Body = ""
			event.BodyState = "omitted_system_filter"
			event.BodyBytes = 0
			event.BodySHA256 = ""
			event.OriginalSHA256 = ""
		} else {
			event.Body, event.BodyState, event.BodyTruncated, event.BodySHA256 = contentguard.Evidence([]byte(event.Body), false, settings.MaxEvidenceBytes)
			event.BodyBytes = len(event.Body)
		}
	}
	if secret := settings.Classifier.APIKey; secret != "" && strings.Contains(event.Body, secret) {
		event.Body, event.BodySHA256, event.BodyState = "", "", "omitted_sensitive"
		event.BodyBytes = 0
	}
	if !detail {
		event.Matches = nil
	}
	raw, _ := json.Marshal(event)
	view := map[string]any{}
	_ = json.Unmarshal(raw, &view)
	view["created_at"], view["reviewed_at"] = auditTime(event.CreatedAt), auditTime(event.ReviewedAt)
	return scrubInterceptSecret(view, settings.Classifier.APIKey)
}

func (m *Manager) QueryInterceptEvents(ctx context.Context, q contentguard.Query) (map[string]any, error) {
	runtime := m.interceptSnapshot()
	if runtime == nil || runtime.store == nil {
		return nil, contentguard.ErrUnavailable
	}
	if q.From < 0 || q.To < 0 || (q.From > 0 && q.To > 0 && q.From > q.To) {
		return nil, contentguard.ErrInvalidQuery
	}
	if len(q.RequestID) > 256 || !utf8.ValidString(q.RequestID) || strings.ContainsAny(q.RequestID, "\x00\r\n") {
		return nil, contentguard.ErrInvalidQuery
	}
	q.RequestID = auditCorrelationID(q.RequestID)
	events, total, err := runtime.store.List(ctx, q)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(events))
	for _, event := range events {
		items = append(items, interceptEventView(event, false, runtime.state.Settings))
	}
	return map[string]any{"items": items, "total": total, "limit": q.Limit, "offset": q.Offset}, nil
}
func validInterceptEventID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func (m *Manager) InterceptEventDetail(ctx context.Context, id string) (map[string]any, error) {
	if !validInterceptEventID(id) {
		return nil, contentguard.ErrInvalidQuery
	}
	runtime := m.interceptSnapshot()
	if runtime == nil || runtime.store == nil {
		return nil, contentguard.ErrUnavailable
	}
	event, err := runtime.store.Detail(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"event": interceptEventView(event, true, runtime.state.Settings)}, nil
}
func (m *Manager) ReviewInterceptEvent(ctx context.Context, raw []byte) (map[string]any, error) {
	var request struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := interceptDecode(raw, 16<<10, &request); err != nil {
		return nil, err
	}
	if !validInterceptEventID(request.ID) || !contentguard.ValidReview(request.Status) || len(request.Note) > 2000 {
		return nil, errInterceptInvalid
	}
	runtime := m.interceptSnapshot()
	if runtime == nil || runtime.store == nil {
		return nil, contentguard.ErrUnavailable
	}
	// Host authentication establishes the administrator role; there is no
	// individual administrator identity in the host ABI and none is invented.
	event, err := runtime.store.Review(ctx, request.ID, request.Status, request.Note)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "event": interceptEventView(event, true, runtime.state.Settings)}, nil
}
func (m *Manager) ExportInterceptEvents(ctx context.Context, raw []byte) (map[string]any, error) {
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := interceptDecode(raw, 16<<10, &request); err != nil {
		return nil, err
	}
	if len(request.IDs) == 0 || len(request.IDs) > contentguard.MaxExport {
		return nil, errInterceptInvalid
	}
	seen := map[string]bool{}
	for _, id := range request.IDs {
		if !validInterceptEventID(id) || seen[id] {
			return nil, errInterceptInvalid
		}
		seen[id] = true
	}
	runtime := m.interceptSnapshot()
	if runtime == nil || runtime.store == nil {
		return nil, contentguard.ErrUnavailable
	}
	events, err := runtime.store.Export(ctx, request.IDs)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(events))
	for _, event := range events {
		items = append(items, interceptEventView(event, true, runtime.state.Settings))
	}
	return map[string]any{"ok": true, "items": items, "exported_at": auditTime(time.Now().UnixMilli()), "timezone": m.ConfiguredTimezone(), "plugin_version": PluginVersion}, nil
}
func (m *Manager) InterceptStatus(ctx context.Context) (map[string]any, error) {
	runtime := m.interceptSnapshot()
	if runtime == nil || runtime.store == nil {
		return nil, contentguard.ErrUnavailable
	}
	zone := m.ConfiguredTimezone()
	if zone == "" {
		zone = usage.DefaultTimezone
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return nil, contentguard.ErrUnavailable
	}
	now := time.Now().In(loc)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	today, err := runtime.store.Stats(ctx, todayStart.UnixMilli())
	if err != nil {
		return nil, err
	}
	week, err := runtime.store.Stats(ctx, todayStart.AddDate(0, 0, -6).UnixMilli())
	if err != nil {
		return nil, err
	}
	settings := runtime.state.Settings
	status := map[string]any{"enabled": settings.Enabled, "mode": settings.Mode, "rules": len(runtime.state.Rules), "enabled_rules": runtime.engine.RuleCount(), "capture_body": settings.CaptureBody, "evidence_include_system": settings.EvidenceIncludeSystem, "failures": m.interceptFailures.Load(), "classifier_failures": m.classifierFailures.Load(), "storage_available": true, "timezone": zone}
	return map[string]any{"status": status, "today": today, "last_7_days": week, "host_sync": m.HostSyncStatus()}, nil
}
