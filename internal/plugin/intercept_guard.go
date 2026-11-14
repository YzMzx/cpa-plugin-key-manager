package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/authz"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/contentguard"
	"github.com/YzMzx/cpa-plugin-key-manager/internal/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// All fields are immutable after publication; guardMu leases fence old writes.
type interceptRuntime struct {
	state  contentguard.State
	engine *contentguard.Engine
	store  *contentguard.Store
}
type interceptWork struct {
	runtime *interceptRuntime
	event   contentguard.Event
	body    []byte
}
type disableWindow struct {
	keyUpdatedAt string
	runtime      *interceptRuntime
	times        []time.Time
	requests     map[string]time.Time
}
type disableTask struct {
	runtime                     *interceptRuntime
	key, fingerprint, requestID string
	keyUpdatedAt                string
	at                          time.Time
}

func normalizedInterceptState(stored *contentguard.State) (contentguard.State, error) {
	if stored == nil {
		return contentguard.DefaultState(), nil
	}
	state := stored.Clone()
	if err := state.Settings.Validate(); err != nil {
		return state, err
	}
	rules, err := contentguard.ValidateRules(state.Rules)
	if err != nil {
		return state, err
	}
	state.Rules = rules
	return state, nil
}
func (m *Manager) prepareIntercept(stored *contentguard.State) (*interceptRuntime, error) {
	state, err := normalizedInterceptState(stored)
	if err != nil {
		return nil, err
	}
	engine, err := contentguard.NewEngine(state.Rules)
	if err != nil {
		return nil, err
	}
	return &interceptRuntime{state: state, engine: engine, store: contentguard.NewStore(m.usageStore.DB())}, nil
}
func (m *Manager) interceptSnapshot() *interceptRuntime {
	m.guardMu.RLock()
	defer m.guardMu.RUnlock()
	return m.guardRuntime
}
func keyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	v := sha256.Sum256([]byte(key))
	return hex.EncodeToString(v[:])
}
func maskedKey(key string) string {
	if len(key) < 12 {
		return "***"
	}
	return usage.MaskAPIKey(key)
}

// start/stop are serialized by managementMu. The worker never owns the DB.
func (m *Manager) startInterceptWorkerLocked() {
	if m.guardDone != nil {
		return
	}
	m.guardQueue = make(chan interceptWork, 16)
	m.guardWake = make(chan struct{}, 1)
	m.guardStop = make(chan struct{})
	m.guardDone = make(chan struct{})
	go m.runInterceptWorker(m.guardQueue, m.guardWake, m.guardStop, m.guardDone)
}
func (m *Manager) stopInterceptWorker() {
	m.guardMu.Lock()
	done := m.guardDone
	if done != nil {
		close(m.guardStop)
	}
	m.guardRuntime = nil
	m.guardMu.Unlock()
	if done != nil {
		<-done
	}
	m.guardMu.Lock()
	m.guardDone = nil
	m.guardQueue = nil
	m.guardMu.Unlock()
	m.disableMu.Lock()
	m.disableWindows = nil
	m.disablePending = nil
	m.disableSeen = nil
	m.disableMu.Unlock()
}
func (m *Manager) runInterceptWorker(queue <-chan interceptWork, wake, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		default:
		}
		select {
		case <-stop:
			return
		case work := <-queue:
			m.writeIntercept(work)
		case <-wake:
			m.processDisableTasks()
		case <-tick.C:
			m.pruneIntercept()
		}
	}
}
func (m *Manager) pruneIntercept() {
	m.guardMu.RLock()
	defer m.guardMu.RUnlock()
	r := m.guardRuntime
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := r.store.Prune(ctx, time.Now(), r.state.Settings); err != nil {
		m.interceptFailures.Add(1)
	}
}
func (m *Manager) writeIntercept(work interceptWork) {
	r := work.runtime
	s := r.state.Settings
	// Body was bounded and copied before enqueue. Never keep the caller's slice.
	if s.CaptureBody && len(work.body) > 0 {
		evidence := contentguard.CaptureEvidence(work.body, s.EvidenceIncludeSystem, s.MaxEvidenceBytes)
		work.event.Body, work.event.BodyState, work.event.BodyTruncated = evidence.Text, evidence.State, evidence.Truncated
		work.event.BodySHA256, work.event.OriginalSHA256 = evidence.SHA256, evidence.OriginalSHA256
		work.event.BodyBytes = len(evidence.Text)
	}
	m.guardMu.RLock()
	defer m.guardMu.RUnlock()
	if m.guardRuntime != r || !r.state.Settings.Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.store.InsertBounded(ctx, work.event, s); err != nil {
		m.interceptFailures.Add(1)
	}
}
func guardJSON(req pluginapi.RequestInterceptRequest, limit int) bool {
	if len(req.Body) > limit || !utf8.Valid(req.Body) {
		return false
	}
	encoding := strings.TrimSpace(req.Headers.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	if typ := req.Headers.Get("Content-Type"); typ != "" {
		media, _, err := mime.ParseMediaType(typ)
		if err != nil || !(media == "application/json" || strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")) {
			return false
		}
	}
	return json.Valid(req.Body)
}

// False means allow. Invalid/oversize/busy inspections follow the configured
// incomplete policy; they never count towards automatic key disable.
func (m *Manager) inspectContent(req pluginapi.RequestInterceptRequest, key, name string) bool {
	r := m.interceptSnapshot()
	if r == nil || !r.state.Settings.Enabled {
		return false
	}
	s := r.state.Settings
	m.mu.RLock()
	inspectionKey, _ := m.cfg.ResolveKeyRule(key)
	m.mu.RUnlock()
	var matches []contentguard.Match
	var record *contentguard.ClassifierRecord
	incomplete := false
	safeBody := false
	select {
	case m.guardScanSlots <- struct{}{}:
		defer func() { <-m.guardScanSlots }()
		safeBody = guardJSON(req, s.MaxScanBytes)
		if safeBody {
			segments, parsed := contentguard.Extract(req.Body, s.MaxScanBytes)
			incomplete = !parsed
			if parsed {
				scanCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				var scanErr error
				matches, scanErr = r.engine.ScanChecked(scanCtx, segments, keyFingerprint(key), s.SnippetContext)
				cancel()
				incomplete = scanErr != nil
				blocked, _ := contentguard.Decide(s.Mode, matches)
				if s.Classifier.Enabled && !blocked && !incomplete && len(segments) > 0 {
					verdict, err := m.classifier.Classify(context.Background(), s.Classifier, contentguard.BuildClassifierText(segments, s.Classifier.MaxChars))
					if err != nil {
						m.classifierFailures.Add(1)
						record = &contentguard.ClassifierRecord{Error: contentguard.ClassifierFailureCode(err)}
						action := contentguard.ActionFlag
						if s.Classifier.FailurePolicy == contentguard.PolicyDeny {
							action = contentguard.ActionBlock
						}
						matches = append(matches, contentguard.Match{Source: "system", RuleName: "审核服务不可用", Action: action, Severity: contentguard.SeverityLow})
					} else {
						record = &contentguard.ClassifierRecord{Flagged: verdict.Flagged, Score: verdict.Score, Category: ""}
						if verdict.Flagged {
							matches = append(matches, contentguard.Match{Source: "classifier", RuleName: "审核模型判定", Action: s.Classifier.Action, Severity: s.Classifier.Severity, Score: verdict.Score, Category: record.Category})
						}
					}
				}
			}
		} else {
			incomplete = true
		}
	default:
		incomplete = true
	}
	if incomplete {
		action := contentguard.ActionFlag
		if s.OversizePolicy == contentguard.PolicyDeny {
			action = contentguard.ActionBlock
		}
		matches = append(matches, contentguard.Match{Source: "system", RuleName: "请求未完整检查", Action: action, Severity: contentguard.SeverityLow})
	}
	if len(matches) == 0 {
		return false
	}
	blocked, severity := contentguard.Decide(s.Mode, matches)
	eligible := false
	for _, hit := range matches {
		if (hit.Source == "rule" || hit.Source == "classifier") && hit.Action == contentguard.ActionBlock && contentguard.SeverityRank(hit.Severity) >= contentguard.SeverityRank(s.AutoDisable.MinSeverity) {
			eligible = true
		}
	}
	fp := keyFingerprint(key)
	if blocked && eligible && !incomplete && s.AutoDisable.Enabled {
		m.recordDisableHitForKey(r, key, fp, req.RequestID, inspectionKey.UpdatedAt)
	}
	names := []string{}
	seen := map[string]bool{}
	for i := range matches {
		hit := &matches[i]
		if !seen[hit.RuleName] {
			seen[hit.RuleName] = true
			names = append(names, auditSafeLabel(hit.RuleName, key))
		}
		// Omission applies to all text copies, not only the main body.
		if !s.CaptureBody || !s.EvidenceIncludeSystem && (hit.Role == contentguard.RoleSystem || hit.Role == contentguard.RoleTool) {
			hit.Matched = ""
			hit.Snippet = ""
			hit.Offset = 0
		}
	}
	matches = contentguard.FilterEvidenceMatches(matches, s.CaptureBody, s.EvidenceIncludeSystem)
	path := ""
	if raw, ok := req.Metadata["request_path"].(string); ok {
		if u, err := url.Parse(raw); err == nil && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") {
			path = u.Path
		}
	}
	action := contentguard.EventFlagged
	if blocked {
		action = contentguard.EventBlocked
	}
	event := contentguard.Event{CreatedAt: time.Now().UTC().UnixMilli(), RequestID: auditCorrelationID(req.RequestID), TraceID: auditCorrelationID(req.TraceID), Path: auditSafeLabel(path, key), Protocol: auditSafeLabel(req.SourceFormat, key), RequestedModel: auditSafeLabel(req.RequestedModel, key), ServedModel: auditSafeLabel(req.Model, key), Stream: req.Stream, KeyName: auditSafeLabel(name, key), KeyMasked: maskedKey(key), KeyFingerprint: fp, Action: action, Mode: s.Mode, Severity: severity, RuleNames: names, Matches: matches, Classifier: record, OriginalBytes: len(req.Body), BodyState: "omitted_disabled", ScanTruncated: incomplete}
	var body []byte
	if s.CaptureBody {
		event.BodyState = "omitted_processing_limit"
		if safeBody {
			body = append([]byte(nil), req.Body...)
		}
	}
	m.guardMu.RLock()
	if m.guardRuntime == r && m.guardQueue != nil {
		select {
		case m.guardQueue <- interceptWork{runtime: r, event: event, body: body}:
		default:
			m.interceptFailures.Add(1)
		}
	}
	m.guardMu.RUnlock()
	return blocked
}
func newContentBlockedResponse() pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: 403, ResponseHeaders: http.Header{"Content-Type": {"application/json; charset=utf-8"}}, ResponseBody: authz.BuildErrorBody(403, "permission_error", "content_policy_violation", "request rejected by content policy")}
}

// A bounded sliding window, keyed by fingerprint. Duplicate execution callbacks
// cannot advance the threshold. Counters are deliberately process-local.
func (m *Manager) recordDisableHit(r *interceptRuntime, key, fp, id string) {
	m.mu.RLock()
	keyRule, _ := m.cfg.ResolveKeyRule(key)
	m.mu.RUnlock()
	m.recordDisableHitForKey(r, key, fp, id, keyRule.UpdatedAt)
}
func (m *Manager) recordDisableHitForKey(r *interceptRuntime, key, fp, id, inspectedKeyVersion string) {
	if id == "" || fp == "" {
		return
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(r.state.Settings.AutoDisable.WindowMinutes) * time.Minute)
	identity := auditCorrelationID(id)
	m.guardMu.RLock()
	defer m.guardMu.RUnlock()
	if m.guardRuntime != r || m.guardDone == nil {
		return
	}
	m.mu.RLock()
	keyRule, listed := m.cfg.ResolveKeyRule(key)
	m.mu.RUnlock()
	if !listed || !keyRule.IsEnabled() || keyRule.UpdatedAt != inspectedKeyVersion {
		return
	}
	m.disableMu.Lock()
	defer m.disableMu.Unlock()
	if m.disableWindows == nil {
		m.disableWindows = map[string]*disableWindow{}
		m.disablePending = map[string]disableTask{}
	}
	if _, ok := m.disablePending[fp]; ok {
		return
	}
	// Keep execution dedup independent of a threshold window or manual re-enable.
	// Never evict live IDs to admit more: saturation is reported and fails safely
	// by declining automatic action, not by double-counting an old execution.
	if m.disableSeen == nil {
		m.disableSeen = map[string]time.Time{}
	}
	if now.Sub(m.disableSeenSweep) >= time.Minute {
		for seen, at := range m.disableSeen {
			if now.Sub(at) > 24*time.Hour {
				delete(m.disableSeen, seen)
			}
		}
		m.disableSeenSweep = now
	}
	dedup := fp + ":" + identity
	if _, exists := m.disableSeen[dedup]; exists {
		return
	}
	if len(m.disableSeen) >= 100000 {
		m.interceptFailures.Add(1)
		return
	}
	m.disableSeen[dedup] = now
	for k, w := range m.disableWindows {
		if w.runtime != r || len(w.times) == 0 || w.times[len(w.times)-1].Before(cutoff) {
			delete(m.disableWindows, k)
		}
	}
	w := m.disableWindows[fp]
	if w != nil && w.keyUpdatedAt != keyRule.UpdatedAt {
		delete(m.disableWindows, fp)
		w = nil
	}
	if w == nil {
		if len(m.disableWindows) >= 2048 {
			m.interceptFailures.Add(1)
			return
		}
		w = &disableWindow{runtime: r, keyUpdatedAt: keyRule.UpdatedAt, requests: map[string]time.Time{}}
		m.disableWindows[fp] = w
	}
	for k, at := range w.requests {
		if at.Before(cutoff) {
			delete(w.requests, k)
		}
	}
	if _, ok := w.requests[identity]; ok {
		return
	}
	w.requests[identity] = now
	keep := w.times[:0]
	for _, at := range w.times {
		if !at.Before(cutoff) {
			keep = append(keep, at)
		}
	}
	w.times = append(keep, now)
	if len(w.times) >= r.state.Settings.AutoDisable.Threshold {
		if len(m.disablePending) >= 2048 {
			delete(m.disableWindows, fp)
			m.interceptFailures.Add(1)
			return
		}
		m.disablePending[fp] = disableTask{runtime: r, key: key, fingerprint: fp, requestID: identity, at: now, keyUpdatedAt: keyRule.UpdatedAt}
		delete(m.disableWindows, fp)
		select {
		case m.guardWake <- struct{}{}:
		default:
		}
	}
}
func (m *Manager) processDisableTasks() {
	for {
		m.disableMu.Lock()
		var task disableTask
		for _, t := range m.disablePending {
			task = t
			break
		}
		m.disableMu.Unlock()
		if task.key == "" {
			return
		}
		m.autoDisableKey(task)
		m.disableMu.Lock()
		delete(m.disablePending, task.fingerprint)
		m.disableMu.Unlock()
	}
}

var errGuardStale = errors.New("intercept policy is no longer current")

func (m *Manager) autoDisableKey(task disableTask) {
	err := m.mutateRules(ruleMutation{op: "intercept auto disable", syncHostKeys: true}, func(state *DynamicRulesState) error {
		if m.interceptSnapshot() != task.runtime {
			return errGuardStale
		}
		if time.Since(task.at) > time.Duration(task.runtime.state.Settings.AutoDisable.WindowMinutes)*time.Minute {
			return errGuardStale
		}
		current, listed := m.cfg.ResolveKeyRule(task.key)
		if !listed || !current.IsEnabled() || current.UpdatedAt != task.keyUpdatedAt {
			return errRuleNotFound
		}
		// Deleted-key tombstones and current policy are resolved before this point.
		copied := cloneKeyRule(current)
		off := false
		copied.Enabled = &off
		copied.QuotaUsedUSD = nil
		copied.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		for i := range state.Keys {
			if state.Keys[i].APIKey == task.key {
				state.Keys[i] = copied
				return nil
			}
		}
		state.Keys = append(state.Keys, copied)
		return nil
	})
	outcome := "disabled"
	if err != nil {
		if errors.Is(err, errGuardStale) || errors.Is(err, errRuleNotFound) {
			return
		}
		outcome = "failed"
		m.interceptFailures.Add(1)
	}
	// Separate disposition event means a saturated evidence queue cannot hide the
	// automatic action. No body, raw key, IP, header or management secret is saved.
	event := contentguard.Event{CreatedAt: time.Now().UTC().UnixMilli(), RequestID: task.requestID, KeyMasked: maskedKey(task.key), KeyFingerprint: task.fingerprint, Action: contentguard.EventBlocked, Mode: contentguard.ModeEnforce, Severity: task.runtime.state.Settings.AutoDisable.MinSeverity, RuleNames: []string{"达到自动停用阈值"}, BodyState: "omitted_disabled", AutoDisabled: outcome}
	m.writeIntercept(interceptWork{runtime: task.runtime, event: event})
}
