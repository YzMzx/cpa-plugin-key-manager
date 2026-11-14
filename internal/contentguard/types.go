// Package contentguard inspects admitted client request content against
// administrator rules and an optional external moderation classifier, and keeps
// bounded forensic evidence of every match. It never edits the upstream request.
package contentguard

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	ModeObserve = "observe"
	ModeEnforce = "enforce"

	ActionBlock = "block"
	ActionFlag  = "flag"

	KindKeyword = "keyword"
	KindRegex   = "regex"

	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"

	RoleUser      = "user"
	RoleSystem    = "system"
	RoleTool      = "tool"
	RoleAssistant = "assistant"

	KeyModeAll     = "all"
	KeyModeInclude = "include"
	KeyModeExclude = "exclude"

	FormatOpenAIModeration = "openai_moderation"
	FormatGeneric          = "generic"

	PolicyAllow = "allow"
	PolicyDeny  = "deny"

	// Event actions persisted in intercept_events.
	EventBlocked = "blocked"
	EventFlagged = "flagged"

	MaxRules             = 200
	MaxPatternsPerRule   = 500
	MaxPatternBytes      = 1024
	MaxTotalPatternBytes = 256 << 10
	MaxKeyFingerprints   = 500
)

var (
	ErrInvalid      = errors.New("invalid intercept configuration")
	ErrNotFound     = errors.New("intercept event not found")
	ErrUnavailable  = errors.New("intercept storage is unavailable")
	ErrInvalidQuery = errors.New("invalid intercept query")
)

// ValidationError carries a safe, user-facing field description. It never
// contains secrets: classifier credentials are not echoed.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }
func (e *ValidationError) Unwrap() error { return ErrInvalid }

func invalid(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

// Settings is the hot intercept configuration persisted with the rules state.
type Settings struct {
	Enabled               bool                `json:"enabled"`
	Mode                  string              `json:"mode"`
	MaxScanBytes          int                 `json:"max_scan_bytes"`
	OversizePolicy        string              `json:"oversize_policy"`
	CaptureBody           bool                `json:"capture_body"`
	EvidenceIncludeSystem bool                `json:"evidence_include_system"`
	MaxEvidenceBytes      int                 `json:"max_evidence_bytes"`
	SnippetContext        int                 `json:"snippet_context"`
	RetentionDays         int                 `json:"retention_days"`
	MaxRecords            int                 `json:"max_records"`
	MaxTotalBytes         int64               `json:"max_total_bytes"`
	AutoDisable           AutoDisableSettings `json:"auto_disable"`
	Classifier            ClassifierSettings  `json:"classifier"`
}

// AutoDisableSettings disables a listed key after repeated blocked requests.
type AutoDisableSettings struct {
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	MinSeverity   string `json:"min_severity"`
}

// ClassifierSettings configures the optional external moderation endpoint.
// APIKey is persisted but never returned by management reads.
type ClassifierSettings struct {
	Enabled        bool    `json:"enabled"`
	URL            string  `json:"url"`
	APIKey         string  `json:"api_key,omitempty"`
	Format         string  `json:"format"`
	Model          string  `json:"model"`
	TimeoutMS      int     `json:"timeout_ms"`
	MaxChars       int     `json:"max_chars"`
	FailurePolicy  string  `json:"failure_policy"`
	Action         string  `json:"action"`
	Severity       string  `json:"severity"`
	ScoreThreshold float64 `json:"score_threshold"`
}

// Rule is one administrator-defined keyword or regular-expression rule.
type Rule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Kind            string   `json:"kind"`
	Patterns        []string `json:"patterns"`
	Roles           []string `json:"roles"`
	Action          string   `json:"action"`
	Severity        string   `json:"severity"`
	KeyMode         string   `json:"key_mode"`
	KeyFingerprints []string `json:"key_fingerprints"`
}

// State is the complete persisted intercept configuration.
type State struct {
	Settings Settings `json:"settings"`
	Rules    []Rule   `json:"rules"`
}

// DefaultSettings is intentionally passive: disabled and observe-only.
func DefaultSettings() Settings {
	return Settings{
		Enabled:               false,
		Mode:                  ModeObserve,
		MaxScanBytes:          2 << 20,
		OversizePolicy:        PolicyAllow,
		CaptureBody:           true,
		EvidenceIncludeSystem: true,
		MaxEvidenceBytes:      64 << 10,
		SnippetContext:        80,
		RetentionDays:         30,
		MaxRecords:            5000,
		MaxTotalBytes:         256 << 20,
		AutoDisable:           AutoDisableSettings{Enabled: false, Threshold: 5, WindowMinutes: 10, MinSeverity: SeverityHigh},
		Classifier: ClassifierSettings{
			Format: FormatOpenAIModeration, TimeoutMS: 3000, MaxChars: 32000,
			FailurePolicy: PolicyAllow, Action: ActionFlag, Severity: SeverityMedium, ScoreThreshold: 0.5,
		},
	}
}

// DefaultState returns a disabled configuration without rules.
func DefaultState() State { return State{Settings: DefaultSettings(), Rules: []Rule{}} }

// Clone returns an independent copy.
func (s State) Clone() State {
	out := State{Settings: s.Settings, Rules: make([]Rule, 0, len(s.Rules))}
	for _, rule := range s.Rules {
		rule.Patterns = append([]string(nil), rule.Patterns...)
		rule.Roles = append([]string(nil), rule.Roles...)
		rule.KeyFingerprints = append([]string(nil), rule.KeyFingerprints...)
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// Limits documents the validation ranges for management clients.
func Limits() map[string]any {
	return map[string]any{
		"max_scan_bytes":     []int{4 << 10, 10 << 20},
		"max_evidence_bytes": []int{1 << 10, 1 << 20},
		"snippet_context":    []int{0, 500},
		"retention_days":     []int{1, 365},
		"max_records":        []int{1, 50000},
		"max_total_bytes":    []int64{1 << 20, 4 << 30},
		"auto_disable":       map[string]any{"threshold": []int{1, 1000}, "window_minutes": []int{1, 1440}},
		"classifier":         map[string]any{"timeout_ms": []int{100, 10000}, "max_chars": []int{256, 200000}, "score_threshold": []float64{0, 1}},
		"rules":              map[string]any{"max_rules": MaxRules, "max_patterns_per_rule": MaxPatternsPerRule, "max_pattern_bytes": MaxPatternBytes, "max_total_pattern_bytes": MaxTotalPatternBytes, "max_key_fingerprints": MaxKeyFingerprints},
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func safeText(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

// SeverityRank orders severities; unknown values rank lowest.
func SeverityRank(value string) int {
	switch value {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Validate checks every field. It never rewrites values, so a request cannot be
// silently widened into a more permissive configuration.
func (s *Settings) Validate() error {
	if !oneOf(s.Mode, ModeObserve, ModeEnforce) {
		return invalid("mode 必须是 observe 或 enforce")
	}
	if s.MaxScanBytes < 4<<10 || s.MaxScanBytes > 10<<20 {
		return invalid("max_scan_bytes 必须在 4 KiB 到 10 MiB 之间")
	}
	if !oneOf(s.OversizePolicy, PolicyAllow, PolicyDeny) {
		return invalid("oversize_policy 必须是 allow 或 deny")
	}
	if s.MaxEvidenceBytes < 1<<10 || s.MaxEvidenceBytes > 1<<20 {
		return invalid("max_evidence_bytes 必须在 1 KiB 到 1 MiB 之间")
	}
	if s.SnippetContext < 0 || s.SnippetContext > 500 {
		return invalid("snippet_context 必须在 0 到 500 之间")
	}
	if s.RetentionDays < 1 || s.RetentionDays > 365 {
		return invalid("retention_days 必须在 1 到 365 之间")
	}
	if s.MaxRecords < 1 || s.MaxRecords > 50000 {
		return invalid("max_records 必须在 1 到 50000 之间")
	}
	if s.MaxTotalBytes < 1<<20 || s.MaxTotalBytes > 4<<30 {
		return invalid("max_total_bytes 必须在 1 MiB 到 4 GiB 之间")
	}
	a := s.AutoDisable
	if a.Threshold < 1 || a.Threshold > 1000 || a.WindowMinutes < 1 || a.WindowMinutes > 1440 || SeverityRank(a.MinSeverity) == 0 {
		return invalid("自动停用阈值、窗口或最低严重度无效")
	}
	c := s.Classifier
	if !oneOf(c.Format, FormatOpenAIModeration, FormatGeneric) || !oneOf(c.FailurePolicy, PolicyAllow, PolicyDeny) || !oneOf(c.Action, ActionBlock, ActionFlag) || SeverityRank(c.Severity) == 0 {
		return invalid("审核模型格式、失败策略、动作或严重度无效")
	}
	if c.TimeoutMS < 100 || c.TimeoutMS > 10000 || c.MaxChars < 256 || c.MaxChars > 200000 {
		return invalid("审核模型超时或文本上限超出范围")
	}
	if math.IsNaN(c.ScoreThreshold) || math.IsInf(c.ScoreThreshold, 0) || c.ScoreThreshold < 0 || c.ScoreThreshold > 1 {
		return invalid("score_threshold 必须在 0 到 1 之间")
	}
	if !safeText(c.Model, 200) || !safeText(c.APIKey, 4096) {
		return invalid("审核模型名称或凭据格式无效")
	}
	if c.URL != "" || c.Enabled {
		if err := validateClassifierURL(c.URL); err != nil {
			return err
		}
	}
	return nil
}

func validateClassifierURL(raw string) error {
	if raw == "" || !safeText(raw, 2048) {
		return invalid("启用审核模型时必须填写有效的 URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return invalid("审核模型 URL 仅支持不含用户名、查询参数和片段的 HTTP(S) 地址；凭据请填写在 API Key 字段")
	}
	return nil
}

// MayPrune reports whether new settings can delete retained evidence.
func MayPrune(old, next Settings) bool {
	return next.RetentionDays < old.RetentionDays || next.MaxRecords < old.MaxRecords || next.MaxTotalBytes < old.MaxTotalBytes
}

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidFingerprint reports whether value is a lower-case SHA-256 hex digest.
func ValidFingerprint(value string) bool { return fingerprintPattern.MatchString(value) }

func newRuleID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return "r" + hex.EncodeToString(raw[:])
}

// ValidateRules normalizes whitespace, assigns missing IDs and compiles every
// rule. It returns a new slice and never mutates its input.
func ValidateRules(rules []Rule) ([]Rule, error) {
	if len(rules) > MaxRules {
		return nil, invalid("规则数量不能超过 %d 条", MaxRules)
	}
	out := make([]Rule, 0, len(rules))
	seen := map[string]bool{}
	total := 0
	var totalInstructions int64
	for index, rule := range rules {
		position := index + 1
		if len(rule.ID) > 48 || len(rule.Name) > 320 {
			return nil, invalid("规则标识或名称超过预算")
		}
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			if rule.ID = newRuleID(); rule.ID == "" {
				return nil, ErrUnavailable
			}
		}
		if !ruleIDPattern.MatchString(rule.ID) || seen[rule.ID] {
			return nil, invalid("第 %d 条规则的 ID 无效或重复", position)
		}
		seen[rule.ID] = true
		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" || !safeText(rule.Name, 320) || utf8.RuneCountInString(rule.Name) > 80 {
			return nil, invalid("第 %d 条规则名称必须为 1–80 个字符", position)
		}
		if !oneOf(rule.Kind, KindKeyword, KindRegex) || !oneOf(rule.Action, ActionBlock, ActionFlag) || SeverityRank(rule.Severity) == 0 {
			return nil, invalid("规则「%s」的类型、动作或严重度无效", rule.Name)
		}
		if rule.KeyMode == "" {
			rule.KeyMode = KeyModeAll
		}
		if !oneOf(rule.KeyMode, KeyModeAll, KeyModeInclude, KeyModeExclude) {
			return nil, invalid("规则「%s」的适用范围无效", rule.Name)
		}
		if len(rule.Patterns) > MaxPatternsPerRule || len(rule.Roles) > 4 || len(rule.KeyFingerprints) > MaxKeyFingerprints {
			return nil, invalid("规则列表超过预算")
		}
		patterns := make([]string, 0, len(rule.Patterns))
		for _, pattern := range rule.Patterns {
			if len(pattern) > MaxPatternBytes {
				return nil, invalid("匹配项超过预算")
			}
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			if len(pattern) > MaxPatternBytes || !utf8.ValidString(pattern) || strings.ContainsRune(pattern, 0) {
				return nil, invalid("规则「%s」包含超过 %d 字节或格式无效的匹配项", rule.Name, MaxPatternBytes)
			}
			total += len(pattern)
			if total > MaxTotalPatternBytes {
				return nil, invalid("全部匹配项超过预算")
			}
			patterns = append(patterns, pattern)
		}
		if len(patterns) == 0 || len(patterns) > MaxPatternsPerRule {
			return nil, invalid("规则「%s」需要 1–%d 个非空匹配项", rule.Name, MaxPatternsPerRule)
		}
		if total > MaxTotalPatternBytes {
			return nil, invalid("全部匹配项总长度不能超过 %d KiB", MaxTotalPatternBytes>>10)
		}
		rule.Patterns = patterns
		roles := make([]string, 0, len(rule.Roles))
		roleSeen := map[string]bool{}
		for _, role := range rule.Roles {
			if len(role) > 32 {
				return nil, invalid("消息角色超过预算")
			}
			role = strings.TrimSpace(role)
			if !oneOf(role, RoleUser, RoleSystem, RoleTool, RoleAssistant) {
				return nil, invalid("规则「%s」包含未知的消息角色", rule.Name)
			}
			if !roleSeen[role] {
				roleSeen[role] = true
				roles = append(roles, role)
			}
		}
		rule.Roles = roles
		fingerprints := make([]string, 0, len(rule.KeyFingerprints))
		fpSeen := map[string]bool{}
		for _, fp := range rule.KeyFingerprints {
			if len(fp) > 64 {
				return nil, invalid("Key 指纹超过预算")
			}
			fp = strings.ToLower(strings.TrimSpace(fp))
			if !ValidFingerprint(fp) {
				return nil, invalid("规则「%s」包含无效的 Key 指纹", rule.Name)
			}
			if !fpSeen[fp] {
				fpSeen[fp] = true
				fingerprints = append(fingerprints, fp)
			}
		}
		if len(fingerprints) > MaxKeyFingerprints {
			return nil, invalid("规则「%s」的 Key 数量不能超过 %d", rule.Name, MaxKeyFingerprints)
		}
		if rule.KeyMode == KeyModeAll {
			fingerprints = []string{}
		} else if len(fingerprints) == 0 {
			return nil, invalid("规则「%s」选择了指定 Key 范围但没有选择任何 Key", rule.Name)
		}
		rule.KeyFingerprints = fingerprints
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, invalid("规则「%s」无法编译：%s", rule.Name, safeCompileError(err))
		}
		totalInstructions += compiled.cost
		if totalInstructions > 65536 {
			return nil, invalid("全部规则编译指令超过预算")
		}
		out = append(out, rule)
	}
	return out, nil
}

func safeCompileError(err error) string {
	message := err.Error()
	if len(message) > 200 {
		message = message[:200]
	}
	return strings.ToValidUTF8(message, "")
}
