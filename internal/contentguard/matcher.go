package contentguard

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// compiledRule is an immutable, ready-to-scan rule. Keyword rules compile into
// one alternation of quoted literals; Go's RE2 engine runs in linear time, so
// administrator patterns cannot cause catastrophic backtracking.
type compiledRule struct {
	rule     Rule
	re       *regexp.Regexp
	keywords []string
	roles    map[string]bool
	keys     map[string]bool
	cost     int64
}

func compileRule(rule Rule) (*compiledRule, error) {
	c := &compiledRule{rule: rule}
	if len(rule.Roles) > 0 {
		c.roles = make(map[string]bool, len(rule.Roles))
		for _, role := range rule.Roles {
			c.roles[role] = true
		}
	}
	if len(rule.KeyFingerprints) > 0 {
		c.keys = make(map[string]bool, len(rule.KeyFingerprints))
		for _, fp := range rule.KeyFingerprints {
			c.keys[fp] = true
		}
	}
	switch rule.Kind {
	case KindKeyword:
		parts := make([]string, 0, len(rule.Patterns))
		for _, pattern := range rule.Patterns {
			folded := Normalize(pattern)
			if folded == "" {
				continue
			}
			c.keywords = append(c.keywords, folded)
			parts = append(parts, regexp.QuoteMeta(folded))
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("no usable keyword")
		}
		re, err := regexp.Compile(strings.Join(parts, "|"))
		if err != nil {
			return nil, err
		}
		c.re = re
	case KindRegex:
		parts := make([]string, 0, len(rule.Patterns))
		for _, pattern := range rule.Patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				return nil, err
			}
			parts = append(parts, "(?:"+pattern+")")
		}
		// Regular expressions run on the normalized (lower-cased) text; (?i)
		// keeps upper-case administrator patterns meaningful as well.
		re, err := regexp.Compile("(?i)" + strings.Join(parts, "|"))
		if err != nil {
			return nil, err
		}
		c.re = re
	default:
		return nil, fmt.Errorf("unknown kind")
	}
	tree, err := syntax.Parse(c.re.String(), syntax.Perl)
	if err != nil {
		return nil, err
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, err
	}
	if len(prog.Inst) > 16384 {
		return nil, fmt.Errorf("compiled rule exceeds instruction budget")
	}
	c.cost = int64(len(prog.Inst))
	return c, nil
}

func (c *compiledRule) appliesToKey(fingerprint string) bool {
	switch c.rule.KeyMode {
	case KeyModeInclude:
		return c.keys[fingerprint]
	case KeyModeExclude:
		return !c.keys[fingerprint]
	default:
		return true
	}
}

func (c *compiledRule) appliesToRole(role string) bool {
	return c.roles == nil || c.roles[role]
}

// Engine is an immutable compiled rule set. A new engine is published on every
// configuration change; scans never take a lock.
type Engine struct {
	rules []*compiledRule
}

// NewEngine compiles validated rules. Disabled rules are skipped.
func NewEngine(rules []Rule) (*Engine, error) {
	validated, err := ValidateRules(rules)
	if err != nil {
		return nil, err
	}
	engine := &Engine{}
	rules = validated
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		engine.rules = append(engine.rules, compiled)
	}
	return engine, nil
}

// RuleCount reports enabled rules.
func (e *Engine) RuleCount() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Match is one rule hit with a bounded snippet of the original text.
type Match struct {
	Source   string  `json:"source"` // "rule" or "classifier"
	RuleID   string  `json:"rule_id,omitempty"`
	RuleName string  `json:"rule_name"`
	Action   string  `json:"action"`
	Severity string  `json:"severity"`
	Role     string  `json:"role,omitempty"`
	Path     string  `json:"path,omitempty"`
	Matched  string  `json:"matched,omitempty"`
	Snippet  string  `json:"snippet,omitempty"`
	Offset   int     `json:"offset"` // byte offset of Matched inside Snippet
	Score    float64 `json:"score,omitempty"`
	Category string  `json:"category,omitempty"`
}

const maxMatchesPerRule = 3
const maxMatchedBytes = 200

// ErrScanBudget means the scan is incomplete, not a clean verdict.
var ErrScanBudget = errors.New("content scan work budget exceeded")

const MaxScanWork int64 = 32 << 20
const MaxSegmentScanBytes = 256 << 10

// Scan preserves the original API; callers enforcing incomplete-scan policy
// must use ScanChecked. Partial hits are returned on a budget/cancellation error.
func (e *Engine) Scan(segments []Segment, fingerprint string, contextBytes int) []Match {
	matches, _ := e.ScanChecked(context.Background(), segments, fingerprint, contextBytes)
	return matches
}

// ScanChecked has hard input/work ceilings and checks cancellation between
// bounded RE2 calls. No worker goroutines can outlive a canceled request.
func (e *Engine) ScanChecked(ctx context.Context, segments []Segment, fingerprint string, contextBytes int) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e == nil || len(e.rules) == 0 || len(segments) == 0 {
		return nil, nil
	}
	if len(segments) > MaxSegments || len(fingerprint) > 64 {
		return nil, ErrScanBudget
	}
	contextBytes = max(0, min(contextBytes, 500))
	total := 0
	for _, segment := range segments {
		if len(segment.Text) > MaxSegmentScanBytes || len(segment.Path) > 2048 || !utf8.ValidString(segment.Text) {
			return nil, ErrScanBudget
		}
		total += len(segment.Text)
		if total > 2<<20 {
			return nil, ErrScanBudget
		}
	}
	folded := make([]normalized, len(segments))
	for i, segment := range segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		folded[i] = normalize(segment.Text)
	}
	var matches []Match
	remaining := MaxScanWork
	for _, rule := range e.rules {
		if !rule.appliesToKey(fingerprint) {
			continue
		}
		hits := 0
		for i, segment := range segments {
			if err := ctx.Err(); err != nil {
				return matches, err
			}
			if !rule.appliesToRole(segment.Role) {
				continue
			}
			cost := (int64(len(folded[i].text)) + 1) * rule.cost
			if cost > remaining {
				return matches, ErrScanBudget
			}
			remaining -= cost
			loc := rule.re.FindStringIndex(folded[i].text)
			if loc == nil || loc[0] == loc[1] {
				continue
			}
			from, to := folded[i].originalSpan(loc[0], loc[1])
			snippet, offset, matched := makeSnippet(segment.Text, from, to, contextBytes)
			matches = append(matches, Match{Source: "rule", RuleID: rule.rule.ID, RuleName: rule.rule.Name, Action: rule.rule.Action, Severity: rule.rule.Severity, Role: segment.Role, Path: segment.Path, Matched: matched, Snippet: snippet, Offset: offset})
			hits++
			if hits >= maxMatchesPerRule {
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return matches, err
	}
	return matches, nil
}

// makeSnippet returns valid UTF-8 context around [from,to) bounded by
// contextBytes on each side, the offset of the hit inside the snippet and the
// hit itself (capped).
func makeSnippet(text string, from, to, contextBytes int) (string, int, string) {
	contextBytes = max(0, min(contextBytes, 500))
	from = min(from, len(text))
	if from < 0 {
		from = 0
	}
	if to > len(text) {
		to = len(text)
	}
	if to < from {
		to = from
	}
	matched := text[from:to]
	if len(matched) > maxMatchedBytes {
		cut := maxMatchedBytes
		for cut > 0 && !utf8.RuneStart(matched[cut]) {
			cut--
		}
		matched = matched[:cut]
		to = from + cut
	}
	start := from - contextBytes
	if start < 0 {
		start = 0
	}
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	end := to + contextBytes
	if end > len(text) {
		end = len(text)
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	snippet := text[start:end]
	return strings.ToValidUTF8(snippet, "\uFFFD"), from - start, strings.ToValidUTF8(matched, "\uFFFD")
}

// Decide combines matches: in enforce mode any block action blocks the request.
// It returns the effective event action and the highest severity.
func Decide(mode string, matches []Match) (blocked bool, severity string) {
	best := 0
	for _, match := range matches {
		if rank := SeverityRank(match.Severity); rank > best {
			best, severity = rank, match.Severity
		}
		if match.Action == ActionBlock && mode == ModeEnforce {
			blocked = true
		}
	}
	return blocked, severity
}
