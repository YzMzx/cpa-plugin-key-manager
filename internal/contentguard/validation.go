package contentguard

import "unicode/utf8"

// validateEvent is a storage trust boundary, independent of handler validation.
func validateEvent(e Event) error {
	if !oneOf(e.Action, EventBlocked, EventFlagged) || !oneOf(e.Mode, ModeObserve, ModeEnforce) || SeverityRank(e.Severity) == 0 || (e.ReviewStatus != "" && !ValidReview(e.ReviewStatus)) {
		return ErrInvalid
	}
	if !oneOf(e.AutoDisabled, "", "disabled", "skipped", "failed") || e.CreatedAt < 0 || e.ReviewedAt < 0 {
		return ErrInvalid
	}
	if e.KeyFingerprint != "" && !ValidFingerprint(e.KeyFingerprint) {
		return ErrInvalid
	}
	if e.OriginalSHA256 != "" && !ValidFingerprint(e.OriginalSHA256) {
		return ErrInvalid
	}
	for _, value := range []string{e.RequestID, e.TraceID, e.Path, e.Protocol, e.RequestedModel, e.ServedModel, e.KeyName, e.KeyMasked, e.BodyState} {
		if !safeText(value, 512) {
			return ErrInvalid
		}
	}
	if len(e.Body) > 1<<20 || !utf8.ValidString(e.Body) || e.BodyBytes < 0 || e.OriginalBytes < 0 || len(e.ReviewNote) > 2000 || !utf8.ValidString(e.ReviewNote) {
		return ErrInvalid
	}
	if e.Body != "" {
		if e.BodyState != "stored_json_filtered" || e.BodySHA256 != digest([]byte(e.Body)) || e.BodyBytes != len(e.Body) {
			return ErrInvalid
		}
		if _, err := decodeJSON([]byte(e.Body), 1<<20); err != nil {
			return ErrInvalid
		}
	} else if e.BodySHA256 != "" || e.BodyBytes != 0 || !(e.BodyState == "" || e.BodyState == "empty" || e.BodyState == "disabled" || e.BodyState == "omitted_disabled" || e.BodyState == "omitted_invalid" || e.BodyState == "omitted_budget" || e.BodyState == "omitted_oversize" || e.BodyState == "omitted_output_budget" || e.BodyState == "omitted_encoding" || e.BodyState == "omitted_content_type" || e.BodyState == "omitted_processing_limit") {
		return ErrInvalid
	}
	if len(e.RuleNames) > MaxRules+2 || len(e.Matches) > MaxRules*maxMatchesPerRule+2 {
		return ErrInvalid
	}
	for _, name := range e.RuleNames {
		if !safeText(name, 320) {
			return ErrInvalid
		}
	}
	for _, m := range e.Matches {
		if !oneOf(m.Source, "rule", "classifier", "system", "error") || !oneOf(m.Action, ActionBlock, ActionFlag) || SeverityRank(m.Severity) == 0 || !validScore(m.Score) {
			return ErrInvalid
		}
		if !safeText(m.RuleID, 64) || !safeText(m.RuleName, 320) || !safeText(m.Path, 2048) || !safeText(m.Role, 32) || !safeText(m.Category, 80) {
			return ErrInvalid
		}
		if len(m.Matched) > maxMatchedBytes || len(m.Snippet) > maxMatchedBytes+1006 || !utf8.ValidString(m.Matched) || !utf8.ValidString(m.Snippet) || m.Offset < 0 || m.Offset > len(m.Snippet) {
			return ErrInvalid
		}
	}
	if e.Classifier != nil {
		c := e.Classifier
		if !validScore(c.Score) || !safeText(c.Category, 80) || len(c.Reason) > 1200 || !utf8.ValidString(c.Reason) || !safeText(c.Error, 80) {
			return ErrInvalid
		}
	}
	return nil
}
