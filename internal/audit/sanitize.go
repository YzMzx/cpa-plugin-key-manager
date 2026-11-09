package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	auditBodyHardLimit    = 32 * 1024
	auditBodyInputLimit   = 256 * 1024
	auditBodyDepthLimit   = 16
	auditBodyElementLimit = 4096
	auditBodyStringLimit  = 4096
)

// BodyResult contains only safely sanitized JSON, never a raw prefix or raw hash.
// SHA256 identifies the retained sanitized representation; it is not tamperproof
// evidence and does not claim comprehensive PII detection. Empty/omitted bodies
// have no digest. Truncated means a safety limit discarded content, not raw slicing.
type BodyResult struct {
	Body      string `json:"body"`
	State     string `json:"state"`
	Truncated bool   `json:"truncated"`
	SHA256    string `json:"sha256"`
	Redacted  bool   `json:"redacted"`
}

var (
	auditBasicPattern       = regexp.MustCompile(`(?i)\b(?:Basic|Digest)[\t\r\n ]+[^\r\n;<>]+`)
	auditBearerPattern      = regexp.MustCompile(`(?i)\bBearer[\t\r\n ]+[^\s,;"'<>]+`)
	auditKeyPattern         = regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]+`)
	auditEmailPattern       = regexp.MustCompile(`(?i)[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,}`)
	auditPhonePattern       = regexp.MustCompile(`(?:\+?[0-9][0-9 .()\-]{7,}[0-9])`)
	auditOpaquePattern      = regexp.MustCompile(`[A-Za-z0-9+/_=-]{64,}`)
	auditURLPattern         = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|/)[^\s<>"'\\]+`)
	auditQuerySecretPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|password|passwd|authorization|access[_-]?token|refresh[_-]?token|token|secret|cookie|email|phone)["']?[\t ]*[:=][\t ]*["']?[^\s&,;"'}]+`)
)

// SanitizeBody retains only bounded JSON objects/arrays. It does not decode
// compression, binary data, Base64, or content-transfer encodings. Callers should
// pass actual active credentials in secrets in addition to pattern redaction.
func SanitizeBody(body []byte, contentType, contentEncoding string, maxBytes int, secrets ...string) BodyResult {
	omitted := func(state string, limit bool) BodyResult { return BodyResult{State: state, Truncated: limit} }
	if len(body) == 0 {
		return BodyResult{State: "empty"}
	}
	if maxBytes <= 0 {
		return omitted("omitted_disabled", false)
	}
	if maxBytes > auditBodyHardLimit {
		maxBytes = auditBodyHardLimit
	}
	encoding := strings.TrimSpace(contentEncoding)
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return omitted("omitted_encoding", false)
	}
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return omitted("omitted_non_json", false)
	}
	media = strings.ToLower(media)
	if media != "application/json" && !(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json")) {
		return omitted("omitted_non_json", false)
	}
	if len(body) > auditBodyInputLimit {
		return omitted("omitted_input_limit", true)
	}
	if !utf8.Valid(body) {
		return omitted("omitted_invalid_json", false)
	}
	if len(secrets) > 128 {
		return omitted("omitted_secret_limit", true)
	}
	safeSecrets := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if len(secret) > auditBodyStringLimit {
			return omitted("omitted_secret_limit", true)
		}
		safeSecrets = append(safeSecrets, secret)
	}
	sort.Slice(safeSecrets, func(i, j int) bool { return len(safeSecrets[i]) > len(safeSecrets[j]) })
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	parser := auditBodyParser{decoder: decoder, secrets: safeSecrets}
	value, ok := parser.value(0)
	if !ok || parser.failure != "" {
		return omitted(parser.failure, parser.limited)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return omitted("omitted_invalid_json", false)
	}
	switch value.(type) {
	case map[string]any, []any:
	default:
		return omitted("omitted_non_container", false)
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(true)
	if encoder.Encode(value) != nil {
		return omitted("omitted_invalid_json", false)
	}
	result := bytes.TrimSuffix(output.Bytes(), []byte("\n"))
	for _, secret := range safeSecrets {
		if bytes.Contains(result, []byte(secret)) {
			return omitted("omitted_secret_collision", false)
		}
	}
	if len(result) > maxBytes {
		return omitted("omitted_output_limit", true)
	}
	digest := sha256.Sum256(result)
	return BodyResult{Body: string(result), State: "stored", SHA256: hex.EncodeToString(digest[:]), Redacted: parser.redacted}
}

type auditBodyParser struct {
	decoder  *json.Decoder
	secrets  []string
	elements int
	redacted bool
	failure  string
	limited  bool
}

func (p *auditBodyParser) fail(state string, limit bool) (any, bool) {
	p.failure = state
	p.limited = limit
	return nil, false
}
func (p *auditBodyParser) value(depth int) (any, bool) {
	if depth > auditBodyDepthLimit {
		return p.fail("omitted_depth_limit", true)
	}
	p.elements++
	if p.elements > auditBodyElementLimit {
		return p.fail("omitted_element_limit", true)
	}
	token, err := p.decoder.Token()
	if err != nil {
		return p.fail("omitted_invalid_json", false)
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := make(map[string]any)
			for p.decoder.More() {
				keyToken, err := p.decoder.Token()
				if err != nil {
					return p.fail("omitted_invalid_json", false)
				}
				key, ok := keyToken.(string)
				if !ok {
					return p.fail("omitted_invalid_json", false)
				}
				if len(key) > auditBodyStringLimit {
					return p.fail("omitted_string_limit", true)
				}
				p.elements++
				if p.elements > auditBodyElementLimit {
					return p.fail("omitted_element_limit", true)
				}
				child, ok := p.value(depth + 1)
				if !ok {
					return nil, false
				}
				safeKey := p.cleanString(key)
				if _, exists := object[safeKey]; exists {
					return p.fail("omitted_ambiguous_json", false)
				}
				if auditMediaField(key) {
					object[safeKey] = "[OMITTED:media]"
					p.redacted = true
					continue
				}
				if auditSensitiveField(key) {
					object[safeKey] = "[REDACTED]"
					p.redacted = true
					continue
				}
				object[safeKey] = child
			}
			end, err := p.decoder.Token()
			if err != nil || end != json.Delim('}') {
				return p.fail("omitted_invalid_json", false)
			}
			return object, true
		case '[':
			array := make([]any, 0)
			for p.decoder.More() {
				value, ok := p.value(depth + 1)
				if !ok {
					return nil, false
				}
				array = append(array, value)
			}
			end, err := p.decoder.Token()
			if err != nil || end != json.Delim(']') {
				return p.fail("omitted_invalid_json", false)
			}
			return array, true
		default:
			return p.fail("omitted_invalid_json", false)
		}
	case string:
		if len(token) > auditBodyStringLimit {
			return p.fail("omitted_string_limit", true)
		}
		return p.cleanString(token), true
	case json.Number:
		if len(token) > 128 {
			return p.fail("omitted_number_limit", true)
		}
		for _, secret := range p.secrets {
			if strings.Contains(string(token), secret) {
				p.redacted = true
				return "[REDACTED]", true
			}
		}
		return token, true
	case bool, nil:
		return token, true
	default:
		return p.fail("omitted_invalid_json", false)
	}
}

func auditFieldName(key string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, key)
}
func auditSensitiveField(key string) bool {
	name := auditFieldName(key)
	switch name {
	case "apikey", "apikeys", "key", "password", "passwd", "pwd", "authorization", "proxyauthorization", "token", "tokens", "accesstoken", "refreshtoken", "idtoken", "authtoken", "sessiontoken", "cookie", "cookies", "setcookie", "email", "emailaddress", "phone", "phonenumber", "telephone", "mobile", "mobilenumber", "secret", "clientsecret", "privatekey", "credential", "credentials", "ssn", "socialsecuritynumber", "creditcard", "cardnumber", "address", "headers", "requestheaders", "responseheaders":
		return true
	}
	for _, suffix := range []string{"password", "apikey", "authorization", "email", "phone", "phonenumber", "token", "cookie", "accesstoken", "refreshtoken", "secret", "secretkey", "secretaccesskey", "signingkey", "encryptionkey", "privatekey", "accesskeyid"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
func auditMediaField(key string) bool {
	switch auditFieldName(key) {
	case "image", "images", "imageurl", "imageurls", "audio", "audioinput", "inputaudio", "audiooutput", "video", "videos", "data", "inlinedata", "file", "files", "filedata", "filecontent", "attachment", "attachments", "base64", "b64json", "imagedata", "audiodata", "binary", "bytes":
		return true
	}
	return false
}

func (p *auditBodyParser) cleanString(value string) string {
	original := value
	for _, secret := range p.secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	value = auditURLPattern.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "[OMITTED:url]"
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery {
			parsed.User = nil
			parsed.RawQuery = ""
			parsed.Fragment = ""
			parsed.RawFragment = ""
			parsed.ForceQuery = false
			return parsed.String()
		}
		return raw
	})
	value = auditBearerPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = auditBasicPattern.ReplaceAllString(value, "Basic [REDACTED]")
	value = auditKeyPattern.ReplaceAllString(value, "[REDACTED]")
	value = auditEmailPattern.ReplaceAllString(value, "[REDACTED]")
	value = auditQuerySecretPattern.ReplaceAllString(value, "[REDACTED]")
	value = auditPhonePattern.ReplaceAllString(value, "[REDACTED]")
	value = auditOpaquePattern.ReplaceAllString(value, "[OMITTED:opaque]")
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "data:") || auditLooksOpaque(value) {
		value = "[OMITTED:opaque]"
	}
	for _, secret := range p.secrets {
		if secret != "" && strings.Contains(value, secret) {
			p.failure = "omitted_secret_collision"
			return ""
		}
	}
	if value != original {
		p.redacted = true
	}
	return value
}

func auditLooksOpaque(value string) bool {
	if len(value) < 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("+/=_-", r)) {
			return false
		}
	}
	return true
}

// SanitizeText applies the same known-secret/pattern policy to bounded metadata.
// It is not a comprehensive PII detector. Control/HTML characters are represented
// with readable escapes, and an unsafe-size value is omitted rather than sliced.
func SanitizeText(raw string, maxBytes int, secrets ...string) string {
	if maxBytes <= 0 {
		return ""
	}
	if maxBytes > auditBodyHardLimit {
		maxBytes = auditBodyHardLimit
	}
	omit := func() string {
		const marker = "[OMITTED:limit]"
		if len(marker) <= maxBytes {
			return marker
		}
		return ""
	}
	if len(raw) > auditBodyStringLimit || !utf8.ValidString(raw) || len(secrets) > 128 {
		return omit()
	}
	for _, secret := range secrets {
		if len(secret) > auditBodyStringLimit {
			return omit()
		}
	}
	p := auditBodyParser{secrets: secrets}
	result := p.cleanString(raw)
	if p.failure != "" {
		return omit()
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return omit()
	}
	escaped := string(encoded[1 : len(encoded)-1])
	if len(escaped) > maxBytes {
		return omit()
	}
	return escaped
}
