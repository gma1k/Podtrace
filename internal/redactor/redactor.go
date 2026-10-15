package redactor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// Rule describes one PII redaction pattern applied to event string fields.
type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Replace  string
	Validate func(match string) bool
}

// ruleSpec is the JSON shape of a custom rule as carried in the
// PODTRACE_REDACT_CUSTOM_RULES env var.
type ruleSpec struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// Redactor applies a list of Rules to event Target and Details fields in-place.
type Redactor struct {
	rules          []Rule
	redactDNSNames bool
}

// Default returns a Redactor with built-in rules for common PII patterns.
func Default() *Redactor {
	return &Redactor{
		rules:          defaultRules(),
		redactDNSNames: config.RedactDNSNames(),
	}
}

// New creates a Redactor with the provided rules.
func New(rules []Rule) *Redactor {
	return &Redactor{rules: rules}
}

// DefaultWithCustomRules returns a Redactor with the built-in rules plus any
// custom rules parsed from jsonSpec (a JSON array of {name,pattern,replace}).
func DefaultWithCustomRules(jsonSpec string) (*Redactor, error) {
	r := Default()
	if jsonSpec == "" {
		return r, nil
	}
	extra, err := ParseRules(jsonSpec)
	r.rules = append(r.rules, extra...)
	return r, err
}

// ParseRules compiles a JSON array of custom rules into Rules.
func ParseRules(jsonSpec string) ([]Rule, error) {
	var specs []ruleSpec
	if err := json.Unmarshal([]byte(jsonSpec), &specs); err != nil {
		return nil, fmt.Errorf("redactor: parse custom rules: %w", err)
	}
	rules := make([]Rule, 0, len(specs))
	var firstErr error
	for i, s := range specs {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			if firstErr == nil {
				name := s.Name
				if name == "" {
					name = fmt.Sprintf("#%d", i)
				}
				firstErr = fmt.Errorf("redactor: rule %q has invalid pattern: %w", name, err)
			}
			continue
		}
		rules = append(rules, Rule{Name: s.Name, Pattern: re, Replace: s.Replace})
	}
	return rules, firstErr
}

// Redact modifies e.Target and e.Details in-place, applying all rules.
func (r *Redactor) Redact(e *events.Event) {
	if e == nil {
		return
	}
	if r.redactDNSNames {
		switch e.Type {
		case events.EventDNS, events.EventDNSQuery:
			e.Target = "[redacted]"
			if e.Details != "" {
				e.Details = "[redacted]"
			}
		case events.EventConnect:
			if e.Details != "" {
				e.Details = "[redacted]"
			}
		case events.EventHTTP3:
			e.Details = redactSNI(e.Details)
		}
	}
	e.Target = r.applyRules(e.Target)
	e.Details = r.applyRules(e.Details)
	e.TraceState = r.applyRules(e.TraceState)
}

func (r *Redactor) RedactText(s string) string {
	return r.applyRules(s)
}

// applyRules runs every rule over s. A rule without Validate uses a straight
// regex replace (with $-group expansion).
func (r *Redactor) applyRules(s string) string {
	for _, rule := range r.rules {
		if rule.Validate == nil {
			s = rule.Pattern.ReplaceAllString(s, rule.Replace)
			continue
		}
		rule := rule
		s = rule.Pattern.ReplaceAllStringFunc(s, func(m string) string {
			if !rule.Validate(m) {
				return m
			}
			idx := rule.Pattern.FindStringSubmatchIndex(m)
			return string(rule.Pattern.ExpandString(nil, rule.Replace, m, idx))
		})
	}
	return s
}

// luhnValid reports whether the digits in s form a Luhn-valid sequence of a
// plausible card length (13–19 digits).
func luhnValid(s string) bool {
	digits := make([]int, 0, len(s))
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// credentialKeyNames is the single source of truth for the key names whose
// values are treated as secrets, shared by the key=value, JSON, and YAML
// rules so coverage cannot drift between formats.
const credentialKeyNames = `password|passwd|pwd|token|api[_-]?key|apikey|secret|access[_-]?key|` +
	`authorization|auth|bearer|session[_-]?id|jsessionid|phpsessid|asp\.net_sessionid|session|sid|` +
	`csrf[_-]?token|xsrf[_-]?token|refresh[_-]?token|id[_-]?token|` +
	`private[_-]?key|client[_-]?key|passphrase|signature|credentials?`

// sensitiveHeaderNames are HTTP header names whose entire value is a
// credential (or a cookie jar of them).
const sensitiveHeaderNames = `cookie|set-cookie|authorization|proxy-authorization|` +
	`www-authenticate|proxy-authenticate|` +
	`x-auth-token|x-api-key|x-csrf-token|x-xsrf-token`

func defaultRules() []Rule {
	return []Rule{
		{
			Name:    "sensitive_headers",
			Pattern: regexp.MustCompile(`(?im)^(` + sensitiveHeaderNames + `)[ \t]*:[ \t]*.+$`),
			Replace: "${1}: ***",
		},
		{
			Name:    "credential_kv",
			Pattern: regexp.MustCompile(`(?i)(` + credentialKeyNames + `)=[^\s&;,]+`),
			Replace: "${1}=***",
		},
		{
			Name:    "bearer_token",
			Pattern: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/\-]+=*`),
			Replace: "Bearer ***",
		},
		{
			Name:    "basic_auth",
			Pattern: regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/]+=*`),
			Replace: "Basic ***",
		},
		{
			Name:    "url_userinfo",
			Pattern: regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://)[^/@\s]+@`),
			Replace: "${1}***@",
		},
		{
			Name:    "credential_json",
			Pattern: regexp.MustCompile(`(?i)"(` + credentialKeyNames + `)"\s*:\s*"[^"]*"`),
			Replace: `"${1}":"***"`,
		},
		{
			Name:    "credential_yaml",
			Pattern: regexp.MustCompile(`(?i)\b(` + credentialKeyNames + `)\s*:\s*[^\s,}]+`),
			Replace: "${1}: ***",
		},
		{
			Name:    "email",
			Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Replace: "***@***",
		},
		{
			Name:     "credit_card",
			Pattern:  regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`),
			Replace:  "****-****-****-****",
			Validate: luhnValid,
		},
	}
}

// redactSNI blanks the server name of a QUIC connection event ("sni: <host>
// alpn: <protocols>"), keeping the ALPN, which names no host.
func redactSNI(details string) string {
	const sniPrefix, alpnMarker = "sni: ", " alpn: "
	if !strings.HasPrefix(details, sniPrefix) {
		return details
	}
	redacted := sniPrefix + "[redacted]"
	if i := strings.Index(details, alpnMarker); i >= 0 {
		redacted += details[i:]
	}
	return redacted
}
