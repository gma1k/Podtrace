package redactor_test

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/redactor"
)

func TestRedact_DNSNames_CoversQUICServerName(t *testing.T) {
	cases := map[string]string{
		"sni: secret-internal.example.com alpn: h3": "sni: [redacted] alpn: h3",
		"sni: secret-internal.example.com":          "sni: [redacted]",
		"HTTP/3 (QUIC)":                             "HTTP/3 (QUIC)",
	}
	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "true")
	for details, want := range cases {
		e := &events.Event{Type: events.EventHTTP3, Target: "10.0.0.1:443", Details: details}
		redactor.Default().Redact(e)
		if e.Details != want {
			t.Errorf("Details %q redacted to %q, want %q", details, e.Details, want)
		}
	}

	t.Setenv("PODTRACE_REDACT_DNS_NAMES", "")
	e := &events.Event{Type: events.EventHTTP3, Details: "sni: kept.example.com alpn: h3"}
	redactor.Default().Redact(e)
	if e.Details != "sni: kept.example.com alpn: h3" {
		t.Errorf("SNI redacted with DNS-name redaction off: %q", e.Details)
	}
}
