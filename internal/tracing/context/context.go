package context

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type TraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Flags        uint8
	State        string
}

func NewTraceContext() *TraceContext {
	return &TraceContext{
		TraceID: generateTraceID(),
		SpanID:  generateSpanID(),
		Flags:   0x01,
	}
}

func (tc *TraceContext) IsValid() bool {
	return tc.TraceID != "" && tc.SpanID != ""
}

func (tc *TraceContext) HasRemoteParent() bool {
	return tc.TraceID != "" && tc.ParentSpanID != ""
}

func (tc *TraceContext) IsSampled() bool {
	return (tc.Flags & 0x01) == 0x01
}

func (tc *TraceContext) SetSampled(sampled bool) {
	if sampled {
		tc.Flags |= 0x01
	} else {
		tc.Flags &= 0xFE
	}
}

func (tc *TraceContext) CreateChild() *TraceContext {
	child := &TraceContext{
		TraceID:      tc.TraceID,
		ParentSpanID: tc.SpanID,
		SpanID:       generateSpanID(),
		Flags:        tc.Flags,
		State:        tc.State,
	}
	return child
}

func generateTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func generateSpanID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// NewTraceContextFromSeed derives a TraceContext whose TraceID is a stable
// function of seed.
func NewTraceContextFromSeed(seed string) *TraceContext {
	sum := sha256.Sum256([]byte(seed))
	return &TraceContext{
		TraceID: hex.EncodeToString(sum[:16]),
		SpanID:  generateSpanID(),
		Flags:   0x01,
	}
}

// isLowerHex reports whether s is non-empty and composed solely of lowercase
// hexadecimal digits, as the W3C trace-context spec requires for trace-id,
// parent-id and trace-flags.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return false
		}
	}
	return true
}

// isAllZeroHex reports whether s consists entirely of '0'. The all-zero
// trace-id and parent-id are explicitly invalid per the W3C spec.
func isAllZeroHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

func ParseW3CTraceParent(traceParent string) (*TraceContext, error) {
	if traceParent == "" {
		return nil, fmt.Errorf("empty traceparent")
	}

	parts := strings.Split(traceParent, "-")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid traceparent format")
	}

	if parts[0] != "00" {
		return nil, fmt.Errorf("unsupported version: %s", parts[0])
	}

	traceID := parts[1]
	parentID := parts[2]
	flags := parts[3]

	if len(traceID) != 32 || !isLowerHex(traceID) {
		return nil, fmt.Errorf("invalid trace ID: %q", traceID)
	}
	if isAllZeroHex(traceID) {
		return nil, fmt.Errorf("trace ID must not be all zero")
	}
	if len(parentID) != 16 || !isLowerHex(parentID) {
		return nil, fmt.Errorf("invalid parent ID: %q", parentID)
	}
	if isAllZeroHex(parentID) {
		return nil, fmt.Errorf("parent ID must not be all zero")
	}
	if len(flags) != 2 || !isLowerHex(flags) {
		return nil, fmt.Errorf("invalid flags: %q", flags)
	}

	var flagsByte uint8
	if _, err := fmt.Sscanf(flags, "%02x", &flagsByte); err != nil {
		return nil, fmt.Errorf("invalid flags: %w", err)
	}

	return &TraceContext{
		TraceID:      traceID,
		ParentSpanID: parentID,
		Flags:        flagsByte,
	}, nil
}

func ParseB3TraceContext(headers map[string]string) *TraceContext {
	var traceID, spanID, parentSpanID, sampled, flags string

	for k, v := range headers {
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "x-b3-traceid":
			traceID = v
		case "x-b3-spanid":
			spanID = v
		case "x-b3-parentspanid":
			parentSpanID = v
		case "x-b3-sampled":
			sampled = v
		case "x-b3-flags":
			flags = v
		}
	}

	traceID, ok := normalizeB3TraceID(traceID)
	if !ok {
		return nil
	}
	spanID = strings.ToLower(spanID)
	if len(spanID) != 16 || !isLowerHex(spanID) || isAllZeroHex(spanID) {
		return nil
	}

	_ = parentSpanID
	tc := &TraceContext{
		TraceID:      traceID,
		ParentSpanID: spanID,
	}

	if sampled == "1" || sampled == "true" || flags == "1" {
		tc.Flags = 0x01
	}

	return tc
}

// normalizeB3TraceID validates an x-b3-traceid and widens it to the 32 hex
// digits W3C and OpenTelemetry use.
func normalizeB3TraceID(traceID string) (string, bool) {
	traceID = strings.ToLower(traceID)
	if len(traceID) != 16 && len(traceID) != 32 {
		return "", false
	}
	if !isLowerHex(traceID) || isAllZeroHex(traceID) {
		return "", false
	}
	if len(traceID) == 16 {
		traceID = strings.Repeat("0", 16) + traceID
	}
	return traceID, true
}

func (tc *TraceContext) ToW3CTraceParent() string {
	if !tc.IsValid() {
		return ""
	}
	flags := fmt.Sprintf("%02x", tc.Flags)
	return fmt.Sprintf("00-%s-%s-%s", tc.TraceID, tc.SpanID, flags)
}

func (tc *TraceContext) ToB3Headers() map[string]string {
	if !tc.IsValid() {
		return nil
	}
	headers := map[string]string{
		"X-B3-TraceId": tc.TraceID,
		"X-B3-SpanId":  tc.SpanID,
	}
	if tc.ParentSpanID != "" {
		headers["X-B3-ParentSpanID"] = tc.ParentSpanID
	}
	if tc.IsSampled() {
		headers["X-B3-Sampled"] = "1"
	}
	return headers
}
