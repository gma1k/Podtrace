package context

import (
	"crypto/rand"
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

	if len(traceID) != 32 {
		return nil, fmt.Errorf("invalid trace ID length: %d", len(traceID))
	}
	if len(parentID) != 16 {
		return nil, fmt.Errorf("invalid parent ID length: %d", len(parentID))
	}
	if len(flags) != 2 {
		return nil, fmt.Errorf("invalid flags length: %d", len(flags))
	}

	var flagsByte uint8
	if _, err := fmt.Sscanf(flags, "%02x", &flagsByte); err != nil {
		return nil, fmt.Errorf("invalid flags: %w", err)
	}

	return &TraceContext{
		TraceID:      traceID,
		ParentSpanID: parentID,
		SpanID:       generateSpanID(),
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

	if traceID == "" || spanID == "" {
		return nil
	}

	tc := &TraceContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
	}

	if sampled == "1" || sampled == "true" || flags == "1" {
		tc.Flags = 0x01
	}

	return tc
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
