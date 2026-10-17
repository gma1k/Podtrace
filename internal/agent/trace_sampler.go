package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type keyedRatioSampler struct {
	key         []byte
	bound       uint64
	description string
}

// newKeyedRatioSampler returns a sampler keeping fraction of traces. Without
// a key it falls back to TraceIDRatioBased.
func newKeyedRatioSampler(fraction float64, key string) sdktrace.Sampler {
	if key == "" {
		return sdktrace.TraceIDRatioBased(fraction)
	}
	if fraction >= 1 {
		return sdktrace.AlwaysSample()
	}
	if fraction < 0 {
		fraction = 0
	}
	return &keyedRatioSampler{
		key:         []byte(key),
		bound:       uint64(fraction * (1 << 63)),
		description: fmt.Sprintf("KeyedTraceIDRatioBased{%g}", fraction),
	}
}

func (s *keyedRatioSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	tsc := trace.SpanContextFromContext(p.ParentContext).TraceState()
	mac := hmac.New(sha256.New, s.key)
	mac.Write(p.TraceID[:])
	sum := mac.Sum(nil)
	if binary.BigEndian.Uint64(sum[:8])>>1 < s.bound {
		return sdktrace.SamplingResult{Decision: sdktrace.RecordAndSample, Tracestate: tsc}
	}
	return sdktrace.SamplingResult{Decision: sdktrace.Drop, Tracestate: tsc}
}

func (s *keyedRatioSampler) Description() string { return s.description }
