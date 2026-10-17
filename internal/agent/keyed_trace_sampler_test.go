package agent

import (
	"context"
	"encoding/binary"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func traceIDWithLowBits(n uint64) trace.TraceID {
	var id trace.TraceID
	binary.BigEndian.PutUint64(id[8:], n)
	id[0] = 0x4b
	return id
}

func sampled(s sdktrace.Sampler, id trace.TraceID) bool {
	return s.ShouldSample(sdktrace.SamplingParameters{ParentContext: context.Background(), TraceID: id}).Decision == sdktrace.RecordAndSample
}

func TestChosenLowTraceIDsNoLongerForceSampling(t *testing.T) {
	plain := sdktrace.TraceIDRatioBased(0.01)
	keyed := newKeyedRatioSampler(0.01, "6f1c2d1e-0b7a-4f5e-9c1d-1a2b3c4d5e6f")

	plainHits, keyedHits := 0, 0
	for i := uint64(0); i < 2000; i++ {
		id := traceIDWithLowBits(i)
		if sampled(plain, id) {
			plainHits++
		}
		if sampled(keyed, id) {
			keyedHits++
		}
	}
	if plainHits != 2000 {
		t.Fatalf("precondition: TraceIDRatioBased sampled %d/2000 chosen ids, want all", plainHits)
	}
	if keyedHits > 100 {
		t.Errorf("keyed sampler sampled %d/2000 attacker-chosen ids at 1%%, want close to 20", keyedHits)
	}
}

func TestKeyedSamplingIsConsistentForOneCRAndHonoursTheRatio(t *testing.T) {
	a := newKeyedRatioSampler(0.25, "uid-1")
	b := newKeyedRatioSampler(0.25, "uid-1")
	hits := 0
	for i := uint64(0); i < 20000; i++ {
		id := traceIDWithLowBits(i * 7919)
		if sampled(a, id) != sampled(b, id) {
			t.Fatalf("two agents with the same CR disagreed on trace %s", id)
		}
		if sampled(a, id) {
			hits++
		}
	}
	if hits < 4500 || hits > 5500 {
		t.Errorf("sampled %d/20000 at 25%%, want about 5000", hits)
	}
}

func TestKeyedSamplerEdgesAndFallback(t *testing.T) {
	id := traceIDWithLowBits(42)
	if sampled(newKeyedRatioSampler(0, "uid"), id) {
		t.Error("a zero ratio sampled a trace")
	}
	if !sampled(newKeyedRatioSampler(1, "uid"), id) {
		t.Error("a full ratio dropped a trace")
	}
	if sampled(newKeyedRatioSampler(-0.5, "uid"), id) {
		t.Error("a negative ratio sampled a trace")
	}
	if got := newKeyedRatioSampler(0.5, "").Description(); got != sdktrace.TraceIDRatioBased(0.5).Description() {
		t.Errorf("without a key the sampler is %q, want the plain ratio sampler", got)
	}
	if got := newKeyedRatioSampler(0.5, "uid").Description(); got != "KeyedTraceIDRatioBased{0.5}" {
		t.Errorf("Description = %q", got)
	}
}
