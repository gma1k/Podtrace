package tracer

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestGRPCGoProbeEventWithRoleBitsIsStillSuppressed(t *testing.T) {
	c := newGRPCDecodeCoverage()
	now := time.Now()
	c.noteDecoded(decodedGRPC(7), now)
	for _, server := range []bool{false, true} {
		ev := &events.Event{Type: events.EventHTTPResp, PID: 7, TCPState: grpcGoProbeTransport | events.HTTPRoleBits(server)}
		if !c.suppresses(ev, now) {
			t.Errorf("server=%v: a role-stamped grpc-go probe event escaped deduplication", server)
		}
	}
}
