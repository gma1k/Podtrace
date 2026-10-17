package tracer

import (
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/h2decode"
	"github.com/gma1k/podtrace/internal/events"
)

// A gRPC-Go call is seen twice: by the grpc-go uprobes (bpf/grpcgo.c), which
// read the headers grpc-go hands its transport, and by the HTTP/2 decoder,
// which reads the same headers off the wire. Counting both counts every call
// at least twice. The decoder is the better source: it pairs a request with
// its response by connection and stream, and it sees the trailers, whose
// grpc-status is the call's outcome. The uprobes pair by the thread's last
// TCP peer and never see grpc-status. So for a process whose gRPC calls the
// decoder is seeing, the uprobe events are dropped; for one it is not, such
// as a connection capture joined too late to decode, they still count.
const (
	grpcCoverageTTL      = time.Minute
	maxGRPCCoverageProcs = 4096
)

// grpcGoProbeTransport is the transport bpf/grpcgo.c stamps on its events. On
// the main ring buffer no other probe emits an HTTP event with an HTTP/2
// transport: HTTP/2 events are built in userspace by the decoder.
const grpcGoProbeTransport = 3

type grpcDecodeCoverage struct {
	mu   sync.Mutex
	seen map[uint32]time.Time
}

func newGRPCDecodeCoverage() *grpcDecodeCoverage {
	return &grpcDecodeCoverage{seen: map[uint32]time.Time{}}
}

// noteDecoded records that the decoder produced a gRPC call for a process.
func (c *grpcDecodeCoverage) noteDecoded(ev *events.Event, now time.Time) {
	if c == nil || !h2decode.IsGRPCResponse(ev) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[ev.PID]; !ok && len(c.seen) >= maxGRPCCoverageProcs {
		for pid, at := range c.seen {
			if now.Sub(at) > grpcCoverageTTL {
				delete(c.seen, pid)
			}
		}
		if len(c.seen) >= maxGRPCCoverageProcs {
			return
		}
	}
	c.seen[ev.PID] = now
}

// suppresses reports whether an event is a grpc-go uprobe event for a
// process whose calls the decoder has seen within grpcCoverageTTL.
func (c *grpcDecodeCoverage) suppresses(ev *events.Event, now time.Time) bool {
	if c == nil || ev == nil || ev.HTTPTransport() != grpcGoProbeTransport {
		return false
	}
	if ev.Type != events.EventHTTPReq && ev.Type != events.EventHTTPResp {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.seen[ev.PID]
	return ok && now.Sub(at) <= grpcCoverageTTL
}
