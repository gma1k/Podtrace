package workloadmetrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	roleL7Requests   = metricPrefix + "l7_requests_total"
	roleL7Duration   = metricPrefix + "l7_request_duration_seconds"
	roleErrors       = metricPrefix + "errors_total"
	roleEdgeRequests = metricPrefix + edgeRequestsTotal
	roleEdgeDuration = metricPrefix + edgeRequestDuration
)

func roleSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SemanticConventions: true,
		ResolvePeer:         staticPeer("payments", "shop"),
		Lookup:              kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func roleKernelSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:    true,
		KernelAggregation:   true,
		SemanticConventions: true,
		ResolvePeer:         staticPeer("payments", "shop"),
		Lookup:              kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func roleResponse(typ events.EventType, roleBits uint32, failed bool) *events.Event {
	e := &events.Event{
		Type:        typ,
		CgroupID:    kernelTestCgroup,
		LatencyNS:   4_000_000,
		Details:     "200",
		Target:      "/payments.Pay/Charge",
		HTTPMethod:  "GET",
		TCPState:    events.HTTPTransportTLS | roleBits,
		PeerDstIP:   "10.244.1.7",
		PeerDstPort: 8443,
		K8s:         enriched(),
	}
	if failed {
		e.Details = "503"
		e.Error = 503
	}
	return e
}

type roleSeries struct {
	l7Requests, l7Duration, errors, httpServer, rpcServer, edgeRequests, edgeDuration int
}

func countRoleSeries(t *testing.T, reg *prometheus.Registry) roleSeries {
	t.Helper()
	return roleSeries{
		l7Requests:   len(gather(t, reg, roleL7Requests)),
		l7Duration:   len(gather(t, reg, roleL7Duration)),
		errors:       len(gather(t, reg, roleErrors)),
		httpServer:   len(gather(t, reg, semconvHTTPDuration)),
		rpcServer:    len(gather(t, reg, semconvRPCDuration)),
		edgeRequests: len(gather(t, reg, roleEdgeRequests)),
		edgeDuration: len(gather(t, reg, roleEdgeDuration)),
	}
}

func exportRole(t *testing.T, sink *Sink, e *events.Event) {
	t.Helper()
	if err := sink.Export(context.Background(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestClientHTTPResponseIsAnEdgeNotAServedRequest(t *testing.T) {
	sink, reg := roleSink(t)
	exportRole(t, sink, roleResponse(events.EventHTTPResp, events.HTTPRoleBits(false), true))

	got := countRoleSeries(t, reg)
	if got.l7Requests != 0 || got.l7Duration != 0 || got.httpServer != 0 || got.errors != 0 {
		t.Errorf("a call the workload made was recorded as one it served: %+v", got)
	}
	if got.edgeRequests != 1 || got.edgeDuration != 1 {
		t.Errorf("the caller's view of the call is missing from the service map: %+v", got)
	}
}

func TestServerHTTPResponseIsAServedRequestNotAnEdge(t *testing.T) {
	sink, reg := roleSink(t)
	exportRole(t, sink, roleResponse(events.EventHTTPResp, events.HTTPRoleBits(true), true))

	got := countRoleSeries(t, reg)
	if got.l7Requests != 1 || got.l7Duration != 1 || got.httpServer != 1 || got.errors != 1 {
		t.Errorf("a served request is missing from the L7 and server families: %+v", got)
	}
	if got.edgeRequests != 0 || got.edgeDuration != 0 {
		t.Errorf("a served request drew an edge to its client's ephemeral port: %+v", got)
	}
}

func TestUnknownRoleHTTPResponseKeepsEveryFamily(t *testing.T) {
	sink, reg := roleSink(t)
	exportRole(t, sink, roleResponse(events.EventHTTPResp, 0, true))

	got := countRoleSeries(t, reg)
	want := roleSeries{l7Requests: 1, l7Duration: 1, errors: 1, httpServer: 1, edgeRequests: 1, edgeDuration: 1}
	if got != want {
		t.Errorf("unknown role changed behaviour: got %+v, want %+v", got, want)
	}
}

func TestClientGRPCMethodIsAnEdgeNotAServedCall(t *testing.T) {
	sink, reg := roleSink(t)
	exportRole(t, sink, roleResponse(events.EventGRPCMethod, events.HTTPRoleBits(false), false))

	got := countRoleSeries(t, reg)
	if got.l7Requests != 0 || got.rpcServer != 0 {
		t.Errorf("a gRPC call the workload made was recorded as served: %+v", got)
	}
	if got.edgeRequests != 1 {
		t.Errorf("the gRPC call is missing from the service map: %+v", got)
	}
}

func TestServerGRPCMethodIsAServedCall(t *testing.T) {
	sink, reg := roleSink(t)
	exportRole(t, sink, roleResponse(events.EventGRPCMethod, events.HTTPRoleBits(true), false))

	got := countRoleSeries(t, reg)
	if got.l7Requests != 1 || got.rpcServer != 1 || got.edgeRequests != 0 {
		t.Errorf("served gRPC call recorded wrongly: %+v", got)
	}
}

func TestRoleDoesNotAffectOtherL7Protocols(t *testing.T) {
	sink, reg := roleSink(t)
	e := roleResponse(events.EventRedisCmd, 0, false)
	e.TCPState = events.HTTPRoleBits(false)
	exportRole(t, sink, e)

	got := countRoleSeries(t, reg)
	if got.l7Requests != 1 || got.edgeRequests != 1 {
		t.Errorf("role bits on a non-HTTP event changed its routing: %+v", got)
	}
}

func TestKernelAggregatedClientEventSkipsServerConvention(t *testing.T) {
	sink, reg := roleKernelSink(t)
	client := roleResponse(events.EventHTTPResp, events.HTTPRoleBits(false), false)
	client.KernelAggregated = true
	exportRole(t, sink, client)
	if n := len(gather(t, reg, semconvHTTPDuration)); n != 0 {
		t.Errorf("kernel-aggregated client response fed %s (%d series)", semconvHTTPDuration, n)
	}

	server := roleResponse(events.EventHTTPResp, events.HTTPRoleBits(true), false)
	server.KernelAggregated = true
	exportRole(t, sink, server)
	if n := len(gather(t, reg, semconvHTTPDuration)); n != 1 {
		t.Errorf("kernel-aggregated server response missing from %s (%d series)", semconvHTTPDuration, n)
	}
}

func roleKernelRow(roleBits uint32, failed bool) kernelagg.Row {
	variant := uint8(events.HTTPTransportTLS) | 2<<3
	if failed {
		variant = uint8(events.HTTPTransportTLS) | 5<<3 | 1<<6
	}
	row := kernelRow(events.EventHTTPResp, variant, kernelagg.BucketIndex(4_000_000), 3, 12_000_000, 0)
	row.Key.Role = uint8(roleBits)
	row.Key.PeerIP = 0x0701f40a
	row.Key.PeerPort = 8443
	return row
}

func TestKernelRowRoleRoutesLikeTheEventPath(t *testing.T) {
	cases := []struct {
		name string
		role uint32
		want roleSeries
	}{
		{"client", events.HTTPRoleBits(false), roleSeries{edgeRequests: 1, edgeDuration: 1}},
		{"server", events.HTTPRoleBits(true), roleSeries{l7Requests: 1, l7Duration: 1, errors: 1}},
		{"unknown", 0, roleSeries{l7Requests: 1, l7Duration: 1, errors: 1, edgeRequests: 1, edgeDuration: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink, reg := roleKernelSink(t)
			if applied := sink.IngestKernel([]kernelagg.Row{roleKernelRow(tc.role, true)}); applied != 1 {
				t.Fatalf("IngestKernel applied %d rows, want 1", applied)
			}
			if got := countRoleSeries(t, reg); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSyntheticKernelEventCarriesRoleAndTransport(t *testing.T) {
	e := syntheticEvent(func() *kernelagg.Row { r := roleKernelRow(events.HTTPRoleBits(true), false); return &r }())
	if e.HTTPRole() != events.HTTPRoleServer {
		t.Errorf("role = %v, want server", e.HTTPRole())
	}
	if e.HTTPTransport() != events.HTTPTransportTLS || e.HTTPProtoLabel() != "HTTPS" {
		t.Errorf("transport = %d proto = %q, want TLS/HTTPS", e.HTTPTransport(), e.HTTPProtoLabel())
	}
}
