package workloadmetrics

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestAFailedConnectIsCountedAsAnErrorOutcome(t *testing.T) {
	families, mapped := recordOne(t, &events.Event{
		Type: events.EventConnect, Error: 111, K8s: enriched(),
	})
	if !mapped {
		t.Fatal("a failed connect fell through record()")
	}

	metrics, ok := families["podtrace_workload_network_connections_total"]
	if !ok {
		t.Fatalf("no connections family; got %v", keysOf(families))
	}
	if got := labelsOf(metrics[0])["outcome"]; got != "error" {
		t.Errorf("outcome = %q, want error", got)
	}
}

func TestConnectionAttemptsCarryBothOutcomesSoTheRatioHasADenominator(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	for _, e := range []*events.Event{
		{Type: events.EventConnect, K8s: enriched()},
		{Type: events.EventConnectResult, K8s: enriched()},
		{Type: events.EventConnect, K8s: enriched()},
		{Type: events.EventConnectResult, K8s: enriched()},
		{Type: events.EventConnect, K8s: enriched()},
		{Type: events.EventConnectResult, Error: -111, K8s: enriched()},
		{Type: events.EventConnect, Error: -113, K8s: enriched()},
	} {
		base, ok := sink.baseLabelValues(e)
		if !ok {
			t.Fatal("fixture is unattributed")
		}
		sink.record(e, base)
	}

	outcomes := map[string]float64{}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "podtrace_workload_network_connections_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			outcomes[labelsOf(m)["outcome"]] = m.GetCounter().GetValue()
		}
	}

	if outcomes["ok"] != 2 || outcomes["error"] != 2 {
		t.Errorf("expected 2 ok and 2 errors from four attempts, got %v.\n\n"+
			"Two handshakes completed, one was refused after connect() returned 0, and "+
			"one failed inside connect() itself. Each attempt must be scored once: the "+
			"refused one only shows up as its handshake result, and the synchronous "+
			"failure only as its connect.", outcomes)
	}
}

func TestRetransmitsAndDeviceErrorsLandInSeparateFamilies(t *testing.T) {
	retrans, mapped := recordOne(t, &events.Event{Type: events.EventTCPRetrans, K8s: enriched()})
	if !mapped {
		t.Fatal("a retransmit fell through record()")
	}
	if _, ok := retrans["podtrace_workload_network_retransmits_total"]; !ok {
		t.Errorf("no retransmit family; got %v", keysOf(retrans))
	}

	devErr, mapped := recordOne(t, &events.Event{Type: events.EventNetDevError, Error: 5, K8s: enriched()})
	if !mapped {
		t.Fatal("a device error fell through record()")
	}
	if _, ok := devErr["podtrace_workload_network_device_errors_total"]; !ok {
		t.Errorf("no device error family; got %v", keysOf(devErr))
	}
}

func TestLockContentionIsGroupedUnderItsOwnErrorKind(t *testing.T) {
	families, _ := recordOne(t, &events.Event{
		Type: events.EventLockContention, Error: -22, LatencyNS: 5_000_000, K8s: enriched(),
	})

	metrics, ok := families["podtrace_workload_errors_total"]
	if !ok {
		t.Fatalf("no errors family; got %v", keysOf(families))
	}
	if got := labelsOf(metrics[0])["kind"]; got != "lock" {
		t.Errorf("kind = %q, want lock", got)
	}
}

func TestTheKernelPathScoresEachConnectionAttemptOnce(t *testing.T) {
	sink, reg := kernelSink(t)
	errorVariant := uint8(1 << 6)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventConnect, 0, kernelagg.BucketNone, 5, 0, 0),
		kernelRow(events.EventConnect, errorVariant, kernelagg.BucketNone, 1, 0, 0),
		kernelRow(events.EventConnectResult, 0, kernelagg.BucketNone, 3, 0, 0),
		kernelRow(events.EventConnectResult, errorVariant, kernelagg.BucketNone, 2, 0, 0),
	})

	outcomes := map[string]float64{}
	for _, m := range gather(t, reg, "podtrace_workload_network_connections_total") {
		outcomes[labelsOf(m)["outcome"]] = m.GetCounter().GetValue()
	}
	if outcomes["ok"] != 3 || outcomes["error"] != 3 {
		t.Errorf("outcomes = %v, want 3 ok and 3 error.\n\nFive connects queued a SYN, "+
			"one failed inside connect(), and five handshakes ended: three established, "+
			"two refused. The five queued connects must not be scored again as successes, "+
			"or the kernel path reports a lower failure rate than the event path.", outcomes)
	}
}

func connectionOutcomes(t *testing.T, sink *Sink) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, m := range gather(t, sink.own, "podtrace_workload_network_connections_total") {
		out[labelsOf(m)["outcome"]] += m.GetCounter().GetValue()
	}
	return out
}

func TestANoRouteForTheFamilyConnectIsCountedApart(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	for _, e := range []*events.Event{
		{Type: events.EventConnect, Error: -101, K8s: enriched()},
		{Type: events.EventConnect, Error: -97, K8s: enriched()},
		{Type: events.EventConnect, Error: -113, K8s: enriched()},
	} {
		base, _ := sink.baseLabelValues(e)
		sink.record(e, base)
	}
	got := connectionOutcomes(t, sink)
	if got["unreachable"] != 2 || got["error"] != 1 {
		t.Errorf("outcomes = %v, want 2 unreachable and 1 error: EHOSTUNREACH is a real "+
			"routing failure, ENETUNREACH and EAFNOSUPPORT mean the pod has no route for "+
			"that address family at all", got)
	}
}

func TestTheKernelPathMarksUnreachableConnectsToo(t *testing.T) {
	sink, _ := kernelSink(t)
	unreachable := uint8(connectVariantUnreachable | 1<<6)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventConnect, unreachable, kernelagg.BucketNone, 8, 0, 0),
		kernelRow(events.EventConnect, 1<<6, kernelagg.BucketNone, 1, 0, 0),
	})
	got := connectionOutcomes(t, sink)
	if got["unreachable"] != 8 || got["error"] != 1 {
		t.Errorf("outcomes = %v, want 8 unreachable and 1 error; the kernel path must agree "+
			"with the event path or the rule reads differently depending on aggregation", got)
	}
}
