package workloadmetrics

import (
	"fmt"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func retransFor(namespace, workload string) *events.Event {
	meta := enriched()
	meta.Namespace = namespace
	meta.WorkloadName = workload
	return &events.Event{Type: events.EventTCPRetrans, K8s: meta}
}

func TestANamespaceThatFilledTheBudgetCannotBlindALaterOne(t *testing.T) {
	sink, reg := newTestSink(t, 8)

	for i := 0; i < 20; i++ {
		_ = sink.Export(t.Context(), []*events.Event{retransFor("noisy", fmt.Sprintf("w%d", i))})
	}
	_ = sink.Export(t.Context(), []*events.Event{retransFor("quiet", "api")})

	perNS := map[string]int{}
	for _, m := range gather(t, reg, "podtrace_workload_network_retransmits_total") {
		perNS[labelsOf(m)["namespace"]]++
	}
	if perNS["noisy"] != 8 {
		t.Errorf("noisy holds %d series, want the budget of 8", perNS["noisy"])
	}
	if perNS["quiet"] != 1 {
		t.Errorf("quiet holds %d series, want 1: a later namespace must still be observed", perNS["quiet"])
	}

	_ = sink.Export(t.Context(), []*events.Event{retransFor("noisy", "w99")})
	if got := len(gather(t, reg, "podtrace_workload_network_retransmits_total")); got != 9 {
		t.Errorf("series = %d, want 9: the namespace over its share must stay refused", got)
	}
}

func TestASingleNamespaceIsCappedAtTheBudgetAsBefore(t *testing.T) {
	sink, reg := newTestSink(t, 8)
	for i := 0; i < 20; i++ {
		_ = sink.Export(t.Context(), []*events.Event{retransFor("only", fmt.Sprintf("w%d", i))})
	}
	if got := len(gather(t, reg, "podtrace_workload_network_retransmits_total")); got != 8 {
		t.Errorf("series = %d, want exactly the budget", got)
	}
}

func TestTheFairOverflowNeverExceedsAQuarterOfTheBudget(t *testing.T) {
	sink, reg := newTestSink(t, 8)
	for i := 0; i < 8; i++ {
		_ = sink.Export(t.Context(), []*events.Event{retransFor("noisy", fmt.Sprintf("w%d", i))})
	}
	for i := 0; i < 10; i++ {
		_ = sink.Export(t.Context(), []*events.Event{retransFor(fmt.Sprintf("tenant-%d", i), "api")})
	}
	if got := len(gather(t, reg, "podtrace_workload_network_retransmits_total")); got != 10 {
		t.Errorf("series = %d, want budget 8 plus a reserve of 2", got)
	}
}

func TestReapReturnsANamespacesShare(t *testing.T) {
	sink, _ := newTestSink(t, 4)
	clock := time.Unix(1_800_000_000, 0)
	sink.now = func() time.Time { return clock }
	for i := 0; i < 4; i++ {
		_ = sink.Export(t.Context(), []*events.Event{retransFor("a", fmt.Sprintf("w%d", i))})
	}
	if sink.perNS["a"] != 4 {
		t.Fatalf("perNS[a] = %d, want 4", sink.perNS["a"])
	}

	clock = clock.Add(time.Hour)
	if removed := sink.Reap(time.Minute); removed != 4 {
		t.Fatalf("Reap removed %d, want 4", removed)
	}
	if len(sink.perNS) != 0 {
		t.Errorf("perNS = %v after every series was reaped, want empty", sink.perNS)
	}
}

func TestNamespaceOfReadsTheFamilysNamespaceLabel(t *testing.T) {
	if namespaceOf(semconvHTTPDuration, []string{"svc", "ns", "c"}) != "ns" {
		t.Error("semconv families carry the namespace second")
	}
	if namespaceOf("errors_total", []string{"ns", "w"}) != "ns" {
		t.Error("base families carry the namespace first")
	}
	if namespaceOf("errors_total", nil) != "" {
		t.Error("an empty label set has no namespace")
	}
}
