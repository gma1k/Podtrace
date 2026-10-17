package agent

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/events"
)

func TestMetricsObserver_OnEventsDropped(t *testing.T) {
	m := NewMetrics()
	obs := m.EngineObserver()

	obs.OnEventsDropped("channel_full", 3)
	obs.OnEventsDropped("ringbuf", 2)
	obs.OnEventsDropped("channel_full", 0)
	obs.OnEventsDropped("channel_full", -1)

	if got := scrapeMetric(t, m, `kernel_events_dropped_total{reason="channel_full"}`); got != 3 {
		t.Errorf(`kernel_events_dropped_total{reason="channel_full"} = %d, want 3`, got)
	}
	if got := scrapeMetric(t, m, `kernel_events_dropped_total{reason="ringbuf"}`); got != 2 {
		t.Errorf(`kernel_events_dropped_total{reason="ringbuf"} = %d, want 2`, got)
	}
	if got := m.KernelDroppedTotal(); got != 5 {
		t.Errorf("KernelDroppedTotal = %d, want 5", got)
	}
}

func TestStatusWriter_ReportsKernelDropsApartFromTheCRsOwn(t *testing.T) {
	router := NewRouter(nil)
	exp := &recExp{name: "x"}
	router.Publish([]CRRule{mkRule("ns", "pt", []uint64{1}, []events.EventType{events.EventDNS}, exp)})
	router.Stats().incrDropped(CRKey{Namespace: "ns", Name: "pt"}, 2)

	pt := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pt"}}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithObjects(pt).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		Build()

	w := &StatusWriter{
		Client:        c,
		NodeName:      "node-x",
		Router:        router,
		Ready:         func() bool { return true },
		KernelDropped: func() int64 { return 3 },
	}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "pt"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.NodeStatus) != 1 {
		t.Fatalf("nodeStatus len = %d, want 1", len(got.Status.NodeStatus))
	}
	if got.Status.NodeStatus[0].DroppedEvents != 2 {
		t.Errorf("DroppedEvents = %d, want 2: only the CR's own loss", got.Status.NodeStatus[0].DroppedEvents)
	}
	if got.Status.NodeStatus[0].KernelDroppedEvents != 3 {
		t.Errorf("KernelDroppedEvents = %d, want the node-wide 3", got.Status.NodeStatus[0].KernelDroppedEvents)
	}
}
