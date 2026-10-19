package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/events"
	podtraceac "github.com/gma1k/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

var deliveryCR = CRKey{Namespace: "team-a", Name: "web"}

func TestDeliveryHealthRecordsAndClearsAFailure(t *testing.T) {
	h := newDeliveryHealth()
	owner := &struct{}{}
	start := time.Unix(1000, 0)
	h.register(deliveryCR, owner)

	h.fail(deliveryCR, owner, "otlp", errors.New("first"), start)
	h.fail(deliveryCR, owner, "otlp", errors.New("dial tcp: connection refused"), start.Add(10*time.Second))

	state, failing := h.failing(deliveryCR)
	if !failing || state.Exporter != "otlp" || state.FailedBatches != 2 || !state.FailingSince.Equal(start) || state.LastError != "dial tcp: connection refused" {
		t.Fatalf("state = %+v failing=%v", state, failing)
	}

	h.delivered(deliveryCR, owner)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("a delivered batch must clear the failure")
	}
}

func TestDeliveryHealthIgnoresADrainingReplacedExporter(t *testing.T) {
	h := newDeliveryHealth()
	old, current := &struct{ n int }{1}, &struct{ n int }{2}
	h.register(deliveryCR, old)
	h.fail(deliveryCR, old, "otlp", errors.New("port 9999 unreachable"), time.Now())

	h.register(deliveryCR, current)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("a newly registered exporter must start healthy")
	}

	h.fail(deliveryCR, old, "otlp", errors.New("old queue still draining"), time.Now())
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("a failure from the replaced exporter stuck to the PodTrace")
	}

	h.fail(deliveryCR, current, "otlp", errors.New("current failure"), time.Now())
	h.delivered(deliveryCR, old)
	h.unregister(deliveryCR, old)
	if state, failing := h.failing(deliveryCR); !failing || state.LastError != "current failure" {
		t.Fatalf("the replaced exporter cleared its successor's failure: %+v", state)
	}

	h.delivered(deliveryCR, current)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("the current exporter's delivery did not clear the failure")
	}
}

func TestDeliveryHealthUnregisterDropsTheRecord(t *testing.T) {
	h := newDeliveryHealth()
	owner := &struct{}{}
	h.register(deliveryCR, owner)
	h.fail(deliveryCR, owner, "otlp", errors.New("x"), time.Now())

	h.unregister(deliveryCR, owner)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("an unregistered PodTrace still reports a failure")
	}
	h.fail(deliveryCR, owner, "otlp", errors.New("late"), time.Now())
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("a failure after unregister must be ignored")
	}
}

func TestDeliveryHealthRedactsAndBoundsTheError(t *testing.T) {
	h := newDeliveryHealth()
	h.register(deliveryCR, h)
	h.fail(deliveryCR, h, "otlp", errors.New(`Post "https://collector.example/v1/traces?token=SECRETVALUE": `+strings.Repeat("é", 400)), time.Now())

	state, _ := h.failing(deliveryCR)
	if strings.Contains(state.LastError, "SECRETVALUE") {
		t.Fatalf("LastError leaks the query string: %q", state.LastError)
	}
	if len(state.LastError) > maxDeliveryErrorBytes+3 || strings.ContainsRune(state.LastError, '\uFFFD') {
		t.Fatalf("LastError not bounded on a rune boundary: %d bytes", len(state.LastError))
	}
}

func TestDeliveryHealthNilIsSafe(t *testing.T) {
	var h *deliveryHealth
	h.register(deliveryCR, h)
	h.fail(deliveryCR, h, "otlp", errors.New("x"), time.Now())
	h.delivered(deliveryCR, h)
	h.unregister(deliveryCR, h)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("nil deliveryHealth reported a failure")
	}
}

func TestDeliveryObservingExporterFeedsDeliveryHealth(t *testing.T) {
	h := newDeliveryHealth()
	inner := &fakeSpanExporter{err: errors.New("401 Unauthorized")}
	e := &deliveryObservingExporter{inner: inner, cr: deliveryCR, name: "otlp", delivery: h}
	h.register(deliveryCR, e)
	spans := make([]sdktrace.ReadOnlySpan, 3)

	_ = e.ExportSpans(context.Background(), spans)
	if state, failing := h.failing(deliveryCR); !failing || state.LastError != "401 Unauthorized" {
		t.Fatalf("failed export not recorded: %+v", state)
	}

	inner.err = nil
	_ = e.ExportSpans(context.Background(), spans)
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("successful export did not clear the failure")
	}

	inner.err = errors.New("again")
	_ = e.ExportSpans(context.Background(), spans)
	_ = e.Shutdown(context.Background())
	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("shutting the exporter down must drop its failure")
	}
}

func TestApplyDeliveryFailureKeepsTheRowReady(t *testing.T) {
	entry := podtracev1alpha1.PodTraceNodeStatus{Node: "n", Ready: true}
	now := time.Unix(1000, 0)
	applyDeliveryFailure(&entry, deliveryState{Exporter: "otlp", FailedBatches: 4, FailingSince: now.Add(-90 * time.Second), LastError: "no such host"}, now)

	if !entry.Ready || entry.Reason != podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed {
		t.Fatalf("entry = %+v, want Ready with ExporterDeliveryFailed", entry)
	}
	for _, want := range []string{"otlp exporter", "4 failed batches", "1m30s", "no such host"} {
		if !strings.Contains(entry.Message, want) {
			t.Errorf("message %q lacks %q", entry.Message, want)
		}
	}
}

func TestApplyDeliveryFailureDoesNotHideAnEarlierProblem(t *testing.T) {
	entry := podtracev1alpha1.PodTraceNodeStatus{Node: "n", Reason: podtracev1alpha1.NodeStatusReasonBundleLoadFailed, Message: "load bundle: missing"}
	applyDeliveryFailure(&entry, deliveryState{Exporter: "otlp", LastError: "x"}, time.Now())

	if entry.Reason != podtracev1alpha1.NodeStatusReasonBundleLoadFailed || entry.Message != "load bundle: missing" {
		t.Fatalf("delivery failure overwrote the earlier reason: %+v", entry)
	}
}

func TestStatusWriterReportsADeliveryFailureOnNodeStatus(t *testing.T) {
	var applied []runtime.ApplyConfiguration
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, _ string, obj runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				applied = append(applied, obj)
				return nil
			},
		}).Build()

	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: deliveryCR}}).Wait()
	h := newDeliveryHealth()
	h.register(deliveryCR, h)
	h.fail(deliveryCR, h, "otlp", errors.New("lookup recv: no such host"), time.Now())

	w := &StatusWriter{Client: c, NodeName: "node-a", Router: router, Ready: func() bool { return true }, Delivery: h}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}

	if len(applied) != 1 {
		t.Fatalf("applied %d status patches, want 1", len(applied))
	}
	pt, ok := applied[0].(*podtraceac.PodTraceApplyConfiguration)
	if !ok || pt.Status == nil || len(pt.Status.NodeStatus) != 1 {
		t.Fatalf("unexpected apply configuration %#v", applied[0])
	}
	row := pt.Status.NodeStatus[0]
	if row.Ready == nil || !*row.Ready {
		t.Fatal("a node that is capturing must stay Ready")
	}
	if row.Reason == nil || *row.Reason != podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed {
		t.Fatalf("reason = %v, want ExporterDeliveryFailed", row.Reason)
	}
	if row.Message == nil || !strings.Contains(*row.Message, "no such host") {
		t.Fatalf("message = %v, want the delivery error", row.Message)
	}
}

func exportOneEvent(t *testing.T, exp interface {
	Export(context.Context, []*events.Event) error
}, tp *sdktrace.TracerProvider) {
	t.Helper()
	if err := exp.Export(context.Background(), []*events.Event{{Type: events.EventDNS, Timestamp: uint64(time.Now().UnixNano()), Details: "1.2.3.4"}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tp.ForceFlush(ctx)
}

func TestReplacingAFailingExporterReportsOnlyTheReplacement(t *testing.T) {
	h := newDeliveryHealth()
	b := &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "x:4318", Insecure: true}

	oldExp, err := newSDKEventExporter("otlp", deliveryCR, b, &fakeSpanExporter{err: errors.New("port 9999 unreachable")}, withDeliveryHealth(h))
	if err != nil {
		t.Fatal(err)
	}
	oldSDK := oldExp.(*sdkEventExporter)
	exportOneEvent(t, oldSDK, oldSDK.tp)
	if _, failing := h.failing(deliveryCR); !failing {
		t.Fatal("the failing exporter was not reported")
	}

	newExp, err := newSDKEventExporter("otlp", deliveryCR, b, &fakeSpanExporter{}, withDeliveryHealth(h))
	if err != nil {
		t.Fatal(err)
	}
	newSDK := newExp.(*sdkEventExporter)
	exportOneEvent(t, oldSDK, oldSDK.tp)
	exportOneEvent(t, newSDK, newSDK.tp)
	if state, failing := h.failing(deliveryCR); failing {
		t.Fatalf("the replaced exporter's draining failures stuck to the PodTrace: %+v", state)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = oldExp.Close(ctx)
	_ = newExp.Close(ctx)
}
