package agent

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func TestObtainExporter_PartialBuildIsCachedNotLeaked(t *testing.T) {
	exp := &fakeExporter{name: "degraded"}
	builds := 0
	r := &AgentReconciler{
		exporterCache: map[CRKey]cachedExporter{},
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			builds++
			return exp, errors.New("metrics")
		},
	}
	key := CRKey{Namespace: "ns", Name: "pt"}
	for i := 0; i < 2; i++ {
		got, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"})
		if got != exp {
			t.Fatalf("obtain %d: exporter = %v, want the partially built one", i, got)
		}
		if err == nil {
			t.Errorf("obtain %d: the metrics failure must stay visible", i)
		}
	}
	if builds != 1 {
		t.Errorf("builder calls = %d, want 1", builds)
	}
	r.closeDisplacedExporters()
	if exp.Closes() != 0 {
		t.Errorf("live exporter closed %d times, want 0", exp.Closes())
	}

	r.releaseExporter(key)
	r.closeDisplacedExporters()
	waitForCloses(t, exp, 1)
}

func TestObtainExporter_ReplacedExporterClosedOnceWhenRebuildFails(t *testing.T) {
	old := &fakeExporter{name: "old"}
	r := &AgentReconciler{
		exporterCache: map[CRKey]cachedExporter{},
		ExporterBuilder: func(p *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			if p.ResourceVer == "1" {
				return old, nil
			}
			return nil, errors.New("bad endpoint")
		},
	}
	key := CRKey{Namespace: "ns", Name: "pt"}
	if _, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "1"}); err != nil {
		t.Fatalf("RV1 build: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := r.obtainExporter(key, &BundlePayload{ResourceVer: "2"}); err == nil {
			t.Fatalf("RV2 obtain %d: expected error", i)
		}
	}
	r.closeDisplacedExporters()
	r.releaseExporter(key)
	r.closeDisplacedExporters()
	waitForCloses(t, old, 1)
	r.exporterCacheMu.Lock()
	pending := len(r.pendingClose)
	r.exporterCacheMu.Unlock()
	if pending != 0 {
		t.Errorf("pendingClose = %d after drain, want 0", pending)
	}
	if old.Closes() != 1 {
		t.Errorf("replaced exporter closed %d times, want 1", old.Closes())
	}
}

func TestReconcile_PartialExporterBuildRoutesCR(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-1")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:     []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
			ExporterRef: corev1.LocalObjectReference{Name: "ignored"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "10")).
		Build()

	exp := &fakeExporter{name: "degraded"}
	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: sysNS,
		Router:          NewRouter(nil),
		Metrics:         NewMetrics(),
		TargetsCh:       make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) {
			return exp, errors.New("start OTLP metric export: refused")
		},
		CgroupResolver: func(_ []*corev1.Pod) (map[uint64]struct{}, error) {
			return map[uint64]struct{}{42: {}}, nil
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	rules := r.Router.RulesSnapshot()
	if len(rules) != 1 {
		t.Fatalf("router rules = %d, want 1", len(rules))
	}
	if rules[0].Err != nil {
		t.Errorf("CR tombstoned with %v; a metrics-only failure must not stop tracing", rules[0].Err)
	}
	if rules[0].Exporter != exp {
		t.Errorf("rule exporter = %v, want the partially built exporter", rules[0].Exporter)
	}
}
