package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestCrossNamespaceDeniedMessage(t *testing.T) {
	msg := crossNamespaceDeniedMessage("team-a", []string{"team-b", "team-c"})
	for _, want := range []string{"team-a", "team-b", podtracev1alpha1.AllowTracingFromAnnotation} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

func TestLabelSelectorToFlag_InvalidReturnsEmpty(t *testing.T) {
	bad := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}},
	}
	if got := labelSelectorToFlag(bad); got != "" {
		t.Errorf("labelSelectorToFlag(invalid) = %q, want empty", got)
	}
	good := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
	if got := labelSelectorToFlag(good); got != "app=x" {
		t.Errorf("labelSelectorToFlag(good) = %q, want app=x", got)
	}
}

func TestCompletedSessionNodes(t *testing.T) {
	refs := []podtracev1alpha1.SessionJobRef{
		{Node: "n1", Completed: true},
		{Node: "n2", Completed: false},
		{Node: "", Completed: true},
		{Node: "n3", Completed: true},
	}
	got := completedSessionNodes(refs)
	if len(got) != 2 {
		t.Fatalf("completedSessionNodes = %v, want 2 entries", got)
	}
	if _, ok := got["n1"]; !ok {
		t.Error("n1 should be marked completed")
	}
	if _, ok := got["n3"]; !ok {
		t.Error("n3 should be marked completed")
	}
	if _, ok := got["n2"]; ok {
		t.Error("n2 is not completed")
	}
}

func TestSessionJobName_EmptyNodeFallsBackToHash(t *testing.T) {
	name := SessionJobName("abcdef012345", "")
	if name == "" {
		t.Fatal("SessionJobName with empty node must still return a name")
	}
	if strings.HasSuffix(name, "-") || strings.HasSuffix(name, ".") {
		t.Errorf("name %q must not end in a separator", name)
	}

	if SessionJobName("aaaa11112222", "") == SessionJobName("bbbb33334444", "") {
		t.Error("empty-node names must still be unique per session UID")
	}
}

func TestPodTraceMapFuncs_ListErrorsReturnNil(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}

	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if got := r.tracerConfigToPodTraces(context.Background(), tc); got != nil {
		t.Errorf("tracerConfigToPodTraces on List error = %v, want nil", got)
	}
	if got := r.namespaceToPodTraces(context.Background(), &corev1.Namespace{}); got != nil {
		t.Errorf("namespaceToPodTraces on List error = %v, want nil", got)
	}
	ec := &podtracev1alpha1.ExporterConfig{ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"}}
	if got := r.exporterConfigToPodTraces(context.Background(), ec); got != nil {
		t.Errorf("exporterConfigToPodTraces on List error = %v, want nil", got)
	}
}

func TestPodTraceTracerConfigMapFunc_NoPodTraces(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}
	tc := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "custom"}}
	if got := r.tracerConfigToPodTraces(context.Background(), tc); len(got) != 0 {
		t.Errorf("no PodTraces should map to no requests, got %v", got)
	}
}

func TestEffectiveSystemNamespace_TracerConfigOverride(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "override-ns"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: "fallback-ns"}
	if got := r.effectiveSystemNamespace(context.Background()); got != "override-ns" {
		t.Errorf("effectiveSystemNamespace = %q, want override-ns", got)
	}

	c2 := fake.NewClientBuilder().WithScheme(scheme).Build()
	r2 := &PodTraceReconciler{Client: c2, Scheme: scheme, SystemNamespace: "fallback-ns"}
	if got := r2.effectiveSystemNamespace(context.Background()); got != "fallback-ns" {
		t.Errorf("effectiveSystemNamespace fallback = %q, want fallback-ns", got)
	}
}
