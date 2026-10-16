package operator

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func kubeSystemFleet() *podtracev1alpha1.TracerConfig {
	return &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test", SystemNamespace: "kube-system"},
	}
}

func TestTracerConfigReconcile_ReservedSystemNamespaceRefused(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(kubeSystemFleet()).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var daemonSets appsv1.DaemonSetList
	if err := c.List(context.Background(), &daemonSets, client.InNamespace("kube-system")); err != nil {
		t.Fatal(err)
	}
	if len(daemonSets.Items) != 0 {
		t.Error("no privileged agent DaemonSet may be created in kube-system")
	}
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "SystemNamespaceInvalid" {
		t.Errorf("degraded condition = %+v, want SystemNamespaceInvalid", cond)
	}
}

func TestFleetSystemNamespaces_SkipsRefusedNamespace(t *testing.T) {
	good := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet-b"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "fleet-b"},
	}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(kubeSystemFleet(), good).Build()
	got, err := fleetSystemNamespaces(context.Background(), c, "podtrace-system")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "fleet-b" {
		t.Errorf("fleetSystemNamespaces = %v; credentials must never be copied into kube-system", got)
	}
}

func TestSessionReconcile_FleetInReservedNamespaceFailsSession(t *testing.T) {
	s := sessMoreSession(nil)
	objects := []client.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default", Labels: map[string]string{"a": "b"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		sessMoreFanOutObjects()[1],
		kubeSystemFleet(),
		s,
	}
	r := frozenTargetsReconciler(t, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if got.Status.State != podtracev1alpha1.SessionStateFailed || cond == nil || !strings.Contains(cond.Message, "refused") {
		t.Fatalf("state %q condition %+v, want Failed naming the refused TracerConfig", got.Status.State, cond)
	}
	var secrets corev1.SecretList
	if err := r.List(context.Background(), &secrets, client.InNamespace("kube-system")); err != nil {
		t.Fatal(err)
	}
	if len(secrets.Items) != 0 {
		t.Error("a refused fleet must not receive the session's bundle")
	}
}

func TestTracerConfigReconcile_ReservedNamespaceStatusErrorIsReturned(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(kubeSystemFleet()).WithInterceptorFuncs(failStatusUpdate).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}}); err == nil {
		t.Fatal("a refusal that could not be recorded must be retried")
	}
}
