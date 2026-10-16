package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func existingBundle(pt *podtracev1alpha1.PodTrace, namespace string) []client.Object {
	labels := map[string]string{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentBundle,
		LabelPodTraceName: pt.Name,
		LabelPodTraceNS:   pt.Namespace,
	}
	meta := metav1.ObjectMeta{Name: ExporterBundleName(pt.UID), Namespace: namespace, Labels: labels}
	return []client.Object{
		&corev1.ConfigMap{ObjectMeta: meta, Data: map[string]string{"target_namespaces": "default,tenant-b"}},
		&corev1.Secret{ObjectMeta: meta, Data: map[string][]byte{"credential": []byte("token")}},
	}
}

func bundleObjectsLeft(t *testing.T, c client.Client) int {
	t.Helper()
	var cms corev1.ConfigMapList
	var secrets corev1.SecretList
	if err := c.List(context.Background(), &cms, client.MatchingLabels{LabelComponent: ComponentBundle}); err != nil {
		t.Fatal(err)
	}
	if err := c.List(context.Background(), &secrets, client.MatchingLabels{LabelComponent: ComponentBundle}); err != nil {
		t.Fatal(err)
	}
	return len(cms.Items) + len(secrets.Items)
}

func newWithdrawalReconciler(t *testing.T, objects ...client.Object) *PodTraceReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(objects...).Build()
	return &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
}

func TestPodTraceReconcile_DeletedExporterConfigWithdrawsBundle(t *testing.T) {
	pt := ptMoreTrace(nil)
	objects := append([]client.Object{pt}, existingBundle(pt, ptMoreSysNS)...)
	r := newWithdrawalReconciler(t, objects...)

	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if left := bundleObjectsLeft(t, r.Client); left != 0 {
		t.Fatalf("an ExporterConfig that no longer resolves must withdraw the bundle; %d object(s) left", left)
	}
	var got podtracev1alpha1.PodTrace
	if err := r.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.TargetNamespaces != nil {
		t.Errorf("status.targetNamespaces = %v, want cleared with the bundle", got.Status.TargetNamespaces)
	}
}

func TestPodTraceReconcile_UnrenderableExporterConfigWithdrawsBundle(t *testing.T) {
	pt := ptMoreTrace(nil)
	ec := ptMoreExporterConfig()
	ec.Spec.OTLP.Headers = []podtracev1alpha1.OTLPHeader{{Name: "bad header", Value: "x"}}
	objects := append([]client.Object{pt, ec}, existingBundle(pt, ptMoreSysNS)...)
	r := newWithdrawalReconciler(t, objects...)

	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if left := bundleObjectsLeft(t, r.Client); left != 0 {
		t.Fatalf("a bundle that cannot be rendered must not leave the last good one behind; %d object(s) left", left)
	}
}

func TestPodTraceReconcile_WritesBundleIntoEveryFleetNamespace(t *testing.T) {
	pt := ptMoreTrace(nil)
	fleetB := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet-b"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "fleet-b-system"},
	}
	defaultFleet := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName}}
	objects := append([]client.Object{pt, ptMoreExporterConfig(), defaultFleet, fleetB}, existingBundle(pt, "retired-fleet")...)
	r := newWithdrawalReconciler(t, objects...)

	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, ns := range []string{ptMoreSysNS, "fleet-b-system"} {
		var cm corev1.ConfigMap
		if err := r.Get(context.Background(), types.NamespacedName{Name: ExporterBundleName(pt.UID), Namespace: ns}, &cm); err != nil {
			t.Errorf("bundle ConfigMap missing in fleet namespace %s: %v", ns, err)
		}
	}
	var stale corev1.ConfigMap
	if err := r.Get(context.Background(), types.NamespacedName{Name: ExporterBundleName(pt.UID), Namespace: "retired-fleet"}, &stale); err == nil {
		t.Error("a bundle in a namespace no fleet reads from must be swept")
	}
}

func TestPodTraceReconcile_NoBundleWhereNoFleetRuns(t *testing.T) {
	pt := ptMoreTrace(nil)
	moved := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "fleet-a-system"},
	}
	r := newWithdrawalReconciler(t, pt, ptMoreExporterConfig(), moved)

	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var cm corev1.ConfigMap
	if err := r.Get(context.Background(), types.NamespacedName{Name: ExporterBundleName(pt.UID), Namespace: "fleet-a-system"}, &cm); err != nil {
		t.Fatalf("bundle missing in the fleet's namespace: %v", err)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: ExporterBundleName(pt.UID), Namespace: ptMoreSysNS}, &cm); err == nil {
		t.Error("no agent reads the operator's namespace once every fleet moved, so no bundle may be copied there")
	}
}
