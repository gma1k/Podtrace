package nodespawn

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func tolPod(ns, name, node string, tols []corev1.Toleration) *corev1.Pod {
	return withRunningContainer(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{NodeName: node, Tolerations: tols},
	})
}

func TestResolveTargetNodes_PropagatesTolerations(t *testing.T) {
	tolA := corev1.Toleration{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}
	tolB := corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoSchedule}

	cs := fake.NewClientset(
		tolPod("ns1", "a", "node-1", []corev1.Toleration{tolA, tolB}),
		tolPod("ns1", "b", "node-1", []corev1.Toleration{tolA}),
		tolPod("ns1", "c", "node-2", []corev1.Toleration{tolB}),
	)
	got, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	want1 := []corev1.Toleration{tolA, tolB}
	if !reflect.DeepEqual(got.TolerationsByNode["node-1"], want1) {
		t.Errorf("node-1 tolerations = %+v, want %+v", got.TolerationsByNode["node-1"], want1)
	}
	want2 := []corev1.Toleration{tolB}
	if !reflect.DeepEqual(got.TolerationsByNode["node-2"], want2) {
		t.Errorf("node-2 tolerations = %+v, want %+v", got.TolerationsByNode["node-2"], want2)
	}
}

func TestResolveTargetNodes_DedupesIdenticalTolerations(t *testing.T) {
	tol := corev1.Toleration{Key: "k", Operator: corev1.TolerationOpExists}
	cs := fake.NewClientset(
		tolPod("ns1", "a", "node-1", []corev1.Toleration{tol}),
		tolPod("ns1", "b", "node-1", []corev1.Toleration{tol}),
	)
	got, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(got.TolerationsByNode["node-1"]) != 1 {
		t.Errorf("expected 1 deduped toleration, got %d: %+v", len(got.TolerationsByNode["node-1"]), got.TolerationsByNode["node-1"])
	}
}
