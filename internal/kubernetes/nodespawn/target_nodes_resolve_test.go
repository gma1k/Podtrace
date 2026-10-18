package nodespawn

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func TestPreResolved_SkipsEmptyContainerID(t *testing.T) {
	r := PodRef{
		Namespace: "ns1",
		Name:      "cart",
		Containers: []ContainerRef{
			{ID: "", Name: "starting"},
			{ID: "abc123", Name: "app"},
		},
	}
	got := r.PreResolved()
	if len(got) != 1 || got[0] != "ns1/cart/abc123/app" {
		t.Errorf("PreResolved() = %v, want only the resolved container", got)
	}
}

func TestPickRunningContainers_NilPod(t *testing.T) {
	if got := pickRunningContainers(nil, ""); got != nil {
		t.Errorf("pickRunningContainers(nil) = %v, want nil", got)
	}
}

func TestResolveTargetNodes_ListErrorPropagates(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	_, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	})
	if err == nil || !strings.Contains(err.Error(), `list pods in "ns1"`) {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestResolveTargetNodes_MissingContainerButOthersRouted(t *testing.T) {
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	hasApp := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "with-app", Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "app", ContainerID: "containerd://aaa", State: running},
		}},
	}
	noApp := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "without-app", Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "sidecar", ContainerID: "containerd://bbb", State: running},
		}},
	}
	cs := fake.NewClientset(hasApp, noApp)

	got, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
		ContainerName:    "app",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	refs := got.ByNode["node-1"]
	if len(refs) != 1 || refs[0].Name != "with-app" {
		t.Fatalf("expected only with-app routed, got %+v", refs)
	}
}
