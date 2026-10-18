package nodespawn

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func newPodForDynamic(ns, name, node string, labels map[string]string) *corev1.Pod {
	return withRunningContainer(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	})
}

func TestRun_DynamicReSpawn_DiscoversNewNode(t *testing.T) {
	cs := fake.NewClientset(
		newPodForDynamic("ns1", "early", "node-1", map[string]string{"app": "x"}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		time.Sleep(250 * time.Millisecond)
		_, _ = cs.CoreV1().Pods("ns1").Create(ctx, newPodForDynamic("ns1", "late", "node-2", map[string]string{"app": "x"}), metav1.CreateOptions{})
	}()

	created := map[string]int{}
	build := func(node string, _ []PodRef) []string { created[node]++; return []string{"--noop"} }

	sel := pkgkube.TargetSelection{DefaultNamespace: "ns1", PodSelector: "app=x", AllInNamespace: true}
	seen := map[string]bool{}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		got, err := ResolveTargetNodes(ctx, cs, sel)
		if err == nil {
			for _, n := range got.NodeNames {
				if !seen[n] {
					seen[n] = true
					build(n, got.ByNode[n])
				}
			}
		}
		if len(seen) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !seen["node-1"] || !seen["node-2"] {
		t.Errorf("expected both node-1 and node-2 to be discovered, got %v", seen)
	}
}

func TestRun_RejectsMissingCallback(t *testing.T) {
	cs := fake.NewClientset()
	err := Run(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Image:      "x",
		Streams:    genericiooptions.IOStreams{},
	})
	if err == nil {
		t.Fatal("expected error for missing BuildChildArgs")
	}
}
