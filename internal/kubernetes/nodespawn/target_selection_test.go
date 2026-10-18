package nodespawn

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/gma1k/podtrace/internal/config"
	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func isolateCgroupResolution(t *testing.T) {
	t.Helper()
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	origCgroup, origProc := config.CgroupBasePath, config.ProcBasePath
	config.SetCgroupBasePath(t.TempDir())
	config.SetProcBasePath(t.TempDir())
	t.Cleanup(func() {
		config.SetCgroupBasePath(origCgroup)
		config.SetProcBasePath(origProc)
	})
}

func resolvedNames(t *testing.T, cs *fake.Clientset, sel pkgkube.TargetSelection) []string {
	t.Helper()
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("ResolveTargetNodes: %v", err)
	}
	var out []string
	for _, refs := range got.ByNode {
		out = append(out, refNames(refs)...)
	}
	sort.Strings(out)
	return out
}

func TestASelectorAcrossAllNamespacesFindsEveryMatch(t *testing.T) {
	cs := fake.NewClientset(
		pod("shop", "checkout-1", "node-1", map[string]string{"app": "checkout"}),
		pod("staging", "checkout-2", "node-2", map[string]string{"app": "checkout"}),
		pod("shop", "cart", "node-1", map[string]string{"app": "cart"}),
	)
	got := resolvedNames(t, cs, pkgkube.TargetSelection{PodSelector: "app=checkout"})
	if !reflect.DeepEqual(got, []string{"shop/checkout-1", "staging/checkout-2"}) {
		t.Fatalf("traced %v", got)
	}
}

func TestNamedPodsAreNotWidenedToTheirWholeNamespaces(t *testing.T) {
	cs := fake.NewClientset(
		pod("a", "x", "node-1", nil),
		pod("a", "other1", "node-1", nil),
		pod("b", "y", "node-2", nil),
		pod("b", "other2", "node-2", nil),
	)
	got := resolvedNames(t, cs, pkgkube.TargetSelection{
		DefaultNamespace: "a",
		Namespaces:       []string{"a", "b"},
		Pods:             []string{"a/x", "b/y"},
	})
	if !reflect.DeepEqual(got, []string{"a/x", "b/y"}) {
		t.Fatalf("traced %v, want only the named pods", got)
	}
}

func TestNamedPodsAreFilteredByTheSelector(t *testing.T) {
	cs := fake.NewClientset(
		pod("a", "x", "node-1", map[string]string{"app": "api"}),
		pod("a", "y", "node-1", map[string]string{"app": "web"}),
		pod("a", "z", "node-1", map[string]string{"app": "api"}),
	)
	got := resolvedNames(t, cs, pkgkube.TargetSelection{
		DefaultNamespace: "a",
		Pods:             []string{"x", "y"},
		PodSelector:      "app=api",
	})
	if !reflect.DeepEqual(got, []string{"a/x"}) {
		t.Fatalf("traced %v, want the intersection [a/x]", got)
	}
}

func TestNamedPodsNoneOfWhichMatchTheSelectorFailClearly(t *testing.T) {
	cs := fake.NewClientset(pod("a", "y", "node-1", map[string]string{"app": "web"}))
	_, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "a", Pods: []string{"y"}, PodSelector: "app=api",
	})
	if err == nil || !strings.Contains(err.Error(), "--pod-selector") {
		t.Fatalf("expected a selector-mismatch error, got %v", err)
	}
}

func TestAPodWithNoRunningContainerIsNotSpawnedFor(t *testing.T) {
	starting := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "starting"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
	}
	cs := fake.NewClientset(starting)
	_, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "ns", Pods: []string{"starting"},
	})
	if err == nil || !strings.Contains(err.Error(), "no running container yet") {
		t.Fatalf("expected a no-running-container error, got %v", err)
	}
}

func TestABarePodNameWithoutANamespaceIsRejected(t *testing.T) {
	_, err := ResolveTargetNodes(context.Background(), fake.NewClientset(), pkgkube.TargetSelection{Pods: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "need a namespace") {
		t.Fatalf("expected a missing-namespace error, got %v", err)
	}
}

func TestSpawnAndLocalPlanesSelectTheSamePods(t *testing.T) {
	isolateCgroupResolution(t)
	hexPod := func(ns, name, node string, labels map[string]string) *corev1.Pod {
		p := pod(ns, name, node, labels)
		p.UID = types.UID(ns + "/" + name)
		p.Status.ContainerStatuses[0].ContainerID = "containerd://0123456789abcdef"
		return p
	}
	objects := []*corev1.Pod{
		hexPod("a", "x", "node-1", map[string]string{"app": "api"}),
		hexPod("a", "other1", "node-1", map[string]string{"app": "api"}),
		hexPod("b", "y", "node-2", map[string]string{"app": "web"}),
		hexPod("b", "other2", "node-2", map[string]string{"app": "api"}),
		hexPod("c", "z", "node-2", map[string]string{"app": "api"}),
	}
	selections := map[string]pkgkube.TargetSelection{
		"refs across namespaces": {DefaultNamespace: "default", Pods: []string{"a/x", "b/y"}},
		"refs inside namespaces": {DefaultNamespace: "a", Namespaces: []string{"a", "b"}, Pods: []string{"a/x", "b/y"}},
		"refs with selector":     {DefaultNamespace: "a", Pods: []string{"a/x", "b/y"}, PodSelector: "app=api"},
		"selector in namespaces": {Namespaces: []string{"a", "b"}, PodSelector: "app=api"},
		"selector everywhere":    {PodSelector: "app=api"},
		"whole namespaces":       {Namespaces: []string{"a", "c"}, AllInNamespace: true},
	}
	for name, sel := range selections {
		t.Run(name, func(t *testing.T) {
			cs := fake.NewClientset()
			for _, p := range objects {
				if _, err := cs.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			spawn := resolvedNames(t, cs, sel)

			registry := pkgkube.NewTargetRegistry(cs, sel)
			ctx, cancel := context.WithCancel(context.Background())
			if err := registry.Start(ctx); err != nil {
				cancel()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cancel()
				<-registry.Done()
			})
			var local []string
			for _, info := range registry.Snapshot() {
				local = append(local, info.Namespace+"/"+info.PodName)
			}
			sort.Strings(local)

			if !reflect.DeepEqual(spawn, local) {
				t.Fatalf("spawn traces %v, local traces %v", spawn, local)
			}
		})
	}
}
