package kubernetes

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func selectablePod(ns, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "-" + name), Labels: labels},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:        "app",
			ContainerID: "containerd://abcdef0123456789",
			State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
}

func isolateRegistryResolution(t *testing.T) {
	t.Helper()
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	useCgroupAndProcBase(t)
}

func startRegistry(t *testing.T, tr *TargetRegistry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := tr.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-tr.Done()
	})
}

func snapshotNames(infos []*PodInfo) []string {
	out := make([]string, 0, len(infos))
	for _, p := range infos {
		out = append(out, p.Namespace+"/"+p.PodName)
	}
	sort.Strings(out)
	return out
}

func TestWatchNamespacesFollowTheNamespacesOfThePodRefs(t *testing.T) {
	sel := TargetSelection{DefaultNamespace: "default", Pods: []string{"ns2/b", "ns1/a"}}
	if got := sel.WatchNamespaces(); !reflect.DeepEqual(got, []string{"ns1", "ns2"}) {
		t.Fatalf("WatchNamespaces = %v, want [ns1 ns2]", got)
	}
}

func TestWatchNamespacesCoverEveryNamespaceWhenNoneIsNamed(t *testing.T) {
	sel := TargetSelection{PodSelector: "app=checkout"}
	if got := sel.WatchNamespaces(); !reflect.DeepEqual(got, []string{metav1.NamespaceAll}) {
		t.Fatalf("WatchNamespaces = %v, want every namespace", got)
	}
}

func TestMatcherIntersectsPodRefsWithTheSelector(t *testing.T) {
	matches, err := TargetSelection{
		Namespaces:  []string{"a", "b"},
		Pods:        []string{"a/x", "b/y"},
		PodSelector: "app=api",
	}.Matcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		pod  *corev1.Pod
		want bool
	}{
		"named and labelled":           {selectablePod("a", "x", map[string]string{"app": "api"}), true},
		"named but not labelled":       {selectablePod("b", "y", map[string]string{"app": "web"}), false},
		"labelled in scope, not named": {selectablePod("a", "other", map[string]string{"app": "api"}), false},
	}
	for name, tc := range cases {
		if got := matches(tc.pod); got != tc.want {
			t.Errorf("%s: matches = %v, want %v", name, got, tc.want)
		}
	}
}

func TestMatcherRejectsAnInvalidSelector(t *testing.T) {
	if _, err := (TargetSelection{PodSelector: "app in (("}).Matcher(); err == nil {
		t.Fatal("expected an invalid selector to be rejected")
	}
}

func TestRegistryTracesPodRefsOutsideTheDefaultNamespace(t *testing.T) {
	isolateRegistryResolution(t)
	cs := fake.NewClientset(selectablePod("ns1", "a", nil), selectablePod("ns2", "b", nil), selectablePod("default", "c", nil))
	tr := NewTargetRegistry(cs, TargetSelection{DefaultNamespace: "default", Pods: []string{"ns1/a", "ns2/b"}})
	startRegistry(t, tr)
	if got := snapshotNames(tr.Snapshot()); !reflect.DeepEqual(got, []string{"ns1/a", "ns2/b"}) {
		t.Fatalf("traced %v, want [ns1/a ns2/b]", got)
	}
}

func TestRegistryWatchesEveryNamespaceForASelectorAlone(t *testing.T) {
	isolateRegistryResolution(t)
	cs := fake.NewClientset(
		selectablePod("shop", "checkout-1", map[string]string{"app": "checkout"}),
		selectablePod("staging", "checkout-2", map[string]string{"app": "checkout"}),
		selectablePod("shop", "cart", map[string]string{"app": "cart"}),
	)
	tr := NewTargetRegistry(cs, TargetSelection{PodSelector: "app=checkout"})
	startRegistry(t, tr)
	if got := snapshotNames(tr.Snapshot()); !reflect.DeepEqual(got, []string{"shop/checkout-1", "staging/checkout-2"}) {
		t.Fatalf("traced %v", got)
	}
}

func TestADeletedPodIsNotResurrectedByAQueuedUpsert(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	pod := selectablePod("ns", "gone", nil)

	tr.enqueueUpsert(pod)
	tr.handlePodDelete(pod)

	tr.pendingMu.Lock()
	queued := len(tr.pending)
	tr.pendingMu.Unlock()
	if queued != 0 {
		t.Fatalf("delete left %d upserts queued", queued)
	}
	if tr.upsertPod(context.Background(), pod) {
		t.Fatal("an upsert already in flight when the pod was deleted reported a change")
	}
	if got := tr.Snapshot(); len(got) != 0 {
		t.Fatalf("deleted pod came back as a target: %v", snapshotNames(got))
	}
}

func TestDeletedPodMemoryIsPruned(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	tr.deleted[types.UID("old")] = time.Now().Add(-2 * deletedPodMemory)
	tr.handlePodDelete(selectablePod("ns", "new", nil))
	if _, ok := tr.deleted[types.UID("old")]; ok {
		t.Fatal("a tombstone older than deletedPodMemory was kept")
	}
	if _, ok := tr.deleted[types.UID("ns-new")]; !ok {
		t.Fatal("the new delete was not remembered")
	}
}
