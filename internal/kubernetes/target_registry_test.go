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
	"k8s.io/client-go/tools/cache"
)

func TestTargetSelection_EffectiveNamespaces(t *testing.T) {
	cases := []struct {
		name string
		sel  TargetSelection
		want []string
	}{
		{"explicit list wins over default", TargetSelection{DefaultNamespace: "fallback", Namespaces: []string{"a", "b"}}, []string{"a", "b"}},
		{"dedup and trim", TargetSelection{Namespaces: []string{"a", " a ", " ", "b", "b"}}, []string{"a", "b"}},
		{"falls back to default", TargetSelection{DefaultNamespace: "ns"}, []string{"ns"}},
		{"empty when nothing set", TargetSelection{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sel.EffectiveNamespaces()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestTargetSelection_PodRefSet(t *testing.T) {
	sel := TargetSelection{
		DefaultNamespace: "def",
		Pods: []string{
			"plain",
			"  ",
			"ns1/qual",
			"ns1/qual", // dedup within ns
			"ns2/other",
		},
	}
	got := sel.PodRefSet()
	want := map[string]map[string]struct{}{
		"def": {"plain": {}},
		"ns1": {"qual": {}},
		"ns2": {"other": {}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestTargetSelection_PodRefSet_Empty(t *testing.T) {
	sel := TargetSelection{DefaultNamespace: "def"}
	got := sel.PodRefSet()
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %#v", got)
	}
}

func TestUniqNonEmpty(t *testing.T) {
	in := []string{"a", " a ", "", "b", "  ", "b", "c"}
	got := uniqNonEmpty(in)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGetIntEnv(t *testing.T) {
	t.Setenv("PODTRACE_TEST_INT_UNSET", "")
	if got := getIntEnv("PODTRACE_TEST_INT_UNSET", 7); got != 7 {
		t.Fatalf("unset: got %d want 7", got)
	}
	t.Setenv("PODTRACE_TEST_INT_OK", "42")
	if got := getIntEnv("PODTRACE_TEST_INT_OK", 7); got != 42 {
		t.Fatalf("ok: got %d want 42", got)
	}
	t.Setenv("PODTRACE_TEST_INT_BAD", "not-a-number")
	if got := getIntEnv("PODTRACE_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("bad: got %d want 7", got)
	}
	t.Setenv("PODTRACE_TEST_INT_NEG", "-3")
	if got := getIntEnv("PODTRACE_TEST_INT_NEG", 7); got != 7 {
		t.Fatalf("neg: got %d want 7 (negative should be rejected)", got)
	}
	t.Setenv("PODTRACE_TEST_INT_ZERO", "0")
	if got := getIntEnv("PODTRACE_TEST_INT_ZERO", 7); got != 7 {
		t.Fatalf("zero: got %d want 7 (zero should be rejected)", got)
	}
}

func TestNewTargetRegistry_AppliesDefaults(t *testing.T) {
	cs := fake.NewSimpleClientset()
	tr := NewTargetRegistry(cs, TargetSelection{
		DefaultNamespace: "ns",
		Pods:             []string{"a", "b/c"},
	})
	if tr == nil {
		t.Fatal("expected non-nil registry")
		return
	}
	if tr.maxTargets != 256 {
		t.Fatalf("default maxTargets: got %d want 256", tr.maxTargets)
	}
	if tr.targets == nil {
		t.Fatal("expected targets map to be initialized")
	}
	if cap(tr.updates) != 8 {
		t.Fatalf("updates buffer cap: got %d want 8", cap(tr.updates))
	}
	if !tr.matchesSelection(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a"}}) {
		t.Errorf("default-namespace pod ref does not match")
	}
	if !tr.matchesSelection(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "b", Name: "c"}}) {
		t.Errorf("qualified pod ref does not match")
	}
}

func TestNewTargetRegistry_HonorsEnvOverride(t *testing.T) {
	t.Setenv("PODTRACE_MAX_TARGET_PODS", "5")
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	if tr.maxTargets != 5 {
		t.Fatalf("env-overridden maxTargets: got %d want 5", tr.maxTargets)
	}
}

func TestTargetRegistry_Snapshot_ReturnsDefensiveCopy(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.targets[types.UID("a")] = &PodInfo{PodName: "a", CgroupPath: "/c/a"}
	tr.targets[types.UID("b")] = &PodInfo{PodName: "b", CgroupPath: "/c/b"}

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len: got %d want 2", len(snap))
	}
	// Mutating an item in the snapshot must not affect the registry.
	snap[0].PodName = "MUTATED"

	again := tr.Snapshot()
	for _, p := range again {
		if p.PodName == "MUTATED" {
			t.Fatal("Snapshot did not return a defensive copy of PodInfo")
		}
	}
}

func TestTargetRegistry_Updates_ReturnsChannel(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	if tr.Updates() == nil {
		t.Fatal("Updates() returned nil")
	}
}

func TestTargetRegistry_MatchesSelection(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{
		DefaultNamespace: "default",
		Namespaces:       []string{"prod", "stage"},
		Pods:             []string{"prod/api", "stage/web"},
	})

	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"nil pod", nil, false},
		{
			"namespace not in selection",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "api"}},
			false,
		},
		{
			"namespace OK but pod-name not in refs",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "other"}},
			false,
		},
		{
			"namespace + name match",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api"}},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tr.matchesSelection(tc.pod); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestTargetRegistry_MatchesSelection_NamespaceOnly(t *testing.T) {
	// No Pods → name filtering is skipped; namespace gate is the only constraint.
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{
		Namespaces: []string{"team-a"},
	})
	in := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "anything"}}
	if !tr.matchesSelection(in) {
		t.Fatal("namespace-only match should accept any pod in that namespace")
	}
	out := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "anything"}}
	if tr.matchesSelection(out) {
		t.Fatal("namespace-only match should reject other namespaces")
	}
}

func TestTargetRegistry_MatchesSelection_NoConstraints(t *testing.T) {
	// Empty selection accepts every non-nil pod.
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "x", Name: "y"}}
	if !tr.matchesSelection(pod) {
		t.Fatal("empty selection should match any pod")
	}
}

func TestTargetRegistry_HandlePodDelete(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	uid := types.UID("abc")
	tr.targets[uid] = &PodInfo{PodName: "p"}

	// Drain initial channel state if any.
	select {
	case <-tr.updates:
	default:
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: uid, Name: "p", Namespace: "ns"}}
	tr.handlePodDelete(pod)

	if _, ok := tr.targets[uid]; ok {
		t.Fatal("expected pod to be removed from targets")
	}
	// emitSnapshot must have produced a value on updates.
	select {
	case snap := <-tr.updates:
		if len(snap) != 0 {
			t.Fatalf("expected empty snapshot after delete, got %d items", len(snap))
		}
	case <-time.After(time.Second):
		t.Fatal("emitSnapshot did not push to updates")
	}
}

func TestTargetRegistry_HandlePodDelete_TombstoneRecovers(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	uid := types.UID("tomb")
	tr.targets[uid] = &PodInfo{PodName: "p"}

	tomb := cache.DeletedFinalStateUnknown{
		Key: "ns/p",
		Obj: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: uid, Name: "p", Namespace: "ns"}},
	}
	tr.handlePodDelete(tomb)

	if _, ok := tr.targets[uid]; ok {
		t.Fatal("expected pod to be removed via tombstone")
	}
}

func TestTargetRegistry_HandlePodDelete_IgnoresUnknownTypes(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.targets[types.UID("a")] = &PodInfo{PodName: "a"}

	// String is neither *Pod nor DeletedFinalStateUnknown → must be a no-op.
	tr.handlePodDelete("not-a-pod")

	if _, ok := tr.targets[types.UID("a")]; !ok {
		t.Fatal("unrelated input should not have mutated targets")
	}
}

func TestTargetRegistry_HandlePodDelete_TombstoneNonPodNoop(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.targets[types.UID("a")] = &PodInfo{PodName: "a"}

	tomb := cache.DeletedFinalStateUnknown{Key: "k", Obj: "not-a-pod"}
	tr.handlePodDelete(tomb)

	if _, ok := tr.targets[types.UID("a")]; !ok {
		t.Fatal("tombstone with non-Pod payload should be ignored")
	}
}

func TestTargetRegistry_HandlePodUpsert_NonMatchingDeletes(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{
		Namespaces: []string{"prod"},
	})
	uid := types.UID("u1")
	tr.targets[uid] = &PodInfo{PodName: "stale"}

	// Upsert with a pod outside the watched namespace must remove it.
	tr.handlePodUpsert(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: uid, Name: "stale", Namespace: "dev"},
	})
	if _, ok := tr.targets[uid]; ok {
		t.Fatal("non-matching upsert should remove existing target")
	}
}

func TestTargetRegistry_EnqueueUpsert_IgnoresNonPod(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.enqueueUpsert("not a pod") // must be a no-op
	tr.enqueueUpsert(nil)         // nil pod
	if len(tr.pending) != 0 || len(tr.targets) != 0 {
		t.Fatal("upsert of non-pod must not enqueue or insert anything")
	}
}

func TestTargetRegistry_HandlePodUpsert_ResolveErrorIsSwallowed(t *testing.T) {
	// Pod matches selection but has no container statuses → resolvePodInfoFromObject errors,
	// so handlePodUpsert returns without inserting.
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "no-status", Name: "p", Namespace: "ns"},
		// Status.ContainerStatuses intentionally empty.
	}
	tr.handlePodUpsert(context.Background(), pod)
	if _, ok := tr.targets[pod.UID]; ok {
		t.Fatal("pod with no container statuses must not be inserted")
	}
}

func TestResolvePodInfoFromObject_ErrorPaths(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
		cn   string
	}{
		{"nil pod", nil, ""},
		{
			"no container statuses",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n"}},
			"",
		},
		{
			"named container missing",
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c0"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "c0", ContainerID: "containerd://" + hex64()},
					},
				},
			},
			"missing-container",
		},
		{
			"malformed container id",
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c0"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "c0", ContainerID: "not-a-real-id"},
					},
				},
			},
			"",
		},
		{
			"container id fails validation",
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c0"}},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "c0", ContainerID: "containerd://short"},
					},
				},
			},
			"",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := resolvePodInfoFromObject(ctx, tc.pod, tc.cn)
			if err == nil {
				t.Fatalf("expected error, got info=%+v", info)
			}
			if info != nil {
				t.Fatalf("expected nil info on error, got %+v", info)
			}
		})
	}
}

func TestClonePodInfos(t *testing.T) {
	in := map[types.UID]*PodInfo{
		"a": {PodName: "a", Labels: map[string]string{"k": "v"}},
		"b": {PodName: "b"},
	}
	out := clonePodInfos(in)
	if len(out) != 2 {
		t.Fatalf("len: got %d want 2", len(out))
	}
	// Stable sort for deterministic comparison.
	sort.Slice(out, func(i, j int) bool { return out[i].PodName < out[j].PodName })
	if out[0].PodName != "a" || out[1].PodName != "b" {
		t.Fatalf("unexpected names: %+v", out)
	}
	// Mutating the clone slice's value-copy must not change the source map.
	out[0].PodName = "mutated"
	if in["a"].PodName != "a" {
		t.Fatal("clonePodInfos returned shallow copies of *PodInfo (struct fields aliased)")
	}
}

func TestEmitSnapshot_LatestWinsOnFullBuffer(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	// Saturate the 8-deep buffer so emitSnapshot exercises the drop-oldest branch.
	for i := 0; i < 16; i++ {
		uid := types.UID([]byte{byte('a' + i)})
		tr.targets = map[types.UID]*PodInfo{uid: {PodName: string(uid)}}
		tr.emitSnapshot()
	}
	// Drain whatever is queued; the last value must reflect the most recent call.
	var last []*PodInfo
	for {
		select {
		case s := <-tr.updates:
			last = s
		case <-time.After(50 * time.Millisecond):
			goto done
		}
	}
done:
	if len(last) != 1 {
		t.Fatalf("expected last snapshot to have 1 element, got %d", len(last))
	}
}

func TestTargetRegistry_Start_NilClientsetErrors(t *testing.T) {
	var tr *TargetRegistry
	if err := tr.Start(context.Background()); err == nil {
		t.Fatal("expected error on nil registry")
	}
	tr = NewTargetRegistry(nil, TargetSelection{})
	if err := tr.Start(context.Background()); err == nil {
		t.Fatal("expected error on nil clientset")
	}
}

func TestTargetRegistry_Start_CacheSyncTimeout(t *testing.T) {
	cs := fake.NewSimpleClientset()
	tr := NewTargetRegistry(cs, TargetSelection{Namespaces: []string{"ns"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled context → WaitForCacheSync returns false immediately.
	if err := tr.Start(ctx); err == nil {
		t.Fatal("expected cache-sync error when context is cancelled")
	}
}

func TestTargetRegistry_Start_HappyPathEmitsInitialSnapshot(t *testing.T) {
	cs := fake.NewSimpleClientset()
	tr := NewTargetRegistry(cs, TargetSelection{Namespaces: []string{"ns"}, PodSelector: "app=x"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case snap := <-tr.Updates():
		if len(snap) != 0 {
			t.Fatalf("expected empty snapshot, got %d", len(snap))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not emit initial snapshot")
	}
}

// hex64 returns a 64-char hex string suitable for ValidateContainerID.
func hex64() string {
	const s = "0123456789abcdef"
	b := make([]byte, 64)
	for i := range b {
		b[i] = s[i%16]
	}
	return string(b)
}
