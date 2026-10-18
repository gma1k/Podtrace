package nodespawn

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func pod(ns, name, node string, labels map[string]string) *corev1.Pod {
	return withRunningContainer(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: node},
	})
}

func withRunningContainer(p *corev1.Pod) *corev1.Pod {
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{
		Name:        "app",
		ContainerID: "containerd://" + p.Name + "-id",
		State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	return p
}

func refNames(refs []PodRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

func TestResolveTargetNodes_NilClientset(t *testing.T) {
	if _, err := ResolveTargetNodes(context.Background(), nil, pkgkube.TargetSelection{}); err == nil {
		t.Fatalf("expected error for nil clientset")
	}
}

func TestResolveTargetNodes_ExplicitPods_FanOutByNode(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "a", "node-1", nil),
		pod("ns1", "b", "node-2", nil),
		pod("ns2", "c", "node-1", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"a", "b", "ns2/c"},
	}

	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	wantNode1 := []string{"ns1/a", "ns2/c"}
	if !reflect.DeepEqual(refNames(got.ByNode["node-1"]), wantNode1) {
		t.Errorf("node-1 refs = %v, want %v", got.ByNode["node-1"], wantNode1)
	}
	wantNode2 := []string{"ns1/b"}
	if !reflect.DeepEqual(refNames(got.ByNode["node-2"]), wantNode2) {
		t.Errorf("node-2 refs = %v, want %v", got.ByNode["node-2"], wantNode2)
	}
}

func TestResolveTargetNodes_PodSelector_AcrossNamespaces(t *testing.T) {
	cs := fake.NewClientset(
		pod("app", "api-1", "node-1", map[string]string{"app": "api"}),
		pod("app", "api-2", "node-2", map[string]string{"app": "api"}),
		pod("app", "worker", "node-1", map[string]string{"app": "worker"}),
		pod("other", "api-3", "node-1", map[string]string{"app": "api"}),
	)
	sel := pkgkube.TargetSelection{
		Namespaces:  []string{"app", "other"},
		PodSelector: "app=api",
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	got1 := refNames(got.ByNode["node-1"])
	want1 := []string{"app/api-1", "other/api-3"}
	if !reflect.DeepEqual(got1, want1) {
		t.Errorf("node-1 refs = %v, want %v", got1, want1)
	}
	got2 := refNames(got.ByNode["node-2"])
	want2 := []string{"app/api-2"}
	if !reflect.DeepEqual(got2, want2) {
		t.Errorf("node-2 refs = %v, want %v", got2, want2)
	}
}

func TestResolveTargetNodes_AllInNamespace(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "p1", "node-1", nil),
		pod("ns1", "p2", "node-2", nil),
		pod("ns2", "ignored", "node-1", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	if got.ByNode["node-1"][0].Name != "p1" || got.ByNode["node-2"][0].Name != "p2" {
		t.Errorf("unexpected refs: %+v", got.ByNode)
	}
}

func TestResolveTargetNodes_SkipsTerminatingPods(t *testing.T) {
	terminating := pod("ns1", "going", "node-1", map[string]string{"app": "x"})
	now := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &now
	cs := fake.NewClientset(
		terminating,
		pod("ns1", "alive", "node-1", map[string]string{"app": "x"}),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.ByNode["node-1"]) != 1 || got.ByNode["node-1"][0].Name != "alive" {
		t.Errorf("expected only the non-terminating pod, got %+v", got.ByNode["node-1"])
	}
}

func TestResolveTargetNodes_AllUnscheduled_Errors(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "pending", "", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"pending"},
	}
	_, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err == nil {
		t.Fatalf("expected error when all pods unscheduled")
		return
	}
	if !strings.Contains(err.Error(), "not yet scheduled") {
		t.Errorf("error %q does not mention scheduling state", err)
	}
}

func TestResolveTargetNodes_GetPodError_Propagates(t *testing.T) {
	cs := fake.NewClientset() // no pods
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"missing"},
	}
	_, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err == nil {
		t.Fatalf("expected error from missing pod")
	}
}

// podWithContainer constructs a pod whose first container is in the given
// state — used by the pickRunningContainer tests to pin the selection logic
// for stale-restart / crash-loop / just-starting scenarios.
func podWithContainer(ns, name, node, cName, cID string, state corev1.ContainerState) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        cName,
				ContainerID: cID,
				State:       state,
			}},
		},
	}
}

func TestPickRunningContainers_SelectsAllRunning(t *testing.T) {
	p := &corev1.Pod{Status: corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{
			{Name: "a", ContainerID: "containerd://aaa", State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"},
			}},
			{Name: "b", ContainerID: "containerd://bbb", State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			}},
			{Name: "c", ContainerID: "containerd://ccc", State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
			}},
		},
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: "mesh", ContainerID: "containerd://mmm", State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{},
			}},
		},
	}}
	got := pickRunningContainers(p, "")
	if len(got) != 2 || got[0].Name != "b" || got[1].Name != "mesh" {
		t.Fatalf("expected all Running containers [b mesh], got %+v", got)
	}
	if named := pickRunningContainers(p, "b"); len(named) != 1 || named[0].Name != "b" {
		t.Fatalf("named pick = %+v, want exactly b", named)
	}
}

func TestPickRunningContainers_RejectsAllNonRunning(t *testing.T) {
	cases := map[string]corev1.ContainerState{
		"Waiting":    {Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
		"Terminated": {Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
	}
	for name, st := range cases {
		t.Run(name, func(t *testing.T) {
			p := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "x", ContainerID: "containerd://xxx", State: st},
			}}}
			if got := pickRunningContainers(p, ""); len(got) != 0 {
				t.Errorf("must not pick a %s container, got %+v", name, got)
			}
		})
	}
}

func TestPickRunningContainers_RejectsRunningWithEmptyID(t *testing.T) {
	// A Pod can momentarily be in Status.Running with ContainerID="" right
	// at startup. We must NOT hand the spawn pod an empty containerID.
	p := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
		{Name: "x", ContainerID: "", State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		}},
	}}}
	if got := pickRunningContainers(p, ""); len(got) != 0 {
		t.Errorf("Running container with empty ID must be rejected, got %+v", got)
	}
}

// TestResolveTargetNodes_SkipsNonRunningContainerIDs — the fix for the
// cross-node "cgroup path not found" failure mode: when one matching pod's
// container is Waiting/Terminated, the workstation must NOT hand its stale
// containerID to the spawn pod. A pod with no running container gives the
// spawn pod nothing to trace, so it is not routed at all.
func TestResolveTargetNodes_SkipsNonRunningContainerIDs(t *testing.T) {
	running := podWithContainer("ns", "alive", "node-1", "app",
		"containerd://aaaaaa", corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		})
	restarting := podWithContainer("ns", "restarting", "node-1", "app",
		"containerd://bbbbbb", corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
		})
	cs := fake.NewClientset(running, restarting)

	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns",
		Pods:             []string{"alive", "restarting"},
	}
	out, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	refs := out.ByNode["node-1"]
	if len(refs) != 1 || refs[0].Name != "alive" {
		t.Fatalf("expected only the running pod routed to node-1, got %v", refs)
	}
	if refs[0].ContainerID != "aaaaaa" {
		t.Errorf("Running pod must propagate containerID, got %q", refs[0].ContainerID)
	}
}

// TestResolveTargetNodes_DedupesNameAndSelectorMatch guards against a pod that
// matches both an explicit --pods entry and the label selector being added
// twice (and thus traced/profiled twice).
func TestResolveTargetNodes_DedupesNameAndSelectorMatch(t *testing.T) {
	p := podWithContainer("ns1", "dup", "node-1", "app",
		"containerd://aaaaaaaaaaaa", corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		})
	p.Labels = map[string]string{"app": "api"}
	cs := fake.NewClientset(p)

	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Namespaces:       []string{"ns1"},
		Pods:             []string{"dup"}, // explicit match
		PodSelector:      "app=api",       // selector match too
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := len(got.ByNode["node-1"]); n != 1 {
		t.Fatalf("pod matched by name AND selector must be added once, got %d refs", n)
	}
}
