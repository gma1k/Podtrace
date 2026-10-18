package nodespawn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func runningOnCreate(cs *fake.Clientset) {
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		pod, ok := ca.GetObject().(*corev1.Pod)
		if !ok {
			return false, nil, nil
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  "podtrace",
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}
		return false, nil, nil
	})
}

func spawnPodSpec(t *testing.T, ns string) *corev1.Pod {
	t.Helper()
	spec, err := BuildPodSpec(PodSpecOptions{
		NodeName:  "node-1",
		Namespace: ns,
		Image:     "ghcr.io/gma1k/podtrace:test",
		Args:      []string{"--noop"},
	})
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	return spec
}

func TestRun_RejectsNilClientset(t *testing.T) {
	err := Run(context.Background(), RunOptions{
		RestConfig:     &rest.Config{},
		Image:          "x",
		BuildChildArgs: func(string, []PodRef) []string { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Clientset and RestConfig required") {
		t.Fatalf("expected clientset/restconfig error, got %v", err)
	}
}

func TestRun_RejectsNilRestConfig(t *testing.T) {
	err := Run(context.Background(), RunOptions{
		Clientset:      fake.NewClientset(),
		Image:          "x",
		BuildChildArgs: func(string, []PodRef) []string { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Clientset and RestConfig required") {
		t.Fatalf("expected clientset/restconfig error, got %v", err)
	}
}

func TestRun_RejectsEmptyImage(t *testing.T) {
	err := Run(context.Background(), RunOptions{
		Clientset:      fake.NewClientset(),
		RestConfig:     &rest.Config{},
		BuildChildArgs: func(string, []PodRef) []string { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Image required") {
		t.Fatalf("expected image-required error, got %v", err)
	}
}

func TestRun_NoScheduledTargetPods(t *testing.T) {

	cs := fake.NewClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "pending", Labels: map[string]string{"app": "x"}},
		Spec:       corev1.PodSpec{},
	})
	err := Run(context.Background(), RunOptions{
		Clientset:      cs,
		RestConfig:     &rest.Config{},
		Image:          "x",
		BuildChildArgs: func(string, []PodRef) []string { return []string{"--noop"} },
		Selection:      pkgkube.TargetSelection{DefaultNamespace: "ns1", AllInNamespace: true},
	})

	if err == nil {
		t.Fatalf("expected an error for no scheduled target pods")
	}
}

func TestRunOneNode_OnPodRunningErrorStopsBeforeAttach(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)

	spec := spawnPodSpec(t, "ns1")
	sentinel := errors.New("callback aborted before attach")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()

	var ranWith *corev1.Pod
	opts := RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		OnPodRunning: func(_ context.Context, pod *corev1.Pod) error {
			ranWith = pod
			return sentinel
		},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "cart-abc")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error from OnPodRunning, got %v", err)
	}
	if ranWith == nil || ranWith.Name != spec.Name {
		t.Fatalf("OnPodRunning got %v, want the created spawn pod %q", ranWith, spec.Name)
	}

	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Errorf("spawn pod should have been cleaned up on error, get err=%v", gerr)
	}
}

func TestRunOneNode_KeepSpawnPodOnFailurePreservesPod(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	errBuf := errOut

	opts := RunOptions{
		Clientset:             cs,
		RestConfig:            &rest.Config{},
		Streams:               genericiooptions.IOStreams{Out: out, ErrOut: errBuf},
		KeepSpawnPodOnFailure: true,
		OnPodRunning: func(context.Context, *corev1.Pod) error {
			return errors.New("boom")
		},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil {
		t.Fatalf("expected error")
	}

	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); gerr != nil {
		t.Errorf("spawn pod must be preserved on failure, get err=%v", gerr)
	}
	if !strings.Contains(errBuf.String(), "spawn pod preserved for debugging") {
		t.Errorf("expected preservation hint on ErrOut, got %q", errBuf.String())
	}
}

func TestRunOneNode_CreateForbiddenPodSecurity(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Resource: "pods"}, "spawn",
			errors.New("violates PodSecurity \"restricted:latest\": privileged"))
	})

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil || !strings.Contains(err.Error(), "PodSecurity") {
		t.Fatalf("expected PodSecurity remediation error, got %v", err)
		return
	}
	if !strings.Contains(err.Error(), "pod-security.kubernetes.io/enforce=privileged") {
		t.Errorf("error should carry the remediation command, got %v", err)
	}
}

func TestRunOneNode_GenericCreateErrorPropagates(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil || !strings.Contains(err.Error(), "create spawn pod") {
		t.Fatalf("expected create-spawn-pod error, got %v", err)
	}
}

func TestRunOneNode_SplunkSecretCreatedAndCleanedUp(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)

	spec := spawnPodSpec(t, "ns1")
	secretName := SpawnSecretName(spec.Name)
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()

	var secretSeenDuringCallback bool
	opts := RunOptions{
		Clientset:   cs,
		RestConfig:  &rest.Config{},
		Streams:     genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		SplunkToken: "hec-token-value",
		OnPodRunning: func(context.Context, *corev1.Pod) error {

			if _, e := cs.CoreV1().Secrets("ns1").Get(context.Background(), secretName, metav1.GetOptions{}); e == nil {
				secretSeenDuringCallback = true
			}
			return errors.New("stop before attach")
		},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !secretSeenDuringCallback {
		t.Errorf("Splunk token secret was not created before the pod ran")
	}

	if _, gerr := cs.CoreV1().Secrets("ns1").Get(context.Background(), secretName, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Errorf("Splunk secret should be cleaned up, get err=%v", gerr)
	}
	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Errorf("spawn pod should be cleaned up, get err=%v", gerr)
	}
}

func TestRunOneNode_SplunkSecretCreateFailureAbortsBeforePod(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("secret quota exceeded")
	})

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:   cs,
		RestConfig:  &rest.Config{},
		Streams:     genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		SplunkToken: "hec-token-value",
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil || !strings.Contains(err.Error(), "create secret") {
		t.Fatalf("expected secret-create error, got %v", err)
	}

	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Errorf("spawn pod must not exist when secret creation fails, err=%v", gerr)
	}
}

func TestRunOneNode_WaitForRunningFailurePropagates(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()

	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca := a.(k8stesting.CreateAction)
		pod := ca.GetObject().(*corev1.Pod)
		pod.Status.Phase = corev1.PodPending
		pod.Status.Conditions = []corev1.PodCondition{{
			Type:    corev1.PodScheduled,
			Status:  corev1.ConditionFalse,
			Reason:  corev1.PodReasonUnschedulable,
			Message: "no nodes match",
		}}
		return false, nil, nil
	})

	spec := spawnPodSpec(t, "ns1")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
	}

	err := runOneNode(context.Background(), opts, spec, false, &wmu, "")
	if err == nil || !strings.Contains(err.Error(), "cannot be scheduled") {
		t.Fatalf("expected unschedulable wait error, got %v", err)
	}

	if _, gerr := cs.CoreV1().Pods("ns1").Get(context.Background(), spec.Name, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Errorf("spawn pod should be cleaned up after wait failure, err=%v", gerr)
	}
}

func TestRun_SingleNode_OrchestratesAndPropagatesError(t *testing.T) {
	useClassicListWatch(t)
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "cart", Labels: map[string]string{"app": "cart"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://abcdef",
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	cs := fake.NewClientset(target)
	runningOnCreate(cs)

	sentinel := errors.New("stop before attach")
	var builtFor []string
	_, _, out, errOut := genericiooptions.NewTestIOStreams()

	err := Run(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Image:      "ghcr.io/gma1k/podtrace:test",
		Selection:  pkgkube.TargetSelection{DefaultNamespace: "ns1", AllInNamespace: true},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		BuildChildArgs: func(node string, refs []PodRef) []string {
			builtFor = append(builtFor, node)
			return []string{"--preresolved-pod", refs[0].PreResolved()[0]}
		},
		OnPodRunning: func(context.Context, *corev1.Pod) error { return sentinel },

		DynamicReSpawn: true,
		PollInterval:   30 * time.Second,
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("Run should surface the runOneNode error, got %v", err)
	}
	if len(builtFor) != 1 || builtFor[0] != "node-1" {
		t.Errorf("BuildChildArgs should be invoked once for node-1, got %v", builtFor)
	}
}

func TestRun_DynamicPollSkipsCoveredNode(t *testing.T) {
	useClassicListWatch(t)
	target := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "cart", Labels: map[string]string{"app": "cart"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://abcdef",
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	cs := fake.NewClientset(target)
	runningOnCreate(cs)

	sentinel := errors.New("stop after poll")
	var buildCalls int32
	_, _, out, errOut := genericiooptions.NewTestIOStreams()

	err := Run(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Image:      "ghcr.io/gma1k/podtrace:test",
		Selection:  pkgkube.TargetSelection{DefaultNamespace: "ns1", AllInNamespace: true},
		Streams:    genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		BuildChildArgs: func(string, []PodRef) []string {
			atomic.AddInt32(&buildCalls, 1)
			return []string{"--noop"}
		},
		OnPodRunning: func(context.Context, *corev1.Pod) error {

			time.Sleep(150 * time.Millisecond)
			return sentinel
		},
		DynamicReSpawn: true,
		PollInterval:   25 * time.Millisecond,
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}

	if got := atomic.LoadInt32(&buildCalls); got != 1 {
		t.Errorf("BuildChildArgs calls = %d, want 1 (covered node must not re-spawn)", got)
	}
}

func TestRunOneNode_OwnSecretFailureIsNonFatal(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("owner-reference update rejected")
	})

	spec := spawnPodSpec(t, "ns1")
	sentinel := errors.New("stop after ownSecret attempt")
	var wmu sync.Mutex
	_, _, out, errOut := genericiooptions.NewTestIOStreams()
	opts := RunOptions{
		Clientset:    cs,
		RestConfig:   &rest.Config{},
		Streams:      genericiooptions.IOStreams{Out: out, ErrOut: errOut},
		SplunkToken:  "hec-token",
		OnPodRunning: func(context.Context, *corev1.Pod) error { return sentinel },
	}

	if err := runOneNode(context.Background(), opts, spec, false, &wmu, ""); !errors.Is(err, sentinel) {
		t.Fatalf("ownSecret failure must be non-fatal; expected sentinel, got %v", err)
	}
}

func TestNodePodLabel_TruncatesLongJoin(t *testing.T) {
	refs := []PodRef{
		{Name: strings.Repeat("a", 40)},
		{Name: strings.Repeat("b", 40)},
	}
	got := nodePodLabel(refs)
	if len([]rune(got)) > 60 {
		t.Errorf("label rune length = %d, want <= 60", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated label should end with an ellipsis, got %q", got)
	}
}

func TestNodePodLabel_SkipsEmptyNames(t *testing.T) {
	if got := nodePodLabel([]PodRef{{Name: ""}, {Name: "cart"}, {Name: ""}}); got != "cart" {
		t.Errorf("nodePodLabel = %q, want %q", got, "cart")
	}
}

type failOnNthWriter struct {
	calls int
	failN int
}

func (w *failOnNthWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls >= w.failN {
		return 0, errors.New("downstream broke")
	}
	return len(p), nil
}

func TestPrefixedWriter_PropagatesLineWriteError(t *testing.T) {
	var mu sync.Mutex

	w := newPrefixedWriter(&failOnNthWriter{failN: 2}, "[n1] ", &mu)
	if _, err := w.Write([]byte("hello\n")); err == nil {
		t.Fatalf("expected the line-write error to propagate")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestPrefixedWriter_PropagatesUnderlyingWriteError(t *testing.T) {
	var mu sync.Mutex
	w := newPrefixedWriter(failingWriter{}, "[n1] ", &mu)
	n, err := w.Write([]byte("hello\n"))
	if err == nil {
		t.Fatalf("expected the underlying write error to propagate")
	}

	if n != len("hello\n") {
		t.Errorf("Write returned n=%d, want %d", n, len("hello\n"))
	}
}
