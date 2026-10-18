package nodespawn

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func TestAStopBetweenRunningAndStreamingIsAnInterruption(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	stubAttach(t, func(context.Context, io.Writer) error {
		t.Error("a trace stopped before it streamed must not attach")
		return nil
	})
	stop := make(chan struct{})
	var wmu sync.Mutex
	err := runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
		Stop:       stop,
		OnPodRunning: func(context.Context, *corev1.Pod) error {
			close(stop)
			return nil
		},
	}, spawnPodSpec(t, "ns1"), false, &wmu, "")
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("want ErrInterrupted, got %v", err)
	}
}

func TestAFailedGracefulDeleteAbortsTheStream(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if da, ok := a.(k8stesting.DeleteActionImpl); ok && da.DeleteOptions.GracePeriodSeconds != nil && *da.DeleteOptions.GracePeriodSeconds > 0 {
			return true, nil, errors.New("forbidden")
		}
		return false, nil, nil
	})
	stop := make(chan struct{})
	stubAttach(t, func(ctx context.Context, _ io.Writer) error {
		close(stop)
		<-ctx.Done()
		return ctx.Err()
	})
	var wmu sync.Mutex
	done := make(chan error, 1)
	go func() {
		done <- runOneNode(context.Background(), RunOptions{
			Clientset:  cs,
			RestConfig: &rest.Config{},
			Streams:    genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
			Stop:       stop,
		}, spawnPodSpec(t, "ns1"), false, &wmu, "")
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInterrupted) {
			t.Fatalf("want ErrInterrupted, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a failed graceful delete left the stream hanging")
	}
}

func TestDeletePodGracefullyReportsAPIErrors(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	if err := DeletePodGracefully(context.Background(), cs, "ns", "p", time.Second); err == nil {
		t.Fatal("expected the API error")
	}
	if err := DeletePodGracefully(context.Background(), fake.NewClientset(), "ns", "gone", time.Second); err != nil {
		t.Fatalf("a pod that is already gone is not an error: %v", err)
	}
}

func TestAnUnreadablePIDNamespaceIsUnknown(t *testing.T) {
	orig := readPIDNamespaceLink
	t.Cleanup(func() { readPIDNamespaceLink = orig })
	for name, read := range map[string]func() (string, error){
		"readlink fails":  func() (string, error) { return "", errors.New("no /proc") },
		"unexpected form": func() (string, error) { return "net:[4026531840]", nil },
	} {
		readPIDNamespaceLink = read
		if got := MachinePIDNamespace(); got != "" {
			t.Errorf("%s: MachinePIDNamespace = %q, want unknown", name, got)
		}
	}
	readPIDNamespaceLink = func() (string, error) { return "pid:[4026531836]", nil }
	if got := MachinePIDNamespace(); got != "4026531836" {
		t.Errorf("MachinePIDNamespace = %q", got)
	}
}

func TestPollingForNewNodesEndsOnStop(t *testing.T) {
	stop := make(chan struct{})
	polls := 0
	err := pollNewNodes(context.Background(), stop, time.Millisecond, func() error {
		polls++
		if polls == 2 {
			close(stop)
		}
		return nil
	})
	if err != nil || polls < 2 {
		t.Fatalf("polls=%d err=%v", polls, err)
	}
}

func TestPollingForNewNodesEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pollNewNodes(ctx, nil, time.Hour, func() error { return errors.New("unexpected poll") }); err != nil {
		t.Fatal(err)
	}
}

func TestAFailedPollEndsPolling(t *testing.T) {
	want := errors.New("spawn failed")
	if err := pollNewNodes(context.Background(), nil, time.Millisecond, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestAnInvalidSelectorIsRejectedBeforeAnyListing(t *testing.T) {
	_, err := ResolveTargetNodes(context.Background(), fake.NewClientset(), pkgkube.TargetSelection{PodSelector: "app in (("})
	if err == nil {
		t.Fatal("expected an invalid-selector error")
	}
}

func TestADynamicTraceSurvivesAFailedPollAndStopsCleanly(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset(withRunningContainer(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "api", Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
	}))
	runningOnCreate(cs)
	var lists atomic.Int32
	pollFailed := make(chan struct{})
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.ListActionImpl).ListOptions.LabelSelector != "app=api" {
			return false, nil, nil
		}
		if lists.Add(1) == 1 {
			return false, nil, nil
		}
		select {
		case <-pollFailed:
		default:
			close(pollFailed)
		}
		return true, nil, errors.New("apiserver unavailable")
	})
	stop := make(chan struct{})
	stubAttach(t, func(ctx context.Context, _ io.Writer) error {
		<-pollFailed
		close(stop)
		return nil
	})

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), RunOptions{
			Clientset:      cs,
			RestConfig:     &rest.Config{},
			Image:          "img",
			BuildChildArgs: func(string, []PodRef) []string { return nil },
			Selection:      pkgkube.TargetSelection{DefaultNamespace: "ns1", PodSelector: "app=api"},
			Streams:        genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
			DynamicReSpawn: true,
			PollInterval:   5 * time.Millisecond,
			Stop:           stop,
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a failed poll must not end the trace, got %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the dynamic trace did not stop")
	}
}
