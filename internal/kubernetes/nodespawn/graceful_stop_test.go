package nodespawn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func stubAttach(t *testing.T, fn func(ctx context.Context, out io.Writer) error) {
	t.Helper()
	orig := attachToPod
	attachToPod = func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _ *corev1.Pod, streams genericiooptions.IOStreams) (bool, error) {
		return false, fn(ctx, streams.Out)
	}
	t.Cleanup(func() { attachToPod = orig })
}

func recordDeleteGrace(cs *fake.Clientset) <-chan int64 {
	graces := make(chan int64, 4)
	cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if da, ok := a.(k8stesting.DeleteActionImpl); ok && da.DeleteOptions.GracePeriodSeconds != nil {
			graces <- *da.DeleteOptions.GracePeriodSeconds
		}
		return false, nil, nil
	})
	return graces
}

func TestAStopWhileStreamingLetsTheSpawnPodPrintItsFinalReport(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	graces := recordDeleteGrace(cs)

	stop := make(chan struct{})
	streaming := make(chan struct{})
	stubAttach(t, func(ctx context.Context, out io.Writer) error {
		_, _ = io.WriteString(out, "live event\n")
		close(streaming)
		select {
		case grace := <-graces:
			if grace != int64(StopGracePeriod/time.Second) {
				t.Errorf("spawn pod deleted with grace %ds, want %s", grace, StopGracePeriod)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		_, _ = io.WriteString(out, "=== final report ===\n")
		return nil
	})
	go func() {
		<-streaming
		close(stop)
	}()

	var out bytes.Buffer
	var wmu sync.Mutex
	err := runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: &out, ErrOut: io.Discard},
		Stop:       stop,
	}, spawnPodSpec(t, "ns1"), false, &wmu, "")
	if err != nil {
		t.Fatalf("a stopped trace must end cleanly, got %v", err)
	}
	if !strings.Contains(out.String(), "=== final report ===") {
		t.Fatalf("final report was not streamed: %q", out.String())
	}
}

func TestAStopBeforeStreamingIsAnInterruption(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	stubAttach(t, func(context.Context, io.Writer) error {
		t.Error("a trace stopped before it streamed must not attach")
		return nil
	})
	stop := make(chan struct{})
	close(stop)

	var wmu sync.Mutex
	err := runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: io.Discard, ErrOut: io.Discard},
		Stop:       stop,
	}, spawnPodSpec(t, "ns1"), false, &wmu, "")
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("want ErrInterrupted, got %v", err)
	}
}

func TestAStoppedTraceThatOutlivesTheGracePeriodIsCutOff(t *testing.T) {
	useClassicListWatch(t)
	origGrace, origMargin := StopGracePeriod, stopStreamMargin
	StopGracePeriod, stopStreamMargin = time.Second, 50*time.Millisecond
	t.Cleanup(func() { StopGracePeriod, stopStreamMargin = origGrace, origMargin })

	cs := fake.NewClientset()
	runningOnCreate(cs)
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
			t.Fatalf("want ErrInterrupted once the grace period ran out, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stopped trace that never exits was not cut off")
	}
}

func TestAnUnterminatedLastLineIsFlushedWithItsPrefix(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	w := newPrefixedWriter(&out, "[node-1] ", &mu)
	_, _ = w.Write([]byte("first\npanic: boom"))
	flushPrefixed(genericiooptions.IOStreams{Out: w})
	if got, want := out.String(), "[node-1] first\n[node-1] panic: boom\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if err := w.Flush(); err != nil || out.Len() != len("[node-1] first\n[node-1] panic: boom\n") {
		t.Fatalf("a second flush must write nothing, got %q (err %v)", out.String(), err)
	}
}
