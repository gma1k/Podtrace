package status

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

type wedgedCluster struct {
	*fakeCluster
	issueReads atomic.Int32
	inFlight   atomic.Int32
	maxFlight  atomic.Int32
}

func (w *wedgedCluster) ActiveIssues(ctx context.Context, _ Agent) ([]LiveIssue, error) {
	w.issueReads.Add(1)
	n := w.inFlight.Add(1)
	defer w.inFlight.Add(-1)
	for {
		m := w.maxFlight.Load()
		if n <= m || w.maxFlight.CompareAndSwap(m, n) {
			break
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (w *wedgedCluster) IssueEvents(ctx context.Context, _ string) ([]corev1.Event, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (w *wedgedCluster) Correlations(ctx context.Context) (Correlation, error) {
	<-ctx.Done()
	return Correlation{}, ctx.Err()
}

func (w *wedgedCluster) Components(ctx context.Context) ([]Component, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWedgedAgentsAndAPIReadsCannotHangACollection(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"), agent("b", "n2"), agent("c", "n3"))
	wc := &wedgedCluster{fakeCluster: fc}
	c := &Collector{Cluster: wc, Now: newVirtualTime().Now, Sleep: noSleep, ScrapeTimeout: 50 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		_, err := c.Collect(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a collection with wedged reads must still report, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a wedged read hung the collection")
	}
	if got := wc.maxFlight.Load(); got < 2 {
		t.Fatalf("issue reads ran %d at a time, want them read concurrently", got)
	}
}

func TestAWedgedComponentsReadCannotHangAHealthCheck(t *testing.T) {
	fc, _ := servingCluster(t, agent("a", "n1"))
	c := &Collector{Cluster: &wedgedCluster{fakeCluster: fc}, Now: newVirtualTime().Now, Sleep: noSleep, ScrapeTimeout: 50 * time.Millisecond}

	done := make(chan struct{})
	go func() {
		_, _ = c.Health(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a wedged components read hung the health check")
	}
}
