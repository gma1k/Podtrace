package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// startProbes boots a ProbeServer on 127.0.0.1:0 and returns its URL
// plus a cleanup function. Zero port means the OS picks one — avoids
// collisions when tests run in parallel.
func startProbes(t *testing.T, stall time.Duration) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	s := NewProbeServer(addr, stall)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	// Wait for the server to start accepting.
	waitForHTTP(t, "http://"+addr+"/healthz", 2*time.Second)

	return "http://" + addr, func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("probe server Run returned %v on shutdown", err)
			}
		case <-time.After(3 * time.Second):
			t.Log("probe server did not shut down cleanly")
		}
	}
}

func waitForHTTP(t *testing.T, url string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		resp, err := http.Get(url) //nolint:noctx // test-only
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe server did not start within %s", d)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProbes_HealthzAndReadyzFlipsOnMarkReady(t *testing.T) {
	base, stop := startProbes(t, 10*time.Second)
	defer stop()

	// /healthz should be 200 immediately (Heartbeat was called in constructor).
	if code := httpGet(t, base+"/healthz"); code != 200 {
		t.Errorf("/healthz=%d want 200", code)
	}

	// /readyz should start 503 (not marked ready yet).
	if code := httpGet(t, base+"/readyz"); code != 503 {
		t.Errorf("/readyz pre-ready=%d want 503", code)
	}
}

func TestProbes_ReadyzFlipsWithMark(t *testing.T) {
	base, stop := startProbes(t, 10*time.Second)
	defer stop()

	// Access the same ProbeServer instance via reflection? Simpler:
	// call MarkReady via a parallel instance is not possible. We
	// re-test the transition via the public Run loop by spinning up a
	// ProbeServer we retain a ref to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	s := NewProbeServer(addr, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	waitForHTTP(t, "http://"+addr+"/healthz", 2*time.Second)

	if code := httpGet(t, "http://"+addr+"/readyz"); code != 503 {
		t.Errorf("pre-MarkReady /readyz=%d want 503", code)
	}
	s.MarkReady()
	if code := httpGet(t, "http://"+addr+"/readyz"); code != 200 {
		t.Errorf("post-MarkReady /readyz=%d want 200", code)
	}
	s.MarkUnready()
	if code := httpGet(t, "http://"+addr+"/readyz"); code != 503 {
		t.Errorf("post-MarkUnready /readyz=%d want 503", code)
	}
	_ = base // keep the initial fixture alive for parallel safety
}

// TestProbes_HealthzFlipsOnStall: when Heartbeat stops being called
// for longer than the stall window, /healthz returns 503 so the
// kubelet restarts a hung agent.
func TestProbes_HealthzFlipsOnStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	// Use a tiny stall window so the test finishes quickly. Constructor
	// calls Heartbeat once, so we have that as a "T0".
	s := NewProbeServer(addr, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	waitForHTTP(t, "http://"+addr+"/healthz", 2*time.Second)

	// Fresh Heartbeat → 200.
	s.Heartbeat()
	if code := httpGet(t, "http://"+addr+"/healthz"); code != 200 {
		t.Fatalf("fresh /healthz=%d want 200", code)
	}

	// Stall past the window.
	time.Sleep(150 * time.Millisecond)
	if code := httpGet(t, "http://"+addr+"/healthz"); code != 503 {
		t.Fatalf("stale /healthz=%d want 503", code)
	}

	// A new heartbeat recovers readiness.
	s.Heartbeat()
	if code := httpGet(t, "http://"+addr+"/healthz"); code != 200 {
		t.Fatalf("recovered /healthz=%d want 200", code)
	}
}

func TestProbes_IsReadyMirrorsMark(t *testing.T) {
	s := NewProbeServer("127.0.0.1:0", 10*time.Second)
	if s.IsReady() {
		t.Error("pristine ProbeServer should not be ready")
	}
	s.MarkReady()
	if !s.IsReady() {
		t.Error("MarkReady did not flip IsReady")
	}
	s.MarkUnready()
	if s.IsReady() {
		t.Error("MarkUnready did not flip IsReady")
	}
}

func httpGet(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test-only
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
