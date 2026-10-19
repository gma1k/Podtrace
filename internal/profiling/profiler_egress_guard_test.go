package profiling

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchRefusesRedirectToAnotherOrigin(t *testing.T) {
	var reached atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = w.Write([]byte("metadata"))
	}))
	t.Cleanup(elsewhere.Close)

	pod := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/computeMetadata/v1/", http.StatusFound)
	}))
	t.Cleanup(pod.Close)

	host, port := mustParseAddr(t, pod.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))

	r := p.FetchHeap(context.Background())
	if r.Available {
		t.Fatal("expected a cross-origin redirect to fail the fetch")
	}
	if !strings.Contains(r.Error, "redirect") {
		t.Errorf("expected a redirect refusal, got %q", r.Error)
	}
	if reached.Load() {
		t.Error("the redirect target must never be contacted")
	}
}

func TestCPUFetchRefusesRedirectToAnotherOrigin(t *testing.T) {
	var reached atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	t.Cleanup(elsewhere.Close)

	pod := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	t.Cleanup(pod.Close)

	host, port := mustParseAddr(t, pod.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))

	if r := p.FetchCPUProfile(context.Background(), 0); r.Available {
		t.Fatal("expected a cross-origin redirect to fail the CPU fetch")
	}
	if reached.Load() {
		t.Error("the redirect target must never be contacted")
	}
}

func TestDiscoverFollowsSameOriginRedirect(t *testing.T) {
	pod := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			http.Redirect(w, r, "/debug/pprof/index", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(pod.Close)

	host, port := mustParseAddr(t, pod.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	if !p.Discover(context.Background()) {
		t.Fatal("expected a same-origin redirect to be followed during discovery")
	}
}

func TestFetchRefusesHostOtherThanPodIP(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	t.Cleanup(srv.Close)

	_, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler("10.255.255.1", []int{port})
	_, _, err := p.fetchText(context.Background(), "http://127.0.0.1:"+strconv.Itoa(port)+"/debug/pprof/")
	if !errors.Is(err, errNotPodAddress) {
		t.Fatalf("expected errNotPodAddress, got %v", err)
	}
	if reached.Load() {
		t.Error("a host other than the pod IP must never be dialed")
	}
}

func TestFetchRefusesHostnameEvenIfItResolvesToPod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	_, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler("127.0.0.1", []int{port})
	_, _, err := p.fetchText(context.Background(), "http://localhost:"+strconv.Itoa(port)+"/")
	if !errors.Is(err, errNotPodAddress) {
		t.Fatalf("expected errNotPodAddress, got %v", err)
	}
}

func TestEndpointBracketsIPv6PodIP(t *testing.T) {
	p := NewPodProfiler("fd00::1", []int{6060})
	if got, want := p.endpoint(6060, "/debug/pprof/"), "http://[fd00::1]:6060/debug/pprof/"; got != want {
		t.Errorf("endpoint=%q want %q", got, want)
	}
}
