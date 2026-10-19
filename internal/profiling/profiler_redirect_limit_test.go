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

func TestFetchStopsFollowingSameOriginRedirectLoop(t *testing.T) {
	var hits atomic.Int64
	pod := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		http.Redirect(w, r, "/loop/"+strconv.FormatInt(n, 10), http.StatusFound)
	}))
	t.Cleanup(pod.Close)

	host, port := mustParseAddr(t, pod.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	_, _, err := p.fetchText(context.Background(), pod.URL+"/debug/pprof/heap")
	if err == nil || !strings.Contains(err.Error(), "more than "+strconv.Itoa(maxPprofRedirects)+" redirects") {
		t.Fatalf("expected the redirect limit to stop the fetch, got %v", err)
	}
	if got := hits.Load(); got != maxPprofRedirects+1 {
		t.Errorf("pod served %d requests, want %d", got, maxPprofRedirects+1)
	}
}

func TestPodPinnedTransportRejectsAddressWithoutPort(t *testing.T) {
	transport := podPinnedTransport("10.0.0.1")
	conn, err := transport.DialContext(context.Background(), "tcp", "10.0.0.1")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected a dial without a port to fail")
	}
	if errors.Is(err, errNotPodAddress) {
		t.Errorf("expected an address parse error, got the pod-address refusal %v", err)
	}
}
