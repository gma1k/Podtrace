package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/gma1k/podtrace/internal/profiling"
)

func status(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	code, _ := get(t, h, path)
	return code
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

const unroutedBody = "404 page not found\n"

func TestTheMetricsPortServesOnlyMetrics(t *testing.T) {
	mux := metricsMux(NewMetrics())
	if code := status(t, mux, "/metrics"); code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200", code)
	}
	for _, path := range []string{"/issues", "/profile"} {
		if code, body := get(t, mux, path); code != http.StatusNotFound || body != unroutedBody {
			t.Errorf("%s on the metrics port = %d, want 404: scrapers in any namespace reach "+
				"this port, and %s names other tenants' workloads", path, code, path)
		}
	}
}

func TestTheInspectPortServesIssuesAndProfileButNotMetrics(t *testing.T) {
	mux := http.NewServeMux()
	registerInspectHandlers(mux, profiling.NewContinuousProfiler(nil, nil), nil)
	if code := status(t, mux, "/profile"); code != http.StatusOK {
		t.Errorf("/profile = %d, want 200", code)
	}
	if _, body := get(t, mux, "/issues"); body == unroutedBody {
		t.Error("/issues is not routed on the inspect port")
	}
	if code := status(t, mux, "/metrics"); code != http.StatusNotFound {
		t.Errorf("/metrics on the inspect port = %d, want 404", code)
	}
}

func TestOneAddressForBothServesEverything(t *testing.T) {
	mux := combinedMux(NewMetrics(), profiling.NewContinuousProfiler(nil, nil), nil)
	for _, path := range []string{"/metrics", "/profile"} {
		if code := status(t, mux, path); code != http.StatusOK {
			t.Errorf("%s = %d, want 200 when --inspect-addr equals --metrics-addr", path, code)
		}
	}
}

func TestInspectPortIsOnByDefault(t *testing.T) {
	o := DefaultOptions()
	if o.InspectAddr == "" || o.InspectAddr == o.MetricsAddr || o.InspectAddr == o.HealthAddr {
		t.Errorf("InspectAddr = %q (metrics %q, health %q); it needs a listener of its own",
			o.InspectAddr, o.MetricsAddr, o.HealthAddr)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func getWhenUp(t *testing.T, url string) (int, string) {
	t.Helper()
	var lastErr error
	for range 100 {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return resp.StatusCode, string(body)
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s: %v", url, lastErr)
	return 0, ""
}

func runServers(t *testing.T, opts Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	servers := httpServers(opts, NewMetrics(), profiling.NewContinuousProfiler(nil, nil), nil, logr.Discard())
	done := make(chan error, len(servers))
	for _, serve := range servers {
		go func() { done <- serve(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		for range servers {
			if err := <-done; err != nil {
				t.Errorf("server returned %v on shutdown", err)
			}
		}
	})
}

func TestTheAgentRunsSeparateMetricsAndInspectListeners(t *testing.T) {
	opts := Options{MetricsAddr: freeAddr(t), InspectAddr: freeAddr(t)}
	if n := len(httpServers(opts, NewMetrics(), nil, nil, logr.Discard())); n != 2 {
		t.Fatalf("%d listeners, want 2", n)
	}
	runServers(t, opts)

	if code, _ := getWhenUp(t, "http://"+opts.MetricsAddr+"/metrics"); code != http.StatusOK {
		t.Errorf("/metrics on the metrics port = %d", code)
	}
	if code, body := getWhenUp(t, "http://"+opts.MetricsAddr+"/profile"); code != http.StatusNotFound || body != unroutedBody {
		t.Errorf("/profile on the metrics port = %d %q, want unrouted", code, body)
	}
	if code, _ := getWhenUp(t, "http://"+opts.InspectAddr+"/profile"); code != http.StatusOK {
		t.Errorf("/profile on the inspect port = %d", code)
	}
}

func TestTheAgentSharesOneListenerWhenBothAddressesMatch(t *testing.T) {
	addr := freeAddr(t)
	opts := Options{MetricsAddr: addr, InspectAddr: addr}
	if n := len(httpServers(opts, NewMetrics(), nil, nil, logr.Discard())); n != 1 {
		t.Fatalf("%d listeners for one address, want 1", n)
	}
	runServers(t, opts)

	for _, path := range []string{"/metrics", "/profile"} {
		if code, _ := getWhenUp(t, "http://"+addr+path); code != http.StatusOK {
			t.Errorf("%s = %d, want 200 on the shared listener", path, code)
		}
	}
}
