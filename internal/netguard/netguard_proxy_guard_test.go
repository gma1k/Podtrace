package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withProxy(t *testing.T, proxyURL string, resolve map[string]string) *atomic.Int32 {
	t.Helper()
	lookups := new(atomic.Int32)
	origProxy, origLookup := proxyFromEnvironment, lookupIPAddr
	t.Cleanup(func() { proxyFromEnvironment, lookupIPAddr = origProxy, origLookup })
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) {
		if proxyURL == "" {
			return nil, nil
		}
		return url.Parse(proxyURL)
	}
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups.Add(1)
		ip, ok := resolve[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return lookups
}

func newRecordingProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func TestHardenedClient_ProxyDoesNotBypassGuardForLiteralIP(t *testing.T) {
	proxy, hits := newRecordingProxy(t)
	withProxy(t, proxy.URL, nil)

	_, err := HardenedClient(5 * time.Second).Get("http://169.254.169.254/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected blocked-address error through proxy, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy received %d requests for a blocked target", hits.Load())
	}
}

func TestHardenedClient_ProxyDoesNotBypassGuardForResolvedName(t *testing.T) {
	proxy, hits := newRecordingProxy(t)
	withProxy(t, proxy.URL, map[string]string{"metadata.attacker.test": "169.254.169.254"})

	_, err := HardenedClient(5 * time.Second).Get("http://metadata.attacker.test/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "blocked address") {
		t.Fatalf("expected blocked-address error through proxy, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy received %d requests for a blocked target", hits.Load())
	}
}

func TestHardenedClient_ProxyStillUsedForAllowedTargets(t *testing.T) {
	proxy, hits := newRecordingProxy(t)
	withProxy(t, proxy.URL, map[string]string{"collector.example.test": "10.0.0.5"})

	for _, target := range []string{"http://collector.example.test/v1/traces", "http://unresolvable.example.test/v1/traces", "http://203.0.113.10/v1/traces"} {
		resp, err := HardenedClient(5 * time.Second).Get(target)
		if err != nil {
			t.Fatalf("GET %s through proxy: %v", target, err)
		}
		_ = resp.Body.Close()
	}
	if hits.Load() != 3 {
		t.Fatalf("proxy hits = %d, want 3", hits.Load())
	}
}

func TestHardenedClient_DirectRequestsSkipResolverCheck(t *testing.T) {
	lookups := withProxy(t, "", nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := HardenedClient(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("direct GET: %v", err)
	}
	_ = resp.Body.Close()
	if lookups.Load() != 0 {
		t.Fatalf("resolver consulted %d times for a direct request", lookups.Load())
	}
}

func TestHardenedTransport_UsesGuardedProxy(t *testing.T) {
	proxy, hits := newRecordingProxy(t)
	withProxy(t, proxy.URL, nil)

	req, _ := http.NewRequest(http.MethodGet, "http://[fd00:ec2::254]/latest/meta-data/", nil)
	if _, err := HardenedTransport().RoundTrip(req); err == nil {
		t.Fatal("expected HardenedTransport to refuse a proxied request to AWS IPv6 IMDS")
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy received %d requests for a blocked target", hits.Load())
	}
}
