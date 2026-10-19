package objectstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func redirectingEndpoint(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/redirected", http.StatusFound)
	}))
	t.Cleanup(front.Close)
	return front, hits
}

func uploadThroughRedirect(t *testing.T, cfg Config) {
	t.Helper()
	sink, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := sink.Upload(ctx, "sess-1.txt", "text/plain", strings.NewReader("report")); err == nil {
		t.Fatal("expected Upload to fail when the endpoint redirects")
	}
}

func TestS3Sink_RefusesEndpointRedirect(t *testing.T) {
	front, hits := redirectingEndpoint(t)
	uploadThroughRedirect(t, Config{
		URI: "s3://bucket/reports/",
		Credentials: map[string][]byte{
			s3SecretKeyAccessKeyID:     []byte("AKIATEST"),
			s3SecretKeySecretAccessKey: []byte("secret"),
			s3SecretKeyEndpoint:        []byte(front.URL),
			s3SecretKeyForcePath:       []byte("true"),
		},
	})
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d signed requests", hits.Load())
	}
}

func TestAzureSink_RefusesEndpointRedirect(t *testing.T) {
	front, hits := redirectingEndpoint(t)
	uploadThroughRedirect(t, Config{
		URI: "azblob://devstoreaccount1/reports/",
		Credentials: map[string][]byte{
			azureSecretKeyAccountKey: []byte(fakeAccountKey),
			azureSecretKeyEndpoint:   []byte(front.URL + "/devstoreaccount1"),
		},
	})
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d signed requests", hits.Load())
	}
}

func TestGCSSink_RefusesEndpointRedirect(t *testing.T) {
	front, hits := redirectingEndpoint(t)
	uploadThroughRedirect(t, Config{
		URI:         "gs://bucket/reports/",
		Credentials: map[string][]byte{gcsSecretKeyEndpoint: []byte(front.URL)},
		Policy:      CredentialPolicy{EndpointAllowlist: []string{"127.0.0.1"}},
	})
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", hits.Load())
	}
}
