package objectstore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestGCSSink_UploadRoundTrip(t *testing.T) {
	var (
		mu      sync.Mutex
		gotName string
		gotCT   string
		gotBody string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ct := r.Header.Get("Content-Type")
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		nameStart := strings.Index(body, `"name":"`)
		if nameStart >= 0 {
			rest := body[nameStart+len(`"name":"`):]
			if end := strings.Index(rest, `"`); end >= 0 {
				gotName = rest[:end]
			}
		}
		ctStart := strings.Index(body, `"contentType":"`)
		if ctStart >= 0 {
			rest := body[ctStart+len(`"contentType":"`):]
			if end := strings.Index(rest, `"`); end >= 0 {
				gotCT = rest[:end]
			}
		}
		if idx := strings.Index(body, "hello report"); idx >= 0 {
			gotBody = "hello report"
		}

		_ = ct
		resp := map[string]any{
			"bucket": "bucket",
			"name":   gotName,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	sink, err := New(context.Background(), Config{
		URI: "gs://bucket/diagnose/",
		Credentials: map[string][]byte{
			gcsSecretKeyEndpoint: []byte(srv.URL),
		},
		Policy: CredentialPolicy{EndpointAllowlist: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	resolved, err := sink.Upload(context.Background(), "sess-1.txt", "text/plain", strings.NewReader("hello report"))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if want := "gs://bucket/diagnose/sess-1.txt"; resolved != want {
		t.Errorf("resolvedURI = %q, want %q", resolved, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotName != "diagnose/sess-1.txt" {
		t.Errorf("object name = %q, want diagnose/sess-1.txt", gotName)
	}
	if gotCT != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", gotCT)
	}
	if gotBody != "hello report" {
		t.Errorf("body = %q, want %q", gotBody, "hello report")
	}
}

func TestGCSSink_EmptyKeyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := New(context.Background(), Config{
		URI: "gs://bucket/",
		Credentials: map[string][]byte{
			gcsSecretKeyEndpoint: []byte(srv.URL),
		},
		Policy: CredentialPolicy{EndpointAllowlist: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if _, err := sink.Upload(context.Background(), "", "text/plain", strings.NewReader("x")); err == nil {
		t.Fatal("expected empty-key rejection, got nil")
	}
}
