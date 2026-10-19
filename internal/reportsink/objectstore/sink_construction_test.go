package objectstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewS3Sink_RegionFromEnv(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-west-1")
	sink, err := New(context.Background(), Config{
		URI: "s3://bucket/reports/",
		Credentials: map[string][]byte{
			s3SecretKeyAccessKeyID:     []byte("k"),
			s3SecretKeySecretAccessKey: []byte("s"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

func TestNewS3Sink_DefaultRegionWhenUnset(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	sink, err := New(context.Background(), Config{
		URI: "s3://bucket/reports/",
		Credentials: map[string][]byte{
			s3SecretKeyAccessKeyID:     []byte("k"),
			s3SecretKeySecretAccessKey: []byte("s"),
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed mid-stream") }

func TestGCSSink_UploadAbortsOnCopyFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
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

	_, err = sink.Upload(context.Background(), "sess-1.txt", "text/plain", failingReader{})
	if err == nil {
		t.Fatal("expected Upload to fail when the body reader errors mid-stream")
		return
	}
	if !strings.Contains(err.Error(), "stream to") {
		t.Errorf("error = %v, want a 'stream to' wrap", err)
	}
}
