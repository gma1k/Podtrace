package objectstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewGCSSink_AmbientCredentialsUnavailable(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))

	_, err := New(context.Background(), Config{
		URI:    "gs://bucket/reports/",
		Policy: CredentialPolicy{AllowAmbientCredentials: true},
	})
	if err == nil || !strings.Contains(err.Error(), "gcs: build transport") {
		t.Fatalf("New err = %v, want the transport build failure", err)
	}
}
