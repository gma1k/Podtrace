package objectstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── defaultRetryLogger.OnAttempt ─────────────────────────────────────────────

func TestDefaultRetryLogger_OnAttempt_WithError(t *testing.T) {
	var l defaultRetryLogger
	l.OnAttempt("s3", "PUT", "https://example/obj", 503, 2, 10*time.Millisecond, errors.New("boom"))
}

func TestDefaultRetryLogger_OnAttempt_NoError(t *testing.T) {
	var l defaultRetryLogger
	l.OnAttempt("gs", "PUT", "https://example/obj", 200, 1, time.Millisecond, nil)
}

// ─── New / parseURI error branches ────────────────────────────────────────────

func TestNew_UnsupportedScheme(t *testing.T) {
	_, err := New(context.Background(), Config{URI: "ftp://host/key"})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
		return
	}
	if !strings.Contains(err.Error(), "unsupported URI scheme") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_EmptyURI(t *testing.T) {
	_, err := New(context.Background(), Config{URI: ""})
	if err == nil {
		t.Fatal("expected error for empty URI")
		return
	}
	if !strings.Contains(err.Error(), "empty URI") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_MalformedURI(t *testing.T) {
	// Control character makes url.Parse fail inside parseURI.
	_, err := New(context.Background(), Config{URI: "s3://bucket/\x7f"})
	if err == nil {
		t.Fatal("expected parse error for malformed URI")
		return
	}
	if !strings.Contains(err.Error(), "parse URI") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseURI_MalformedURL(t *testing.T) {
	_, err := parseURI("s3://bucket/\x7f")
	if err == nil {
		t.Fatal("expected parse error for control character in URI")
	}
}

func TestValidateURI_Malformed(t *testing.T) {
	if err := ValidateURI("s3://bucket/\x7f"); err == nil {
		t.Fatal("expected ValidateURI to reject malformed URI")
	}
}

// ─── newAzureSink credential branches ─────────────────────────────────────────

// fakeAccountKey is a valid base64 string accepted by NewSharedKeyCredential.
const fakeAccountKey = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

func TestNewAzureSink_DefaultEndpoint(t *testing.T) {
	// No endpoint cred → endpoint is derived from the account host. Uses a
	// shared-key credential so no network/default-credential chain is touched.
	sink, err := New(context.Background(), Config{
		URI: "azblob://devstoreaccount1/reports/",
		Credentials: map[string][]byte{
			azureSecretKeyAccountKey: []byte(fakeAccountKey),
		},
	})
	if err != nil {
		t.Fatalf("New (default endpoint): %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

func TestNewAzureSink_BadAccountKey(t *testing.T) {
	// Non-base64 account key fails NewSharedKeyCredential synchronously.
	_, err := New(context.Background(), Config{
		URI: "azblob://devstoreaccount1/reports/",
		Credentials: map[string][]byte{
			azureSecretKeyAccountKey: []byte("not-valid-base64!!!"),
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid shared-key credential")
		return
	}
	if !strings.Contains(err.Error(), "shared key credential") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewAzureSink_SPNCredential(t *testing.T) {
	// Service-principal branch: NewClientSecretCredential validates input
	// format synchronously without contacting Azure AD.
	sink, err := New(context.Background(), Config{
		URI: "azblob://devstoreaccount1/reports/",
		Credentials: map[string][]byte{
			azureSecretKeyTenantID:     []byte("11111111-1111-1111-1111-111111111111"),
			azureSecretKeyClientID:     []byte("22222222-2222-2222-2222-222222222222"),
			azureSecretKeyClientSecret: []byte("super-secret"),
			azureSecretKeyEndpoint:     []byte("https://devstoreaccount1.blob.core.windows.net"),
		},
	})
	if err != nil {
		t.Fatalf("New (SPN): %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

func TestNewAzureSink_DefaultCredential(t *testing.T) {
	// No credentials → falls through to NewDefaultAzureCredential, which
	// builds a lazy credential chain without making network calls.
	sink, err := New(context.Background(), Config{
		URI:    "azblob://devstoreaccount1/reports/",
		Policy: CredentialPolicy{AllowAmbientCredentials: true},
	})
	if err != nil {
		t.Fatalf("New (default credential): %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

// ─── newGCSSink service-account JSON branch ───────────────────────────────────

func TestNewGCSSink_BadServiceAccountJSON(t *testing.T) {
	// Malformed service-account JSON fails credentials.DetectDefault
	// synchronously, before any network access.
	_, err := New(context.Background(), Config{
		URI: "gs://bucket/reports/",
		Credentials: map[string][]byte{
			gcsSecretKeyServiceAccountJSON: []byte("{not valid json"),
		},
	})
	if err == nil {
		t.Fatal("expected error for malformed service account JSON")
		return
	}
	if !strings.Contains(err.Error(), "service account JSON") {
		t.Errorf("unexpected error: %v", err)
	}
}
