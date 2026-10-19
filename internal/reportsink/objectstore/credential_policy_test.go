package objectstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCredentialPolicy_EndpointRequiresStaticCredentialsOrAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		creds   map[string][]byte
		policy  CredentialPolicy
		wantErr string
	}{
		{
			name:    "azure endpoint with ambient fallback",
			uri:     "azblob://acct/c/",
			creds:   map[string][]byte{azureSecretKeyEndpoint: []byte("https://attacker.example")},
			policy:  CredentialPolicy{AllowAmbientCredentials: true},
			wantErr: "only honoured with static credentials",
		},
		{
			name:    "s3 endpoint with ambient fallback",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("https://attacker.example")},
			policy:  CredentialPolicy{AllowAmbientCredentials: true},
			wantErr: "only honoured with static credentials",
		},
		{
			name:    "s3 endpoint with half a static credential",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("https://attacker.example"), s3SecretKeyAccessKeyID: []byte("k")},
			policy:  CredentialPolicy{AllowAmbientCredentials: true},
			wantErr: "only honoured with static credentials",
		},
		{
			name:    "gcs unauthenticated endpoint",
			uri:     "gs://bucket/",
			creds:   map[string][]byte{gcsSecretKeyEndpoint: []byte("http://fake-gcs:4443")},
			wantErr: "only honoured with static credentials",
		},
		{
			name:  "s3 endpoint with static keys",
			uri:   "s3://bucket/",
			creds: map[string][]byte{s3SecretKeyEndpoint: []byte("http://minio.storage.svc:9000"), s3SecretKeyAccessKeyID: []byte("k"), s3SecretKeySecretAccessKey: []byte("s")},
		},
		{
			name:  "azure endpoint with shared key",
			uri:   "azblob://devstoreaccount1/c/",
			creds: map[string][]byte{azureSecretKeyEndpoint: []byte("http://azurite:10000/devstoreaccount1"), azureSecretKeyAccountKey: []byte("a2V5")},
		},
		{
			name:  "azure endpoint with service principal",
			uri:   "azblob://acct/c/",
			creds: map[string][]byte{azureSecretKeyEndpoint: []byte("https://acct.blob.core.chinacloudapi.cn"), azureSecretKeyTenantID: []byte("t"), azureSecretKeyClientID: []byte("c"), azureSecretKeyClientSecret: []byte("s")},
		},
		{
			name:  "gcs endpoint with service account",
			uri:   "gs://bucket/",
			creds: map[string][]byte{gcsSecretKeyEndpoint: []byte("https://storage.example"), gcsSecretKeyServiceAccountJSON: []byte("{}")},
		},
		{
			name:   "allowlisted endpoint with ambient credentials",
			uri:    "s3://bucket/",
			creds:  map[string][]byte{s3SecretKeyEndpoint: []byte("https://bucket.vpce-1.s3.eu-west-1.vpce.amazonaws.com")},
			policy: CredentialPolicy{AllowAmbientCredentials: true, EndpointAllowlist: []string{"*.vpce.amazonaws.com"}},
		},
		{
			name:   "allowlisted unauthenticated gcs endpoint",
			uri:    "gs://bucket/",
			creds:  map[string][]byte{gcsSecretKeyEndpoint: []byte("http://fake-gcs:4443")},
			policy: CredentialPolicy{EndpointAllowlist: []string{" FAKE-GCS "}},
		},
		{
			name:    "allowlisted endpoint still needs the ambient opt-in",
			uri:     "azblob://acct/c/",
			creds:   map[string][]byte{azureSecretKeyEndpoint: []byte("https://acct.blob.core.chinacloudapi.cn")},
			policy:  CredentialPolicy{EndpointAllowlist: []string{"acct.blob.core.chinacloudapi.cn"}},
			wantErr: "ambient credentials are not allowed",
		},
		{
			name:    "wildcard does not match the apex or a lookalike",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("https://evilexample.com")},
			policy:  CredentialPolicy{AllowAmbientCredentials: true, EndpointAllowlist: []string{"*.example.com"}},
			wantErr: "only honoured with static credentials",
		},
		{
			name:    "metadata literal even with static credentials",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("http://169.254.169.254"), s3SecretKeyAccessKeyID: []byte("k"), s3SecretKeySecretAccessKey: []byte("s")},
			wantErr: "blocked address",
		},
		{
			name:    "azure wireserver literal even when allowlisted",
			uri:     "azblob://acct/c/",
			creds:   map[string][]byte{azureSecretKeyEndpoint: []byte("http://168.63.129.16"), azureSecretKeyAccountKey: []byte("a2V5")},
			policy:  CredentialPolicy{EndpointAllowlist: []string{"168.63.129.16"}},
			wantErr: "blocked address",
		},
		{
			name:    "endpoint without a scheme",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("minio:9000"), s3SecretKeyAccessKeyID: []byte("k"), s3SecretKeySecretAccessKey: []byte("s")},
			wantErr: "must be an http(s) URL",
		},
		{
			name:    "endpoint that is not a URL",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("http://[::1"), s3SecretKeyAccessKeyID: []byte("k"), s3SecretKeySecretAccessKey: []byte("s")},
			wantErr: "endpoint is not a valid URL",
		},
		{
			name:    "unsupported destination scheme",
			uri:     "ftp://bucket/",
			policy:  CredentialPolicy{AllowAmbientCredentials: true},
			wantErr: "unsupported URI scheme",
		},
		{
			name:   "blank allowlist entries are skipped",
			uri:    "s3://bucket/",
			creds:  map[string][]byte{s3SecretKeyEndpoint: []byte("https://minio.storage.example")},
			policy: CredentialPolicy{AllowAmbientCredentials: true, EndpointAllowlist: []string{" ", ".", "minio.storage.example."}},
		},
		{
			name:    "only blank allowlist entries allow nothing",
			uri:     "s3://bucket/",
			creds:   map[string][]byte{s3SecretKeyEndpoint: []byte("https://minio.storage.example")},
			policy:  CredentialPolicy{AllowAmbientCredentials: true, EndpointAllowlist: []string{"", "  "}},
			wantErr: "only honoured with static credentials",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.policy.Check(c.uri, c.creds)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Check err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

func TestCredentialPolicy_AmbientFallbackRequiresOptIn(t *testing.T) {
	for _, uri := range []string{"s3://bucket/", "gs://bucket/", "azblob://acct/c/"} {
		err := CredentialPolicy{}.Check(uri, nil)
		if !errors.Is(err, ErrAmbientCredentialsDenied) {
			t.Errorf("Check(%s, no creds) = %v, want ErrAmbientCredentialsDenied", uri, err)
		}
		if err := (CredentialPolicy{AllowAmbientCredentials: true}).Check(uri, nil); err != nil {
			t.Errorf("Check(%s, no creds, ambient allowed) = %v", uri, err)
		}
	}
	if err := (CredentialPolicy{}).Check("s3://bucket/", map[string][]byte{s3SecretKeyAccessKeyID: []byte("k"), s3SecretKeySecretAccessKey: []byte("s")}); err != nil {
		t.Errorf("static S3 keys rejected without ambient opt-in: %v", err)
	}
}

func TestNew_RefusesTenantEndpointWithDefaultAzureCredential(t *testing.T) {
	_, err := New(context.Background(), Config{
		URI:         "azblob://acct/reports/",
		Credentials: map[string][]byte{azureSecretKeyEndpoint: []byte("https://attacker.example")},
		Policy:      CredentialPolicy{AllowAmbientCredentials: true},
	})
	if err == nil || !strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("New err = %v, want the tenant endpoint refused", err)
	}
}

func TestNew_RefusesAmbientCredentialsByDefault(t *testing.T) {
	_, err := New(context.Background(), Config{URI: "s3://other-tenant-bucket/key"})
	if !errors.Is(err, ErrAmbientCredentialsDenied) {
		t.Fatalf("New err = %v, want ErrAmbientCredentialsDenied", err)
	}
}
