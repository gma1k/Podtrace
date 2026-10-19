package objectstore

import (
	"reflect"
	"testing"
)

func TestParseEndpointAllowlist(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{raw: "", want: nil},
		{raw: " , ,", want: nil},
		{raw: "minio.storage.svc", want: []string{"minio.storage.svc"}},
		{raw: " *.vpce.amazonaws.com ,, fake-gcs ,", want: []string{"*.vpce.amazonaws.com", "fake-gcs"}},
	}
	for _, c := range cases {
		if got := ParseEndpointAllowlist(c.raw); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseEndpointAllowlist(%q) = %#v, want %#v", c.raw, got, c.want)
		}
	}
}

func TestPolicyFromEnv(t *testing.T) {
	cases := []struct {
		name      string
		ambient   string
		allowlist string
		want      CredentialPolicy
	}{
		{name: "unset is strict", want: CredentialPolicy{}},
		{name: "ambient opt-in with allowlist", ambient: " true ", allowlist: "minio.storage.svc, *.example.com", want: CredentialPolicy{AllowAmbientCredentials: true, EndpointAllowlist: []string{"minio.storage.svc", "*.example.com"}}},
		{name: "unparsable ambient value stays strict", ambient: "yes-please", want: CredentialPolicy{}},
		{name: "explicit false", ambient: "false", allowlist: "fake-gcs", want: CredentialPolicy{EndpointAllowlist: []string{"fake-gcs"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(EnvAllowAmbientCredentials, c.ambient)
			t.Setenv(EnvEndpointAllowlist, c.allowlist)
			if got := PolicyFromEnv(); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("PolicyFromEnv() = %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestUnknownSchemeHasNoStaticCredentialsOrEndpoint(t *testing.T) {
	creds := map[string][]byte{
		s3SecretKeyAccessKeyID:         []byte("k"),
		s3SecretKeySecretAccessKey:     []byte("s"),
		s3SecretKeyEndpoint:            []byte("https://minio.example"),
		gcsSecretKeyServiceAccountJSON: []byte("{}"),
		azureSecretKeyAccountKey:       []byte("a2V5"),
	}
	if hasStaticCredentials("ftp", creds) {
		t.Error("an unknown scheme must never count as statically authenticated")
	}
	if got := endpointFromCreds("ftp", creds); got != "" {
		t.Errorf("endpointFromCreds(unknown scheme) = %q, want empty", got)
	}
}
