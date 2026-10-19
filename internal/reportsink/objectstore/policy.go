package objectstore

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/gma1k/podtrace/internal/netguard"
)

var ErrAmbientCredentialsDenied = errors.New("ambient credentials are not allowed for this session: " +
	"supply static credentials in credentialsSecretRef, or have the cluster admin enable " +
	"cross-namespace ambient credentials on the operator")

// CredentialPolicy bounds what a tenant-supplied report destination may
// make the uploader do.
type CredentialPolicy struct {
	AllowAmbientCredentials bool

	EndpointAllowlist []string
}

// Check reports whether a destination URI with the given Secret data is
// permitted. It opens no connections.
func (p CredentialPolicy) Check(uri string, creds map[string][]byte) error {
	d, err := parseURI(uri)
	if err != nil {
		return err
	}
	return p.check(d, creds)
}

func (p CredentialPolicy) check(d destination, creds map[string][]byte) error {
	static := hasStaticCredentials(d.scheme, creds)
	endpoint := endpointFromCreds(d.scheme, creds)
	if endpoint != "" {
		host, err := endpointHost(endpoint)
		if err != nil {
			return err
		}
		if err := netguard.ValidateEndpointHost(host); err != nil {
			return fmt.Errorf("%s: %w", d.scheme, err)
		}
		if !static && !p.endpointAllowed(host) {
			return fmt.Errorf("%s: custom endpoint host %q is only honoured with static credentials in the same Secret "+
				"or when the cluster admin allowlists it on the operator", d.scheme, host)
		}
	}
	unauthenticatedGCS := d.scheme == SchemeGCS && endpoint != ""
	if !static && !unauthenticatedGCS && !p.AllowAmbientCredentials {
		return fmt.Errorf("%s: %w", d.scheme, ErrAmbientCredentialsDenied)
	}
	return nil
}

func (p CredentialPolicy) endpointAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range p.EndpointAllowlist {
		entry = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "."))
		if entry == "" {
			continue
		}
		if suffix, ok := strings.CutPrefix(entry, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == strings.Trim(entry, "[]") {
			return true
		}
	}
	return false
}

// hasStaticCredentials reports whether creds carry a complete credential
// for the backend, so the SDK never consults its default chain.
func hasStaticCredentials(scheme string, creds map[string][]byte) bool {
	switch scheme {
	case SchemeS3:
		return stringFromCreds(creds, s3SecretKeyAccessKeyID) != "" &&
			stringFromCreds(creds, s3SecretKeySecretAccessKey) != ""
	case SchemeGCS:
		return stringFromCreds(creds, gcsSecretKeyServiceAccountJSON) != ""
	case SchemeAzure:
		return stringFromCreds(creds, azureSecretKeyAccountKey) != "" || azureHasSPN(creds)
	default:
		return false
	}
}

func azureHasSPN(creds map[string][]byte) bool {
	return stringFromCreds(creds, azureSecretKeyTenantID) != "" &&
		stringFromCreds(creds, azureSecretKeyClientID) != "" &&
		stringFromCreds(creds, azureSecretKeyClientSecret) != ""
}

func endpointFromCreds(scheme string, creds map[string][]byte) string {
	switch scheme {
	case SchemeS3:
		return stringFromCreds(creds, s3SecretKeyEndpoint)
	case SchemeGCS:
		return stringFromCreds(creds, gcsSecretKeyEndpoint)
	case SchemeAzure:
		return stringFromCreds(creds, azureSecretKeyEndpoint)
	default:
		return ""
	}
}

func endpointHost(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("endpoint is not a valid URL")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", fmt.Errorf("endpoint %q must be an http(s) URL with a host", u.Redacted())
	}
	return u.Hostname(), nil
}

// guardedHTTPClient is the data-plane client every backend talks to the
// bucket through: the netguard dial guard (also applied to proxied
// targets) and no redirects.
func guardedHTTPClient(wrap func(http.RoundTripper) http.RoundTripper) *http.Client {
	var rt http.RoundTripper = netguard.HardenedTransport()
	if wrap != nil {
		rt = wrap(rt)
	}
	return &http.Client{Transport: rt, CheckRedirect: netguard.RefuseRedirect}
}

// Environment the operator sets on the uploader sidecar to carry the
// policy. An unset variable is the strict default.
const (
	EnvAllowAmbientCredentials = "PODTRACE_OBJECTSTORE_ALLOW_AMBIENT_CREDENTIALS"
	EnvEndpointAllowlist       = "PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST"
)

// PolicyFromEnv reads the policy the operator handed the uploader.
func PolicyFromEnv() CredentialPolicy {
	allow, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnvAllowAmbientCredentials)))
	return CredentialPolicy{
		AllowAmbientCredentials: allow,
		EndpointAllowlist:       ParseEndpointAllowlist(os.Getenv(EnvEndpointAllowlist)),
	}
}

// ParseEndpointAllowlist splits a comma-separated host list, dropping
// empty entries.
func ParseEndpointAllowlist(raw string) []string {
	var out []string
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}
