// Package objectstore uploads PodTraceSession reports to cloud object
// storage (S3, GCS, Azure Blob).
//
// Backend selection is by URI scheme:
//
//	s3://bucket/key-or-prefix
//	gs://bucket/key-or-prefix
//	azblob://account/container/key-or-prefix
//
// A trailing slash on the URI means "prefix mode" — the uploader picks
// the object key by appending a hint (typically <session>-<starttime>.txt).
// No trailing slash means "exact key mode": the URI's path is used
// verbatim.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// SchemeS3 / SchemeGCS / SchemeAzure are the URI schemes this package
// recognises. Exposed so callers (webhook validators, the operator) can
// validate URIs against the same canonical list.
const (
	SchemeS3    = "s3"
	SchemeGCS   = "gs"
	SchemeAzure = "azblob"
)

// Sink uploads session artifacts to an object-storage backend.
//
// Implementations are returned by New and are single-use: a Sink is
// constructed for one session's worth of uploads and Close()d at the end.
type Sink interface {
	Upload(ctx context.Context, keyHint, contentType string, body io.Reader) (resolvedURI string, err error)

	Close() error
}

// Config is the construction-time data for a Sink. URI is required;
// Credentials are optional (when empty the backend falls back to the
// SDK's default credential chain — IRSA / Workload Identity / Managed
// Identity / static env vars) when Policy allows it.
type Config struct {
	URI string

	Credentials map[string][]byte

	Policy CredentialPolicy
}

// destination is the parsed form of a URI. Shared by all backends.
type destination struct {
	scheme string // s3 | gs | azblob
	bucket string // bucket / container / blob-container name
	path   string
	prefix bool
}

// parseURI splits a podtrace ObjectStore URI into its components.
// Trailing slash on the URI means prefix mode.
//
// Examples:
//
//	"s3://bucket/path/"           ⇒ bucket="bucket", path="path", prefix=true
//	"s3://bucket/path/report.txt" ⇒ bucket="bucket", path="path/report.txt", prefix=false
//	"s3://bucket/"                ⇒ bucket="bucket", path="",     prefix=true
//	"azblob://acct/container/k"   ⇒ bucket="container", path="k", prefix=false
func parseURI(raw string) (destination, error) {
	if raw == "" {
		return destination{}, errors.New("empty URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return destination{}, fmt.Errorf("parse URI %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return destination{}, fmt.Errorf("URI %q must include scheme and host", raw)
	}

	d := destination{
		scheme: u.Scheme,
		prefix: strings.HasSuffix(u.Path, "/") || u.Path == "",
	}

	path := strings.TrimPrefix(u.Path, "/")
	path = strings.TrimSuffix(path, "/")

	switch u.Scheme {
	case SchemeS3, SchemeGCS:
		d.bucket = u.Host
		d.path = path
	case SchemeAzure:
		parts := strings.SplitN(path, "/", 2)
		if parts[0] == "" {
			return destination{}, fmt.Errorf("azblob URI %q must include a container after the account", raw)
		}
		d.bucket = parts[0]
		if len(parts) == 2 {
			d.path = parts[1]
		}
	default:
		return destination{}, fmt.Errorf("unsupported URI scheme %q (want %s, %s, or %s)",
			u.Scheme, SchemeS3, SchemeGCS, SchemeAzure)
	}
	return d, nil
}

// resolveKey returns the final object key for an Upload call. Joins the
// destination's prefix with keyHint when in prefix mode; uses the exact
// path otherwise. Strips any accidental leading slash.
func (d destination) resolveKey(keyHint string) string {
	if !d.prefix {
		return d.path
	}
	keyHint = strings.TrimPrefix(keyHint, "/")
	if d.path == "" {
		return keyHint
	}
	return d.path + "/" + keyHint
}

// New constructs a Sink for the given config. Dispatches on URI scheme.
// Returns a useful error when the scheme is unknown or the URI is malformed
// — the webhook validates the same way, so this path should only fire on
// programmer bugs or out-of-band CR edits that bypass admission.
func New(ctx context.Context, cfg Config) (Sink, error) {
	d, err := parseURI(cfg.URI)
	if err != nil {
		return nil, err
	}
	if err := cfg.Policy.check(d, cfg.Credentials); err != nil {
		return nil, err
	}
	switch d.scheme {
	case SchemeS3:
		return newS3Sink(ctx, cfg, d)
	case SchemeGCS:
		return newGCSSink(ctx, cfg, d)
	case SchemeAzure:
		return newAzureSink(ctx, cfg, d)
	default:
		return nil, fmt.Errorf("no backend registered for scheme %q", d.scheme)
	}
}

// ValidateURI is the helper the admission webhook calls. Same parsing
// rules as New, but does not open any client connections. Returns nil
// when the URI is well-formed; returns the same error New would return
// otherwise.
func ValidateURI(raw string) error {
	_, err := parseURI(raw)
	return err
}
