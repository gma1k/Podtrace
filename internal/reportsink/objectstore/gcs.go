package objectstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"

	"github.com/gma1k/podtrace/internal/netguard"
)

const (
	gcsSecretKeyServiceAccountJSON = "service_account_json"
	gcsSecretKeyEndpoint           = "endpoint"
)

// gcsScopes lists the OAuth2 scopes the storage client needs. Hardcoding
// them keeps the credentials-construction path explicit.
var gcsScopes = []string{
	"https://www.googleapis.com/auth/devstorage.read_write",
	"https://www.googleapis.com/auth/cloud-platform",
}

type gcsSink struct {
	client    *storage.Client
	dest      destination
	uriPrefix string
}

func newGCSSink(ctx context.Context, cfg Config, d destination) (Sink, error) {
	creds := cfg.Credentials

	authOpts := []option.ClientOption{option.WithScopes(gcsScopes...)}
	saJSON := stringFromCreds(creds, gcsSecretKeyServiceAccountJSON)
	if saJSON != "" {
		ac, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, []byte(saJSON), &credentials.DetectOptions{
			Scopes: gcsScopes,
		})
		if err != nil {
			return nil, fmt.Errorf("gcs: load service account JSON: %w", err)
		}
		authOpts = append(authOpts, option.WithAuthCredentials(ac))
	}
	endpoint := stringFromCreds(creds, gcsSecretKeyEndpoint)
	if endpoint != "" {
		authOpts = append(authOpts, option.WithEndpoint(endpoint))
		if saJSON == "" {
			_, _ = fmt.Fprintf(os.Stderr,
				`{"component":"objectstore.gcs","level":"warn","message":"custom endpoint without %s: uploading WITHOUT AUTHENTICATION; this mode is for fake-gcs-server/dev only","endpoint":%q}`+"\n",
				gcsSecretKeyServiceAccountJSON, endpoint)
			authOpts = append(authOpts, option.WithoutAuthentication())
		}
	}

	rt, err := htransport.NewTransport(ctx, netguard.HardenedTransport(), authOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: build transport: %w", err)
	}
	opts := []option.ClientOption{option.WithHTTPClient(&http.Client{Transport: rt, CheckRedirect: netguard.RefuseRedirect})}
	if endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
	}

	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: new client: %w", err)
	}

	client.SetRetry(storage.WithErrorFunc(loggingGCSShouldRetry))

	return &gcsSink{
		client:    client,
		dest:      d,
		uriPrefix: SchemeGCS + "://" + d.bucket,
	}, nil
}

// loggingGCSShouldRetry mirrors storage.ShouldRetry's decision while
// emitting one structured log line per evaluation.
func loggingGCSShouldRetry(err error) bool {
	if err == nil {
		return false
	}
	shouldRetry := storage.ShouldRetry(err)
	_, _ = fmt.Fprintf(os.Stderr,
		`{"component":"objectstore.retry","backend":"gs","retry":%v,"error":%q}`+"\n",
		shouldRetry, err.Error(),
	)
	return shouldRetry
}

func (g *gcsSink) Upload(ctx context.Context, keyHint, contentType string, body io.Reader) (string, error) {
	key := g.dest.resolveKey(keyHint)
	if key == "" {
		return "", fmt.Errorf("gcs: resolved object key is empty (URI must include a key or prefix)")
	}
	// Aborting a GCS upload requires cancelling the writer's context:
	// Close() FINALIZES the object with whatever bytes were buffered, so
	// closing after a mid-stream copy failure committed a silently
	// truncated report (which a prefix-keyed retry would not overwrite).
	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()
	w := g.client.Bucket(g.dest.bucket).Object(key).NewWriter(writeCtx)
	w.ContentType = contentType
	if _, err := io.Copy(w, body); err != nil {
		cancelWrite()
		_ = w.Close() // releases resources; the object is NOT committed
		return "", fmt.Errorf("gcs: stream to %s/%s: %w", g.dest.bucket, key, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("gcs: finalise %s/%s: %w", g.dest.bucket, key, err)
	}
	return g.uriPrefix + "/" + key, nil
}

func (g *gcsSink) Close() error {
	return g.client.Close()
}
