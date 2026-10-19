package objectstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
)

const (
	azureSecretKeyTenantID     = "tenant_id"
	azureSecretKeyClientID     = "client_id"
	azureSecretKeyClientSecret = "client_secret"
	azureSecretKeyAccountKey   = "account_key"
	azureSecretKeyEndpoint     = "endpoint"
)

type azureSink struct {
	client    *azblob.Client
	container string
	dest      destination
	uriPrefix string
}

func newAzureSink(_ context.Context, cfg Config, d destination) (Sink, error) {
	creds := cfg.Credentials

	u, err := url.Parse(cfg.URI)
	if err != nil {
		return nil, fmt.Errorf("azblob: re-parse URI %q: %w", cfg.URI, err)
	}
	account := u.Host
	endpoint := stringFromCreds(creds, azureSecretKeyEndpoint)
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net", account)
	}
	endpoint = strings.TrimRight(endpoint, "/")

	azClientOpts := &azblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			PerRetryPolicies: []policy.Policy{newAzureRetryLogPolicy()},
			Transport:        guardedHTTPClient(nil),
		},
	}

	var client *azblob.Client
	switch {
	case stringFromCreds(creds, azureSecretKeyAccountKey) != "":
		key, err := azblob.NewSharedKeyCredential(account, stringFromCreds(creds, azureSecretKeyAccountKey))
		if err != nil {
			return nil, fmt.Errorf("azblob: shared key credential: %w", err)
		}
		client, err = azblob.NewClientWithSharedKeyCredential(endpoint, key, azClientOpts)
		if err != nil {
			return nil, fmt.Errorf("azblob: new shared-key client: %w", err)
		}
	case azureHasSPN(creds):
		spn, err := azidentity.NewClientSecretCredential(
			stringFromCreds(creds, azureSecretKeyTenantID),
			stringFromCreds(creds, azureSecretKeyClientID),
			stringFromCreds(creds, azureSecretKeyClientSecret),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("azblob: SPN credential: %w", err)
		}
		client, err = azblob.NewClient(endpoint, spn, azClientOpts)
		if err != nil {
			return nil, fmt.Errorf("azblob: new SPN client: %w", err)
		}
	default:
		def, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azblob: default credential: %w", err)
		}
		client, err = azblob.NewClient(endpoint, def, azClientOpts)
		if err != nil {
			return nil, fmt.Errorf("azblob: new default-cred client: %w", err)
		}
	}

	return &azureSink{
		client:    client,
		container: d.bucket,
		dest:      d,
		uriPrefix: SchemeAzure + "://" + account + "/" + d.bucket,
	}, nil
}

func (a *azureSink) Upload(ctx context.Context, keyHint, contentType string, body io.Reader) (string, error) {
	key := a.dest.resolveKey(keyHint)
	if key == "" {
		return "", fmt.Errorf("azblob: resolved object key is empty (URI must include a key or prefix)")
	}
	_, err := a.client.UploadStream(ctx, a.container, key, body, &azblob.UploadStreamOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: toPtr(contentType),
		},
	})
	if err != nil {
		return "", fmt.Errorf("azblob: upload %s/%s: %w", a.container, key, err)
	}
	return a.uriPrefix + "/" + key, nil
}

func (a *azureSink) Close() error {
	return nil
}

func toPtr[T any](v T) *T { return &v }

var _ = azcore.NullValue[int]

type azureRetryLogPolicy struct {
	attempts sync.Map
}

func newAzureRetryLogPolicy() *azureRetryLogPolicy {
	return &azureRetryLogPolicy{}
}

func (p *azureRetryLogPolicy) Do(req *policy.Request) (*http.Response, error) {
	raw := req.Raw()
	key := raw.Method + " " + raw.URL.Host + raw.URL.Path
	counter := p.counterFor(key)
	attempt := int(counter.Add(1))

	started := time.Now()
	resp, err := req.Next()
	took := time.Since(started)

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	_, _ = fmt.Fprintf(os.Stderr,
		`{"component":"objectstore.retry","backend":%q,"method":%q,"url":%q,"status":%d,"attempt":%d,"took_ms":%d,"error":%q}`+"\n",
		SchemeAzure, raw.Method, redactURL(raw.URL), status, attempt, took.Milliseconds(), errStr,
	)
	return resp, err
}

func (p *azureRetryLogPolicy) counterFor(key string) *atomic.Int32 {
	if v, ok := p.attempts.Load(key); ok {
		return v.(*atomic.Int32)
	}
	fresh := new(atomic.Int32)
	actual, _ := p.attempts.LoadOrStore(key, fresh)
	return actual.(*atomic.Int32)
}
