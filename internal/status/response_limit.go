package status

import (
	"fmt"
	"io"
	"net/http"

	"k8s.io/client-go/rest"
)

// MaxResponseBytes bounds any one response the status command reads. An
// agent's /metrics or pprof profile is buffered whole to be decoded, so a
// misbehaving agent could otherwise exhaust the memory of the CLI.
const MaxResponseBytes = 128 << 20

// LimitResponses makes every response body read through cfg fail once it
// passes max bytes, instead of being buffered to the end.
func LimitResponses(cfg *rest.Config, max int64) {
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return limitedTransport{next: rt, max: max}
	})
}

type limitedTransport struct {
	next http.RoundTripper
	max  int64
}

func (t limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &limitedBody{ReadCloser: resp.Body, remaining: t.max, max: t.max}
	return resp, nil
}

type limitedBody struct {
	io.ReadCloser
	remaining int64
	max       int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, b.tooLarge()
	}
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return 0, b.tooLarge()
	}
	return n, err
}

func (b *limitedBody) tooLarge() error {
	return fmt.Errorf("response is larger than %d bytes", b.max)
}
