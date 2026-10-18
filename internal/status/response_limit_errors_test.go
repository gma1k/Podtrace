package status

import (
	"errors"
	"net/http"
	"testing"

	"k8s.io/client-go/rest"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestATransportErrorPassesThroughTheLimit(t *testing.T) {
	cfg := &rest.Config{Host: "http://example.invalid"}
	LimitResponses(cfg, 10)
	rt := cfg.WrapTransport(failingTransport{})
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	if _, err := rt.RoundTrip(req); err == nil || err.Error() != "connection refused" {
		t.Fatalf("err = %v, want the transport's own error", err)
	}
}
