package alerting

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

var errWebhookRefused = errors.New("refused")

func TestAPlainSendErrorHasEmbeddedURLsRedacted(t *testing.T) {
	cause := fmt.Errorf("posting to https://hooks.example.com/services/%s failed: %w", leakMarker, errWebhookRefused)

	err := redactSendError(cause)

	if strings.Contains(err.Error(), leakMarker) {
		t.Fatalf("error leaks the webhook secret: %v", err)
	}
	if !strings.Contains(err.Error(), "https://hooks.example.com") {
		t.Errorf("error lost the host it failed against: %v", err)
	}
	if !errors.Is(err, errWebhookRefused) {
		t.Error("redaction must keep the cause reachable through errors.Is")
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		t.Error("a plain error must not be turned into a *url.Error")
	}
}
