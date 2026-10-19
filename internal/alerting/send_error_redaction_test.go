package alerting

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const leakMarker = "XyZsEcReTtOkEn42"

func closedPortURL(t *testing.T, path string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return "http://" + address + path
}

func TestSenderTransportErrorsOmitWebhookSecret(t *testing.T) {
	target := closedPortURL(t, "/services/T000/B000/"+leakMarker+"?token="+leakMarker)
	client := &http.Client{Timeout: 2 * time.Second}
	senders := []Sender{
		&SlackSender{webhookURL: target, channel: "#a", client: client},
		&WebhookSender{url: target, client: client},
		&SplunkAlertSender{endpoint: target, token: "t", client: client},
	}
	for _, sender := range senders {
		err := sender.Send(context.Background(), deliveryTestAlert())
		if err == nil {
			t.Fatalf("%s: expected a transport error", sender.Name())
		}
		if strings.Contains(err.Error(), leakMarker) {
			t.Errorf("%s: error leaks the webhook secret: %v", sender.Name(), err)
		}
		var urlError *url.Error
		if errors.As(err, &urlError) && strings.Contains(urlError.URL, leakMarker) {
			t.Errorf("%s: *url.Error still carries the secret URL %q", sender.Name(), urlError.URL)
		}
		if !strings.Contains(err.Error(), "http://127.0.0.1:") {
			t.Errorf("%s: error lost the host it failed against: %v", sender.Name(), err)
		}
	}
}

func TestSenderTimeoutStaysDetectableAfterRedaction(t *testing.T) {
	target := closedPortURL(t, "/services/"+leakMarker)
	sender := &WebhookSender{url: target, client: &http.Client{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sender.Send(ctx, deliveryTestAlert())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(err, context.Canceled) = false for %v", err)
	}
	if strings.Contains(err.Error(), leakMarker) {
		t.Errorf("error leaks the webhook secret: %v", err)
	}
}

func TestSenderConstructorParseErrorsOmitURL(t *testing.T) {
	raw := "https://hooks.slack.com/services/" + leakMarker + "/%zz"
	if _, err := NewSlackSender(raw, "", time.Second); err == nil || strings.Contains(err.Error(), leakMarker) {
		t.Errorf("slack constructor error = %v", err)
	}
	if _, err := NewWebhookSender(raw, time.Second); err == nil || strings.Contains(err.Error(), leakMarker) {
		t.Errorf("webhook constructor error = %v", err)
	}
	if _, err := NewSplunkAlertSender(raw, "t", time.Second); err == nil || strings.Contains(err.Error(), leakMarker) {
		t.Errorf("splunk constructor error = %v", err)
	}
}

func TestDeliveryFailureLogOmitsWebhookSecret(t *testing.T) {
	enableAlerting(t)
	core, logs := observer.New(zapcore.DebugLevel)
	original := alertLog
	alertLog = zap.New(core)
	t.Cleanup(func() { alertLog = original })

	leaky := &mockSender{name: "leaky", sendFunc: func(context.Context, *Alert) error {
		return fmt.Errorf("custom transport: Post %q: dial tcp: refused", "https://hooks.slack.com/services/T0/B0/"+leakMarker)
	}}
	m := deliveryTestManager(leaky)
	m.SendAlert(deliveryTestAlert())
	waitForDeliveries(t, m)

	entries := logs.FilterMessage("Alert delivery failed").All()
	if len(entries) != 1 {
		t.Fatalf("delivery failure log entries = %d, want 1", len(entries))
	}
	for key, value := range entries[0].ContextMap() {
		if strings.Contains(fmt.Sprint(value), leakMarker) {
			t.Errorf("log field %q leaks the webhook secret: %v", key, value)
		}
	}
	if got := fmt.Sprint(entries[0].ContextMap()["error"]); !strings.Contains(got, "https://hooks.slack.com") {
		t.Errorf("redacted error lost the receiver host: %q", got)
	}
}
