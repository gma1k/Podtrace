package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type WebhookSender struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func NewWebhookSender(webhookURL string, timeout time.Duration) (*WebhookSender, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}
	parsedURL, err := url.Parse(webhookURL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("webhook URL must use http or https scheme")
	}
	host := strings.ToLower(parsedURL.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		if parsedURL.Scheme == "http" {
			return nil, fmt.Errorf("non-localhost URLs must use https")
		}
	}
	return &WebhookSender{
		url:     webhookURL,
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}, nil
}

func (w *WebhookSender) Send(ctx context.Context, alert *Alert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	payload := map[string]interface{}{
		"severity":  string(alert.Severity),
		"title":     alert.Title,
		"message":   alert.Message,
		"timestamp": alert.Timestamp.Format(time.RFC3339),
		"source":    alert.Source,
		"pod":       alert.PodName,
		"namespace": alert.Namespace,
		"context":   alert.Context,
	}
	if alert.ErrorCode != "" {
		payload["error_code"] = alert.ErrorCode
	}
	if len(alert.Recommendations) > 0 {
		payload["recommendations"] = alert.Recommendations
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}
	if int64(len(jsonData)) > config.AlertMaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", len(jsonData), config.AlertMaxPayloadSize)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", config.GetUserAgent())
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func (w *WebhookSender) Name() string {
	return "webhook"
}
