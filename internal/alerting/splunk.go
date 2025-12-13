package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type SplunkAlertSender struct {
	endpoint string
	token    string
	client   *http.Client
	timeout  time.Duration
}

type SplunkAlertEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Sourcetype string                 `json:"sourcetype,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

func NewSplunkAlertSender(endpoint, token string, timeout time.Duration) (*SplunkAlertSender, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("splunk endpoint is required")
	}
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid splunk endpoint: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("splunk endpoint must use http or https scheme")
	}
	if token == "" {
		return nil, fmt.Errorf("splunk token is required")
	}
	return &SplunkAlertSender{
		endpoint: endpoint,
		token:    token,
		client:   &http.Client{Timeout: timeout},
		timeout:  timeout,
	}, nil
}

func (s *SplunkAlertSender) Send(ctx context.Context, alert *Alert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	eventData := map[string]interface{}{
		"severity":  string(alert.Severity),
		"title":     alert.Title,
		"message":   alert.Message,
		"source":    alert.Source,
		"pod":       alert.PodName,
		"namespace": alert.Namespace,
	}
	if alert.ErrorCode != "" {
		eventData["error_code"] = alert.ErrorCode
	}
	if len(alert.Recommendations) > 0 {
		eventData["recommendations"] = alert.Recommendations
	}
	if len(alert.Context) > 0 {
		for k, v := range alert.Context {
			if len(k) <= 64 {
				eventData[k] = v
			}
		}
	}
	event := SplunkAlertEvent{
		Time:       alert.Timestamp.Unix(),
		Sourcetype: "Podtrace:alert",
		Event:      eventData,
	}
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal Splunk event: %w", err)
	}
	if int64(len(jsonData)) > config.AlertMaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", len(jsonData), config.AlertMaxPayloadSize)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("User-Agent", config.GetUserAgent())
	resp, err := s.client.Do(req)
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

func (s *SplunkAlertSender) Name() string {
	return "splunk"
}
