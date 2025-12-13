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

type SlackSender struct {
	webhookURL string
	channel    string
	client     *http.Client
	timeout    time.Duration
}

type SlackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Footer    string       `json:"footer,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
	MrkdwnIn  []string     `json:"mrkdwn_in,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type SlackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

func NewSlackSender(webhookURL, channel string, timeout time.Duration) (*SlackSender, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("slack webhook URL is required")
	}
	parsedURL, err := url.Parse(webhookURL)
	if err != nil {
		return nil, fmt.Errorf("invalid slack webhook URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("slack webhook URL must use https scheme")
	}
	if !strings.Contains(webhookURL, "hooks.slack.com") {
		return nil, fmt.Errorf("invalid slack webhook URL format")
	}
	if channel == "" {
		channel = "#alerts"
	}
	return &SlackSender{
		webhookURL: webhookURL,
		channel:    channel,
		client:     &http.Client{Timeout: timeout},
		timeout:    timeout,
	}, nil
}

func (s *SlackSender) Send(ctx context.Context, alert *Alert) error {
	if alert == nil {
		return fmt.Errorf("alert is nil")
	}
	color := mapSeverityToSlackColor(alert.Severity)
	fields := buildSlackFields(alert)
	attachment := SlackAttachment{
		Color:     color,
		Title:     alert.Title,
		Text:      alert.Message,
		Fields:    fields,
		Footer:    "Podtrace",
		Timestamp: alert.Timestamp.Unix(),
		MrkdwnIn:  []string{"text", "fields"},
	}
	payload := SlackPayload{
		Channel:     s.channel,
		Attachments: []SlackAttachment{attachment},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}
	if int64(len(jsonData)) > config.AlertMaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", len(jsonData), config.AlertMaxPayloadSize)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", config.GetUserAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func (s *SlackSender) Name() string {
	return "slack"
}

func mapSeverityToSlackColor(severity AlertSeverity) string {
	switch severity {
	case SeverityFatal:
		return "danger"
	case SeverityCritical:
		return "danger"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "warning"
	default:
		return "#808080"
	}
}

func buildSlackFields(alert *Alert) []SlackField {
	fields := make([]SlackField, 0, 8)
	fields = append(fields, SlackField{
		Title: "Severity",
		Value: string(alert.Severity),
		Short: true,
	})
	fields = append(fields, SlackField{
		Title: "Source",
		Value: alert.Source,
		Short: true,
	})
	if alert.PodName != "" {
		fields = append(fields, SlackField{
			Title: "Pod",
			Value: alert.PodName,
			Short: true,
		})
	}
	if alert.Namespace != "" {
		fields = append(fields, SlackField{
			Title: "Namespace",
			Value: alert.Namespace,
			Short: true,
		})
	}
	if alert.ErrorCode != "" {
		fields = append(fields, SlackField{
			Title: "Error Code",
			Value: alert.ErrorCode,
			Short: true,
		})
	}
	if len(alert.Recommendations) > 0 {
		recs := strings.Join(alert.Recommendations[:min(3, len(alert.Recommendations))], "\n")
		fields = append(fields, SlackField{
			Title: "Recommendations",
			Value: recs,
			Short: false,
		})
	}
	return fields
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
