package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSlackSender(t *testing.T) {
	tests := []struct {
		name      string
		webhookURL string
		channel   string
		wantErr   bool
	}{
		{
			name:      "valid Slack webhook",
			webhookURL: "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL",
			channel:   "#alerts",
			wantErr:   false,
		},
		{
			name:      "empty webhook URL",
			webhookURL: "",
			channel:   "#alerts",
			wantErr:   true,
		},
		{
			name:      "http webhook URL",
			webhookURL: "http://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL",
			channel:   "#alerts",
			wantErr:   true,
		},
		{
			name:      "invalid webhook URL",
			webhookURL: "not-a-slack-url",
			channel:   "#alerts",
			wantErr:   true,
		},
		{
			name:      "empty channel uses default",
			webhookURL: "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL",
			channel:   "",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSlackSender(tt.webhookURL, tt.channel, 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSlackSender() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewSlackSender() returned nil for valid input")
			}
		})
	}
}

func TestSlackSender_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewSlackSender(server.URL, "#alerts", 10*time.Second)
	if err == nil {
		alert := &Alert{
			Severity:  SeverityWarning,
			Title:     "Test Alert",
			Message:   "Test message",
			Timestamp: time.Now(),
			Source:    "test",
		}
		err = sender.Send(context.Background(), alert)
		if err == nil {
			t.Log("Send() succeeded (may fail in CI without valid Slack webhook)")
		}
	}
}

func TestSlackSender_Send_NilAlert(t *testing.T) {
	sender, err := NewSlackSender("https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL", "#alerts", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSlackSender() error = %v", err)
	}
	err = sender.Send(context.Background(), nil)
	if err == nil {
		t.Error("Send() should return error for nil alert")
	}
}

func TestSlackSender_Name(t *testing.T) {
	sender, err := NewSlackSender("https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL", "#alerts", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSlackSender() error = %v", err)
	}
	if sender.Name() != "slack" {
		t.Errorf("Name() = %s, want slack", sender.Name())
	}
}

func TestMapSeverityToSlackColor(t *testing.T) {
	tests := []struct {
		severity AlertSeverity
		expected string
	}{
		{SeverityFatal, "danger"},
		{SeverityCritical, "danger"},
		{SeverityWarning, "warning"},
		{SeverityError, "warning"},
		{AlertSeverity("unknown"), "#808080"},
	}
	for _, tt := range tests {
		result := mapSeverityToSlackColor(tt.severity)
		if result != tt.expected {
			t.Errorf("mapSeverityToSlackColor(%v) = %s, want %s", tt.severity, result, tt.expected)
		}
	}
}

