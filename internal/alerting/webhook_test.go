package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestNewWebhookSender(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid https URL",
			url:     "https://example.com/webhook",
			wantErr: false,
		},
		{
			name:    "valid http localhost",
			url:     "http://localhost:8080/webhook",
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			url:     "not-a-url",
			wantErr: true,
		},
		{
			name:    "http non-localhost",
			url:     "http://example.com/webhook",
			wantErr: true,
		},
		{
			name:    "http localhost.evil.com",
			url:     "http://localhost.evil.com/webhook",
			wantErr: true,
		},
		{
			name:    "http 127.0.0.1",
			url:     "http://127.0.0.1:8080/webhook",
			wantErr: false,
		},
		{
			name:    "http ::1",
			url:     "http://[::1]:8080/webhook",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewWebhookSender(tt.url, 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWebhookSender() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewWebhookSender() returned nil for valid input")
			}
		})
	}
}

func TestWebhookSender_Send(t *testing.T) {
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

	sender, err := NewWebhookSender(server.URL, 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

func TestWebhookSender_Send_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sender, err := NewWebhookSender(server.URL, 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}

	err = sender.Send(context.Background(), alert)
	if err == nil {
		t.Error("Send() should return error for non-2xx status")
	}
}

func TestWebhookSender_Send_NilAlert(t *testing.T) {
	sender, err := NewWebhookSender("https://example.com/webhook", 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}
	err = sender.Send(context.Background(), nil)
	if err == nil {
		t.Error("Send() should return error for nil alert")
	}
}

func TestWebhookSender_Name(t *testing.T) {
	sender, err := NewWebhookSender("https://example.com/webhook", 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}
	if sender.Name() != "webhook" {
		t.Errorf("Name() = %s, want webhook", sender.Name())
	}
}

func TestWebhookSender_Send_WithAllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewWebhookSender(server.URL, 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:       SeverityWarning,
		Title:          "Test Alert",
		Message:        "Test message",
		Timestamp:      time.Now(),
		Source:         "test",
		PodName:        "test-pod",
		Namespace:      "test-ns",
		ErrorCode:      "ERR001",
		Recommendations: []string{"rec1", "rec2"},
		Context:        map[string]interface{}{"key": "value"},
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

func TestWebhookSender_Send_PayloadTooLarge(t *testing.T) {
	originalMaxSize := config.AlertMaxPayloadSize
	config.AlertMaxPayloadSize = 100
	defer func() { config.AlertMaxPayloadSize = originalMaxSize }()

	sender, err := NewWebhookSender("https://example.com/webhook", 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     strings.Repeat("A", 200),
		Message:   strings.Repeat("B", 200),
		Timestamp: time.Now(),
		Source:    "test",
	}

	err = sender.Send(context.Background(), alert)
	if err == nil {
		t.Error("Send() should return error for payload too large")
	}
}

func TestWebhookSender_Send_HTTPError(t *testing.T) {
	sender, err := NewWebhookSender("https://invalid-host-that-does-not-exist-12345.com/webhook", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err = sender.Send(ctx, alert)
	if err == nil {
		t.Error("Send() should return error for HTTP timeout")
	}
}

func TestNewWebhookSender_InvalidScheme(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "ftp scheme",
			url:     "ftp://example.com/webhook",
			wantErr: true,
		},
		{
			name:    "file scheme",
			url:     "file:///tmp/webhook",
			wantErr: true,
		},
		{
			name:    "invalid URL parse",
			url:     "://invalid-url",
			wantErr: true,
		},
		{
			name:    "IPv6 localhost",
			url:     "http://[::1]:8080/webhook",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewWebhookSender(tt.url, 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWebhookSender() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewWebhookSender() returned nil for valid input")
			}
		})
	}
}

func TestWebhookSender_Send_MarshalError(t *testing.T) {
	sender, err := NewWebhookSender("https://example.com/webhook", 10*time.Second)
	if err != nil {
		t.Fatalf("NewWebhookSender() error = %v", err)
	}

	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
		Context:   map[string]interface{}{"invalid": make(chan int)},
	}

	err = sender.Send(context.Background(), alert)
	if err == nil {
		t.Error("Send() should return error for invalid JSON")
	}
}

