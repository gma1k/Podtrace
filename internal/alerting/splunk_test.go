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

func TestNewSplunkAlertSender(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		token    string
		wantErr  bool
	}{
		{
			name:     "valid Splunk endpoint",
			endpoint: "https://splunk.example.com:8088/services/collector",
			token:    "test-token",
			wantErr:  false,
		},
		{
			name:     "empty endpoint",
			endpoint: "",
			token:    "test-token",
			wantErr:  true,
		},
		{
			name:     "empty token",
			endpoint: "https://splunk.example.com:8088/services/collector",
			token:    "",
			wantErr:  true,
		},
		{
			name:     "invalid URL",
			endpoint: "not-a-url",
			token:    "test-token",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSplunkAlertSender(tt.endpoint, tt.token, 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSplunkAlertSender() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewSplunkAlertSender() returned nil for valid input")
			}
		})
	}
}

func TestSplunkAlertSender_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("Expected Authorization header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewSplunkAlertSender(server.URL, "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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

func TestSplunkAlertSender_Send_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	sender, err := NewSplunkAlertSender(server.URL, "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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

func TestSplunkAlertSender_Send_NilAlert(t *testing.T) {
	sender, err := NewSplunkAlertSender("https://splunk.example.com:8088/services/collector", "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
	}
	err = sender.Send(context.Background(), nil)
	if err == nil {
		t.Error("Send() should return error for nil alert")
	}
}

func TestSplunkAlertSender_Name(t *testing.T) {
	sender, err := NewSplunkAlertSender("https://splunk.example.com:8088/services/collector", "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
	}
	if sender.Name() != "splunk" {
		t.Errorf("Name() = %s, want splunk", sender.Name())
	}
}

func TestSplunkAlertSender_Send_WithAllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewSplunkAlertSender(server.URL, "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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
		Context:        map[string]interface{}{
			"key1": "value1",
			"key2": 123,
			"very_long_key_name_that_exceeds_64_characters_limit_should_be_ignored": "value",
		},
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

func TestSplunkAlertSender_Send_PayloadTooLarge(t *testing.T) {
	originalMaxSize := config.AlertMaxPayloadSize
	config.AlertMaxPayloadSize = 100
	defer func() { config.AlertMaxPayloadSize = originalMaxSize }()

	sender, err := NewSplunkAlertSender("https://splunk.example.com:8088/services/collector", "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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

func TestSplunkAlertSender_Send_HTTPError(t *testing.T) {
	sender, err := NewSplunkAlertSender("https://invalid-host-that-does-not-exist-12345.com/collector", "test-token", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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

func TestNewSplunkAlertSender_InvalidScheme(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		token    string
		wantErr  bool
	}{
		{
			name:     "ftp scheme",
			endpoint: "ftp://splunk.example.com:8088/services/collector",
			token:    "test-token",
			wantErr:  true,
		},
		{
			name:     "http scheme",
			endpoint: "http://splunk.example.com:8088/services/collector",
			token:    "test-token",
			wantErr:  false,
		},
		{
			name:     "https scheme",
			endpoint: "https://splunk.example.com:8088/services/collector",
			token:    "test-token",
			wantErr:  false,
		},
		{
			name:     "invalid URL parse",
			endpoint: "://invalid-url",
			token:    "test-token",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSplunkAlertSender(tt.endpoint, tt.token, 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSplunkAlertSender() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewSplunkAlertSender() returned nil for valid input")
			}
		})
	}
}

func TestSplunkAlertSender_Send_MarshalError(t *testing.T) {
	sender, err := NewSplunkAlertSender("https://splunk.example.com:8088/services/collector", "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
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

func TestSplunkAlertSender_Send_ContextKeysTooLong(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewSplunkAlertSender(server.URL, "test-token", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSplunkAlertSender() error = %v", err)
	}

	longKey := strings.Repeat("a", 65)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
		Context:   map[string]interface{}{longKey: "value"},
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}


