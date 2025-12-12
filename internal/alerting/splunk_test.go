package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

