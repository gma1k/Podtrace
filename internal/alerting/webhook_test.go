package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

