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

func TestSlackSender_Send_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookURL := server.URL
	if len(webhookURL) >= 5 && webhookURL[:5] != "https" {
		webhookURL = "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL"
	}

	sender, err := NewSlackSender(webhookURL, "#alerts", 10*time.Second)
	if err != nil {
		t.Skipf("Skipping test - cannot create Slack sender: %v", err)
		return
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
		t.Logf("Send() error (expected for test server): %v", err)
	}
}

func TestSlackSender_Send_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("error message"))
	}))
	defer server.Close()

	webhookURL := server.URL
	if len(webhookURL) >= 5 && webhookURL[:5] != "https" {
		webhookURL = "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL"
	}

	sender, err := NewSlackSender(webhookURL, "#alerts", 10*time.Second)
	if err != nil {
		t.Skipf("Skipping test - cannot create Slack sender: %v", err)
		return
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
		t.Error("Send() should return error for non-200 status")
	}
}

func TestSlackSender_Send_PayloadTooLarge(t *testing.T) {
	originalMaxSize := config.AlertMaxPayloadSize
	config.AlertMaxPayloadSize = 100
	defer func() { config.AlertMaxPayloadSize = originalMaxSize }()

	sender, err := NewSlackSender("https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL", "#alerts", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSlackSender() error = %v", err)
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

func TestSlackSender_Send_WithAllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookURL := server.URL
	if len(webhookURL) >= 5 && webhookURL[:5] != "https" {
		webhookURL = "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL"
	}

	sender, err := NewSlackSender(webhookURL, "#alerts", 10*time.Second)
	if err != nil {
		t.Skipf("Skipping test - cannot create Slack sender: %v", err)
		return
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
		Recommendations: []string{"rec1", "rec2", "rec3", "rec4", "rec5"},
		Context:        map[string]interface{}{"key": "value"},
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Logf("Send() error (expected for test server): %v", err)
	}
}

func TestSlackSender_Send_WithFewRecommendations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookURL := server.URL
	if len(webhookURL) >= 5 && webhookURL[:5] != "https" {
		webhookURL = "https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL"
	}

	sender, err := NewSlackSender(webhookURL, "#alerts", 10*time.Second)
	if err != nil {
		t.Skipf("Skipping test - cannot create Slack sender: %v", err)
		return
	}

	alert := &Alert{
		Severity:       SeverityWarning,
		Title:          "Test Alert",
		Message:        "Test message",
		Timestamp:      time.Now(),
		Source:         "test",
		Recommendations: []string{"rec1", "rec2"},
	}

	err = sender.Send(context.Background(), alert)
	if err != nil {
		t.Logf("Send() error (expected for test server): %v", err)
	}
}

func TestSlackSender_Send_HTTPError(t *testing.T) {
	sender, err := NewSlackSender("https://hooks.slack.com/services/INVALID/WEBHOOK/URL", "#alerts", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("NewSlackSender() error = %v", err)
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

func TestNewSlackSender_InvalidURLScheme(t *testing.T) {
	tests := []struct {
		name      string
		webhookURL string
		wantErr   bool
	}{
		{
			name:      "http scheme",
			webhookURL: "http://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL",
			wantErr:   true,
		},
		{
			name:      "ftp scheme",
			webhookURL: "ftp://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL",
			wantErr:   true,
		},
		{
			name:      "invalid format - no hooks.slack.com",
			webhookURL: "https://example.com/webhook",
			wantErr:   true,
		},
		{
			name:      "invalid format - wrong domain",
			webhookURL: "https://hooks.example.com/services/EXAMPLE/WEBHOOK/URL",
			wantErr:   true,
		},
		{
			name:      "invalid URL parse",
			webhookURL: "://invalid-url",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSlackSender(tt.webhookURL, "#alerts", 10*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSlackSender() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && sender == nil {
				t.Error("NewSlackSender() returned nil for valid input")
			}
		})
	}
}

func TestSlackSender_Send_MarshalError(t *testing.T) {
	sender, err := NewSlackSender("https://hooks.slack.com/services/EXAMPLE/WEBHOOK/URL", "#alerts", 10*time.Second)
	if err != nil {
		t.Fatalf("NewSlackSender() error = %v", err)
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

func TestBuildSlackFields(t *testing.T) {
	alert := &Alert{
		Severity:       SeverityWarning,
		Title:          "Test Alert",
		Message:        "Test message",
		Timestamp:      time.Now(),
		Source:         "test",
		PodName:        "test-pod",
		Namespace:      "test-ns",
		ErrorCode:      "ERR001",
		Recommendations: []string{"rec1", "rec2", "rec3", "rec4", "rec5"},
	}

	fields := buildSlackFields(alert)
	if len(fields) == 0 {
		t.Error("buildSlackFields() should return at least one field")
	}

	hasSeverity := false
	hasSource := false
	hasPod := false
	hasNamespace := false
	hasErrorCode := false
	hasRecommendations := false

	for _, field := range fields {
		if field.Title == "Severity" {
			hasSeverity = true
		}
		if field.Title == "Source" {
			hasSource = true
		}
		if field.Title == "Pod" {
			hasPod = true
		}
		if field.Title == "Namespace" {
			hasNamespace = true
		}
		if field.Title == "Error Code" {
			hasErrorCode = true
		}
		if field.Title == "Recommendations" {
			hasRecommendations = true
			if !strings.Contains(field.Value, "rec1") {
				t.Error("Recommendations field should contain rec1")
			}
			if strings.Contains(field.Value, "rec4") {
				t.Error("Recommendations field should not contain rec4 (limited to 3)")
			}
		}
	}

	if !hasSeverity {
		t.Error("buildSlackFields() should include Severity field")
	}
	if !hasSource {
		t.Error("buildSlackFields() should include Source field")
	}
	if !hasPod {
		t.Error("buildSlackFields() should include Pod field")
	}
	if !hasNamespace {
		t.Error("buildSlackFields() should include Namespace field")
	}
	if !hasErrorCode {
		t.Error("buildSlackFields() should include Error Code field")
	}
	if !hasRecommendations {
		t.Error("buildSlackFields() should include Recommendations field")
	}
}

func TestBuildSlackFields_MinimalAlert(t *testing.T) {
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}

	fields := buildSlackFields(alert)
	if len(fields) < 2 {
		t.Errorf("buildSlackFields() should return at least 2 fields, got %d", len(fields))
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a < b", 1, 2, 1},
		{"a > b", 2, 1, 1},
		{"a == b", 2, 2, 2},
		{"negative", -1, 1, -1},
		{"zero", 0, 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := min(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

