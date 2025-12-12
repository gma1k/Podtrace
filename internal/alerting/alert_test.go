package alerting

import (
	"testing"
	"time"
)

func TestAlert_Validate(t *testing.T) {
	tests := []struct {
		name    string
		alert   *Alert
		wantErr bool
	}{
		{
			name:    "nil alert",
			alert:   nil,
			wantErr: true,
		},
		{
			name: "valid alert",
			alert: &Alert{
				Severity:  SeverityWarning,
				Title:     "Test Alert",
				Message:   "Test message",
				Timestamp: time.Now(),
				Source:    "test",
			},
			wantErr: false,
		},
		{
			name: "missing severity",
			alert: &Alert{
				Title:     "Test Alert",
				Message:   "Test message",
				Timestamp: time.Now(),
				Source:    "test",
			},
			wantErr: true,
		},
		{
			name: "missing title",
			alert: &Alert{
				Severity:  SeverityWarning,
				Message:   "Test message",
				Timestamp: time.Now(),
				Source:    "test",
			},
			wantErr: true,
		},
		{
			name: "missing message",
			alert: &Alert{
				Severity:  SeverityWarning,
				Title:     "Test Alert",
				Timestamp: time.Now(),
				Source:    "test",
			},
			wantErr: true,
		},
		{
			name: "missing timestamp",
			alert: &Alert{
				Severity: SeverityWarning,
				Title:    "Test Alert",
				Message:  "Test message",
				Source:   "test",
			},
			wantErr: true,
		},
		{
			name: "missing source",
			alert: &Alert{
				Severity:  SeverityWarning,
				Title:     "Test Alert",
				Message:   "Test message",
				Timestamp: time.Now(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.alert.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Alert.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAlert_Sanitize(t *testing.T) {
	longString := make([]byte, 300)
	for i := range longString {
		longString[i] = 'a'
	}
	alert := &Alert{
		Title:     string(longString),
		Message:   string(make([]byte, 1100)),
		PodName:   string(make([]byte, 300)),
		Namespace: string(make([]byte, 300)),
		Source:    string(make([]byte, 150)),
		ErrorCode: string(make([]byte, 100)),
		Recommendations: []string{
			string(make([]byte, 600)),
			string(make([]byte, 600)),
		},
	}
	alert.Sanitize()
	if len(alert.Title) > 256 {
		t.Errorf("Title not sanitized: length %d", len(alert.Title))
	}
	if len(alert.Message) > 1024 {
		t.Errorf("Message not sanitized: length %d", len(alert.Message))
	}
	if len(alert.PodName) > 256 {
		t.Errorf("PodName not sanitized: length %d", len(alert.PodName))
	}
	if len(alert.Namespace) > 256 {
		t.Errorf("Namespace not sanitized: length %d", len(alert.Namespace))
	}
	if len(alert.Source) > 128 {
		t.Errorf("Source not sanitized: length %d", len(alert.Source))
	}
	if len(alert.ErrorCode) > 64 {
		t.Errorf("ErrorCode not sanitized: length %d", len(alert.ErrorCode))
	}
	if len(alert.Recommendations) > 10 {
		t.Errorf("Recommendations not sanitized: length %d", len(alert.Recommendations))
	}
	for i, rec := range alert.Recommendations {
		if len(rec) > 512 {
			t.Errorf("Recommendation %d not sanitized: length %d", i, len(rec))
		}
	}
}

func TestAlert_Key(t *testing.T) {
	alert1 := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Source:    "test",
		PodName:   "pod1",
		Namespace: "ns1",
	}
	alert2 := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Source:    "test",
		PodName:   "pod1",
		Namespace: "ns1",
	}
	alert3 := &Alert{
		Severity:  SeverityCritical,
		Title:     "Test",
		Source:    "test",
		PodName:   "pod1",
		Namespace: "ns1",
	}
	key1 := alert1.Key()
	key2 := alert2.Key()
	key3 := alert3.Key()
	if key1 != key2 {
		t.Errorf("Same alerts should have same key: %s != %s", key1, key2)
	}
	if key1 == key3 {
		t.Errorf("Different alerts should have different keys")
	}
	if key1 == "" {
		t.Errorf("Key should not be empty")
	}
}

func TestMapResourceAlertLevel(t *testing.T) {
	tests := []struct {
		level    uint32
		expected AlertSeverity
	}{
		{0, SeverityError},
		{1, SeverityWarning},
		{2, SeverityCritical},
		{3, SeverityFatal},
		{4, SeverityError},
	}
	for _, tt := range tests {
		result := MapResourceAlertLevel(tt.level)
		if result != tt.expected {
			t.Errorf("MapResourceAlertLevel(%d) = %v, want %v", tt.level, result, tt.expected)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected AlertSeverity
	}{
		{"fatal", SeverityFatal},
		{"critical", SeverityCritical},
		{"warning", SeverityWarning},
		{"error", SeverityError},
		{"unknown", SeverityError},
		{"", SeverityError},
	}
	for _, tt := range tests {
		result := ParseSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity AlertSeverity
		expected int
	}{
		{SeverityFatal, 4},
		{SeverityCritical, 3},
		{SeverityWarning, 2},
		{SeverityError, 1},
		{AlertSeverity("unknown"), 0},
	}
	for _, tt := range tests {
		result := SeverityLevel(tt.severity)
		if result != tt.expected {
			t.Errorf("SeverityLevel(%v) = %d, want %d", tt.severity, result, tt.expected)
		}
	}
}

