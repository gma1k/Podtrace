package validation

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePodName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid pod name", "my-pod-123", false},
		{"valid with numbers", "pod123", false},
		{"valid single char", "a", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 64)), true},
		{"starts with dash", "-pod", true},
		{"ends with dash", "pod-", true},
		{"uppercase", "MyPod", true},
		{"with underscore", "my_pod", true},
		{"max length valid", "a" + strings.Repeat("b", 61), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePodName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePodName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNamespace(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid namespace", "default", false},
		{"valid with numbers", "namespace123", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 254)), true},
		{"starts with dash", "-namespace", true},
		{"ends with dash", "namespace-", true},
		{"uppercase", "Default", true},
		{"max length valid", "a" + strings.Repeat("b", 251), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNamespace(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNamespace() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateContainerName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid container", "my-container", false},
		{"empty (allowed)", "", false},
		{"with underscore", "my_container", false},
		{"with dot", "my.container", false},
		{"too long", string(make([]byte, 64)), true},
		{"starts with dash", "-container", true},
		{"ends with dash", "container-", true},
		{"uppercase", "Container", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainerName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContainerName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateExportFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid json", "json", false},
		{"valid csv", "csv", false},
		{"valid JSON uppercase", "JSON", false},
		{"valid CSV uppercase", "CSV", false},
		{"empty (allowed)", "", false},
		{"invalid format", "xml", true},
		{"invalid format", "yaml", true},
		{"too long", string(make([]byte, 11)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExportFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExportFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEventFilter(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid dns", "dns", false},
		{"valid net", "net", false},
		{"valid fs", "fs", false},
		{"valid cpu", "cpu", false},
		{"valid proc", "proc", false},
		{"valid multiple", "dns,net,fs", false},
		{"valid with spaces", "dns, net, fs", false},
		{"empty (allowed)", "", false},
		{"invalid filter", "invalid", true},
		{"mixed valid invalid", "dns,invalid", true},
		{"too long", string(make([]byte, 101)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEventFilter(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEventFilter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePID(t *testing.T) {
	tests := []struct {
		name string
		pid  uint32
		want bool
	}{
		{"valid pid", 1234, true},
		{"pid 1", 1, true},
		{"pid 0", 0, false},
		{"max valid", 4194303, true},
		{"too large", 4194304, false},
		{"very large", 9999999, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidatePID(tt.pid); got != tt.want {
				t.Errorf("ValidatePID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeProcessName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal name", "nginx", "nginx"},
		{"with spaces", "nginx worker", "nginx worker"},
		{"with percent", "nginx%20worker", "nginx20worker"},
		{"with newline", "nginx\nworker", "nginxworker"},
		{"with control chars", "nginx\x00worker", "nginxworker"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
		{"unicode", "nginx-中文", "nginx-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeProcessName(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeProcessName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateContainerID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid 64 char", "a" + string(make([]byte, 63)), false}, // Need lowercase hex
		{"valid 12 char", "123456789abc", true},
		{"valid 20 char", "12345678901234567890", true},
		{"empty", "", false},
		{"too short", "123", false},
		{"too long", string(make([]byte, 129)), false},
		{"with path traversal", "../container", false},
		{"with slash", "container/id", false},
		{"with dots", "container..id", false},
		{"invalid chars", "container-id!", false},
		{"uppercase hex", "ABCDEF123456", false}, // Container IDs are lowercase
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateContainerID(tt.input)
			if result != tt.expected {
				t.Errorf("ValidateContainerID() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSanitizeCSVField(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal field", "nginx", "nginx"},
		{"with comma", "nginx,worker", `"nginx,worker"`},
		{"with quote", `nginx"worker`, `"nginx""worker"`},
		{"with newline", "nginx\nworker", `"nginx
worker"`},
		{"with carriage return", "nginx\rworker", `"nginx` + "\r" + `worker"`}, // \r is quoted
		{"empty", "", ""},
		{"all special chars", `a,b"c\nd`, `"a,b""c\nd"`}, // Backslash is preserved
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeCSVField(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeCSVField() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateErrorRateThreshold(t *testing.T) {
	tests := []struct {
		name    string
		input   float64
		wantErr bool
	}{
		{"valid 0", 0, false},
		{"valid 50", 50, false},
		{"valid 100", 100, false},
		{"negative", -1, true},
		{"too large", 101, true},
		{"valid 10", 10, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateErrorRateThreshold(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateErrorRateThreshold() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRTTThreshold(t *testing.T) {
	tests := []struct {
		name    string
		input   float64
		wantErr bool
	}{
		{"valid 0", 0, false},
		{"valid 100", 100, false},
		{"valid large", 1000, false},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRTTThreshold(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRTTThreshold() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFSThreshold(t *testing.T) {
	tests := []struct {
		name    string
		input   float64
		wantErr bool
	}{
		{"valid 0", 0, false},
		{"valid 10", 10, false},
		{"valid large", 1000, false},
		{"negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFSThreshold(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFSThreshold() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDiagnoseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   time.Duration
		wantErr bool
	}{
		{"valid 1s", time.Second, false},
		{"valid 1m", time.Minute, false},
		{"valid 1h", time.Hour, false},
		{"valid 24h", 24 * time.Hour, false},
		{"zero", 0, true},
		{"negative", -time.Second, true},
		{"too long", 25 * time.Hour, true},
		{"valid 23h59m", 23*time.Hour + 59*time.Minute, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDiagnoseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDiagnoseDuration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
