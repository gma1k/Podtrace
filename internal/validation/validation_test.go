package validation

import (
	"os"
	"path/filepath"
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
		{"valid crypto", "crypto", false},
		{"valid usdt", "usdt", false},
		{"valid multiple", "dns,net,fs,crypto,usdt", false},
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
		{"NUL terminates the comm", "nginx\x00worker", "nginx"},
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
		{"with comma", "nginx,worker", "nginx,worker"},
		{"with quote", `nginx"worker`, `nginx"worker`},
		{"with newline", "nginx\nworker", "nginx\nworker"},
		{"empty", "", ""},
		{"formula equals", "=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"formula plus", "+1+1", "'+1+1"},
		{"formula minus", "-2+3", "'-2+3"},
		{"formula at", "@SUM(A1)", "'@SUM(A1)"},
		{"formula leading tab", "\t=1+1", "'\t=1+1"},
		{"formula with comma", "=1,2", "'=1,2"},
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

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		basePath string
		wantErr  bool
	}{
		{
			name:     "valid path within base",
			path:     "/base/subdir/file",
			basePath: "/base",
			wantErr:  false,
		},
		{
			name:     "path with traversal",
			path:     "/base/../etc/passwd",
			basePath: "/base",
			wantErr:  true,
		},
		{
			name:     "path outside base",
			path:     "/etc/passwd",
			basePath: "/base",
			wantErr:  true,
		},
		{
			name:     "empty path",
			path:     "",
			basePath: "/base",
			wantErr:  true,
		},
		{
			name:     "exact base path",
			path:     "/base",
			basePath: "/base",
			wantErr:  false,
		},
		{
			name:     "filename containing dot-dot is not traversal",
			path:     "/base/release-1..2/file",
			basePath: "/base",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path, tt.basePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePath_SymlinkEscape: a symlink that is lexically inside basePath
// but resolves outside must be rejected; a symlink that stays inside is fine.
func TestValidatePath_SymlinkEscape(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{base, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	escape := filepath.Join(base, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := ValidatePath(escape, base); err == nil {
		t.Error("symlink escaping basePath must be rejected")
	}

	inside := filepath.Join(base, "sub")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "inlink")
	if err := os.Symlink(inside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := ValidatePath(link, base); err != nil {
		t.Errorf("symlink staying inside basePath must be accepted, got %v", err)
	}
}

func TestValidateContainerPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		containerID string
		wantErr     bool
	}{
		{
			name:        "valid path",
			path:        "file.txt",
			containerID: "abc123def456",
			wantErr:     false,
		},
		{
			name:        "path with traversal",
			path:        "../etc/passwd",
			containerID: "abc123def456",
			wantErr:     true,
		},
		{
			name:        "path with slash",
			path:        "/etc/passwd",
			containerID: "abc123def456",
			wantErr:     true,
		},
		{
			name:        "invalid container ID",
			path:        "file.txt",
			containerID: "../etc",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainerPath(tt.path, tt.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContainerPath() error = %v, wantErr %v", err, tt.wantErr)
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
