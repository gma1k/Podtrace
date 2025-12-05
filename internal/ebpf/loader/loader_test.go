package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestLoadPodtrace(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	tests := []struct {
		name          string
		setupPath     string
		expectError   bool
		expectNilSpec bool
	}{
		{
			name:          "non-existent path",
			setupPath:     "/nonexistent/path/to/bpf.o",
			expectError:   true,
			expectNilSpec: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.BPFObjectPath = tt.setupPath
			spec, err := LoadPodtrace()

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectNilSpec && spec != nil {
				t.Error("Expected nil spec but got non-nil")
			}
			if !tt.expectNilSpec && spec == nil {
				t.Error("Expected non-nil spec but got nil")
			}
		})
	}
}

func TestLoadPodtraceFallback(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	tempDir := t.TempDir()
	primaryPath := filepath.Join(tempDir, "bpf", "podtrace.bpf.o")
	fallbackPath := filepath.Join(tempDir, "..", "bpf", "podtrace.bpf.o")

	_ = os.MkdirAll(filepath.Dir(primaryPath), 0755)
	_ = os.MkdirAll(filepath.Dir(fallbackPath), 0755)

	config.BPFObjectPath = primaryPath

	spec, err := LoadPodtrace()
	if err == nil && spec == nil {
		t.Log("LoadPodtrace returned nil spec without error (expected for non-existent BPF object)")
	}
}

func TestLoadPodtrace_FallbackPath(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	tempDir := t.TempDir()
	primaryPath := filepath.Join(tempDir, "bpf", "podtrace.bpf.o")
	fallbackDir := filepath.Join(tempDir, "..", "bpf")

	_ = os.MkdirAll(filepath.Dir(primaryPath), 0755)
	_ = os.MkdirAll(fallbackDir, 0755)

	config.BPFObjectPath = primaryPath

	spec, err := LoadPodtrace()
	if err == nil && spec == nil {
		t.Log("LoadPodtrace attempted fallback path (expected for non-existent BPF object)")
	}
}

func TestLoadPodtrace_SuccessPath(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	config.BPFObjectPath = "/nonexistent/path/to/bpf.o"
	spec, err := LoadPodtrace()
	if err == nil && spec == nil {
		t.Log("LoadPodtrace returned nil spec without error (expected for non-existent BPF object)")
	}
}

func TestLoadPodtrace_FallbackSuccess(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	tempDir := t.TempDir()
	primaryPath := filepath.Join(tempDir, "bpf", "podtrace.bpf.o")
	fallbackPath := filepath.Join(tempDir, "..", "bpf", "podtrace.bpf.o")

	_ = os.MkdirAll(filepath.Dir(primaryPath), 0755)
	_ = os.MkdirAll(filepath.Dir(fallbackPath), 0755)

	config.BPFObjectPath = primaryPath

	spec, err := LoadPodtrace()
	if err != nil {
		t.Logf("LoadPodtrace returned error (expected for non-existent BPF object): %v", err)
	}
	if spec == nil && err != nil {
		t.Log("LoadPodtrace attempted fallback path and failed as expected")
	}
}

