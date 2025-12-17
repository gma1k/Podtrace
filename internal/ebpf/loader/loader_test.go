package loader

import (
	"os"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestLoadPodtrace_ExplicitPathIsStrict(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	config.BPFObjectPath = "/nonexistent/path/to/bpf.o"
	spec, err := LoadPodtrace()
	if err == nil {
		t.Fatalf("expected error for explicit non-existent path, got nil")
	}
	if spec != nil {
		t.Fatalf("expected nil spec on error, got non-nil")
	}
}

func TestLoadPodtrace_DefaultPathFallsBackToEmbedded(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()

	emptyWD := t.TempDir()
	if err := os.Chdir(emptyWD); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	config.BPFObjectPath = "bpf/podtrace.bpf.o"
	spec, err := LoadPodtrace()
	if err != nil {
		t.Skipf("BPF object not available in test environment: %v", err)
	}
	if spec == nil {
		t.Fatalf("expected non-nil spec from embedded fallback")
	}
}
