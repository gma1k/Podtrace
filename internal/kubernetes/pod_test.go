package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestFindCgroupPath_NotFound(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	if path, err := findCgroupPath("nonexistent"); err == nil || path != "" {
		t.Fatalf("expected error and empty path for missing cgroup, got path=%q err=%v", path, err)
	}
}

func TestFindCgroupPath_Found(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	if err := os.MkdirAll(kubepodsSlice, 0o755); err != nil {
		t.Fatalf("failed to create kubepods.slice: %v", err)
	}

	containerID := "abcdef1234567890"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	if path, err := findCgroupPath(containerID); err != nil || path == "" {
		t.Fatalf("expected to find cgroup path, got path=%q err=%v", path, err)
	}
}
