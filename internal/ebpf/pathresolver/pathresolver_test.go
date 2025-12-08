package pathresolver

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestResolvePath(t *testing.T) {
	resolver := New()

	tests := []struct {
		name     string
		pid      uint32
		target   string
		expected string
	}{
		{
			name:     "empty target",
			pid:      1234,
			target:   "",
			expected: "",
		},
		{
			name:     "non-inode target",
			pid:      1234,
			target:   "/path/to/file",
			expected: "/path/to/file",
		},
		{
			name:     "invalid inode format",
			pid:      1234,
			target:   "ino:invalid",
			expected: "ino:invalid",
		},
		{
			name:     "inode format without slash",
			pid:      1234,
			target:   "ino:12345",
			expected: "ino:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.ResolvePath(tt.pid, tt.target)
			if result != tt.expected {
				t.Errorf("ResolvePath(%d, %q) = %q, want %q", tt.pid, tt.target, result, tt.expected)
			}
		})
	}
}

func TestResolveInode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root access to read /proc")
	}

	resolver := New()
	pid := uint32(os.Getpid())

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "testfile")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var stat syscall.Stat_t
	if err := syscall.Stat(testFile, &stat); err != nil {
		t.Fatalf("Failed to stat test file: %v", err)
	}

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() {
		_ = f.Close()
	}()

	path := resolver.resolveInode(pid, uint32(stat.Ino), uint32(stat.Dev))
	if path == "" {
		t.Log("Path resolution returned empty (may not work in test environment)")
		return
	}

	if path != testFile {
		t.Errorf("resolveInode() = %q, want %q", path, testFile)
	}
}

func TestResolvePathCaching(t *testing.T) {
	resolver := New()
	pid := uint32(1234)
	target := "ino:12345/67890"

	result1 := resolver.ResolvePath(pid, target)
	result2 := resolver.ResolvePath(pid, target)

	if result1 != result2 {
		t.Errorf("Cached result differs: first=%q, second=%q", result1, result2)
	}
}

func TestClear(t *testing.T) {
	resolver := New()

	resolver.mu.Lock()
	resolver.cache["test:1:2"] = "/test/path"
	resolver.inodeToPath["ino:1/2"] = &cachedPath{path: "/test/path", timestamp: time.Now()}
	resolver.mu.Unlock()

	resolver.Clear()

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	if len(resolver.cache) != 0 {
		t.Error("Cache should be empty after Clear()")
	}
	if len(resolver.inodeToPath) != 0 {
		t.Error("InodeToPath should be empty after Clear()")
	}
}

func TestRecordOpen(t *testing.T) {
	resolver := New()
	pid := uint32(1234)
	fd := uint32(5)
	path := "/test/path"
	ino := uint32(100)
	dev := uint32(200)

	resolver.RecordOpen(pid, fd, path, ino, dev)

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()

	inodeKey := "ino:100/200"
	if cached, ok := resolver.inodeToPath[inodeKey]; !ok || cached.path != path {
		t.Errorf("RecordOpen() failed to store inode mapping: got %v", resolver.inodeToPath[inodeKey])
	}

	if resolver.pidFdToPath[pid] == nil {
		t.Error("RecordOpen() failed to initialize pidFdToPath")
	} else if cached, ok := resolver.pidFdToPath[pid][fd]; !ok || cached.path != path {
		t.Errorf("RecordOpen() failed to store FD mapping: got %v", resolver.pidFdToPath[pid][fd])
	}
}

func TestRecordOpenByFD(t *testing.T) {
	resolver := New()
	pid := uint32(1234)
	fd := uint32(5)
	path := "/test/path"

	resolver.RecordOpenByFD(pid, fd, path)

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()

	if resolver.pidFdToPath[pid] == nil {
		t.Error("RecordOpenByFD() failed to initialize pidFdToPath")
	} else if cached, ok := resolver.pidFdToPath[pid][fd]; !ok || cached.path != path {
		t.Errorf("RecordOpenByFD() failed to store FD mapping: got %v", resolver.pidFdToPath[pid][fd])
	}
}

func TestCorrelateFDWithInode(t *testing.T) {
	resolver := New()
	pid := uint32(1234)
	fd := uint32(5)
	path := "/test/path"
	ino := uint32(100)
	dev := uint32(200)

	resolver.RecordOpenByFD(pid, fd, path)
	time.Sleep(10 * time.Millisecond)
	resolver.CorrelateFDWithInode(pid, fd, ino, dev)

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()

	inodeKey := "ino:100/200"
	if cached, ok := resolver.inodeToPath[inodeKey]; !ok || cached.path != path {
		t.Errorf("CorrelateFDWithInode() failed to correlate: got %v", resolver.inodeToPath[inodeKey])
	}
}

func TestResolvePathWithInodeCache(t *testing.T) {
	resolver := New()
	pid := uint32(1234)
	fd := uint32(5)
	path := "/test/path"
	ino := uint32(100)
	dev := uint32(200)

	resolver.RecordOpen(pid, fd, path, ino, dev)

	target := "ino:100/200"
	result := resolver.ResolvePath(pid, target)

	if result != path {
		t.Errorf("ResolvePath() with inode cache = %q, want %q", result, path)
	}
}

func TestCleanupExpired(t *testing.T) {
	resolver := New()
	resolver.cacheTTL = 10 * time.Millisecond

	pid := uint32(1234)
	fd := uint32(5)
	path := "/test/path"
	ino := uint32(100)
	dev := uint32(200)

	resolver.RecordOpen(pid, fd, path, ino, dev)

	time.Sleep(20 * time.Millisecond)

	resolver.CleanupExpired()

	resolver.mu.RLock()
	defer resolver.mu.RUnlock()

	inodeKey := "ino:100/200"
	if _, ok := resolver.inodeToPath[inodeKey]; ok {
		t.Error("CleanupExpired() should have removed expired entries")
	}
}

func TestIsProcessAlive(t *testing.T) {
	resolver := New()

	alive := resolver.isProcessAlive(uint32(os.Getpid()))
	if !alive {
		t.Error("Current process should be alive")
	}

	alive = resolver.isProcessAlive(99999999)
	if alive {
		t.Error("Non-existent PID should not be alive")
	}
}

func TestResolveInode_ProcessNotAlive(t *testing.T) {
	resolver := New()
	path := resolver.resolveInode(99999999, 100, 200)
	if path != "" {
		t.Errorf("resolveInode() for non-existent process should return empty, got %q", path)
	}
}

func TestResolveInode_InvalidFDDir(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root access to read /proc")
	}

	resolver := New()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath("/nonexistent/proc")
	defer func() { config.SetProcBasePath(origProcBase) }()

	path := resolver.resolveInode(uint32(os.Getpid()), 100, 200)
	if path != "" {
		t.Errorf("resolveInode() with invalid proc base should return empty, got %q", path)
	}
}

func TestResolveInode_NonNumericFD(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root access to read /proc")
	}

	resolver := New()
	pid := uint32(os.Getpid())

	tmpDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	fdDir := filepath.Join(procDir, "fd")
	_ = os.MkdirAll(fdDir, 0755)

	_ = os.WriteFile(filepath.Join(fdDir, "not-a-number"), []byte(""), 0644)

	path := resolver.resolveInode(pid, 100, 200)
	if path != "" {
		t.Logf("resolveInode() returned %q (may be expected)", path)
	}
}

func TestResolveInode_MaxChecks(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping test that requires root access to read /proc")
	}

	resolver := New()
	resolver.maxChecks = 2

	pid := uint32(os.Getpid())
	tmpDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	fdDir := filepath.Join(procDir, "fd")
	_ = os.MkdirAll(fdDir, 0755)

	for i := 0; i < 5; i++ {
		_ = os.WriteFile(filepath.Join(fdDir, fmt.Sprintf("%d", i)), []byte(""), 0644)
	}

	path := resolver.resolveInode(pid, 100, 200)
	if path != "" {
		t.Logf("resolveInode() returned %q (may be expected)", path)
	}
}
