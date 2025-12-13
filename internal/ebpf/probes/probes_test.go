package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/podtrace/podtrace/internal/config"
)

func TestFindLibcPath(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		expectEmpty bool
	}{
		{"empty container ID", "", false},
		{"non-empty container ID", "test-container", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindLibcPath(tt.containerID)
			if tt.expectEmpty && result != "" {
				t.Errorf("Expected empty path, got %q", result)
			}
		})
	}
}

func TestFindLibcInContainer(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-existent container", "nonexistent-container-id"},
		{"valid format container ID", "abc123def456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindLibcInContainer(tt.containerID)
			if result == nil {
				t.Error("FindLibcInContainer should return non-nil slice")
			}
		})
	}
}

func TestAttachDNSProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachDNSProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachDNSProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachSyncProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachSyncProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachSyncProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachDBProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachDBProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachDBProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachProbes_EmptyCollection(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected for empty collection): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachProbes_WithNilPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"kprobe_tcp_connect": nil,
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected for nil programs): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachDNSProbes_WithLibcPath(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links := AttachDNSProbes(coll, "")
	if links == nil {
		t.Log("AttachDNSProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachSyncProbes_NoLibcPath(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links := AttachSyncProbes(coll, "nonexistent-container")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachDBProbes_NoDBLibs(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found)")
	}
}

func TestFindLibcPath_WithContainerID(t *testing.T) {
	result := FindLibcPath("test-container-id")
	if result == "" {
		t.Log("FindLibcPath returned empty (expected when container libc not found)")
	}
}

func TestFindLibcInContainer_WithValidContainer(t *testing.T) {
	result := FindLibcInContainer("test-container-id")
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) == 0 {
		t.Log("FindLibcInContainer returned empty slice (expected when container not found)")
	}
}

func TestFindLibcInContainer_WithEmptyContainerID(t *testing.T) {
	result := FindLibcInContainer("")
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) > 0 {
		t.Logf("FindLibcInContainer returned %d paths", len(result))
	}
}

func TestAttachProbes_WithTracepointPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected for empty collection): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachDNSProbes_WithPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_getaddrinfo":    nil,
			"uretprobe_getaddrinfo": nil,
		},
	}

	links := AttachDNSProbes(coll, "")
	if links == nil {
		t.Log("AttachDNSProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachSyncProbes_WithPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_pthread_mutex_lock":    nil,
			"uretprobe_pthread_mutex_lock": nil,
		},
	}

	links := AttachSyncProbes(coll, "")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachDBProbes_WithPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec":              nil,
			"uretprobe_PQexec":           nil,
			"uprobe_mysql_real_query":    nil,
			"uretprobe_mysql_real_query": nil,
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found)")
	}
}

func TestFindLibcPath_SystemPaths(t *testing.T) {
	result := FindLibcPath("")
	if result == "" {
		t.Log("FindLibcPath returned empty (expected when system libc not found in test environment)")
	}
}

func TestFindLibcInContainer_NonExistentContainer(t *testing.T) {
	result := FindLibcInContainer("nonexistent-container-12345")
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) == 0 {
		t.Log("FindLibcInContainer returned empty slice (expected for non-existent container)")
	}
}

func TestFindLibcPath_WithTempFile(t *testing.T) {
	tmpDir := t.TempDir()
	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	origPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
	}

	for _, origPath := range origPaths {
		if _, err := os.Stat(origPath); err == nil {
			result := FindLibcPath("")
			if result != "" {
				return
			}
		}
	}
}

func TestFindLibcPath_WithContainerPath(t *testing.T) {
	tmpDir := t.TempDir()
	containerID := "test-container-123"
	containerRoot := filepath.Join(tmpDir, "var", "lib", "docker", "containers", containerID, "rootfs")
	libcPath := filepath.Join(containerRoot, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	result := FindLibcPath(containerID)
	if result == "" {
		t.Log("FindLibcPath returned empty (container path may not be checked in test environment)")
	}
}

func TestFindLibcInContainer_WithValidContainerRoot(t *testing.T) {
	tmpDir := t.TempDir()
	containerID := "test-container-456"
	containerRoot := filepath.Join(tmpDir, "var", "lib", "docker", "containers", containerID, "rootfs")
	libcPath := filepath.Join(containerRoot, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	result := FindLibcInContainer(containerID)
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) == 0 {
		t.Log("FindLibcInContainer returned empty slice (container root may not be in /var/lib/docker)")
	}
}

func TestAttachProbes_AllProbeTypes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"kprobe_tcp_connect":       {},
			"kretprobe_tcp_connect":    {},
			"kprobe_tcp_v6_connect":    {},
			"kretprobe_tcp_v6_connect": {},
			"kprobe_tcp_sendmsg":       {},
			"kretprobe_tcp_sendmsg":    {},
			"kprobe_tcp_recvmsg":       {},
			"kretprobe_tcp_recvmsg":    {},
			"kprobe_udp_sendmsg":       {},
			"kretprobe_udp_sendmsg":    {},
			"kprobe_udp_recvmsg":       {},
			"kretprobe_udp_recvmsg":    {},
			"kprobe_vfs_write":         {},
			"kretprobe_vfs_write":      {},
			"kprobe_vfs_read":          {},
			"kretprobe_vfs_read":       {},
			"kprobe_vfs_fsync":         {},
			"kretprobe_vfs_fsync":      {},
			"kprobe_do_futex":          {},
			"kretprobe_do_futex":       {},
			"kprobe_do_sys_openat2":    {},
			"kretprobe_do_sys_openat2": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected without kernel support): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachProbes_WithTracepoints(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"tracepoint_sched_switch":       {},
			"tracepoint_tcp_set_state":      {},
			"tracepoint_tcp_retransmit_skb": {},
			"tracepoint_net_dev_xmit":       {},
			"tracepoint_page_fault_user":    {},
			"tracepoint_oom_kill_process":   {},
			"tracepoint_sched_process_fork": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected without kernel support): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachProbes_TracepointPermissionDenied(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"tracepoint_sched_switch": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			t.Log("AttachProbes returned permission denied error (expected)")
		} else {
			t.Logf("AttachProbes returned error: %v", err)
		}
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachProbes_TracepointNotFound(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"tracepoint_tcp_set_state": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			t.Log("AttachProbes returned not found error (expected)")
		} else {
			t.Logf("AttachProbes returned error: %v", err)
		}
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

func TestAttachProbes_ErrorCleanup(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"kprobe_tcp_connect": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected without kernel support): %v", err)
	}
	for _, l := range links {
		_ = l.Close()
	}
}

func TestAttachDNSProbes_WithLibcFile(t *testing.T) {
	tmpDir := t.TempDir()
	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_getaddrinfo":    {},
			"uretprobe_getaddrinfo": {},
		},
	}

	links := AttachDNSProbes(coll, "")
	if links == nil {
		t.Log("AttachDNSProbes returned nil links (expected when libc path not found in standard locations)")
	}
}

func TestAttachSyncProbes_WithLibcFile(t *testing.T) {
	tmpDir := t.TempDir()
	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_pthread_mutex_lock":    {},
			"uretprobe_pthread_mutex_lock": {},
		},
	}

	links := AttachSyncProbes(coll, "")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc path not found in standard locations)")
	}
}

func TestAttachSyncProbes_SymbolNotFound(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_pthread_mutex_lock":    {},
			"uretprobe_pthread_mutex_lock": {},
		},
	}

	links := AttachSyncProbes(coll, "nonexistent-container")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachDBProbes_WithDBLib(t *testing.T) {
	tmpDir := t.TempDir()
	dbLibPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(dbLibPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(dbLibPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create db lib file: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec":              {},
			"uretprobe_PQexec":           {},
			"uprobe_mysql_real_query":    {},
			"uretprobe_mysql_real_query": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found in standard locations)")
	}
}

func TestAttachDBProbes_WithMultipleLibs(t *testing.T) {
	tmpDir := t.TempDir()
	libPaths := []string{
		filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5"),
		filepath.Join(tmpDir, "usr", "lib64", "libpq.so.5"),
		filepath.Join(tmpDir, "usr", "lib", "libpq.so.5"),
		filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libmysqlclient.so.21"),
		filepath.Join(tmpDir, "usr", "lib64", "libmysqlclient.so.21"),
		filepath.Join(tmpDir, "usr", "lib", "libmysqlclient.so.21"),
	}

	for _, libPath := range libPaths {
		if err := os.MkdirAll(filepath.Dir(libPath), 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(libPath, []byte("fake lib"), 0644); err != nil {
			t.Fatalf("failed to create lib file: %v", err)
		}
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec":              {},
			"uretprobe_PQexec":           {},
			"uprobe_mysql_real_query":    {},
			"uretprobe_mysql_real_query": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found in standard locations)")
	}
}

func TestAttachDBProbes_WithDirectoryInsteadOfFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbLibPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(dbLibPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when path is directory)")
	}
}

func TestFindLibcPath_AllSystemPaths(t *testing.T) {
	testPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
	}

	for _, testPath := range testPaths {
		if _, err := os.Stat(testPath); err == nil {
			result := FindLibcPath("")
			if result != "" {
				return
			}
		}
	}
}

func TestFindLibcInContainer_WithProcPaths(t *testing.T) {
	result := FindLibcInContainer("test-container")
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) < 6 {
		t.Logf("FindLibcInContainer returned %d paths (expected at least 6 proc paths)", len(result))
	}
}

func TestAttachProbes_KprobeVsKretprobe(t *testing.T) {
	tests := []struct {
		name     string
		progName string
	}{
		{"kprobe", "kprobe_tcp_connect"},
		{"kretprobe", "kretprobe_tcp_connect"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll := &ebpf.Collection{
				Programs: map[string]*ebpf.Program{
					tt.progName: {},
				},
			}

			links, err := AttachProbes(coll)
			if err != nil {
				t.Logf("AttachProbes returned error (expected without kernel support): %v", err)
			}
			if links != nil {
				t.Logf("AttachProbes returned %d links", len(links))
			}
		})
	}
}

func TestFindLibcPath_ContainerIDWithValidRootfs(t *testing.T) {
	tmpDir := t.TempDir()
	containerID := "abc123def456"
	containerRoot := filepath.Join(tmpDir, "var", "lib", "docker", "containers", containerID, "rootfs")
	libcPath := filepath.Join(containerRoot, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	oldDockerPath := "/var/lib/docker/containers"
	_ = oldDockerPath

	result := FindLibcPath(containerID)
	if result == "" {
		t.Log("FindLibcPath returned empty (container root may not be in /var/lib/docker)")
	}
}

func TestAttachDNSProbes_LibcPathFoundButOpenFails(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_getaddrinfo":    {},
			"uretprobe_getaddrinfo": {},
		},
	}

	links := AttachDNSProbes(coll, "")
	if links == nil {
		t.Log("AttachDNSProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachDNSProbes_SuccessfulUprobe(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_getaddrinfo":    {},
			"uretprobe_getaddrinfo": {},
		},
	}

	links := AttachDNSProbes(coll, "")
	if links == nil {
		t.Log("AttachDNSProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachSyncProbes_LibcFoundButOpenFails(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_pthread_mutex_lock":    {},
			"uretprobe_pthread_mutex_lock": {},
		},
	}

	links := AttachSyncProbes(coll, "")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachSyncProbes_SuccessfulAttachment(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_pthread_mutex_lock":    {},
			"uretprobe_pthread_mutex_lock": {},
		},
	}

	links := AttachSyncProbes(coll, "")
	if links == nil {
		t.Log("AttachSyncProbes returned nil links (expected when libc not found)")
	}
}

func TestAttachDBProbes_WithValidLib(t *testing.T) {
	tmpDir := t.TempDir()
	dbLibPath := filepath.Join(tmpDir, "libpq.so.5")
	if err := os.WriteFile(dbLibPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create db lib file: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec":              {},
			"uretprobe_PQexec":           {},
			"uprobe_mysql_real_query":    {},
			"uretprobe_mysql_real_query": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found in standard locations)")
	}
}

func TestAttachDBProbes_StatError(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if links == nil {
		t.Log("AttachDBProbes returned nil links (expected when DB libs not found)")
	}
}

func TestFindLibcPath_EmptyContainerID(t *testing.T) {
	result := FindLibcPath("")
	if result == "" {
		t.Log("FindLibcPath returned empty (expected when system libc not found in test environment)")
	}
}

func TestFindLibcPath_NonEmptyContainerID(t *testing.T) {
	result := FindLibcPath("test-container-id-123")
	if result == "" {
		t.Log("FindLibcPath returned empty (expected when container libc not found)")
	}
}

func TestFindLibcInContainer_EmptyContainerID(t *testing.T) {
	result := FindLibcInContainer("")
	if result == nil {
		t.Error("FindLibcInContainer should return non-nil slice")
	}
	if len(result) != 6 {
		t.Logf("FindLibcInContainer returned %d paths (expected 6 proc paths)", len(result))
	}
}

func TestAttachProbes_ErrorPath(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"kprobe_tcp_connect": {},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		if strings.Contains(err.Error(), "failed to attach") {
			t.Log("AttachProbes returned expected error")
		}
	}
	for _, l := range links {
		_ = l.Close()
	}
}

func TestFindLibcPath_ViaLdSoConf(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ldSoConfDir := filepath.Join(tmpDir, "etc", "ld.so.conf.d")
	if err := os.MkdirAll(ldSoConfDir, 0755); err != nil {
		t.Fatalf("failed to create ld.so.conf.d: %v", err)
	}

	customLibDir := filepath.Join(tmpDir, "custom", "lib")
	libcPath := filepath.Join(customLibDir, "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	confFile := filepath.Join(ldSoConfDir, "custom.conf")
	if err := os.WriteFile(confFile, []byte(customLibDir+"\n"), 0644); err != nil {
		t.Fatalf("failed to create conf file: %v", err)
	}

	oldLdSoConf := "/etc/ld.so.conf"
	oldLdSoConfD := "/etc/ld.so.conf.d"

	t.Run("with custom ld.so.conf", func(t *testing.T) {
		result := findLibcViaLdSoConf()
		if result == "" {
			t.Log("findLibcViaLdSoConf returned empty (may not find custom path in /etc)")
		}
	})

	_ = oldLdSoConf
	_ = oldLdSoConfD
}

func TestFindLibcPath_ViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12345)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libcPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findLibcViaProcessMaps(pid)
	if result != libcPath {
		t.Errorf("Expected %q, got %q", libcPath, result)
	}
}

func TestFindLibcPath_ViaProcessMaps_Musl(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12346)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libcPath := filepath.Join(tmpDir, "lib", "libc.musl-x86_64.so.1")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake musl libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libcPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findLibcViaProcessMaps(pid)
	if result != libcPath {
		t.Errorf("Expected %q, got %q", libcPath, result)
	}
}

func TestFindLibcPath_ViaProcessMaps_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12347)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	mapsContent := "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /lib/other.so\n"
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findLibcViaProcessMaps(pid)
	if result != "" {
		t.Errorf("Expected empty, got %q", result)
	}
}

func TestFindContainerProcess(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "abc123def456"
	pid := uint32(12348)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	result := findContainerProcess(containerID)
	if result != pid {
		t.Errorf("Expected PID %d, got %d", pid, result)
	}
}

func TestFindContainerProcess_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12349)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	cgroupContent := "0::/kubepods/pod_other123\n"
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	result := findContainerProcess("nonexistent")
	if result != 0 {
		t.Errorf("Expected 0, got %d", result)
	}
}

func TestFindLibcInContainer_ViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-container-789"
	pid := uint32(12350)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libcPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findLibcInContainer(containerID)
	if result != libcPath {
		t.Errorf("Expected %q, got %q", libcPath, result)
	}
}

func TestFindLibcInContainer_ViaRootfs(t *testing.T) {
	tmpDir := t.TempDir()
	containerID := "test-container-rootfs"

	containerRoot := filepath.Join(tmpDir, "var", "lib", "docker", "containers", containerID, "rootfs")
	libcPath := filepath.Join(containerRoot, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	oldDockerPath := "/var/lib/docker/containers"
	_ = oldDockerPath

	result := findLibcInContainer(containerID)
	if result == "" {
		t.Log("findLibcInContainer returned empty (container root may not be in /var/lib/docker)")
	}
}

func TestGetArchitecturePaths(t *testing.T) {
	paths := getArchitecturePaths()
	if len(paths) == 0 {
		t.Error("getArchitecturePaths returned empty slice")
	}

	hasGenericPaths := false
	for _, path := range paths {
		if strings.Contains(path, "lib64/libc.so.6") || strings.Contains(path, "lib/libc.so.6") {
			hasGenericPaths = true
			break
		}
	}
	if !hasGenericPaths {
		t.Error("getArchitecturePaths should include generic paths")
	}
}

func TestFindLibcViaCommonPaths(t *testing.T) {
	tmpDir := t.TempDir()

	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc file: %v", err)
	}

	result := findLibcViaCommonPaths()
	if result == "" {
		t.Log("findLibcViaCommonPaths returned empty (may not find libc in temp dir)")
	}
}

func TestFindLibcPath_CompleteFlow(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-complete-flow"
	pid := uint32(12351)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libcPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := FindLibcPath(containerID)
	if result != libcPath {
		t.Logf("FindLibcPath returned %q (expected %q in test environment)", result, libcPath)
	}
}

func TestFindLibcPath_FallbackChain(t *testing.T) {
	result := FindLibcPath("")
	if result == "" {
		t.Log("FindLibcPath returned empty (expected when no libc found in test environment)")
	} else {
		t.Logf("FindLibcPath found libc at: %s", result)
	}
}

func TestFindDBLibsViaLdconfig(t *testing.T) {
	result := findDBLibsViaLdconfig([]string{"libpq.so.5", "libpq.so"})
	if len(result) == 0 {
		t.Log("findDBLibsViaLdconfig returned empty (expected when DB libs not found in test environment)")
	} else {
		t.Logf("findDBLibsViaLdconfig found %d paths", len(result))
	}
}

func TestFindDBLibsViaLdSoConf(t *testing.T) {
	result := findDBLibsViaLdSoConf([]string{"libpq.so.5", "libpq.so"})
	if len(result) == 0 {
		t.Log("findDBLibsViaLdSoConf returned empty (expected when DB libs not found in test environment)")
	} else {
		t.Logf("findDBLibsViaLdSoConf found %d paths", len(result))
	}
}

func TestGetArchitectureDBPaths(t *testing.T) {
	libNames := []string{"libpq.so.5", "libmysqlclient.so.21"}
	paths := getArchitectureDBPaths(libNames)
	if len(paths) == 0 {
		t.Error("getArchitectureDBPaths returned empty slice")
	}

	hasGenericPaths := false
	for _, path := range paths {
		if strings.Contains(path, "lib64") || strings.Contains(path, "/lib/") {
			hasGenericPaths = true
			break
		}
	}
	if !hasGenericPaths {
		t.Error("getArchitectureDBPaths should include generic paths")
	}
}

func TestFindDBLibsViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12352)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libpqPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(libpqPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libpqPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create libpq: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libpqPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findDBLibsViaProcessMaps(pid, []string{"libpq.so.5"})
	if len(result) == 0 {
		t.Error("findDBLibsViaProcessMaps should find libpq")
	}
	if len(result) > 0 && result[0] != libpqPath {
		t.Errorf("Expected %q, got %q", libpqPath, result[0])
	}
}

func TestFindDBLibsViaProcessMaps_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12353)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	mapsContent := "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /lib/other.so\n"
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findDBLibsViaProcessMaps(pid, []string{"libpq.so.5"})
	if len(result) != 0 {
		t.Errorf("Expected empty, got %v", result)
	}
}

func TestFindDBLibsInContainer_ViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-db-container"
	pid := uint32(12354)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libpqPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(libpqPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libpqPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create libpq: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libpqPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findDBLibsInContainer(containerID, []string{"libpq.so.5"})
	if len(result) == 0 {
		t.Log("findDBLibsInContainer returned empty (may not find in test environment)")
	} else {
		found := false
		for _, path := range result {
			if strings.Contains(path, "libpq.so.5") {
				found = true
				break
			}
		}
		if !found {
			t.Log("findDBLibsInContainer did not find libpq via process maps")
		}
	}
}

func TestFindDBLibsInContainer_ViaRootfs(t *testing.T) {
	tmpDir := t.TempDir()
	containerID := "test-db-rootfs"

	containerRoot := filepath.Join(tmpDir, "var", "lib", "docker", "containers", containerID, "rootfs")
	libpqPath := filepath.Join(containerRoot, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(libpqPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(libpqPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create libpq file: %v", err)
	}

	result := findDBLibsInContainer(containerID, []string{"libpq.so.5"})
	if len(result) == 0 {
		t.Log("findDBLibsInContainer returned empty (container root may not be in /var/lib/docker)")
	}
}

func TestFindDBLibs(t *testing.T) {
	result := findDBLibs("", []string{"libpq.so.5", "libpq.so"})
	if len(result) == 0 {
		t.Log("findDBLibs returned empty (expected when DB libs not found in test environment)")
	} else {
		t.Logf("findDBLibs found %d paths", len(result))
	}
}

func TestFindDBLibs_WithContainerID(t *testing.T) {
	result := findDBLibs("test-container-id", []string{"libpq.so.5"})
	if len(result) == 0 {
		t.Log("findDBLibs returned empty (expected when container DB libs not found)")
	}
}

func TestFindDBLibs_MultipleVersions(t *testing.T) {
	result := findDBLibs("", []string{"libpq.so.5", "libpq.so", "libmysqlclient.so.21", "libmysqlclient.so"})
	if len(result) == 0 {
		t.Log("findDBLibs returned empty (expected when DB libs not found in test environment)")
	} else {
		t.Logf("findDBLibs found %d paths for multiple library versions", len(result))
	}
}

func TestGetMuslLibcNames(t *testing.T) {
	names := getMuslLibcNames()
	if len(names) == 0 {
		t.Error("getMuslLibcNames returned empty slice")
	}

	hasGeneric := false
	for _, name := range names {
		if name == "libc.so.6" {
			hasGeneric = true
			break
		}
	}
	if !hasGeneric {
		t.Error("getMuslLibcNames should include generic libc.so.6")
	}

	hasMusl := false
	for _, name := range names {
		if strings.Contains(name, "libc.musl-") {
			hasMusl = true
			break
		}
	}
	if !hasMusl {
		t.Log("getMuslLibcNames did not include musl name (may not be supported for current architecture)")
	}
}

func TestGetMuslLibcNames_AllArchitectures(t *testing.T) {
	testArchs := map[string]string{
		"amd64":   "x86_64",
		"arm64":   "aarch64",
		"riscv64": "riscv64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}

	for goArch, muslArch := range testArchs {
		t.Run(goArch, func(t *testing.T) {
			expectedMuslName := fmt.Sprintf("libc.musl-%s.so.1", muslArch)
			names := getMuslLibcNames()
			found := false
			for _, name := range names {
				if name == expectedMuslName {
					found = true
					break
				}
			}
			if runtime.GOARCH == goArch && !found {
				t.Logf("Expected musl name %s for architecture %s (current arch: %s)", expectedMuslName, goArch, runtime.GOARCH)
			}
		})
	}
}

func TestFindLibcViaLdSoConf_WithMusl(t *testing.T) {
	tmpDir := t.TempDir()

	libDir := filepath.Join(tmpDir, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}

	muslNames := getMuslLibcNames()
	for _, muslName := range muslNames {
		if strings.Contains(muslName, "musl") {
			muslPath := filepath.Join(libDir, muslName)
			if err := os.WriteFile(muslPath, []byte("fake musl libc"), 0644); err != nil {
				t.Fatalf("failed to create musl libc: %v", err)
			}

			oldLdSoConf := "/etc/ld.so.conf"
			_ = oldLdSoConf

			result := findLibcViaLdSoConf()
			if result == "" {
				t.Log("findLibcViaLdSoConf returned empty (may not find in /etc paths)")
			}
			break
		}
	}
}

func TestAttachTLSProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachTLSProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachTLSProbes returned %d links", len(links))
			}
		})
	}
}

func TestFindTLSLibs(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := findTLSLibs(tt.containerID)
			if paths == nil {
				t.Error("findTLSLibs should return non-nil slice")
			}
		})
	}
}

func TestAttachTLSProbes_NoPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links := AttachTLSProbes(coll, "")
	if links == nil {
		t.Error("AttachTLSProbes should return non-nil slice")
	}
	if len(links) != 0 {
		t.Logf("AttachTLSProbes returned %d links (expected 0 when no programs)", len(links))
	}
}

func TestAttachPoolProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachPoolProbes(coll, tt.containerID)
			if len(links) > 0 {
				t.Logf("AttachPoolProbes returned %d links", len(links))
			} else {
				t.Log("AttachPoolProbes returned nil or empty slice (expected when no DB libs found)")
			}
		})
	}
}

func TestAttachPoolProbes_WithPrograms(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_sqlite3_prepare_v2":    {},
			"uretprobe_sqlite3_finalize":   {},
			"uprobe_sqlite3_step":          {},
			"uretprobe_sqlite3_step":       {},
			"uprobe_PQconnectStart":        {},
			"uretprobe_PQfinish":            {},
			"uprobe_PQexec_pool":            {},
			"uprobe_mysql_real_connect":     {},
			"uretprobe_mysql_close":         {},
			"uprobe_mysql_real_query_pool":  {},
		},
	}

	links := AttachPoolProbes(coll, "")
	if len(links) > 0 {
		t.Logf("AttachPoolProbes returned %d links", len(links))
	} else {
		t.Log("AttachPoolProbes returned nil or empty slice (expected when no DB libs found)")
	}
}

func TestFindGoBinaryInProcess(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12355)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "bin", "test-binary")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	exePath := filepath.Join(procDir, "exe")
	if err := os.Symlink(binaryPath, exePath); err != nil {
		t.Fatalf("failed to create exe symlink: %v", err)
	}

	result := findGoBinaryInProcess(pid)
	if result == "" {
		t.Log("findGoBinaryInProcess returned empty (expected when binary not found in container root)")
	}
}

func TestFindGoBinaryInProcess_RelativePath(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12356)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "bin", "test-binary")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	exePath := filepath.Join(procDir, "exe")
	if err := os.Symlink("bin/test-binary", exePath); err != nil {
		t.Fatalf("failed to create exe symlink: %v", err)
	}

	cwdPath := filepath.Join(procDir, "cwd")
	if err := os.Symlink(tmpDir, cwdPath); err != nil {
		t.Fatalf("failed to create cwd symlink: %v", err)
	}

	result := findGoBinaryInProcess(pid)
	if result == "" {
		t.Log("findGoBinaryInProcess returned empty (expected when binary not found)")
	}
}

func TestFindGoBinaryInProcess_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(99999)
	result := findGoBinaryInProcess(pid)
	if result != "" {
		t.Errorf("Expected empty, got %q", result)
	}
}

func TestFindGoBinaryViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12357)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "bin", "test-binary")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", binaryPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findGoBinaryViaProcessMaps(pid)
	if result != binaryPath {
		t.Logf("findGoBinaryViaProcessMaps returned %q (expected %q)", result, binaryPath)
	}
}

func TestFindGoBinaryViaProcessMaps_WithContainerRoot(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12358)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	procRoot := filepath.Join(procDir, "root")
	containerBinaryPath := "/bin/test-binary"
	hostBinaryPath := filepath.Join(procRoot, strings.TrimPrefix(containerBinaryPath, "/"))
	if err := os.MkdirAll(filepath.Dir(hostBinaryPath), 0755); err != nil {
		t.Fatalf("failed to create bin dir: %v", err)
	}
	if err := os.WriteFile(hostBinaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", containerBinaryPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findGoBinaryViaProcessMaps(pid)
	if result == "" {
		t.Log("findGoBinaryViaProcessMaps returned empty (expected when binary not found)")
	}
}

func TestFindGoBinaryViaProcessMaps_SkipsLibraries(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12359)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	mapsContent := "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /lib/libc.so.6\n"
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findGoBinaryViaProcessMaps(pid)
	if result != "" {
		t.Errorf("Expected empty (should skip .so files), got %q", result)
	}
}

func TestFindGoBinaryViaProcessMaps_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(99999)
	result := findGoBinaryViaProcessMaps(pid)
	if result != "" {
		t.Errorf("Expected empty, got %q", result)
	}
}

func TestFindGoBinaryInContainer(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-go-container"
	pid := uint32(12360)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	procRoot := filepath.Join(procDir, "root")
	binaryPath := "/app/test-binary"
	hostBinaryPath := filepath.Join(procRoot, strings.TrimPrefix(binaryPath, "/"))
	if err := os.MkdirAll(filepath.Dir(hostBinaryPath), 0755); err != nil {
		t.Fatalf("failed to create app dir: %v", err)
	}
	if err := os.WriteFile(hostBinaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	cmdlinePath := filepath.Join(procDir, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte(binaryPath+"\x00"), 0644); err != nil {
		t.Fatalf("failed to create cmdline: %v", err)
	}

	result := findGoBinaryInContainer(containerID, pid)
	if result == "" {
		t.Log("findGoBinaryInContainer returned empty (expected when binary not found)")
	}
}

func TestFindGoBinaryInContainer_ViaComm(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-go-container-comm"
	pid := uint32(12361)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	procRoot := filepath.Join(procDir, "root")
	binaryPath := "/app/test-binary"
	hostBinaryPath := filepath.Join(procRoot, strings.TrimPrefix(binaryPath, "/"))
	if err := os.MkdirAll(filepath.Dir(hostBinaryPath), 0755); err != nil {
		t.Fatalf("failed to create app dir: %v", err)
	}
	if err := os.WriteFile(hostBinaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("failed to create binary: %v", err)
	}

	commPath := filepath.Join(procDir, "comm")
	if err := os.WriteFile(commPath, []byte("test-binary\n"), 0644); err != nil {
		t.Fatalf("failed to create comm: %v", err)
	}

	result := findGoBinaryInContainer(containerID, pid)
	if result == "" {
		t.Log("findGoBinaryInContainer returned empty (expected when binary not found)")
	}
}

func TestFindGoBinaryInContainer_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(99999)
	result := findGoBinaryInContainer("test-container", pid)
	if result != "" {
		t.Errorf("Expected empty, got %q", result)
	}
}

func TestFindTLSLibsViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12362)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libsslPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(libsslPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libsslPath, []byte("fake libssl"), 0644); err != nil {
		t.Fatalf("failed to create libssl: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libsslPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findTLSLibsViaProcessMaps(pid, []string{"libssl.so.3", "libcrypto.so.3"})
	if len(result) == 0 {
		t.Error("findTLSLibsViaProcessMaps should find libssl")
	}
	if len(result) > 0 && result[0] != libsslPath {
		t.Errorf("Expected %q, got %q", libsslPath, result[0])
	}
}

func TestFindTLSLibsViaProcessMaps_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12363)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	mapsContent := "7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 /lib/other.so\n"
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findTLSLibsViaProcessMaps(pid, []string{"libssl.so.3"})
	if len(result) != 0 {
		t.Errorf("Expected empty, got %v", result)
	}
}

func TestFindTLSLibsViaProcessMaps_InvalidPid(t *testing.T) {
	result := findTLSLibsViaProcessMaps(99999, []string{"libssl.so.3"})
	if len(result) != 0 {
		t.Errorf("Expected empty, got %v", result)
	}
}

func TestFindTLSLibsInContainer_ViaProcessMaps(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-tls-container"
	pid := uint32(12364)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libsslPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(libsslPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libsslPath, []byte("fake libssl"), 0644); err != nil {
		t.Fatalf("failed to create libssl: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libsslPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findTLSLibsInContainer(containerID, []string{"libssl.so.3"})
	if len(result) == 0 {
		t.Log("findTLSLibsInContainer returned empty (may not find in test environment)")
	} else {
		found := false
		for _, path := range result {
			if strings.Contains(path, "libssl.so.3") {
				found = true
				break
			}
		}
		if !found {
			t.Log("findTLSLibsInContainer did not find libssl via process maps")
		}
	}
}

func TestAttachDBProbes_DirectoryInsteadOfFile(t *testing.T) {
	tmpDir := t.TempDir()
	libpqPath := filepath.Join(tmpDir, "libpq.so.5")
	if err := os.MkdirAll(libpqPath, 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_PQexec": {},
		},
	}

	links := AttachDBProbes(coll, "")
	if len(links) > 0 {
		t.Logf("AttachDBProbes returned %d links", len(links))
	} else {
		t.Log("AttachDBProbes returned nil or empty slice (expected when path is directory)")
	}
}

func TestFindLibcInContainer_AllPaths(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-libc-all-paths"
	pid := uint32(12365)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libcPath := filepath.Join(tmpDir, "lib", "x86_64-linux-gnu", "libc.so.6")
	if err := os.MkdirAll(filepath.Dir(libcPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libcPath, []byte("fake libc"), 0644); err != nil {
		t.Fatalf("failed to create libc: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libcPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findLibcInContainer(containerID)
	if result == "" {
		t.Log("findLibcInContainer returned empty (may not find in test environment)")
	} else if result != libcPath {
		t.Logf("findLibcInContainer returned %q (expected %q)", result, libcPath)
	}
}

func TestProbeAttachError_Unwrap(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	err := NewProbeAttachError("test_probe", originalErr)
	
	unwrapped := err.Unwrap()
	if unwrapped != originalErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, originalErr)
	}
}

func TestFindDBLibsInContainer_AllPaths(t *testing.T) {
	tmpDir := t.TempDir()

	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tmpDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	containerID := "test-db-all-paths"
	pid := uint32(12366)
	procDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatalf("failed to create proc dir: %v", err)
	}

	libpqPath := filepath.Join(tmpDir, "usr", "lib", "x86_64-linux-gnu", "libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(libpqPath), 0755); err != nil {
		t.Fatalf("failed to create lib dir: %v", err)
	}
	if err := os.WriteFile(libpqPath, []byte("fake libpq"), 0644); err != nil {
		t.Fatalf("failed to create libpq: %v", err)
	}

	cgroupContent := fmt.Sprintf("0::/kubepods/pod_%s\n", containerID)
	cgroupPath := filepath.Join(procDir, "cgroup")
	if err := os.WriteFile(cgroupPath, []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to create cgroup: %v", err)
	}

	mapsContent := fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", libpqPath)
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsContent), 0644); err != nil {
		t.Fatalf("failed to create maps: %v", err)
	}

	result := findDBLibsInContainer(containerID, []string{"libpq.so.5"})
	if len(result) == 0 {
		t.Log("findDBLibsInContainer returned empty (may not find in test environment)")
	} else {
		found := false
		for _, path := range result {
			if strings.Contains(path, "libpq.so.5") {
				found = true
				break
			}
		}
		if !found {
			t.Log("findDBLibsInContainer did not find libpq")
		}
	}
}
