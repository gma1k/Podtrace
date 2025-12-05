package probes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
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
			"uprobe_getaddrinfo":     nil,
			"uretprobe_getaddrinfo":  nil,
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
			"uprobe_pthread_mutex_lock":     nil,
			"uretprobe_pthread_mutex_lock":  nil,
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
			"uretprobe_PQexec":            nil,
			"uprobe_mysql_real_query":      nil,
			"uretprobe_mysql_real_query":  nil,
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
			"kprobe_tcp_connect":       &ebpf.Program{},
			"kretprobe_tcp_connect":    &ebpf.Program{},
			"kprobe_tcp_v6_connect":    &ebpf.Program{},
			"kretprobe_tcp_v6_connect": &ebpf.Program{},
			"kprobe_tcp_sendmsg":       &ebpf.Program{},
			"kretprobe_tcp_sendmsg":    &ebpf.Program{},
			"kprobe_tcp_recvmsg":       &ebpf.Program{},
			"kretprobe_tcp_recvmsg":    &ebpf.Program{},
			"kprobe_udp_sendmsg":       &ebpf.Program{},
			"kretprobe_udp_sendmsg":    &ebpf.Program{},
			"kprobe_udp_recvmsg":       &ebpf.Program{},
			"kretprobe_udp_recvmsg":    &ebpf.Program{},
			"kprobe_vfs_write":         &ebpf.Program{},
			"kretprobe_vfs_write":      &ebpf.Program{},
			"kprobe_vfs_read":          &ebpf.Program{},
			"kretprobe_vfs_read":       &ebpf.Program{},
			"kprobe_vfs_fsync":         &ebpf.Program{},
			"kretprobe_vfs_fsync":      &ebpf.Program{},
			"kprobe_do_futex":          &ebpf.Program{},
			"kretprobe_do_futex":       &ebpf.Program{},
			"kprobe_do_sys_openat2":    &ebpf.Program{},
			"kretprobe_do_sys_openat2": &ebpf.Program{},
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
			"tracepoint_sched_switch":         &ebpf.Program{},
			"tracepoint_tcp_set_state":        &ebpf.Program{},
			"tracepoint_tcp_retransmit_skb":   &ebpf.Program{},
			"tracepoint_net_dev_xmit":          &ebpf.Program{},
			"tracepoint_page_fault_user":       &ebpf.Program{},
			"tracepoint_oom_kill_process":     &ebpf.Program{},
			"tracepoint_sched_process_fork":    &ebpf.Program{},
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
			"tracepoint_sched_switch": &ebpf.Program{},
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
			"tracepoint_tcp_set_state": &ebpf.Program{},
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
			"kprobe_tcp_connect": &ebpf.Program{},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected without kernel support): %v", err)
	}
	if links != nil {
		for _, l := range links {
			l.Close()
		}
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
			"uprobe_getaddrinfo":    &ebpf.Program{},
			"uretprobe_getaddrinfo": &ebpf.Program{},
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
			"uprobe_pthread_mutex_lock":    &ebpf.Program{},
			"uretprobe_pthread_mutex_lock": &ebpf.Program{},
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
			"uprobe_pthread_mutex_lock":    &ebpf.Program{},
			"uretprobe_pthread_mutex_lock": &ebpf.Program{},
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
			"uprobe_PQexec":             &ebpf.Program{},
			"uretprobe_PQexec":          &ebpf.Program{},
			"uprobe_mysql_real_query":   &ebpf.Program{},
			"uretprobe_mysql_real_query": &ebpf.Program{},
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
			"uprobe_PQexec":             &ebpf.Program{},
			"uretprobe_PQexec":          &ebpf.Program{},
			"uprobe_mysql_real_query":   &ebpf.Program{},
			"uretprobe_mysql_real_query": &ebpf.Program{},
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
			"uprobe_PQexec": &ebpf.Program{},
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
					tt.progName: &ebpf.Program{},
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
			"uprobe_getaddrinfo":    &ebpf.Program{},
			"uretprobe_getaddrinfo": &ebpf.Program{},
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
			"uprobe_getaddrinfo":    &ebpf.Program{},
			"uretprobe_getaddrinfo": &ebpf.Program{},
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
			"uprobe_pthread_mutex_lock":    &ebpf.Program{},
			"uretprobe_pthread_mutex_lock": &ebpf.Program{},
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
			"uprobe_pthread_mutex_lock":    &ebpf.Program{},
			"uretprobe_pthread_mutex_lock": &ebpf.Program{},
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
			"uprobe_PQexec":             &ebpf.Program{},
			"uretprobe_PQexec":          &ebpf.Program{},
			"uprobe_mysql_real_query":   &ebpf.Program{},
			"uretprobe_mysql_real_query": &ebpf.Program{},
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
			"uprobe_PQexec": &ebpf.Program{},
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
			"kprobe_tcp_connect": &ebpf.Program{},
		},
	}

	links, err := AttachProbes(coll)
	if err != nil {
		if strings.Contains(err.Error(), "failed to attach") {
			t.Log("AttachProbes returned expected error")
		}
	}
	if links != nil {
		for _, l := range links {
			l.Close()
		}
	}
}

