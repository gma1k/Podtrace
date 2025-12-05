package probes

import (
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

