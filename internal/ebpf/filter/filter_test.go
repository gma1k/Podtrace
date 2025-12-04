package filter

import (
	"fmt"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestCgroupFilter_EmptyPath(t *testing.T) {
	filter := NewCgroupFilter()
	filter.SetCgroupPath("")

	if !filter.IsPIDInCgroup(1234) {
		t.Error("Empty cgroup path should accept all PIDs")
	}
}

func TestCgroupFilter_InvalidPID(t *testing.T) {
	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	if filter.IsPIDInCgroup(0) {
		t.Error("PID 0 should be rejected")
	}

	if filter.IsPIDInCgroup(4194305) {
		t.Error("PID > 4194304 should be rejected")
	}
}

func TestNormalizeCgroupPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with /sys/fs/cgroup prefix",
			input:    "/sys/fs/cgroup/kubepods/test",
			expected: "/kubepods/test",
		},
		{
			name:     "without prefix",
			input:    "/kubepods/test",
			expected: "/kubepods/test",
		},
		{
			name:     "with trailing slash",
			input:    "/kubepods/test/",
			expected: "/kubepods/test",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "",
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "just /sys/fs/cgroup",
			input:    "/sys/fs/cgroup",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeCgroupPath(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestExtractCgroupPathFromProc(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "cgroup v2 format",
			input:    "0::/kubepods/test",
			expected: "/kubepods/test",
		},
		{
			name:     "cgroup v1 format",
			input:    "1:name=systemd:/kubepods/test",
			expected: "/kubepods/test",
		},
		{
			name:     "multiple lines v1",
			input:    "1:name=systemd:/system\n2:cpu:/kubepods/test",
			expected: "/kubepods/test",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCgroupPathFromProc(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestCgroupFilter_PIDCache(t *testing.T) {
	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	if filter.IsPIDInCgroup(0) {
		t.Error("PID 0 should be rejected and cached")
	}

	for i := uint32(1); i <= 10001; i++ {
		_ = filter.IsPIDInCgroup(i)
	}
}

func TestCgroupFilter_ExactMatch(t *testing.T) {
	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	normalized := NormalizeCgroupPath("/sys/fs/cgroup/kubepods/test")
	if normalized != "/kubepods/test" {
		t.Errorf("Expected normalized path '/kubepods/test', got '%s'", normalized)
	}
}

func BenchmarkIsPIDInCgroup(b *testing.B) {
	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.IsPIDInCgroup(uint32(i%1000 + 1))
	}
}

func BenchmarkNormalizeCgroupPath(b *testing.B) {
	path := "/sys/fs/cgroup/kubepods/pod123/container456"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeCgroupPath(path)
	}
}

func BenchmarkExtractCgroupPathFromProc(b *testing.B) {
	content := "1:name=systemd:/system\n2:cpu:/kubepods/pod123/container456"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractCgroupPathFromProc(content)
	}
}

func TestCgroupFilter_LongCgroupFilePath(t *testing.T) {
	origProcBase := config.ProcBasePath
	t.Cleanup(func() { config.SetProcBasePath(origProcBase) })

	longPath := "/this/is/a/very/long/path/that/makes/the/proc/file/name/exceed/sixtyfour/characters"
	config.SetProcBasePath(longPath)

	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	expectedPath := fmt.Sprintf("%s/%d/cgroup", longPath, 1234)
	if filter.IsPIDInCgroup(1234) {
		t.Fatalf("expected false when cgroup file path length exceeds limit (MaxCgroupFilePathLength=%d, actual path length=%d)", config.MaxCgroupFilePathLength, len(expectedPath))
	}
}

func TestCgroupFilter_ReadFileErrorCachingAndEviction(t *testing.T) {
	origReadFile := readFile
	origProcBase := config.ProcBasePath
	t.Cleanup(func() {
		readFile = origReadFile
		config.SetProcBasePath(origProcBase)
	})

	config.SetProcBasePath("/proc")
	readFile = func(path string) ([]byte, error) {
		return nil, fmt.Errorf("forced error")
	}

	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	for i := uint32(1); i <= 10005; i++ {
		_ = filter.IsPIDInCgroup(i)
	}

	if len(filter.pidCache) == 0 {
		t.Fatalf("expected pid cache to be populated")
	}
}

func TestCgroupFilter_RelationshipsAndSuccessCache(t *testing.T) {
	origReadFile := readFile
	origProcBase := config.ProcBasePath
	t.Cleanup(func() {
		readFile = origReadFile
		config.SetProcBasePath(origProcBase)
	})

	config.SetProcBasePath("/proc")

	type tc struct {
		name        string
		targetPath  string
		procContent string
		expect      bool
	}

	cases := []tc{
		{
			name:        "exact match",
			targetPath:  "/sys/fs/cgroup/kubepods/pod1",
			procContent: "0::/kubepods/pod1",
			expect:      true,
		},
		{
			name:        "pid under target",
			targetPath:  "/sys/fs/cgroup/kubepods/pod1",
			procContent: "0::/kubepods/pod1/container1",
			expect:      true,
		},
		{
			name:        "target under pid",
			targetPath:  "/sys/fs/cgroup/kubepods/pod1/container1",
			procContent: "0::/kubepods/pod1",
			expect:      true,
		},
		{
			name:        "unrelated paths",
			targetPath:  "/sys/fs/cgroup/kubepods/pod1",
			procContent: "0::/otherpod",
			expect:      false,
		},
	}

	for pid := uint32(1000); pid < 1004; pid++ {
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			readFile = func(path string) ([]byte, error) {
				return []byte(c.procContent), nil
			}

			filter := NewCgroupFilter()
			filter.SetCgroupPath(c.targetPath)

			pid := uint32(2000 + i)

			got := filter.IsPIDInCgroup(pid)
			if got != c.expect {
				t.Fatalf("expected %v, got %v", c.expect, got)
			}

			gotCached := filter.IsPIDInCgroup(pid)
			if gotCached != c.expect {
				t.Fatalf("cached path: expected %v, got %v", c.expect, gotCached)
			}
		})
	}
}

func TestCgroupFilter_SuccessEvictionPath(t *testing.T) {
	origReadFile := readFile
	origProcBase := config.ProcBasePath
	t.Cleanup(func() {
		readFile = origReadFile
		config.SetProcBasePath(origProcBase)
	})

	config.SetProcBasePath("/proc")
	readFile = func(path string) ([]byte, error) {
		return []byte("0::/kubepods/pod1"), nil
	}

	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/pod1")

	for i := uint32(1); i <= 11000; i++ {
		_ = filter.IsPIDInCgroup(i)
	}

	if len(filter.pidCache) == 0 || len(filter.pidCache) >= 11000 {
		t.Fatalf("expected pid cache to be populated and eviction to have occurred, got size %d", len(filter.pidCache))
	}
}

func TestCgroupFilter_EmptyCgroupPathFromProc(t *testing.T) {
	origReadFile := readFile
	origProcBase := config.ProcBasePath
	t.Cleanup(func() {
		readFile = origReadFile
		config.SetProcBasePath(origProcBase)
	})

	config.SetProcBasePath("/proc")
	readFile = func(path string) ([]byte, error) {
		return []byte("invalid"), nil
	}

	filter := NewCgroupFilter()
	filter.SetCgroupPath("/sys/fs/cgroup/kubepods/test")

	for i := uint32(1); i <= 10005; i++ {
		_ = filter.IsPIDInCgroup(i)
	}

	if len(filter.pidCache) == 0 {
		t.Fatalf("expected pid cache to be populated for empty cgroup path case")
	}
}
