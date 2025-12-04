package filter

import (
	"testing"
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
