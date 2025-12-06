package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetEnvOrDefault(t *testing.T) {
	key := "TEST_ENV_VAR"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name         string
		setValue     string
		defaultValue string
		expected     string
	}{
		{"env set", "test-value", "default", "test-value"},
		{"env not set", "", "default", "default"},
		{"env empty", "", "default", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := getEnvOrDefault(key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetFloatEnvOrDefault(t *testing.T) {
	key := "TEST_FLOAT_ENV_VAR"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name         string
		setValue     string
		defaultValue float64
		expected     float64
	}{
		{"valid float", "123.45", 0.0, 123.45},
		{"valid int", "100", 0.0, 100.0},
		{"invalid float", "invalid", 50.0, 50.0},
		{"env not set", "", 50.0, 50.0},
		{"empty string", "", 50.0, 50.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := getFloatEnvOrDefault(key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestSetCgroupBasePath(t *testing.T) {
	original := CgroupBasePath
	defer func() { CgroupBasePath = original }()

	newPath := "/test/cgroup/path"
	SetCgroupBasePath(newPath)

	if CgroupBasePath != newPath {
		t.Errorf("Expected CgroupBasePath to be %q, got %q", newPath, CgroupBasePath)
	}
}

func TestSetProcBasePath(t *testing.T) {
	original := ProcBasePath
	defer func() { ProcBasePath = original }()

	newPath := "/test/proc/path"
	SetProcBasePath(newPath)

	if ProcBasePath != newPath {
		t.Errorf("Expected ProcBasePath to be %q, got %q", newPath, ProcBasePath)
	}
}

func TestGetMetricsAddress(t *testing.T) {
	key := "PODTRACE_METRICS_ADDR"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name     string
		setValue string
		expected string
	}{
		{"env set", "127.0.0.1:9090", "127.0.0.1:9090"},
		{"env not set", "", DefaultMetricsHost + ":3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := GetMetricsAddress()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAllowNonLoopbackMetrics(t *testing.T) {
	key := "PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name     string
		setValue string
		expected bool
	}{
		{"enabled", "1", true},
		{"disabled", "0", false},
		{"not set", "", false},
		{"invalid", "true", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := AllowNonLoopbackMetrics()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if DefaultNamespace == "" {
		t.Error("DefaultNamespace should not be empty")
	}
	if DefaultErrorRateThreshold <= 0 {
		t.Error("DefaultErrorRateThreshold should be positive")
	}
	if DefaultRTTThreshold <= 0 {
		t.Error("DefaultRTTThreshold should be positive")
	}
	if DefaultFSSlowThreshold <= 0 {
		t.Error("DefaultFSSlowThreshold should be positive")
	}
	if DefaultMetricsPort <= 0 {
		t.Error("DefaultMetricsPort should be positive")
	}
	if EventChannelBufferSize <= 0 {
		t.Error("EventChannelBufferSize should be positive")
	}
	if MaxProcessCacheSize <= 0 {
		t.Error("MaxProcessCacheSize should be positive")
	}
	if MemlockLimitBytes <= 0 {
		t.Error("MemlockLimitBytes should be positive")
	}
	if DefaultPodResolveTimeout <= 0 {
		t.Error("DefaultPodResolveTimeout should be positive")
	}
}

func TestGetIntEnvOrDefault(t *testing.T) {
	key := "TEST_INT_ENV_VAR"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name         string
		setValue     string
		defaultValue int
		expected     int
	}{
		{"valid int", "123", 0, 123},
		{"invalid int", "invalid", 50, 50},
		{"negative int", "-5", 50, 50},
		{"zero", "0", 50, 50},
		{"env not set", "", 50, 50},
		{"empty string", "", 50, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := getIntEnvOrDefault(key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetDefaultLibSearchPaths(t *testing.T) {
	paths := GetDefaultLibSearchPaths()
	if len(paths) == 0 {
		t.Error("Expected at least one library search path")
	}
	expectedPaths := []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64"}
	for _, expected := range expectedPaths {
		found := false
		for _, path := range paths {
			if path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path %q not found in results", expected)
		}
	}
}

func TestGetDockerContainerRootfs(t *testing.T) {
	original := DockerBasePath
	defer func() { DockerBasePath = original }()

	DockerBasePath = "/test/docker"
	containerID := "abc123"
	result := GetDockerContainerRootfs(containerID)
	expected := filepath.Join("/test/docker", containerID, "rootfs")
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestGetContainerdOverlayPattern(t *testing.T) {
	result := GetContainerdOverlayPattern()
	if result == "" {
		t.Error("Expected non-empty containerd overlay pattern")
	}
	if result != ContainerdOverlayPath {
		t.Errorf("Expected %q, got %q", ContainerdOverlayPath, result)
	}
}

func TestGetContainerdNativePattern(t *testing.T) {
	result := GetContainerdNativePattern()
	if result == "" {
		t.Error("Expected non-empty containerd native pattern")
	}
	if result != ContainerdNativePath {
		t.Errorf("Expected %q, got %q", ContainerdNativePath, result)
	}
}

func TestGetLdSoConfPath(t *testing.T) {
	original := LdSoConfBasePath
	defer func() { LdSoConfBasePath = original }()

	LdSoConfBasePath = "/test/etc"
	result := GetLdSoConfPath()
	expected := filepath.Join("/test/etc", "ld.so.conf")
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestGetLdSoConfDPattern(t *testing.T) {
	original := LdSoConfBasePath
	defer func() { LdSoConfBasePath = original }()

	LdSoConfBasePath = "/test/etc"
	result := GetLdSoConfDPattern()
	expected := filepath.Join("/test/etc", "ld.so.conf.d", "*.conf")
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestGetProcRootPath(t *testing.T) {
	original := ProcBasePath
	defer func() { ProcBasePath = original }()

	ProcBasePath = "/test/proc"
	pid := uint32(1234)
	result := GetProcRootPath(pid)
	expected := filepath.Join("/test/proc", "1234", "root")
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestGetDefaultProcRootPath(t *testing.T) {
	original := ProcBasePath
	defer func() { ProcBasePath = original }()

	ProcBasePath = "/test/proc"
	result := GetDefaultProcRootPath()
	expected := filepath.Join("/test/proc", "1", "root")
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

