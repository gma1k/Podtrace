package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	containerID := "abc123def456"
	result, err := GetDockerContainerRootfs(containerID)
	if err != nil {
		t.Fatalf("GetDockerContainerRootfs() error = %v", err)
	}
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

func TestGetInt64EnvOrDefault(t *testing.T) {
	key := "TEST_INT64_ENV_VAR"
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
		defaultValue int64
		expected     int64
	}{
		{"valid int64", "123456789", 0, 123456789},
		{"invalid int64", "invalid", 50, 50},
		{"negative int64", "-5", 50, 50},
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
			result := getInt64EnvOrDefault(key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetDurationEnvOrDefault(t *testing.T) {
	key := "TEST_DURATION_ENV_VAR"
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
		defaultValue time.Duration
		expected     time.Duration
	}{
		{"valid duration", "10s", 5 * time.Second, 10 * time.Second},
		{"valid duration minutes", "2m", 5 * time.Second, 2 * time.Minute},
		{"invalid duration", "invalid", 5 * time.Second, 5 * time.Second},
		{"negative duration", "-5s", 5 * time.Second, 5 * time.Second},
		{"zero duration", "0s", 5 * time.Second, 5 * time.Second},
		{"env not set", "", 5 * time.Second, 5 * time.Second},
		{"empty string", "", 5 * time.Second, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := getDurationEnvOrDefault(key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetCommonBinarySearchPaths(t *testing.T) {
	key := "PODTRACE_BINARY_SEARCH_PATHS"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	t.Run("env not set", func(t *testing.T) {
		_ = os.Unsetenv(key)
		paths := GetCommonBinarySearchPaths()
		if len(paths) == 0 {
			t.Error("Expected at least one binary search path")
		}
		expectedPaths := []string{"/app/main", "/app/app", "/usr/local/bin/app", "/bin/app"}
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
	})

	t.Run("env set", func(t *testing.T) {
		_ = os.Setenv(key, "/custom/path1:/custom/path2:/custom/path3")
		paths := GetCommonBinarySearchPaths()
		expectedPaths := []string{"/custom/path1", "/custom/path2", "/custom/path3"}
		if len(paths) != len(expectedPaths) {
			t.Errorf("Expected %d paths, got %d", len(expectedPaths), len(paths))
		}
		for i, expected := range expectedPaths {
			if paths[i] != expected {
				t.Errorf("Expected path %q at index %d, got %q", expected, i, paths[i])
			}
		}
	})
}

func TestGetDockerContainerRootfs_ErrorCases(t *testing.T) {
	original := DockerBasePath
	defer func() { DockerBasePath = original }()

	tests := []struct {
		name        string
		basePath    string
		containerID string
		expectError bool
		errorMsg    string
	}{
		{"empty container ID", "/test/docker", "", true, "invalid container ID length"},
		{"too long container ID", "/test/docker", string(make([]byte, MaxContainerIDLength+1)), true, "invalid container ID length"},
		{"contains path traversal", "/test/docker", "../container", true, "invalid container ID: contains path traversal"},
		{"contains slash", "/test/docker", "container/id", true, "invalid container ID: contains path traversal"},
		{"valid container ID", "/test/docker", "abc123def456", false, ""},
		{"empty base path causes outside path", "", "validcontainer", true, "invalid rootfs path: outside base path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DockerBasePath = tt.basePath
			result, err := GetDockerContainerRootfs(tt.containerID)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for container ID %q, got nil", tt.containerID)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for container ID %q: %v", tt.containerID, err)
				}
				expected := filepath.Join(tt.basePath, tt.containerID, "rootfs")
				if result != expected {
					t.Errorf("Expected %q, got %q", expected, result)
				}
			}
		})
	}
}

func TestGetContainerdOverlayPattern_WithEnv(t *testing.T) {
	key := "PODTRACE_CONTAINERD_OVERLAY_PATTERN"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	_ = os.Setenv(key, "/custom/overlay/pattern")
	result := GetContainerdOverlayPattern()
	if result != "/custom/overlay/pattern" {
		t.Errorf("Expected %q, got %q", "/custom/overlay/pattern", result)
	}
}

func TestGetContainerdNativePattern_WithEnv(t *testing.T) {
	key := "PODTRACE_CONTAINERD_NATIVE_PATTERN"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	_ = os.Setenv(key, "/custom/native/pattern")
	result := GetContainerdNativePattern()
	if result != "/custom/native/pattern" {
		t.Errorf("Expected %q, got %q", "/custom/native/pattern", result)
	}
}

func TestGetAlertMinSeverity(t *testing.T) {
	key := "PODTRACE_ALERT_MIN_SEVERITY"
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
		{"env set", "critical", "critical"},
		{"env not set", "", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setValue != "" {
				_ = os.Setenv(key, tt.setValue)
			} else {
				_ = os.Unsetenv(key)
			}
			result := GetAlertMinSeverity()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetSplunkEndpoint(t *testing.T) {
	key := "PODTRACE_ALERT_SPLUNK_ENABLED"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
		AlertSplunkEnabled = getEnvOrDefault("PODTRACE_ALERT_SPLUNK_ENABLED", "false") == "true"
	}()

	t.Run("splunk disabled", func(t *testing.T) {
		_ = os.Unsetenv(key)
		AlertSplunkEnabled = false
		result := GetSplunkEndpoint()
		if result != "" {
			t.Errorf("Expected empty string when Splunk is disabled, got %q", result)
		}
	})

	t.Run("splunk enabled", func(t *testing.T) {
		_ = os.Setenv(key, "true")
		AlertSplunkEnabled = true
		splunkEndpointKey := "PODTRACE_SPLUNK_ENDPOINT"
		originalEndpoint := os.Getenv(splunkEndpointKey)
		defer func() {
			if originalEndpoint != "" {
				_ = os.Setenv(splunkEndpointKey, originalEndpoint)
			} else {
				_ = os.Unsetenv(splunkEndpointKey)
			}
			SplunkEndpoint = getEnvOrDefault("PODTRACE_SPLUNK_ENDPOINT", DefaultSplunkEndpoint)
		}()

		_ = os.Setenv(splunkEndpointKey, "http://test-splunk:8088")
		SplunkEndpoint = "http://test-splunk:8088"
		result := GetSplunkEndpoint()
		if result != "http://test-splunk:8088" {
			t.Errorf("Expected %q, got %q", "http://test-splunk:8088", result)
		}
	})
}

func TestGetSplunkToken(t *testing.T) {
	key := "PODTRACE_ALERT_SPLUNK_ENABLED"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
		AlertSplunkEnabled = getEnvOrDefault("PODTRACE_ALERT_SPLUNK_ENABLED", "false") == "true"
	}()

	t.Run("splunk disabled", func(t *testing.T) {
		_ = os.Unsetenv(key)
		AlertSplunkEnabled = false
		result := GetSplunkToken()
		if result != "" {
			t.Errorf("Expected empty string when Splunk is disabled, got %q", result)
		}
	})

	t.Run("splunk enabled", func(t *testing.T) {
		_ = os.Setenv(key, "true")
		AlertSplunkEnabled = true
		splunkTokenKey := "PODTRACE_SPLUNK_TOKEN"
		originalToken := os.Getenv(splunkTokenKey)
		defer func() {
			if originalToken != "" {
				_ = os.Setenv(splunkTokenKey, originalToken)
			} else {
				_ = os.Unsetenv(splunkTokenKey)
			}
			SplunkToken = getEnvOrDefault("PODTRACE_SPLUNK_TOKEN", "")
		}()

		_ = os.Setenv(splunkTokenKey, "test-token-123")
		SplunkToken = "test-token-123"
		result := GetSplunkToken()
		if result != "test-token-123" {
			t.Errorf("Expected %q, got %q", "test-token-123", result)
		}
	})
}

func TestGetVersion(t *testing.T) {
	key := "PODTRACE_VERSION"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
	}()

	t.Run("default version", func(t *testing.T) {
		_ = os.Unsetenv(key)
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
		result := GetVersion()
		if result != DefaultVersion {
			t.Errorf("Expected %q, got %q", DefaultVersion, result)
		}
	})

	t.Run("env version set", func(t *testing.T) {
		_ = os.Setenv(key, "v0.8.0")
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
		result := GetVersion()
		if result != "v0.8.0" {
			t.Errorf("Expected %q, got %q", "v0.8.0", result)
		}
	})
}

func TestGetUserAgent(t *testing.T) {
	key := "PODTRACE_VERSION"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
	}()

	t.Run("default user agent", func(t *testing.T) {
		_ = os.Unsetenv(key)
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
		result := GetUserAgent()
		expected := "Podtrace/" + DefaultVersion
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("env version user agent", func(t *testing.T) {
		_ = os.Setenv(key, "v0.9.0")
		Version = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
		result := GetUserAgent()
		expected := "Podtrace/v0.9.0"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})
}
