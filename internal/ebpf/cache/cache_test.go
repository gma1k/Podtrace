package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestGetProcessNameQuick_InvalidPID(t *testing.T) {
	tests := []struct {
		name string
		pid  uint32
	}{
		{"zero PID", 0},
		{"too large PID", 4194304},
		{"very large PID", 99999999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetProcessNameQuick(tt.pid)
			if result != "" {
				t.Errorf("Expected empty string for invalid PID %d, got %q", tt.pid, result)
			}
		})
	}
}

func TestGetProcessNameQuick_FromCmdline(t *testing.T) {
	originalProcPath := config.ProcBasePath
	defer func() { config.ProcBasePath = originalProcPath }()

	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12345)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/usr/bin/test-process\x00arg1\x00arg2")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := GetProcessNameQuick(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process', got %q", result)
	}
}

func TestGetProcessNameQuick_FromCmdlineWithPath(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12346)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/usr/local/bin/my-app\x00")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := GetProcessNameQuick(pid)
	if result != "my-app" {
		t.Errorf("Expected 'my-app', got %q", result)
	}
}

func TestGetProcessNameQuick_FromStat(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12347)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	statPath := filepath.Join(procDir, "stat")
	statContent := "12347 (test-process-name) S 1 12347 12347 0 -1 4194560"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := GetProcessNameQuick(pid)
	if result != "test-process-name" {
		t.Errorf("Expected 'test-process-name', got %q", result)
	}
}

func TestGetProcessNameQuick_FromComm(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12348)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	commPath := filepath.Join(procDir, "comm")
	commContent := "  comm-process  \n"
	_ = os.WriteFile(commPath, []byte(commContent), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process', got %q", result)
	}
}

func TestGetProcessNameQuick_CacheHit(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12349)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/usr/bin/cached-process\x00")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result1 := GetProcessNameQuick(pid)
	if result1 != "cached-process" {
		t.Errorf("Expected 'cached-process', got %q", result1)
	}

	_ = os.Remove(cmdlinePath)

	result2 := GetProcessNameQuick(pid)
	if result2 != "cached-process" {
		t.Errorf("Expected cached result 'cached-process', got %q", result2)
	}
}

func TestGetProcessNameQuick_CacheEviction(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ResetGlobalCache()
	defer ResetGlobalCache()

	for i := uint32(20000); i < 20010; i++ {
		procDir := filepath.Join(tempDir, fmt.Sprintf("%d", i))
		_ = os.MkdirAll(procDir, 0755)
		cmdlinePath := filepath.Join(procDir, "cmdline")
		cmdlineContent := []byte(fmt.Sprintf("/usr/bin/process-%d\x00", i))
		_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)
		GetProcessNameQuick(i)
	}
}

func TestGetProcessNameQuick_EmptyCmdline(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12350)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	statContent := "12350 (fallback-process) S 1 12350 12350 0 -1 4194560"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := GetProcessNameQuick(pid)
	if result != "fallback-process" {
		t.Errorf("Expected 'fallback-process' from stat, got %q", result)
	}
}

func TestGetProcessNameQuick_InvalidStatFormat(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12351)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("invalid stat format"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestGetProcessNameQuick_SanitizeProcessName(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12352)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("process%with%special\x00")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := GetProcessNameQuick(pid)
	if strings.Contains(result, "%") {
		t.Errorf("Expected sanitized process name without %%, got %q", result)
	}
}

func TestGetProcessNameQuick_StatWithInvalidFormat(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12353)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("invalid format no parentheses"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestGetProcessNameQuick_StatWithStartButNoEnd(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12354)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("12354 (process-name"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestGetProcessNameQuick_CmdlineWithEmptyFirstPart(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12355)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("\x00arg1\x00arg2")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	statPath := filepath.Join(procDir, "stat")
	statContent := "12355 (fallback-process) S 1 12355 12355 0 -1 4194560"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := GetProcessNameQuick(pid)
	if result != "fallback-process" {
		t.Errorf("Expected 'fallback-process' from stat, got %q", result)
	}
}

func TestGetProcessNameQuick_AllMethodsFail(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12356)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	result := GetProcessNameQuick(pid)
	if result == "" {
		t.Log("GetProcessNameQuick returned empty string (expected when all methods fail)")
	}
}

func TestGetProcessNameQuick_StatEndBeforeStart(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12357)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("12357 ) process-name ( S"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestGetProcessNameQuick_StatEndEqualsStart(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12358)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("12358 () S"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := GetProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestGetProcessNameQuick_CommEmpty(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	pid := uint32(12359)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("invalid"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte(""), 0644)

	result := GetProcessNameQuick(pid)
	if result != "" {
		t.Logf("GetProcessNameQuick returned %q (expected empty when all methods fail)", result)
	}
}

func TestGetProcessNameQuick_CacheEvictionExactMax(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ResetGlobalCache()
	defer ResetGlobalCache()

	for i := uint32(50000); i < uint32(50000+config.MaxProcessCacheSize); i++ {
		procDir := filepath.Join(tempDir, fmt.Sprintf("%d", i))
		_ = os.MkdirAll(procDir, 0755)
		cmdlinePath := filepath.Join(procDir, "cmdline")
		cmdlineContent := []byte(fmt.Sprintf("/usr/bin/process-%d\x00", i))
		_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)
		GetProcessNameQuick(i)
	}
}

func TestGetProcessNameQuick_CacheEvictionOneOverMax(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ResetGlobalCache()
	defer ResetGlobalCache()

	for i := uint32(60000); i < uint32(60000+config.MaxProcessCacheSize+1); i++ {
		procDir := filepath.Join(tempDir, fmt.Sprintf("%d", i))
		_ = os.MkdirAll(procDir, 0755)
		cmdlinePath := filepath.Join(procDir, "cmdline")
		cmdlineContent := []byte(fmt.Sprintf("/usr/bin/process-%d\x00", i))
		_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)
		GetProcessNameQuick(i)
	}
}

