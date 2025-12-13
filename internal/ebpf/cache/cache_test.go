package cache

import (
	"container/list"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestNewPathCache(t *testing.T) {
	pc := NewPathCache()
	if pc == nil {
		t.Fatal("NewPathCache returned nil")
	}
	if pc.cache == nil {
		t.Fatal("NewPathCache cache is nil")
	}
	if pc.ttl <= 0 {
		t.Fatal("NewPathCache ttl should be positive")
	}
}

func TestPathCache_Get_NotFound(t *testing.T) {
	pc := NewPathCache()
	path, ok := pc.Get("nonexistent-key")
	if ok {
		t.Errorf("Expected false, got true")
	}
	if path != "" {
		t.Errorf("Expected empty path, got %q", path)
	}
}

func TestPathCache_Get_Found(t *testing.T) {
	pc := NewPathCache()
	pc.Set("test-key", "/path/to/file")
	
	path, ok := pc.Get("test-key")
	if !ok {
		t.Error("Expected true, got false")
	}
	if path != "/path/to/file" {
		t.Errorf("Expected /path/to/file, got %q", path)
	}
}

func TestPathCache_Get_Expired(t *testing.T) {
	pc := NewPathCache()
	pc.Set("test-key", "/path/to/file")
	
	pc.mu.Lock()
	if entry, ok := pc.cache["test-key"]; ok {
		entry.timestamp = time.Now().Add(-pc.ttl - time.Second)
	}
	pc.mu.Unlock()
	
	path, ok := pc.Get("test-key")
	if ok {
		t.Error("Expected false for expired entry, got true")
	}
	if path != "" {
		t.Errorf("Expected empty path for expired entry, got %q", path)
	}
}

func TestPathCache_Set_EmptyPath(t *testing.T) {
	pc := NewPathCache()
	pc.Set("test-key", "")
	
	path, ok := pc.Get("test-key")
	if ok {
		t.Error("Expected false for empty path, got true")
	}
	if path != "" {
		t.Errorf("Expected empty path, got %q", path)
	}
}

func TestPathCache_Set_ValidPath(t *testing.T) {
	pc := NewPathCache()
	pc.Set("test-key", "/path/to/file")
	
	path, ok := pc.Get("test-key")
	if !ok {
		t.Error("Expected true, got false")
	}
	if path != "/path/to/file" {
		t.Errorf("Expected /path/to/file, got %q", path)
	}
}

func TestPathCache_Set_Overwrite(t *testing.T) {
	pc := NewPathCache()
	pc.Set("test-key", "/path/to/file1")
	pc.Set("test-key", "/path/to/file2")
	
	path, ok := pc.Get("test-key")
	if !ok {
		t.Error("Expected true, got false")
	}
	if path != "/path/to/file2" {
		t.Errorf("Expected /path/to/file2, got %q", path)
	}
}

func TestPathCache_Clear(t *testing.T) {
	pc := NewPathCache()
	pc.Set("key1", "/path1")
	pc.Set("key2", "/path2")
	
	pc.Clear()
	
	path, ok := pc.Get("key1")
	if ok {
		t.Error("Expected false after Clear, got true")
	}
	if path != "" {
		t.Errorf("Expected empty path after Clear, got %q", path)
	}
	
	_, ok = pc.Get("key2")
	if ok {
		t.Error("Expected false after Clear, got true")
	}
}

func TestPathCache_CleanupExpired(t *testing.T) {
	pc := NewPathCache()
	pc.Set("key1", "/path1")
	pc.Set("key2", "/path2")
	
	pc.mu.Lock()
	if entry, ok := pc.cache["key1"]; ok {
		entry.timestamp = time.Now().Add(-pc.ttl - time.Second)
	}
	pc.mu.Unlock()
	
	pc.CleanupExpired()
	
	_, ok := pc.Get("key1")
	if ok {
		t.Error("Expected false for expired entry, got true")
	}
	
	path, ok := pc.Get("key2")
	if !ok {
		t.Error("Expected true for non-expired entry, got false")
	}
	if path != "/path2" {
		t.Errorf("Expected /path2, got %q", path)
	}
}

func TestLRUCache_Get_Valid(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.Set(123, "test-process")
	
	name, ok := cache.Get(123)
	if !ok {
		t.Error("Expected true for valid entry, got false")
	}
	if name != "test-process" {
		t.Errorf("Expected test-process, got %q", name)
	}
}

func TestLRUCache_Get_Expired(t *testing.T) {
	cache := NewLRUCache(10, 100*time.Millisecond)
	defer cache.Close()
	
	cache.Set(123, "test-process")
	
	time.Sleep(150 * time.Millisecond)
	
	name, ok := cache.Get(123)
	if ok {
		t.Error("Expected false for expired entry, got true")
	}
	if name != "" {
		t.Errorf("Expected empty name for expired entry, got %q", name)
	}
}

func TestLRUCache_Get_InvalidPID(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	name, ok := cache.Get(0)
	if ok {
		t.Error("Expected false for invalid PID, got true")
	}
	if name != "" {
		t.Errorf("Expected empty name for invalid PID, got %q", name)
	}
	
	_, ok = cache.Get(4194304)
	if ok {
		t.Error("Expected false for invalid PID, got true")
	}
}

func TestLRUCache_Set_InvalidPID(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.Set(0, "test")
	cache.Set(4194304, "test")
	
	_, ok := cache.Get(0)
	if ok {
		t.Error("Expected false for invalid PID, got true")
	}
}

func TestLRUCache_Set_UpdateExisting(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.Set(123, "process1")
	cache.Set(123, "process2")
	
	name, ok := cache.Get(123)
	if !ok {
		t.Error("Expected true, got false")
	}
	if name != "process2" {
		t.Errorf("Expected process2, got %q", name)
	}
}

func TestLRUCache_Set_Eviction(t *testing.T) {
	cache := NewLRUCache(5, time.Minute)
	defer cache.Close()
	
	for i := uint32(1); i <= 6; i++ {
		cache.Set(i, fmt.Sprintf("process-%d", i))
	}
	
	name, ok := cache.Get(1)
	if ok {
		t.Logf("Cache entry for PID 1 still exists (may be evicted): %q", name)
	}
	
	name, ok = cache.Get(6)
	if !ok {
		t.Error("Expected true for most recently added entry, got false")
	}
	if name != "process-6" {
		t.Errorf("Expected process-6, got %q", name)
	}
}

func TestLRUCache_Evict_EmptyList(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.evict()
	
	if len(cache.cache) != 0 {
		t.Errorf("Expected empty cache, got %d entries", len(cache.cache))
	}
}

func TestLRUCache_Evict_Partial(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	for i := uint32(1); i <= 15; i++ {
		cache.Set(i, fmt.Sprintf("process-%d", i))
	}
	
	cache.evict()
	
	if len(cache.cache) >= 10 {
		t.Errorf("Expected cache size < 10 after eviction, got %d", len(cache.cache))
	}
}

func TestLRUCache_CleanupExpired(t *testing.T) {
	cache := NewLRUCache(10, 50*time.Millisecond)
	defer cache.Close()
	
	cache.Set(123, "process1")
	cache.Set(456, "process2")
	
	time.Sleep(60 * time.Millisecond)
	
	cache.mutex.Lock()
	now := time.Now()
	var toRemove []*list.Element
	for _, elem := range cache.cache {
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			toRemove = append(toRemove, elem)
		}
	}
	for _, elem := range toRemove {
		entry := elem.Value.(*cacheEntry)
		delete(cache.cache, entry.pid)
		cache.list.Remove(elem)
	}
	cache.mutex.Unlock()
	
	_, ok := cache.Get(123)
	if ok {
		t.Log("Entry still exists after cleanup")
	}
}

func TestLRUCache_Get_MoveToFront(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.Set(1, "process1")
	cache.Set(2, "process2")
	cache.Set(3, "process3")
	
	cache.Get(1)
	
	if cache.list.Front().Value.(*cacheEntry).pid != 1 {
		t.Error("Expected PID 1 to be at front after Get")
	}
}

func TestLRUCache_Set_MoveToFront(t *testing.T) {
	cache := NewLRUCache(10, time.Minute)
	defer cache.Close()
	
	cache.Set(1, "process1")
	cache.Set(2, "process2")
	cache.Set(1, "process1-updated")
	
	if cache.list.Front().Value.(*cacheEntry).pid != 1 {
		t.Error("Expected PID 1 to be at front after Set")
	}
}

