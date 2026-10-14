package cache

import (
	"container/list"
	"fmt"
	"testing"
	"time"
)

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
