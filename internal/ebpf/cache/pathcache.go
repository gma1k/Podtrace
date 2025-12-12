package cache

import (
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type pathCacheEntry struct {
	path      string
	timestamp time.Time
}

type PathCache struct {
	mu    sync.RWMutex
	cache map[string]*pathCacheEntry
	ttl   time.Duration
}

func NewPathCache() *PathCache {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	return &PathCache{
		cache: make(map[string]*pathCacheEntry),
		ttl:   ttl,
	}
}

func (pc *PathCache) Get(key string) (string, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	entry, ok := pc.cache[key]
	if !ok {
		return "", false
	}
	if time.Since(entry.timestamp) > pc.ttl {
		return "", false
	}
	return entry.path, true
}

func (pc *PathCache) Set(key, path string) {
	if path == "" {
		return
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.cache[key] = &pathCacheEntry{
		path:      path,
		timestamp: time.Now(),
	}
}

func (pc *PathCache) Clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.cache = make(map[string]*pathCacheEntry)
}

func (pc *PathCache) CleanupExpired() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	now := time.Now()
	for key, entry := range pc.cache {
		if now.Sub(entry.timestamp) > pc.ttl {
			delete(pc.cache, key)
		}
	}
}

