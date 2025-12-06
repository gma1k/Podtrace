package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/validation"
)

type cacheEntry struct {
	pid       uint32
	name      string
	expiresAt time.Time
	element   *list.Element
}

type LRUCache struct {
	cache      map[uint32]*list.Element
	list       *list.List
	maxSize    int
	ttl        time.Duration
	mutex      sync.RWMutex
	stopCleanup chan struct{}
}

func NewLRUCache(maxSize int, ttl time.Duration) *LRUCache {
	c := &LRUCache{
		cache:      make(map[uint32]*list.Element),
		list:       list.New(),
		maxSize:    maxSize,
		ttl:        ttl,
		stopCleanup: make(chan struct{}),
	}
	go c.cleanupExpired()
	return c
}

func (c *LRUCache) Get(pid uint32) (string, bool) {
	if !validation.ValidatePID(pid) {
		return "", false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	elem, ok := c.cache[pid]
	if !ok {
		return "", false
	}

	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		delete(c.cache, pid)
		c.list.Remove(elem)
		return "", false
	}

	c.list.MoveToFront(elem)
	metricsexporter.RecordProcessCacheHit()
	return entry.name, true
}

func (c *LRUCache) Set(pid uint32, name string) {
	if !validation.ValidatePID(pid) {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if elem, ok := c.cache[pid]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.name = name
		entry.expiresAt = time.Now().Add(c.ttl)
		c.list.MoveToFront(elem)
		return
	}

	if len(c.cache) >= c.maxSize {
		c.evict()
	}

	entry := &cacheEntry{
		pid:       pid,
		name:      name,
		expiresAt: time.Now().Add(c.ttl),
	}
	elem := c.list.PushFront(entry)
	entry.element = elem
	c.cache[pid] = elem
}

func (c *LRUCache) evict() {
	evictTarget := int(float64(c.maxSize) * config.CacheEvictionThreshold)
	for len(c.cache) >= evictTarget {
		back := c.list.Back()
		if back == nil {
			break
		}
		entry := back.Value.(*cacheEntry)
		delete(c.cache, entry.pid)
		c.list.Remove(back)
	}
}

func (c *LRUCache) cleanupExpired() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mutex.Lock()
			now := time.Now()
			var toRemove []*list.Element
			for _, elem := range c.cache {
				entry := elem.Value.(*cacheEntry)
				if now.After(entry.expiresAt) {
					toRemove = append(toRemove, elem)
				}
			}
			for _, elem := range toRemove {
				entry := elem.Value.(*cacheEntry)
				delete(c.cache, entry.pid)
				c.list.Remove(elem)
			}
			c.mutex.Unlock()
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *LRUCache) Close() {
	close(c.stopCleanup)
}

