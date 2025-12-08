package pathresolver

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type cachedPath struct {
	path      string
	timestamp time.Time
}

type Resolver struct {
	mu           sync.RWMutex
	cache        map[string]string
	inodeToPath  map[string]*cachedPath
	pidFdToPath  map[uint32]map[uint32]*cachedPath
	pidFdToInode map[uint32]map[uint32]string
	maxChecks    int
	cacheTTL     time.Duration
}

func New() *Resolver {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	maxChecks := getIntEnvOrDefault("PODTRACE_PATH_MAX_FD_CHECKS", 100)
	return &Resolver{
		cache:        make(map[string]string),
		inodeToPath:  make(map[string]*cachedPath),
		pidFdToPath:  make(map[uint32]map[uint32]*cachedPath),
		pidFdToInode: make(map[uint32]map[uint32]string),
		maxChecks:    maxChecks,
		cacheTTL:     ttl,
	}
}

func getIntEnvOrDefault(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func (r *Resolver) ResolvePath(pid uint32, target string) string {
	if target == "" || !strings.HasPrefix(target, "ino:") {
		return target
	}

	parts := strings.SplitN(target[4:], "/", 2)
	if len(parts) != 2 {
		return target
	}

	ino, err1 := strconv.ParseUint(parts[0], 10, 32)
	dev, err2 := strconv.ParseUint(parts[1], 10, 32)
	if err1 != nil || err2 != nil {
		return target
	}

	r.mu.RLock()
	if cached, ok := r.inodeToPath[target]; ok {
		if time.Since(cached.timestamp) < r.cacheTTL {
			r.mu.RUnlock()
			return cached.path
		}
	}
	r.mu.RUnlock()

	cacheKey := fmt.Sprintf("%d:%d:%d", pid, ino, dev)
	r.mu.RLock()
	if cached, ok := r.cache[cacheKey]; ok {
		r.mu.RUnlock()
		return cached
	}
	r.mu.RUnlock()

	path := r.resolveInode(pid, uint32(ino), uint32(dev))
	if path != "" {
		r.mu.Lock()
		r.cache[cacheKey] = path
		r.inodeToPath[target] = &cachedPath{
			path:      path,
			timestamp: time.Now(),
		}
		r.mu.Unlock()
		return path
	}

	return target
}

func (r *Resolver) RecordOpen(pid uint32, fd uint32, path string, ino, dev uint32) {
	if path == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	inodeKey := fmt.Sprintf("ino:%d/%d", ino, dev)
	r.inodeToPath[inodeKey] = &cachedPath{
		path:      path,
		timestamp: time.Now(),
	}

	if r.pidFdToPath[pid] == nil {
		r.pidFdToPath[pid] = make(map[uint32]*cachedPath)
	}
	r.pidFdToPath[pid][fd] = &cachedPath{
		path:      path,
		timestamp: time.Now(),
	}

	if r.pidFdToInode[pid] == nil {
		r.pidFdToInode[pid] = make(map[uint32]string)
	}
	r.pidFdToInode[pid][fd] = inodeKey
}

func (r *Resolver) RecordOpenByFD(pid uint32, fd uint32, path string) {
	if path == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pidFdToPath[pid] == nil {
		r.pidFdToPath[pid] = make(map[uint32]*cachedPath)
	}
	r.pidFdToPath[pid][fd] = &cachedPath{
		path:      path,
		timestamp: time.Now(),
	}
}

func (r *Resolver) CorrelateFDWithInode(pid uint32, fd uint32, ino, dev uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pidFdToPath[pid] == nil {
		return
	}

	cached, ok := r.pidFdToPath[pid][fd]
	if !ok {
		return
	}

	if time.Since(cached.timestamp) > 5*time.Second {
		return
	}

	inodeKey := fmt.Sprintf("ino:%d/%d", ino, dev)
	r.inodeToPath[inodeKey] = &cachedPath{
		path:      cached.path,
		timestamp: time.Now(),
	}

	if r.pidFdToInode[pid] == nil {
		r.pidFdToInode[pid] = make(map[uint32]string)
	}
	r.pidFdToInode[pid][fd] = inodeKey
}

func (r *Resolver) isProcessAlive(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("%s/%d", config.ProcBasePath, pid))
	return err == nil
}

func (r *Resolver) resolveInode(pid uint32, ino, dev uint32) string {
	if !r.isProcessAlive(pid) {
		return ""
	}

	fdDir := fmt.Sprintf("%s/%d/fd", config.ProcBasePath, pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ""
	}

	checked := 0

	for _, entry := range entries {
		if checked >= r.maxChecks {
			break
		}

		_, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		checked++

		fdPath := filepath.Join(fdDir, entry.Name())
		linkPath, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		if !filepath.IsAbs(linkPath) {
			linkPath = filepath.Join(fdDir, linkPath)
		}

		var stat syscall.Stat_t
		if err := syscall.Stat(linkPath, &stat); err != nil {
			continue
		}

		if stat.Ino == uint64(ino) && stat.Dev == uint64(dev) {
			return linkPath
		}
	}

	return ""
}

func (r *Resolver) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]string)
	r.inodeToPath = make(map[string]*cachedPath)
	r.pidFdToPath = make(map[uint32]map[uint32]*cachedPath)
	r.pidFdToInode = make(map[uint32]map[uint32]string)
}

func (r *Resolver) CleanupExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for key, cached := range r.inodeToPath {
		if now.Sub(cached.timestamp) > r.cacheTTL {
			delete(r.inodeToPath, key)
		}
	}

	for pid, fdMap := range r.pidFdToPath {
		for fd, cached := range fdMap {
			if now.Sub(cached.timestamp) > r.cacheTTL {
				delete(fdMap, fd)
			}
		}
		if len(fdMap) == 0 {
			delete(r.pidFdToPath, pid)
			delete(r.pidFdToInode, pid)
		}
	}
}
