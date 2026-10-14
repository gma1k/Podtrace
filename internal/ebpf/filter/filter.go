package filter

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/validation"
)

var readFile = os.ReadFile

type pidCacheEntry struct {
	result bool
	at     time.Time
}

type CgroupFilter struct {
	cgroupPath  string
	cgroupPaths map[string]struct{}
	pidCache    map[uint32]pidCacheEntry
	pidCacheMu  sync.RWMutex
	pathsMu     sync.RWMutex
	now         func() time.Time
	ttl         time.Duration
}

func NewCgroupFilter() *CgroupFilter {
	return &CgroupFilter{
		cgroupPaths: make(map[string]struct{}),
		pidCache:    make(map[uint32]pidCacheEntry),
	}
}

func (f *CgroupFilter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

func (f *CgroupFilter) cacheTTL() time.Duration {
	if f.ttl > 0 {
		return f.ttl
	}
	return time.Duration(config.PIDCacheTTLSeconds) * time.Second
}

func (f *CgroupFilter) SetCgroupPath(path string) {
	f.pathsMu.Lock()
	f.cgroupPath = path
	f.cgroupPaths = make(map[string]struct{})
	if path != "" {
		f.cgroupPaths[path] = struct{}{}
	}
	f.pathsMu.Unlock()
	f.pidCacheMu.Lock()
	f.pidCache = make(map[uint32]pidCacheEntry)
	f.pidCacheMu.Unlock()
}

func (f *CgroupFilter) SetCgroupPaths(paths []string) {
	f.pathsMu.Lock()
	f.cgroupPath = ""
	f.cgroupPaths = make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		f.cgroupPaths[path] = struct{}{}
	}
	f.pathsMu.Unlock()
	f.pidCacheMu.Lock()
	f.pidCache = make(map[uint32]pidCacheEntry)
	f.pidCacheMu.Unlock()
}

// snapshotTargets copies the configured target paths under pathsMu. The
// agent calls SetCgroupPaths on every reconcile while IsPIDInCgroup runs on
// the event hot path; only pidCache used to be locked, so the map swap raced
// the iteration below.
func (f *CgroupFilter) snapshotTargets() []string {
	f.pathsMu.RLock()
	defer f.pathsMu.RUnlock()
	targets := make([]string, 0, len(f.cgroupPaths)+1)
	if f.cgroupPath != "" {
		targets = append(targets, f.cgroupPath)
	}
	for p := range f.cgroupPaths {
		if p != "" {
			targets = append(targets, p)
		}
	}
	return targets
}

// HasTargets reports whether any cgroup target is configured.
func (f *CgroupFilter) HasTargets() bool {
	f.pathsMu.RLock()
	defer f.pathsMu.RUnlock()
	if f.cgroupPath != "" {
		return true
	}
	for p := range f.cgroupPaths {
		if p != "" {
			return true
		}
	}
	return false
}

func (f *CgroupFilter) IsPIDInCgroup(pid uint32) bool {
	configuredTargets := f.snapshotTargets()
	if len(configuredTargets) == 0 {
		return true
	}

	if !validation.ValidatePID(pid) {
		return false
	}

	f.pidCacheMu.RLock()
	if cached, ok := f.pidCache[pid]; ok && f.clock().Sub(cached.at) < f.cacheTTL() {
		f.pidCacheMu.RUnlock()
		metricsexporter.RecordPIDCacheHit()
		return cached.result
	}
	f.pidCacheMu.RUnlock()
	metricsexporter.RecordPIDCacheMiss()

	cgroupFile := fmt.Sprintf("%s/%d/cgroup", config.ProcBasePath, pid)
	if len(cgroupFile) > config.MaxCgroupFilePathLength {
		return false
	}
	data, err := readFile(cgroupFile)
	if err != nil {
		f.pidCacheMu.Lock()
		f.pidCache[pid] = pidCacheEntry{result: false, at: f.clock()}
		if len(f.pidCache) > config.MaxPIDCacheSize {
			evictCount := len(f.pidCache) / 10
			if evictCount < 1 {
				evictCount = 1
			}
			for k := range f.pidCache {
				delete(f.pidCache, k)
				evictCount--
				if evictCount <= 0 {
					break
				}
			}
		}
		f.pidCacheMu.Unlock()
		return false
	}

	cgroupContent := strings.TrimSpace(string(data))
	pidCgroupPath := ExtractCgroupPathFromProc(cgroupContent)
	if pidCgroupPath == "" {
		f.pidCacheMu.Lock()
		f.pidCache[pid] = pidCacheEntry{result: false, at: f.clock()}
		if len(f.pidCache) > config.MaxPIDCacheSize {
			evictCount := len(f.pidCache) / 10
			if evictCount < 1 {
				evictCount = 1
			}
			for k := range f.pidCache {
				delete(f.pidCache, k)
				evictCount--
				if evictCount <= 0 {
					break
				}
			}
		}
		f.pidCacheMu.Unlock()
		return false
	}

	normalizedPID := NormalizeCgroupPath(pidCgroupPath)

	result := false
	for _, target := range configuredTargets {
		normalizedTarget := NormalizeCgroupPath(target)
		// If the configured target normalizes to empty (e.g. "/" or the cgroup base),
		// treat it as invalid to avoid accidentally matching everything.
		if normalizedTarget == "" {
			continue
		}
		if normalizedPID == normalizedTarget || strings.HasPrefix(normalizedPID, normalizedTarget+"/") {
			result = true
			break
		}
	}

	f.pidCacheMu.Lock()
	if len(f.pidCache) >= config.MaxPIDCacheSize {
		evictTarget := int(float64(config.MaxPIDCacheSize) * config.PIDCacheEvictionRatio)
		for k := range f.pidCache {
			delete(f.pidCache, k)
			if len(f.pidCache) < evictTarget {
				break
			}
		}
	}
	f.pidCache[pid] = pidCacheEntry{result: result, at: f.clock()}
	f.pidCacheMu.Unlock()

	return result
}

func NormalizeCgroupPath(path string) string {
	path = strings.TrimPrefix(path, config.CgroupBasePath)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	return path
}

func ExtractCgroupPathFromProc(cgroupContent string) string {
	lines := strings.Split(cgroupContent, "\n")
	// Prefer cgroup v2 unified hierarchy line wherever it appears.
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}

	// Fallback to cgroup v1: pick a "cpu" controller if possible, else any valid line.
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			controllers := parts[1]
			if controllers == "cpu" || controllers == "cpu,cpuacct" || strings.Contains(controllers, "cpu") {
				return parts[2]
			}
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			return parts[2]
		}
	}
	return ""
}
