package filter

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/validation"
)

var readFile = os.ReadFile

type CgroupFilter struct {
	cgroupPath string
	pidCache   map[uint32]bool
	pidCacheMu sync.RWMutex
}

func NewCgroupFilter() *CgroupFilter {
	return &CgroupFilter{
		pidCache: make(map[uint32]bool),
	}
}

func (f *CgroupFilter) SetCgroupPath(path string) {
	f.cgroupPath = path
}

func (f *CgroupFilter) IsPIDInCgroup(pid uint32) bool {
	if f.cgroupPath == "" {
		return true
	}

	if !validation.ValidatePID(pid) {
		return false
	}

	f.pidCacheMu.RLock()
	if cached, ok := f.pidCache[pid]; ok {
		f.pidCacheMu.RUnlock()
		metricsexporter.RecordPIDCacheHit()
		return cached
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
		f.pidCache[pid] = false
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
		f.pidCache[pid] = false
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

	normalizedTarget := NormalizeCgroupPath(f.cgroupPath)
	normalizedPID := NormalizeCgroupPath(pidCgroupPath)

	result := false
	// If the configured target normalizes to empty (e.g. "/" or the cgroup base),
	// treat it as invalid to avoid accidentally matching everything.
	if normalizedTarget == "" {
		result = false
	} else if normalizedPID == normalizedTarget {
		result = true
	} else if strings.HasPrefix(normalizedPID, normalizedTarget+"/") {
		result = true
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
	f.pidCache[pid] = result
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
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
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
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return ""
}
