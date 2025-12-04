package ebpf

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/validation"
)

var (
	processNameCache      = make(map[uint32]string)
	processNameCacheMutex = &sync.RWMutex{}
)

func getProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	processNameCacheMutex.RLock()
	if name, ok := processNameCache[pid]; ok {
		processNameCacheMutex.RUnlock()
		return name
	}
	processNameCacheMutex.RUnlock()

	name := ""

	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		statPath := fmt.Sprintf("/proc/%d/stat", pid)
		if data, err := os.ReadFile(statPath); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	processNameCacheMutex.Lock()
	if len(processNameCache) >= config.MaxProcessCacheSize {
		evictCount := len(processNameCache) - int(float64(config.MaxProcessCacheSize)*config.ProcessCacheEvictionRatio)
		for k := range processNameCache {
			delete(processNameCache, k)
			evictCount--
			if evictCount <= 0 {
				break
			}
		}
	}
	processNameCache[pid] = name
	processNameCacheMutex.Unlock()

	return validation.SanitizeProcessName(name)
}
