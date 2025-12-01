package tracker

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

type PidInfo struct {
	Pid        uint32
	Name       string
	Count      int
	Percentage float64
}

func AnalyzeProcessActivity(events []*events.Event) []PidInfo {
	pidMap := make(map[uint32]int)
	totalEvents := len(events)

	for _, e := range events {
		pidMap[e.PID]++
	}

	var pidInfos []PidInfo
	for pid, count := range pidMap {
		percentage := float64(count) / float64(totalEvents) * 100
		name := ""
		for _, e := range events {
			if e.PID == pid && e.ProcessName != "" {
				name = e.ProcessName
				break
			}
		}
		if name == "" {
			name = getProcessName(pid)
		}
		if name == "" {
			name = "unknown"
		}
		pidInfos = append(pidInfos, PidInfo{
			Pid:        pid,
			Name:       name,
			Count:      count,
			Percentage: percentage,
		})
	}

	sort.Slice(pidInfos, func(i, j int) bool {
		return pidInfos[i].Count > pidInfos[j].Count
	})

	return pidInfos
}

func getProcessName(pid uint32) string {
	name := getProcessNameFromProc(pid)
	return validation.SanitizeProcessName(name)
}

func getProcessNameFromProc(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	name := ""

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if data, err := os.ReadFile(statPath); err == nil {
		statStr := string(data)
		start := strings.Index(statStr, "(")
		end := strings.LastIndex(statStr, ")")
		if start >= 0 && end > start {
			name = statStr[start+1 : end]
		}
	}

	if name == "" {
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	if name == "" {
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
	}

	if name == "" {
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if link, err := os.Readlink(exePath); err == nil {
			if idx := strings.LastIndex(link, "/"); idx >= 0 {
				name = link[idx+1:]
			} else {
				name = link
			}
		}
	}

	if name == "" {
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		if data, err := os.ReadFile(statusPath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Name:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						name = parts[1]
						break
					}
				}
			}
		}
	}

	return name
}
