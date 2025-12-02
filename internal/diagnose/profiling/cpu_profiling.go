package profiling

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func GenerateCPUUsageReport(events []*events.Event, duration time.Duration) string {
	pidActivity := tracker.AnalyzeProcessActivity(events)
	if len(pidActivity) == 0 {
		return GenerateCPUUsageFromProc(duration)
	}

	report := "CPU Usage by Process:\n"

	durationSec := duration.Seconds()
	totalCPUPercent := 0.0

	pidCPUTimes := make(map[uint32]cpuTimeInfo)
	for _, info := range pidActivity {
		cpuTime := getProcessCPUTime(info.Pid)
		if cpuTime.totalNS > 0 {
			cpuPercent := (float64(cpuTime.totalNS) / 1e9) / durationSec * 100.0
			pidCPUTimes[info.Pid] = cpuTimeInfo{
				cpuPercent: cpuPercent,
				cpuTimeSec: float64(cpuTime.totalNS) / 1e9,
				name:       info.Name,
			}
		}
	}

	type cpuUsageInfo struct {
		pid        uint32
		name       string
		cpuPercent float64
		cpuTimeSec float64
	}

	var podProcesses []cpuUsageInfo
	var kernelProcesses []cpuUsageInfo

	for pid, cpuInfo := range pidCPUTimes {
		info := cpuUsageInfo{
			pid:        pid,
			name:       cpuInfo.name,
			cpuPercent: cpuInfo.cpuPercent,
			cpuTimeSec: cpuInfo.cpuTimeSec,
		}
		if IsKernelThread(pid, cpuInfo.name) {
			kernelProcesses = append(kernelProcesses, info)
		} else {
			podProcesses = append(podProcesses, info)
		}
	}

	sort.Slice(podProcesses, func(i, j int) bool {
		return podProcesses[i].cpuPercent > podProcesses[j].cpuPercent
	})
	sort.Slice(kernelProcesses, func(i, j int) bool {
		return kernelProcesses[i].cpuPercent > kernelProcesses[j].cpuPercent
	})

	podCPUPercent := 0.0
	if len(podProcesses) > 0 {
		report += "  Pod Processes:\n"
		for i, info := range podProcesses {
			if i >= 10 {
				break
			}
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%.2fs / %.2fs)\n",
				info.pid, info.name, info.cpuPercent, info.cpuTimeSec, durationSec)
			podCPUPercent += info.cpuPercent
		}
		report += "\n"
	}

	if len(kernelProcesses) > 0 {
		kernelCPUPercent := 0.0
		report += "  System/Kernel Processes:\n"
		for i, info := range kernelProcesses {
			if i >= 5 {
				break
			}
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%.2fs / %.2fs)\n",
				info.pid, info.name, info.cpuPercent, info.cpuTimeSec, durationSec)
			kernelCPUPercent += info.cpuPercent
		}
		if extra := len(kernelProcesses) - 5; extra > 0 {
			report += fmt.Sprintf("    ... and %d more system processes\n", extra)
		}
		report += "\n"
		totalCPUPercent = podCPUPercent + kernelCPUPercent
	} else {
		totalCPUPercent = podCPUPercent
	}

	report += fmt.Sprintf("\n  Total CPU usage: %.1f%% (%.2fs / %.2fs)\n",
		totalCPUPercent, totalCPUPercent*durationSec/100.0, durationSec)
	report += fmt.Sprintf("  Idle time: %.1f%% (%.2fs / %.2fs)\n\n",
		100.0-totalCPUPercent, (100.0-totalCPUPercent)*durationSec/100.0, durationSec)

	return report
}

type cpuTimeInfo struct {
	totalNS    uint64
	cpuPercent float64
	cpuTimeSec float64
	name       string
}

func getProcessCPUTime(pid uint32) cpuTimeInfo {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return cpuTimeInfo{}
	}

	fields := strings.Fields(string(data))
	if len(fields) < 14 {
		return cpuTimeInfo{}
	}

	utime, _ := strconv.ParseUint(fields[13], 10, 64)
	stime, _ := strconv.ParseUint(fields[14], 10, 64)

	clockTicks := uint64(100)
	if data, err := os.ReadFile("/proc/self/auxv"); err == nil {
		for i := 0; i < len(data)-8; i += 16 {
			key := uint64(data[i]) | uint64(data[i+1])<<8 | uint64(data[i+2])<<16 | uint64(data[i+3])<<24 |
				uint64(data[i+4])<<32 | uint64(data[i+5])<<40 | uint64(data[i+6])<<48 | uint64(data[i+7])<<56
			if key == 11 {
				clockTicks = uint64(data[i+8]) | uint64(data[i+9])<<8 | uint64(data[i+10])<<16 | uint64(data[i+11])<<24 |
					uint64(data[i+12])<<32 | uint64(data[i+13])<<40 | uint64(data[i+14])<<48 | uint64(data[i+15])<<56
				break
			}
		}
	}

	if clockTicks == 0 {
		clockTicks = 100
	}

	totalNS := (utime + stime) * (1e9 / clockTicks)
	return cpuTimeInfo{totalNS: totalNS}
}

func IsKernelThread(pid uint32, name string) bool {

	kernelPrefixes := []string{
		"kworker",
		"irq/",
		"ksoftirqd",
		"migration",
		"rcu_",
		"rcu_sched",
		"rcu_bh",
		"watchdog",
		"khugepaged",
		"kswapd",
		"kthreadd",
		"jbd2",
		"dmcrypt",
		"kcryptd",
	}

	nameLower := strings.ToLower(name)
	for _, prefix := range kernelPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return true
		}
	}

	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		return true
	}

	return false
}

func GenerateCPUUsageFromProc(duration time.Duration) string {
	report := "CPU Usage by Process:\n"
	report += "  No CPU events collected during diagnostic period.\n"
	report += "  This may indicate:\n"
	report += "    - Pod is idle or sleeping\n"
	report += "    - eBPF probes not attached correctly\n"
	report += "    - No processes matching cgroup filter\n"
	report += "  Try:\n"
	report += "    - Longer duration: --diagnose 30s\n"
	report += "    - Check pod is active: kubectl logs <pod-name>\n"
	report += "    - Verify eBPF attachment (check stderr output)\n\n"
	return report
}
