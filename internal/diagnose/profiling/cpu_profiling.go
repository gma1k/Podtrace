package profiling

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/procfs"
)

func GenerateCPUUsageReport(allEvents []*events.Event, duration time.Duration) string {
	return GenerateProcessCPUReport(allEvents, duration, nil)
}

// GenerateProcessCPUReport reports CPU time per traced process. kernelNS is
// the kernel's on-CPU time per process ID, which also covers processes that
// exited before /proc could be read; /proc is the fallback for the rest.
func GenerateProcessCPUReport(allEvents []*events.Event, duration time.Duration, kernelNS map[uint32]uint64) string {
	pidActivity := tracker.AnalyzeProcessActivity(allEvents)
	if len(pidActivity) == 0 {
		return GenerateCPUUsageFromProc(duration)
	}

	report := "CPU Usage by Process:\n"

	durationSec := duration.Seconds()
	totalCPUPercent := 0.0

	pidCPUTimes := make(map[uint32]cpuTimeInfo)
	for _, info := range pidActivity {
		deltaNS := kernelNS[info.Pid]
		if deltaNS == 0 {
			deltaNS = procCPUDeltaNS(info.Pid)
		}
		if deltaNS > 0 {
			cpuPercent := (float64(deltaNS) / 1e9) / durationSec * 100.0
			if maxPercent := 100.0 * float64(runtime.NumCPU()); cpuPercent > maxPercent {
				cpuPercent = maxPercent
			}
			pidCPUTimes[info.Pid] = cpuTimeInfo{
				cpuPercent: cpuPercent,
				cpuTimeSec: float64(deltaNS) / 1e9,
				name:       info.Name,
			}
		}
	}

	if len(pidCPUTimes) == 0 {
		return report + "  " + cpuUnavailable(pidActivity) + "\n\n"
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
			if i >= config.TopProcessesLimit*2 {
				break
			}
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%s / %.2fs)\n",
				info.pid, info.name, info.cpuPercent, formatCPUTime(info.cpuTimeSec), durationSec)
			podCPUPercent += info.cpuPercent
		}
		report += "\n"
	}

	if len(kernelProcesses) > 0 {
		kernelCPUPercent := 0.0
		report += "  System/Kernel Processes:\n"
		for i, info := range kernelProcesses {
			if i >= config.TopProcessesLimit {
				break
			}
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%s / %.2fs)\n",
				info.pid, info.name, info.cpuPercent, formatCPUTime(info.cpuTimeSec), durationSec)
			kernelCPUPercent += info.cpuPercent
		}
		if extra := len(kernelProcesses) - config.TopProcessesLimit; extra > 0 {
			report += fmt.Sprintf("    ... and %d more system processes\n", extra)
		}
		report += "\n"
		totalCPUPercent = podCPUPercent + kernelCPUPercent
	} else {
		totalCPUPercent = podCPUPercent
	}

	idlePercent := 100.0 - totalCPUPercent
	if idlePercent < 0 {
		idlePercent = 0
	}
	report += fmt.Sprintf("\n  Total CPU usage: %.1f%% (%.2fs / %.2fs)\n",
		totalCPUPercent, totalCPUPercent*durationSec/100.0, durationSec)
	report += fmt.Sprintf("  Idle time: %.1f%% (%.2fs / %.2fs)\n\n",
		idlePercent, idlePercent*durationSec/100.0, durationSec)

	return report
}

// formatCPUTime keeps a short-lived process's few milliseconds readable
// instead of rounding them to 0.00s.
func formatCPUTime(sec float64) string {
	if sec < 1 {
		return fmt.Sprintf("%.1fms", sec*1000)
	}
	return fmt.Sprintf("%.2fs", sec)
}

// procCPUDeltaNS is the CPU time /proc shows for pid since the tracer first
// saw it, in whole scheduler ticks; zero once the process has exited.
func procCPUDeltaNS(pid uint32) uint64 {
	totalNS := getProcessCPUTime(pid).totalNS
	if base := cache.GetCPUTime(pid).BaselineNS; base > 0 && totalNS >= base {
		return totalNS - base
	}
	return totalNS
}

// cpuUnavailable says why no process got a CPU figure, instead of repeating
// the event ranking the Process Activity section already shows.
func cpuUnavailable(activity []tracker.PidInfo) string {
	exited := 0
	for _, a := range activity {
		if _, err := procfs.ReadFile(fmt.Sprintf("%d/stat", a.Pid)); err != nil {
			exited++
		}
	}
	n := len(activity)
	noun := "processes"
	if n == 1 {
		noun = "process"
	}
	var why string
	switch {
	case exited == n && n == 1:
		why = "it exited before sampling"
	case exited == n:
		why = "all exited before sampling"
	case exited > 0:
		why = fmt.Sprintf("%d exited before sampling, the rest had no CPU samples", exited)
	default:
		why = "no CPU samples"
	}
	return fmt.Sprintf("CPU time unavailable for the %d traced %s (%s); see Process Activity for event counts.", n, noun, why)
}

type cpuTimeInfo struct {
	totalNS    uint64
	cpuPercent float64
	cpuTimeSec float64
	name       string
}

func getProcessCPUTime(pid uint32) cpuTimeInfo {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/stat", pid))
	if err != nil {
		if cached := cache.GetCPUTime(pid); cached.TotalNS > 0 {
			return cpuTimeInfo{totalNS: cached.TotalNS}
		}
		return cpuTimeInfo{}
	}

	raw := string(data)
	rparen := strings.LastIndex(raw, ")")
	if rparen < 0 || rparen+2 > len(raw) {
		return cpuTimeInfo{}
	}
	fields := strings.Fields(raw[rparen+1:])
	if len(fields) < 13 {
		return cpuTimeInfo{}
	}

	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)

	clockTicks := uint64(100)
	if data, err := procfs.ReadFile("self/auxv"); err == nil {
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
