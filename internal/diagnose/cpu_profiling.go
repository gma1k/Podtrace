package diagnose

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func (d *Diagnostician) generateCPUUsageReport(duration time.Duration) string {
	
	pidActivity := d.analyzeProcessActivity()
	if len(pidActivity) == 0 {
		return d.generateCPUUsageFromProc(duration)
	}
	
	totalActivity := 0
	for _, info := range pidActivity {
		totalActivity += info.count
	}
	
	if totalActivity == 0 {
		return d.generateCPUUsageFromProc(duration)
	}
	
	var report string
	report += fmt.Sprintf("CPU Usage by Process:\n")
	
	totalDurationNS := uint64(duration.Nanoseconds())
	totalCPUPercent := 0.0
	
	sort.Slice(pidActivity, func(i, j int) bool {
		return pidActivity[i].count > pidActivity[j].count
	})
	
	var podProcesses []pidInfo
	var kernelProcesses []pidInfo
	
	for _, info := range pidActivity {
		if isKernelThread(info.pid, info.name) {
			kernelProcesses = append(kernelProcesses, info)
		} else {
			podProcesses = append(podProcesses, info)
		}
	}
	
	podCPUPercent := 0.0
	if len(podProcesses) > 0 {
		report += fmt.Sprintf("  Pod Processes:\n")
		for i, info := range podProcesses {
			if i >= 10 {
				break
			}
			
			cpuTimeNS := uint64(float64(totalDurationNS) * info.percentage / 100.0)
			cpuPercent := info.percentage
			cpuTimeSec := float64(cpuTimeNS) / 1e9
			durationSec := duration.Seconds()
			
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%.2fs / %.2fs)\n",
				info.pid, info.name, cpuPercent, cpuTimeSec, durationSec)
			
			podCPUPercent += cpuPercent
		}
		report += "\n"
	}
	
	if len(kernelProcesses) > 0 {
		kernelCPUPercent := 0.0
		report += fmt.Sprintf("  System/Kernel Processes:\n")
		for i, info := range kernelProcesses {
			if i >= 5 { 
				break
			}
			
			cpuTimeNS := uint64(float64(totalDurationNS) * info.percentage / 100.0)
			cpuPercent := info.percentage
			cpuTimeSec := float64(cpuTimeNS) / 1e9
			durationSec := duration.Seconds()
			
			report += fmt.Sprintf("    PID %d (%s):      %5.1f%% CPU (%.2fs / %.2fs)\n",
				info.pid, info.name, cpuPercent, cpuTimeSec, durationSec)
			
			kernelCPUPercent += cpuPercent
		}
		if len(kernelProcesses) > 5 {
			report += fmt.Sprintf("    ... and %d more system processes\n", len(kernelProcesses)-5)
		}
		report += "\n"
		totalCPUPercent = podCPUPercent + kernelCPUPercent
	} else {
		totalCPUPercent = podCPUPercent
	}
	
	report += fmt.Sprintf("\n  Total CPU usage: %.1f%% (%.2fs / %.2fs)\n",
		totalCPUPercent, totalCPUPercent*duration.Seconds()/100.0, duration.Seconds())
	report += fmt.Sprintf("  Idle time: %.1f%% (%.2fs / %.2fs)\n\n",
		100.0-totalCPUPercent, (100.0-totalCPUPercent)*duration.Seconds()/100.0, duration.Seconds())
	
	return report
}

func isKernelThread(pid uint32, name string) bool {
	
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

func (d *Diagnostician) generateCPUUsageFromProc(duration time.Duration) string {
	var report string
	report += fmt.Sprintf("CPU Usage by Process:\n")
	report += fmt.Sprintf("  ⚠ No CPU events collected during diagnostic period.\n")
	report += fmt.Sprintf("  This may indicate:\n")
	report += fmt.Sprintf("    - Pod is idle or sleeping\n")
	report += fmt.Sprintf("    - eBPF probes not attached correctly\n")
	report += fmt.Sprintf("    - No processes matching cgroup filter\n")
	report += fmt.Sprintf("  Try:\n")
	report += fmt.Sprintf("    - Longer duration: --diagnose 30s\n")
	report += fmt.Sprintf("    - Check pod is active: kubectl logs <pod-name>\n")
	report += fmt.Sprintf("    - Verify eBPF attachment (check stderr output)\n\n")
	return report
}
