package resource

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/logger"
)

type cpuQuotaValue struct {
	QuotaMicros  uint64
	PeriodMicros uint64
}

func (rm *ResourceMonitor) EnableBPFCPUSampler(quotaMap bpfLimitMap, alertsMap bpfAlertReadMap) {
	if quotaMap == nil || alertsMap == nil {
		return
	}
	rm.mu.Lock()
	rm.cpuQuotaMap = quotaMap
	rm.cpuAlertsReadMap = alertsMap
	rm.cpuSamplerOn = true
	rm.mu.Unlock()

	if err := rm.syncCPUQuota(); err != nil {
		logger.Warn("Failed to sync CPU quota to BPF sampler", zap.Error(err))
	}
}

func (rm *ResourceMonitor) syncCPUQuota() error {
	rm.mu.RLock()
	quotaMap := rm.cpuQuotaMap
	quota := rm.cpuQuotaMicros
	period := rm.cpuPeriodMicros
	inode := rm.cgroupInode
	rm.mu.RUnlock()

	if quotaMap == nil {
		return nil
	}
	if quota == 0 || period == 0 {
		if err := quotaMap.Delete(inode); err != nil && !isBenignMapDeleteError(err) {
			return fmt.Errorf("clear CPU quota: %w", err)
		}
		return nil
	}
	value := cpuQuotaValue{QuotaMicros: quota, PeriodMicros: period}
	if err := quotaMap.Put(inode, value); err != nil {
		return fmt.Errorf("put CPU quota: %w", err)
	}
	return nil
}

func (rm *ResourceMonitor) checkBPFCPUAlerts() {
	rm.mu.RLock()
	alertsMap := rm.cpuAlertsReadMap
	on := rm.cpuSamplerOn
	inode := rm.cgroupInode
	quota := rm.cpuQuotaMicros
	period := rm.cpuPeriodMicros
	rm.mu.RUnlock()

	if !on || alertsMap == nil {
		return
	}

	key := resourceMapKey{CgroupID: inode, ResourceType: ResourceCPU}
	var level uint32
	if err := alertsMap.Lookup(key, &level); err != nil {
		if !isBenignMapDeleteError(err) {
			logger.Debug("Failed to read CPU alert from BPF map", zap.Error(err))
		}
		return
	}
	if level == AlertNone {
		return
	}

	manager := alerting.GetGlobalManager()
	if manager == nil {
		return
	}

	severity := alerting.MapResourceAlertLevel(level)
	allowedCPUs := "unknown"
	if period > 0 {
		allowedCPUs = fmt.Sprintf("%.2f", float64(quota)/float64(period))
	}
	title := fmt.Sprintf("Resource Limit %s", severity)
	message := fmt.Sprintf("cpu utilization reached %s threshold (limit: %s CPUs)", severity, allowedCPUs)
	podName, namespace := rm.alertSubject()
	alert := &alerting.Alert{
		Severity:  severity,
		Title:     title,
		Message:   message,
		PodName:   podName,
		Timestamp: time.Now(),
		Source:    alerting.AlertSourceResourceMonitorBPF,
		Namespace: namespace,
		Context: map[string]interface{}{
			"resource_type": "cpu",
			"alert_level":   level,
			"cpu_limit":     allowedCPUs,
			"cgroup_path":   rm.cgroupPath,
			"detected_by":   "in-kernel sampler",
		},
		Recommendations: []string{
			"Check for CPU-bound hot loops",
			"Review CPU limits",
			"Consider scaling up pod CPU resources",
		},
	}
	manager.SendAlert(alert)
}
