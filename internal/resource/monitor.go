package resource

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
)

const (
	ResourceCPU    = 0
	ResourceMemory = 1
	ResourceIO     = 2
)

const (
	AlertNone      = 0
	AlertWarning   = 1
	AlertCritical  = 2
	AlertEmergency = 3
)

type ResourceLimit struct {
	LimitBytes   uint64
	UsageBytes   uint64
	LastUpdateNS uint64
	ResourceType uint32
}

type ResourceMonitor struct {
	cgroupPath    string
	cgroupInode   uint64
	limitsMap     *ebpf.Map
	alertsMap     *ebpf.Map
	eventChan     chan<- *events.Event
	mu            sync.RWMutex
	limits        map[uint32]*ResourceLimit
	checkInterval time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	namespace     string
}

func NewResourceMonitor(cgroupPath string, limitsMap, alertsMap *ebpf.Map, eventChan chan<- *events.Event, namespace string) (*ResourceMonitor, error) {
	inode, err := getCgroupInode(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get cgroup inode: %w", err)
	}

	rm := &ResourceMonitor{
		cgroupPath:    cgroupPath,
		cgroupInode:   inode,
		limitsMap:     limitsMap,
		alertsMap:     alertsMap,
		eventChan:     eventChan,
		limits:        make(map[uint32]*ResourceLimit),
		checkInterval: 5 * time.Second,
		stopCh:        make(chan struct{}),
		namespace:     namespace,
	}

	if err := rm.readLimits(); err != nil {
		logger.Warn("Failed to read initial resource limits", zap.Error(err), zap.String("cgroup_path", cgroupPath))
	} else {
		logger.Debug("Resource limits read successfully", zap.Int("num_limits", len(rm.limits)))
		for rType, limit := range rm.limits {
			logger.Debug("Resource limit", zap.Uint32("type", rType), zap.Uint64("limit", limit.LimitBytes))
		}
	}

	return rm, nil
}

func (rm *ResourceMonitor) Start(ctx context.Context) {
	rm.wg.Add(1)
	go rm.monitorLoop(ctx)
}

func (rm *ResourceMonitor) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
}

func (rm *ResourceMonitor) monitorLoop(ctx context.Context) {
	defer rm.wg.Done()

	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case <-ticker.C:
			if err := rm.updateResourceUsage(); err != nil {
				logger.Debug("Failed to update resource usage", zap.Error(err))
			}
			rm.checkAlerts()
		}
	}
}

func (rm *ResourceMonitor) readLimits() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	isV2, err := isCgroupV2(rm.cgroupPath)
	if err != nil {
		return err
	}

	if isV2 {
		return rm.readLimitsV2()
	}
	return rm.readLimitsV1()
}

func (rm *ResourceMonitor) readLimitsV2() error {
	logger.Debug("Reading cgroup v2 limits", zap.String("cgroup_path", rm.cgroupPath))
	cpuMaxPath := filepath.Join(rm.cgroupPath, "cpu.max")
	cpuMax, err := readCgroupFile(cpuMaxPath)
	if err == nil {
		quota, period, unlimited := parseCPUMax(cpuMax)
		if !unlimited && quota > 0 {
			rm.limits[ResourceCPU] = &ResourceLimit{
				LimitBytes:   quota,
				ResourceType: ResourceCPU,
				LastUpdateNS: period,
			}
			logger.Debug("CPU limit read", zap.Uint64("quota", quota), zap.Uint64("period", period))
		} else {
			logger.Debug("CPU limit is unlimited or zero", zap.String("cpu_max", cpuMax))
		}
	} else {
		logger.Debug("Failed to read CPU limit", zap.String("path", cpuMaxPath), zap.Error(err))
	}

	memMaxPath := filepath.Join(rm.cgroupPath, "memory.max")
	memMax, err := readCgroupFile(memMaxPath)
	if err == nil {
		limit := parseMemoryMax(memMax)
		if limit > 0 && limit != ^uint64(0) {
			rm.limits[ResourceMemory] = &ResourceLimit{
				LimitBytes:   limit,
				ResourceType: ResourceMemory,
				LastUpdateNS: uint64(time.Now().UnixNano()),
			}
			logger.Debug("Memory limit read", zap.Uint64("limit", limit))
		} else {
			logger.Debug("Memory limit is unlimited or zero", zap.String("mem_max", memMax))
		}
	} else {
		logger.Debug("Failed to read memory limit", zap.String("path", memMaxPath), zap.Error(err))
	}

	ioMax, err := readCgroupFile(filepath.Join(rm.cgroupPath, "io.max"))
	if err == nil {
		limit := parseIOMax(ioMax)
		if limit > 0 {
			rm.limits[ResourceIO] = &ResourceLimit{
				LimitBytes:   limit,
				ResourceType: ResourceIO,
				LastUpdateNS: uint64(time.Now().UnixNano()),
			}
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) readLimitsV1() error {
	cpuQuota, _ := readCgroupFile(filepath.Join(rm.cgroupPath, "cpu", "cpu.cfs_quota_us"))
	cpuPeriod, _ := readCgroupFile(filepath.Join(rm.cgroupPath, "cpu", "cpu.cfs_period_us"))
	if cpuQuota != "" && cpuPeriod != "" {
		quota, _ := strconv.ParseUint(strings.TrimSpace(cpuQuota), 10, 64)
		period, _ := strconv.ParseUint(strings.TrimSpace(cpuPeriod), 10, 64)
		if quota > 0 && period > 0 {
			rm.limits[ResourceCPU] = &ResourceLimit{
				LimitBytes:   quota,
				ResourceType: ResourceCPU,
				LastUpdateNS: uint64(time.Now().UnixNano()),
			}
		}
	}

	memLimit, err := readCgroupFile(filepath.Join(rm.cgroupPath, "memory", "memory.limit_in_bytes"))
	if err == nil {
		limit := parseMemoryMax(memLimit)
		if limit > 0 {
			rm.limits[ResourceMemory] = &ResourceLimit{
				LimitBytes:   limit,
				ResourceType: ResourceMemory,
				LastUpdateNS: uint64(time.Now().UnixNano()),
			}
		}
	}

	ioRead, _ := readCgroupFile(filepath.Join(rm.cgroupPath, "blkio", "blkio.throttle.read_bps_device"))
	if ioRead != "" {
		limit := parseIOV1(ioRead)
		if limit > 0 {
			rm.limits[ResourceIO] = &ResourceLimit{
				LimitBytes:   limit,
				ResourceType: ResourceIO,
				LastUpdateNS: uint64(time.Now().UnixNano()),
			}
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) updateResourceUsage() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	isV2, err := isCgroupV2(rm.cgroupPath)
	if err != nil {
		return err
	}

	if isV2 {
		return rm.updateUsageV2()
	}
	return rm.updateUsageV1()
}

func (rm *ResourceMonitor) updateUsageV2() error {
	cpuStat, err := readCgroupFile(filepath.Join(rm.cgroupPath, "cpu.stat"))
	if err == nil {
		usage := parseCPUStat(cpuStat)
		if limit, ok := rm.limits[ResourceCPU]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	memCurrent, err := readCgroupFile(filepath.Join(rm.cgroupPath, "memory.current"))
	if err == nil {
		usage := parseMemoryMax(memCurrent)
		if limit, ok := rm.limits[ResourceMemory]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	ioStat, err := readCgroupFile(filepath.Join(rm.cgroupPath, "io.stat"))
	if err == nil {
		usage := parseIOStat(ioStat)
		if limit, ok := rm.limits[ResourceIO]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) updateUsageV1() error {
	cpuUsage, err := readCgroupFile(filepath.Join(rm.cgroupPath, "cpuacct", "cpuacct.usage"))
	if err == nil {
		usage, _ := strconv.ParseUint(strings.TrimSpace(cpuUsage), 10, 64)
		if limit, ok := rm.limits[ResourceCPU]; ok {
			limit.UsageBytes = usage / 1000 // Convert nanoseconds to microseconds
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	memUsage, err := readCgroupFile(filepath.Join(rm.cgroupPath, "memory", "memory.usage_in_bytes"))
	if err == nil {
		usage := parseMemoryMax(memUsage)
		if limit, ok := rm.limits[ResourceMemory]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	ioBytes, err := readCgroupFile(filepath.Join(rm.cgroupPath, "blkio", "blkio.io_service_bytes"))
	if err == nil {
		usage := parseIOV1(ioBytes)
		if limit, ok := rm.limits[ResourceIO]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) syncToBPF() error {
	if rm.limitsMap == nil {
		return nil
	}

	for resourceType, limit := range rm.limits {
		key := rm.cgroupInode
		value := struct {
			LimitBytes   uint64
			UsageBytes   uint64
			LastUpdateNS uint64
			ResourceType uint32
			_            [4]byte
		}{
			LimitBytes:   limit.LimitBytes,
			UsageBytes:   limit.UsageBytes,
			LastUpdateNS: limit.LastUpdateNS,
			ResourceType: resourceType,
		}

		if err := rm.limitsMap.Put(key, value); err != nil {
			logger.Warn("Failed to update BPF map",
				zap.Uint64("cgroup_inode", key),
				zap.Uint32("resource_type", resourceType),
				zap.Error(err))
		}
	}

	return nil
}

func (rm *ResourceMonitor) checkAlerts() {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.alertsMap == nil {
		return
	}

	resourceTypeLabels := map[uint32]string{
		ResourceCPU:    "cpu",
		ResourceMemory: "memory",
		ResourceIO:     "io",
	}

	for resourceType, limit := range rm.limits {
		if limit.LimitBytes == 0 || limit.LimitBytes == ^uint64(0) {
			continue
		}

		utilization := (limit.UsageBytes * 100) / limit.LimitBytes
		if utilization > 100 {
			utilization = 100
		}
		utilizationUint32 := uint32(utilization)

		var alertLevel uint32
		if utilizationUint32 >= 95 {
			alertLevel = AlertEmergency
		} else if utilizationUint32 >= 90 {
			alertLevel = AlertCritical
		} else if utilizationUint32 >= 80 {
			alertLevel = AlertWarning
		} else {
			alertLevel = AlertNone
		}

		key := rm.cgroupInode
		if alertLevel > 0 {
			if err := rm.alertsMap.Put(key, alertLevel); err != nil {
				logger.Warn("Failed to update alert map", zap.Error(err))
			}
		} else {
			if err := rm.alertsMap.Delete(key); err != nil {
				logger.Warn("Failed to delete alert from map", zap.Error(err))
			}
		}

		resourceTypeLabel := resourceTypeLabels[resourceType]
		if resourceTypeLabel == "" {
			resourceTypeLabel = fmt.Sprintf("resource_%d", resourceType)
		}

		utilizationPercent := float64(utilizationUint32)
		metricsexporter.ExportResourceMetrics(
			resourceTypeLabel,
			rm.namespace,
			limit.LimitBytes,
			limit.UsageBytes,
			utilizationPercent,
			alertLevel,
		)

		if alertLevel > AlertNone {
			manager := alerting.GetGlobalManager()
			if manager != nil {
				severity := alerting.MapResourceAlertLevel(alertLevel)
				title := fmt.Sprintf("Resource Limit %s", severity)
				message := fmt.Sprintf("%s utilization: %d%% (limit: %d bytes, usage: %d bytes)",
					resourceTypeLabel, utilizationUint32, limit.LimitBytes, limit.UsageBytes)
				recommendations := []string{
					"Check for resource leaks",
					"Review resource limits",
					"Consider scaling up pod resources",
				}
				if utilizationUint32 >= 95 {
					recommendations = append(recommendations, "Immediate action required - resource exhaustion imminent")
				}
				alert := &alerting.Alert{
					Severity:        severity,
					Title:           title,
					Message:         message,
					Timestamp:       time.Now(),
					Source:          "resource_monitor",
					PodName:         "",
					Namespace:       rm.namespace,
					Context: map[string]interface{}{
						"resource_type":      resourceTypeLabel,
						"utilization_percent": float64(utilizationUint32),
						"usage_bytes":         limit.UsageBytes,
						"limit_bytes":         limit.LimitBytes,
						"cgroup_path":         rm.cgroupPath,
					},
					Recommendations: recommendations,
				}
				manager.SendAlert(alert)
			}
			if rm.eventChan != nil {
				event := &events.Event{
					Type:        events.EventResourceLimit,
					PID:         0,
					ProcessName: "cgroup",
					LatencyNS:   limit.LimitBytes,
					Error:       int32(utilizationUint32),
					Bytes:       limit.UsageBytes,
					TCPState:    resourceType,
					Target:      rm.cgroupPath,
					Timestamp:   uint64(time.Now().UnixNano()),
				}
				select {
				case rm.eventChan <- event:
					logger.Debug("Resource limit event sent",
						zap.String("resource_type", resourceTypeLabel),
						zap.Uint32("utilization", utilizationUint32),
						zap.Uint32("alert_level", alertLevel))
				default:
					logger.Warn("Failed to send resource limit event, channel full",
						zap.String("resource_type", resourceTypeLabel),
						zap.Uint32("utilization", utilizationUint32))
				}
			}
		}
	}
}

func (rm *ResourceMonitor) GetLimits() map[uint32]*ResourceLimit {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[uint32]*ResourceLimit)
	for k, v := range rm.limits {
		result[k] = &ResourceLimit{
			LimitBytes:   v.LimitBytes,
			UsageBytes:   v.UsageBytes,
			LastUpdateNS: v.LastUpdateNS,
			ResourceType: v.ResourceType,
		}
	}
	return result
}


func getCgroupInode(cgroupPath string) (uint64, error) {
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get stat")
	}
	return uint64(stat.Ino), nil
}

func isCgroupV2(cgroupPath string) (bool, error) {
	controllersPath := filepath.Join(cgroupPath, "cgroup.controllers")
	_, err := os.Stat(controllersPath)
	if err == nil {
		return true, nil
	}
	if _, err := os.Stat(filepath.Join(cgroupPath, "cpu")); err == nil {
		return false, nil
	}
	if _, err := os.Stat(filepath.Join(cgroupPath, "memory")); err == nil {
		return false, nil
	}
	return false, fmt.Errorf("cannot determine cgroup version")
}

func readCgroupFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close cgroup file", zap.String("path", path), zap.Error(err))
		}
	}()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	return "", scanner.Err()
}

func parseCPUMax(cpuMax string) (quota, period uint64, unlimited bool) {
	cpuMax = strings.TrimSpace(cpuMax)
	if cpuMax == "max" {
		return 0, 0, true
	}
	parts := strings.Fields(cpuMax)
	if len(parts) >= 1 {
		quota, _ = strconv.ParseUint(parts[0], 10, 64)
	}
	if len(parts) >= 2 {
		period, _ = strconv.ParseUint(parts[1], 10, 64)
	} else {
		period = 100000
	}
	return quota, period, false
}

func parseMemoryMax(memMax string) uint64 {
	memMax = strings.TrimSpace(memMax)
	if memMax == "max" {
		return ^uint64(0)
	}
	val, _ := strconv.ParseUint(memMax, 10, 64)
	return val
}

func parseIOMax(ioMax string) uint64 {
	var maxBytes uint64
	parts := strings.Fields(ioMax)
	for _, part := range parts {
		if strings.HasPrefix(part, "rbps=") {
			val, _ := strconv.ParseUint(strings.TrimPrefix(part, "rbps="), 10, 64)
			if val > maxBytes {
				maxBytes = val
			}
		}
		if strings.HasPrefix(part, "wbps=") {
			val, _ := strconv.ParseUint(strings.TrimPrefix(part, "wbps="), 10, 64)
			if val > maxBytes {
				maxBytes = val
			}
		}
	}
	return maxBytes
}

func parseIOV1(ioData string) uint64 {
	var total uint64
	scanner := bufio.NewScanner(strings.NewReader(ioData))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			if val, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
				total += val
			}
		}
	}
	return total
}

func parseCPUStat(cpuStat string) uint64 {
	scanner := bufio.NewScanner(strings.NewReader(cpuStat))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "usage_usec") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				return val
			}
		}
	}
	return 0
}

func parseIOStat(ioStat string) uint64 {
	var totalBytes uint64
	scanner := bufio.NewScanner(strings.NewReader(ioStat))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "rbytes=") {
				val, _ := strconv.ParseUint(strings.TrimPrefix(part, "rbytes="), 10, 64)
				totalBytes += val
			}
			if strings.HasPrefix(part, "wbytes=") {
				val, _ := strconv.ParseUint(strings.TrimPrefix(part, "wbytes="), 10, 64)
				totalBytes += val
			}
		}
	}
	return totalBytes
}
