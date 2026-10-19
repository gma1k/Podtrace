package resource

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sysfs"
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

type bpfLimitMap interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
}

type limitMapValue struct {
	LimitBytes   uint64
	UsageBytes   uint64
	LastUpdateNS uint64
	ResourceType uint32
	_            [4]byte
}

// resourceMapKey mirrors struct resource_key in bpf/maps.h. Keying the
// BPF maps by cgroup inode alone made CPU, memory, and IO entries
// clobber each other — the surviving entry depended on Go map iteration
// order, so the kernel-visible limit and alert level flapped between
// resource types on every sync.
type resourceMapKey struct {
	CgroupID     uint64
	ResourceType uint32
	_            [4]byte
}

// resourceSample is one (cumulative usage, wall clock) observation, kept so
// CPU and IO utilization can be computed as RATES between ticks.
type resourceSample struct {
	usage  uint64
	wallNS uint64
}

type ResourceMonitor struct {
	cgroupPath    string
	cgroupInode   uint64
	limitsMap     bpfLimitMap
	alertsMap     bpfLimitMap
	eventChan     chan<- *events.Event
	mu            sync.RWMutex
	limits        map[uint32]*ResourceLimit
	checkInterval time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup

	identityMu sync.RWMutex
	namespace  string
	podName    string

	cpuQuotaMicros  uint64
	cpuPeriodMicros uint64
	previousSamples map[uint32]resourceSample

	cpuQuotaMap      bpfLimitMap
	cpuAlertsReadMap bpfAlertReadMap
	cpuSamplerOn     bool
}

type bpfAlertReadMap interface {
	Lookup(key, valueOut interface{}) error
}

func NewResourceMonitor(cgroupPath string, limitsMap, alertsMap *ebpf.Map, eventChan chan<- *events.Event, namespace string) (*ResourceMonitor, error) {
	inode, err := getCgroupInode(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get cgroup inode: %w", err)
	}

	rm := &ResourceMonitor{
		cgroupPath:      cgroupPath,
		cgroupInode:     inode,
		eventChan:       eventChan,
		limits:          make(map[uint32]*ResourceLimit),
		previousSamples: make(map[uint32]resourceSample),
		checkInterval:   config.ResourceMonitorInterval,
		stopCh:          make(chan struct{}),
		namespace:       namespace,
	}
	if limitsMap != nil {
		rm.limitsMap = limitsMap
	}
	if alertsMap != nil {
		rm.alertsMap = alertsMap
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

// SetPodIdentity records the Kubernetes pod that owns the monitored cgroup so
// alerts name the pod (and can become trigger Events) instead of the cgroup.
func (rm *ResourceMonitor) SetPodIdentity(podName, namespace string) {
	rm.identityMu.Lock()
	defer rm.identityMu.Unlock()
	rm.podName = podName
	rm.namespace = namespace
}

// alertSubject returns the PodName/Namespace an alert carries. Without a
// resolved pod the cgroup path stays the subject only when no namespace is
// known either, so it keeps alerts for distinct cgroups apart but can never
// become the involved object of a Kubernetes Event.
func (rm *ResourceMonitor) alertSubject() (podName, namespace string) {
	rm.identityMu.RLock()
	defer rm.identityMu.RUnlock()
	if rm.podName != "" || rm.namespace != "" {
		return rm.podName, rm.namespace
	}
	return rm.cgroupPath, ""
}

func (rm *ResourceMonitor) metricsNamespace() string {
	rm.identityMu.RLock()
	defer rm.identityMu.RUnlock()
	return rm.namespace
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
			rm.checkBPFCPUAlerts()
		}
	}
}

func (rm *ResourceMonitor) readLimits() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if isCgroupV2(rm.cgroupPath) {
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
		if !unlimited && quota > 0 && period > 0 {
			rm.cpuQuotaMicros = quota
			rm.cpuPeriodMicros = period
			rm.limits[ResourceCPU] = &ResourceLimit{
				LimitBytes:   quota,
				ResourceType: ResourceCPU,
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

// cgroup v1 controller mount directory candidates, relative to
// config.CgroupBasePath. Each controller is its own hierarchy; cpu and cpuacct
// are usually co-mounted ("cpu,cpuacct") but may be split, so try both forms.
var (
	cgroupV1CPUDirs     = []string{"cpu,cpuacct", "cpuacct,cpu", "cpu"}
	cgroupV1CPUAcctDirs = []string{"cpu,cpuacct", "cpuacct,cpu", "cpuacct"}
	cgroupV1MemoryDirs  = []string{"memory"}
	cgroupV1BlkioDirs   = []string{"blkio"}
)

// cgroupV1Subpath returns the pod's cgroup path relative to a v1 controller
// root: the discovered path with the base and the leading controller segment
// stripped. For "/sys/fs/cgroup/cpu,cpuacct/kubepods/pod123" it returns
// "kubepods/pod123", which then reattaches under any controller hierarchy.
func cgroupV1Subpath(cgroupPath string) (string, bool) {
	rel, ok := sysfs.CgroupRelative(cgroupPath)
	if !ok || rel == "." {
		return "", false
	}
	slash := strings.IndexByte(rel, '/')
	if slash < 0 {
		return "", false
	}
	return rel[slash+1:], true
}

// readV1ControllerFile reads a cgroup v1 file from the first controller mount
// that has it: <base>/<controller>/<subpath>/<file>. Unlike v2, the controller
// is a path PREFIX (a separate hierarchy), not a subdirectory of the pod path.
func readV1ControllerFile(controllers []string, subpath, file string) (string, error) {
	var lastErr error
	for _, ctrl := range controllers {
		content, err := readCgroupFile(filepath.Join(config.CgroupBasePath, ctrl, subpath, file))
		if err == nil {
			return content, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no controller mount found for %s among %v", file, controllers)
	}
	return "", lastErr
}

func (rm *ResourceMonitor) readLimitsV1() error {
	subpath, ok := cgroupV1Subpath(rm.cgroupPath)
	if !ok {
		logger.Debug("cgroup v1: cannot derive controller subpath from cgroup path",
			zap.String("cgroup_path", rm.cgroupPath))
		return rm.syncToBPF()
	}

	cpuQuota, _ := readV1ControllerFile(cgroupV1CPUDirs, subpath, "cpu.cfs_quota_us")
	cpuPeriod, _ := readV1ControllerFile(cgroupV1CPUDirs, subpath, "cpu.cfs_period_us")
	if cpuQuota != "" && cpuPeriod != "" {
		quota, _ := strconv.ParseUint(strings.TrimSpace(cpuQuota), 10, 64)
		period, _ := strconv.ParseUint(strings.TrimSpace(cpuPeriod), 10, 64)
		if quota > 0 && period > 0 {
			rm.cpuQuotaMicros = quota
			rm.cpuPeriodMicros = period
			rm.limits[ResourceCPU] = &ResourceLimit{
				LimitBytes:   quota,
				ResourceType: ResourceCPU,
			}
		}
	}

	memLimit, err := readV1ControllerFile(cgroupV1MemoryDirs, subpath, "memory.limit_in_bytes")
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

	ioRead, _ := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.throttle.read_bps_device")
	ioWrite, _ := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.throttle.write_bps_device")
	limit := parseBlkioThrottleBps(ioRead)
	if w := parseBlkioThrottleBps(ioWrite); w > limit {
		limit = w
	}
	if limit > 0 {
		rm.limits[ResourceIO] = &ResourceLimit{
			LimitBytes:   limit,
			ResourceType: ResourceIO,
			LastUpdateNS: uint64(time.Now().UnixNano()),
		}
	}

	return rm.syncToBPF()
}

func (rm *ResourceMonitor) updateResourceUsage() error {
	rm.mu.Lock()
	for _, resourceType := range []uint32{ResourceCPU, ResourceIO} {
		if limit, ok := rm.limits[resourceType]; ok && limit.LastUpdateNS != 0 {
			rm.previousSamples[resourceType] = resourceSample{usage: limit.UsageBytes, wallNS: limit.LastUpdateNS}
		}
	}
	defer rm.mu.Unlock()

	if isCgroupV2(rm.cgroupPath) {
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
	subpath, ok := cgroupV1Subpath(rm.cgroupPath)
	if !ok {
		return rm.syncToBPF()
	}

	cpuUsage, err := readV1ControllerFile(cgroupV1CPUAcctDirs, subpath, "cpuacct.usage")
	if err == nil {
		usage, _ := strconv.ParseUint(strings.TrimSpace(cpuUsage), 10, 64)
		if limit, ok := rm.limits[ResourceCPU]; ok {
			limit.UsageBytes = usage / 1000 // Convert nanoseconds to microseconds
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	memUsage, err := readV1ControllerFile(cgroupV1MemoryDirs, subpath, "memory.usage_in_bytes")
	if err == nil {
		usage := parseMemoryMax(memUsage)
		if limit, ok := rm.limits[ResourceMemory]; ok {
			limit.UsageBytes = usage
			limit.LastUpdateNS = uint64(time.Now().UnixNano())
		}
	}

	ioBytes, err := readV1ControllerFile(cgroupV1BlkioDirs, subpath, "blkio.io_service_bytes")
	if err == nil {
		usage := parseBlkioServiceBytes(ioBytes)
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
		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		value := limitMapValue{
			LimitBytes:   limit.LimitBytes,
			UsageBytes:   limit.UsageBytes,
			LastUpdateNS: limit.LastUpdateNS,
			ResourceType: resourceType,
		}

		if err := rm.limitsMap.Put(key, value); err != nil {
			logger.Warn("Failed to update BPF map",
				zap.Uint64("cgroup_inode", rm.cgroupInode),
				zap.Uint32("resource_type", resourceType),
				zap.Error(err))
		}
	}

	return nil
}

func isBenignMapDeleteError(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

// utilizationPercent returns the 0-100 utilization for one resource.
func (rm *ResourceMonitor) utilizationPercent(resourceType uint32, limit *ResourceLimit) (uint64, bool) {
	clamp := func(v float64) (uint64, bool) {
		if v < 0 {
			return 0, false
		}
		if v > 100 {
			return 100, true
		}
		return uint64(v), true
	}

	switch resourceType {
	case ResourceMemory:
		return clamp(float64(limit.UsageBytes) * 100 / float64(limit.LimitBytes))

	case ResourceCPU:
		if rm.cpuQuotaMicros == 0 || rm.cpuPeriodMicros == 0 {
			return 0, false
		}
		previous, ok := rm.previousSamples[ResourceCPU]
		if !ok || limit.LastUpdateNS <= previous.wallNS || limit.UsageBytes < previous.usage {
			return 0, false
		}
		usedMicros := float64(limit.UsageBytes - previous.usage)
		wallMicros := float64(limit.LastUpdateNS-previous.wallNS) / 1000
		if wallMicros <= 0 {
			return 0, false
		}
		allowedCPUs := float64(rm.cpuQuotaMicros) / float64(rm.cpuPeriodMicros)
		return clamp(usedMicros / wallMicros / allowedCPUs * 100)

	case ResourceIO:
		previous, ok := rm.previousSamples[ResourceIO]
		if !ok || limit.LastUpdateNS <= previous.wallNS || limit.UsageBytes < previous.usage {
			return 0, false
		}
		bytesPerSecond := float64(limit.UsageBytes-previous.usage) /
			(float64(limit.LastUpdateNS-previous.wallNS) / 1e9)
		return clamp(bytesPerSecond / float64(limit.LimitBytes) * 100)

	default:
		return clamp(float64(limit.UsageBytes) * 100 / float64(limit.LimitBytes))
	}
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

		if resourceType == ResourceCPU && rm.cpuSamplerOn {
			continue
		}

		utilization, ok := rm.utilizationPercent(resourceType, limit)
		if !ok {
			continue
		}
		utilizationUint32 := safeconv.Uint64ToUint32(utilization)

		var alertLevel uint32
		switch {
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertEmergPct):
			alertLevel = AlertEmergency
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertCritPct):
			alertLevel = AlertCritical
		case utilizationUint32 >= safeconv.IntToUint32(config.AlertWarnPct):
			alertLevel = AlertWarning
		default:
			alertLevel = AlertNone
		}

		key := resourceMapKey{CgroupID: rm.cgroupInode, ResourceType: resourceType}
		if alertLevel > 0 {
			if err := rm.alertsMap.Put(key, alertLevel); err != nil {
				logger.Warn("Failed to update alert map", zap.Error(err))
			}
		} else {
			if err := rm.alertsMap.Delete(key); err != nil && !isBenignMapDeleteError(err) {
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
			rm.metricsNamespace(),
			limit.LimitBytes,
			limit.UsageBytes,
			utilizationPercent,
			alertLevel,
		)

		if alertLevel > AlertNone {
			manager := alerting.GetGlobalManager()
			if manager != nil {
				severity := alerting.MapResourceAlertLevel(alertLevel)
				title := fmt.Sprintf("Resource Limit %s: %s", severity, resourceTypeLabel)
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
				podName, namespace := rm.alertSubject()
				alert := &alerting.Alert{
					Severity:  severity,
					Title:     title,
					Message:   message,
					Timestamp: time.Now(),
					Source:    alerting.AlertSourceResourceMonitor,
					PodName:   podName,
					Namespace: namespace,
					Context: map[string]interface{}{
						"resource_type":       resourceTypeLabel,
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
					CgroupID:    rm.cgroupInode,
					ProcessName: "cgroup",
					LatencyNS:   limit.LimitBytes,
					Error:       safeconv.Uint64ToInt32(utilization),
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

// isCgroupV2 reports whether the cgroup hierarchy backing cgroupPath is the
// unified v2 hierarchy. A cgroup.controllers file exists only under v2 — never
// inside a v1 controller hierarchy — so its presence at the mount root
// (config.CgroupBasePath) is the authoritative signal, matching the check the
// tracer and CLI use. The per-path check is a fallback for callers whose base
// is itself a unified-hierarchy node. When neither is present the node is v1.
//
// The previous implementation probed for cpu/ and memory/ SUBDIRECTORIES of
// the pod path and returned an error otherwise. That never matched a real v1
// node — there the controllers are separate sibling hierarchies ABOVE the pod
// path (/sys/fs/cgroup/cpu,cpuacct/..., /sys/fs/cgroup/memory/...), not
// subdirectories of it — so v1 always fell through to "cannot determine
// version" and resource monitoring silently did nothing.
func isCgroupV2(cgroupPath string) bool {
	if _, err := os.Stat(filepath.Join(config.CgroupBasePath, "cgroup.controllers")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(cgroupPath, "cgroup.controllers")); err == nil {
		return true
	}
	return false
}

func readCgroupFile(path string) (string, error) {
	rel, ok := sysfs.CgroupRelative(path)
	if !ok {
		return "", fmt.Errorf("cgroup path %q is not under %s", path, config.CgroupBasePath)
	}
	file, err := sysfs.CgroupOpen(rel)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close cgroup file", zap.String("path", path), zap.Error(err))
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
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

// parseBlkioThrottleBps parses blkio.throttle.{read,write}_bps_device,
// whose real format is two fields per line ("MAJ:MIN bytes_per_sec").
func parseBlkioThrottleBps(ioData string) uint64 {
	var maxBps uint64
	scanner := bufio.NewScanner(strings.NewReader(ioData))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 && strings.Contains(parts[0], ":") {
			if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil && val > maxBps {
				maxBps = val
			}
		}
	}
	return maxBps
}

// parseBlkioServiceBytes sums the Read and Write rows of
// blkio.io_service_bytes ("MAJ:MIN Read N").
func parseBlkioServiceBytes(ioData string) uint64 {
	var total uint64
	scanner := bufio.NewScanner(strings.NewReader(ioData))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 3 && (parts[1] == "Read" || parts[1] == "Write") {
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
