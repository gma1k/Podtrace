package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultNamespace             = "default"
	DefaultErrorRateThreshold    = 10.0
	DefaultRTTThreshold          = 100.0
	DefaultFSSlowThreshold       = 10.0
	DefaultMetricsPort           = 3000
	DefaultMetricsHost           = "127.0.0.1"
	DefaultRingBufferSizeKB      = 2048
	DefaultLogLevel              = "info"
	DefaultTracingEnabled        = false
	DefaultSynthesizeSpans       = false
	DefaultTracingSampleRate     = 1.0
	DefaultOTLPEndpoint          = "http://localhost:4318"
	DefaultJaegerEndpoint        = "http://localhost:14268/api/traces"
	DefaultSplunkEndpoint        = "http://localhost:8088/services/collector"
	DefaultDataDogEndpoint       = "http://localhost:8126/v0.4/traces"
	DefaultZipkinEndpoint        = "http://localhost:9411/api/v2/spans"
	DefaultAlertHTTPTimeout      = 10 * time.Second
	DefaultAlertDedupWindow      = 5 * time.Minute
	DefaultAlertRateLimitPerMin  = 10
	DefaultAlertMaxRetries       = 3
	MaxAlertRetries              = 20
	DefaultAlertRetryBackoffBase = 1 * time.Second
	DefaultAlertMaxPayloadSize   = 1024 * 1024
)

const (
	MaxProcessCacheSize              = 10000
	DefaultProcessCacheEvictionRatio = 0.9
	MaxPIDCacheSize                  = 10000
	DefaultPIDCacheEvictionRatio     = 0.9
	DefaultPIDCacheTTLSeconds        = 30
	MaxStackDepth                    = 64
	MaxTargetStringLength            = 256
	MaxCgroupFilePathLength          = 64
	MaxContainerIDLength             = 128
	DefaultCacheEvictionThreshold    = 0.9
	MaxTraceContextCacheSize         = 100000
)

var (
	EventChannelBufferSize    = getIntEnvOrDefault("PODTRACE_EVENT_BUFFER_SIZE", 10000)
	CacheMaxSize              = getIntEnvOrDefault("PODTRACE_CACHE_MAX_SIZE", MaxProcessCacheSize)
	CacheTTLSeconds           = getIntEnvOrDefault("PODTRACE_CACHE_TTL_SECONDS", DefaultCacheTTLSeconds)
	ErrorBackoffEnabled       = getBoolEnvOrDefault("PODTRACE_ERROR_BACKOFF_ENABLED", true)
	CircuitBreakerEnabled     = getBoolEnvOrDefault("PODTRACE_CIRCUIT_BREAKER_ENABLED", true)
	TracingEnabled            = getBoolEnvOrDefault("PODTRACE_TRACING_ENABLED", false)
	TracingSampleRate         = getFloatEnvInRange("PODTRACE_TRACING_SAMPLE_RATE", DefaultTracingSampleRate, 0, 1)
	SynthesizeSpans           = getBoolEnvOrDefault("PODTRACE_TRACING_SYNTHESIZE_SPANS", DefaultSynthesizeSpans)
	OTLPEndpoint              = getEnvOrDefault("PODTRACE_OTLP_ENDPOINT", DefaultOTLPEndpoint)
	OTLPHeaders               map[string]string
	JaegerEndpoint            = os.Getenv("PODTRACE_JAEGER_ENDPOINT")
	SplunkEndpoint            = os.Getenv("PODTRACE_SPLUNK_ENDPOINT")
	SplunkToken               = getEnvOrDefault("PODTRACE_SPLUNK_TOKEN", "")
	DataDogEndpoint           = getEnvOrDefault("PODTRACE_DATADOG_ENDPOINT", DefaultDataDogEndpoint)
	DataDogAPIKey             = getEnvOrDefault("PODTRACE_DATADOG_API_KEY", "")
	ZipkinEndpoint            = getEnvOrDefault("PODTRACE_ZIPKIN_ENDPOINT", DefaultZipkinEndpoint)
	MaxTraceIDLength          = 32
	MaxSpanIDLength           = 16
	MaxTraceStateLength       = 512
	AlertingEnabled           = getBoolEnvOrDefault("PODTRACE_ALERTING_ENABLED", false)
	AlertEventsEnabled        = getBoolEnvOrDefault("PODTRACE_ALERT_EVENTS_ENABLED", true)
	AlertWebhookURL           = getEnvOrDefault("PODTRACE_ALERT_WEBHOOK_URL", "")
	AlertSlackWebhookURL      = getEnvOrDefault("PODTRACE_ALERT_SLACK_WEBHOOK_URL", "")
	AlertSlackChannel         = getEnvOrDefault("PODTRACE_ALERT_SLACK_CHANNEL", "#alerts")
	AlertSplunkEnabled        = getBoolEnvOrDefault("PODTRACE_ALERT_SPLUNK_ENABLED", false)
	AlertDeduplicationWindow  = getDurationEnvOrDefault("PODTRACE_ALERT_DEDUP_WINDOW", DefaultAlertDedupWindow)
	AlertRateLimitPerMinute   = getIntEnvOrDefault("PODTRACE_ALERT_RATE_LIMIT", DefaultAlertRateLimitPerMin)
	AlertHTTPTimeout          = getDurationEnvOrDefault("PODTRACE_ALERT_HTTP_TIMEOUT", DefaultAlertHTTPTimeout)
	AlertMaxRetries           = min(getIntEnvOrDefault("PODTRACE_ALERT_MAX_RETRIES", DefaultAlertMaxRetries), MaxAlertRetries)
	AlertMaxPayloadSize       = getInt64EnvOrDefault("PODTRACE_ALERT_MAX_PAYLOAD_SIZE", DefaultAlertMaxPayloadSize)
	K8sAPITimeout             = getDurationEnvOrDefault("PODTRACE_K8S_API_TIMEOUT", DefaultK8sAPITimeout)
	BatchProcessingInterval   = getDurationEnvOrDefault("PODTRACE_BATCH_INTERVAL", DefaultBatchProcessingInterval)
	TracingExporterTimeout    = getDurationEnvOrDefault("PODTRACE_TRACING_EXPORTER_TIMEOUT", DefaultTracingExporterTimeout)
	ShutdownTimeout           = getDurationEnvOrDefault("PODTRACE_SHUTDOWN_TIMEOUT", DefaultShutdownTimeout)
	EventBatchSize            = getIntEnvOrDefault("PODTRACE_EVENT_BATCH_SIZE", DefaultEventBatchSize)
	ResourceMonitorInterval   = getDurationEnvOrDefault("PODTRACE_RESOURCE_MONITOR_INTERVAL", DefaultResourceMonitorInterval)
	MetricsLabelLimit         = getIntEnvOrDefault("PODTRACE_METRICS_LABEL_LIMIT", 200)
	MetricsPodLabelLimit      = getIntEnvOrDefault("PODTRACE_METRICS_POD_LABEL_LIMIT", 500)
	MaxTrackedTraces          = getIntEnvOrDefault("PODTRACE_MAX_TRACKED_TRACES", 10000)
	MaxSpansPerTrace          = getIntEnvOrDefault("PODTRACE_MAX_SPANS_PER_TRACE", 1000)
	ProcessCacheEvictionRatio = getFloatEnvInRange("PODTRACE_PROCESS_CACHE_EVICTION_RATIO", DefaultProcessCacheEvictionRatio, 0, 1)
	PIDCacheEvictionRatio     = getFloatEnvInRange("PODTRACE_PID_CACHE_EVICTION_RATIO", DefaultPIDCacheEvictionRatio, 0, 1)
	PIDCacheTTLSeconds        = getIntEnvOrDefault("PODTRACE_PID_CACHE_TTL_SECONDS", DefaultPIDCacheTTLSeconds)
	CacheEvictionThreshold    = getFloatEnvInRange("PODTRACE_CACHE_EVICTION_THRESHOLD", DefaultCacheEvictionThreshold, 0, 1)
	RateLimitPerSec           = getIntEnvOrDefault("PODTRACE_RATE_LIMIT_PER_SEC", DefaultRateLimitPerSec)
	RateLimitBurst            = getIntEnvOrDefault("PODTRACE_RATE_LIMIT_BURST", DefaultRateLimitBurst)
	TopTargetsLimit           = getIntEnvOrDefault("PODTRACE_TOP_TARGETS_LIMIT", DefaultTopTargetsLimit)
	TopFilesLimit             = getIntEnvOrDefault("PODTRACE_TOP_FILES_LIMIT", DefaultTopFilesLimit)
	TopURLsLimit              = getIntEnvOrDefault("PODTRACE_TOP_URLS_LIMIT", DefaultTopURLsLimit)
	TopProcessesLimit         = getIntEnvOrDefault("PODTRACE_TOP_PROCESSES_LIMIT", DefaultTopProcessesLimit)
	TopStatesLimit            = getIntEnvOrDefault("PODTRACE_TOP_STATES_LIMIT", DefaultTopStatesLimit)
	MaxStackTracesLimit       = getIntEnvOrDefault("PODTRACE_MAX_STACK_TRACES_LIMIT", DefaultMaxStackTracesLimit)
	MaxStackFramesLimit       = getIntEnvOrDefault("PODTRACE_MAX_STACK_FRAMES_LIMIT", DefaultMaxStackFramesLimit)
	MaxOOMKillsDisplay        = getIntEnvOrDefault("PODTRACE_MAX_OOM_KILLS_DISPLAY", DefaultMaxOOMKillsDisplay)
	MaxBurstsDisplay          = getIntEnvOrDefault("PODTRACE_MAX_BURSTS_DISPLAY", DefaultMaxBurstsDisplay)
	TimelineBuckets           = getIntEnvOrDefault("PODTRACE_TIMELINE_BUCKETS", DefaultTimelineBuckets)
	MaxConnectionTargets      = getIntEnvOrDefault("PODTRACE_MAX_CONNECTION_TARGETS", DefaultMaxConnectionTargets)
	HighErrorCountThreshold   = getIntEnvOrDefault("PODTRACE_HIGH_ERROR_COUNT_THRESHOLD", DefaultHighErrorCountThreshold)
	SpikeRateThreshold        = getPositiveFloatEnvOrDefault("PODTRACE_SPIKE_RATE_THRESHOLD", DefaultSpikeRateThreshold)
	MaxEventsForStacks        = getIntEnvOrDefault("PODTRACE_MAX_EVENTS_FOR_STACKS", DefaultMaxEventsForStacks)
	MinLatencyForStackNS      = getInt64EnvOrDefault("PODTRACE_MIN_LATENCY_FOR_STACK_NS", DefaultMinLatencyForStackNS)
	MaxBytesForBandwidth      = getInt64EnvOrDefault("PODTRACE_MAX_BYTES_FOR_BANDWIDTH", DefaultMaxBytesForBandwidth)
	EventSamplingRate         = getIntEnvOrDefault("PODTRACE_EVENT_SAMPLING_RATE", DefaultEventSamplingRate)
	ContainerPID              = getIntEnvOrDefault("PODTRACE_CONTAINER_PID", DefaultContainerPID)

	RingBufferSizeKB = getIntEnvOrDefault("PODTRACE_RING_BUFFER_SIZE_KB", DefaultRingBufferSizeKB)
	BPFHashMapSize   = getIntEnvOrDefault("PODTRACE_BPF_HASH_MAP_SIZE", DefaultBPFHashMapSize)

	AlertWarnPct  = ClampPct(getIntEnvOrDefault("PODTRACE_ALERT_WARN_PCT", DefaultAlertWarnPct))
	AlertCritPct  = ClampPct(getIntEnvOrDefault("PODTRACE_ALERT_CRIT_PCT", DefaultAlertCritPct))
	AlertEmergPct = ClampPct(getIntEnvOrDefault("PODTRACE_ALERT_EMERG_PCT", DefaultAlertEmergPct))

	ManagementPort = getIntEnvOrDefault("PODTRACE_MANAGEMENT_PORT", 0)

	GRPCPort            = getIntEnvOrDefault("PODTRACE_GRPC_PORT", 50051)
	USDTEnabled         = getBoolEnvOrDefault("PODTRACE_USDT_ENABLED", true)
	UprobeMultiEnabled  = getBoolEnvOrDefault("PODTRACE_UPROBE_MULTI", true)
	DNSPayloadEnabled   = getBoolEnvOrDefault("PODTRACE_DNS_PAYLOAD_ENABLED", true)
	RedactPII           = getBoolEnvOrDefault("PODTRACE_REDACT_PII", false)
	RedactCustomRules   = getEnvOrDefault("PODTRACE_REDACT_CUSTOM_RULES", "")
	CaptureHeaders      = getEnvOrDefault("PODTRACE_CAPTURE_HEADERS", "")
	CriticalPathEnabled = getBoolEnvOrDefault("PODTRACE_CRITICAL_PATH", true)

	RequestStamping bool

	ProfilingEnabled         = getBoolEnvOrDefault("PODTRACE_PROFILING_ENABLED", false)
	ProfilingPprofPorts      = getEnvOrDefault("PODTRACE_PROFILING_PPROF_PORTS", "6060,8080,8081,9090,2345")
	ProfilingAutoTriggerMS   = getPositiveFloatEnvOrDefault("PODTRACE_PROFILING_AUTO_TRIGGER_MS", DefaultProfilingAutoTriggerMS)
	ProfilingDefaultDuration = getDurationEnvOrDefault("PODTRACE_PROFILING_DEFAULT_DURATION", DefaultProfilingDuration)
	ProfilingMaxConcurrent   = getIntEnvOrDefault("PODTRACE_PROFILING_MAX_CONCURRENT", DefaultProfilingMaxConcurrent)
	ProfilingMaxDuration     = getDurationEnvOrDefault("PODTRACE_PROFILING_MAX_DURATION", DefaultProfilingMaxDuration)

	ContinuousProfilingEnabled = getBoolEnvOrDefault("PODTRACE_CONTINUOUS_PROFILING_ENABLED", false)

	SockOpsRTTEnabled = getBoolEnvOrDefault("PODTRACE_SOCKOPS_RTT_ENABLED", false)

	ProfileSnapshotTimeout = getDurationEnvOrDefault("PODTRACE_PROFILE_SNAPSHOT_TIMEOUT", 20*time.Second)

	ReportGenerationTimeout = getDurationEnvOrDefault("PODTRACE_REPORT_GENERATION_TIMEOUT", DefaultReportGenerationTimeout)
)

const DefaultWorkloadMetricsBudget = 40000

var (
	WorkloadMetricsEnabled          = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS", false)
	WorkloadMetricsNativeHistograms = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS", true)
	WorkloadMetricsBudget           = getIntEnvOrDefault("PODTRACE_WORKLOAD_METRICS_SERIES_BUDGET", DefaultWorkloadMetricsBudget)
	WorkloadMetricsPodLabel         = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_POD_LABEL", false)
	WorkloadMetricsProcessLabel     = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_PROCESS_LABEL", false)
	WorkloadMetricsSemanticConv     = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_SEMANTIC_CONVENTIONS", false)
	WorkloadMetricsAttributeLimit   = getIntEnvOrDefault("PODTRACE_WORKLOAD_METRICS_ATTRIBUTE_CARDINALITY", 50)

	WorkloadMetricsKernelAggregation = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_KERNEL_AGGREGATION", false)
	WorkloadMetricsFilesystem        = getBoolEnvOrDefault("PODTRACE_WORKLOAD_METRICS_FILESYSTEM", true)

	WorkloadMetricsSeriesTTL = getDurationEnvOrDefault("PODTRACE_WORKLOAD_METRICS_SERIES_TTL", 15*time.Minute)

	WorkloadMetricsReapInterval = getDurationEnvOrDefault("PODTRACE_WORKLOAD_METRICS_REAP_INTERVAL", time.Minute)

	WorkloadMetricsDrainInterval = getDurationEnvOrDefault("PODTRACE_WORKLOAD_METRICS_DRAIN_INTERVAL", 10*time.Second)
)

var (
	InspectionsEnabled = getBoolEnvOrDefault("PODTRACE_INSPECTIONS", false)

	InspectionsInterval = getDurationEnvOrDefault("PODTRACE_INSPECTIONS_INTERVAL", 30*time.Second)

	InspectionsBudget = getIntEnvOrDefault("PODTRACE_INSPECTIONS_BUDGET", 512)

	InspectionsAlerts = getBoolEnvOrDefault("PODTRACE_INSPECTIONS_ALERTS", true)

	InspectionErrorRatePercent     = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_ERROR_RATE_PCT", 5)
	InspectionMinRequestsPerSecond = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_MIN_REQUEST_RATE", 0.1)
	InspectionMeanLatency          = getDurationEnvOrDefault("PODTRACE_INSPECTIONS_MEAN_LATENCY", time.Second)
	InspectionAcquireMean          = getDurationEnvOrDefault("PODTRACE_INSPECTIONS_ACQUIRE_MEAN", 100*time.Millisecond)
	InspectionCPUBlockedMean       = getDurationEnvOrDefault("PODTRACE_INSPECTIONS_CPU_BLOCKED_MEAN", 50*time.Millisecond)
	InspectionPoolUtilizationPct   = getIntEnvOrDefault("PODTRACE_INSPECTIONS_POOL_UTILIZATION_PCT", 80)
	InspectionMinPreemptions       = getIntEnvOrDefault("PODTRACE_INSPECTIONS_MIN_PREEMPTIONS", 100)
	InspectionDNSSlowLookupPct     = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_DNS_SLOW_LOOKUP_PCT", 5)
	InspectionFSSlowOperationsPct  = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_FS_SLOW_OPERATIONS_PCT", 5)
	InspectionDNSFailurePct        = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_DNS_FAILURE_PCT", 5)
	InspectionTLSFailurePct        = getFloatEnvOrDefault("PODTRACE_INSPECTIONS_TLS_HANDSHAKE_FAILURE_PCT", 5)

	InspectionsHoldTime = getDurationEnvOrDefault("PODTRACE_INSPECTIONS_HOLD_TIME", 0)
)

var WorkloadMetricsExcludedNamespaces = splitCommaEnv("PODTRACE_WORKLOAD_METRICS_EXCLUDE_NAMESPACES")

func splitCommaEnv(key string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

const (
	DefaultPodResolveTimeout       = 30 * time.Second
	DefaultMetricsReadTimeout      = 5 * time.Second
	DefaultMetricsWriteTimeout     = 10 * time.Second
	DefaultMetricsShutdownTimeout  = 5 * time.Second
	DefaultRealtimeUpdateInterval  = 5 * time.Second
	DefaultErrorLogInterval        = 5 * time.Second
	DefaultAddr2lineTimeout        = 500 * time.Millisecond
	DefaultReportGenerationTimeout = 25 * time.Second
	MinBurstWindowDuration         = 100 * time.Millisecond
	MaxDiagnoseDuration            = 24 * time.Hour
	DefaultK8sAPITimeout           = 500 * time.Millisecond
	DefaultBatchProcessingInterval = 10 * time.Millisecond
	DefaultTracingExporterTimeout  = 10 * time.Second
	DefaultShutdownTimeout         = 5 * time.Second
	DefaultEventBatchSize          = 100
	DefaultResourceMonitorInterval = 5 * time.Second
)

const (
	MemlockLimitBytes      = 512 * 1024 * 1024
	MaxRequestSize         = 1024 * 1024
	DefaultRateLimitPerSec = 10
	DefaultRateLimitBurst  = 20
)

const (
	DefaultTopTargetsLimit      = 5
	DefaultTopFilesLimit        = 5
	DefaultTopURLsLimit         = 5
	DefaultTopProcessesLimit    = 10
	DefaultTopStatesLimit       = 10
	DefaultMaxStackTracesLimit  = 5
	DefaultMaxStackFramesLimit  = 5
	DefaultMaxOOMKillsDisplay   = 5
	DefaultMaxBurstsDisplay     = 3
	DefaultTimelineBuckets      = 5
	DefaultMaxConnectionTargets = 10
)

const (
	DefaultHighErrorCountThreshold = 100
	DefaultSpikeRateThreshold      = 5.0
	DefaultMaxEventsForStacks      = 10000
	DefaultMinLatencyForStackNS    = 1000000
	DefaultMaxBytesForBandwidth    = 10 * 1024 * 1024
	EAGAIN                         = 11
	MaxEvents                      = 1000000
	DefaultEventSamplingRate       = 100

	DefaultBPFHashMapSize = 4096

	DefaultAlertWarnPct  = 80
	DefaultAlertCritPct  = 90
	DefaultAlertEmergPct = 95

	DefaultProfilingAutoTriggerMS = 500.0
	DefaultProfilingDuration      = 30 * time.Second
	DefaultProfilingMaxConcurrent = 1
	DefaultProfilingMaxDuration   = 5 * time.Minute
)

const (
	ErrorCategoryTransient   = 1
	ErrorCategoryRecoverable = 2
	ErrorCategoryPermanent   = 3
)

const (
	DefaultCacheTTLSeconds         = 3600
	DefaultErrorBackoffMinInterval = 1 * time.Second
	DefaultErrorBackoffMaxInterval = 60 * time.Second
	DefaultCircuitBreakerThreshold = 100
	DefaultCircuitBreakerTimeout   = 30 * time.Second
	DefaultSlidingWindowSize       = 5 * time.Second
	DefaultSlidingWindowBuckets    = 10
)

const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
)

const (
	DefaultFileMode       = 0644
	DefaultDirMode        = 0755
	DefaultContainerPID   = 1
	LdSoConfPath          = "/etc/ld.so.conf"
	LdSoConfDPattern      = "/etc/ld.so.conf.d/*.conf"
	DockerContainersPath  = "/var/lib/docker/containers"
	ContainerdOverlayPath = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs"
	ContainerdNativePath  = "/var/lib/containerd/io.containerd.snapshotter.v1.native/snapshots/*/fs"
	DefaultLibPaths       = "/lib:/usr/lib:/lib64:/usr/lib64"
)

const (
	NSPerMS              = 1000000
	NSPerSecond          = 1000000000
	DroppedEventsLogRate = 10000
	RTTSpikeThresholdMS  = 100
	Percent100           = 100.0
	TruncateEllipsisLen  = 3
)

var (
	CgroupBasePath     = getEnvOrDefault("PODTRACE_CGROUP_BASE", "/sys/fs/cgroup")
	ProcBasePath       = getEnvOrDefault("PODTRACE_PROC_BASE", "/proc")
	BPFObjectPath      = getEnvOrDefault("PODTRACE_BPF_OBJECT", DefaultBPFObjectPath())
	BTFFilePath        = getEnvOrDefault("PODTRACE_BTF_FILE", "")
	DockerBasePath     = getEnvOrDefault("PODTRACE_DOCKER_BASE", DockerContainersPath)
	ContainerdBasePath = getEnvOrDefault("PODTRACE_CONTAINERD_BASE", "/var/lib/containerd")
	LdSoConfBasePath   = getEnvOrDefault("PODTRACE_LDSOCONF_BASE", "/etc")
)

func SetCgroupBasePath(path string) {
	CgroupBasePath = path
}

func DefaultBPFObjectPath() string {
	return fmt.Sprintf("internal/ebpf/embedded/podtrace.%s.bpf.o", runtime.GOARCH)
}

func SetProcBasePath(path string) {
	ProcBasePath = path
}

func GetDefaultLibSearchPaths() []string {
	return []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"}
}

func GetCommonBinarySearchPaths() []string {
	pathsEnv := getEnvOrDefault("PODTRACE_BINARY_SEARCH_PATHS", "")
	if pathsEnv != "" {
		return strings.Split(pathsEnv, ":")
	}
	return []string{
		"/app/main",
		"/app/app",
		"/usr/local/bin/app",
		"/bin/app",
	}
}

func GetDockerContainerRootfs(containerID string) (string, error) {
	if containerID == "" || len(containerID) > MaxContainerIDLength {
		return "", fmt.Errorf("invalid container ID length")
	}
	if strings.Contains(containerID, "..") || strings.Contains(containerID, "/") {
		return "", fmt.Errorf("invalid container ID: contains path traversal")
	}
	rootfsPath := filepath.Join(DockerBasePath, containerID, "rootfs")
	cleanPath := filepath.Clean(rootfsPath)
	cleanBase := filepath.Clean(DockerBasePath)
	if !strings.HasPrefix(cleanPath, cleanBase) {
		return "", fmt.Errorf("invalid rootfs path: outside base path")
	}
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid rootfs path: contains traversal sequence")
	}
	return rootfsPath, nil
}

func GetContainerdOverlayPattern() string {
	pattern := getEnvOrDefault("PODTRACE_CONTAINERD_OVERLAY_PATTERN", ContainerdOverlayPath)
	return pattern
}

func GetContainerdNativePattern() string {
	pattern := getEnvOrDefault("PODTRACE_CONTAINERD_NATIVE_PATTERN", ContainerdNativePath)
	return pattern
}

func GetLdSoConfPath() string {
	return filepath.Join(LdSoConfBasePath, "ld.so.conf")
}

func GetLdSoConfDPattern() string {
	return filepath.Join(LdSoConfBasePath, "ld.so.conf.d", "*.conf")
}

func GetProcRootPath(pid uint32) string {
	return filepath.Join(ProcBasePath, fmt.Sprintf("%d", pid), "root")
}

func GetDefaultProcRootPath() string {
	return filepath.Join(ProcBasePath, fmt.Sprintf("%d", ContainerPID), "root")
}

var (
	TCPLatencySpikeThresholdMS = getPositiveFloatEnvOrDefault("PODTRACE_TCP_LATENCY_SPIKE_MS", 100.0)
	TCPRealtimeThresholdMS     = getPositiveFloatEnvOrDefault("PODTRACE_TCP_REALTIME_MS", 10.0)
	UDPLatencySpikeThresholdMS = getPositiveFloatEnvOrDefault("PODTRACE_UDP_LATENCY_SPIKE_MS", 100.0)
	ConnectLatencyThresholdMS  = getPositiveFloatEnvOrDefault("PODTRACE_CONNECT_LATENCY_MS", 1.0)
)

func parseBoolLenient(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on", "enable", "enabled":
		return true, true
	case "0", "f", "false", "n", "no", "off", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

// getBoolEnvOrDefault parses the env var with parseBoolLenient. A set-but-
// unrecognized value is reported instead of silently ignored.
func getBoolEnvOrDefault(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if b, ok := parseBoolLenient(value); ok {
		return b
	}
	warnIgnoredEnv(key, value, "not a boolean")
	return defaultValue
}

// warnIgnoredEnv surfaces configuration that LOOKS set but is being
// ignored. It writes directly to stderr because internal/logger imports
// this package (cycle).
func warnIgnoredEnv(key, value, reason string) {
	_, _ = fmt.Fprintf(os.Stderr,
		`{"level":"warn","component":"config","message":"environment variable ignored","key":%q,"value":%q,"reason":%q}`+"\n",
		key, value, reason)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getFloatEnvInRange parses a float and accepts it only within the inclusive
// [lo, hi] range its consumer requires (e.g. a sample rate or eviction ratio
// in [0,1]).
func getFloatEnvInRange(key string, defaultValue, lo, hi float64) float64 {
	if value := os.Getenv(key); value != "" {
		f, err := strconv.ParseFloat(value, 64)
		switch {
		case err != nil:
			warnIgnoredEnv(key, value, "not a number")
		case f < lo || f > hi:
			warnIgnoredEnv(key, value, fmt.Sprintf("must be within [%g, %g]", lo, hi))
		default:
			return f
		}
	}
	return defaultValue
}

// getPositiveFloatEnvOrDefault mirrors getIntEnvOrDefault for float knobs that
// must be strictly positive (durations, latency thresholds).
func getPositiveFloatEnvOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		f, err := strconv.ParseFloat(value, 64)
		switch {
		case err != nil:
			warnIgnoredEnv(key, value, "not a number")
		case f <= 0:
			warnIgnoredEnv(key, value, "must be a positive number")
		default:
			return f
		}
	}
	return defaultValue
}

// getIntEnvOrDefault keeps the positive-only constraint (every consumer is
// a size, port, or count where 0/negative would disable or break the
// feature), but a set-and-ignored value is now reported instead of
// silently falling back to the default.
func getIntEnvOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil && i > 0 {
			return i
		}
		warnIgnoredEnv(key, value, "must be a positive integer")
	}
	return defaultValue
}

// ParseNonNegativeFloat is the accepted form of a float-valued environment
// variable. It is exported because the operator writes these values and the
// agent parses them: a value the operator renders but this rejects falls back
// to a default with only a warning, so the user's setting would be silently
// ignored. Having one named function lets a test assert the two halves agree.
//
// Zero is accepted. For a rate threshold it means "any occurrence at all
// fires", which is a real setting rather than an unset one.
func ParseNonNegativeFloat(value string) (float64, bool) {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return f, true
}

// getFloatEnvOrDefault reads a non-negative float.
func getFloatEnvOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if f, ok := ParseNonNegativeFloat(value); ok {
			return f
		}
		warnIgnoredEnv(key, value, "must be a non-negative number")
	}
	return defaultValue
}

func ClampPct(pct int) int {
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func ClampUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// getInt64EnvOrDefault mirrors getIntEnvOrDefault for 64-bit knobs: the
// positive-only constraint holds (every consumer is a size or threshold
// where 0/negative would disable or break the feature), and a set-but-
// rejected value is reported instead of silently falling back.
func getInt64EnvOrDefault(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil && i > 0 {
			return i
		}
		warnIgnoredEnv(key, value, "must be a positive integer")
	}
	return defaultValue
}

func getDurationEnvOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil && d > 0 {
			return d
		}
		warnIgnoredEnv(key, value, "must be a positive Go duration")
	}
	return defaultValue
}

func GetMetricsAddress() string {
	addr := os.Getenv("PODTRACE_METRICS_ADDR")
	if addr == "" {
		addr = DefaultMetricsHost + ":" + strconv.Itoa(DefaultMetricsPort)
	}
	return addr
}

const EnvArtifactBaseDir = "PODTRACE_ARTIFACT_BASE"

// ArtifactBaseDir returns the directory session artifacts must be written
// within, or "" when unconstrained.
func ArtifactBaseDir() string {
	return os.Getenv(EnvArtifactBaseDir)
}

func AllowNonLoopbackMetrics() bool {
	return getBoolEnvOrDefault("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR", false)
}

func GetAlertMinSeverity() string {
	return getEnvOrDefault("PODTRACE_ALERT_MIN_SEVERITY", "warning")
}

func GetSplunkEndpoint() string {
	if AlertSplunkEnabled {
		return SplunkEndpoint
	}
	return ""
}

func GetSplunkToken() string {
	if AlertSplunkEnabled {
		return SplunkToken
	}
	return ""
}

var (
	Version = "dev"
	Commit  = "unknown"
	Image   = "ghcr.io/gma1k/podtrace"
)

// AllowedAgentImageRepos returns the repository prefixes the operator accepts
// in TracerConfig.spec.image.
func AllowedAgentImageRepos() []string {
	raw, set := os.LookupEnv("PODTRACE_ALLOWED_AGENT_IMAGE_REPOS")
	if !set {
		return []string{Image}
	}
	var repos []string
	for _, r := range strings.Split(raw, ",") {
		if r = strings.TrimSpace(r); r != "" {
			repos = append(repos, r)
		}
	}
	return repos
}

var readVCSRevision = func() string {
	return revisionFrom(debug.ReadBuildInfo())
}

func revisionFrom(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return s.Value[:7]
		}
	}
	return ""
}

func GetVersion() string {
	if v := os.Getenv("PODTRACE_VERSION"); v != "" {
		return v
	}
	if Version != "dev" {
		return Version
	}
	if rev := readVCSRevision(); rev != "" {
		return "dev-" + rev
	}
	return "dev"
}

func GetUserAgent() string {
	return "Podtrace/" + GetVersion()
}

func OTLPAllowInsecureNonLoopback() bool {
	return getBoolEnvOrDefault("PODTRACE_OTLP_INSECURE", false)
}

func ExporterAllowInsecureNonLoopback() bool {
	return getBoolEnvOrDefault("PODTRACE_EXPORTER_INSECURE", false)
}

func ExporterBlockPrivateRanges() bool {
	return getBoolEnvOrDefault("PODTRACE_EXPORTER_BLOCK_PRIVATE", false)
}

func MetricsEnablePprof() bool {
	return getBoolEnvOrDefault("PODTRACE_METRICS_ENABLE_PPROF", false) || ProfilingEnabled
}

func SplunkAlertAllowHTTP() bool {
	return getBoolEnvOrDefault("PODTRACE_ALERT_SPLUNK_ALLOW_HTTP", false)
}

func WebhookAllowHTTP() bool {
	return getBoolEnvOrDefault("PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP", false)
}

func AllowCgroupFilterAutoDisable() bool {
	return getBoolEnvOrDefault("PODTRACE_ALLOW_CGROUP_FILTER_DISABLE", false)
}

// RedactDNSNames reports whether DNS names are stripped from captured events.
func RedactDNSNames() bool {
	return getBoolEnvOrDefault("PODTRACE_REDACT_DNS_NAMES", false)
}

// DNSPacketCaptureEnabled reports whether the packet-based DNS capture path is
// active. Enabled unless explicitly disabled.
func DNSPacketCaptureEnabled() bool {
	return getBoolEnvOrDefault("PODTRACE_DNS_PACKET_CAPTURE", true)
}

// K8sEnrichmentEnabled reports whether events are enriched with pod metadata.
// Enabled unless explicitly disabled.
func K8sEnrichmentEnabled() bool {
	return getBoolEnvOrDefault("PODTRACE_K8S_ENRICHMENT_ENABLED", true)
}

// K8sUseInformers reports whether pod metadata comes from informers rather than
// direct API calls. Enabled unless explicitly disabled.
func K8sUseInformers() bool {
	return getBoolEnvOrDefault("PODTRACE_K8S_USE_INFORMERS", true)
}

// CRIResolveEnabled reports whether cgroup paths may be resolved via the CRI
// socket. Enabled unless explicitly disabled.
func CRIResolveEnabled() bool {
	return getBoolEnvOrDefault("PODTRACE_CRI_RESOLVE", true)
}

const MaxCaptureHeaders = 4

const MaxCaptureHeaderNameLen = 32

func CaptureHeaderList() []string {
	return ParseCaptureHeaders(CaptureHeaders)
}

// ParseCaptureHeaders normalizes a comma-separated header allowlist: names are
// lowercased, invalid tokens dropped, and the list capped at
// MaxCaptureHeaders entries.
func ParseCaptureHeaders(raw string) []string {
	var out []string
	for _, n := range strings.Split(raw, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || len(n) > MaxCaptureHeaderNameLen || !isHeaderToken(n) {
			continue
		}
		out = append(out, n)
		if len(out) == MaxCaptureHeaders {
			break
		}
	}
	return out
}

// isHeaderToken reports whether s is a valid HTTP header field name
// (RFC 9110 token).
func isHeaderToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '!' || c == '#' ||
			c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
			c == '+' || c == '^' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return len(s) > 0
}
