package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	DefaultTracingSampleRate     = 1.0
	DefaultOTLPEndpoint          = "http://localhost:4318"
	DefaultJaegerEndpoint        = "http://localhost:14268/api/traces"
	DefaultSplunkEndpoint        = "http://localhost:8088/services/collector"
	DefaultAlertHTTPTimeout      = 10 * time.Second
	DefaultAlertDedupWindow      = 5 * time.Minute
	DefaultAlertRateLimitPerMin  = 10
	DefaultAlertMaxRetries       = 3
	DefaultAlertRetryBackoffBase = 1 * time.Second
	DefaultAlertMaxPayloadSize   = 1024 * 1024
	DefaultVersion               = "v0.7.0"
)

const (
	MaxProcessCacheSize              = 10000
	DefaultProcessCacheEvictionRatio = 0.9
	MaxPIDCacheSize                  = 10000
	DefaultPIDCacheEvictionRatio     = 0.9
	MaxStackDepth                    = 64
	MaxTargetStringLength            = 256
	MaxCgroupFilePathLength          = 64
	MaxContainerIDLength             = 128
	DefaultCacheEvictionThreshold    = 0.9
)

var (
	EventChannelBufferSize    = getIntEnvOrDefault("PODTRACE_EVENT_BUFFER_SIZE", 10000)
	CacheMaxSize              = getIntEnvOrDefault("PODTRACE_CACHE_MAX_SIZE", MaxProcessCacheSize)
	CacheTTLSeconds           = getIntEnvOrDefault("PODTRACE_CACHE_TTL_SECONDS", DefaultCacheTTLSeconds)
	ErrorBackoffEnabled       = getEnvOrDefault("PODTRACE_ERROR_BACKOFF_ENABLED", "true") == "true"
	CircuitBreakerEnabled     = getEnvOrDefault("PODTRACE_CIRCUIT_BREAKER_ENABLED", "true") == "true"
	TracingEnabled            = getEnvOrDefault("PODTRACE_TRACING_ENABLED", "false") == "true"
	TracingSampleRate         = getFloatEnvOrDefault("PODTRACE_TRACING_SAMPLE_RATE", DefaultTracingSampleRate)
	OTLPEndpoint              = getEnvOrDefault("PODTRACE_OTLP_ENDPOINT", DefaultOTLPEndpoint)
	JaegerEndpoint            = getEnvOrDefault("PODTRACE_JAEGER_ENDPOINT", DefaultJaegerEndpoint)
	SplunkEndpoint            = getEnvOrDefault("PODTRACE_SPLUNK_ENDPOINT", DefaultSplunkEndpoint)
	SplunkToken               = getEnvOrDefault("PODTRACE_SPLUNK_TOKEN", "")
	MaxTraceIDLength          = 32
	MaxSpanIDLength           = 16
	MaxTraceStateLength       = 512
	AlertingEnabled           = getEnvOrDefault("PODTRACE_ALERTING_ENABLED", "false") == "true"
	AlertWebhookURL           = getEnvOrDefault("PODTRACE_ALERT_WEBHOOK_URL", "")
	AlertSlackWebhookURL      = getEnvOrDefault("PODTRACE_ALERT_SLACK_WEBHOOK_URL", "")
	AlertSlackChannel         = getEnvOrDefault("PODTRACE_ALERT_SLACK_CHANNEL", "#alerts")
	AlertSplunkEnabled        = getEnvOrDefault("PODTRACE_ALERT_SPLUNK_ENABLED", "false") == "true"
	AlertDeduplicationWindow  = getDurationEnvOrDefault("PODTRACE_ALERT_DEDUP_WINDOW", DefaultAlertDedupWindow)
	AlertRateLimitPerMinute   = getIntEnvOrDefault("PODTRACE_ALERT_RATE_LIMIT", DefaultAlertRateLimitPerMin)
	AlertHTTPTimeout          = getDurationEnvOrDefault("PODTRACE_ALERT_HTTP_TIMEOUT", DefaultAlertHTTPTimeout)
	AlertMaxRetries           = getIntEnvOrDefault("PODTRACE_ALERT_MAX_RETRIES", DefaultAlertMaxRetries)
	AlertMaxPayloadSize       = getInt64EnvOrDefault("PODTRACE_ALERT_MAX_PAYLOAD_SIZE", DefaultAlertMaxPayloadSize)
	K8sAPITimeout             = getDurationEnvOrDefault("PODTRACE_K8S_API_TIMEOUT", DefaultK8sAPITimeout)
	BatchProcessingInterval   = getDurationEnvOrDefault("PODTRACE_BATCH_INTERVAL", DefaultBatchProcessingInterval)
	TracingExporterTimeout    = getDurationEnvOrDefault("PODTRACE_TRACING_EXPORTER_TIMEOUT", DefaultTracingExporterTimeout)
	ShutdownTimeout           = getDurationEnvOrDefault("PODTRACE_SHUTDOWN_TIMEOUT", DefaultShutdownTimeout)
	EventBatchSize            = getIntEnvOrDefault("PODTRACE_EVENT_BATCH_SIZE", DefaultEventBatchSize)
	ResourceMonitorInterval   = getDurationEnvOrDefault("PODTRACE_RESOURCE_MONITOR_INTERVAL", DefaultResourceMonitorInterval)
	ProcessCacheEvictionRatio = getFloatEnvOrDefault("PODTRACE_PROCESS_CACHE_EVICTION_RATIO", DefaultProcessCacheEvictionRatio)
	PIDCacheEvictionRatio     = getFloatEnvOrDefault("PODTRACE_PID_CACHE_EVICTION_RATIO", DefaultPIDCacheEvictionRatio)
	CacheEvictionThreshold    = getFloatEnvOrDefault("PODTRACE_CACHE_EVICTION_THRESHOLD", DefaultCacheEvictionThreshold)
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
	SpikeRateThreshold        = getFloatEnvOrDefault("PODTRACE_SPIKE_RATE_THRESHOLD", DefaultSpikeRateThreshold)
	MaxEventsForStacks        = getIntEnvOrDefault("PODTRACE_MAX_EVENTS_FOR_STACKS", DefaultMaxEventsForStacks)
	MinLatencyForStackNS      = getInt64EnvOrDefault("PODTRACE_MIN_LATENCY_FOR_STACK_NS", DefaultMinLatencyForStackNS)
	MaxBytesForBandwidth      = getInt64EnvOrDefault("PODTRACE_MAX_BYTES_FOR_BANDWIDTH", DefaultMaxBytesForBandwidth)
	EventSamplingRate         = getIntEnvOrDefault("PODTRACE_EVENT_SAMPLING_RATE", DefaultEventSamplingRate)
	ContainerPID              = getIntEnvOrDefault("PODTRACE_CONTAINER_PID", DefaultContainerPID)
	Version                   = getEnvOrDefault("PODTRACE_VERSION", DefaultVersion)
)

const (
	DefaultPodResolveTimeout       = 30 * time.Second
	DefaultMetricsReadTimeout      = 5 * time.Second
	DefaultMetricsWriteTimeout     = 10 * time.Second
	DefaultMetricsShutdownTimeout  = 5 * time.Second
	DefaultRealtimeUpdateInterval  = 5 * time.Second
	DefaultErrorLogInterval        = 5 * time.Second
	DefaultAddr2lineTimeout        = 500 * time.Millisecond
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
	DefaultTopProcessesLimit    = 5
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
)

const (
	PriorityCritical = 1
	PriorityHigh     = 2
	PriorityNormal   = 3
	PriorityLow      = 4
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
	BPFObjectPath      = getEnvOrDefault("PODTRACE_BPF_OBJECT", "bpf/podtrace.bpf.o")
	DockerBasePath     = getEnvOrDefault("PODTRACE_DOCKER_BASE", DockerContainersPath)
	ContainerdBasePath = getEnvOrDefault("PODTRACE_CONTAINERD_BASE", "/var/lib/containerd")
	LdSoConfBasePath   = getEnvOrDefault("PODTRACE_LDSOCONF_BASE", "/etc")
)

func SetCgroupBasePath(path string) {
	CgroupBasePath = path
}

func SetProcBasePath(path string) {
	ProcBasePath = path
}

func GetDefaultLibSearchPaths() []string {
	return []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64"}
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
	TCPLatencySpikeThresholdMS = getFloatEnvOrDefault("PODTRACE_TCP_LATENCY_SPIKE_MS", 100.0)
	TCPRealtimeThresholdMS     = getFloatEnvOrDefault("PODTRACE_TCP_REALTIME_MS", 10.0)
	UDPLatencySpikeThresholdMS = getFloatEnvOrDefault("PODTRACE_UDP_LATENCY_SPIKE_MS", 100.0)
	ConnectLatencyThresholdMS  = getFloatEnvOrDefault("PODTRACE_CONNECT_LATENCY_MS", 1.0)
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getFloatEnvOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return defaultValue
}

func getIntEnvOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil && i > 0 {
			return i
		}
	}
	return defaultValue
}

func getInt64EnvOrDefault(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil && i > 0 {
			return i
		}
	}
	return defaultValue
}

func getDurationEnvOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil && d > 0 {
			return d
		}
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

func AllowNonLoopbackMetrics() bool {
	return os.Getenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR") == "1"
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

func GetVersion() string {
	return Version
}

func GetUserAgent() string {
	return "Podtrace/" + Version
}
