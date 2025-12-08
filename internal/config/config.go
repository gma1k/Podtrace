package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	DefaultNamespace          = "default"
	DefaultErrorRateThreshold = 10.0
	DefaultRTTThreshold       = 100.0
	DefaultFSSlowThreshold    = 10.0
	DefaultMetricsPort        = 3000
	DefaultMetricsHost        = "127.0.0.1"
	DefaultRingBufferSizeKB   = 2048
	DefaultLogLevel           = "info"
	DefaultTracingEnabled     = false
	DefaultTracingSampleRate  = 1.0
	DefaultOTLPEndpoint       = "http://localhost:4318"
	DefaultJaegerEndpoint     = "http://localhost:14268/api/traces"
	DefaultSplunkEndpoint     = "http://localhost:8088/services/collector"
)

const (
	MaxProcessCacheSize       = 10000
	ProcessCacheEvictionRatio = 0.9
	MaxPIDCacheSize           = 10000
	PIDCacheEvictionRatio     = 0.9
	MaxStackDepth             = 64
	MaxTargetStringLength     = 256
	MaxCgroupFilePathLength   = 64
	MaxContainerIDLength      = 128
)

var (
	EventChannelBufferSize = getIntEnvOrDefault("PODTRACE_EVENT_BUFFER_SIZE", 10000)
	CacheMaxSize           = getIntEnvOrDefault("PODTRACE_CACHE_MAX_SIZE", MaxProcessCacheSize)
	CacheTTLSeconds        = getIntEnvOrDefault("PODTRACE_CACHE_TTL_SECONDS", DefaultCacheTTLSeconds)
	ErrorBackoffEnabled    = getEnvOrDefault("PODTRACE_ERROR_BACKOFF_ENABLED", "true") == "true"
	CircuitBreakerEnabled  = getEnvOrDefault("PODTRACE_CIRCUIT_BREAKER_ENABLED", "true") == "true"
	TracingEnabled         = getEnvOrDefault("PODTRACE_TRACING_ENABLED", "false") == "true"
	TracingSampleRate      = getFloatEnvOrDefault("PODTRACE_TRACING_SAMPLE_RATE", DefaultTracingSampleRate)
	OTLPEndpoint           = getEnvOrDefault("PODTRACE_OTLP_ENDPOINT", DefaultOTLPEndpoint)
	JaegerEndpoint         = getEnvOrDefault("PODTRACE_JAEGER_ENDPOINT", DefaultJaegerEndpoint)
	SplunkEndpoint         = getEnvOrDefault("PODTRACE_SPLUNK_ENDPOINT", DefaultSplunkEndpoint)
	SplunkToken            = getEnvOrDefault("PODTRACE_SPLUNK_TOKEN", "")
	MaxTraceIDLength       = 32
	MaxSpanIDLength        = 16
	MaxTraceStateLength    = 512
)

const (
	DefaultPodResolveTimeout      = 30 * time.Second
	DefaultMetricsReadTimeout     = 5 * time.Second
	DefaultMetricsWriteTimeout    = 10 * time.Second
	DefaultMetricsShutdownTimeout = 5 * time.Second
	DefaultRealtimeUpdateInterval = 5 * time.Second
	DefaultErrorLogInterval       = 5 * time.Second
	DefaultAddr2lineTimeout       = 500 * time.Millisecond
	MinBurstWindowDuration        = 100 * time.Millisecond
	MaxDiagnoseDuration           = 24 * time.Hour
)

const (
	MemlockLimitBytes = 512 * 1024 * 1024
	MaxRequestSize    = 1024 * 1024
	RateLimitPerSec   = 10
	RateLimitBurst    = 20
)

const (
	TopTargetsLimit      = 5
	TopFilesLimit        = 5
	TopURLsLimit         = 5
	TopProcessesLimit    = 5
	TopStatesLimit       = 10
	MaxStackTracesLimit  = 5
	MaxStackFramesLimit  = 5
	MaxOOMKillsDisplay   = 5
	MaxBurstsDisplay     = 3
	TimelineBuckets      = 5
	MaxConnectionTargets = 10
)

const (
	HighErrorCountThreshold = 100
	SpikeRateThreshold      = 5.0
	MaxEventsForStacks      = 10000
	MinLatencyForStackNS    = 1000000
	MaxBytesForBandwidth    = 10 * 1024 * 1024
	EAGAIN                  = 11
	MaxEvents               = 1000000
	EventSamplingRate       = 100
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
	CacheEvictionThreshold         = 0.9
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

func GetDockerContainerRootfs(containerID string) string {
	return filepath.Join(DockerBasePath, containerID, "rootfs")
}

func GetContainerdOverlayPattern() string {
	return ContainerdOverlayPath
}

func GetContainerdNativePattern() string {
	return ContainerdNativePath
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
	return filepath.Join(ProcBasePath, fmt.Sprintf("%d", DefaultContainerPID), "root")
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
