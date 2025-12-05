package config

import (
	"os"
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
)

const (
	EventChannelBufferSize    = 100
	MaxProcessCacheSize       = 10000
	ProcessCacheEvictionRatio = 0.9
	MaxPIDCacheSize           = 10000
	PIDCacheEvictionRatio     = 0.9
	MaxStackDepth             = 64
	MaxTargetStringLength     = 256
	MaxCgroupFilePathLength   = 64
	MaxContainerIDLength      = 128
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
)

const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
)

var (
	CgroupBasePath = getEnvOrDefault("PODTRACE_CGROUP_BASE", "/sys/fs/cgroup")
	ProcBasePath   = getEnvOrDefault("PODTRACE_PROC_BASE", "/proc")
	BPFObjectPath  = getEnvOrDefault("PODTRACE_BPF_OBJECT", "bpf/podtrace.bpf.o")
)

func SetCgroupBasePath(path string) {
	CgroupBasePath = path
}

func SetProcBasePath(path string) {
	ProcBasePath = path
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
