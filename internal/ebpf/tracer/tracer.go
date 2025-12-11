package tracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/cache"
	"github.com/podtrace/podtrace/internal/ebpf/filter"
	"github.com/podtrace/podtrace/internal/ebpf/loader"
	"github.com/podtrace/podtrace/internal/ebpf/parser"
	"github.com/podtrace/podtrace/internal/ebpf/pathresolver"
	"github.com/podtrace/podtrace/internal/ebpf/probes"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/resource"
	"github.com/podtrace/podtrace/internal/validation"
)

type stackTraceValue struct {
	IPs [config.MaxStackDepth]uint64
	Nr  uint32
	Pad uint32
}

type Tracer struct {
	collection       *ebpf.Collection
	links            []link.Link
	reader           *ringbuf.Reader
	filter           *filter.CgroupFilter
	containerID      string
	processNameCache *cache.LRUCache
	pathResolver     *pathresolver.Resolver
	resourceMonitor  *resource.ResourceMonitor
	cgroupPath       string
}

var _ TracerInterface = (*Tracer)(nil)

func NewTracer() (*Tracer, error) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		logger.Warn("Failed to set dumpable flag", zap.Error(err))
	}

	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlim); err == nil {
		if rlim.Cur < config.MemlockLimitBytes {
			originalMax := rlim.Max
			if rlim.Max < config.MemlockLimitBytes {
				rlim.Max = config.MemlockLimitBytes
			}
			rlim.Cur = config.MemlockLimitBytes
			if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
				rlim.Cur = rlim.Max
				if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
					rlim.Max = originalMax
					if err := rlimit.RemoveMemlock(); err != nil {
						logger.Warn("Failed to increase memlock limit", zap.Error(err))
					}
				}
			}
		}
	} else {
		if err := rlimit.RemoveMemlock(); err != nil {
			logger.Warn("Failed to remove memlock limit", zap.Error(err))
		}
	}

	spec, err := loader.LoadPodtrace()
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, NewCollectionError(err)
	}

	links, err := probes.AttachProbes(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
		return nil, NewRingBufferError(err)
	}

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	processCache := cache.NewLRUCache(config.CacheMaxSize, ttl)

	return &Tracer{
		collection:       coll,
		links:            links,
		reader:           rd,
		filter:           filter.NewCgroupFilter(),
		processNameCache: processCache,
		pathResolver:     pathresolver.New(),
	}, nil
}

func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	t.filter.SetCgroupPath(cgroupPath)
	t.cgroupPath = cgroupPath
	return nil
}

func (t *Tracer) SetContainerID(containerID string) error {
	t.containerID = containerID
	dnsLinks := probes.AttachDNSProbes(t.collection, containerID)
	if len(dnsLinks) > 0 {
		t.links = append(t.links, dnsLinks...)
	}
	syncLinks := probes.AttachSyncProbes(t.collection, containerID)
	if len(syncLinks) > 0 {
		t.links = append(t.links, syncLinks...)
	}
	dbLinks := probes.AttachDBProbes(t.collection, containerID)
	if len(dbLinks) > 0 {
		t.links = append(t.links, dbLinks...)
	}
	poolLinks := probes.AttachPoolProbes(t.collection, containerID)
	if len(poolLinks) > 0 {
		t.links = append(t.links, poolLinks...)
	}
	tlsLinks := probes.AttachTLSProbes(t.collection, containerID)
	if len(tlsLinks) > 0 {
		t.links = append(t.links, tlsLinks...)
	}
	return nil
}

func (t *Tracer) Start(ctx context.Context, eventChan chan<- *events.Event) error {
	errorLimiter := newErrorRateLimiter()
	slidingWindow := newSlidingWindow(config.DefaultSlidingWindowSize, config.DefaultSlidingWindowBuckets)
	circuitBreaker := newCircuitBreaker(config.DefaultCircuitBreakerThreshold, config.DefaultCircuitBreakerTimeout)
	stackMap := t.collection.Maps["stack_traces"]

	if t.cgroupPath != "" {
		limitsMap := t.collection.Maps["cgroup_limits"]
		alertsMap := t.collection.Maps["cgroup_alerts"]
		if limitsMap != nil && alertsMap != nil {
			rm, err := resource.NewResourceMonitor(t.cgroupPath, limitsMap, alertsMap, eventChan, "")
			if err != nil {
				logger.Warn("Failed to create resource monitor", zap.Error(err), zap.String("cgroup_path", t.cgroupPath))
			} else {
				t.resourceMonitor = rm
				logger.Debug("Resource monitor initialized", zap.String("cgroup_path", t.cgroupPath))
				rm.Start(ctx)
				logger.Debug("Resource monitor started")
			}
		} else {
			logger.Warn("Resource monitor maps not found in BPF collection")
		}
	} else {
		logger.Debug("Cgroup path not set, skipping resource monitor initialization")
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if t.pathResolver != nil {
					t.pathResolver.CleanupExpired()
				}
			}
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in event reader", zap.Any("panic", r))
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := t.reader.Read()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) || strings.Contains(err.Error(), "closed") {
					return
				}

				if !circuitBreaker.canProceed() {
					continue
				}

				category := classifyError(err)
				if category == ErrorCategoryTransient {
					circuitBreaker.recordSuccess()
				} else {
					circuitBreaker.recordFailure()
				}

				slidingWindow.addError()
				errorRate := slidingWindow.getErrorRate()
				metricsexporter.RecordRingBufferDrop()

				if config.ErrorBackoffEnabled && errorLimiter.shouldLog() {
					if errorRate > config.HighErrorCountThreshold {
						logger.Warn("High ring buffer error rate, events may be dropped",
							zap.Int("error_rate", errorRate),
							zap.String("error_category", errorCategoryString(category)),
							zap.Duration("window", config.DefaultSlidingWindowSize))
					} else {
						logger.Error("Error reading ring buffer", zap.Error(err))
					}
				} else if !config.ErrorBackoffEnabled {
					if errorRate > config.HighErrorCountThreshold {
						logger.Warn("High ring buffer error rate, events may be dropped",
							zap.Int("error_rate", errorRate),
							zap.Duration("window", config.DefaultSlidingWindowSize))
					} else {
						logger.Error("Error reading ring buffer", zap.Error(err))
					}
				}
				continue
			}

			if circuitBreaker.canProceed() {
				circuitBreaker.recordSuccess()
			}

			processingStart := time.Now()
			event := parser.ParseEvent(record.RawSample)
			if event != nil {
				if stackMap != nil && event.StackKey != 0 {
					var stack stackTraceValue
					key := event.StackKey
					if err := stackMap.Lookup(&key, &stack); err == nil {
						n := int(stack.Nr)
						if n > len(stack.IPs) {
							n = len(stack.IPs)
						}
						if n > 0 {
							frames := make([]uint64, n)
							copy(frames, stack.IPs[:n])
							event.Stack = frames
						}
					}
				}
				event.ProcessName = t.getProcessNameQuick(event.PID)
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if event.Type == events.EventOpen {
					fd := uint32(event.Bytes)
					if event.Target != "" && fd != 0xFFFFFFFF {
						t.pathResolver.RecordOpenByFD(event.PID, fd, event.Target)
						if ino, dev := t.extractInodeFromFD(event.PID, fd); ino != 0 {
							t.pathResolver.RecordOpen(event.PID, fd, event.Target, ino, dev)
						}
					}
				}

				if (event.Type == events.EventRead || event.Type == events.EventWrite || event.Type == events.EventFsync) && strings.HasPrefix(event.Target, "ino:") {
					parts := strings.SplitN(event.Target[4:], "/", 2)
					if len(parts) == 2 {
						if ino, err1 := strconv.ParseUint(parts[0], 10, 32); err1 == nil {
							if dev, err2 := strconv.ParseUint(parts[1], 10, 32); err2 == nil {
								if fd := t.findFDForInode(event.PID, uint32(ino), uint32(dev)); fd != 0 {
									t.pathResolver.CorrelateFDWithInode(event.PID, fd, uint32(ino), uint32(dev))
								}
							}
						}
					}
					event.Target = t.pathResolver.ResolvePath(event.PID, event.Target)
				}

				if event.Error != 0 {
					metricsexporter.RecordError(event.TypeString(), event.Error)
				}

				if t.filter.IsPIDInCgroup(event.PID) {
					select {
					case <-ctx.Done():
						parser.PutEvent(event)
						return
					case eventChan <- event:
						metricsexporter.RecordEventProcessingLatency(time.Since(processingStart))
					default:
						metricsexporter.RecordRingBufferDrop()
						parser.PutEvent(event)
					}
				} else {
					parser.PutEvent(event)
				}
			}
		}
	}()

	return nil
}

func (t *Tracer) Stop() error {
	if t.reader != nil {
		_ = t.reader.Close()
	}

	for _, l := range t.links {
		_ = l.Close()
	}

	if t.collection != nil {
		t.collection.Close()
	}

	if t.processNameCache != nil {
		t.processNameCache.Close()
	}

	if t.pathResolver != nil {
		t.pathResolver.Clear()
	}

	if t.resourceMonitor != nil {
		t.resourceMonitor.Stop()
	}

	return nil
}

func (t *Tracer) extractInodeFromFD(pid uint32, fd uint32) (uint32, uint32) {
	fdPath := fmt.Sprintf("%s/%d/fd/%d", config.ProcBasePath, pid, fd)
	var stat syscall.Stat_t
	if err := syscall.Stat(fdPath, &stat); err != nil {
		return 0, 0
	}
	return uint32(stat.Ino), uint32(stat.Dev)
}

func (t *Tracer) findFDForInode(pid uint32, ino, dev uint32) uint32 {
	fdDir := fmt.Sprintf("%s/%d/fd", config.ProcBasePath, pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}

	maxChecks := 20
	checked := 0

	for _, entry := range entries {
		if checked >= maxChecks {
			break
		}

		fdNum, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		checked++

		fdPath := filepath.Join(fdDir, entry.Name())
		var stat syscall.Stat_t
		if err := syscall.Stat(fdPath, &stat); err != nil {
			continue
		}

		if stat.Ino == uint64(ino) && stat.Dev == uint64(dev) {
			return uint32(fdNum)
		}
	}

	return 0
}

func (t *Tracer) getProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	if name, ok := t.processNameCache.Get(pid); ok {
		return name
	}

	metricsexporter.RecordProcessCacheMiss()

	name := ""

	cmdlinePath := fmt.Sprintf("%s/%d/cmdline", config.ProcBasePath, pid)
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		statPath := fmt.Sprintf("%s/%d/stat", config.ProcBasePath, pid)
		if data, err := os.ReadFile(statPath); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		commPath := fmt.Sprintf("%s/%d/comm", config.ProcBasePath, pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	sanitized := validation.SanitizeProcessName(name)
	t.processNameCache.Set(pid, sanitized)
	return sanitized
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
