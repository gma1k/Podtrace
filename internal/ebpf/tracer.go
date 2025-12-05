package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/filter"
	"github.com/podtrace/podtrace/internal/ebpf/parser"
	"github.com/podtrace/podtrace/internal/ebpf/probes"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/validation"
)

type stackTraceValue struct {
	IPs [config.MaxStackDepth]uint64
	Nr  uint32
	Pad uint32
}

var stackFramePool = sync.Pool{
	New: func() interface{} {
		return make([]uint64, 0, 64)
	},
}

type Tracer struct {
	collection        *ebpf.Collection
	links             []link.Link
	reader            *ringbuf.Reader
	filter            *filter.CgroupFilter
	containerID       string
	processNameCache  map[uint32]string
	processCacheMutex *sync.RWMutex
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

	spec, err := loadPodtrace()
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	links, err := probes.AttachProbes(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return nil, err
	}

	return &Tracer{
		collection:        coll,
		links:             links,
		reader:            rd,
		filter:            filter.NewCgroupFilter(),
		processNameCache:  make(map[uint32]string),
		processCacheMutex: &sync.RWMutex{},
	}, nil
}

func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	t.filter.SetCgroupPath(cgroupPath)
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
	return nil
}


func (t *Tracer) Start(ctx context.Context, eventChan chan<- *events.Event) error {
	var errorCount int
	var lastErrorLog time.Time
	var errorCountMu sync.Mutex
	stackMap := t.collection.Maps["stack_traces"]

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
				errorCountMu.Lock()
				errorCount++
				now := time.Now()
				shouldLog := now.Sub(lastErrorLog) > config.DefaultErrorLogInterval
				count := errorCount
				if shouldLog {
					errorCount = 0
					lastErrorLog = now
				}
				errorCountMu.Unlock()
				metricsexporter.RecordRingBufferDrop()
				if shouldLog {
					if count > config.HighErrorCountThreshold {
						logger.Warn("High ring buffer error rate, events may be dropped",
							zap.Int("error_count", count),
							zap.Duration("period", config.DefaultErrorLogInterval))
					} else {
						logger.Error("Error reading ring buffer", zap.Error(err))
					}
				}
				continue
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
							frames := stackFramePool.Get().([]uint64)
							if cap(frames) < n {
								frames = make([]uint64, n)
							} else {
								frames = frames[:n]
							}
							copy(frames, stack.IPs[:n])
							event.Stack = frames
						}
					}
				}
				event.ProcessName = t.getProcessNameQuick(event.PID)
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if event.Error != 0 {
					metricsexporter.RecordError(event.TypeString(), event.Error)
				}

				if t.filter.IsPIDInCgroup(event.PID) {
					select {
					case <-ctx.Done():
						if event.Stack != nil {
							stackFramePool.Put(event.Stack[:0])
						}
						parser.PutEvent(event)
						return
					case eventChan <- event:
						metricsexporter.RecordEventProcessingLatency(time.Since(processingStart))
					default:
						logger.Warn("Event channel full, dropping event",
							zap.String("event_type", event.TypeString()),
							zap.Uint32("pid", event.PID))
						metricsexporter.RecordRingBufferDrop()
						if event.Stack != nil {
							stackFramePool.Put(event.Stack[:0])
						}
						parser.PutEvent(event)
					}
				} else {
					if event.Stack != nil {
						stackFramePool.Put(event.Stack[:0])
					}
					parser.PutEvent(event)
				}
			}
		}
	}()

	return nil
}

func (t *Tracer) Stop() error {
	if t.reader != nil {
		t.reader.Close()
	}

	for _, l := range t.links {
		l.Close()
	}

	if t.collection != nil {
		t.collection.Close()
	}

	return nil
}

func (t *Tracer) getProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	t.processCacheMutex.RLock()
	if name, ok := t.processNameCache[pid]; ok {
		t.processCacheMutex.RUnlock()
		metricsexporter.RecordProcessCacheHit()
		return name
	}
	t.processCacheMutex.RUnlock()
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

	t.processCacheMutex.Lock()
	if len(t.processNameCache) >= config.MaxProcessCacheSize {
		evictCount := len(t.processNameCache) - int(float64(config.MaxProcessCacheSize)*config.ProcessCacheEvictionRatio)
		for k := range t.processNameCache {
			delete(t.processNameCache, k)
			evictCount--
			if evictCount <= 0 {
				break
			}
		}
	}
	t.processNameCache[pid] = name
	t.processCacheMutex.Unlock()

	return validation.SanitizeProcessName(name)
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
