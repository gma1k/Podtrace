package ebpf

import (
	"fmt"
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
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/ebpf/filter"
	"github.com/podtrace/podtrace/internal/ebpf/parser"
	"github.com/podtrace/podtrace/internal/ebpf/probes"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

type Tracer struct {
	collection  *ebpf.Collection
	links       []link.Link
	reader      *ringbuf.Reader
	filter      *filter.CgroupFilter
	containerID string
}

func NewTracer() (*Tracer, error) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to set dumpable flag: %v\n", err)
	}

	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlim); err == nil {
		if rlim.Cur < 512*1024*1024 {
			originalMax := rlim.Max
			if rlim.Max < 512*1024*1024 {
				rlim.Max = 512 * 1024 * 1024
			}
			rlim.Cur = 512 * 1024 * 1024
			if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
				rlim.Cur = rlim.Max
				if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
					rlim.Max = originalMax
					if err := rlimit.RemoveMemlock(); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to increase memlock limit: %v\n", err)
					}
				}
			}
		}
	} else {
		if err := rlimit.RemoveMemlock(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove memlock limit: %v\n", err)
		}
	}

	spec, err := loadPodtrace()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	links, err := probes.AttachProbes(coll)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach probes: %w", err)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return nil, fmt.Errorf("failed to open ring buffer reader: %w", err)
	}

	return &Tracer{
		collection: coll,
		links:      links,
		reader:     rd,
		filter:     filter.NewCgroupFilter(),
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
	return nil
}


func (t *Tracer) Start(eventChan chan<- *events.Event) error {
	var errorCount int
	var lastErrorLog time.Time
	var errorCountMu sync.Mutex
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Panic in event reader: %v\n", r)
			}
		}()
		for {
			record, err := t.reader.Read()
			if err != nil {
				if err.Error() != "" && strings.Contains(err.Error(), "closed") {
					return
				}
				errorCountMu.Lock()
				errorCount++
				now := time.Now()
				shouldLog := now.Sub(lastErrorLog) > 5*time.Second
				count := errorCount
				if shouldLog {
					errorCount = 0
					lastErrorLog = now
				}
				errorCountMu.Unlock()
				if shouldLog {
					if count > 100 {
						fmt.Fprintf(os.Stderr, "Warning: High ring buffer error rate: %d errors in last period. Events may be dropped.\n", count)
					} else {
						fmt.Fprintf(os.Stderr, "Error reading ring buffer: %v\n", err)
					}
				}
				continue
			}

			event := parser.ParseEvent(record.RawSample)
			if event != nil {
				event.ProcessName = getProcessNameQuick(event.PID)
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if t.filter.IsPIDInCgroup(event.PID) {
					select {
					case eventChan <- event:
					default:
						fmt.Fprintf(os.Stderr, "Warning: Event channel full, dropping event\n")
					}
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


func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
