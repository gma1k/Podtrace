package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

type Tracer struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	cgroupPath string
}

// NewTracer creates a new eBPF tracer
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

	links, err := attachProbes(coll)
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
	}, nil
}

// AttachToCgroup stores the cgroup path for userspace filtering
func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	t.cgroupPath = cgroupPath
	return nil
}

// isPIDInCgroup checks if a PID belongs to the target cgroup
func (t *Tracer) isPIDInCgroup(pid uint32) bool {
	if t.cgroupPath == "" {
		return true
	}

	if !validation.ValidatePID(pid) {
		return false
	}

	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return false
	}

	cgroupContent := strings.TrimSpace(string(data))
	pidCgroupPath := extractCgroupPathFromProc(cgroupContent)
	if pidCgroupPath == "" {
		return false
	}

	normalizedTarget := normalizeCgroupPath(t.cgroupPath)
	normalizedPID := normalizeCgroupPath(pidCgroupPath)

	if normalizedPID == normalizedTarget {
		return true
	}

	if strings.HasPrefix(normalizedPID, normalizedTarget+"/") {
		return true
	}

	if strings.HasPrefix(normalizedTarget, normalizedPID+"/") {
		return true
	}

	return false
}

// normalizeCgroupPath normalizes a cgroup path for comparison
func normalizeCgroupPath(path string) string {
	path = strings.TrimPrefix(path, "/sys/fs/cgroup")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	return path
}

// extractCgroupPathFromProc extracts the cgroup path from /proc/<pid>/cgroup content
func extractCgroupPathFromProc(cgroupContent string) string {
	if strings.HasPrefix(cgroupContent, "0::") {
		return strings.TrimPrefix(cgroupContent, "0::")
	}

	lines := strings.Split(cgroupContent, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return ""
}

// Start begins collecting events and sends them to the event channel
func (t *Tracer) Start(eventChan chan<- *events.Event) error {
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
				fmt.Fprintf(os.Stderr, "Error reading ring buffer: %v\n", err)
				continue
			}

			event := parseEvent(record.RawSample)
			if event != nil {
				event.ProcessName = getProcessNameQuick(event.PID)
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if t.isPIDInCgroup(event.PID) {
					eventChan <- event
				}
			}
		}
	}()

	return nil
}

// Stop the tracer and cleans up resources
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

func parseEvent(data []byte) *events.Event {
	if len(data) < 32 {
		return nil
	}

	var e struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		Target    [64]byte
		Details   [64]byte
	}

	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		return nil
	}

	return &events.Event{
		Timestamp: e.Timestamp,
		PID:       e.PID,
		Type:      events.EventType(e.Type),
		LatencyNS: e.LatencyNS,
		Error:     e.Error,
		Target:    string(bytes.TrimRight(e.Target[:], "\x00")),
		Details:   string(bytes.TrimRight(e.Details[:], "\x00")),
	}
}

// attachProbes attaches all kprobes to the kernel
func attachProbes(coll *ebpf.Collection) ([]link.Link, error) {
	var links []link.Link

	probes := map[string]string{
		"kprobe_tcp_connect":       "tcp_v4_connect",
		"kretprobe_tcp_connect":    "tcp_v4_connect",
		"kprobe_tcp_v6_connect":    "tcp_v6_connect",
		"kretprobe_tcp_v6_connect": "tcp_v6_connect",
		"kprobe_tcp_sendmsg":       "tcp_sendmsg",
		"kretprobe_tcp_sendmsg":    "tcp_sendmsg",
		"kprobe_tcp_recvmsg":       "tcp_recvmsg",
		"kretprobe_tcp_recvmsg":    "tcp_recvmsg",
		"kprobe_vfs_write":         "vfs_write",
		"kretprobe_vfs_write":      "vfs_write",
		"kprobe_vfs_read":          "vfs_read",
		"kretprobe_vfs_read":       "vfs_read",
		"kprobe_vfs_fsync":         "vfs_fsync",
		"kretprobe_vfs_fsync":      "vfs_fsync",
	}

	for progName, symbol := range probes {
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}

		var l link.Link
		var err error

		if strings.HasPrefix(progName, "kretprobe_") {
			l, err = link.Kretprobe(symbol, prog, nil)
		} else {
			l, err = link.Kprobe(symbol, prog, nil)
		}

		if err != nil {
			for _, existingLink := range links {
				existingLink.Close()
			}
			return nil, fmt.Errorf("failed to attach %s: %w", progName, err)
		}

		links = append(links, l)
	}

	if tracepointProg := coll.Programs["tracepoint_sched_switch"]; tracepointProg != nil {
		tp, err := link.Tracepoint("sched", "sched_switch", tracepointProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") {
				fmt.Fprintf(os.Stderr, "Note: CPU/scheduling tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	libcPath := findLibcPath()
	if libcPath != "" {
		uprobe, err := link.OpenExecutable(libcPath)
		if err == nil {
			if uprobeProg := coll.Programs["uprobe_getaddrinfo"]; uprobeProg != nil {
				l, err := uprobe.Uprobe("getaddrinfo", uprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					fmt.Fprintf(os.Stderr, "Note: DNS tracking (uprobe) unavailable: %v\n", err)
				}
			}
			if uretprobeProg := coll.Programs["uretprobe_getaddrinfo"]; uretprobeProg != nil {
				l, err := uprobe.Uretprobe("getaddrinfo", uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					fmt.Fprintf(os.Stderr, "Note: DNS tracking (uretprobe) unavailable: %v\n", err)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Note: DNS tracking unavailable (libc not found)\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "Note: DNS tracking unavailable (libc path not found)\n")
	}

	return links, nil
}

func findLibcPath() string {
	libcPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
	}

	for _, path := range libcPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	return ""
}

const maxProcessCacheSize = 1000

var processNameCache = make(map[uint32]string)
var processNameCacheMutex = &sync.Mutex{}

func getProcessNameQuick(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	processNameCacheMutex.Lock()
	if name, ok := processNameCache[pid]; ok {
		processNameCacheMutex.Unlock()
		return name
	}
	processNameCacheMutex.Unlock()

	name := ""

	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
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
		statPath := fmt.Sprintf("/proc/%d/stat", pid)
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
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	processNameCacheMutex.Lock()
	if len(processNameCache) >= maxProcessCacheSize {
		for k := range processNameCache {
			delete(processNameCache, k)
			break
		}
	}
	processNameCache[pid] = name
	processNameCacheMutex.Unlock()

	return name
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
