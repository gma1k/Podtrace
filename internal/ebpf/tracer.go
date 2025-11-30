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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

type Tracer struct {
	collection  *ebpf.Collection
	links       []link.Link
	reader      *ringbuf.Reader
	cgroupPath  string
	pidCache    map[uint32]bool
	pidCacheMu  sync.RWMutex
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
		pidCache:   make(map[uint32]bool),
	}, nil
}

func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	t.cgroupPath = cgroupPath
	return nil
}

func (t *Tracer) SetContainerID(containerID string) error {
	t.containerID = containerID
	dnsLinks := attachDNSProbes(t.collection, containerID)
	if len(dnsLinks) > 0 {
		t.links = append(t.links, dnsLinks...)
	}
	return nil
}

func (t *Tracer) isPIDInCgroup(pid uint32) bool {
	if t.cgroupPath == "" {
		return true
	}

	if !validation.ValidatePID(pid) {
		return false
	}

	t.pidCacheMu.RLock()
	if cached, ok := t.pidCache[pid]; ok {
		t.pidCacheMu.RUnlock()
		return cached
	}
	t.pidCacheMu.RUnlock()

	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	if len(cgroupFile) > 64 {
		return false
	}
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		t.pidCacheMu.Lock()
		t.pidCache[pid] = false
		if len(t.pidCache) > 10000 {
			for k := range t.pidCache {
				delete(t.pidCache, k)
				break
			}
		}
		t.pidCacheMu.Unlock()
		return false
	}

	cgroupContent := strings.TrimSpace(string(data))
	pidCgroupPath := extractCgroupPathFromProc(cgroupContent)
	if pidCgroupPath == "" {
		t.pidCacheMu.Lock()
		t.pidCache[pid] = false
		if len(t.pidCache) > 10000 {
			for k := range t.pidCache {
				delete(t.pidCache, k)
				break
			}
		}
		t.pidCacheMu.Unlock()
		return false
	}

	normalizedTarget := normalizeCgroupPath(t.cgroupPath)
	normalizedPID := normalizeCgroupPath(pidCgroupPath)

	result := false
	if normalizedPID == normalizedTarget {
		result = true
	} else if strings.HasPrefix(normalizedPID, normalizedTarget+"/") {
		result = true
	} else if strings.HasPrefix(normalizedTarget, normalizedPID+"/") {
		result = true
	}

	t.pidCacheMu.Lock()
	if len(t.pidCache) >= 10000 {
		for k := range t.pidCache {
			delete(t.pidCache, k)
			if len(t.pidCache) < 9000 {
				break
			}
		}
	}
	t.pidCache[pid] = result
	t.pidCacheMu.Unlock()

	return result
}

func normalizeCgroupPath(path string) string {
	path = strings.TrimPrefix(path, "/sys/fs/cgroup")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	return path
}

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

			event := parseEvent(record.RawSample)
			if event != nil {
				event.ProcessName = getProcessNameQuick(event.PID)
				event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

				if t.isPIDInCgroup(event.PID) {
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

func parseEvent(data []byte) *events.Event {
	const expectedEventSize = 304
	if len(data) < expectedEventSize {
		return nil
	}

	var e struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		Bytes     uint64
		TCPState  uint32
		Target    [128]byte
		Details   [128]byte
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
		Bytes:     e.Bytes,
		TCPState:  e.TCPState,
		Target:    string(bytes.TrimRight(e.Target[:], "\x00")),
		Details:   string(bytes.TrimRight(e.Details[:], "\x00")),
	}
}

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
		"kprobe_udp_sendmsg":       "udp_sendmsg",
		"kretprobe_udp_sendmsg":    "udp_sendmsg",
		"kprobe_udp_recvmsg":       "udp_recvmsg",
		"kretprobe_udp_recvmsg":    "udp_recvmsg",
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

	if tcpStateProg := coll.Programs["tracepoint_tcp_set_state"]; tcpStateProg != nil {
		tp, err := link.Tracepoint("tcp", "tcp_set_state", tcpStateProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: TCP state tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	if pageFaultProg := coll.Programs["tracepoint_page_fault_user"]; pageFaultProg != nil {
		tp, err := link.Tracepoint("exceptions", "page_fault_user", pageFaultProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: Page fault tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	if oomKillProg := coll.Programs["tracepoint_oom_kill_process"]; oomKillProg != nil {
		tp, err := link.Tracepoint("oom", "oom_kill_process", oomKillProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: OOM kill tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	return links, nil
}

func attachDNSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	var links []link.Link
	libcPath := findLibcPath(containerID)
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
	return links
}

func findLibcPath(containerID string) string {
	libcPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
	}

	for _, path := range libcPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	if containerID != "" {
		containerPaths := findLibcInContainer(containerID)
		for _, path := range containerPaths {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}

	return ""
}

func findLibcInContainer(containerID string) []string {
	var paths []string
	containerRoot := fmt.Sprintf("/var/lib/docker/containers/%s/rootfs", containerID)
	if _, err := os.Stat(containerRoot); err == nil {
		libcPaths := []string{
			containerRoot + "/lib/x86_64-linux-gnu/libc.so.6",
			containerRoot + "/lib64/libc.so.6",
			containerRoot + "/lib/libc.so.6",
			containerRoot + "/usr/lib/x86_64-linux-gnu/libc.so.6",
			containerRoot + "/usr/lib64/libc.so.6",
			containerRoot + "/usr/lib/libc.so.6",
		}
		paths = append(paths, libcPaths...)
	}

	procPaths := []string{
		"/proc/1/root/lib/x86_64-linux-gnu/libc.so.6",
		"/proc/1/root/lib64/libc.so.6",
		"/proc/1/root/lib/libc.so.6",
		"/proc/1/root/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/proc/1/root/usr/lib64/libc.so.6",
		"/proc/1/root/usr/lib/libc.so.6",
	}
	paths = append(paths, procPaths...)

	return paths
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
