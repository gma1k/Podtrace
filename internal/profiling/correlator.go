package profiling

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sanitize"
)

const maxCorrelatedSlowEvents = 20

const maxCorrelatedStackDepth = 16

const maxSymbolizedFrames = 64

const maxReportedFrames = 10

const symbolizeBudget = 15 * time.Second

func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// FrameResolver renders one captured instruction pointer.
type FrameResolver interface {
	Resolve(ctx context.Context, pid uint32, addr uint64) string
}

// FrameCount holds a stack frame address/symbol and how many times it appeared
// in SchedSwitch events during slow-operation windows.
type FrameCount struct {
	Frame string
	Count int
}

// ProcessCPU summarises CPU scheduling activity for a single process.
type ProcessCPU struct {
	PID        uint32
	Name       string
	SchedCount int
	AvgBlockNS float64
}

// CorrelatedResult is the output of Correlate, it ties together BPF-observed
// slow events, CPU hot-path frames from SchedSwitch stacks, memory page-fault
// data, and optional pprof endpoint results fetched from the pod.
type CorrelatedResult struct {
	SlowEvents []*events.Event

	HotFrames []FrameCount

	SchedulerFrames int

	CPUHotProcesses []ProcessCPU

	PageFaultCounts map[uint32]int // PID → fault count
	OOMEvents       []*events.Event

	HeapProfile      *ProfileResult
	GoroutineProfile *ProfileResult
	CPUProfile       *ProfileResult

	PprofAvailable bool
	PodIP          string

	StartTime time.Time
	EndTime   time.Time
}

// Correlate analyses allEvents and the optional profiling results, producing a
// CorrelatedResult that links slow I/O / CPU events with stack-level context.
func Correlate(
	ctx context.Context,
	allEvents []*events.Event,
	heap *ProfileResult,
	goroutine *ProfileResult,
	cpuTriggerMS float64,
	resolver FrameResolver,
) *CorrelatedResult {
	result := &CorrelatedResult{
		PageFaultCounts: map[uint32]int{},
		PprofAvailable:  (heap != nil && heap.Available) || (goroutine != nil && goroutine.Available),
	}
	if heap != nil {
		result.HeapProfile = heap
	}
	if goroutine != nil {
		result.GoroutineProfile = goroutine
	}

	if len(allEvents) == 0 {
		return result
	}

	triggerNS := uint64(cpuTriggerMS * float64(config.NSPerMS))

	// Collect slow events (windows are built after capping, below).
	for _, e := range allEvents {
		if e == nil {
			continue
		}
		// Track OOM events regardless of latency.
		if e.Type == events.EventOOMKill {
			result.OOMEvents = append(result.OOMEvents, e)
			continue
		}
		if e.Type == events.EventPageFault {
			result.PageFaultCounts[e.PID]++
			continue
		}

		if e.LatencyNS >= triggerNS && isSlowEventType(e.Type) {
			result.SlowEvents = append(result.SlowEvents, e)
		}
	}

	sort.Slice(result.SlowEvents, func(i, j int) bool {
		return result.SlowEvents[i].LatencyNS > result.SlowEvents[j].LatencyNS
	})
	if len(result.SlowEvents) > maxCorrelatedSlowEvents {
		result.SlowEvents = result.SlowEvents[:maxCorrelatedSlowEvents]
	}

	type window struct{ start, end time.Time }
	slowWindows := make([]window, 0, len(result.SlowEvents))
	for _, e := range result.SlowEvents {
		eventWall := clock.BPFTimestampToWall(e.Timestamp)
		slowWindows = append(slowWindows, window{
			start: eventWall.Add(-50 * time.Millisecond),
			end:   eventWall.Add(time.Duration(safeInt64(e.LatencyNS)) + 50*time.Millisecond),
		})
	}

	pidStats := map[uint32]*ProcessCPU{}
	frameAgg := map[frameAddr]int{}

	for _, e := range allEvents {
		if e == nil || e.Type != events.EventSchedSwitch {
			continue
		}
		ps, ok := pidStats[e.PID]
		if !ok {
			ps = &ProcessCPU{PID: e.PID, Name: e.ProcessName}
			pidStats[e.PID] = ps
		}
		ps.SchedCount++
		ps.AvgBlockNS += float64(e.LatencyNS)

		// Check if this SchedSwitch falls inside any slow-event window.
		if len(slowWindows) > 0 && len(e.Stack) > 0 {
			eventWall := clock.BPFTimestampToWall(e.Timestamp)
			inWindow := false
			for _, w := range slowWindows {
				if !eventWall.Before(w.start) && !eventWall.After(w.end) {
					inWindow = true
					break
				}
			}
			if inWindow {
				for i, addr := range e.Stack {
					if i >= maxCorrelatedStackDepth {
						break
					}
					if addr == 0 {
						continue
					}
					frameAgg[frameAddr{pid: e.PID, addr: addr}]++
				}
			}
		}
	}

	for _, ps := range pidStats {
		if ps.SchedCount > 0 {
			ps.AvgBlockNS /= float64(ps.SchedCount)
		}
		result.CPUHotProcesses = append(result.CPUHotProcesses, *ps)
	}
	sort.Slice(result.CPUHotProcesses, func(i, j int) bool {
		return result.CPUHotProcesses[i].SchedCount > result.CPUHotProcesses[j].SchedCount
	})
	if len(result.CPUHotProcesses) > 10 {
		result.CPUHotProcesses = result.CPUHotProcesses[:10]
	}

	result.HotFrames, result.SchedulerFrames = symbolizeHotFramesHidingScheduler(ctx, frameAgg, resolver)

	if len(allEvents) > 0 {
		result.StartTime = clock.BPFTimestampToWall(allEvents[0].Timestamp)
		result.EndTime = clock.BPFTimestampToWall(allEvents[len(allEvents)-1].Timestamp)
	}

	return result
}

// frameAddr is one captured instruction pointer, kept with the pid whose
// address space it belongs to: user addresses are only meaningful against that
// process's mappings, so aggregating on the address alone would merge frames
// from unrelated binaries.
type frameAddr struct {
	pid  uint32
	addr uint64
}

// symbolizeHotFrames turns raw addresses into named frames, keeping only the
// ones worth printing.
func symbolizeHotFrames(ctx context.Context, counts map[frameAddr]int, resolver FrameResolver) []FrameCount {
	frames, _ := symbolizeHotFramesHidingScheduler(ctx, counts, resolver)
	return frames
}

// symbolizeHotFramesHidingScheduler is symbolizeHotFrames that also reports how
// many frame hits it hid as Go scheduler machinery, so a profile that is all
// scheduler can say so instead of looking empty.
func symbolizeHotFramesHidingScheduler(ctx context.Context, counts map[frameAddr]int, resolver FrameResolver) ([]FrameCount, int) {
	if len(counts) == 0 {
		return nil, 0
	}

	ranked := make([]struct {
		frame frameAddr
		count int
	}, 0, len(counts))
	for f, c := range counts {
		ranked = append(ranked, struct {
			frame frameAddr
			count int
		}{f, c})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count != ranked[j].count {
			return ranked[i].count > ranked[j].count
		}
		if ranked[i].frame.pid != ranked[j].frame.pid {
			return ranked[i].frame.pid < ranked[j].frame.pid
		}
		return ranked[i].frame.addr < ranked[j].frame.addr
	})

	top := ranked
	if len(top) > maxSymbolizedFrames {
		top = top[:maxSymbolizedFrames]
	}

	byProcess := make([]int, len(top))
	for i := range byProcess {
		byProcess[i] = i
	}
	sort.SliceStable(byProcess, func(a, b int) bool {
		fa, fb := top[byProcess[a]].frame, top[byProcess[b]].frame
		if fa.pid != fb.pid {
			return fa.pid < fb.pid
		}
		return fa.addr < fb.addr
	})
	names := make([]string, len(top))
	for _, idx := range byProcess {
		f := top[idx].frame
		if resolver != nil {
			names[idx] = resolver.Resolve(ctx, f.pid, f.addr)
		}
		if names[idx] == "" {
			names[idx] = fmt.Sprintf("0x%x", f.addr)
		}
	}

	merged := map[string]int{}
	order := []string{}
	hidden := 0
	for i, r := range top {
		name := names[i]
		if isSchedulerFrame(name) {
			hidden += r.count
			continue
		}
		if _, seen := merged[name]; !seen {
			order = append(order, name)
		}
		merged[name] += r.count
	}

	out := make([]FrameCount, 0, len(order))
	for _, name := range order {
		out = append(out, FrameCount{Frame: name, Count: merged[name]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > maxReportedFrames {
		out = out[:maxReportedFrames]
	}
	return out, hidden
}

// isSlowEventType returns true for event types where LatencyNS reflects a real
// blocking operation latency worth correlating against CPU profiles.
func isSlowEventType(t events.EventType) bool {
	switch t {
	case events.EventTCPSend, events.EventTCPRecv,
		events.EventConnect,
		events.EventRead, events.EventWrite, events.EventFsync,
		events.EventDNS,
		events.EventDBQuery,
		events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventGRPCMethod,
		events.EventKafkaProduce, events.EventKafkaFetch,
		events.EventTLSHandshake,
		events.EventLockContention,
		events.EventHTTPResp,
		events.EventFastCGIResp:
		return true
	default:
		return false
	}
}

// GenerateSection produces the "Performance Profiling Correlation" report section
// from a CorrelatedResult. It is called by Handler.GenerateSection.
func GenerateSection(cr *CorrelatedResult, duration time.Duration) string {
	if cr == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Performance Profiling Correlation:\n")

	if cr.PprofAvailable {
		fmt.Fprintf(&sb, "  pprof endpoint: available (pod %s)\n", cr.PodIP)
	} else {
		sb.WriteString("  pprof endpoint: not found on target pod\n")
		sb.WriteString("    Tip: add  import _ \"net/http/pprof\"  to your Go binary and\n")
		sb.WriteString("    expose a /debug/pprof/ HTTP listener to enable heap / goroutine data.\n")
	}
	sb.WriteString("\n")

	if len(cr.SlowEvents) > 0 {
		fmt.Fprintf(&sb, "  Slow events (> threshold) count: %d\n", len(cr.SlowEvents))
		sb.WriteString("  Top slow events:\n")
		for i, e := range cr.SlowEvents {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&sb, "    %s  PID=%-6d  %-12s  latency=%v  target=%s\n",
				e.TypeString(),
				e.PID,
				sanitize.Terminal(e.ProcessName),
				time.Duration(safeInt64(e.LatencyNS)),
				sanitize.Terminal(truncate(e.Target, 60)))
		}
		sb.WriteString("\n")
	}

	if len(cr.CPUHotProcesses) > 0 {
		sb.WriteString("  CPU Scheduling Activity (from BPF sched_switch):\n")
		fmt.Fprintf(&sb, "    %-8s  %-16s  %-10s  %s\n",
			"PID", "Process", "Switches", "Avg Block Time")
		for _, ps := range cr.CPUHotProcesses {
			fmt.Fprintf(&sb, "    %-8d  %-16s  %-10d  %v\n",
				ps.PID, sanitize.Terminal(truncate(ps.Name, 15)), ps.SchedCount,
				time.Duration(int64(ps.AvgBlockNS)).Round(time.Microsecond))
		}
		sb.WriteString("\n")
	}

	if len(cr.HotFrames) > 0 {
		sb.WriteString("  CPU hot frames during slow-event windows (BPF stacks):\n")
		for i, f := range cr.HotFrames {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "    %-5d  %s\n", f.Count, sanitize.Terminal(f.Frame))
		}
		sb.WriteString("  Frames are resolved where the process was still running; any that\n")
		sb.WriteString("  remain as raw addresses belong to a process that had already exited.\n")
	}
	if cr.SchedulerFrames > 0 {
		fmt.Fprintf(&sb, "  %d Go scheduler frame hits (runtime.schedule, runtime.park_m, ...) hidden.\n",
			cr.SchedulerFrames)
	}
	if len(cr.HotFrames) > 0 || cr.SchedulerFrames > 0 {
		sb.WriteString("\n")
	}

	if cr.GoroutineProfile != nil && cr.GoroutineProfile.Available {
		fmt.Fprintf(&sb, "  Goroutines: %d total, %d blocked\n",
			cr.GoroutineProfile.GoroutineCount,
			cr.GoroutineProfile.BlockedCount)
		if cr.GoroutineProfile.BlockedCount > 50 {
			sb.WriteString("  WARNING: high blocked goroutine count may indicate lock contention or slow I/O.\n")
		}
		sb.WriteString("\n")
	}

	if cr.HeapProfile != nil && cr.HeapProfile.Available && len(cr.HeapProfile.TopFunctions) > 0 {
		sb.WriteString("  Top heap allocating functions (from pprof heap profile):\n")
		for i, f := range cr.HeapProfile.TopFunctions {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "    %-10s  count=%-6d  %s\n",
				formatBytes(f.Bytes), f.Count, sanitize.Terminal(f.Function))
		}
		sb.WriteString("\n")
	}

	if cr.CPUProfile != nil && cr.CPUProfile.Available && len(cr.CPUProfile.TopCPUFunctions) > 0 {
		fmt.Fprintf(&sb, "  Top CPU functions (from %v pprof CPU profile, flat time):\n", cr.CPUProfile.Duration)
		for i, f := range cr.CPUProfile.TopCPUFunctions {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&sb, "    %-10v  samples=%-6d  %s\n",
				f.CPUTime.Round(time.Millisecond), f.Samples, sanitize.Terminal(f.Function))
		}
		sb.WriteString("\n")
	}

	if len(cr.PageFaultCounts) > 0 {
		type kv struct {
			pid   uint32
			count int
		}
		var faults []kv
		for pid, cnt := range cr.PageFaultCounts {
			faults = append(faults, kv{pid, cnt})
		}
		sort.Slice(faults, func(i, j int) bool { return faults[i].count > faults[j].count })
		fmt.Fprintf(&sb, "  Page faults observed: %d distinct PIDs\n", len(faults))
		for i, f := range faults {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&sb, "    PID %-6d  faults=%d\n", f.pid, f.count)
		}
		sb.WriteString("\n")
	}

	if len(cr.OOMEvents) > 0 {
		fmt.Fprintf(&sb, "  OOM Kill events: %d\n", len(cr.OOMEvents))
		for _, e := range cr.OOMEvents {
			fmt.Fprintf(&sb, "    task=%s  mem=%s\n", sanitize.Terminal(e.Target), formatBytes(safeInt64(e.Bytes)))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// truncate delegates to events.TruncateString, the shared rune-safe and
// panic-safe truncator, so the logic lives in one place.
func truncate(s string, maxLen int) string {
	return events.TruncateString(s, maxLen)
}

func formatBytes(b int64) string {
	if b < 0 {
		return "?"
	}
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}
