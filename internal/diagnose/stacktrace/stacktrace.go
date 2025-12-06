package stacktrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type Diagnostician interface {
	GetEvents() []*events.Event
}

type stackSummary struct {
	Key        string
	Count      int
	Sample     *events.Event
	FirstFrame string
}

type stackResolver struct {
	cache map[string]string
}

func (r *stackResolver) resolve(ctx context.Context, pid uint32, addr uint64) string {
	select {
	case <-ctx.Done():
		return ""
	default:
	}

	if addr == 0 {
		return ""
	}
	if r.cache == nil {
		r.cache = make(map[string]string)
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exePath == "" {
		return fmt.Sprintf("0x%x", addr)
	}
	key := exePath + "|" + fmt.Sprintf("%x", addr)
	if v, ok := r.cache[key]; ok {
		return v
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, config.DefaultAddr2lineTimeout)
	defer cancel()
	cmd := exec.CommandContext(timeoutCtx, "addr2line", "-e", exePath, fmt.Sprintf("%#x", addr))
	out, err := cmd.Output()
	if err != nil {
		v := fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
		r.cache[key] = v
		return v
	}
	line := strings.TrimSpace(string(out))
	if line == "" || line == "??:0" || line == "??:?" {
		line = fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
	} else {
		line = filepath.Base(exePath) + ":" + line
	}
	r.cache[key] = line
	return line
}

func GenerateStackTraceSectionWithContext(d Diagnostician, ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}

	resolver := &stackResolver{cache: make(map[string]string)}
	stackMap := make(map[string]*stackSummary)
	processed := 0

	for _, e := range allEvents {
		if processed >= config.MaxEventsForStacks {
			break
		}
		if e == nil {
			continue
		}
		if len(e.Stack) == 0 {
			continue
		}
		if e.LatencyNS < config.MinLatencyForStackNS && e.Type != events.EventLockContention && e.Type != events.EventDBQuery {
			continue
		}
		processed++
		top := e.Stack[0]
		frame := resolver.resolve(ctx, e.PID, top)
		if frame == "" {
			continue
		}
		key := fmt.Sprintf("%s|%d", frame, e.Type)
		if entry, ok := stackMap[key]; ok {
			entry.Count++
		} else {
			stackMap[key] = &stackSummary{
				Key:        key,
				Count:      1,
				Sample:     e,
				FirstFrame: frame,
			}
		}
	}

	if len(stackMap) == 0 {
		return ""
	}

	var summaries []*stackSummary
	for _, v := range stackMap {
		summaries = append(summaries, v)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Count > summaries[j].Count
	})

	var report string
	report += "Stack Traces for Slow Operations:\n"
	limit := config.MaxStackTracesLimit
	if len(summaries) < limit {
		limit = len(summaries)
	}
	for i := 0; i < limit; i++ {
		s := summaries[i]
		e := s.Sample
		if e == nil {
			continue
		}
		report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, target=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), e.Target, float64(e.LatencyNS)/float64(config.NSPerMS))
		maxFrames := config.MaxStackFramesLimit
		if len(e.Stack) < maxFrames {
			maxFrames = len(e.Stack)
		}
		for j := 0; j < maxFrames; j++ {
			addr := e.Stack[j]
			frame := resolver.resolve(ctx, e.PID, addr)
			report += fmt.Sprintf("    #%d %s\n", j, frame)
		}
	}
	report += "\n"
	return report
}

