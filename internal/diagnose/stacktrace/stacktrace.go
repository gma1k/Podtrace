package stacktrace

import (
	"context"
	"debug/elf"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/procmaps"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sanitize"
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

type Resolver struct {
	inner stackResolver
}

// NewResolver returns a Resolver with an empty cache. It is not safe for
// concurrent use; construct one per report.
func NewResolver() *Resolver {
	return &Resolver{inner: stackResolver{cache: make(map[string]string)}}
}

// Resolve renders one instruction pointer captured in pid's address space.
func (r *Resolver) Resolve(ctx context.Context, pid uint32, addr uint64) string {
	return sanitize.Terminal(r.inner.resolve(ctx, pid, addr))
}

type stackResolver struct {
	// symbols is nil in production, meaning sharedSymbolTables.
	symbols  *symbolTableCache
	cache    map[string]string
	segments map[string][]loadSegment
	mappings map[string][]exeMapping
	allMaps  map[uint32][]procmaps.Entry
}

// loadSegment is a PT_LOAD program header: the file-offset range it covers and
// the virtual address it loads at in the ELF's own (unbiased) address space.
type loadSegment struct {
	off    uint64
	vaddr  uint64
	filesz uint64
}

// exeMapping is one file-backed line from /proc/<pid>/maps: the runtime address
// range and the file offset at its start.
type exeMapping struct {
	start uint64
	end   uint64
	pgoff uint64
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
	if IsKernelAddress(addr) {
		if sym := defaultKallsyms.Resolve(addr); sym != "" {
			return sym
		}
		return fmt.Sprintf("0x%x", addr)
	}
	mapsPath, err := procfs.Readlink(fmt.Sprintf("%d/exe", pid))
	if err != nil || mapsPath == "" {
		return fmt.Sprintf("0x%x", addr)
	}
	exePath := exeLink(pid)
	if !hostfs.IsRegularFile(exePath) {
		return fmt.Sprintf("0x%x", addr)
	}
	key := exePath + "|" + fmt.Sprintf("%x", addr)
	if v, ok := r.cache[key]; ok {
		return v
	}
	symAddrForTable := addr
	if v, ok := r.translateAddr(pid, mapsPath, exePath, addr); ok {
		symAddrForTable = v
	} else if other, unmapped := r.otherMappedFile(pid, mapsPath, addr); other != "" || unmapped {
		v := fmt.Sprintf("0x%x", addr)
		if other != "" {
			v = fmt.Sprintf("%s@0x%x", other, addr)
		}
		r.cache[key] = v
		return v
	}
	if name := r.symbolTables().get(exePath).lookupAt(exePath, symAddrForTable); name != "" {
		r.cache[key] = name
		return name
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, config.DefaultAddr2lineTimeout)
	defer cancel()
	addr2lineBin, err := exec.LookPath("addr2line")
	if err != nil {
		v := fmt.Sprintf("%s@0x%x", filepath.Base(mapsPath), addr)
		r.cache[key] = v
		return v
	}
	cmd := exec.CommandContext(timeoutCtx, addr2lineBin, "-e", exePath, fmt.Sprintf("%#x", symAddrForTable)) // #nosec G204 -- LookPath-resolved binary; exePath is the fixed /proc/<pid>/exe link; address is %#x-formatted
	out, err := cmd.Output()
	if err != nil {
		v := fmt.Sprintf("%s@0x%x", filepath.Base(mapsPath), addr)
		r.cache[key] = v
		return v
	}
	line := strings.TrimSpace(string(out))
	if line == "" || line == "??:0" || line == "??:?" {
		line = fmt.Sprintf("%s@0x%x", filepath.Base(mapsPath), addr)
	} else {
		line = filepath.Base(mapsPath) + ":" + line
	}
	r.cache[key] = line
	return line
}

func (r *stackResolver) symbolTables() *symbolTableCache {
	if r.symbols != nil {
		return r.symbols
	}
	return sharedSymbolTables
}

// exeLink is the kernel's link to the file pid is executing. Opening it
// reaches that exact inode without walking the name readlink reports, which
// the traced process controls: it may since have been replaced by a FIFO
// that blocks the open, or by a symlink that leads out of the container.
func exeLink(pid uint32) string {
	return filepath.Join(config.ProcBasePath, strconv.FormatUint(uint64(pid), 10), "exe")
}

// translateAddr converts a runtime instruction pointer into the ELF virtual
// address addr2line expects.
func (r *stackResolver) translateAddr(pid uint32, mapsPath, filePath string, addr uint64) (uint64, bool) {
	mappings := r.exeMappings(pid, mapsPath)
	var fileOffset uint64
	found := false
	for _, m := range mappings {
		if addr >= m.start && addr < m.end {
			fileOffset = addr - m.start + m.pgoff
			found = true
			break
		}
	}
	if !found {
		return 0, false
	}

	for _, s := range r.loadSegments(filePath) {
		if fileOffset >= s.off && fileOffset < s.off+s.filesz {
			return fileOffset - s.off + s.vaddr, true
		}
	}
	return 0, false
}

// exeMappings returns the file-backed mappings of exePath in process pid,
// parsed from /proc/<pid>/maps and cached per (pid, exePath).
func (r *stackResolver) exeMappings(pid uint32, exePath string) []exeMapping {
	if r.mappings == nil {
		r.mappings = make(map[string][]exeMapping)
	}
	key := fmt.Sprintf("%d|%s", pid, exePath)
	if m, ok := r.mappings[key]; ok {
		return m
	}

	want := strings.TrimSuffix(exePath, deletedSuffix)
	var out []exeMapping
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err == nil {
		for _, e := range procmaps.Parse(data) {
			if e.Path != want {
				continue
			}
			out = append(out, exeMapping{start: e.Start, end: e.End, pgoff: e.Offset})
		}
	}
	r.mappings[key] = out
	return out
}

const deletedSuffix = " (deleted)"

// otherMappedFile names the file other than the executable mapped at addr in
// pid, such as libc.so.6 or [vdso]; "" when addr is in the executable, in an
// anonymous mapping, or the maps cannot be read.
func (r *stackResolver) otherMappedFile(pid uint32, exePath string, addr uint64) (name string, unmapped bool) {
	if r.allMaps == nil {
		r.allMaps = make(map[uint32][]procmaps.Entry)
	}
	entries, ok := r.allMaps[pid]
	if !ok {
		if data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid)); err == nil {
			entries = procmaps.Parse(data)
		}
		r.allMaps[pid] = entries
	}
	exe := strings.TrimSuffix(exePath, deletedSuffix)
	for _, e := range entries {
		if addr >= e.Start && addr < e.End {
			if e.Path == "" || e.Path == exe {
				return "", false
			}
			return filepath.Base(e.Path), false
		}
	}
	return "", len(entries) > 0
}

// loadSegments returns exePath's PT_LOAD program headers, parsing the ELF once
// and caching the result.
func (r *stackResolver) loadSegments(exePath string) []loadSegment {
	if r.segments == nil {
		r.segments = make(map[string][]loadSegment)
	}
	if s, ok := r.segments[exePath]; ok {
		return s
	}

	out := readLoadSegments(exePath)
	r.segments[exePath] = out
	return out
}

func readLoadSegments(exePath string) (out []loadSegment) {
	defer safeelf.RecoverParse("stacktrace.loadSegments")
	f, _, err := safeelf.OpenRegular(exePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil
	}
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD {
			out = append(out, loadSegment{off: p.Off, vaddr: p.Vaddr, filesz: p.Filesz})
		}
	}
	return out
}

func GenerateStackTraceSectionWithContext(d Diagnostician, ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}

	resolver := NewResolver()
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
		if e.LatencyNS < safeconv.Int64ToUint64(config.MinLatencyForStackNS) && e.Type != events.EventLockContention && e.Type != events.EventDBQuery {
			continue
		}
		processed++
		top := e.Stack[0]
		frame := resolver.Resolve(ctx, e.PID, top)
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
		if e.Target != "" {
			report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, target=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), sanitize.Terminal(e.Target), float64(e.LatencyNS)/float64(config.NSPerMS))
		} else {
			report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), float64(e.LatencyNS)/float64(config.NSPerMS))
		}
		maxFrames := config.MaxStackFramesLimit
		if len(e.Stack) < maxFrames {
			maxFrames = len(e.Stack)
		}
		for j := 0; j < maxFrames; j++ {
			frame := resolver.Resolve(ctx, e.PID, e.Stack[j])
			if frame == "" {
				break
			}
			report += fmt.Sprintf("    #%d %s\n", j, frame)
		}
	}
	report += "\n"
	return report
}
