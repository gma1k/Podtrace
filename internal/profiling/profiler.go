package profiling

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/pprof/profile"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/sanitize"
)

// maxCPUProfileBytes caps how much of a target pod's CPU profile is read.
const maxCPUProfileBytes = 32 * 1024 * 1024

// maxTopFunctions caps how many functions a parsed profile keeps.
const maxTopFunctions = 20

// maxPprofRedirects bounds how many same-origin redirects a pprof fetch follows
// (net/http/pprof answers /debug/pprof with a redirect to /debug/pprof/).
const maxPprofRedirects = 3

// ProfileType identifies the kind of profile to collect.
type ProfileType int

const (
	ProfileHeap      ProfileType = iota // /debug/pprof/heap?debug=1
	ProfileGoroutine                    // /debug/pprof/goroutine?debug=2
	ProfileCPU                          // /debug/pprof/profile?seconds=N (binary, stored raw)
)

func (t ProfileType) String() string {
	switch t {
	case ProfileHeap:
		return "heap"
	case ProfileGoroutine:
		return "goroutine"
	case ProfileCPU:
		return "cpu"
	default:
		return "unknown"
	}
}

// FunctionSample represents a single allocation or sample from a pprof text profile.
type FunctionSample struct {
	Function string
	Bytes    int64
	Count    int64
}

// CPUFunctionSample is one function's flat CPU time from a pprof CPU profile.
type CPUFunctionSample struct {
	Function string
	CPUTime  time.Duration
	Samples  int64
}

// ProfileResult holds the result of a single profile fetch from a target pod.
type ProfileResult struct {
	Type            ProfileType
	FetchedAt       time.Time
	Duration        time.Duration
	TextData        string
	RawBytes        []byte
	TopFunctions    []FunctionSample
	TopCPUFunctions []CPUFunctionSample

	GoroutineCount int
	BlockedCount   int
	Available      bool   // false = endpoint not found or fetch error
	Error          string // non-empty on failure
}

// PodProfiler discovers and fetches pprof profiles from a running pod.
// It is safe for concurrent use after construction.
type PodProfiler struct {
	podIP string
	ports []int
	// foundPort is 0 until discovery succeeds. Atomic because Discover
	// runs on the trace goroutine while the HTTP fetchers read it from
	// handler goroutines concurrently.
	foundPort  atomic.Int64
	httpClient *http.Client
}

// NewPodProfiler creates a PodProfiler for the given pod IP and candidate ports.
func NewPodProfiler(podIP string, ports []int) *PodProfiler {
	return &PodProfiler{
		podIP: podIP,
		ports: ports,
		httpClient: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     podPinnedTransport(podIP),
			CheckRedirect: sameOriginRedirect,
		},
	}
}

var errNotPodAddress = errors.New("pprof fetch refused: destination is not the target pod IP")

// podPinnedTransport returns a transport that can only ever connect to podIP.
func podPinnedTransport(podIP string) *http.Transport {
	pinned := net.ParseIP(podIP)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if pinned == nil || !pinned.Equal(net.ParseIP(host)) {
				return nil, fmt.Errorf("%w: %s", errNotPodAddress, sanitize.Terminal(host))
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
		},
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
}

// sameOriginRedirect follows a redirect only when it stays on the scheme,
// host and port of the original request.
func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxPprofRedirects {
		return fmt.Errorf("pprof fetch refused: more than %d redirects", maxPprofRedirects)
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		return fmt.Errorf("pprof fetch refused: redirect leaves %s://%s", origin.Scheme, origin.Host)
	}
	return nil
}

// endpoint builds the URL for path on the pod at port, bracketing IPv6.
func (p *PodProfiler) endpoint(port int64, path string) string {
	return "http://" + net.JoinHostPort(p.podIP, strconv.FormatInt(port, 10)) + path
}

// Discover probes each candidate port for a live pprof HTTP index endpoint.
// Returns true if one is found and caches the port for subsequent fetches.
// Uses a short per-port timeout to avoid blocking the caller.
func (p *PodProfiler) Discover(ctx context.Context) bool {
	if p.foundPort.Load() != 0 {
		return true
	}
	if p.podIP == "" {
		return false
	}

	probeClient := &http.Client{
		Timeout:       200 * time.Millisecond,
		Transport:     p.httpClient.Transport,
		CheckRedirect: p.httpClient.CheckRedirect,
	}
	for _, port := range p.ports {
		url := p.endpoint(int64(port), "/debug/pprof/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			p.foundPort.Store(int64(port))
			logger.Info("Discovered pprof endpoint on target pod",
				zap.String("pod_ip", p.podIP),
				zap.Int("port", port))
			return true
		}
	}
	logger.Info("No pprof endpoint found on target pod — CPU correlation will use BPF stacks only",
		zap.String("pod_ip", p.podIP),
		zap.Ints("ports_tried", p.ports))
	return false
}

// FetchHeap fetches the heap profile in text mode (?debug=1) and parses
// top allocating functions.
func (p *PodProfiler) FetchHeap(ctx context.Context) *ProfileResult {
	port := p.foundPort.Load()
	if port == 0 {
		return &ProfileResult{Type: ProfileHeap, Available: false, Error: "no pprof endpoint discovered"}
	}
	url := p.endpoint(port, "/debug/pprof/heap?debug=1")
	text, raw, err := p.fetchText(ctx, url)
	if err != nil {
		return &ProfileResult{Type: ProfileHeap, Available: false, Error: err.Error()}
	}
	result := &ProfileResult{
		Type:         ProfileHeap,
		FetchedAt:    time.Now(),
		TextData:     text,
		RawBytes:     raw,
		Available:    true,
		TopFunctions: parseHeapText(text),
	}
	return result
}

// FetchGoroutine fetches the goroutine profile in full text mode (?debug=2)
// and counts total and blocked goroutines.
func (p *PodProfiler) FetchGoroutine(ctx context.Context) *ProfileResult {
	port := p.foundPort.Load()
	if port == 0 {
		return &ProfileResult{Type: ProfileGoroutine, Available: false, Error: "no pprof endpoint discovered"}
	}
	url := p.endpoint(port, "/debug/pprof/goroutine?debug=2")
	text, raw, err := p.fetchText(ctx, url)
	if err != nil {
		return &ProfileResult{Type: ProfileGoroutine, Available: false, Error: err.Error()}
	}
	total, blocked := parseGoroutineText(text)
	return &ProfileResult{
		Type:           ProfileGoroutine,
		FetchedAt:      time.Now(),
		TextData:       text,
		RawBytes:       raw,
		Available:      true,
		GoroutineCount: total,
		BlockedCount:   blocked,
	}
}

// FetchCPUProfile triggers a CPU profile of the given duration and parses it
// into the functions with the most flat CPU time. The binary body is dropped
// once parsed so a stored result does not pin up to maxCPUProfileBytes.
func (p *PodProfiler) FetchCPUProfile(ctx context.Context, duration time.Duration) *ProfileResult {
	port := p.foundPort.Load()
	if port == 0 {
		return &ProfileResult{Type: ProfileCPU, Available: false, Error: "no pprof endpoint discovered"}
	}
	secs := int(duration.Seconds())
	if secs < 1 {
		secs = 1
	}
	url := p.endpoint(port, "/debug/pprof/profile?seconds="+strconv.Itoa(secs))
	// Use a longer timeout for CPU profiles — duration + 5s buffer.
	fetchCtx, cancel := context.WithTimeout(ctx, duration+5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return &ProfileResult{Type: ProfileCPU, Available: false, Error: err.Error()}
	}
	// p.httpClient carries a 5s global timeout for discovery and the quick
	// profile endpoints, but /debug/pprof/profile?seconds=N blocks for the
	// FULL N seconds before responding — the shared client timed out every
	// CPU profile longer than ~5s (the default is 30s). Use a dedicated
	// client bounded only by fetchCtx.
	cpuClient := &http.Client{Transport: p.httpClient.Transport, CheckRedirect: p.httpClient.CheckRedirect}
	resp, err := cpuClient.Do(req)
	if err != nil {
		return &ProfileResult{Type: ProfileCPU, Available: false, Error: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &ProfileResult{Type: ProfileCPU, Available: false,
			Error: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, url)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCPUProfileBytes))
	if err != nil {
		return &ProfileResult{Type: ProfileCPU, Available: false, Error: err.Error()}
	}
	top, err := parseCPUProfile(raw)
	if err != nil {
		logger.Warn("CPU profile from target pod could not be parsed",
			zap.String("pod_ip", p.podIP), zap.Error(err))
	}
	return &ProfileResult{
		Type:            ProfileCPU,
		FetchedAt:       time.Now(),
		Duration:        duration,
		Available:       true,
		TopCPUFunctions: top,
	}
}

// parseCPUProfile returns the functions with the most flat CPU time in a
// pprof CPU profile, highest first.
func parseCPUProfile(raw []byte) ([]CPUFunctionSample, error) {
	prof, err := profile.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	countIdx, cpuIdx := -1, -1
	for i, st := range prof.SampleType {
		switch {
		case st.Type == "samples" && countIdx < 0:
			countIdx = i
		case st.Type == "cpu" && st.Unit == "nanoseconds" && cpuIdx < 0:
			cpuIdx = i
		}
	}
	if cpuIdx < 0 {
		return nil, fmt.Errorf("profile has no cpu/nanoseconds sample type")
	}
	type agg struct {
		cpu     int64
		samples int64
	}
	byFunction := map[string]*agg{}
	for _, s := range prof.Sample {
		if len(s.Location) == 0 || cpuIdx >= len(s.Value) {
			continue
		}
		name := leafFunctionName(s.Location[0])
		a := byFunction[name]
		if a == nil {
			a = &agg{}
			byFunction[name] = a
		}
		a.cpu += s.Value[cpuIdx]
		if countIdx >= 0 && countIdx < len(s.Value) {
			a.samples += s.Value[countIdx]
		}
	}
	out := make([]CPUFunctionSample, 0, len(byFunction))
	for name, a := range byFunction {
		out = append(out, CPUFunctionSample{Function: name, CPUTime: time.Duration(a.cpu), Samples: a.samples})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUTime != out[j].CPUTime {
			return out[i].CPUTime > out[j].CPUTime
		}
		return out[i].Function < out[j].Function
	})
	if len(out) > maxTopFunctions {
		out = out[:maxTopFunctions]
	}
	return out, nil
}

// leafFunctionName names the innermost function at loc, falling back to the
// address for unsymbolized locations.
func leafFunctionName(loc *profile.Location) string {
	if len(loc.Line) > 0 && loc.Line[0].Function != nil && loc.Line[0].Function.Name != "" {
		return sanitize.Terminal(loc.Line[0].Function.Name)
	}
	return fmt.Sprintf("0x%x", loc.Address)
}

// fetchText fetches a URL and returns both the body as string and raw bytes.
func (p *PodProfiler) fetchText(ctx context.Context, url string) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)) // 4 MB cap
	if err != nil {
		return "", nil, err
	}
	return string(raw), raw, nil
}

// parseHeapText parses the text output of /debug/pprof/heap?debug=1 and
// returns the top allocating functions sorted by bytes.
//
// Format example lines:
//
//	1: 1048576 [1: 1048576] @ 0x... 0x...
//	#	0x...	runtime.mallocgc+0x...	...
//	#	0x...	net/http.(*persistConn).roundTrip+0x...	...
func parseHeapText(text string) []FunctionSample {
	type raw struct {
		bytes int64
		count int64
		fn    string
	}
	// We scan for the "heap profile:" section which lists allocations grouped
	// by stack. Each group starts with a line like "N: Mbytes [N: Mbytes] @ addr..."
	// followed by "#" lines showing the stack.
	aggregated := map[string]*raw{}

	scanner := bufio.NewScanner(strings.NewReader(text))
	var curBytes, curCount int64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			curBytes = 0
			curCount = 0
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Stack frame line — extract function name.
			// Format: "#\t0xADDR\tfuncname+offset\tfile:line"
			parts := strings.Fields(line)
			if len(parts) >= 3 && curBytes > 0 {
				fn := parts[2]
				// Strip "+offset" suffix.
				if idx := strings.Index(fn, "+"); idx > 0 {
					fn = fn[:idx]
				}
				if fn == "" || fn == "runtime.mallocgc" {
					continue
				}
				fn = sanitize.Terminal(fn)
				if existing, ok := aggregated[fn]; ok {
					existing.bytes += curBytes
					existing.count += curCount
				} else {
					aggregated[fn] = &raw{bytes: curBytes, count: curCount, fn: fn}
				}
			}
			continue
		}
		// Try to parse allocation header: "N: BYTES [N: BYTES] @ ..."
		if strings.Contains(line, ":") && strings.Contains(line, "@") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				countStr := strings.TrimSuffix(parts[0], ":")
				bytesStr := parts[1]
				c, err1 := strconv.ParseInt(countStr, 10, 64)
				b, err2 := strconv.ParseInt(bytesStr, 10, 64)
				if err1 == nil && err2 == nil {
					curCount = c
					curBytes = b
				}
			}
		}
	}

	samples := make([]FunctionSample, 0, len(aggregated))
	for _, r := range aggregated {
		samples = append(samples, FunctionSample{Function: r.fn, Bytes: r.bytes, Count: r.count})
	}
	// Sort by bytes descending.
	for i := 0; i < len(samples)-1; i++ {
		for j := i + 1; j < len(samples); j++ {
			if samples[j].Bytes > samples[i].Bytes {
				samples[i], samples[j] = samples[j], samples[i]
			}
		}
	}
	if len(samples) > maxTopFunctions {
		samples = samples[:maxTopFunctions]
	}
	return samples
}

// parseGoroutineText counts goroutines and blocked goroutines from
// /debug/pprof/goroutine?debug=2 text output.
//
// Each goroutine block starts with "goroutine N [state]:".
// A "blocked" goroutine is in state: chan receive, chan send, select,
// semacquire, IO wait, sleep, syscall, etc.
func parseGoroutineText(text string) (total, blocked int) {
	blockedStates := map[string]bool{
		"chan receive":           true,
		"chan send":              true,
		"select":                 true,
		"semacquire":             true,
		"IO wait":                true,
		"sleep":                  true,
		"syscall":                true,
		"sync.Mutex":             true,
		"sync.RWMutex":           true,
		"timer goroutine (idle)": true,
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "goroutine ") {
			continue
		}
		total++
		// Extract state from "goroutine N [state]:" or "goroutine N [state, N minutes]:"
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		state := line[start+1 : end]
		// State may have duration: "chan receive, 5 minutes"
		if comma := strings.Index(state, ","); comma > 0 {
			state = strings.TrimSpace(state[:comma])
		}
		if blockedStates[state] {
			blocked++
		}
	}
	return total, blocked
}
