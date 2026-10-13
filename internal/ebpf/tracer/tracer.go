package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/attribution"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/dns"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/ebpf/h2decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3stream"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/loader"
	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/ebpf/parser"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/ebpf/quicinitial"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/redactor"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sanitize"
	"github.com/gma1k/podtrace/internal/sysfs"
	"github.com/gma1k/podtrace/internal/validation"
)

type stackTraceValue struct {
	IPs [config.MaxStackDepth]uint64
	Nr  uint32
	Pad uint32
}

// ProfilingController is implemented by internal/profiling.Handler and
// registered via SetProfilingController before Start() to expose
// /profile/* routes on the management port HTTP server.
type ProfilingController interface {
	HTTPStart(w http.ResponseWriter, r *http.Request)
	HTTPStatus(w http.ResponseWriter, r *http.Request)
	HTTPResult(w http.ResponseWriter, r *http.Request)
}

// ProfilingControllerSetter is satisfied by *Tracer.
type ProfilingControllerSetter interface {
	SetProfilingController(ctrl ProfilingController)
}

type Tracer struct {
	cgroupMkdirAttached bool
	inheritedCache      sync.Map
	collection          *ebpf.Collection
	links               []link.Link
	probeGroupsMu       sync.Mutex
	probeGroups         map[probes.ProbeGroup][]link.Link
	dnsPacketLinks      map[string][]link.Link
	http3Links          map[string][]link.Link
	sockOpsLinks        map[string][]link.Link
	sockOpsCoverage     sockOpsCoverage

	onCPUMu      sync.Mutex
	onCPUSampler *oncpu.Sampler

	probesClosed bool

	intentionallyDisabled map[probes.ProbeGroup]struct{}
	detachWarned          map[probes.ProbeGroup]struct{}

	containerUprobes              map[string]*containerUprobeSet
	globalProtocolAttached        bool
	attachContainerGroupFn        func(g probes.ProbeGroup, id string, pids []uint32) []link.Link
	reader                        *ringbuf.Reader
	h2Reader                      *ringbuf.Reader
	h2Decoder                     *h2decode.Decoder
	grpcCoverage                  *grpcDecodeCoverage
	h3Reader                      *ringbuf.Reader
	h3Decoder                     *h3decode.Decoder
	h3ChunkReader                 *ringbuf.Reader
	h3Assembler                   *h3stream.Assembler
	h3SectionStash                *h3stream.SectionStash
	h3ParkedMu                    sync.Mutex
	h3Parked                      []h3ParkedTxn
	quicReader                    *ringbuf.Reader
	dnsPayloadReader              *ringbuf.Reader
	dnsResolvedMap                *ebpf.Map
	dnsResolved6Map               *ebpf.Map
	filter                        *filter.CgroupFilter
	containerID                   string
	containerIDMu                 sync.Mutex
	containerPID                  uint32
	processNameCache              *cache.LRUCache
	attributionTable              *attribution.Table
	attributionCorrelatorDisabled bool
	pathCache                     *cache.PathCache
	resourceMgr                   *resourceMonitorManager
	lastDNSDrops                  uint64
	dropReport                    atomic.Pointer[dropReportFn]
	cgroupPaths                   atomic.Pointer[[]string]
	useUserspaceCgroupFilter      atomic.Bool
	denyWhenNoTargets             atomic.Bool
	targetCgroupIDs               atomic.Pointer[map[uint64]struct{}]
	cgroupCapacityWarned          atomic.Int64
	cgroupWriteMu                 sync.Mutex
	onCPUFlags                    uint32
	piiRedactor                   *redactor.Redactor
	profilingCtrl                 ProfilingController

	stopCancel context.CancelFunc
	stopOnce   sync.Once
	readerWG   sync.WaitGroup
}

// registerGroupLinks records freshly attached links under their probe group
// (so Disable/EnableProbeGroup can manage them) and in the flat registry
// Stop() closes.
func (t *Tracer) registerGroupLinks(g probes.ProbeGroup, ls []link.Link) {
	if len(ls) == 0 {
		return
	}
	t.probeGroupsMu.Lock()
	if t.probesClosed {
		t.probeGroupsMu.Unlock()
		closeLinks(ls)
		return
	}
	defer t.probeGroupsMu.Unlock()
	t.probeGroups[g] = append(t.probeGroups[g], ls...)
	t.links = append(t.links, ls...)
}

func (t *Tracer) addLinks(ls []link.Link) {
	if len(ls) == 0 {
		return
	}
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	t.links = append(t.links, ls...)
}

func (t *Tracer) linkCount() int {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	return len(t.links)
}

type ContainerProbeTarget struct {
	ID   string
	PIDs []uint32
}

type containerUprobeSet struct {
	pids  []uint32
	links map[probes.ProbeGroup][]link.Link
	// seen and claimed persist for the container's lifetime: a process that
	// starts later only adds uprobes for files no earlier process covered,
	// so the container's probes are never torn down while it runs.
	seen    map[uint32]struct{}
	claimed map[probes.ProbeGroup]*probes.AttachedFiles
}

func newContainerUprobeSet(pids []uint32) *containerUprobeSet {
	s := &containerUprobeSet{
		pids:    pids,
		links:   map[probes.ProbeGroup][]link.Link{},
		seen:    make(map[uint32]struct{}, len(pids)),
		claimed: map[probes.ProbeGroup]*probes.AttachedFiles{},
	}
	for _, p := range pids {
		s.seen[p] = struct{}{}
	}
	return s
}

// claimFor returns the group's record of attached files, creating it.
func (s *containerUprobeSet) claimFor(g probes.ProbeGroup) *probes.AttachedFiles {
	if s.claimed == nil {
		s.claimed = map[probes.ProbeGroup]*probes.AttachedFiles{}
	}
	af := s.claimed[g]
	if af == nil {
		af = probes.NewAttachedFiles()
		s.claimed[g] = af
	}
	return af
}

// unseenPIDs returns the pids this set has not attached for yet.
func (s *containerUprobeSet) unseenPIDs(pids []uint32) []uint32 {
	var out []uint32
	for _, p := range pids {
		if _, ok := s.seen[p]; !ok {
			out = append(out, p)
		}
	}
	return out
}

func samePIDSet(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *containerUprobeSet) allLinks() []link.Link {
	var out []link.Link
	for _, ls := range s.links {
		out = append(out, ls...)
	}
	return out
}

func closeLinks(ls []link.Link) {
	closeLinksConcurrently(ls, maxConcurrentLinkCloses)
}

// containerUprobeGroups lists the probe groups that carry container-scoped
// uprobes, in attach order.
var containerUprobeGroups = []probes.ProbeGroup{
	probes.GroupTLS,
	probes.GroupDatabase,
	probes.GroupPool,
	probes.GroupCache,
	probes.GroupMessaging,
	probes.GroupUSDT,
}

// attachGlobalProtocolProbesOnce attaches the protocol kprobes that are NOT
// container-scoped (HTTP/1.x, gRPC HTTP/2, FastCGI on shared kernel functions)
// exactly once.
func (t *Tracer) attachGlobalProtocolProbesOnce() {
	t.probeGroupsMu.Lock()
	if t.probesClosed {
		t.probeGroupsMu.Unlock()
		return
	}
	already := t.globalProtocolAttached
	t.globalProtocolAttached = true
	t.probeGroupsMu.Unlock()
	if already || t.collection == nil {
		return
	}
	t.registerGroupLinks(probes.GroupFastCGI, probes.AttachFastCGIProbes(t.collection))
	t.registerGroupLinks(probes.GroupNetwork, probes.AttachGRPCProbes(t.collection))
	t.registerGroupLinks(probes.GroupNetwork, probes.AttachHTTPProbes(t.collection))
	t.registerGroupLinks(probes.GroupNetwork, probes.AttachH2Probes(t.collection))
}

// attachContainerGroupUprobes attaches one probe group's container-scoped
// uprobes for one container and returns the links, without registering them
// in the shared probeGroups registry, the per-container lifecycle in
// SetContainerTargets owns them.
func (t *Tracer) attachContainerGroupUprobes(g probes.ProbeGroup, id string, pids []uint32, af *probes.AttachedFiles) []link.Link {
	coll := t.collection
	if coll == nil || id == "" || len(pids) == 0 {
		return nil
	}
	if af == nil {
		af = probes.NewAttachedFiles()
	}
	var ls []link.Link
	for _, pid := range pids {
		newBinary := af.Claim("exe:"+string(g), fmt.Sprintf("%s/%d/exe", config.ProcBasePath, pid))
		switch g {
		case probes.GroupTLS:
			ls = append(ls, probes.AttachDNSProbesWithPID(coll, id, pid, af)...)
			ls = append(ls, probes.AttachSyncProbesWithPID(coll, id, pid, af)...)
			ls = append(ls, probes.AttachTLSProbesWithPID(coll, id, pid, af)...)
			if !newBinary {
				continue
			}
			ls = append(ls, probes.AttachGoTLSProbes(coll, pid)...)
			ls = append(ls, probes.AttachGoGRPCProbes(coll, pid)...)
			ls = append(ls, probes.AttachRustlsProbes(coll, pid)...)
			ls = append(ls, probes.AttachGoHTTP3Probes(coll, pid)...)
			ls = append(ls, probes.AttachGoRequestProbes(coll, pid)...)
			ls = append(ls, probes.AttachNghttp3Probes(coll, pid, af)...)
			ls = append(ls, probes.AttachQuicheProbes(coll, pid, af)...)
			ls = append(ls, probes.AttachQuicheRustProbes(coll, pid)...)
		case probes.GroupDatabase:
			ls = append(ls, probes.AttachDBProbesWithPID(coll, id, pid, af)...)
		case probes.GroupPool:
			ls = append(ls, probes.AttachPoolProbesWithPID(coll, id, pid, af)...)
		case probes.GroupCache:
			ls = append(ls, probes.AttachRedisProbesWithPID(coll, id, pid, af)...)
			ls = append(ls, probes.AttachMemcachedProbesWithPID(coll, id, pid, af)...)
		case probes.GroupMessaging:
			ls = append(ls, probes.AttachKafkaProbesWithPID(coll, id, pid, af)...)
		case probes.GroupUSDT:
			if newBinary {
				ls = append(ls, probes.AttachUSDTProbes(coll, pid)...)
			}
		default:
			return nil
		}
	}
	return ls
}

// attachContainerGroup dispatches to the test seam when set.
func (t *Tracer) attachContainerGroup(g probes.ProbeGroup, id string, pids []uint32, af *probes.AttachedFiles) []link.Link {
	if t.attachContainerGroupFn != nil {
		return t.attachContainerGroupFn(g, id, pids)
	}
	return t.attachContainerGroupUprobes(g, id, pids, af)
}

// attachContainerUprobes attaches every currently-enabled container-scoped
// uprobe group for pids of one container, recording what it attached in set.
func (t *Tracer) attachContainerUprobes(id string, pids []uint32, set *containerUprobeSet) map[probes.ProbeGroup][]link.Link {
	out := make(map[probes.ProbeGroup][]link.Link, len(containerUprobeGroups))
	for _, g := range containerUprobeGroups {
		t.probeGroupsMu.Lock()
		_, disabled := t.intentionallyDisabled[g]
		af := set.claimFor(g)
		t.probeGroupsMu.Unlock()
		if disabled {
			continue
		}
		if ls := t.attachContainerGroup(g, id, pids, af); len(ls) > 0 {
			out[g] = ls
		}
	}
	return out
}

// SetContainerTargets reconciles container-scoped uprobes against the full set
// of currently-targeted containers.
func (t *Tracer) SetContainerTargets(targets []ContainerProbeTarget) error {
	t.attachGlobalProtocolProbesOnce()

	want := make(map[string][]uint32, len(targets))
	for _, ct := range targets {
		if ct.ID != "" {
			want[ct.ID] = t.pidsForContainer(ct.ID, ct.PIDs)
		}
	}

	t.probeGroupsMu.Lock()
	if t.probesClosed {
		t.probeGroupsMu.Unlock()
		return nil
	}
	if t.containerUprobes == nil {
		t.containerUprobes = map[string]*containerUprobeSet{}
	}
	var stale []link.Link
	for id, set := range t.containerUprobes {
		if _, ok := want[id]; ok {
			continue
		}
		stale = append(stale, set.allLinks()...)
		delete(t.containerUprobes, id)
	}
	type attachJob struct {
		id   string
		pids []uint32
		set  *containerUprobeSet
	}
	var jobs []attachJob
	for id, pids := range want {
		set, ok := t.containerUprobes[id]
		if !ok {
			set = newContainerUprobeSet(pids)
			t.containerUprobes[id] = set
			jobs = append(jobs, attachJob{id: id, pids: pids, set: set})
			continue
		}
		fresh := set.unseenPIDs(pids)
		set.pids = pids
		for _, p := range fresh {
			set.seen[p] = struct{}{}
		}
		if len(fresh) > 0 {
			jobs = append(jobs, attachJob{id: id, pids: fresh, set: set})
		}
	}
	t.probeGroupsMu.Unlock()

	for _, l := range stale {
		_ = l.Close()
	}

	for _, j := range jobs {
		links := t.attachContainerUprobes(j.id, j.pids, j.set)
		t.probeGroupsMu.Lock()
		if t.probesClosed || t.containerUprobes[j.id] != j.set {
			t.probeGroupsMu.Unlock()
			closeLinks((&containerUprobeSet{links: links}).allLinks())
			continue
		}
		for g, ls := range links {
			j.set.links[g] = append(j.set.links[g], ls...)
		}
		t.probeGroupsMu.Unlock()
	}
	return nil
}

// attachGroupUprobes re-attaches the probes of a group that are NOT
// container-scoped.
func (t *Tracer) attachGroupUprobes(g probes.ProbeGroup) []link.Link {
	coll := t.collection
	if coll == nil {
		return nil
	}
	switch g {
	case probes.GroupFastCGI:
		return probes.AttachFastCGIProbes(coll)
	case probes.GroupNetwork:
		var ls []link.Link
		ls = append(ls, probes.AttachGRPCProbes(coll)...)
		ls = append(ls, probes.AttachHTTPProbes(coll)...)
		ls = append(ls, probes.AttachH2Probes(coll)...)
		return ls
	}
	return nil
}

// reattachContainerGroupUprobes re-attaches one probe group's container-scoped
// uprobes for every currently-targeted container that lost them.
func (t *Tracer) reattachContainerGroupUprobes(g probes.ProbeGroup) int {
	type target struct {
		id   string
		pids []uint32
	}
	t.probeGroupsMu.Lock()
	missing := make([]target, 0, len(t.containerUprobes))
	for id, set := range t.containerUprobes {
		if len(set.links[g]) == 0 {
			missing = append(missing, target{id: id, pids: set.pids})
			if set.claimed != nil {
				delete(set.claimed, g)
			}
		}
	}
	t.probeGroupsMu.Unlock()

	reattached := 0
	for _, c := range missing {
		t.probeGroupsMu.Lock()
		var af *probes.AttachedFiles
		if set, ok := t.containerUprobes[c.id]; ok {
			af = set.claimFor(g)
		}
		t.probeGroupsMu.Unlock()
		ls := t.attachContainerGroup(g, c.id, c.pids, af)
		if len(ls) == 0 {
			continue
		}
		t.probeGroupsMu.Lock()
		if set, ok := t.containerUprobes[c.id]; ok {
			if set.links == nil {
				set.links = map[probes.ProbeGroup][]link.Link{}
			}
			set.links[g] = append(set.links[g], ls...)
			reattached += len(ls)
			t.probeGroupsMu.Unlock()
			continue
		}
		t.probeGroupsMu.Unlock()
		for _, l := range ls {
			_ = l.Close()
		}
	}
	return reattached
}

// syncDNSPacketProbes reconciles the per-cgroup dns_egress/dns_ingress
// attachments with the current target set.
func (t *Tracer) syncDNSPacketProbes(paths []string) {
	if t.collection == nil {
		return
	}
	t.reconcileCgroupLinks(&t.dnsPacketLinks, cgroupSet(paths), attachDNSPacketProbes)
}

// syncSockOpsProbes reconciles the per-cgroup sock_ops RTT observer with the
// current target set, on the same pattern as the two cgroup_skb groups above.
func (t *Tracer) syncSockOpsProbes(paths []string) {
	if t.collection == nil || !probes.SockOpsEnabled() {
		return
	}
	want := cgroupSet(paths)
	if len(want) == 0 {
		if root := kubepodsRoot(); root != "" {
			want[root] = struct{}{}
		}
	}
	t.reconcileCgroupLinks(&t.sockOpsLinks, want, attachSockOpsProbes)
	t.reportSockOpsCoverage(len(want))
}

type sockOpsCoverage int

const (
	sockOpsCoverageUnreported sockOpsCoverage = iota
	sockOpsCoverageAttached
	sockOpsCoverageNone
)

// reportSockOpsCoverage logs the sock_ops outcome for the node when it
// changes: attached somewhere, or wanted and attached nowhere.
func (t *Tracer) reportSockOpsCoverage(wanted int) {
	t.probeGroupsMu.Lock()
	covered := 0
	for _, ls := range t.sockOpsLinks {
		if len(ls) > 0 {
			covered++
		}
	}
	now := sockOpsCoverageAttached
	if covered == 0 {
		if wanted == 0 {
			t.probeGroupsMu.Unlock()
			return
		}
		now = sockOpsCoverageNone
	}
	changed := now != t.sockOpsCoverage
	t.sockOpsCoverage = now
	t.probeGroupsMu.Unlock()
	if changed {
		logSockOpsCoverage(now, covered, wanted)
	}
}

// logSockOpsCoverage is replaceable so tests can count what is logged.
var logSockOpsCoverage = func(now sockOpsCoverage, covered, wanted int) {
	if now == sockOpsCoverageAttached {
		logger.Info("Smoothed-RTT sock_ops hook attached", zap.Int("cgroups", covered))
		return
	}
	logger.Warn("Smoothed-RTT sock_ops hook attached to nothing; network_rtt_seconds stays "+
		"empty and net.rtt_spike_rate falls back to syscall latency",
		zap.Int("cgroupsConsidered", wanted), zap.String("kubepodsRoot", kubepodsRoot()))
}

// syncHTTP3Probes reconciles the per-cgroup http3_egress/http3_ingress QUIC
// detector attachments with the current target set.
func (t *Tracer) syncHTTP3Probes(paths []string) {
	if t.collection == nil {
		return
	}
	t.reconcileCgroupLinks(&t.http3Links, cgroupSet(paths), attachHTTP3Probes)
}

// The per-cgroup attach functions, replaceable so the reconcile logic can be
// exercised without loading programs into a kernel.
var (
	attachDNSPacketProbes = probes.AttachDNSPacketProbes
	attachHTTP3Probes     = probes.AttachHTTP3Probes
	attachSockOpsProbes   = probes.AttachSockOpsProbes
	kubepodsRoot          = probes.KubepodsRoot
)

// cgroupSet is paths as a set, without empty entries.
func cgroupSet(paths []string) map[string]struct{} {
	want := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p != "" {
			want[p] = struct{}{}
		}
	}
	return want
}

// reconcileCgroupLinks makes *links hold exactly one attachment per cgroup in
// want: it closes the links of cgroups no longer wanted and attaches the ones
// not yet present.
func (t *Tracer) reconcileCgroupLinks(links *map[string][]link.Link, want map[string]struct{}, attach func(*ebpf.Collection, []string) []link.Link) {
	t.probeGroupsMu.Lock()
	if t.probesClosed {
		t.probeGroupsMu.Unlock()
		return
	}
	if *links == nil {
		*links = map[string][]link.Link{}
	}
	for p, ls := range *links {
		if _, ok := want[p]; ok {
			continue
		}
		closeLinks(ls)
		delete(*links, p)
	}
	var missing []string
	for p := range want {
		if _, ok := (*links)[p]; !ok {
			missing = append(missing, p)
		}
	}
	t.probeGroupsMu.Unlock()

	for _, p := range missing {
		ls := attach(t.collection, []string{p})
		t.probeGroupsMu.Lock()
		if t.probesClosed {
			t.probeGroupsMu.Unlock()
			closeLinks(ls)
			continue
		}
		(*links)[p] = ls
		t.probeGroupsMu.Unlock()
	}
}

// SetProfilingController wires an optional profiling controller into the
// management API server.
func (t *Tracer) SetProfilingController(ctrl ProfilingController) {
	t.profilingCtrl = ctrl
}

// loadCgroupIDs returns the current cgroup-ID filter set.
func (t *Tracer) loadCgroupIDs() map[uint64]struct{} {
	if p := t.targetCgroupIDs.Load(); p != nil {
		return *p
	}
	return nil
}

// storeCgroupIDs atomically publishes a new cgroup-ID filter set.
func (t *Tracer) storeCgroupIDs(m map[uint64]struct{}) {
	t.targetCgroupIDs.Store(&m)
}

// roundUpPow2 rounds n up to the nearest power of two, minimum 4096.
func roundUpPow2(n uint32) uint32 {
	if n < 4096 {
		return 4096
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	return n + 1
}

var _ TracerInterface = (*Tracer)(nil)

// bpfLoopAvailable reports whether the running kernel supports the bpf_loop
// helper.
func bpfLoopAvailable() bool {
	if os.Getenv("PODTRACE_FORCE_DISABLE_L7") == "1" {
		return false
	}
	err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnLoop)
	if err == nil {
		return true
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false
	}
	logger.Warn("bpf_loop capability probe inconclusive; assuming available", zap.Error(err))
	return true
}

// pruneL7ProbesIfNoBPFLoop removes the L7 protocol programs (identified by an
// actual bpf_loop call in their instruction stream, no hardcoded list) from
// the collection spec when the kernel lacks bpf_loop.
func kernelTypesFromFile(path string) (*btf.Spec, error) {
	if path == "" {
		return nil, nil
	}
	spec, err := btf.LoadSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load BTF from PODTRACE_BTF_FILE %s: %w", path, err)
	}
	return spec, nil
}

func pruneL7ProbesIfNoBPFLoop(spec *ebpf.CollectionSpec) {
	if bpfLoopAvailable() {
		return
	}
	var pruned []string
	for name, ps := range spec.Programs {
		for i := range ps.Instructions {
			ins := ps.Instructions[i]
			if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnLoop) {
				delete(spec.Programs, name)
				pruned = append(pruned, name)
				break
			}
		}
	}
	if len(pruned) > 0 {
		logger.Warn("Kernel lacks the bpf_loop helper (needs mainline 5.17+ or a distro that backports it); "+
			"disabling L7 protocol tracing (HTTP/2, HTTP/3, gRPC, HTTP header capture) and continuing with core L4 tracing",
			zap.Int("pruned_programs", len(pruned)))
	}
}

func NewTracer(tracerOpts ...Option) (*Tracer, error) {
	var startup tracerOptions
	for _, apply := range tracerOpts {
		apply(&startup)
	}

	if err := setDumpable(); err != nil {
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

	defer tightGCForLoad()()
	spec, err := loader.LoadPodtrace()
	if err != nil {
		return nil, err
	}

	rbBytes := config.RingBufferSizeKB
	if rbBytes > 0 && rbBytes <= math.MaxInt/1024 {
		rbBytes *= 1024
	} else {
		rbBytes = config.DefaultRingBufferSizeKB * 1024
	}
	rbSize := roundUpPow2(config.ClampUint32(rbBytes))
	if m, ok := spec.Maps["events"]; ok {
		m.MaxEntries = rbSize
	}
	hashSize := config.ClampUint32(config.BPFHashMapSize)
	for name, m := range spec.Maps {
		if m.Type == ebpf.Hash && m.MaxEntries < hashSize {
			spec.Maps[name].MaxEntries = hashSize
		}
	}

	var opts ebpf.CollectionOptions
	kspec, err := kernelTypesFromFile(config.BTFFilePath)
	if err != nil {
		return nil, err
	}
	if kspec != nil {
		opts.Programs.KernelTypes = kspec
		logger.Info("Using BTF from file instead of host BTF",
			zap.String("path", config.BTFFilePath))
	}
	applyVerifierLogOptions(&opts)

	pruneL7ProbesIfNoBPFLoop(spec)
	pruneOnCPUTaskRegsIfUnsupported(spec)
	pruneFSTracingIfUnsupported(spec, kspec != nil)
	pruneReturnTracingIfUnsupported(spec, kspec != nil)

	HaveSkStorageCrossContext()

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		logVerifierFailure(err)
		return nil, NewCollectionError(err)
	}

	if threshMap, ok := coll.Maps["alert_thresholds"]; ok && threshMap != nil {
		thresholds := []uint32{
			config.ClampUint32(config.AlertWarnPct),
			config.ClampUint32(config.AlertCritPct),
			config.ClampUint32(config.AlertEmergPct),
		}
		for i, v := range thresholds {
			k := uint32(i)
			val := v
			if err := threshMap.Update(&k, &val, ebpf.UpdateAny); err != nil {
				logger.Warn("Failed to set alert threshold", zap.Int("index", i), zap.Uint32("value", val), zap.Error(err))
			}
		}
	}

	probeGroups, err := probes.AttachProbesByGroup(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}
	initiallyDisabled := map[probes.ProbeGroup]struct{}{}
	if startup.gateAtStartup {
		initiallyDisabled = gateInitialProbeGroups(probeGroups, startup.initialCategories)
	}

	var links []link.Link
	for _, ls := range probeGroups {
		links = append(links, ls...)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
		return nil, NewRingBufferError(err)
	}

	captureHeaders := config.CaptureHeaderList()

	var h2rd *ringbuf.Reader
	var h2dec *h2decode.Decoder
	if m := coll.Maps["h2_hdr_events"]; m != nil {
		if r, herr := ringbuf.NewReader(m); herr == nil {
			h2rd = r
			h2dec = h2decode.New()
			h2dec.SetCaptureHeaders(captureHeaders)
		} else {
			logger.Warn("HTTP/2 userspace decode disabled: ringbuf reader unavailable", zap.Error(herr))
		}
	}

	var h3rd *ringbuf.Reader
	if m := coll.Maps["h3_txn_events"]; m != nil {
		if r, herr := ringbuf.NewReader(m); herr == nil {
			h3rd = r
		} else {
			logger.Warn("HTTP/3 L7 decode disabled: ringbuf reader unavailable", zap.Error(herr))
		}
	}

	var h3chunkrd *ringbuf.Reader
	var h3stash *h3stream.SectionStash
	var h3asm *h3stream.Assembler
	if m := coll.Maps["h3_stream_chunks"]; m != nil {
		if r, herr := ringbuf.NewReader(m); herr == nil {
			h3chunkrd = r
			h3stash = h3stream.NewSectionStash(h3SectionTTL, h3SectionStashCap)
			stash := h3stash
			h3asm = h3stream.NewAssembler(func(k h3stream.ConnKey, sec h3stream.Section) {
				if n := h3SectionLogCount.Add(1); n <= 20 {
					logger.Debug("h3 inbound section decoded",
						zap.Uint32("tgid", k.TGID), zap.Uint64("conn", k.Conn),
						zap.Uint64("stream", sec.StreamID), zap.Uint16("status", sec.Status),
						zap.String("method", sec.Method))
				}
				stash.Put(h3stream.SectionKey{TGID: k.TGID, Conn: k.Conn, Stream: sec.StreamID}, sec)
			})
		} else {
			logger.Warn("HTTP/3 inbound header decode disabled: ringbuf reader unavailable", zap.Error(herr))
		}
	}
	populateCaptureHeaderNames(coll, captureHeaders)
	_ = populatePidNamespace(coll)
	setGRPCPort(coll, config.GRPCPort)

	var quicrd *ringbuf.Reader
	if m := coll.Maps["quic_initial_events"]; m != nil {
		if r, qerr := ringbuf.NewReader(m); qerr == nil {
			quicrd = r
		} else {
			logger.Warn("HTTP/3 SNI extraction disabled: ringbuf reader unavailable", zap.Error(qerr))
		}
	}

	var dnspayrd *ringbuf.Reader
	var dnsResolvedMap, dnsResolved6Map *ebpf.Map
	if config.DNSPayloadEnabled {
		if m := coll.Maps["dns_payload_events"]; m != nil {
			if r, derr := ringbuf.NewReader(m); derr == nil {
				dnspayrd = r
				setDNSPayloadFlag(coll, true)
				dnsResolvedMap = coll.Maps["dns_resolved"]
				dnsResolved6Map = coll.Maps["dns_resolved6"]
			} else {
				logger.Warn("DNS payload decode disabled: ringbuf reader unavailable", zap.Error(derr))
			}
		}
	}

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	processCache := cache.NewLRUCache(config.CacheMaxSize, ttl)

	t := &Tracer{
		collection:                    coll,
		links:                         links,
		probeGroups:                   probeGroups,
		intentionallyDisabled:         initiallyDisabled,
		reader:                        rd,
		h2Reader:                      h2rd,
		h2Decoder:                     h2dec,
		grpcCoverage:                  newGRPCDecodeCoverage(),
		h3Reader:                      h3rd,
		h3Decoder:                     h3decode.NewDecoder(captureHeaders),
		h3ChunkReader:                 h3chunkrd,
		h3Assembler:                   h3asm,
		h3SectionStash:                h3stash,
		quicReader:                    quicrd,
		dnsPayloadReader:              dnspayrd,
		dnsResolvedMap:                dnsResolvedMap,
		dnsResolved6Map:               dnsResolved6Map,
		filter:                        filter.NewCgroupFilter(),
		processNameCache:              processCache,
		attributionTable:              attribution.New(0, 0),
		attributionCorrelatorDisabled: os.Getenv("PODTRACE_DISABLE_ATTRIBUTION_CORRELATOR") == "1",
		pathCache:                     cache.NewPathCache(),
		resourceMgr:                   newResourceMonitorManager(),
	}
	t.useUserspaceCgroupFilter.Store(true)
	t.storeCgroupIDs(map[uint64]struct{}{})

	if config.RedactPII {
		r, err := redactor.DefaultWithCustomRules(config.RedactCustomRules)
		if err != nil {
			logger.Error("Ignoring invalid PODTRACE_REDACT_CUSTOM_RULES; built-in redaction still active",
				zap.Error(err))
		}
		t.piiRedactor = r
	}

	return t, nil
}

// SetDenyWhenNoTargets makes an empty target set mean "capture nothing"
// instead of "capture everything".
func (t *Tracer) SetDenyWhenNoTargets(deny bool) {
	t.denyWhenNoTargets.Store(deny)
}

// idleDeny reports whether the tracer is in deny-when-no-targets mode with
// no targets configured on either filter layer.
func (t *Tracer) idleDeny() bool {
	return t.denyWhenNoTargets.Load() &&
		len(t.loadCgroupIDs()) == 0 && !t.filter.HasTargets()
}

// cgroupAllows reports whether an event passes the active cgroup target gate.
func (t *Tracer) cgroupAllows(event *events.Event) bool {
	cgroupIDs := t.loadCgroupIDs()
	switch {
	case len(cgroupIDs) > 0 && event.CgroupID != 0:
		if _, ok := cgroupIDs[event.CgroupID]; ok {
			return true
		}
		_, inherited := t.InheritedCgroupParent(event.CgroupID)
		return inherited
	case t.idleDeny():
		return false
	case t.useUserspaceCgroupFilter.Load():
		return t.filter.IsPIDInCgroup(event.PID)
	default:
		return true
	}
}

// SetCgroups replaces the tracer's entire cgroup filter set with the
// given paths.
// setCgroupPaths atomically publishes the current cgroup target set. Callers
// hold cgroupWriteMu to serialize writers.
func (t *Tracer) setCgroupPaths(paths []string) {
	t.cgroupPaths.Store(&paths)
}

func (t *Tracer) currentCgroupPaths() []string {
	if p := t.cgroupPaths.Load(); p != nil {
		return *p
	}
	return nil
}

func (t *Tracer) primaryCgroupPath() string {
	if p := t.cgroupPaths.Load(); p != nil && len(*p) > 0 {
		return (*p)[0]
	}
	return ""
}

func (t *Tracer) SetCgroups(cgroupPaths []string) error {
	if len(cgroupPaths) == 0 {
		t.cgroupWriteMu.Lock()
		t.setCgroupPaths(nil)
		t.storeCgroupIDs(map[uint64]struct{}{})
		t.filter.SetCgroupPaths(nil)
		if err := t.syncTargetCgroupMap(); err != nil {
			logger.Warn("Failed to clear target_cgroup_ids map", zap.Error(err))
		}
		t.cgroupWriteMu.Unlock()
		t.syncDNSPacketProbes(nil)
		t.syncHTTP3Probes(nil)
		t.syncSockOpsProbes(nil)
		logger.Debug("Detached all cgroups")
		return nil
	}
	return t.attachCgroups(cgroupPaths, true /* replace */)
}

// AttachToCgroup adds cgroupPath to the tracer's filter set and is
// idempotent.
func (t *Tracer) AttachToCgroup(cgroupPath string) error {
	return t.attachCgroups([]string{cgroupPath}, false /* replace */)
}

// AttachToCgroups replaces the tracer's entire cgroup filter set with
// the given list.
func (t *Tracer) AttachToCgroups(cgroupPaths []string) error {
	return t.attachCgroups(cgroupPaths, true /* replace */)
}

// attachCgroups is the shared implementation. When replace=false the
// new cgroups are merged into the existing filter state (engine path).
func (t *Tracer) attachCgroups(cgroupPaths []string, replace bool) error {
	normalized := make([]string, 0, len(cgroupPaths))
	for _, cgroupPath := range cgroupPaths {
		if cgroupPath == "" {
			continue
		}
		containerSubPath := filepath.Join(cgroupPath, "container")
		if _, err := os.Stat(filepath.Join(containerSubPath, "cgroup.procs")); err == nil {
			logger.Debug("Found CRI-O container subfolder, using it for precise cgroup filtering",
				zap.String("parent_path", cgroupPath),
				zap.String("container_path", containerSubPath))
			cgroupPath = containerSubPath
		}
		if filter.NormalizeCgroupPath(cgroupPath) == "" && os.Getenv("PODTRACE_ALLOW_ROOT_CGROUP") != "1" {
			return fmt.Errorf("podtrace: resolved cgroup path %q normalizes to root; refusing to attach (set PODTRACE_ALLOW_ROOT_CGROUP=1 to override)", cgroupPath)
		}
		normalized = append(normalized, cgroupPath)
	}
	if len(normalized) == 0 {
		return fmt.Errorf("no valid cgroup paths provided")
	}

	t.cgroupWriteMu.Lock()
	defer t.cgroupWriteMu.Unlock()

	var allPaths []string
	var newIDs map[uint64]struct{}
	if replace {
		allPaths = normalized
		newIDs = make(map[uint64]struct{}, len(normalized))
	} else {
		existing := t.currentCgroupPaths()
		seen := make(map[string]struct{}, len(existing)+len(normalized))
		for _, p := range existing {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			allPaths = append(allPaths, p)
		}
		for _, p := range normalized {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			allPaths = append(allPaths, p)
		}
		newIDs = make(map[uint64]struct{}, len(allPaths))
		for k := range t.loadCgroupIDs() {
			newIDs[k] = struct{}{}
		}
	}

	t.setCgroupPaths(allPaths)
	t.filter.SetCgroupPaths(allPaths)

	if !pidInCgroupPaths(t.containerPID, allPaths) {
		t.containerPID = 0
		for _, cgroupPath := range allPaths {
			if pid := readMainPIDFromCgroupProcs(cgroupPath); pid != 0 {
				t.containerPID = pid
				break
			}
		}
	}

	if isCgroupV2Base(config.CgroupBasePath) {
		newPaths := normalized
		for _, cgroupPath := range newPaths {
			if cgid, err := getCgroupIDFromPath(cgroupPath); err == nil && cgid != 0 {
				newIDs[cgid] = struct{}{}
			} else if err != nil {
				logger.Debug("Could not get cgroup ID from path", zap.Error(err), zap.String("cgroup_path", cgroupPath))
			}
			if entries, err := os.ReadDir(cgroupPath); err == nil {
				for _, e := range entries {
					if !e.IsDir() {
						continue
					}
					child := filepath.Join(cgroupPath, e.Name())
					if cgid, err := getCgroupIDFromPath(child); err == nil && cgid != 0 {
						newIDs[cgid] = struct{}{}
					}
				}
			}
		}
		t.storeCgroupIDs(newIDs)
		if err := t.syncTargetCgroupMap(); err != nil {
			logger.Warn("Failed to sync target_cgroup_ids map", zap.Error(err))
		} else if len(newIDs) > 0 {
			logger.Debug("Set target cgroup IDs for in-kernel filtering", zap.Int("count", len(newIDs)))
		}
		t.syncCgroupInheritance(allPaths)
		if len(newIDs) > 0 && os.Getenv("PODTRACE_DISABLE_USERSPACE_CGROUP_FILTER") == "1" {
			t.useUserspaceCgroupFilter.Store(false)
		}
	} else {
		t.storeCgroupIDs(newIDs)
		logger.Debug("Cgroup v2 not detected, using userspace filtering only", zap.String("cgroup_base", config.CgroupBasePath))
	}
	currentPaths := allPaths
	t.syncDNSPacketProbes(currentPaths)
	t.syncHTTP3Probes(currentPaths)
	t.syncSockOpsProbes(currentPaths)

	if t.resourceMgr != nil {
		t.resourceMgr.reconcile(currentPaths)
	}

	logger.Debug("Attached to cgroups",
		zap.Int("cgroup_count", len(allPaths)),
		zap.Uint32("container_pid", t.containerPID),
		zap.Int("target_cgroup_id_count", len(newIDs)),
		zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()),
		zap.Bool("replace", replace))
	return nil
}

func (t *Tracer) syncTargetCgroupMap() error {
	if t.collection == nil || t.collection.Maps == nil {
		return nil
	}
	targetMap, ok := t.collection.Maps["target_cgroup_ids"]
	if !ok || targetMap == nil {
		return nil
	}

	ids := t.loadCgroupIDs()
	t.warnOnCgroupCapacity(len(ids), targetMap.MaxEntries())

	if len(ids) == 0 {
		deny := t.denyWhenNoTargets.Load() && len(t.currentCgroupPaths()) == 0
		if err := t.setCgroupFilterEnabled(deny); err != nil {
			return err
		}
	}

	var key uint64
	var val uint8
	stale := make([]uint64, 0)
	iter := targetMap.Iterate()
	for iter.Next(&key, &val) {
		if _, want := ids[key]; !want {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate target_cgroup_ids: %w", err)
	}
	for _, k := range stale {
		staleKey := k
		if err := targetMap.Delete(&staleKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	one := uint8(1)
	for cgid := range ids {
		cgidCopy := cgid
		if err := targetMap.Update(&cgidCopy, &one, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	if len(ids) > 0 {
		return t.setCgroupFilterEnabled(true)
	}
	return nil
}

// cgroupCapacityExceeded / cgroupCapacityNearFull classify how close the
// desired target set is to the target_cgroup_ids map capacity.
const (
	cgroupCapacityOK = iota
	cgroupCapacityNearFull
	cgroupCapacityExceeded
)

// classifyCgroupCapacity reports whether count exceeds maxEntries or sits
// above 80% of it.
func classifyCgroupCapacity(count int, maxEntries uint32) int {
	if maxEntries == 0 {
		return cgroupCapacityOK
	}
	switch {
	case count > int(maxEntries):
		return cgroupCapacityExceeded
	case count*10 > int(maxEntries)*8:
		return cgroupCapacityNearFull
	default:
		return cgroupCapacityOK
	}
}

// warnOnCgroupCapacity logs when the desired target set approaches or exceeds
// the capacity of the LRU target_cgroup_ids map: beyond capacity the kernel
// silently evicts the oldest entries and their containers' events are
// dropped.
func (t *Tracer) warnOnCgroupCapacity(count int, maxEntries uint32) {
	level := classifyCgroupCapacity(count, maxEntries)
	if level == cgroupCapacityOK {
		t.cgroupCapacityWarned.Store(0)
		return
	}
	if t.cgroupCapacityWarned.Swap(int64(count)) == int64(count) {
		return
	}
	if level == cgroupCapacityExceeded {
		logger.Error("Target cgroup count exceeds kernel filter capacity; the oldest entries are silently evicted (LRU) and their containers' events dropped",
			zap.Int("target_count", count),
			zap.Uint32("max_entries", maxEntries))
		return
	}
	logger.Warn("Target cgroup count approaching kernel filter capacity; targets beyond capacity will be silently evicted (LRU)",
		zap.Int("target_count", count),
		zap.Uint32("max_entries", maxEntries))
}

// setCgroupFilterEnabled flips the dedicated flag the BPF side consults
// before applying the in-kernel cgroup prefilter.
func (t *Tracer) setCgroupFilterEnabled(enabled bool) error {
	if t.collection == nil || t.collection.Maps == nil {
		return nil
	}
	flagMap, ok := t.collection.Maps["cgroup_filter_enabled"]
	if !ok || flagMap == nil {
		return nil
	}
	var zero uint32
	val := uint32(0)
	if enabled {
		val = 1
	}
	return flagMap.Update(&zero, &val, ebpf.UpdateAny)
}

// readPIDsFromCgroupProcs returns every PID listed in the cgroup's
// cgroup.procs file, in file order.
func readPIDsFromCgroupProcs(cgroupPath string) []uint32 {
	rel, ok := sysfs.CgroupRelative(cgroupPath)
	if !ok {
		return nil
	}
	data, err := sysfs.CgroupReadFile(filepath.Join(rel, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(line, "%d", &pid); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readMainPIDFromCgroupProcs returns the container's main host PID, the lowest
// (oldest, hence entrypoint) PID in cgroup.procs or 0.
func readMainPIDFromCgroupProcs(cgroupPath string) uint32 {
	var main uint32
	for _, p := range readPIDsFromCgroupProcs(cgroupPath) {
		if p != 0 && (main == 0 || p < main) {
			main = p
		}
	}
	return main
}

// pidInCgroupPaths reports whether pid is currently listed in any of the given
// cgroups' cgroup.procs — i.e. still alive and a member, not exited or reused.
func pidInCgroupPaths(pid uint32, cgroupPaths []string) bool {
	if pid == 0 {
		return false
	}
	for _, cp := range cgroupPaths {
		for _, p := range readPIDsFromCgroupProcs(cp) {
			if p == pid {
				return true
			}
		}
	}
	return false
}

func isCgroupV2Base(basePath string) bool {
	controllersPath := filepath.Join(basePath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err == nil {
		return true
	}
	return false
}

func getCgroupIDFromPath(path string) (uint64, error) {
	sys, err := statRecord(path)
	if err != nil {
		return 0, err
	}
	return sys.Ino, nil
}

// statRecord stats path and returns the platform stat record, failing both
// when the path is gone and when the file system gives no inode.
func statRecord(path string) (*syscall.Stat_t, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return statRecordOf(st)
}

// statRecordOf returns the platform stat record behind a FileInfo.
func statRecordOf(st os.FileInfo) (*syscall.Stat_t, error) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return nil, fmt.Errorf("unsupported stat type for %s", st.Name())
	}
	return sys, nil
}

func (t *Tracer) SetContainerID(containerID string) error {
	return t.SetContainerIDs([]string{containerID})
}

func (t *Tracer) SetContainerIDs(containerIDs []string) error {
	if len(containerIDs) == 0 {
		return fmt.Errorf("no container IDs provided")
	}
	targets := make([]ContainerProbeTarget, 0, len(containerIDs))
	seen := make(map[string]struct{}, len(containerIDs))
	for _, id := range containerIDs {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}

		target := ContainerProbeTarget{ID: id}
		if pid := probes.FindContainerProcess(id); pid != 0 {
			target.PIDs = []uint32{pid}
		} else {
			logger.Debug("No process found for container; its uprobes will not attach",
				zap.String("container_id", id))
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return fmt.Errorf("all container IDs are empty")
	}
	t.containerIDMu.Lock()
	t.containerID = targets[0].ID
	t.containerIDMu.Unlock()
	return t.SetContainerTargets(targets)
}

// lastContainerID returns the most recently recorded primary container ID
// under the guarding mutex, so readers never race a concurrent
// SetContainerIDs writer.
func (t *Tracer) lastContainerID() string {
	t.containerIDMu.Lock()
	defer t.containerIDMu.Unlock()
	return t.containerID
}

const maxDistinctBinariesPerContainer = 8

// pidsForContainer resolves the PIDs used to discover a container's binaries
// for uprobe attachment: one representative PID per distinct executable
// (deduplicated by the exe's device+inode) among all processes in the
// container's cgroup.
func (t *Tracer) pidsForContainer(id string, seeds []uint32) []uint32 {
	short := id
	if len(short) > 12 {
		short = short[:12]
	}
	var procs []uint32
	for _, p := range t.currentCgroupPaths() {
		if strings.Contains(p, id) || (short != "" && strings.Contains(p, short)) {
			if procs = readPIDsFromCgroupProcs(p); len(procs) > 0 {
				break
			}
		}
	}
	if len(procs) == 0 {
		out := make([]uint32, 0, len(seeds))
		seen := map[uint32]struct{}{}
		for _, s := range seeds {
			if _, dup := seen[s]; s == 0 || dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
		if len(out) > 0 {
			sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
			return out
		}
		logger.Warn("No attached cgroup path matched container ID; uprobe attachment will fall back to scanning /proc for the container",
			zap.String("container_id", id),
			zap.Strings("cgroup_paths", t.currentCgroupPaths()))
		return []uint32{0}
	}

	type exeKey struct {
		dev uint64
		ino uint64
	}
	seenExe := map[exeKey]struct{}{}
	out := make([]uint32, 0, maxDistinctBinariesPerContainer)
	dropped := 0
	for _, pid := range procs {
		sys, err := statRecord(filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe"))
		if err != nil {
			continue
		}
		k := exeKey{dev: uint64(sys.Dev), ino: sys.Ino}
		if _, dup := seenExe[k]; dup {
			continue
		}
		seenExe[k] = struct{}{}
		if len(out) >= maxDistinctBinariesPerContainer {
			dropped++
			continue
		}
		out = append(out, pid)
	}
	if dropped > 0 {
		logger.Warn("Container has more distinct binaries than the uprobe discovery cap; the extra binaries get no library uprobes",
			zap.String("container_id", id),
			zap.Int("cap", maxDistinctBinariesPerContainer),
			zap.Int("dropped_binaries", dropped))
	}
	if len(out) == 0 {
		out = append(out, procs[0])
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type dropReportFn func(reason string, n int)

// SetDropReporter installs a callback the tracer invokes on every discarded
// event.
func (t *Tracer) SetDropReporter(report func(reason string, n int)) {
	if report == nil {
		t.dropReport.Store(nil)
		return
	}
	fn := dropReportFn(report)
	t.dropReport.Store(&fn)
}

func (t *Tracer) reportDrop(reason string, n int) {
	if fn := t.dropReport.Load(); fn != nil && *fn != nil {
		(*fn)(reason, n)
	}
}

// recoverReaderPanic recovers a panic from processing a single record so a
// malformed/edge-case event skips that iteration instead of unwinding the
// reader goroutine and permanently ending event collection.
func recoverReaderPanic(where string) {
	if r := recover(); r != nil {
		logger.Error("panic processing record (recovered, reader continues)",
			zap.String("reader", where),
			zap.Any("panic", r),
			zap.ByteString("stack", debug.Stack()))
	}
}

func (t *Tracer) Start(ctx context.Context, eventChan chan<- *events.Event) error {
	errorLimiter := newErrorRateLimiter()
	slidingWindow := newSlidingWindow(config.DefaultSlidingWindowSize, config.DefaultSlidingWindowBuckets)
	circuitBreaker := newCircuitBreaker(config.DefaultCircuitBreakerThreshold, config.DefaultCircuitBreakerTimeout)
	stackMap := t.collection.Maps["stack_traces"]

	stopCtx, stopCancel := context.WithCancel(ctx)
	t.stopCancel = stopCancel
	ctx = stopCtx

	t.cgroupWriteMu.Lock()
	dnsCgroups := t.currentCgroupPaths()
	if err := t.syncTargetCgroupMap(); err != nil {
		logger.Warn("Failed initial target cgroup map sync", zap.Error(err))
	}
	t.cgroupWriteMu.Unlock()
	t.syncDNSPacketProbes(dnsCgroups)
	t.syncHTTP3Probes(dnsCgroups)
	t.syncSockOpsProbes(dnsCgroups)

	t.resourceMgr.activate(ctx, eventChan,
		t.collection.Maps["cgroup_limits"],
		t.collection.Maps["cgroup_alerts"],
		t.collection.Maps["cgroup_cpu_quota"])

	t.readerWG.Add(1)
	go func() {
		defer t.readerWG.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if t.pathCache != nil {
					t.pathCache.CleanupExpired()
				}
				t.pollBPFMapUtilization()
			}
		}
	}()

	t.readerWG.Add(1)
	go func() {
		defer t.readerWG.Done()
		t.runDNSTimeoutSweeper(ctx, eventChan)
	}()

	if config.ManagementPort > 0 {
		go t.serveManagementAPI(ctx, config.ManagementPort)
	}

	var eventsCollected atomic.Int64
	var eventsFiltered atomic.Int64
	var eventsParsed atomic.Int64
	var filteringDisabled atomic.Bool
	ec := &eventCounters{
		collected:         &eventsCollected,
		filtered:          &eventsFiltered,
		parsed:            &eventsParsed,
		filteringDisabled: &filteringDisabled,
	}
	startTime := time.Now()

	logger.Info("Starting event collection",
		zap.String("cgroup_path", t.primaryCgroupPath()),
		zap.Uint32("container_pid", t.containerPID),
		zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
		zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))

	t.readerWG.Add(1)
	go func() {
		defer t.readerWG.Done()
		eventCollectionTicker := time.NewTicker(5 * time.Second)
		defer eventCollectionTicker.Stop()
		filterAutoDisableHintLogged := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-eventCollectionTicker.C:
				if t.idleDeny() {
					continue
				}
				elapsed := time.Since(startTime)
				if !filteringDisabled.Load() && eventsParsed.Load() > 10 && eventsCollected.Load() == 0 && elapsed > 10*time.Second {
					if config.AllowCgroupFilterAutoDisable() {
						logger.Warn("Events being parsed but all filtered - disabling filtering as fallback",
							zap.Int64("events_parsed", eventsParsed.Load()),
							zap.Int64("events_filtered", eventsFiltered.Load()),
							zap.Int64("events_collected", eventsCollected.Load()),
							zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
							zap.String("cgroup_path", t.primaryCgroupPath()),
							zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))
						filteringDisabled.Store(true)
						t.cgroupWriteMu.Lock()
						t.useUserspaceCgroupFilter.Store(false)
						t.storeCgroupIDs(map[uint64]struct{}{})
						if err := t.syncTargetCgroupMap(); err == nil {
							logger.Info("Cleared kernel-side cgroup filter")
						}
						t.cgroupWriteMu.Unlock()
					} else if !filterAutoDisableHintLogged {
						filterAutoDisableHintLogged = true
						logger.Warn("Events parsed but all filtered; automatic cgroup filter disable not applied. Set PODTRACE_ALLOW_CGROUP_FILTER_DISABLE=1 to allow clearing cgroup filters as a last resort",
							zap.Int64("events_parsed", eventsParsed.Load()),
							zap.Int64("events_filtered", eventsFiltered.Load()),
							zap.Int64("events_collected", eventsCollected.Load()),
							zap.String("cgroup_path", t.primaryCgroupPath()))
					}
				} else if eventsParsed.Load() == 0 && elapsed > 15*time.Second {
					logger.Warn("No events parsed from ring buffer after 15 seconds - check eBPF program attachment",
						zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
						zap.String("cgroup_path", t.primaryCgroupPath()),
						zap.Duration("elapsed", elapsed),
						zap.Int("links_attached", t.linkCount()))
					logger.Warn("If running in a container (e.g. DaemonSet), ensure host /sys/fs/cgroup and /proc are mounted and PODTRACE_CGROUP_BASE / PODTRACE_PROC_BASE point at them; see installation doc 'Running as a DaemonSet'")
				} else if eventsCollected.Load() == 0 && eventsParsed.Load() > 0 && elapsed > 10*time.Second {
					logger.Warn("Events parsed but none collected - filtering may be too strict",
						zap.Int64("events_parsed", eventsParsed.Load()),
						zap.Int64("events_filtered", eventsFiltered.Load()),
						zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
						zap.String("cgroup_path", t.primaryCgroupPath()),
						zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()),
						zap.Duration("elapsed", elapsed))
					if t.useUserspaceCgroupFilter.Load() {
						logger.Warn("Running in a container (e.g. DaemonSet)? Set PODTRACE_CGROUP_BASE and PODTRACE_PROC_BASE to the host's cgroup and proc mount paths so the target pod's cgroup is visible and filtering can match events",
							zap.String("cgroup_base", config.CgroupBasePath),
							zap.String("proc_base", config.ProcBasePath))
					}
				}
			}
		}
	}()

	t.readerWG.Add(1)
	go func() {
		defer t.readerWG.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in event reader",
					zap.Any("panic", r),
					zap.ByteString("stack", debug.Stack()))
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
				t.reportDrop("ringbuf", 1)

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
			func() {
				defer recoverReaderPanic("event reader")
				event := parser.ParseEvent(record.RawSample)
				if event != nil && !t.grpcCoverage.suppresses(event, processingStart) {
					t.processAndDispatch(ctx, event, eventChan, stackMap, ec, processingStart)
				}
			}()
		}
	}()

	if t.h2Reader != nil && t.h2Decoder != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runH2DecodeReader(ctx, eventChan, stackMap, ec) }()
	}

	if t.h3Reader != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runH3DecodeReader(ctx, eventChan, stackMap, ec) }()
	}

	if t.h3ChunkReader != nil && t.h3Assembler != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runH3ChunkReader(ctx) }()
	}

	if t.h3Reader != nil && t.h3SectionStash != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runH3ParkedFlusher(ctx, eventChan, stackMap, ec) }()
	}

	if t.quicReader != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runQUICInitialReader(ctx, eventChan, stackMap, ec) }()
	}

	if t.dnsPayloadReader != nil {
		t.readerWG.Add(1)
		go func() { defer t.readerWG.Done(); t.runDNSPayloadReader(ctx, eventChan, stackMap, ec) }()
	}

	return nil
}

// eventCounters bundles the diagnostic counters shared between the event-reader
// goroutines and the monitoring goroutine.
type eventCounters struct {
	collected         *atomic.Int64
	filtered          *atomic.Int64
	parsed            *atomic.Int64
	filteringDisabled *atomic.Bool
}

// processAndDispatch enriches a parsed event (stack, process name, redaction,
// resolveAndConsumeStack copies the captured user stack for event.StackKey
// out of stackMap onto the event, then deletes the entry.
func resolveAndConsumeStack(stackMap *ebpf.Map, event *events.Event) {
	if stackMap == nil || event.StackKey == 0 {
		return
	}
	var stack stackTraceValue
	key := event.StackKey
	if err := stackMap.Lookup(&key, &stack); err != nil {
		return
	}
	n := int(stack.Nr)
	if n > len(stack.IPs) {
		n = len(stack.IPs)
	}
	if n > 0 {
		frames := make([]uint64, n)
		copy(frames, stack.IPs[:n])
		event.Stack = frames
	}
	_ = stackMap.Delete(&key)
}

// critical-path), applies cgroup filtering, and forwards it to eventChan.
func (t *Tracer) processAndDispatch(ctx context.Context, event *events.Event,
	eventChan chan<- *events.Event, stackMap *ebpf.Map, ec *eventCounters,
	processingStart time.Time) {
	ec.parsed.Add(1)
	resolveAndConsumeStack(stackMap, event)
	attributionSource := t.attributeProcessName(event)
	event.ProcessName = validation.SanitizeProcessName(event.ProcessName)

	if isLikelyTransientComm(event.ProcessName) {
		resolved := false
		if data, err := procfs.ReadFile(fmt.Sprintf("%d/comm", event.PID)); err == nil {
			real := strings.TrimSpace(string(data))
			if real != "" && !isLikelyTransientComm(real) {
				event.ProcessName = validation.SanitizeProcessName(real)
				resolved = true
			}
		}
		if !resolved {
			event.ProcessName = "runc-bootstrap[" + event.ProcessName + "]"
		}
	}

	t.recordAttributionOutcome(event, attributionSource)

	cache.SnapshotCPUTime(event.PID)

	if t.piiRedactor != nil {
		t.piiRedactor.Redact(event)
	}

	// IsError, not Error != 0: a couple of event types carry a utilization
	// percentage in that field rather than an error code, and counting those
	// reports every busy pool and every loaded container as a failure.
	if event.IsError() {
		metricsexporter.RecordError(event.TypeString(), event.Error)
	}

	allowed := true
	cgroupIDs := t.loadCgroupIDs()
	if ec.filteringDisabled.Load() {
		// Fallback mode: allow all events
		allowed = true
	} else if len(cgroupIDs) > 0 && event.CgroupID != 0 {
		_, allowed = cgroupIDs[event.CgroupID]
		if !allowed {
			_, allowed = t.InheritedCgroupParent(event.CgroupID)
		}
		if !allowed {
			if ec.filtered.Add(1) <= 5 || time.Now().Unix()%10 == 0 {
				logger.Debug("Event filtered by cgroup ID mismatch",
					zap.Uint64("event_cgroup_id", event.CgroupID),
					zap.Int("target_cgroup_id_count", len(cgroupIDs)),
					zap.Uint32("pid", event.PID),
					zap.String("process", event.ProcessName))
			}
		}
	} else if t.idleDeny() {
		allowed = false
		ec.filtered.Add(1)
	} else if event.PID == 0 && event.CgroupID != 0 {
		// Some events have no owning task to check. A sock_ops RTT
		// callback runs from the ACK path, so there is no "current" to
		// resolve a PID from and IsPIDInCgroup would reject every one of
		// them. These carry the socket's own cgroup id instead, and the
		// probe already tested that id against the same target set this
		// filter enforces, in the kernel, before emitting. Confinement is
		// not being skipped here, it is being applied on the only key the
		// event has.
		allowed = true
	} else if t.useUserspaceCgroupFilter.Load() {
		allowed = t.filter.IsPIDInCgroup(event.PID)
		if !allowed {
			if ec.filtered.Add(1) <= 5 || time.Now().Unix()%10 == 0 {
				logger.Debug("Event filtered by userspace PID cgroup check",
					zap.Uint32("pid", event.PID),
					zap.String("process", event.ProcessName),
					zap.String("cgroup_path", t.primaryCgroupPath()))
			}
		}
	} else {
		if ec.parsed.Load() <= 5 {
			logger.Debug("No cgroup filtering active, allowing all events",
				zap.Uint64("event_cgroup_id", event.CgroupID),
				zap.Int("target_cgroup_id_count", len(t.loadCgroupIDs())),
				zap.Bool("use_userspace_filter", t.useUserspaceCgroupFilter.Load()))
		}
	}

	if allowed {
		select {
		case <-ctx.Done():
			parser.PutEvent(event)
			return
		case eventChan <- event:
			if ec.collected.Add(1) <= 5 {
				logger.Debug("Event collected",
					zap.Uint64("cgroup_id", event.CgroupID),
					zap.Uint32("pid", event.PID),
					zap.String("process", event.ProcessName),
					zap.String("type", event.TypeString()))
			}
			metricsexporter.RecordEventProcessingLatency(time.Since(processingStart))
		default:
			metricsexporter.RecordRingBufferDrop()
			t.reportDrop("channel_full", 1)
			parser.PutEvent(event)
		}
	} else {
		parser.PutEvent(event)
	}
}

// runH2DecodeReader drains the raw HPACK fragment ringbuf, feeds the userspace
// HTTP/2 decode stage (reorder, reassemble, per-connection hpack.Decoder),
// and dispatches the resulting EventHTTPReq/EventHTTPResp through the same
// enrichment + filtering path as kernel events.
func (t *Tracer) runH2DecodeReader(ctx context.Context, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in HTTP/2 decode reader",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
		}
	}()

	t.readerWG.Add(1)
	go func() {
		defer t.readerWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.dispatchDecoded(ctx, t.h2Decoder.Sweep(), eventChan, stackMap, ec)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := t.h2Reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) ||
				strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		func() {
			defer recoverReaderPanic("http/2 decode")
			t.handleH2Record(ctx, record.RawSample, eventChan, stackMap, ec)
		}()
	}
}

// handleH2Record decodes one record from the HTTP/2 header ring buffer: a
// connection's close evicts its state, anything else is decoded.
func (t *Tracer) handleH2Record(ctx context.Context, raw []byte, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	rec, ok := h2decode.ParseRecord(raw)
	if !ok {
		return
	}
	if rec.IsClose() {
		t.dispatchDecoded(ctx, t.h2Decoder.Evict(rec.ConnID), eventChan, stackMap, ec)
		return
	}
	t.dispatchDecoded(ctx, t.h2Decoder.Ingest(rec), eventChan, stackMap, ec)
}

// dispatchDecoded sends the HTTP/2 decoder's events on, noting which
// processes it is seeing gRPC calls for.
func (t *Tracer) dispatchDecoded(ctx context.Context, evs []*events.Event, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	for _, ev := range evs {
		now := time.Now()
		t.grpcCoverage.noteDecoded(ev, now)
		t.processAndDispatch(ctx, ev, eventChan, stackMap, ec, now)
	}
}

const dnsResolvedNameLen = 128

// setGRPCPort publishes the runtime gRPC destination port (PODTRACE_GRPC_PORT)
// into the array map the gRPC method probe filters on.
func setGRPCPort(coll *ebpf.Collection, port int) {
	if coll == nil || coll.Maps == nil {
		return
	}
	m, ok := coll.Maps["grpc_port_cfg"]
	if !ok || m == nil {
		return
	}
	if port <= 0 || port > 65535 {
		return
	}
	var zero uint32
	val := uint32(port)
	if err := m.Update(&zero, &val, ebpf.UpdateAny); err != nil {
		logger.Warn("failed to set gRPC port config", zap.Error(err))
	}
}

// setDNSPayloadFlag flips the dedicated array flag the DNS ingress program
// consults before shipping raw DNS payloads.
func setDNSPayloadFlag(coll *ebpf.Collection, enabled bool) {
	if coll == nil || coll.Maps == nil {
		return
	}
	m, ok := coll.Maps["dns_payload_enabled"]
	if !ok || m == nil {
		return
	}
	var zero uint32
	val := uint32(0)
	if enabled {
		val = 1
	}
	if err := m.Update(&zero, &val, ebpf.UpdateAny); err != nil {
		logger.Warn("failed to enable DNS payload flag", zap.Error(err))
	}
}

// runDNSPayloadReader drains the raw DNS payload ringbuf, decodes the full
// answer set in userspace (the in-kernel path only records a single address),
// and dispatches one enriched EventDNS per response through the same
// enrichment + filtering path as kernel events.
func (t *Tracer) runDNSPayloadReader(ctx context.Context, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in DNS payload reader",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := t.dnsPayloadReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) ||
				strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		func() {
			defer recoverReaderPanic("dns payload")
			rec, ok := dns.ParseRecord(record.RawSample)
			if !ok {
				return
			}
			t.populateDNSResolved(rec)
			t.processAndDispatch(ctx, buildDNSEventFromRecord(rec), eventChan, stackMap, ec, time.Now())
		}()
	}
}

func dnsResolvedKeyV4(cgroupID uint64, ip4 net.IP) [16]byte {
	var key [16]byte
	binary.NativeEndian.PutUint64(key[0:8], cgroupID)
	copy(key[8:12], ip4)
	return key
}

func dnsResolvedKeyV6(cgroupID uint64, ip6 net.IP) [24]byte {
	var key [24]byte
	binary.NativeEndian.PutUint64(key[0:8], cgroupID)
	copy(key[8:24], ip6)
	return key
}

func (t *Tracer) populateDNSResolved(rec dns.Record) {
	name := dnsResolvedValue(rec.Msg.QName)
	for _, a := range rec.Msg.Answers {
		switch a.Type {
		case dns.TypeA:
			if t.dnsResolvedMap == nil {
				continue
			}
			if ip4 := net.ParseIP(a.IP).To4(); ip4 != nil {
				key := dnsResolvedKeyV4(rec.CgroupID, ip4)
				_ = t.dnsResolvedMap.Update(key[:], name[:], ebpf.UpdateAny)
			}
		case dns.TypeAAAA:
			if t.dnsResolved6Map == nil {
				continue
			}
			if ip6 := net.ParseIP(a.IP).To16(); ip6 != nil {
				key := dnsResolvedKeyV6(rec.CgroupID, ip6)
				_ = t.dnsResolved6Map.Update(key[:], name[:], ebpf.UpdateAny)
			}
		}
	}
}

// dnsResolvedValue renders a query name into the fixed-width, NUL-terminated
// buffer the BPF dns_resolved maps store as their value (char[MAX_STRING_LEN]).
func dnsResolvedValue(name string) [dnsResolvedNameLen]byte {
	var buf [dnsResolvedNameLen]byte
	// Reserve the final byte for the NUL terminator.
	copy(buf[:dnsResolvedNameLen-1], name)
	return buf
}

// buildDNSEventFromRecord turns a decoded DNS payload record into the same
// events.Event shape the compact BPF path emits, but with every resolved
// address (A/AAAA) joined into Details instead of just the first.
func buildDNSEventFromRecord(rec dns.Record) *events.Event {
	e := &events.Event{
		Timestamp:    rec.Timestamp,
		PID:          rec.PID,
		CgroupID:     rec.CgroupID,
		Type:         events.EventDNS,
		LatencyNS:    rec.LatencyNS,
		Error:        int32(rec.RCode),
		TCPState:     uint32(rec.QType),
		DNSServerIP:  rec.ServerIP,
		DNSServerIP6: rec.ServerIP6,
		DNSTransport: rec.Transport,
		Target:       sanitize.Terminal(rec.Msg.QName),

		KernelAggregated: rec.AggRecorded,
	}

	if ips := rec.ResolvedIPs(); len(ips) > 0 {
		e.Details = strings.Join(ips, ", ")
	} else {
		for _, a := range rec.Msg.Answers {
			if a.CNAME != "" {
				e.Details = sanitize.Terminal(a.CNAME)
				break
			}
		}
	}
	return e
}

// runH3DecodeReader drains the HTTP/3 transaction ringbuf (one record per
// request/response captured at the net/http boundary) and dispatches the paired
// EventHTTPReq/EventHTTPResp through the same enrichment + filtering path as
// kernel events.
func (t *Tracer) runH3DecodeReader(ctx context.Context, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in HTTP/3 L7 decode reader",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := t.h3Reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) ||
				strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}

		func() {
			defer recoverReaderPanic("http/3 decode")
			txn, ok := t.h3Decoder.ParseRecord(record.RawSample)
			if !ok {
				return
			}
			if h3Logged := h3TxnLogCount.Add(1); h3Logged <= 20 {
				logger.Debug("h3 txn decoded",
					zap.String("method", txn.Method), zap.String("path", txn.Path),
					zap.Uint16("status", txn.Status), zap.Bool("client", txn.IsClient),
					zap.Uint8("flags", txn.Flags), zap.String("peer_ip", txn.PeerIP),
					zap.Uint16("peer_port", txn.PeerPort), zap.Int("headers", len(txn.Headers)))
			}
			if t.h3EnrichOrPark(txn) {
				return
			}
			for _, ev := range txn.Events() {
				t.processAndDispatch(ctx, ev, eventChan, stackMap, ec, time.Now())
			}
		}()
	}
}

var h3TxnLogCount atomic.Int64

// Inbound-section enrichment tuning: how long decoded sections wait for
// their transaction, how many are held, how long a transaction is parked
// waiting for its section, and how many may be parked at once.
const (
	h3SectionTTL      = 5 * time.Second
	h3SectionStashCap = 2048
	h3ParkWindow      = 200 * time.Millisecond
	h3MaxParked       = 512
)

// h3ParkedTxn is a transaction briefly held back because the decoded
// inbound section that completes it.
type h3ParkedTxn struct {
	txn      *h3decode.Txn
	deadline time.Time
}

// h3EnrichOrPark completes txn from its stream's decoded inbound section.
func (t *Tracer) h3EnrichOrPark(txn *h3decode.Txn) bool {
	if t.h3SectionStash == nil || txn.AdapterConn == 0 {
		return false
	}
	key := h3stream.SectionKey{TGID: txn.PID, Conn: txn.AdapterConn, Stream: txn.AdapterStream}
	if sec, ok := t.h3SectionStash.Take(key); ok {
		h3stream.EnrichTxn(txn, sec)
		if n := h3EnrichLogCount.Add(1); n <= 20 {
			logger.Debug("h3 txn enriched inline",
				zap.Uint16("status", txn.Status), zap.String("method", txn.Method))
		}
		return false
	}
	needsStatus := txn.IsClient && txn.Status == 0 &&
		txn.Flags&(h3decode.FlagAborted|h3decode.FlagRequestOnly) == 0
	needsRequest := txn.Flags&h3decode.FlagResponseOnly != 0 && txn.Method == ""
	if !needsStatus && !needsRequest {
		return false
	}
	t.h3ParkedMu.Lock()
	defer t.h3ParkedMu.Unlock()
	if len(t.h3Parked) >= h3MaxParked {
		return false
	}
	t.h3Parked = append(t.h3Parked, h3ParkedTxn{txn: txn, deadline: time.Now().Add(h3ParkWindow)})
	return true
}

var (
	h3EnrichLogCount  atomic.Int64
	h3ChunkLogCount   atomic.Int64
	h3SectionLogCount atomic.Int64
)

// runH3ChunkReader drains the captured inbound stream bytes and feeds the
// reassembler, which decodes QPACK field sections into the section stash.
func (t *Tracer) runH3ChunkReader(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in HTTP/3 stream chunk reader",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := t.h3ChunkReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) ||
				strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}
		func() {
			defer recoverReaderPanic("http/3 chunk")
			if c, ok := h3stream.ParseChunk(record.RawSample); ok {
				if n := h3ChunkLogCount.Add(1); n <= 20 {
					logger.Debug("h3 stream chunk",
						zap.Uint32("tgid", c.TGID), zap.Uint64("conn", c.Conn),
						zap.Uint64("stream", c.StreamID), zap.Uint32("len", c.CopiedLen),
						zap.Uint32("offset", c.Offset))
				}
				t.h3Assembler.Feed(c)
			}
		}()
	}
}

// runH3ParkedFlusher dispatches parked transactions: enriched as soon as
// their section decodes, unenriched once the park window expires.
func (t *Tracer) runH3ParkedFlusher(ctx context.Context, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		var ready []*h3decode.Txn
		t.h3ParkedMu.Lock()
		kept := t.h3Parked[:0]
		for _, p := range t.h3Parked {
			key := h3stream.SectionKey{TGID: p.txn.PID, Conn: p.txn.AdapterConn, Stream: p.txn.AdapterStream}
			if sec, ok := t.h3SectionStash.Take(key); ok {
				h3stream.EnrichTxn(p.txn, sec)
				ready = append(ready, p.txn)
			} else if now.After(p.deadline) {
				ready = append(ready, p.txn)
			} else {
				kept = append(kept, p)
			}
		}
		t.h3Parked = kept
		t.h3ParkedMu.Unlock()
		for _, txn := range ready {
			for _, ev := range txn.Events() {
				t.processAndDispatch(ctx, ev, eventChan, stackMap, ec, time.Now())
			}
		}
	}
}

var selfPIDNamespace = "/proc/self/ns/pid"

func pidNamespaceStat(procBase string) (string, syscall.Stat_t, error) {
	nsPath := filepath.Join(procBase, "1", "ns", "pid")
	var st syscall.Stat_t
	if err := syscall.Stat(nsPath, &st); err != nil {
		if fallbackErr := syscall.Stat(selfPIDNamespace, &st); fallbackErr != nil {
			return nsPath, st, fallbackErr
		}
	}
	return nsPath, st, nil
}

// pidNamespaceInfo mirrors struct pidns_info in bpf/maps.h.
type pidNamespaceInfo struct {
	Dev uint64
	Ino uint64
}

// populatePidNamespace records this process's pid namespace so BPF programs
// can translate tgids into the namespace the agent keys its per-pid maps
// with. On nested nodes (kind, container-in-container runtimes) the
// init-namespace tgid from bpf_get_current_pid_tgid() differs from the pid
// the agent sees.
func populatePidNamespace(coll *ebpf.Collection) string {
	const warning = "pid namespace not recorded; per-pid maps miss on a nested node"

	m := coll.Maps["pidns_ref"]
	if m == nil {
		reason := "BPF object has no pidns_ref map"
		logger.Warn(warning, zap.String("reason", reason))
		return reason
	}
	nsPath, st, err := pidNamespaceStat(config.ProcBasePath)
	if err != nil {
		reason := "pid namespace not readable"
		logger.Warn(warning, zap.String("reason", reason),
			zap.String("path", nsPath), zap.Error(err))
		return reason
	}
	k := uint32(0)
	v := pidNamespaceInfo{Dev: uint64(st.Dev), Ino: st.Ino}
	if err := m.Update(&k, &v, ebpf.UpdateAny); err != nil {
		reason := "pidns_ref update failed"
		logger.Warn(warning, zap.String("reason", reason), zap.Error(err))
		return reason
	}
	logger.Debug("pid namespace reference recorded",
		zap.String("path", nsPath), zap.Uint64("ino", st.Ino))
	return ""
}

// captureHeaderName mirrors struct h3_hdr_name in bpf/maps.h.
type captureHeaderName struct {
	Len  uint8
	Name [32]byte
}

// populateCaptureHeaderNames pushes the header-capture allowlist into the
// h3_hdr_names array map; slot order matches the userspace decoder's.
func populateCaptureHeaderNames(coll *ebpf.Collection, names []string) {
	if len(names) == 0 {
		return
	}
	m := coll.Maps["h3_hdr_names"]
	if m == nil {
		return
	}
	for i, name := range names {
		if i >= config.MaxCaptureHeaders {
			break
		}
		var v captureHeaderName
		n := copy(v.Name[:], name)
		if n < 0 || n > math.MaxUint8 {
			continue
		}
		v.Len = uint8(n)
		k := uint32(i)
		if err := m.Update(&k, &v, ebpf.UpdateAny); err != nil {
			logger.Debug("capture headers: map update failed",
				zap.String("name", name), zap.Error(err))
		}
	}
	logger.Debug("capture headers configured", zap.Strings("names", names))
}

// quicFlowKey identifies one QUIC flow, mirroring the BPF quic_seen key.
type quicFlowKey struct {
	cgroup uint64
	addr   [16]byte
	port   uint16
}

// quicFlowState accumulates the Initial packets of one flow until the SNI is
// extracted (quic-go splits the ClientHello across two Initials) or the BPF
// per-flow packet cap is reached.
type quicFlowState struct {
	pkts     [][]byte
	done     bool
	lastSeen time.Time
}

const (
	quicInitialMaxPackets = 3
	quicMaxTrackedFlows   = 2048
	quicFlowTTL           = 30 * time.Second
)

// evictQUICFlows makes room in the flow table without discarding flows that are
// still mid-reassembly.
func evictQUICFlows(flows map[quicFlowKey]*quicFlowState, now time.Time) {
	var oldestKey quicFlowKey
	var oldest time.Time
	found := false
	for k, st := range flows {
		if now.Sub(st.lastSeen) > quicFlowTTL {
			delete(flows, k)
			continue
		}
		if !found || st.lastSeen.Before(oldest) {
			oldestKey, oldest, found = k, st.lastSeen, true
		}
	}
	if len(flows) >= quicMaxTrackedFlows && found {
		delete(flows, oldestKey)
	}
}

// runQUICInitialReader drains the QUIC Initial packet ringbuf, extracts the SNI
// (server name) and ALPN from the client's ClientHello via the quicinitial
// package (reassembling across a flow's Initial packets), and emits one
// EVENT_HTTP3 connection event per flow.
func (t *Tracer) runQUICInitialReader(ctx context.Context, eventChan chan<- *events.Event,
	stackMap *ebpf.Map, ec *eventCounters) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in HTTP/3 reader",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
		}
	}()
	const hdr = 60
	flows := make(map[quicFlowKey]*quicFlowState)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		record, err := t.quicReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ringbuf.ErrClosed) ||
				strings.Contains(err.Error(), "closed") {
				return
			}
			continue
		}
		func() {
			defer recoverReaderPanic("http/3 quic")
			data := record.RawSample
			if len(data) <= hdr {
				return
			}
			family := data[20]
			dport := binary.LittleEndian.Uint16(data[22:24])
			var v6 [16]byte
			copy(v6[:], data[24:40])
			var ip string
			if family == 10 {
				ip = events.PeerIP(10, 0, v6)
			} else {
				ip = events.PeerIP(2, binary.BigEndian.Uint32(data[24:28]), v6)
			}

			now := time.Now()
			key := quicFlowKey{cgroup: binary.LittleEndian.Uint64(data[8:16]), addr: v6, port: dport}
			st := flows[key]
			if st == nil {
				if len(flows) >= quicMaxTrackedFlows {
					evictQUICFlows(flows, now)
				}
				st = &quicFlowState{lastSeen: now}
				flows[key] = st
			}
			if st.done {
				return
			}
			st.lastSeen = now
			pktEnd := hdr + int(binary.LittleEndian.Uint16(data[40:42]))
			if pktEnd > len(data) {
				pktEnd = len(data)
			}
			pkt := make([]byte, pktEnd-hdr)
			copy(pkt, data[hdr:pktEnd])
			st.pkts = append(st.pkts, pkt)

			info, xerr := quicinitial.ExtractPackets(st.pkts)
			if xerr != nil && len(st.pkts) < quicInitialMaxPackets {
				return
			}
			st.done = true
			st.pkts = nil

			ev := &events.Event{}
			ev.Timestamp = binary.LittleEndian.Uint64(data[0:8])
			ev.CgroupID = binary.LittleEndian.Uint64(data[8:16])
			ev.PID = binary.LittleEndian.Uint32(data[16:20])
			ev.ProcessName = string(bytes.TrimRight(data[44:60], "\x00"))
			ev.Type = events.EventHTTP3
			ev.Target = fmt.Sprintf("%s:%d", ip, dport)
			ev.PeerDstIP = ip
			ev.PeerDstPort = dport
			if xerr == nil && info.SNI != "" {
				ev.Details = "sni: " + info.SNI
				if len(info.ALPN) > 0 {
					ev.Details += " alpn: " + strings.Join(info.ALPN, ",")
				}
			} else {
				ev.Details = "HTTP/3 (QUIC)"
			}
			t.processAndDispatch(ctx, ev, eventChan, stackMap, ec, time.Now())
		}()
	}
}

// Stop tears the tracer down. Only the first call does anything, so a
// shutdown path and a deferred cleanup can both call it.
func (t *Tracer) Stop() error {
	t.stopOnce.Do(t.stop)
	return nil
}

func (t *Tracer) stop() {
	if t.stopCancel != nil {
		t.stopCancel()
	}
	if t.reader != nil {
		_ = t.reader.Close()
	}
	if t.h2Reader != nil {
		_ = t.h2Reader.Close()
	}
	if t.h3Reader != nil {
		_ = t.h3Reader.Close()
	}
	if t.h3ChunkReader != nil {
		_ = t.h3ChunkReader.Close()
	}
	if t.quicReader != nil {
		_ = t.quicReader.Close()
	}
	if t.dnsPayloadReader != nil {
		_ = t.dnsPayloadReader.Close()
	}

	t.probeGroupsMu.Lock()
	t.probesClosed = true
	closing := t.links
	t.links = nil
	t.probeGroups = map[probes.ProbeGroup][]link.Link{}
	for _, ls := range t.dnsPacketLinks {
		closing = append(closing, ls...)
	}
	t.dnsPacketLinks = nil
	for _, ls := range t.sockOpsLinks {
		closeLinks(ls)
	}
	t.sockOpsLinks = nil
	for _, ls := range t.http3Links {
		closing = append(closing, ls...)
	}
	t.http3Links = nil
	for _, set := range t.containerUprobes {
		closing = append(closing, set.allLinks()...)
	}
	t.containerUprobes = nil
	t.probeGroupsMu.Unlock()
	closeLinks(closing)
	t.stopOnCPUSampler()

	t.readerWG.Wait()

	if t.collection != nil {
		t.collection.Close()
	}

	if t.processNameCache != nil {
		t.processNameCache.Close()
	}

	if t.pathCache != nil {
		t.pathCache.Clear()
	}

	if t.resourceMgr != nil {
		t.resourceMgr.stopAll()
	}
}

func isLikelyTransientComm(name string) bool {
	if len(name) != 1 {
		return false
	}
	c := name[0]
	return c >= '0' && c <= '9'
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

	pidStr := fmt.Sprintf("%d", pid)

	if cmdline, err := procfs.ReadFile(pidStr + "/cmdline"); err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			name = parts[0]
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = name[idx+1:]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/stat"); err == nil {
			statStr := string(data)
			start := strings.Index(statStr, "(")
			end := strings.LastIndex(statStr, ")")
			if start >= 0 && end > start {
				name = statStr[start+1 : end]
			}
		}
	}

	if name == "" {
		if data, err := procfs.ReadFile(pidStr + "/comm"); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	sanitized := validation.SanitizeProcessName(name)
	t.processNameCache.Set(pid, sanitized)
	return sanitized
}

func (t *Tracer) pollBPFMapUtilization() {
	if t.collection == nil {
		return
	}
	tracked := []string{"stack_traces", "start_times", "socket_conns", "db_queries", "pool_states"}
	for _, name := range tracked {
		m, ok := t.collection.Maps[name]
		if !ok || m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil || info.MaxEntries == 0 {
			continue
		}
		count, ok := batchCountMapEntries(m)
		if !ok {
			count = 0
			var key, val []byte
			iter := m.Iterate()
			for iter.Next(&key, &val) {
				count++
			}
		}
		ratio := float64(count) / float64(info.MaxEntries)
		metricsexporter.RecordBPFMapUtilization(name, ratio)
	}
}

// batchCountMapEntries counts a map's live entries using BPF_MAP_LOOKUP_BATCH,
// turning the O(n) per-entry get_next_key syscalls of a full iteration into
// O(n/batch) syscalls.
func batchCountMapEntries(m *ebpf.Map) (uint32, bool) {
	ks, vs := int(m.KeySize()), int(m.ValueSize())
	if ks == 0 || vs == 0 {
		return 0, false
	}
	const batch = 256
	keys := make([]byte, batch*ks)
	vals := make([]byte, batch*vs)
	var cursor ebpf.MapBatchCursor
	var count uint32
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		count += safeconv.IntToUint32(n)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true
		}
		if err != nil {
			return 0, false
		}
		if n == 0 {
			return count, true
		}
	}
}

// ActiveProbeGroups returns the set of probe groups currently enabled.
func (t *Tracer) ActiveProbeGroups() []probes.ProbeGroup {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	result := make([]probes.ProbeGroup, 0, len(t.probeGroups))
	for g := range t.probeGroups {
		result = append(result, g)
	}
	return result
}

// SetEnabledCategories disables probe groups whose CRD-filter categories
// are absent from `categories`.
func (t *Tracer) SetEnabledCategories(categories []string) error {
	if categories == nil {
		return nil
	}
	wanted := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		wanted[c] = struct{}{}
	}

	for g := range groupCategoryNeeds {
		if probeGroupNeededBy(g, wanted) {
			continue
		}
		t.DisableProbeGroup(g)
		t.probeGroupsMu.Lock()
		if t.intentionallyDisabled == nil {
			t.intentionallyDisabled = map[probes.ProbeGroup]struct{}{}
		}
		t.intentionallyDisabled[g] = struct{}{}
		t.probeGroupsMu.Unlock()
	}

	for c := range wanted {
		needs := groupsNeededFor(c)
		for _, g := range needs {
			t.probeGroupsMu.Lock()
			_, disabled := t.intentionallyDisabled[g]
			t.probeGroupsMu.Unlock()
			if !disabled {
				continue
			}
			if err := t.EnableProbeGroup(g); err != nil {
				t.probeGroupsMu.Lock()
				if t.detachWarned == nil {
					t.detachWarned = map[probes.ProbeGroup]struct{}{}
				}
				_, warned := t.detachWarned[g]
				if !warned {
					t.detachWarned[g] = struct{}{}
				}
				t.probeGroupsMu.Unlock()
				if !warned {
					logger.Warn("SetEnabledCategories: category needs a detached probe group that could not be re-attached (events in this group are not captured until the agent restarts; common cause: tracefs/debugfs not mounted into the agent)",
						zap.String("category", c), zap.String("group", string(g)), zap.Error(err))
				}
			}
		}
	}
	return nil
}

// EnableProbeGroup re-attaches a probe group that was previously disabled
// by SetEnabledCategories.
func (t *Tracer) EnableProbeGroup(g probes.ProbeGroup) error {
	t.probeGroupsMu.Lock()
	if existing, ok := t.probeGroups[g]; ok && len(existing) > 0 {
		t.probeGroupsMu.Unlock()
		return nil
	}
	coll := t.collection
	t.probeGroupsMu.Unlock()

	if coll == nil {
		return fmt.Errorf("no eBPF collection available to re-attach group %q", g)
	}

	newLinks, err := probes.AttachProbeGroup(coll, g)
	if err != nil {
		return err
	}
	newLinks = append(newLinks, t.attachGroupUprobes(g)...)

	t.probeGroupsMu.Lock()
	if t.probesClosed {
		t.probeGroupsMu.Unlock()
		closeLinks(newLinks)
		return nil
	}
	t.probeGroups[g] = append(t.probeGroups[g], newLinks...)
	t.links = append(t.links, newLinks...)
	delete(t.intentionallyDisabled, g)
	delete(t.detachWarned, g)
	t.probeGroupsMu.Unlock()

	containerLinks := t.reattachContainerGroupUprobes(g)

	logger.Info("Probe group re-attached",
		zap.String("group", string(g)),
		zap.Int("links", len(newLinks)),
		zap.Int("container_links", containerLinks))
	return nil
}

// probeGroupNeededBy reports whether a group should stay attached
// given the set of categories currently desired by some active CR.
// Option configures NewTracer.
type Option func(*tracerOptions)

type tracerOptions struct {
	initialCategories []string
	gateAtStartup     bool
}

// WithInitialCategories restricts which probe groups stay attached once the
// mandatory attach has been verified.
func WithInitialCategories(categories []string) Option {
	return func(o *tracerOptions) {
		if categories == nil {
			categories = []string{}
		}
		o.initialCategories = categories
		o.gateAtStartup = true
	}
}

// gateInitialProbeGroups closes the links of every gateable group the
// initial category set does not want, and reports which groups it closed so
// the caller can seed intentionallyDisabled.
func gateInitialProbeGroups(
	probeGroups map[probes.ProbeGroup][]link.Link,
	categories []string,
) map[probes.ProbeGroup]struct{} {
	wanted := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		wanted[c] = struct{}{}
	}

	disabled := map[probes.ProbeGroup]struct{}{}
	for g := range groupCategoryNeeds {
		if probeGroupNeededBy(g, wanted) {
			continue
		}
		closeLinks(probeGroups[g])
		delete(probeGroups, g)
		disabled[g] = struct{}{}
	}

	if len(disabled) > 0 {
		names := make([]string, 0, len(disabled))
		for g := range disabled {
			names = append(names, string(g))
		}
		sort.Strings(names)
		logger.Info("Probe groups gated at startup",
			zap.Strings("disabled", names),
			zap.Strings("categories", categories))
	}
	return disabled
}

func probeGroupNeededBy(g probes.ProbeGroup, wanted map[string]struct{}) bool {
	needs, gated := groupCategoryNeeds[g]
	if !gated {
		return true // not gateable by category
	}
	for _, c := range needs {
		if _, ok := wanted[c]; ok {
			return true
		}
	}
	return false
}

// groupsNeededFor returns the probe groups required to surface a
// given CRD category.
func groupsNeededFor(category string) []probes.ProbeGroup {
	var out []probes.ProbeGroup
	for g, needs := range groupCategoryNeeds {
		for _, c := range needs {
			if c == category {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// groupCategoryNeeds maps each probe group to the CRD filter
// categories that require it.
var groupCategoryNeeds = map[probes.ProbeGroup][]string{
	probes.GroupNetwork:    {"net"},
	probes.GroupFileSystem: {"fs"},
	probes.GroupCPU:        {"cpu", "proc"},
	probes.GroupMemory:     {"proc"},
	probes.GroupFastCGI:    {"net"},
	probes.GroupTLS:        {"dns", "cpu", "net"},
	probes.GroupCrypto:     {"crypto"},
	probes.GroupUSDT:       {"usdt"},
}

// DisableProbeGroup closes all links associated with the given group,
// including the container-scoped uprobes attached for it.
func (t *Tracer) DisableProbeGroup(g probes.ProbeGroup) {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	ls := t.probeGroups[g]
	var containerLinks []link.Link
	for _, set := range t.containerUprobes {
		if cls := set.links[g]; len(cls) > 0 {
			containerLinks = append(containerLinks, cls...)
			delete(set.links, g)
		}
	}
	if len(ls) == 0 && len(containerLinks) == 0 {
		return
	}
	closed := make(map[link.Link]struct{}, len(ls))
	for _, l := range ls {
		_ = l.Close()
		closed[l] = struct{}{}
	}
	for _, l := range containerLinks {
		_ = l.Close()
	}
	kept := t.links[:0]
	for _, l := range t.links {
		if _, isClosed := closed[l]; !isClosed {
			kept = append(kept, l)
		}
	}
	t.links = kept
	delete(t.probeGroups, g)
	logger.Info("Probe group disabled",
		zap.String("group", string(g)),
		zap.Int("links", len(ls)),
		zap.Int("container_links", len(containerLinks)))
}

// serveManagementAPI starts a lightweight HTTP server for probe group management.
func (t *Tracer) serveManagementAPI(ctx context.Context, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		groups := t.ActiveProbeGroups()
		strs := make([]string, len(groups))
		for i, g := range groups {
			strs[i] = string(g)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active_groups": strs})
	})
	mux.HandleFunc("/probes/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/probes/"), "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		group := probes.ProbeGroup(parts[0])
		action := parts[1]
		switch action {
		case "disable":
			t.DisableProbeGroup(group)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	})

	if t.profilingCtrl != nil {
		mux.HandleFunc("/profile/start", t.profilingCtrl.HTTPStart)
		mux.HandleFunc("/profile/status", t.profilingCtrl.HTTPStatus)
		mux.HandleFunc("/profile/result", t.profilingCtrl.HTTPResult)
		logger.Info("Profiling management endpoints registered",
			zap.Int("port", port))
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	logger.Info("Management API listening", zap.Int("port", port))
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Warn("Management API server error", zap.Error(err))
	}
}

func WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

// SetKernelAggregationMode selects what the probes do with an observation:
// nothing, fold-and-ship, or fold-and-skip-the-ringbuf.
func (t *Tracer) SetKernelAggregationMode(mode kernelagg.Mode) error {
	if t == nil || t.collection == nil {
		return nil
	}
	m := t.collection.Maps[kernelagg.EnabledMapName]
	if m == nil {
		return nil
	}
	return kernelagg.SetMode(m, mode)
}

// DrainKernelMetrics reads and clears the aggregation map, returning the
// deltas accumulated since the previous drain.
func (t *Tracer) DrainKernelMetrics() ([]kernelagg.Row, error) {
	if t == nil || t.collection == nil {
		return nil, nil
	}
	m := t.collection.Maps[kernelagg.MapName]
	if m == nil {
		return nil, nil
	}
	return kernelagg.Drain(m)
}
