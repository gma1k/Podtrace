package probes

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/ldsoconf"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/procmaps"
)

// mandatoryProbes must all attach successfully; failure returns an actionable error.
var mandatoryProbes = map[string]string{
	"kprobe_tcp_connect":       "tcp_v4_connect",
	"kretprobe_tcp_connect":    "tcp_v4_connect",
	"kprobe_tcp_v6_connect":    "tcp_v6_connect",
	"kretprobe_tcp_v6_connect": "tcp_v6_connect",
	"kprobe_tcp_sendmsg":       "tcp_sendmsg",
	"kretprobe_tcp_sendmsg":    "tcp_sendmsg",
	"kprobe_tcp_recvmsg":       "tcp_recvmsg",
	"kretprobe_tcp_recvmsg":    "tcp_recvmsg",
}

// optionalProbes are attached when available; failure is logged but does not abort.
// Kernel symbol names can change across versions (e.g. do_futex renamed in 5.16+),
// so these degrade gracefully.
var optionalProbes = map[string]string{
	"kprobe_udp_sendmsg":       "udp_sendmsg",
	"kretprobe_udp_sendmsg":    "udp_sendmsg",
	"kprobe_udp_recvmsg":       "udp_recvmsg",
	"kretprobe_udp_recvmsg":    "udp_recvmsg",
	"kprobe_do_futex":          "do_futex",
	"kretprobe_do_futex":       "do_futex",
	"kprobe_do_sys_openat2":    "do_sys_openat2",
	"kretprobe_do_sys_openat2": "do_sys_openat2",
	"kprobe_vfs_unlink":        "vfs_unlink",
	"kprobe_close_fd":          "close_fd",
	"kretprobe_vfs_unlink":     "vfs_unlink",
	"kprobe_vfs_rename":        "vfs_rename",
	"kretprobe_vfs_rename":     "vfs_rename",
}

// kprobeSymbolAlternatives lists, for a program whose kernel function was
// replaced, the symbols to try before its table entry, newest first. close(2)
// calls file_close_fd() since Linux 6.7; close_fd() still exists there but no
// longer runs on an ordinary close.
var kprobeSymbolAlternatives = map[string][]string{
	"kprobe_close_fd": {"file_close_fd"},
}

var kprobeAttach = func(symbol string, prog *ebpf.Program, ret bool) (link.Link, error) {
	if ret {
		return link.Kretprobe(symbol, prog, nil)
	}
	return link.Kprobe(symbol, prog, nil)
}

func attachKprobe(progName, symbol string, prog *ebpf.Program) (link.Link, error) {
	ret := strings.HasPrefix(progName, "kretprobe_")
	for _, alt := range kprobeSymbolAlternatives[progName] {
		if l, err := kprobeAttach(alt, prog, ret); err == nil {
			return l, nil
		}
	}
	return kprobeAttach(symbol, prog, ret)
}

// AttachProbes attaches every probe whose program is present in the
// collection and returns a flat slice of the resulting links.
func AttachProbes(coll *ebpf.Collection) ([]link.Link, error) {
	groups, err := AttachProbesByGroup(coll)
	if err != nil {
		return nil, err
	}
	return flattenGroupedLinks(groups), nil
}

// flattenGroupedLinks concatenates a group→links map into a single
// slice.
func flattenGroupedLinks(groups map[ProbeGroup][]link.Link) []link.Link {
	var out []link.Link
	for _, g := range allProbeGroups() {
		out = append(out, groups[g]...)
	}
	return out
}

// allProbeGroups returns the canonical ordering of probe groups. New
// groups added to groups.go must be added here too.
func allProbeGroups() []ProbeGroup {
	return []ProbeGroup{
		GroupNetwork, GroupFileSystem, GroupDatabase, GroupTLS,
		GroupMemory, GroupCPU, GroupPool, GroupCache,
		GroupMessaging, GroupFastCGI, GroupCrypto,
	}
}

// AttachProbesByGroup performs the same attach work as AttachProbes but
// returns the resulting links bucketed by the ProbeGroup each program
// belongs to.
func AttachProbesByGroup(coll *ebpf.Collection) (map[ProbeGroup][]link.Link, error) {
	groups := map[ProbeGroup][]link.Link{}
	appendLink := func(progName string, l link.Link) {
		g := GroupForProbe(progName)
		groups[g] = append(groups[g], l)
	}
	closeAll := func() {
		for _, ls := range groups {
			for _, l := range ls {
				_ = l.Close()
			}
		}
	}

	// --- Mandatory kprobes: all must attach or we return an error. ---
	for progName, symbol := range mandatoryProbes {
		prog := coll.Programs[progName]
		if prog == nil {
			logger.Debug("Mandatory probe program not found in collection, skipping",
				zap.String("prog", progName))
			continue
		}

		l, err := attachProbe(coll, progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, true, err)
			closeAll()
			return nil, fmt.Errorf(
				"%w\n\n"+
					"Hint: mandatory kprobe %q could not attach to kernel symbol %q.\n"+
					"  • Verify symbol exists: grep -w %q /proc/kallsyms\n"+
					"  • Check for BPF denials: dmesg | grep -i bpf\n"+
					"  • Kernel 5.8+ required (current: %s)\n"+
					"  • On GKE Autopilot / AWS Fargate kprobes are not allowed; use a standard node pool.\n"+
					"  • On OpenShift ensure the pod SCC allows CAP_BPF and CAP_SYS_ADMIN",
				NewProbeAttachError(progName, err), progName, symbol, symbol, kernelVersionString())
		}
		appendLink(progName, l)
		logger.Debug("Mandatory probe attached", zap.String("prog", progName), zap.String("symbol", symbol))
	}

	var skippedOptional []string

	// --- Optional kprobes: log failures but continue. ---
	for progName, symbol := range optionalProbes {
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}

		l, err := attachProbe(coll, progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, false, err)
			skippedOptional = append(skippedOptional, fmt.Sprintf("%s->%s", progName, symbol))
			logger.Debug("Optional probe unavailable (skipping)",
				zap.String("prog", progName), zap.String("symbol", symbol), zap.Error(err))
			continue
		}
		appendLink(progName, l)
		logger.Debug("Optional probe attached", zap.String("prog", progName), zap.String("symbol", symbol))
	}

	fsLinks, fsSkipped, fe := attachFSProbes(coll)
	if fe != nil {
		closeAll()
		reportAttachFailure(fe.probe.kprobe, fe.probe.symbol, true, fe.err)
		return nil, fmt.Errorf("%w\n\n"+
			"Hint: the filesystem probe on %q attached neither as fentry/fexit nor as a kprobe.\n"+
			"  • Verify the symbol exists: grep -w %q /proc/kallsyms\n"+
			"  • Check for BPF denials: dmesg | grep -i bpf",
			NewProbeAttachError(fe.probe.kprobe, fe), fe.probe.symbol, fe.probe.symbol)
	}
	if len(fsLinks) > 0 {
		groups[GroupFileSystem] = append(groups[GroupFileSystem], fsLinks...)
	}
	for _, sym := range fsSkipped {
		skippedOptional = append(skippedOptional, "filesystem->"+sym)
	}

	if len(skippedOptional) > 0 {
		logger.Info("Some optional probes unavailable (non-critical features degraded)",
			zap.Strings("skipped", skippedOptional))
	}

	for _, tp := range tracepointProbes {
		if l, ok := attachTracepointSpec(coll, tp); ok {
			appendLink(tp.prog, l)
		}
	}

	return groups, nil
}

// tracepointSpec describes a tracepoint-backed BPF program and how to
// attach it.
type tracepointSpec struct {
	prog     string
	category string
	event    string
	failMsg  string
	// raw attaches the program as a raw tracepoint, which is handed the
	// tracepoint's arguments rather than its record, whose layout changes
	// between kernels.
	raw bool
}

// tracepointProbes is the single source of truth for every tracepoint
// program, shared by AttachProbesByGroup (startup) and AttachProbeGroup
// (hot re-attach) so the two paths can never drift.
var tracepointProbes = []tracepointSpec{
	{"tracepoint_sched_switch", "sched", "sched_switch", "CPU/scheduling tracking unavailable", false},
	{"tracepoint_inet_sock_set_state", "sock", "inet_sock_set_state", "TCP state-change tracking unavailable", false},
	{"tracepoint_tcp_retransmit_skb", "tcp", "tcp_retransmit_skb", "TCP retransmission tracking unavailable", false},
	{"tracepoint_net_dev_xmit", "net", "net_dev_xmit", "Network device error tracking unavailable", false},
	{"tracepoint_page_fault_user", "exceptions", "page_fault_user", "Page fault tracking unavailable", false},
	{"tracepoint_oom_mark_victim", "oom", "mark_victim", "OOM kill tracking unavailable", false},
	{"raw_tracepoint_sched_process_fork", "sched", "sched_process_fork", "Process fork tracking unavailable", true},
	{"tracepoint_sched_process_exec", "sched", "sched_process_exec", "Process exec tracking unavailable", false},
	{"tracepoint_sys_enter_bind", "syscalls", "sys_enter_bind", "AF_ALG crypto-socket detection unavailable", false},
	{"tracepoint_sys_exit_fsync", "syscalls", "sys_exit_fsync", "fsync tracking unavailable", false},
	{"tracepoint_sys_enter_fsync", "syscalls", "sys_enter_fsync", "fsync tracking unavailable", false},
	{"tracepoint_sys_exit_fdatasync", "syscalls", "sys_exit_fdatasync", "fdatasync tracking unavailable", false},
	{"tracepoint_sys_enter_fdatasync", "syscalls", "sys_enter_fdatasync", "fdatasync tracking unavailable", false},
}

// attachTracepointSpec attaches one tracepoint, returning (link, true) on
// success or (nil, false) if the program is absent or the attach fails
// (logged, non-fatal — tracepoints are best-effort).
func attachTracepointSpec(coll *ebpf.Collection, tp tracepointSpec) (link.Link, bool) {
	prog := coll.Programs[tp.prog]
	if prog == nil {
		return nil, false
	}
	var l link.Link
	var err error
	if tp.raw {
		l, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.event, Program: prog})
	} else {
		l, err = link.Tracepoint(tp.category, tp.event, prog, nil)
	}
	if err != nil {
		sym := tp.category + ":" + tp.event
		reportAttachFailure(tp.prog, sym, false, err)
		if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
			if tp.failMsg != "" {
				logger.Info(tp.failMsg, zap.Error(err))
			} else {
				logger.Debug("tracepoint unavailable", zap.String("tracepoint", sym), zap.Error(err))
			}
		}
		return nil, false
	}
	return l, true
}

// AttachProbeGroup attaches only the kprobes/tracepoints belonging to a
// single ProbeGroup. It is used for hot re-attach: SetEnabledCategories
// calls it when a CR newly needs a category whose group was previously
// detached.
func AttachProbeGroup(coll *ebpf.Collection, target ProbeGroup) ([]link.Link, error) {
	var links []link.Link
	rollback := func() {
		for _, l := range links {
			_ = l.Close()
		}
	}

	for progName, symbol := range mandatoryProbes {
		if GroupForProbe(progName) != target {
			continue
		}
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		l, err := attachProbe(coll, progName, symbol, prog)
		if err != nil {
			reportAttachFailure(progName, symbol, true, err)
			rollback()
			return nil, fmt.Errorf("re-attach mandatory probe %q (%s): %w", progName, symbol, NewProbeAttachError(progName, err))
		}
		links = append(links, l)
	}

	for progName, symbol := range optionalProbes {
		if GroupForProbe(progName) != target {
			continue
		}
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		l, err := attachProbe(coll, progName, symbol, prog)
		if err != nil {
			logger.Debug("optional probe unavailable on re-attach",
				zap.String("prog", progName), zap.String("symbol", symbol), zap.Error(err))
			continue
		}
		links = append(links, l)
	}

	if target == GroupFileSystem {
		fsLinks, _, fe := attachFSProbes(coll)
		if fe != nil {
			rollback()
			return nil, fmt.Errorf("re-attach filesystem probes: %w", fe)
		}
		links = append(links, fsLinks...)
	}

	for _, tp := range tracepointProbes {
		if GroupForProbe(tp.prog) != target {
			continue
		}
		if l, ok := attachTracepointSpec(coll, tp); ok {
			links = append(links, l)
		}
	}

	return links, nil
}

func AttachDNSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachDNSProbesWithPID(coll, containerID, 0, nil)
}

// packetDNSCaptureEnabled reports whether the libc-independent, packet-based
// DNS capture path is active.
func packetDNSCaptureEnabled() bool {
	return config.DNSPacketCaptureEnabled()
}

// AttachDNSPacketProbes attaches the cgroup_skb DNS program to each target pod
// cgroup, capturing DNS by parsing packets rather than via libc uprobes.
func AttachDNSPacketProbes(coll *ebpf.Collection, cgroupPaths []string) []link.Link {
	if !packetDNSCaptureEnabled() {
		logger.Debug("Packet-based DNS capture disabled via PODTRACE_DNS_PACKET_CAPTURE=false")
		return nil
	}
	egress := coll.Programs["dns_egress"]
	ingress := coll.Programs["dns_ingress"]
	if egress == nil && ingress == nil {
		return nil
	}
	attach := []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
		name string
	}{
		{egress, ebpf.AttachCGroupInetEgress, "egress"},
		{ingress, ebpf.AttachCGroupInetIngress, "ingress"},
	}

	var links []link.Link
	seen := make(map[string]struct{}, len(cgroupPaths))
	for _, path := range cgroupPaths {
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		for _, a := range attach {
			if a.prog == nil {
				continue
			}
			l, err := link.AttachCgroup(link.CgroupOptions{
				Path:    path,
				Attach:  a.typ,
				Program: a.prog,
			})
			if err != nil {
				logger.Info("Packet-based DNS capture unavailable for cgroup; falling back to libc uprobe only",
					zap.String("cgroup", path), zap.String("direction", a.name), zap.Error(err))
				continue
			}
			links = append(links, l)
		}
	}
	if len(links) == 0 {
		logger.Info("Packet-based DNS capture attached to no cgroups",
			zap.Int("cgroup_paths_given", len(cgroupPaths)))
	}
	return links
}

// AttachHTTP3Probes attaches the cgroup_skb HTTP/3 (QUIC) detector to each
// target pod cgroup, emitting one HTTP/3 connection event per (cgroup, peer,
// port).
func AttachHTTP3Probes(coll *ebpf.Collection, cgroupPaths []string) []link.Link {
	egress := coll.Programs["http3_egress"]
	ingress := coll.Programs["http3_ingress"]
	if egress == nil && ingress == nil {
		return nil
	}
	attach := []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
		name string
	}{
		{egress, ebpf.AttachCGroupInetEgress, "egress"},
		{ingress, ebpf.AttachCGroupInetIngress, "ingress"},
	}

	var links []link.Link
	seen := make(map[string]struct{}, len(cgroupPaths))
	for _, path := range cgroupPaths {
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		for _, a := range attach {
			if a.prog == nil {
				continue
			}
			l, err := link.AttachCgroup(link.CgroupOptions{
				Path:    path,
				Attach:  a.typ,
				Program: a.prog,
			})
			if err != nil {
				logger.Info("HTTP/3 detection unavailable for cgroup",
					zap.String("cgroup", path), zap.String("direction", a.name), zap.Error(err))
				continue
			}
			links = append(links, l)
		}
	}
	return links
}

func AttachDNSProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link
	libcPath := FindLibcPathWithPID(containerID, pid)
	if libcPath != "" && !af.Claim("dns", libcPath) {
		return links
	}
	if libcPath != "" {
		uprobe, err := openExecutable(libcPath)
		if err == nil {
			defer func() { _ = uprobe.Close() }()
			for _, fn := range libcResolvers {
				links = append(links, attachLibcResolver(coll, uprobe, fn)...)
			}
		} else if packetDNSCaptureEnabled() {
			logger.Debug("libc uprobe DNS unavailable; DNS is captured via the packet-based path instead")
		} else {
			logger.Info("DNS tracking disabled: libc was located but could not be opened for uprobe attachment. DNS name resolution will not be traced; other tracing is unaffected.")
		}
	} else if packetDNSCaptureEnabled() {
		logger.Debug("libc uprobe DNS unavailable; DNS is captured via the packet-based path instead")
	} else {
		logger.Info("DNS tracking disabled: no libc found in the target container and packet-based DNS capture is disabled. DNS name resolution will not be traced; other tracing is unaffected.")
	}
	return links
}

// libcResolvers are the libc functions a lookup goes through. glibc's
// gethostbyname and gethostbyname2 run the same code as their _r forms, so
// probing the _r forms sees all four.
var libcResolvers = []string{"getaddrinfo", "gethostbyname_r", "gethostbyname2_r"}

// uprobeTarget is the binary a resolver's probes attach to.
type uprobeTarget interface {
	Uprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error)
	Uretprobe(symbol string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error)
}

// attachLibcResolver attaches one resolver's return probe and then its entry
// probe, so no entry is recorded with nothing to consume it.
func attachLibcResolver(coll *ebpf.Collection, exe uprobeTarget, fn string) []link.Link {
	ret, entry := coll.Programs["uretprobe_"+fn], coll.Programs["uprobe_"+fn]
	if ret == nil || entry == nil {
		return nil
	}
	retLink, err := exe.Uretprobe(fn, ret, nil)
	if err != nil {
		logger.Info("DNS tracking (uretprobe) unavailable", zap.String("function", fn), zap.Error(err))
		return nil
	}
	entryLink, err := exe.Uprobe(fn, entry, nil)
	if err != nil {
		_ = retLink.Close()
		logger.Info("DNS tracking (uprobe) unavailable", zap.String("function", fn), zap.Error(err))
		return nil
	}
	return []link.Link{retLink, entryLink}
}

func AttachSyncProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachSyncProbesWithPID(coll, containerID, 0, nil)
}

func AttachSyncProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link
	libcPath := FindLibcPathWithPID(containerID, pid)
	if libcPath == "" || !af.Claim("sync", libcPath) {
		return links
	}
	uprobe, err := openExecutable(libcPath)
	if err != nil {
		logger.Info("Lock tracking unavailable", zap.Error(err))
		return links
	}
	defer func() { _ = uprobe.Close() }()
	if prog := coll.Programs["uprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	if prog := coll.Programs["uretprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uretprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	return links
}

func AttachDBProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachDBProbesWithPID(coll, containerID, 0, nil)
}

func AttachDBProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link

	libpqPaths := findDBLibsWithPID(containerID, pid, []string{"libpq.so.5", "libpq.so"})
	for _, path := range libpqPaths {
		if !hostfs.IsRegularFile(path) {
			continue
		}
		if !af.Claim("db", path) {
			continue
		}
		exe, err := openExecutable(path)
		if err != nil {
			continue
		}
		defer func() { _ = exe.Close() }()
		if prog := coll.Programs["uprobe_PQexec"]; prog != nil {
			l, err := exe.Uprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_PQexec"]; prog != nil {
			l, err := exe.Uretprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	mysqlPaths := findDBLibsWithPID(containerID, pid, []string{"libmysqlclient.so.21", "libmysqlclient.so"})
	for _, path := range mysqlPaths {
		if !hostfs.IsRegularFile(path) {
			continue
		}
		if !af.Claim("db", path) {
			continue
		}
		exe, err := openExecutable(path)
		if err != nil {
			continue
		}
		defer func() { _ = exe.Close() }()
		if prog := coll.Programs["uprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uretprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	return links
}

type dbProbeConfig struct {
	name           string
	libPatterns    []string
	acquireSymbols []string
	releaseSymbol  string
	exhaustSymbol  string
	acquireProg    string
	releaseProg    string
	exhaustProg    string
	exhaustRetProg string
}

// databaseProbeConfigs is the connection-lifecycle probe configuration, one
// entry per client library.
func databaseProbeConfigs() []dbProbeConfig {
	return []dbProbeConfig{
		{
			name:           "sqlite",
			libPatterns:    []string{"libsqlite3.so.0", "libsqlite3.so", "sqlite3.so"},
			acquireSymbols: []string{"sqlite3_prepare_v2", "sqlite3_prepare", "sqlite3_prepare16", "sqlite3_prepare16_v2"},
			releaseSymbol:  "sqlite3_finalize",
			exhaustSymbol:  "sqlite3_step",
			acquireProg:    "uprobe_sqlite3_prepare_v2",
			releaseProg:    "uretprobe_sqlite3_finalize",
			exhaustProg:    "uprobe_sqlite3_step",
			exhaustRetProg: "uretprobe_sqlite3_step",
		},
		{
			name:        "postgresql",
			libPatterns: []string{"libpq.so.5", "libpq.so"},
			// The public connection entry points. PQconnectStart alone was
			// wrong: it is the low-level asynchronous API, and synchronous
			// clients, which is nearly all of them, psql and pgbench
			// included, reach libpq through PQconnectdb or
			// PQconnectdbParams instead and never call it.
			acquireSymbols: []string{"PQconnectdb", "PQconnectdbParams", "PQconnectStart"},
			releaseSymbol:  "PQfinish",
			exhaustSymbol:  "PQexec",
			acquireProg:    "uprobe_PQconnectStart",
			releaseProg:    "uretprobe_PQfinish",
			exhaustProg:    "uprobe_PQexec_pool",
			exhaustRetProg: "",
		},
		{
			name:           "mysql",
			libPatterns:    []string{"libmysqlclient.so.21", "libmysqlclient.so"},
			acquireSymbols: []string{"mysql_real_connect"},
			releaseSymbol:  "mysql_close",
			exhaustSymbol:  "mysql_real_query",
			acquireProg:    "uprobe_mysql_real_connect",
			releaseProg:    "uretprobe_mysql_close",
			exhaustProg:    "uprobe_mysql_real_query_pool",
			exhaustRetProg: "",
		},
	}
}

func AttachPoolProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachPoolProbesWithPID(coll, containerID, 0, nil)
}

func AttachPoolProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	var links []link.Link

	var binaryPaths []string
	if pid == 0 && containerID != "" {
		pid = findContainerProcess(containerID)
	}
	if pid > 0 {
		logger.Debug("Found container process", zap.Uint32("pid", pid), zap.String("containerID", containerID))

		binaryPath := findGoBinaryViaProcessMaps(pid)
		if binaryPath == "" {
			binaryPath = findGoBinaryInProcess(pid)
		}
		if binaryPath == "" {
			binaryPath = findGoBinaryInContainer(containerID, pid)
		}

		if binaryPath != "" {
			binaryPaths = append(binaryPaths, binaryPath)
			logger.Debug("Found Go binary for pool monitoring", zap.String("path", binaryPath), zap.Uint32("pid", pid))
			links = append(links, attachGoAcquireProbes(coll, binaryPath, pid)...)
		} else {
			logger.Debug("Go binary not found for process", zap.Uint32("pid", pid))
		}
	} else {
		logger.Debug("Container process not found", zap.String("containerID", containerID))
	}

	dbConfigs := databaseProbeConfigs()

	for _, dbConfig := range dbConfigs {
		var dbPaths []string
		dbPaths = append(dbPaths, binaryPaths...)
		libPaths := findDBLibsWithPID(containerID, pid, dbConfig.libPatterns)
		dbPaths = append(dbPaths, libPaths...)

		if len(dbPaths) == 0 {
			logger.Debug("No libraries found for database", zap.String("database", dbConfig.name), zap.String("containerID", containerID))
			continue
		}

		for _, path := range dbPaths {
			logger.Debug("Attaching pool probes", zap.String("database", dbConfig.name), zap.String("path", path))
			if !hostfs.IsRegularFile(path) {
				continue
			}
			if !af.Claim("pool/"+dbConfig.name, path) {
				continue
			}
			exe, err := openExecutable(path)
			if err != nil {
				logger.Debug("Failed to open executable for pool probes", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
				continue
			}
			defer func() { _ = exe.Close() }()

			// Every acquire symbol is attached, not just the first that
			// resolves. These are sibling *public* entry points, not a
			// fallback chain: libpq exports PQconnectdb, PQconnectdbParams
			// and PQconnectStart, and a client calls exactly one of them per
			// connection. Stopping at the first meant attaching to whichever
			// symbol merely *existed* in the library — PQconnectdb always
			// does — while the client actually called a different one, so
			// the probe never fired. Verified on kind: pgbench imports
			// PQconnectdbParams and produced zero events while a probe sat
			// on PQconnectStart.
			//
			// This does not double count, because these entry points do not
			// call one another; they share a lower-level internal
			// (PQconnectStartParams) which is deliberately NOT hooked.
			acquireAttached := 0
			for _, symbol := range dbConfig.acquireSymbols {
				prog := coll.Programs[dbConfig.acquireProg]
				if prog == nil {
					break
				}
				l, err := exe.Uprobe(symbol, prog, nil)
				if err != nil {
					continue
				}
				links = append(links, l)
				acquireAttached++
				logger.Debug("Attached pool acquire probe", zap.String("database", dbConfig.name), zap.String("symbol", symbol), zap.String("path", path))
			}
			if acquireAttached == 0 {
				logger.Debug("No pool acquire probe attached; release and exhaustion events are suppressed because they key off acquire state",
					zap.String("database", dbConfig.name), zap.String("path", path),
					zap.Strings("symbols", dbConfig.acquireSymbols))
			}

			if dbConfig.releaseProg != "" && dbConfig.releaseSymbol != "" {
				if prog := coll.Programs[dbConfig.releaseProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.releaseSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool release probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.releaseSymbol)) {
						logger.Debug("Pool release probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustProg]; prog != nil {
					l, err := exe.Uprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool exhaustion probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustRetProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustRetProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion retprobe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}
		}
	}

	if len(links) > 0 {
		logger.Debug("Pool monitoring probes attached", zap.Int("total_links", len(links)), zap.String("containerID", containerID))
	} else {
		logger.Debug("No pool monitoring probes attached", zap.String("containerID", containerID))
	}

	return links
}

// hostWideLibrarySearch reports whether the agent may look for probe targets
// outside the traced workload, in its own mount namespace, via ldconfig, or in
// the node's root filesystem through /proc/1/root.
func hostWideLibrarySearch(containerID string, pid uint32) bool {
	return containerID == "" && pid == 0
}

func FindLibcPath(containerID string) string {
	return FindLibcPathWithPID(containerID, 0)
}

func findLibcHostWide() string {
	if path := findLibcViaLdconfig(); path != "" {
		return path
	}

	if path := findLibcViaLdSoConf(); path != "" {
		return path
	}

	return findLibcViaCommonPaths()
}

func FindLibcPathWithPID(containerID string, pid uint32) string {
	if pid > 0 {
		if path := findLibcViaProcessMaps(pid); path != "" {
			return path
		}
		if path := findLibcInProcess(pid); path != "" {
			return path
		}
	}
	if containerID != "" {
		lookup := findLibcInContainer
		if pid > 0 {
			lookup = findLibcInContainerRootfs
		}
		if path := lookup(containerID); path != "" {
			return path
		}
	}
	if !hostWideLibrarySearch(containerID, pid) {
		logger.Debug("No libc inside the trace target; not falling back to node-wide libc",
			zap.String("container_id", containerID), zap.Uint32("pid", pid))
		return ""
	}
	return findLibcHostWide()
}

func findLibcViaLdconfig() string {
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libc.so.6") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "=>" && i+1 < len(parts) {
					path := strings.TrimSpace(parts[i+1])
					if hostfs.IsRegularFile(path) {
						return path
					}
				}
			}
		}
	}
	return ""
}

func getMuslLibcNames() []string {
	names := []string{"libc.so.6"}
	arch := runtime.GOARCH

	muslArchMap := map[string]string{
		"amd64":   "x86_64",
		"arm64":   "aarch64",
		"riscv64": "riscv64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}

	if muslArch, ok := muslArchMap[arch]; ok {
		names = append(names, fmt.Sprintf("libc.musl-%s.so.1", muslArch))
	}

	return names
}

func findLibcViaLdSoConf() string {
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	libcNames := getMuslLibcNames()
	for _, searchPath := range searchPaths {
		for _, libcName := range libcNames {
			path := filepath.Join(searchPath, libcName)
			if hostfs.IsRegularFile(path) {
				return path
			}
		}
	}
	return ""
}

// libcMapsPatterns are the pathname substrings that mark a libc mapping.
var libcMapsPatterns = []string{"libc.so", "libc.musl"}

func findLibcViaProcessMaps(pid uint32) string {
	for _, path := range mappedFilesMatching(pid, libcMapsPatterns) {
		return path
	}
	return ""
}

func findLibcInProcess(pid uint32) string {
	return findLibcInRoot(procRoot(pid))
}

// findLibcInRoot returns the first libc at a well-known path inside a
// container rootfs.
func findLibcInRoot(root string) string {
	for _, basePath := range getArchitecturePaths() {
		if path := fileWithinRoot(root, basePath); path != "" {
			return path
		}
	}
	return ""
}

// fileInProcMapFiles resolves a memory-mapped file through
// /proc/<pid>/map_files/<start>-<end> using the address range from a
// /proc/<pid>/maps line.
func fileInProcMapFiles(pid uint32, addrRange string) string {
	if addrRange == "" || !strings.Contains(addrRange, "-") {
		return ""
	}
	p := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "map_files", addrRange)
	if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
		return p
	}
	return ""
}

// FindContainerProcess resolves a container's main process id by scanning
// /proc for a task whose cgroup names the container.
func FindContainerProcess(containerID string) uint32 {
	return findContainerProcess(containerID)
}

func findContainerProcess(containerID string) uint32 {
	entries, err := os.ReadDir(config.ProcBasePath)
	if err != nil {
		logger.Debug("Container process scan: cannot read proc base",
			zap.String("proc_base", config.ProcBasePath), zap.Error(err))
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		if data, err := procfs.ReadFile(pidStr + "/cgroup"); err == nil {
			if strings.Contains(string(data), containerID) {
				var pid uint32
				if _, err := fmt.Sscanf(pidStr, "%d", &pid); err == nil {
					return pid
				}
			}
		}
	}
	logger.Debug("Container process scan found no process; library uprobes for this container are silently skipped",
		zap.String("container_id", containerID))
	return 0
}

func findGoBinaryInProcess(pid uint32) string {
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		logger.Debug("Failed to read exe symlink", zap.Uint32("pid", pid), zap.String("path", exePath), zap.Error(err))
		return ""
	}

	if !filepath.IsAbs(target) {
		cwdPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "cwd")
		cwd, err := os.Readlink(cwdPath)
		if err != nil {
			logger.Debug("Failed to read cwd symlink", zap.Uint32("pid", pid), zap.Error(err))
			cwd = "/"
		}
		target = filepath.Join(cwd, target)
	}

	if hostPath := fileInProcRoot(pid, target); hostPath != "" {
		logger.Debug("Found binary via container root", zap.Uint32("pid", pid), zap.String("container_path", target), zap.String("host_path", hostPath))
		return hostPath
	}

	logger.Debug("Binary not found under the target's own rootfs", zap.Uint32("pid", pid), zap.String("target", target))
	return ""
}

func findGoBinaryViaProcessMaps(pid uint32) string {
	started, timed := processStartTimeOf(pid)
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		logger.Debug("Failed to read process maps", zap.Uint32("pid", pid), zap.Error(err))
		return ""
	}

	for _, e := range procmaps.Parse(data) {
		if !e.Named() || !e.Executable() {
			continue
		}
		if strings.Contains(e.Path, ".so") || strings.Contains(e.Path, "vdso") || strings.Contains(e.Path, "vsyscall") {
			continue
		}
		if resolved := resolveMappedFile(pid, e); resolved != "" {
			if timed && !sameProcess(pid, started) {
				return ""
			}
			logger.Debug("Found binary via process maps", zap.Uint32("pid", pid), zap.String("container_path", e.Path), zap.String("host_path", resolved))
			return resolved
		}
	}
	return ""
}

func findGoBinaryInContainer(containerID string, pid uint32) string {
	procRootPath := procRoot(pid)

	if cmdlineData, err := procfs.ReadFile(fmt.Sprintf("%d/cmdline", pid)); err == nil {
		cmdline := string(cmdlineData)
		if len(cmdline) > 0 {
			parts := strings.Split(cmdline, "\x00")
			if len(parts) > 0 && parts[0] != "" {
				binaryPath := parts[0]
				if filepath.IsAbs(binaryPath) {
					if hostPath := fileWithinRoot(procRootPath, binaryPath); hostPath != "" {
						logger.Debug("Found binary via cmdline", zap.Uint32("pid", pid), zap.String("cmdline_path", binaryPath), zap.String("host_path", hostPath))
						return hostPath
					}
				}
			}
		}
	}

	if commData, err := procfs.ReadFile(fmt.Sprintf("%d/comm", pid)); err == nil {
		commName := strings.TrimSpace(string(commData))
		if commName != "" {
			commonPaths := []string{
				filepath.Join("/app", commName),
				filepath.Join("/app", commName+".app"),
				filepath.Join("/usr/local/bin", commName),
				filepath.Join("/bin", commName),
				filepath.Join("/app", "main"),
				filepath.Join("/app", "app"),
			}
			for _, relPath := range commonPaths {
				if hostPath := fileWithinRoot(procRootPath, relPath); hostPath != "" {
					logger.Debug("Found binary via comm name", zap.Uint32("pid", pid), zap.String("comm", commName), zap.String("path", hostPath))
					return hostPath
				}
			}
		}
	}

	commonPaths := config.GetCommonBinarySearchPaths()

	for _, relPath := range commonPaths {
		if hostPath := fileWithinRoot(procRootPath, relPath); hostPath != "" {
			logger.Debug("Found binary via container root common paths", zap.Uint32("pid", pid), zap.String("path", hostPath))
			return hostPath
		}
	}

	rootfsPaths := []string{}
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	commonPathsForRootfs := config.GetCommonBinarySearchPaths()
	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			for _, relPath := range commonPathsForRootfs {
				if path := fileWithinRoot(rootfs, relPath); path != "" {
					logger.Debug("Found binary via container rootfs", zap.String("rootfs", rootfs), zap.String("path", path))
					return path
				}
			}
		}
	}

	return ""
}

func findLibcInContainer(containerID string) string {
	if containerID == "" {
		return ""
	}
	if pid := findContainerProcess(containerID); pid > 0 {
		if path := findLibcViaProcessMaps(pid); path != "" {
			return path
		}
		if path := findLibcInProcess(pid); path != "" {
			return path
		}
	}
	return findLibcInContainerRootfs(containerID)
}

// findLibcInContainerRootfs looks for libc in the container's rootfs as the
// runtime lays it out on the host, without a process to resolve through.
func findLibcInContainerRootfs(containerID string) string {
	for _, rootfs := range containerRootfsPaths(containerID) {
		if path := findLibcInRoot(rootfs); path != "" {
			return path
		}
	}
	return ""
}

// containerRootfsPaths lists the host directories that may hold
// containerID's rootfs under Docker or containerd.
func containerRootfsPaths(containerID string) []string {
	var rootfsPaths []string
	if dockerRootfs, err := config.GetDockerContainerRootfs(containerID); err == nil {
		rootfsPaths = append(rootfsPaths, dockerRootfs)
	}
	for _, pattern := range []string{config.GetContainerdOverlayPattern(), config.GetContainerdNativePattern()} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}
	var present []string
	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			present = append(present, rootfs)
		}
	}
	return present
}

func getArchitecturePaths() []string {
	arch := runtime.GOARCH
	paths := []string{}

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			paths = append(paths,
				fmt.Sprintf("lib/%s/libc.so.6", suffix),
				fmt.Sprintf("usr/lib/%s/libc.so.6", suffix),
			)
		}
	}

	paths = append(paths,
		"lib64/libc.so.6",
		"lib/libc.so.6",
		"usr/lib64/libc.so.6",
		"usr/lib/libc.so.6",
	)

	return paths
}

func findLibcViaCommonPaths() string {
	paths := getArchitecturePaths()
	for _, relPath := range paths {
		path := filepath.Join("/", relPath)
		if hostfs.IsRegularFile(path) {
			return path
		}
	}
	return ""
}

func findDBLibsViaLdconfig(libNames []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if hostfs.IsRegularFile(path) {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsViaLdSoConf(libNames []string) []string {
	var paths []string
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	for _, searchPath := range searchPaths {
		for _, libName := range libNames {
			path := filepath.Join(searchPath, libName)
			if hostfs.IsRegularFile(path) {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func getArchitectureDBPaths(libNames []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			for _, libName := range libNames {
				paths = append(paths,
					fmt.Sprintf("/usr/lib/%s/%s", suffix, libName),
					fmt.Sprintf("/lib/%s/%s", suffix, libName),
				)
			}
		}
	}

	for _, libName := range libNames {
		paths = append(paths,
			fmt.Sprintf("/usr/lib64/%s", libName),
			fmt.Sprintf("/usr/lib/%s", libName),
			fmt.Sprintf("/lib64/%s", libName),
			fmt.Sprintf("/lib/%s", libName),
		)
	}

	return paths
}

func findDBLibsViaProcessMaps(pid uint32, libNames []string) []string {
	return mappedFilesMatching(pid, libNames)
}

func findDBLibsInContainer(containerID string, libNames []string) []string {
	if containerID == "" {
		return nil
	}
	var paths []string
	if pid := findContainerProcess(containerID); pid > 0 {
		paths = append(paths, findDBLibsViaProcessMaps(pid, libNames)...)
		paths = append(paths, findDBLibsInRoot(procRoot(pid), libNames)...)
	}
	paths = append(paths, findDBLibsInContainerRootfs(containerID, libNames)...)

	// No fallback to config.GetDefaultProcRootPath() (/proc/1/root): the node's
	// own libraries are not the traced container's. See hostWideLibrarySearch.
	return paths
}

// findDBLibsInContainerRootfs looks for the client libraries in the
// container's rootfs as the runtime lays it out on the host.
func findDBLibsInContainerRootfs(containerID string, libNames []string) []string {
	var paths []string
	for _, rootfs := range containerRootfsPaths(containerID) {
		paths = append(paths, findDBLibsInRoot(rootfs, libNames)...)
	}
	return paths
}

// findDBLibsInRoot returns the client libraries present at the well-known
// library paths inside a container rootfs.
func findDBLibsInRoot(root string, libNames []string) []string {
	var paths []string
	for _, basePath := range getArchitectureDBPaths(libNames) {
		if path := fileWithinRoot(root, basePath); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func findDBLibsWithPID(containerID string, pid uint32, libNames []string) []string {
	if pid > 0 {
		var out []string
		seen := make(map[string]bool)
		found := append(findDBLibsViaProcessMaps(pid, libNames), findDBLibsInRoot(procRoot(pid), libNames)...)
		for _, p := range found {
			if !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
		}
		if len(out) > 0 {
			return out
		}
		if containerID != "" {
			return findDBLibsInContainerRootfs(containerID, libNames)
		}
	}

	if containerID != "" {
		if paths := findDBLibsInContainer(containerID, libNames); len(paths) > 0 {
			return paths
		}
	}
	if !hostWideLibrarySearch(containerID, pid) {
		logger.Debug("No database client library inside the trace target; not falling back to node-wide libraries",
			zap.String("container_id", containerID), zap.Uint32("pid", pid), zap.Strings("libs", libNames))
		return nil
	}
	return findDBLibs(containerID, libNames)
}

func findDBLibs(containerID string, libNames []string) []string {
	var paths []string
	seen := make(map[string]bool)

	if containerID != "" {
		containerPaths := findDBLibsInContainer(containerID, libNames)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findDBLibsViaLdconfig(libNames)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findDBLibsViaLdSoConf(libNames)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	commonPaths := getArchitectureDBPaths(libNames)
	for _, path := range commonPaths {
		if !seen[path] {
			if hostfs.IsRegularFile(path) {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

func FindLibcInContainer(containerID string) []string {
	paths := []string{}
	containerRoot, err := config.GetDockerContainerRootfs(containerID)
	if err != nil {
		return paths
	}
	if _, err := os.Stat(containerRoot); err == nil {
		libcPaths := getArchitecturePaths()
		for _, libcPath := range libcPaths {
			paths = append(paths, filepath.Join(containerRoot, libcPath))
		}
	}

	if hostWideLibrarySearch(containerID, 0) {
		procPaths := getArchitecturePaths()
		for _, basePath := range procPaths {
			paths = append(paths, filepath.Join(config.GetDefaultProcRootPath(), basePath))
		}
	}

	return paths
}

// findTLSLibsViaProcessMaps resolves the TLS libraries pid has mapped.
func findTLSLibsViaProcessMaps(pid uint32, libPatterns []string) []string {
	return mappedFilesMatching(pid, libPatterns)
}

func findTLSLibsInContainer(containerID string, libPatterns []string) []string {
	if containerID == "" {
		return nil
	}
	var paths []string
	if pid := findContainerProcess(containerID); pid > 0 {
		paths = append(paths, findTLSLibsViaProcessMaps(pid, libPatterns)...)
	}
	return append(paths, findTLSLibsInContainerRootfs(containerID, libPatterns)...)
}

// findTLSLibsInContainerRootfs scans the library directories of the
// container's rootfs as the runtime lays it out on the host.
func findTLSLibsInContainerRootfs(containerID string, libPatterns []string) []string {
	var paths []string
	for _, rootfs := range containerRootfsPaths(containerID) {
		paths = append(paths, scanLibDirsWithinRoot(rootfs, libPatterns)...)
	}
	return paths
}

func findTLSLibsInContainerWithPID(containerID string, pid uint32, libPatterns []string) []string {
	if pid > 0 {
		if foundPaths := findTLSLibsViaProcessMaps(pid, libPatterns); len(foundPaths) > 0 {
			return foundPaths
		}
		if foundPaths := findTLSLibsViaProcRootScan(pid, libPatterns); len(foundPaths) > 0 {
			return foundPaths
		}
		if containerID == "" {
			return nil
		}
		return findTLSLibsInContainerRootfs(containerID, libPatterns)
	}
	return findTLSLibsInContainer(containerID, libPatterns)
}

// findTLSLibsViaProcRootScan walks the container rootfs (via /proc/<pid>/root)
// looking for shared-library files whose name matches one of libPatterns,
// independent of whether the resolved process has them mapped.
func findTLSLibsViaProcRootScan(pid uint32, libPatterns []string) []string {
	paths := scanLibDirsWithinRoot(procRoot(pid), libPatterns)
	logger.Debug("TLS rootfs scan complete", zap.Uint32("pid", pid), zap.Int("found", len(paths)))
	return paths
}

// maxLibDirEntries bounds how many entries one library directory scan reads,
// so a rootfs shaped to be huge cannot stall the attach path.
const maxLibDirEntries = 4096

// scanLibDirsWithinRoot lists the shared libraries in a rootfs's standard
// library directories whose name matches one of libPatterns. Directories and
// files are both resolved inside root, so a symlinked directory cannot
// redirect the scan into the agent's own filesystem.
func scanLibDirsWithinRoot(root string, libPatterns []string) []string {
	dirs := append(config.GetDefaultLibSearchPaths(),
		"/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
		"/usr/lib/aarch64-linux-gnu", "/lib/aarch64-linux-gnu",
	)
	patternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		patternsLower[i] = strings.ToLower(p)
	}
	var paths []string
	seen := make(map[string]bool)
	for _, d := range dirs {
		resolvedDir, ok := resolveWithinRoot(root, d)
		if !ok {
			continue
		}
		dirPath := filepath.Join(root, resolvedDir)
		entries, err := readDirLimited(dirPath, maxLibDirEntries)
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Debug("TLS rootfs scan: readdir failed", zap.String("dir", dirPath), zap.Error(err))
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			nameLower := strings.ToLower(e.Name())
			if !strings.Contains(nameLower, ".so") || !containsAnyPattern(nameLower, patternsLower) {
				continue
			}
			full := fileWithinRoot(root, filepath.Join(resolvedDir, e.Name()))
			if full == "" || seen[full] {
				continue
			}
			seen[full] = true
			paths = append(paths, full)
		}
	}
	return paths
}

// readDirLimited reads at most limit entries of dir.
func readDirLimited(dir string, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(dir) // #nosec G304 -- dir is a rootfs library directory already resolved inside the target's root.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return entries, nil
}

func findTLSLibsViaLdconfig(libPatterns []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for _, pattern := range libPatternsLower {
			if strings.Contains(lineLower, pattern) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if hostfs.IsRegularFile(path) {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsViaLdSoConf(libPatterns []string) []string {
	var paths []string
	searchPaths := append(config.GetDefaultLibSearchPaths(), ldsoconf.SearchPaths()...)

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	for _, searchPath := range searchPaths {
		_ = hostfs.WalkRegular(searchPath, func(path string, info os.FileInfo) error {
			baseName := strings.ToLower(filepath.Base(path))
			for _, pattern := range libPatternsLower {
				if strings.Contains(baseName, pattern) {
					paths = append(paths, path)
					return nil
				}
			}
			return nil
		})
	}
	return paths
}

// tlsLibPatterns are the shared library basename substrings we scan for when
// attaching TLS uprobes.
var tlsLibPatterns = []string{"libssl", "libgnutls", "libnss", "libmbedtls", "libmbedx509", "ssl", "tcnative"}

func findTLSLibs(containerID string) []string {
	var paths []string
	seen := make(map[string]bool)

	libPatterns := tlsLibPatterns

	if containerID != "" {
		containerPaths := findTLSLibsInContainer(containerID, libPatterns)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findTLSLibsViaLdconfig(libPatterns)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findTLSLibsViaLdSoConf(libPatterns)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	archPaths := getArchitectureTLSPaths(libPatterns)
	for _, path := range archPaths {
		if !seen[path] {
			if hostfs.IsRegularFile(path) {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	commonLibPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
		"/usr/local/lib64",
		"/usr/local/lib",
	}

	for _, libPath := range commonLibPaths {
		if _, err := os.Stat(libPath); err != nil {
			continue
		}
		err := filepath.Walk(libPath, func(walkPath string, info os.FileInfo, err error) error {
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			baseName := strings.ToLower(filepath.Base(walkPath))
			for _, pattern := range libPatterns {
				if strings.Contains(baseName, strings.ToLower(pattern)) {
					if !seen[walkPath] {
						paths = append(paths, walkPath)
						seen[walkPath] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	return paths
}

// tlsExecutableForPID returns the target process's executable path
// (/proc/<pid>/exe) when it statically bundles an attachable OpenSSL.
func tlsExecutableForPID(pid uint32) string {
	if pid == 0 {
		return ""
	}
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	if executableExportsSSL(exePath) {
		return exePath
	}
	return ""
}

func findTLSLibsWithPID(containerID string, pid uint32) []string {
	var paths []string
	seen := make(map[string]bool)

	libPatterns := tlsLibPatterns

	if containerID != "" || pid > 0 {
		containerPaths := findTLSLibsInContainerWithPID(containerID, pid, libPatterns)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	if exe := tlsExecutableForPID(pid); exe != "" {
		if !seen[exe] {
			paths = append(paths, exe)
			seen[exe] = true
			logger.Debug("TLS probe: target executable bundles OpenSSL", zap.String("exe", exe))
		}
	}

	if !hostWideLibrarySearch(containerID, pid) {
		if len(paths) == 0 {
			logger.Debug("No TLS library inside the trace target; not falling back to node-wide libraries",
				zap.String("container_id", containerID), zap.Uint32("pid", pid))
		}
		return paths
	}

	ldconfigPaths := findTLSLibsViaLdconfig(libPatterns)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findTLSLibsViaLdSoConf(libPatterns)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	archPaths := getArchitectureTLSPaths(libPatterns)
	for _, path := range archPaths {
		if !seen[path] {
			if hostfs.IsRegularFile(path) {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

func getArchitectureTLSPaths(libPatterns []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
		"arm":     {"arm-linux-gnueabihf", "arm-linux-gnueabi"},
		"386":     {"i386-linux-gnu", "i686-linux-gnu"},
		"mips":    {"mips-linux-gnu", "mipsel-linux-gnu"},
		"mips64":  {"mips64-linux-gnuabi64", "mips64el-linux-gnuabi64"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			basePaths := []string{
				fmt.Sprintf("/usr/lib/%s", suffix),
				fmt.Sprintf("/lib/%s", suffix),
			}
			for _, basePath := range basePaths {
				if _, err := os.Stat(basePath); err == nil {
					for _, pattern := range libPatterns {
						err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
							if err != nil || !info.Mode().IsRegular() {
								return nil
							}
							baseName := strings.ToLower(filepath.Base(walkPath))
							if strings.Contains(baseName, strings.ToLower(pattern)) {
								paths = append(paths, walkPath)
							}
							return nil
						})
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	commonPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
	}

	for _, basePath := range commonPaths {
		if _, err := os.Stat(basePath); err == nil {
			for _, pattern := range libPatterns {
				err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
					if err != nil || !info.Mode().IsRegular() {
						return nil
					}
					baseName := strings.ToLower(filepath.Base(walkPath))
					if strings.Contains(baseName, strings.ToLower(pattern)) {
						paths = append(paths, walkPath)
					}
					return nil
				})
				if err != nil {
					continue
				}
			}
		}
	}

	return paths
}

func AttachTLSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	return AttachTLSProbesWithPID(coll, containerID, 0, nil)
}

func AttachTLSProbesWithPID(coll *ebpf.Collection, containerID string, pid uint32, af *AttachedFiles) []link.Link {
	links := []link.Link{}

	tlsLibPaths := findTLSLibsWithPID(containerID, pid)
	tlsSymbols := map[string][]string{
		"SSL_connect":           {"uprobe_SSL_connect", "uretprobe_SSL_connect"},
		"SSL_accept":            {"uprobe_SSL_accept", "uretprobe_SSL_accept"},
		"SSL_do_handshake":      {"uprobe_SSL_do_handshake", "uretprobe_SSL_do_handshake"},
		"SSL_get_error":         {"uprobe_SSL_get_error", "uretprobe_SSL_get_error"},
		"SSL_free":              {"uprobe_SSL_free", ""},
		"gnutls_handshake":      {"uprobe_gnutls_handshake", "uretprobe_gnutls_handshake"},
		"mbedtls_ssl_handshake": {"uprobe_mbedtls_ssl_handshake", "uretprobe_mbedtls_ssl_handshake"},
		"SSL_write":             {"uprobe_SSL_write", "uretprobe_SSL_write"},
		"SSL_read":              {"uprobe_SSL_read", "uretprobe_SSL_read"},
		"SSL_write_ex":          {"uprobe_SSL_write_ex", "uretprobe_SSL_write_ex"},
		"SSL_read_ex":           {"uprobe_SSL_read_ex", "uretprobe_SSL_read_ex"},
		"gnutls_record_send":    {"uprobe_gnutls_record_send", "uretprobe_gnutls_record_send"},
		"gnutls_record_recv":    {"uprobe_gnutls_record_recv", "uretprobe_gnutls_record_recv"},
	}

	logger.Debug("TLS probe attach: candidate libraries",
		zap.Strings("libs", tlsLibPaths), zap.String("containerID", containerID), zap.Uint32("pid", pid))

	for _, libPath := range tlsLibPaths {
		if !hostfs.IsRegularFile(libPath) {
			continue
		}
		if !af.Claim("tls", libPath) {
			continue
		}
		exe, err := openExecutable(libPath)
		if err != nil {
			logger.Debug("TLS probe: cannot open library", zap.String("lib", libPath), zap.Error(err))
			continue
		}
		defer func() { _ = exe.Close() }()

		for symbol, progNames := range tlsSymbols {
			if len(progNames) < 2 {
				continue
			}
			uprobeProg := coll.Programs[progNames[0]]
			uretprobeProg := coll.Programs[progNames[1]]

			if uretprobeProg != nil {
				l, err := exe.Uretprobe(symbol, uretprobeProg, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "not found") {
						logger.Debug("TLS uretprobe attach failed", zap.String("symbol", symbol), zap.String("lib", libPath), zap.Error(err))
					}
					continue
				}
				links = append(links, l)
			}
			if uprobeProg != nil {
				l, err := exe.Uprobe(symbol, uprobeProg, nil)
				if err == nil {
					links = append(links, l)
					logger.Debug("TLS uprobe attached", zap.String("symbol", symbol), zap.String("lib", libPath))
				} else if !strings.Contains(err.Error(), "not found") {
					logger.Debug("TLS uprobe attach failed", zap.String("symbol", symbol), zap.String("lib", libPath), zap.Error(err))
				}
			}
		}
	}

	if pid > 0 {
		exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
		if !executableExportsSSL(exePath) {
			if off, ok := resolveSSLOffsets(exePath, pid); ok {
				if l := attachSSLByOffset(coll, exePath, off); len(l) > 0 {
					links = append(links, l...)
					logger.Info("TLS probes attached by offset (stripped binary)",
						zap.String("exe", exePath), zap.String("source", off.source),
						zap.Int("links", len(l)))
				}
			}
		}
	}

	logger.Debug("TLS probe attach complete", zap.Int("links", len(links)))
	return links
}

// AttachGoTLSProbes attaches an entry uprobe on crypto/tls.(*Conn).Write in a
// statically-linked Go binary (resolved via /proc/<pid>/exe), capturing HTTPS
// request endpoints, HTTP/1.x or h2, from the plaintext buffer before
// encryption.
func AttachGoTLSProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	var links []link.Link
	prog := coll.Programs["uprobe_go_tls_write"]
	if prog == nil || pid == 0 {
		return links
	}
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	exe, err := openExecutable(exePath)
	if err != nil {
		logger.Debug("Go TLS probe: cannot open executable",
			zap.String("path", exePath), zap.Error(err))
		return links
	}
	defer func() { _ = exe.Close() }()
	links = append(links, attachGoHandshakeProbes(coll, exe, exePath, pid)...)
	const sym = "crypto/tls.(*Conn).Write"
	l, err := exe.Uprobe(sym, prog, nil)
	if err != nil {
		if off, ok := goSymbolFileOffset(exePath, sym); ok {
			l, err = exe.Uprobe("", prog, &link.UprobeOptions{Address: off})
			if err == nil {
				logger.Debug("Go TLS uprobe attached via gopclntab",
					zap.Uint32("pid", pid), zap.Uint64("offset", off))
			}
		}
	}
	if err != nil {
		logger.Debug("Go TLS uprobe not attached",
			zap.String("symbol", sym), zap.Uint32("pid", pid), zap.Error(err))
		return links
	}
	links = append(links, l)
	logger.Debug("Go TLS uprobe attached", zap.Uint32("pid", pid))

	links = append(links, attachGoTLSReadProbes(coll, exe, exePath, pid)...)
	return links
}

// goHandshakeFuncs are the crypto/tls functions that run a handshake that
// actually happens.
var goHandshakeFuncs = []string{
	"crypto/tls.(*Conn).clientHandshake",
	"crypto/tls.(*Conn).serverHandshake",
}

var goFuncReturns = goFuncReturnOffsets

// attachGoHandshakeProbes attaches, for each handshake function, an entry
// uprobe and one on every RET: a uretprobe is unsafe in Go, whose goroutine
// stacks move.
func attachGoHandshakeProbes(coll *ebpf.Collection, exe uprobeTarget, exePath string, pid uint32) []link.Link {
	entryProg, retProg := coll.Programs["uprobe_go_tls_handshake"], coll.Programs["uprobe_go_tls_handshake_ret"]
	if entryProg == nil || retProg == nil {
		return nil
	}
	var links []link.Link
	for _, sym := range goHandshakeFuncs {
		entryOff, retOffs, ok := goFuncReturns(exePath, sym)
		if !ok {
			logger.Debug("Go TLS handshake probe: symbol not resolved",
				zap.String("symbol", sym), zap.Uint32("pid", pid))
			continue
		}
		links = append(links, attachEntryAfterReturns(exe, entryProg, retProg, entryOff, retOffs)...)
	}
	if len(links) > 0 {
		logger.Debug("Go TLS handshake uprobes attached", zap.Uint32("pid", pid), zap.Int("links", len(links)))
	}
	return links
}

// AttachGoGRPCProbes attaches entry uprobes on grpc-go's internal/transport
// header functions in a statically-linked Go binary, capturing gRPC
// :method/:path/:status from the plaintext []hpack.HeaderField slice.
func AttachGoGRPCProbes(coll *ebpf.Collection, pid uint32) []link.Link {
	var links []link.Link
	if pid == 0 {
		return links
	}
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	exe, err := openExecutable(exePath)
	if err != nil {
		return links
	}
	defer func() { _ = exe.Close() }()
	targets := []struct{ prog, sym string }{
		{"uprobe_grpc_go_write_header", "google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader"},
		{"uprobe_grpc_go_server_headers", "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders"},
		{"uprobe_grpc_go_client_headers", "google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders"},
	}
	for _, t := range targets {
		prog := coll.Programs[t.prog]
		if prog == nil {
			continue
		}
		l, err := exe.Uprobe(t.sym, prog, nil)
		if err != nil {
			if off, ok := goSymbolFileOffset(exePath, t.sym); ok {
				l, err = exe.Uprobe("", prog, &link.UprobeOptions{Address: off})
			}
		}
		if err != nil {
			logger.Debug("Go gRPC uprobe not attached",
				zap.String("symbol", t.sym), zap.Uint32("pid", pid), zap.Error(err))
			continue
		}
		links = append(links, l)
		logger.Debug("Go gRPC uprobe attached", zap.String("symbol", t.sym), zap.Uint32("pid", pid))
	}
	return links
}

// attachGoTLSReadProbes attaches the entry + return-address uprobes on
// crypto/tls.(*Conn).Read so the decrypted response/inbound plaintext is
// captured on return.
func attachGoTLSReadProbes(coll *ebpf.Collection, exe uprobeTarget, exePath string, pid uint32) []link.Link {
	var links []link.Link
	entryProg := coll.Programs["uprobe_go_tls_read"]
	retProg := coll.Programs["uprobe_go_tls_read_ret"]
	if entryProg == nil || retProg == nil {
		return links
	}
	const sym = "crypto/tls.(*Conn).Read"
	entryOff, retOffs, ok := goFuncReturns(exePath, sym)
	if !ok {
		logger.Debug("Go TLS Read probe: no return sites resolved (unsupported arch or symbol missing)",
			zap.Uint32("pid", pid))
		return links
	}
	links = attachEntryAfterReturns(exe, entryProg, retProg, entryOff, retOffs)
	if len(links) == 0 {
		logger.Debug("Go TLS Read uprobes not attached", zap.Uint32("pid", pid))
		return nil
	}
	logger.Debug("Go TLS Read uprobes attached",
		zap.Uint32("pid", pid), zap.Int("ret_sites", len(links)-1))
	return links
}

// publishPoolOffsets resolves database/sql.DB's field offsets for one target
// and hands them to BPF, keyed by tgid.
func publishPoolOffsets(coll *ebpf.Collection, exePath string, pid uint32) {
	m := coll.Maps["pool_offsets"]
	if m == nil || pid == 0 {
		return
	}
	off, ok := resolvePoolFieldOffsets(exePath, pid)
	if !ok {
		return
	}
	value := struct{ NumOpen, MaxOpen, FreeConn uint32 }{NumOpen: off.NumOpen, MaxOpen: off.MaxOpen, FreeConn: off.FreeConn}
	if err := m.Update(pid, value, ebpf.UpdateAny); err != nil {
		logger.Debug("Pool utilization: could not publish field offsets",
			zap.Uint32("pid", pid), zap.Error(err))
		return
	}
	logger.Debug("Pool utilization: field offsets published",
		zap.Uint32("pid", pid),
		zap.Uint32("num_open", off.NumOpen),
		zap.Uint32("max_open", off.MaxOpen),
		zap.Uint32("free_conn", off.FreeConn))
}

// attachGoAcquireProbes attaches the entry + return uprobes on
// database/sql.(*DB).conn, whose entry-to-return duration is the time a
// caller spent waiting for a free pooled connection.
func attachGoAcquireProbes(coll *ebpf.Collection, exePath string, pid uint32) []link.Link {
	var links []link.Link

	entryProg := coll.Programs["uprobe_go_db_conn"]
	retProg := coll.Programs["uprobe_go_db_conn_ret"]
	if entryProg == nil || retProg == nil {
		return links
	}

	const sym = "database/sql.(*DB).conn"
	entryOff, retOffs, ok := goFuncReturnOffsets(exePath, sym)
	if !ok {
		logger.Debug("Go pool wait probe: symbol not resolved",
			zap.String("path", exePath), zap.Uint32("pid", pid))
		return links
	}

	exe, err := openExecutable(exePath)
	if err != nil {
		logger.Debug("Go pool wait probe: cannot open executable",
			zap.String("path", exePath), zap.Error(err))
		return links
	}
	defer func() { _ = exe.Close() }()

	el, err := exe.Uprobe("", entryProg, &link.UprobeOptions{Address: entryOff})
	if err != nil {
		logger.Debug("Go pool wait entry uprobe not attached", zap.Error(err))
		return links
	}
	links = append(links, el)

	// Publish the DB field offsets before the probe can fire. Without an
	// entry the BPF side emits no pool stats at all, which is the intended
	// behaviour for a binary that shipped no DWARF.
	publishPoolOffsets(coll, exePath, pid)

	attached := 0
	for _, ro := range retOffs {
		rl, err := exe.Uprobe("", retProg, &link.UprobeOptions{Address: ro})
		if err != nil {
			continue
		}
		links = append(links, rl)
		attached++
	}

	if attached == 0 {
		for _, l := range links {
			_ = l.Close()
		}
		logger.Debug("Go pool wait probe: no return sites attached, entry probe dropped",
			zap.Uint32("pid", pid))
		return nil
	}

	logger.Debug("Go pool wait uprobes attached",
		zap.Uint32("pid", pid), zap.Int("ret_sites", attached))
	return links
}

// AttachGoHTTP3Probes attaches uprobes that read already-decoded HTTP/3 header
// fields from a quic-go process: http3.parseHeaders for inbound headers and
// qpack.(*Encoder).WriteField for outbound.
func AttachGoHTTP3Probes(coll *ebpf.Collection, pid uint32) []link.Link {
	var links []link.Link
	if pid == 0 {
		return links
	}
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	exe, err := openExecutable(exePath)
	if err != nil {
		logger.Debug("Go HTTP/3 probe: cannot open executable",
			zap.String("path", exePath), zap.Error(err))
		return links
	}
	defer func() { _ = exe.Close() }()

	if m := coll.Maps["h3_offsets"]; m != nil {
		off, src := resolveH3FieldOffsets(exePath, pid)
		tgid := pid
		if err := m.Update(&tgid, &off, ebpf.UpdateAny); err != nil {
			logger.Debug("HTTP/3 offsets: map update failed", zap.Uint32("pid", pid), zap.Error(err))
		} else {
			logger.Debug("HTTP/3 field offsets resolved",
				zap.Uint32("pid", pid), zap.String("source", src),
				zap.Uint32("method", off.Method), zap.Uint32("url", off.URL),
				zap.Uint32("path", off.Path), zap.Uint32("status", off.Status))
		}
	}

	clientRootType := ""
	for _, cand := range []struct{ sym, rootType string }{
		{"github.com/quic-go/quic-go/http3.(*ClientConn).RoundTrip",
			"github.com/quic-go/quic-go/http3.ClientConn"},
		{"github.com/quic-go/quic-go/http3.(*SingleDestinationRoundTripper).RoundTrip",
			"github.com/quic-go/quic-go/http3.SingleDestinationRoundTripper"},
		{"github.com/quic-go/quic-go/http3.(*Transport).RoundTrip", ""},
	} {
		ls := attachGoEntryReturnProbes(coll, exe, exePath, pid, cand.sym,
			"uprobe_h3_roundtrip", "uprobe_h3_roundtrip_ret")
		if len(ls) > 0 {
			links = append(links, ls...)
			clientRootType = cand.rootType
			break
		}
	}

	if m := coll.Maps["h3_peer_paths_map"]; m != nil {
		if paths, ok := resolveH3PeerPaths(exePath, pid, clientRootType); ok {
			tgid := pid
			if err := m.Update(&tgid, &paths, ebpf.UpdateAny); err != nil {
				logger.Debug("HTTP/3 peer paths: map update failed",
					zap.Uint32("pid", pid), zap.Error(err))
			} else {
				logger.Debug("HTTP/3 peer paths resolved",
					zap.Uint32("pid", pid),
					zap.Uint8("client_steps", paths.Client.NSteps),
					zap.Uint8("server_steps", paths.Server.NSteps))
			}
		} else {
			logger.Debug("HTTP/3 peer paths unresolved (no DWARF or unsupported quic-go layout)",
				zap.Uint32("pid", pid))
		}
	}

	links = append(links, attachGoReturnProbes(coll, exe, exePath, pid,
		"github.com/quic-go/quic-go/http3.requestFromHeaders",
		"uprobe_h3_req_from_headers_ret")...)

	for _, sym := range []string{
		"github.com/quic-go/quic-go/http3.(*RawServerConn).handleRequestStream",
		"github.com/quic-go/quic-go/http3.(*ServerConn).handleRequestStream",
		"github.com/quic-go/quic-go/http3.(*connection).handleRequestStream",
	} {
		if ls := attachGoReturnProbes(coll, exe, exePath, pid, sym,
			"uprobe_h3_handle_request_ret"); len(ls) > 0 {
			links = append(links, ls...)
			break
		}
	}
	if prog := coll.Programs["uprobe_h3_write_header"]; prog != nil {
		const sym = "github.com/quic-go/quic-go/http3.(*responseWriter).WriteHeader"
		if l, ok := attachGoUprobeBySymbol(exe, exePath, sym, prog); ok {
			links = append(links, l)
			logger.Debug("Go HTTP/3 WriteHeader uprobe attached", zap.Uint32("pid", pid))
		}
	}

	if prog := coll.Programs["uprobe_h3_qpack_write_field"]; prog != nil {
		const sym = "github.com/quic-go/qpack.(*Encoder).WriteField"
		if l, ok := attachGoUprobeBySymbol(exe, exePath, sym, prog); ok {
			links = append(links, l)
			logger.Debug("Go HTTP/3 WriteField (traceparent) uprobe attached", zap.Uint32("pid", pid))
		}
	}
	links = append(links, attachGoEntryReturnProbes(coll, exe, exePath, pid,
		"github.com/quic-go/quic-go/http3.parseHeaders",
		"uprobe_h3_parse_headers", "uprobe_h3_parse_headers_ret")...)

	return links
}

// AttachNghttp3Probes attaches uprobes on nghttp3's public C ABI
// (nghttp3_conn_submit_request / nghttp3_conn_submit_response) in libraries
// mapped by the target process.
func AttachNghttp3Probes(coll *ebpf.Collection, pid uint32, af *AttachedFiles) []link.Link {
	return attachCLibraryH3Probes(coll, pid, af, "nghttp3",
		[]string{"libnghttp3"},
		map[string][2]string{
			"nghttp3_conn_submit_request":  {"uprobe_nghttp3_submit_request", ""},
			"nghttp3_conn_submit_response": {"uprobe_nghttp3_submit_response", ""},
			"nghttp3_conn_read_stream":     {"uprobe_nghttp3_read_stream", ""},
		})
}

// AttachQuicheProbes attaches uprobes on Cloudflare quiche's C FFI
// (quiche_h3_send_request / quiche_h3_send_response); see bpf/quiche.c.
func AttachQuicheProbes(coll *ebpf.Collection, pid uint32, af *AttachedFiles) []link.Link {
	return attachCLibraryH3Probes(coll, pid, af, "quiche",
		[]string{"libquiche"},
		map[string][2]string{
			"quiche_h3_send_request":  {"uprobe_quiche_h3_send_request", "uretprobe_quiche_h3_send_request"},
			"quiche_h3_send_response": {"uprobe_quiche_h3_send_response", ""},
			"quiche_h3_conn_poll":     {"uprobe_quiche_h3_conn_poll", "uretprobe_quiche_h3_conn_poll"},
		})
}

// attachCLibraryH3Probes discovers libraries matching the patterns in the
// target process's memory maps (including dlopen'd-then-deleted files via
// map_files) and attaches the given symbol->program uprobes.
func attachCLibraryH3Probes(coll *ebpf.Collection, pid uint32, af *AttachedFiles, adapter string,
	libPatterns []string, symbolProgs map[string][2]string) []link.Link {
	var links []link.Link
	if pid == 0 {
		return links
	}
	anyProg := false
	for _, progNames := range symbolProgs {
		if coll.Programs[progNames[0]] != nil || coll.Programs[progNames[1]] != nil {
			anyProg = true
			break
		}
	}
	if !anyProg {
		return links
	}

	seen := make(map[string]bool)
	var libPaths []string
	for _, p := range findTLSLibsViaProcessMaps(pid, libPatterns) {
		if !seen[p] {
			libPaths = append(libPaths, p)
			seen[p] = true
		}
	}
	for _, p := range findTLSLibsViaProcRootScan(pid, libPatterns) {
		if !seen[p] {
			libPaths = append(libPaths, p)
			seen[p] = true
		}
	}

	for _, libPath := range libPaths {
		if !af.Claim(adapter, libPath) {
			continue
		}
		exe, err := openExecutable(libPath)
		if err != nil {
			logger.Debug("HTTP/3 adapter: cannot open library",
				zap.String("adapter", adapter), zap.String("lib", libPath), zap.Error(err))
			continue
		}
		defer func() { _ = exe.Close() }()
		attached := 0
		for symbol, progNames := range symbolProgs {
			if prog := coll.Programs[progNames[0]]; prog != nil {
				if l, err := exe.Uprobe(symbol, prog, nil); err == nil {
					links = append(links, l)
					attached++
				}
			}
			if progNames[1] == "" {
				continue
			}
			if prog := coll.Programs[progNames[1]]; prog != nil {
				if l, err := exe.Uretprobe(symbol, prog, nil); err == nil {
					links = append(links, l)
					attached++
				}
			}
		}
		if attached > 0 {
			logger.Debug("HTTP/3 adapter uprobes attached",
				zap.String("adapter", adapter), zap.String("lib", libPath),
				zap.Uint32("pid", pid), zap.Int("links", attached))
		}
	}
	return links
}

// attachGoUprobeBySymbol attaches an entry uprobe, falling back to a gopclntab
// file-offset attach when the symbol is absent from the dynamic symbol table.
func attachGoUprobeBySymbol(exe *executable, exePath, sym string, prog *ebpf.Program) (link.Link, bool) {
	l, err := exe.Uprobe(sym, prog, nil)
	if err != nil {
		off, ok := goSymbolFileOffset(exePath, sym)
		if !ok {
			return nil, false
		}
		l, err = exe.Uprobe("", prog, &link.UprobeOptions{Address: off})
		if err != nil {
			return nil, false
		}
	}
	return l, true
}

// attachGoEntryReturnProbes attaches an entry uprobe on a Go function plus a
// uprobe at each of its return sites.
func attachGoEntryReturnProbes(coll *ebpf.Collection, exe uprobeTarget, exePath string, pid uint32,
	sym, entryProgName, retProgName string) []link.Link {
	var links []link.Link
	entryProg := coll.Programs[entryProgName]
	retProg := coll.Programs[retProgName]
	if entryProg == nil || retProg == nil {
		return links
	}
	entryOff, retOffs, ok := goFuncReturns(exePath, sym)
	if !ok {
		logger.Debug("Go entry+return probes: no return sites resolved (symbol missing or unsupported arch)",
			zap.String("symbol", sym), zap.Uint32("pid", pid))
		return links
	}
	links = attachEntryAfterReturns(exe, entryProg, retProg, entryOff, retOffs)
	if len(links) == 0 {
		logger.Debug("Go entry+return uprobes not attached", zap.String("symbol", sym), zap.Uint32("pid", pid))
		return nil
	}
	logger.Debug("Go entry+return uprobes attached",
		zap.String("symbol", sym), zap.Uint32("pid", pid), zap.Int("ret_sites", len(links)-1))
	return links
}

// attachEntryAfterReturns attaches a uprobe at every return site first and
// the entry uprobe only once at least one of them is in place, so an entry
// never stashes state that no return will clear. It returns the return links
// followed by the entry, or nothing.
func attachEntryAfterReturns(exe uprobeTarget, entryProg, retProg *ebpf.Program, entryOff uint64, retOffs []uint64) []link.Link {
	var rets []link.Link
	for _, ro := range retOffs {
		if rl, err := exe.Uprobe("", retProg, &link.UprobeOptions{Address: ro}); err == nil {
			rets = append(rets, rl)
		}
	}
	if len(rets) == 0 {
		return nil
	}
	el, err := exe.Uprobe("", entryProg, &link.UprobeOptions{Address: entryOff})
	if err != nil {
		for _, l := range rets {
			_ = l.Close()
		}
		return nil
	}
	return append(rets, el)
}

// attachGoReturnProbes attaches a uprobe at each return site of a Go function
// (no entry probe). Used when only the function's result is needed.
func attachGoReturnProbes(coll *ebpf.Collection, exe *executable, exePath string, pid uint32,
	sym, retProgName string) []link.Link {
	var links []link.Link
	retProg := coll.Programs[retProgName]
	if retProg == nil {
		return links
	}
	_, retOffs, ok := goFuncReturnOffsets(exePath, sym)
	if !ok {
		logger.Debug("Go HTTP/3: no return sites resolved",
			zap.String("symbol", sym), zap.Uint32("pid", pid))
		return links
	}
	for _, ro := range retOffs {
		if rl, err := exe.Uprobe("", retProg, &link.UprobeOptions{Address: ro}); err == nil {
			links = append(links, rl)
		}
	}
	logger.Debug("Go HTTP/3 return uprobes attached",
		zap.String("symbol", sym), zap.Uint32("pid", pid), zap.Int("ret_sites", len(links)))
	return links
}

// kernelVersionString returns the running kernel version for use in error messages.
func kernelVersionString() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	for i, f := range fields {
		if strings.EqualFold(f, "version") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "unknown"
}

func SockOpsEnabled() bool {
	return config.SockOpsRTTEnabled
}

var attachCgroupLink = link.AttachCgroup

// AttachSockOpsProbes attaches the sock_ops RTT observer to each cgroup.
func AttachSockOpsProbes(coll *ebpf.Collection, cgroupPaths []string) []link.Link {
	if !SockOpsEnabled() {
		return nil
	}
	prog := coll.Programs["sockops_rtt"]
	if prog == nil {
		logger.Warn("Smoothed-RTT sock_ops hook requested but the program is not in the " +
			"loaded collection; network_rtt_seconds will stay empty and " +
			"net.rtt_spike_rate will fall back to syscall latency")
		return nil
	}

	attach := []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
		name string
	}{
		{coll.Programs["cgroup_skb_stamp_egress"], ebpf.AttachCGroupInetEgress, "stamp-egress"},
		{coll.Programs["cgroup_skb_stamp_ingress"], ebpf.AttachCGroupInetIngress, "stamp-ingress"},
		{prog, ebpf.AttachCGroupSockOps, "sockops"},
	}

	targets := sockOpsCgroups(cgroupPaths)
	var links []link.Link
	for _, path := range targets {
		attached := 0
		for _, a := range attach {
			if a.prog == nil {
				continue
			}
			l, err := attachCgroupLink(link.CgroupOptions{
				Path:    path,
				Attach:  a.typ,
				Program: a.prog,
			})
			if err != nil {
				logger.Debug("Smoothed-RTT hook unavailable for cgroup",
					zap.String("cgroup", path), zap.String("program", a.name), zap.Error(err))
				continue
			}
			links = append(links, l)
			attached++
		}
		if attached > 0 {
			logger.Debug("Smoothed-RTT sock_ops hook attached to cgroup",
				zap.String("cgroup", path), zap.Int("programs", attached))
		}
	}
	return links
}

// sockOpsCgroups decides which cgroups the hook attaches to: the caller's
// targets with blanks and duplicates removed, or the kubepods root when there
// are none.
func sockOpsCgroups(cgroupPaths []string) []string {
	return sockOpsCgroupsWith(cgroupPaths, KubepodsRoot())
}

// sockOpsCgroupsWith is sockOpsCgroups with the fallback root injected, so
// both outcomes can be tested on a host that has no kubelet.
func sockOpsCgroupsWith(cgroupPaths []string, root string) []string {
	kept := make([]string, 0, len(cgroupPaths))
	seen := make(map[string]struct{}, len(cgroupPaths))
	for _, path := range cgroupPaths {
		if path == "" {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		kept = append(kept, path)
	}

	out := make([]string, 0, len(kept))
	for _, path := range kept {
		nested := false
		for _, other := range kept {
			if other != path && isCgroupDescendant(path, other) {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		if root != "" {
			return []string{root}
		}
		return nil
	}
	return out
}

// kubepodsRootCandidates lists the well-known cgroup directories kubelet
// publishes per-pod slices under, relative to the cgroup mount.
var kubepodsRootCandidates = []string{
	"kubepods.slice",
	"kubepods",
	"kubelet.slice/kubelet-kubepods.slice",
	"system.slice/kubelet.service/kubepods",
}

// KubepodsRoot returns the first kubepods cgroup root present on this node,
// or empty when none is, which is the case outside Kubernetes.
func KubepodsRoot() string { return kubepodsRootUnder(config.CgroupBasePath) }

// kubepodsRootUnder is KubepodsRoot with the mount point injected, so the
// candidate order can be tested without a kubelet.
func kubepodsRootUnder(base string) string {
	if base == "" {
		return ""
	}
	for _, c := range kubepodsRootCandidates {
		candidate := filepath.Join(base, c)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// isCgroupDescendant reports whether child sits under ancestor in the cgroup
// tree. Both are absolute filesystem paths, so this is a path-prefix test on
// whole segments: "/a/bc" is not inside "/a/b".
func isCgroupDescendant(child, ancestor string) bool {
	if ancestor == "" || child == ancestor {
		return false
	}
	return strings.HasPrefix(child, strings.TrimSuffix(ancestor, "/")+"/")
}
