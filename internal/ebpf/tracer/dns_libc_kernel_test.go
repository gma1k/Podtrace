//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	libcWorkerResolv = "PODTRACE_LIBC_WORKER_RESOLV"
	libcWorkerNames  = "localhost noerror.test nxdomain.test servfail.test"
)

func TestKernelLibcDNSWorker(t *testing.T) {
	resolv := os.Getenv(libcWorkerResolv)
	if resolv == "" {
		t.Skip("only runs as the child of the libc DNS kernel test")
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(resolv, "/etc/resolv.conf", "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	script := "for n in " + libcWorkerNames + "; do getent hosts $n >/dev/null; done; echo done"
	if err := syscall.Exec("/bin/sh", []string{"sh", "-c", script}, os.Environ()); err != nil {
		t.Fatal(err)
	}
}

func TestKernelGethostbynameLookupsAreClassedLikeGetaddrinfo(t *testing.T) {
	w := newFSWorker(t, "dns-libc")
	server := serveDNS(t)
	tr := dnsTracer(t, false, w)

	links := probes.AttachDNSProbes(tr.collection, "")
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	if len(links) < 4 {
		t.Skipf("%d libc resolver probes attached; this libc lacks gethostbyname_r or gethostbyname2_r", len(links))
	}

	host, _, _ := splitHostPort(server)
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver "+host+"\noptions timeout:1 attempts:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInCgroup(t, w.cgroup, "TestKernelLibcDNSWorker", libcWorkerResolv+"="+resolv)

	rows, err := tr.DrainKernelMetrics()
	if err != nil {
		t.Fatal(err)
	}
	answers := map[string]uint64{}
	failed := map[string]bool{}
	for _, r := range rows {
		if r.Key.CgroupID != w.id || events.EventType(r.Key.EventType) != events.EventDNS {
			continue
		}
		v := kernelagg.DecodeVariant(r.Key.Variant)
		if v.Transport != events.DNSSourceLibc {
			continue
		}
		answer := events.DNSAnswerOfClass(v.StatusClass)
		answers[answer] += r.Value.Count
		failed[answer] = failed[answer] || v.IsError
	}

	for _, want := range []string{events.DNSAnswerNoError, events.DNSAnswerNXDomain, events.DNSAnswerServFail} {
		if answers[want] == 0 {
			t.Errorf("no %s lookup from gethostbyname: %v", want, answers)
		}
	}
	if answers[events.DNSAnswerOther] != 0 {
		t.Errorf("%d lookups classed other: h_errno was not read, so a known failure lost its class (%v)",
			answers[events.DNSAnswerOther], answers)
	}
	if failed[events.DNSAnswerNoError] || failed[events.DNSAnswerNXDomain] || !failed[events.DNSAnswerServFail] {
		t.Errorf("error bits %v: only the server failure is a failure", failed)
	}
}

func splitHostPort(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}
