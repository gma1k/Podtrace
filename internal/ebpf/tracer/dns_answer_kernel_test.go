//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/dns"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	dnsWorkerServer = "PODTRACE_DNS_WORKER_SERVER"
	dnsRetryWait    = 300 * time.Millisecond
	dnsSilentTxID   = 0x5157
)

var dnsWorkerQueries = []struct {
	name    string
	txid    uint16
	sends   int
	answers bool
}{
	{"noerror.test", 0x1001, 1, true},
	{"nxdomain.test", 0x1002, 1, true},
	{"servfail.test", 0x1003, 1, true},
	{"refused.test", 0x1004, 1, true},
	{"formerr.test", 0x1005, 1, true},
	{"retry.test", 0x1006, 2, true},
	{"silent.test", dnsSilentTxID, 2, false},
}

func dnsQuery(txid uint16, name string) []byte {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	return append(msg, 0, 0, 1, 0, 1)
}

func TestKernelDNSWorker(t *testing.T) {
	server := os.Getenv(dnsWorkerServer)
	if server == "" {
		t.Skip("only runs as the child of the DNS kernel tests")
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reply := make([]byte, 512)
	for _, q := range dnsWorkerQueries {
		for send := 0; send < q.sends; send++ {
			if _, err := conn.Write(dnsQuery(q.txid, q.name)); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(dnsRetryWait))
			if _, err := conn.Read(reply); err == nil {
				break
			}
		}
	}
	fmt.Println("done")
}

var dnsRCodeFor = map[string]uint16{
	"noerror.test": 0, "nxdomain.test": 3, "servfail.test": 2, "refused.test": 5, "formerr.test": 1, "retry.test": 0,
}

func qnameOf(msg []byte) string {
	var labels []string
	for off := 12; off < len(msg) && msg[off] != 0; {
		n := int(msg[off])
		if off+1+n > len(msg) {
			break
		}
		labels = append(labels, string(msg[off+1:off+1+n]))
		off += 1 + n
	}
	return strings.Join(labels, ".")
}

func serveDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:53: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		retried := false
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			name := qnameOf(buf[:n])
			rcode, ok := dnsRCodeFor[name]
			if !ok || (name == "retry.test" && !retried) {
				retried = retried || name == "retry.test"
				continue
			}
			resp := append([]byte(nil), buf[:n]...)
			binary.BigEndian.PutUint16(resp[2:4], 0x8180|rcode)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

type dnsClassCounts map[string]uint64

func dnsRows(t *testing.T, rows []kernelagg.Row, cgroup uint64) (dnsClassCounts, uint64, uint64) {
	t.Helper()
	counts := dnsClassCounts{}
	var failed, noerrorNS uint64
	for _, r := range rows {
		if r.Key.CgroupID != cgroup || events.EventType(r.Key.EventType) != events.EventDNS {
			continue
		}
		v := kernelagg.DecodeVariant(r.Key.Variant)
		if v.Transport != events.DNSSourceUDP {
			t.Errorf("a lookup over UDP came from source %d", v.Transport)
		}
		answer := events.DNSAnswerOfClass(v.StatusClass)
		counts[answer] += r.Value.Count
		if v.IsError {
			failed += r.Value.Count
		}
		if answer == events.DNSAnswerNoError {
			noerrorNS += r.Value.SumNS
		}
	}
	return counts, failed, noerrorNS
}

func dnsTracer(t *testing.T, payload bool, w fsWorker) *Tracer {
	t.Helper()
	orig := config.DNSPayloadEnabled
	config.DNSPayloadEnabled = payload
	t.Cleanup(func() { config.DNSPayloadEnabled = orig })
	tr := fsTracer(t, "fentry", w)
	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}
	return tr
}

func readPayloadRecords(t *testing.T, tr *Tracer) []dns.Record {
	t.Helper()
	if tr.dnsPayloadReader == nil {
		t.Fatal("full answers are on and there is no payload reader")
	}
	var out []dns.Record
	for {
		tr.dnsPayloadReader.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := tr.dnsPayloadReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return out
			}
			t.Fatal(err)
		}
		if r, ok := dns.ParseRecord(rec.RawSample); ok {
			out = append(out, r)
		}
	}
}

func TestKernelEveryAnswerIsClassedAndARetryKeepsItsWait(t *testing.T) {
	for _, payload := range []bool{true, false} {
		t.Run(fmt.Sprintf("full-answers=%v", payload), func(t *testing.T) {
			w := newFSWorker(t, fmt.Sprintf("dns-%v", payload))
			server := serveDNS(t)
			tr := dnsTracer(t, payload, w)
			runInCgroup(t, w.cgroup, "TestKernelDNSWorker", dnsWorkerServer+"="+server)

			rows, err := tr.DrainKernelMetrics()
			if err != nil {
				t.Fatal(err)
			}
			counts, failed, noerrorNS := dnsRows(t, rows, w.id)
			want := dnsClassCounts{"NOERROR": 2, "NXDOMAIN": 1, "SERVFAIL": 1, "REFUSED": 1, "other": 1}
			if len(counts) != len(want) {
				t.Fatalf("answers %v, want %v", counts, want)
			}
			for answer, n := range want {
				if counts[answer] != n {
					t.Errorf("%s = %d, want %d (all %v)", answer, counts[answer], n, counts)
				}
			}
			if failed != 3 {
				t.Errorf("%d lookups carry the error bit, want the SERVFAIL, REFUSED and FORMERR, not the NXDOMAIN", failed)
			}
			if noerrorNS < uint64(dnsRetryWait) {
				t.Errorf("the answered lookups took %v in all, want at least the %v the retried one waited: "+
					"a retransmission restarted its clock", time.Duration(noerrorNS), dnsRetryWait)
			}

			if payload {
				recs := readPayloadRecords(t, tr)
				if len(recs) != 6 {
					t.Fatalf("%d payload records, want one per answer", len(recs))
				}
				for _, r := range recs {
					if !r.AggRecorded {
						t.Errorf("the answer to %q is unmarked though the kernel counted it", r.Msg.QName)
					}
				}
			}

			var state dnsQueryState
			key := dnsFlowKey{CgroupID: w.id, Txid: dnsSilentTxID}
			if err := tr.collection.Maps["dns_inflight"].Lookup(&key, &state); err != nil {
				t.Fatalf("the unanswered query is not in flight: %v", err)
			}
			if state.LastNS < state.TsNS+uint64(dnsRetryWait) {
				t.Errorf("first send %d, last %d: the retransmission did not move only the latest send", state.TsNS, state.LastNS)
			}
		})
	}
}

func TestKernelAQueryWithNoAnswerBecomesATimeout(t *testing.T) {
	w := newFSWorker(t, "dns-timeout")
	server := serveDNS(t)
	tr := dnsTracer(t, true, w)
	runInCgroup(t, w.cgroup, "TestKernelDNSWorker", dnsWorkerServer+"="+server)

	time.Sleep(time.Duration(dnsTimeoutThresholdNS) + 500*time.Millisecond)
	ch := make(chan *events.Event, 16)
	tr.sweepDNSTimeouts(context.Background(), ch)
	close(ch)

	var timeouts []*events.Event
	for e := range ch {
		if e.CgroupID == w.id {
			timeouts = append(timeouts, e)
		}
	}
	if len(timeouts) != 1 {
		t.Fatalf("%d timeouts, want the one query that got no answer", len(timeouts))
	}
	e := timeouts[0]
	if e.Target != "silent.test" || e.DNSAnswer() != events.DNSAnswerTimeout || !e.IsError() {
		t.Errorf("target %q answer %q error %v", e.Target, e.DNSAnswer(), e.IsError())
	}
	if e.LatencyNS < dnsTimeoutThresholdNS+uint64(dnsRetryWait) {
		t.Errorf("latency %v, want the whole wait since the first send", time.Duration(e.LatencyNS))
	}
}
