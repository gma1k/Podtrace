package ebpf

import (
	"strings"
	"testing"
)

func TestDNSQueryPidIsInAgentNamespace(t *testing.T) {
	body := functionBody(t, bpfSource(t, "dns.c"), "dns_egress")
	if strings.Contains(body, "bpf_get_current_pid_tgid() >> 32") {
		t.Fatal("dns_egress records a host-namespace tgid that does not exist in the agent's /proc")
	}
	if !strings.Contains(body, "q.pid = agent_ns_tgid();") {
		t.Fatal("dns_egress must record the query pid with agent_ns_tgid()")
	}
}

func TestOOMKillIsAttributedToTheVictim(t *testing.T) {
	body := functionBody(t, bpfSource(t, "memory.c"), "tracepoint_oom_mark_victim")
	acquire := strings.Index(body, "bpf_task_from_pid(")
	release := strings.Index(body, "bpf_task_release(victim)")
	if acquire < 0 || release < 0 {
		t.Fatal("tracepoint_oom_mark_victim no longer holds a victim task reference")
	}
	held := body[acquire:release]
	for _, want := range []string{
		"task_ns_tgid(victim,",
		"BPF_CORE_READ(victim, nsproxy, net_ns, ns.inum)",
	} {
		if !strings.Contains(held, want) {
			t.Errorf("tracepoint_oom_mark_victim must read %s while the victim reference is held", want)
		}
	}
	if !strings.Contains(body, "victim_tgid == (u32)(bpf_get_current_pid_tgid() >> 32)") {
		t.Error("tracepoint_oom_mark_victim must only capture the user stack when the victim is current")
	}
}

func TestSSLReadSettlesPendingHandshake(t *testing.T) {
	text := bpfSource(t, "http.c")
	stash := functionBody(t, text, "ssl_read_stash")
	if !strings.Contains(stash, "ssl_hs_undecided(") {
		t.Error("ssl_read_stash must stash its SSL* while a handshake is undecided, even with HTTP tracing off")
	}
	complete := functionBody(t, text, "ssl_read_complete")
	settle := strings.Index(complete, "ssl_hs_settle(ctx, conn)")
	gate := strings.Index(complete, "if (!http_should_trace())")
	if settle < 0 {
		t.Fatal("ssl_read_complete must settle a handshake OpenSSL completed inside the read")
	}
	if gate >= 0 && gate < settle {
		t.Fatal("ssl_read_complete settles the handshake only when HTTP tracing is on")
	}
	for _, fn := range []string{"uretprobe_SSL_read", "uretprobe_SSL_read_ex"} {
		if !strings.Contains(functionBody(t, text, fn), "ssl_read_complete(") {
			t.Errorf("%s must complete through ssl_read_complete", fn)
		}
	}
}

func TestPthreadLockErrorsAreNegatedLikeFutexReturns(t *testing.T) {
	body := functionBody(t, bpfSource(t, "cpu.c"), "uretprobe_pthread_mutex_lock")
	if !strings.Contains(body, "prc > 0 ? -prc : prc") {
		t.Fatal("pthread_mutex_lock returns a positive errno; it must be negated so Event.IsError treats every lock event alike")
	}
}

func TestOOMKillCarriesTheVictimsResidentMemory(t *testing.T) {
	body := functionBody(t, bpfSource(t, "memory.c"), "tracepoint_oom_mark_victim")
	for _, want := range []string{"bpf_core_field_exists(tp->anon_rss)", "file_rss", "shmem_rss", "* 1024"} {
		if !strings.Contains(body, want) {
			t.Errorf("tracepoint_oom_mark_victim lacks %q; the report would show 0 B for every kill", want)
		}
	}
}

func TestTasksInvisibleToTheAgentGetNoHostPID(t *testing.T) {
	body := functionBody(t, bpfSource(t, "helpers.h"), "task_ns_tgid")
	if strings.Count(body, "return init_tgid;") != 1 {
		t.Fatal("task_ns_tgid may fall back to the host PID only when the agent has no pid namespace reference; " +
			"a task it cannot see (exited, or outside its namespace) must come back as 0")
	}
	cpu := bpfSource(t, "cpu.c")
	if !strings.Contains(functionBody(t, cpu, "tracepoint_sched_switch"), "tgid ? get_event_buf() : NULL") {
		t.Error("sched_switch must not emit an event for a task whose PID the agent cannot see")
	}
	if !strings.Contains(functionBody(t, cpu, "proc_cpu_accumulate"), "if (!tgid)") {
		t.Error("CPU time must not be counted under PID 0")
	}
	if !strings.Contains(functionBody(t, bpfSource(t, "http3.c"), "quic_ship"), "egress ? agent_ns_tgid() : 0") {
		t.Error("an ingress QUIC packet is handled in softirq; current is not the receiving process")
	}
}
