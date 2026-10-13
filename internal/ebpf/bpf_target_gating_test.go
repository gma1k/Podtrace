package ebpf

import (
	"strings"
	"testing"
)

func TestNodeWideEntryProbesGateOnTargetCgroup(t *testing.T) {
	cases := []struct{ file, function string }{
		{"cpu.c", "kprobe_do_futex"},
		{"network.c", "kprobe_tcp_connect"},
		{"network.c", "kprobe_tcp_v6_connect"},
		{"network.c", "kprobe_tcp_sendmsg"},
		{"network.c", "kprobe_tcp_recvmsg"},
		{"network.c", "kprobe_udp_sendmsg"},
		{"network.c", "kprobe_udp_recvmsg"},
	}
	for _, tc := range cases {
		body := functionBody(t, bpfSource(t, tc.file), tc.function)
		gate := strings.Index(body, "cgroup_allows(bpf_get_current_cgroup_id())")
		write := strings.Index(body, "bpf_map_update_elem(")
		if gate < 0 {
			t.Errorf("%s:%s fills shared maps for every task on the node; it must check cgroup_allows first",
				tc.file, tc.function)
			continue
		}
		if write >= 0 && write < gate {
			t.Errorf("%s:%s writes a map before its cgroup gate", tc.file, tc.function)
		}
	}
}

func TestSocketTracepointsGateOnSocketOwner(t *testing.T) {
	text := bpfSource(t, "network.c")
	for _, fn := range []string{
		"tracepoint_inet_sock_set_state",
		"tracepoint_tcp_retransmit_skb",
		"tracepoint_net_dev_xmit",
	} {
		body := functionBody(t, text, fn)
		owner := strings.Index(body, "apply_sk_owner(")
		gate := strings.Index(body, "cgroup_allows(e->cgroup_id)")
		emit := strings.Index(body, "bpf_ringbuf_output(")
		if owner < 0 || gate < 0 || gate < owner || gate > emit {
			t.Errorf("%s must resolve the socket owner and drop untargeted owners before emitting", fn)
		}
		if strings.Contains(body, "capture_user_stack(") {
			t.Errorf("%s captures the user stack of whatever task softirq interrupted", fn)
		}
		if !strings.Contains(body, "socket_event_context(") {
			t.Errorf("%s must only keep stack and netns when current is the socket owner", fn)
		}
	}
	if strings.Contains(functionBody(t, text, "tracepoint_net_dev_xmit"), "apply_sk_owner(e, 0)") {
		t.Error("tracepoint_net_dev_xmit must resolve its owner from skb->sk")
	}
}

func TestClosedSocketForgetsItsOwnerBeforeTheGate(t *testing.T) {
	body := functionBody(t, bpfSource(t, "network.c"), "tracepoint_inet_sock_set_state")
	forget := strings.Index(body, "bpf_map_delete_elem(&sk_owner,")
	gate := strings.Index(body, "cgroup_allows(e->cgroup_id)")
	if forget < 0 {
		t.Fatal("a closed socket's owner must be forgotten, or the next socket at that address inherits it")
	}
	if gate >= 0 && forget > gate {
		t.Fatal("the owner must be forgotten before the target gate, also for untargeted sockets")
	}
	if !strings.Contains(body[:forget], "PT_TCP_CLOSE") {
		t.Fatal("the owner must be forgotten on the transition to TCP_CLOSE")
	}
}

func TestSocketEventsFallBackToTheSocketsOwnCgroup(t *testing.T) {
	text := bpfSource(t, "network.c")
	helper := functionBody(t, text, "sk_cgroup_id")
	for _, want := range []string{
		"bpf_core_field_exists(struct sock_cgroup_data, cgroup)",
		"sk_cgrp_data.cgroup",
		"sock_cgroup_data___old",
		"BPF_CORE_READ(cg, kn, id)",
	} {
		if !strings.Contains(helper, want) {
			t.Errorf("sk_cgroup_id lacks %q; both the 5.15+ and the older sock_cgroup_data layout must be read", want)
		}
	}
	apply := functionBody(t, text, "apply_sk_owner")
	if !strings.Contains(apply, "e->cgroup_id = sk_cgid;") {
		t.Error("an ownerless socket event (an accepted connection before its first read) must carry the socket's cgroup")
	}
	if !strings.Contains(apply, "o->cgroup_id != sk_cgid") {
		t.Error("an owner whose cgroup differs from the socket's is a leftover and must not be applied")
	}
}

func TestEncryptedDNSEmitsOncePerFlow(t *testing.T) {
	body := functionBody(t, bpfSource(t, "dns.c"), "emit_encrypted_dns")
	first := strings.Index(body, "encrypted_dns_first_seen(")
	reserve := strings.Index(body, "bpf_ringbuf_reserve(")
	if first < 0 || reserve < 0 || first > reserve {
		t.Fatal("emit_encrypted_dns must deduplicate by flow before reserving an event")
	}
	block, ok := mapBlock(bpfSource(t, "maps.h"), "encrypted_dns_seen")
	if !ok || !strings.Contains(block, "BPF_MAP_TYPE_LRU_HASH") {
		t.Fatal("encrypted_dns_seen must be an LRU map")
	}
	maps := bpfSource(t, "maps.h")
	keyAt := strings.Index(maps, "struct encrypted_dns_flow {")
	if keyAt < 0 {
		t.Fatal("struct encrypted_dns_flow not found in maps.h")
	}
	key, ok := braceBody(maps, keyAt)
	if !ok || !strings.Contains(key, "sport") {
		t.Fatal("the encrypted DNS flow key must include the source port so each connection counts once")
	}
}

func TestProcessCPUIsCountedPerProcessOnlyWhenEnabledAndTargeted(t *testing.T) {
	text := bpfSource(t, "cpu.c")
	acc := functionBody(t, text, "proc_cpu_accumulate")
	enabled := strings.Index(acc, "proc_cpu_enabled")
	gate := strings.Index(acc, "cgroup_allows(bpf_get_current_cgroup_id())")
	key := strings.Index(acc, "agent_ns_tgid()")
	if enabled < 0 || gate < 0 || key < 0 || enabled >= gate || gate >= key {
		t.Error("proc_cpu_accumulate must check its enable flag, then the target cgroup, then key by the agent-namespace process ID")
	}
	if !strings.Contains(functionBody(t, text, "tracepoint_sched_switch"), "proc_cpu_accumulate(on_cpu)") {
		t.Error("sched_switch must add each task's on-CPU time to its process")
	}
	block, ok := mapBlock(bpfSource(t, "maps.h"), "proc_cpu_ns")
	if !ok || !strings.Contains(block, "BPF_MAP_TYPE_LRU_HASH") {
		t.Error("proc_cpu_ns must be an LRU map so exited processes cannot fill it")
	}
}

func TestContainersCreatedUnderATargetedPodAreTracedFromTheStart(t *testing.T) {
	hook := functionBody(t, bpfSource(t, "resources.c"), "raw_tracepoint_cgroup_mkdir")
	for _, want := range []string{
		"BPF_CORE_READ(cgrp, self.parent, cgroup, kn, id)",
		"bpf_map_lookup_elem(&target_parent_cgroup_ids, &parent)",
		"bpf_map_update_elem(&inherited_cgroup_ids, &id, &parent",
	} {
		if !strings.Contains(hook, want) {
			t.Errorf("raw_tracepoint_cgroup_mkdir lacks %q", want)
		}
	}
	helpers := bpfSource(t, "helpers.h")
	if !strings.Contains(functionBody(t, helpers, "cgroup_targeted"), "inherited_cgroup_ids") {
		t.Error("cgroup_targeted must accept inherited container cgroups")
	}
	for _, file := range []string{"cpu.c", "http.c", "oncpu.c"} {
		if strings.Contains(bpfSource(t, file), "bpf_map_lookup_elem(&target_cgroup_ids") {
			t.Errorf("%s checks target_cgroup_ids directly and so ignores inherited container cgroups", file)
		}
	}
}
