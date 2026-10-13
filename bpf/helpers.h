// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_HELPERS_H
#define PODTRACE_HELPERS_H

#include "common.h"
#include "maps.h"

#define PIDNS_MAX_LEVELS 8

static __noinline u32 task_ns_tgid(struct task_struct *task, u32 fallback)
{
	u32 init_tgid = fallback;
	u32 zero = 0;
	struct pidns_info *want = bpf_map_lookup_elem(&pidns_ref, &zero);
	if (!want || !want->ino)
		return init_tgid;

	if (!task)
		return 0;
	struct pid *tpid = BPF_CORE_READ(task, group_leader, thread_pid);
	if (!tpid)
		return 0;
	u32 level = BPF_CORE_READ(tpid, level);

#pragma unroll
	for (int i = 0; i < PIDNS_MAX_LEVELS; i++) {
		if ((u32)i > level)
			break;
		struct upid up;
		if (BPF_CORE_READ_INTO(&up, tpid, numbers[i]) != 0)
			break;
		if (up.ns && BPF_CORE_READ(up.ns, ns.inum) == (u32)want->ino)
			return (u32)up.nr;
	}
	return 0;
}

static __always_inline u32 agent_ns_tgid(void)
{
	return task_ns_tgid((struct task_struct *)bpf_get_current_task(),
			    bpf_get_current_pid_tgid() >> 32);
}

static inline u64 get_key(u32 pid, u32 tid) {
	return ((u64)pid << 32) | tid;
}

static __always_inline u64 mix64(u64 h)
{
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

static __always_inline u64 process_scoped_id(u64 ptr)
{
	if (!ptr)
		return 0;
	u64 tgid = bpf_get_current_pid_tgid() >> 32;
	u64 h = mix64(ptr ^ (tgid * 0x9e3779b97f4a7c15ULL));
	return h ? h : 1;
}

static inline struct pair_key make_pair_key(u32 pair) {
	struct pair_key k = {};
	k.pid_tgid = bpf_get_current_pid_tgid();
	k.pair = pair;
	return k;
}

#define TCP_PEER_MAX_AGE_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)

static inline struct tcp_peer *fresh_tcp_peer(struct pair_key *k, u64 now) {
	struct tcp_peer *p = bpf_map_lookup_elem(&tcp_peer_stash, k);
	if (p && now >= p->stash_ns && now - p->stash_ns < TCP_PEER_MAX_AGE_NS)
		return p;
	return NULL;
}

static inline struct tcp_peer *lookup_tcp_peer(u32 prefer_pair) {
	u64 now = bpf_ktime_get_ns();
	struct pair_key k = {};
	k.pid_tgid = bpf_get_current_pid_tgid();
	k.pair = prefer_pair;
	struct tcp_peer *p = fresh_tcp_peer(&k, now);
	if (p)
		return p;
	if (prefer_pair == PAIR_UDP_SENDMSG || prefer_pair == PAIR_UDP_RECVMSG)
		return NULL;
	k.pair = (prefer_pair == PAIR_TCP_SENDMSG) ? PAIR_TCP_RECVMSG : PAIR_TCP_SENDMSG;
	return fresh_tcp_peer(&k, now);
}

static inline void fill_event_peer_pref(struct event *e, u32 prefer_pair) {
	struct tcp_peer *p = lookup_tcp_peer(prefer_pair);
	if (!p)
		return;
	e->peer_family = (u8)p->family;
	e->peer_sport = p->sport;
	e->peer_dport = p->dport;
	e->peer_saddr = p->saddr;
	e->peer_daddr = p->daddr;
	__builtin_memcpy(e->peer_saddr6, p->saddr6, 16);
	__builtin_memcpy(e->peer_daddr6, p->daddr6, 16);
}

static inline void fill_event_peer(struct event *e) {
	struct tcp_peer *p = lookup_tcp_peer(PAIR_TCP_SENDMSG);
	if (!p)
		return;
	e->peer_family = (u8)p->family;
	e->peer_sport = p->sport;
	e->peer_dport = p->dport;
	e->peer_saddr = p->saddr;
	e->peer_daddr = p->daddr;
	__builtin_memcpy(e->peer_saddr6, p->saddr6, 16);
	__builtin_memcpy(e->peer_daddr6, p->daddr6, 16);
}

static inline void fill_h2_record_peer(struct h2_hdr_record *rec, u32 dir) {
	u32 prefer = (dir == H2_DIR_EGRESS) ? PAIR_TCP_SENDMSG : PAIR_TCP_RECVMSG;
	struct tcp_peer *p = lookup_tcp_peer(prefer);
	if (!p)
		return;
	rec->peer_family = (u8)p->family;
	rec->peer_sport = p->sport;
	rec->peer_dport = p->dport;
	rec->peer_saddr = p->saddr;
	rec->peer_daddr = p->daddr;
	__builtin_memcpy(rec->peer_saddr6, p->saddr6, 16);
	__builtin_memcpy(rec->peer_daddr6, p->daddr6, 16);
}

static inline void record_start_time(const struct pair_key *key) {
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, key, &ts, BPF_ANY);
}

static __always_inline u64 request_id_now(void) {
	return (bpf_ktime_get_ns() & ~0xFFULL) | (bpf_get_smp_processor_id() & 0xFF);
}

static inline u64 calc_latency(u64 start) {
	u64 now = bpf_ktime_get_ns();
	return now > start ? now - start : 0;
}

static __attribute__((noinline)) u32 append_dec(char *buf, u32 idx, u32 max_idx, u32 val) {
	u32 divisor = 10000;
	int started = 0;
	for (int i = 0; i < 5; i++) {
		u32 digit = (val / divisor) % 10;
		if (digit != 0 || started || i == 4) {
			if (idx < max_idx) buf[idx++] = '0' + digit;
			started = 1;
		}
		if (divisor > 1)
			divisor /= 10;
	}
	return idx;
}

static inline void format_ip_port(u32 ip, u16 port, char *buf) {
	u8 a = (ip >> 24) & 0xFF;
	u8 b = (ip >> 16) & 0xFF;
	u8 c = (ip >> 8) & 0xFF;
	u8 d = ip & 0xFF;
	u32 idx = 0;
	u32 max_idx = MAX_STRING_LEN - 1;

	idx = append_dec(buf, idx, max_idx, a);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, b);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, c);
	if (idx < max_idx) buf[idx++] = '.';
	idx = append_dec(buf, idx, max_idx, d);
	if (idx < max_idx) buf[idx++] = ':';
	idx = append_dec(buf, idx, max_idx, port);
	buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
}

static inline void format_ipv6_port(const u8 *ipv6, u16 port, char *buf) {
	u16 p = port;
	u32 idx = 0;
	u32 max_idx = MAX_STRING_LEN - 1;
	u32 port_start_limit = MAX_STRING_LEN - 6;
	
	for (int i = 0; i < 8 && idx < port_start_limit; i++) {
		if (i > 0 && idx < max_idx) {
			buf[idx++] = ':';
		}
		if (idx >= max_idx) break;
		u16 seg = (ipv6[i*2] << 8) | ipv6[i*2 + 1];
		u8 d1 = (seg >> 12) & 0xF;
		u8 d2 = (seg >> 8) & 0xF;
		u8 d3 = (seg >> 4) & 0xF;
		u8 d4 = seg & 0xF;
		
		if (d1 > 0 && idx < max_idx) {
			buf[idx++] = d1 < 10 ? '0' + d1 : 'a' + (d1 - 10);
		}
		if (idx < max_idx) buf[idx++] = d2 < 10 ? '0' + d2 : 'a' + (d2 - 10);
		if (idx < max_idx) buf[idx++] = d3 < 10 ? '0' + d3 : 'a' + (d3 - 10);
		if (idx < max_idx) buf[idx++] = d4 < 10 ? '0' + d4 : 'a' + (d4 - 10);
	}
	
	if (idx < port_start_limit) {
		if (idx < max_idx) buf[idx++] = ':';
		idx = append_dec(buf, idx, max_idx, p);
	}
	buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
}

static inline u64 build_stack_key(u32 pid, u32 tid, u64 timestamp) {
	u64 h = (((u64)pid << 32) | tid) ^ timestamp;
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}

static inline struct event *get_event_buf_unfiltered(void) {
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&event_buf, &zero);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(&e->comm, sizeof(e->comm));

		struct task_struct *__task = (struct task_struct *)bpf_get_current_task();
		if (__task) {
			e->net_ns_id = BPF_CORE_READ(__task, nsproxy, net_ns, ns.inum);
		}
	}
	return e;
}

static __always_inline int cgroup_targeted(u64 cgid) {
	return bpf_map_lookup_elem(&target_cgroup_ids, &cgid) != NULL ||
	       bpf_map_lookup_elem(&inherited_cgroup_ids, &cgid) != NULL;
}

static inline int cgroup_allows(u64 cgid) {
	u32 zero = 0;
	u32 *enabled = bpf_map_lookup_elem(&cgroup_filter_enabled, &zero);
	if (!enabled || !*enabled) {
		return 1;
	}
	return cgroup_targeted(cgid);
}

__noinline u64 podtrace_current_request(void);

static inline struct event *get_event_buf(void) {
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return NULL;
	}

	if (!cgroup_allows(e->cgroup_id)) {
		return NULL;
	}
	e->correlation_id = podtrace_current_request();
	return e;
}

static inline void capture_user_stack(void *ctx, u32 pid, u32 tid, struct event *e) {
	if (!e) {
		return;
	}
	u32 zero = 0;
	struct stack_trace_t *trace = bpf_map_lookup_elem(&stack_buf, &zero);
	if (!trace) {
		e->stack_key = 0;
		return;
	}
	trace->nr = 0;
	int sz = bpf_get_stack(ctx, trace->ips, sizeof(trace->ips), BPF_F_USER_STACK);
	if (sz <= 0) {
		e->stack_key = 0;
		return;
	}
	u32 max_frames = sizeof(trace->ips) / sizeof(u64);
	u32 nr_frames = (u32)(sz / sizeof(u64));
	trace->nr = nr_frames > max_frames ? max_frames : nr_frames;
	u64 key = build_stack_key(pid, tid, e->timestamp);
	bpf_map_update_elem(&stack_traces, &key, trace, BPF_ANY);
	e->stack_key = key;
}

static __always_inline s32 http_parse_status3(const char *s)
{
	if (s[0] < '0' || s[0] > '9' ||
	    s[1] < '0' || s[1] > '9' ||
	    s[2] < '0' || s[2] > '9')
		return -1;
	return (s32)((s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0'));
}

#endif
