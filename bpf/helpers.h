// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_HELPERS_H
#define PODTRACE_HELPERS_H

#include "common.h"
#include "maps.h"

static inline u64 get_key(u32 pid, u32 tid) {
	return ((u64)pid << 32) | tid;
}

static inline u64 calc_latency(u64 start) {
	u64 now = bpf_ktime_get_ns();
	return now > start ? now - start : 0;
}

static inline void format_ip_port(u32 ip, u16 port, char *buf) {
	u8 a = (ip >> 24) & 0xFF;
	u8 b = (ip >> 16) & 0xFF;
	u8 c = (ip >> 8) & 0xFF;
	u8 d = ip & 0xFF;
	u16 p = port;
	u32 idx = 0;
	u32 max_idx = MAX_STRING_LEN - 1;
	
	if (idx < max_idx) buf[idx++] = '0' + (a / 100) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (a / 10) % 10;
	if (idx < max_idx) buf[idx++] = '0' + a % 10;
	if (idx < max_idx) buf[idx++] = '.';
	if (idx < max_idx) buf[idx++] = '0' + (b / 100) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (b / 10) % 10;
	if (idx < max_idx) buf[idx++] = '0' + b % 10;
	if (idx < max_idx) buf[idx++] = '.';
	if (idx < max_idx) buf[idx++] = '0' + (c / 100) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (c / 10) % 10;
	if (idx < max_idx) buf[idx++] = '0' + c % 10;
	if (idx < max_idx) buf[idx++] = '.';
	if (idx < max_idx) buf[idx++] = '0' + (d / 100) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (d / 10) % 10;
	if (idx < max_idx) buf[idx++] = '0' + d % 10;
	if (idx < max_idx) buf[idx++] = ':';
	if (idx < max_idx) buf[idx++] = '0' + (p / 10000) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (p / 1000) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (p / 100) % 10;
	if (idx < max_idx) buf[idx++] = '0' + (p / 10) % 10;
	if (idx < max_idx) buf[idx++] = '0' + p % 10;
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
		if (idx < max_idx) buf[idx++] = '0' + (p / 10000) % 10;
		if (idx < max_idx) buf[idx++] = '0' + (p / 1000) % 10;
		if (idx < max_idx) buf[idx++] = '0' + (p / 100) % 10;
		if (idx < max_idx) buf[idx++] = '0' + (p / 10) % 10;
		if (idx < max_idx) buf[idx++] = '0' + p % 10;
	}
	buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
}

static inline u64 build_stack_key(u32 pid, u32 tid, u64 timestamp) {
	u64 base = ((u64)pid << 32) | tid;
	return base ^ timestamp;
}

static inline struct event *get_event_buf(void) {
	u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&event_buf, &zero);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
	}
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

#endif
