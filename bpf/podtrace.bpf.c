// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_STRING_LEN 64

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

enum event_type {
	EVENT_DNS,
	EVENT_CONNECT,
	EVENT_TCP_SEND,
	EVENT_TCP_RECV,
	EVENT_WRITE,
	EVENT_READ,
	EVENT_FSYNC,
	EVENT_SCHED_SWITCH,
};

struct event {
	u64 timestamp;
	u32 pid;
	u32 type;
	u64 latency_ns;
	s32 error;
	char target[MAX_STRING_LEN];
	char details[MAX_STRING_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} dns_targets SEC(".maps");

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
	
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (a / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (a / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + a % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (b / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (b / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + b % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (c / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (c / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + c % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (d / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (d / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + d % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = ':';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 10000) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 1000) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + p % 10;
	if (idx < MAX_STRING_LEN) buf[idx] = '\0';
}

static inline void format_ipv6_port(const u8 *ipv6, u16 port, char *buf) {
	u16 p = port;
	u32 idx = 0;
	
	for (int i = 0; i < 8; i++) {
		u16 segment = (ipv6[i*2] << 8) | ipv6[i*2 + 1];
		if (segment == 0 && i > 0 && i < 7) {
			if (idx < MAX_STRING_LEN - 10) {
				buf[idx++] = ':';
			}
		} else {
			if (i > 0 && idx < MAX_STRING_LEN - 10) {
				buf[idx++] = ':';
			}
			u8 high = (segment >> 12) & 0xF;
			u8 low = (segment >> 8) & 0xF;
			u8 high2 = (segment >> 4) & 0xF;
			u8 low2 = segment & 0xF;
			
			if (high > 0 || i == 0) {
				if (idx < MAX_STRING_LEN - 10) {
					buf[idx++] = high < 10 ? '0' + high : 'a' + (high - 10);
				}
			}
			if (idx < MAX_STRING_LEN - 10) {
				buf[idx++] = low < 10 ? '0' + low : 'a' + (low - 10);
				buf[idx++] = high2 < 10 ? '0' + high2 : 'a' + (high2 - 10);
				buf[idx++] = low2 < 10 ? '0' + low2 : 'a' + (low2 - 10);
			}
		}
	}
	
	if (idx < MAX_STRING_LEN - 6) {
		buf[idx++] = ':';
		buf[idx++] = '0' + (p / 10000) % 10;
		buf[idx++] = '0' + (p / 1000) % 10;
		buf[idx++] = '0' + (p / 100) % 10;
		buf[idx++] = '0' + (p / 10) % 10;
		buf[idx++] = '0' + p % 10;
	}
	buf[idx] = '\0';
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

struct sockaddr_in6_simple {
	u16 sin6_family;
	u16 sin6_port;
	u32 sin6_flowinfo;
	u8 sin6_addr[16];
	u32 sin6_scope_id;
};

SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_CONNECT;
	e.latency_ns = calc_latency(*start_ts);
	e.error = PT_REGS_RC(ctx);
	
	struct sockaddr_in6_simple addr;
	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		bpf_probe_read_user(&addr, sizeof(addr), uaddr);
		if (addr.sin6_family == 10) { // AF_INET6
			u16 port = __builtin_bswap16(addr.sin6_port);
			format_ipv6_port(addr.sin6_addr, port, e.target);
		} else {
			e.target[0] = '\0';
		}
	} else {
		e.target[0] = '\0';
	}
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_CONNECT;
	e.latency_ns = calc_latency(*start_ts);
	e.error = PT_REGS_RC(ctx);
	
	struct sockaddr_in addr;
	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		bpf_probe_read_user(&addr, sizeof(addr), uaddr);
		if (addr.sin_family == 2) { // AF_INET
			u16 port = __builtin_bswap16(addr.sin_port);
			u32 ip_be;
			bpf_probe_read_user(&ip_be, sizeof(ip_be), &addr.sin_addr.s_addr);
			u32 ip = __builtin_bswap32(ip_be);
			format_ip_port(ip, port, e.target);
		} else {
			e.target[0] = '\0';
		}
	} else {
		e.target[0] = '\0';
	}
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_TCP_SEND;
	e.latency_ns = calc_latency(*start_ts);
	e.error = PT_REGS_RC(ctx);
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_TCP_RECV;
	e.latency_ns = calc_latency(*start_ts);
	e.error = PT_REGS_RC(ctx);
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	if (latency < 1000000) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_READ;
	e.latency_ns = latency;
	e.error = PT_REGS_RC(ctx);
	e.target[0] = '\0';
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/vfs_write")
int kretprobe_vfs_write(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	if (latency < 1000000) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_WRITE;
	e.latency_ns = latency;
	e.error = PT_REGS_RC(ctx);
	e.target[0] = '\0';
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/vfs_fsync")
int kprobe_vfs_fsync(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/vfs_fsync")
int kretprobe_vfs_fsync(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	if (latency < 1000000) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_FSYNC;
	e.latency_ns = latency;
	e.error = PT_REGS_RC(ctx);
	e.target[0] = '\0';
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(void *ctx) {
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		char prev_comm[16];
		u32 prev_pid;
		int prev_prio;
		long prev_state;
		char next_comm[16];
		u32 next_pid;
		int next_prio;
	} *args = (typeof(args))ctx;
	
	u32 prev_pid = args->prev_pid;
	u32 next_pid = args->next_pid;
	u64 timestamp = bpf_ktime_get_ns();
	
	if (prev_pid > 0) {
		u64 key = get_key(prev_pid, 0);
		u64 *block_start = bpf_map_lookup_elem(&start_times, &key);
		
		if (block_start) {
			u64 block_time = calc_latency(*block_start);
			if (block_time > 1000000) { // Only track blocks > 1ms
				struct event e = {};
				e.timestamp = timestamp;
				e.pid = prev_pid;
				e.type = EVENT_SCHED_SWITCH;
				e.latency_ns = block_time;
				e.error = 0;
				e.target[0] = '\0';
				e.details[0] = '\0';
				
				bpf_ringbuf_output(&events, &e, sizeof(e), 0);
			}
			bpf_map_delete_elem(&start_times, &key);
		}
	}
	
	if (next_pid > 0) {
		u64 new_key = get_key(next_pid, 0);
		u64 now = bpf_ktime_get_ns();
		bpf_map_update_elem(&start_times, &new_key, &now, BPF_ANY);
	}
	
	return 0;
}

SEC("uprobe/getaddrinfo")
int uprobe_getaddrinfo(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	void *node_ptr = (void *)PT_REGS_PARM1(ctx);
	if (node_ptr) {
		char target[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(target, sizeof(target), node_ptr);
		bpf_map_update_elem(&dns_targets, &key, target, BPF_ANY);
	}
	
	return 0;
}

SEC("uretprobe/getaddrinfo")
int uretprobe_getaddrinfo(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_DNS;
	e.latency_ns = latency;
	
	s64 ret = PT_REGS_RC(ctx);
	if (ret == 0) {
		e.error = 0;
	} else {
		e.error = ret;
	}
	
	char *target_ptr = bpf_map_lookup_elem(&dns_targets, &key);
	if (target_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), target_ptr);
		bpf_map_delete_elem(&dns_targets, &key);
	} else {
		e.target[0] = '\0';
	}
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

