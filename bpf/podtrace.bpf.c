// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_STRING_LEN 128

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
	EVENT_TCP_STATE,
	EVENT_PAGE_FAULT,
	EVENT_OOM_KILL,
	EVENT_UDP_SEND,
	EVENT_UDP_RECV,
	EVENT_HTTP_REQ,
	EVENT_HTTP_RESP,
};

struct event {
	u64 timestamp;
	u32 pid;
	u32 type;
	u64 latency_ns;
	s32 error;
	u64 bytes;
	u32 tcp_state;
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} socket_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} file_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} tcp_sockets SEC(".maps");

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
	
	for (int i = 0; i < 8 && idx < MAX_STRING_LEN - 10; i++) {
		if (i > 0) {
			buf[idx++] = ':';
		}
		u16 seg = (ipv6[i*2] << 8) | ipv6[i*2 + 1];
		u8 d1 = (seg >> 12) & 0xF;
		u8 d2 = (seg >> 8) & 0xF;
		u8 d3 = (seg >> 4) & 0xF;
		u8 d4 = seg & 0xF;
		
		if (d1 > 0) {
			buf[idx++] = d1 < 10 ? '0' + d1 : 'a' + (d1 - 10);
		}
		buf[idx++] = d2 < 10 ? '0' + d2 : 'a' + (d2 - 10);
		buf[idx++] = d3 < 10 ? '0' + d3 : 'a' + (d3 - 10);
		buf[idx++] = d4 < 10 ? '0' + d4 : 'a' + (d4 - 10);
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
	e.bytes = 0;
	e.tcp_state = 0;
	e.target[0] = '\0';
	
	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		u16 family;
		if (bpf_probe_read_user(&family, sizeof(family), uaddr) == 0) {
			if (family == 10) {
				struct {
					u16 sin6_family;
					u16 sin6_port;
				} addr;
				if (bpf_probe_read_user(&addr, sizeof(addr), uaddr) == 0) {
					u16 port = __builtin_bswap16(addr.sin6_port);
					e.target[0] = '[';
					e.target[1] = 'I';
					e.target[2] = 'P';
					e.target[3] = 'v';
					e.target[4] = '6';
					e.target[5] = ']';
					e.target[6] = ':';
					u32 idx = 7;
					if (port >= 10000) {
						e.target[idx++] = '0' + (port / 10000) % 10;
					}
					if (port >= 1000) {
						e.target[idx++] = '0' + (port / 1000) % 10;
					}
					if (port >= 100) {
						e.target[idx++] = '0' + (port / 100) % 10;
					}
					if (port >= 10) {
						e.target[idx++] = '0' + (port / 10) % 10;
					}
					e.target[idx++] = '0' + port % 10;
					e.target[idx] = '\0';
				}
			}
		}
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
	e.bytes = 0;
	e.tcp_state = 0;
	
	struct sockaddr_in addr;
	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		if (bpf_probe_read_user(&addr, sizeof(addr), uaddr) == 0) {
			if (addr.sin_family == 2) {
				u16 port = __builtin_bswap16(addr.sin_port);
				u32 ip_be;
				if (bpf_probe_read_user(&ip_be, sizeof(ip_be), &addr.sin_addr.s_addr) == 0) {
					u32 ip = __builtin_bswap32(ip_be);
					format_ip_port(ip, port, e.target);
				} else {
					e.target[0] = '\0';
				}
			} else {
				e.target[0] = '\0';
			}
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_TCP_SEND;
	e.latency_ns = calc_latency(*start_ts);
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	
	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), conn_ptr);
		bpf_map_delete_elem(&socket_conns, &key);
	} else {
		e.target[0] = '\0';
	}
	
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_TCP_RECV;
	e.latency_ns = calc_latency(*start_ts);
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	
	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), conn_ptr);
		bpf_map_delete_elem(&socket_conns, &key);
	} else {
		e.target[0] = '\0';
	}
	
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_READ;
	e.latency_ns = latency;
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e.target[0] = '\0';
	}
	
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_WRITE;
	e.latency_ns = latency;
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e.target[0] = '\0';
	}
	
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
	e.bytes = 0;
	e.tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e.target[0] = '\0';
	}
	
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
			if (block_time > 1000000) {
				struct event e = {};
				e.timestamp = timestamp;
				e.pid = prev_pid;
				e.type = EVENT_SCHED_SWITCH;
				e.latency_ns = block_time;
				e.error = 0;
				e.bytes = 0;
				e.tcp_state = 0;
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
	e.bytes = 0;
	e.tcp_state = 0;
	
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

SEC("tp/tcp/tcp_set_state")
int tracepoint_tcp_set_state(void *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		const void *skaddr;
		int oldstate;
		int newstate;
		__u16 sport;
		__u16 dport;
		__u32 saddr;
		__u32 daddr;
	} args_local;
	
	bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx);
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_TCP_STATE;
	e.latency_ns = 0;
	e.error = 0;
	e.bytes = 0;
	e.tcp_state = args_local.newstate;
	e.target[0] = '\0';
	
	u16 dport = __builtin_bswap16(args_local.dport);
	u32 daddr = __builtin_bswap32(args_local.daddr);
	
	if (daddr != 0) {
		format_ip_port(daddr, dport, e.target);
	}
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	return 0;
}

SEC("tp/exceptions/page_fault_user")
int tracepoint_page_fault_user(void *ctx) {
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		unsigned long address;
		unsigned int error_code;
	} args_local;
	
	bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx);
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = args_local.common_pid;
	e.type = EVENT_PAGE_FAULT;
	e.latency_ns = 0;
	e.error = args_local.error_code;
	e.bytes = 0;
	e.tcp_state = 0;
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	return 0;
}

SEC("tp/oom/oom_kill_process")
int tracepoint_oom_kill_process(void *ctx) {
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		char comm[16];
		u32 pid;
		u32 tid;
		u64 totalpages;
		u64 points;
		u64 victim_points;
		const char *constraint;
		u32 constraint_kind;
		u32 gfp_mask;
		int order;
	} args_local;
	
	bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx);
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = args_local.pid;
	e.type = EVENT_OOM_KILL;
	e.latency_ns = 0;
	e.error = 0;
	e.bytes = args_local.totalpages * 4096;
	e.tcp_state = 0;
	
	bpf_probe_read_kernel_str(e.target, sizeof(e.target), args_local.comm);
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe_udp_sendmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_UDP_SEND;
	e.latency_ns = calc_latency(*start_ts);
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_UDP_RECV;
	e.latency_ns = calc_latency(*start_ts);
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/http_request")
int uprobe_http_request(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	char *url = (char *)PT_REGS_PARM1(ctx);
	if (url) {
		char url_buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(url_buf, sizeof(url_buf), url);
		bpf_map_update_elem(&socket_conns, &key, url_buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/http_request")
int uretprobe_http_request(struct pt_regs *ctx) {
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
	e.type = EVENT_HTTP_REQ;
	e.latency_ns = calc_latency(*start_ts);
	e.error = 0;
	e.bytes = 0;
	e.tcp_state = 0;
	
	char *url_ptr = bpf_map_lookup_elem(&socket_conns, &key);
	if (url_ptr) {
		bpf_probe_read_kernel_str(e.target, sizeof(e.target), url_ptr);
		bpf_map_delete_elem(&socket_conns, &key);
	} else {
		e.target[0] = '\0';
	}
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/http_response")
int uprobe_http_response(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/http_response")
int uretprobe_http_response(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && ret < 10 * 1024 * 1024) {
		bytes = (u64)ret;
	}
	
	struct event e = {};
	e.timestamp = bpf_ktime_get_ns();
	e.pid = pid;
	e.type = EVENT_HTTP_RESP;
	e.latency_ns = calc_latency(*start_ts);
	e.error = ret < 0 ? ret : 0;
	e.bytes = bytes;
	e.tcp_state = 0;
	e.target[0] = '\0';
	
	bpf_ringbuf_output(&events, &e, sizeof(e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

