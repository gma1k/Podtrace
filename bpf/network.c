// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

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
