// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

static __noinline void stash_tcp_peer(struct pt_regs *ctx, u32 pair)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return;
	u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (dport_be == 0)
		return;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	char buf[MAX_STRING_LEN] = {};
	struct tcp_peer peer = {};
	peer.family = family;
	peer.dport = __builtin_bswap16(dport_be);
	peer.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (family == AF_INET) {
		u32 daddr_be = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		if (daddr_be == 0)
			return;
		peer.daddr = __builtin_bswap32(daddr_be);
		peer.saddr = __builtin_bswap32(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
		format_ip_port(peer.daddr, peer.dport, buf);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&peer.daddr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&peer.saddr6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		format_ipv6_port(peer.daddr6, peer.dport, buf);
	} else {
		return;
	}
	peer.stash_ns = bpf_ktime_get_ns();
	struct pair_key key = make_pair_key(pair);
	bpf_map_update_elem(&tcp_target, &key, buf, BPF_ANY);
	bpf_map_update_elem(&tcp_peer_stash, &key, &peer, BPF_ANY);
}

static __always_inline void stash_sk_owner(struct pt_regs *ctx)
{
	u64 sk = (u64)PT_REGS_PARM1(ctx);
	if (!sk)
		return;
	struct sk_owner o = {};
	o.cgroup_id = bpf_get_current_cgroup_id();
	o.pid = agent_ns_tgid();
	bpf_get_current_comm(&o.comm, sizeof(o.comm));
	bpf_map_update_elem(&sk_owner, &sk, &o, BPF_ANY);
}

struct sock_cgroup_data___old {
	u64 val;
} __attribute__((preserve_access_index));

static __always_inline u64 sk_cgroup_id(u64 skaddr)
{
	if (!skaddr)
		return 0;
	struct sock *sk = (struct sock *)skaddr;
	struct cgroup *cg = NULL;
	if (bpf_core_field_exists(struct sock_cgroup_data, cgroup)) {
		cg = BPF_CORE_READ(sk, sk_cgrp_data.cgroup);
	} else {
		struct sock_cgroup_data___old *d =
			(struct sock_cgroup_data___old *)&sk->sk_cgrp_data;
		u64 val = BPF_CORE_READ(d, val);
		if (val & 1)
			return 0;
		cg = (struct cgroup *)val;
	}
	if (!cg)
		return 0;
	return BPF_CORE_READ(cg, kn, id);
}

static __always_inline void apply_sk_owner(struct event *e, u64 skaddr)
{
	struct sk_owner *o = skaddr ? bpf_map_lookup_elem(&sk_owner, &skaddr) : NULL;
	u64 sk_cgid = sk_cgroup_id(skaddr);
	if (o && sk_cgid && o->cgroup_id != sk_cgid)
		o = NULL;
	if (o) {
		e->pid = o->pid;
		e->cgroup_id = o->cgroup_id;
		__builtin_memcpy(e->comm, o->comm, COMM_LEN);
	} else {
		e->pid = 0;
		e->cgroup_id = sk_cgid;
		__builtin_memset(e->comm, 0, COMM_LEN);
	}
}

static __always_inline void socket_event_context(void *ctx, struct event *e, u32 cur_pid)
{
	if (e->pid && e->pid == cur_pid) {
		capture_user_stack(ctx, cur_pid, 0, e);
		return;
	}
	e->stack_key = 0;
	e->net_ns_id = 0;
}

static __always_inline void drop_pair_sidemaps(struct pair_key *key)
{
	bpf_map_delete_elem(&start_times, key);
	bpf_map_delete_elem(&tcp_target, key);
	bpf_map_delete_elem(&connect_addrs, key);
	bpf_map_delete_elem(&dns_targets, key);
	bpf_map_delete_elem(&db_queries, key);
}

static __noinline int peer_from_msghdr(struct msghdr *msg, struct tcp_peer *peer);

static __noinline int peer_from_connected_sock(struct sock *sk, struct tcp_peer *peer)
{
	if (!sk || !peer)
		return 0;
	u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (dport_be == 0)
		return 0;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		u32 daddr_be = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		if (daddr_be == 0)
			return 0;
		peer->family = family;
		peer->dport = __builtin_bswap16(dport_be);
		peer->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		peer->daddr = __builtin_bswap32(daddr_be);
		peer->saddr = __builtin_bswap32(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
		return 1;
	}
	if (family == AF_INET6) {
		peer->family = family;
		peer->dport = __builtin_bswap16(dport_be);
		peer->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
		BPF_CORE_READ_INTO(&peer->daddr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&peer->saddr6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		return 1;
	}
	return 0;
}

static __noinline void stash_udp_peer(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_UDP_SENDMSG);
	struct tcp_peer peer = {};

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (peer_from_connected_sock(sk, &peer)) {
		peer.stash_ns = bpf_ktime_get_ns();
		bpf_map_update_elem(&tcp_peer_stash, &key, &peer, BPF_ANY);
		return;
	}

	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	if (!peer_from_msghdr(msg, &peer))
		return;
	peer.sport = sk ? BPF_CORE_READ(sk, __sk_common.skc_num) : 0;
	peer.stash_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&tcp_peer_stash, &key, &peer, BPF_ANY);
}

static __noinline int peer_from_msghdr(struct msghdr *msg, struct tcp_peer *peer)
{
	if (!msg || !peer)
		return 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (!name)
		return 0;

	u16 family = 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), name) != 0)
		return 0;

	if (family == AF_INET) {
		struct {
			u16 sin_family;
			u16 sin_port;
			u32 sin_addr;
		} sa4;
		if (bpf_probe_read_kernel(&sa4, sizeof(sa4), name) != 0)
			return 0;
		if (sa4.sin_addr == 0 || sa4.sin_port == 0)
			return 0;
		peer->family = AF_INET;
		peer->dport = __builtin_bswap16(sa4.sin_port);
		peer->daddr = __builtin_bswap32(sa4.sin_addr);
	} else if (family == AF_INET6) {
		struct {
			u16 sin6_family;
			u16 sin6_port;
			u32 sin6_flowinfo;
			u8  sin6_addr[16];
		} sa6;
		if (bpf_probe_read_kernel(&sa6, sizeof(sa6), name) != 0)
			return 0;
		if (sa6.sin6_port == 0)
			return 0;
		peer->family = AF_INET6;
		peer->dport = __builtin_bswap16(sa6.sin6_port);
		__builtin_memcpy(peer->daddr6, sa6.sin6_addr, 16);
	} else {
		return 0;
	}
	return 1;
}

static __noinline void stash_udp_recv_peer(void)
{
	struct pair_key key = make_pair_key(PAIR_UDP_RECVMSG);
	u64 *saved = bpf_map_lookup_elem(&udp_recv_msghdr, &key);
	if (!saved)
		return;
	struct msghdr *msg = (struct msghdr *)*saved;
	bpf_map_delete_elem(&udp_recv_msghdr, &key);

	struct tcp_peer peer = {};
	if (!peer_from_msghdr(msg, &peer))
		return;
	peer.stash_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&tcp_peer_stash, &key, &peer, BPF_ANY);
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V4);
	record_start_time(&key);
	stash_sk_owner(ctx);

	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		struct sockaddr_in sa;
		if (bpf_probe_read_kernel(&sa, sizeof(sa), uaddr) == 0 &&
		    sa.sin_family == AF_INET) {
			struct connect_addr ca = {};
			ca.family = AF_INET;
			ca.port_be = sa.sin_port;
			ca.addr_be = sa.sin_addr.s_addr;
			bpf_map_update_elem(&connect_addrs, &key, &ca, BPF_ANY);
		}
	}
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V6);
	record_start_time(&key);
	stash_sk_owner(ctx);

	void *uaddr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr) {
		struct {
			u16 sin6_family;
			u16 sin6_port;
			u32 sin6_flowinfo;
			u8  sin6_addr[16];
			u32 sin6_scope_id;
		} sa6;
		if (bpf_probe_read_kernel(&sa6, sizeof(sa6), uaddr) == 0 &&
		    sa6.sin6_family == AF_INET6) {
			struct connect_addr ca = {};
			ca.family = AF_INET6;
			ca.port_be = sa6.sin6_port;
			__builtin_memcpy(ca.addr6, sa6.sin6_addr, 16);
			bpf_map_update_elem(&connect_addrs, &key, &ca, BPF_ANY);
		}
	}
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V6);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_CONNECT;
	e->latency_ns = calc_latency(*start_ts);
	e->error = PT_REGS_RC(ctx);
	e->bytes = 0;
	e->tcp_state = (e->error == -101 || e->error == -97) ? 1 : 0;
	e->target[0] = '\0';
	e->details[0] = '\0';

	struct connect_addr *ca = bpf_map_lookup_elem(&connect_addrs, &key);
	if (ca && ca->family == AF_INET6) {
		u16 port = __builtin_bswap16(ca->port_be);
		format_ipv6_port(ca->addr6, port, e->target);
		struct dns_v6key k6 = { .cgroup_id = bpf_get_current_cgroup_id() };
		__builtin_memcpy(k6.addr, ca->addr6, 16);
		char *resolved = bpf_map_lookup_elem(&dns_resolved6, &k6);
		if (resolved) {
			__builtin_memcpy(e->details, resolved, MAX_STRING_LEN);
		}
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&connect_addrs, &key);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_connect(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_CONNECT_V4);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_CONNECT;
	e->latency_ns = calc_latency(*start_ts);
	e->error = PT_REGS_RC(ctx);
	e->bytes = 0;
	e->tcp_state = (e->error == -101 || e->error == -97) ? 1 : 0;
	e->target[0] = '\0';
	e->details[0] = '\0';

	struct connect_addr *ca = bpf_map_lookup_elem(&connect_addrs, &key);
	if (ca && ca->family == AF_INET) {
		u16 port = __builtin_bswap16(ca->port_be);
		u32 ip = __builtin_bswap32(ca->addr_be);
		format_ip_port(ip, port, e->target);
		struct dns_resolved_key rk = { .cgroup_id = bpf_get_current_cgroup_id(), .ip = ca->addr_be };
		char *resolved = bpf_map_lookup_elem(&dns_resolved, &rk);
		if (resolved) {
			__builtin_memcpy(e->details, resolved, MAX_STRING_LEN);
		}
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&connect_addrs, &key);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_TCP_SENDMSG);
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	stash_tcp_peer(ctx, PAIR_TCP_SENDMSG);
	stash_sk_owner(ctx);
	return 0;
}

static __always_inline int tcp_sendmsg_return(void *ctx, long rc)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_SENDMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	u64 conn_key = get_key(pid, tid);

	if (!start_ts) {
		drop_pair_sidemaps(&key);
		bpf_map_delete_elem(&grpc_methods, &conn_key);
		return 0;
	}

	s64 ret = (int)rc;
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}

	u64 latency_ns = calc_latency(*start_ts);

	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		bpf_map_delete_elem(&grpc_methods, &conn_key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_SEND;
	e->latency_ns = latency_ns;
	e->error = SOCKET_ERROR(ret);
	e->bytes = bytes;
	e->tcp_state = 0;

	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), conn_ptr);
	} else {
		char *peer = bpf_map_lookup_elem(&tcp_target, &key);
		if (peer) {
			bpf_probe_read_kernel_str(e->target, sizeof(e->target), peer);
		} else {
			e->target[0] = '\0';
		}
	}
	bpf_map_delete_elem(&tcp_target, &key);
	fill_event_peer_pref(e, PAIR_TCP_SENDMSG);
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);

	char *grpc_method_ptr = bpf_map_lookup_elem(&grpc_methods, &conn_key);
	if (grpc_method_ptr) {
		struct event *eg = get_event_buf();
		if (eg) {
			eg->timestamp  = bpf_ktime_get_ns();
			eg->pid        = pid;
			eg->type       = EVENT_GRPC_METHOD;
			eg->latency_ns = latency_ns;
			eg->error      = ret < 0 ? (s32)ret : 0;
			eg->bytes      = bytes;
			eg->tcp_state  = 0;
			eg->details[0] = '\0';
			bpf_probe_read_kernel_str(eg->target, sizeof(eg->target), grpc_method_ptr);
			capture_user_stack(ctx, pid, tid, eg);
			bpf_ringbuf_output(&events, eg, sizeof(*eg), 0);
		}
		bpf_map_delete_elem(&grpc_methods, &conn_key);
	}

	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx)
{
	long rc = PT_REGS_RC(ctx);
	return tcp_sendmsg_return(ctx, rc);
}

SEC("fexit/tcp_sendmsg")
int fexit_tcp_sendmsg(u64 *ctx)
{
	u64 rc = 0;
	bpf_get_func_ret(ctx, &rc);
	return tcp_sendmsg_return(ctx, (long)rc);
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_TCP_RECVMSG);
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	stash_tcp_peer(ctx, PAIR_TCP_RECVMSG);
	stash_sk_owner(ctx);
	return 0;
}

static __always_inline int tcp_recvmsg_return(void *ctx, long rc)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_TCP_RECVMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	s64 ret = (int)rc;
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TCP_RECV;
	e->latency_ns = calc_latency(*start_ts);
	e->error = SOCKET_ERROR(ret);
	e->bytes = bytes;
	e->tcp_state = 0;

	u64 conn_key = get_key(pid, tid);
	char *conn_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (conn_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), conn_ptr);
	} else {
		char *peer = bpf_map_lookup_elem(&tcp_target, &key);
		if (peer) {
			bpf_probe_read_kernel_str(e->target, sizeof(e->target), peer);
		} else {
			e->target[0] = '\0';
		}
	}
	bpf_map_delete_elem(&tcp_target, &key);
	fill_event_peer_pref(e, PAIR_TCP_RECVMSG);
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx)
{
	long rc = PT_REGS_RC(ctx);
	return tcp_recvmsg_return(ctx, rc);
}

SEC("fexit/tcp_recvmsg")
int fexit_tcp_recvmsg(u64 *ctx)
{
	u64 rc = 0;
	bpf_get_func_ret(ctx, &rc);
	return tcp_recvmsg_return(ctx, (long)rc);
}

struct hostent_call {
	u64 result;
	u64 h_errnop;
	u32 depth;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, struct hostent_call);
} hostent_calls SEC(".maps");

#define HOST_NOT_FOUND 1
#define TRY_AGAIN      2
#define NO_RECOVERY    3
#define NO_DATA        4
#define EAI_FAIL       -4
#define ERANGE_ERRNO   34

static __always_inline int hostent_enter(u64 name, u64 result, u64 h_errnop)
{
	struct pair_key key = make_pair_key(PAIR_GETHOSTBYNAME);
	struct hostent_call *outer = bpf_map_lookup_elem(&hostent_calls, &key);
	if (outer) {
		outer->depth++;
		return 0;
	}
	struct hostent_call call = { .result = result, .h_errnop = h_errnop, .depth = 1 };
	bpf_map_update_elem(&hostent_calls, &key, &call, BPF_ANY);

	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	if (name) {
		char target[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(target, sizeof(target), (void *)name);
		bpf_map_update_elem(&dns_targets, &key, target, BPF_ANY);
	}
	return 0;
}

static __always_inline s32 hostent_error(u64 entry, s32 h_errno)
{
	if (entry)
		return 0;
	switch (h_errno) {
	case HOST_NOT_FOUND:
		return EAI_NONAME;
	case TRY_AGAIN:
		return EAI_AGAIN;
	case NO_DATA:
		return EAI_NODATA;
	default:
		return EAI_FAIL;
	}
}

static __always_inline int hostent_exit(struct pt_regs *ctx, s32 ret)
{
	struct pair_key key = make_pair_key(PAIR_GETHOSTBYNAME);
	struct hostent_call *call = bpf_map_lookup_elem(&hostent_calls, &key);
	if (!call)
		return 0;
	if (call->depth > 1) {
		call->depth--;
		return 0;
	}
	u64 result = call->result;
	u64 h_errnop = call->h_errnop;
	bpf_map_delete_elem(&hostent_calls, &key);

	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts || ret == ERANGE_ERRNO) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	u64 latency = calc_latency(*start_ts);

	u64 entry = 0;
	s32 h_errno = 0;
	if (result)
		bpf_probe_read_user(&entry, sizeof(entry), (void *)result);
	if (h_errnop)
		bpf_probe_read_user(&h_errno, sizeof(h_errno), (void *)h_errnop);

	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = agent_ns_tgid();
	e->type = EVENT_DNS;
	e->latency_ns = latency;
	e->dns_transport = DNS_SOURCE_LIBC;
	e->error = hostent_error(entry, h_errno);

	char *target = bpf_map_lookup_elem(&dns_targets, &key);
	if (target)
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), target);
	capture_user_stack(ctx, e->pid, (u32)bpf_get_current_pid_tgid(), e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	drop_pair_sidemaps(&key);
	return 0;
}

SEC("uprobe/gethostbyname_r")
int uprobe_gethostbyname_r(struct pt_regs *ctx) {
#if defined(__TARGET_ARCH_arm64)
	u64 h_errnop = ctx->regs[5];
#else
	u64 h_errnop = ctx->r9;
#endif
	u64 name = PT_REGS_PARM1(ctx);
	u64 result = PT_REGS_PARM5(ctx);
	return hostent_enter(name, result, h_errnop);
}

SEC("uretprobe/gethostbyname_r")
int uretprobe_gethostbyname_r(struct pt_regs *ctx) {
	s32 ret = (s32)PT_REGS_RC(ctx);
	return hostent_exit(ctx, ret);
}

SEC("uprobe/gethostbyname2_r")
int uprobe_gethostbyname2_r(struct pt_regs *ctx) {
	u64 name = PT_REGS_PARM1(ctx);
#if defined(__TARGET_ARCH_arm64)
	u64 result = ctx->regs[5];
	u64 h_errnop = ctx->regs[6];
#else
	u64 result = ctx->r9;
	u64 sp = PT_REGS_SP(ctx);
	u64 h_errnop = 0;
	bpf_probe_read_user(&h_errnop, sizeof(h_errnop), (void *)(sp + 8));
#endif
	return hostent_enter(name, result, h_errnop);
}

SEC("uretprobe/gethostbyname2_r")
int uretprobe_gethostbyname2_r(struct pt_regs *ctx) {
	s32 ret = (s32)PT_REGS_RC(ctx);
	return hostent_exit(ctx, ret);
}

SEC("uprobe/getaddrinfo")
int uprobe_getaddrinfo(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_GETADDRINFO);
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
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GETADDRINFO);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	u64 latency = calc_latency(*start_ts);
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DNS;
	e->latency_ns = latency;
	e->bytes = 0;
	e->tcp_state = 0;
	e->dns_transport = DNS_SOURCE_LIBC;
	
	s64 ret = PT_REGS_RC_INT(ctx);
	if (ret == 0) {
		e->error = 0;
	} else {
		e->error = ret;
	}
	
	char *target_ptr = bpf_map_lookup_elem(&dns_targets, &key);
	if (target_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), target_ptr);
		bpf_map_delete_elem(&dns_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

struct inet_sock_set_state_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, skaddr) == 8, "inet_sock_set_state: skaddr must be at offset 8");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, oldstate) == 16, "inet_sock_set_state: oldstate must be at offset 16");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, newstate) == 20, "inet_sock_set_state: newstate must be at offset 20");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, sport) == 24, "inet_sock_set_state: sport must be at offset 24");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, dport) == 26, "inet_sock_set_state: dport must be at offset 26");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, family) == 28, "inet_sock_set_state: family must be at offset 28");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, protocol) == 30, "inet_sock_set_state: protocol must be at offset 30");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, saddr) == 32, "inet_sock_set_state: saddr must be at offset 32");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, daddr) == 36, "inet_sock_set_state: daddr must be at offset 36");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, saddr_v6) == 40, "inet_sock_set_state: saddr_v6 must be at offset 40");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_args, daddr_v6) == 56, "inet_sock_set_state: daddr_v6 must be at offset 56");

#define PT_TCP_ESTABLISHED 1
#define PT_TCP_SYN_SENT    2
#define PT_TCP_CLOSE       7

static __always_inline void emit_connect_result(const void *skaddr, int oldstate, int newstate, struct event *e)
{
	if (oldstate != PT_TCP_SYN_SENT)
		return;
	if (newstate != PT_TCP_ESTABLISHED && newstate != PT_TCP_CLOSE)
		return;
	if (e->cgroup_id == 0 || !cgroup_allows(e->cgroup_id))
		return;

	s32 err = 0;
	if (newstate == PT_TCP_CLOSE) {
		err = BPF_CORE_READ((struct sock *)skaddr, sk_err);
		if (err <= 0)
			return;
		err = -err;
	}

	e->type = EVENT_CONNECT_RESULT;
	e->error = err;
	e->tcp_state = 0;
	e->stack_key = 0;
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

SEC("tp/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(void *ctx) {
	u32 pid = agent_ns_tgid();

	struct inet_sock_set_state_args args_local;
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}
	if (args_local.protocol != IPPROTO_TCP) {
		return 0;
	}

	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	apply_sk_owner(e, (u64)args_local.skaddr);
	if (args_local.newstate == PT_TCP_CLOSE) {
		u64 skaddr = (u64)args_local.skaddr;
		bpf_map_delete_elem(&sk_owner, &skaddr);
	}
	if (!cgroup_allows(e->cgroup_id))
		return 0;
	e->type = EVENT_TCP_STATE;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = args_local.newstate;
	e->target[0] = '\0';

	if (args_local.family == AF_INET6) {
		format_ipv6_port(args_local.daddr_v6, args_local.dport, e->target);
	} else {
		u32 daddr = ((u32)args_local.daddr[0] << 24) |
		            ((u32)args_local.daddr[1] << 16) |
		            ((u32)args_local.daddr[2] << 8) |
		            (u32)args_local.daddr[3];
		if (daddr != 0) {
			format_ip_port(daddr, args_local.dport, e->target);
		}
	}
	socket_event_context(ctx, e, pid);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	emit_connect_result(args_local.skaddr, args_local.oldstate, args_local.newstate, e);
	return 0;
}

struct tcp_retransmit_skb_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, skbaddr) == 8, "tcp_retransmit_skb: skbaddr must be at offset 8");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, skaddr) == 16, "tcp_retransmit_skb: skaddr must be at offset 16");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, state) == 24, "tcp_retransmit_skb: state must be at offset 24");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, sport) == 28, "tcp_retransmit_skb: sport must be at offset 28");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, dport) == 30, "tcp_retransmit_skb: dport must be at offset 30");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, family) == 32, "tcp_retransmit_skb: family must be at offset 32");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, saddr) == 34, "tcp_retransmit_skb: saddr must be at offset 34");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, daddr) == 38, "tcp_retransmit_skb: daddr must be at offset 38");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, saddr_v6) == 42, "tcp_retransmit_skb: saddr_v6 must be at offset 42");
_Static_assert(__builtin_offsetof(struct tcp_retransmit_skb_args, daddr_v6) == 58, "tcp_retransmit_skb: daddr_v6 must be at offset 58");

SEC("tp/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit_skb(void *ctx) {
	u32 pid = agent_ns_tgid();
	struct tcp_retransmit_skb_args args_local;
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	apply_sk_owner(e, (u64)args_local.skaddr);
	if (!cgroup_allows(e->cgroup_id))
		return 0;
	e->type = EVENT_TCP_RETRANS;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';

	if (args_local.family == AF_INET6) {
		format_ipv6_port(args_local.daddr_v6, args_local.dport, e->target);
	} else {
		u32 daddr = ((u32)args_local.daddr[0] << 24) |
		            ((u32)args_local.daddr[1] << 16) |
		            ((u32)args_local.daddr[2] << 8) |
		            (u32)args_local.daddr[3];
		if (daddr != 0) {
			format_ip_port(daddr, args_local.dport, e->target);
		}
	}
	socket_event_context(ctx, e, pid);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

struct net_dev_xmit_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *skbaddr;
	unsigned int len;
	int rc;
	unsigned int name_loc;
};
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, len) == 16, "net_dev_xmit: len must be at offset 16");
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, rc) == 20, "net_dev_xmit: rc must be at offset 20");
_Static_assert(__builtin_offsetof(struct net_dev_xmit_args, name_loc) == 24, "net_dev_xmit: name __data_loc must be at offset 24");

SEC("tp/net/net_dev_xmit")
int tracepoint_net_dev_xmit(void *ctx) {
	u32 pid = agent_ns_tgid();
	struct net_dev_xmit_args args_local;
	if (bpf_probe_read_kernel(&args_local, sizeof(args_local), ctx) != 0) {
		return 0;
	}
	if (args_local.rc == 0) {
		return 0;
	}
	struct event *e = get_event_buf_unfiltered();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	struct sk_buff *skb = (struct sk_buff *)args_local.skbaddr;
	apply_sk_owner(e, skb ? (u64)BPF_CORE_READ(skb, sk) : 0);
	if (!cgroup_allows(e->cgroup_id))
		return 0;
	e->type = EVENT_NET_DEV_ERROR;
	e->latency_ns = 0;
	e->error = args_local.rc;
	e->bytes = args_local.len;
	e->tcp_state = 0;
	unsigned short name_off = (unsigned short)(args_local.name_loc & 0xffff);
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), (char *)ctx + name_off);
	socket_event_context(ctx, e, pid);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_UDP_SENDMSG);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	stash_udp_peer(ctx);
	return 0;
}

static __always_inline int udp_sendmsg_return(void *ctx, long rc)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_SENDMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	s64 ret = (int)rc;
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_UDP_SEND;
	e->latency_ns = calc_latency(*start_ts);
	e->error = SOCKET_ERROR(ret);
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	fill_event_peer_pref(e, PAIR_UDP_SENDMSG);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe_udp_sendmsg(struct pt_regs *ctx)
{
	long rc = PT_REGS_RC(ctx);
	return udp_sendmsg_return(ctx, rc);
}

SEC("fexit/udp_sendmsg")
int fexit_udp_sendmsg(u64 *ctx)
{
	u64 rc = 0;
	bpf_get_func_ret(ctx, &rc);
	return udp_sendmsg_return(ctx, (long)rc);
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
	if (!cgroup_allows(bpf_get_current_cgroup_id()))
		return 0;
	struct pair_key key = make_pair_key(PAIR_UDP_RECVMSG);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);

	struct tcp_peer peer = {};
	if (peer_from_connected_sock((struct sock *)PT_REGS_PARM1(ctx), &peer)) {
		peer.stash_ns = bpf_ktime_get_ns();
		bpf_map_update_elem(&tcp_peer_stash, &key, &peer, BPF_ANY);
	}

	u64 msg = (u64)PT_REGS_PARM2(ctx);
	if (msg)
		bpf_map_update_elem(&udp_recv_msghdr, &key, &msg, BPF_ANY);
	return 0;
}

static __always_inline int udp_recvmsg_return(void *ctx, long rc)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_UDP_RECVMSG);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	s64 ret = (int)rc;
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_UDP_RECV;
	e->latency_ns = calc_latency(*start_ts);
	e->error = SOCKET_ERROR(ret);
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	stash_udp_recv_peer();
	fill_event_peer_pref(e, PAIR_UDP_RECVMSG);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx)
{
	long rc = PT_REGS_RC(ctx);
	return udp_recvmsg_return(ctx, rc);
}

SEC("fexit/udp_recvmsg")
int fexit_udp_recvmsg(u64 *ctx)
{
	u64 rc = 0;
	bpf_get_func_ret(ctx, &rc);
	return udp_recvmsg_return(ctx, (long)rc);
}

SEC("uprobe/http_request")
int uprobe_http_request(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_REQUEST);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	char *url = (char *)PT_REGS_PARM1(ctx);
	if (url) {
		char url_buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(url_buf, sizeof(url_buf), url);
		u64 conn_key = get_key(pid, tid);
		bpf_map_update_elem(&socket_conns, &conn_key, url_buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/http_request")
int uretprobe_http_request(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_REQUEST);
	u64 conn_key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);

	if (!start_ts) {
		drop_pair_sidemaps(&key);
		bpf_map_delete_elem(&socket_conns, &conn_key);
		return 0;
	}

	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		bpf_map_delete_elem(&socket_conns, &conn_key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_HTTP_REQ;
	e->latency_ns = calc_latency(*start_ts);
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	
	char *url_ptr = bpf_map_lookup_elem(&socket_conns, &conn_key);
	if (url_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), url_ptr);
		bpf_map_delete_elem(&socket_conns, &conn_key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/http_response")
int uprobe_http_response(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_HTTP_RESPONSE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/http_response")
int uretprobe_http_response(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_HTTP_RESPONSE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_HTTP_RESP;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/PQexec")
int uprobe_PQexec(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_PQEXEC);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	char *query = (char *)PT_REGS_PARM2(ctx);
	if (query) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), query);
		u32 i;
		for (i = 0; i < MAX_STRING_LEN; i++) {
			if (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t' || buf[i] == '\0') {
				buf[i] = '\0';
				break;
			}
		}
		bpf_map_update_elem(&db_queries, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/PQexec")
int uretprobe_PQexec(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_PQEXEC);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DB_QUERY;
	e->latency_ns = latency;
	long ret = PT_REGS_RC(ctx);
	e->error = ret == 0 ? -1 : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	char *qptr = bpf_map_lookup_elem(&db_queries, &key);
	if (qptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), qptr);
		bpf_map_delete_elem(&db_queries, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/mysql_real_query")
int uprobe_mysql_real_query(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_MYSQL_QUERY);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	const char *query = (const char *)PT_REGS_PARM2(ctx);
	if (query) {
		char buf[MAX_STRING_LEN] = {};
		bpf_probe_read_user_str(buf, sizeof(buf), query);
		u32 i;
		for (i = 0; i < MAX_STRING_LEN; i++) {
			if (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t' || buf[i] == '\0') {
				buf[i] = '\0';
				break;
			}
		}
		bpf_map_update_elem(&db_queries, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/mysql_real_query")
int uretprobe_mysql_real_query(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MYSQL_QUERY);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_DB_QUERY;
	e->latency_ns = latency;
	long ret = PT_REGS_RC(ctx);
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *qptr = bpf_map_lookup_elem(&db_queries, &key);
	if (qptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), qptr);
		bpf_map_delete_elem(&db_queries, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}
static __always_inline int openssl_handshake_step(long ret)
{
	return ret < 0;
}

static __always_inline s32 openssl_handshake_error(long ret)
{
	return ret == 1 ? 0 : -1;
}

static __always_inline void ssl_note_handshake(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u64 ssl = (u64)PT_REGS_PARM1(ctx);
	struct ssl_hs_call *c = bpf_map_lookup_elem(&ssl_hs_ssl, &id);
	if (c && c->ssl == ssl && c->depth > 0 && c->depth < 8) {
		c->depth++;
		return;
	}
	struct ssl_hs_call fresh = {.ssl = ssl, .depth = 1};
	bpf_map_update_elem(&ssl_hs_ssl, &id, &fresh, BPF_ANY);
}

static __always_inline int ssl_handshake_nested(void)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_hs_call *c = bpf_map_lookup_elem(&ssl_hs_ssl, &id);
	if (!c || c->depth == 0)
		return 0;
	c->depth--;
	return c->depth > 0;
}

static __always_inline void ssl_park_handshake(u64 latency_ns)
{
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_hs_call *c = bpf_map_lookup_elem(&ssl_hs_ssl, &id);
	if (!c)
		return;
	struct ssl_hs_pending p = {.ssl = c->ssl, .latency_ns = latency_ns};
	bpf_map_update_elem(&ssl_hs_pending, &id, &p, BPF_ANY);
}

static __always_inline void ssl_forget_handshake(void)
{
	u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&ssl_hs_pending, &id);
	bpf_map_delete_elem(&ssl_hs_ssl, &id);
}

static __always_inline int openssl_error_is_fatal(long reason)
{
	return reason == 1 || reason == 5 || reason == 6;
}

static __always_inline int gnutls_handshake_step(long ret)
{
	return ret == -28 /* GNUTLS_E_AGAIN */ ||
	       ret == -52 /* GNUTLS_E_INTERRUPTED */ ||
	       ret == -16 /* GNUTLS_E_WARNING_ALERT_RECEIVED */ ||
	       ret == -37 /* GNUTLS_E_REHANDSHAKE */ ||
	       ret == -38 /* GNUTLS_E_GOT_APPLICATION_DATA */;
}

static __always_inline int mbedtls_handshake_step(long ret)
{
	return ret == -0x6900 /* MBEDTLS_ERR_SSL_WANT_READ */ ||
	       ret == -0x6880 /* MBEDTLS_ERR_SSL_WANT_WRITE */ ||
	       ret == -0x6500 /* MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS */ ||
	       ret == -0x7000 /* MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS */ ||
	       ret == -0x7B00 /* MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET */ ||
	       ret == -0x7C00 /* MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA */;
}

struct ssl_hs_key {
	u64 ssl;
	u32 tgid;
	u32 _pad;
};

struct ssl_hs_state {
	u64 start_ns;
	u32 decided;
	u32 _pad;
};

static __always_inline struct ssl_hs_key ssl_hs_key_of(u64 ssl)
{
	struct ssl_hs_key key = {.ssl = ssl, .tgid = bpf_get_current_pid_tgid() >> 32};
	return key;
}

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct ssl_hs_key);
	__type(value, struct ssl_hs_state);
} ssl_hs_states SEC(".maps");

static __always_inline void ssl_hs_begin(u64 ssl)
{
	if (!ssl)
		return;
	struct ssl_hs_key key = ssl_hs_key_of(ssl);
	struct ssl_hs_state fresh = {.start_ns = bpf_ktime_get_ns()};
	bpf_map_update_elem(&ssl_hs_states, &key, &fresh, BPF_NOEXIST);
}

static __always_inline int ssl_hs_decide(u64 ssl, u64 *latency)
{
	struct ssl_hs_key key = ssl_hs_key_of(ssl);
	struct ssl_hs_state *st = bpf_map_lookup_elem(&ssl_hs_states, &key);
	if (!st)
		return 1;
	if (st->decided)
		return 0;
	st->decided = 1;
	u64 now = bpf_ktime_get_ns();
	if (now > st->start_ns)
		*latency = now - st->start_ns;
	return 1;
}

static __always_inline void ssl_emit_handshake(struct pt_regs *ctx, u64 latency, s32 error)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct event *e = get_event_buf();
	if (!e)
		return;
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = latency;
	e->error = error;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

static __always_inline int ssl_hs_undecided(u64 ssl)
{
	if (!ssl)
		return 0;
	struct ssl_hs_key key = ssl_hs_key_of(ssl);
	struct ssl_hs_state *st = bpf_map_lookup_elem(&ssl_hs_states, &key);
	return st && !st->decided;
}

static __always_inline void ssl_hs_settle(struct pt_regs *ctx, u64 ssl)
{
	if (!ssl_hs_undecided(ssl))
		return;
	u64 latency = 0;
	if (ssl_hs_decide(ssl, &latency))
		ssl_emit_handshake(ctx, latency, 0);
}

static __always_inline int ssl_handshake_entry(struct pt_regs *ctx, u32 pair)
{
	struct pair_key key = make_pair_key(pair);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	ssl_note_handshake(ctx);
	ssl_hs_begin((u64)PT_REGS_PARM1(ctx));
	return 0;
}

static __always_inline int ssl_handshake_return(struct pt_regs *ctx, u32 pair, long ret)
{
	struct pair_key key = make_pair_key(pair);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	if (ssl_handshake_nested()) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_hs_call *c = bpf_map_lookup_elem(&ssl_hs_ssl, &id);
	u64 ssl = c ? c->ssl : 0;
	if (openssl_handshake_step(ret)) {
		ssl_park_handshake(latency);
		drop_pair_sidemaps(&key);
		return 0;
	}
	ssl_forget_handshake();
	drop_pair_sidemaps(&key);
	if (ssl_hs_decide(ssl, &latency))
		ssl_emit_handshake(ctx, latency, openssl_handshake_error(ret));
	return 0;
}

SEC("uprobe/SSL_connect")
int uprobe_SSL_connect(struct pt_regs *ctx) {
	return ssl_handshake_entry(ctx, PAIR_SSL_CONNECT);
}

SEC("uretprobe/SSL_connect")
int uretprobe_SSL_connect(struct pt_regs *ctx) {
	long ret = PT_REGS_RC_INT(ctx);
	return ssl_handshake_return(ctx, PAIR_SSL_CONNECT, ret);
}

SEC("uprobe/SSL_accept")
int uprobe_SSL_accept(struct pt_regs *ctx) {
	return ssl_handshake_entry(ctx, PAIR_SSL_ACCEPT);
}

SEC("uretprobe/SSL_accept")
int uretprobe_SSL_accept(struct pt_regs *ctx) {
	long ret = PT_REGS_RC_INT(ctx);
	return ssl_handshake_return(ctx, PAIR_SSL_ACCEPT, ret);
}

SEC("uprobe/SSL_do_handshake")
int uprobe_SSL_do_handshake(struct pt_regs *ctx) {
	return ssl_handshake_entry(ctx, PAIR_SSL_DO_HANDSHAKE);
}

SEC("uretprobe/SSL_do_handshake")
int uretprobe_SSL_do_handshake(struct pt_regs *ctx) {
	long ret = PT_REGS_RC_INT(ctx);
	return ssl_handshake_return(ctx, PAIR_SSL_DO_HANDSHAKE, ret);
}

SEC("uprobe/SSL_get_error")
int uprobe_SSL_get_error(struct pt_regs *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	struct ssl_hs_pending *p = bpf_map_lookup_elem(&ssl_hs_pending, &id);
	if (!p || p->ssl != (u64)PT_REGS_PARM1(ctx))
		return 0;
	u64 one = 1;
	bpf_map_update_elem(&ssl_get_error_args, &id, &one, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_get_error")
int uretprobe_SSL_get_error(struct pt_regs *ctx) {
	long reason = PT_REGS_RC_INT(ctx);
	u64 id = bpf_get_current_pid_tgid();
	if (!bpf_map_lookup_elem(&ssl_get_error_args, &id))
		return 0;
	bpf_map_delete_elem(&ssl_get_error_args, &id);
	struct ssl_hs_pending *p = bpf_map_lookup_elem(&ssl_hs_pending, &id);
	if (!p)
		return 0;
	u64 latency = p->latency_ns;
	u64 ssl = p->ssl;
	if (!openssl_error_is_fatal(reason)) {
		bpf_map_delete_elem(&ssl_hs_pending, &id);
		return 0;
	}
	ssl_forget_handshake();
	if (ssl_hs_decide(ssl, &latency))
		ssl_emit_handshake(ctx, latency, -(s32)reason);
	return 0;
}

SEC("uprobe/SSL_free")
int uprobe_SSL_free(struct pt_regs *ctx) {
	struct ssl_hs_key key = ssl_hs_key_of((u64)PT_REGS_PARM1(ctx));
	struct ssl_hs_state *st = bpf_map_lookup_elem(&ssl_hs_states, &key);
	if (!st)
		return 0;
	u64 start = st->start_ns;
	u32 decided = st->decided;
	bpf_map_delete_elem(&ssl_hs_states, &key);
	if (decided)
		return 0;
	u64 now = bpf_ktime_get_ns();
	ssl_emit_handshake(ctx, now > start ? now - start : 0, -1);
	return 0;
}

SEC("uprobe/gnutls_handshake")
int uprobe_gnutls_handshake(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_GNUTLS_HANDSHAKE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_handshake")
int uretprobe_gnutls_handshake(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_GNUTLS_HANDSHAKE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	long ret = PT_REGS_RC_INT(ctx);
	if (gnutls_handshake_step(ret)) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? (s32)ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/mbedtls_ssl_handshake")
int uprobe_mbedtls_ssl_handshake(struct pt_regs *ctx) {
	struct pair_key key = make_pair_key(PAIR_MBEDTLS_HANDSHAKE);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/mbedtls_ssl_handshake")
int uretprobe_mbedtls_ssl_handshake(struct pt_regs *ctx) {
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct pair_key key = make_pair_key(PAIR_MBEDTLS_HANDSHAKE);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	long ret = PT_REGS_RC_INT(ctx);
	if (mbedtls_handshake_step(ret)) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	struct event *e = get_event_buf();
	if (!e) {
		drop_pair_sidemaps(&key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = calc_latency(*start_ts);
	e->error = ret < 0 ? (s32)ret : 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	capture_user_stack(ctx, pid, tid, e);
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}
