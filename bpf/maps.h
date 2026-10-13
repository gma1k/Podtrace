// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_MAPS_H
#define PODTRACE_MAPS_H

#include "common.h"
#include "events.h"
#include "agg.h"

struct stack_trace_t {
	u64 ips[MAX_STACK_DEPTH];
	u32 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} events SEC(".maps");

enum probe_pair {
	PAIR_TCP_CONNECT_V4 = 1,
	PAIR_TCP_CONNECT_V6,
	PAIR_TCP_SENDMSG,
	PAIR_TCP_RECVMSG,
	PAIR_UDP_SENDMSG,
	PAIR_UDP_RECVMSG,
	PAIR_GETADDRINFO,
	PAIR_HTTP_REQUEST,
	PAIR_HTTP_RESPONSE,
	PAIR_PQEXEC,
	PAIR_MYSQL_QUERY,
	PAIR_SSL_CONNECT,
	PAIR_SSL_ACCEPT,
	PAIR_SSL_DO_HANDSHAKE,
	PAIR_GNUTLS_HANDSHAKE,
	PAIR_MBEDTLS_HANDSHAKE,
	PAIR_OPENAT,
	PAIR_VFS_UNLINK,
	PAIR_VFS_RENAME,
	PAIR_VFS_READ,
	PAIR_VFS_WRITE,
	PAIR_VFS_FSYNC,
	PAIR_FUTEX,
	PAIR_PTHREAD_MUTEX,
	PAIR_REDIS_COMMAND,
	PAIR_REDIS_COMMAND_ARGV,
	PAIR_MEMCACHED,
	PAIR_KAFKA_TOPIC_NEW,
	PAIR_KAFKA_PRODUCE,
	PAIR_KAFKA_POLL,
	PAIR_GETHOSTBYNAME,
};

struct pair_key {
	u64 pid_tgid;
	u32 pair;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, u64);
} start_times SEC(".maps");

struct ssl_hs_pending {
	u64 ssl;
	u64 latency_ns;
};

struct ssl_hs_call {
	u64 ssl;
	u32 depth;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct ssl_hs_call);
} ssl_hs_ssl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct ssl_hs_pending);
} ssl_hs_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} ssl_get_error_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} dns_targets SEC(".maps");

#define USDT_PROVIDER_LEN 64
#define USDT_NAME_LEN 64
#define USDT_MAX_ARGS 4

#define USDT_ARG_UNSUPPORTED 0
#define USDT_ARG_REG 1
#define USDT_ARG_MEM 2
#define USDT_ARG_CONST 3

struct usdt_arg {
	s8 size;
	u8 kind;
	u16 reg_off;
	s64 disp;
};

struct usdt_probe {
	char provider[USDT_PROVIDER_LEN];
	char name[USDT_NAME_LEN];
	u8 nargs;
	u8 _pad[7];
	struct usdt_arg args[USDT_MAX_ARGS];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct usdt_probe);
} usdt_probes SEC(".maps");

struct dns_flow_key {
	u64 cgroup_id;
	u32 txid;
	u32 _pad;
};

struct dns_query_state {
	u64 ts_ns;
	u32 pid;
	u32 qtype;
	u32 server_ip;
	u8 transport;
	u8 _pad[3];
	char comm[COMM_LEN];
	char name[MAX_STRING_LEN];
	u8 server_ip6[16];
	u64 last_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct dns_flow_key);
	__type(value, struct dns_query_state);
} dns_inflight SEC(".maps");

struct dns_resolved_key {
	u64 cgroup_id;
	u32 ip;
	u32 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_resolved_key);
	__type(value, char[MAX_STRING_LEN]);
} dns_resolved SEC(".maps");

struct dns_v6key {
	u64 cgroup_id;
	u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_v6key);
	__type(value, char[MAX_STRING_LEN]);
} dns_resolved6 SEC(".maps");

#define DNS_PAYLOAD_MAX 512

struct dns_payload_record {
	u64 cgroup_id;
	u64 timestamp;
	u64 latency_ns;
	u32 pid;
	u32 server_ip;
	u8  server_ip6[16];
	u16 txid;
	u16 qtype;
	u16 payload_len;
	u8  transport;
	u8  is_v6;
	u8  rcode;
	u8  agg_recorded;
	u8  _pad[6];
};

struct dns_payload_scratch {
	struct dns_payload_record rec;
	u8 payload[DNS_PAYLOAD_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct dns_payload_scratch);
} dns_payload_scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} dns_payload_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} dns_payload_enabled SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} grpc_port_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} dns_drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} socket_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, u64);
	__type(value, struct stack_trace_t);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} lock_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} db_queries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} tcp_target SEC(".maps");

struct tcp_peer {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u16 family;
	u16 _pad;
	u8  saddr6[16];
	u8  daddr6[16];
	u64 stash_ns;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, struct tcp_peer);
} tcp_peer_stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, u64);
} udp_recv_msghdr SEC(".maps");

struct sk_owner {
	u64 cgroup_id;
	u32 pid;
	u32 _pad;
	char comm[COMM_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct sk_owner);
} sk_owner SEC(".maps");

#define QUIC_INITIAL_MAX_PKTS 3

struct quic_flow_key {
	u64 cgroup_id;
	u8  daddr6[16];
	u16 dport;
	u16 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct quic_flow_key);
	__type(value, u8);
} quic_seen SEC(".maps");

struct encrypted_dns_flow {
	u64 cgroup_id;
	u8  daddr6[16];
	u16 dport;
	u16 sport;
	u32 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct encrypted_dns_flow);
	__type(value, u8);
} encrypted_dns_seen SEC(".maps");

#define QUIC_PKT_CAP 1500
struct quic_initial_record {
	u64 timestamp;
	u64 cgroup_id;
	u32 pid;
	u8  family;
	u8  _pad;
	u16 dport;
	u8  daddr6[16];
	u16 pktlen;
	u16 _pad2;
	char comm[COMM_LEN];
	u8  pkt[QUIC_PKT_CAP];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} quic_initial_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct quic_initial_record);
} quic_initial_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} syscall_paths SEC(".maps");

struct resource_limit {
	u64 limit_bytes;
	u64 usage_bytes;
	u64 last_update_ns;
	u32 resource_type;
};

#define RESOURCE_CPU    0
#define RESOURCE_MEMORY 1
#define RESOURCE_IO     2

struct resource_key {
	u64 cgroup_id;
	u32 resource_type;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct resource_key);
	__type(value, struct resource_limit);
} cgroup_limits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct resource_key);
	__type(value, u32);
} cgroup_alerts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} target_cgroup_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u8);
} target_parent_cgroup_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} inherited_cgroup_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_filter_enabled SEC(".maps");

struct cpu_quota {
	u64 quota_us;
	u64 period_us;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct cpu_quota);
} cgroup_cpu_quota SEC(".maps");

struct cpu_window {
	u64 window_start_ns;
	u64 runtime_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct cpu_window);
} cgroup_cpu_window SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} proc_cpu_enabled SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, u64);
} proc_cpu_ns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} sched_in_ts SEC(".maps");

struct connect_addr {
	u16 family;
	u16 port_be;
	u32 addr_be;
	u8 addr6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, struct connect_addr);
} connect_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} sk_cgroup_ids SEC(".maps");

struct sched_interval {
	u64 ns;
	u64 preempted;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct sched_interval);
} sched_out_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct sched_interval);
} sched_pending_blocked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} page_fault_seq SEC(".maps");

struct pool_state {
	u64 last_use_ns;
	u32 connection_id;
	u32 in_use;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct pool_state);
} pool_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} pool_acquire_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} pool_db_types SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, u32);
	__type(value, u32);
} alert_thresholds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} event_buf SEC(".maps");

struct fastcgi_req {
	u64 start_ns;
	char uri[MAX_STRING_LEN];
	char method[16];
};
struct fcgi_req_key {
	u32 pid;
	u32 tid;
	u16 request_id;
	u16 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct fcgi_req_key);
	__type(value, struct fastcgi_req);
} fastcgi_reqs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} recvmsg_args SEC(".maps");

struct fcgi_pending {
	u32 request_id;
	u32 expected_body_bytes;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct fcgi_pending);
} fastcgi_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} redis_cmds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} memcached_ops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} grpc_methods SEC(".maps");

struct http_req {
	u64 start_ns;
	char endpoint[MAX_STRING_LEN];
	u8 method;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct http_req);
} http_reqs SEC(".maps");

struct ssl_read_state {
	u64 buf;
	u64 conn;
	u64 out_len;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct ssl_read_state);
} http_recv_base SEC(".maps");

#define HTTP_SCAN_BUF_SIZE 512
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, char[HTTP_SCAN_BUF_SIZE]);
} http_scan_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct ssl_read_state);
} ssl_read_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct ssl_read_state);
} ssl_write_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct ssl_read_state);
} rustls_read_args SEC(".maps");

struct h2_recv_info {
	u64 base;
	u64 conn_id;
	u64 iov;
	u32 nr_segs;
	u32 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct h2_recv_info);
} h2_recv_base SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct h2_recv_info);
} h2_send_base SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} h2_hdr_events SEC(".maps");

struct h2_hdr_scratch {
	struct h2_hdr_record rec;
	u8 frag[H2_HDR_FRAG_MAX];
	u32 off;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct h2_hdr_scratch);
} h2_hdr_scratch_map SEC(".maps");

struct grpc_go_scratch {
	char method[16];
	char path[MAX_STRING_LEN];
	char status[8];
	u8 have_path;
	u8 have_status;
	u8 have_method;
	u8 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct grpc_go_scratch);
} grpc_go_scratch_map SEC(".maps");

struct grpc_pair_key {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 stream;
	u32 _pad;
};
struct grpc_pair_val {
	u64 start_ns;
	char path[MAX_STRING_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct grpc_pair_key);
	__type(value, struct grpc_pair_val);
} grpc_go_pairs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct grpc_pair_val);
} grpc_go_pairval_map SEC(".maps");

struct h2_seq_key {
	u64 conn_id;
	u32 dir;
	u32 _pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct h2_seq_key);
	__type(value, u64);
} h2_seq SEC(".maps");

struct go_tls_read_state {
	u64 buf;
	u64 conn;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct go_tls_read_state);
} go_tls_read_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} go_acquire_starts SEC(".maps");

struct pool_field_offsets {
	u32 num_open;
	u32 max_open;
	u32 free_conn;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct pool_field_offsets);
} pool_offsets SEC(".maps");

struct pool_sample {
	u64 last_emit_ns;
	u64 acc;
	u32 peak_open;
	u32 max_open;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct pool_sample);
} pool_samples SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} h3_txn_events SEC(".maps");

struct h3_txn_scratch {
	struct h3_txn_record rec;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct h3_txn_scratch);
} h3_txn_scratch_map SEC(".maps");

struct h3_req_inflight {
	u64 start_ts;
	u8  method_len;
	u16 path_len;
	u8  peer_family;
	u16 peer_dport;
	u8  _pad[2];
	char method[H3_TXN_METHOD_MAX];
	char path[H3_TXN_PATH_MAX];
	u8  peer_daddr6[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct h3_req_inflight);
} h3_req_stash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct h3_field_offsets);
} h3_offsets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct h3_peer_paths);
} h3_peer_paths_map SEC(".maps");

struct pidns_info {
	u64 dev;
	u64 ino;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct pidns_info);
} pidns_ref SEC(".maps");

struct h3_hdr_name {
	u8   len;
	char name[H3_HDR_NAME_MAX];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, H3_HDR_SLOTS);
	__type(key, u32);
	__type(value, struct h3_hdr_name);
} h3_hdr_names SEC(".maps");

struct h3_pending_hdrs {
	u8   vlen[H3_HDR_SLOTS];
	u8   _pad[4];
	char val[H3_HDR_SLOTS][H3_HDR_VAL_MAX];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct h3_pending_hdrs);
} h3_pending_hdrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct h3_pending_hdrs);
} h3_hdr_scratch SEC(".maps");

#define H3_ADAPTER_KIND_REQUEST 1
#define H3_ADAPTER_KIND_ARRIVAL 2

struct h3_adapter_stream_key {
	u64 tgid;
	u64 conn;
	u64 stream_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct h3_adapter_stream_key);
	__type(value, struct h3_txn_record);
} h3_adapter_streams SEC(".maps");

struct h3_adapter_call {
	u64 conn;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct h3_adapter_call);
} h3_adapter_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct h3_txn_record);
} h3_adapter_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} h3_stream_chunks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct h3_stream_chunk);
} h3_chunk_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct h3_adapter_stream_key);
	__type(value, u32);
} h3_stream_captured SEC(".maps");

struct h3_pending_tp {
	u8   len;
	u8   _pad[7];
	char buf[H3_TXN_TP_MAX];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct h3_pending_tp);
} h3_pending_tp SEC(".maps");

struct h3_parse_state {
	u64 fields_ptr;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, struct h3_parse_state);
} h3_parse_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u8);
} h2_conns SEC(".maps");

struct h2_frame_state {
	u32 remaining;
	u32 stream_id;
	u8  type;
	u8  flags;
	u8  preface_seen;
	u8  pad;
	u8  hdr_have;
	u8  hdr_partial[9];
	u8  pad_len_pending;
	u8  pre_skip;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct h2_seq_key);
	__type(value, struct h2_frame_state);
} h2_frame_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_names SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, char[MAX_STRING_LEN]);
} kafka_topic_tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct pair_key);
	__type(value, u64);
} proto_bytes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct stack_trace_t);
} stack_buf SEC(".maps");

#ifndef BPF_MAP_TYPE_STACK_TRACE
#define BPF_MAP_TYPE_STACK_TRACE 7
#endif

#define ONCPU_STACK_ENTRIES 8192
#define ONCPU_COUNT_ENTRIES 32768
#define ONCPU_LOST_STACK 0
#define ONCPU_LOST_FULL 1
#define ONCPU_LOST_REASONS 2

struct oncpu_key {
	u64 cgroup_id;
	u64 correlation_id;
	u32 pid;
	u32 stack_id;
};

#define ONCPU_KIND_HTTP1 0
#define ONCPU_KIND_H2    1
#define ONCPU_KIND_H3    2

struct oncpu_thread_request {
	u64 correlation_id;
	u64 conn;
	u64 stream;
	u32 kind;
	u32 _pad;
};

#define ONCPU_GO_NETHTTP 1
#define ONCPU_GO_H2      2
#define ONCPU_GO_GRPC    3
#define ONCPU_GO_H3      4

#define REQUEST_DONE_GO 0x100

#define ONCPU_REQUEST_MAX_NS (60ULL * 1000ULL * 1000ULL * 1000ULL)

struct oncpu_goroutine_key {
	u32 tgid;
	u32 _pad;
	u64 goroutine;
};

struct oncpu_goroutine_request {
	u64 correlation_id;
	u32 kind;
	u32 _pad;
};

struct oncpu_request_done {
	u64 latency_ns;
	u64 cgroup_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, ONCPU_STACK_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} oncpu_stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ONCPU_COUNT_ENTRIES);
	__type(key, struct oncpu_key);
	__type(value, u64);
} oncpu_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} oncpu_enabled SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct oncpu_thread_request);
} oncpu_thread_requests SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, struct oncpu_request_done);
} oncpu_requests_done SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, struct oncpu_thread_request);
} oncpu_conn_requests SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u8);
} oncpu_event_loop_threads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u64);
} oncpu_thread_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, u64);
} oncpu_conn_aliases SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct oncpu_goroutine_key);
	__type(value, struct oncpu_goroutine_request);
} oncpu_goroutine_requests SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, u8);
} oncpu_go_procs SEC(".maps");

struct h2_stream_key {
	u64 conn;
	u32 stream;
	u32 _pad;
};

struct h2_stream_state {
	u64 start_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, u8);
} h2_server_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct h2_stream_key);
	__type(value, struct h2_stream_state);
} h2_streams SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ONCPU_LOST_REASONS);
	__type(key, u32);
	__type(value, u64);
} oncpu_lost SEC(".maps");

#endif
