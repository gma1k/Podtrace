// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_EVENTS_H
#define PODTRACE_EVENTS_H

#include "common.h"

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
	EVENT_LOCK_CONTENTION,
	EVENT_TCP_RETRANS,
	EVENT_NET_DEV_ERROR,
	EVENT_DB_QUERY,
	EVENT_EXEC,
	EVENT_FORK,
	EVENT_OPEN,
	EVENT_CLOSE,
	EVENT_TLS_HANDSHAKE,
	EVENT_TLS_ERROR,
	EVENT_RESOURCE_LIMIT,
	EVENT_POOL_ACQUIRE,
	EVENT_POOL_RELEASE,
	EVENT_POOL_EXHAUSTED,
	EVENT_UNLINK,
	EVENT_RENAME,
	EVENT_REDIS_CMD,
	EVENT_MEMCACHED_CMD,
	EVENT_FASTCGI_REQUEST,
	EVENT_FASTCGI_RESPONSE,
	EVENT_GRPC_METHOD,
	EVENT_KAFKA_PRODUCE,
	EVENT_KAFKA_FETCH,
	EVENT_DNS_QUERY,
	EVENT_AF_ALG,
	EVENT_HTTP3,
	EVENT_USDT,
	EVENT_DB_ACQUIRE,
	EVENT_DB_POOL_STATS,
	EVENT_TCP_RTT,
	EVENT_CONNECT_RESULT,
	EVENT_REQUEST_DONE,
};

struct event {
	u64 timestamp;
	u32 pid;
	u32 type;
	u64 latency_ns;
	s32 error;
	u64 bytes;
	u32 tcp_state;
	u64 stack_key;
	u64 cgroup_id;
	char comm[COMM_LEN];
	char target[MAX_STRING_LEN];
	char details[MAX_STRING_LEN];
	u32 net_ns_id;
	u32 _pad2;
	u32 dns_server_ip;
	u8  dns_transport;
	u8  _pad3[3];
	u8  dns_server_ip6[16];
	u32 peer_saddr;
	u32 peer_daddr;
	u16 peer_sport;
	u16 peer_dport;
	u8  peer_family;
	u8  _pad4[3];
	u8  peer_saddr6[16];
	u8  peer_daddr6[16];
	u64 correlation_id;
	u8  http_method;
	u8  agg_recorded;
	u8  _pad5[6];
};

#define H2_HDR_FRAG_MAX 1024

#define H2_DIR_EGRESS  0
#define H2_DIR_INGRESS 1
#define H2_HDR_FLAG_END_HEADERS  0x1
#define H2_HDR_FLAG_CONTINUATION 0x2
#define H2_HDR_FLAG_CLOSE        0x4
#define H2_HDR_FLAG_MID_FRAME    0x8

struct h2_hdr_record {
	u64 conn_id;
	u64 timestamp;
	u64 cgroup_id;
	u32 pid;
	u32 seq;
	u32 stream_id;
	u16 frag_len;
	u8  direction;
	u8  transport;
	u8  flags;
	u8  _pad[7];
	u32 peer_saddr;
	u32 peer_daddr;
	u16 peer_sport;
	u16 peer_dport;
	u8  peer_family;
	u8  _pad5[3];
	u8  peer_saddr6[16];
	u8  peer_daddr6[16];
};

#define H3_TXN_METHOD_MAX 16
#define H3_TXN_PATH_MAX   256

struct h3_field_offsets {
	u32 method;
	u32 url;
	u32 path;
	u32 status;
};

#define H3_PEER_MAX_STEPS 6

struct h3_peer_step {
	u32 off;
	u8  iface;
	u8  _pad[3];
};

struct h3_peer_path {
	u8  nsteps;
	u8  _pad[3];
	u32 ip_off;
	u32 port_off;
	struct h3_peer_step steps[H3_PEER_MAX_STEPS];
};

struct h3_peer_paths {
	struct h3_peer_path client;
	struct h3_peer_path server;
};

#define H3_TXN_TP_MAX 64

#define H3_HDR_SLOTS    4
#define H3_HDR_NAME_MAX 32
#define H3_HDR_VAL_MAX  64

#define H3_TXN_F_REQ_ONLY  0x1
#define H3_TXN_F_RESP_ONLY 0x2
#define H3_TXN_F_ABORTED   0x4

struct h3_txn_record {
	u64 timestamp;
	u64 latency_ns;
	u64 cgroup_id;
	u32 pid;
	u16 status;
	u8  is_client;
	u8  method_len;
	u16 path_len;
	u8  tp_len;
	u8  flags;
	u8  peer_family;
	u8  _pad;
	u16 peer_dport;
	char method[H3_TXN_METHOD_MAX];
	char path[H3_TXN_PATH_MAX];
	char traceparent[H3_TXN_TP_MAX];
	u8  peer_daddr6[16];
	u8  hdr_vlen[H3_HDR_SLOTS];
	char hdr_val[H3_HDR_SLOTS][H3_HDR_VAL_MAX];
	u8  _pad_tail[4];
	u64 adapter_conn;
	u64 adapter_stream;
};

#define H3_CHUNK_DATA_MAX      512
#define H3_STREAM_CAPTURE_MAX  4096
#define H3_CHUNKS_PER_READ     8
#define H3_CAPTURED_UNCAPPED   0x80000000u
#define H3_STREAM_TYPE_ENCODER 0x02

struct h3_stream_chunk {
	u64 tgid;
	u64 conn;
	u64 stream_id;
	u32 stream_len;
	u32 copied_len;
	u32 offset;
	u32 flags;
	char data[H3_CHUNK_DATA_MAX];
};

#define H3_CHUNK_F_CONN_CLOSED 0x1

#define DNS_SOURCE_UDP       0
#define DNS_SOURCE_TCP       1
#define DNS_SOURCE_ENCRYPTED 2
#define DNS_SOURCE_LIBC      3

#define DNS_CLASS_NOERROR  0
#define DNS_CLASS_NXDOMAIN 1
#define DNS_CLASS_SERVFAIL 2
#define DNS_CLASS_REFUSED  3
#define DNS_CLASS_OTHER    4

#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_REFUSED  5

#define EAI_NONAME -2
#define EAI_AGAIN  -3
#define EAI_NODATA -5

static __always_inline u32 dns_answer_class(u8 source, s32 error)
{
	if (error == 0)
		return DNS_CLASS_NOERROR;
	if (source == DNS_SOURCE_LIBC) {
		if (error == EAI_NONAME)
			return DNS_CLASS_NXDOMAIN;
		if (error == EAI_NODATA)
			return DNS_CLASS_NOERROR;
		if (error == EAI_AGAIN)
			return DNS_CLASS_SERVFAIL;
		return DNS_CLASS_OTHER;
	}
	if (error == DNS_RCODE_NXDOMAIN)
		return DNS_CLASS_NXDOMAIN;
	if (error == DNS_RCODE_SERVFAIL)
		return DNS_CLASS_SERVFAIL;
	if (error == DNS_RCODE_REFUSED)
		return DNS_CLASS_REFUSED;
	return DNS_CLASS_OTHER;
}

static __always_inline int dns_class_failed(u32 class)
{
	return class != DNS_CLASS_NOERROR && class != DNS_CLASS_NXDOMAIN;
}

#endif
