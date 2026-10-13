// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include <bpf/bpf_endian.h>

#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define DNS_PORT 53
#define DOT_PORT 853
#define DOH_PORT 443
#define IPV6_HEADER_LEN 40
#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28
#define MAX_ANSWERS 4
#define MAX_NAME_LABELS 32
#define DNS_OFF_MASK 0x7ff
#define DNS_PTR_MASK 0x3fff
#define DNS_NAME_SCAN_LEN 96
#define IP6_HOPOPTS 0
#define IP6_ROUTING 43
#define IP6_FRAGMENT 44
#define IP6_DSTOPTS 60
#define MAX_IP6_EXTHDR 4

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

static __always_inline int l4_offset(struct __sk_buff *skb, u8 *is_v6, u8 *proto_out) {
	__u8 ver = 0;
	if (bpf_skb_load_bytes(skb, 0, &ver, 1) < 0)
		return -1;
	ver >>= 4;
	if (ver == 4) {
		__u8 verihl = 0;
		if (bpf_skb_load_bytes(skb, 0, &verihl, 1) < 0)
			return -1;
		__u8 ihl = (verihl & 0x0f) * 4;
		if (ihl < 20)
			return -1;
		__u8 proto = 0;
		if (bpf_skb_load_bytes(skb, 9, &proto, 1) < 0)
			return -1;
		if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
			return -1;
		__u16 frag = 0;
		if (bpf_skb_load_bytes(skb, 6, &frag, sizeof(frag)) < 0)
			return -1;
		if (bpf_ntohs(frag) & 0x1FFF)
			return -1;
		*is_v6 = 0;
		*proto_out = proto;
		return ihl;
	}
	if (ver == 6) {
		__u8 nexthdr = 0;
		if (bpf_skb_load_bytes(skb, 6, &nexthdr, 1) < 0)
			return -1;
		int off = IPV6_HEADER_LEN;
		for (int i = 0; i < MAX_IP6_EXTHDR; i++) {
			if (nexthdr == IPPROTO_UDP || nexthdr == IPPROTO_TCP) {
				*is_v6 = 1;
				*proto_out = nexthdr;
				return off & DNS_OFF_MASK;
			}
			if (nexthdr != IP6_HOPOPTS && nexthdr != IP6_ROUTING &&
			    nexthdr != IP6_FRAGMENT && nexthdr != IP6_DSTOPTS)
				return -1;
			off &= DNS_OFF_MASK;
			__u8 nh = 0;
			if (bpf_skb_load_bytes(skb, off, &nh, 1) < 0)
				return -1;
			if (nexthdr == IP6_FRAGMENT) {
				__u16 fragoff = 0;
				if (bpf_skb_load_bytes(skb, off + 2, &fragoff, sizeof(fragoff)) < 0)
					return -1;
				if (bpf_ntohs(fragoff) & 0xFFF8)
					return -1;
				off += 8;
			} else {
				__u8 hlen = 0;
				if (bpf_skb_load_bytes(skb, off + 1, &hlen, 1) < 0)
					return -1;
				off += ((int)hlen + 1) * 8;
			}
			nexthdr = nh;
		}
		return -1;
	}
	return -1;
}

static __always_inline int dns_msg_offset(struct __sk_buff *skb, int l4, u8 proto, u8 *transport) {
	if (proto == IPPROTO_UDP) {
		*transport = 0;
		return l4 + 8;
	}
	__u8 doff = 0;
	if (bpf_skb_load_bytes(skb, l4 + 12, &doff, 1) < 0)
		return -1;
	int tcphlen = ((doff >> 4) * 4) & 0x3c;
	if (tcphlen < 20)
		return -1;
	*transport = 1;
	return l4 + tcphlen + 2;
}

static __noinline int parse_qname(struct __sk_buff *skb, int off, char *out) {
	int j = 0, label_remaining = 0, need_len = 1;
	for (int i = 0; i < MAX_STRING_LEN - 1; i++) {
		__u8 c = 0;
		if (bpf_skb_load_bytes(skb, off, &c, 1) < 0)
			break;
		off++;
		if (need_len) {
			if (c == 0)
				break;
			if (c > 63)
				break;
			if (j > 0 && j < MAX_STRING_LEN - 1) {
				out[j & (MAX_STRING_LEN - 1)] = '.';
				j++;
			}
			label_remaining = c;
			need_len = 0;
		} else {
			if (j < MAX_STRING_LEN - 1)
				out[j & (MAX_STRING_LEN - 1)] = c;
			j++;
			label_remaining--;
			if (label_remaining <= 0)
				need_len = 1;
		}
	}
	return off;
}

static __noinline void parse_name_compressed(struct __sk_buff *skb, int dns_off, int off, char *out) {
	__u8 first = 0;
	if (bpf_skb_load_bytes(skb, off, &first, 1) < 0)
		return;
	if ((first & 0xc0) == 0xc0) {
		__u8 lo = 0;
		if (bpf_skb_load_bytes(skb, off + 1, &lo, 1) < 0)
			return;
		off = (dns_off + (((first & 0x3f) << 8) | lo)) & DNS_PTR_MASK;
	}

	int j = 0, label_remaining = 0, need_len = 1;
	for (int i = 0; i < DNS_NAME_SCAN_LEN; i++) {
		__u8 c = 0;
		if (bpf_skb_load_bytes(skb, off, &c, 1) < 0)
			break;
		off++;
		if (need_len) {
			if ((c & 0xc0) == 0xc0)
				break;
			if (c == 0)
				break;
			if (c > 63)
				break;
			if (j > 0 && j < MAX_STRING_LEN - 1) {
				out[j & (MAX_STRING_LEN - 1)] = '.';
				j++;
			}
			label_remaining = c;
			need_len = 0;
		} else {
			if (j < MAX_STRING_LEN - 1)
				out[j & (MAX_STRING_LEN - 1)] = c;
			j++;
			label_remaining--;
			if (label_remaining <= 0)
				need_len = 1;
		}
	}
	out[j & (MAX_STRING_LEN - 1)] = '\0';
}

static __always_inline int is_known_doh(__u32 d) {
	return d == 0x01010101 || // 1.1.1.1 Cloudflare
	       d == 0x01000001 || // 1.0.0.1 Cloudflare
	       d == 0x08080808 || // 8.8.8.8 Google
	       d == 0x04040808 || // 8.8.4.4 Google
	       d == 0x09090909;   // 9.9.9.9 Quad9
}

static __always_inline int is_known_doh6(const u8 *a) {
	if (a[0] == 0x26 && a[1] == 0x06 && a[2] == 0x47 && a[3] == 0x00 &&
	    a[4] == 0x47 && a[5] == 0x00)
		return 1; // 2606:4700:4700:: Cloudflare
	if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x48 && a[3] == 0x60 &&
	    a[4] == 0x48 && a[5] == 0x60)
		return 1; // 2001:4860:4860:: Google
	if (a[0] == 0x26 && a[1] == 0x20 && a[2] == 0x00 && a[3] == 0xfe)
		return 1; // 2620:fe:: Quad9
	return 0;
}

static __always_inline void dns_drop_inc(void) {
	u32 z = 0;
	u64 *c = bpf_map_lookup_elem(&dns_drops, &z);
	if (c)
		(*c)++;
}

static __always_inline int encrypted_dns_first_seen(struct __sk_buff *skb, u8 is_v6,
						    __u16 dport, __u16 sport) {
	struct encrypted_dns_flow k = {};
	k.cgroup_id = bpf_skb_cgroup_id(skb);
	k.dport = dport;
	k.sport = sport;
	int rc = is_v6 ? bpf_skb_load_bytes(skb, 24, k.daddr6, 16)
		       : bpf_skb_load_bytes(skb, 16, k.daddr6, 4);
	if (rc < 0)
		return 1;
	if (bpf_map_lookup_elem(&encrypted_dns_seen, &k))
		return 0;
	u8 one = 1;
	bpf_map_update_elem(&encrypted_dns_seen, &k, &one, BPF_ANY);
	return 1;
}

static __always_inline void emit_encrypted_dns(struct __sk_buff *skb, u8 is_v6, __u16 port,
					       __u16 sport, int is_doh) {
	if (!encrypted_dns_first_seen(skb, is_v6, port, sport))
		return;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		dns_drop_inc();
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp = bpf_ktime_get_ns();
	e->pid = agent_ns_tgid();
	e->type = EVENT_DNS;
	e->cgroup_id = bpf_skb_cgroup_id(skb);
	e->dns_transport = DNS_SOURCE_ENCRYPTED;
	if (is_v6) {
		u8 a6[16] = {};
		if (bpf_skb_load_bytes(skb, 24, a6, sizeof(a6)) == 0) {
			format_ipv6_port(a6, port, e->target);
			__builtin_memcpy(e->dns_server_ip6, a6, 16);
		}
	} else {
		__u32 daddr = 0;
		if (bpf_skb_load_bytes(skb, 16, &daddr, sizeof(daddr)) == 0) {
			/* daddr is network order; format_ip_port expects host order.
			 * The raw field stays network order for the Go consumers. */
			format_ip_port(__builtin_bswap32(daddr), port, e->target);
			e->dns_server_ip = daddr;
		}
	}
	__builtin_memcpy(e->details, is_doh ? "encrypted (DoH)" : "encrypted (DoT)",
			 sizeof("encrypted (DoH)"));
	if (agg_absorbed(e, 0))
		bpf_ringbuf_discard(e, 0);
	else
		bpf_ringbuf_submit(e, 0);
}

static __noinline int skip_name(struct __sk_buff *skb, int off) {
	for (int i = 0; i < MAX_NAME_LABELS; i++) {
		off &= DNS_OFF_MASK;
		__u8 c = 0;
		if (bpf_skb_load_bytes(skb, off, &c, 1) < 0)
			return -1;
		if ((c & 0xc0) == 0xc0)
			return (off + 2) & DNS_OFF_MASK;
		if (c == 0)
			return (off + 1) & DNS_OFF_MASK;
		off += 1 + c;
	}
	return off & DNS_OFF_MASK;
}

SEC("cgroup_skb/egress")
int dns_egress(struct __sk_buff *skb) {
	u8 is_v6 = 0, proto = 0;
	int l4 = l4_offset(skb, &is_v6, &proto);
	if (l4 < 0)
		return 1;

	__u16 dport = 0;
	if (bpf_skb_load_bytes(skb, l4 + 2, &dport, sizeof(dport)) < 0)
		return 1;
	__u16 dporth = bpf_ntohs(dport);
	__u16 sport = 0;
	bpf_skb_load_bytes(skb, l4, &sport, sizeof(sport));

	if (dporth == DOT_PORT) {
		emit_encrypted_dns(skb, is_v6, DOT_PORT, sport, 0);
		return 1;
	}

	if (dporth == DOH_PORT) {
		if (!is_v6) {
			__u32 daddr = 0;
			if (bpf_skb_load_bytes(skb, 16, &daddr, sizeof(daddr)) == 0 && is_known_doh(daddr)) {
				emit_encrypted_dns(skb, 0, DOH_PORT, sport, 1);
				return 1;
			}
		} else {
			u8 a6[16] = {};
			if (bpf_skb_load_bytes(skb, 24, a6, sizeof(a6)) == 0 && is_known_doh6(a6)) {
				emit_encrypted_dns(skb, 1, DOH_PORT, sport, 1);
				return 1;
			}
		}
	}

	if (dporth != DNS_PORT)
		return 1;

	u8 transport = 0;
	int dns_off = dns_msg_offset(skb, l4, proto, &transport);
	if (dns_off < 0)
		return 1;
	__u16 flags = 0;
	if (bpf_skb_load_bytes(skb, dns_off + 2, &flags, sizeof(flags)) < 0)
		return 1;
	if (bpf_ntohs(flags) & 0x8000)
		return 1;

	__u16 txid = 0;
	if (bpf_skb_load_bytes(skb, dns_off, &txid, sizeof(txid)) < 0)
		return 1;

	struct dns_flow_key key = {};
	key.cgroup_id = bpf_skb_cgroup_id(skb);
	key.txid = bpf_ntohs(txid);

	struct dns_query_state *sent = bpf_map_lookup_elem(&dns_inflight, &key);
	if (sent) {
		sent->last_ns = bpf_ktime_get_ns();
		return 1;
	}

	struct dns_query_state q = {};
	q.ts_ns = bpf_ktime_get_ns();
	q.last_ns = q.ts_ns;
	q.pid = agent_ns_tgid();
	q.transport = transport;
	if (!is_v6) {
		__u32 daddr = 0;
		if (bpf_skb_load_bytes(skb, 16, &daddr, sizeof(daddr)) == 0)
			q.server_ip = daddr;
	} else {
		bpf_skb_load_bytes(skb, 24, q.server_ip6, sizeof(q.server_ip6));
	}

	int qend = parse_qname(skb, dns_off + 12, q.name);
	__u16 qtype = 0;
	if (bpf_skb_load_bytes(skb, qend, &qtype, sizeof(qtype)) == 0)
		q.qtype = bpf_ntohs(qtype);

	if (bpf_map_update_elem(&dns_inflight, &key, &q, BPF_ANY) < 0)
		dns_drop_inc();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 1;
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp = q.ts_ns;
	e->pid = q.pid;
	e->type = EVENT_DNS_QUERY;
	e->cgroup_id = key.cgroup_id;
	e->tcp_state = q.qtype;
	e->dns_server_ip = q.server_ip;
	e->dns_transport = q.transport;
	__builtin_memcpy(e->dns_server_ip6, q.server_ip6, 16);
	__builtin_memcpy(e->comm, q.comm, COMM_LEN);
	__builtin_memcpy(e->target, q.name, MAX_STRING_LEN);
	if (agg_absorbed(e, 0))
		bpf_ringbuf_discard(e, 0);
	else
		bpf_ringbuf_submit(e, 0);
	return 1;
}

struct dns_payload_meta {
	u64 cgroup_id;
	u64 latency_ns;
	u16 txid;
	u8 rcode;
	u8 is_v6;
	u8 agg_recorded;
};

static __noinline void emit_dns_payload(struct __sk_buff *skb, int dns_off,
					struct dns_query_state *q,
					struct dns_payload_meta *m) {
	u32 zero = 0;
	struct dns_payload_scratch *scr =
		bpf_map_lookup_elem(&dns_payload_scratch_map, &zero);
	if (!scr)
		return;
	__builtin_memset(&scr->rec, 0, sizeof(scr->rec));
	scr->rec.cgroup_id = m->cgroup_id;
	scr->rec.timestamp = bpf_ktime_get_ns();
	scr->rec.latency_ns = m->latency_ns;
	scr->rec.pid = q->pid;
	scr->rec.server_ip = q->server_ip;
	__builtin_memcpy(scr->rec.server_ip6, q->server_ip6, 16);
	scr->rec.txid = m->txid;
	scr->rec.qtype = (u16)q->qtype;
	scr->rec.transport = q->transport;
	scr->rec.is_v6 = m->is_v6;
	scr->rec.rcode = m->rcode;
	scr->rec.agg_recorded = m->agg_recorded;

	u32 avail = skb->len > (u32)dns_off ? skb->len - (u32)dns_off : 0;
	if (avail > DNS_PAYLOAD_MAX - 1)
		avail = DNS_PAYLOAD_MAX - 1;
	barrier_var(avail);
	avail &= (DNS_PAYLOAD_MAX - 1);
	if (avail == 0) {
		dns_drop_inc();
		return;
	}
	if (bpf_skb_load_bytes(skb, dns_off, scr->payload, avail) < 0) {
		dns_drop_inc();
		return;
	}
	scr->rec.payload_len = (u16)avail;
	bpf_ringbuf_output(&dns_payload_events, scr, sizeof(scr->rec) + avail, 0);
}

SEC("cgroup_skb/ingress")
int dns_ingress(struct __sk_buff *skb) {
	u8 is_v6 = 0, proto = 0;
	int l4 = l4_offset(skb, &is_v6, &proto);
	if (l4 < 0)
		return 1;

	__u16 sport = 0;
	if (bpf_skb_load_bytes(skb, l4, &sport, sizeof(sport)) < 0)
		return 1;
	if (bpf_ntohs(sport) != DNS_PORT)
		return 1;

	u8 transport = 0;
	int dns_off = dns_msg_offset(skb, l4, proto, &transport);
	if (dns_off < 0)
		return 1;
	__u16 flags = 0, txid = 0;
	if (bpf_skb_load_bytes(skb, dns_off, &txid, sizeof(txid)) < 0)
		return 1;
	if (bpf_skb_load_bytes(skb, dns_off + 2, &flags, sizeof(flags)) < 0)
		return 1;
	__u16 flagsh = bpf_ntohs(flags);
	if (!(flagsh & 0x8000))
		return 1;

	struct dns_flow_key key = {};
	key.cgroup_id = bpf_skb_cgroup_id(skb);
	key.txid = bpf_ntohs(txid);
	struct dns_query_state *q = bpf_map_lookup_elem(&dns_inflight, &key);
	if (!q)
		return 1;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		dns_drop_inc();
		bpf_map_delete_elem(&dns_inflight, &key);
		return 1;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp = bpf_ktime_get_ns();
	e->pid = q->pid;
	e->type = EVENT_DNS;
	e->cgroup_id = key.cgroup_id;
	e->latency_ns = e->timestamp - q->ts_ns;
	e->error = flagsh & 0x000f;
	e->tcp_state = q->qtype;
	e->dns_server_ip = q->server_ip;
	e->dns_transport = q->transport;
	__builtin_memcpy(e->dns_server_ip6, q->server_ip6, 16);
	__builtin_memcpy(e->comm, q->comm, COMM_LEN);
	__builtin_memcpy(e->target, q->name, MAX_STRING_LEN);

	u32 pz = 0;
	u32 *payload_on = bpf_map_lookup_elem(&dns_payload_enabled, &pz);
	if (payload_on && *payload_on) {
		u64 latency = e->latency_ns;
		int recorded = agg_from_event(e, 0);
		bpf_ringbuf_discard(e, 0);
		struct dns_payload_meta meta = {
			.cgroup_id = key.cgroup_id,
			.latency_ns = latency,
			.txid = (u16)key.txid,
			.rcode = (u8)(flagsh & 0x000f),
			.is_v6 = is_v6,
			.agg_recorded = (u8)recorded,
		};
		emit_dns_payload(skb, dns_off, q, &meta);
		bpf_map_delete_elem(&dns_inflight, &key);
		return 1;
	}

	__u16 ancount = 0;
	if (bpf_skb_load_bytes(skb, dns_off + 6, &ancount, sizeof(ancount)) == 0)
		ancount = bpf_ntohs(ancount);
	e->bytes = ancount;

	int qname_end = skip_name(skb, dns_off + 12);
	int aoff = qname_end + 4;
	int wrote_detail = 0;

	for (int a = 0; a < MAX_ANSWERS; a++) {
		if (a >= ancount || qname_end < 0)
			break;
		aoff = skip_name(skb, aoff);
		if (aoff < 0)
			break;
		aoff &= DNS_OFF_MASK;
		__u16 atype = 0, rdlen = 0;
		if (bpf_skb_load_bytes(skb, aoff, &atype, sizeof(atype)) < 0)
			break;
		atype = bpf_ntohs(atype);
		if (bpf_skb_load_bytes(skb, (aoff + 8) & DNS_OFF_MASK, &rdlen, sizeof(rdlen)) < 0)
			break;
		rdlen = bpf_ntohs(rdlen);
		int rdata = (aoff + 10) & DNS_OFF_MASK;

		if (atype == DNS_TYPE_A) {
			__u32 ip = 0;
			if (bpf_skb_load_bytes(skb, rdata, &ip, sizeof(ip)) == 0) {
				struct dns_resolved_key rk = { .cgroup_id = key.cgroup_id, .ip = ip };
				bpf_map_update_elem(&dns_resolved, &rk, q->name, BPF_ANY);
				format_ip_port(__builtin_bswap32(ip), 0, e->details);
				wrote_detail = 1;
			}
		} else if (atype == DNS_TYPE_AAAA) {
			struct dns_v6key k6 = { .cgroup_id = key.cgroup_id };
			if (bpf_skb_load_bytes(skb, rdata, k6.addr, sizeof(k6.addr)) == 0) {
				bpf_map_update_elem(&dns_resolved6, &k6, q->name, BPF_ANY);
				if (!wrote_detail) {
					format_ipv6_port(k6.addr, 0, e->details);
					wrote_detail = 1;
				}
			}
		} else if (atype == DNS_TYPE_CNAME && !wrote_detail) {
			parse_name_compressed(skb, dns_off, rdata, e->details);
			wrote_detail = 1;
		}
		aoff = (rdata + (rdlen & DNS_OFF_MASK)) & DNS_OFF_MASK;
	}

	/* A reserved record must be released either way: discard rather than
	 * submit when the map already absorbed it, or the reservation leaks
	 * and the ring wedges. */
	if (agg_absorbed(e, 0))
		bpf_ringbuf_discard(e, 0);
	else
		bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&dns_inflight, &key);
	return 1;
}