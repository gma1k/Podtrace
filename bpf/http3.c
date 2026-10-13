// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

static __always_inline int quic_is_initial(struct __sk_buff *skb, int l4) {
	u8 first = 0;
	if (bpf_skb_load_bytes(skb, l4 + 8, &first, 1) < 0)
		return 0;
	if ((first & 0xC0) != 0xC0)
		return 0;
	u32 version = 0;
	if (bpf_skb_load_bytes(skb, l4 + 9, &version, sizeof(version)) < 0)
		return 0;
	u32 v = bpf_ntohl(version);
	if (v == 0x00000001)
		return (first & 0x30) == 0x00;
	if (v == 0x6b3343cf)
		return (first & 0x30) == 0x10;
	return 0;
}

static __always_inline void quic_ship(struct __sk_buff *skb, u8 is_v6,
				      u32 addr_off, u32 port_l4_off, int l4, u8 egress) {
	struct quic_flow_key k = {};
	k.cgroup_id = bpf_skb_cgroup_id(skb);
	u16 port_be = 0;
	if (bpf_skb_load_bytes(skb, l4 + port_l4_off, &port_be, sizeof(port_be)) < 0)
		return;
	k.dport = bpf_ntohs(port_be);
	if (is_v6) {
		if (bpf_skb_load_bytes(skb, addr_off, k.daddr6, 16) < 0)
			return;
	} else {
		if (bpf_skb_load_bytes(skb, addr_off, k.daddr6, 4) < 0)
			return;
	}
	u8 *cnt = bpf_map_lookup_elem(&quic_seen, &k);
	if (cnt) {
		if (*cnt >= QUIC_INITIAL_MAX_PKTS)
			return;
		*cnt += 1;
	} else {
		u8 one = 1;
		bpf_map_update_elem(&quic_seen, &k, &one, BPF_ANY);
	}

	u32 zero = 0;
	struct quic_initial_record *rec =
		bpf_map_lookup_elem(&quic_initial_scratch, &zero);
	if (!rec)
		return;
	rec->timestamp = bpf_ktime_get_ns();
	rec->cgroup_id = k.cgroup_id;
	rec->pid = egress ? agent_ns_tgid() : 0;
	__builtin_memset(rec->comm, 0, sizeof(rec->comm));
	rec->family = is_v6 ? 10 : 2;
	rec->_pad = 0;
	rec->dport = k.dport;
	rec->_pad2 = 0;
	__builtin_memcpy(rec->daddr6, k.daddr6, 16);
	u32 off = (u32)l4 + 8;
	u32 caplen = skb->len > off ? skb->len - off : 0;
	if (caplen > QUIC_PKT_CAP)
		caplen = QUIC_PKT_CAP;
	if (caplen < 20 || bpf_skb_load_bytes(skb, off, rec->pkt, caplen) < 0)
		return;
	rec->pktlen = (u16)caplen;
	bpf_ringbuf_output(&quic_initial_events, rec,
			   __builtin_offsetof(struct quic_initial_record, pkt) + caplen, 0);
}

SEC("cgroup_skb/egress")
int http3_egress(struct __sk_buff *skb) {
	u8 is_v6 = 0, proto = 0;
	int l4 = l4_offset(skb, &is_v6, &proto);
	if (l4 < 0 || proto != IPPROTO_UDP)
		return 1;
	if (!quic_is_initial(skb, l4))
		return 1;
	quic_ship(skb, is_v6, is_v6 ? 24 : 16, 2, l4, 1);
	return 1;
}

SEC("cgroup_skb/ingress")
int http3_ingress(struct __sk_buff *skb) {
	u8 is_v6 = 0, proto = 0;
	int l4 = l4_offset(skb, &is_v6, &proto);
	if (l4 < 0 || proto != IPPROTO_UDP)
		return 1;
	if (!quic_is_initial(skb, l4))
		return 1;
	quic_ship(skb, is_v6, is_v6 ? 8 : 12, 0, l4, 0);
	return 1;
}