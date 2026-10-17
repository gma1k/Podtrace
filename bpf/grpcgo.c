// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"


#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GRPC_GO_HF_PTR(ctx)       ((u64)(ctx)->di)
#define GRPC_GO_HF_LEN(ctx)       ((u64)(ctx)->si)
#define GRPC_GO_WH_STREAM(ctx)    ((u32)(ctx)->bx)
#define GRPC_GO_SRV_FRAME(ctx)    ((u64)(ctx)->di)
#define GRPC_GO_CLI_FRAME(ctx)    ((u64)(ctx)->bx)
#define GRPC_GO_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GRPC_GO_HF_PTR(ctx)       ((u64)(ctx)->regs[3])
#define GRPC_GO_HF_LEN(ctx)       ((u64)(ctx)->regs[4])
#define GRPC_GO_WH_STREAM(ctx)    ((u32)(ctx)->regs[1])
#define GRPC_GO_SRV_FRAME(ctx)    ((u64)(ctx)->regs[3])
#define GRPC_GO_CLI_FRAME(ctx)    ((u64)(ctx)->regs[1])
#define GRPC_GO_SUPPORTED 1
#endif


#ifdef GRPC_GO_SUPPORTED

#define GRPC_HF_STRIDE 40
#define GRPC_HF_MAX    32
#define GRPC_NAME_PEEK 12

#define GRPC_METAFRAME_HEADERS_PTR 0
#define GRPC_METAFRAME_FIELDS_PTR 8
#define GRPC_METAFRAME_FIELDS_LEN 16
#define GRPC_FRAMEHEADER_STREAMID 8

struct grpc_hf_ctx {
	u64 fields;
	u32 n;
};

static long grpc_hf_cb(u32 i, void *vctx)
{
	struct grpc_hf_ctx *c = (struct grpc_hf_ctx *)vctx;
	if (i >= c->n)
		return 1;
	u32 zero = 0;
	struct grpc_go_scratch *s = bpf_map_lookup_elem(&grpc_go_scratch_map, &zero);
	if (!s)
		return 1;

	u64 fptr = c->fields + (u64)i * GRPC_HF_STRIDE;
	u64 nptr = 0, nlen = 0;
	if (bpf_probe_read_user(&nptr, sizeof(nptr), (void *)fptr) != 0)
		return 0;
	if (bpf_probe_read_user(&nlen, sizeof(nlen), (void *)(fptr + 8)) != 0)
		return 0;
	if (nlen == 0 || nptr == 0)
		return 0;

	char name[GRPC_NAME_PEEK] = {};
	u32 rn = nlen < GRPC_NAME_PEEK ? (u32)nlen : GRPC_NAME_PEEK;
	if (bpf_probe_read_user(name, rn, (void *)nptr) != 0)
		return 0;

	if (name[0] != ':')
		return 0;

	u64 vptr = 0, vlen = 0;
	if (bpf_probe_read_user(&vptr, sizeof(vptr), (void *)(fptr + 16)) != 0)
		return 0;
	if (bpf_probe_read_user(&vlen, sizeof(vlen), (void *)(fptr + 24)) != 0)
		return 0;
	if (vptr == 0)
		return 0;

	if (name[1] == 'p' && name[2] == 'a' && name[3] == 't' && name[4] == 'h') {
		if (s->have_path)
			return 0;
		__builtin_memset(s->path, 0, sizeof(s->path));
		u32 vl = vlen < (MAX_STRING_LEN - 1) ? (u32)vlen : (MAX_STRING_LEN - 1);
		if (vl > 0 && bpf_probe_read_user(s->path, vl, (void *)vptr) == 0) {
			s->path[vl & (MAX_STRING_LEN - 1)] = '\0';
			s->have_path = 1;
		}
	} else if (name[1] == 'm' && name[2] == 'e' && name[3] == 't') {
		if (s->have_method)
			return 0;
		__builtin_memset(s->method, 0, sizeof(s->method));
		u32 vl = vlen < (sizeof(s->method) - 1) ? (u32)vlen : (sizeof(s->method) - 1);
		if (vl > 0 && bpf_probe_read_user(s->method, vl, (void *)vptr) == 0) {
			s->method[vl & (sizeof(s->method) - 1)] = '\0';
			s->have_method = 1;
		}
	} else if (name[1] == 's' && name[2] == 't' && name[3] == 'a') {
		if (s->have_status)
			return 0;
		__builtin_memset(s->status, 0, sizeof(s->status));
		u32 vl = vlen < (sizeof(s->status) - 1) ? (u32)vlen : (sizeof(s->status) - 1);
		if (vl > 0 && bpf_probe_read_user(s->status, vl, (void *)vptr) == 0) {
			s->status[vl & (sizeof(s->status) - 1)] = '\0';
			s->have_status = 1;
		}
	}
	return 0;
}

static __always_inline int grpc_pair_key_build(struct grpc_pair_key *k, u32 stream)
{
	struct tcp_peer *p = lookup_tcp_peer(PAIR_TCP_SENDMSG);
	if (!p)
		return 0;
	__builtin_memset(k, 0, sizeof(*k));
	k->saddr = p->saddr;
	k->daddr = p->daddr;
	k->sport = p->sport;
	k->dport = p->dport;
	k->stream = stream;
	return 1;
}

static __always_inline void grpc_go_process(void *ctx, u64 fields, u64 n, u32 stream, u8 inbound)
{
	if (!fields || n == 0)
		return;

	u32 zero = 0;
	struct grpc_go_scratch *s = bpf_map_lookup_elem(&grpc_go_scratch_map, &zero);
	if (!s)
		return;
	__builtin_memset(s, 0, sizeof(*s));

	struct grpc_hf_ctx c = {
		.fields = fields,
		.n = n < GRPC_HF_MAX ? (u32)n : GRPC_HF_MAX,
	};
	bpf_loop(GRPC_HF_MAX, grpc_hf_cb, &c, 0);

	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct grpc_pair_key pk;
	int have_key = grpc_pair_key_build(&pk, stream);

	if (s->have_path) {
		u64 start_ns = bpf_ktime_get_ns();
		if (have_key) {
			u32 pz = 0;
			struct grpc_pair_val *pv = bpf_map_lookup_elem(&grpc_go_pairval_map, &pz);
			if (pv) {
				pv->start_ns = start_ns;
				__builtin_memcpy(pv->path, s->path, sizeof(pv->path));
				bpf_map_update_elem(&grpc_go_pairs, &pk, pv, BPF_ANY);
			}
		}
		struct event *e = get_event_buf();
		if (e) {
			e->timestamp = start_ns;
			e->pid = pid;
			e->type = EVENT_HTTP_REQ;
			e->latency_ns = 0;
			e->error = 0;
			e->bytes = 0;
			e->tcp_state = HTTP_TRANSPORT_H2_TLS | HTTP_ROLE_KNOWN | (inbound ? HTTP_ROLE_SERVER : 0);
			e->correlation_id = start_ns;
			bpf_probe_read_kernel_str(e->target, sizeof(e->target), s->path);
			fill_event_peer(e);
			capture_user_stack(ctx, pid, tid, e);
			bpf_ringbuf_output(&events, e, sizeof(*e), 0);
		}
	} else if (s->have_status) {
		struct event *e = get_event_buf();
		if (e) {
			e->timestamp = bpf_ktime_get_ns();
			e->pid = pid;
			e->type = EVENT_HTTP_RESP;
			e->latency_ns = 0;
			s32 code = http_parse_status3(s->status);
			e->error = code >= 500 ? code : 0;
			e->bytes = 0;
			e->tcp_state = HTTP_TRANSPORT_H2_TLS | HTTP_ROLE_KNOWN | (inbound ? 0 : HTTP_ROLE_SERVER);
			bpf_probe_read_kernel_str(e->details, sizeof(e->details), s->status);
			if (have_key) {
				struct grpc_pair_val *v = bpf_map_lookup_elem(&grpc_go_pairs, &pk);
				if (v) {
					bpf_probe_read_kernel_str(e->target, sizeof(e->target), v->path);
					e->latency_ns = calc_latency(v->start_ns);
					e->correlation_id = v->start_ns;
					bpf_map_delete_elem(&grpc_go_pairs, &pk);
				}
			}
			fill_event_peer(e);
			capture_user_stack(ctx, pid, tid, e);
			bpf_ringbuf_output(&events, e, sizeof(*e), 0);
		}
	}
}

static __always_inline u32 grpc_go_stream_from_frame(u64 frame)
{
	u64 hf = 0;
	if (bpf_probe_read_user(&hf, sizeof(hf), (void *)(frame + GRPC_METAFRAME_HEADERS_PTR)) != 0 || !hf)
		return 0;
	u32 sid = 0;
	if (bpf_probe_read_user(&sid, sizeof(sid), (void *)(hf + GRPC_FRAMEHEADER_STREAMID)) != 0)
		return 0;
	return sid;
}

static __always_inline void grpc_go_process_frame(void *ctx, u64 frame, u8 inbound)
{
	if (!frame)
		return;
	u64 fptr = 0, flen = 0;
	if (bpf_probe_read_user(&fptr, sizeof(fptr), (void *)(frame + GRPC_METAFRAME_FIELDS_PTR)) != 0)
		return;
	if (bpf_probe_read_user(&flen, sizeof(flen), (void *)(frame + GRPC_METAFRAME_FIELDS_LEN)) != 0)
		return;
	grpc_go_process(ctx, fptr, flen, grpc_go_stream_from_frame(frame), inbound);
}

SEC("uprobe/grpc_go_write_header")
int uprobe_grpc_go_write_header(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	grpc_go_process(ctx, GRPC_GO_HF_PTR(ctx), GRPC_GO_HF_LEN(ctx), GRPC_GO_WH_STREAM(ctx), 0);
	return 0;
}

SEC("uprobe/grpc_go_server_headers")
int uprobe_grpc_go_server_headers(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	grpc_go_process_frame(ctx, GRPC_GO_SRV_FRAME(ctx), 1);
	return 0;
}

SEC("uprobe/grpc_go_client_headers")
int uprobe_grpc_go_client_headers(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;
	grpc_go_process_frame(ctx, GRPC_GO_CLI_FRAME(ctx), 1);
	return 0;
}

#else

SEC("uprobe/grpc_go_write_header")
int uprobe_grpc_go_write_header(struct pt_regs *ctx) { return 0; }

SEC("uprobe/grpc_go_server_headers")
int uprobe_grpc_go_server_headers(struct pt_regs *ctx) { return 0; }

SEC("uprobe/grpc_go_client_headers")
int uprobe_grpc_go_client_headers(struct pt_regs *ctx) { return 0; }

#endif