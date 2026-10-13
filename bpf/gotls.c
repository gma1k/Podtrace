// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "protocols.h"


#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_ARG_PTR(ctx)   ((void *)(ctx)->bx)
#define GO_ARG_LEN(ctx)   ((u64)(ctx)->cx)
#define GO_ARG_RECV(ctx)  ((u64)(ctx)->ax)
#define GO_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_TLS_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_ARG_PTR(ctx)   ((void *)PT_REGS_PARM2(ctx))
#define GO_ARG_LEN(ctx)   ((u64)PT_REGS_PARM3(ctx))
#define GO_ARG_RECV(ctx)  ((u64)PT_REGS_PARM1(ctx))
#define GO_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_TLS_SUPPORTED 1
#endif


#ifdef GO_TLS_SUPPORTED

#define GO_PEEK_LEN 16

static __always_inline int go_tls_is_http1_response(const u8 *peek)
{
	return peek[0] == 'H' && peek[1] == 'T' && peek[2] == 'T' && peek[3] == 'P' &&
	       peek[4] == '/' && peek[5] == '1' && peek[6] == '.';
}

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	void *base = GO_ARG_PTR(ctx);
	u64 avail = GO_ARG_LEN(ctx);
	u64 conn = process_scoped_id(GO_ARG_RECV(ctx));
	if (!base || avail < HTTP2_FRAME_HDR)
		return 0;

	u8 peek[GO_PEEK_LEN] = {};
	u32 plen = avail < GO_PEEK_LEN ? (u32)avail : GO_PEEK_LEN;
	if (bpf_probe_read_user(peek, plen, base) != 0)
		return 0;

	if (http_method_len(peek) > 0) {
		http_emit_request(ctx, base, avail, HTTP_TRANSPORT_TLS, conn);
	} else if (go_tls_is_http1_response(peek)) {
		http_emit_response(ctx, base, avail, HTTP_TRANSPORT_TLS, conn);
	} else {
		h2_emit_frames(base, avail, conn, H2_DIR_EGRESS,
			       HTTP_TRANSPORT_H2_TLS);
	}
	return 0;
}

SEC("uprobe/go_tls_read")
int uprobe_go_tls_read(struct pt_regs *ctx)
{
	if (!http_should_trace())
		return 0;

	void *buf = GO_ARG_PTR(ctx);
	if (!buf)
		return 0;

	u64 key = process_scoped_id(GO_GOROUTINE(ctx));
	struct go_tls_read_state st = {
		.buf = (u64)buf,
		.conn = process_scoped_id(GO_ARG_RECV(ctx)),
	};
	bpf_map_update_elem(&go_tls_read_args, &key, &st, BPF_ANY);
	return 0;
}

SEC("uprobe/go_tls_read_ret")
int uprobe_go_tls_read_ret(struct pt_regs *ctx)
{
	u64 key = process_scoped_id(GO_GOROUTINE(ctx));
	struct go_tls_read_state *st = bpf_map_lookup_elem(&go_tls_read_args, &key);
	if (!st)
		return 0;
	void *buf = (void *)st->buf;
	u64 conn = st->conn;
	bpf_map_delete_elem(&go_tls_read_args, &key);

	s64 n = (s64)PT_REGS_RC(ctx);
	if (n <= 0)
		return 0;

	u8 peek[GO_PEEK_LEN] = {};
	u32 plen = (u64)n < GO_PEEK_LEN ? (u32)n : GO_PEEK_LEN;
	if (bpf_probe_read_user(peek, plen, buf) != 0)
		return 0;

	if (go_tls_is_http1_response(peek))
		http_emit_response(ctx, buf, (u64)n, HTTP_TRANSPORT_TLS | HTTP_INBOUND, conn);
	else if (http_method_len(peek) > 0)
		http_emit_request(ctx, buf, (u64)n, HTTP_TRANSPORT_TLS | HTTP_INBOUND, conn);
	else
		h2_emit_frames(buf, (u64)n, conn, H2_DIR_INGRESS, HTTP_TRANSPORT_H2_TLS);
	return 0;
}

#else

SEC("uprobe/go_tls_write")
int uprobe_go_tls_write(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_tls_read")
int uprobe_go_tls_read(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_tls_read_ret")
int uprobe_go_tls_read_ret(struct pt_regs *ctx) { return 0; }

#endif