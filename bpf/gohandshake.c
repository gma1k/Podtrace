// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"
#include "agg.h"

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define GO_HS_GOROUTINE(ctx) ((u64)(ctx)->r14)
#define GO_HS_ERROR_TYPE(ctx) ((u64)(ctx)->ax)
#define GO_HS_SUPPORTED 1
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define GO_HS_GOROUTINE(ctx) ((u64)(ctx)->regs[28])
#define GO_HS_ERROR_TYPE(ctx) ((u64)(ctx)->regs[0])
#define GO_HS_SUPPORTED 1
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} go_tls_handshakes SEC(".maps");

#ifdef GO_HS_SUPPORTED

SEC("uprobe/go_tls_handshake")
int uprobe_go_tls_handshake(struct pt_regs *ctx)
{
	u64 g = process_scoped_id(GO_HS_GOROUTINE(ctx));
	if (g == 0)
		return 0;
	u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&go_tls_handshakes, &g, &now, BPF_ANY);
	return 0;
}

SEC("uprobe/go_tls_handshake_ret")
int uprobe_go_tls_handshake_ret(struct pt_regs *ctx)
{
	u64 g = process_scoped_id(GO_HS_GOROUTINE(ctx));
	u64 error_type = GO_HS_ERROR_TYPE(ctx);
	if (g == 0)
		return 0;
	u64 *start = bpf_map_lookup_elem(&go_tls_handshakes, &g);
	if (!start)
		return 0;
	u64 began = *start;
	bpf_map_delete_elem(&go_tls_handshakes, &g);

	u64 now = bpf_ktime_get_ns();
	if (now <= began)
		return 0;

	struct event *e = get_event_buf();
	if (!e)
		return 0;
	e->timestamp = now;
	e->pid = agent_ns_tgid();
	e->type = EVENT_TLS_HANDSHAKE;
	e->latency_ns = now - began;
	e->error = error_type ? -1 : 0;
	if (!agg_absorbed(e, 0))
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

#else

SEC("uprobe/go_tls_handshake")
int uprobe_go_tls_handshake(struct pt_regs *ctx) { return 0; }

SEC("uprobe/go_tls_handshake_ret")
int uprobe_go_tls_handshake_ret(struct pt_regs *ctx) { return 0; }

#endif
