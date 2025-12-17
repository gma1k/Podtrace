// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("tp/exceptions/page_fault_user")
int tracepoint_page_fault_user(void *ctx) {
	// NOTE: Tracepoint argument layouts can differ across kernels/distros when using raw tracepoints.
	// For stability, avoid relying on tracepoint "common_pid" field offsets here and use the
	// current task PID from bpf_get_current_pid_tgid().
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	
	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_PAGE_FAULT;
	e->latency_ns = 0;
	// Best-effort: omit error_code (layout is not stable without BTF-typed tracepoints).
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->target[0] = '\0';
	
	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
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
	
	struct event *e = get_event_buf();
	if (!e) {
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = args_local.pid;
	e->type = EVENT_OOM_KILL;
	e->latency_ns = 0;
	e->error = 0;
	e->bytes = args_local.totalpages * PAGE_SIZE;
	e->tcp_state = 0;
	
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), args_local.comm);
	
	capture_user_stack(ctx, e->pid, 0, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}
