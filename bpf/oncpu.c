// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "helpers.h"
#include "oncpu.h"

#define ONCPU_CTX_U64(field)   (*(volatile u64 *)&(field))
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#define ONCPU_USER_MODE(regs)  ((ONCPU_CTX_U64((regs)->cs) & 3) == 3)
#define ONCPU_GOROUTINE(regs)  ONCPU_CTX_U64((regs)->r14)
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define ONCPU_USER_MODE(regs)  ((ONCPU_CTX_U64((regs)->pstate) & 0xf) == 0)
#define ONCPU_GOROUTINE(regs)  ONCPU_CTX_U64((regs)->regs[28])
#else
#define ONCPU_USER_MODE(regs)  0
#define ONCPU_GOROUTINE(regs)  0
#endif

static __always_inline void oncpu_count_lost(u32 reason)
{
	u64 *lost = bpf_map_lookup_elem(&oncpu_lost, &reason);
	if (lost)
		(*lost)++;
}

static __always_inline u64 oncpu_task_goroutine(void)
{
	struct pt_regs *user = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
	if (!user)
		return 0;
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
	return BPF_CORE_READ(user, r14);
#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	return BPF_CORE_READ(user, regs[28]);
#else
	return 0;
#endif
}

static __always_inline u64 oncpu_goroutine_active(struct pt_regs *regs, u32 tgid, int task_regs)
{
	struct oncpu_goroutine_key k = {.tgid = tgid};
	if (ONCPU_USER_MODE(regs))
		k.goroutine = ONCPU_GOROUTINE(regs);
	else if (task_regs)
		k.goroutine = oncpu_task_goroutine();
	if (!k.goroutine)
		return 0;
	struct oncpu_goroutine_request *r = bpf_map_lookup_elem(&oncpu_goroutine_requests, &k);
	if (!r)
		return 0;
	u64 correlation_id = r->correlation_id;
	if (bpf_ktime_get_ns() - correlation_id > ONCPU_REQUEST_MAX_NS) {
		bpf_map_delete_elem(&oncpu_goroutine_requests, &k);
		return 0;
	}
	return correlation_id;
}

static __always_inline int oncpu_thread_live(struct oncpu_thread_request *r)
{
	u64 correlation_id = r->correlation_id;
	if (bpf_ktime_get_ns() - correlation_id > ONCPU_REQUEST_MAX_NS)
		return 0;
	if (r->kind == ONCPU_KIND_H2) {
		struct h2_stream_key k = {.conn = r->conn, .stream = (u32)r->stream};
		struct h2_stream_state *st = bpf_map_lookup_elem(&h2_streams, &k);
		return st && st->start_ns == correlation_id;
	}
	if (r->kind == ONCPU_KIND_H3) {
		struct h3_adapter_stream_key k = h3_adapter_key(r->conn, r->stream);
		struct h3_txn_record *st = bpf_map_lookup_elem(&h3_adapter_streams, &k);
		return st && st->flags == H3_ADAPTER_KIND_ARRIVAL && st->timestamp == correlation_id;
	}
	u64 conn = r->conn;
	struct http_req *live = bpf_map_lookup_elem(&http_reqs, &conn);
	return live && live->start_ns == correlation_id;
}

static __always_inline u64 oncpu_thread_active(u32 tid)
{
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_thread_requests, &tid);
	if (!r)
		return 0;
	if (!oncpu_thread_live(r)) {
		bpf_map_delete_elem(&oncpu_thread_requests, &tid);
		return 0;
	}
	return r->correlation_id;
}

static __always_inline u64 oncpu_event_loop_active(u32 tid)
{
	u64 *cur = bpf_map_lookup_elem(&oncpu_thread_conns, &tid);
	if (!cur)
		return 0;
	u64 conn = *cur;
	struct oncpu_thread_request *r = bpf_map_lookup_elem(&oncpu_conn_requests, &conn);
	if (!r)
		return 0;
	if (!oncpu_thread_live(r)) {
		bpf_map_delete_elem(&oncpu_conn_requests, &conn);
		return 0;
	}
	return r->correlation_id;
}

__noinline u64 podtrace_current_request(void)
{
	if (!(oncpu_flags() & ONCPU_FLAG_REQUESTS))
		return 0;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	u32 tid = (u32)pid_tgid;
	if (tgid == 0)
		return 0;

	if (bpf_map_lookup_elem(&oncpu_go_procs, &tgid)) {
		if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_task_pt_regs))
			return 0;
		struct oncpu_goroutine_key k = {.tgid = tgid, .goroutine = oncpu_task_goroutine()};
		if (!k.goroutine)
			return 0;
		struct oncpu_goroutine_request *r = bpf_map_lookup_elem(&oncpu_goroutine_requests, &k);
		if (!r)
			return 0;
		u64 correlation_id = r->correlation_id;
		if (bpf_ktime_get_ns() - correlation_id > ONCPU_REQUEST_MAX_NS)
			return 0;
		return correlation_id;
	}
	if (bpf_map_lookup_elem(&oncpu_event_loop_threads, &tid))
		return oncpu_event_loop_active(tid);
	return oncpu_thread_active(tid);
}

__noinline int podtrace_emit_request_done(u64 correlation_id, u64 latency_ns, u32 kind)
{
	struct event *e = get_event_buf_unfiltered();
	if (!e)
		return 0;
	if (!cgroup_allows(e->cgroup_id))
		return 0;
	e->timestamp = bpf_ktime_get_ns();
	e->pid = agent_ns_tgid();
	e->type = EVENT_REQUEST_DONE;
	e->latency_ns = latency_ns;
	e->tcp_state = kind;
	e->correlation_id = correlation_id;
	return bpf_ringbuf_output(&events, e, sizeof(*e), 0) == 0;
}

static __always_inline int oncpu_sample(struct pt_regs *ctx, int task_regs)
{
	if (!(oncpu_flags() & ONCPU_FLAG_SAMPLER))
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;
	u32 tid = (u32)pid_tgid;

	u64 cgid = bpf_get_current_cgroup_id();
	if (!cgroup_targeted(cgid))
		return 0;

	long stack_id = bpf_get_stackid(ctx, &oncpu_stacks, BPF_F_USER_STACK);
	if (stack_id < 0) {
		oncpu_count_lost(ONCPU_LOST_STACK);
		return 0;
	}

	struct oncpu_key key = {};
	key.cgroup_id = cgid;
	if (bpf_map_lookup_elem(&oncpu_go_procs, &tgid))
		key.correlation_id = oncpu_goroutine_active(ctx, tgid, task_regs);
	else if (bpf_map_lookup_elem(&oncpu_event_loop_threads, &tid))
		key.correlation_id = oncpu_event_loop_active(tid);
	else
		key.correlation_id = oncpu_thread_active(tid);
	key.pid = agent_ns_tgid();
	key.stack_id = (u32)stack_id;

	u64 *count = bpf_map_lookup_elem(&oncpu_counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return 0;
	}
	u64 one = 1;
	if (bpf_map_update_elem(&oncpu_counts, &key, &one, BPF_NOEXIST) == 0)
		return 0;
	count = bpf_map_lookup_elem(&oncpu_counts, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		oncpu_count_lost(ONCPU_LOST_FULL);
	return 0;
}

SEC("perf_event")
int perf_event_oncpu_sample(struct pt_regs *ctx)
{
	return oncpu_sample(ctx, 0);
}

SEC("perf_event")
int perf_event_oncpu_sample_task_regs(struct pt_regs *ctx)
{
	return oncpu_sample(ctx, 1);
}
