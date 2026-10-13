// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#define MC_OP_GET "get "
#define MC_OP_SET "set "
#define MC_OP_DEL "del "

static __always_inline void mc_store_op(const struct pair_key *key, u64 ts,
	const char *op_prefix, u32 prefix_len,
	const char *mc_key, u64 key_len, u64 bytes_val)
{
	char buf[MAX_STRING_LEN] = {};

	if (prefix_len < MAX_STRING_LEN)
		__builtin_memcpy(buf, op_prefix, prefix_len);

	u32 remaining = MAX_STRING_LEN - prefix_len - 1;
	u32 n = key_len < remaining ? (u32)key_len : remaining;
	n &= (MAX_STRING_LEN - 1);
	if (n > 0)
		bpf_probe_read_user(buf + prefix_len, n, mc_key);
	buf[prefix_len + n] = '\0';

	bpf_map_update_elem(&memcached_ops, key, buf, BPF_ANY);
	bpf_map_update_elem(&start_times, key, &ts, BPF_ANY);
	if (bytes_val > 0)
		bpf_map_update_elem(&proto_bytes, key, &bytes_val, BPF_ANY);
}

static __always_inline int mc_emit(struct pt_regs *ctx, u32 pid, u32 tid, int ret_is_pointer)
{
	struct pair_key key = make_pair_key(PAIR_MEMCACHED);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		bpf_map_delete_elem(&memcached_ops, &key);
		bpf_map_delete_elem(&proto_bytes, &key);
		return 0;
	}

	u64 latency = calc_latency(*start_ts);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		bpf_map_delete_elem(&memcached_ops, &key);
		bpf_map_delete_elem(&proto_bytes, &key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_MEMCACHED_CMD;
	e->latency_ns = latency;
	if (ret_is_pointer)
		e->error = PT_REGS_RC(ctx) == 0 ? -1 : 0;
	else
		e->error = (s32)PT_REGS_RC(ctx);
	e->tcp_state  = 0;

	u64 *bptr = bpf_map_lookup_elem(&proto_bytes, &key);
	e->bytes = bptr ? *bptr : 0;

	char *op_ptr = bpf_map_lookup_elem(&memcached_ops, &key);
	if (op_ptr)
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), op_ptr);
	else
		e->details[0] = '\0';

	e->target[0] = '\0';

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	bpf_map_delete_elem(&start_times, &key);
	bpf_map_delete_elem(&memcached_ops, &key);
	bpf_map_delete_elem(&proto_bytes, &key);
	return 0;
}

SEC("uprobe/memcached_get")
int uprobe_memcached_get(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_MEMCACHED);
	const char *mc_key = (const char *)PT_REGS_PARM2(ctx);
	if (!mc_key) return 0;
	mc_store_op(&key, bpf_ktime_get_ns(), MC_OP_GET, 4, mc_key, (u64)PT_REGS_PARM3(ctx), 0);
	return 0;
}

SEC("uretprobe/memcached_get")
int uretprobe_memcached_get(struct pt_regs *ctx)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return mc_emit(ctx, pid, tid, 1);
}

SEC("uprobe/memcached_set")
int uprobe_memcached_set(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_MEMCACHED);
	const char *mc_key = (const char *)PT_REGS_PARM2(ctx);
	if (!mc_key) return 0;
	u64 vlen = (u64)PT_REGS_PARM5(ctx);
	mc_store_op(&key, bpf_ktime_get_ns(), MC_OP_SET, 4, mc_key, (u64)PT_REGS_PARM3(ctx), vlen);
	return 0;
}

SEC("uretprobe/memcached_set")
int uretprobe_memcached_set(struct pt_regs *ctx)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return mc_emit(ctx, pid, tid, 0);
}

SEC("uprobe/memcached_delete")
int uprobe_memcached_delete(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_MEMCACHED);
	const char *mc_key = (const char *)PT_REGS_PARM2(ctx);
	if (!mc_key) return 0;
	mc_store_op(&key, bpf_ktime_get_ns(), MC_OP_DEL, 4, mc_key, (u64)PT_REGS_PARM3(ctx), 0);
	return 0;
}

SEC("uretprobe/memcached_delete")
int uretprobe_memcached_delete(struct pt_regs *ctx)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return mc_emit(ctx, pid, tid, 0);
}
