// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

static __always_inline void redis_store_cmd(const struct pair_key *key, const char *format_ptr, u64 ts)
{
	char buf[MAX_STRING_LEN] = {};
	bpf_probe_read_user_str(buf, sizeof(buf), format_ptr);

	u32 i;
	for (i = 0; i < MAX_STRING_LEN; i++) {
		if (buf[i] == ' ' || buf[i] == '%' || buf[i] == '\0') {
			buf[i] = '\0';
			break;
		}
	}

	bpf_map_update_elem(&redis_cmds, key, buf, BPF_ANY);
	bpf_map_update_elem(&start_times, key, &ts, BPF_ANY);
}

static __always_inline int redis_emit(struct pt_regs *ctx, u32 pair, u32 pid, u32 tid)
{
	struct pair_key key = make_pair_key(pair);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		bpf_map_delete_elem(&redis_cmds, &key);
		return 0;
	}

	u64 latency = calc_latency(*start_ts);

	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		bpf_map_delete_elem(&redis_cmds, &key);
		return 0;
	}

	e->timestamp  = bpf_ktime_get_ns();
	e->pid        = pid;
	e->type       = EVENT_REDIS_CMD;
	e->latency_ns = latency;
	e->error      = PT_REGS_RC(ctx) == 0 ? -1 : 0;
	e->bytes      = 0;
	e->tcp_state  = 0;

	char *cmd_ptr = bpf_map_lookup_elem(&redis_cmds, &key);
	if (cmd_ptr)
		bpf_probe_read_kernel_str(e->details, sizeof(e->details), cmd_ptr);
	else
		e->details[0] = '\0';

	e->target[0] = '\0';

	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);

	bpf_map_delete_elem(&start_times, &key);
	bpf_map_delete_elem(&redis_cmds, &key);
	return 0;
}

SEC("uprobe/redisCommand")
int uprobe_redisCommand(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_REDIS_COMMAND);
	u64 ts  = bpf_ktime_get_ns();

	const char *fmt = (const char *)PT_REGS_PARM2(ctx);
	if (fmt)
		redis_store_cmd(&key, fmt, ts);
	return 0;
}

SEC("uretprobe/redisCommand")
int uretprobe_redisCommand(struct pt_regs *ctx)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return redis_emit(ctx, PAIR_REDIS_COMMAND, pid, tid);
}

SEC("uprobe/redisCommandArgv")
int uprobe_redisCommandArgv(struct pt_regs *ctx)
{
	struct pair_key key = make_pair_key(PAIR_REDIS_COMMAND_ARGV);
	u64 ts  = bpf_ktime_get_ns();

	const char **argv = (const char **)PT_REGS_PARM3(ctx);
	if (!argv)
		return 0;

	const char *cmd_ptr = NULL;
	if (bpf_probe_read_user(&cmd_ptr, sizeof(cmd_ptr), argv) != 0 || !cmd_ptr)
		return 0;

	char buf[MAX_STRING_LEN] = {};
	bpf_probe_read_user_str(buf, sizeof(buf), cmd_ptr);

	bpf_map_update_elem(&redis_cmds, &key, buf, BPF_ANY);
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe/redisCommandArgv")
int uretprobe_redisCommandArgv(struct pt_regs *ctx)
{
	u32 pid = agent_ns_tgid();
	u32 tid = (u32)bpf_get_current_pid_tgid();
	return redis_emit(ctx, PAIR_REDIS_COMMAND_ARGV, pid, tid);
}
