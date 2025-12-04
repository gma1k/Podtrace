// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

SEC("tp/sched/sched_switch")
int tracepoint_sched_switch(void *ctx) {
	struct {
		unsigned short common_type;
		unsigned char common_flags;
		unsigned char common_preempt_count;
		int common_pid;
		char prev_comm[16];
		u32 prev_pid;
		int prev_prio;
		long prev_state;
		char next_comm[16];
		u32 next_pid;
		int next_prio;
	} *args = (typeof(args))ctx;
	
	u32 prev_pid = args->prev_pid;
	u32 next_pid = args->next_pid;
	u64 timestamp = bpf_ktime_get_ns();
	
	if (prev_pid > 0) {
		u64 key = get_key(prev_pid, 0);
		u64 *block_start = bpf_map_lookup_elem(&start_times, &key);
		
		if (block_start) {
			u64 block_time = calc_latency(*block_start);
			if (block_time > MIN_LATENCY_NS) {
				struct event *e = get_event_buf();
				if (!e) {
					bpf_map_delete_elem(&start_times, &key);
					return 0;
				}
				e->timestamp = timestamp;
				e->pid = prev_pid;
				e->type = EVENT_SCHED_SWITCH;
				e->latency_ns = block_time;
				e->error = 0;
				e->bytes = 0;
				e->tcp_state = 0;
				e->target[0] = '\0';
				e->details[0] = '\0';
				
				capture_user_stack(ctx, prev_pid, 0, e);
				bpf_ringbuf_output(&events, e, sizeof(*e), 0);
			}
			bpf_map_delete_elem(&start_times, &key);
		}
	}
	
	if (next_pid > 0) {
		u64 new_key = get_key(next_pid, 0);
		u64 now = bpf_ktime_get_ns();
		bpf_map_update_elem(&start_times, &new_key, &now, BPF_ANY);
	}
	
	return 0;
}

SEC("kprobe/do_futex")
int kprobe_do_futex(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	long *uaddr = (long *)PT_REGS_PARM1(ctx);
	if (uaddr) {
		char buf[MAX_STRING_LEN] = {};
		u64 addr = (u64)uaddr;
		u32 idx = 0;
		if (idx < MAX_STRING_LEN - 2) {
			buf[idx++] = '0';
			buf[idx++] = 'x';
		}
		u32 max_idx = MAX_STRING_LEN - 1;
		for (int i = 0; i < HEX_ADDR_LEN && idx < max_idx; i++) {
			u8 nibble = (addr >> ((HEX_ADDR_LEN - 1 - i) * 4)) & 0xF;
			if (nibble < 10) {
				buf[idx++] = '0' + nibble;
			} else {
				buf[idx++] = 'a' + (nibble - 10);
			}
		}
		buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
		bpf_map_update_elem(&lock_targets, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("kretprobe/do_futex")
int kretprobe_do_futex(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	if (latency < MIN_LATENCY_NS) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	long ret = PT_REGS_RC(ctx);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_LOCK_CONTENTION;
	e->latency_ns = latency;
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *name_ptr = bpf_map_lookup_elem(&lock_targets, &key);
	if (name_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), name_ptr);
		bpf_map_delete_elem(&lock_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("uprobe/pthread_mutex_lock")
int uprobe_pthread_mutex_lock(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	void *mutex = (void *)PT_REGS_PARM1(ctx);
	if (mutex) {
		char buf[MAX_STRING_LEN] = {};
		u64 addr = (u64)mutex;
		u32 idx = 0;
		if (idx < MAX_STRING_LEN - 10) {
			buf[idx++] = 'm';
			buf[idx++] = 't';
			buf[idx++] = 'x';
			buf[idx++] = '@';
		}
		if (idx < MAX_STRING_LEN - 2) {
			buf[idx++] = '0';
			buf[idx++] = 'x';
		}
		u32 max_idx = MAX_STRING_LEN - 1;
		for (int i = 0; i < HEX_ADDR_LEN && idx < max_idx; i++) {
			u8 nibble = (addr >> ((HEX_ADDR_LEN - 1 - i) * 4)) & 0xF;
			if (nibble < 10) {
				buf[idx++] = '0' + nibble;
			} else {
				buf[idx++] = 'a' + (nibble - 10);
			}
		}
		buf[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
		bpf_map_update_elem(&lock_targets, &key, buf, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int uretprobe_pthread_mutex_lock(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
	if (!start_ts) {
		return 0;
	}
	u64 latency = calc_latency(*start_ts);
	if (latency < MIN_LATENCY_NS) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	long ret = PT_REGS_RC(ctx);
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_LOCK_CONTENTION;
	e->latency_ns = latency;
	e->error = ret;
	e->bytes = 0;
	e->tcp_state = 0;
	char *name_ptr = bpf_map_lookup_elem(&lock_targets, &key);
	if (name_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), name_ptr);
		bpf_map_delete_elem(&lock_targets, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}