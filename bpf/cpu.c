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
			if (block_time > 1000000) {
				struct event e = {};
				e.timestamp = timestamp;
				e.pid = prev_pid;
				e.type = EVENT_SCHED_SWITCH;
				e.latency_ns = block_time;
				e.error = 0;
				e.bytes = 0;
				e.tcp_state = 0;
				e.target[0] = '\0';
				e.details[0] = '\0';
				
				bpf_ringbuf_output(&events, &e, sizeof(e), 0);
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
