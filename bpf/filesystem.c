// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#ifndef ENABLE_FILE_PATH_TRACKING
#define ENABLE_FILE_PATH_TRACKING 1
#endif

#if ENABLE_FILE_PATH_TRACKING
static inline int extract_file_path(struct file *file, char *path_buf, u32 buf_size) {
	if (!file) {
		return -1;
	}
	
	struct path f_path = BPF_CORE_READ(file, f_path);
	
	long ret = bpf_d_path(&f_path, path_buf, buf_size);
	if (ret < 0) {
		return -1;
	}
	
	if (ret >= buf_size) {
		path_buf[buf_size - 1] = '\0';
	} else if (ret > 0) {
		path_buf[ret] = '\0';
	} else {
		path_buf[0] = '\0';
	}
	
	return 0;
}
#else
static inline int extract_file_path(struct file *file, char *path_buf, u32 buf_size) {
	(void)file;
	(void)path_buf;
	(void)buf_size;
	return -1;
}
#endif

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	if (file) {
		char path_buf[MAX_STRING_LEN] = {};
		if (extract_file_path(file, path_buf, sizeof(path_buf)) == 0) {
			bpf_map_update_elem(&file_paths, &key, path_buf, BPF_ANY);
		}
	}
	
	return 0;
}

SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	if (file) {
		char path_buf[MAX_STRING_LEN] = {};
		if (extract_file_path(file, path_buf, sizeof(path_buf)) == 0) {
			bpf_map_update_elem(&file_paths, &key, path_buf, BPF_ANY);
		}
	}
	
	return 0;
}

SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx) {
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_READ;
	e->latency_ns = latency;
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kretprobe/vfs_write")
int kretprobe_vfs_write(struct pt_regs *ctx) {
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
	
	s64 ret = PT_REGS_RC(ctx);
	u64 bytes = 0;
	if (ret > 0 && (u64)ret < MAX_BYTES_THRESHOLD) {
		bytes = (u64)ret;
	}
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_WRITE;
	e->latency_ns = latency;
	e->error = ret < 0 ? ret : 0;
	e->bytes = bytes;
	e->tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}

SEC("kprobe/vfs_fsync")
int kprobe_vfs_fsync(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_key(pid, tid);
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
	
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	if (file) {
		char path_buf[MAX_STRING_LEN] = {};
		if (extract_file_path(file, path_buf, sizeof(path_buf)) == 0) {
			bpf_map_update_elem(&file_paths, &key, path_buf, BPF_ANY);
		}
	}
	
	return 0;
}

SEC("kretprobe/vfs_fsync")
int kretprobe_vfs_fsync(struct pt_regs *ctx) {
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
	
	struct event *e = get_event_buf();
	if (!e) {
		bpf_map_delete_elem(&start_times, &key);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = EVENT_FSYNC;
	e->latency_ns = latency;
	e->error = PT_REGS_RC(ctx);
	e->bytes = 0;
	e->tcp_state = 0;
	
	char *path_ptr = bpf_map_lookup_elem(&file_paths, &key);
	if (path_ptr) {
		bpf_probe_read_kernel_str(e->target, sizeof(e->target), path_ptr);
		bpf_map_delete_elem(&file_paths, &key);
	} else {
		e->target[0] = '\0';
	}
	capture_user_stack(ctx, pid, tid, e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	bpf_map_delete_elem(&start_times, &key);
	return 0;
}