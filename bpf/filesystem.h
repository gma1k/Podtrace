// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_FILESYSTEM_H
#define PODTRACE_FILESYSTEM_H

#include "common.h"
#include "maps.h"
#include "helpers.h"

#define FS_S_IFMT  00170000
#define FS_S_IFREG 0100000

#define FS_TASK_SLOT_READ  0
#define FS_TASK_SLOT_WRITE 1
#define FS_TASK_SLOTS      2

struct fs_inflight {
	u64 start_ns;
	u64 file;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pair_key);
	__type(value, struct fs_inflight);
} fs_inflight SEC(".maps");

struct fs_task_starts {
	u64 start_ns[FS_TASK_SLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, 1); /* BPF_F_NO_PREALLOC */
	__type(key, int);
	__type(value, struct fs_task_starts);
} fs_task_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct agg_key);
	__type(value, struct agg_value);
	__uint(max_entries, 16384);
} fs_fast_ops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} fs_fast_ops_enabled SEC(".maps");

static __always_inline int fs_fast_ops_on(void)
{
	u32 zero = 0;
	u32 *on = bpf_map_lookup_elem(&fs_fast_ops_enabled, &zero);
	return on && *on;
}

static inline int get_path_str_from_file(struct file *file, char *out_buf, u32 buf_size)
{
    if (!file || !out_buf || buf_size < 2) {
        if (out_buf && buf_size > 0) out_buf[0] = '\0';
        return 0;
    }

    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name) {
        out_buf[0] = '\0';
        return 0;
    }
    int ret = bpf_probe_read_kernel_str(out_buf, buf_size, name);
    return ret > 1 ? 1 : 0;
}

static __always_inline int fs_is_regular(struct file *file)
{
	if (!file)
		return 0;
	unsigned short mode = BPF_CORE_READ(file, f_inode, i_mode);
	return (mode & FS_S_IFMT) == FS_S_IFREG;
}

static __always_inline struct file *fs_file_of_fd(unsigned int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd >= BPF_CORE_READ(fdt, max_fds))
		return NULL;
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *file = NULL;
	if (!fds || bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]) != 0)
		return NULL;
	return file;
}

static __always_inline int fs_traced(void)
{
	return cgroup_allows(bpf_get_current_cgroup_id());
}

static __always_inline int fs_count(u32 type, u64 latency_ns, u64 bytes, s32 err)
{
	u64 cgroup_id = bpf_get_current_cgroup_id();
	u8 variant = AGG_VARIANT(0, 0, err != 0 ? 1 : 0);
	if (agg_record(cgroup_id, (u8)type, variant, 0, 0, 0, latency_ns, bytes, 1))
		return 1;
	if (latency_ns < MIN_LATENCY_NS && fs_fast_ops_on())
		agg_record_in(&fs_fast_ops, cgroup_id, (u8)type, variant, 0, 0, 0, latency_ns, bytes, 1);
	return 0;
}

static __always_inline void fs_emit(void *ctx, struct event *e, int recorded)
{
	e->agg_recorded = (u8)recorded;
	if (recorded && agg_mode() == AGG_MODE_BYPASS)
		return;
	capture_user_stack(ctx, e->pid, (u32)bpf_get_current_pid_tgid(), e);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

#endif
