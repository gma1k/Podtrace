/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h fallback for environments without bpftool.
 * At build time the Makefile regenerates a kernel-specific header into
 * bpf/.generated/vmlinux.h when kernel BTF is available.
 *
 * All primitive types (u8/u16/u32/u64, __u*, etc.) and kernel structs used by
 * podtrace are defined locally in common.h, so this fallback only needs to
 * forward-declare struct file (used as an opaque pointer in filesystem.c).
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned long size_t;

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct qstr d_name;
};

struct path {
	struct dentry *dentry;
};

struct inode {
	unsigned short i_mode;
};

struct file {
	struct path f_path;
	struct inode *f_inode;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
};

struct files_struct {
	struct fdtable *fdt;
};

struct renamedata {
	struct dentry *old_dentry;
	struct dentry *new_dentry;
};

struct ns_common {
	unsigned int inum;
};

struct pid_namespace {
	struct ns_common ns;
};

struct net {
	struct ns_common ns;
};

struct nsproxy {
	struct net *net_ns;
};

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	unsigned int level;
	struct upid numbers[1];
};

struct kernfs_node {
	unsigned long long id;
};

struct cgroup;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys_state *parent;
};

struct cgroup {
	struct cgroup_subsys_state self;
	struct kernfs_node *kn;
};

struct css_set {
	struct cgroup *dfl_cgrp;
};

struct task_struct {
	int pid;
	int tgid;
	char comm[16];
	struct task_struct *group_leader;
	struct pid *thread_pid;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct files_struct *files;
};

struct trace_event_raw_mark_victim {
	int pid;
	unsigned int __data_loc_comm;
	unsigned long anon_rss;
	unsigned long file_rss;
	unsigned long shmem_rss;
};

struct in6_addr {
	union {
		unsigned char u6_addr8[16];
	} in6_u;
};

struct sock_common {
	unsigned int skc_daddr;
	unsigned int skc_rcv_saddr;
	unsigned short skc_num;
	unsigned short skc_dport;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock_cgroup_data {
	struct cgroup *cgroup;
};

struct sock {
	struct sock_common __sk_common;
	int sk_err;
	struct sock_cgroup_data sk_cgrp_data;
};

struct sk_buff {
	struct sock *sk;
};

struct iovec {
	void *iov_base;
	unsigned long iov_len;
};

enum bpf_func_id {
	BPF_FUNC_task_pt_regs = 175,
};

enum iter_type {
	ITER_UBUF,
	ITER_IOVEC,
	ITER_BVEC,
	ITER_KVEC,
	ITER_FOLIOQ,
	ITER_XARRAY,
	ITER_DISCARD,
};

struct iov_iter {
	unsigned char iter_type;
	unsigned long iov_offset;
	union {
		struct {
			union {
				const struct iovec *__iov;
				void *ubuf;
			};
			unsigned long count;
		};
	};
	unsigned long nr_segs;
};

struct msghdr {
	void *msg_name;
	struct iov_iter msg_iter;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
