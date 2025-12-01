// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_MAPS_H
#define PODTRACE_MAPS_H

#include "common.h"
#include "events.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} dns_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} socket_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, char[MAX_STRING_LEN]);
} file_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u64);
} tcp_sockets SEC(".maps");

#endif
