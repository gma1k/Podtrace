// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_HELPERS_H
#define PODTRACE_HELPERS_H

#include "common.h"

static inline u64 get_key(u32 pid, u32 tid) {
	return ((u64)pid << 32) | tid;
}

static inline u64 calc_latency(u64 start) {
	u64 now = bpf_ktime_get_ns();
	return now > start ? now - start : 0;
}

static inline void format_ip_port(u32 ip, u16 port, char *buf) {
	u8 a = (ip >> 24) & 0xFF;
	u8 b = (ip >> 16) & 0xFF;
	u8 c = (ip >> 8) & 0xFF;
	u8 d = ip & 0xFF;
	u16 p = port;
	u32 idx = 0;
	
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (a / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (a / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + a % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (b / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (b / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + b % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (c / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (c / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + c % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '.';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (d / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (d / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + d % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = ':';
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 10000) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 1000) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 100) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + (p / 10) % 10;
	if (idx < MAX_STRING_LEN - 1) buf[idx++] = '0' + p % 10;
	if (idx < MAX_STRING_LEN) buf[idx] = '\0';
}

static inline void format_ipv6_port(const u8 *ipv6, u16 port, char *buf) {
	u16 p = port;
	u32 idx = 0;
	
	for (int i = 0; i < 8 && idx < MAX_STRING_LEN - 10; i++) {
		if (i > 0) {
			buf[idx++] = ':';
		}
		u16 seg = (ipv6[i*2] << 8) | ipv6[i*2 + 1];
		u8 d1 = (seg >> 12) & 0xF;
		u8 d2 = (seg >> 8) & 0xF;
		u8 d3 = (seg >> 4) & 0xF;
		u8 d4 = seg & 0xF;
		
		if (d1 > 0) {
			buf[idx++] = d1 < 10 ? '0' + d1 : 'a' + (d1 - 10);
		}
		buf[idx++] = d2 < 10 ? '0' + d2 : 'a' + (d2 - 10);
		buf[idx++] = d3 < 10 ? '0' + d3 : 'a' + (d3 - 10);
		buf[idx++] = d4 < 10 ? '0' + d4 : 'a' + (d4 - 10);
	}
	
	if (idx < MAX_STRING_LEN - 6) {
		buf[idx++] = ':';
		buf[idx++] = '0' + (p / 10000) % 10;
		buf[idx++] = '0' + (p / 1000) % 10;
		buf[idx++] = '0' + (p / 100) % 10;
		buf[idx++] = '0' + (p / 10) % 10;
		buf[idx++] = '0' + p % 10;
	}
	buf[idx] = '\0';
}

#endif
