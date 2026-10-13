// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_PROTOCOLS_H
#define PODTRACE_PROTOCOLS_H

/* === DEFAULT PROTOCOL PORTS === */
#define REDIS_DEFAULT_PORT      6379
#define MEMCACHED_DEFAULT_PORT  11211
#define KAFKA_DEFAULT_PORT      9092
#define GRPC_DEFAULT_PORT       50051

/* === FastCGI Record Types === */
#define FCGI_VERSION_1       1
#define FCGI_BEGIN_REQUEST   1
#define FCGI_ABORT_REQUEST   2
#define FCGI_END_REQUEST     3
#define FCGI_PARAMS          4
#define FCGI_STDIN           5
#define FCGI_STDOUT          6
#define FCGI_STDERR          7

#include "h2_frame.h"

/* === HPACK Static Table Shortcuts === */
#define HPACK_METHOD_GET     0x82   /* :method = GET  (index 2) */
#define HPACK_METHOD_POST    0x83   /* :method = POST (index 3) */
#define HPACK_PATH_SLASH     0x84   /* :path = /      (index 4) */

/* HTTP/2 client connection preface length */
#define HTTP2_PREFACE_LEN    24     /* "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */

/* === HTTP/1.x socket-level inspection (bpf/http.c) === */
#define HTTP_INSPECT_LEN     80
#define HTTP_MIN_REQUEST_LEN 16
#define W3C_TRACEPARENT_LEN  55

/* Bit 0 = TLS (encrypted), bit 1 = HTTP/2, bit 2 = HTTP/3. */
#define HTTP_TRANSPORT_PLAINTEXT 0  /* HTTP/1.x cleartext */
#define HTTP_TRANSPORT_TLS       1  /* HTTP/1.x over TLS (OpenSSL, GnuTLS, Go) */
#define HTTP_TRANSPORT_H2C       2  /* HTTP/2 cleartext */
#define HTTP_TRANSPORT_H2_TLS    3  /* HTTP/2 over TLS (Go crypto/tls) */
#define HTTP_TRANSPORT_H3        5  /* HTTP/3 over QUIC (always encrypted): H3 bit | TLS bit */

/* === FastCGI NV Pair Helpers === */
#define FCGI_NV_LEN_4BYTE    0x80

#define FCGI_HEADER_LEN      8

#define FCGI_PARAMS_SCAN_LEN 128

static __always_inline void *msghdr_user_base(struct msghdr *msg, u64 *avail)
{
	if (!msg)
		return NULL;
	u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (it == (u8)bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
		void *ubuf = (void *)BPF_CORE_READ(msg, msg_iter.ubuf);
		size_t count = BPF_CORE_READ(msg, msg_iter.count);
		size_t off = BPF_CORE_READ(msg, msg_iter.iov_offset);
		if (avail)
			*avail = count;
		if (!ubuf)
			return NULL;
		return (u8 *)ubuf + off;
	}
	if (it == (u8)bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		if (!iov)
			return NULL;
		struct iovec iov_entry;
		if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) != 0)
			return NULL;
		if (avail)
			*avail = iov_entry.iov_len;
		return iov_entry.iov_base;
	}
	return NULL;
}

static __always_inline const struct iovec *msghdr_iovec(struct msghdr *msg, u32 *nr_segs)
{
	if (!msg)
		return NULL;
	u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (it != (u8)bpf_core_enum_value(enum iter_type, ITER_IOVEC))
		return NULL;
	unsigned long n = BPF_CORE_READ(msg, msg_iter.nr_segs);
	if (n < 2)
		return NULL;
	*nr_segs = n > 0xffffffffUL ? 0xffffffffU : (u32)n;
	return BPF_CORE_READ(msg, msg_iter.__iov);
}

static __always_inline int read_msghdr_data(struct msghdr *msg, void *buf, u32 buf_size)
{
	if (!buf || buf_size == 0)
		return -1;
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base || avail < buf_size)
		return -1;
	return bpf_probe_read_user(buf, buf_size, base);
}

#endif
