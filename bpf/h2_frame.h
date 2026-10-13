// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_H2_FRAME_H
#define PODTRACE_H2_FRAME_H

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define HTTP2_FRAME_HDR      9

#define HTTP2_DATA           0x0
#define HTTP2_HEADERS        0x1
#define HTTP2_PRIORITY       0x2
#define HTTP2_RST_STREAM     0x3
#define HTTP2_SETTINGS       0x4
#define HTTP2_PUSH_PROMISE   0x5
#define HTTP2_PING           0x6
#define HTTP2_GOAWAY         0x7
#define HTTP2_WINDOW_UPDATE  0x8
#define HTTP2_CONTINUATION   0x9

/* === HTTP/2 frame flags (HEADERS / CONTINUATION) === */
#define HTTP2_FLAG_END_STREAM  0x01
#define HTTP2_FLAG_END_HEADERS 0x04
#define HTTP2_FLAG_PADDED      0x08
#define HTTP2_FLAG_PRIORITY    0x20
#define HTTP2_FLAG_ACK         0x01 /* SETTINGS / PING */

#define H2_DEFAULT_MAX_FRAME 16384

static __always_inline int h2_frame_header_valid(const unsigned char *fh)
{
	unsigned int flen = ((unsigned int)fh[0] << 16) | ((unsigned int)fh[1] << 8) | (unsigned int)fh[2];
	unsigned char type = fh[3];
	unsigned char flags = fh[4];
	if (fh[5] & 0x80)
		return 0;
	unsigned int sid = ((unsigned int)fh[5] << 24) | ((unsigned int)fh[6] << 16) |
			   ((unsigned int)fh[7] << 8) | (unsigned int)fh[8];
	if (flen > H2_DEFAULT_MAX_FRAME)
		return 0;

	switch (type) {
	case HTTP2_DATA:
		return sid != 0 && !(flags & ~(HTTP2_FLAG_END_STREAM | HTTP2_FLAG_PADDED));
	case HTTP2_HEADERS:
		return sid != 0 && !(flags & ~(HTTP2_FLAG_END_STREAM | HTTP2_FLAG_END_HEADERS |
					       HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY));
	case HTTP2_PRIORITY:
		return sid != 0 && flen == 5 && flags == 0;
	case HTTP2_RST_STREAM:
		return sid != 0 && flen == 4 && flags == 0;
	case HTTP2_SETTINGS:
		if (sid != 0 || (flags & ~HTTP2_FLAG_ACK))
			return 0;
		return (flags & HTTP2_FLAG_ACK) ? flen == 0 : flen % 6 == 0;
	case HTTP2_PUSH_PROMISE:
		return sid != 0 && flen >= 4 &&
		       !(flags & ~(HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_PADDED));
	case HTTP2_PING:
		return sid == 0 && flen == 8 && !(flags & ~HTTP2_FLAG_ACK);
	case HTTP2_GOAWAY:
		return sid == 0 && flen >= 8 && flags == 0;
	case HTTP2_WINDOW_UPDATE:
		return flen == 4 && flags == 0;
	case HTTP2_CONTINUATION:
		return sid != 0 && !(flags & ~HTTP2_FLAG_END_HEADERS);
	}
	return 0;
}

#endif
