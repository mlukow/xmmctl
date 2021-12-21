/*	$OpenBSD$	*/
/*
 * Copyright (c) 2020 genua GmbH
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <errno.h>
#include <sys/types.h>
#include <stdint.h>

struct asn1_buf {
	uint8_t *buf;
	size_t len;
	size_t off;
};

struct asn1_buf_cp {
	size_t val;
};

#define ASN1_TAG_INT	2
#define ASN1_TAG_NULL	5

#define	ASN1_TAG_APPARRAY_BYTE	0x15
#define	ASN1_TAG_APPARRAY_WORD	0x16
#define	ASN1_TAG_APPARRAY_DWORD	0x17
#define	ASN1_TAG_APPARRAY_QWORD	0x18


#define	ASN1_CLASS_UNIVERSAL	0x00
#define	ASN1_CLASS_APPLICATION	0x40
#define	ASN1_CLASS_CONTEXT	0x80
#define	ASN1_CLASS_PRIVATE	0xc0

#define ASN1_TAG_MASK		0x1f
#define ASN1_FLAG_CONSTRUCTED	0x20
#define ASN1_TYPE_MASK		0xc0

struct asn1_val {
	uint64_t tag;
	uint8_t tag_type;
	uint8_t constructed;
	uint64_t len;
	union {
		uint64_t ui;
		int64_t i;
		struct {
			union {
				uint8_t *p8;
				uint16_t *p16;
				uint32_t *p32;
				uint64_t *p64;
			};
			size_t elem_size;
		};
	};
};

static inline int
asn1_val_is_null(const struct asn1_val *val)
{
	if (val->tag_type != ASN1_CLASS_UNIVERSAL)
		return 0;
	if (val->constructed != 0)
		return 0;
	if (val->tag != ASN1_TAG_NULL)
		return 0;
	if (val->len != 0)
		return 0;

	return 1;
}


static inline int
asn1_val_is_int(const struct asn1_val *val)
{
	if (val->tag_type != ASN1_CLASS_UNIVERSAL)
		return 0;
	if (val->constructed != 0)
		return 0;
	if (val->tag != ASN1_TAG_INT)
		return 0;

	return 1;
}

static inline int
asn1_val_is_apparray(const struct asn1_val *val)
{
	if (val->tag_type != ASN1_CLASS_APPLICATION)
		return 0;
	if (val->constructed != 0)
		return 0;
	switch (val->tag) {
	case ASN1_TAG_APPARRAY_BYTE:
	case ASN1_TAG_APPARRAY_WORD:
	case ASN1_TAG_APPARRAY_DWORD:
	case ASN1_TAG_APPARRAY_QWORD:
		break;
	default:
		return 0;
	}

	return 1;
}

static inline size_t
asn1_buf_len(struct asn1_buf *buf)
{
	if (buf->off > buf->len)
		return 0;

	return buf->len - buf->off;
}

static inline struct asn1_buf_cp
asn1_buf_checkpoint(struct asn1_buf *buf)
{
	struct asn1_buf_cp ret = {
		.val = asn1_buf_len(buf)
	};

	return ret;
}

static inline int
asn1_buf_rollback(struct asn1_buf *buf, struct asn1_buf_cp c)
{
	if (buf->len < c.val)
		return EINVAL;
	buf->off = buf->len - c.val;

	return 0;
}


int asn1_buf_init(struct asn1_buf *buf);
void asn1_buf_reset(struct asn1_buf *buf);
void *asn1_buf_steal(struct asn1_buf *buf);
void asn1_buf_release(struct asn1_buf *buf);

int asn1_buf_pad(struct asn1_buf *buf, size_t len);
int asn1_buf_prepend(struct asn1_buf *buf, uint8_t *data, size_t len);
int asn1_add_null(struct asn1_buf *buf);
int asn1_add_int8(struct asn1_buf *buf, int8_t val);
int asn1_add_int16(struct asn1_buf *buf, int16_t val);
int asn1_add_int32(struct asn1_buf *buf, int32_t val);
int asn1_add_raw_u32(struct asn1_buf *buf, uint32_t val);
int asn1_add_int64(struct asn1_buf *buf, int64_t val);
int asn1_add_ll(struct asn1_buf *buf, long long val);
int asn1_add_length(struct asn1_buf *buf, unsigned long long ulen);
int asn1_add_tag(struct asn1_buf *buf, uint8_t type, uint8_t constructed,
    unsigned long long tag);
int asn1_add_apparray(struct asn1_buf *buf, unsigned int tag, void *data,
    size_t nvalid);
int asn1_encode_one(struct asn1_buf *buf, struct asn1_val *val);


int asn1_decode_tag(struct asn1_buf *buf, struct asn1_val *val);
int asn1_decode_length(struct asn1_buf *buf, uint64_t *lenp);
int __asn1_decode_null(struct asn1_buf *buf, struct asn1_val *val);
int __asn1_decode_int(struct asn1_buf *buf, struct asn1_val *val);
int __asn1_decode_apparray(struct asn1_buf *buf, struct asn1_val *val);
int asn1_decode_one(struct asn1_buf *buf, struct asn1_val *val);
int asn1_decode(struct asn1_buf *buf, struct asn1_val *val, size_t *np);
int asn1_decode_raw_u32(struct asn1_buf *buf, uint32_t *valp);
