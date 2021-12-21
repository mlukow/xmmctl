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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>

#include "asn1.h"

int
asn1_buf_init(struct asn1_buf *buf)
{
	buf->buf = NULL;
	buf->len = 0;
	buf->off = 0;

	return 0;
}

void
asn1_buf_reset(struct asn1_buf *buf)
{
	buf->off = buf->len;
}

void
asn1_buf_release(struct asn1_buf *buf)
{
	if (buf->buf)
		free(buf->buf);
	buf->buf = NULL;
	buf->len = buf->off = 0;
}

void *
asn1_buf_steal(struct asn1_buf *buf)
{
	void *ret = buf->buf;

	buf->buf = NULL;
	buf->len = buf->off = 0;

	return ret;
}


static int
asn1_buf_grow(struct asn1_buf *buf, size_t diff)
{
	uint8_t *n;
	size_t grow;

	while (buf->off < diff) {
		grow = (buf->len < 128) ? 128 : buf->len + 15U;

		grow -= grow % 16U;
		if (buf->len + grow < buf->len)
			return ENOMEM;
		n = malloc(buf->len + grow);
		if (n == NULL)
			return ENOMEM;
		if (buf->len) {
			memcpy(n + grow, buf->buf, buf->len);
			free(buf->buf);
		}
		buf->buf = n;
		buf->off += grow;
		buf->len += grow;
	}

	return 0;
}

int
asn1_buf_pad(struct asn1_buf *buf, size_t len)
{
	int ret;

	ret = asn1_buf_grow(buf, len);
	if (ret != 0)
		return ret;
	buf->off -= len;
	memset(buf->buf + buf->off, 0, len);

	return 0;
}

int
asn1_buf_prepend(struct asn1_buf *buf, uint8_t *data, size_t len)
{
	int ret;

	ret = asn1_buf_grow(buf, len);
	if (ret != 0)
		return ret;
	buf->off -= len;
	memcpy(buf->buf + buf->off, data, len);

	return 0;
}

int
asn1_add_null(struct asn1_buf *buf)
{
	uint8_t data[2] = {
		ASN1_TAG_NULL, 0
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_int8(struct asn1_buf *buf, int8_t val)
{
	uint8_t data[sizeof(val) + 2] = {
	    ASN1_TAG_INT, sizeof(val),
	    val
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_int16(struct asn1_buf *buf, int16_t val)
{
	uint16_t uval = val;
	uint8_t data[sizeof(val) + 2] = {
	    ASN1_TAG_INT, sizeof(val),
	    uval >> 8, uval
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_int32(struct asn1_buf *buf, int32_t val)
{
	uint32_t uval = val;
	uint8_t data[sizeof(val) + 2] = {
	    ASN1_TAG_INT, sizeof(val),
	    uval >> 24, uval >> 16, uval >> 8, uval
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_raw_u32(struct asn1_buf *buf, uint32_t uval)
{
	uint8_t data[sizeof(uval)] = {
	    uval, uval >> 8, uval >> 16, uval >> 24,
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_int64(struct asn1_buf *buf, int64_t val)
{
	uint64_t uval = val;
	uint8_t data[sizeof(val) + 2] = {
	    ASN1_TAG_INT, sizeof(val),
	    uval >> 56, uval >> 48, uval >> 40, uval >> 32,
	    uval >> 24, uval >> 16, uval >> 8, uval
	};

	return asn1_buf_prepend(buf, data, sizeof(data));
}

int
asn1_add_ll(struct asn1_buf *buf, long long val)
{
	unsigned long long uval = val;
	uint8_t data[sizeof(val) + 2] = {
	    0, 0,
	    uval >> 56, uval >> 48, uval >> 40, uval >> 32,
	    uval >> 24, uval >> 16, uval >> 8, uval
	};
	size_t off;

	off = 2;
	if (data[off] & 0x80U) {
		for (; off < sizeof(data) - 1; off++) {
			if (data[off] != 0xffU)
				break;
			if ((data[off + 1] & 0x80U) == 0)
				break;
		}
	} else {
		for (; off < sizeof(data) - 1; off++) {
			if (data[off] != 0)
				break;
			if ((data[off + 1] & 0x80U) != 0)
				break;
		}
	}
	data[off-1] = sizeof(data) - off;
	data[off-2] = ASN1_TAG_INT;
	off -= 2;

	return asn1_buf_prepend(buf, data + off, sizeof(data) - off);
}

/* XXX Little endian encoding of multi byte length, violates ASN.1 */
int
asn1_add_length(struct asn1_buf *buf, unsigned long long ulen)
{
	uint8_t data[sizeof(ulen) + 1] = {
	    0x80, 0,
	};
	size_t off = 1;
	size_t start = 0;

	while (ulen) {
		data[off] = ulen;
		off++;
		ulen >>= 8;
		data[0]++;
	}

	if (off == 1)
		off = 2;
	if (off == 2 && (data[1] & 0x80) == 0)
		start = 1;

	return asn1_buf_prepend(buf, data + start, off - start);
}

int
asn1_add_tag(struct asn1_buf *buf, uint8_t type, uint8_t constructed,
    unsigned long long tag)
{
	uint8_t data[11]; // XXX magic
	size_t off;

	if ((type & ASN1_TYPE_MASK) != type)
		return EINVAL;
	if ((constructed & ASN1_FLAG_CONSTRUCTED) != constructed)
		return EINVAL;

	off = sizeof(data);
	if (tag > 30U) {
		uint8_t mask = 0;
		while (tag) {
			assert(off > 0);
			off--;
			data[off] = mask + (tag % 128);
			tag /= 128;
			mask = 0x80U;
		}
		tag = 31U;
	}
	assert(off > 0);
	off--;
	data[off] = type | constructed | tag;

	return asn1_buf_prepend(buf, data + off, sizeof(data) - off);
}

/*
 * XXX CEH: Not in BER form?
 * one byte tag: Vendor (0x40) + 0x11, 0x12, 0x13 or 0x14.
 *	0x15: Array of uint8_t
 *	0x16: Array of uint16_t
 *	0x17: Array of uint32_t
 *	0x18: Array of uint64_t
 * Number of elements aka nvalid, ASN.1 length encoded.
 *	XXX This is not BER. BER would not encode nvalid but the
 *	number of bytes in the rest of the tag.
 * Number of _bytes_ used for the data ASN.1 integer encoded this
 *	includes padding bytes, i.e. nvalid * size of one element + pad.
 *	Encoding uses fixed length of 4.
 * Number of _bytes_ used for padding, ASN.1 integer encoded.
 *	Encoding uses fixed length of 4.
 * nvalid * size of element bytes from data
 * pad zero bytes: NOTE: pad is calculated such that the start of the
 *	array calculated from the end of the structure is 4-byte aligned.
 */
int
asn1_add_apparray(struct asn1_buf *buf, unsigned int tag, void *data,
    size_t nvalid)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);
	int ret;
	size_t elem_size, count, pad;

	switch (tag) {
	case ASN1_TAG_APPARRAY_BYTE:
		elem_size = 1;
		break;
	case ASN1_TAG_APPARRAY_WORD:
		elem_size = 2;
		break;
	case ASN1_TAG_APPARRAY_DWORD:
		elem_size = 4;
		break;
	case ASN1_TAG_APPARRAY_QWORD:
		elem_size = 8;
		break;
	default:
		assert(0);
	}
	count = nvalid * elem_size;
	/* Test for integer overflow */
	if (count / elem_size != nvalid)
		return ENOMEM;
	if (count != 0)
		pad = ((buf->off % 4) + 4 - (count % 4)) % 4;
	else
		pad = 0;

	ret = asn1_buf_pad(buf, pad);
	if (ret != 0)
		goto err;
	ret = asn1_buf_prepend(buf, data, count);
	if (ret != 0)
		goto err;
	ret = asn1_add_int32(buf, pad);
	if (ret != 0)
		goto err;
	ret = asn1_add_int32(buf, count + pad);
	if (ret != 0)
		goto err;
	ret = asn1_add_length(buf, nvalid);
	if (ret != 0)
		goto err;
	ret = asn1_add_tag(buf, ASN1_CLASS_APPLICATION, 0, tag);
	if (ret != 0)
		goto err;

	return 0;

err:
	asn1_buf_rollback(buf, cp);
	return ret;
}

int
asn1_encode_one(struct asn1_buf *buf, struct asn1_val *val)
{
	int ret = EINVAL;

	switch (val->tag_type | val->constructed) {
	case ASN1_CLASS_UNIVERSAL:
		switch (val->tag) {
		case ASN1_TAG_INT:
			switch (val->len) {
			case 1:
				ret = asn1_add_int8(buf, val->i);
				break;
			case 2:
				ret = asn1_add_int16(buf, val->i);
				break;
			case 4:
				ret = asn1_add_int32(buf, val->i);
				break;
			case 8:
				ret = asn1_add_int64(buf, val->i);
				break;
			default:
				ret = asn1_add_ll(buf, val->i);
				break;
			}
			break;
		case ASN1_TAG_NULL:
			ret = asn1_add_null(buf);
			break;
		}
		break;
	case ASN1_CLASS_APPLICATION:
		switch (val->tag) {
		case ASN1_TAG_APPARRAY_BYTE:
			ret =  asn1_add_apparray(buf, val->tag, val->p8,
			    val->len);
			break;
		case ASN1_TAG_APPARRAY_WORD:
			ret =  asn1_add_apparray(buf, val->tag, val->p16,
			    val->len);
			break;
		case ASN1_TAG_APPARRAY_DWORD:
			ret =  asn1_add_apparray(buf, val->tag, val->p32,
			    val->len);
			break;
		case ASN1_TAG_APPARRAY_QWORD:
			ret =  asn1_add_apparray(buf, val->tag, val->p64,
			    val->len);
			break;
		}
	}

	return ret;
}

int
asn1_decode_tag(struct asn1_buf *buf, struct asn1_val *val)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);

	if (asn1_buf_len(buf) == 0)
		return EINVAL;
	val->tag_type = buf->buf[buf->off] & ASN1_TYPE_MASK;
	val->constructed = buf->buf[buf->off] & ASN1_FLAG_CONSTRUCTED;
	val->tag = buf->buf[buf->off] & ASN1_TAG_MASK;
	buf->off++;

	/* Long form of the tag. */
	if (val->tag == ASN1_TAG_MASK) {
		val->tag = 0;
		while (1) {
			if (asn1_buf_len(buf) == 0) {
				asn1_buf_rollback(buf, cp);
				return EINVAL;
			}
			if (((val->tag << 7) >> 7) != val->tag) {
				asn1_buf_rollback(buf, cp);
				return EINVAL;
			}
			val->tag <<= 7;
			val->tag |= buf->buf[buf->off] & 0x7fU;
			buf->off++;
			if ((buf->buf[buf->off-1] & 0x80) == 0)
				break;
		}
	}

	return 0;
}

int
asn1_decode_length(struct asn1_buf *buf, uint64_t *lenp)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);
	uint64_t ret;

	if (buf->off >= buf->len)
		return EINVAL;
	ret = buf->buf[buf->off];
	buf->off++;
	if ((ret & 0x80) != 0) {
		size_t k, bytes = ret % 0x80;
		if (bytes > sizeof(ret)) {
			asn1_buf_rollback(buf, cp);
			return EINVAL;
		}
		if (asn1_buf_len(buf) < bytes) {
			asn1_buf_rollback(buf, cp);
			return EINVAL;
		}

		buf->off += bytes;
		ret = 0;
		for (k = 1; k <= bytes; ++k) {
			ret <<= 8;
			ret |= buf->buf[buf->off - k];
		}
	}

	*lenp = ret;

	return 0;
}

int
__asn1_decode_null(struct asn1_buf *buf, struct asn1_val *val)
{
	(void)buf;

	if (val->len != 0)
		return EINVAL;

	return 0;
}

int
__asn1_decode_int(struct asn1_buf *buf, struct asn1_val *val)
{
	uint64_t v;
	unsigned int i;

	if (val->len > sizeof(v) || val->len == 0)
		return EINVAL;
	v = 0;
	if ((buf->buf[buf->off] & 0x80U) != 0)
		v =~0ULL;
	for (i = 0; i < val->len; i++) {
		v <<= 8;
		v |= buf->buf[buf->off];
		buf->off++;
	}

	val->i = v;

	return 0;
}

int
__asn1_decode_apparray(struct asn1_buf *buf, struct asn1_val *val)
{
	uint64_t count, pad;
	struct asn1_val i;
	size_t elem_size;
	int ret;

	switch (val->tag) {
	case ASN1_TAG_APPARRAY_BYTE:
		elem_size = 1;
		break;
	case ASN1_TAG_APPARRAY_WORD:
		elem_size = 2;
		break;
	case ASN1_TAG_APPARRAY_DWORD:
		elem_size = 4;
		break;
	case ASN1_TAG_APPARRAY_QWORD:
		elem_size = 8;
		break;
	default:
		return EINVAL;
	}

	ret = asn1_decode_one(buf, &i);
	if (ret != 0)
		return ret;
	if (!asn1_val_is_int(&i) || i.i < 0)
		return EINVAL;
	count = i.i;
	ret = asn1_decode_one(buf, &i);
	if (ret != 0)
		return ret;
	if (!asn1_val_is_int(&i) || i.i < 0)
		return EINVAL;
	pad = i.i;

	/* Sometimes count on a non-empty array is reported as zero. */
	if (count == 0 && val->len > 0)
		count = val->len * elem_size + pad;

	if (asn1_buf_len(buf) < count)
		return EINVAL;
	if (pad > count)
		return EINVAL;
	count -= pad;

	if (count / elem_size != val->len || val->len * elem_size != count)
		return EINVAL;

	val->elem_size = elem_size;
	val->p8 = buf->buf + buf->off;
	buf->off += count + pad;

	return 0;
}

int
asn1_decode_one(struct asn1_buf *buf, struct asn1_val *val)
{
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);
	int ret;

	ret = asn1_decode_tag(buf, val);
	if (ret != 0)
		goto out;
	ret = asn1_decode_length(buf, &val->len);
	if (ret != 0)
		goto out;
	ret = EINVAL;
	/* Not sufficient for apparray which violates TLV in BER. */
	if (asn1_buf_len(buf) < val->len)
		goto out;

	switch (val->tag_type | val->constructed) {
	case ASN1_CLASS_UNIVERSAL:
		switch (val->tag) {
		case ASN1_TAG_INT:
			ret = __asn1_decode_int(buf, val);
			break;
		case ASN1_TAG_NULL:
			ret = __asn1_decode_null(buf, val);
			break;
		}
		break;
	case ASN1_CLASS_APPLICATION:
		switch (val->tag) {
		case ASN1_TAG_APPARRAY_BYTE:
		case ASN1_TAG_APPARRAY_WORD:
		case ASN1_TAG_APPARRAY_DWORD:
		case ASN1_TAG_APPARRAY_QWORD:
			ret =  __asn1_decode_apparray(buf, val);
			break;
		}
		break;
	}

out:
	if (ret)
		asn1_buf_rollback(buf, cp);

	return ret;
}

/*
 * @return Zero if buffer was decoded completely, otherwise the error code
 *     from the first item that failed to decode. In any case *np gives
 *     the number of items that were decoded successfully and removed
 *     from the start of the buffer. The error code is the decoding
 *     error from the first item that failed to decode or ENOSPC if
 *     there were more items in @buf than in @val.
 */
int
asn1_decode(struct asn1_buf *buf, struct asn1_val *val, size_t *np)
{
	int ret;
	size_t nval = *np;

	*np = 0;
	while (buf->off < buf->len) {
		if (*np == nval)
			return ENOSPC;
		ret = asn1_decode_one(buf, val + (*np));
		if (ret != 0)
			return ret;
		(*np)++;
	}

	return 0;
}

int
asn1_decode_raw_u32(struct asn1_buf *buf, uint32_t *valp)
{
	uint32_t val = 0;
	unsigned int k;

	if (asn1_buf_len(buf) < sizeof(val))
		return EINVAL;
	for (k = 1; k <= sizeof(val); ++k) {
		val <<= 8;
		val += buf->buf[buf->off + sizeof(val) - k];
	}
	buf->off += 4;

	*valp = val;

	return 0;
}
