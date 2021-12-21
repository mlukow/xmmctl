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
#include <sys/errno.h>
// #include <bsd/string.h>

#include "uta.h"

static unsigned char zero[512];

#define PACK(X...) do {			\
	ret = X;			\
	if (ret != 0)			\
		goto err;		\
} while (0)

#define PACK8(X) PACK(asn1_add_int8(buf, (X)))
#define PACK16(X) PACK(asn1_add_int16(buf, (X)))
#define PACK32(X) PACK(asn1_add_int32(buf, (X)))
#define PACKSTRING(S, N) PACK(asn1_add_apparray(buf, \
    ASN1_TAG_APPARRAY_BYTE, (void *)(S), (N)))
#define PACKZERO(N) do {					\
	if ((N) > sizeof(zero)) {				\
		ret = EINVAL;					\
		goto err;					\
	}							\
	PACK(asn1_add_apparray(buf, ASN1_TAG_APPARRAY_BYTE,	\
	    (void *)zero, (N)));				\
} while (0)

#define STRINGIFY(X) #X
#define _PACK_HEADER(X) STRINGIFY(pack/_##X##_.h)
#define PACK_HEADER(X) _PACK_HEADER(X)

#define PACK_BEGIN(TYPE, ...)					\
int								\
pack_##TYPE(struct asn1_buf *buf, ##__VA_ARGS__)		\
{								\
	struct asn1_buf_cp cp = asn1_buf_checkpoint(buf);	\
	int ret;

#define PACK_END(TYPE)						\
	return 0;						\
err:								\
	asn1_buf_rollback(buf, cp);				\
	return ret;						\
}

PACK_BEGIN(UtaMsCallPsAttachApnConfigReq, const char *apn)
	unsigned char apnbuf[101];
	memset(apnbuf, 0, sizeof(apnbuf));
	strncpy((void *)apnbuf, apn, sizeof(apnbuf) - 1);
#	include PACK_HEADER(UtaMsCallPsAttachApnConfigReq)
PACK_END(UtaMsCallPsAttachApnConfigReq)

PACK_BEGIN(UtaMsCallPsGetNegIpAddrReq)
#	include PACK_HEADER(UtaMsCallPsGetNegIpAddrReq)
PACK_END(UtaMsCallPsGetNegIpAddrReq)

PACK_BEGIN(UtaMsNetAttachReq)
#	include PACK_HEADER(UtaMsNetAttachReq)
PACK_END(UtaMsNetAttachReq)

PACK_BEGIN(UtaMsCallPsGetNegotiatedDnsReq)
#	include PACK_HEADER(UtaMsCallPsGetNegotiatedDnsReq)
PACK_END(UtaMsCallPsGetNegotiatedDnsReq)

PACK_BEGIN(UtaMsCallPsConnectReq)
#	include PACK_HEADER(UtaMsCallPsConnectReq)
PACK_END(UtaMsCallPsConnectReq)

PACK_BEGIN(UtaRPCPsConnectToDatachannelReq, const char *path)
#	include PACK_HEADER(UtaRPCPsConnectToDatachannelReq)
PACK_END(UtaRPCPsConnectToDatachannelReq)

PACK_BEGIN(UtaSysGetInfo, int index)
#	include PACK_HEADER(UtaSysGetInfo)
PACK_END(UtaSysGetInfo)

PACK_BEGIN(UtaModeSetReq, unsigned int mode)
	ret = EINVAL;
	if ((int32_t)mode < 0)
		goto err;
#	include PACK_HEADER(UtaModeSetReq)
PACK_END(UtaModeSetReq)
