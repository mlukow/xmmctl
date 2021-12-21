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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
/*
#include <netinet/in.h>
#include <netinet/in_var.h>
*/
#include <sys/ioctl.h>
#include <net/route.h>

#include "msg.h"
#include "at_cmd.h"

static int rpcfd = -1;
static unsigned int requested_mode = ~0U;
static unsigned int current_mode = ~0U;
static bool attach_allowed = false;	/* NOTE: unknown. */
static bool timed_out = false;

static int
write_msg(struct asn1_buf *buf)
{
	size_t off = buf->off;

	while (off < buf->len) {
		int ret = write(rpcfd, buf->buf + off, buf->len - off);
		if (ret < 0) {
			ret = errno;
			return ret;
		}
		off += ret;
	}

	return 0;
}

static int
read_msg(struct asn1_buf *buf)
{
	static const size_t mmax = 1024;
	int ret;
	char data[mmax];
	size_t off = 0;
	size_t limit;

	limit = sizeof(uint32_t);
	while (off < limit) {
		ret = read(rpcfd, data + off, mmax - off);
		if (ret < 0 && errno == EINTR) {
			if (off == 0) {
			    return EINTR;
			} else {
				continue;
			}
		}
		if (ret < 0) {
			return errno;
		}
		if (ret == 0)
			break;
		off += ret;
		if (limit == sizeof(uint32_t) && off >= limit) {
			limit = *(uint32_t *)data;
			if (limit > mmax - sizeof(uint32_t))
				return ENOMEM;
			limit += sizeof(uint32_t);
		}
	}
	if (limit == sizeof(uint32_t) || off != limit)
		return EIO;

	ret = asn1_buf_prepend(buf, (uint8_t *)data, limit);
	if (ret != 0)
		asn1_buf_release(buf);

	return ret;
}

static int
check_format(const struct xmm_msg *msg, const char *format)
{
	unsigned int i;
	char real;

	for (i = 0; format[i]; ++i) {
		if (format[i] == '$') {
			assert(format[i + 1] == '\0');
			if (msg->nval == i) {
				return  0;
			} else {
				syslog(LOG_DEBUG, "%s: Excess value at '$' (code=0x%x)",
				     __func__, msg->code);
				return EINVAL;
			}
		}
		if (i >= msg->nval) {
			syslog(LOG_DEBUG, "%s: Not enough values at %d (code=0x%x)",
			    __func__, i, msg->code);
			return EINVAL;
		}
		if (format[i] == '.')
			continue;
		if (asn1_val_is_int(&msg->val[i]))
			real = 'i';
		else if (asn1_val_is_null(&msg->val[i]))
			real = 'N';
		else if (asn1_val_is_apparray(&msg->val[i]))
			real = 'a';
		else
			real = '.';
		if (format[i] != real) {
			syslog(LOG_DEBUG, "%s: Invalid format at %d (%c vs. %c)",
			    __func__, msg->code, real, format[i]);
			return EINVAL;
		}
	}

	return 0;
}

// XXX for debugging only
static const char *
get_format(const struct xmm_msg *msg)
{
	unsigned int i, pos = 0;
	int ret;
	static char buf[200];

	for (i = 0; i < msg->nval; ++i) {
		if (asn1_val_is_int(&msg->val[i]))
			ret = snprintf(buf + pos, sizeof(buf) - pos, "i%ld", msg->val[i].i);
		else if (asn1_val_is_null(&msg->val[i]))
			ret = snprintf(buf + pos, sizeof(buf) - pos, "N");
		else if (asn1_val_is_apparray(&msg->val[i]))
			ret = snprintf(buf + pos, sizeof(buf) - pos, "a%lu", msg->val[i].len);
		else
			ret = snprintf(buf + pos, sizeof(buf) - pos, ".");
		assert(ret > 0);
		pos += ret;
		if (pos >= sizeof(buf))
			break;
	}
	buf[sizeof(buf)-1] = 0;
	return buf;
}

static int
handle_UtaModeSetRspCb(struct xmm_msg *msg)
{
	if (check_format(msg, "i") != 0) {
		syslog(LOG_ERR, "%s: Bad message format", __func__);
		return EIO;
	}
	if (msg->val[0].i > UINT32_MAX) {
		syslog(LOG_ERR, "%s: Bad mode number %lld", __func__,
		    (unsigned long long)msg->val[0].i);
		return EIO;
	}
	if (current_mode == ~0U && requested_mode == ~0U) {
		current_mode = requested_mode = msg->val[0].i;
		syslog(LOG_DEBUG, "%s: Initial mode set: %u", __func__, current_mode);
	} else {
		current_mode = msg->val[0].i;
		if (current_mode != requested_mode) {
			syslog(LOG_ERR, "%s: Mode set failed %u vs. %u",
			    __func__, current_mode, requested_mode);
			return EIO;
		}
	}
	return 0;
}

static int
handle_UtaMsNetIsAttachAllowedIndCb(struct xmm_msg *msg)
{
	if (check_format(msg, "..i") != 0) {
		syslog(LOG_ERR, "%s: Bad message format", __func__);
		return EIO;
	}
	if (msg->val[2].i != 0)
		attach_allowed = true;
	else
		attach_allowed = false;
	return 0;
}

static int
handle_unsolicited(struct xmm_msg *msg)
{
	int ret = 0;

	switch (msg->code) {
	case UtaModeSetRspCb:
		ret = handle_UtaModeSetRspCb(msg);
		syslog(LOG_DEBUG, "response: UtaModeSetRspCb %s", get_format(msg));
		break;
	case UtaMsNetIsAttachAllowedIndCb:
		ret = handle_UtaMsNetIsAttachAllowedIndCb(msg);
		syslog(LOG_DEBUG, "response: UtaMsNetIsAttachAllowedIndCb %s", get_format(msg));
		break;
	default:
		syslog(LOG_DEBUG, "Unsolicited response: 0x%-3x %s", msg->code,
		    unsol_name(msg->code));
		break;
	}
	return ret;
}

static int
pump(struct xmm_msg *orig_msg){
	struct asn1_buf buf;
	struct xmm_msg mymsg;
	struct xmm_msg *msg = orig_msg ? orig_msg : &mymsg;
	int ret;

	ret = asn1_buf_init(&buf);
	if (ret != 0)
		return ret;

	while (!timed_out) {
		asn1_buf_reset(&buf);
		ret = read_msg(&buf);
		if (ret != 0)
			continue;
		ret = xmm_msg_decode(&buf, msg);
		if (ret != 0) {
			xmm_msg_release(msg);
			break;
		}
		if (xmm_msg_is_response(msg)) {
			if (orig_msg != NULL) {
				/*
				syslog(LOG_DEBUG, "Reply to %s %s",
				    call_id_name(msg->code), get_format(msg));
				*/
				break;
			}
			/*
			syslog(LOG_DEBUG, "Unexpected reply message %s %s",
			    call_id_name(msg->code), get_format(msg));
			*/
		} else if (xmm_msg_is_unsolicited(msg)) {
			ret = handle_unsolicited(msg);
			if (orig_msg == NULL) {
				xmm_msg_release(msg);
				break;
			}
		} else {
			/*
			syslog(LOG_DEBUG, "%s: Async ack 0x%-3x %s %s", __func__, msg->code,
			    call_id_name(msg->code - 2000), get_format(msg));
				*/
		}
		xmm_msg_release(msg);
	}

	asn1_buf_release(&buf);

	return ret;
}

static int
execute(enum xmm_7360_call_ids cmd, struct asn1_buf *buf, bool async,
    struct xmm_msg *reply, const char *format)
{
	struct asn1_buf mybuf;
	int ret = 0;

	/*
	syslog(LOG_DEBUG, "%s: %s", __func__, call_id_name(cmd));
	*/

	ret = asn1_buf_init(&mybuf);
	if (ret != 0)
		return ret;
	if (buf == NULL) {
		buf = &mybuf;
		ret = asn1_add_int32(buf, 0);
		if (ret != 0)
			goto err;
	}

	ret = xmm_msg_add_header(buf, cmd, async);
	if (ret != 0)
		goto err;
	ret = write_msg(buf);
	if (ret != 0)
		goto err;
	asn1_buf_release(&mybuf);

	ret = asn1_buf_init(&mybuf);
	if (ret != 0)
		return ret;
	ret = pump(reply);
	if (ret != 0)
		goto err;
	if (format != NULL) {
		ret = check_format(reply, format);
		if (ret != 0) {
			xmm_msg_release(reply);
			goto err;
		}
	}

	return 0;

err:
	asn1_buf_release(&mybuf);

	return ret;
}

int
execute_simple(enum xmm_7360_call_ids cmd)
{
	struct xmm_msg msg;
	int ret = execute(cmd, NULL, false, &msg, NULL);

	if (ret == 0) {
		xmm_msg_release(&msg);
		return 0;
	} else {
		syslog(LOG_ERR, "execute_simple(0x%x) failed with %d", cmd, ret);
		return ret;
	}
}

int
UtaModeSet(unsigned int mode)
{
	struct asn1_buf buf;
	struct xmm_msg msg;
	int ret;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		goto err;
	}
	ret = pack_UtaModeSetReq(&buf, mode);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaModeSetReq => %d", __func__, ret);
		goto err;
	}
	requested_mode = mode;
	ret = execute(UtaModeSetReq, &buf, false, &msg, "i");
	if (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaModeSetReq,...) => %d",
		    __func__, ret);
		goto err;
	}
	if (msg.val[0].i != 0) {
		syslog(LOG_ERR, "%s: execute(UtaModeSetReq,...): Bad mode?",
		    __func__);
		xmm_msg_release(&msg);
		ret = EIO;
		goto err;
	}

	asn1_buf_release(&buf);
	xmm_msg_release(&msg);

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return ret;
	}
	while (current_mode != requested_mode) {
		ret = pump(NULL);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: pump() => %d", __func__, ret);
			goto err;
		}
	}

	return 0;

err:
	asn1_buf_release(&buf);

	return ret;
}

int
UtaApnSet(const char *apn)
{
	struct asn1_buf buf;
	struct xmm_msg msg;
	int ret;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return ret;
	}
	ret = pack_UtaMsCallPsAttachApnConfigReq(&buf, apn);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaMsCallPsAttachApnConfigReq => %d",
		    __func__, ret);
		goto err;
	}
	ret = execute(UtaMsCallPsAttachApnConfigReq, &buf, true, &msg, NULL);
	if  (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaMsCallPsAttachApnConfigReq,...) => %d",
		    __func__, ret);
		goto err;
	}

	xmm_msg_release(&msg);
err:
	asn1_buf_release(&buf);

	return ret;
}

int
do_fcc_unlock()
{
	SHA256_CTX ctx;
	struct asn1_buf buf;
	struct xmm_msg msg;
	uint32_t resp;
	int ret = execute(CsiFccLockQueryReq, NULL, true, &msg, "iii");

	if (ret != 0) {
		syslog(LOG_ERR, "CsiFccLockQueryReq failed with %d", ret);
		return ret;
	}
	/* fcc_mode == 0: No fcc lock required. */
	if (msg.val[2].i == 0) {
		syslog(LOG_DEBUG, "%s: No FCC lock required", __func__);
		ret = 0;
		goto out;
	}
	/* fcc_state != 0: already unlocked. */
	if (msg.val[1].i != 0) {
		syslog(LOG_DEBUG, "%s: Already unlocked", __func__);
		ret = 0;
		goto out;
	}

	ret = execute(CsiFccLockGenChallengeReq, NULL, true, &msg, "ii");
	if (ret != 0) {
		syslog(LOG_ERR, "CsiFccLockGenChallengeReq failed with %d", ret);
		return ret;
	}

	ret = asn1_buf_init(&buf);
	if (ret != 0)
		return ret;

	ret = asn1_add_raw_u32(&buf, 0x19c7f83d);
	if (ret != 0)
		return ret;

	ret = asn1_add_raw_u32(&buf, msg.val[1].i);
	if (ret != 0)
		return ret;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf.buf + buf.off, 8);

	asn1_buf_reset(&buf);
	ret = asn1_buf_pad(&buf, SHA256_DIGEST_LENGTH);
	if (ret != 0)
		return ret;

	SHA256_Final(buf.buf + buf.off, &ctx);
	asn1_decode_raw_u32(&buf, &resp);

	asn1_buf_reset(&buf);
	ret = asn1_add_int32(&buf, resp);
	if (ret != 0)
		return ret;

	ret = execute(CsiFccLockVerChallengeReq, &buf, true, &msg, "i");
	if (ret != 0) {
		syslog(LOG_ERR, "CsiFccLockVerChallengeReq failed with %d", ret);
		return ret;
	}

	if (msg.val[0].i != 1) {
		syslog(LOG_ERR, "FCC unlock failed: %d", ret);
		return ret;
	}

	syslog(LOG_DEBUG, "%s: FCC unlocked", __func__);

	ret = 0;
out:
	xmm_msg_release(&msg);
	return ret;
}

static int
UtaMsNetAttach()
{
	struct xmm_msg msg;
	struct asn1_buf buf;
	int ret;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return ret;
	}
	ret = pack_UtaMsNetAttachReq(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaMsNetAttachReq => %d", __func__, ret);
		goto err;
	}
	ret = execute(UtaMsNetAttachReq, &buf, true, &msg, "ii");
	if (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaMsNetAttachReq,...) => %d",
		    __func__, ret);
		goto err;
	}
	ret = 0;
	if (msg.val[1].i == -1)
		ret = EAGAIN;

	xmm_msg_release(&msg);
err:
	asn1_buf_release(&buf);

	return ret;
}

static ssize_t
UtaGetIps(struct in_addr **addrs)
{
	struct xmm_msg msg;
	struct asn1_buf buf;
	int ret;
	unsigned int i, j;
	uint32_t addr;
	uint64_t len;

	*addrs = NULL;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return -ret;
	}
	ret = pack_UtaMsCallPsGetNegIpAddrReq(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaMsCallPsGetNegIpAddrReq => %d",
		    __func__, ret);
		goto out;
	}
	ret = execute(UtaMsCallPsGetNegIpAddrReq, &buf, true, &msg,
	    "iaiiii");
	if (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaMsCallPsGetNegIpAddrReq,...) => %d",
		    __func__, ret);
		goto out;
	}

	len = msg.val[1].len * msg.val[1].elem_size;
	if (len % 4 != 0) {
		ret = EIO;
		goto out_with_msg;
	}
	len /= 4;
	if (len > SSIZE_MAX) {
		ret = ENOMEM;
		goto out_with_msg;
	}
	*addrs = malloc(len * sizeof(struct in_addr));
	if (*addrs == NULL) {
		ret = ENOMEM;
		goto out_with_msg;
	}
	for (i = 0; i < len; ++i) {
		addr = 0;
		for (j = 0; j < 4; ++j) {
			addr <<= 8;
			addr += msg.val[1].p8[4*i+j];
		}
		(*addrs)[i].s_addr = htonl(addr);
	}

out_with_msg:
	xmm_msg_release(&msg);

out:
	asn1_buf_release(&buf);

	if (ret != 0)
		return -ret;
	else
		return len;
}

struct dns_addr {
	sa_family_t	family;
	union {
		struct in6_addr addr6;
		struct in_addr addr4;
	};
};

static ssize_t
UtaGetDns(struct dns_addr **addrs)
{
	struct xmm_msg msg;
	struct asn1_buf buf;
	int ret;
	unsigned int i, k, idx = 0;
	uint32_t addr;
	size_t total;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return -ret;
	}
	ret = pack_UtaMsCallPsGetNegotiatedDnsReq(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaMsCallPsGetNegotiatedDnsReq => %d",
		    __func__, ret);
		goto err;
	}
	ret = execute(UtaMsCallPsGetNegotiatedDnsReq, &buf, true, &msg,
	    "iaiaiaiaiaiaiaiaiaiaiaiaiaiaiaiaiiaiiii");
	if (ret != 0) {
		syslog(LOG_ERR,
		    "%s: execute(UtaMsCallPsGetNegotiatedDnsReq,...) => %d",
		    __func__, ret);
		goto err;
	}

	*addrs = malloc(16*sizeof(struct dns_addr));
	if (*addrs == NULL) {
		ret = ENOMEM;
		goto err_with_msg;
	}

	for (i = 0; i < 16; ++i) {
		total = msg.val[2*i+1].len * msg.val[2*i+1].elem_size;

		switch (msg.val[2*i+2].i) {
		case 0:	/* Empty */
			break;
		case 1:	/* IPv4 */
			if (total < 4) {
				ret = EIO;
				syslog(LOG_ERR, "%s: Invalid IPv4 size: %d",
				    __func__, (int)total);
				goto err_with_addrs;
				}
			total = 4;
			addr = 0;
			for (k = 0; k < total; ++k) {
				addr <<= 8;
				addr += msg.val[2*i+1].p8[k];
			}
			(*addrs)[idx].family = AF_INET;
			(*addrs)[idx].addr4.s_addr = htonl(addr);
			idx++;
			break;
		case 2:	/* IPv6 */
			if (total < 16) {
				ret = EIO;
				syslog(LOG_ERR, "%s: Invalid IPv6 size %d",
				    __func__, (int)total);
				goto err_with_addrs;
				}
			total = 16;
			(*addrs)[idx].family = AF_INET6;
			for (k = 0; k < total; ++k)
				(*addrs)[idx].addr6.s6_addr[k] =
				    msg.val[2*i+1].p8[k];
			idx++;
			break;
		default:
			syslog(LOG_DEBUG, "%s: Unsupported address format %lld",
			    __func__, (long long)msg.val[2*i+2].i);
			/* XXX */
			break;
		}
	}

err_with_addrs:
	if (ret != 0) {
		free(*addrs);
		*addrs = NULL;
	}

err_with_msg:
	xmm_msg_release(&msg);
err:
	asn1_buf_release(&buf);

	if (ret != 0)
		return -ret;
	else
		return idx;
}

int
UtaSetupConnection()
{
	struct xmm_msg m1, m2;
	struct asn1_buf buf;
	unsigned int i;
	int ret;

	ret = asn1_buf_init(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_buf_init => %d", __func__, ret);
		return ret;
	}
	ret = pack_UtaMsCallPsConnectReq(&buf);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaMsCallPsConnectReq => %d", __func__, ret);
		goto err;
	}
	ret = execute(UtaMsCallPsConnectReq, &buf, true, &m1, NULL);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaMsCallPsConnectReq,...) => %d",
		    __func__, ret);
		goto err;
	}
	if (m1.nval == 0 || !asn1_val_is_int(&m1.val[m1.nval - 1])) {
		ret = EIO;
		syslog(LOG_ERR, "%s: execute(UtaMsCallPsConnectReq,...) "
		    "=> Invalid response", __func__);
		goto err_with_m1;
	}

	asn1_buf_reset(&buf);
	ret = pack_UtaRPCPsConnectToDatachannelReq(&buf,
	    "/sioscc/PCIE/IOSM/IPS/0");
	if (ret != 0) {
		syslog(LOG_ERR, "%s: pack_UtaRPCPsConnectToDatachannelReq => %d",
		    __func__, ret);
		goto err_with_m1;
	}
	ret = execute(UtaRPCPsConnectToDatachannelReq, &buf, false, &m2, NULL);
	if (ret != 0) {
		syslog(LOG_ERR,
		    "%s: execute(UtaRPCPsConnectToDatachannelReq,...) => %d",
		    __func__, ret);
		goto err_with_m1;
	}

	asn1_buf_reset(&buf);
	ret = asn1_add_int32(&buf, 0);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: asn1_add_int32 => %d", __func__, ret);
		goto err_with_m2;
	}
	for (i = m2.nval; i > 0; i--) {
		ret = asn1_encode_one(&buf, &m2.val[i - 1]);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: asn1_encode_one => %d", __func__, ret);
			goto err_with_m2;
		}
	}
	for (i = m1.nval - 1; i > 0; i--) {
		ret = asn1_encode_one(&buf, &m1.val[i - 1]);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: asn1_encode_one => %d", __func__, ret);
			goto err_with_m2;
		}
	}

	xmm_msg_release(&m1);
	xmm_msg_release(&m2);

	ret = execute(UtaRPCPSConnectSetupReq, &buf, false, &m1, NULL);
	if (ret != 0) {
		syslog(LOG_ERR, "%s: execute(UtaRPCPSConnectSetupReq,...) => %d",
		    __func__, ret);
		goto err;
	}

	xmm_msg_release(&m1);
	asn1_buf_release(&buf);
	return 0;

err_with_m2:
	xmm_msg_release(&m2);
err_with_m1:
	xmm_msg_release(&m1);
err:
	asn1_buf_release(&buf);

	return ret;
}

int
select_ip_addr(const struct in_addr *addrs, ssize_t count, const struct in_addr **addr) {
	int i;

	*addr = NULL;

	for (i = 0; i < count; i++) {
		if (addrs[i].s_addr != 0)
			*addr = &addrs[i];
		else
			break;
	}
	if (*addr == NULL)
		return EFAULT;

	return 0;
}

void
timeout(int _sig)
{
	syslog(LOG_DEBUG, "timed out waiting for attach_allowed");
	timed_out = true;
}

 /**
    * Create socket function
    */
    int create_socket() {

      int sockfd = 0;

      sockfd = socket(AF_INET, SOCK_DGRAM, 0);
      if(sockfd == -1){
        fprintf(stderr, "Could not get socket.\n");
        return -1;
      }

      return sockfd;

    }

    /**
    * Generic ioctrlcall to reduce code size
    */
    int generic_ioctrlcall(int sockfd, u_long *flags, struct ifreq *ifr) {

      if (ioctl(sockfd, (long unsigned int)flags, &ifr) < 0) {
        fprintf(stderr, "ioctl: %s\n", (char *)flags);
        return -1;
      }
      return 1;
    }

    /**
    * Set route with metric 100
    */
    int set_route(int sockfd, char *gateway_addr,  struct sockaddr_in *addr) {
      struct rtentry route;
      memset(&route, 0, sizeof(route));
      addr = (struct sockaddr_in*) &route.rt_gateway;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = inet_addr(gateway_addr);
      addr = (struct sockaddr_in*) &route.rt_dst;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = inet_addr("0.0.0.0");
      addr = (struct sockaddr_in*) &route.rt_genmask;
      addr->sin_family = AF_INET;
      addr->sin_addr.s_addr = inet_addr("0.0.0.0");
      route.rt_flags = RTF_UP | RTF_GATEWAY;
      route.rt_metric = 100;

	  if (ioctl(sockfd, SIOCADDRT, &route) < 0) {
		  printf("ioctl in set_route\n");
		  return -1;
	  }

	  return 1;
    }

    /**
    * Set ip function
    */
    int set_ip(char *iface_name, char *ip_addr, char *gateway_addr)
    {
      if(!iface_name)
        return -1;
      struct ifreq ifr;
      struct sockaddr_in sin;
      int sockfd = create_socket();

      sin.sin_family = AF_INET;

      // Convert IP from numbers and dots to binary notation
      inet_aton(ip_addr,(struct in_addr *)&sin.sin_addr.s_addr);

      /* get interface name */
      strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

      /* Read interface flags */
	  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		  printf("ioctl 1\n");
		  return -1;
	  }
      //generic_ioctrlcall(sockfd, (u_long *)"SIOCGIFFLAGS", &ifr);
      /*
      * Expected in <net/if.h> according to
      * "UNIX Network Programming".
      */
      #ifdef ifr_flags
      # define IRFFLAGS       ifr_flags
      #else   /* Present on kFreeBSD */
      # define IRFFLAGS       ifr_flagshigh
      #endif
      // If interface is down, bring it up
      if (ifr.IRFFLAGS | ~(IFF_UP)) {
        ifr.IRFFLAGS |= IFF_UP;
        //generic_ioctrlcall(sockfd, (u_long *)"SIOCSIFFLAGS", &ifr);
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
			printf("ioctl 2\n");
			return -1;
		}
      }
      // Set route
      set_route(sockfd, gateway_addr    ,  &sin);

      memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

      // Set interface address
      if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        fprintf(stderr, "Cannot set IP address. ");
        perror(ifr.ifr_name);
        return -1;
      }
      #undef IRFFLAGS

      return 0;
    }

void
usage(const char* progname)
{
	fprintf(stderr,
	    "usage: %s -a <apn> [-p <pin>] <iface>\n",
	     progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	return set_ip("ens33", "192.168.45.67", "192.168.45.67");
}

/*
 * # Usage
 *
 * xmmctl -a apn [-p <pin>] [-r] <iface>
 *
 * -a   Set Apn for the connection
 * -p   Set Pin for the connection. Leaving this option out
 *          means no pin
 *
 */

int
main2(int argc, char *argv[])
{
	int ret, ch, i;
	const char *apn = NULL, *pin = NULL, *ifname = NULL;
	struct in_addr *ip_addrs = NULL;
	const struct in_addr *addr;
	struct dns_addr *dns_servers = NULL;
	ssize_t ip_count, dns_count;
	char buf[INET6_ADDRSTRLEN];
	unsigned int iface_num;

	while ((ch = getopt(argc, argv, "a:p:")) != -1) {
		switch (ch) {
		case 'a':
			apn = optarg;
			break;
		case 'p':
			pin = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind + 1 != argc) {
		usage(argv[0]);
		return 1;
	}

	ifname = argv[optind];

	if (apn == NULL) {
		usage(argv[0]);
		return 1;
	}

	ret = sscanf(ifname, "xmm%u", &iface_num);
	if (ret != 1) {
		err(1, "invalid interface name");
	}

	ret = snprintf(buf, sizeof(buf), "/dev/xmmc%u.1", iface_num);
	if (ret < 0 || ret >= sizeof(buf))
		errx(1, "failed to open rpc interface");

	for (i = 0; i < 5; i++) {
		rpcfd = open(buf, O_RDWR | O_SYNC | O_CLOEXEC);
		if (rpcfd >= 0) {
			break;
		} else if (rpcfd < 0 && errno == EAGAIN) {
			/*
			 * Reopening RPC interface. Wait for the prior
			 * close to complete.
			 */
			sleep(2);
			continue;
		} else {
			syslog(LOG_ERR, "failed to open rpc device: %m");
			return 1;
		}
	}
	if (rpcfd < 0) {
		syslog(LOG_ERR, "timed out opening RPC interface");
		return 1;
	}

	if ((ret = execute_simple(UtaMsSmsInit)) != 0 ||
	    (ret = execute_simple(UtaMsCbsInit)) != 0 ||
	    (ret = execute_simple(UtaMsNetOpen)) != 0 ||
	    (ret = execute_simple(UtaMsCallCsInit)) != 0 ||
	    (ret = execute_simple(UtaMsCallPsInitialize)) != 0 ||
	    (ret = execute_simple(UtaMsSsInit)) != 0 ||
	    (ret = execute_simple(UtaMsSimOpenReq)) != 0) {
		syslog(LOG_ERR, "failed to set up interface");
		return 1;
	}

	if (do_fcc_unlock() != 0) {
		syslog(LOG_ERR, "failed to unlock FCC");
		return 1;
	}

	if (UtaModeSet(1) != 0) {
		syslog(LOG_ERR, "failed to set mode");
		return 1;
	}

	if (UtaApnSet(apn) != 0) {
		syslog(LOG_ERR, "failed to set Apn");
		return 1;
	}

	/* XXX needed to stabilize configuration */
	if (pin) {
		sleep(3);
		if ((ret = at_setup_pin(iface_num, pin)) != 0) {
			errno = ret;
			syslog(LOG_ERR, "failed to setup PIN: %m");
			return 1;
		}
	}

	ret = UtaMsNetAttach();
	if (ret != 0) {
		errno = ret;
		syslog(LOG_ERR, "failed to attach net %m");
		return 1;
	}

	ip_count = UtaGetIps(&ip_addrs);
	if (ip_count < 0) {
		syslog(LOG_ERR, "failed to receive IP addresses");
		return 1;
	}
	dns_count = UtaGetDns(&dns_servers);
	if (dns_count < 0) {
		syslog(LOG_ERR, "failed to receive DNS servers");
		return 1;
	}

	ret = select_ip_addr(ip_addrs, ip_count, &addr);
	if (ret != 0) {
		syslog(LOG_ERR, "failed to select ip address");
		return 1;
	}

	/*
	retp = inet_ntop(AF_INET, addr, buf, sizeof(buf));
	if (retp != NULL) {
		syslog(LOG_DEBUG, "got ip addr %s", retp);

		retp_len = strlen(retp);
		char *cmd = malloc(21 + 2 * retp_len + strlen(ifname));
		sprintf(cmd, "/sbin/ifconfig %s %s/32 %s", ifname, buf, buf);
		ret = system(cmd);
		if (ret != 0) {
			syslog(LOG_ERR, "ifconfig failed");
			return 1;
		}

		free(cmd);
		cmd = malloc(37 + retp_len);
		sprintf(cmd, "/sbin/route add -priority 6 default %s", buf);
		ret = system(cmd);
		free(cmd);
		if (ret != 0) {
			syslog(LOG_ERR, "route failed");
			return 1;
		}
	}

	if (dns_count > 0) {
		resolv_file = fopen("/etc/resolv.conf", "w");
		fprintf(resolv_file, "# Generated by xmmctl\n");
		for (i = 0; i < dns_count; i++) {
			retp = inet_ntop(dns_servers[i].family, &(dns_servers[i].addr4),
					buf, sizeof(buf));
			if (retp != NULL) {
				fprintf(resolv_file, "nameserver %s\n", buf);
			}
		}
		fclose(resolv_file);
	}
	*/

	if ((ret = UtaSetupConnection()) != 0) {
		syslog(LOG_ERR, "failed to set up connection");
		return 1;
	}

	close(rpcfd);

	return 0;
}
