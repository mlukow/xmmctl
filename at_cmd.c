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
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <termios.h>

#include "at_cmd.h"

#define CMEE_PREFIX "+CME ERROR: "
#define CMEE_PREFIX_SIZE (sizeof(CMEE_PREFIX)-1)
#define GTURCREADY_PREFIX "+GTURCREADY: "
#define GTURCREADY_PREFIX_SIZE (sizeof(GTURCREADY_PREFIX)-1)
#define GTSIM_PREFIX "+GTSIM: "
#define GTSIM_PREFIX_SIZE (sizeof(GTSIM_PREFIX)-1)

enum at_arg_mode {
	AT_DIRECT,
	AT_STRING,
};

int
at_write_cmd(int atfd, const char *cmd, const char *arg, enum at_arg_mode mode)
{
	int ret, written = 0, count;
	char buf[64];

	if (arg == NULL)
		ret = snprintf(buf, sizeof(buf), "AT%s?\n", cmd);
	else if (mode == AT_DIRECT)
		ret = snprintf(buf, sizeof(buf), "AT%s=%s\n", cmd, arg);
	else
		ret = snprintf(buf, sizeof(buf), "AT%s=\"%s\"\n", cmd, arg);
	if (ret < 0)
		return errno;
	if ((size_t)ret >= sizeof(buf))
		return ENOMEM;

	count = ret;

	while (written < count) {
		ret = write(atfd, buf + written, count - written);
		if (ret < 0)
			return errno;
		written += ret;
	}

	return 0;
}

int
at_read_line(int atfd, char **line)
{
	unsigned int off = 0;
	int ret;
	char *end;
	char buf[100]; /* XXX */

	while ((end = memchr(buf, '\n', off)) == NULL || buf + off == end + 1) {
		if (off >= sizeof(buf))
			return ENOMEM;
		ret = read(atfd, buf + off, sizeof(buf) - off);
		if (ret < 0)
			return errno;
		off += ret;
	}
	if (end[1] != '\n')
		return EIO;
	end[0] = '\0';

	*line = strndup(buf, sizeof(buf));
	if (*line == NULL)
		return ENOMEM;

	return 0;
}

#define RESP_BUF_NUM 8

struct at_resp {
	bool at_ok;
	char *at_msg;
	char *at_buf[RESP_BUF_NUM];
	int8_t at_buf_count;
	long at_gturcready;
	long at_gtsim;
};

void
at_resp_free_msg(struct at_resp *resp)
{
	int i;
	for (i = 0; i < resp->at_buf_count; ++i) {
		free(resp->at_buf[i]);
	}
	resp->at_msg = NULL;
}

void
at_resp_push_buf(struct at_resp *resp, char *buf)
{
	assert(resp->at_buf_count < RESP_BUF_NUM);
	resp->at_buf[resp->at_buf_count] = buf;
	resp->at_buf_count++;
}

int
at_read_resp(int atfd, struct at_resp *resp, const char *query)
{
	int ret;
	char *line = NULL, *end;
	size_t query_len;
	long val;

	resp->at_msg = NULL;
	resp->at_buf_count = 0;
	resp->at_gturcready = resp->at_gtsim = -1;

	while (true) {
		ret = at_read_line(atfd, &line);
		if (ret != 0)
			goto err_no_line;
		if (strcmp(line, "") == 0) {
			free(line);
			continue;
		}
		if (strcmp(line, "OK") == 0) {
			resp->at_ok = true;
			free(line);
			goto out;
		}
		if (resp->at_msg != NULL) {
			ret = EIO;
			goto err;
		}
		if (strcmp(line, "ERROR") == 0) {
			resp->at_ok = false;
			free(line);
			goto out;
		}
		if (strncmp(line, CMEE_PREFIX, CMEE_PREFIX_SIZE) == 0) {
			resp->at_ok = false;
			at_resp_push_buf(resp, line);
			resp->at_msg = line + CMEE_PREFIX_SIZE;
			goto out;
		}
		if (strncmp(line, GTURCREADY_PREFIX,
		    GTURCREADY_PREFIX_SIZE) == 0) {
			val = strtol(line + GTURCREADY_PREFIX_SIZE,
			    &end, 10);
			if (end[0] != '\0') {
				ret = EIO;
				goto err;
			}
			resp->at_gturcready = val;
			free(line);
			continue;
		}
		if(strncmp(line, GTSIM_PREFIX, GTSIM_PREFIX_SIZE) == 0) {
			val = strtol(line + GTSIM_PREFIX_SIZE, &end, 10);
			if (end[0] != '\0') {
				ret = EIO;
				goto err;
			}
			resp->at_gtsim = val;
			free(line);
			continue;
		}
		if (query != NULL) {
			query_len = strlen(query);
			if (strncmp(line, query, query_len) == 0
			    && strncmp(line + query_len, ": ", 2) == 0) {
				at_resp_push_buf(resp, line);
				resp->at_msg = line + query_len + 2;
				continue;
			}
		}
		at_resp_push_buf(resp, line);
	}

out:
	fsync(atfd);
	return 0;

err:
	free(line);
err_no_line:
	at_resp_free_msg(resp);

	return ret;
}

int
at_setup_pin(unsigned int iface_num, const char *pin)
{
	int atfd, ret;
	struct at_resp resp;
	char buf[20];

	ret = snprintf(buf, sizeof(buf), "/dev/xmmc%u.4", iface_num);
	if (ret < 0 || ret >= sizeof(buf))
		return EINVAL;

	atfd = open(buf, O_RDWR | O_CLOEXEC);
	if (atfd < 0)
		return errno;

	ret = at_write_cmd(atfd, "+CMEE", "2", AT_DIRECT);
	if (ret != 0)
		goto out;

	ret = at_read_resp(atfd, &resp, NULL);
	if (ret != 0)
		goto out;
	if (!resp.at_ok) {
		if (resp.at_msg)
			syslog(LOG_ERR, "AT: %s", resp.at_msg);
		ret = EFAULT;
		goto out_resp;
	}

	at_resp_free_msg(&resp);

	ret = at_write_cmd(atfd, "+CPIN", NULL, 0);
	if (ret != 0)
		goto out;

	ret = at_read_resp(atfd, &resp, "+CPIN");
	if (ret != 0)
		goto out;
	if (!resp.at_ok) {
		if (resp.at_msg)
			syslog(LOG_ERR, "AT: %s", resp.at_msg);
		ret = EFAULT;
		goto out_resp;
	}

	if (resp.at_msg == NULL) {
		ret = EFAULT;
		goto out_resp;
	}

	if (strcmp(resp.at_msg, "READY") == 0) {
		ret = 0;
		goto out_resp;
	}

	if (strcmp(resp.at_msg, "SIM PIN") != 0) {
		ret = EFAULT;
		goto out_resp;
	}

	if (pin == NULL) {
		ret = EINVAL;
		goto out_resp;
	}

	at_resp_free_msg(&resp);

	ret = at_write_cmd(atfd, "+CPIN", pin, AT_STRING);
	if (ret != 0)
		goto out;

	ret = at_read_resp(atfd, &resp, NULL);
	if (ret != 0)
		goto out;
	if (!resp.at_ok) {
		if (resp.at_msg)
			syslog(LOG_ERR, "AT: %s", resp.at_msg);
		ret = EINVAL;
		goto out_resp;
	}

	ret = 0;

out_resp:
	at_resp_free_msg(&resp);

out:
	close(atfd);
	return ret;
}
