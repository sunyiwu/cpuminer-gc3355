/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define DEF_RPC_URL		"http://127.0.0.1:9332/"

enum workio_commands {
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum sha256_algos {
	ALGO_SCRYPT,		/* scrypt(1024,1,1) */
	ALGO_SHA256D,		/* SHA-256d */
};

static const char *algo_names[] = {
	[ALGO_SCRYPT]		= "scrypt",
	[ALGO_SHA256D]		= "sha256d",
};

#define GC3355_DEFAULT_CHIPS 5
#define API_DEFAUKT_PORT 4028
#define API_QUEUE 16
#define API_STATS "stats"
#define API_MINER_START_TIME "t"
#define API_DEVICES "d"
#define API_CHIPS "c"
#define API_LAST_SHARE "l"
#define API_CHIP_ACCEPTED "ac"
#define API_CHIP_REJECTED "re"
#define API_CHIP_HW_ERRORS "hw"
#define API_CHIP_FREQUENCY "fr"
#define API_CHIP_HASHRATE "ha"
#define API_CHIP_SHARES "sh"

struct gc3355_dev {
	int	id;
	int	dev_fd;
	unsigned char chips;
	bool resend;
	char *devname;
	unsigned short *freq;
	uint32_t *last_nonce;
	unsigned long long *hashes;
	double *time_now;
	double *time_spent;
	unsigned short *total_hwe;
	unsigned short *hwe;
	unsigned short *adjust;
	unsigned short *steps;
	unsigned int *accepted;
	unsigned int *rejected;
	double *hashrate;
	unsigned long long *shares;
	unsigned int *last_share;
};

static char *gc3355_devname = NULL;
static unsigned short opt_frequency = 600;
static char *opt_gc3355_frequency = NULL;
static char opt_gc3355_autotune = 0x0;
static unsigned short opt_gc3355_chips = GC3355_DEFAULT_CHIPS;
static struct gc3355_dev *gc3355_devs;
static unsigned int gc3355_time_start;

bool opt_debug = false;
bool opt_protocol = false;
bool want_stratum = true;
bool have_stratum = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 5;
int opt_timeout = 270;
int opt_scantime = 5;
static int opt_n_threads;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
unsigned short opt_api_port = API_DEFAUKT_PORT;
int api_sock;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -G, --gc3355=DEV0,DEV1,...,DEVn      					enable GC3355 chip mining mode (default: no)\n\
  -F, --freq=FREQUENCY  								set GC3355 core frequency in NONE dual mode (default: 600)\n\
  -f, --gc3355-freq=DEV0:F0,DEV1:F1,...,DEVn:Fn			individual frequency setting\n\
	  --gc3355-freq=DEV0:F0:CHIP0,...,DEVn:Fn:CHIPn		individual per chip frequency setting\n\
  -A, --gc3355-autotune  								auto overclocking each GC3355 chip (default: no)\n\
  -c, --gc3355-chips=N  								# of GC3355 chips (default: 5)\n\
  -a, --api-port=PORT  									set the JSON API port (default: 4028)\n\
  -o, --url=URL         								URL of mining server (default: " DEF_RPC_URL ")\n\
  -O, --userpass=U:P    								username:password pair for mining server\n\
  -u, --user=USERNAME   								username for mining server\n\
  -p, --pass=PASSWORD   								password for mining server\n\
  -r, --retries=N       								number of times to retry if a network call fails\n\
														(default: retry indefinitely)\n\
  -R, --retry-pause=N									time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       								network timeout, in seconds (default: 270)\n\
  -q, --quiet           								disable per-thread hashmeter output\n\
  -D, --debug           								enable debug output\n\
  -P, --protocol-dump   								verbose dump of protocol-level activities\n\
  -V, --version         								display version information and exit\n\
  -h, --help            								display this help text and exit\n";

static char const short_options[] = 
	"G:F:f:A:c"
	"PDhp:qr:R:T:o:u:O:V";

static struct option const options[] = {
	{ "gc3355", 1, NULL, 'G' },
	{ "freq", 1, NULL, 'F' },
	{ "gc3355-freq", 1, NULL, 'f' },
	{ "gc3355-autotune", 0, NULL, 'A' },
	{ "gc3355-chips", 1, NULL, 'c' },
	{ "api-port", 1, NULL, 'a' },
	{ "debug", 0, NULL, 'D' },
	{ "pass", 1, NULL, 'p' },
	{ "quiet", 0, NULL, 'q' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "version", 0, NULL, 'V' },
	{ "help", 0, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

struct work {
	uint32_t data[32];
	uint32_t *target;
	char *job_id;
	uint32_t *work_id;
	unsigned char xnonce2[4];
	unsigned short thr_id;
};

static uint32_t g_prev_target[8];
static uint32_t g_curr_target[8];
static char g_prev_job_id[128];
static char g_curr_job_id[128];
static uint32_t g_prev_work_id;
static uint32_t g_curr_work_id;
static char can_work = 0x1;

static struct work *g_works;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;

static bool submit_work(struct thr_info *thr, const struct work *work_in);

/* added for GC3355 chip miner */
#include "gc3355.h"
/* end */

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;
	
	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON inval data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON inval target");
		goto err_out;
	}

	for (i = 0; i < ARRAY_SIZE(work->data); i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

static void share_result(int result, const char *reason, int thr_id, int chip_id)
{
	int i, j;
	struct timeval timestr;
	double chip_hashrate, hashrate = 0, pool_hashrate = 0, thread_hashrate = 0;
	unsigned int thread_accepted = 0, thread_rejected = 0;
	pthread_mutex_lock(&stats_lock);
	if(result)
		gc3355_devs[thr_id].accepted[chip_id]++;
	else
		gc3355_devs[thr_id].rejected[chip_id]++;
	gettimeofday(&timestr, NULL);
	gc3355_devs[thr_id].last_share[chip_id] = timestr.tv_sec;
	gc3355_devs[thr_id].shares[chip_id] += stratum.job.diff;
	chip_hashrate = gc3355_devs[thr_id].hashrate[chip_id];
	for(i = 0; i < opt_n_threads; i++)
	{
		for(j = 0; j < 5; j++)
		{
			hashrate += gc3355_devs[i].hashrate[j];
			pool_hashrate += gc3355_devs[i].shares[j];
			if(i == thr_id)
			{
				thread_accepted += gc3355_devs[i].accepted[j];
				thread_rejected += gc3355_devs[i].rejected[j];
				thread_hashrate += gc3355_devs[i].hashrate[j];
			}
		}
	}
	pool_hashrate = (1 << 16) / ((timestr.tv_sec - gc3355_time_start) / pool_hashrate);
	pthread_mutex_unlock(&stats_lock);
	#ifndef WIN32
	applog(LOG_INFO, "%s%d@%d: %s %lu/%lu (%.2f%%) %.1lf/%.1lf/%.1lf (Pool: %.1lf) KH/s[0m",
		   result ? "[1;32m" : "[1;31m",
		   thr_id, chip_id,
		   result ? "accepted" : "rejected",
		   thread_accepted,
		   thread_accepted + thread_rejected,
		   100. * thread_accepted / (thread_accepted + thread_rejected),
		   chip_hashrate / 1000, thread_hashrate / 1000, hashrate / 1000, pool_hashrate / 1000);
	#else
	if(result)
		set_text_color(FOREGROUND_LIGHTGREEN);
	else
		set_text_color(FOREGROUND_LIGHTRED);
	applog(LOG_INFO, "%d@%d: %s %lu/%lu (%.2f%%) %.1lf/%.1lf/%.1lf (Pool: %.1lf) KH/s",
		   thr_id, chip_id,
		   result ? "accepted" : "rejected",
		   thread_accepted,
		   thread_accepted + thread_rejected,
		   100. * thread_accepted / (thread_accepted + thread_rejected),
		   chip_hashrate / 1000, thread_hashrate / 1000, hashrate / 1000, pool_hashrate / 1000);
	set_text_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	#endif
	if (reason)
		applog(LOG_INFO, "DEBUG: reject reason: %s", reason);
}

static void restart_threads(void)
{
	int i;
	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	json_t *val, *res, *reason;
	char s[345];
	int i;
	bool rc = false;

	if (have_stratum) {
		uint32_t ntime, nonce;
		char *ntimestr, *noncestr, *xnonce2str;

		if (!work->job_id)
			return true;
		le32enc(&ntime, work->data[17]);
		le32enc(&nonce, work->data[19]);
		ntimestr = bin2hex((const unsigned char *)(&ntime), 4);
		noncestr = bin2hex((const unsigned char *)(&nonce), 4);
		xnonce2str = bin2hex(work->xnonce2, 4);
		int chip_id = work->data[19] / (0xffffffff / 5);
		sprintf(s,
			"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%d}",
			rpc_user, work->job_id, xnonce2str, ntimestr, noncestr, chip_id << 8 | work->thr_id);
		free(ntimestr);
		free(noncestr);
		free(xnonce2str);
		
		if (unlikely(!stratum_send_line(&stratum, s))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			can_work = 0x0;
			goto out;
		}
		can_work = 0x1;
	}

	rc = true;

out:
	return rc;
}

static const char *rpc_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	bool rc;
	struct timeval tv_start, tv_end, diff;

	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, rpc_req,
			    true, false, NULL);
	gettimeofday(&tv_end, NULL);

	if (have_stratum) {
		if (val)
			json_decref(val);
		return true;
	}

	if (!val)
		return false;

	rc = work_decode(json_object_get(val, "result"), work);

	if (opt_debug && rc) {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: got new work in %d ms",
		       diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}

	json_decref(val);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		free(wc->u.work->job_id);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	while (ok) {
		struct workio_cmd *wc;
		
		/* wait for workio_cmd sent to us, on our queue */
		wc = tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;
		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	
	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(*work_in));
	wc->u.work->job_id = strdup(wc->u.work->job_id);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	unsigned char merkle_root[64];
	int i;

	work->job_id = g_curr_job_id;
	
	uint32_t xnonce2;
	if(!memcmp(work->xnonce2, "\x00\x00\x00\x00", 4))
	{
		xnonce2 = 0xffffffff / (work->thr_id + 2);
	}
	else
	{
		xnonce2 = (uint32_t)(work->xnonce2[0]) << 24 |
			(uint32_t)(work->xnonce2[1]) << 16 |
			(uint32_t)(work->xnonce2[2]) << 8  |
			(uint32_t)(work->xnonce2[3]);
		if(xnonce2 < (0xffffffff / (work->thr_id + 1)) - 1)
		{
			xnonce2++;
		}
		else
		{
			xnonce2 = 0xffffffff / (work->thr_id + 2);
		}
	}
	unsigned char *coinbase = malloc(sctx->job.coinbase_size);
	memcpy(coinbase, sctx->job.coinbase, sctx->job.coinbase_size);
	unsigned char xnonce2s[4] = {xnonce2 >> 24, xnonce2 >> 16, xnonce2 >> 8, xnonce2};
	memcpy(coinbase + (sctx->job.xnonce2 - sctx->job.coinbase), xnonce2s, 4);
	memcpy(work->xnonce2, xnonce2s, 4);
	
	/* Generate merkle root */
	sha256d(merkle_root, coinbase, sctx->job.coinbase_size);
	for (i = 0; i < sctx->job.merkle_count; i++)
	{
		memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
		sha256d(merkle_root, merkle_root, 64);
	}

	/* Assemble block header */
	memset(work->data, 0, 128);
	work->data[0] = le32dec(sctx->job.version);
	for (i = 0; i < 8; i++)
		work->data[1 + i] = le32dec((uint32_t *)sctx->job.prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_root + i);
	work->data[17] = le32dec(sctx->job.ntime);
	work->data[18] = le32dec(sctx->job.nbits);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;
	
	work->target = g_curr_target;
	work->work_id = &g_curr_work_id;
	
	free(coinbase);
}

static bool stratum_handle_response(char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	bool ret = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");
	
	if (!id_val || json_is_null(id_val))
	{
		applog(LOG_INFO, "Unrecognized JSON response: %s", buf);
		goto out;
	}

	int res_id = (int) json_integer_value(id_val);
	share_result(json_is_true(res_val),
		err_val ? json_string_value(json_array_get(err_val, 1)) : NULL, res_id & 0xff, res_id >> 8);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	char *s;
	int i;
	struct timeval timestr;
	int restarted;
	
	stratum.url = tq_pop(mythr->q, NULL);
	if (!stratum.url)
		goto out;
	applog(LOG_INFO, "Starting Stratum on %s", stratum.url);
	
	g_works = malloc(opt_n_threads * sizeof(struct work));
	for(i = 0; i < opt_n_threads; i++)
	{
		memset(g_works[i].xnonce2, 0, 4);
		g_works[i].thr_id = i;
	}
	
	while (1) {
		int failures = 0;

		while (!stratum.curl) {
			pthread_mutex_lock(&g_work_lock);
			g_work_time = 0;
			pthread_mutex_unlock(&g_work_lock);
			restart_threads();

			if (!stratum_connect(&stratum, stratum.url) ||
			    !stratum_subscribe(&stratum) ||
			    !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
				stratum_disconnect(&stratum);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					applog(LOG_ERR, "...terminating workio thread");
					tq_push(thr_info[work_thr_id].q, NULL);
					goto out;
				}
				applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}
		}

		restarted = 0;
		if (stratum.job.job_id &&
		    (strcmp(stratum.job.job_id, g_curr_job_id) || !g_work_time)) {
			applog(LOG_INFO, "New job_id: %s Diff: %d", stratum.job.job_id, (int) (stratum.job.diff));
			if (stratum.job.clean)
			{
				applog(LOG_INFO, "Stratum detected new block");
			}
			restart_threads();
			pthread_mutex_lock(&g_work_lock);
			strcpy(g_prev_job_id, g_curr_job_id);
			for(i = 0; i < 8; i++) g_prev_target[i] = g_curr_target[i];
			g_prev_work_id = g_curr_work_id;
			for(i = 0; i < opt_n_threads; i++)
			{
				g_works[i].job_id = g_prev_job_id;
				g_works[i].target = g_prev_target;
				g_works[i].work_id = &g_prev_work_id;
			}
			gettimeofday(&timestr, NULL);
			g_curr_work_id = (timestr.tv_sec & 0xffff) << 16 | timestr.tv_usec & 0xffff;
			pthread_mutex_lock(&stratum.work_lock);
			strcpy(g_curr_job_id, stratum.job.job_id);
			diff_to_target(g_curr_target, stratum.job.diff / 65536.0);
			applog(LOG_INFO, "Dispatching new work to GC3355 threads (0x%x)", g_curr_work_id);
			for(i = 0; i < opt_n_threads; i++)
			{
				stratum_gen_work(&stratum, &g_works[i]);
			}
			pthread_mutex_unlock(&stratum.work_lock);
			time(&g_work_time);
			restarted = 1;
			pthread_mutex_unlock(&g_work_lock);
		}
		
		if (!stratum_socket_full(&stratum, 120)) {
			applog(LOG_ERR, "Stratum connection timed out");
			s = NULL;
		} else
			s = stratum_recv_line(&stratum);
		if (!s) {
			stratum_disconnect(&stratum);
			applog(LOG_ERR, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(&stratum, s))
			stratum_handle_response(s);
		else if(!restarted)
		{
			if(stratum.job.diff != stratum.next_diff && stratum.next_diff > 0)
			{
				applog(LOG_INFO, "Stratum difficulty changed");
				restart_threads();
				pthread_mutex_lock(&g_work_lock);
				for(i = 0; i < 8; i++) g_prev_target[i] = g_curr_target[i];
				for(i = 0; i < opt_n_threads; i++)
				{
					g_works[i].target = g_prev_target;
				}
				pthread_mutex_unlock(&stratum.work_lock);
				stratum.job.diff = stratum.next_diff;
				diff_to_target(g_curr_target, stratum.job.diff / 65536.0);
				applog(LOG_INFO, "Dispatching new work to GC3355 threads");
				for(i = 0; i < opt_n_threads; i++)
				{
					stratum_gen_work(&stratum, &g_works[i]);
				}
				pthread_mutex_unlock(&stratum.work_lock);
				pthread_mutex_unlock(&g_work_lock);
			}
		}
		free(s);
	}
	
	free(g_works);

out:
	return NULL;
}

#ifndef WIN32
static void api_request_handler(int sock)
{
    int i, j, read_size, read_pos, buffer_size = 256, err_size = 256;
    char request[buffer_size], *message, *pos, err_msg[err_size];
	const char *api_get;
	json_t *req, *get, *obj, *dev, *devs, *chips, *chip, *err;
	json_error_t json_err;
read:
	memset(err_msg, 0, err_size);
	memset(request, 0, buffer_size);
	read_pos = 0;
    while((read_size = recv(sock, request + read_pos, buffer_size - read_pos, 0)) > 0)
    {
		read_pos += read_size;
		if(read_pos >= buffer_size) goto read;
		if((pos = strchr(request, '\n')) == NULL) continue;
		while((pos = strchr(request, '\r')) != NULL || (pos = strchr(request, '\n')) != NULL)
			*pos = '\0';
		obj = json_object();
		req = JSON_LOADS(request, &json_err);
		if (!req)
		{
			snprintf(err_msg, err_size, "API: JSON decode failed(%d): %s (%s)", json_err.line, json_err.text, request);
			goto err;
		}
		get = json_object_get(req, "get");
		if (!get || !json_is_string(get))
		{
			snprintf(err_msg, err_size, "API: Unrecognized JSON response: %s", request);
			goto err;
		}
		api_get = json_string_value(get);
		if(!strcmp(api_get, API_STATS))
		{
			json_object_set_new(obj, API_MINER_START_TIME, json_integer(gc3355_time_start));
			err = json_integer(0);
			devs = json_object();
			pthread_mutex_lock(&stats_lock);
			for(i = 0; i < opt_n_threads; i++)
			{
				dev = json_object();
				chips = json_array();
				for(j = 0; j < gc3355_devs[i].chips; j++)
				{
					chip = json_object();
					json_object_set_new(chip, API_CHIP_ACCEPTED, json_integer(gc3355_devs[i].accepted[j]));
					json_object_set_new(chip, API_CHIP_REJECTED, json_integer(gc3355_devs[i].rejected[j]));
					json_object_set_new(chip, API_CHIP_HW_ERRORS, json_integer(gc3355_devs[i].total_hwe[j]));
					json_object_set_new(chip, API_CHIP_FREQUENCY, json_integer(gc3355_devs[i].freq[j]));
					json_object_set_new(chip, API_CHIP_HASHRATE, json_integer(gc3355_devs[i].hashrate[j]));
					json_object_set_new(chip, API_CHIP_SHARES, json_integer(gc3355_devs[i].shares[j]));
					json_object_set_new(chip, API_LAST_SHARE, json_integer(gc3355_devs[i].last_share[j]));
					json_array_append_new(chips, chip);
				}
				json_object_set_new(dev, API_CHIPS, chips);
				char *path = gc3355_devs[i].devname;
				char *base = strrchr(path, '/');
				json_object_set_new(devs, base ? base + 1 : path, dev);
			}
			pthread_mutex_unlock(&stats_lock);
			json_object_set_new(obj, API_DEVICES, devs);
		}
		else
		{
			snprintf(err_msg, err_size, "API: Unrecognized Command: %s", api_get);
			goto err;
		}
		applog(LOG_INFO, "API: Command: %s", api_get);
		goto write;
    }
	close(sock);
    return;
err:
	applog(LOG_ERR, "%s", err_msg);
	err = json_integer(1);
	json_object_set_new(obj, "errstr", json_string(err_msg));
write:
	if(req)
		json_decref(req);
	json_object_set_new(obj, "err", err);
	message = json_dumps(obj, JSON_COMPACT);
	json_decref(obj);
	write(sock, message, strlen(message));
	free(message);
	goto read;
}
#endif

#ifndef WIN32
static void *api_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
    int new_socket, c, yes;
    struct sockaddr_in server, client;
	char client_ip[INET_ADDRSTRLEN];
    api_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (api_sock == -1)
    {
        applog(LOG_ERR, "Could not create socket");
		goto out;
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(opt_api_port);
	yes = 1;
	if(setsockopt(api_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
	{
        applog(LOG_ERR, "API: Sockopt failed");
		goto out;
	}
    if(bind(api_sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        applog(LOG_ERR, "API: Bind failed");
		goto out;
    }
    listen(api_sock, API_QUEUE);
    c = sizeof(struct sockaddr_in);
    while((new_socket = accept(api_sock, (struct sockaddr *)&client, (socklen_t*)&c)))
    {
		inet_ntop(AF_INET, &(client.sin_addr.s_addr), client_ip, INET_ADDRSTRLEN);
		//applog(LOG_INFO, "API: Client %s connected", client_ip);
		api_request_handler(new_socket);
		usleep(100000);
    }
    if (new_socket < 0)
    {
		applog(LOG_ERR, "API: Accept failed");
		goto out;
    }
out:
	if(api_sock != -1)
	{
		close(api_sock);
	}
	return NULL;
}
#endif

static void show_version_and_exit(void)
{
	printf("%s\n%s\n%s\n", PACKAGE_STRING, curl_version(), GC3355_VERSION);
	exit(0);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

static void parse_arg (int key, char *arg)
{
	char *p;
	int v, i;

	switch(key) {
	case 'G':
		gc3355_devname = strdup(arg);
		break;
	case 'F':
		opt_frequency = atoi(arg);
		break;
	case 'f':
		opt_gc3355_frequency = strdup(arg);
		break;
	case 'A':
		opt_gc3355_autotune = 0x1;
		break;
	case 'c':
		opt_gc3355_chips = atoi(arg);
		break;
	case 'a':
		opt_api_port = atoi(arg);
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999)	/* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o':			/* --url */
		p = strstr(arg, "://");
		if (p) {
			if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
					strncasecmp(arg, "stratum+tcp://", 14))
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = strdup(arg);
		} else {
			if (!strlen(arg) || *arg == '/')
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = malloc(strlen(arg) + 8);
			sprintf(rpc_url, "http://%s", arg);
		}
		p = strrchr(rpc_url, '@');
		if (p) {
			char *sp, *ap;
			*p = '\0';
			ap = strstr(rpc_url, "://") + 3;
			sp = strchr(ap, ':');
			if (sp) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = calloc(sp - ap + 1, 1);
				strncpy(rpc_user, ap, sp - ap);
				free(rpc_pass);
				rpc_pass = strdup(sp + 1);
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			memmove(ap, p + 1, strlen(p + 1) + 1);
		}
		have_stratum = !strncasecmp(rpc_url, "stratum", 7);
		break;
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p)
			show_usage_and_exit(1);
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(p + 1);
		break;
	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument '%s'\n",
			argv[0], argv[optind]);
		show_usage_and_exit(1);
	}
}

static void clean_up()
{
	close(api_sock);
	int i;
	for(i = 0; i < opt_n_threads; i++)
	{
		gc3355_close(gc3355_devs[i].dev_fd);	
	}
}

#ifndef WIN32
void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		clean_up();
		applog(LOG_INFO, "SIGINT received, exiting");
		exit(0);
		break;
	case SIGTERM:
		clean_up();
		applog(LOG_INFO, "SIGTERM received, exiting");
		exit(0);
		break;
	}
}
#endif

int main(int argc, char *argv[])
{
	struct thr_info *thr;
	long flags;
	int i;

	rpc_url = strdup(DEF_RPC_URL);
	rpc_user = strdup("");
	rpc_pass = strdup("");

	/* parse command line */
	parse_cmdline(argc, argv);

	pthread_mutex_init(&applog_lock, NULL);
	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

#ifndef WIN32
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#endif
	
	flags = strncmp(rpc_url, "https:", 6)
	      ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	      : CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}
	
	opt_n_threads = 1;

	if (gc3355_devname != NULL) {
		char *p = gc3355_devname;
		int nn=0;
		do {
			p = strchr(p+1, ',');
			nn++;
		} while(p!=NULL);
		opt_n_threads = nn;
	}
	
	struct gc3355_dev devs[opt_n_threads];
	memset(&devs, 0, sizeof(devs));
	gc3355_devs = devs;

	if (!rpc_userpass) {
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = calloc(opt_n_threads + 4, sizeof(*thr));
	if (!thr_info)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}
	
	if (want_stratum) {
		/* init stratum thread info */
		stratum_thr_id = opt_n_threads + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start stratum thread */
		if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr))) {
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}

		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}
	/* start mining threads */
	if (gc3355_devname != NULL) {
		if (create_gc3355_miner_threads(thr_info, opt_n_threads) != 0)
			return 1;
	
#ifndef WIN32
		/* init api thread info */
		api_thr_id = opt_n_threads + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		/* start api thread */
		if (unlikely(pthread_create(&thr->pth, NULL, api_thread, thr))) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
#endif
	}

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);
	applog(LOG_INFO, "workio thread dead, exiting.");
	
	clean_up();
	
	return 0;
}