/*
 * Driver for GC3355 chip to mine Litecoin, power by GridChip & GridSeed
 *
 * Copyright 2013 faster <develop@gridseed.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <termios.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#define GC3355_MINER_VERSION	"v2.3.2.20140115.01"
#define GC3355_VERSION			"LightningAsic Custom"

static const char *gc3355_version = GC3355_MINER_VERSION;
static char *dev_freq = NULL;

#define GRIDSEED_LTC_PROXY_PORT	4350

struct gc3355_dev {
	int		id;
	int		dev_fd;
	// Runtime
	bool	resend;
	// Stats
	char* devname;
	char* freq;
};

static char **str_frequency;
static char **cmd_frequency;

/* commands for single LTC mode */
static const char *single_cmd_init[] = {
	"55AAC000808080800000000001000000"
	"55AAC000C0C0C0C00500000001000000",
	"55AAEF020000000000000000000000000000000000000000",
	"55AAEF3020000000",
	NULL
};

static const char *single_cmd_reset[] = {
	"55AA1F2816000000",
	"55AA1F2817000000",
	NULL
};

static const char *cmd_chipbaud[] = {
	"55AAC000B0B0B0B040420F0001000000",
	NULL
}; 

/* external functions */
extern void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output,
    uint32_t *midstate, unsigned char *scratchpad);

/* local functions */
static int gc3355_scanhash(struct gc3355_dev *gc3355, uint32_t *pdata, unsigned char *scratchbuf, const uint32_t *ptarget);

/* close UART device */
static void gc3355_close(int fd)
{
	if (fd > 0)
		close(fd);
	return;
}

/* open UART device */
static int gc3355_open(struct gc3355_dev *gc3355, const char *devname, speed_t baud)
{
	struct termios	my_termios;
	int fd;
	applog(LOG_INFO, "%d: open device %s", gc3355->id, devname);
	if (gc3355->dev_fd > 0)
		gc3355_close(gc3355->dev_fd);

    fd = open(devname, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd < 0) {
		if (errno == EACCES)
			applog(LOG_ERR, "%d: Do not have user privileges to open %s", gc3355->id, devname);
		else
			applog(LOG_ERR, "%d: failed open device %s", gc3355->id, devname);
		return 1;
	}
	
	gc3355->devname = strdup(devname);

	tcgetattr(fd, &my_termios);
	cfsetispeed(&my_termios, baud);
	cfsetospeed(&my_termios, baud);
	cfsetspeed(&my_termios,  baud);
	
	my_termios.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
	my_termios.c_cflag |= CS8;
	my_termios.c_cflag |= CREAD;
	my_termios.c_cflag |= CLOCAL;

	my_termios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK |
			ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	my_termios.c_oflag &= ~OPOST;
	my_termios.c_lflag &= ~(ECHO | ECHOE | ECHONL | ICANON | ISIG | IEXTEN);

	// Code must specify a valid timeout value (0 means don't timeout)
	my_termios.c_cc[VTIME] = (cc_t)1;
	my_termios.c_cc[VMIN] = 0;
	
	tcsetattr(fd, TCSANOW, &my_termios);
	tcflush(fd, TCIOFLUSH);
	gc3355->dev_fd = fd;

	return 0;
}

/* send data to UART */
static int gc3355_write(struct gc3355_dev *gc3355, const void *buf, size_t buflen)
{
	size_t ret;
	int i;
	unsigned char *p;

	if (false) {
		p = (unsigned char *)buf;
		printf("[1;33m%d: >>> LTC :[0m ", gc3355->id);
		for(i=0; i<buflen; i++)
			printf("%02x", *(p++));
		printf("\n");
	}

	ret = write(gc3355->dev_fd, buf, buflen);
	if (ret != buflen)
	{
		applog(LOG_INFO, "%d: UART write error", gc3355->id);
		return 1;
	}
	return 0;
}

/* read data from UART */
static int gc3355_gets(struct gc3355_dev *gc3355, unsigned char *buf, int read_amount)
{
	int				fd;
	unsigned char	*bufhead, *p;
	fd_set			rdfs;
	struct timeval	tv;
	ssize_t			nread;
	int				n;

	fd = gc3355->dev_fd;
	memset(buf, 0, read_amount);
	tv.tv_sec  = 0;
	tv.tv_usec = 100000;
	FD_ZERO(&rdfs);
	FD_SET(fd, &rdfs);
	n = select(fd+1, &rdfs, NULL, NULL, &tv);
	if (n < 0)
	{
		return 1;
	}
	else if (n == 0)
	{
		return 0;
	}
	nread = read(fd, buf, read_amount);
	if (nread != read_amount)
	{
		return 1;
	}
	return 0;
}

static void gc3355_send_cmds(struct gc3355_dev *gc3355, const char *cmds[])
{
	unsigned char	ob[160];
	int				i;

	for(i=0; ; i++) {
		if (cmds[i] == NULL)
			break;
		memset(ob, 0, sizeof(ob));
		hex2bin(ob, cmds[i], sizeof(ob));
		gc3355_write(gc3355, ob, strlen(cmds[i])/2);
		usleep(10000);
	}
	return;
}

static void gc3355_set_core_freq(struct gc3355_dev *gc3355, const char *freq)
{
	int		i, inx=5;
	char	*p;
	char	*cmds[2];

	if (freq != NULL) {
		for(i=0; ;i++) {
			if (str_frequency[i] == NULL)
				break;
			if (strcmp(freq, str_frequency[i]) == 0)
				inx = i;
		}
	}

	cmds[0] = (char *)cmd_frequency[inx];
	cmds[1] = NULL;
	gc3355_send_cmds(gc3355, (const char **)cmds);
	applog(LOG_INFO, "%d: Set GC3355 core frequency to %sMhz", gc3355->id, str_frequency[inx]);
	return;
}

/*
 * miner thread
 */
static void *gc3355_thread(void *userdata)
{
	struct thr_info	*mythr = userdata;
	int thr_id = mythr->id;
	struct gc3355_dev gc3355;
	struct work work;
	unsigned char *scratchbuf = NULL;
	int i;
	
	gc3355.id = thr_id;
	gc3355.dev_fd = -1;
	gc3355.resend = true;
	gc3355.freq = dev_freq;

	scratchbuf = scrypt_buffer_alloc();

	applog(LOG_INFO, "%d: GC3355 chip mining thread started, in SINGLE mode", thr_id);
	if (gc3355_open(&gc3355, mythr->devname, B115200))
		return NULL;
	applog(LOG_INFO, "%d: Open UART device %s", thr_id, mythr->devname);

	gc3355_send_cmds(&gc3355, single_cmd_init);
	gc3355_set_core_freq(&gc3355, gc3355.freq == NULL ? opt_frequency : gc3355.freq);
	
	int rc = 0;
	while(1)
	{
		if (have_stratum)
		{
			while (g_works[thr_id].job_id == NULL || time(NULL) >= g_work_time + 120)
			usleep(10000);
		}

		if (work_restart[thr_id].restart || memcmp(work.data, g_works[thr_id].data, 76))
		{
			pthread_mutex_lock(&g_work_lock);
			memcpy(&work, &g_works[thr_id], sizeof(struct work));
			pthread_mutex_unlock(&g_work_lock);
			gc3355.resend = true;
		}
		else
		{
			gc3355.resend = false;
		}
		work_restart[thr_id].restart = 0;
		
		rc = gc3355_scanhash(&gc3355, work.data, scratchbuf, work.target);
		if(rc == -1)
		{
			continue;
		}
		if (rc && !submit_work(mythr, &work))
			break;
	}

out_gc3355:
	tq_freeze(mythr->q);
	gc3355_close(gc3355.dev_fd);
	return NULL;
}

/* scan hash in GC3355 chips */
static int gc3355_scanhash(struct gc3355_dev *gc3355, uint32_t *pdata, unsigned char *scratchbuf, const uint32_t *ptarget)
{
	int ret, i;
	unsigned char *ph;
	int thr_id = gc3355->id;
	unsigned char rptbuf[12];
	uint32_t data[20], nonce, hash[8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	
	memcpy(data, pdata, 80);
	sha256_init(midstate);
	sha256_transform(midstate, data, 0);
		
	if (gc3355->resend) {
		applog(LOG_INFO, "%d: Dispatching new work to GC3355 LTC core", gc3355->id);
		unsigned char bin[156];
		// swab for big endian
		uint32_t midstate2[8];
		uint32_t data2[20];
		uint32_t target2[8];
		for (i = 0; i < 20; i++)
			data2[i] = swab32(pdata[i]);
		for (i = 0; i < 8; i++)
			target2[i] = swab32(ptarget[i]);
		for (i = 0; i < 8; i++)
			midstate2[i] = swab32(midstate[i]);
		data2[19] = 0;
		memset(bin, 0, sizeof(bin));
		memcpy(bin, "\x55\xaa\x1f\x00", 4);
		memcpy(bin+4, (unsigned char *)target2, 32);
		memcpy(bin+36, (unsigned char *)midstate2, 32);
		memcpy(bin+68, (unsigned char *)data2, 80);
		memcpy(bin+148, "\xff\xff\xff\xff", 4);
		memcpy(bin+152, "\x12\x34\x56\x78", 4);
		gc3355_send_cmds(gc3355, single_cmd_reset);
		gc3355_write(gc3355, bin, 156);
		gc3355->resend = false;
	}

	while((ret = gc3355_gets(gc3355, (unsigned char *)rptbuf, 12)) == 0 && !work_restart[thr_id].restart)
	{
		if (rptbuf[0] == 0x55 && rptbuf[1] == 0x20)
		{
			// swab for big endian
			memcpy((unsigned char *)&nonce, rptbuf+4, 4);
			nonce = swab32(nonce);
			memcpy(pdata+19, &nonce, sizeof(nonce));
			data[19] = nonce;
			scrypt_1024_1_1_256(data, hash, midstate, scratchbuf);
			
			unsigned char bin[32];
			if(opt_debug)
			{
				ph = (unsigned char *)ptarget;
				for(i=31; i>=16; i -= 4)
				{
					sprintf(bin+(31-i)*2, "%08x", swab32((uint32_t)(*(ph+i)) << 24 |
						(uint32_t)(*(ph+i-1)) << 16 |
						(uint32_t)(*(ph+i-2)) << 8  |
						(uint32_t)(*(ph+i-3)))
					);
				}
				applog(LOG_INFO, "%d: Target:\t%s", gc3355->id, bin);
				
				ph = (unsigned char *)hash;
				for(i=31; i>=16; i -= 4)
				{
					sprintf(bin+(31-i)*2, "%08x", swab32((uint32_t)(*(ph+i)) << 24 |
						(uint32_t)(*(ph+i-1)) << 16 |
						(uint32_t)(*(ph+i-2)) << 8  |
						(uint32_t)(*(ph+i-3)))
					);
				}
				applog(LOG_INFO, "%d: Hash:\t%s", gc3355->id, bin);
			}
			
			ph = (unsigned char *)&nonce;
			for(i=0; i<4; i++)
				sprintf(bin+i*2, "%02x", *(ph++));

			int stop = 1;
			if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
				applog(LOG_INFO, "%d: Got nonce %s, [1;32mHash <= Htarget![0m", gc3355->id, bin);
			} else {
				if(work_restart[thr_id].restart) break;
				applog(LOG_INFO, "%d: Got nonce %s, [1;31mInvalid nonce![0m", gc3355->id, bin);
				stop = -1;
				struct timeval timestr;
				char path[28];
				gettimeofday(&timestr, NULL);
				sprintf(path, "%s%llu", "/tmp/ltc/", ((unsigned long long)timestr.tv_sec * 1000000) + timestr.tv_usec);
				int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
				size_t needed = snprintf(NULL, 0, "%s|%c|%d", gc3355->devname, 'H', 0);
				char *buffer = malloc(needed);
				sprintf(buffer, "%s|%c|%d", gc3355->devname, 'H', 0);
				write(fd, buffer, needed);
				close(fd);
				free(buffer);
			}
			return stop;
		}
	}
	return 0;
}

/*
 * create miner thread
 */
static int create_gc3355_miner_threads(struct thr_info *thr_info, int opt_n_threads)
{
	struct thr_info *thr;
	unsigned char *pd, *p;
	int i, j, k;
	
	mkdir("/tmp/ltc", S_IRWXU | S_IRWXG | S_IRWXO);
	
	char *di[opt_n_threads];
	char *df[opt_n_threads];
	
	i = 0;
	if(opt_gc3355_frequency != NULL)
	{
		char *end;
		char *freq = strtok_r(opt_gc3355_frequency, ",", &end);
		while(freq != NULL)
		{
			char *end2;
			char *tmp;
			tmp = strtok_r(freq, ":", &end2);
			di[i] = strdup(tmp);
			tmp = strtok_r(NULL, ":", &end2);
			df[i] = strdup(tmp);
			freq = strtok_r(NULL, ",", &end);
			i++;
		}
	}
	k = i;
	
	pd = gc3355_dev;
	/* start GC3355 chip mining thread */
	for (i=0; i<opt_n_threads; i++) {
		thr = &thr_info[i];
		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		p = strchr(pd, ',');
		if (p != NULL)
			*p = '\0';
		thr->devname = strdup(pd);
		dev_freq = NULL;
		for(j = 0; j < k; j++)
		{
			if(strcmp(thr->devname, di[j]) == 0)
			{
				dev_freq = strdup(df[j]);
				break;
			}
		}
		pd = p + 1;

		if (unlikely(pthread_create(&thr->pth, NULL, gc3355_thread, thr))) {
			applog(LOG_ERR, "%d: GC3355 chip mining thread create failed", thr->id);
			return 1;
		}
		usleep(100000);
	}
	return 0;
}
