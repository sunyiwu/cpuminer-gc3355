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
#include <gc3355-commands.h>

#define GC3355_MINER_VERSION	"v3e"
#define GC3355_VERSION			"LightningAsic"

static const char *gc3355_version = GC3355_MINER_VERSION;
static char can_start = 0x0;

#define GC3355_OVERCLOCK_MAX_HWE 5
#define GC3355_OVERCLOCK_ADJUST_STEPS 3845
#define GC3355_OVERCLOCK_FREQ_STEP 25
#define GC3355_MIN_FREQ 600
#define GC3355_MAX_FREQ 1400
#define GC3355_HASH_SPEED 84.705882
#define GC3355_TRESHOLD 0.98

/* external functions */
extern void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output,
    uint32_t *midstate, unsigned char *scratchpad);

/* local functions */
static int gc3355_scanhash(struct gc3355_dev *gc3355, uint32_t *pdata, unsigned char *scratchbuf, const uint32_t *ptarget, uint32_t *midstate);

/* close UART device */
static void gc3355_close(int fd)
{
	if (fd > 0)
		close(fd);
	return;
}

static void gc3355_exit(struct gc3355_dev *gc3355)
{
	applog(LOG_INFO, "%d: Terminating GC3355 chip mining thread", gc3355->id);
	gc3355_close(gc3355->dev_fd);
	pthread_exit(NULL);
}

/* open UART device */
static int gc3355_open(struct gc3355_dev *gc3355, speed_t baud)
{
	struct termios	my_termios;
	int i, fd;

	applog(LOG_INFO, "%d: open device %s", gc3355->id, gc3355->devname);
	if (gc3355->dev_fd > 0)
		gc3355_close(gc3355->dev_fd);

    fd = open(gc3355->devname, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd < 0) {
		if (errno == EACCES)
			applog(LOG_ERR, "%d: Do not have user privileges to open %s", gc3355->id, gc3355->devname);
		else
			applog(LOG_ERR, "%d: failed open device %s", gc3355->id, gc3355->devname);
		return 1;
	}

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
	size_t ret = write(gc3355->dev_fd, buf, buflen);
	usleep(10000);
	if (ret != buflen)
	{
		applog(LOG_INFO, "%d: UART write error", gc3355->id);
		gc3355_exit(gc3355);
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

static void gc3355_send_cmds(struct gc3355_dev *gc3355, const unsigned char *cmds[])
{
	int i;
	for(i = 0; cmds[i] != NULL; i++)
	{
		gc3355_write(gc3355, cmds[i] + 1, cmds[i][0]);
	}
}

static void gc3355_set_core_freq(struct gc3355_dev *gc3355, int chip_id, unsigned short freq)
{
	const uint16_t x = ((freq / 25) * 0x20) + 0x7fe0;
	unsigned char cmds[] = {0x55, 0xaa, 0xe0 + chip_id, 0, 0x05, 0, x & 0xff, x >> 8};
	gc3355_write(gc3355, cmds, 8);
	gc3355->freq[chip_id] = freq - freq % 25;
	applog(LOG_INFO, "%d@%d: Set GC3355 core frequency to %dMhz", gc3355->id, chip_id, gc3355->freq[chip_id]);
}

static unsigned short next_freq(struct gc3355_dev *gc3355, int chip_id)
{
	return gc3355->freq[chip_id] <= gc3355->adjust[chip_id] - GC3355_OVERCLOCK_FREQ_STEP ? gc3355->freq[chip_id] + GC3355_OVERCLOCK_FREQ_STEP : gc3355->freq[chip_id];
}

static unsigned short prev_freq(struct gc3355_dev *gc3355, int chip_id)
{
	return gc3355->freq[chip_id] - GC3355_OVERCLOCK_FREQ_STEP >= GC3355_MIN_FREQ ? gc3355->freq[chip_id] - GC3355_OVERCLOCK_FREQ_STEP : gc3355->freq[chip_id];
}

/*
 * miner thread
 */
static void *gc3355_thread(void *userdata)
{
	struct thr_info	*mythr = userdata;
	int thr_id = mythr->id;
	struct gc3355_dev *gc3355;
	struct work work;
	unsigned char *scratchbuf = NULL;
	int i;

	struct timeval timestr;
	gettimeofday(&timestr, NULL);
	gc3355 = &gc3355_devs[thr_id];
	for(i = 0; i < GC3355_CHIPS; i++)
	{
		gc3355->adjust[i] = GC3355_MAX_FREQ;
		gc3355->last_share[i] = timestr.tv_sec;
	}
	gc3355->id = thr_id;
	gc3355->dev_fd = -1;
	gc3355->resend = true;
	
	scratchbuf = scrypt_buffer_alloc();

	applog(LOG_INFO, "%d: GC3355 chip mining thread started, in SINGLE mode", thr_id);
	if (gc3355_open(gc3355, B115200))
	{
		can_start++;
		gc3355_exit(gc3355);
	}
	applog(LOG_INFO, "%d: Open UART device %s", thr_id, gc3355->devname);
	
	gc3355_send_cmds(gc3355, single_cmd_init);
	for(i = 0; i < GC3355_CHIPS; i++)
	{
		gc3355_set_core_freq(gc3355, i, gc3355->freq[i]);
	}
	
	int rc = 0;
	uint32_t midstate[8];
	can_start++;
	while(1)
	{
		if (have_stratum)
		{
			while (can_start < opt_n_threads || !can_work || g_works[thr_id].job_id == NULL || time(NULL) >= g_work_time + 120)
			usleep(100000);
		}
		if (work_restart[thr_id].restart || memcmp(work.data, g_works[thr_id].data, 76))
		{
			pthread_mutex_lock(&g_work_lock);
			memcpy(&work, &g_works[thr_id], sizeof(struct work));
			pthread_mutex_unlock(&g_work_lock);
			sha256_init(midstate);
			sha256_transform(midstate, work.data, 0);
			gc3355->resend = true;
		}
		else
		{
			gc3355->resend = false;
		}
		work_restart[thr_id].restart = 0;
		
		rc = gc3355_scanhash(gc3355, work.data, scratchbuf, work.target, midstate);
		if(rc == -1)
		{
			continue;
		}
		if (rc && !submit_work(mythr, &work))
			break;
	}
	gc3355_exit(gc3355);
}

/* scan hash in GC3355 chips */
static int gc3355_scanhash(struct gc3355_dev *gc3355, uint32_t *pdata, unsigned char *scratchbuf, const uint32_t *ptarget, uint32_t *midstate)
{
	int ret, i;
	unsigned char *ph;
	int thr_id = gc3355->id;
	unsigned char rptbuf[12];
	struct timeval timestr;
	double time_now;
	
	if (gc3355->resend)
	{
		unsigned char bin[156];
		// swab for big endian
		uint32_t midstate2[8];
		uint32_t data2[20];
		uint32_t target2[8];
		for(i = 0; i < 19; i++)
		{
			data2[i] = htole32(pdata[i]);
			if(i >= 8) continue;
			target2[i] = htole32(ptarget[i]);
			midstate2[i] = htole32(midstate[i]);
		}
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
		gettimeofday(&timestr, NULL);
		time_now = timestr.tv_sec + timestr.tv_usec / 1000000.0;
		for(i = 0; i < GC3355_CHIPS; i++)
		{
			gc3355->time_now[i] = time_now;
			gc3355->last_nonce[i] = i * (0xffffffff / GC3355_CHIPS);
		}
		// clear buffer
		gc3355_gets(gc3355, (unsigned char *)rptbuf, 12);
	}
	
	while((ret = gc3355_gets(gc3355, (unsigned char *)rptbuf, 12)) == 0 && !work_restart[thr_id].restart)
	{
		if (!memcmp(rptbuf, "\x55\x20\x00\x00", 4))
		{
			uint32_t nonce, hash[8];
			const uint32_t Htarg = ptarget[7];
			unsigned char bin[32];
			int stop, chip_id;
			unsigned short freq;
			unsigned int add_hashes = 0;
			unsigned char add_hwe = 0;
			
			// swab for big endian
			memcpy((unsigned char *)&nonce, rptbuf+4, 4);
			nonce = htole32(nonce);
			memcpy(pdata+19, &nonce, sizeof(nonce));
			scrypt_1024_1_1_256(pdata, hash, midstate, scratchbuf);
			ph = (unsigned char *)&nonce;
			for(i=0; i<4; i++)
				sprintf(bin+i*2, "%02x", *(ph++));
				
			stop = 1;
			chip_id = nonce / (0xffffffff / GC3355_CHIPS);
			if(work_restart[thr_id].restart || !can_work)
			{
				gc3355->last_nonce[chip_id] = nonce;
				break;
			}
			gettimeofday(&timestr, NULL);
			time_now = timestr.tv_sec + timestr.tv_usec / 1000000.0;
			freq = gc3355->freq[chip_id];
			if (hash[7] <= Htarg && fulltest(hash, ptarget))
			{
				add_hashes = nonce - gc3355->last_nonce[chip_id];
				applog(LOG_INFO, "%d@%d %dMHz: Got nonce %s, [1;34mHash <= Htarget![0m", gc3355->id, chip_id, freq, bin);
			}
			else
			{
				add_hwe = 1;
				stop = -1;
				applog(LOG_INFO, "%d@%d %dMHz: Got nonce %s, [1;35mInvalid nonce! (%d)[0m", gc3355->id, chip_id, freq, bin, gc3355->hwe[chip_id] + 1);
			}
			pthread_mutex_lock(&stats_lock);
			gc3355->hashes[chip_id] += add_hashes;
			gc3355->total_hwe[chip_id] += add_hwe;
			gc3355->hwe[chip_id] += add_hwe;
			gc3355->time_spent[chip_id] += time_now - gc3355->time_now[chip_id];
			gc3355->hashrate[chip_id] = gc3355->hashes[chip_id] / gc3355->time_spent[chip_id];
			if(!add_hwe)
				gc3355->last_nonce[chip_id] = nonce;
			else
				gc3355->last_nonce[chip_id] = chip_id * (0xffffffff / GC3355_CHIPS);
			gc3355->time_now[chip_id] = time_now;
			if(opt_gc3355_autotune && gc3355->adjust[chip_id])
			{
				gc3355->steps[chip_id] += stratum.job.diff;
				if(gc3355->hwe[chip_id] >= GC3355_OVERCLOCK_MAX_HWE)
				{
					freq = prev_freq(gc3355, chip_id);
					gc3355->adjust[chip_id] = freq;
				}
				else
				{
					if(gc3355->hashrate[chip_id] < GC3355_HASH_SPEED * freq * GC3355_TRESHOLD)
					{
						unsigned short prev_f = prev_freq(gc3355, chip_id);
						if(gc3355->steps[chip_id] >= GC3355_OVERCLOCK_ADJUST_STEPS)
						{
							if(prev_f != freq)
							{
								freq = prev_f;
								gc3355->adjust[chip_id] = freq;
							}
							else
							{
								gc3355->hashes[chip_id] = 0;
								gc3355->time_spent[chip_id] = 0;
								gc3355->hwe[chip_id] = 0;
								gc3355->steps[chip_id] = 0;
								applog(LOG_INFO, "%d@%d: restart step counter", gc3355->id, chip_id);
							}
						}
						else
							applog(LOG_INFO, "%d@%d: %d steps until frequency adjusts to %dMHz", gc3355->id, chip_id, GC3355_OVERCLOCK_ADJUST_STEPS - gc3355->steps[chip_id], prev_f);
					}
					else
					{
						unsigned short next_f = next_freq(gc3355, chip_id);
						if(gc3355->steps[chip_id] >= GC3355_OVERCLOCK_ADJUST_STEPS)
						{
							if(next_f != freq)
								freq = next_f;
							else
							{
								gc3355->hashes[chip_id] = 0;
								gc3355->time_spent[chip_id] = 0;
								gc3355->hwe[chip_id] = 0;
								gc3355->steps[chip_id] = 0;
								applog(LOG_INFO, "%d@%d: restart step counter", gc3355->id, chip_id);
							}
						}
						else
						{
							if(next_f != freq)
								applog(LOG_INFO, "%d@%d: %d steps until frequency adjusts to %dMHz", gc3355->id, chip_id, GC3355_OVERCLOCK_ADJUST_STEPS - gc3355->steps[chip_id], next_f);
							else
								applog(LOG_INFO, "%d@%d: %d steps until step counter restarts", gc3355->id, chip_id, GC3355_OVERCLOCK_ADJUST_STEPS - gc3355->steps[chip_id]);
						}
					}
				}
				if(freq != gc3355->freq[chip_id])
				{
					gc3355->hashes[chip_id] = 0;
					gc3355->time_spent[chip_id] = 0;
					gc3355_set_core_freq(gc3355, chip_id, freq);
					gc3355->hwe[chip_id] = 0;
					gc3355->steps[chip_id] = 0;
				}
			}
			pthread_mutex_unlock(&stats_lock);
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
	int i, j, k, l;
	char *p, *pd, *end, *str, *end2, *tmp;
	
	char *di[opt_n_threads];
	char *df[opt_n_threads];
	
	struct timeval timestr;
	gettimeofday(&timestr, NULL);
	gc3355_time_start = timestr.tv_sec;
	
	i = 0;
	if(opt_gc3355_frequency != NULL)
	{
		pd = opt_gc3355_frequency;
		while((str = strtok_r(pd, ",", &end)))
		{
			tmp = strtok_r(str, ":", &end2);
			di[i] = strdup(tmp);
			tmp = strtok_r(NULL, ":", &end2);
			df[i] = strdup(tmp);
			pd = end;
			i++;
		}
	}
	k = i;
	pd = gc3355_devname;
	int freq = 0;
	if(opt_frequency != NULL && strlen(opt_frequency))
	{
		freq = 1;
		str = opt_frequency;
		while(*str)
		{
			if(!isdigit(*str))
			{
				freq = 0;
				break;
			}
			str++;
		}
	}
	freq = freq ? atoi(opt_frequency) : GC3355_MIN_FREQ;
	for (i = 0; i < opt_n_threads; i++)
	{
		thr = &thr_info[i];
		thr->id = i;
		
		p = strchr(pd, ',');
		if(p != NULL)
			*p = '\0';
		gc3355_devs[i].devname = strdup(pd);
		pd = p + 1;

		for(l = 0; l < GC3355_CHIPS; l++)
		{
			gc3355_devs[i].freq[l] = freq;
		}
		for(j = 0; j < k; j++)
		{
			if(!strcmp(gc3355_devs[i].devname, di[j]))
			{
				for(l = 0; l < GC3355_CHIPS; l++)
				{
					gc3355_devs[i].freq[l] = atoi(df[j]);
				}
				break;
			}
		}

		pthread_attr_t attrs;
		pthread_attr_init(&attrs);
		if(unlikely(pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED)))
		{
			applog(LOG_ERR, "%d: Failed to detach GC3355 chip mining thread", thr->id);
			return 1;
		}
		if (unlikely(pthread_create(&thr->pth, &attrs, gc3355_thread, thr)))
		{
			applog(LOG_ERR, "%d: GC3355 chip mining thread create failed", thr->id);
			return 1;
		}
		usleep(100000);
	}
	free(gc3355_devname);
	for(j = 0; j < k; j++)
	{
		free(di[j]);
		free(df[j]);
	}
	return 0;
}