/*************************************************************************
	> File Name: test.c
	> Author: bxq
	> Mail: 544177215@qq.com 
	> Created Time: Saturday, December 12, 2015 PM03:19:12 CST
 ************************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "rtsp_demo.h"

#ifndef __WINDOWS__
#define O_BINARY 0
#endif

#include <signal.h>
static int flag_run = 1;
static void sig_proc(int signo)
{
	flag_run = 0;
}

static int get_next_video_frame (int fd, uint8_t **buff, int *size)
{
	static uint8_t szbuf[1024];
	static int szlen = 0;
	int ret;
	if (!(*buff)) {
		*buff = malloc(2*1024*1024);
		if (!(*buff))
			return -1;
	}

	*size = 0;

	if (szlen >= 4) {
		memcpy(*buff, szbuf, 4);
		*size += 4;
		memmove(szbuf, szbuf + 4, szlen - 4);
		szlen -= 4;
	}

	while ((ret = read(fd, szbuf + szlen, sizeof(szbuf) - szlen)) > 0) {
		int i = 0;
		szlen += ret;
		while (i < szlen - 3 && !(szbuf[i] == 0 &&  szbuf[i+1] == 0 && (szbuf[i+2] == 1 || (szbuf[i+2] == 0 && szbuf[i+3] == 1)))) i++;
		memcpy(*buff + *size, szbuf, i);
		*size += i;
		memmove(szbuf, szbuf + i, szlen - i);
		szlen -= i;
		if (szlen > 3)
			break;
	}
	if (ret > 0)
		return *size;
	return 0;
}

static int get_next_audio_frame (int fd, uint8_t **buff, int *size)
{
	int ret;
#define AUDIO_FRAME_SIZE 320
	if (!(*buff)) {
		*buff = malloc(AUDIO_FRAME_SIZE);
		if (!(*buff))
			return -1;
	}

	ret = read(fd, *buff, AUDIO_FRAME_SIZE);
	if (ret > 0) {
		*size = ret;
		return ret;
	}
	return 0;
}

int main(int argc, char *argv[0])
{
	int ret;
	int vfd, afd;
	uint8_t *vbuf = NULL;
	uint8_t *abuf = NULL;
	uint64_t ts = 0;
	int vsize = 0, asize = 0;

	vfd = open(argv[1], O_RDONLY|O_BINARY);
	if (vfd < 0) {
		fprintf(stderr, "open %s failed\n", argv[1]);
		fprintf(stderr, "Usage: %s <H264FILE> <G711AFILE>\n", argv[0]);
		return 0;
	}

	afd = open(argv[2], O_RDONLY|O_BINARY);
	if (afd < 0) {
		fprintf(stderr, "open %s failed\n", argv[2]);
		fprintf(stderr, "Usage: %s <H264FILE> <G711AFILE>\n", argv[0]);
		return 0;
	}

	ret = rtsp_start(0);
	if (ret < 0) {
		printf("rtsp_start failed\n");
		return -1;
	}

	signal(SIGINT, sig_proc);
	while (flag_run) {
		uint8_t type = 0;
		ret = rtsp_do_event();

		if (ret < 0)
			break;

		ret = get_next_video_frame(vfd, &vbuf, &vsize);
		if (ret < 0) {
			fprintf(stderr, "get_next_video_frame failed\n");
			break;
		}
		if (ret == 0) {
			lseek(vfd, 0, SEEK_SET);
			lseek(afd, 0, SEEK_SET);
			continue;
		}

		rtsp_tx_video(vbuf, vsize, ts);

		if (vbuf[0] == 0 && vbuf[1] == 0 && vbuf[2] == 1) {
			type = vbuf[3] & 0x1f;
		}
		if (vbuf[0] == 0 && vbuf[1] == 0 && vbuf[2] == 0 && vbuf[3] == 1) {
			type = vbuf[4] & 0x1f;
		}
		if (type == 5 || type == 1) {
			ret = get_next_audio_frame(afd, &abuf, &asize);
			if (ret < 0) {
				fprintf(stderr, "get_next_audio_frame failed\n");
				break;
			}
			if (ret == 0) {
				lseek(vfd, 0, SEEK_SET);
				lseek(afd, 0, SEEK_SET);
				continue;
			}
			rtsp_tx_audio(abuf, asize, ts);

			//I/P frame
			ts += 1000000 / 25;
			usleep(1000000 / 26);
			printf(".");fflush(stdout);
		}
	}

	free(vbuf);
	free(abuf);
	rtsp_stop();
	printf("Exit.\n");
	return 0;
}
