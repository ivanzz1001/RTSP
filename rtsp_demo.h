/*************************************************************************
	> File Name: rtsp_demo.h
	> Author: bxq
	> Mail: 544177215@qq.com 
	> Created Time: Monday, November 23, 2015 AM12:22:43 CST
 ************************************************************************/

#ifndef __RTSP_DEMO_H__
#define __RTSP_DEMO_H__
/*
 * a simple RTSP server demo
 * RTP over UDP/TCP H264/G711a 
 * */

#include <stdint.h>

int rtsp_start (int port);
int rtsp_do_event (void);
int rtsp_tx_video (const uint8_t *frame, int len, uint64_t ts);
int rtsp_tx_audio (const uint8_t *frame, int len, uint64_t ts);
void rtsp_stop (void);

#endif
