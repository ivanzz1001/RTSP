/*************************************************************************
	> File Name: rtp_enc.h
	> Author: bxq
	> Mail: 544177215@qq.com 
	> Created Time: Saturday, December 19, 2015 PM08:27:54 CST
 ************************************************************************/

#ifndef __RTP_ENC_H__
#define __RTP_ENC_H__

#include <stdint.h>

typedef struct __rtp_enc 
{
	uint32_t ssrc;
	uint16_t seq;
	uint8_t  pt;
	uint8_t  nbpkts;
	uint16_t pktsiz;
	uint32_t sample_rate;
	uint8_t *szbuf;
} rtp_enc;

int rtp_enc_init (rtp_enc *e, uint16_t pktsiz, uint8_t nbpkts);
int rtp_enc_h264 (rtp_enc *e, const uint8_t *frame, int len, uint64_t ts, uint8_t *packets[], int pktsizs[]);
int rtp_enc_g711 (rtp_enc *e, const uint8_t *frame, int len, uint64_t ts, uint8_t *packets[], int pktsizs[]);
void rtp_enc_deinit (rtp_enc *e);

#endif

