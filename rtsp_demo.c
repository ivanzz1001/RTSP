/*************************************************************************
	> File Name: rtsp_demo.c
	> Author: bxq
	> Mail: 544177215@qq.com 
	> Created Time: Monday, November 23, 2015 AM12:34:09 CST
 ************************************************************************/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifdef __WINDOWS__
#include <winsock2.h>
typedef int socklen_t;
#define MSG_DONTWAIT 0
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "comm.h"
#include "rtsp_demo.h"
#include "rtsp_msg.h"
#include "rtp_enc.h"

//TODO LIST
//RTCP support
//SDP H264 SPS/PPS
//rtp_enc.c optimize
//rtsp_demo.sessions optimize

struct rtp_session
{
	int flags;
#define RTP_SESSION_FLAG_OVER_TCP	(1<<0)
	int sockfd_interleaved[2];
		//if over rtp/udp. [0] is rtp socket, [1] is rtcp socket
		//if over rtp/tcp. [0] is rtsp socket, [1] is rtp interleaved
	rtp_enc enc;
};

struct rtsp_session
{
	int state;	//session state
#define RTSP_SESSION_STATE_INIT			0
#define RTSP_SESSION_STATE_READY		1
#define RTSP_SESSION_STATE_PLAYING		2
#define RTSP_SESSION_STATE_RECORDING	3

	int sockfd;		//rtsp client socket
	unsigned long session;	//session id

	char reqbuf[1024];
	int  reqlen;

	struct rtp_session *vrtp;
	struct rtp_session *artp;
};

struct rtsp_demo 
{
	int  sockfd;	//rtsp server socket 0:invalid
	uint8_t h264_sps_pps[2][64];
	int     h264_sps_pps_len[2];
#define RTSP_SESSION_MAX_NUM 16 //XXX
	struct rtsp_session *sessions[RTSP_SESSION_MAX_NUM];
};

static struct rtsp_demo demo;

/*****************************************************************************
* b64_encode: Stolen from VLC's http.c.
* Simplified by Michael.
* Fixed edge cases and made it work from data (vs. strings) by Ryan.
*****************************************************************************/
static char *base64_encode (char *out, int out_size, const uint8_t *in, int in_size)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *ret, *dst;
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_size;

#define __UINT_MAX (~0lu)
#define __BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)
#define __RB32(x)                                \
    (((uint32_t)((const uint8_t*)(x))[0] << 24) |    \
               (((const uint8_t*)(x))[1] << 16) |    \
               (((const uint8_t*)(x))[2] <<  8) |    \
                ((const uint8_t*)(x))[3])
    if (in_size >= __UINT_MAX / 4 ||
        out_size < __BASE64_SIZE(in_size))
        return NULL;
    ret = dst = out;
    while (bytes_remaining > 3) {
        i_bits = __RB32(in);
        in += 3; bytes_remaining -= 3;
        *dst++ = b64[ i_bits>>26        ];
        *dst++ = b64[(i_bits>>20) & 0x3F];
        *dst++ = b64[(i_bits>>14) & 0x3F];
        *dst++ = b64[(i_bits>>8 ) & 0x3F];
    }
    i_bits = 0;
    while (bytes_remaining) {
        i_bits = (i_bits << 8) + *in++;
        bytes_remaining--;
        i_shift += 8;
    }
    while (i_shift > 0) {
        *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
        i_shift -= 6;
    }
    while ((dst - ret) & 3)
        *dst++ = '=';
    *dst = '\0';

    return ret;
}

static int rtsp_simple_sdp (uint8_t *sps, int sps_len, uint8_t *pps, int pps_len, char *sdp, int maxlen)
{
	char *p = sdp;

	p += sprintf(p, "v=0\r\n");
	p += sprintf(p, "o=- 0 0 IN IP4 0.0.0.0\r\n");
	p += sprintf(p, "s=h264+pcm_alaw\r\n");
	p += sprintf(p, "t=0 0\r\n");
	p += sprintf(p, "a=control:*\r\n");
	p += sprintf(p, "a=range:npt=0-\r\n");

	p += sprintf(p, "m=video 0 RTP/AVP 96\r\n");
	p += sprintf(p, "c=IN IP4 0.0.0.0\r\n");
	p += sprintf(p, "a=rtpmap:96 H264/90000\r\n");
	if (sps && pps && sps_len > 0 && pps_len > 0) {
		if (sps[0] == 0 && sps[1] == 0 && sps[2] == 1) {
			sps += 3;
			sps_len -= 3;
		}
		if (sps[0] == 0 && sps[1] == 0 && sps[2] == 0 && sps[3] == 1) {
			sps += 4;
			sps_len -= 4;
		}
		if (pps[0] == 0 && pps[1] == 0 && pps[2] == 1) {
			pps += 3;
			pps_len -= 3;
		}
		if (pps[0] == 0 && pps[1] == 0 && pps[2] == 0 && pps[3] == 1) {
			pps += 4;
			pps_len -= 4;
		}
		p += sprintf(p, "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=");
		base64_encode(p, (maxlen - (p - sdp)), sps, sps_len);
		p += strlen(p);
		p += sprintf(p, ",");
		base64_encode(p, (maxlen - (p - sdp)), pps, pps_len);
		p += strlen(p);
		p += sprintf(p, "\r\n");
	} else {
		p += sprintf(p, "a=fmtp:96 packetization-mode=1\r\n");
	}
	p += sprintf(p, "a=control:track1\r\n");

//	p += sprintf(p, "m=audio 0 RTP/AVP 8\r\n"); //PCMA/8000/1 (G711A)
	p += sprintf(p, "m=audio 0 RTP/AVP 97\r\n");
	p += sprintf(p, "c=IN IP4 0.0.0.0\r\n");
	p += sprintf(p, "a=rtpmap:97 PCMA/8000/1\r\n");
	p += sprintf(p, "a=control:track2\r\n");

	return (p - sdp);
}

int rtsp_start (int port)
{
	struct sockaddr_in inaddr;
	int sockfd, ret;
	
#ifdef __WINDOWS__
	WSADATA ws;
	WSAStartup(MAKEWORD(2,2), &ws);
#endif
	memset(&demo, 0, sizeof(demo));

	ret = socket(AF_INET, SOCK_STREAM, 0);
	if (ret < 0) {
		err("create socket failed : %s\n", strerror(errno));
		return -1;
	}
	sockfd = ret;

	if (port <= 0)
		port = 554;

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	inaddr.sin_port = htons(port);
	ret = bind(sockfd, (struct sockaddr*)&inaddr, sizeof(inaddr));
	if (ret < 0) {
		err("bind socket to address failed : %s\n", strerror(errno));
		close(sockfd);
		return -1;
	}

	ret = listen(sockfd, RTSP_SESSION_MAX_NUM);
	if (ret < 0) {
		err("listen socket failed : %s\n", strerror(errno));
		close(sockfd);
		return -1;
	}

	demo.sockfd = sockfd;

	info("rtsp server demo starting on port %d\n", port);
	return 0;
}

static int rtsp_new_session (void)
{
	struct sockaddr_in inaddr;
	int sockfd, i;
	socklen_t addrlen = sizeof(inaddr);

	int ret = accept(demo.sockfd, (struct sockaddr*)&inaddr, &addrlen);
	if (ret < 0) {
		err("accept failed : %s\n", strerror(errno));
		return -1;
	}
	sockfd = ret;

	info("new rtsp client %s:%u comming\n", 
			inet_ntoa(inaddr.sin_addr), ntohs(inaddr.sin_port));

	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++)
		if (demo.sessions[i] == NULL)
			break;
	if (i == RTSP_SESSION_MAX_NUM) {
		warn("clinet num too many! this client will lost\n");
		return -1;
	}

	demo.sessions[i] = (struct rtsp_session*)calloc(1, sizeof(struct rtsp_session));
	if (demo.sessions[i] == NULL) {
		err("alloc mem for new session failed : %s\n", strerror(errno));
		return -1;
	}

	demo.sessions[i]->sockfd = sockfd;
	return i;
}

static void rtsp_del_rtp_session(struct rtsp_session *s, int isaudio);
static void rtsp_del_session(int id)
{
	struct rtsp_session *s = demo.sessions[id];

	rtsp_del_rtp_session(s, 0);
	rtsp_del_rtp_session(s, 1);
	close(s->sockfd);
	free(s);
	demo.sessions[id] = NULL;
}

static int rtsp_handle_OPTIONS(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	uint32_t public_ = 0;
	dbg("\n");
	public_ |= RTSP_MSG_PUBLIC_OPTIONS;
	public_ |= RTSP_MSG_PUBLIC_DESCRIBE;
	public_ |= RTSP_MSG_PUBLIC_SETUP;
	public_ |= RTSP_MSG_PUBLIC_PAUSE;
	public_ |= RTSP_MSG_PUBLIC_PLAY;
	public_ |= RTSP_MSG_PUBLIC_TEARDOWN;
	rtsp_msg_set_public(resmsg, public_);
	return 0;
}

static int rtsp_handle_DESCRIBE(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	char sdp[512] = "";
	int len = 0;
	uint32_t accept = 0;

	dbg("\n");
	if (rtsp_msg_get_accept(reqmsg, &accept) < 0 && !(accept & RTSP_MSG_ACCEPT_SDP)) {
		rtsp_msg_set_response(resmsg, 406);
		warn("client not support accept SDP\n");
		return 0;
	}
	
	if (demo.h264_sps_pps_len[0] > 0 && demo.h264_sps_pps_len[1]) {
		len = rtsp_simple_sdp(demo.h264_sps_pps[0], demo.h264_sps_pps_len[0], 
							demo.h264_sps_pps[1], demo.h264_sps_pps_len[1], 
							sdp, sizeof(sdp));
	} else {
		len = rtsp_simple_sdp(NULL, 0, NULL, 0, sdp, sizeof(sdp));
	}

	rtsp_msg_set_content_type(resmsg, RTSP_MSG_CONTENT_TYPE_SDP);
	rtsp_msg_set_content_length(resmsg, len);
	resmsg->body.body = rtsp_mem_dup(sdp, len);
	return 0;
}

static unsigned long __rtp_gen_ssrc(void)
{
	static unsigned long ssrc = 0x22345678;
	return ssrc++;
}

static int __rtp_rtcp_socket(int *rtpsock, int *rtcpsock, const char *peer_ip, int peer_port)
{
	int i, ret;

	for (i = 65536/4*3/2*2; i < 65536; i += 2) {
		struct sockaddr_in inaddr;
		uint16_t port;

		*rtpsock = socket(AF_INET, SOCK_DGRAM, 0);
		if (*rtpsock < 0) {
			err("create rtp socket failed: %s\n", strerror(errno));
			return -1;
		}

		*rtcpsock = socket(AF_INET, SOCK_DGRAM, 0);
		if (*rtcpsock < 0) {
			err("create rtcp socket failed: %s\n", strerror(errno));
			close(*rtpsock);
			return -1;
		}

		port = i;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		inaddr.sin_port = htons(port);
		ret = bind(*rtpsock, (struct sockaddr*)&inaddr, sizeof(inaddr));
		if (ret < 0) {
			close(*rtpsock);
			close(*rtcpsock);
			continue;
		}

		port = i + 1;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		inaddr.sin_port = htons(port);
		ret = bind(*rtcpsock, (struct sockaddr*)&inaddr, sizeof(inaddr));
		if (ret < 0) {
			close(*rtpsock);
			close(*rtcpsock);
			continue;
		}

		port = peer_port / 2 * 2;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = inet_addr(peer_ip);
		inaddr.sin_port = htons(port);
		ret = connect(*rtpsock, (struct sockaddr*)&inaddr, sizeof(inaddr));
		if (ret < 0) {
			close(*rtpsock);
			close(*rtcpsock);
			err("connect peer rtp port failed: %s\n", strerror(errno));
			return -1;
		}

		port = peer_port / 2 * 2 + 1;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = inet_addr(peer_ip);
		inaddr.sin_port = htons(port);
		ret = connect(*rtcpsock, (struct sockaddr*)&inaddr, sizeof(inaddr));
		if (ret < 0) {
			close(*rtpsock);
			close(*rtcpsock);
			err("connect peer rtcp port failed: %s\n", strerror(errno));
			return -1;
		}

		return i;
	}

	err("not found free local port for rtp/rtcp\n");
	return -1;
}

#define RTP_MAX_PKTSIZ	((1500-42)/4*4)
#define RTP_MAX_NBPKTS	(100)

static int rtsp_new_rtp_session(struct rtsp_session *s, const char *peer_ip, int peer_port_interleaved, int isaudio, int flags)
{
	struct rtp_session *rtp;
	int ret;

	rtp = (struct rtp_session*) calloc(1, sizeof(struct rtp_session));
	if (rtp == NULL) {
		err("alloc mem for rtp session failed: %s\n", strerror(errno));
		return -1;
	}

	rtp->flags = flags;
	rtp->enc.ssrc = __rtp_gen_ssrc();
	rtp->enc.seq = 0;
	rtp->enc.pt = isaudio ? 97 : 96;
	rtp->enc.sample_rate = isaudio ? 8000: 90000;
	rtp_enc_init(&rtp->enc, RTP_MAX_PKTSIZ, RTP_MAX_NBPKTS);

	if (flags & RTP_SESSION_FLAG_OVER_TCP) {
		rtp->sockfd_interleaved[0] = s->sockfd;
		rtp->sockfd_interleaved[1] = peer_port_interleaved;
		ret = rtp->sockfd_interleaved[1];
	} else {
		int rtpsock, rtcpsock;
		ret = __rtp_rtcp_socket(&rtpsock, &rtcpsock, peer_ip, peer_port_interleaved);
		if (ret < 0) {
			free(rtp);
			return -1;
		}

		rtp->sockfd_interleaved[0] = rtpsock;
		rtp->sockfd_interleaved[1] = rtcpsock;
	}

	if (isaudio)
		s->artp = rtp;
	else
		s->vrtp = rtp;
	info("rtsp session %08lX new %s %d-%d %s\n", 
			s->session,
			(isaudio ? "artp" : "vrtp"), 
			ret, ret + 1, 
			(flags&RTP_SESSION_FLAG_OVER_TCP ? "OverTCP" : "OverUDP"));
	return ret;
}

static void rtsp_del_rtp_session(struct rtsp_session *s, int isaudio)
{
	struct rtp_session *rtp;

	if (isaudio) {
		rtp = s->artp;
		s->artp = NULL;
	} else {
		rtp = s->vrtp;
		s->vrtp = NULL;
	}

	if (rtp) {
		if (!(rtp->flags & RTP_SESSION_FLAG_OVER_TCP)) {
			close(rtp->sockfd_interleaved[0]);
			close(rtp->sockfd_interleaved[1]);
		}
		rtp_enc_deinit(&rtp->enc);
		free(rtp);
	}
}

static const char *__get_peer_ip(int sockfd)
{
	struct sockaddr_in inaddr;
	socklen_t addrlen = sizeof(inaddr);
	int ret = getpeername(sockfd, (struct sockaddr*)&inaddr, &addrlen);
	if (ret < 0) {
		err("getpeername failed: %s\n", strerror(errno));
		return NULL;
	}
	return inet_ntoa(inaddr.sin_addr);
}

static int rtsp_handle_SETUP(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	uint32_t ssrc = 0;
	int istcp = 0, isaudio = 0;

	dbg("\n");
	if (s->state != RTSP_SESSION_STATE_INIT && s->state != RTSP_SESSION_STATE_READY) 
	{
		rtsp_msg_set_response(resmsg, 455);
		warn("rtsp status err\n");
		return 0;
	}

	if (!reqmsg->hdrs.transport) {
		rtsp_msg_set_response(resmsg, 461);
		warn("rtsp no transport err\n");
		return 0;
	}

	if (reqmsg->hdrs.transport->type == RTSP_MSG_TRANSPORT_TYPE_RTP_AVP_TCP) {
		istcp = 1;
		if (!(reqmsg->hdrs.transport->flags & RTSP_MSG_TRANSPORT_FLAG_INTERLEAVED)) {
			warn("rtsp no interleaved err\n");
			rtsp_msg_set_response(resmsg, 461);
			return 0;
		}
	} else {
		if (!(reqmsg->hdrs.transport->flags & RTSP_MSG_TRANSPORT_FLAG_CLIENT_PORT)) {
			warn("rtsp no client_port err\n");
			rtsp_msg_set_response(resmsg, 461);
			return 0;
		}
	}

	if (strstr(reqmsg->hdrs.startline.reqline.uri.abspath, "/track1")) {
		isaudio = 0;
	} else if (strstr(reqmsg->hdrs.startline.reqline.uri.abspath, "/track2")) {//XXX
		isaudio = 1;
	} else {
		warn("rtsp urlpath:%s err\n", reqmsg->hdrs.startline.reqline.uri.abspath);
		rtsp_msg_set_response(resmsg, 461);
		return 0;
	}

	rtsp_del_rtp_session(s, isaudio);

	if (istcp) {
		int ret = rtsp_new_rtp_session(s, __get_peer_ip(s->sockfd), 
			reqmsg->hdrs.transport->interleaved, isaudio, 
			RTP_SESSION_FLAG_OVER_TCP);
		if (ret < 0) {
			rtsp_msg_set_response(resmsg, 500);
			return 0;
		}
		ssrc = isaudio ? s->artp->enc.ssrc : s->vrtp->enc.ssrc;
		rtsp_msg_set_transport_tcp(resmsg, ssrc, 
				reqmsg->hdrs.transport->interleaved);
	} else {
		int ret = rtsp_new_rtp_session(s, __get_peer_ip(s->sockfd), 
			reqmsg->hdrs.transport->client_port, isaudio, 0);
		if (ret < 0) {
			rtsp_msg_set_response(resmsg, 500);
			return 0;
		}
		ssrc = isaudio ? s->artp->enc.ssrc : s->vrtp->enc.ssrc;
		rtsp_msg_set_transport_udp(resmsg, ssrc, 
				reqmsg->hdrs.transport->client_port, ret);
	}

	if (s->state == RTSP_SESSION_STATE_INIT) {
		s->state = RTSP_SESSION_STATE_READY;
		s->session = rtsp_msg_gen_session_id();
		rtsp_msg_set_session(resmsg, s->session);
	}

	return 0;
}

static int rtsp_handle_PAUSE(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	dbg("\n");
	if (s->state != RTSP_SESSION_STATE_READY && s->state != RTSP_SESSION_STATE_PLAYING) 
	{
		rtsp_msg_set_response(resmsg, 455);
		warn("rtsp status err\n");
		return 0;
	}

	if (s->state != RTSP_SESSION_STATE_READY)
		s->state = RTSP_SESSION_STATE_READY;
	return 0;
}

static int rtsp_handle_PLAY(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	dbg("\n");
	if (s->state != RTSP_SESSION_STATE_READY && s->state != RTSP_SESSION_STATE_PLAYING) 
	{
		rtsp_msg_set_response(resmsg, 455);
		warn("rtsp status err\n");
		return 0;
	}

	if (s->state != RTSP_SESSION_STATE_PLAYING)
		s->state = RTSP_SESSION_STATE_PLAYING;
	return 0;
}

static int rtsp_handle_TEARDOWN(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	dbg("\n");
	rtsp_del_rtp_session(s, 0);
	rtsp_del_rtp_session(s, 1);
	s->state = RTSP_SESSION_STATE_INIT;
	return 0;
}

static int rtsp_process_request(struct rtsp_session *s, const rtsp_msg_s *reqmsg, rtsp_msg_s *resmsg)
{
	uint32_t cseq = 0, session = 0;
	rtsp_msg_set_response(resmsg, 200);

	if (rtsp_msg_get_cseq(reqmsg, &cseq) < 0) {
		rtsp_msg_set_response(resmsg, 400);
		warn("No CSeq field\n");
		return 0;
	}
	if (s->state != RTSP_SESSION_STATE_INIT) {
		if (rtsp_msg_get_session(reqmsg, &session) < 0 || session != s->session) {
			warn("Invalid Session field\n");
			rtsp_msg_set_response(resmsg, 454);
			return 0;
		}
	}

	rtsp_msg_set_cseq(resmsg, cseq);
	if (s->state != RTSP_SESSION_STATE_INIT) {
		rtsp_msg_set_session(resmsg, session);
	}
	rtsp_msg_set_date(resmsg, NULL);
	rtsp_msg_set_server(resmsg, "rtsp_demo");

	switch (reqmsg->hdrs.startline.reqline.method) {
		case RTSP_MSG_METHOD_OPTIONS:
			return rtsp_handle_OPTIONS(s, reqmsg, resmsg);
		case RTSP_MSG_METHOD_DESCRIBE:
			return rtsp_handle_DESCRIBE(s, reqmsg, resmsg);
		case RTSP_MSG_METHOD_SETUP:
			return rtsp_handle_SETUP(s, reqmsg, resmsg);
		case RTSP_MSG_METHOD_PAUSE:
			return rtsp_handle_PAUSE(s, reqmsg, resmsg);
		case RTSP_MSG_METHOD_PLAY:
			return rtsp_handle_PLAY(s, reqmsg, resmsg);
		case RTSP_MSG_METHOD_TEARDOWN:
			return rtsp_handle_TEARDOWN(s, reqmsg, resmsg);
		default:
			break;
	}

	rtsp_msg_set_response(resmsg, 501);
	return 0;
}

static int rtsp_recv_msg(struct rtsp_session *s, rtsp_msg_s *msg)
{
	int ret;
	
	ret = recv(s->sockfd, s->reqbuf + s->reqlen, sizeof(s->reqbuf) - s->reqlen - 1, MSG_DONTWAIT);
	if (ret <= 0) {
		err("recv data failed: %s\n", strerror(errno));
		return -1;
	}
	s->reqlen += ret;
	s->reqbuf[s->reqlen] = 0;
	
	ret = rtsp_msg_parse_from_array(msg, s->reqbuf, s->reqlen);
	if (ret < 0) {
		err("Invalid frame\n");
		return -1;
	}
	if (ret == 0) {
		return 0;
	}

	memmove(s->reqbuf, s->reqbuf + ret, s->reqlen - ret);
	s->reqlen -= ret;
	return ret;
}

static int rtsp_send_msg(struct rtsp_session *s, rtsp_msg_s *msg) 
{
	char szbuf[1024] = "";
	int ret = rtsp_msg_build_to_array(msg, szbuf, sizeof(szbuf));
	if (ret < 0) {
		err("rtsp_msg_build_to_array failed\n");
		return -1;
	}

	ret = send(s->sockfd, szbuf, ret, 0);
	if (ret < 0) {
		err("rtsp response send failed: %s\n", strerror(errno));
		return -1;
	}
	return ret;
}

int rtsp_do_event (void)
{
	fd_set rfds;
	int maxfd, i, ret;
	struct rtsp_session *s;
	rtsp_msg_s reqmsg, resmsg;
	struct timeval tv;

	if (demo.sockfd == 0)
		return -1;

	FD_ZERO(&rfds);
	FD_SET(demo.sockfd, &rfds);

	maxfd = demo.sockfd;
	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++) {
		s = demo.sessions[i];
		if (!s) 
			continue;

		FD_SET(s->sockfd, &rfds);
		if (s->sockfd > maxfd)
			maxfd = s->sockfd;
		if (s->vrtp) {
			//TODO add video rtcp sock to rfds
		}
		if (s->artp) {
			//TODO add audio rtcp sock to rfds
		}
	}

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
	if (ret < 0) {
		err("select failed : %s\n", strerror(errno));
		return -1;
	}
	if (ret == 0) {
		return 0;
	}

	if (FD_ISSET(demo.sockfd, &rfds)) {
		//new session
		rtsp_new_session();
	}

	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++) {
		s = demo.sessions[i];
		if (!s)
			continue;
		
		if (s->vrtp) {
			//TODO process video rtcp socket
		}
		if (s->artp) {
			//TODO process audio rtcp socket
		}

		if (!FD_ISSET(s->sockfd, &rfds))
			continue;

		rtsp_msg_init(&reqmsg);
		rtsp_msg_init(&resmsg);

		ret = rtsp_recv_msg(s, &reqmsg);
		if (ret == 0)
			continue;
		if (ret < 0) {
			rtsp_del_session(i);
			continue;
		}

		if (reqmsg.type == RTSP_MSG_TYPE_INTERLEAVED) {
			//TODO process RTCP over TCP frame
			warn("TODO TODO TODO process interleaved frame\n");
			rtsp_msg_free(&reqmsg);
			continue;
		}

		if (reqmsg.type != RTSP_MSG_TYPE_REQUEST) {
			err("not request frame.\n");
			rtsp_msg_free(&reqmsg);
			continue;
		}

		ret = rtsp_process_request(s, &reqmsg, &resmsg);
		if (ret < 0) {
			err("request internal err\n");
		} else {
			rtsp_send_msg(s, &resmsg);
		}

		rtsp_msg_free(&reqmsg);
		rtsp_msg_free(&resmsg);
	}

	return 1;
}

static int rtp_tx_data (struct rtp_session *s, const uint8_t *data, int size)
{
	uint8_t szbuf[RTP_MAX_PKTSIZ + 4];
	int ret;

	if (s->flags & RTP_SESSION_FLAG_OVER_TCP) {
		szbuf[0] = '$';
		szbuf[1] = s->sockfd_interleaved[1];
		*((uint16_t*)&szbuf[2]) = htons(size);
		memcpy(szbuf + 4, data, size);
		data = szbuf;
		size += 4;
	}

	ret = send(s->sockfd_interleaved[0], data, size, 0);
	if (ret < 0) {
		err("rtp send %d bytes failed: %s\n", size, strerror(errno));
		return -1;
	}

	return size;
}

static int rtsp_try_set_sps_pps (const uint8_t *frame, int len)
{
	uint8_t type = 0;
	if (demo.h264_sps_pps_len[0] && demo.h264_sps_pps_len[1]) {
		return 0;
	}

	if (frame[0] == 0 && frame[1] == 0 && frame[2] == 1) {
		type = frame[3] & 0x1f;
		frame += 3;
		len   -= 3;
	}
	if (frame[0] == 0 && frame[1] == 0 && frame[2] == 0 && frame[3] == 1) {
		type = frame[4] & 0x1f;
		frame += 4;
		len   -= 4;
	}

	if (len < 1)
		return -1;

	if (type == 7 && 0 == demo.h264_sps_pps_len[0]) {
		dbg("sps %d\n", len);
		if (len > sizeof(demo.h264_sps_pps[0]))
			len = sizeof(demo.h264_sps_pps[0]);
		memcpy(demo.h264_sps_pps[0], frame, len);
		demo.h264_sps_pps_len[0] = len;
	}

	if (type == 8 && 0 == demo.h264_sps_pps_len[1]) {
		dbg("pps %d\n", len);
		if (len > sizeof(demo.h264_sps_pps[1]))
			len = sizeof(demo.h264_sps_pps[1]);
		memcpy(demo.h264_sps_pps[1], frame, len);
		demo.h264_sps_pps_len[1] = len;
	}

	return 0;
}

static int rtsp_tx_video_internal (const uint8_t *frame, int len, uint64_t ts)
{
	uint8_t *packets[RTP_MAX_NBPKTS] = {NULL};
	int pktsizs[RTP_MAX_NBPKTS] = {0};
	int count, i;

	rtsp_try_set_sps_pps(frame, len);

	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++) {
		struct rtsp_session *s = demo.sessions[i];
		int j;
		if (!s) 
			continue;
		if (s->state != RTSP_SESSION_STATE_PLAYING || !s->vrtp)
			continue;

		count = rtp_enc_h264(&s->vrtp->enc, frame, len, ts, packets, pktsizs);
		if (count <= 0) {
			err("rtp_enc_h264 ret = %d\n", count);
			continue;
		}
		for (j = 0; j < count; j++) {
			rtp_tx_data(s->vrtp, packets[j], pktsizs[j]);
		}
	}
	return len;
}

static const uint8_t *rtsp_find_h264_nalu (const uint8_t *buff, int len, uint8_t *type, int *size) 
{
	const uint8_t *s = NULL;
	while (len >= 3) {
		if (buff[0] == 0 && buff[1] == 0 && buff[2] == 1) {
			if (!s) {
				if (len < 4)
					return NULL;
				s = buff;
				*type = buff[3] & 0x1f;
			} else {
				*size = (buff - s);
				return s;
			}
			bbuff+= 3;
			len  -= 3;
			continue;
		}
		if (len >= 4 && buff[0] == 0 && buff[1] == 0 && buff[2] == 0 && buff[3] == 1) {
			if (!s) {
				if (len < 5)
					return NULL;
				s = buff;
				*type = buff[4] & 0x1f;
			} else {
				*size = (buff - s);
				return s;
			}
			bbuff+= 4;
			len  -= 4;
			continue;
		}
		bbuff++;
		len --;
	}
	if (!s)
		return NULL;
	*size = (buff -s + len);
	return s;
}

int rtsp_tx_video (const uint8_t *frame, int len, uint64_t ts)
{
	int ret = 0;
	if (demo.sockfd == 0 || !frame)
		return -1;

	//dbg("framelen = %d\n", len);
	while (len > 0) {
		const uint8_t *start = NULL;
		uint8_t type = 0;
		int size = 0;
		start = rtsp_find_h264_nalu(frame, len, &type, &size);
		if (!start) {
			warn("not found nal header\n");
			break;
		}
		//dbg("type:%u size:%d\n", type, size);
		ret += rtsp_tx_video_internal(start, size, ts);
		len -= (start - frame) + size;
		frame = start + size;
	}
	return ret;
}

int rtsp_tx_audio (const uint8_t *frame, int len, uint64_t ts)
{
	uint8_t *packets[RTP_MAX_NBPKTS] = {NULL};
	int pktsizs[RTP_MAX_NBPKTS] = {0};
	int count, i;

	if (demo.sockfd == 0 || !frame)
		return -1;
	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++) {
		struct rtsp_session *s = demo.sessions[i];
		int j;
		if (!s) 
			continue;
		if (s->state != RTSP_SESSION_STATE_PLAYING || !s->artp)
			continue;

		count = rtp_enc_g711(&s->artp->enc, frame, len, ts, packets, pktsizs);
		if (count <= 0) {
			err("rtp_enc_g711 ret = %d\n", count);
			continue;
		}
		for (j = 0; j < count; j++) {
			rtp_tx_data(s->artp, packets[j], pktsizs[j]);
		}
	}
	return len;
}

void rtsp_stop (void)
{
	int i;
	
	if (demo.sockfd == 0)
		return;

	for (i = 0; i < RTSP_SESSION_MAX_NUM; i++) {
		if (demo.sessions[i]) {
			rtsp_del_session(i);
		}
	}

	close(demo.sockfd);
	demo.sockfd = 0;
}

#if 0
#include <signal.h>
static int flag_run = 1;
static void sig_proc(int signo)
{
	flag_run = 0;
}

int main()
{
	int ret;

	ret = rtsp_start(554);
	if (ret < 0) {
		printf("rtsp_start failed\n");
		return -1;
	}

	signal(SIGINT, sig_proc);
	while (flag_run) {
		ret = rtsp_do_event();
		rtsp_tx_video(NULL, 0, 0);
		rtsp_tx_audio(NULL, 0, 0);
		if (ret < 0)
			break;
		if (ret == 0)
			usleep(200000);
	}

	rtsp_stop();
	return 0;
}
#endif
