/*! \file    rtp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP processing
 * \details  Implementation of the RTP header. Since the gateway does not
 * much more than relaying frames around, the only thing we're interested
 * in is the RTP header and how to get its payload, and parsing extensions.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#include <string.h>
#include "rtp.h"
#include "rtpsrtp.h"
#include "debug.h"

char *janus_rtp_payload(char *buf, int len, int *plen) {
	if(!buf || len < 12)
		return NULL;

	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;

	if(rtp->extension) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension*)(buf+hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(len > (hlen + extlen))
			hlen += extlen;
	}
	if(plen)
		*plen = len-hlen;
	return buf+hlen;
}

int janus_rtp_header_extension_get_id(const char *sdp, const char *extension) {
	if(!sdp || !extension)
		return -1;
	char extmap[100];
	g_snprintf(extmap, 100, "a=extmap:%%d %s", extension);
	/* Look for the extmap */
	const char *line = strstr(sdp, "m=");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, "a=extmap") && strstr(line, extension)) {
				/* Gotcha! */
				int id = 0;
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
				if(sscanf(line, extmap, &id) == 1) {
#pragma GCC diagnostic warning "-Wformat-nonliteral"
					*next = '\n';
					return id;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return -2;
}

const char *janus_rtp_header_extension_get_from_id(const char *sdp, int id) {
	if(!sdp || id < 0)
		return NULL;
	/* Look for the mapping */
	char extmap[100];
	g_snprintf(extmap, 100, "a=extmap:%d ", id);
	const char *line = strstr(sdp, "m=");
	while(line) {
		char *next = strchr(line, '\n');
		if(next) {
			*next = '\0';
			if(strstr(line, extmap)) {
				/* Gotcha! */
				char extension[100];
				if(sscanf(line, "a=extmap:%d %s", &id, extension) == 2) {
					*next = '\n';
					if(strstr(extension, JANUS_RTP_EXTMAP_AUDIO_LEVEL))
						return JANUS_RTP_EXTMAP_AUDIO_LEVEL;
					if(strstr(extension, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION))
						return JANUS_RTP_EXTMAP_VIDEO_ORIENTATION;
					if(strstr(extension, JANUS_RTP_EXTMAP_PLAYOUT_DELAY))
						return JANUS_RTP_EXTMAP_PLAYOUT_DELAY;
					if(strstr(extension, JANUS_RTP_EXTMAP_TOFFSET))
						return JANUS_RTP_EXTMAP_TOFFSET;
					if(strstr(extension, JANUS_RTP_EXTMAP_ABS_SEND_TIME))
						return JANUS_RTP_EXTMAP_ABS_SEND_TIME;
					if(strstr(extension, JANUS_RTP_EXTMAP_CC_EXTENSIONS))
						return JANUS_RTP_EXTMAP_CC_EXTENSIONS;
					if(strstr(extension, JANUS_RTP_EXTMAP_RTP_STREAM_ID))
						return JANUS_RTP_EXTMAP_RTP_STREAM_ID;
					JANUS_LOG(LOG_ERR, "Unsupported extension '%s'\n", extension);
					return NULL;
				}
			}
			*next = '\n';
		}
		line = next ? (next+1) : NULL;
	}
	return NULL;
}

/* Static helper to quickly find the extension data */
static int janus_rtp_header_extension_find(char *buf, int len, int id,
		uint8_t *byte, uint32_t *word, char **ref) {
	if(!buf || len < 12)
		return -1;
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension *)(buf+hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(len > (hlen + extlen)) {
			/* 1-Byte extension */
			if(ntohs(ext->type) == 0xBEDE) {
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen;
				int i = 0;
				while(i < extlen) {
					extid = buf[hlen+i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					idlen = (buf[hlen+i] & 0xF)+1;
					if(extid == id) {
						/* Found! */
						if(byte)
							*byte = buf[hlen+i+1];
						if(word)
							*word = *(uint32_t *)(buf+hlen+i);
						if(ref)
							*ref = &buf[hlen];
						return 0;
					}
					i += 1 + idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -1;
}

int janus_rtp_header_extension_parse_audio_level(char *buf, int len, int id, int *level) {
	uint8_t byte = 0;
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
		return -1;
	/* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
	int v = (byte & 0x80) >> 7;
	int value = byte & 0x7F;
	JANUS_LOG(LOG_DBG, "%02x --> v=%d, level=%d\n", byte, v, value);
	if(level)
		*level = value;
	return 0;
}

int janus_rtp_header_extension_parse_video_orientation(char *buf, int len, int id,
		gboolean *c, gboolean *f, gboolean *r1, gboolean *r0) {
	uint8_t byte = 0;
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
		return -1;
	/* a=extmap:4 urn:3gpp:video-orientation */
	gboolean cbit = (byte & 0x08) >> 3;
	gboolean fbit = (byte & 0x04) >> 2;
	gboolean r1bit = (byte & 0x02) >> 1;
	gboolean r0bit = byte & 0x01;
	JANUS_LOG(LOG_DBG, "%02x --> c=%d, f=%d, r1=%d, r0=%d\n", byte, cbit, fbit, r1bit, r0bit);
	if(c)
		*c = cbit;
	if(f)
		*f = fbit;
	if(r1)
		*r1 = r1bit;
	if(r0)
		*r0 = r0bit;
	return 0;
}

int janus_rtp_header_extension_parse_playout_delay(char *buf, int len, int id,
		uint16_t *min_delay, uint16_t *max_delay) {
	uint32_t bytes = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, &bytes, NULL) < 0)
		return -1;
	/* a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay */
	uint16_t min = (bytes & 0x00FFF000) >> 12;
	uint16_t max = bytes & 0x00000FFF;
	JANUS_LOG(LOG_DBG, "%"SCNu32"x --> min=%"SCNu16", max=%"SCNu16"\n", bytes, min, max);
	if(min_delay)
		*min_delay = min;
	if(max_delay)
		*max_delay = max;
	return 0;
}

int janus_rtp_header_extension_parse_rtp_stream_id(char *buf, int len, int id,
		char *sdes_item, int sdes_len) {
	char *ext = NULL;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext) < 0)
		return -1;
	/* a=extmap:3/sendonly urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id */
	if(ext == NULL)
		return -2;
	int val_len = (*ext & 0x0F) + 1;
	if(val_len > (sdes_len-1)) {
		JANUS_LOG(LOG_WARN, "SDES buffer is too small (%d < %d), RTP stream ID will be cut\n", val_len, sdes_len);
		val_len = sdes_len-1;
	}
	memcpy(sdes_item, ext+1, val_len);
	*(sdes_item+val_len) = '\0';
	return 0;
}


/* RTP context related methods */
void janus_rtp_switching_context_reset(janus_rtp_switching_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	memset(context, 0, sizeof(*context));
}

void janus_rtp_header_update(janus_rtp_header *header, janus_rtp_switching_context *context, gboolean video, int step) {
	if(header == NULL || context == NULL || step < 0)
		return;
	uint32_t ssrc = ntohl(header->ssrc);
	uint32_t timestamp = ntohl(header->timestamp);
	uint16_t seq = ntohs(header->seq_number);
	if(video) {
		if(ssrc != context->v_last_ssrc) {
			/* Video SSRC changed: update both sequence number and timestamp */
			JANUS_LOG(LOG_VERB, "Video SSRC changed, %"SCNu32" --> %"SCNu32"\n",
				context->v_last_ssrc, ssrc);
			context->v_last_ssrc = ssrc;
			context->v_base_ts_prev = context->v_last_ts;
			context->v_base_ts = timestamp;
			context->v_base_seq_prev = context->v_last_seq;
			context->v_base_seq = seq;
		}
		if(context->v_seq_reset) {
			/* Video sequence number was paused for a while: just update that */
			context->v_seq_reset = FALSE;
			context->v_base_seq_prev = context->v_last_seq;
			context->v_base_seq = seq;
		}
		/* Compute a coherent timestamp and sequence number */
		context->v_last_ts = (timestamp-context->v_base_ts) + context->v_base_ts_prev+step;
		context->v_last_seq = (seq-context->v_base_seq)+context->v_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet */
		header->timestamp = htonl(context->v_last_ts);
		header->seq_number = htons(context->v_last_seq);
	} else {
		if(ssrc != context->a_last_ssrc) {
			/* Audio SSRC changed: update both sequence number and timestamp */
			JANUS_LOG(LOG_VERB, "Audio SSRC changed, %"SCNu32" --> %"SCNu32"\n",
				context->a_last_ssrc, ssrc);
			context->a_last_ssrc = ssrc;
			context->a_base_ts_prev = context->a_last_ts;
			context->a_base_ts = timestamp;
			context->a_base_seq_prev = context->a_last_seq;
			context->a_base_seq = seq;
		}
		if(context->a_seq_reset) {
			/* Audio sequence number was paused for a while: just update that */
			context->a_seq_reset = FALSE;
			context->a_base_seq_prev = context->a_last_seq;
			context->a_base_seq = seq;
		}
		/* Compute a coherent timestamp and sequence number */
		context->a_last_ts = (timestamp-context->a_base_ts) + context->a_base_ts_prev+step;
		context->a_last_seq = (seq-context->a_base_seq)+context->a_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet */
		header->timestamp = htonl(context->a_last_ts);
		header->seq_number = htons(context->a_last_seq);
	}
}


/* SRTP stuff: we may need our own randomizer */
#ifdef HAVE_SRTP_2
int srtp_crypto_get_random(uint8_t *key, int len) {
	/* libsrtp 2.0 doesn't have crypto_get_random, we use OpenSSL's RAND_* to replace it:
	 * 		https://wiki.openssl.org/index.php/Random_Numbers */
	int rc = RAND_bytes(key, len);
	if(rc != 1) {
		/* Error generating */
		return -1;
	}
	return 0;
}
#endif
/* SRTP error codes as a string array */
static const char *janus_srtp_error[] =
{
#ifdef HAVE_SRTP_2
	"srtp_err_status_ok",
	"srtp_err_status_fail",
	"srtp_err_status_bad_param",
	"srtp_err_status_alloc_fail",
	"srtp_err_status_dealloc_fail",
	"srtp_err_status_init_fail",
	"srtp_err_status_terminus",
	"srtp_err_status_auth_fail",
	"srtp_err_status_cipher_fail",
	"srtp_err_status_replay_fail",
	"srtp_err_status_replay_old",
	"srtp_err_status_algo_fail",
	"srtp_err_status_no_such_op",
	"srtp_err_status_no_ctx",
	"srtp_err_status_cant_check",
	"srtp_err_status_key_expired",
	"srtp_err_status_socket_err",
	"srtp_err_status_signal_err",
	"srtp_err_status_nonce_bad",
	"srtp_err_status_read_fail",
	"srtp_err_status_write_fail",
	"srtp_err_status_parse_err",
	"srtp_err_status_encode_err",
	"srtp_err_status_semaphore_err",
	"srtp_err_status_pfkey_err",
#else
	"err_status_ok",
	"err_status_fail",
	"err_status_bad_param",
	"err_status_alloc_fail",
	"err_status_dealloc_fail",
	"err_status_init_fail",
	"err_status_terminus",
	"err_status_auth_fail",
	"err_status_cipher_fail",
	"err_status_replay_fail",
	"err_status_replay_old",
	"err_status_algo_fail",
	"err_status_no_such_op",
	"err_status_no_ctx",
	"err_status_cant_check",
	"err_status_key_expired",
	"err_status_socket_err",
	"err_status_signal_err",
	"err_status_nonce_bad",
	"err_status_read_fail",
	"err_status_write_fail",
	"err_status_parse_err",
	"err_status_encode_err",
	"err_status_semaphore_err",
	"err_status_pfkey_err",
#endif
};
const char *janus_srtp_error_str(int error) {
	if(error < 0 || error > 24)
		return NULL;
	return janus_srtp_error[error];
}
