/*! \file    rtp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP processing
 * \details  Implementation of the RTP header. Since the server does not
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
#include "utils.h"

gboolean janus_is_rtp(char *buf, guint len) {
	if (len < 12)
		return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type < 64) || (header->type >= 96));
}

char *janus_rtp_payload(char *buf, int len, int *plen) {
	if(!buf || len < 12)
		return NULL;
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	if (rtp->version != 2) {
		return NULL;
	}
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
	if (len-hlen <= 0) {
		return NULL;
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
					if(strstr(extension, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
						return JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC;
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
	if (rtp->version != 2) {
		return -1;
	}
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
						if(word && idlen >= 3 && (i+3) < extlen) {
							memcpy(word, buf+hlen+i, sizeof(uint32_t));
							*word = ntohl(*word);
						}
						if(ref)
							*ref = &buf[hlen+i];
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

int janus_rtp_header_extension_parse_mid(char *buf, int len, int id,
		char *sdes_item, int sdes_len) {
	char *ext = NULL;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext) < 0)
		return -1;
	/* a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid */
	if(ext == NULL)
		return -2;
	int val_len = (*ext & 0x0F) + 1;
	if(val_len > (sdes_len-1)) {
		JANUS_LOG(LOG_WARN, "SDES buffer is too small (%d < %d), MID will be cut\n", val_len, sdes_len);
		val_len = sdes_len-1;
	}
	if (val_len > len-(ext-buf)-1 ) {
		return -3;
	}
	memcpy(sdes_item, ext+1, val_len);
	*(sdes_item+val_len) = '\0';
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
	if (val_len > len-(ext-buf)-1 ) {
		return -3;
	}
	memcpy(sdes_item, ext+1, val_len);
	*(sdes_item+val_len) = '\0';
	return 0;
}

int janus_rtp_header_extension_parse_transport_wide_cc(char *buf, int len, int id, uint16_t *transSeqNum) {
	char *ext = NULL;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext) < 0)
		return -1;
	/*  0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  ID   | L=1   |transport-wide sequence number | zero padding  |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if(ext == NULL)
		return -2;
	int val_len = (*ext & 0x0F) + 1;
	if (val_len < 2 || val_len > len-(ext-buf)-1) {
		return -3;
	}
	memcpy(transSeqNum, ext+1, sizeof(uint16_t));
	*transSeqNum = ntohs(*transSeqNum);
	return 0;
}

/* RTP context related methods */
void janus_rtp_switching_context_reset(janus_rtp_switching_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	memset(context, 0, sizeof(*context));
}

int janus_rtp_skew_compensate_audio(janus_rtp_header *header, janus_rtp_switching_context *context, gint64 now) {
	/* Reset values if a new ssrc has been detected */
	if (context->a_new_ssrc) {
		JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" resetting status\n", context->a_last_ssrc);
		context->a_reference_time = now;
		context->a_start_time = 0;
		context->a_evaluating_start_time = 0;
		context->a_start_ts = 0;
		context->a_active_delay = 0;
		context->a_prev_delay = 0;
		context->a_seq_offset = 0;
		context->a_ts_offset = 0;
		context->a_target_ts = 0;
		context->a_new_ssrc = FALSE;
	}

	/* N 	: a N sequence number jump has been performed */
	/* 0  	: any new skew compensation has been applied */
	/* -N  	: a N packet drop must be performed */
	int exit_status = 0;

	/* Do not execute skew analysis in the first seconds */
	if (now-context->a_reference_time < SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
		return 0;
	} else if (!context->a_start_time) {
		JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase start\n", context->a_last_ssrc);
		context->a_start_time = now;
		context->a_evaluating_start_time = now;
		context->a_start_ts = context->a_last_ts;
	}

	/* Skew analysis */
	/* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
	if (context->a_target_ts > 0 && (gint32)(context->a_target_ts - context->a_last_ts) > 0) {
		context->a_seq_offset--;
		exit_status = -1;
	} else {
		context->a_target_ts = 0;
		/* Do not execute analysis for out of order packets or multi-packets frame */
		if (context->a_last_seq == context->a_prev_seq + 1 && context->a_last_ts != context->a_prev_ts) {
			/* Set the sample rate according to the header */
			guint32 akhz = 48; /* 48khz for Opus */
			if(header->type == 0 || header->type == 8 || header->type == 9)
				akhz = 8;
			/* Evaluate the local RTP timestamp according to the local clock */
			guint32 expected_ts = ((now - context->a_start_time)*akhz)/1000 + context->a_start_ts;
			/* Evaluate current delay */
			gint32 delay_now = context->a_last_ts - expected_ts;
			/* Exponentially weighted moving average estimation */
			gint32 delay_estimate = (63*context->a_prev_delay + delay_now)/64;
			/* Save previous delay for the next iteration*/
			context->a_prev_delay = delay_estimate;
			/* Evaluate the distance between active delay and current delay estimate */
			gint32 offset = context->a_active_delay - delay_estimate;
			JANUS_LOG(LOG_HUGE, "audio skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16"\n", context->a_last_ssrc, context->a_last_ts, expected_ts, offset, context->a_ts_offset, context->a_seq_offset);
			gint32 skew_th = RTP_AUDIO_SKEW_TH_MS*akhz;
			/* Evaluation phase */
			if (context->a_evaluating_start_time > 0) {
				/* Check if the offset has surpassed half the threshold during the evaluating phase */
				if (now-context->a_evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
					if (abs(offset) <= skew_th/2) {
						JANUS_LOG(LOG_HUGE, "audio skew SSRC=%"SCNu32" evaluation phase continue\n", context->a_last_ssrc);
					} else {
						JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase reset\n", context->a_last_ssrc);
						context->a_start_time = now;
						context->a_evaluating_start_time = now;
						context->a_start_ts = context->a_last_ts;
					}
				} else {
					JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase stop\n", context->a_last_ssrc);
					context->a_evaluating_start_time = 0;
				}
				return 0;
			}
			/* Check if the offset has surpassed the threshold */
			if (offset >= skew_th) {
				/* The source is slowing down */
				/* Update active delay */
				context->a_active_delay = delay_estimate;
				/* Adjust ts offset */
				context->a_ts_offset += skew_th;
				/* Calculate last ts increase */
				guint32 ts_incr = context->a_last_ts-context->a_prev_ts;
				/* Evaluate sequence number jump */
				guint16 jump = (skew_th+ts_incr-1)/ts_incr;
				/* Adjust seq num offset */
				context->a_seq_offset += jump;
				exit_status = jump;
			} else if (offset <= -skew_th) {
				/* The source is speeding up*/
				/* Update active delay */
				context->a_active_delay = delay_estimate;
				/* Adjust ts offset */
				context->a_ts_offset -= skew_th;
				/* Set target ts */
				context->a_target_ts = context->a_last_ts + skew_th;
				if (context->a_target_ts == 0)
					context->a_target_ts = 1;
				/* Adjust seq num offset */
				context->a_seq_offset--;
				exit_status = -1;
			}
		}
	}

	/* Skew compensation */
	/* Fix header timestamp considering the active offset */
	guint32 fixed_rtp_ts = context->a_last_ts + context->a_ts_offset;
	header->timestamp = htonl(fixed_rtp_ts);
	/* Fix header sequence number considering the total offset */
	guint16 fixed_rtp_seq = context->a_last_seq + context->a_seq_offset;
	header->seq_number = htons(fixed_rtp_seq);

	return exit_status;
}

int janus_rtp_skew_compensate_video(janus_rtp_header *header, janus_rtp_switching_context *context, gint64 now) {
	/* Reset values if a new ssrc has been detected */
	if (context->v_new_ssrc) {
		JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" resetting status\n", context->v_last_ssrc);
		context->v_reference_time = now;
		context->v_start_time = 0;
		context->v_evaluating_start_time = 0;
		context->v_start_ts = 0;
		context->v_active_delay = 0;
		context->v_prev_delay = 0;
		context->v_seq_offset = 0;
		context->v_ts_offset = 0;
		context->v_target_ts = 0;
		context->v_new_ssrc = FALSE;
	}

	/* N 	: a N sequence numbers jump has been performed */
	/* 0  	: any new skew compensation has been applied */
	/* -N  	: a N packets drop must be performed */
	int exit_status = 0;

	/* Do not execute skew analysis in the first seconds */
	if (now-context->v_reference_time < SKEW_DETECTION_WAIT_TIME_SECS/2 *G_USEC_PER_SEC) {
		return 0;
	} else if (!context->v_start_time) {
		JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase start\n", context->v_last_ssrc);
		context->v_start_time = now;
		context->v_evaluating_start_time = now;
		context->v_start_ts = context->v_last_ts;
	}

	/* Skew analysis */
	/* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
	if (context->v_target_ts > 0 && (gint32)(context->v_target_ts - context->v_last_ts) > 0) {
		context->v_seq_offset--;
		exit_status = -1;
	} else {
		context->v_target_ts = 0;
		/* Do not execute analysis for out of order packets or multi-packets frame */
		if (context->v_last_seq == context->v_prev_seq + 1 && context->v_last_ts != context->v_prev_ts) {
			/* Set the sample rate */
			guint32 vkhz = 90; /* 90khz */
			/* Evaluate the local RTP timestamp according to the local clock */
			guint32 expected_ts = ((now - context->v_start_time)*vkhz)/1000 + context->v_start_ts;
			/* Evaluate current delay */
			gint32 delay_now = context->v_last_ts - expected_ts;
			/* Exponentially weighted moving average estimation */
			gint32 delay_estimate = (63*context->v_prev_delay + delay_now)/64;
			/* Save previous delay for the next iteration*/
			context->v_prev_delay = delay_estimate;
			/* Evaluate the distance between active delay and current delay estimate */
			gint32 offset = context->v_active_delay - delay_estimate;
			JANUS_LOG(LOG_HUGE, "video skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16"\n", context->v_last_ssrc, context->v_last_ts, expected_ts, offset, context->v_ts_offset, context->v_seq_offset);
			gint32 skew_th = RTP_VIDEO_SKEW_TH_MS*vkhz;
			/* Evaluation phase */
			if (context->v_evaluating_start_time > 0) {
				/* Check if the offset has surpassed half the threshold during the evaluating phase */
				if (now-context->v_evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
					if (abs(offset) <= skew_th/2) {
						JANUS_LOG(LOG_HUGE, "video skew SSRC=%"SCNu32" evaluation phase continue\n", context->v_last_ssrc);
					} else {
						JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase reset\n", context->v_last_ssrc);
						context->v_start_time = now;
						context->v_evaluating_start_time = now;
						context->v_start_ts = context->v_last_ts;
					}
				} else {
					JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase stop\n", context->v_last_ssrc);
					context->v_evaluating_start_time = 0;
				}
				return 0;
			}
			/* Check if the offset has surpassed the threshold */
			if (offset >= skew_th) {
				/* The source is slowing down */
				/* Update active delay */
				context->v_active_delay = delay_estimate;
				/* Adjust ts offset */
				context->v_ts_offset += skew_th;
				/* Calculate last ts increase */
				guint32 ts_incr = context->v_last_ts-context->v_prev_ts;
				/* Evaluate sequence number jump */
				guint16 jump = (skew_th+ts_incr-1)/ts_incr;
				/* Adjust seq num offset */
				context->v_seq_offset += jump;
				exit_status = jump;
			} else if (offset <= -skew_th) {
				/* The source is speeding up*/
				/* Update active delay */
				context->v_active_delay = delay_estimate;
				/* Adjust ts offset */
				context->v_ts_offset -= skew_th;
				/* Set target ts */
				context->v_target_ts = context->v_last_ts + skew_th;
				if (context->v_target_ts == 0)
					context->v_target_ts = 1;
				/* Adjust seq num offset */
				context->v_seq_offset--;
				exit_status = -1;
			}
		}
	}

	/* Skew compensation */
	/* Fix header timestamp considering the active offset */
	guint32 fixed_rtp_ts = context->v_last_ts + context->v_ts_offset;
	header->timestamp = htonl(fixed_rtp_ts);
	/* Fix header sequence number considering the total offset */
	guint16 fixed_rtp_seq = context->v_last_seq + context->v_seq_offset;
	header->seq_number = htons(fixed_rtp_seq);

	return exit_status;
}

void janus_rtp_header_update(janus_rtp_header *header, janus_rtp_switching_context *context, gboolean video, int step) {
	if(header == NULL || context == NULL)
		return;
	/* Note: while the step property is still there for compatibility reasons, to
	 * keep the signature as it was before, it's ignored: whenever there's a switch
	 * to take into account, we compute how much time passed between the last RTP
	 * packet with the old SSRC and this new one, and prepare a timestamp accordingly */
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
			/* How much time since the last video RTP packet? We compute an offset accordingly */
			if(context->v_last_time > 0) {
				gint64 time_diff = janus_get_monotonic_time() - context->v_last_time;
				time_diff = (time_diff*90)/1000; 	/* We're assuming 90khz here */
				if(time_diff == 0)
					time_diff = 1;
				context->v_base_ts_prev += (guint32)time_diff;
				context->v_last_ts += (guint32)time_diff;
				JANUS_LOG(LOG_VERB, "Computed offset for video RTP timestamp: %"SCNu32"\n", (guint32)time_diff);
			}
			/* Reset skew compensation data */
			context->v_new_ssrc = TRUE;
		}
		if(context->v_seq_reset) {
			/* Video sequence number was paused for a while: just update that */
			context->v_seq_reset = FALSE;
			context->v_base_seq_prev = context->v_last_seq;
			context->v_base_seq = seq;
		}
		/* Compute a coherent timestamp and sequence number */
		context->v_prev_ts = context->v_last_ts;
		context->v_last_ts = (timestamp-context->v_base_ts) + context->v_base_ts_prev;
		context->v_prev_seq = context->v_last_seq;
		context->v_last_seq = (seq-context->v_base_seq)+context->v_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet */
		header->timestamp = htonl(context->v_last_ts);
		header->seq_number = htons(context->v_last_seq);
		/* Take note of when we last handled this RTP packet */
		context->v_last_time = janus_get_monotonic_time();
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
			/* How much time since the last audio RTP packet? We compute an offset accordingly */
			if(context->a_last_time > 0) {
				gint64 time_diff = janus_get_monotonic_time() - context->a_last_time;
				int akhz = 48;
				if(header->type == 0 || header->type == 8 || header->type == 9)
					akhz = 8;	/* We're assuming 48khz here (Opus), unless it's G.711/G.722 (8khz) */
				time_diff = (time_diff*akhz)/1000;
				if(time_diff == 0)
					time_diff = 1;
				context->a_base_ts_prev += (guint32)time_diff;
				context->a_prev_ts += (guint32)time_diff;
				context->a_last_ts += (guint32)time_diff;
				JANUS_LOG(LOG_VERB, "Computed offset for audio RTP timestamp: %"SCNu32"\n", (guint32)time_diff);
			}
			/* Reset skew compensation data */
			context->a_new_ssrc = TRUE;
		}
		if(context->a_seq_reset) {
			/* Audio sequence number was paused for a while: just update that */
			context->a_seq_reset = FALSE;
			context->a_base_seq_prev = context->a_last_seq;
			context->a_base_seq = seq;
		}
		/* Compute a coherent timestamp and sequence number */
		context->a_prev_ts = context->a_last_ts;
		context->a_last_ts = (timestamp-context->a_base_ts) + context->a_base_ts_prev;
		context->a_prev_seq = context->a_last_seq;
		context->a_last_seq = (seq-context->a_base_seq)+context->a_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet */
		header->timestamp = htonl(context->a_last_ts);
		header->seq_number = htons(context->a_last_seq);
		/* Take note of when we last handled this RTP packet */
		context->a_last_time = janus_get_monotonic_time();
	}
}


/* SRTP stuff: we may need our own randomizer */
#ifdef HAVE_SRTP_2
int srtp_crypto_get_random(uint8_t *key, int len) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* libsrtp 2.0 doesn't have crypto_get_random, we use OpenSSL's RAND_* to replace it:
	 * 		https://wiki.openssl.org/index.php/Random_Numbers */
	int rc = RAND_bytes(key, len);
	if(rc != 1) {
		/* Error generating */
		return -1;
	}
#endif
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

/* Payload types we'll offer internally */
#define OPUS_PT		111
#define ISAC32_PT	104
#define ISAC16_PT	103
#define PCMU_PT		0
#define PCMA_PT		8
#define G722_PT		9
#define VP8_PT		96
#define VP9_PT		101
#define H264_PT		107
const char *janus_audiocodec_name(janus_audiocodec acodec) {
	switch(acodec) {
		case JANUS_AUDIOCODEC_NONE:
			return "none";
		case JANUS_AUDIOCODEC_OPUS:
			return "opus";
		case JANUS_AUDIOCODEC_PCMU:
			return "pcmu";
		case JANUS_AUDIOCODEC_PCMA:
			return "pcma";
		case JANUS_AUDIOCODEC_G722:
			return "g722";
		case JANUS_AUDIOCODEC_ISAC_32K:
			return "isac32";
		case JANUS_AUDIOCODEC_ISAC_16K:
			return "isac16";
		default:
			/* Shouldn't happen */
			return "opus";
	}
}
janus_audiocodec janus_audiocodec_from_name(const char *name) {
	if(name == NULL)
		return JANUS_AUDIOCODEC_NONE;
	else if(!strcasecmp(name, "opus"))
		return JANUS_AUDIOCODEC_OPUS;
	else if(!strcasecmp(name, "isac32"))
		return JANUS_AUDIOCODEC_ISAC_32K;
	else if(!strcasecmp(name, "isac16"))
		return JANUS_AUDIOCODEC_ISAC_16K;
	else if(!strcasecmp(name, "pcmu"))
		return JANUS_AUDIOCODEC_PCMU;
	else if(!strcasecmp(name, "pcma"))
		return JANUS_AUDIOCODEC_PCMA;
	else if(!strcasecmp(name, "g722"))
		return JANUS_AUDIOCODEC_G722;
	JANUS_LOG(LOG_WARN, "Unsupported audio codec '%s'\n", name);
	return JANUS_AUDIOCODEC_NONE;
}
int janus_audiocodec_pt(janus_audiocodec acodec) {
	switch(acodec) {
		case JANUS_AUDIOCODEC_NONE:
			return -1;
		case JANUS_AUDIOCODEC_OPUS:
			return OPUS_PT;
		case JANUS_AUDIOCODEC_ISAC_32K:
			return ISAC32_PT;
		case JANUS_AUDIOCODEC_ISAC_16K:
			return ISAC16_PT;
		case JANUS_AUDIOCODEC_PCMU:
			return PCMU_PT;
		case JANUS_AUDIOCODEC_PCMA:
			return PCMA_PT;
		case JANUS_AUDIOCODEC_G722:
			return G722_PT;
		default:
			/* Shouldn't happen */
			return OPUS_PT;
	}
}

const char *janus_videocodec_name(janus_videocodec vcodec) {
	switch(vcodec) {
		case JANUS_VIDEOCODEC_NONE:
			return "none";
		case JANUS_VIDEOCODEC_VP8:
			return "vp8";
		case JANUS_VIDEOCODEC_VP9:
			return "vp9";
		case JANUS_VIDEOCODEC_H264:
			return "h264";
		default:
			/* Shouldn't happen */
			return "vp8";
	}
}
janus_videocodec janus_videocodec_from_name(const char *name) {
	if(name == NULL)
		return JANUS_VIDEOCODEC_NONE;
	else if(!strcasecmp(name, "vp8"))
		return JANUS_VIDEOCODEC_VP8;
	else if(!strcasecmp(name, "vp9"))
		return JANUS_VIDEOCODEC_VP9;
	else if(!strcasecmp(name, "h264"))
		return JANUS_VIDEOCODEC_H264;
	JANUS_LOG(LOG_WARN, "Unsupported video codec '%s'\n", name);
	return JANUS_VIDEOCODEC_NONE;
}
int janus_videocodec_pt(janus_videocodec vcodec) {
	switch(vcodec) {
		case JANUS_VIDEOCODEC_NONE:
			return -1;
		case JANUS_VIDEOCODEC_VP8:
			return VP8_PT;
		case JANUS_VIDEOCODEC_VP9:
			return VP9_PT;
		case JANUS_VIDEOCODEC_H264:
			return H264_PT;
		default:
			/* Shouldn't happen */
			return VP8_PT;
	}
}

void janus_rtp_simulcasting_context_reset(janus_rtp_simulcasting_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	memset(context, 0, sizeof(*context));
	context->substream = -1;
	context->templayer = -1;
}

gboolean janus_rtp_simulcasting_context_process_rtp(janus_rtp_simulcasting_context *context,
		char *buf, int len, uint32_t *ssrcs, janus_videocodec vcodec, janus_rtp_switching_context *sc) {
	if(!context || !buf || len < 1)
		return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	uint32_t ssrc = ntohl(header->ssrc);
	/* Reset the flags */
	context->changed_substream = FALSE;
	context->changed_temporal = FALSE;
	context->need_pli = FALSE;
	/* Access the packet payload */
	int plen = 0;
	char *payload = janus_rtp_payload(buf, len, &plen);
	if(payload == NULL)
		return FALSE;
	if(context->substream != context->substream_target) {
		/* There has been a change: let's wait for a keyframe on the target */
		int step = (context->substream < 1 && context->substream_target == 2);
		if((ssrc == *(ssrcs + context->substream_target)) || (step && ssrc == *(ssrcs + step))) {
			if((vcodec == JANUS_VIDEOCODEC_VP8 && janus_vp8_is_keyframe(payload, plen)) ||
					(vcodec == JANUS_VIDEOCODEC_H264 && janus_h264_is_keyframe(payload, plen))) {
				uint32_t ssrc_old = 0;
				if(context->substream != -1)
					ssrc_old = *(ssrcs + context->substream);
				JANUS_LOG(LOG_VERB, "Received keyframe on SSRC %"SCNu32", switching (was %"SCNu32")\n", ssrc, ssrc_old);
				context->substream = (ssrc == *(ssrcs + context->substream_target) ? context->substream_target : step);
				/* Notify the caller that the substream changed */
				context->changed_substream = TRUE;
			//~ } else {
				//~ JANUS_LOG(LOG_WARN, "Not a keyframe on SSRC %"SCNu32" yet, waiting before switching\n", ssrc);
			}
		}
	}
	/* If we haven't received our desired substream yet, let's drop temporarily */
	if(context->last_relayed == 0) {
		/* Let's start slow */
		context->last_relayed = janus_get_monotonic_time();
	} else {
		/* Check if 250ms went by with no packet relayed */
		gint64 now = janus_get_monotonic_time();
		if(now-context->last_relayed >= 250000) {
			context->last_relayed = now;
			int substream = context->substream-1;
			if(substream < 0)
				substream = 0;
			if(context->substream != substream) {
				JANUS_LOG(LOG_WARN, "No packet received on substream %d for a while, falling back to %d\n",
					context->substream, substream);
				context->substream = substream;
				/* Notify the caller that we need a PLI */
				context->need_pli = TRUE;
				/* Notify the caller that the substream changed as well */
				context->changed_substream = TRUE;
			}
		}
	}
	/* Do we need to drop this? */
	if(ssrc != *(ssrcs + context->substream)) {
		JANUS_LOG(LOG_HUGE, "Dropping packet (it's from SSRC %"SCNu32", but we're only relaying SSRC %"SCNu32" now\n",
			ssrc, *(ssrcs + context->substream));
		return FALSE;
	}
	context->last_relayed = janus_get_monotonic_time();
	/* Temporal layers are only available for VP8, so don't do anything else for other codecs */
	if(vcodec == JANUS_VIDEOCODEC_VP8) {
		/* Check if there's any temporal scalability to take into account */
		uint16_t picid = 0;
		uint8_t tlzi = 0;
		uint8_t tid = 0;
		uint8_t ybit = 0;
		uint8_t keyidx = 0;
		if(janus_vp8_parse_descriptor(payload, plen, &picid, &tlzi, &tid, &ybit, &keyidx) == 0) {
			//~ JANUS_LOG(LOG_WARN, "%"SCNu16", %u, %u, %u, %u\n", picid, tlzi, tid, ybit, keyidx);
			if(context->templayer != context->templayer_target && tid == context->templayer_target) {
				/* FIXME We should be smarter in deciding when to switch */
				context->templayer = context->templayer_target;
				/* Notify the caller that the temporal layer changed */
				context->changed_temporal = TRUE;
			}
			if(tid > context->templayer) {
				JANUS_LOG(LOG_HUGE, "Dropping packet (it's temporal layer %d, but we're capping at %d)\n",
					tid, context->templayer);
				/* We increase the base sequence number, or there will be gaps when delivering later */
				if(sc)
					sc->v_base_seq++;
				return FALSE;
			}
		}
	}
	/* If we got here, the packet can be relayed */
	return TRUE;
}
