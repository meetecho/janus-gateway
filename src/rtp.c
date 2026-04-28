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

/* Local, private, structures for parsing video-layers-allocation extensions */
typedef struct janus_rtp_vla_spatial_layer {
	uint8_t id;
	uint8_t tls;
} janus_rtp_vla_spatial_layer;

typedef struct janus_rtp_vla_rtp_stream {
	uint8_t rid;
	uint8_t sl_bm;
	janus_rtp_vla_spatial_layer sl[4];
} janus_rtp_vla_rtp_stream;

/* Public methods */
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
		janus_rtp_header_extension *ext = (janus_rtp_header_extension *)(buf+hlen);
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
				if(sscanf(line, extmap, &id) == 1) {
#pragma GCC diagnostic pop
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
				if(sscanf(line, "a=extmap:%d %99s", &id, extension) == 2) {
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
					if(strstr(extension, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME))
						return JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME;
					if(strstr(extension, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
						return JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC;
					if(strstr(extension, JANUS_RTP_EXTMAP_MID))
						return JANUS_RTP_EXTMAP_MID;
					if(strstr(extension, JANUS_RTP_EXTMAP_RID))
						return JANUS_RTP_EXTMAP_RID;
					if(strstr(extension, JANUS_RTP_EXTMAP_REPAIRED_RID))
						return JANUS_RTP_EXTMAP_REPAIRED_RID;
					if(strstr(extension, JANUS_RTP_EXTMAP_DEPENDENCY_DESC))
						return JANUS_RTP_EXTMAP_DEPENDENCY_DESC;
					if(strstr(extension, JANUS_RTP_EXTMAP_VIDEO_LAYERS))
						return JANUS_RTP_EXTMAP_VIDEO_LAYERS;
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
		uint8_t *byte, uint32_t *word, char **ref, uint8_t *idlen) {
	if(idlen == NULL)
		return -1;
	*idlen = 0;
	if(!buf || len < 12)
		return -2;
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	if(rtp->version != 2) {
		return -3;
	}
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension && (len > hlen + (int)sizeof(janus_rtp_header_extension))) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension *)(buf+hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(len > (hlen + extlen)) {
			if(ntohs(ext->type) == 0xBEDE) {
				/* 1-Byte extension */
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0;
				int i = 0;
				while(i < extlen) {
					extid = (uint8_t)buf[hlen+i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					*idlen = ((uint8_t)buf[hlen+i] & 0xF)+1;
					i++;
					if(extid == id && ((i+*idlen) <= extlen)) {
						/* Found! */
						if(byte)
							*byte = (uint8_t)buf[hlen+i];
						if(word && *idlen >= 4 && (i+4) < extlen) {
							memcpy(word, buf+hlen+i, sizeof(uint32_t));
							*word = ntohl(*word);
						}
						if(ref)
							*ref = &buf[hlen+i];
						return 0;
					}
					i += *idlen;
				}
			} else if(ntohs(ext->type) == 0x1000) {
				/* 2-Byte extension */
				const uint8_t padding = 0x00;
				uint8_t extid = 0;
				int i = 0;
				while(i < extlen) {
					if((extlen-i) < 2)
						break;
					extid = buf[hlen+i];
					if(extid == padding) {
						i += 2;
						continue;
					}
					i++;
					*idlen = buf[hlen+i];
					i++;
					if(extid == id && ((i+*idlen) <= extlen)) {
						/* Found! */
						if(byte)
							*byte = (uint8_t)buf[hlen+i];
						if(word && *idlen >= 4 && (i+4) < extlen) {
							memcpy(word, buf+hlen+i, sizeof(uint32_t));
							*word = ntohl(*word);
						}
						if(ref)
							*ref = &buf[hlen+i];
						return 0;
					}
					i += *idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -1;
}

int janus_rtp_header_extension_parse_audio_level(char *buf, int len, int id, gboolean *vad, int *level) {
	uint8_t byte = 0, idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL, &idlen) < 0)
		return -1;
	/* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
	gboolean v = (byte & 0x80) >> 7;
	int value = byte & 0x7F;
	JANUS_LOG(LOG_DBG, "%02x --> v=%d, level=%d\n", byte, v, value);
	if(vad)
		*vad = v;
	if(level)
		*level = value;
	return 0;
}

int janus_rtp_header_extension_parse_video_orientation(char *buf, int len, int id,
		gboolean *c, gboolean *f, gboolean *r1, gboolean *r0) {
	uint8_t byte = 0, idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL, NULL, &idlen) < 0)
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
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, &bytes, NULL, &idlen) < 0)
		return -1;
	if(idlen < 3)
		return -2;
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
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid */
	if(ext == NULL || idlen < 1)
		return -2;
	if(idlen > (sdes_len-1)) {
		JANUS_LOG(LOG_WARN, "Buffer is too small (%d > %d), MID will be cut\n", idlen, sdes_len);
		idlen = sdes_len-1;
	}
	if(idlen > len-(ext-buf)-1) {
		return -3;
	}
	memcpy(sdes_item, ext, idlen);
	*(sdes_item+idlen) = '\0';
	return 0;
}

int janus_rtp_header_extension_parse_rid(char *buf, int len, int id,
		char *sdes_item, int sdes_len) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id */
	/* a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id */
	if(ext == NULL || idlen < 1)
		return -2;
	if(idlen > (sdes_len-1)) {
		JANUS_LOG(LOG_WARN, "Buffer is too small (%d > %d), RTP stream ID will be cut\n", idlen, sdes_len);
		idlen = sdes_len-1;
	}
	if(idlen > len-(ext-buf)-1) {
		return -3;
	}
	memcpy(sdes_item, ext, idlen);
	*(sdes_item+idlen) = '\0';
	return 0;
}

int janus_rtp_header_extension_parse_dependency_desc(char *buf, int len, int id,
		uint8_t *dd_item, int *dd_len) {
	char *ext = NULL;
	uint8_t idlen = 0;
	int buflen = *dd_len;
	*dd_len = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:10 https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension */
	if(ext == NULL || idlen < 1)
		return -2;
	if(idlen > buflen) {
		JANUS_LOG(LOG_WARN, "Buffer is too small (%d > %d), dependency descriptor will be cut\n", idlen, buflen);
		idlen = buflen;
	}
	if(idlen > len-(ext-buf)-1) {
		return -3;
	}
	memcpy(dd_item, ext, idlen);
	*dd_len = idlen;
	return 0;
}

int janus_rtp_header_extension_parse_abs_send_time(char *buf, int len, int id, uint32_t *abs_ts) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time */
	if(ext == NULL)
		return -2;
	if(idlen < 3 || idlen > len-(ext-buf)-1)
		return -3;
	uint32_t abs24 = 0;
	memcpy(&abs24, ext, 3);
	if(abs_ts)
		*abs_ts = ntohl(abs24 << 8);
	return 0;
}

int janus_rtp_header_extension_set_abs_send_time(char *buf, int len, int id, uint32_t abs_ts) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	if(ext == NULL)
		return -2;
	if(idlen < 3 || idlen > len-(ext-buf)-1)
		return -3;
	uint32_t abs24 = htonl(abs_ts) >> 8;
	memcpy(ext, &abs24, 3);
	return 0;
}

int janus_rtp_header_extension_parse_abs_capture_time(char *buf, int len, int id, uint64_t *abs_ts) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time */
	if(ext == NULL)
		return -2;
	if(idlen < 8 || idlen > len-(ext-buf)-1)
		return -3;
	uint64_t abs64 = 0;
	memcpy(&abs64, ext, 8);
	if(abs_ts)
		*abs_ts = ntohll(abs64);
	return 0;
}

int janus_rtp_header_extension_set_abs_capture_time(char *buf, int len, int id, uint64_t abs_ts) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	if(ext == NULL)
		return -2;
	if(idlen < 8 || idlen > len-(ext-buf)-1)
		return -3;
	uint64_t abs64 = htonll(abs_ts);
	memcpy(ext, &abs64, 8);
	return 0;
}

int janus_rtp_header_extension_parse_transport_wide_cc(char *buf, int len, int id, uint16_t *transSeqNum) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/*  0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  ID   | L=1   |transport-wide sequence number | zero padding  |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if(ext == NULL)
		return -2;
	if(idlen < 2 || idlen > len-(ext-buf)-1)
		return -3;
	memcpy(transSeqNum, ext, sizeof(uint16_t));
	*transSeqNum = ntohs(*transSeqNum);
	return 0;
}

int janus_rtp_header_extension_set_transport_wide_cc(char *buf, int len, int id, uint16_t transSeqNum) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	if(ext == NULL)
		return -2;
	if(idlen < 2 || idlen > len-(ext-buf)-1)
		return -3;
	transSeqNum = htons(transSeqNum);
	memcpy(ext, &transSeqNum, sizeof(uint16_t));
	return 0;
}

int janus_rtp_header_extension_parse_video_layers_allocation(char *buf, int len, int id,
		int8_t *spatial_layers, int8_t *temporal_layers) {
	char *ext = NULL;
	uint8_t idlen = 0;
	if(janus_rtp_header_extension_find(buf, len, id, NULL, NULL, &ext, &idlen) < 0)
		return -1;
	/* a=extmap:9 http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00 */
	if(ext == NULL || idlen < 2)
		return -2;
	/* Parse the extension to reconstruct the layers topology */
	janus_rtp_vla_rtp_stream streams[4] = { 0 };
	/* First byte */
	uint8_t offset = 0;
	uint8_t ns = (ext[offset] & 0x30) >> 4;
	uint8_t sl_bm = ext[offset] & 0x0F;
	offset++;
	/* Spatial layer bitmasks (up to two bytes) */
	uint8_t i = 0;
	for(i=0; i<=ns; i++) {
		if(sl_bm > 0) {
			/* Copy the shared value */
			streams[i].sl_bm = sl_bm;
		} else {
			if(i == 2) {
				offset++;
				if(offset == idlen)
					return -3;
			}
			if(i % 2 == 0) {
				streams[i].sl_bm = (ext[offset] & 0xF0) >> 4;
			} else {
				streams[i].sl_bm = ext[offset] & 0x0F;
			}
		}
	}
	if(sl_bm == 0)
		offset++;
	if(offset == idlen)
		return -3;
	/* Temporal layers (one byte) */
	uint8_t j = 0, boff = 8, sl = 0, tl = 0;
	for(i=0; i<=ns; i++) {
		sl = 0;
		for(j=0; j<4; j++) {
			if((streams[i].sl_bm & (1 << j)) == 0)
				continue;
			sl++;
			boff -= 2;
			streams[i].sl[j].id = j;
			streams[i].sl[j].tls = (ext[offset] >> boff) & 0x03;
			tl = streams[i].sl[j].tls + 1;
			if(temporal_layers && tl > *temporal_layers)
				*temporal_layers = tl;
			if(boff == 0) {
				boff = 8;
				offset++;
				if(offset == idlen)
					return -3;
			}
		}
		if(spatial_layers && sl > *spatial_layers)
			*spatial_layers = sl;
	}
	/* Done, we don't care about bitrates and resolutions for now */
	return 0;
}

int janus_rtp_header_extension_replace_id(char *buf, int len, int id, int new_id) {
	if(!buf || len < 12)
		return -1;
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	if (rtp->version != 2) {
		return -2;
	}
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension *)(buf+hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(len > (hlen + extlen)) {
			if(ntohs(ext->type) == 0xBEDE) {
				/* 1-Byte extension */
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen = 0;
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
						buf[hlen+i] = (new_id << 4) + (idlen - 1);
						return 0;
					}
					i += 1 + idlen;
				}
			} if(ntohs(ext->type) == 0x1000) {
				/* 2-Byte extension */
				const uint8_t padding = 0x00;
				uint8_t extid = 0, idlen = 0;
				int i = 0;
				while(i < extlen) {
					if((extlen-i) < 2)
						break;
					extid = buf[hlen+i];
					if(extid == padding) {
						i += 2;
						continue;
					}
					if(extid == id) {
						/* Found! */
						buf[hlen+i] = new_id;
						return 0;
					}
					i++;
					idlen = buf[hlen+i];
					i += 1 + idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -3;
}

int janus_rtp_extension_id(const char *type) {
	if(type == NULL)
		return 0;
	if(!strcasecmp(type, JANUS_RTP_EXTMAP_AUDIO_LEVEL))
		return 1;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_TOFFSET))
		return 14;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_ABS_SEND_TIME))
		return 2;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME))
		return 7;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION))
		return 13;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
		return 3;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_PLAYOUT_DELAY))
		return 12;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_MID))
		return 4;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_RID))
		return 5;
	else if(!strcasecmp(type, JANUS_RTP_EXTMAP_REPAIRED_RID))
		return 6;
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
	if(context->new_ssrc) {
		JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" resetting status\n", context->last_ssrc);
		context->reference_time = now;
		context->start_time = 0;
		context->evaluating_start_time = 0;
		context->start_ts = 0;
		context->active_delay = 0;
		context->prev_delay = 0;
		context->seq_offset = 0;
		context->ts_offset = 0;
		context->target_ts = 0;
		context->new_ssrc = FALSE;
	}

	/* N 	: a N sequence number jump has been performed */
	/* 0  	: any new skew compensation has been applied */
	/* -N  	: a N packet drop must be performed */
	int exit_status = 0;

	/* Do not execute skew analysis in the first seconds */
	if(now-context->reference_time < SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
		return 0;
	} else if(!context->start_time) {
		JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase start\n", context->last_ssrc);
		context->start_time = now;
		context->evaluating_start_time = now;
		context->start_ts = context->last_ts;
	}

	/* Skew analysis */
	/* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
	if(context->target_ts > 0 && (gint32)(context->target_ts - context->last_ts) > 0) {
		context->seq_offset--;
		exit_status = -1;
	} else {
		context->target_ts = 0;
		/* Do not execute analysis for out of order packets or multi-packets frame */
		if(context->last_seq == context->prev_seq + 1 && context->last_ts != context->prev_ts) {
			/* Set the sample rate according to the header */
			guint32 akhz = 48; /* 48khz for Opus */
			if(header->type == 0 || header->type == 8 || header->type == 9)
				akhz = 8;
			/* Evaluate the local RTP timestamp according to the local clock */
			guint32 expected_ts = ((now - context->start_time)*akhz)/1000 + context->start_ts;
			/* Evaluate current delay */
			gint32 delay_now = context->last_ts - expected_ts;
			/* Exponentially weighted moving average estimation */
			gint32 delay_estimate = (63*context->prev_delay + delay_now)/64;
			/* Save previous delay for the next iteration*/
			context->prev_delay = delay_estimate;
			/* Evaluate the distance between active delay and current delay estimate */
			gint32 offset = context->active_delay - delay_estimate;
			JANUS_LOG(LOG_HUGE, "audio skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16"\n", context->last_ssrc, context->last_ts, expected_ts, offset, context->ts_offset, context->seq_offset);
			gint32 skew_th = RTP_AUDIO_SKEW_TH_MS*akhz;
			/* Evaluation phase */
			if(context->evaluating_start_time > 0) {
				/* Check if the offset has surpassed half the threshold during the evaluating phase */
				if(now-context->evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
					if(abs(offset) <= skew_th/2) {
						JANUS_LOG(LOG_HUGE, "audio skew SSRC=%"SCNu32" evaluation phase continue\n", context->last_ssrc);
					} else {
						JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase reset\n", context->last_ssrc);
						context->start_time = now;
						context->evaluating_start_time = now;
						context->start_ts = context->last_ts;
					}
				} else {
					JANUS_LOG(LOG_VERB, "audio skew SSRC=%"SCNu32" evaluation phase stop\n", context->last_ssrc);
					context->evaluating_start_time = 0;
				}
				return 0;
			}
			/* Check if the offset has surpassed the threshold */
			if(offset >= skew_th) {
				/* The source is slowing down */
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset += skew_th;
				/* Calculate last ts increase */
				guint32 ts_incr = context->last_ts-context->prev_ts;
				/* Evaluate sequence number jump */
				guint16 jump = (skew_th+ts_incr-1)/ts_incr;
				/* Adjust seq num offset */
				context->seq_offset += jump;
				exit_status = jump;
			} else if(offset <= -skew_th) {
				/* The source is speeding up*/
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset -= skew_th;
				/* Set target ts */
				context->target_ts = context->last_ts + skew_th;
				if (context->target_ts == 0)
					context->target_ts = 1;
				/* Adjust seq num offset */
				context->seq_offset--;
				exit_status = -1;
			}
		}
	}

	/* Skew compensation */
	/* Fix header timestamp considering the active offset */
	guint32 fixed_rtp_ts = context->last_ts + context->ts_offset;
	header->timestamp = htonl(fixed_rtp_ts);
	/* Fix header sequence number considering the total offset */
	guint16 fixed_rtp_seq = context->last_seq + context->seq_offset;
	header->seq_number = htons(fixed_rtp_seq);

	return exit_status;
}

int janus_rtp_skew_compensate_video(janus_rtp_header *header, janus_rtp_switching_context *context, gint64 now) {
	/* Reset values if a new ssrc has been detected */
	if(context->new_ssrc) {
		JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" resetting status\n", context->last_ssrc);
		context->reference_time = now;
		context->start_time = 0;
		context->evaluating_start_time = 0;
		context->start_ts = 0;
		context->active_delay = 0;
		context->prev_delay = 0;
		context->seq_offset = 0;
		context->ts_offset = 0;
		context->target_ts = 0;
		context->new_ssrc = FALSE;
	}

	/* N 	: a N sequence numbers jump has been performed */
	/* 0  	: any new skew compensation has been applied */
	/* -N  	: a N packets drop must be performed */
	int exit_status = 0;

	/* Do not execute skew analysis in the first seconds */
	if(now-context->reference_time < SKEW_DETECTION_WAIT_TIME_SECS/2 *G_USEC_PER_SEC) {
		return 0;
	} else if(!context->start_time) {
		JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase start\n", context->last_ssrc);
		context->start_time = now;
		context->evaluating_start_time = now;
		context->start_ts = context->last_ts;
	}

	/* Skew analysis */
	/* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
	if(context->target_ts > 0 && (gint32)(context->target_ts - context->last_ts) > 0) {
		context->seq_offset--;
		exit_status = -1;
	} else {
		context->target_ts = 0;
		/* Do not execute analysis for out of order packets or multi-packets frame */
		if(context->last_seq == context->prev_seq + 1 && context->last_ts != context->prev_ts) {
			/* Set the sample rate */
			guint32 vkhz = 90; /* 90khz */
			/* Evaluate the local RTP timestamp according to the local clock */
			guint32 expected_ts = ((now - context->start_time)*vkhz)/1000 + context->start_ts;
			/* Evaluate current delay */
			gint32 delay_now = context->last_ts - expected_ts;
			/* Exponentially weighted moving average estimation */
			gint32 delay_estimate = (63*context->prev_delay + delay_now)/64;
			/* Save previous delay for the next iteration*/
			context->prev_delay = delay_estimate;
			/* Evaluate the distance between active delay and current delay estimate */
			gint32 offset = context->active_delay - delay_estimate;
			JANUS_LOG(LOG_HUGE, "video skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16"\n", context->last_ssrc, context->last_ts, expected_ts, offset, context->ts_offset, context->seq_offset);
			gint32 skew_th = RTP_VIDEO_SKEW_TH_MS*vkhz;
			/* Evaluation phase */
			if(context->evaluating_start_time > 0) {
				/* Check if the offset has surpassed half the threshold during the evaluating phase */
				if(now-context->evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS/2 * G_USEC_PER_SEC) {
					if(abs(offset) <= skew_th/2) {
						JANUS_LOG(LOG_HUGE, "video skew SSRC=%"SCNu32" evaluation phase continue\n", context->last_ssrc);
					} else {
						JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase reset\n", context->last_ssrc);
						context->start_time = now;
						context->evaluating_start_time = now;
						context->start_ts = context->last_ts;
					}
				} else {
					JANUS_LOG(LOG_VERB, "video skew SSRC=%"SCNu32" evaluation phase stop\n", context->last_ssrc);
					context->evaluating_start_time = 0;
				}
				return 0;
			}
			/* Check if the offset has surpassed the threshold */
			if(offset >= skew_th) {
				/* The source is slowing down */
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset += skew_th;
				/* Calculate last ts increase */
				guint32 ts_incr = context->last_ts-context->prev_ts;
				/* Evaluate sequence number jump */
				guint16 jump = (skew_th+ts_incr-1)/ts_incr;
				/* Adjust seq num offset */
				context->seq_offset += jump;
				exit_status = jump;
			} else if(offset <= -skew_th) {
				/* The source is speeding up*/
				/* Update active delay */
				context->active_delay = delay_estimate;
				/* Adjust ts offset */
				context->ts_offset -= skew_th;
				/* Set target ts */
				context->target_ts = context->last_ts + skew_th;
				if(context->target_ts == 0)
					context->target_ts = 1;
				/* Adjust seq num offset */
				context->seq_offset--;
				exit_status = -1;
			}
		}
	}

	/* Skew compensation */
	/* Fix header timestamp considering the active offset */
	guint32 fixed_rtp_ts = context->last_ts + context->ts_offset;
	header->timestamp = htonl(fixed_rtp_ts);
	/* Fix header sequence number considering the total offset */
	guint16 fixed_rtp_seq = context->last_seq + context->seq_offset;
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
	if(ssrc != context->last_ssrc) {
		/* Audio SSRC changed: update both sequence number and timestamp */
		JANUS_LOG(LOG_VERB, "SSRC changed, %"SCNu32" --> %"SCNu32"\n",
			context->last_ssrc, ssrc);
		context->last_ssrc = ssrc;
		context->ts_reset = TRUE;
		context->seq_reset = TRUE;
		/* Reset skew compensation data */
		context->new_ssrc = TRUE;
	}
	if(context->ts_reset) {
		/* RTP timestamp was paused for a while */
		JANUS_LOG(LOG_HUGE, "RTP timestamp reset requested\n");
		context->ts_reset = FALSE;
		context->base_ts_prev = context->last_ts;
		context->base_ts = timestamp;
		/* How much time since the last audio RTP packet? We compute an offset accordingly */
		if(context->last_time > 0) {
			gint64 time_diff = janus_get_monotonic_time() - context->last_time;
			/* We're assuming 90khz for video and 48khz for audio, here */
			int khz = video ? 90 : 48;
			if(!video && (header->type == 0 || header->type == 8 || header->type == 9))
				khz = 8;	/* We're assuming 48khz here (Opus), unless it's G.711/G.722 (8khz) */
			time_diff = (time_diff*khz)/1000;
			if(time_diff == 0)
				time_diff = 1;
			context->base_ts_prev += (guint32)time_diff;
			context->prev_ts += (guint32)time_diff;
			context->last_ts += (guint32)time_diff;
			JANUS_LOG(LOG_VERB, "Computed offset for RTP timestamp: %"SCNu32"\n", (guint32)time_diff);
		}
	}
	if(context->seq_reset) {
		/* Audio sequence number was paused for a while: just update that */
		context->seq_reset = FALSE;
		context->base_seq_prev = context->last_seq;
		context->base_seq = seq;
	}
	/* Compute a coherent timestamp and sequence number */
	context->prev_ts = context->last_ts;
	context->last_ts = (timestamp-context->base_ts) + context->base_ts_prev;
	context->prev_seq = context->last_seq;
	context->last_seq = (seq-context->base_seq)+context->base_seq_prev+1;
	/* Update the timestamp and sequence number in the RTP packet */
	header->timestamp = htonl(context->last_ts);
	header->seq_number = htons(context->last_seq);
	/* Take note of when we last handled this RTP packet */
	context->last_time = janus_get_monotonic_time();
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
#define MULTIOPUS_PT	OPUS_PT
#define OPUSRED_PT	120
#define ISAC32_PT	104
#define ISAC16_PT	103
#define PCMU_PT		0
#define PCMA_PT		8
#define G722_PT		9
#define L16_48_PT	105
#define L16_PT		106
#define VP8_PT		96
#define VP9_PT		101
#define H264_PT		107
#define AV1_PT		98
#define H265_PT		100
const char *janus_audiocodec_name(janus_audiocodec acodec) {
	switch(acodec) {
		case JANUS_AUDIOCODEC_NONE:
			return "none";
		case JANUS_AUDIOCODEC_OPUS:
			return "opus";
		case JANUS_AUDIOCODEC_MULTIOPUS:
			return "multiopus";
		case JANUS_AUDIOCODEC_OPUSRED:
			return "red";
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
		case JANUS_AUDIOCODEC_L16_48K:
			return "l16-48";
		case JANUS_AUDIOCODEC_L16_16K:
			return "l16";
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
	else if(!strcasecmp(name, "multiopus"))
		return JANUS_AUDIOCODEC_MULTIOPUS;
	else if(!strcasecmp(name, "red"))
		return JANUS_AUDIOCODEC_OPUSRED;
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
	else if(!strcasecmp(name, "l16-48"))
		return JANUS_AUDIOCODEC_L16_48K;
	else if(!strcasecmp(name, "l16"))
		return JANUS_AUDIOCODEC_L16_16K;
	JANUS_LOG(LOG_WARN, "Unsupported audio codec '%s'\n", name);
	return JANUS_AUDIOCODEC_NONE;
}
int janus_audiocodec_pt(janus_audiocodec acodec) {
	switch(acodec) {
		case JANUS_AUDIOCODEC_NONE:
			return -1;
		case JANUS_AUDIOCODEC_OPUS:
			return OPUS_PT;
		case JANUS_AUDIOCODEC_MULTIOPUS:
			return MULTIOPUS_PT;
		case JANUS_AUDIOCODEC_OPUSRED:
			return OPUSRED_PT;
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
		case JANUS_AUDIOCODEC_L16_48K:
			return L16_48_PT;
		case JANUS_AUDIOCODEC_L16_16K:
			return L16_PT;
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
		case JANUS_VIDEOCODEC_AV1:
			return "av1";
		case JANUS_VIDEOCODEC_H265:
			return "h265";
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
	else if(!strcasecmp(name, "av1"))
		return JANUS_VIDEOCODEC_AV1;
	else if(!strcasecmp(name, "h265"))
		return JANUS_VIDEOCODEC_H265;
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
		case JANUS_VIDEOCODEC_AV1:
			return AV1_PT;
		case JANUS_VIDEOCODEC_H265:
			return H265_PT;
		default:
			/* Shouldn't happen */
			return VP8_PT;
	}
}

void janus_rtp_simulcasting_context_reset(janus_rtp_simulcasting_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	janus_av1_svc_context_reset(&context->av1_context[0]);
	janus_av1_svc_context_reset(&context->av1_context[1]);
	janus_av1_svc_context_reset(&context->av1_context[2]);
	memset(context, 0, sizeof(*context));
	context->rid_ext_id = -1;
	context->substream = -1;
	context->substream_target_temp = -1;
	context->templayer = -1;
}

void janus_rtp_simulcasting_prepare(json_t *simulcast, int *rid_ext_id, uint32_t *ssrcs, char **rids) {
	if(simulcast == NULL)
		return;
	json_t *r = json_object_get(simulcast, "rids");
	json_t *s = json_object_get(simulcast, "ssrcs");
	if(r && json_array_size(r) > 0) {
		JANUS_LOG(LOG_VERB, "  -- Simulcasting is rid based\n");
		size_t i = 0;
		int count = json_array_size(r);
		for(i=count; i > 0; i--) {
			json_t *rid = json_array_get(r, i-1);
			if(rid && json_is_string(rid) && rids)
				rids[count-i] = g_strdup(json_string_value(rid));
		}
		json_t *rid_ext = json_object_get(simulcast, "rid-ext");
		if(rid_ext_id != NULL)
			*rid_ext_id = json_integer_value(rid_ext);
	} else if(s && json_array_size(s) > 0) {
		JANUS_LOG(LOG_VERB, "  -- Simulcasting is SSRC based\n");
		size_t i = 0;
		for(i=0; i<json_array_size(s); i++) {
			if(i == 3)
				break;
			json_t *ssrc = json_array_get(s, i);
			if(ssrc && json_is_integer(ssrc) && ssrcs)
				ssrcs[i] = json_integer_value(ssrc);
		}
	}
}

void janus_rtp_simulcasting_cleanup(int *rid_ext_id, uint32_t *ssrcs, char **rids, janus_mutex *rid_mutex) {
	if(rid_mutex != NULL)
		janus_mutex_lock(rid_mutex);
	if(rid_ext_id)
		*rid_ext_id = -1;
	if(ssrcs || rids) {
		int i = 0;
		for(i=0; i<3; i++) {
			if(ssrcs)
				*(ssrcs+i) = 0;
			if(rids) {
				g_free(rids[i]);
				rids[i] = NULL;
			}
		}
	}
	if(rid_mutex != NULL)
		janus_mutex_unlock(rid_mutex);
}

gboolean janus_rtp_simulcasting_context_process_rtp(janus_rtp_simulcasting_context *context,
		char *buf, int len, uint8_t *dd_content, int dd_len, uint32_t *ssrcs, char **rids,
		janus_videocodec vcodec, janus_rtp_switching_context *sc, janus_mutex *rid_mutex) {
	if(!context || !buf || len < 1)
		return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	uint32_t ssrc = ntohl(header->ssrc);
	int substream = -1;
	if(ssrc == *(ssrcs)) {
		substream = 0;
	} else if(ssrc == *(ssrcs+1)) {
		substream = 1;
	} else if(ssrc == *(ssrcs+2)) {
		substream = 2;
	} else {
		/* We don't recognize this SSRC, check if rid can help us */
		if(context->rid_ext_id < 1 || rids == NULL)
			return FALSE;
		char sdes_item[16];
		if(janus_rtp_header_extension_parse_rid(buf, len, context->rid_ext_id, sdes_item, sizeof(sdes_item)) != 0)
			return FALSE;
		if(rid_mutex != NULL)
			janus_mutex_lock(rid_mutex);
		if(rids[0] != NULL && !strcmp(rids[0], sdes_item)) {
			JANUS_LOG(LOG_VERB, "Simulcasting: rid=%s --> ssrc=%"SCNu32"\n", sdes_item, ssrc);
			*(ssrcs) = ssrc;
			substream = 0;
		} else if(rids[1] != NULL && !strcmp(rids[1], sdes_item)) {
			JANUS_LOG(LOG_VERB, "Simulcasting: rid=%s --> ssrc=%"SCNu32"\n", sdes_item, ssrc);
			*(ssrcs+1) = ssrc;
			substream = 1;
		} else if(rids[2] != NULL && !strcmp(rids[2], sdes_item)) {
			JANUS_LOG(LOG_VERB, "Simulcasting: rid=%s --> ssrc=%"SCNu32"\n", sdes_item, ssrc);
			*(ssrcs+2) = ssrc;
			substream = 2;
		}
		if(rid_mutex != NULL)
			janus_mutex_unlock(rid_mutex);
		if(substream == -1) {
			JANUS_LOG(LOG_WARN, "Simulcasting: unknown rid '%s'...\n", sdes_item);
			return FALSE;
		}
	}
	/* Reset the flags */
	context->changed_substream = FALSE;
	context->changed_temporal = FALSE;
	context->need_pli = FALSE;
	gint64 now = janus_get_monotonic_time();
	/* Access the packet payload */
	int plen = 0;
	char *payload = janus_rtp_payload(buf, len, &plen);
	if(payload == NULL)
		return FALSE;
	/* Check what's our target */
	if(context->substream_target_temp != -1 && (substream > context->substream_target_temp ||
			context->substream_target <= context->substream_target_temp)) {
		/* We either just received media on a substream that is higher than
		 * the target we dropped to (which means the one we want is now flowing
		 * again) or we've been requested a lower substream target instead */
		context->substream_target_temp = -1;
	}
	int target = (context->substream_target_temp == -1) ? context->substream_target : context->substream_target_temp;
	/* Check what we need to do with the packet */
	if(context->substream == -1) {
		if((vcodec == JANUS_VIDEOCODEC_VP8 && janus_vp8_is_keyframe(payload, plen)) ||
				(vcodec == JANUS_VIDEOCODEC_VP9 && janus_vp9_is_keyframe(payload, plen)) ||
				(vcodec == JANUS_VIDEOCODEC_H264 && janus_h264_is_keyframe(payload, plen)) ||
				(vcodec == JANUS_VIDEOCODEC_AV1 && janus_av1_is_keyframe(payload, plen)) ||
				(vcodec == JANUS_VIDEOCODEC_H265 && janus_h265_is_keyframe(payload, plen))) {
			context->substream = substream;
			/* Notify the caller that the substream changed */
			context->changed_substream = TRUE;
			context->last_relayed = now;
		} else {
			/* Don't relay anything until we get a keyframe */
			return FALSE;
		}
	} else if(context->substream != target) {
		/* We're not on the substream we'd like: let's wait for a keyframe on the target */
		if(((context->substream < target && substream > context->substream) ||
				(context->substream > target && substream < context->substream)) &&
					((vcodec == JANUS_VIDEOCODEC_VP8 && janus_vp8_is_keyframe(payload, plen)) ||
					(vcodec == JANUS_VIDEOCODEC_VP9 && janus_vp9_is_keyframe(payload, plen)) ||
					(vcodec == JANUS_VIDEOCODEC_H264 && janus_h264_is_keyframe(payload, plen)) ||
					(vcodec == JANUS_VIDEOCODEC_AV1 && janus_av1_is_keyframe(payload, plen)) ||
					(vcodec == JANUS_VIDEOCODEC_H265 && janus_h265_is_keyframe(payload, plen)))) {
			JANUS_LOG(LOG_VERB, "Received keyframe on #%d (SSRC %"SCNu32"), switching (was #%d/%"SCNu32")\n",
				substream, ssrc, context->substream, *(ssrcs + context->substream));
			context->substream = substream;
			/* Notify the caller that the substream changed */
			context->changed_substream = TRUE;
			context->last_relayed = now;
		}
	}
	/* If we haven't received our desired substream yet, let's drop temporarily */
	if(context->last_relayed == 0) {
		/* Let's start slow */
		context->last_relayed = now;
	} else if(context->substream > 0) {
		/* Check if too much time went by with no packet relayed */
		gint64 delay_us = (now - context->last_relayed);
		if(delay_us > (context->drop_trigger ? context->drop_trigger : 250000)) {
			context->last_relayed = now;
			if(context->substream != substream && context->substream_target_temp != 0) {
				if(context->substream_target > substream) {
					int prev_target = context->substream_target_temp;
					if(context->substream_target_temp == -1)
						context->substream_target_temp = context->substream_target - 1;
					else
						context->substream_target_temp--;
					if(context->substream_target_temp < 0)
						context->substream_target_temp = 0;
					if(context->substream_target_temp != prev_target) {
						JANUS_LOG(LOG_WARN, "No packet received on substream %d for %"SCNi64"ms, falling back to %d\n",
							context->substream, (delay_us / 1000), context->substream_target_temp);
						/* Notify the caller that we (still) need a PLI */
						context->need_pli = TRUE;
					}
				}
			}
		}
	}
	/* Do we need to drop this? */
	if(context->substream < 0)
		return FALSE;
	if(substream != context->substream) {
		JANUS_LOG(LOG_HUGE, "Dropping packet (it's from SSRC %"SCNu32", but we're only relaying SSRC %"SCNu32" now\n",
			ssrc, *(ssrcs + context->substream));
		return FALSE;
	}
	context->last_relayed = janus_get_monotonic_time();
	/* Temporal layers are only easily available for some codecs */
	if(vcodec == JANUS_VIDEOCODEC_VP8) {
		/* Check if there's any temporal scalability to take into account */
		gboolean m = FALSE;
		uint16_t picid = 0;
		uint8_t tlzi = 0;
		uint8_t tid = 0;
		uint8_t ybit = 0;
		uint8_t keyidx = 0;
		if(janus_vp8_parse_descriptor(payload, plen, &m, &picid, &tlzi, &tid, &ybit, &keyidx) == 0) {
			//~ JANUS_LOG(LOG_WARN, "%"SCNu16", %u, %u, %u, %u\n", picid, tlzi, tid, ybit, keyidx);
			if(context->templayer != context->templayer_target && tid == context->templayer_target) {
				/* FIXME We should be smarter in deciding when to switch */
				context->templayer = context->templayer_target;
				/* Notify the caller that the temporal layer changed */
				context->changed_temporal = TRUE;
			}
			if(context->templayer != -1 && tid > context->templayer) {
				JANUS_LOG(LOG_HUGE, "Dropping packet (it's temporal layer %d, but we're capping at %d)\n",
					tid, context->templayer);
				/* We increase the base sequence number, or there will be gaps when delivering later */
				if(sc)
					sc->base_seq++;
				return FALSE;
			}
		}
	} else if(vcodec == JANUS_VIDEOCODEC_VP9) {
		/* We use the VP9 SVC parser to extract info on temporal layers */
		gboolean found = FALSE;
		janus_vp9_svc_info svc_info = { 0 };
		if(janus_vp9_parse_svc(payload, plen, &found, &svc_info) == 0 && found) {
			int temporal_layer = context->templayer;
			if(context->templayer_target > context->templayer) {
				/* We need to upscale */
				if(svc_info.ubit && svc_info.bbit &&
						svc_info.temporal_layer > context->templayer &&
						svc_info.temporal_layer <= context->templayer_target) {
					context->templayer = svc_info.temporal_layer;
					temporal_layer = context->templayer;
					context->changed_temporal = TRUE;
				}
			} else if(context->templayer_target < context->templayer) {
				/* We need to downscale */
				if(svc_info.ebit && svc_info.temporal_layer == context->templayer_target) {
					context->templayer = context->templayer_target;
					context->changed_temporal = TRUE;
				}
			}
			if(temporal_layer < svc_info.temporal_layer) {
				JANUS_LOG(LOG_HUGE, "Dropping packet (it's temporal layer %d, but we're capping at %d)\n",
					svc_info.temporal_layer, context->templayer);
				/* We increase the base sequence number, or there will be gaps when delivering later */
				if(sc)
					sc->base_seq++;
				return FALSE;
			}
		}
	} else if(vcodec == JANUS_VIDEOCODEC_AV1 && dd_content != NULL && dd_len > 0) {
		/* Use the Dependency Descriptor to check temporal layers */
		janus_av1_svc_context *av1ctx = NULL;
		if(context->substream >= 0 && context->substream <= 2)
			av1ctx = &context->av1_context[context->substream];
		if(av1ctx != NULL) {
			uint8_t template = 0;
			if(janus_av1_svc_context_process_dd(av1ctx, dd_content, dd_len, &template, NULL)) {
				janus_av1_svc_template *t = g_hash_table_lookup(av1ctx->templates, GUINT_TO_POINTER(template));
				if(t) {
					int temporal_layer = context->templayer;
					if(context->templayer_target > context->templayer) {
						/* We need to upscale */
						if(t->temporal > context->templayer && t->temporal <= context->templayer_target) {
							context->templayer = t->temporal;
							temporal_layer = context->templayer;
							context->changed_temporal = TRUE;
						}
					} else if(context->templayer_target < context->templayer) {
						/* We need to downscale */
						if(t->temporal == context->templayer_target) {
							context->templayer = context->templayer_target;
							context->changed_temporal = TRUE;
						}
					}
					if(temporal_layer < t->temporal) {
						JANUS_LOG(LOG_HUGE, "Dropping packet (it's temporal layer %d, but we're capping at %d)\n",
							t->temporal, context->templayer);
						/* We increase the base sequence number, or there will be gaps when delivering later */
						if(sc)
							sc->base_seq++;
						return FALSE;
					}
				}
			}
		}
	}
	/* If we got here, the packet can be relayed */
	return TRUE;
}

/* VP9 SVC */
void janus_rtp_svc_context_reset(janus_rtp_svc_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	janus_av1_svc_context_reset(&context->dd_context);
	memset(context, 0, sizeof(*context));
	context->spatial = -1;
	context->temporal = -1;
}

gboolean janus_rtp_svc_context_process_rtp(janus_rtp_svc_context *context,
		char *buf, int len, uint8_t *dd_content, int dd_len,
		janus_videocodec vcodec, janus_vp9_svc_info *info, janus_rtp_switching_context *sc) {
	if(!context || !buf || len < 1 || (vcodec != JANUS_VIDEOCODEC_VP9 && vcodec != JANUS_VIDEOCODEC_AV1))
		return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	/* Reset the flags */
	context->changed_spatial = FALSE;
	context->changed_temporal = FALSE;
	context->need_pli = FALSE;
	gint64 now = janus_get_monotonic_time();
	/* Access the packet payload */
	int plen = 0;
	char *payload = janus_rtp_payload(buf, len, &plen);
	if(payload == NULL)
		return FALSE;
	/* Check if we should use the Dependency Descriptor */
	if(vcodec == JANUS_VIDEOCODEC_AV1) {
		/* We do, make sure the data is there */
		if(dd_content == NULL || dd_len < 1) {
			/* No Dependency Descriptor, relay as it is */
			return TRUE;
		}
		uint8_t template = 0, ebit = 0;
		if(!janus_av1_svc_context_process_dd(&context->dd_context, dd_content, dd_len, &template, &ebit)) {
			/* We couldn't parse the Dependency Descriptor, relay as it is */
			return TRUE;
		}
		janus_av1_svc_template *t = g_hash_table_lookup(context->dd_context.templates, GUINT_TO_POINTER(template));
		if(t == NULL) {
			/* We couldn't find the template, relay as it is */
			return TRUE;
		}
		/* Now let's check if we should let the packet through or not */
		gboolean keyframe = janus_av1_is_keyframe((const char *)payload, plen);
		gboolean override_mark_bit = FALSE, has_marker_bit = header->markerbit;
		int spatial_layer = context->spatial;
		if(t->spatial >= 0 && t->spatial <= 2)
			context->last_spatial_layer[t->spatial] = now;
		if(context->spatial_target > context->spatial) {
			JANUS_LOG(LOG_HUGE, "We need to upscale spatially: (%d < %d)\n",
				context->spatial, context->spatial_target);
			/* We need to upscale: wait for a keyframe */
			if(keyframe) {
				int new_spatial_layer = context->spatial_target;
				while(new_spatial_layer > context->spatial && new_spatial_layer > 0) {
					if(now - context->last_spatial_layer[new_spatial_layer] >= (context->drop_trigger ? context->drop_trigger : 250000)) {
						/* We haven't received packets from this layer for a while, try a lower layer */
						JANUS_LOG(LOG_HUGE, "Haven't received packets from layer %d for a while, trying %d instead...\n",
							new_spatial_layer, new_spatial_layer-1);
						new_spatial_layer--;
					} else {
						break;
					}
				}
				if(new_spatial_layer > context->spatial) {
					JANUS_LOG(LOG_HUGE, "  -- Upscaling spatial layer: %d --> %d (need %d)\n",
						context->spatial, new_spatial_layer, context->spatial_target);
					context->spatial = new_spatial_layer;
					spatial_layer = context->spatial;
					context->changed_spatial = TRUE;
				}
			}
		} else if(context->spatial_target < context->spatial) {
			/* We need to scale: wait for a keyframe */
			JANUS_LOG(LOG_HUGE, "We need to downscale spatially: (%d > %d)\n",
				context->spatial, context->spatial_target);
			/* Check the E bit to see if this is an end-of-frame */
			if(ebit) {
				JANUS_LOG(LOG_HUGE, "  -- Downscaling spatial layer: %d --> %d\n",
					context->spatial, context->spatial_target);
				context->spatial = context->spatial_target;
				context->changed_spatial = TRUE;
			}
		}
		if(spatial_layer < t->spatial) {
			/* Drop the packet: update the context to make sure sequence number is increased normally later */
			JANUS_LOG(LOG_HUGE, "Dropping packet (spatial layer %d < %d)\n", spatial_layer, t->spatial);
			if(sc)
				sc->base_seq++;
			return FALSE;
		} else if(ebit && spatial_layer == t->spatial) {
			/* If we stop at layer 0, we need a marker bit now, as the one from layer 1 will not be received */
			override_mark_bit = TRUE;
		}
		int temporal = context->temporal;
		if(context->temporal_target > context->temporal) {
			/* We need to upscale */
			if(t->temporal > context->temporal && t->temporal <= context->temporal_target) {
				context->temporal = t->temporal;
				temporal = context->temporal;
				context->changed_temporal = TRUE;
			}
		} else if(context->temporal_target < context->temporal) {
			/* We need to downscale */
			if(t->temporal == context->temporal_target) {
				context->temporal = context->temporal_target;
				context->changed_temporal = TRUE;
			}
		}
		if(temporal < t->temporal) {
			JANUS_LOG(LOG_HUGE, "Dropping packet (it's temporal layer %d, but we're capping at %d)\n",
				t->temporal, context->temporal);
			/* We increase the base sequence number, or there will be gaps when delivering later */
			if(sc)
				sc->base_seq++;
			return FALSE;
		}
		/* If we got here, we can send the frame: this doesn't necessarily mean it's
		 * one of the layers the user wants, as there may be dependencies involved */
		JANUS_LOG(LOG_HUGE, "Sending packet (spatial=%d, temporal=%d)\n",
			t->spatial, t->temporal);
		if(override_mark_bit && !has_marker_bit)
			header->markerbit = 1;
		return TRUE;
	}
	/* If we got here, it's VP9, for which we parse the payload manually:
	 * if we don't have any info parsed from the VP9 payload header, get it now */
	janus_vp9_svc_info svc_info = { 0 };
	if(!info) {
		gboolean found = FALSE;
		if(janus_vp9_parse_svc(payload, plen, &found, &svc_info) < 0) {
			/* Error parsing, relay as it is */
			return TRUE;
		}
		if(!found) {
			/* No SVC info, maybe a generic VP9 payload? Relay as it is */
			return TRUE;
		}
	} else {
		svc_info = *info;
	}
	/* Note: Following code inspired by the excellent job done by Sergio Garcia Murillo here:
	 * https://github.com/medooze/media-server/blob/master/src/vp9/VP9LayerSelector.cpp */
	gboolean keyframe = janus_vp9_is_keyframe((const char *)payload, plen);
	gboolean override_mark_bit = FALSE, has_marker_bit = header->markerbit;
	int spatial_layer = context->spatial;
	if(svc_info.spatial_layer >= 0 && svc_info.spatial_layer <= 2)
		context->last_spatial_layer[svc_info.spatial_layer] = now;
	if(context->spatial_target > context->spatial) {
		JANUS_LOG(LOG_HUGE, "We need to upscale spatially: (%d < %d)\n",
			context->spatial, context->spatial_target);
		/* We need to upscale: wait for a keyframe */
		if(keyframe) {
			int new_spatial_layer = context->spatial_target;
			while(new_spatial_layer > context->spatial && new_spatial_layer > 0) {
				if(now - context->last_spatial_layer[new_spatial_layer] >= (context->drop_trigger ? context->drop_trigger : 250000)) {
					/* We haven't received packets from this layer for a while, try a lower layer */
					JANUS_LOG(LOG_HUGE, "Haven't received packets from layer %d for a while, trying %d instead...\n",
						new_spatial_layer, new_spatial_layer-1);
					new_spatial_layer--;
				} else {
					break;
				}
			}
			if(new_spatial_layer > context->spatial) {
				JANUS_LOG(LOG_HUGE, "  -- Upscaling spatial layer: %d --> %d (need %d)\n",
					context->spatial, new_spatial_layer, context->spatial_target);
				context->spatial = new_spatial_layer;
				spatial_layer = context->spatial;
				context->changed_spatial = TRUE;
			}
		}
	} else if(context->spatial_target < context->spatial) {
		/* We need to downscale */
		JANUS_LOG(LOG_HUGE, "We need to downscale spatially: (%d > %d)\n",
			context->spatial, context->spatial_target);
		gboolean downscaled = FALSE;
		if(!svc_info.fbit && keyframe) {
			/* Non-flexible mode: wait for a keyframe */
			downscaled = TRUE;
		} else if(svc_info.fbit && svc_info.ebit) {
			/* Flexible mode: check the E bit */
			downscaled = TRUE;
		}
		if(downscaled) {
			JANUS_LOG(LOG_HUGE, "  -- Downscaling spatial layer: %d --> %d\n",
				context->spatial, context->spatial_target);
			context->spatial = context->spatial_target;
			context->changed_spatial = TRUE;
		}
	}
	if(spatial_layer < svc_info.spatial_layer) {
		/* Drop the packet: update the context to make sure sequence number is increased normally later */
		JANUS_LOG(LOG_HUGE, "Dropping packet (spatial layer %d < %d)\n", spatial_layer, svc_info.spatial_layer);
		if(sc)
			sc->base_seq++;
		return FALSE;
	} else if(svc_info.ebit && spatial_layer == svc_info.spatial_layer) {
		/* If we stop at layer 0, we need a marker bit now, as the one from layer 1 will not be received */
		override_mark_bit = TRUE;
	}
	int temporal_layer = context->temporal;
	if(context->temporal_target > context->temporal) {
		/* We need to upscale */
		JANUS_LOG(LOG_HUGE, "We need to upscale temporally: (%d < %d)\n",
			context->temporal, context->temporal_target);
		if(svc_info.ubit && svc_info.bbit &&
				svc_info.temporal_layer > context->temporal &&
				svc_info.temporal_layer <= context->temporal_target) {
			JANUS_LOG(LOG_HUGE, "  -- Upscaling temporal layer: %d --> %d (want %d)\n",
				context->temporal, svc_info.temporal_layer, context->temporal_target);
			context->temporal = svc_info.temporal_layer;
			temporal_layer = context->temporal;
			context->changed_temporal = TRUE;
		}
	} else if(context->temporal_target < context->temporal) {
		/* We need to downscale */
		JANUS_LOG(LOG_HUGE, "We need to downscale temporally: (%d > %d)\n",
			context->temporal, context->temporal_target);
		if(svc_info.ebit && svc_info.temporal_layer == context->temporal_target) {
			JANUS_LOG(LOG_HUGE, "  -- Downscaling temporal layer: %d --> %d\n",
				context->temporal, context->temporal_target);
			context->temporal = context->temporal_target;
			context->changed_temporal = TRUE;
		}
	}
	if(temporal_layer < svc_info.temporal_layer) {
		/* Drop the packet: update the context to make sure sequence number is increased normally later */
		JANUS_LOG(LOG_HUGE, "Dropping packet (temporal layer %d < %d)\n", temporal_layer, svc_info.temporal_layer);
		if(sc)
			sc->base_seq++;
		return FALSE;
	}
	/* If we got here, we can send the frame: this doesn't necessarily mean it's
	 * one of the layers the user wants, as there may be dependencies involved */
	JANUS_LOG(LOG_HUGE, "Sending packet (spatial=%d, temporal=%d)\n",
		svc_info.spatial_layer, svc_info.temporal_layer);
	if(override_mark_bit && !has_marker_bit)
		header->markerbit = 1;
	/* If we got here, the packet can be relayed */
	return TRUE;
}

/* AV1 SVC (still WIP) */
void janus_av1_svc_context_reset(janus_av1_svc_context *context) {
	if(context == NULL)
		return;
	/* Reset the context values */
	if(context->templates != NULL)
		g_hash_table_destroy(context->templates);
	memset(context, 0, sizeof(*context));
}

gboolean janus_av1_svc_context_process_dd(janus_av1_svc_context *context,
		uint8_t *dd, int dd_len, uint8_t *template_id, uint8_t *ebit) {
	if(!context || !dd || dd_len < 3)
		return FALSE;

	/* First of all, let's parse the Dependency Descriptor */
	size_t blen = dd_len*8;
	uint32_t offset = 0;
	/* mandatory_descriptor_fields() */
	uint8_t start = janus_bitstream_getbit(dd, offset++);
	uint8_t end = janus_bitstream_getbit(dd, offset++);
	if(ebit)
		*ebit = end;
	uint8_t template = janus_bitstream_getbits(dd, 6, &offset);
	uint16_t frame = janus_bitstream_getbits(dd, 16, &offset);
	JANUS_LOG(LOG_HUGE, "  -- s=%u, e=%u, t=%u, f=%u\n",
		start, end, template, frame);
	if(blen > 24) {
		/* extended_descriptor_fields() */
		uint8_t tdeps = janus_bitstream_getbit(dd, offset++);
		(void)janus_bitstream_getbit(dd, offset++);
		(void)janus_bitstream_getbit(dd, offset++);
		(void)janus_bitstream_getbit(dd, offset++);
		(void)janus_bitstream_getbit(dd, offset++);
		/* template_dependency_structure() */
		if(tdeps) {
			uint8_t tioff = janus_bitstream_getbits(dd, 6, &offset);
			(void)janus_bitstream_getbits(dd, 5, &offset);
			/* template_layers() */
			uint32_t nlidc = 0;
			uint8_t tcnt = 0;
			int spatial_layers = 0;
			int temporal_layers = 0;
			do {
				nlidc = janus_bitstream_getbits(dd, 2, &offset);
				if(context->templates == NULL)
					context->templates = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)g_free);
				janus_av1_svc_template *t = g_hash_table_lookup(context->templates,
					GUINT_TO_POINTER(tcnt));
				if(t == NULL) {
					t = g_malloc0(sizeof(janus_av1_svc_template));
					t->id = tcnt;
					g_hash_table_insert(context->templates, GUINT_TO_POINTER(t->id), t);
					context->updated = TRUE;
				}
				t->spatial = spatial_layers;
				t->temporal = temporal_layers;
				JANUS_LOG(LOG_HUGE, "  -- -- -- [%u] spatial=%u, temporal=%u\n",
					tcnt, t->spatial, t->temporal);
				if(nlidc == 1) {
					temporal_layers++;
				} else if(nlidc == 2) {
					temporal_layers = 0;
					spatial_layers++;
				}
				tcnt++;
			} while(nlidc != 3);
			/* Check if anything changed since the latest update */
			if(context->tcnt != tcnt || context->tioff != tioff ||
					context->spatial_layers != spatial_layers ||
					context->temporal_layers != temporal_layers)
				context->updated = TRUE;
			context->tcnt = tcnt;
			context->tioff = tioff;
			context->spatial_layers = spatial_layers;
			context->temporal_layers = temporal_layers;
			/* FIXME We currently don't care about the other fields */
		}
	}
	/* frame_dependency_definition() */
	uint8_t tindex = (template + 64 - context->tioff) % 64;
	janus_av1_svc_template *t = context->templates ? g_hash_table_lookup(context->templates,
		GUINT_TO_POINTER(tindex)) : NULL;
	if(t == NULL) {
		JANUS_LOG(LOG_WARN, "Invalid template ID '%u' (count is %u), ignoring packet...\n",
			tindex, context->tcnt);
		return FALSE;
	}
	JANUS_LOG(LOG_HUGE, "  -- spatial=%u, temporal=%u (tindex %u)\n",
		t->spatial, t->temporal, t->id);
	/* FIXME We currently don't care about the other fields */

	/* If we got here, the packet is fine */
	if(template_id != NULL)
		*template_id = tindex;
	return TRUE;
}
