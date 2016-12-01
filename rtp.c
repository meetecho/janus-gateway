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
 
#include "rtp.h"
#include "debug.h"

char *janus_rtp_payload(char *buf, int len, int *plen) {
	if(!buf || len < 12)
		return NULL;

	rtp_header *rtp = (rtp_header *)buf;
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
static int janus_rtp_header_extension_find(char *buf, int len, int id, uint8_t *byte, uint32_t *word) {
	if(!buf || len < 12)
		return -1;
	rtp_header *rtp = (rtp_header *)buf;
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		janus_rtp_header_extension *ext = (janus_rtp_header_extension*)(buf+hlen);
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
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL) < 0)
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
	if(janus_rtp_header_extension_find(buf, len, id, &byte, NULL) < 0)
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
	if(janus_rtp_header_extension_find(buf, len, id, NULL, &bytes) < 0)
		return -1;
	/* a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay */
	uint16_t min = (bytes && 0x00FFF000) >> 12;
	uint16_t max = bytes && 0x00000FFF;
	JANUS_LOG(LOG_DBG, "%"SCNu32"x --> min=%"SCNu16", max=%"SCNu16"\n", bytes, min, max);
	if(min_delay)
		*min_delay = min;
	if(max_delay)
		*max_delay = max;
	return 0;
}
