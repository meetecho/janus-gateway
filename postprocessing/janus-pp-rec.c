/*! \file    janus-pp-rec.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Simple utility to post-process .mjr files saved by Janus
 * \details  Our Janus WebRTC gateway provides a simple helper (janus_recorder)
 * to allow plugins to record audio, video and text frames sent by users. At the time
 * of writing, this helper has been integrated in several plugins in Janus.
 * To keep things simple on the Janus side, though, no processing
 * at all is done in the recording step: this means that the recorder
 * actually only dumps the RTP frames it receives to a file in a structured way,
 * so that they can be post-processed later on to extract playable media
 * files. This utility allows you to process those files, in order to
 * get a working media file you can playout with an external player.
 * The tool will generate a .webm if the recording includes VP8 frames,
 * an .opus if the recording includes Opus frames, an .mp4 if the recording
 * includes H.264 frames, and a .wav file if the recording includes
 * G.711 (mu-law or a-law) frames. In case the recording contains text
 * frames as received via data channels, instead, a .srt file will be
 * generated with the text content and the related timing information.
 * 
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the .mjr source file you want to post-process, and the
 * path to the destination file, e.g.:
 * 
\verbatim
./janus-pp-rec /path/to/source.mjr /path/to/destination.[opus|wav|webm|h264|srt]
\endverbatim 
 * 
 * An attempt to specify an output format that is not compliant with the
 * recording content (e.g., a .webm for H.264 frames) will result in an
 * error since, again, no transcoding is involved.
 *
 * You can also just print the internal header of the recording, or parse
 * it without processing it (e.g., for debugging), by invoking the tool
 * in a different way:
 *
\verbatim
./janus-pp-rec --header /path/to/source.mjr
./janus-pp-rec --parse /path/to/source.mjr
\endverbatim
 *
 * \note This utility does not do any form of transcoding. It just
 * depacketizes the RTP frames in order to get the payload, and saves
 * the frames in a valid container. Any further post-processing (e.g.,
 * muxing audio and video belonging to the same media session in a single
 * .webm file) is up to third-party applications.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <glib.h>
#include <jansson.h>

#include "../debug.h"
#include "../version.h"
#include "pp-rtp.h"
#include "pp-webm.h"
#include "pp-h264.h"
#include "pp-opus.h"
#include "pp-g711.h"
#include "pp-g722.h"
#include "pp-srt.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;

static janus_pp_frame_packet *list = NULL, *last = NULL;
static int working = 0;

static int post_reset_trigger = 200;


/* Signal handler */
static void janus_pp_handle_signal(int signum) {
	working = 0;
}


/* Main Code */
int main(int argc, char *argv[])
{
	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	JANUS_LOG(LOG_INFO, "Janus version: %d (%s)\n", janus_version, janus_version_string);
	JANUS_LOG(LOG_INFO, "Janus commit: %s\n", janus_build_git_sha);
	JANUS_LOG(LOG_INFO, "Compiled on:  %s\n\n", janus_build_git_time);

	/* Check the JANUS_PPREC_DEBUG environment variable for the debugging level */
	if(g_getenv("JANUS_PPREC_DEBUG") != NULL) {
		int val = atoi(g_getenv("JANUS_PPREC_DEBUG"));
		if(val >= LOG_NONE && val <= LOG_MAX)
			janus_log_level = val;
		JANUS_LOG(LOG_INFO, "Logging level: %d\n", janus_log_level);
	}
	if(g_getenv("JANUS_PPREC_POSTRESETTRIGGER") != NULL) {
		int val = atoi(g_getenv("JANUS_PPREC_POSTRESETTRIGGER"));
		if(val >= 0)
			post_reset_trigger = val;
		JANUS_LOG(LOG_INFO, "Post reset trigger: %d\n", post_reset_trigger);
	}
	
	/* Evaluate arguments */
	if(argc != 3) {
		JANUS_LOG(LOG_INFO, "Usage: %s source.mjr destination.[opus|wav|webm|mp4|srt]\n", argv[0]);
		JANUS_LOG(LOG_INFO, "       %s --header source.mjr (only parse header)\n", argv[0]);
		JANUS_LOG(LOG_INFO, "       %s --parse source.mjr (only parse and re-order packets)\n", argv[0]);
		return -1;
	}
	char *source = NULL, *destination = NULL, *extension = NULL;
	gboolean header_only = !strcmp(argv[1], "--header");
	gboolean parse_only = !strcmp(argv[1], "--parse");
	if(header_only || parse_only) {
		/* Only parse the .mjr header and/or re-order the packets, no processing */
		source = argv[2];
	} else {
		/* Post-process the .mjr recording */
		source = argv[1];
		destination = argv[2];
		JANUS_LOG(LOG_INFO, "%s --> %s\n", source, destination);
		/* Check the extension */
		extension = strrchr(destination, '.');
		if(extension == NULL) {
			/* No extension? */
			JANUS_LOG(LOG_ERR, "No extension? Unsupported target file\n");
			exit(1);
		}
		if(strcasecmp(extension, ".opus") && strcasecmp(extension, ".wav") &&
				strcasecmp(extension, ".webm") && strcasecmp(extension, ".mp4") &&
				strcasecmp(extension, ".srt")) {
			/* Unsupported extension? */
			JANUS_LOG(LOG_ERR, "Unsupported extension '%s'\n", extension);
			exit(1);
		}
	}
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Could not open file %s\n", source);
		return -1;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_INFO, "File is %zu bytes\n", fsize);

	/* Handle SIGINT */
	working = 1;
	signal(SIGINT, janus_pp_handle_signal);

	/* Pre-parse */
	JANUS_LOG(LOG_INFO, "Pre-parsing file to generate ordered index...\n");
	gboolean parsed_header = FALSE;
	int video = 0, data = 0;
	int opus = 0, g711 = 0, g722 = 0, vp8 = 0, vp9 = 0, h264 = 0;
	gint64 c_time = 0, w_time = 0;
	int bytes = 0, skip = 0;
	long offset = 0;
	uint16_t len = 0;
	uint32_t count = 0;
	uint32_t ssrc = 0;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(working && offset < fsize) {
		if(header_only && parsed_header) {
			/* We only needed to parse the header */
			exit(0);
		}
		/* Read frame header */
		skip = 0;
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			JANUS_LOG(LOG_WARN, "Invalid header at offset %ld (%s), the processing will stop here...\n",
				offset, bytes != 8 ? "not enough bytes" : "wrong prefix");
			break;
		}
		if(prebuffer[1] == 'E') {
			/* Either the old .mjr format header ('MEETECHO' header followed by 'audio' or 'video'), or a frame */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len == 5 && !parsed_header) {
				/* This is the main header */
				parsed_header = TRUE;
				JANUS_LOG(LOG_WARN, "Old .mjr header format\n");
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] == 'v') {
					JANUS_LOG(LOG_INFO, "This is a video recording, assuming VP8\n");
					video = 1;
					data = 0;
					vp8 = 1;
					if(extension && strcasecmp(extension, ".webm")) {
						JANUS_LOG(LOG_ERR, "VP8 RTP packets can only be converted to a .webm file\n");
						exit(1);
					}
				} else if(prebuffer[0] == 'a') {
					JANUS_LOG(LOG_INFO, "This is an audio recording, assuming Opus\n");
					video = 0;
					data = 0;
					opus = 1;
					if(extension && strcasecmp(extension, ".opus")) {
						JANUS_LOG(LOG_ERR, "Opus RTP packets can only be converted to an .opus file\n");
						exit(1);
					}
				} else if(prebuffer[0] == 'd') {
					JANUS_LOG(LOG_INFO, "This is a text data recording, assuming SRT\n");
					video = 0;
					data = 1;
					if(extension && strcasecmp(extension, ".srt")) {
						JANUS_LOG(LOG_ERR, "Data channel packets can only be converted to a .srt file\n");
						exit(1);
					}
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording media type...\n");
					exit(1);
				}
				offset += len;
				continue;
			} else if(!data && len < 12) {
				/* Not RTP, skip */
				JANUS_LOG(LOG_VERB, "Skipping packet (not RTP?)\n");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, the header may contain useful info */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				JANUS_LOG(LOG_WARN, "New .mjr header format\n");
				bytes = fread(prebuffer, sizeof(char), len, file);
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				json_error_t error;
				json_t *info = json_loads(prebuffer, 0, &error);
				if(!info) {
					JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
					JANUS_LOG(LOG_WARN, "Error parsing info header...\n");
					exit(1);
				}
				/* Is it audio or video? */
				json_t *type = json_object_get(info, "t");
				if(!type || !json_is_string(type)) {
					JANUS_LOG(LOG_WARN, "Missing/invalid recording type in info header...\n");
					exit(1);
				}
				const char *t = json_string_value(type);
				if(!strcasecmp(t, "v")) {
					video = 1;
					data = 0;
				} else if(!strcasecmp(t, "a")) {
					video = 0;
					data = 0;
				} else if(!strcasecmp(t, "d")) {
					video = 0;
					data = 1;
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported recording type '%s' in info header...\n", t);
					exit(1);
				}
				/* What codec was used? */
				json_t *codec = json_object_get(info, "c");
				if(!codec || !json_is_string(codec)) {
					JANUS_LOG(LOG_WARN, "Missing recording codec in info header...\n");
					exit(1);
				}
				const char *c = json_string_value(codec);
				if(video) {
					if(!strcasecmp(c, "vp8")) {
						vp8 = 1;
						if(extension && strcasecmp(extension, ".webm")) {
							JANUS_LOG(LOG_ERR, "VP8 RTP packets can only be converted to a .webm file\n");
							exit(1);
						}
					} else if(!strcasecmp(c, "vp9")) {
						vp9 = 1;
						if(extension && strcasecmp(extension, ".webm")) {
							JANUS_LOG(LOG_ERR, "VP9 RTP packets can only be converted to a .webm file\n");
							exit(1);
						}
					} else if(!strcasecmp(c, "h264")) {
						h264 = 1;
						if(extension && strcasecmp(extension, ".mp4")) {
							JANUS_LOG(LOG_ERR, "H.264 RTP packets can only be converted to a .mp4 file\n");
							exit(1);
						}
					} else {
						JANUS_LOG(LOG_WARN, "The post-processor only supports VP8, VP9 and H.264 video for now (was '%s')...\n", c);
						exit(1);
					}
				} else if(!video && !data) {
					if(!strcasecmp(c, "opus")) {
						opus = 1;
						if(extension && strcasecmp(extension, ".opus")) {
							JANUS_LOG(LOG_ERR, "Opus RTP packets can only be converted to a .opus file\n");
							exit(1);
						}
					} else if(!strcasecmp(c, "g711") || !strcasecmp(c, "pcmu") || !strcasecmp(c, "pcma")) {
						g711 = 1;
						if(extension && strcasecmp(extension, ".wav")) {
							JANUS_LOG(LOG_ERR, "G.711 RTP packets can only be converted to a .wav file\n");
							exit(1);
						}
					} else if(!strcasecmp(c, "g722")) {
						g722 = 1;
						if(extension && strcasecmp(extension, ".wav")) {
							JANUS_LOG(LOG_ERR, "G.722 RTP packets can only be converted to a .wav file\n");
							exit(1);
						}
					} else {
						JANUS_LOG(LOG_WARN, "The post-processor only supports Opus and G.711 audio for now (was '%s')...\n", c);
						exit(1);
					}
				} else if(data) {
					if(strcasecmp(c, "text")) {
						JANUS_LOG(LOG_WARN, "The post-processor only supports text data for now (was '%s')...\n", c);
						exit(1);
					}
					if(extension && strcasecmp(extension, ".srt")) {
						JANUS_LOG(LOG_ERR, "Data channel packets can only be converted to a .srt file\n");
						exit(1);
					}
				}
				/* When was the file created? */
				json_t *created = json_object_get(info, "s");
				if(!created || !json_is_integer(created)) {
					JANUS_LOG(LOG_WARN, "Missing recording created time in info header...\n");
					exit(1);
				}
				c_time = json_integer_value(created);
				/* When was the first frame written? */
				json_t *written = json_object_get(info, "u");
				if(!written || !json_is_integer(written)) {
					JANUS_LOG(LOG_WARN, "Missing recording written time in info header...\n");
					exit(1);
				}
				w_time = json_integer_value(written);
				/* Summary */
				JANUS_LOG(LOG_INFO, "This is %s recording:\n", video ? "a video" : (data ? "a text data" : "an audio"));
				JANUS_LOG(LOG_INFO, "  -- Codec:   %s\n", c);
				JANUS_LOG(LOG_INFO, "  -- Created: %"SCNi64"\n", c_time);
				JANUS_LOG(LOG_INFO, "  -- Written: %"SCNi64"\n", w_time);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Invalid header...\n");
			exit(1);
		}
		/* Skip data for now */
		offset += len;
	}
	if(!working)
		exit(0);
	/* Now let's parse the frames and order them */
	uint32_t last_ts = 0, reset = 0;
	int times_resetted = 0;
	int post_reset_pkts = 0;
	offset = 0;
	/* Timestamp reset related stuff */
	last_ts = 0;
	reset = 0;
	times_resetted = 0;
	post_reset_pkts = 0;
	uint64_t max32 = UINT32_MAX;
	/* Start loop */
	while(working && offset < fsize) {
		/* Read frame header */
		skip = 0;
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			/* Broken packet? Stop here */
			break;
		}
		prebuffer[8] = '\0';
		JANUS_LOG(LOG_VERB, "Header: %s\n", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		JANUS_LOG(LOG_VERB, "  -- Length: %"SCNu16"\n", len);
		offset += 2;
		if(prebuffer[1] == 'J' || (!data && len < 12)) {
			/* Not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Not RTP, skipping\n");
			offset += len;
			continue;
		}
		if(!data && len > 2000) {
			/* Way too large, very likely not RTP, skip */
			JANUS_LOG(LOG_VERB, "  -- Too large packet (%d bytes), skipping\n", len);
			offset += len;
			continue;
		}
		if(data) {
			/* Things are simpler for data, no reordering is needed: start by the data time */
			gint64 when = 0;
			bytes = fread(&when, sizeof(gint64), 1, file);
			when = ntohll(when);
			offset += sizeof(gint64);
			len -= sizeof(gint64);
			/* Generate frame packet and insert in the ordered list */
			janus_pp_frame_packet *p = g_malloc(sizeof(janus_pp_frame_packet));
			p->seq = 0;
			/* We "abuse" the timestamp field for the timing info */
			p->ts = when-c_time;
			p->len = len;
			p->pt = 0;
			p->drop = 0;
			p->offset = offset;
			p->skip = 0;
			p->next = NULL;
			p->prev = NULL;
			if(list == NULL) {
				list = p;
			} else {
				last->next = p;
			}
			last = p;
			/* Done */
			offset += len;
			continue;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		janus_pp_rtp_header *rtp = (janus_pp_rtp_header *)prebuffer;
		JANUS_LOG(LOG_VERB, "  -- RTP packet (ssrc=%"SCNu32", pt=%"SCNu16", ext=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32")\n",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		if(rtp->csrccount) {
			JANUS_LOG(LOG_VERB, "  -- -- Skipping CSRC list\n");
			skip += rtp->csrccount*4;
		}
		if(rtp->extension) {
			janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(prebuffer+12);
			JANUS_LOG(LOG_VERB, "  -- -- RTP extension (type=%"SCNu16", length=%"SCNu16")\n",
				ntohs(ext->type), ntohs(ext->length));
			skip += 4 + ntohs(ext->length)*4;
		}
		if(ssrc == 0) {
			ssrc = ntohl(rtp->ssrc);
			JANUS_LOG(LOG_INFO, "SSRC detected: %"SCNu32"\n", ssrc);
		}
		if(ssrc != ntohl(rtp->ssrc)) {
			JANUS_LOG(LOG_WARN, "Dropping packet with unexpected SSRC: %"SCNu32" != %"SCNu32"\n",
				ntohl(rtp->ssrc), ssrc);
			/* Skip data */
			offset += len;
			count++;
			continue;
		}
		/* Generate frame packet and insert in the ordered list */
		janus_pp_frame_packet *p = g_malloc0(sizeof(janus_pp_frame_packet));
		p->seq = ntohs(rtp->seq_number);
		p->pt = rtp->type;
		/* Due to resets, we need to mess a bit with the original timestamps */
		if(last_ts == 0) {
			/* Simple enough... */
			p->ts = ntohl(rtp->timestamp);
		} else {
			/* Is the new timestamp smaller than the next one, and if so, is it a timestamp reset or simply out of order? */
			gboolean late_pkt = FALSE;
			if(ntohl(rtp->timestamp) < last_ts && (last_ts-ntohl(rtp->timestamp) > 2*1000*1000*1000)) {
				if(post_reset_pkts > post_reset_trigger) {
					reset = ntohl(rtp->timestamp);
					JANUS_LOG(LOG_WARN, "Timestamp reset: %"SCNu32"\n", reset);
					times_resetted++;
					post_reset_pkts = 0;
				}
			} else if(ntohl(rtp->timestamp) > reset && ntohl(rtp->timestamp) > last_ts &&
					(ntohl(rtp->timestamp)-last_ts > 2*1000*1000*1000)) {
				if(post_reset_pkts < post_reset_trigger) {
					JANUS_LOG(LOG_WARN, "Late pre-reset packet after a timestamp reset: %"SCNu32"\n", ntohl(rtp->timestamp));
					late_pkt = TRUE;
					times_resetted--;
				}
			} else if(ntohl(rtp->timestamp) < reset) {
				if(post_reset_pkts < post_reset_trigger) {
					JANUS_LOG(LOG_WARN, "Updating latest timestamp reset: %"SCNu32" (was %"SCNu32")\n", ntohl(rtp->timestamp), reset);
					reset = ntohl(rtp->timestamp);
				} else {
					reset = ntohl(rtp->timestamp);
					JANUS_LOG(LOG_WARN, "Timestamp reset: %"SCNu32"\n", reset);
					times_resetted++;
					post_reset_pkts = 0;
				}
			}
			/* Take into account the number of resets when setting the internal, 64-bit, timestamp */
			p->ts = (times_resetted*max32)+ntohl(rtp->timestamp);
			if(late_pkt)
				times_resetted++;
		}
		p->len = len;
		p->drop = 0;
		if(rtp->padding) {
			/* There's padding data, let's check the last byte to see how much data we should skip */
			fseek(file, offset + len - 1, SEEK_SET);
			bytes = fread(prebuffer, sizeof(char), 1, file);
			uint8_t padlen = (uint8_t)prebuffer[0];
			JANUS_LOG(LOG_VERB, "Padding at sequence number %hu: %d/%d\n",
				ntohs(rtp->seq_number), padlen, p->len);
			p->len -= padlen;
			if((p->len - skip - 12) <= 0) {
				/* Only padding, take note that we should drop the packet later */
				p->drop = 1;
				JANUS_LOG(LOG_VERB, "  -- All padding, marking packet as dropped\n");
			}
		}
		last_ts = ntohl(rtp->timestamp);
		post_reset_pkts++;
		/* Fill in the rest of the details */
		p->offset = offset;
		p->skip = skip;
		p->next = NULL;
		p->prev = NULL;
		if(list == NULL) {
			/* First element becomes the list itself (and the last item), at least for now */
			list = p;
			last = p;
		} else if(!p->drop) {
			/* Check where we should insert this, starting from the end */
			int added = 0;
			janus_pp_frame_packet *tmp = last;
			while(tmp) {
				if(tmp->ts < p->ts) {
					/* The new timestamp is greater than the last one we have, append */
					added = 1;
					if(tmp->next != NULL) {
						/* We're inserting */
						tmp->next->prev = p;
						p->next = tmp->next;
					} else {
						/* Update the last packet */
						last = p;
					}
					tmp->next = p;
					p->prev = tmp;
					break;
				} else if(tmp->ts == p->ts) {
					/* Same timestamp, check the sequence number */
					if(tmp->seq < p->seq && (abs(tmp->seq - p->seq) < 10000)) {
						/* The new sequence number is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq > p->seq && (abs(tmp->seq - p->seq) > 10000)) {
						/* The new sequence number (resetted) is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq == p->seq) {
						/* Maybe a retransmission? Skip */
						JANUS_LOG(LOG_WARN, "Skipping duplicate packet (seq=%"SCNu16")\n", p->seq);
						p->drop = 1;
						break;
					}
				}
				/* If either the timestamp ot the sequence number we just got is smaller, keep going back */
				tmp = tmp->prev;
			}
			if(p->drop) {
				/* We don't need this */
				g_free(p);
			} else if(!added) {
				/* We reached the start */
				p->next = list;
				list->prev = p;
				list = p;
			}
		}
		/* Skip data for now */
		offset += len;
		count++;
	}
	if(!working)
		exit(0);
	
	JANUS_LOG(LOG_INFO, "Counted %"SCNu32" RTP packets\n", count);
	janus_pp_frame_packet *tmp = list;
	count = 0;
	while(tmp) {
		count++;
		if(!data)
			JANUS_LOG(LOG_VERB, "[%10lu][%4d] seq=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s\n", tmp->offset, tmp->len, tmp->seq, tmp->ts, (tmp->ts-list->ts)/90000);
		else
			JANUS_LOG(LOG_VERB, "[%10lu][%4d] time=%"SCNu64"s\n", tmp->offset, tmp->len, tmp->ts);
		tmp = tmp->next;
	}
	JANUS_LOG(LOG_INFO, "Counted %"SCNu32" frame packets\n", count);

	if(video) {
		/* Look for maximum width and height, if possible, and for the average framerate */
		if(vp8 || vp9) {
			if(janus_pp_webm_preprocess(file, list, vp8) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing %s RTP frames...\n", vp8 ? "VP8" : "VP9");
				exit(1);
			}
		} else if(h264) {
			if(janus_pp_h264_preprocess(file, list) < 0) {
				JANUS_LOG(LOG_ERR, "Error pre-processing H.264 RTP frames...\n");
				exit(1);
			}
		}
	}

	if(parse_only) {
		/* We only needed to parse and re-order the packets, we're done here */
		JANUS_LOG(LOG_INFO, "Parsing and reordering completed, bye!\n");
		exit(0);
	}

	if(!video && !data) {
		if(opus) {
			if(janus_pp_opus_create(destination) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .opus file...\n");
				exit(1);
			}
		} else if(g711) {
			if(janus_pp_g711_create(destination) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .wav file...\n");
				exit(1);
			}
		} else if(g722) {
			if(janus_pp_g722_create(destination) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .wav file...\n");
				exit(1);
			}
		}
	} else if(data) {
		if(janus_pp_srt_create(destination) < 0) {
			JANUS_LOG(LOG_ERR, "Error creating .srt file...\n");
			exit(1);
		}
	} else {
		if(vp8 || vp9) {
			if(janus_pp_webm_create(destination, vp8) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .webm file...\n");
				exit(1);
			}
		} else if(h264) {
			if(janus_pp_h264_create(destination) < 0) {
				JANUS_LOG(LOG_ERR, "Error creating .mp4 file...\n");
				exit(1);
			}
		}
	}
	
	/* Loop */
	if(!video && !data) {
		if(opus) {
			if(janus_pp_opus_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing Opus RTP frames...\n");
			}
		} else if(g711) {
			if(janus_pp_g711_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing G.711 RTP frames...\n");
			}
		} else if(g722) {
			if(janus_pp_g722_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing G.722 RTP frames...\n");
			}
		}
	} else if(data) {
		if(janus_pp_srt_process(file, list, &working) < 0) {
			JANUS_LOG(LOG_ERR, "Error processing text data frames...\n");
		}
	} else {
		if(vp8 || vp9) {
			if(janus_pp_webm_process(file, list, vp8, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing %s RTP frames...\n", vp8 ? "VP8" : "VP9");
			}
		} else {
			if(janus_pp_h264_process(file, list, &working) < 0) {
				JANUS_LOG(LOG_ERR, "Error processing H.264 RTP frames...\n");
			}
		}
	}

	/* Clean up */
	if(video) {
		if(vp8 || vp9) {
			janus_pp_webm_close();
		} else {
			janus_pp_h264_close();
		}
	} else if(data) {
		janus_pp_srt_close();
	} else {
		if(opus) {
			janus_pp_opus_close();
		} else if(g711) {
			janus_pp_g711_close();
		} else if(g722) {
			janus_pp_g722_close();
		}
	}
	fclose(file);
	
	file = fopen(destination, "rb");
	if(file == NULL) {
		JANUS_LOG(LOG_INFO, "No destination file %s??\n", destination);
	} else {
		fseek(file, 0L, SEEK_END);
		fsize = ftell(file);
		fseek(file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
		fclose(file);
	}
	janus_pp_frame_packet *temp = list, *next = NULL;
	while(temp) {
		next = temp->next;
		g_free(temp);
		temp = next;
	}

	JANUS_LOG(LOG_INFO, "Bye!\n");
	return 0;
}
