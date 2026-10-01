/*! \file    pp-opus.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .opus files
 * \details  Implementation of the post-processing code (based on libogg)
 * needed to generate .opus files out of Opus RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#if defined(__MACH__) || defined(__FreeBSD__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "pp-avformat.h"
#include "pp-opus.h"
#include "pp-opus-silence.h"
#include "../debug.h"
#include "../version.h"

static gboolean multichannel_opus = FALSE;
static AVFormatContext *fctx;
static AVStream *vStream;

static const uint8_t opus_extradata[19] = {
	'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',
	1, 2, 0, 0, 128, 187,
	0, 0, 0, 0, 0,
};
static const uint8_t multiopus_extradata[27] = {
	'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',
	1, 6, 0, 0, 128, 187,
	0, 0, 0, 0, 1,
	/* FIXME The following is the mapping of the streams: we should
	 * check what was negotiated in the SDP, but for now we hardcode it */
	4, 2, 0, 4, 1, 2, 3, 5
};

/* In case we need to decapsulate RED */
static int red_pt = 0;

/* Supported target formats */
static const char *janus_pp_opus_formats[] = {
	"opus", "ogg", "mka", NULL
};
const char **janus_pp_opus_get_extensions(void) {
	return janus_pp_opus_formats;
}

/* Processing methods */
int janus_pp_opus_create(char *destination, char *metadata, gboolean multiopus, const char *extension, int opusred_pt) {
	if(destination == NULL)
		return -1;

	/* .opus and .ogg are the same thing */
	if(!strcasecmp(extension, "opus"))
		extension = "ogg";
	/* .mka is Matroska audio */
	if(!strcasecmp(extension, "mka"))
		extension = "matroska";

	/* Audio output */
	fctx = janus_pp_create_avformatcontext(extension, metadata, destination);
	if(fctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error allocating context\n");
		return -1;
	}

	multichannel_opus = multiopus;
	if(!multichannel_opus) {
		/* Regular Opus stream */
		vStream = janus_pp_new_audio_avstream(fctx, AV_CODEC_ID_OPUS, 48000, 2, opus_extradata, sizeof(opus_extradata));
	} else {
		/* Multichannel Opus Stream*/
		vStream = janus_pp_new_audio_avstream(fctx, AV_CODEC_ID_OPUS, 48000, 6, multiopus_extradata, sizeof(multiopus_extradata));
	}
	if(vStream == NULL) {
		JANUS_LOG(LOG_ERR, "Error adding stream\n");
		return -1;
	}

	if(avformat_write_header(fctx, NULL) < 0) {
		JANUS_LOG(LOG_ERR, "Error writing header\n");
		return -1;
	}

	if(opusred_pt > 0) {
		red_pt = opusred_pt;
		JANUS_LOG(LOG_INFO, "  -- Enabling RED decapsulation (pt=%d)\n", red_pt);
	}
	return 0;
}

// It assumes ALL the packets are of the 20ms kind
#define OPUS_PACKET_DURATION 48 * 20;

int janus_pp_opus_process(FILE *file, janus_pp_frame_packet *list, gboolean restamping, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, last_seq = 0;
	uint64_t pos = 0;
	double ts = 0.0;
	uint8_t *buffer = g_malloc0(1500);

	/* Before we start, check if we're dealing with RED: if so, we need to pre-traverse the
	 * list to decapsulate all RED packets to Opus packets, filling the blanks if needed */
	if(red_pt > 0) {
		while(*working && tmp != NULL) {
			/* Check if we need to decapsulate RED */
			if(tmp->pt == red_pt) {
				/* RTP payload */
				offset = tmp->offset+12+tmp->skip;
				fseek(file, offset, SEEK_SET);
				len = tmp->len-12-tmp->skip;
				if(len < 1) {
					tmp = tmp->next;
					continue;
				}
				bytes = fread(buffer, sizeof(char), len, file);
				if(bytes != len) {
					JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
					tmp = tmp->next;
					continue;
				}
				uint8_t *payload = buffer;
				int plen = bytes;
				/* Find out how many generations are in the RED packet */
				int gens = 0;
				uint32_t red_block;
				uint8_t follow = 0, block_pt = 0;
				uint16_t ts_offset = 0, block_len = 0;
				GList *lengths = NULL;
				/* Parse the header */
				while(payload != NULL && plen > 0) {
					/* Go through the header for the different generations */
					gens++;
					follow = ((*payload) & 0x80) >> 7;
					block_pt = (*payload) & 0x7F;
					if(follow && plen > 3) {
						/* Read the rest of the header */
						memcpy(&red_block, payload, sizeof(red_block));
						red_block = ntohl(red_block);
						ts_offset = (red_block & 0x00FFFC00) >> 10;
						block_len = (red_block & 0x000003FF);
						JANUS_LOG(LOG_HUGE, "  [%d] f=%u, pt=%u, tsoff=%"SCNu16", blen=%"SCNu16"\n",
							gens, follow, block_pt, ts_offset, block_len);
						lengths = g_list_append(lengths, GUINT_TO_POINTER(block_len));
						payload += 4;
						plen -= 4;
					} else {
						/* Header parsed */
						payload++;
						plen--;
						JANUS_LOG(LOG_HUGE, "  [%d] f=%u, pt=%u, tsoff=0, blen=TBD.\n",
							gens, follow, block_pt);
						break;
					}
				}
				/* Go through the blocks, iterating on the lengths */
				if(lengths != NULL) {
					int tot_gens = gens;
					gens = 0;
					uint16_t length = 0;
					GList *temp = lengths;
					while(temp != NULL) {
						gens++;
						tot_gens--;
						length = GPOINTER_TO_UINT(temp->data);
						if(length > plen) {
							JANUS_LOG(LOG_WARN, "  >> [%d] Broken red payload:\n", gens);
							payload = NULL;
							break;
						}
						if(length > 0) {
							/* Redundant data, check if we have this packet already */
							JANUS_LOG(LOG_HUGE, "  >> [%d] plen=%"SCNu16"\n", gens, length);
							if(tmp->prev != NULL) {
								/* Go back until we either find it, or find a hole where it's supposed to be */
								janus_pp_frame_packet *prev = tmp->prev;
								ts_offset = tot_gens*960;
								while(prev) {
									if(prev->ts < ts_offset) {
										JANUS_LOG(LOG_WARN, "Redundant packet precedes start of recording, ignoring\n");
										break;
									} else if(prev->ts == (tmp->ts - ts_offset)) {
										/* We have this packet already */
										break;
									} else if(prev->ts < (tmp->ts - ts_offset)) {
										/* We're missing this packet, insert it here */
										JANUS_LOG(LOG_WARN, "Missing packet (ts=%"SCNi64"), restoring using redundant information\n",
											(tmp->ts - ts_offset));
										/* TODO */
										janus_pp_frame_packet *p = g_malloc0(sizeof(janus_pp_frame_packet));
										p->header = tmp->header;
										p->version = tmp->version;
										p->ts = tmp->ts - ts_offset;
										p->p_ts = tmp->p_ts - ts_offset;
										p->seq = tmp->seq - tot_gens;
										p->pt = block_pt;
										p->drop = tmp->drop;
										p->skip = tmp->skip;
										p->offset = (payload-buffer);
										p->len = (length + 12 + tmp->skip);
										p->audiolevel = tmp->audiolevel;
										p->next = prev->next;
										p->next->prev = p;
										p->prev = prev;
										prev->next = p;
										break;
									}
									prev = prev->prev;
								}
							}
							payload += length;
							plen -= length;
						}
						temp = temp->next;
					}
					/* The last block is the primary data, so just update the current
					 * stored packet with the Opus payload type and the right offset/len */
					gens++;
					JANUS_LOG(LOG_HUGE, "  >> [%d] plen=%d\n", gens, plen);
					tmp->pt = block_pt;
					tmp->offset += (payload-buffer);
					tmp->len = (plen + 12 + tmp->skip);
					g_list_free(lengths);
				}
				tmp = tmp->next;
				continue;
			}
			tmp = tmp->next;
		}
	}

	/* Get to work */
	tmp = list;
#ifdef FF_API_INIT_PACKET
	AVPacket *pkt = av_packet_alloc();
#else
	AVPacket apkt = { 0 }, *pkt = &apkt;
#endif
	AVRational timebase = {1, 48000};

	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && ((tmp->ts - tmp->prev->ts)/48 > 20)) {
			int silence_count = 0;
			if(tmp->seq != tmp->prev->seq+1) {
				/* Packet Lost */
				JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
					tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
				/* insert 20ms silence packets before the current packet */
				silence_count = (tmp->ts - tmp->prev->ts)/48/20 - 1;
			} else if(restamping && tmp->restamped == 1) {
				/* Packet restamped due to RTP clock issues */
				JANUS_LOG(LOG_WARN, "Restamped packet detected (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
					tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
				/* insert 20ms silence packets before the current packet */
				silence_count = (tmp->ts - tmp->prev->ts)/48/20 - 1;
			} else {
				/* plen > 20 ms, DTX ?*/
				JANUS_LOG(LOG_WARN, "DTX packet detected (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
					tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
				/* insert 20ms silence packets for the whole DTX duration */
				silence_count = (tmp->ts - tmp->prev->ts)/48/20;
				/* drop this packet since it's DTX silence */
				tmp->drop = 1;
			}
			/* use ts differ to insert silence packet */
			pos = (tmp->prev->ts - list->ts) / 48 / 20 + 1;
			JANUS_LOG(LOG_WARN, "[FILL] pos: %06"SCNu64", writing silences (count=%d)\n", pos, silence_count);
			int i=0;
			pos = tmp->prev->ts - list->ts;
			for(i=0; i<silence_count; i++) {
				pos += OPUS_PACKET_DURATION;
				if(tmp->next != NULL && pos >= (tmp->next->ts - list->ts)) {
					JANUS_LOG(LOG_WARN, "[SKIP] pos: %06" SCNu64 ", skipping remaining silence\n", pos / 48 / 20 + 1);
					break;
				}
#ifdef FF_API_INIT_PACKET
				av_packet_unref(pkt);
#endif
				pkt->stream_index = 0;
				pkt->data = opus_silence;
				pkt->size = sizeof(opus_silence);
				pkt->pts = pkt->dts = av_rescale_q(pos, timebase, fctx->streams[0]->time_base);
				pkt->duration = OPUS_PACKET_DURATION;

				int res = av_write_frame(fctx, pkt);
				if(res < 0) {
					JANUS_LOG(LOG_ERR, "Error writing audio frame to file... (error %d, %s)\n",
						res, av_err2str(res));
				}
			}
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked audio packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/48000);
			tmp = tmp->next;
			continue;
		}
		if(red_pt > 0 && tmp->pt == red_pt) {
			/* There's still a RED packet in the list? Shouldn't happen, drop it */
			tmp = tmp->next;
			continue;
		}
		if(tmp->audiolevel != -1) {
			ts = (double)(tmp->ts - list->ts)/(double)48000;
			JANUS_LOG(LOG_VERB, "[audiolevel][%.2f] Audio level: %d dB\n", ts, tmp->audiolevel);
		}
		guint16 diff = tmp->prev == NULL ? 1 : (tmp->seq - tmp->prev->seq);
		len = 0;
		/* RTP payload */
		offset = tmp->offset+12+tmp->skip;
		fseek(file, offset, SEEK_SET);
		len = tmp->len-12-tmp->skip;
		if(len < 1) {
			tmp = tmp->next;
			continue;
		}
		bytes = fread(buffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			tmp = tmp->next;
			continue;
		}
		if(last_seq == 0)
			last_seq = tmp->seq;
		if(tmp->seq < last_seq) {
			last_seq = tmp->seq;
		}
		pos = tmp->prev != NULL ? ((tmp->prev->ts - list->ts) / 48 / 20 + 1) : 0;
		JANUS_LOG(LOG_VERB, "pos: %06"SCNu64", writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			pos, bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/48000);
#ifdef FF_API_INIT_PACKET
		av_packet_unref(pkt);
#else
		av_init_packet(pkt);
#endif
		pkt->stream_index = 0;
		pkt->data = buffer;
		pkt->size = bytes;
		pkt->pts = pkt->dts = av_rescale_q(tmp->ts - list->ts, timebase, fctx->streams[0]->time_base);
		pkt->duration = OPUS_PACKET_DURATION;

		if(av_write_frame(fctx, pkt) < 0) {
			JANUS_LOG(LOG_ERR, "Error writing audio frame to file...\n");
		}

		tmp = tmp->next;
	}
	g_free(buffer);
#ifdef FF_API_INIT_PACKET
	av_packet_free(&pkt);
#endif
	return 0;
}

void janus_pp_opus_close(void) {
	if(fctx != NULL) {
                av_write_trailer(fctx);
                avio_close(fctx->pb);
                avformat_free_context(fctx);
	}
}
