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

static AVFormatContext *fctx;
static AVStream *vStream;

static const uint8_t opus_extradata[19] = {
	'O', 'p', 'u', 's', 'H', 'e', 'a', 'd',
	1, 2, 0, 0, 128, 187,
	0, 0, 0, 0, 0,
};

/* Supported target formats */
static const char *janus_pp_opus_formats[] = {
	"opus", "ogg", "mka", NULL
};
const char **janus_pp_opus_get_extensions(void) {
	return janus_pp_opus_formats;
}

/* Processing methods */
int janus_pp_opus_create(char *destination, char *metadata, const char *extension) {
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

	vStream = janus_pp_new_audio_avstream(fctx, AV_CODEC_ID_OPUS, 48000, 2, opus_extradata, sizeof(opus_extradata));
	if(vStream == NULL) {
		JANUS_LOG(LOG_ERR, "Error adding stream\n");
		return -1;
	}

	if(avformat_write_header(fctx, NULL) < 0) {
		JANUS_LOG(LOG_ERR, "Error writing header\n");
		return -1;
	}
	return 0;
}

// It assumes ALL the packets are of the 20ms kind
#define OPUS_PACKET_DURATION 48 * 20;

int janus_pp_opus_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint64_t pos = 0, nextPos = 0;
	uint8_t *buffer = g_malloc0(1500);
	AVPacket *pkt = av_packet_alloc();
	AVRational timebase = {1, 48000};

	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && ((tmp->ts - tmp->prev->ts)/48/20 > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
			/* use ts differ to insert silence packet */
			int silence_count = (tmp->ts - tmp->prev->ts)/48/20 - 1;
			pos = (tmp->prev->ts - list->ts) / 48 / 20 + 1;
			JANUS_LOG(LOG_WARN, "[FILL] pos: %06"SCNu64", writing silences (count=%d)\n", pos, silence_count);
			int i=0;
			pos = tmp->prev->ts - list->ts;
			for(i=0; i<silence_count; i++) {
				pos += OPUS_PACKET_DURATION;
				if(tmp->next != NULL)
					nextPos = tmp->next->ts - list->ts;
				if(pos >= nextPos) {
					JANUS_LOG(LOG_WARN, "[SKIP] pos: %06" SCNu64 ", skipping remaining silence\n", pos / 48 / 20 + 1);
					break;
				}
				av_packet_unref(pkt);
				pkt->stream_index = 0;
				pkt->data = opus_silence;
				pkt->size = sizeof(opus_silence);
				pkt->pts = pkt->dts = av_rescale_q(pos, timebase, fctx->streams[0]->time_base);
				pkt->duration = OPUS_PACKET_DURATION;

				if(av_write_frame(fctx, pkt) < 0) {
					JANUS_LOG(LOG_ERR, "Error writing audio frame to file...\n");
				}
			}
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked audio packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/48000);
			tmp = tmp->next;
			continue;
		}
		if(tmp->audiolevel != -1) {
			JANUS_LOG(LOG_VERB, "Audio level: %d dB\n", tmp->audiolevel);
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
			steps++;
		}
		JANUS_LOG(LOG_VERB, "pos: %06"SCNu64", writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			pos, bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/48000);
		av_packet_unref(pkt);
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
	av_packet_free(&pkt);
	return 0;
}

void janus_pp_opus_close(void) {
	if(fctx != NULL) {
                av_write_trailer(fctx);
                avio_close(fctx->pb);
                avformat_free_context(fctx);
	}
}
