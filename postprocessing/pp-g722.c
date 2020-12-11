/*! \file    pp-g722.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files out of G.722 (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of G.722 RTP frames.
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

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "pp-g722.h"
#include "../debug.h"


#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))

#if LIBAVCODEC_VER_AT_LEAST(57, 14)
#define USE_CODECPAR
#endif


/* G.722 decoder */
static AVCodec *dec_codec;			/* FFmpeg decoding codec */
static AVCodecContext *dec_ctx;		/* FFmpeg decoding context */

/* WAV header */
typedef struct janus_pp_g711_wav {
	char riff[4];
	uint32_t len;
	char wave[4];
	char fmt[4];
	uint32_t formatsize;
	uint16_t format;
	uint16_t channels;
	uint32_t samplerate;
	uint32_t avgbyterate;
	uint16_t samplebytes;
	uint16_t channelbits;
	char data[4];
	uint32_t blocksize;
} janus_pp_g711_wav;
static FILE *wav_file = NULL;


/* Processing methods */
int janus_pp_g722_create(char *destination, char *metadata) {
	if(destination == NULL)
		return -1;
	/* Setup FFmpeg */
#if ( LIBAVFORMAT_VERSION_INT < AV_VERSION_INT(58,9,100) )
	av_register_all();
#endif
	/* Adjust logging to match the postprocessor's */
	av_log_set_level(janus_log_level <= LOG_NONE ? AV_LOG_QUIET :
		(janus_log_level == LOG_FATAL ? AV_LOG_FATAL :
			(janus_log_level == LOG_ERR ? AV_LOG_ERROR :
				(janus_log_level == LOG_WARN ? AV_LOG_WARNING :
					(janus_log_level == LOG_INFO ? AV_LOG_INFO :
						(janus_log_level == LOG_VERB ? AV_LOG_VERBOSE : AV_LOG_DEBUG))))));
	/* Create decoding context */
#if LIBAVCODEC_VER_AT_LEAST(53, 21)
	int codec = AV_CODEC_ID_ADPCM_G722;
#else
	int codec = CODEC_ID_ADPCM_G722;
#endif
	dec_codec = avcodec_find_decoder(codec);
	if(!dec_codec) {
		/* Error finding G.722 codec... */
		JANUS_LOG(LOG_ERR, "Unsupported decoder (G.722)...\n");
		return -1;
	}
	dec_ctx = avcodec_alloc_context3(dec_codec);
	if(!dec_ctx) {
		/* Error creating FFmpeg context... */
		JANUS_LOG(LOG_ERR, "Error creating FFmpeg context...\n");
		return -1;
	}
	if(avcodec_open2(dec_ctx, dec_codec, NULL) < 0) {
		/* Error finding video codec... */
		JANUS_LOG(LOG_ERR, "Error opening G.722 decoder...\n");
		return -1;
	}
	/* Create wav file */
	wav_file = fopen(destination, "wb");
	if(wav_file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		return -1;
	}
	/* Add header */
	JANUS_LOG(LOG_INFO, "Writing .wav file header\n");
	janus_pp_g711_wav header = {
		{'R', 'I', 'F', 'F'},
		0,
		{'W', 'A', 'V', 'E'},
		{'f', 'm', 't', ' '},
		16,
		1,
		1,
		16000,
		16000,
		2,
		16,
		{'d', 'a', 't', 'a'},
		0
	};
	/* Note: .wav files don't seem to support arbitrary comments
	 * so there's nothing we can do with the provided metadata*/
	if(fwrite(&header, 1, sizeof(header), wav_file) != sizeof(header)) {
		JANUS_LOG(LOG_ERR, "Couldn't write WAV header, expect problems...\n");
	}
	fflush(wav_file);
	return 0;
}

int janus_pp_g722_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint8_t *buffer = g_malloc0(1500);
	int16_t samples[1500];
	memset(samples, 0, sizeof(samples));
	uint num_samples = 320;
	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && ((tmp->ts - tmp->prev->ts)/8/20 > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/8000);
			int silence_count = (tmp->ts - tmp->prev->ts)/8/20 - 1;
			int i=0;
			for(i=0; i<silence_count; i++) {
				JANUS_LOG(LOG_WARN, "[FILL] Writing silence (seq=%d, index=%d)\n",
					tmp->prev->seq+i+1, i+1);
				/* Add silence */
				memset(samples, 0, num_samples*2);
				if(wav_file != NULL) {
					if(fwrite(samples, sizeof(uint16_t), num_samples, wav_file) != num_samples) {
						JANUS_LOG(LOG_ERR, "Couldn't write sample...\n");
					}
					fflush(wav_file);
				}
			}
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked audio packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/8000);
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
		JANUS_LOG(LOG_VERB, "Writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/8000);
		/* Decode and save to wav */
		AVPacket avpacket;
		av_init_packet(&avpacket);
		avpacket.data = (uint8_t *)buffer;
		avpacket.size = bytes;
		int err = 0;
#if LIBAVCODEC_VER_AT_LEAST(55,28)
		AVFrame *frame = av_frame_alloc();
#else
		AVFrame *frame = avcodec_alloc_frame();
#endif
#ifdef USE_CODECPAR
		err = avcodec_send_packet(dec_ctx, &avpacket);
		if(err < 0) {
			JANUS_LOG(LOG_ERR, "Error decoding audio frame... (%d)\n", err);
		} else {
			err = avcodec_receive_frame(dec_ctx, frame);
		}
		if(err > -1) {
#else
		int got_frame = 0;
		err = avcodec_decode_audio4(dec_ctx, frame, &got_frame, &avpacket);
		if(err < 0 || !got_frame) {
			JANUS_LOG(LOG_ERR, "Error decoding audio frame... (%d)\n", err);
		} else {
#endif
			if(wav_file != NULL) {
				int data_size = av_get_bytes_per_sample(dec_ctx->sample_fmt);
				int i=0, ch=0;
				for(i=0; i<frame->nb_samples; i++) {
					for(ch=0; ch<dec_ctx->channels; ch++) {
						fwrite(frame->data[ch] + data_size*i, 1, data_size, wav_file);
					}
				}
				fflush(wav_file);
			}
		}
#if LIBAVCODEC_VER_AT_LEAST(55,28)
		av_frame_free(&frame);
#else
		avcodec_free_frame(&frame);
#endif
		tmp = tmp->next;
	}
	g_free(buffer);
	return 0;
}

void janus_pp_g722_close(void) {
	/* Close decoder */
	avcodec_close(dec_ctx);
	av_free(dec_ctx);
	dec_ctx = NULL;
	/* Flush and close file */
	if(wav_file != NULL) {
		/* Update the header */
		fseek(wav_file, 0, SEEK_END);
		uint32_t size = ftell(wav_file) - 8;
		fseek(wav_file, 4, SEEK_SET);
		fwrite(&size, sizeof(uint32_t), 1, wav_file);
		size += 8;
		fseek(wav_file, 40, SEEK_SET);
		fwrite(&size, sizeof(uint32_t), 1, wav_file);
		fflush(wav_file);
		fclose(wav_file);
	}
	wav_file = NULL;
}
