/*! \file    pp-av1.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files out of AV1 frames
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of AV1 RTP frames.
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

#include "pp-av1.h"
#include "../debug.h"


#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))

#if LIBAVCODEC_VER_AT_LEAST(51, 42)
#define PIX_FMT_YUV420P AV_PIX_FMT_YUV420P
#endif

#if LIBAVCODEC_VER_AT_LEAST(56, 56)
#ifndef CODEC_FLAG_GLOBAL_HEADER
#define CODEC_FLAG_GLOBAL_HEADER AV_CODEC_FLAG_GLOBAL_HEADER
#endif
#ifndef FF_INPUT_BUFFER_PADDING_SIZE
#define FF_INPUT_BUFFER_PADDING_SIZE AV_INPUT_BUFFER_PADDING_SIZE
#endif
#endif

#if LIBAVCODEC_VER_AT_LEAST(57, 14)
#define USE_CODECPAR
#endif


/* MP4 output */
static AVFormatContext *fctx;
static AVStream *vStream;
#ifdef USE_CODECPAR
static AVCodecContext *vEncoder;
#endif
static int max_width = 0, max_height = 0, fps = 0;


int janus_pp_av1_create(char *destination, char *metadata, gboolean faststart) {
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
	/* MP4 output */
	fctx = avformat_alloc_context();
	if(fctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error allocating context\n");
		return -1;
	}
	/* We save the metadata part as a comment (see #1189) */
	if(metadata)
		av_dict_set(&fctx->metadata, "comment", metadata, 0);
	fctx->oformat = av_guess_format("mp4", NULL, NULL);
	if(fctx->oformat == NULL) {
		JANUS_LOG(LOG_ERR, "Error guessing format\n");
		return -1;
	}
    char filename[1024];
	snprintf(filename, sizeof(filename), "%s", destination);
#ifdef USE_CODECPAR
	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_AV1);
	if(!codec) {
		/* Error opening video codec */
		JANUS_LOG(LOG_ERR, "Encoder not available\n");
		return -1;
	}
	fctx->video_codec = codec;
	fctx->oformat->video_codec = codec->id;
	vStream = avformat_new_stream(fctx, codec);
	vStream->id = fctx->nb_streams-1;
	vEncoder = avcodec_alloc_context3(codec);
	vEncoder->width = max_width;
	vEncoder->height = max_height;
	vEncoder->time_base = (AVRational){ 1, fps };
	vEncoder->pix_fmt = AV_PIX_FMT_YUV420P;
	vEncoder->flags |= CODEC_FLAG_GLOBAL_HEADER;
	if(avcodec_open2(vEncoder, codec, NULL) < 0) {
		/* Error opening video codec */
		JANUS_LOG(LOG_ERR, "Encoder error\n");
		return -1;
	}
	avcodec_parameters_from_context(vStream->codecpar, vEncoder);
#else
	vStream = avformat_new_stream(fctx, 0);
	if(vStream == NULL) {
		JANUS_LOG(LOG_ERR, "Error adding stream\n");
		return -1;
	}
#if LIBAVCODEC_VER_AT_LEAST(53, 21)
	avcodec_get_context_defaults3(vStream->codec, AVMEDIA_TYPE_VIDEO);
#else
	avcodec_get_context_defaults2(vStream->codec, AVMEDIA_TYPE_VIDEO);
#endif
#if LIBAVCODEC_VER_AT_LEAST(54, 25)
	vStream->codec->codec_id = AV_CODEC_ID_AV1;
#else
	vStream->codec->codec_id = CODEC_ID_AV1;
#endif
	vStream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
	vStream->codec->time_base = (AVRational){1, fps};
	vStream->time_base = (AVRational){1, 90000};
	vStream->codec->width = max_width;
	vStream->codec->height = max_height;
	vStream->codec->pix_fmt = PIX_FMT_YUV420P;
	//~ if (fctx->flags & AVFMT_GLOBALHEADER)
		vStream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
#endif
	AVDictionary *options = NULL;
	if(faststart)
		av_dict_set(&options, "movflags", "+faststart", 0);

	int res = avio_open2(&fctx->pb, filename, AVIO_FLAG_WRITE, NULL, &options);
	if(res < 0) {
		JANUS_LOG(LOG_ERR, "Error opening file for output (%d)\n", res);
		return -1;
	}
	if(avformat_write_header(fctx, &options) < 0) {
		JANUS_LOG(LOG_ERR, "Error writing header\n");
		return -1;
	}
	return 0;
}

int janus_pp_av1_preprocess(FILE *file, janus_pp_frame_packet *list) {
	if(!file || !list)
		return -1;
	janus_pp_frame_packet *tmp = list;
	int bytes = 0, min_ts_diff = 0, max_ts_diff = 0;
	int rotation = -1;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	while(tmp) {
		if(tmp->prev != NULL && tmp->ts > tmp->prev->ts) {
			if(tmp->ts > tmp->prev->ts) {
				int diff = tmp->ts - tmp->prev->ts;
				if(min_ts_diff == 0 || min_ts_diff > diff)
					min_ts_diff = diff;
				if(max_ts_diff == 0 || max_ts_diff < diff)
					max_ts_diff = diff;
			}
			if(tmp->seq - tmp->prev->seq > 1) {
				JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
					tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/90000);
			}
		}
		/* Parse AV1 header now */
			/* TODO */
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked video packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/90000);
			tmp = tmp->next;
			continue;
		}
		if(tmp->rotation != -1 && tmp->rotation != rotation) {
			rotation = tmp->rotation;
			JANUS_LOG(LOG_INFO, "Video rotation: %d degrees\n", rotation);
		}
		tmp = tmp->next;
	}
	int mean_ts = min_ts_diff;	/* FIXME: was an actual mean, (max_ts_diff+min_ts_diff)/2; */
	fps = (90000/(mean_ts > 0 ? mean_ts : 30));
	JANUS_LOG(LOG_INFO, "  -- %dx%d (fps [%d,%d] ~ %d)\n", max_width, max_height, min_ts_diff, max_ts_diff, fps);
	if(max_width == 0 && max_height == 0) {
		JANUS_LOG(LOG_WARN, "No resolution info?? assuming 640x480...\n");
		max_width = 640;
		max_height = 480;
	}
	if(max_width < 160) {
		JANUS_LOG(LOG_WARN, "Width seems weirdly low (%d), setting 640 instead...\n", max_width);
		max_width = 640;
	}
	if(max_height < 120) {
		JANUS_LOG(LOG_WARN, "Height seems weirdly low (%d), setting 480 instead...\n", max_height);
		max_height = 480;
	}
	if(fps == 0) {
		JANUS_LOG(LOG_WARN, "No fps?? assuming 1...\n");
		fps = 1;	/* Prevent divide by zero error */
	}
	return 0;
}

int janus_pp_av1_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;

	int bytes = 0, numBytes = max_width*max_height*3;	/* FIXME */
	uint8_t *received_frame = g_malloc0(numBytes);
	uint8_t *buffer = g_malloc0(numBytes), *start = buffer;
	int len = 0, frameLen = 0;
	int keyFrame = 0;
	gboolean keyframe_found = FALSE;

	while(*working && tmp != NULL) {
		keyFrame = 0;
		frameLen = 0;
		len = 0;
		while(tmp != NULL) {
			if(tmp->drop) {
				/* Check if timestamp changes: marker bit is not mandatory, and may be lost as well */
				if(tmp->next == NULL || tmp->next->ts > tmp->ts)
					break;
				tmp = tmp->next;
				continue;
			}
			/* RTP payload */
			buffer = start;
			fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
			len = tmp->len-12-tmp->skip;
			if(len < 1) {
				if(tmp->next == NULL || tmp->next->ts > tmp->ts)
					break;
				tmp = tmp->next;
				continue;
			}
			bytes = fread(buffer, sizeof(char), len, file);
			if(bytes != len) {
				JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
				if(tmp->next == NULL || tmp->next->ts > tmp->ts)
					break;
				tmp = tmp->next;
				continue;
			}
			/* AV1 depay */
				/* TODO */
			/* Check if timestamp changes: marker bit is not mandatory, and may be lost as well */
			if(tmp->next == NULL || tmp->next->ts > tmp->ts)
				break;
			tmp = tmp->next;
		}
		if(frameLen > 0) {
			/* Save the frame */
			memset(received_frame + frameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);

			AVPacket packet;
			av_init_packet(&packet);
			packet.stream_index = 0;
			packet.data = received_frame;
			packet.size = frameLen;
			if(keyFrame)
				packet.flags |= AV_PKT_FLAG_KEY;

			/* First we save to the file... */
			packet.dts = tmp->ts-list->ts;
			packet.pts = tmp->ts-list->ts;
			JANUS_LOG(LOG_HUGE, "%"SCNu64" - %"SCNu64" --> %"SCNu64"\n",
				tmp->ts, list->ts, packet.pts);
			if(fctx) {
				int res = av_write_frame(fctx, &packet);
				if(res < 0) {
					JANUS_LOG(LOG_ERR, "Error writing video frame to file... (error %d)\n", res);
				}
			}
		}
		tmp = tmp->next;
	}
	g_free(received_frame);
	g_free(start);
	return 0;
}

/* Close MP4 file */
void janus_pp_av1_close(void) {
	if(fctx != NULL)
		av_write_trailer(fctx);
#ifdef USE_CODECPAR
	if(vEncoder != NULL)
		avcodec_close(vEncoder);
#else
	if(vStream != NULL && vStream->codec != NULL)
		avcodec_close(vStream->codec);
#endif
	if(fctx != NULL && fctx->streams[0] != NULL) {
#ifndef USE_CODECPAR
		av_free(fctx->streams[0]->codec);
#endif
		av_free(fctx->streams[0]);
	}
	if(fctx != NULL) {
		avio_close(fctx->pb);
		av_free(fctx);
	}
}
