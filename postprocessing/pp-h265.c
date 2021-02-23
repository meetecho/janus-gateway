/*! \file    pp-h265.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files out of H.265 frames
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of H.265 RTP frames.
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

#include "pp-h265.h"
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


int janus_pp_h265_create(char *destination, char *metadata, gboolean faststart) {
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
	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H265);
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
	vStream->codec->codec_id = AV_CODEC_ID_H265;
#else
	vStream->codec->codec_id = CODEC_ID_H265;
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

/* Helpers to decode Exp-Golomb */
static uint32_t janus_pp_h265_eg_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}

static uint32_t janus_pp_h265_eg_getbits(uint8_t *base, uint8_t num, uint32_t *offset) {
	uint32_t res = 0;
	int32_t i = 0;
	for(i=num-1; i>=0; i--) {
		res |= janus_pp_h265_eg_getbit(base, (*offset)++) << i;
	}
	return res;
}

static uint32_t janus_pp_h265_eg_decode(uint8_t *base, uint32_t *offset) {
	uint32_t zeros = 0;
	while(janus_pp_h265_eg_getbit(base, (*offset)++) == 0)
		zeros++;
	uint32_t res = 1 << zeros;
	int32_t i = 0;
	for(i=zeros-1; i>=0; i--) {
		res |= janus_pp_h265_eg_getbit(base, (*offset)++) << i;
	}
	return res-1;
}

/* Helper to parse a SPS (only to get the video resolution) */
static void janus_pp_h265_parse_sps(char *buffer, int *width, int *height) {
	/* Get the layer ID first */
	uint16_t unit = 0;
	memcpy(&unit, buffer, sizeof(uint16_t));
	unit = ntohs(unit);
	uint8_t lid = (unit & 0x01F8) >> 3;
	gboolean multilayer = (lid > 0);
	uint8_t sps_maxorext_m1 = 0;
	/* Evaluate/skip everything until we get to the resolution */
	uint32_t offset = 0;
	uint8_t *base = (uint8_t *)(buffer+2);
	int i = 0;
	/* Skip sps_video_parameter_set_id (4 bits) */
	janus_pp_h265_eg_getbits(base, 4, &offset);
	if(lid == 0) {
		/* Skip sps_max_sub_layers_minus1 (3 bits) */
		sps_maxorext_m1 = janus_pp_h265_eg_getbits(base, 3, &offset);
	} else {
		/* Skip sps_ext_or_max_sub_layers_minus1 (3 bits) */
		sps_maxorext_m1 = janus_pp_h265_eg_getbits(base, 3, &offset);
		if(sps_maxorext_m1 == 7)
			multilayer = TRUE;
	}
	if(!multilayer) {
		/* Skip sps_temporal_id_nesting_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* profile_tier_level is variable, start skipping general_profile_space (2 bits) */
		janus_pp_h265_eg_getbits(base, 2, &offset);
		/* Skip general_tier_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_profile_idc (5 bits) */
		janus_pp_h265_eg_getbits(base, 5, &offset);
		/* Skip general_profile_compatibility_flag (32 bits) */
		janus_pp_h265_eg_getbits(base, 32, &offset);
		/* Skip general_progressive_source_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_interlaced_source_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_non_packed_constraint_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_frame_only_constraint_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_reserved_zero_43bits (43 bits) */
		janus_pp_h265_eg_getbits(base, 43, &offset);
		/* Skip general_reserved_zero_bit (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
		/* Skip general_level_idc (8 bits) */
		janus_pp_h265_eg_getbits(base, 8, &offset);
		/* Skip sub layer bits (2 per layer-1) */
		if(sps_maxorext_m1) {
			for(i=0; i<8; i++) {
				janus_pp_h265_eg_getbit(base, offset++);
				janus_pp_h265_eg_getbit(base, offset++);
			}
		}
		/* FIXME There are other things to skip for multiple layers... */
	}
	/* Skip sps_seq_parameter_set_id */
	janus_pp_h265_eg_decode(base, &offset);
	/* Skip chroma_format_idc */
	uint32_t cfidc = janus_pp_h265_eg_decode(base, &offset);
	if(cfidc == 3) {
		/* Skip separate_colour_plane_flag (1 bit) */
		janus_pp_h265_eg_getbit(base, offset++);
	}
	/* We need pic_width_in_luma_samples and pic_heigth_in_luma_samples */
	*width = janus_pp_h265_eg_decode(base, &offset);
	*height = janus_pp_h265_eg_decode(base, &offset);
}

int janus_pp_h265_preprocess(FILE *file, janus_pp_frame_packet *list) {
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
		/* Read the packet */
		fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
		int len = tmp->len-12-tmp->skip;
		if(len < 1) {
			tmp = tmp->next;
			continue;
		}
		bytes = fread(prebuffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			tmp->drop = TRUE;
			tmp = tmp->next;
			continue;
		}
		/* Parse H.265 header now */
		if(len < 2) {
			JANUS_LOG(LOG_WARN, "Packet too small...\n");
			tmp->drop = TRUE;
			if(tmp->next == NULL || tmp->next->ts > tmp->ts)
				break;
			tmp = tmp->next;
			continue;
		}
		uint16_t unit = 0;
		memcpy(&unit, prebuffer, sizeof(uint16_t));
		unit = ntohs(unit);
		uint8_t fbit = (unit & 0x8000) >> 15;
		uint8_t type = (unit & 0x7E00) >> 9;
		uint8_t lid = (unit & 0x01F8) >> 3;
		uint8_t tid = (unit & 0x0007);
		if(type == 32) {
			/* VPS */
			JANUS_LOG(LOG_HUGE, "[VPS] %u/%u/%u/%u\n", fbit, type, lid, tid);
		} else if(type == 33) {
			/* SPS */
			JANUS_LOG(LOG_HUGE, "[SPS] %u/%u/%u/%u\n", fbit, type, lid, tid);
			/* Get rid of the Emulation Prevention code, if present */
			int i = 0, j = 0, zeros = 0;
			for(i=0; i<len; i++) {
				if(zeros == 2 && prebuffer[i] == 0x03) {
					/* Found, get rid of it */
					i++;
					zeros = 0;
				}
				/* Update the content of the buffer as we go along */
				prebuffer[j] = prebuffer[i];
				if(prebuffer[i] == 0x00) {
					/* Found a zero, may be part of a start code */
					zeros++;
				} else {
					/* Not a zero, so not the beginning of a start code */
					zeros = 0;
				}
				j++;
			}
			/* Update the length of the buffer */
			len = j;
			/* Parse to get width/height */
			int width = 0, height = 0;
			janus_pp_h265_parse_sps(prebuffer, &width, &height);
			if(width*height > max_width*max_height) {
				max_width = width;
				max_height = height;
			}
		} else if(type == 34) {
			/* PPS */
			JANUS_LOG(LOG_HUGE, "[PPS] %u/%u/%u/%u\n", fbit, type, lid, tid);
		} else if(type == 49) {
			/* FU */
			uint8_t fuh = prebuffer[2];
			uint8_t startbit = (fuh & 0x80) >> 7;
			uint8_t endbit = (fuh & 0x40) >> 6;
			uint16_t nut = (fuh & 0x1F);
			JANUS_LOG(LOG_HUGE, "[FU] %u/%u/%u/%u, %u/%u/%u\n", fbit, type, lid, tid, startbit, endbit, nut);
		}
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

int janus_pp_h265_process(FILE *file, janus_pp_frame_packet *list, int *working) {
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
			/* H.265 depay */
			if(len < 2) {
				JANUS_LOG(LOG_WARN, "Packet too small...\n");
				if(tmp->next == NULL || tmp->next->ts > tmp->ts)
					break;
				tmp = tmp->next;
				continue;
			}
			/* Read the header and skip it */
			uint16_t unit = 0;
			memcpy(&unit, buffer, sizeof(uint16_t));
			unit = ntohs(unit);
			uint8_t type = (unit & 0x7E00) >> 9;
			if(type == 32 || type == 33 || type == 34) {
				if(type == 32 || type == 33) {
					keyFrame = 1;
					if(!keyframe_found) {
						keyframe_found = TRUE;
						JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
					}
				}
				/* Add the NAL delimiter */
				uint8_t *temp = received_frame + frameLen;
				memset(temp, 0x00, 1);
				memset(temp + 1, 0x00, 1);
				memset(temp + 2, 0x01, 1);
				frameLen += 3;
			}
			if(type == 49) {
				/* Check if this is the beginning of the FU */
				uint8_t fuh = *(buffer+2);
				uint8_t startbit = (fuh & 0x80) >> 7;
				if(startbit) {
					/* Add the NAL delimiter */
					uint8_t *temp = received_frame + frameLen;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x01, 1);
					frameLen += 3;
					/* Update the NAL unit */
					uint16_t fbit = (unit & 0x8000);
					uint16_t nut = (fuh & 0x1F);
					uint16_t lid = (unit & 0x01F8);
					uint16_t tid = (unit & 0x0007);
					unit = fbit + (nut << 9) + lid + tid;
					unit = htons(unit);
					memcpy(received_frame + frameLen, &unit, sizeof(uint16_t));
					frameLen += 2;
				}
				/* Skip the FU header */
				buffer += 3;
				len -= 3;
			}
			/* Frame manipulation */
			memcpy(received_frame + frameLen, buffer, len);
			frameLen += len;
			if(len == 0)
				break;
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
void janus_pp_h265_close(void) {
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
