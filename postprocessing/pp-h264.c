/*! \file    pp-h264.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of H.264 RTP frames.
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

#include "pp-h264.h"
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


int janus_pp_h264_create(char *destination, char *metadata, gboolean faststart) {
	if(destination == NULL)
		return -1;
	/* Setup FFmpeg */
	av_register_all();
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
	snprintf(fctx->filename, sizeof(fctx->filename), "%s", destination);
#ifdef USE_CODECPAR
	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);
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
	vStream->codec->codec_id = AV_CODEC_ID_H264;
#else
	vStream->codec->codec_id = CODEC_ID_H264;
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

	if(avio_open2(&fctx->pb, fctx->filename, AVIO_FLAG_WRITE, NULL, &options) < 0) {
		JANUS_LOG(LOG_ERR, "Error opening file for output\n");
		return -1;
	}
	if(avformat_write_header(fctx, &options) < 0) {
		JANUS_LOG(LOG_ERR, "Error writing header\n");
		return -1;
	}
	return 0;
}

/* Helpers to decode Exp-Golomb */
static uint32_t janus_pp_h264_eg_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}

static uint32_t janus_pp_h264_eg_decode(uint8_t *base, uint32_t *offset) {
	uint32_t zeros = 0;
	while(janus_pp_h264_eg_getbit(base, (*offset)++) == 0)
		zeros++;
	uint32_t res = 1 << zeros;
	int32_t i = 0;
	for(i=zeros-1; i>=0; i--) {
		res |= janus_pp_h264_eg_getbit(base, (*offset)++) << i;
	}
	return res-1;
}

/* Helper to parse a SPS (only to get the video resolution) */
static void janus_pp_h264_parse_sps(char *buffer, int *width, int *height) {
	/* Let's check if it's the right profile, first */
	int index = 1;
	int profile_idc = *(buffer+index);
	if(profile_idc != 66) {
		JANUS_LOG(LOG_WARN, "Profile is not baseline (%d != 66)\n", profile_idc);
	}
	/* Then let's skip 2 bytes and evaluate/skip the rest */
	index += 3;
	uint32_t offset = 0;
	uint8_t *base = (uint8_t *)(buffer+index);
	/* Skip seq_parameter_set_id */
	janus_pp_h264_eg_decode(base, &offset);
	if(profile_idc >= 100) {
		/* Skip chroma_format_idc */
		janus_pp_h264_eg_decode(base, &offset);
		/* Skip bit_depth_luma_minus8 */
		janus_pp_h264_eg_decode(base, &offset);
		/* Skip bit_depth_chroma_minus8 */
		janus_pp_h264_eg_decode(base, &offset);
		/* Skip qpprime_y_zero_transform_bypass_flag */
		janus_pp_h264_eg_getbit(base, offset++);
		/* Skip seq_scaling_matrix_present_flag */
		janus_pp_h264_eg_getbit(base, offset++);
	}
	/* Skip log2_max_frame_num_minus4 */
	janus_pp_h264_eg_decode(base, &offset);
	/* Evaluate pic_order_cnt_type */
	int pic_order_cnt_type = janus_pp_h264_eg_decode(base, &offset);
	if(pic_order_cnt_type == 0) {
		/* Skip log2_max_pic_order_cnt_lsb_minus4 */
		janus_pp_h264_eg_decode(base, &offset);
	} else if(pic_order_cnt_type == 1) {
		/* Skip delta_pic_order_always_zero_flag, offset_for_non_ref_pic,
		 * offset_for_top_to_bottom_field and num_ref_frames_in_pic_order_cnt_cycle */
		janus_pp_h264_eg_getbit(base, offset++);
		janus_pp_h264_eg_decode(base, &offset);
		janus_pp_h264_eg_decode(base, &offset);
		int num_ref_frames_in_pic_order_cnt_cycle = janus_pp_h264_eg_decode(base, &offset);
		int i = 0;
		for(i=0; i<num_ref_frames_in_pic_order_cnt_cycle; i++) {
			janus_pp_h264_eg_decode(base, &offset);
		}
	}
	/* Skip max_num_ref_frames and gaps_in_frame_num_value_allowed_flag */
	janus_pp_h264_eg_decode(base, &offset);
	janus_pp_h264_eg_getbit(base, offset++);
	/* We need the following three values */
	int pic_width_in_mbs_minus1 = janus_pp_h264_eg_decode(base, &offset);
	int pic_height_in_map_units_minus1 = janus_pp_h264_eg_decode(base, &offset);
	int frame_mbs_only_flag = janus_pp_h264_eg_getbit(base, offset++);
	if(!frame_mbs_only_flag) {
		/* Skip mb_adaptive_frame_field_flag */
		janus_pp_h264_eg_getbit(base, offset++);
	}
	/* Skip direct_8x8_inference_flag */
	janus_pp_h264_eg_getbit(base, offset++);
	/* We need the following value to evaluate offsets, if any */
	int frame_cropping_flag = janus_pp_h264_eg_getbit(base, offset++);
	int frame_crop_left_offset = 0, frame_crop_right_offset = 0,
		frame_crop_top_offset = 0, frame_crop_bottom_offset = 0;
	if(frame_cropping_flag) {
		frame_crop_left_offset = janus_pp_h264_eg_decode(base, &offset);
		frame_crop_right_offset = janus_pp_h264_eg_decode(base, &offset);
		frame_crop_top_offset = janus_pp_h264_eg_decode(base, &offset);
		frame_crop_bottom_offset = janus_pp_h264_eg_decode(base, &offset);
	}
	/* Skip vui_parameters_present_flag */
	janus_pp_h264_eg_getbit(base, offset++);

	/* We skipped what we didn't care about and got what we wanted, compute width/height */
	if(width)
		*width = ((pic_width_in_mbs_minus1 +1)*16) - frame_crop_left_offset*2 - frame_crop_right_offset*2;
	if(height)
		*height = ((2 - frame_mbs_only_flag)* (pic_height_in_map_units_minus1 +1) * 16) - (frame_crop_top_offset * 2) - (frame_crop_bottom_offset * 2);
}


int janus_pp_h264_preprocess(FILE *file, janus_pp_frame_packet *list) {
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
		/* Parse H264 header now */
		fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
		int len = tmp->len-12-tmp->skip;
		if(len < 1) {
			tmp = tmp->next;
			continue;
		}
		bytes = fread(prebuffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			tmp = tmp->next;
			continue;
		}
		if((prebuffer[0] & 0x1F) == 7) {
			/* SPS, see if we can extract the width/height as well */
			JANUS_LOG(LOG_VERB, "Parsing width/height\n");
			int width = 0, height = 0;
			janus_pp_h264_parse_sps(prebuffer, &width, &height);
			if(width > max_width)
				max_width = width;
			if(height > max_height)
				max_height = height;
		} else if((prebuffer[0] & 0x1F) == 24) {
			/* May we find an SPS in this STAP-A? */
			JANUS_LOG(LOG_HUGE, "Parsing STAP-A...\n");
			char *buffer = prebuffer;
			buffer++;
			int tot = len-1;
			uint16_t psize = 0;
			while(tot > 0) {
				memcpy(&psize, buffer, 2);
				psize = ntohs(psize);
				buffer += 2;
				tot -= 2;
				int nal = *buffer & 0x1F;
				JANUS_LOG(LOG_HUGE, "  -- NALU of size %u: %d\n", psize, nal);
				if(nal == 7) {
					JANUS_LOG(LOG_VERB, "Parsing width/height\n");
					int width = 0, height = 0;
					janus_pp_h264_parse_sps(buffer, &width, &height);
					if(width > max_width)
						max_width = width;
					if(height > max_height)
						max_height = height;
				}
				buffer += psize;
				tot -= psize;
			}
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

int janus_pp_h264_process(FILE *file, janus_pp_frame_packet *list, int *working) {
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
			/* H.264 depay */
			int jump = 0;
			uint8_t fragment = *buffer & 0x1F;
			uint8_t nal = *(buffer+1) & 0x1F;
			uint8_t start_bit = *(buffer+1) & 0x80;
			if(fragment == 28 || fragment == 29)
				JANUS_LOG(LOG_HUGE, "Fragment=%d, NAL=%d, Start=%d (len=%d, frameLen=%d)\n", fragment, nal, start_bit, len, frameLen);
			else
				JANUS_LOG(LOG_HUGE, "Fragment=%d (len=%d, frameLen=%d)\n", fragment, len, frameLen);
			if(fragment == 5 ||
					((fragment == 28 || fragment == 29) && nal == 5 && start_bit == 128)) {
				JANUS_LOG(LOG_VERB, "(seq=%"SCNu16", ts=%"SCNu64") Key frame\n", tmp->seq, tmp->ts);
				keyFrame = 1;
				/* Is this the first keyframe we find? */
				if(!keyframe_found) {
					keyframe_found = TRUE;
					JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
				}
			}
			/* Frame manipulation */
			if((fragment > 0) && (fragment < 24)) {	/* Add a start code */
				uint8_t *temp = received_frame + frameLen;
				memset(temp, 0x00, 1);
				memset(temp + 1, 0x00, 1);
				memset(temp + 2, 0x01, 1);
				frameLen += 3;
			} else if(fragment == 24) {	/* STAP-A */
				/* De-aggregate the NALs and write each of them separately */
				buffer++;
				int tot = len-1;
				uint16_t psize = 0;
				while(tot > 0) {
					memcpy(&psize, buffer, 2);
					psize = ntohs(psize);
					if((frameLen + psize) >= numBytes) {
						JANUS_LOG(LOG_ERR, "Invalid size %u + %"SCNu16" (exceeds buffer size)\n", frameLen, psize);
						/* Done, we'll wait for the next video data to write the frame */
						if(tmp->next == NULL || tmp->next->ts > tmp->ts)
							break;
						tmp = tmp->next;
						continue;
					}
					buffer += 2;
					tot -= 2;
					/* Now we have a single NAL */
					uint8_t *temp = received_frame + frameLen;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x01, 1);
					frameLen += 3;
					memcpy(received_frame + frameLen, buffer, psize);
					frameLen += psize;
					/* Go on */
					buffer += psize;
					tot -= psize;
				}
				/* Done, we'll wait for the next video data to write the frame */
				if(tmp->next == NULL || tmp->next->ts > tmp->ts)
					break;
				tmp = tmp->next;
				continue;
			} else if((fragment == 28) || (fragment == 29)) {	/* FIXME true fr FU-A, not FU-B */
				uint8_t indicator = *buffer;
				uint8_t header = *(buffer+1);
				jump = 2;
				len -= 2;
				if(header & 0x80) {
					/* First part of fragmented packet (S bit set) */
					uint8_t *temp = received_frame + frameLen;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x01, 1);
					memset(temp + 3, (indicator & 0xE0) | (header & 0x1F), 1);
					frameLen += 4;
				} else if (header & 0x40) {
					/* Last part of fragmented packet (E bit set) */
				}
			}
			memcpy(received_frame + frameLen, buffer+jump, len);
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
void janus_pp_h264_close(void) {
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
