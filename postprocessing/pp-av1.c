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
static uint16_t max_width = 0, max_height = 0;
int fps = 0;


int janus_pp_av1_create(char *destination, char *metadata, gboolean faststart) {
	if(destination == NULL)
		return -1;
#if !LIBAVCODEC_VER_AT_LEAST(57, 25)
	JANUS_LOG(LOG_ERR, "This version of libavcodec doesn't support AV1...\n");
	return -1;
#endif
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
#if LIBAVCODEC_VER_AT_LEAST(57, 25)
	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_AV1);
#else
	if(!codec) {
		/* Error opening video codec */
		JANUS_LOG(LOG_ERR, "Encoder not available\n");
		return -1;
	}
#endif
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
	vEncoder->strict_std_compliance = -2;
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
#if LIBAVCODEC_VER_AT_LEAST(57, 25)
	vStream->codec->codec_id = AV_CODEC_ID_AV1;
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

/* Helper to decode a leb128 integer  */
static uint32_t janus_pp_av1_lev128_decode(uint8_t *base, uint16_t maxlen, size_t *read) {
	uint32_t val = 0;
	uint8_t *cur = base;
	while((cur-base) < maxlen) {
		/* We only read the 7 least significant bits of each byte */
		val |= ((uint32_t)(*cur & 0x7f)) << ((cur-base)*7);
		if((*cur & 0x80) == 0) {
			/* Most significant bit is 0, we're done */
			*read = (cur-base)+1;
			return val;
		}
		cur++;
	}
	/* If we got here, we read all bytes, but no one with 0 as MSB? */
	return 0;
}
/* Helper to encode a leb128 integer  */
static void janus_pp_av1_lev128_encode(uint32_t value, uint8_t *base, size_t *written) {
	uint8_t *cur = base;
	while(value >= 0x80) {
		/* All these bytes need MSB=1 */
		*cur = (0x80 | (value & 0x7F));
		cur++;
		value >>= 7;
	}
	/* Last byte will have MSB=0 */
	*cur = value;
	*written = (cur-base)+1;
}

/* Helpers to read a bit, or group of bits, in a Sequence Header */
static uint32_t janus_pp_av1_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}
static uint32_t janus_pp_av1_getbits(uint8_t *base, uint8_t num, uint32_t *offset) {
	uint32_t res = 0;
	int32_t i = 0;
	for(i=num-1; i>=0; i--) {
		res |= janus_pp_av1_getbit(base, (*offset)++) << i;
	}
	return res;
}
/* Helper to parse a Sequence Header (only to get the video resolution) */
static void janus_pp_av1_parse_sh(char *buffer, uint16_t *width, uint16_t *height) {
	/* Evaluate/skip everything until we get to the resolution */
	uint32_t offset = 0, value = 0, i = 0;
	uint8_t *base = (uint8_t *)(buffer);
	/* Skip seq_profile (3 bits) */
	janus_pp_av1_getbits(base, 3, &offset);
	/* Skip still_picture (1 bit) */
	janus_pp_av1_getbit(base, offset++);
	/* Skip reduced_still_picture_header (1 bit) */
	value = janus_pp_av1_getbit(base, offset++);
	if(value) {
		/* Skip seq_level_idx (5 bits) */
		janus_pp_av1_getbits(base, 5, &offset);
	} else {
		gboolean decoder_model_info = FALSE, initial_display_delay = FALSE;
		uint32_t bdlm1 = 0;
		/* Skip timing_info_present_flag (1 bit) */
		value = janus_pp_av1_getbit(base, offset++);
		if(value) {
			/* Skip num_units_in_display_tick (32 bits) */
			janus_pp_av1_getbits(base, 32, &offset);
			/* Skip time_scale (32 bits) */
			janus_pp_av1_getbits(base, 32, &offset);
			/* Skip equal_picture_interval (1 bit)*/
			value = janus_pp_av1_getbit(base, offset++);
			if(value) {
				/* TODO Skip num_ticks_per_picture_minus_1 (uvlc) */
			}
			/* Skip decoder_model_info_present_flag (1 bit) */
			value = janus_pp_av1_getbit(base, offset++);
			if(value) {
				decoder_model_info = TRUE;
				/* Skip buffer_delay_length_minus_1 (5 bits) */
				bdlm1 = janus_pp_av1_getbits(base, 5, &offset);
				/* Skip num_units_in_decoding_tick (32 bits) */
				janus_pp_av1_getbits(base, 32, &offset);
				/* Skip buffer_removal_time_length_minus_1 (5 bits) */
				janus_pp_av1_getbits(base, 5, &offset);
				/* Skip frame_presentation_time_length_minus_1 (5 bits) */
				janus_pp_av1_getbits(base, 5, &offset);
			}
		}
		/* Skip initial_display_delay_present_flag (1 bit) */
		value = janus_pp_av1_getbit(base, offset++);
		if(value)
			initial_display_delay = TRUE;
		/* Skip operating_points_cnt_minus_1 (5 bits) */
		uint32_t opcm1 = janus_pp_av1_getbits(base, 5, &offset)+1;
		for(i=0; i<opcm1; i++) {
			/* Skip operating_point_idc[i] (12 bits) */
			janus_pp_av1_getbits(base, 12, &offset);
			/* Skip seq_level_idx[i] (5 bits) */
			value = janus_pp_av1_getbits(base, 5, &offset);
			if(value > 7) {
				/* Skip seq_tier[i] (1 bit) */
				janus_pp_av1_getbit(base, offset++);
			}
			if(decoder_model_info) {
				/* Skip decoder_model_present_for_this_op[i] (1 bit) */
				value = janus_pp_av1_getbit(base, offset++);
				if(value) {
					/* Skip operating_parameters_info(i) */
					janus_pp_av1_getbits(base, (2*bdlm1)+1, &offset);
				}
			}
			if(initial_display_delay) {
				/* Skip initial_display_delay_present_for_this_op[i] (1 bit) */
				value = janus_pp_av1_getbit(base, offset++);
				if(value) {
					/* Skip initial_display_delay_minus_1[i] (4 bits) */
					janus_pp_av1_getbits(base, 4, &offset);
				}
			}
		}
	}
	/* Read frame_width_bits_minus_1 (4 bits) */
	uint32_t fwbm1 = janus_pp_av1_getbits(base, 4, &offset);
	/* Read frame_height_bits_minus_1 (4 bits) */
	uint32_t fhbm1 = janus_pp_av1_getbits(base, 4, &offset);
	/* Read max_frame_width_minus_1 (n bits) */
	*width = janus_pp_av1_getbits(base, fwbm1+1, &offset)+1;
	/* Read max_frame_height_minus_1 (n bits) */
	*height = janus_pp_av1_getbits(base, fhbm1+1, &offset)+1;
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
		/* Read the packet */
		fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
		int len = tmp->len-12-tmp->skip;
		if(len < 3) {
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
		/* Parse AV1 header now: first byte is the aggregation header */
		char *payload = prebuffer;
		uint8_t aggrh = *payload;
		uint8_t zbit = (aggrh & 0x80) >> 7;
		uint8_t ybit = (aggrh & 0x40) >> 6;
		uint8_t w = (aggrh & 0x30) >> 4;
		uint8_t nbit = (aggrh & 0x08) >> 3;
		JANUS_LOG(LOG_HUGE, "[%04d] z=%u, y=%u, w=%u, n=%u\n", len, zbit, ybit, w, nbit);
		payload++;
		len--;
		uint8_t obus = 0;
		uint32_t obusize = 0;
		while(!zbit && len > 0) {
			obus++;
			if(w == 0 || w > obus) {
				/* Then the OBU size (leb128) */
				size_t read = 0;
				obusize = janus_pp_av1_lev128_decode((uint8_t *)payload, len, &read);
				JANUS_LOG(LOG_HUGE, "  -- OBU size: %"SCNu32"/%d (in %zu leb128 bytes)\n", obusize, len, read);
				payload += read;
				len -= read;
			} else {
				obusize = len;
				JANUS_LOG(LOG_HUGE, "  -- OBU size: %d (last OBU)\n", len);
			}
			/* Then we have the OBU header */
			uint8_t obuh = *payload;
			uint8_t fbit = (obuh & 0x80) >> 7;
			uint8_t type = (obuh & 0x78) >> 3;
			uint8_t ebit = (obuh & 0x04) >> 2;
			uint8_t sbit = (obuh & 0x02) >> 1;
			JANUS_LOG(LOG_HUGE, "  -- OBU header: f=%u, type=%u, e=%u, s=%u\n", fbit, type, ebit, sbit);
			if(ebit) {
				/* Skip the extension, if present */
				payload++;
				len--;
				obusize--;
			}
			if(type == 1) {
				/* Sequence header */
				uint16_t width = 0, height = 0;
				/* TODO Fix currently broken parsing of SH */
				janus_pp_av1_parse_sh(payload+1, &width, &height);
				if(width*height > max_width*max_height) {
					max_width = width;
					max_height = height;
				}
				JANUS_LOG(LOG_INFO, "  -- Detected new resolution: %"SCNu16"x%"SCNu16" (seq=%"SCNu16")\n", width, height, tmp->seq);
			}
			payload += obusize;
			len -= obusize;
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
	JANUS_LOG(LOG_INFO, "  -- %"SCNu16"x%"SCNu16" (fps [%d,%d] ~ %d)\n", max_width, max_height, min_ts_diff, max_ts_diff, fps);
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
	uint8_t *received_frame = g_malloc0(numBytes), *obu_data = g_malloc0(numBytes);
	uint8_t *buffer = g_malloc0(1500), *start = buffer;
	int len = 0, frameLen = 0, total = 0, dataLen = 0;
	int keyFrame = 0;
	gboolean keyframe_found = FALSE;

	while(*working && tmp != NULL) {
		keyFrame = 0;
		frameLen = 0;
		dataLen = 0;
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
			/* Parse AV1 header now: first byte is the aggregation header */
			uint8_t aggrh = *buffer;
			uint8_t zbit = (aggrh & 0x80) >> 7;
			uint8_t ybit = (aggrh & 0x40) >> 6;
			uint8_t w = (aggrh & 0x30) >> 4;
			uint8_t nbit = (aggrh & 0x08) >> 3;
			/* FIXME Ugly hack: we consider a packet with Z=0 and N=1 a keyframe */
			keyFrame = (!zbit && nbit);
			if(keyFrame && !keyframe_found) {
				keyframe_found = TRUE;
				JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
			}
			buffer++;
			len--;
			uint8_t obus = 0;
			uint32_t obusize = 0;
			while(!zbit && len > 0) {
				obus++;
				if(w == 0 || w > obus) {
					/* Read the OBU size (leb128) */
					size_t read = 0;
					obusize = janus_pp_av1_lev128_decode((uint8_t *)buffer, len, &read);
					buffer += read;
					len -= read;
				} else {
					obusize = len;
				}
				/* Update the OBU header to set the S bit */
				uint8_t obuh = *buffer;
				obuh |= (1 << 1);
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU header: 1\n", tmp->ts);
				memcpy(received_frame + frameLen, &obuh, sizeof(uint8_t));
				frameLen++;
				buffer++;
				len--;
				obusize--;
				if(w == 0 || w > obus || !ybit) {
					/* We have the whole OBU, write the OBU size */
					size_t written = 0;
					uint8_t leb[8];
					janus_pp_av1_lev128_encode(obusize, leb, &written);
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU size (%"SCNu32"): %zu\n", tmp->ts, obusize, written);
					memcpy(received_frame + frameLen, leb, written);
					frameLen += written;
					/* Copy the actual data */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU data: %"SCNu32"\n", tmp->ts, obusize);
					memcpy(received_frame + frameLen, buffer, obusize);
					frameLen += obusize;
				} else {
					/* OBU will continue in another packet, buffer the data */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU data (part.): %d\n", tmp->ts, obusize);
					memcpy(obu_data + dataLen, buffer, obusize);
					dataLen += obusize;
				}
				/* Move to the next OBU, if any */
				buffer += obusize;
				len -= obusize;
			}
			/* Frame manipulation */
			if(len > 0) {
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU data (cont.): %d\n", tmp->ts, len);
				memcpy(obu_data + dataLen, buffer, len);
				dataLen += len;
			}
			/* Check if timestamp changes: marker bit is not mandatory, and may be lost as well */
			if(tmp->next == NULL || tmp->next->ts > tmp->ts)
				break;
			tmp = tmp->next;
		}
		if(dataLen > 0) {
			/* We have a buffered OBU, write the OBU size */
			size_t written = 0;
			uint8_t leb[8];
			janus_pp_av1_lev128_encode(dataLen, leb, &written);
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU size (%d): %zu\n", tmp->ts, dataLen, written);
			memcpy(received_frame + frameLen, leb, written);
			frameLen += written;
			/* Copy the actual data */
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] OBU data: %"SCNu32"\n", tmp->ts, dataLen);
			memcpy(received_frame + frameLen, obu_data, dataLen);
			frameLen += dataLen;
		}
		if(frameLen > 0) {
			/* Save the frame */
			memset(received_frame + frameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);
			total += frameLen;
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Saving frame: %d (tot=%d)\n", tmp->ts, frameLen, total);

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
	g_free(obu_data);
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
