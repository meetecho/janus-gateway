/*! \file    pp-webm.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .webm files
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .webm files out of VP8 RTP frames.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "pp-webm.h"
#include "../debug.h"


/* WebRTC stuff (VP8) */
#if defined(__ppc__) || defined(__ppc64__)
	# define swap2(d)  \
	((d&0x000000ff)<<8) |  \
	((d&0x0000ff00)>>8)
#else
	# define swap2(d) d
#endif

#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))


/* WebM output */
AVFormatContext *fctx;
AVStream *vStream;
int max_width = 0, max_height = 0, fps = 0;


int janus_pp_webm_create(char *destination) {
	if(destination == NULL)
		return -1;
	/* Setup FFmpeg */
	av_register_all();
	/* WebM output */
	fctx = avformat_alloc_context();
	if(fctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error allocating context\n");
		return -1;
	}
	//~ fctx->oformat = guess_format("webm", NULL, NULL);
	fctx->oformat = av_guess_format("webm", NULL, NULL);
	if(fctx->oformat == NULL) {
		JANUS_LOG(LOG_ERR, "Error guessing format\n");
		return -1;
	}
	snprintf(fctx->filename, sizeof(fctx->filename), "%s", destination);
	//~ vStream = av_new_stream(fctx, 0);
	vStream = avformat_new_stream(fctx, 0);
	if(vStream == NULL) {
		JANUS_LOG(LOG_ERR, "Error adding stream\n");
		return -1;
	}
	//~ avcodec_get_context_defaults2(vStream->codec, CODEC_TYPE_VIDEO);
#if LIBAVCODEC_VER_AT_LEAST(53, 21)
	avcodec_get_context_defaults3(vStream->codec, AVMEDIA_TYPE_VIDEO);
#else
	avcodec_get_context_defaults2(vStream->codec, AVMEDIA_TYPE_VIDEO);
#endif
#if LIBAVCODEC_VER_AT_LEAST(54, 25)
	vStream->codec->codec_id = AV_CODEC_ID_VP8;
#else
	vStream->codec->codec_id = CODEC_ID_VP8;
#endif
	//~ vStream->codec->codec_type = CODEC_TYPE_VIDEO;
	vStream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
	vStream->codec->time_base = (AVRational){1, fps};
	vStream->codec->width = max_width;
	vStream->codec->height = max_height;
	vStream->codec->pix_fmt = PIX_FMT_YUV420P;
	if (fctx->flags & AVFMT_GLOBALHEADER)
		vStream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
	//~ fctx->timestamp = 0;
	//~ if(url_fopen(&fctx->pb, fctx->filename, URL_WRONLY) < 0) {
	if(avio_open(&fctx->pb, fctx->filename, AVIO_FLAG_WRITE) < 0) {
		JANUS_LOG(LOG_ERR, "Error opening file for output\n");
		return -1;
	}
	//~ memset(&parameters, 0, sizeof(AVFormatParameters));
	//~ av_set_parameters(fctx, &parameters);
	//~ fctx->preload = (int)(0.5 * AV_TIME_BASE);
	//~ fctx->max_delay = (int)(0.7 * AV_TIME_BASE);
	//~ if(av_write_header(fctx) < 0) {
	if(avformat_write_header(fctx, NULL) < 0) {
		JANUS_LOG(LOG_ERR, "Error writing header\n");
		return -1;
	}
	return 0;
}

int janus_pp_webm_preprocess(FILE *file, janus_pp_frame_packet *list) {
	if(!file || !list)
		return -1;
	janus_pp_frame_packet *tmp = list;
	int bytes = 0, min_ts_diff = 0, max_ts_diff = 0;
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	while(tmp) {
		if(tmp == list || tmp->ts > tmp->prev->ts) {
			if(tmp->prev != NULL && tmp->ts > tmp->prev->ts) {
				int diff = tmp->ts - tmp->prev->ts;
				if(min_ts_diff == 0 || min_ts_diff > diff)
					min_ts_diff = diff;
				if(max_ts_diff == 0 || max_ts_diff < diff)
					max_ts_diff = diff;
			}
			if(tmp->prev != NULL && (tmp->seq - tmp->prev->seq > 1)) {
				JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
					tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/90000); 
			}
			/* http://tools.ietf.org/html/draft-ietf-payload-vp8-04 */
			/* Read the first bytes of the payload, and get the first octet (VP8 Payload Descriptor) */
			fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
			bytes = fread(prebuffer, sizeof(char), 16, file);
			if(bytes != 16)
				JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < 16)...\n", bytes);
			char *buffer = (char *)&prebuffer;
			uint8_t vp8pd = *buffer;
			uint8_t xbit = (vp8pd & 0x80);
			uint8_t sbit = (vp8pd & 0x10);
			if(!xbit) {
				/* Just skip the first byte */
				buffer++;
			} else {
				/* Read the Extended control bits octet */
				buffer++;
				vp8pd = *buffer;
				uint8_t ibit = (vp8pd & 0x80);
				uint8_t lbit = (vp8pd & 0x40);
				uint8_t tbit = (vp8pd & 0x20);
				uint8_t kbit = (vp8pd & 0x10);
				if(ibit) {
					/* Read the PictureID octet */
					buffer++;
					vp8pd = *buffer;
					uint16_t picid = vp8pd, wholepicid = picid;
					uint8_t mbit = (vp8pd & 0x80);
					if(mbit) {
						memcpy(&picid, buffer, sizeof(uint16_t));
						wholepicid = ntohs(picid);
						picid = (wholepicid & 0x7FFF);
						buffer++;
					}
				}
				if(lbit) {
					/* Read the TL0PICIDX octet */
					buffer++;
					vp8pd = *buffer;
				}
				if(tbit || kbit) {
					/* Read the TID/KEYIDX octet */
					buffer++;
					vp8pd = *buffer;
				}
				buffer++;	/* Now we're in the payload */
				if(sbit) {
					unsigned long int vp8ph = 0;
					memcpy(&vp8ph, buffer, 4);
					vp8ph = ntohl(vp8ph);
					uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
					if(!pbit) {
						/* Get resolution */
						unsigned char *c = (unsigned char *)buffer+3;
						/* vet via sync code */
						if(c[0]!=0x9d||c[1]!=0x01||c[2]!=0x2a) {
							JANUS_LOG(LOG_WARN, "First 3-bytes after header not what they're supposed to be?\n");
						} else {
							int vp8w = swap2(*(unsigned short*)(c+3))&0x3fff;
							int vp8ws = swap2(*(unsigned short*)(c+3))>>14;
							int vp8h = swap2(*(unsigned short*)(c+5))&0x3fff;
							int vp8hs = swap2(*(unsigned short*)(c+5))>>14;
							JANUS_LOG(LOG_VERB, "(seq=%"SCNu16", ts=%"SCNu64") Key frame: %dx%d (scale=%dx%d)\n", tmp->seq, tmp->ts, vp8w, vp8h, vp8ws, vp8hs);
							if(vp8w > max_width)
								max_width = vp8w;
							if(vp8h > max_height)
								max_height = vp8h;
						}
					}
				}
			}
		}
		tmp = tmp->next;
	}
	int mean_ts = min_ts_diff;	/* FIXME: was an actual mean, (max_ts_diff+min_ts_diff)/2; */
	fps = (90000/(mean_ts > 0 ? mean_ts : 30));
	JANUS_LOG(LOG_INFO, "  -- %dx%d (fps [%d,%d] ~ %d)\n", max_width, max_height, min_ts_diff, max_ts_diff, fps);
	if(max_width == 0 && max_height == 0) {
		JANUS_LOG(LOG_WARN, "No key frame?? assuming 640x480...\n");
		max_width = 640;
		max_height = 480;
	}
	if(fps == 0) {
		JANUS_LOG(LOG_INFO, "No fps?? assuming 1...\n");
		fps = 1;	/* Prevent divide by zero error */
	}
	return 0;
}

int janus_pp_webm_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;

	int bytes = 0, numBytes = max_width*max_height*3;	/* FIXME */
	uint8_t *received_frame = g_malloc0(numBytes);
	uint8_t *buffer = g_malloc0(10000), *start = buffer;
	int len = 0, frameLen = 0;
	//~ int vp8gotFirstKey = 0;	/* FIXME Ugly check to wait for the first key frame, before starting decoding */
	int keyFrame = 0;
	uint32_t keyframe_ts = 0;

	while(*working && tmp != NULL) {
		keyFrame = 0;
		frameLen = 0;
		len = 0;
		while(1) {
			/* RTP payload */
			buffer = start;
			fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
			len = tmp->len-12-tmp->skip;
			bytes = fread(buffer, sizeof(char), len, file);
			if(bytes != len)
				JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			/* VP8 depay */
				/* http://tools.ietf.org/html/draft-ietf-payload-vp8-04 */
			/* Read the first octet (VP8 Payload Descriptor) */
			int skipped = 1;
			len--;
			uint8_t vp8pd = *buffer;
			uint8_t xbit = (vp8pd & 0x80);
			uint8_t sbit = (vp8pd & 0x10);
			if(!xbit) {
				/* Just skip the first byte */
				buffer++;
			} else {
				/* Read the Extended control bits octet */
				buffer++;
				len--;
				skipped++;
				vp8pd = *buffer;
				uint8_t ibit = (vp8pd & 0x80);
				uint8_t lbit = (vp8pd & 0x40);
				uint8_t tbit = (vp8pd & 0x20);
				uint8_t kbit = (vp8pd & 0x10);
				if(ibit) {
					/* Read the PictureID octet */
					buffer++;
					len--;
					skipped++;
					vp8pd = *buffer;
					uint16_t picid = vp8pd, wholepicid = picid;
					uint8_t mbit = (vp8pd & 0x80);
					if(mbit) {
						memcpy(&picid, buffer, sizeof(uint16_t));
						wholepicid = ntohs(picid);
						picid = (wholepicid & 0x7FFF);
						buffer++;
						len--;
						skipped++;
					}
				}
				if(lbit) {
					/* Read the TL0PICIDX octet */
					buffer++;
					len--;
					skipped++;
					vp8pd = *buffer;
				}
				if(tbit || kbit) {
					/* Read the TID/KEYIDX octet */
					buffer++;
					len--;
					skipped++;
					vp8pd = *buffer;
				}
				buffer++;	/* Now we're in the payload */
				if(sbit) {
					unsigned long int vp8ph = 0;
					memcpy(&vp8ph, buffer, 4);
					vp8ph = ntohl(vp8ph);
					uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
					if(!pbit) {
						//~ vp8gotFirstKey = 1;
						keyFrame = 1;
						/* Get resolution */
						unsigned char *c = buffer+3;
						/* vet via sync code */
						if(c[0]!=0x9d||c[1]!=0x01||c[2]!=0x2a) {
							JANUS_LOG(LOG_WARN, "First 3-bytes after header not what they're supposed to be?\n");
						} else {
							int vp8w = swap2(*(unsigned short*)(c+3))&0x3fff;
							int vp8ws = swap2(*(unsigned short*)(c+3))>>14;
							int vp8h = swap2(*(unsigned short*)(c+5))&0x3fff;
							int vp8hs = swap2(*(unsigned short*)(c+5))>>14;
							JANUS_LOG(LOG_VERB, "(seq=%"SCNu16", ts=%"SCNu64") Key frame: %dx%d (scale=%dx%d)\n", tmp->seq, tmp->ts, vp8w, vp8h, vp8ws, vp8hs);
							/* Is this the first keyframe we find? */
							if(keyframe_ts == 0) {
								keyframe_ts = tmp->ts;
								JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
							}
						}
					}
				}
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
		if(frameLen > 0) {// && vp8gotFirstKey) {
			memset(received_frame + frameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);

			AVPacket packet;
			av_init_packet(&packet);
			packet.stream_index = 0;
			packet.data = received_frame;
			packet.size = frameLen;
			if(keyFrame)
				//~ packet.flags |= PKT_FLAG_KEY;
				packet.flags |= AV_PKT_FLAG_KEY;

			/* First we save to the file... */
			//~ packet.dts = AV_NOPTS_VALUE;
			//~ packet.pts = AV_NOPTS_VALUE;
			packet.dts = (tmp->ts-list->ts)/90;
			packet.pts = (tmp->ts-list->ts)/90;
			if(fctx) {
				if(av_write_frame(fctx, &packet) < 0) {
					JANUS_LOG(LOG_ERR, "Error writing video frame to file...\n");
				}
			}
		}
		tmp = tmp->next;
	}
	g_free(received_frame);
	g_free(start);
	return 0;
}

/* Close WebM file */
void janus_pp_webm_close(void) {
	if(fctx != NULL)
		av_write_trailer(fctx);
	if(vStream->codec != NULL)
		avcodec_close(vStream->codec);
	if(fctx->streams[0] != NULL) {
		av_free(fctx->streams[0]->codec);
		av_free(fctx->streams[0]);
	}
	if(fctx != NULL) {
		//~ url_fclose(fctx->pb);
		avio_close(fctx->pb);
		av_free(fctx);
	}
}
