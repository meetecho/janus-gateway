/*! \file    pp-webm.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .webm files
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .webm files out of VP8/VP9 RTP frames.
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
#include "pp-webm.h"
#include "../debug.h"

/* WebRTC stuff (VP8/VP9) */
#if defined(__ppc__) || defined(__ppc64__)
	# define swap2(d)  \
	((d&0x000000ff)<<8) |  \
	((d&0x0000ff00)>>8)
#else
	# define swap2(d) d
#endif


/* WebM output */
static AVFormatContext *fctx;
static AVStream *vStream;
static int max_width = 0, max_height = 0, fps = 0;

/* Supported target formats */
static const char *janus_pp_webm_formats[] = {
	"webm", "mkv", NULL
};
const char **janus_pp_webm_get_extensions(void) {
	return janus_pp_webm_formats;
}

/* Processing methods */
int janus_pp_webm_create(char *destination, char *metadata, gboolean vp8, const char *extension) {
	if(destination == NULL)
		return -1;
#if LIBAVCODEC_VERSION_MAJOR < 55
	if(!vp8) {
		JANUS_LOG(LOG_FATAL, "Your FFmpeg version does not support VP9\n");
		return -1;
	}
#endif
	/* .mkv is Matroska video */
	if(!strcasecmp(extension, "mkv"))
		extension = "matroska";

	/* Video output */
	fctx = janus_pp_create_avformatcontext(extension, metadata, destination);
	if(fctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error allocating context\n");
		return -1;
	}

	int codec_id;
#if LIBAVCODEC_VER_AT_LEAST(54, 25)
	#if LIBAVCODEC_VERSION_MAJOR >= 55
	codec_id = vp8 ? AV_CODEC_ID_VP8 : AV_CODEC_ID_VP9;
	#else
	codec_id = AV_CODEC_ID_VP8;
	#endif
#else
	codec_id = CODEC_ID_VP8;
#endif

	vStream = janus_pp_new_video_avstream(fctx, codec_id, max_width, max_height);
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

int janus_pp_webm_preprocess(FILE *file, janus_pp_frame_packet *list, gboolean vp8) {
	if(!file || !list)
		return -1;
	janus_pp_frame_packet *tmp = list;
	int bytes = 0, min_ts_diff = 0, max_ts_diff = 0;
	int rotation = -1;
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
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked video packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/90000);
			tmp = tmp->next;
			continue;
		}
		if(tmp->rotation != -1 && tmp->rotation != rotation) {
			rotation = tmp->rotation;
			double ts = (double)(tmp->ts-list->ts)/(double)90000;
			JANUS_LOG(LOG_INFO, "[%8.3fs] Video rotation: %d degrees\n", ts, rotation);
		}
		if(vp8) {
			/* https://tools.ietf.org/html/draft-ietf-payload-vp8 */
			/* Read the first bytes of the payload, and get the first octet (VP8 Payload Descriptor) */
			fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
			bytes = fread(prebuffer, sizeof(char), 16, file);
			if(bytes != 16) {
				JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < 16)...\n", bytes);
				tmp = tmp->next;
				continue;
			}
			char *buffer = (char *)&prebuffer;
			uint8_t vp8pd = *buffer;
			uint8_t xbit = (vp8pd & 0x80);
			uint8_t sbit = (vp8pd & 0x10);
			/* Read the Extended control bits octet */
			if(xbit) {
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
						if(vp8w*vp8h > max_width*max_height) {
							max_width = vp8w;
							max_height = vp8h;
						}
					}
				}
			}
		} else {
			/* https://tools.ietf.org/html/draft-ietf-payload-vp9 */
			/* Read the first bytes of the payload, and get the first octet (VP9 Payload Descriptor) */
			fseek(file, tmp->offset+12+tmp->skip, SEEK_SET);
			bytes = fread(prebuffer, sizeof(char), 16, file);
			if(bytes != 16) {
				JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < 16)...\n", bytes);
				tmp = tmp->next;
				continue;
			}
			char *buffer = (char *)&prebuffer;
			uint8_t vp9pd = *buffer;
			uint8_t ibit = (vp9pd & 0x80);
			uint8_t pbit = (vp9pd & 0x40);
			uint8_t lbit = (vp9pd & 0x20);
			uint8_t fbit = (vp9pd & 0x10);
			uint8_t vbit = (vp9pd & 0x02);
			buffer++;
			if(ibit) {
				/* Read the PictureID octet */
				vp9pd = *buffer;
				uint16_t picid = vp9pd, wholepicid = picid;
				uint8_t mbit = (vp9pd & 0x80);
				if(!mbit) {
					buffer++;
				} else {
					memcpy(&picid, buffer, sizeof(uint16_t));
					wholepicid = ntohs(picid);
					picid = (wholepicid & 0x7FFF);
					buffer += 2;
				}
			}
			if(lbit) {
				buffer++;
				if(!fbit) {
					/* Non-flexible mode, skip TL0PICIDX */
					buffer++;
				}
			}
			if(fbit && pbit) {
				/* Skip reference indices */
				uint8_t nbit = 1;
				while(nbit) {
					vp9pd = *buffer;
					nbit = (vp9pd & 0x01);
					buffer++;
				}
			}
			if(vbit) {
				/* Parse and skip SS */
				vp9pd = *buffer;
				uint n_s = (vp9pd & 0xE0) >> 5;
				n_s++;
				uint8_t ybit = (vp9pd & 0x10);
				if(ybit) {
					/* Iterate on all spatial layers and get resolution */
					buffer++;
					uint i=0;
					for(i=0; i<n_s; i++) {
						/* Width */
						uint16_t *w = (uint16_t *)buffer;
						int width = ntohs(*w);
						buffer += 2;
						/* Height */
						uint16_t *h = (uint16_t *)buffer;
						int height = ntohs(*h);
						buffer += 2;
						if(width*height > max_width*max_height) {
							max_width = width;
							max_height = height;
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
		JANUS_LOG(LOG_WARN, "No fps?? assuming 1...\n");
		fps = 1;	/* Prevent divide by zero error */
	}
	return 0;
}

int janus_pp_webm_process(FILE *file, janus_pp_frame_packet *list, gboolean vp8, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;

	int bytes = 0, numBytes = max_width*max_height*3;	/* FIXME */
	uint8_t *received_frame = g_malloc0(numBytes);
	uint8_t *buffer = g_malloc0(numBytes), *start = buffer;
	int len = 0, frameLen = 0;
	int keyFrame = 0;
	gboolean keyframe_found = FALSE;
	AVPacket *packet = av_packet_alloc();
	AVRational timebase = {1, 90000};

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
			if(vp8) {
				/* VP8 depay */
					/* https://tools.ietf.org/html/draft-ietf-payload-vp8 */
				/* Read the first octet (VP8 Payload Descriptor) */
				int skipped = 1;
				len--;
				uint8_t vp8pd = *buffer;
				uint8_t xbit = (vp8pd & 0x80);
				uint8_t sbit = (vp8pd & 0x10);

				if (xbit) {
					buffer++;
					skipped++;
					len--;

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
				}
				buffer++;	/* Now we're in the payload */
				if(sbit) {
					unsigned long int vp8ph = 0;
					memcpy(&vp8ph, buffer, 4);
					vp8ph = ntohl(vp8ph);
					uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
					if(!pbit) {
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
							if(!keyframe_found) {
								keyframe_found = TRUE;
								JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
							}
						}
					}
				}

			} else {
				/* VP9 depay */
					/* https://tools.ietf.org/html/draft-ietf-payload-vp9-02 */
				/* Read the first octet (VP9 Payload Descriptor) */
				int skipped = 0;
				uint8_t vp9pd = *buffer;
				uint8_t ibit = (vp9pd & 0x80);
				uint8_t pbit = (vp9pd & 0x40);
				uint8_t lbit = (vp9pd & 0x20);
				uint8_t fbit = (vp9pd & 0x10);
				uint8_t vbit = (vp9pd & 0x02);
				/* Move to the next octet and see what's there */
				buffer++;
				len--;
				skipped++;
				if(ibit) {
					/* Read the PictureID octet */
					vp9pd = *buffer;
					uint16_t picid = vp9pd, wholepicid = picid;
					uint8_t mbit = (vp9pd & 0x80);
					if(!mbit) {
						buffer++;
						len--;
						skipped++;
					} else {
						memcpy(&picid, buffer, sizeof(uint16_t));
						wholepicid = ntohs(picid);
						picid = (wholepicid & 0x7FFF);
						buffer += 2;
						len -= 2;
						skipped += 2;
					}
				}
				if(lbit) {
					buffer++;
					len--;
					skipped++;
					if(!fbit) {
						/* Non-flexible mode, skip TL0PICIDX */
						buffer++;
						len--;
						skipped++;
					}
				}
				if(fbit && pbit) {
					/* Skip reference indices */
					uint8_t nbit = 1;
					while(nbit) {
						vp9pd = *buffer;
						nbit = (vp9pd & 0x01);
						buffer++;
						len--;
						skipped++;
					}
				}
				if(vbit) {
					/* Parse and skip SS */
					vp9pd = *buffer;
					int n_s = (vp9pd & 0xE0) >> 5;
					n_s++;
					uint8_t ybit = (vp9pd & 0x10);
					uint8_t gbit = (vp9pd & 0x08);
					if(ybit) {
						keyFrame = 1;
						/* Iterate on all spatial layers and get resolution */
						buffer++;
						len--;
						skipped++;
						int i=0;
						for(i=0; i<n_s; i++) {
							/* Been there, done that: skip skip skip */
							buffer += 4;
							len -= 4;
							skipped += 4;
						}
						/* Is this the first keyframe we find?
						 * (FIXME assuming this really means "keyframe...) */
						if(!keyframe_found) {
							keyframe_found = TRUE;
							JANUS_LOG(LOG_INFO, "First keyframe: %"SCNu64"\n", tmp->ts-list->ts);
						}
					}
					if(gbit) {
						if(!ybit) {
							buffer++;
							len--;
							skipped++;
						}
						uint8_t n_g = *buffer;
						buffer++;
						len--;
						skipped++;
						if(n_g > 0) {
							uint i=0;
							for(i=0; i<n_g; i++) {
								/* Read the R bits */
								vp9pd = *buffer;
								int r = (vp9pd & 0x0C) >> 2;
								if(r > 0) {
									/* Skip reference indices */
									buffer += r;
									len -= r;
									skipped += r;
								}
								buffer++;
								len--;
								skipped++;
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
		if(frameLen > 0) {
			memset(received_frame + frameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);

			av_packet_unref(packet);
			packet->stream_index = 0;
			packet->data = received_frame;
			packet->size = frameLen;
			if(keyFrame)
				//~ packet.flags |= PKT_FLAG_KEY;
				packet->flags |= AV_PKT_FLAG_KEY;

			/* First we save to the file... */
			packet->pts = packet->dts = av_rescale_q(tmp->ts-list->ts, timebase, fctx->streams[0]->time_base);
			if(fctx) {
				if(av_write_frame(fctx, packet) < 0) {
					JANUS_LOG(LOG_ERR, "Error writing video frame to file...\n");
				}
			}
		}
		tmp = tmp->next;
	}
	av_packet_free(&packet);
	g_free(received_frame);
	g_free(start);
	return 0;
}

/* Close WebM file */
void janus_pp_webm_close(void) {
	if(fctx != NULL) {
		av_write_trailer(fctx);
		avio_close(fctx->pb);
		avformat_free_context(fctx);
	}
}
