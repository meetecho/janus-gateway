/*! \file    pp-opus.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .opus files
 * \details  Implementation of the post-processing code (based on libogg
 * or, optionally, FFmpeg/libav) needed to generate .opus files out of
 * Opus RTP frames.
 * 
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <ogg/ogg.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "pp-opus.h"
#include "../debug.h"


/* Whether we're going to use libogg or not */
static gboolean use_libogg = TRUE;


/* OGG/Opus helpers */
FILE *ogg_file = NULL;
ogg_stream_state *stream = NULL;

void le32(unsigned char *p, int v);
void le16(unsigned char *p, int v);
ogg_packet *op_opushead(void);
ogg_packet *op_opustags(void);
ogg_packet *op_from_pkt(const unsigned char *pkt, int len);
void op_free(ogg_packet *op);
int ogg_write(void);
int ogg_flush(void);


/* FFmpeg/libav helpers */
AVFormatContext *fctx;
AVStream *audio_stream;

#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))


int janus_pp_opus_create(char *destination) {
	/* Check the JANUS_PPREC_NOLIBOGG environment variable for the tool to use */
	if(g_getenv("JANUS_PPREC_NOLIBOGG") != NULL) {
		int val = atoi(g_getenv("JANUS_PPREC_NOLIBOGG"));
		if(val)
			use_libogg = FALSE;
	}
	JANUS_LOG(LOG_INFO, "Using libogg: %s\n", use_libogg ? "true" : "false");
	if(use_libogg) {
		/* Use libogg */
		stream = malloc(sizeof(ogg_stream_state));
		if(stream == NULL) {
			JANUS_LOG(LOG_ERR, "Couldn't allocate stream struct\n");
			return -1;
		}
		if(ogg_stream_init(stream, rand()) < 0) {
			JANUS_LOG(LOG_ERR, "Couldn't initialize Ogg stream state\n");
			return -1;
		}
		ogg_file = fopen(destination, "wb");
		if(ogg_file == NULL) {
			JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
			return -1;
		}
		JANUS_LOG(LOG_INFO, "Writing .opus file header\n");
		/* Write stream headers */
		ogg_packet *op = op_opushead();
		ogg_stream_packetin(stream, op);
		op_free(op);
		op = op_opustags();
		ogg_stream_packetin(stream, op);
		op_free(op);
		ogg_flush();
	} else {
		/* Use FFmpeg/libav */
		av_register_all();
		/* Opus output */
		fctx = avformat_alloc_context();
		if(fctx == NULL) {
			JANUS_LOG(LOG_ERR, "Error allocating context\n");
			return -1;
		}
		fctx->oformat = av_guess_format("opus", NULL, NULL);
		if(fctx->oformat == NULL) {
			JANUS_LOG(LOG_ERR, "Error guessing format\n");
			return -1;
		}
		snprintf(fctx->filename, sizeof(fctx->filename), "%s", destination);
		audio_stream = avformat_new_stream(fctx, 0);
		if(audio_stream == NULL) {
			JANUS_LOG(LOG_ERR, "Error adding stream\n");
			return -1;
		}
#if LIBAVCODEC_VER_AT_LEAST(53, 21)
		avcodec_get_context_defaults3(audio_stream->codec, NULL);
#else
		avcodec_get_context_defaults2(audio_stream->codec, AVMEDIA_TYPE_AUDIO);
#endif
#if LIBAVCODEC_VER_AT_LEAST(54, 25)
		audio_stream->codec->codec_id = AV_CODEC_ID_OPUS;
#else
		audio_stream->codec->codec_id = CODEC_ID_OPUS;
#endif
		audio_stream->codec->codec_type = AVMEDIA_TYPE_AUDIO;
		audio_stream->codec->sample_fmt = AV_SAMPLE_FMT_S16;
		audio_stream->codec->sample_rate = 48000;
		audio_stream->time_base = (AVRational){ 1, audio_stream->codec->sample_rate };
		if (fctx->flags & AVFMT_GLOBALHEADER)
			audio_stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
		if(avio_open(&fctx->pb, fctx->filename, AVIO_FLAG_WRITE) < 0) {
			JANUS_LOG(LOG_ERR, "Error opening file for output\n");
			return -1;
		}
		if(avformat_write_header(fctx, NULL) < 0) {
			JANUS_LOG(LOG_ERR, "Error writing header\n");
			return -1;
		}
	}
	return 0;
}

int janus_pp_opus_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint64_t pos = 0;
	uint8_t *buffer = calloc(1500, sizeof(uint8_t));
	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && (tmp->seq - tmp->prev->seq > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000); 
		}
		guint16 diff = tmp->prev == NULL ? 1 : (tmp->seq - tmp->prev->seq);
		len = 0;
		/* RTP payload */
		offset = tmp->offset+12+tmp->skip;
		fseek(file, offset, SEEK_SET);
		len = tmp->len-12-tmp->skip;
		bytes = fread(buffer, sizeof(char), len, file);
		if(bytes != len)
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
		if(last_seq == 0)
			last_seq = tmp->seq;
		if(tmp->seq < last_seq) {
			last_seq = tmp->seq;
			steps++;
		}
		if(use_libogg) {
			/* Use libogg */
			ogg_packet *op = op_from_pkt((const unsigned char *)buffer, bytes);
			pos = tmp->seq-list->seq+diff+steps*65535;
			JANUS_LOG(LOG_VERB, "pos: %04"SCNu64", writing %d bytes out of %d (step=%"SCNu16")\n", pos, bytes, tmp->len, diff);
			op->granulepos = 960*(pos); /* FIXME: get this from the toc byte */
			ogg_stream_packetin(stream, op);
			free(op);
			ogg_write();
		} else {
			/* Use FFmpeg/libav */
			AVPacket packet;
			av_init_packet(&packet);
			packet.stream_index = 0;
			packet.data = buffer;
			packet.size = bytes;
			/* First we save to the file... */
			packet.dts = (tmp->ts-list->ts)/48;
			packet.pts = (tmp->ts-list->ts)/48;
			JANUS_LOG(LOG_VERB, "pts: %04"SCNi64", writing %d bytes out of %d (step=%"SCNu16")\n", packet.pts, bytes, tmp->len, diff);
			if(fctx) {
				if(av_write_frame(fctx, &packet) < 0) {
					JANUS_LOG(LOG_ERR, "Error writing audio frame to file...\n");
				}
			}
		}
		tmp = tmp->next;
	}
	return 0;
}

void janus_pp_opus_close(void) {
	if(use_libogg) {
		/* Use libogg */
		if(ogg_file)
			fclose(ogg_file);
		ogg_file = NULL;
		if(stream)
			ogg_stream_destroy(stream);
		stream = NULL;
	} else {
		/* Use FFmpeg/libav */
		if(fctx != NULL)
			av_write_trailer(fctx);
		if(audio_stream->codec != NULL)
			avcodec_close(audio_stream->codec);
		if(fctx->streams[0] != NULL) {
			av_free(fctx->streams[0]->codec);
			av_free(fctx->streams[0]);
		}
		if(fctx != NULL) {
			avio_close(fctx->pb);
			av_free(fctx);
		}
	}
}


/* OGG/Opus helpers */
/* Write a little-endian 32 bit int to memory */
void le32(unsigned char *p, int v) {
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}


/* Write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v) {
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

/* ;anufacture a generic OpusHead packet */
ogg_packet *op_opushead(void) {
	int size = 19;
	unsigned char *data = malloc(size);
	ogg_packet *op = malloc(sizeof(*op));

	if(!data) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate data buffer...\n");
		return NULL;
	}
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet...\n");
		return NULL;
	}

	memcpy(data, "OpusHead", 8);  /* identifier */
	data[8] = 1;                  /* version */
	data[9] = 2;                  /* channels */
	le16(data+10, 0);             /* pre-skip */
	le32(data + 12, 48000);       /* original sample rate */
	le16(data + 16, 0);           /* gain */
	data[18] = 0;                 /* channel mapping family */

	op->packet = data;
	op->bytes = size;
	op->b_o_s = 1;
	op->e_o_s = 0;
	op->granulepos = 0;
	op->packetno = 0;

	return op;
}

/* Manufacture a generic OpusTags packet */
ogg_packet *op_opustags(void) {
	const char *identifier = "OpusTags";
	const char *vendor = "Janus post-processing";
	int size = strlen(identifier) + 4 + strlen(vendor) + 4;
	unsigned char *data = malloc(size);
	ogg_packet *op = malloc(sizeof(*op));

	if(!data) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate data buffer...\n");
		return NULL;
	}
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet...\n");
		return NULL;
	}

	memcpy(data, identifier, 8);
	le32(data + 8, strlen(vendor));
	memcpy(data + 12, vendor, strlen(vendor));
	le32(data + 12 + strlen(vendor), 0);

	op->packet = data;
	op->bytes = size;
	op->b_o_s = 0;
	op->e_o_s = 0;
	op->granulepos = 0;
	op->packetno = 1;

	return op;
}

/* Allocate an ogg_packet */
ogg_packet *op_from_pkt(const unsigned char *pkt, int len) {
	ogg_packet *op = malloc(sizeof(*op));
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet.\n");
		return NULL;
	}

	op->packet = (unsigned char *)pkt;
	op->bytes = len;
	op->b_o_s = 0;
	op->e_o_s = 0;

	return op;
}

/* Free a packet and its contents */
void op_free(ogg_packet *op) {
	if(op) {
		if(op->packet) {
			free(op->packet);
		}
		free(op);
	}
}

/* Write out available ogg pages */
int ogg_write(void) {
	ogg_page page;
	size_t written;

	if(!stream || !ogg_file) {
		return -1;
	}

	while (ogg_stream_pageout(stream, &page)) {
		written = fwrite(page.header, 1, page.header_len, ogg_file);
		if(written != (size_t)page.header_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page header\n");
			return -2;
		}
		written = fwrite(page.body, 1, page.body_len, ogg_file);
		if(written != (size_t)page.body_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page body\n");
			return -3;
		}
	}
	return 0;
}

/* Flush remaining ogg data */
int ogg_flush(void) {
	ogg_page page;
	size_t written;

	if(!stream || !ogg_file) {
		return -1;
	}

	while (ogg_stream_flush(stream, &page)) {
		written = fwrite(page.header, 1, page.header_len, ogg_file);
		if(written != (size_t)page.header_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page header\n");
			return -2;
		}
		written = fwrite(page.body, 1, page.body_len, ogg_file);
		if(written != (size_t)page.body_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page body\n");
			return -3;
		}
	}
	return 0;
}
