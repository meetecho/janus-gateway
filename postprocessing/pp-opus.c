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
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <ogg/ogg.h>

#include "pp-opus.h"
#include "pp-opus-silence.h"
#include "../debug.h"
#include "../version.h"


/* OGG/Opus helpers */
FILE *ogg_file = NULL;
ogg_stream_state *stream = NULL;

void le32(unsigned char *p, int v);
void le16(unsigned char *p, int v);
ogg_packet *op_opushead(void);
ogg_packet *op_opustags(char *metadata);
ogg_packet *op_from_pkt(const unsigned char *pkt, int len);
void op_free(ogg_packet *op);
int ogg_write(void);
int ogg_flush(void);


int janus_pp_opus_create(char *destination, char *metadata) {
	stream = g_malloc0(sizeof(ogg_stream_state));
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
	op = op_opustags(metadata);
	ogg_stream_packetin(stream, op);
	op_free(op);
	ogg_flush();
	return 0;
}

int janus_pp_opus_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint64_t pos = 0, nextPos = 0;
	uint8_t *buffer = g_malloc0(1500);
	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && ((tmp->ts - tmp->prev->ts)/48/20 > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
			ogg_packet *op = op_from_pkt((const unsigned char *)opus_silence, sizeof(opus_silence));
			/* use ts differ to insert silence packet */
			int silence_count = (tmp->ts - tmp->prev->ts)/48/20 - 1;
			pos = (tmp->prev->ts - list->ts) / 48 / 20 + 1;
			JANUS_LOG(LOG_WARN, "[FILL] pos: %06"SCNu64", writing silences (count=%d)\n", pos, silence_count);
			int i=0;
			for(i=0; i<silence_count; i++) {
				pos = (tmp->prev->ts - list->ts) / 48 / 20 + i + 1;
				if(tmp->next != NULL)
					nextPos = (tmp->next->ts - list->ts) / 48 / 20;
				if(pos >= nextPos) {
					JANUS_LOG(LOG_WARN, "[SKIP] pos: %06" SCNu64 ", skipping remaining silence\n", pos);
					break;
				}
				op->granulepos = 960*(pos); /* FIXME: get this from the toc byte */
				ogg_stream_packetin(stream, op);
				ogg_write();
			}
			ogg_flush();
			g_free(op);
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
		ogg_packet *op = op_from_pkt((const unsigned char *)buffer, bytes);
		pos = (tmp->ts - list->ts) / 48 / 20 + 1;
		JANUS_LOG(LOG_VERB, "pos: %06"SCNu64", writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			pos, bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/48000);
		op->granulepos = 960*(pos); /* FIXME: get this from the toc byte */
		ogg_stream_packetin(stream, op);
		g_free(op);
		ogg_write();
		ogg_flush();
		tmp = tmp->next;
	}
	g_free(buffer);
	return 0;
}

void janus_pp_opus_close(void) {
	ogg_flush();
	if(ogg_file)
		fclose(ogg_file);
	ogg_file = NULL;
	if(stream)
		ogg_stream_destroy(stream);
	stream = NULL;
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

/* Manufacture a generic OpusHead packet */
ogg_packet *op_opushead(void) {
	int size = 19;
	unsigned char *data = g_malloc(size);
	ogg_packet *op = g_malloc(sizeof(*op));

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
ogg_packet *op_opustags(char *metadata) {
	const char *identifier = "OpusTags";
	const char *desc = "DESCRIPTION=";
	char vendor[256];
	g_snprintf(vendor, sizeof(vendor), "Janus post-processor %s", janus_version_string);
	int size = strlen(identifier) + 4 + strlen(vendor) + 4;
	int dlen = strlen(desc), mlen = metadata ? strlen(metadata) : 0;
	if(mlen > 0)
		size += (4+dlen+mlen);
	unsigned char *data = g_malloc(size);
	ogg_packet *op = g_malloc(sizeof(*op));

	/* Write down the tags */
	memcpy(data, identifier, 8);
	le32(data + 8, strlen(vendor));
	memcpy(data + 12, vendor, strlen(vendor));
	le32(data + 12 + strlen(vendor), mlen > 0 ? 1 : 0);
	/* Check if we have metadata to write down: we'll use the "DESCRIPTION" tag */
	if(metadata && strlen(metadata) > 0) {
		/* Add a single comment */
		le32(data + 12 + strlen(vendor) + 4, dlen+mlen);
		memcpy(data + 12 + strlen(vendor) + 8, desc, dlen);
		memcpy(data + 12 + strlen(vendor) + 8 + dlen, metadata, mlen);
	}

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
	ogg_packet *op = g_malloc(sizeof(*op));

	op->packet = (unsigned char *)pkt;
	op->bytes = len;
	op->b_o_s = 0;
	op->e_o_s = 0;
	op->granulepos = 0;
	op->packetno = 0;

	return op;
}

/* Free a packet and its contents */
void op_free(ogg_packet *op) {
	if(op) {
		if(op->packet) {
			g_free(op->packet);
		}
		g_free(op);
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
