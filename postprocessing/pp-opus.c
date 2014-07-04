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
#include <endian.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <ogg/ogg.h>

#include "pp-opus.h"
#include "debug.h"


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


int janus_pp_opus_create(char *destination) {
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
		len = 0;
		/* RTP payload */
		offset = tmp->offset+12+tmp->skip;
		fseek(file, offset, SEEK_SET);
		len = tmp->len-12-tmp->skip;
		bytes = fread(buffer, sizeof(char), len, file);
		if(bytes != len)
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
		ogg_packet *op = op_from_pkt((const unsigned char *)buffer, bytes);
		if(last_seq == 0)
			last_seq = tmp->seq;
		if(tmp->seq < last_seq)
			steps++;
		pos = tmp->seq-list->seq+1+steps*65535;
		JANUS_LOG(LOG_VERB, "pos: %04"SCNu64", writing %d bytes out of %d\n", pos, bytes, tmp->len);
		op->granulepos = 960*(pos); /* FIXME: get this from the toc byte */
		ogg_stream_packetin(stream, op);
		free(op);
		ogg_write();
		tmp = tmp->next;
	}
	return 0;
}

void janus_pp_opus_close(void) {
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

/* ;anufacture a generic OpusHead packet */
ogg_packet *op_opushead() {
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
ogg_packet *op_opustags() {
	char *identifier = "OpusTags";
	char *vendor = "Janus post-processing";
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
int ogg_write() {
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
int ogg_flush() {
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
