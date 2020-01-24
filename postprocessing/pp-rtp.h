/*! \file    pp-rtp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Helper structures to handle RTP post-processing (headers)
 * \details  A few structures to ease the post-processing of RTP frames:
 * the RTP header, its extensions (that we just skip), and a linked list
 * we use to re-order them for post-processing audio/video later on.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_RTP
#define JANUS_PP_RTP

#ifdef __MACH__
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include <glib.h>

typedef struct janus_pp_rtp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t csrccount:4;
	uint16_t markerbit:1;
	uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} janus_pp_rtp_header;

typedef struct janus_pp_rtp_header_extension {
	uint16_t type;
	uint16_t length;
} janus_pp_rtp_header_extension;

typedef struct janus_pp_frame_packet {
	janus_pp_rtp_header *header; /* Pointer to RTP header */
	int version;	/* Version of the .mjr file (2=has timestamps) */
	uint32_t p_ts;	/* Packet timestamp as saved by Janus (if available) */
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	uint16_t len;	/* Length of the data */
	int pt;			/* Payload type of the data */
	long offset;	/* Offset of the data in the file */
	int skip;		/* Bytes to skip, besides the RTP header */
	uint8_t drop;	/* Whether this packet can be dropped (e.g., padding)*/
	int audiolevel;	/* Value of audio level in RTP extension, if parsed */
	int rotation;	/* Value of rotation in RTP extension, if parsed */
	struct janus_pp_frame_packet *next;
	struct janus_pp_frame_packet *prev;
} janus_pp_frame_packet;

#endif
