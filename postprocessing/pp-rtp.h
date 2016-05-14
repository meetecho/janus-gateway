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

#ifndef _JANUS_PP_RTP
#define _JANUS_PP_RTP


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
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	int len;		/* Length of the data */
	long offset;	/* Offset of the data in the file */
	int skip;		/* Bytes to skip, besides the RTP header */
	uint8_t drop;	/* Whether this packet can be dropped (e.g., padding)*/
	struct janus_pp_frame_packet *next;
	struct janus_pp_frame_packet *prev;
} janus_pp_frame_packet;


#endif
