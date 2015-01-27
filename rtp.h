/*! \file    rtp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP processing (headers)
 * \details  Implementation the RTP header. Since the gateway does not
 * much more than relaying frames around, the only thing we're interested
 * in is the RTP header and how to get its payload.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_RTP_H
#define _JANUS_RTP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>

#define RTP_HEADER_SIZE	12

/*! \brief RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
typedef struct rtp_header
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
} rtp_header;

/*! \brief RTP packet */
typedef struct janus_rtp_packet {
	char *data;
	gint length;
	gint64 last_retransmit;
} janus_rtp_packet;

#endif
