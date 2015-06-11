/*! \file    rtcp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTCP processing (headers)
 * \details  Implementation of the RTCP messages. RTCP messages coming
 * through the gateway are parsed and, if needed (according to
 * http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00),
 * fixed before they are sent to the peers (e.g., to fix SSRCs that may
 * have been changed by the gateway). Methods to generate FIR messages
 * and generate/cap REMB messages are provided as well.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_RTCP_H
#define _JANUS_RTCP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>

/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
typedef enum {
    RTCP_FIR = 192,
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
    RTCP_RTPFB = 205,
    RTCP_PSFB = 206,
} rtcp_type;
 
 
/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
typedef struct rtcp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
#endif
	uint16_t length:16;
} rtcp_header;

/*! \brief RTCP Sender Information (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct sender_info
{
	uint32_t ntp_ts_msw;
	uint32_t ntp_ts_lsw;
	uint32_t rtp_ts;
	uint32_t s_packets;
	uint32_t s_octets;
} sender_info;

/*! \brief RTCP Report Block (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct report_block
{
	uint32_t ssrc;
	uint32_t flcnpl;
	uint32_t ehsnr;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t delay;
} report_block;

/*! \brief RTCP Sender Report (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct rtcp_sr
{
	rtcp_header header;
	uint32_t ssrc;
	sender_info si;
	report_block rb[1];
} rtcp_sr;

/*! \brief RTCP Receiver Report (http://tools.ietf.org/html/rfc3550#section-6.4.2) */
typedef struct rtcp_rr
{
	rtcp_header header;
	uint32_t ssrc;
	report_block rb[1];
} rtcp_rr;

/*! \brief RTCP SDES (http://tools.ietf.org/html/rfc3550#section-6.5) */
typedef struct rtcp_sdes_chunk
{
	uint32_t csrc;
} rtcp_sdes_chunk;

typedef struct rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char content[1];
} rtcp_sdes_item;

typedef struct rtcp_sdes
{
	rtcp_header header;
	uint32_t ssrc;
	rtcp_sdes_chunk chunk;
	rtcp_sdes_item item;
} rtcp_sdes;

/*! \brief RTCP BYE (http://tools.ietf.org/html/rfc3550#section-6.6) */
typedef struct rtcp_bye
{
	rtcp_header header;
	uint32_t ssrc[1];
} rtcp_bye_t;

/*! \brief RTCP APP (http://tools.ietf.org/html/rfc3550#section-6.7) */
typedef struct rtcp_app
{
	rtcp_header header;
	uint32_t ssrc;
	char name[4];
} rtcp_app_t;

/*! \brief RTCP NACK (http://tools.ietf.org/html/rfc4585#section-6.2.1) */
typedef struct rtcp_nack
{
	/*! \brief Packet ID */
	uint16_t pid;
	/*! \brief bitmask of following lost packets */
	uint16_t blp;
} rtcp_nack;

/*! \brief Janus representation (linked list) of sequence numbers to send again */
typedef struct janus_nack {
	/*! \brief Sequence number to send again */
	uint16_t seq_no;
	/*! \brief Next element in the linked list */
	struct janus_nack *next;
} janus_nack;


/*! \brief RTCP REMB (http://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03) */
typedef struct rtcp_remb
{
	/*! \brief Unique identifier ('R' 'E' 'M' 'B') */
	char id[4];
	/*! \brief Num SSRC, Br Exp, Br Mantissa (bit mask) */
	uint32_t bitrate;
	/*! \brief SSRC feedback */
	uint32_t ssrc[1];
} rtcp_remb;


/*! \brief RTCP FIR (http://tools.ietf.org/search/rfc5104#section-4.3.1.1) */
typedef struct rtcp_fir
{
	/*! \brief SSRC of the media sender that needs to send a key frame */
	uint32_t ssrc;
	/*! \brief Sequence number (only the first 8 bits are used, the other 24 are reserved) */
	uint32_t seqnr;
} rtcp_fir;


/*! \brief RTCP-FB (http://tools.ietf.org/html/rfc4585) */
typedef struct rtcp_fb
{
	/*! \brief Common header */
	rtcp_header header;
	/*! \brief Sender SSRC */
	uint32_t ssrc;
	/*! \brief Media source */
	uint32_t media;
	/*! \brief Feedback Control Information */
	char fci[1];
} rtcp_fb;


/*! \brief Method to quickly retrieve the sender SSRC (needed for demuxing RTCP in BUNDLE)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns The sender SSRC, or 0 in case of error */
guint32 janus_rtcp_get_sender_ssrc(char *packet, int len);
/*! \brief Method to quickly retrieve the received SSRC (needed for demuxing RTCP in BUNDLE)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns The receiver SSRC, or 0 in case of error */
guint32 janus_rtcp_get_receiver_ssrc(char *packet, int len);

/*! \brief Method to parse/validate an RTCP message
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_parse(char *packet, int len);

/*! \brief Method to fix an RTCP message (http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] fixssrc Whether the method needs to fix the message or just parse it
 * @param[in] newssrcl The SSRC of the sender to put in the message
 * @param[in] newssrcr The SSRC of the receiver to put in the message
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_fix_ssrc(char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr);

/*! \brief Method to check whether an RTCP message contains a FIR request
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE in case of success, FALSE otherwise */
gboolean janus_rtcp_has_fir(char *packet, int len);

/*! \brief Method to check whether an RTCP message contains a PLI request
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE in case of success, FALSE otherwise */
gboolean janus_rtcp_has_pli(char *packet, int len);

/*! \brief Method to parse an RTCP NACK message
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns A list of janus_nack elements containing the sequence numbers to send again */
GSList *janus_rtcp_get_nacks(char *packet, int len);

/*! \brief Method to remove an RTCP NACK message
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns The new message data length in bytes
 * @note This is mostly a placeholder: for the sake of simplicity, whenever we handle
 * some sequence numbers in a NACK, we remove the NACK as a whole before forwarding the
 * RTCP message. Future versions will only selectively remove the sequence numbers that
 * have been handled. */
int janus_rtcp_remove_nacks(char *packet, int len);

/*! \brief Inspect an existing RTCP REMB message to retrieve the reported bitrate
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns The reported bitrate if successful, 0 if no REMB packet was available */
uint64_t janus_rtcp_get_remb(char *packet, int len);

/*! \brief Method to modify an existing RTCP REMB message to cap the reported bitrate
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] bitrate The new bitrate to report (e.g., 128000)
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_cap_remb(char *packet, int len, uint64_t bitrate);

/*! \brief Method to generate a new RTCP SDES message
 * @param[in] packet The buffer data
 * @param[in] len The buffer data length in bytes
 * @param[in] cname The CNAME to write
 * @param[in] cnamelen The CNAME data length in bytes
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_sdes(char *packet, int len, const char *cname, int cnamelen);

/*! \brief Method to generate a new RTCP REMB message to cap the reported bitrate
 * @param[in] packet The buffer data (MUST be at least 24 chars)
 * @param[in] len The message data length in bytes (MUST be 24)
 * @param[in] bitrate The bitrate to report (e.g., 128000)
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_remb(char *packet, int len, uint64_t bitrate);

/*! \brief Method to generate a new RTCP FIR message to request a key frame
 * @param[in] packet The buffer data (MUST be at least 20 chars)
 * @param[in] len The message data length in bytes (MUST be 20)
 * @param[in,out] seqnr The current FIR sequence number (will be incremented by the method)
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_fir(char *packet, int len, int *seqnr);

/*! \brief Method to generate a new legacy RTCP FIR (RFC2032) message to request a key frame
 * \note This is actually identical to janus_rtcp_fir(), with the difference that we set 192 as packet type
 * @param[in] packet The buffer data (MUST be at least 20 chars)
 * @param[in] len The message data length in bytes (MUST be 20)
 * @param[in,out] seqnr The current FIR sequence number (will be incremented by the method)
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_fir_legacy(char *packet, int len, int *seqnr);

/*! \brief Method to generate a new RTCP PLI message to request a key frame
 * @param[in] packet The buffer data (MUST be at least 12 chars)
 * @param[in] len The message data length in bytes (MUST be 12)
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_pli(char *packet, int len);

/*! \brief Method to generate a new RTCP NACK message to report lost packets
 * @param[in] packet The buffer data (MUST be at least 16 chars)
 * @param[in] len The message data length in bytes (MUST be 16)
 * @param[in] nacks List of packets to NACK
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_nacks(char *packet, int len, GSList *nacks);

#endif
