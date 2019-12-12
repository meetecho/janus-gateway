/*! \file    rtcp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTCP processing (headers)
 * \details  Implementation of the RTCP messages. RTCP messages coming
 * through the server are parsed and, if needed (according to
 * http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00),
 * fixed before they are sent to the peers (e.g., to fix SSRCs that may
 * have been changed by the server). Methods to generate FIR messages
 * and generate/cap REMB messages are provided as well.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_RTCP_H
#define JANUS_RTCP_H

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
    RTCP_XR = 207,
} rtcp_type;
typedef rtcp_type janus_rtcp_type;


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
typedef rtcp_header janus_rtcp_header;

/*! \brief RTCP Sender Information (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct sender_info
{
	uint32_t ntp_ts_msw;
	uint32_t ntp_ts_lsw;
	uint32_t rtp_ts;
	uint32_t s_packets;
	uint32_t s_octets;
} sender_info;
typedef sender_info janus_sender_info;

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
typedef report_block janus_report_block;

/*! \brief RTCP Sender Report (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct rtcp_sr
{
	rtcp_header header;
	uint32_t ssrc;
	sender_info si;
	report_block rb[1];
} rtcp_sr;
typedef rtcp_sr janus_rtcp_sr;

/*! \brief RTCP Receiver Report (http://tools.ietf.org/html/rfc3550#section-6.4.2) */
typedef struct rtcp_rr
{
	rtcp_header header;
	uint32_t ssrc;
	report_block rb[1];
} rtcp_rr;
typedef rtcp_rr janus_rtcp_rr;

/*! \brief RTCP SDES (http://tools.ietf.org/html/rfc3550#section-6.5) */
typedef struct rtcp_sdes_chunk
{
	uint32_t ssrc;
} rtcp_sdes_chunk;
typedef rtcp_sdes_chunk janus_rtcp_sdes_chunk;

typedef struct rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char content[1];
} rtcp_sdes_item;
typedef rtcp_sdes_item janus_rtcp_sdes_item;

typedef struct rtcp_sdes
{
	rtcp_header header;
	rtcp_sdes_chunk chunk;
	rtcp_sdes_item item;
} rtcp_sdes;
typedef rtcp_sdes janus_rtcp_sdes;

/*! \brief RTCP BYE (http://tools.ietf.org/html/rfc3550#section-6.6) */
typedef struct rtcp_bye
{
	rtcp_header header;
	uint32_t ssrc[1];
} rtcp_bye;
typedef rtcp_bye janus_rtcp_bye;

/*! \brief RTCP APP (http://tools.ietf.org/html/rfc3550#section-6.7) */
typedef struct rtcp_app
{
	rtcp_header header;
	uint32_t ssrc;
	char name[4];
} rtcp_app;
typedef rtcp_app janus_rtcp_app;

/*! \brief RTCP NACK (http://tools.ietf.org/html/rfc4585#section-6.2.1) */
typedef struct rtcp_nack
{
	/*! \brief Packet ID */
	uint16_t pid;
	/*! \brief bitmask of following lost packets */
	uint16_t blp;
} rtcp_nack;
typedef rtcp_nack janus_rtcp_nack;

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
	/*! \brief SSRC feedback (we expect at max three SSRCs in there) */
	uint32_t ssrc[3];
} rtcp_remb;
typedef rtcp_remb janus_rtcp_fb_remb;


/*! \brief RTCP FIR (http://tools.ietf.org/search/rfc5104#section-4.3.1.1) */
typedef struct rtcp_fir
{
	/*! \brief SSRC of the media sender that needs to send a key frame */
	uint32_t ssrc;
	/*! \brief Sequence number (only the first 8 bits are used, the other 24 are reserved) */
	uint32_t seqnr;
} rtcp_fir;
typedef rtcp_fir janus_rtcp_fb_fir;


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
typedef rtcp_fb janus_rtcp_fb;

/*! \brief RTCP Extended Report Block (https://tools.ietf.org/html/rfc3611#section-3) */
typedef struct extended_report_block
{
	/*! \brief Block type (BT) */
	uint8_t blocktype;
	/*! \brief Type-specific */
	uint8_t typesp;
	/*! \brief Block length */
	uint16_t length;
	/*! \brief Content (variable length) */
	char content[1];

} extended_report_block;
typedef extended_report_block janus_extended_report_block;

/*! \brief RTCP Extended Report (https://tools.ietf.org/html/rfc3611#section-2) */
typedef struct rtcp_xr
{
	rtcp_header header;
	uint32_t ssrc;
	extended_report_block erb[1];
} rtcp_xr;
typedef rtcp_xr janus_rtcp_xr;


/*! \brief Internal RTCP state context (for RR/SR) */
typedef struct rtcp_context
{
	/* Whether we received any RTP packet at all (don't send RR otherwise) */
	uint8_t rtp_recvd:1;
	uint32_t rtp_last_inorder_ts;
	int64_t rtp_last_inorder_time;

	uint16_t max_seq_nr;
	uint16_t seq_cycle;
	uint16_t base_seq;
	/* Payload type */
	uint16_t pt;

	/* RFC 3550 A.8 Interarrival Jitter */
	int64_t transit;
	double jitter, jitter_remote;
	/* Timestamp base (e.g., 48000 for opus audio, or 90000 for video) */
	uint32_t tb;

	/* Last SR received */
	uint32_t lsr;
	/* Monotonic time of last SR received */
	int64_t lsr_ts;

	/* Last RR/SR we sent */
	int64_t last_sent;

	/* Estimated round-trip time */
	uint32_t rtt;

	/* RFC 3550 A.3 */
	uint32_t received;
	uint32_t received_prior;
	uint32_t expected;
	uint32_t expected_prior;
	uint32_t lost, lost_remote;

	uint32_t retransmitted;
	uint32_t retransmitted_prior;

	/* Inbound RR process */
	int64_t rr_last_ts;
	uint32_t rr_last_ehsnr;
	uint32_t rr_last_lost;
	uint32_t rr_last_nack_count;
	gint sent_packets_since_last_rr;
	gint nack_count;

	/* Link quality estimations */
	double in_link_quality;
	double in_media_link_quality;
	double out_link_quality;
	double out_media_link_quality;
} rtcp_context;
typedef rtcp_context janus_rtcp_context;

/*! \brief Stores transport wide packet reception statistics */
typedef struct rtcp_transport_wide_cc_stats
{
	/*! \brief Transwport wide sequence number */
	guint32 transport_seq_num;
	/*! \brief Reception time */
	guint64 timestamp;
} rtcp_transport_wide_cc_stats;
typedef rtcp_transport_wide_cc_stats janus_rtcp_transport_wide_cc_stats;

/*! \brief Method to retrieve the estimated round-trip time from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @returns The estimated round-trip time */
uint32_t janus_rtcp_context_get_rtt(janus_rtcp_context *ctx);
/*! \brief Method to retrieve the total number of lost packets from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @param[in] remote Whether we're quering the remote (provided by peer) or local (computed by Janus) info
 * @returns The total number of lost packets */
uint32_t janus_rtcp_context_get_lost_all(janus_rtcp_context *ctx, gboolean remote);
/*! \brief Method to retrieve the jitter from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @param[in] remote Whether we're quering the remote (provided by peer) or local (computed by Janus) info
 * @returns The computed jitter */
uint32_t janus_rtcp_context_get_jitter(janus_rtcp_context *ctx, gboolean remote);
/*! \brief Method to retrieve inbound link quality from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @returns Inbound link quality estimation */
uint32_t janus_rtcp_context_get_in_link_quality(janus_rtcp_context *ctx);
/*! \brief Method to retrieve inbound media link quality from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @returns Inbound media link quality estimation */
uint32_t janus_rtcp_context_get_in_media_link_quality(janus_rtcp_context *ctx);
/*! \brief Method to retrieve outbound link quality from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @returns Outbound link quality estimation */
uint32_t janus_rtcp_context_get_out_link_quality(janus_rtcp_context *ctx);
/*! \brief Method to retrieve outbound media link quality from an existing RTCP context
 * @param[in] ctx The RTCP context to query
 * @returns Outbound media link quality estimation */
uint32_t janus_rtcp_context_get_out_media_link_quality(janus_rtcp_context *ctx);
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

/*! \brief Method to check that a RTCP packet size is at least the minimum necessary (8 bytes)
 *  and to validate the length field against the actual size
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE if packet is OK, or FALSE in case of error */
gboolean janus_rtcp_check_len(janus_rtcp_header *rtcp, int len);
/*! \brief Method to check if a RTCP packet could contain a Receiver Report
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE if packet is OK, or FALSE in case of error */
gboolean janus_rtcp_check_rr(janus_rtcp_header *rtcp, int len);
/*! \brief Method to check if a RTCP packet could contain a Sender Report
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE if packet is OK, or FALSE in case of error */
gboolean janus_rtcp_check_sr(janus_rtcp_header *rtcp, int len);
/*! \brief Method to check if a RTCP packet could contain a Feedback Message
 * with a defined FCI size.
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] sizeof_fci The size of a FCI entry
 * @returns TRUE if packet is OK, or FALSE in case of error */
gboolean janus_rtcp_check_fci(janus_rtcp_header *rtcp, int len, int sizeof_fci);
/*! \brief Method to check if a RTCP packet could contain an AFB REMB Message
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE if packet is OK, or FALSE in case of error */
gboolean janus_rtcp_check_remb(janus_rtcp_header *rtcp, int len);

/*! \brief Helper method to demultiplex RTCP from other protocols
 * @param[in] buf Buffer to inspect
 * @param[in] len Length of the buffer to inspect */
gboolean janus_is_rtcp(char *buf, guint len);

/*! \brief Method to parse/validate an RTCP message
 * @param[in] ctx RTCP context to update, if needed (optional)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_parse(janus_rtcp_context *ctx, char *packet, int len);

/*! \brief Method to fix incoming RTCP SR and RR data
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] base_ts RTP context base timestamp to compute offset
 * @param[in] base_ts_prev RTP context base timestamp to compute offset
 * @param[in] ssrc_peer The remote SSRC in usage for this stream
 * @param[in] ssrc_local The local SSRC in usage for this stream
 * @param[in] ssrc_expected The expected SSRC for this RTCP packet
 * @param[in] video Whether the RTCP packet contains report for video data
 * @returns The number of fields updated, negative values on errors */
int janus_rtcp_fix_report_data(char *packet, int len, uint32_t base_ts, uint32_t base_ts_prev, uint32_t ssrc_peer, uint32_t ssrc_local, uint32_t ssrc_expected, gboolean video);

/*! \brief Method to fix an RTCP message (http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00)
 * @param[in] ctx RTCP context to update, if needed (optional)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] fixssrc Whether the method needs to fix the message or just parse it
 * @param[in] fixssrc Whether the method needs to fix the message or just parse it
 * @param[in] newssrcl The SSRC of the sender to put in the message
 * @param[in] newssrcr The SSRC of the receiver to put in the message
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_fix_ssrc(janus_rtcp_context *ctx, char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr);

/*! \brief Method to filter an outgoing RTCP message (http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00)
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in,out] newlen The data length of the filtered RTCP message
 * @returns A pointer to the new RTCP message data, NULL in case all messages have been filtered out */
char *janus_rtcp_filter(char *packet, int len, int *newlen);

/*! \brief Method to quickly process the header of an incoming RTP packet to update the associated RTCP context
 * @param[in] ctx RTCP context to update, if needed (optional)
 * @param[in] packet The RTP packet
 * @param[in] len The packet data length in bytes
 * @param[in] rfc4588_pkt True if this is a RTX packet
 * @param[in] rfc4588_enabled True if this packet comes from a RTX enabled stream
 * @param[in] retransmissions_disabled True if retransmissions are not supported at all for this stream
 * @param[in] clock_rates Mapping between payload types and clock rates, if available
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_process_incoming_rtp(janus_rtcp_context *ctx, char *packet, int len,
	gboolean rfc4588_pkt, gboolean rfc4588_enabled, gboolean retransmissions_disabled,
	GHashTable *clock_rates);

/*! \brief Method to fill in a Report Block in a Receiver Report
 * @param[in] ctx The RTCP context to use for the report
 * @param[in] rb Pointer to a valid report_block area of the RTCP data
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_report_block(janus_rtcp_context *ctx, janus_report_block *rb);

/*! \brief Method to quickly fetch the lost packets info from an RR packet, if present
 * \note This is just means as a simple way for plugins to extract this information from
 * a packet, without the need to setup a dedicated RTCP context for tracking the stats flow
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[out] lost The number of lost packets as a whole
 * @param[out] fraction The fraction of lost packets since the last RR/SR
 * @returns TRUE in case of success, FALSE otherwise */
gboolean janus_rtcp_parse_lost_info(char *packet, int len, uint32_t *lost, int *fraction);

/*! \brief Method to check whether an RTCP message contains a BYE message
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @returns TRUE in case of success, FALSE otherwise */
gboolean janus_rtcp_has_bye(char *packet, int len);

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
uint32_t janus_rtcp_get_remb(char *packet, int len);

/*! \brief Method to modify an existing RTCP REMB message to cap the reported bitrate
 * @param[in] packet The message data
 * @param[in] len The message data length in bytes
 * @param[in] bitrate The new bitrate to report (e.g., 128000)
 * @returns 0 in case of success, -1 on errors */
int janus_rtcp_cap_remb(char *packet, int len, uint32_t bitrate);

/*! \brief Method to generate a new RTCP SDES message
 * @param[in] packet The buffer data
 * @param[in] len The buffer data length in bytes
 * @param[in] cname The CNAME to write
 * @param[in] cnamelen The CNAME data length in bytes
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_sdes_cname(char *packet, int len, const char *cname, int cnamelen);

/*! \brief Method to generate a new RTCP REMB message to cap the reported bitrate
 * @param[in] packet The buffer data (MUST be at least 24 chars)
 * @param[in] len The message data length in bytes (MUST be 24)
 * @param[in] bitrate The bitrate to report (e.g., 128000)
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_remb(char *packet, int len, uint32_t bitrate);

/*! \brief Method to generate a new RTCP REMB message to cap the reported bitrate, but for more SSRCs
 * @param[in] packet The buffer data (MUST be at least 24 chars)
 * @param[in] len The message data length in bytes (MUST be 24)
 * @param[in] bitrate The bitrate to report (e.g., 128000)
 * @param[in] numssrc The number of SSRCs to include in the request
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_remb_ssrcs(char *packet, int len, uint32_t bitrate, uint8_t numssrc);

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

/*! \brief Method to generate a new RTCP transport wide message to report reception stats
 * @param[in] packet The buffer data (MUST be at least 16 chars)
 * @param[in] len The message data length in bytes
 * @param[in] ssrc SSRC of the origin stream
 * @param[in] media SSRC of the destination stream
 * @param[in] feedback_packet_count Feedback paccket count
 * @param[in] transport_wide_cc_stats List of rtp packet reception stats
 * @returns The message data length in bytes, if successful, -1 on errors */
int janus_rtcp_transport_wide_cc_feedback(char *packet, size_t len, guint32 ssrc, guint32 media, guint8 feedback_packet_count, GQueue *transport_wide_cc_stats);

#endif
