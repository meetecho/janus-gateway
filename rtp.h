/*! \file    rtp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP processing (headers)
 * \details  Implementation of the RTP header. Since the server does not
 * much more than relaying frames around, the only thing we're interested
 * in is the RTP header and how to get its payload, and parsing extensions.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_RTP_H
#define JANUS_RTP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <glib.h>
#include <jansson.h>

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
typedef rtp_header janus_rtp_header;

/*! \brief RTP packet */
typedef struct janus_rtp_packet {
	char *data;
	gint length;
	gint64 created;
	gint64 last_retransmit;
} janus_rtp_packet;

/*! \brief RTP extension */
typedef struct janus_rtp_header_extension {
	uint16_t type;
	uint16_t length;
} janus_rtp_header_extension;

/*! \brief a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
#define JANUS_RTP_EXTMAP_AUDIO_LEVEL		"urn:ietf:params:rtp-hdrext:ssrc-audio-level"
/*! \brief a=extmap:2 urn:ietf:params:rtp-hdrext:toffset */
#define JANUS_RTP_EXTMAP_TOFFSET			"urn:ietf:params:rtp-hdrext:toffset"
/*! \brief a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time */
#define JANUS_RTP_EXTMAP_ABS_SEND_TIME		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
/*! \brief a=extmap:4 urn:3gpp:video-orientation */
#define JANUS_RTP_EXTMAP_VIDEO_ORIENTATION	"urn:3gpp:video-orientation"
/*! \brief a=extmap:5 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01 */
#define JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC	"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
/*! \brief a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay */
#define JANUS_RTP_EXTMAP_PLAYOUT_DELAY		"http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"
/*! \brief a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid */
#define JANUS_RTP_EXTMAP_MID				"urn:ietf:params:rtp-hdrext:sdes:mid"
/*! \brief a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id */
#define JANUS_RTP_EXTMAP_RID				"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
/*! \brief a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id */
#define JANUS_RTP_EXTMAP_REPAIRED_RID		"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
/*! \brief a=extmap:8 http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07 */
#define JANUS_RTP_EXTMAP_FRAME_MARKING		"http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07"
/*! \brief \note Note: We don't support encrypted extensions yet */
#define JANUS_RTP_EXTMAP_ENCRYPTED			"urn:ietf:params:rtp-hdrext:encrypt"


typedef enum janus_audiocodec {
	JANUS_AUDIOCODEC_NONE,
	JANUS_AUDIOCODEC_OPUS,
	JANUS_AUDIOCODEC_MULTIOPUS,
	JANUS_AUDIOCODEC_PCMU,
	JANUS_AUDIOCODEC_PCMA,
	JANUS_AUDIOCODEC_G722,
	JANUS_AUDIOCODEC_ISAC_32K,
	JANUS_AUDIOCODEC_ISAC_16K
} janus_audiocodec;
const char *janus_audiocodec_name(janus_audiocodec acodec);
janus_audiocodec janus_audiocodec_from_name(const char *name);
int janus_audiocodec_pt(janus_audiocodec acodec);

typedef enum janus_videocodec {
	JANUS_VIDEOCODEC_NONE,
	JANUS_VIDEOCODEC_VP8,
	JANUS_VIDEOCODEC_VP9,
	JANUS_VIDEOCODEC_H264,
	JANUS_VIDEOCODEC_AV1,
	JANUS_VIDEOCODEC_H265
} janus_videocodec;
const char *janus_videocodec_name(janus_videocodec vcodec);
janus_videocodec janus_videocodec_from_name(const char *name);
int janus_videocodec_pt(janus_videocodec vcodec);


/*! \brief Helper method to demultiplex RTP from other protocols
 * @param[in] buf Buffer to inspect
 * @param[in] len Length of the buffer to inspect */
gboolean janus_is_rtp(char *buf, guint len);

/*! \brief Helper to quickly access the RTP payload, skipping header and extensions
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[out] plen The payload data length in bytes
 * @returns A pointer to where the payload data starts, or NULL otherwise; plen is also set accordingly */
char *janus_rtp_payload(char *buf, int len, int *plen);

/*! \brief Ugly and dirty helper to quickly get the id associated with an RTP extension (extmap) in an SDP
 * @param sdp The SDP to parse
 * @param extension The extension namespace to look for
 * @returns The extension id, if found, -1 otherwise */
int janus_rtp_header_extension_get_id(const char *sdp, const char *extension);

/*! \brief Ugly and dirty helper to quickly get the RTP extension namespace associated with an id (extmap) in an SDP
 * @note This only looks for the extensions we know about, those defined in rtp.h
 * @param sdp The SDP to parse
 * @param id The extension id to look for
 * @returns The extension namespace, if found, NULL otherwise */
const char *janus_rtp_header_extension_get_from_id(const char *sdp, int id);

/*! \brief Helper to parse a ssrc-audio-level RTP extension (https://tools.ietf.org/html/rfc6464)
 * @note Browsers apparently always set the VAD to 1, so it's unreliable and should be ignored:
 * only use this method if you're interested in the audio-level value itself.
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] vad Whether the encoder thinks there's voice activity
 * @param[out] level The level value in dBov (0=max, 127=min)
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_audio_level(char *buf, int len, int id, gboolean *vad, int *level);

/*! \brief Helper to parse a video-orientation RTP extension (http://www.3gpp.org/ftp/Specs/html-info/26114.htm)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] c The value of the Camera (C) bit
 * @param[out] f The value of the Flip (F) bit
 * @param[out] r1 The value of the first Rotation (R1) bit
 * @param[out] r0 The value of the second Rotation (R0) bit
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_video_orientation(char *buf, int len, int id,
	gboolean *c, gboolean *f, gboolean *r1, gboolean *r0);

/*! \brief Helper to parse a playout-delay RTP extension (https://webrtc.org/experiments/rtp-hdrext/playout-delay)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] min_delay The minimum delay value
 * @param[out] max_delay The maximum delay value
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_playout_delay(char *buf, int len, int id,
	uint16_t *min_delay, uint16_t *max_delay);

/*! \brief Helper to parse a sdes-mid RTP extension (https://tools.ietf.org/html/draft-ietf-mmusic-sdp-bundle-negotiation-54)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] sdes_item Buffer where the RTP stream ID will be written
 * @param[in] sdes_len Size of the input/output buffer
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_mid(char *buf, int len, int id,
	char *sdes_item, int sdes_len);

/*! \brief Helper to parse a rtp-stream-id RTP extension (https://tools.ietf.org/html/draft-ietf-avtext-rid-09)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] sdes_item Buffer where the RTP stream ID will be written
 * @param[in] sdes_len Size of the input/output buffer
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_rid(char *buf, int len, int id,
	char *sdes_item, int sdes_len);

/*! \brief Helper to parse a frame-marking RTP extension (http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07)
 * \note This is currently only used to get temporal layers for H.264 simulcasting
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[in] codec The video codec (as a janus_videocodec instance) the extension refers to
 * @param[out] tid Temporal layer ID of the frame
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_framemarking(char *buf, int len, int id, janus_videocodec codec, uint8_t *tid);

/*! \brief Helper to parse a transport wide sequence number (https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] transSeqNum Variable to read the transport wide sequence number in
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_parse_transport_wide_cc(char *buf, int len, int id, uint16_t *transSeqNum);

/*! \brief Helper to set a transport wide sequence number (https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] transSeqNum Transport wide sequence number to set
 * @returns 0 if found, -1 otherwise */
int janus_rtp_header_extension_set_transport_wide_cc(char *buf, int len, int id, uint16_t transSeqNum);

/*! \brief Helper to replace the ID of an RTP extension with a different one (e.g.,
 * to turn a repaired-rtp-stream-id into a rtp-stream-id after a successful rtx)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for and replace
 * @param[in] new_id The new value for the extension ID
 * @returns 0 if found, a negative integer otherwise */
int janus_rtp_header_extension_replace_id(char *buf, int len, int id, int new_id);

/*! \brief RTP context, in order to make sure SSRC changes result in coherent seq/ts increases */
typedef struct janus_rtp_switching_context {
	uint32_t a_last_ssrc, a_last_ts, a_base_ts, a_base_ts_prev, a_prev_ts, a_target_ts, a_start_ts,
			v_last_ssrc, v_last_ts, v_base_ts, v_base_ts_prev, v_prev_ts, v_target_ts, v_start_ts;
	uint16_t a_last_seq, a_prev_seq, a_base_seq, a_base_seq_prev,
			v_last_seq, v_prev_seq, v_base_seq, v_base_seq_prev;
	gboolean a_seq_reset, a_new_ssrc,
			v_seq_reset, v_new_ssrc;
	gint16 a_seq_offset,
			v_seq_offset;
	gint32 a_prev_delay, a_active_delay, a_ts_offset,
			v_prev_delay, v_active_delay, v_ts_offset;
	gint64 a_last_time, a_reference_time, a_start_time, a_evaluating_start_time,
			v_last_time, v_reference_time, v_start_time, v_evaluating_start_time;
} janus_rtp_switching_context;

/*! \brief Set (or reset) the context fields to their default values
 * @param[in] context The context to (re)set */
void janus_rtp_switching_context_reset(janus_rtp_switching_context *context);

/*! \brief Use the context info to update the RTP header of a packet, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] video Whether this is an audio or a video packet
 * @param[in] step \b deprecated The expected timestamp step */
void janus_rtp_header_update(janus_rtp_header *header, janus_rtp_switching_context *context, gboolean video, int step);

#define RTP_AUDIO_SKEW_TH_MS 120
#define RTP_VIDEO_SKEW_TH_MS 120
#define SKEW_DETECTION_WAIT_TIME_SECS 10

/*! \brief Use the context info to compensate for audio source skew, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] now \b The packet arrival monotonic time
 * @returns 0 if no compensation is needed, -N if a N packets drop must be performed, N if a N sequence numbers jump has been performed */
int janus_rtp_skew_compensate_audio(janus_rtp_header *header, janus_rtp_switching_context *context, gint64 now);
/*! \brief Use the context info to compensate for video source skew, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] now \b The packet arrival monotonic time
 * @returns 0 if no compensation is needed, -N if a N packets drop must be performed, N if a N sequence numbers jump has been performed */
int janus_rtp_skew_compensate_video(janus_rtp_header *header, janus_rtp_switching_context *context, gint64 now);


/*! \brief Helper struct for processing and tracking simulcast streams */
typedef struct janus_rtp_simulcasting_context {
	/*! \brief RTP Stream extension ID, if any */
	gint rid_ext_id;
	/*! \brief Frame marking extension ID, if any */
	gint framemarking_ext_id;
	/*! \brief Which simulcast substream we should forward back */
	int substream;
	/*! \brief As above, but to handle transitions (e.g., wait for keyframe, or get this if available) */
	int substream_target, substream_target_temp;
	/*! \brief Which simulcast temporal layer we should forward back */
	int templayer;
	/*! \brief As above, but to handle transitions (e.g., wait for keyframe) */
	int templayer_target;
	/*! \brief How much time (in us, default 250000) without receiving packets will make us drop to the substream below */
	guint32 drop_trigger;
	/*! \brief When we relayed the last packet (used to detect when substreams become unavailable) */
	gint64 last_relayed;
	/*! \brief Whether the substream has changed after processing a packet */
	gboolean changed_substream;
	/*! \brief Whether the temporal layer has changed after processing a packet */
	gboolean changed_temporal;
	/*! \brief Whether we need to send the user a keyframe request (PLI) */
	gboolean need_pli;
} janus_rtp_simulcasting_context;

/*! \brief Set (or reset) the context fields to their default values
 * @param[in] context The context to (re)set */
void janus_rtp_simulcasting_context_reset(janus_rtp_simulcasting_context *context);

/*! \brief Helper method to prepare the simulcasting info (rids and/or SSRCs) from
 * the simulcast object the core passes to plugins for new PeerConnections
 * @param[in] simulcast JSON object containing SSRCs and rids
 * @param[in] rid_ext_id The rid RTP extension ID to set, if any
 * @param[in] framemarking_ext_id The frame marking RTP extension ID to set, if any
 * @param[in] ssrcs The list of simulcast SSRCs to update, if any
 * @param[in] rids The list of rids to update, if any (items will be allocated) */
void janus_rtp_simulcasting_prepare(json_t *simulcast, int *rid_ext_id, int *framemarking_ext_id, uint32_t *ssrcs, char **rids);

/*! \brief Process an RTP packet, and decide whether this should be relayed or not, updating the context accordingly
 * \note Calling this method resets the \c changed_substream , \c changed_temporal and \c need_pli
 * properties, and updates them according to the decisions made after processinf the packet
 * @param[in] context The simulcasting context to use
 * @param[in] buf The RTP packet to process
 * @param[in] len The length of the RTP packet (header, extension and payload)
 * @param[in] ssrcs The simulcast SSRCs to refer to (may be updated if rids are involved)
 * @param[in] rids The simulcast rids to refer to, if any
 * @param[in] vcodec Video codec of the RTP payload
 * @param[in] sc RTP switching context to refer to, if any (only needed for VP8 and dropping temporal layers)
 * @returns TRUE if the packet should be relayed, FALSE if it should be dropped instead */
gboolean janus_rtp_simulcasting_context_process_rtp(janus_rtp_simulcasting_context *context,
	char *buf, int len, uint32_t *ssrcs, char **rids,
	janus_videocodec vcodec, janus_rtp_switching_context *sc);

#endif
