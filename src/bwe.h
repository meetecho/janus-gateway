/*! \file    bwe.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Bandwidth estimation tools (headers)
 * \details  Implementation of a basic bandwidth estimator for outgoing
 * RTP flows, based on Transport Wide CC and a few other utilities.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_BWE_H
#define JANUS_BWE_H

#include <glib.h>

#include "mutex.h"

/*! \brief Tracker for a stream bitrate (whether it's simulcast/SVC or not) */
typedef struct janus_bwe_stream_bitrate {
	/*! \brief Time based queue of packet sizes */
	GQueue *packets[9];
	/*! \brief Current bitrate */
	uint32_t bitrate[9];
	/*! \brief Mutex to lock this instance */
	janus_mutex mutex;
} janus_bwe_stream_bitrate;
/*! \brief Helper method to create a new janus_bwe_stream_bitrate instance
 * @returns A janus_bwe_stream_bitrate instance, if successful, or NULL otherwise */
janus_bwe_stream_bitrate *janus_bwe_stream_bitrate_create(void);
/*! \brief Helper method to update an existing janus_bwe_stream_bitrate instance with new data
 * \note Passing \c -1 or \c 0 as size just updates the queue to get rid of older values
 * @param[in] bwe_sb The janus_bwe_stream_bitrate instance to update
 * @param[in] when Timestamp of the packet
 * @param[in] sl Substream or spatial layer of the packet (can be 0 for audio)
 * @param[in] sl Temporal layer of the packet (can be 0 for audio)
 * @param[in] size Size of the packet */
void janus_bwe_stream_bitrate_update(janus_bwe_stream_bitrate *bwe_sb, int64_t when, int sl, int tl, int size);
/*! \brief Helper method to destroy an existing janus_bwe_stream_bitrate instance
 * @param[in] bwe_sb The janus_bwe_stream_bitrate instance to destroy */
void janus_bwe_stream_bitrate_destroy(janus_bwe_stream_bitrate *bwe_sb);

/*! \brief Packet size and time */
typedef struct janus_bwe_stream_packet {
	/*! \brief Timestamp */
	int64_t sent_ts;
	/*! \brief Size of packet */
	uint16_t size;
} janus_bwe_stream_packet;

/*! \brief Transport Wide CC statuses */
typedef enum janus_bwe_twcc_status {
	janus_bwe_twcc_status_notreceived = 0,
	janus_bwe_twcc_status_smalldelta = 1,
	janus_bwe_twcc_status_largeornegativedelta = 2,
	janus_bwe_twcc_status_reserved = 3
} janus_bwe_twcc_status;
/*! \brief Helper to return a string description of a TWCC status
 * @param[in] status The janus_bwe_twcc_status status
 * @returns A string description */
const char *janus_bwe_twcc_status_description(janus_bwe_twcc_status status);

/*! \brief Type of in-flight packet */
typedef enum janus_bwe_packet_type {
	/*! \brief Regular RTP packet */
	janus_bwe_packet_type_regular = 0,
	/*! \brief RTC packet */
	janus_bwe_packet_type_rtx,
	/*! \brief Probing */
	janus_bwe_packet_type_probing
} janus_bwe_packet_type;

/*! \brief Tracking info for in-flight packet we're waiting TWCC feedback for */
typedef struct janus_bwe_twcc_inflight {
	/*! \brief The TWCC sequence number */
	uint16_t seq;
	/*! \brief Monotonic time this packet was delivered */
	int64_t sent_ts;
	/*! \brief Delta (in us) since the delivery of the previous packet */
	int64_t delta_us;
	/*! \brief Type of packet (e.g., regular or rtx) */
	janus_bwe_packet_type type;
	/*! \brief Size of the sent packet */
	int size;
} janus_bwe_twcc_inflight;

/*! \brief Current status of the bandwidth estimator */
typedef enum janus_bwe_status {
	/* BWE just started */
	janus_bwe_status_start = 0,
	/* BWE in the regular/increasing stage */
	janus_bwe_status_regular,
	/* BWE detected too many losses */
	janus_bwe_status_lossy,
	/* BWE detected congestion */
	janus_bwe_status_congested,
	/* BWE recovering from losses/congestion */
	janus_bwe_status_recovering
} janus_bwe_status;
/*! \brief Helper to return a string description of a BWE status
 * @param[in] status The janus_bwe_status status
 * @returns A string description */
const char *janus_bwe_status_description(janus_bwe_status status);

/*! \brief Bandwidth estimation context */
typedef struct janus_bwe_context {
	/*! \brief Current status of the context */
	janus_bwe_status status;
	/*! \brief Monotonic timestamp of when the BWE work started */
	int64_t started;
	/*! \brief Monotonic timestamp of when the BWE status last changed */
	int64_t status_changed;
	/*! \brief Index of the m-line we're using for probing */
	int probing_mindex;
	/*! \brief How much we should aim for with out probing (and how much we sent in a second) */
	uint32_t probing_target, probing_sent;
	/*! \brief How many times we went through probing in a second */
	uint8_t probing_count;
	/*! \brief Portion of probing we didn't manage to send the previous round */
	double probing_portion;
	/*! \brief Whether probing should grow incrementally (e.g., after recovery) */
	uint8_t probing_part;
	/*! \brief Monotonic timestamp of the last sent packet */
	int64_t last_sent_ts;
	/*! \brief Last twcc seq number of a received packet */
	uint16_t last_recv_seq;
	/*! \brief Map of in-flight packets */
	GHashTable *packets;
	/*! \brief Monotonic timestamp of when we last computed the bitrates */
	int64_t bitrate_ts;
	/*! \brief Bitrate tracker for sent and acked packets */
	janus_bwe_stream_bitrate *sent, *acked;
	/*! \brief How much delay has been accumulated (may be negative) */
	int64_t delay;
	/*! \brief Number of packets with a received status, and number of lost ones */
	uint16_t received_pkts, lost_pkts;
	/*! \brief Latest average delay */
	double avg_delay;
	/*! \brief Latest loss ratio */
	double loss_ratio;
	/*! \brief Latest estimated bitrate */
	uint32_t estimate;
	/*! \brief Whether we can notify the plugin about the estimate */
	gboolean notify_plugin;
	/*! \brief When we last notified the plugin */
	int64_t last_notified;
} janus_bwe_context;
/*! \brief Helper to create a new bandwidth estimation context
 * @returns a new janus_bwe_context instance, if successful, or NULL otherwise */
janus_bwe_context *janus_bwe_context_create(void);
/*! \brief Helper to destroy an existing bandwidth estimation context
 * @param[in] bew The janus_bwe_context instance to destroy */
void janus_bwe_context_destroy(janus_bwe_context *bwe);

/*! \brief Helper method to quickly add a new inflight packet to a BWE instance
 * @param[in] bwe The janus_bwe_context instance to update
 * @param[in] seq The TWCC sequence number of the new inflight packet
 * @param[in] sent The timestamp of the packet delivery
 * @param[in] type The type of this packet
 * @param[in] size The size of this packet
 * @returns TRUE, if successful, or FALSE otherwise */
gboolean janus_bwe_context_add_inflight(janus_bwe_context *bwe,
	uint16_t seq, int64_t sent, janus_bwe_packet_type type, int size);
/*! \brief Handle feedback on an inflight packet
 * @param[in] bwe The janus_bwe_context instance to update
 * @param[in] seq The TWCC sequence number of the inflight packet we have feedback for
 * @param[in] status Feedback status for the packet
 * @param[in] delta_us If the packet was received, the delta that was provided
 * @param[in] first True if this is the first received packet in a TWCC feedback */
void janus_bwe_context_handle_feedback(janus_bwe_context *bwe,
	uint16_t seq, janus_bwe_twcc_status status, int64_t delta_us, gboolean first);
/*! \brief Update the internal BWE context state with a new tick
 * @param[in] bwe The janus_bwe_context instance to update */
void janus_bwe_context_update(janus_bwe_context *bwe);

#endif