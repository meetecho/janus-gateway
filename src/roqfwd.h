/*! \file    roqfwd.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP over QUIC (RoQ) forwarders (headers)
 * \details  Implementation of the same principle of RTP forwarders,
 * but based on RTP over QUIC (RoQ), with ability to multiplex multiple
 * streams on top of the same connection. Only available if Janus was built
 * with <a href="https://imquic.conf.meetecho.com/">imquic</a> support.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_ROQFWD_H
#define JANUS_ROQFWD_H

#ifdef HAVE_IMQUIC

#include <imquic/imquic.h>
#include <imquic/roq.h>

#include "rtp.h"


/*! \brief RoQ forwarders code initialization
 * @returns 0 in case of success, a negative integer on errors */
int janus_roq_forwarders_init(void);
/*! \brief RoQ forwarders code de-initialization */
void janus_roq_forwarders_deinit(void);

/*! \brief Helper struct for implementing RoQ forwarders */
typedef struct janus_roq_forwarder {
	/* \brief Opaque pointer to the owner of this forwarder */
	void *source;
	/* \brief Context of the forwarder */
	char *context;
	/* \brief Unique ID (within the context) of the forwarder */
	uint32_t id;
	/*! \brief RoQ client */
	imquic_client *roq_client;
	/*! \brief imquic connection */
	imquic_connection *roq_conn;
	/*! \brief Map of RoQ flows in this connection */
	GHashTable *flows;
	/* \brief Callback to invoke when receiving RTCP messages, if any */
	void (*rtcp_callback)(struct janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len);
	/* \brief Opaque metadata property, in case it's useful to the owner
	 * \note This can be anything (e.g., a string, an allocated struct, etc.),
	 * as long as it can be freed with a single call to g_free(), as
	 * that's all that will be done when getting rid of the forwarder */
	void *metadata;
	/*! \brief Mutex to lock/unlock the instance */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_roq_forwarder;

/*! \brief Helper struct for track a specific RoQ flow */
typedef struct janus_roq_forwarder_flow {
	/*! \brief RoQ flow ID */
	uint64_t flow_id;
	/* \brief Whether this is a video stream */
	gboolean is_video;
	/* \brief SSRC to put in forwarded RTP packets */
	uint32_t ssrc;
	/* \brief Payload type to put in forwarded RTP packets */
	int payload_type;
	/* \brief Substream to forward, in case this is part of a simulcast stream */
	int substream;
	/* \brief Whether simulcast automatic selection is enabled for this forwarder */
	gboolean simulcast;
	/* \brief RTP switching context, if needed */
	janus_rtp_switching_context rtp_context;
	/* \brief Simulcast context, if needed */
	janus_rtp_simulcasting_context sim_context;
} janus_roq_forwarder_flow;

/*! \brief Helper method to create a new janus_roq_forwarder instance
 * \note This only establishes a RoQ connection: flows to forward RTP
 * packets must be created separately, using janus_roq_forwarder_add_flow
 * @param[in] ctx The context of this forwarder (e.g., the plugin name)
 * @param[in] id The unique forwarder ID to assign as part of the context (0=autogenerate)
 * @param[in] host The RoQ server address
 * @param[in] port The RoQ server port
 * @param[in] rtcp_callback The function to invoke when RTCP feedback is received
 * @returns A pointer to a valid janus_roq_forwarder instance, if successful, NULL otherwise */
janus_roq_forwarder *janus_roq_forwarder_create(const char *ctx, uint32_t id, const char *host, int port,
	void (*rtcp_callback)(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len));
/*! \brief Helper method to add a new flow to an existing RoQ forwarder
 * @param[in] rf The janus_roq_forwarder instance to add the flow to
 * @param[in] flow_id The RoQ flow ID to use
 * @param[in] ssrc The SSRC to put in outgoing RTP packets
 * @param[in] pt The payload type to put in outgoing RTP packets
 * @param[in] simulcast Whether the RTP forwarder should act as a simulcast viewer
 * 		(meaning it will only forward the highest quality available substream)
 * @param[in] substream In case we want to forward a specific simulcast substream, which substream it is
 * 	\note Do NOT mix the simulcast and substream properties, as they implement different behaviours
 * @param[in] is_video Whether this a video forwarder
 * @returns 0 if successful, a negative integer otherwise */
int janus_roq_forwarder_add_flow(janus_roq_forwarder *rf, uint64_t flow_id,
	uint32_t ssrc, int pt, gboolean simulcast, int substream, gboolean is_video);
/*! \brief Helper method to remove an existing flow from an existing RoQ forwarder
 * @param[in] rf The janus_roq_forwarder instance to remove the flow from
 * @param[in] flow_id The RoQ flow ID to remove
 * @returns 0 if successful, a negative integer otherwise */
int janus_roq_forwarder_remove_flow(janus_roq_forwarder *rf, uint64_t flow_id);
/*! \brief Helper method to forward an RTP packet within the context of a forwarder
 * @note This is equivalent to calling janus_roq_forwarder_send_rtp_full
 * with all the extra arguments that are usually not required set to NULL
 * @param[in] rf The janus_roq_forwarder instance to use
 * @param[in] flow_id The flow ID to use in RoQ
 * @param[in] buffer The RTP packet buffer
 * @param[in] len The length of the RTP packet buffer
 * @param[in] substream In case the forwarder is relaying a single simulcast
 * 		substream, the substream the packet belongs to (pass -1 to ignore) */
void janus_roq_forwarder_send_rtp(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len, int substream);
/*! \brief Extended version of janus_roq_forwarder_send_rtp, to be used when the forwarder
 * is configured to act as a simulcast receiver, and so will call janus_rtp_simulcasting_context_process_rtp
 * @param[in] rf The janus_roq_forwarder instance to use
 * @param[in] flow_id The flow ID to use in RoQ
 * @param[in] buffer The RTP packet buffer
 * @param[in] len The length of the RTP packet buffer
 * @param[in] substream In case the forwarder is relaying a single simulcast
 * 		substream, the substream the packet belongs to (pass -1 to ignore)
 * @param[in] ssrcs The simulcast SSRCs to refer to (may be updated if rids are involved)
 * @param[in] rids The simulcast rids to refer to, if any
 * @param[in] vcodec Video codec of the RTP payload
 * @param[in] rid_mutex A mutex that must be acquired before reading the rids array, if any */
void janus_roq_forwarder_send_rtp_full(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len,
	int substream, uint32_t *ssrcs, char **rids, janus_videocodec vcodec, janus_mutex *rid_mutex);
/*! \brief Helper method to free a janus_roq_forwarder instance
 * @param[in] rf The janus_roq_forwarder instance to free */
void janus_roq_forwarder_destroy(janus_roq_forwarder *rf);

#endif

#endif
