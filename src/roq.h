/*! \file    roq.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP over QUIC (RoQ) support (headers)
 * \details  Integration of RTP over QUIC (RoQ) functionality in the
 * Janus core, as a feature that plugins can leverage. This includes
 * RoQ forwarders (basically the same principle of RTP forwarders, but
 * based on RTP over QUIC) and basic RoQ servers. Both have the ability
 * to handle multiplex multiple streams on top of the same connection.
 *
 * Notice the functionality documented here is only available if Janus was built
 * with <a href="https://imquic.conf.meetecho.com/">imquic</a> support.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_ROQ_H
#define JANUS_ROQ_H

#ifdef HAVE_IMQUIC

#include <imquic/imquic.h>
#include <imquic/roq.h>

#include "rtp.h"


/*! \brief RoQ code initialization
 * @param enable_roq Whether the RoQ support should be enabled or not
 * @param cert_pem The certificate to use for RoQ servers
 * @param cert_key The certificate key to use for RoQ servers
 * @param password The password to use for the certificate, if any
 * @returns 0 in case of success, a negative integer on errors */
int janus_roq_init(gboolean enable_roq, const char *cert_pem, const char *cert_key, const char *password);
/*! \brief RoQ code de-initialization */
void janus_roq_deinit(void);

/** @name RoQ forwarders
 */
///@{
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
	void (*incoming_rtcp)(struct janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len);
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
 * @param[in] incoming_rtcp The function to invoke when RTCP feedback is received
 * @returns A pointer to a valid janus_roq_forwarder instance, if successful, NULL otherwise */
janus_roq_forwarder *janus_roq_forwarder_create(const char *ctx, uint32_t id, const char *host, int port,
	void (*incoming_rtcp)(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len));
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
///@}

/** @name RoQ servers
 */
///@{
/*! \brief Helper struct for implementing RoQ servers */
typedef struct janus_roq_server {
	/* \brief Opaque pointer to the owner of this server */
	void *source;
	/* \brief Context of the server */
	char *context;
	/* \brief Unique ID (within the context) of the server */
	char *id;
	/*! \brief RoQ server */
	imquic_client *roq_server;
	/*! \brief Connections handled by this server */
	GHashTable *connections;
	/* \brief Callback to invoke when a new connection is available */
	void (*new_roq_client)(struct janus_roq_server *rs, imquic_connection *conn);
	/* \brief Callback to invoke when receiving RTP packets */
	void (*incoming_rtp)(struct janus_roq_server *rs, imquic_connection *conn,
		imquic_roq_multiplexing multiplexing, uint64_t flow_id, char *buffer, int len);
	/* \brief Callback to invoke when a connection is gone */
	void (*roq_client_gone)(struct janus_roq_server *rs, imquic_connection *conn);
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
} janus_roq_server;
/*! \brief Helper method to create a new janus_roq_server instance
 * @param[in] ctx The context of this server (e.g., the plugin name)
 * @param[in] id The unique server ID to assign as part of the context
 * @param[in] host The address to bind the RoQ server to
 * @param[in] port The port to bind the RoQ server to
 * @param[in] new_roq_client The function to invoke when a new client connects
 * @param[in] incoming_rtp The function to invoke when an RTP packet is received
 * @param[in] roq_client_gone The function to invoke when an existing client disconnects
 * @returns A pointer to a valid janus_roq_forwarder instance, if successful, NULL otherwise */
janus_roq_server *janus_roq_server_create(const char *ctx, const char *id, const char *host, int port,
	void (*new_roq_client)(struct janus_roq_server *rs, imquic_connection *conn),
	void (*incoming_rtp)(struct janus_roq_server *rs, imquic_connection *conn,
		imquic_roq_multiplexing multiplexing, uint64_t flow_id, char *buffer, int len),
	void (*roq_client_gone)(struct janus_roq_server *rs, imquic_connection *conn));
/*! \brief Helper method to free a janus_roq_server instance
 * @param[in] rs The janus_roq_server instance to free */
void janus_roq_server_destroy(janus_roq_server *rs);
///@}


#endif

#endif
