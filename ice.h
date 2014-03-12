/*! \file    ice.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
 * \brief    ICE/STUN/TURN processing (headers)
 * \details  Implementation (based on libnice) of the ICE process. The
 * code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. Incoming RTP and RTCP packets from peers are relayed to the associated
 * plugins by means of the incoming_rtp and incoming_rtcp callbacks. Packets
 * to be sent to peers are relayed by peers invoking the relay_rtp and
 * relay_rtcp gateway callbacks instead. 
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_ICE_H
#define _JANUS_ICE_H

#include <glib.h>
#include <agent.h>

#include "plugins/plugin.h"


/*! \brief ICE stuff initialization
 * @param[in] stun_server STUN server address to use, if any
 * @param[in] stun_port STUN port to use, if any
 * @param[in] rtp_min_port Minimum port to use for RTP/RTCP, if a range is to be used
 * @param[in] rtp_max_port Maximum port to use for RTP/RTCP, if a range is to be used
 * @returns 0 in case of success, a negative integer on errors */
gint janus_ice_init(gchar *stun_server, uint16_t stun_port, uint16_t rtp_min_port, uint16_t rtp_max_port);
/*! \brief Method to get the STUN server IP address
 * @returns The currently used STUN server IP address, if available, or NULL if not */
char *janus_ice_get_stun_server(void);
/*! \brief Method to get the STUN server port
 * @returns The currently used STUN server port, if available, or 0 if not */
uint16_t janus_ice_get_stun_port(void);


/*! \brief Helper method to get a string representation of a libnice ICE state
 * @param[in] state The libnice ICE state
 * @returns A string representation of the libnice ICE state */
const gchar *janus_get_ice_state_name(gint state);


/*! \brief Janus ICE handle/session */
typedef struct janus_ice_handle janus_ice_handle;
/*! \brief Janus ICE stream */
typedef struct janus_ice_stream janus_ice_stream;
/*! \brief Janus ICE component */
typedef struct janus_ice_component janus_ice_component;

/*! \brief Janus ICE handle */
struct janus_ice_handle {
	/*! \brief Opaque pointer to the gateway/peer session */
	void *session;
	/*! \brief Handle identifier */
	guint64 handle_id;
	/*! \brief Opaque application (plugin) pointer */
	void *app;
	/*! \brief Opaque gateway/plugin session pointer */
	janus_pluginession *app_handle;
	/*! \brief Flag to check whether this ICE session needs to stop right now */
	gint stop:1;
	/*! \brief Number of gathered candidates */
	gint cdone;
	/*! \brief GLib context for libnice */
	GMainContext *icectx;
	/*! \brief GLib loop for libnice */
	GMainLoop *iceloop;
	/*! \brief GLib thread for libnice */
	GThread *icethread;
	/*! \brief libnice ICE agent */
	NiceAgent *agent;
	/*! \brief libnice ICE audio ID */
	gint audio_id;
	/*! \brief libnice ICE audio ID */
	gint video_id;
	/*! \brief Number of streams */
	gint streams_num;
	/*! \brief GLib hash table of streams (IDs are the keys) */
	GHashTable *streams;
	/*! \brief Audio stream */
	janus_ice_stream *audio_stream;
	/*! \brief Video stream */
	janus_ice_stream *video_stream;
	/*! \brief Hashing algorhitm used by the peer for the DTLS certificate (e.g., "SHA-256") */
	gchar *remote_hashing;
	/*! \brief Hashed fingerprint of the peer's certificate, as parsed in SDP */
	gchar *remote_fingerprint;
	/*! \brief Mutex to lock/unlock the ICE session */
	janus_mutex mutex;
};

/*! \brief Janus ICE stream */
struct janus_ice_stream {
	/*! \brief Janus ICE handle this stream belongs to */
	janus_ice_handle *handle;
	/*! \brief libnice ICE stream ID */
	guint stream_id;
	/*! \brief Whether this stream is ready to be used */
	gint cdone:1;
	/*! \brief SSRC of the gateway */
	guint32 ssrc;
	/*! \brief SSRC of the peer */
	guint32 ssrc_peer;
	/*! \brief RTP payload type of this stream */
	gint payload_type;
	/*! \brief DTLS role of the gateway for this stream */
	janus_dtls_role dtls_role;
	/*! \brief GLib hash table of components (IDs are the keys) */
	GHashTable *components;
	/*! \brief RTP component */
	janus_ice_component *rtp_component;
	/*! \brief RTCP component */
	janus_ice_component *rtcp_component;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gint noerrorlog:1;
	/*! \brief Mutex to lock/unlock this stream */
	janus_mutex mutex;
};

/*! \brief Janus ICE component */
struct janus_ice_component {
	/*! \brief Janus ICE stream this component belongs to */
	janus_ice_stream *stream;
	/*! \brief libnice ICE stream ID */
	guint stream_id;
	/*! \brief libnice ICE component ID */
	guint component_id;
	/*! \brief GLib list of libnice candidates for this component */
	GSList *candidates;
	/*! \brief DTLS-SRTP stack */
	janus_dtls_srtp *dtls;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gint noerrorlog:1;
	/*! \brief Mutex to lock/unlock this stream */
	janus_mutex mutex;
};

/** @name Janus ICE handle methods
 */
///@{
/*! \brief Method to create a new Janus ICE handle
 * @param[in] gateway_session The gateway/peer session this ICE handle will belong to
 * @returns The created Janus ICE handle if successful, NULL otherwise */
janus_ice_handle *janus_ice_handle_create(void *gateway_session);
/*! \brief Method to find an existing Janus ICE handle from its ID
 * @param[in] gateway_session The gateway/peer session this ICE handle belongs to
 * @param[in] handle_id The Janus ICE handle ID
 * @returns The created Janus ICE handle if successful, NULL otherwise */
janus_ice_handle *janus_ice_handle_find(void *gateway_session, guint64 handle_id);
/*! \brief Method to attach a Janus ICE handle to a plugin
 * \details This method is very important, as it allows plugins to send/receive media (RTP/RTCP) to/from a WebRTC peer.
 * @param[in] gateway_session The gateway/peer session this ICE handle belongs to
 * @param[in] handle_id The Janus ICE handle ID
 * @param[in] plugin The plugin the ICE handle needs to be attached to
 * @returns 0 in case of success, a negative integer otherwise */
gint janus_ice_handle_attach_plugin(void *gateway_session, guint64 handle_id, janus_plugin *plugin);
/*! \brief Method to destroy a Janus ICE handle
 * @param[in] gateway_session The gateway/peer session this ICE handle belongs to
 * @param[in] handle_id The Janus ICE handle ID to destroy
 * @returns 0 in case of success, a negative integer otherwise */
gint janus_ice_handle_destroy(void *gateway_session, guint64 handle_id);
///@}


/** @name Janus ICE handle callbacks
 */
///@{
/*! \brief libnice callback to notify when candidates have been gathered for an ICE agent
 * @param[in] agent The libnice agent for which the callback applies
 * @param[in] stream_id The stream ID for which the callback applies
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
void janus_ice_cb_candidate_gathering_done (NiceAgent *agent, guint stream_id, gpointer ice);
/*! \brief libnice callback to notify when the state of a component changes for an ICE agent
 * @param[in] agent The libnice agent for which the callback applies
 * @param[in] stream_id The stream ID for which the callback applies
 * @param[in] component_id The component ID for which the callback applies
 * @param[in] state New ICE state of the component
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
void janus_ice_cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice);
/*! \brief libnice callback to notify when a pair of candidates has been selected for an ICE agent
 * @param[in] agent The libnice agent for which the callback applies
 * @param[in] stream_id The stream ID for which the callback applies
 * @param[in] component_id The component ID for which the callback applies
 * @param[in] lfoundation ICE foundation
 * @param[in] rfoundation ICE foundation
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, gchar *lfoundation, gchar *rfoundation, gpointer ice);
/*! \brief libnice callback to notify when data has been received by an ICE agent
 * @param[in] agent The libnice agent for which the callback applies
 * @param[in] stream_id The stream ID for which the callback applies
 * @param[in] component_id The component ID for which the callback applies
 * @param[in] len Length of the data buffer
 * @param[in] buf Data buffer
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
void janus_ice_cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice);

/*! \brief Gateway RTP callback, called when a plugin has an RTP packet to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] video Whether this is an audio or a video frame
 * @param[in] buf The packet data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len);
/*! \brief Gateway RTCP callback, called when a plugin has an RTCP message to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] video Whether this is related to an audio or a video stream
 * @param[in] buf The message data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_rtcp(janus_ice_handle *handle, int video, char *buf, int len);
///@}


/** @name Janus ICE handle helpers
 */
///@{
/*! \brief Janus ICE handle thread */
void *janus_ice_thread(void *data);
/*! \brief Method to locally set up the ICE candidates (initialization and gathering)
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] offer Whether this is for an OFFER or an ANSWER
 * @param[in] audio Whether audio is enabled
 * @param[in] video Whether video is enabled
 * @returns 0 in case of success, a negative integer otherwise */
int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video);
/*! \brief Method to add local candidates to the gateway SDP
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in,out] sdp The handle description the gateway is preparing
 * @param[in] stream_id The stream ID of the candidate to add to the SDP
 * @param[in] component_id The component ID of the candidate to add to the SDP */
void janus_ice_setup_candidate(janus_ice_handle *handle, char *sdp, guint stream_id, guint component_id);
/*! \brief Method to handle remote candidates and start the connectivity checks
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] stream_id The stream ID of the candidate to add to the SDP
 * @param[in] component_id The component ID of the candidate to add to the SDP */
void janus_ice_setup_remote_candidate(janus_ice_handle *handle, guint stream_id, guint component_id);
/*! \brief Callback to be notified when the DTLS handshake for a specific component has been completed
 * \details This method also decides when to notify attached plugins about the availability of a reliable PeerConnection
 * @param[in] handle The Janus ICE handle this callback refers to
 * @param[in] component The Janus ICE component that is now ready to be used */
void janus_ice_dtls_handshake_done(janus_ice_handle *handle, janus_ice_component *component);
///@}

#endif
