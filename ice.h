/*! \file    ice.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
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

#include "dtls.h"
#include "sctp.h"
#include "utils.h"
#include "plugins/plugin.h"


/*! \brief ICE stuff initialization
 * @param[in] ice_lite Whether the ICE Lite mode should be enabled or not
 * @param[in] ice_tcp Whether ICE-TCP support should be enabled or not (only libnice >= 0.1.8, currently broken)
 * @param[in] ipv6 Whether IPv6 candidates must be negotiated or not
 * @param[in] rtp_min_port Minimum port to use for RTP/RTCP, if a range is to be used
 * @param[in] rtp_max_port Maximum port to use for RTP/RTCP, if a range is to be used */
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean ipv6, uint16_t rtp_min_port, uint16_t rtp_max_port);
/*! \brief ICE stuff de-initialization */
void janus_ice_deinit(void);
/*! \brief Method to force Janus to use a STUN server when gathering candidates
 * @param[in] stun_server STUN server address to use
 * @param[in] stun_port STUN port to use
 * @returns 0 in case of success, a negative integer on errors */
int janus_ice_set_stun_server(gchar *stun_server, uint16_t stun_port);
/*! \brief Method to force Janus to use a TURN server when gathering candidates
 * @param[in] turn_server TURN server address to use
 * @param[in] turn_port TURN port to use
 * @param[in] turn_type Relay type (udp, tcp or tls)
 * @param[in] turn_user TURN username, if needed
 * @param[in] turn_pwd TURN password, if needed
 * @returns 0 in case of success, a negative integer on errors */
int janus_ice_set_turn_server(gchar *turn_server, uint16_t turn_port, gchar *turn_type, gchar *turn_user, gchar *turn_pwd);
/*! \brief Method to force Janus to contact a TURN REST API server to get a TURN service to use when gathering candidates.
 * The TURN REST API takes precedence over any static credential passed via janus_ice_set_turn_server
 * @note Requires libcurl to be available, and a working TURN REST API backend (see turnrest.h)
 * @param[in] api_server TURN REST API backend (NULL to disable the API)
 * @param[in] api_key API key to use, if required
 * @returns 0 in case of success, a negative integer on errors */
int janus_ice_set_turn_rest_api(gchar *api_server, gchar *api_key);
/*! \brief Method to get the STUN server IP address
 * @returns The currently used STUN server IP address, if available, or NULL if not */
char *janus_ice_get_stun_server(void);
/*! \brief Method to get the STUN server port
 * @returns The currently used STUN server port, if available, or 0 if not */
uint16_t janus_ice_get_stun_port(void);
/*! \brief Method to get the TURN server IP address
 * @returns The currently used TURN server IP address, if available, or NULL if not */
char *janus_ice_get_turn_server(void);
/*! \brief Method to get the TURN server port
 * @returns The currently used TURN server port, if available, or 0 if not */
uint16_t janus_ice_get_turn_port(void);
/*! \brief Method to get the specified TURN REST API backend, if any
 * @returns The currently specified  TURN REST API backend, if available, or NULL if not */
char *janus_ice_get_turn_rest_api(void);
/*! \brief Helper method to force Janus to overwrite all host candidates with the public IP */
void janus_ice_enable_nat_1_1(void);
/*! \brief Method to add an interface/IP to the enforce list for ICE (that is, only gather candidates from these and ignore the others)
 * \note This method is especially useful to speed up the ICE gathering process on the gateway: in fact,
 * if you know in advance which interface must be used (e.g., the main interface connected to the internet),
 * adding it to the enforce list will prevent libnice from gathering candidates from other interfaces.
 * If you're interested in excluding interfaces explicitly, instead, check janus_ice_ignore_interface.
 * @param[in] ip Interface/IP to enforce (e.g., 192.168. or eth0) */
void janus_ice_enforce_interface(const char *ip);
/*! \brief Method to check whether an interface is currently in the enforce list for ICE (that is, won't have candidates)
 * @param[in] ip Interface/IP to check (e.g., 192.168.244.1 or eth1)
 * @returns true if the interface/IP is in the enforce list, false otherwise */
gboolean janus_ice_is_enforced(const char *ip);
/*! \brief Method to add an interface/IP to the ignore list for ICE (that is, don't gather candidates)
 * \note This method is especially useful to speed up the ICE gathering process on the gateway: in fact,
 * if you know in advance an interface is not going to be used (e.g., one of those created by VMware),
 * adding it to the ignore list will prevent libnice from gathering a candidate for it.
 * Unlike the enforce list, the ignore list also accepts IP addresses, partial or complete.
 * If you're interested in only using specific interfaces, instead, check janus_ice_enforce_interface.
 * @param[in] ip Interface/IP to ignore (e.g., 192.168. or eth1) */
void janus_ice_ignore_interface(const char *ip);
/*! \brief Method to check whether an interface/IP is currently in the ignore list for ICE (that is, won't have candidates)
 * @param[in] ip Interface/IP to check (e.g., 192.168.244.1 or eth1)
 * @returns true if the interface/IP is in the ignore list, false otherwise */
gboolean janus_ice_is_ignored(const char *ip);
/*! \brief Method to check whether ICE Lite mode is enabled or not (still WIP)
 * @returns true if ICE-TCP support is enabled/supported, false otherwise */
gboolean janus_ice_is_ice_lite_enabled(void);
/*! \brief Method to check whether ICE-TCP support is enabled/supported or not (still WIP)
 * @returns true if ICE-TCP support is enabled/supported, false otherwise */
gboolean janus_ice_is_ice_tcp_enabled(void);
/*! \brief Method to check whether IPv6 candidates are enabled/supported or not (still WIP)
 * @returns true if IPv6 candidates are enabled/supported, false otherwise */
gboolean janus_ice_is_ipv6_enabled(void);
/*! \brief Method to check whether BUNDLE support is forced or not
 * @returns true if BUNDLE is mandatory, false otherwise */
gboolean janus_ice_is_bundle_forced(void);
/*! \brief Method to set the BUNDLE support mode (true means mandatory, false means optional)
 * @param forced whether BUNDLE support must be forced or not (default is false) */
void janus_ice_force_bundle(gboolean forced);
/*! \brief Method to check whether rtcp-mux support is forced or not
 * @returns true if rtcp-mux is mandatory, false otherwise */
gboolean janus_ice_is_rtcpmux_forced(void);
/*! \brief Method to set the rtcp-mux support mode (true means mandatory, false means optional)
 * @param forced whether rtcp-mux support must be forced or not (default is false) */
void janus_ice_force_rtcpmux(gboolean forced);
/*! \brief Method to get the port that has been assigned for the RTCP component blackhole in case of rtcp-mux
 * @returns The blackhole port */
gint janus_ice_get_rtcpmux_blackhole_port(void);
/*! \brief Method to modify the max NACK value (i.e., the number of packets per handle to store for retransmissions)
 * @param[in] mnq The new max NACK value */
void janus_set_max_nack_queue(uint mnq);
/*! \brief Method to get the current max NACK value (i.e., the number of packets per handle to store for retransmissions)
 * @returns The current max NACK value */
uint janus_get_max_nack_queue(void);
/*! \brief Method to check whether libnice debugging has been enabled (http://nice.freedesktop.org/libnice/libnice-Debug-messages.html)
 * @returns True if libnice debugging is enabled, FALSE otherwise */
gboolean janus_ice_is_ice_debugging_enabled(void);
/*! \brief Method to enable libnice debugging (http://nice.freedesktop.org/libnice/libnice-Debug-messages.html) */
void janus_ice_debugging_enable(void);
/*! \brief Method to disable libnice debugging (the default) */
void janus_ice_debugging_disable(void);


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
/*! \brief Helper to handle pending trickle candidates (e.g., when we're still waiting for an offer) */
typedef struct janus_ice_trickle janus_ice_trickle;


#define JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER	(1 << 0)
#define JANUS_ICE_HANDLE_WEBRTC_START				(1 << 1)
#define JANUS_ICE_HANDLE_WEBRTC_READY				(1 << 2)
#define JANUS_ICE_HANDLE_WEBRTC_STOP				(1 << 3)
#define JANUS_ICE_HANDLE_WEBRTC_ALERT				(1 << 4)
#define JANUS_ICE_HANDLE_WEBRTC_BUNDLE				(1 << 5)
#define JANUS_ICE_HANDLE_WEBRTC_RTCPMUX				(1 << 6)
#define JANUS_ICE_HANDLE_WEBRTC_TRICKLE				(1 << 7)
#define JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES		(1 << 8)
#define JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED		(1 << 9)
#define JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS		(1 << 10)
#define JANUS_ICE_HANDLE_WEBRTC_PLAN_B				(1 << 11)
#define JANUS_ICE_HANDLE_WEBRTC_CLEANING			(1 << 12)
#define JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO			(1 << 13)
#define JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO			(1 << 14)
#define JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER			(1 << 15)
#define JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER			(1 << 16)


/*! \brief Janus media statistics
 * \note To improve with more stuff */
typedef struct janus_ice_stats {
	/*! \brief Audio bytes sent or received */
	guint64 audio_bytes;
	/*! \brief Audio bytes sent or received in the last second */
	GList *audio_bytes_lastsec;
	/*! \brief Whether or not we notified about audio lastsec issues already */
	gboolean audio_notified_lastsec;
	/*! \brief Number of audio NACKs sent or received */
	guint32 audio_nacks;
	/*! \brief Video bytes sent or received */
	guint64 video_bytes;
	/*! \brief Video bytes sent or received in the last second */
	GList *video_bytes_lastsec;
	/*! \brief Whether or not we notified about video lastsec issues already */
	gboolean video_notified_lastsec;
	/*! \brief Number of video NACKs sent or received */
	guint32 video_nacks;
	/*! \brief Data bytes sent or received */
	guint64 data_bytes;
} janus_ice_stats;

/*! \brief Janus media statistics: received packet info
 * \note To improve with more stuff */
typedef struct janus_ice_stats_item {
	/*! \brief Bytes sent or received */
	guint64 bytes;
	/*! \brief Time at which this happened */
	gint64 when;
} janus_ice_stats_item;

/*! \brief Quick helper method to reset stats
 * @param stats The janus_ice_stats instance to reset */
void janus_ice_stats_reset(janus_ice_stats *stats);

/*! \brief Quick helper method to notify a WebRTC hangup through the Janus API
 * @param handle The janus_ice_handle instance this event refers to
 * @param reason A description of why this happened */
void janus_ice_notify_hangup(janus_ice_handle *handle, const char *reason);


/*! \brief Quick helper method to check if a plugin session associated with a Janus handle is still valid
 * @param plugin_session The janus_plugin_session instance to validate
 * @returns true if the plugin session is valid, false otherwise */
gboolean janus_plugin_session_is_alive(janus_plugin_session *plugin_session);


/*! \brief A helper struct for determining when to send NACKs */
typedef struct janus_seq_info {
	gint64 ts;
	guint16 seq;
	guint16 state;
	struct janus_seq_info *next;
	struct janus_seq_info *prev;
} seq_info_t;
enum {
	SEQ_MISSING,
	SEQ_NACKED,
	SEQ_GIVEUP,
	SEQ_RECVED
};


/*! \brief Janus ICE handle */
struct janus_ice_handle {
	/*! \brief Opaque pointer to the gateway/peer session */
	void *session;
	/*! \brief Handle identifier, guaranteed to be non-zero */
	guint64 handle_id;
	/*! \brief Monotonic time of when the handle has been created */
	gint64 created;
	/*! \brief Opaque application (plugin) pointer */
	void *app;
	/*! \brief Opaque gateway/plugin session pointer */
	janus_plugin_session *app_handle;
	/*! \brief Mask of WebRTC-related flags for this handle */
	janus_flags webrtc_flags;
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
	/*! \brief Monotonic time of when the ICE agent has been created */
	gint64 agent_created;
	/*! \brief ICE role (controlling or controlled) */
	gboolean controlling;
	/*! \brief libnice ICE audio ID */
	guint audio_id;
	/*! \brief libnice ICE video ID */
	guint video_id;
	/*! \brief libnice ICE DataChannels ID */
	guint data_id;
	/*! \brief Audio mid (media ID) */
	gchar *audio_mid;
	/*! \brief Video mid (media ID) */
	gchar *video_mid;
	/*! \brief Data channel mid (media ID) */
	gchar *data_mid;
	/*! \brief Number of streams */
	gint streams_num;
	/*! \brief GLib hash table of streams (IDs are the keys) */
	GHashTable *streams;
	/*! \brief Audio stream */
	janus_ice_stream *audio_stream;
	/*! \brief Video stream */
	janus_ice_stream *video_stream;
	/*! \brief SCTP/DataChannel stream */
	janus_ice_stream *data_stream;
	/*! \brief SDP generated locally (just for debugging purposes) */
	gchar *local_sdp;
	/*! \brief SDP received by the peer (just for debugging purposes) */
	gchar *remote_sdp;
	/*! \brief List of pending trickle candidates (those we received before getting the JSEP offer) */
	GList *pending_trickles;
	/*! \brief Queue of outgoing packets to send */
	GAsyncQueue *queued_packets;
	/*! \brief GLib thread for sending outgoing packets */
	GThread *send_thread;
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
	/*! \brief Whether the medium associated with this stream has been disabled (e.g., m=audio 0) */
	guint disabled;
	/*! \brief Audio SSRC of the gateway for this stream (may be bundled) */
	guint32 audio_ssrc;
	/*! \brief Video SSRC of the gateway for this stream (may be bundled) */
	guint32 video_ssrc;
	/*! \brief Audio SSRC of the peer for this stream (may be bundled) */
	guint32 audio_ssrc_peer;
	/*! \brief Video SSRC of the peer for this stream (may be bundled) */
	guint32 video_ssrc_peer;
	/*! \brief Video retransmissions SSRC of the peer for this stream (may be bundled) */
	guint32 video_ssrc_peer_rtx;
	/*! \brief RTP payload type of this stream */
	gint payload_type;
	/*! \brief DTLS role of the gateway for this stream */
	janus_dtls_role dtls_role;
	/*! \brief Hashing algorhitm used by the peer for the DTLS certificate (e.g., "SHA-256") */
	gchar *remote_hashing;
	/*! \brief Hashed fingerprint of the peer's certificate, as parsed in SDP */
	gchar *remote_fingerprint;
	/*! \brief The ICE username for this stream */
	gchar *ruser;
	/*! \brief The ICE password for this stream */
	gchar *rpass;
	/*! \brief GLib hash table of components (IDs are the keys) */
	GHashTable *components;
	/*! \brief RTP (or SCTP, if this is the data stream) component */
	janus_ice_component *rtp_component;
	/*! \brief RTCP component */
	janus_ice_component *rtcp_component;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gint noerrorlog:1;
	/*! \brief Mutex to lock/unlock this stream */
	janus_mutex mutex;
};

#define LAST_SEQS_MAX_LEN 160
/*! \brief Janus ICE component */
struct janus_ice_component {
	/*! \brief Janus ICE stream this component belongs to */
	janus_ice_stream *stream;
	/*! \brief libnice ICE stream ID */
	guint stream_id;
	/*! \brief libnice ICE component ID */
	guint component_id;
	/*! \brief libnice ICE component state */
	guint state;
	/*! \brief Monotonic time of when this component has successfully connected */
	gint64 component_connected;
	/*! \brief GLib list of libnice remote candidates for this component */
	GSList *candidates;
	/*! \brief GLib list of local candidates for this component (summary) */
	GSList *local_candidates;
	/*! \brief GLib list of remote candidates for this component (summary) */
	GSList *remote_candidates;
	/*! \brief String representation of the selected pair as notified by libnice (foundations) */
	gchar *selected_pair;
	/*! \brief Whether the setup of remote candidates for this component has started or not */
	gboolean process_started;
	/*! \brief Re-transmission timer for DTLS */
	GSource *source;
	/*! \brief DTLS-SRTP stack */
	janus_dtls_srtp *dtls;
	/*! \brief List of previously sent janus_rtp_packet RTP packets, in case we receive NACKs */
	GList *retransmit_buffer;
	/*! \brief Last time a log message about sending retransmits was printed */
	gint64 retransmit_log_ts;
	/*! \brief Number of retransmitted packets since last log message */
	guint retransmit_recent_cnt;
	/*! \brief Last time a log message about sending NACKs was printed */
	gint64 nack_sent_log_ts;
	/*! \brief Number of NACKs sent since last log message */
	guint nack_sent_recent_cnt;
	/*! \brief List of recently received audio sequence numbers (as a support to NACK generation) */
	seq_info_t *last_seqs_audio;
	/*! \brief List of recently received video sequence numbers (as a support to NACK generation) */
	seq_info_t *last_seqs_video;
	/*! \brief Last time the slow_link callback (of the plugin) was called */
	gint64 last_slowlink_time;
	/*! \brief Start time of recent NACKs (for slow_link) */
	gint64 sl_nack_period_ts;
	/*! \brief Count of recent NACKs (for slow_link) */
	guint sl_nack_recent_cnt;
	/*! \brief Stats for incoming data (audio/video/data) */
	janus_ice_stats in_stats;
	/*! \brief Stats for outgoing data (audio/video/data) */
	janus_ice_stats out_stats;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gint noerrorlog:1;
	/*! \brief Mutex to lock/unlock this component */
	janus_mutex mutex;
};

/*! \brief Helper to handle pending trickle candidates (e.g., when we're still waiting for an offer) */
struct janus_ice_trickle {
	/*! \brief Janus ICE handle this trickle candidate belongs to */
	janus_ice_handle *handle;
	/*! \brief Monotonic time of when this trickle candidate has been received */
	gint64 received;
	/*! \brief Janus API transaction ID of the original trickle request */
	char *transaction;
	/*! \brief JSON object of the trickle candidate(s) */
	json_t *candidate;
};

/** @name Janus ICE trickle candidates methods
 */
///@{
/*! \brief Helper method to allocate a janus_ice_trickle instance
 * @param[in] handle The Janus ICE handle this trickle candidate belongs to
 * @param[in] transaction The Janus API ID of the original trickle request
 * @param[in] candidate The trickle candidate, as a Jansson object
 * @returns a pointer to the new instance, if successful, NULL otherwise */
janus_ice_trickle *janus_ice_trickle_new(janus_ice_handle *handle, const char *transaction, json_t *candidate);
/*! \brief Helper method to parse trickle candidates
 * @param[in] handle The Janus ICE handle this candidate belongs to
 * @param[in] candidate The trickle candidate to parse, as a Jansson object
 * @param[in,out] error Error string describing the failure, if any
 * @returns 0 in case of success, any code from apierror.h in case of failure */
gint janus_ice_trickle_parse(janus_ice_handle *handle, json_t *candidate, const char **error);
/*! \brief Helper method to destroy a janus_ice_trickle instance
 * @param[in] trickle The janus_ice_trickle instance to destroy */
void janus_ice_trickle_destroy(janus_ice_trickle *trickle);
///@}


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
/*! \brief Method to actually free the resources allocated by a Janus ICE handle
 * @param[in] handle The Janus ICE handle instance to free */
void janus_ice_free(janus_ice_handle *handle);
/*! \brief Method to only hangup (e.g., DTLS alert) the WebRTC PeerConnection allocated by a Janus ICE handle
 * @param[in] handle The Janus ICE handle instance managing the WebRTC PeerConnection to hangup */
void janus_ice_webrtc_hangup(janus_ice_handle *handle);
/*! \brief Method to only free the WebRTC related resources allocated by a Janus ICE handle
 * @param[in] handle The Janus ICE handle instance managing the WebRTC resources to free */
void janus_ice_webrtc_free(janus_ice_handle *handle);
/*! \brief Method to only free resources related to a specific ICE stream allocated by a Janus ICE handle
 * @param[in] container The map containing the list of all streams for the handle
 * @param[in] stream The Janus ICE stream instance to free */
void janus_ice_stream_free(GHashTable *container, janus_ice_stream *stream);
/*! \brief Method to only free resources related to a specific ICE component allocated by a Janus ICE handle
 * @param[in] container The map containing the list of all components for the stream
 * @param[in] component The Janus ICE component instance to free */
void janus_ice_component_free(GHashTable *container, janus_ice_component *component);
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
 * @param[in] local Local candidate (or foundation)
 * @param[in] remote Remote candidate (or foundation)
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
#ifndef HAVE_LIBNICE_TCP
void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, gchar *local, gchar *remote, gpointer ice);
#else
void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local, NiceCandidate *remote, gpointer ice);
#endif
/*! \brief libnice callback to notify when a new remote candidate has been discovered for an ICE agent
 * @param[in] agent The libnice agent for which the callback applies
 * @param[in] stream_id The stream ID for which the callback applies
 * @param[in] component_id The component ID for which the callback applies
 * @param[in] foundation Candidate (or foundation)
 * @param[in] ice Opaque pointer to the Janus ICE handle associated with the libnice ICE agent */
#ifndef HAVE_LIBNICE_TCP
void janus_ice_cb_new_remote_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *candidate, gpointer ice);
#else
void janus_ice_cb_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice);
#endif
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
/*! \brief Gateway SCTP/DataChannel callback, called when a plugin has data to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] buf The message data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_data(janus_ice_handle *handle, char *buf, int len);
/*! \brief Plugin SCTP/DataChannel callback, called by the SCTP stack when when there's data for a plugin
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] buffer The message data (buffer)
 * @param[in] length The buffer lenght */
void janus_ice_incoming_data(janus_ice_handle *handle, char *buffer, int length);
///@}


/** @name Janus ICE handle helpers
 */
///@{
/*! \brief Janus ICE handle thread */
void *janus_ice_thread(void *data);
/*! \brief Janus ICE thread for sending outgoing packets */
void *janus_ice_send_thread(void *data);
/*! \brief Method to locally set up the ICE candidates (initialization and gathering)
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] offer Whether this is for an OFFER or an ANSWER
 * @param[in] audio Whether audio is enabled
 * @param[in] video Whether video is enabled
 * @param[in] data Whether SCTP data channels are enabled
 * @param[in] bundle Whether BUNDLE is supported or not
 * @param[in] rtcpmux Whether rtcp-mux is supported or not
 * @param[in] trickle Whether ICE trickling is supported or not
 * @returns 0 in case of success, a negative integer otherwise */
int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video, int data, int bundle, int rtcpmux, int trickle);
/*! \brief Method to add local candidates to the gateway SDP
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in,out] sdp The handle description the gateway is preparing
 * @param[in] stream_id The stream ID of the candidate to add to the SDP
 * @param[in] component_id The component ID of the candidate to add to the SDP */
void janus_ice_candidates_to_sdp(janus_ice_handle *handle, char *sdp, guint stream_id, guint component_id);
/*! \brief Method to handle remote candidates and start the connectivity checks
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] stream_id The stream ID of the candidate to add to the SDP
 * @param[in] component_id The component ID of the candidate to add to the SDP */
void janus_ice_setup_remote_candidates(janus_ice_handle *handle, guint stream_id, guint component_id);
/*! \brief Callback to be notified when the DTLS handshake for a specific component has been completed
 * \details This method also decides when to notify attached plugins about the availability of a reliable PeerConnection
 * @param[in] handle The Janus ICE handle this callback refers to
 * @param[in] component The Janus ICE component that is now ready to be used */
void janus_ice_dtls_handshake_done(janus_ice_handle *handle, janus_ice_component *component);
///@}

#endif
