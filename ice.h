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
 * relay_rtcp core callbacks instead. 
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_ICE_H
#define _JANUS_ICE_H

#include <glib.h>
#include <agent.h>

#include "sdp.h"
#include "dtls.h"
#include "sctp.h"
#include "rtcp.h"
#include "text2pcap.h"
#include "utils.h"
#include "refcount.h"
#include "plugins/plugin.h"


/*! \brief ICE stuff initialization
 * @param[in] ice_lite Whether the ICE Lite mode should be enabled or not
 * @param[in] ice_tcp Whether ICE-TCP support should be enabled or not (only libnice >= 0.1.8, currently broken)
 * @param[in] full_trickle Whether full-trickle must be used (instead of half-trickle)
 * @param[in] ipv6 Whether IPv6 candidates must be negotiated or not
 * @param[in] rtp_min_port Minimum port to use for RTP/RTCP, if a range is to be used
 * @param[in] rtp_max_port Maximum port to use for RTP/RTCP, if a range is to be used */
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean full_trickle, gboolean ipv6, uint16_t rtp_min_port, uint16_t rtp_max_port);
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
 * @param[in] api_method HTTP method to use (POST by default)
 * @returns 0 in case of success, a negative integer on errors */
int janus_ice_set_turn_rest_api(gchar *api_server, gchar *api_key, gchar *api_method);
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
 * \note This method is especially useful to speed up the ICE gathering process on the server: in fact,
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
 * \note This method is especially useful to speed up the ICE gathering process on the server: in fact,
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
/*! \brief Method to check whether full-trickle support is enabled or not
 * @returns true if full-trickle support is enabled, false otherwise */
gboolean janus_ice_is_full_trickle_enabled(void);
/*! \brief Method to check whether IPv6 candidates are enabled/supported or not (still WIP)
 * @returns true if IPv6 candidates are enabled/supported, false otherwise */
gboolean janus_ice_is_ipv6_enabled(void);
/*! \brief Method to modify the max NACK value (i.e., the number of packets per handle to store for retransmissions)
 * @param[in] mnq The new max NACK value */
void janus_set_max_nack_queue(uint mnq);
/*! \brief Method to get the current max NACK value (i.e., the number of packets per handle to store for retransmissions)
 * @returns The current max NACK value */
uint janus_get_max_nack_queue(void);
/*! \brief Method to modify the no-media event timer (i.e., the number of seconds where no media arrives before Janus notifies this)
 * @param[in] timer The new timer value, in seconds */
void janus_set_no_media_timer(uint timer);
/*! \brief Method to get the current no-media event timer (see above)
 * @returns The current no-media event timer */
uint janus_get_no_media_timer(void);
/*! \brief Method to enable or disable the RFC4588 support negotiation
 * @param[in] enabled The new timer value, in seconds */
void janus_set_rfc4588_enabled(gboolean enabled);
/*! \brief Method to check whether the RFC4588 support is enabled
 * @returns TRUE if it's enabled, FALSE otherwise */
gboolean janus_is_rfc4588_enabled(void);
/*! \brief Method to modify the event handler statistics period (i.e., the number of seconds that should pass before Janus notifies event handlers about media statistics for a PeerConnection)
 * @param[in] period The new period value, in seconds */
void janus_ice_set_event_stats_period(int period);
/*! \brief Method to get the current event handler statistics period (see above)
 * @returns The current event handler stats period */
int janus_ice_get_event_stats_period(void);
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
#define JANUS_ICE_HANDLE_WEBRTC_TRICKLE				(1 << 7)
#define JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES		(1 << 8)
#define JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED		(1 << 9)
#define JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS		(1 << 10)
#define JANUS_ICE_HANDLE_WEBRTC_CLEANING			(1 << 11)
#define JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO			(1 << 12)
#define JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO			(1 << 13)
#define JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER			(1 << 14)
#define JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER			(1 << 15)
#define JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT			(1 << 16)
#define JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART			(1 << 17)
#define JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES		(1 << 18)
#define JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX			(1 << 19)
#define JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP	(1 << 20)


/*! \brief Janus media statistics
 * \note To improve with more stuff */
typedef struct janus_ice_stats_info {
	/*! \brief Packets sent or received */
	guint32 packets;
	/*! \brief Bytes sent or received */
	guint64 bytes;
	/*! \brief Bytes sent or received in the last second */
	guint32 bytes_lastsec, bytes_lastsec_temp;
	/*! \brief Time we last updated the last second counter */
	gint64 updated;
	/*! \brief Whether or not we notified about lastsec issues already */
	gboolean notified_lastsec;
	/*! \brief Number of NACKs sent or received */
	guint32 nacks;
} janus_ice_stats_info;

/*! \brief Janus media statistics container
 * \note To improve with more stuff */
typedef struct janus_ice_stats {
	/*! \brief Audio info */
	janus_ice_stats_info audio;
	/*! \brief Video info (considering we may be simulcasting) */
	janus_ice_stats_info video[3];
	/*! \brief Data info */
	janus_ice_stats_info data;
	/*! \brief Last time the slow_link callback (of the plugin) was called */
	gint64 last_slowlink_time;
	/*! \brief Start time of recent NACKs (for slow_link) */
	gint64 sl_nack_period_ts;
	/*! \brief Count of recent NACKs (for slow_link) */
	guint sl_nack_recent_cnt;
} janus_ice_stats;

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
} janus_seq_info;
void janus_seq_list_free(janus_seq_info **head);
enum {
	SEQ_MISSING,
	SEQ_NACKED,
	SEQ_GIVEUP,
	SEQ_RECVED
};


/*! \brief Janus ICE handle */
struct janus_ice_handle {
	/*! \brief Opaque pointer to the core/peer session */
	void *session;
	/*! \brief Handle identifier, guaranteed to be non-zero */
	guint64 handle_id;
	/*! \brief Opaque identifier, e.g., to provide inter-handle relationships to external tools */
	char *opaque_id;
	/*! \brief Monotonic time of when the handle has been created */
	gint64 created;
	/*! \brief Opaque application (plugin) pointer */
	void *app;
	/*! \brief Opaque core/plugin session pointer */
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
	/*! \brief GLib sources for outgoing traffic, recurring RTCP, and stats */
	GSource *rtp_source, *rtcp_source, *stats_source;
	/*! \brief Atomic flag to check if the ICE loop is still running */
	volatile gint looprunning;
	/*! \brief libnice ICE agent */
	NiceAgent *agent;
	/*! \brief Monotonic time of when the ICE agent has been created */
	gint64 agent_created;
	/*! \brief ICE role (controlling or controlled) */
	gboolean controlling;
	/*! \brief Audio mid (media ID) */
	gchar *audio_mid;
	/*! \brief Video mid (media ID) */
	gchar *video_mid;
	/*! \brief Data channel mid (media ID) */
	gchar *data_mid;
	/*! \brief Main mid (will be a pointer to one of the above) */
	gchar *stream_mid;
	/*! \brief ICE Stream ID */
	guint stream_id;
	/*! \brief ICE stream */
	janus_ice_stream *stream;
	/*! \brief RTP profile set by caller (so that we can match it) */
	gchar *rtp_profile;
	/*! \brief SDP generated locally (just for debugging purposes) */
	gchar *local_sdp;
	/*! \brief SDP received by the peer (just for debugging purposes) */
	gchar *remote_sdp;
	/*! \brief Reason this handle has been hung up*/
	const gchar *hangup_reason;
	/*! \brief List of pending trickle candidates (those we received before getting the JSEP offer) */
	GList *pending_trickles;
	/*! \brief Queue of outgoing packets to send */
	GAsyncQueue *queued_packets;
	/*! \brief Count of the recent SRTP replay errors, in order to avoid spamming the logs */
	guint srtp_errors_count;
	/*! \brief Count of the recent SRTP replay errors, in order to avoid spamming the logs */
	gint last_srtp_error, last_srtp_summary;
	/*! \brief Count of how many seconds passed since the last stats passed to event handlers */
	gint last_event_stats;
	/*! \brief Flag to decide whether or not packets need to be dumped to a text2pcap file */
	volatile gint dump_packets;
	/*! \brief In case this session must be saved to text2pcap, the instance to dump packets to */
	janus_text2pcap *text2pcap;
	/*! \brief Mutex to lock/unlock the ICE session */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
};

/*! \brief Janus ICE stream */
struct janus_ice_stream {
	/*! \brief Janus ICE handle this stream belongs to */
	janus_ice_handle *handle;
	/*! \brief libnice ICE stream ID */
	guint stream_id;
	/*! \brief Whether this stream is ready to be used */
	gint cdone:1;
	/*! \brief Audio SSRC of the server for this stream */
	guint32 audio_ssrc;
	/*! \brief Video SSRC of the server for this stream */
	guint32 video_ssrc;
	/*! \brief Video retransmission SSRC of the peer for this stream */
	guint32 video_ssrc_rtx;
	/*! \brief Audio SSRC of the peer for this stream */
	guint32 audio_ssrc_peer, audio_ssrc_peer_new, audio_ssrc_peer_orig;
	/*! \brief Video SSRC(s) of the peer for this stream (may be simulcasting) */
	guint32 video_ssrc_peer[3], video_ssrc_peer_new[3], video_ssrc_peer_orig[3];
	/*! \brief Video retransmissions SSRC(s) of the peer for this stream */
	guint32 video_ssrc_peer_rtx[3], video_ssrc_peer_rtx_new[3], video_ssrc_peer_rtx_orig[3];
	/*! \brief Array of RTP Stream IDs (for Firefox simulcasting, if enabled) */
	char *rid[3];
	/*! \brief RTP switching context(s) in case of renegotiations (audio+video and/or simulcast) */
	janus_rtp_switching_context rtp_ctx[3];
	/*! \brief List of payload types we can expect for audio */
	GList *audio_payload_types;
	/*! \brief List of payload types we can expect for video */
	GList *video_payload_types;
	/*! \brief Mapping of rtx payload types to actual media-related packet types */
	GHashTable *rtx_payload_types;
	/*! \brief RTP payload types of this stream */
	gint audio_payload_type, video_payload_type, video_rtx_payload_type;
	/*! \brief Codecs used by this stream */
	char *audio_codec, *video_codec;
	/*! \brief Pointer to function to check if a packet is a keyframe (depends on negotiated codec) */
	gboolean (* video_is_keyframe)(char* buffer, int len);
	/*! \brief Media direction */
	gboolean audio_send, audio_recv, video_send, video_recv;
	/*! \brief RTCP context for the audio stream */
	janus_rtcp_context *audio_rtcp_ctx;
	/*! \brief RTCP context(s) for the video stream (may be simulcasting) */
	janus_rtcp_context *video_rtcp_ctx[3];
	/*! \brief Map(s) of the NACKed packets (to track retransmissions and avoid duplicates) */
	GHashTable *rtx_nacked[3];
	/*! \brief First received audio NTP timestamp */
	gint64 audio_first_ntp_ts;
	/*! \brief First received audio RTP timestamp */
	guint32 audio_first_rtp_ts;
	/*! \brief First received video NTP timestamp (for all simulcast video streams) */
	gint64 video_first_ntp_ts[3];
	/*! \brief First received video NTP RTP timestamp (for all simulcast video streams) */
	guint32 video_first_rtp_ts[3];
	/*! \brief Last sent audio RTP timestamp */
	guint32 audio_last_ts;
	/*! \brief Last sent video RTP timestamp */
	guint32 video_last_ts;
	/*! \brief  Wether we do transport wide cc for video */
	gboolean do_transport_wide_cc;
	/*! \brief Transport wide cc rtp ext ID */
	guint transport_wide_cc_ext_id;
	/*! \brief Last received transport wide seq num */
	guint32 transport_wide_cc_last_seq_num;
	/*! \brief Last transport wide seq num sent on feedback */
	guint32 transport_wide_cc_last_feedback_seq_num;
	/*! \brief Transport wide cc transport seq num wrap cycles */
	guint16 transport_wide_cc_cycles;
	/*! \brief Transport wide cc rtp ext ID */
	guint transport_wide_cc_feedback_count;
	/*! \brief GLib list of transport wide cc stats in reverse received order */
	GSList *transport_wide_received_seq_nums;
	/*! \brief DTLS role of the server for this stream */
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
	/*! \brief ICE component */
	janus_ice_component *component;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gboolean noerrorlog;
	/*! \brief Mutex to lock/unlock this stream */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
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
	/*! \brief Timer to check when we should consider ICE as failed */
	GSource *icestate_source;
	/*! \brief Time of when we first detected an ICE failed (we'll need this for the timer above) */
	gint64 icefailed_detected;
	/*! \brief Re-transmission timer for DTLS */
	GSource *dtlsrt_source;
	/*! \brief DTLS-SRTP stack */
	janus_dtls_srtp *dtls;
	/*! \brief Whether we should do NACKs (in or out) for audio */
	gboolean do_audio_nacks;
	/*! \brief Whether we should do NACKs (in or out) for video */
	gboolean do_video_nacks;
	/*! \brief List of previously sent janus_rtp_packet RTP packets, in case we receive NACKs */
	GQueue *audio_retransmit_buffer, *video_retransmit_buffer;
	/*! \brief HashTable of retransmittable sequence numbers, in case we receive NACKs */
	GHashTable *audio_retransmit_seqs, *video_retransmit_seqs;
	/*! \brief Current sequence number for the RFC4588 rtx SSRC session */
	guint16 rtx_seq_number;
	/*! \brief Last time a log message about sending retransmits was printed */
	gint64 retransmit_log_ts;
	/*! \brief Number of retransmitted packets since last log message */
	guint retransmit_recent_cnt;
	/*! \brief Last time a log message about sending NACKs was printed */
	gint64 nack_sent_log_ts;
	/*! \brief Number of NACKs sent since last log message */
	guint nack_sent_recent_cnt;
	/*! \brief List of recently received audio sequence numbers (as a support to NACK generation) */
	janus_seq_info *last_seqs_audio;
	/*! \brief List of recently received video sequence numbers (as a support to NACK generation, for each simulcast SSRC) */
	janus_seq_info *last_seqs_video[3];
	/*! \brief Stats for incoming data (audio/video/data) */
	janus_ice_stats in_stats;
	/*! \brief Stats for outgoing data (audio/video/data) */
	janus_ice_stats out_stats;
	/*! \brief Helper flag to avoid flooding the console with the same error all over again */
	gboolean noerrorlog;
	/*! \brief Mutex to lock/unlock this component */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
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
 * @param[in] transaction The Janus API ID of the original trickle request
 * @param[in] candidate The trickle candidate, as a Jansson object
 * @returns a pointer to the new instance, if successful, NULL otherwise */
janus_ice_trickle *janus_ice_trickle_new(const char *transaction, json_t *candidate);
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
 * @param[in] core_session The core/peer session this ICE handle will belong to
 * @param[in] opaque_id The opaque identifier provided by the creator, if any (optional)
 * @returns The created Janus ICE handle if successful, NULL otherwise */
janus_ice_handle *janus_ice_handle_create(void *core_session, const char *opaque_id);
/*! \brief Method to attach a Janus ICE handle to a plugin
 * \details This method is very important, as it allows plugins to send/receive media (RTP/RTCP) to/from a WebRTC peer.
 * @param[in] core_session The core/peer session this ICE handle belongs to
 * @param[in] handle The Janus ICE handle
 * @param[in] plugin The plugin the ICE handle needs to be attached to
 * @returns 0 in case of success, a negative integer otherwise */
gint janus_ice_handle_attach_plugin(void *core_session, janus_ice_handle *handle, janus_plugin *plugin);
/*! \brief Method to destroy a Janus ICE handle
 * @param[in] core_session The core/peer session this ICE handle belongs to
 * @param[in] handle The Janus ICE handle to destroy
 * @returns 0 in case of success, a negative integer otherwise */
gint janus_ice_handle_destroy(void *core_session, janus_ice_handle *handle);
/*! \brief Method to only hangup (e.g., DTLS alert) the WebRTC PeerConnection allocated by a Janus ICE handle
 * @param[in] handle The Janus ICE handle instance managing the WebRTC PeerConnection to hangup
 * @param[in] reason A description of why this happened */
void janus_ice_webrtc_hangup(janus_ice_handle *handle, const char *reason);
/*! \brief Method to only free the WebRTC related resources allocated by a Janus ICE handle
 * @param[in] handle The Janus ICE handle instance managing the WebRTC resources to free */
void janus_ice_webrtc_free(janus_ice_handle *handle);
/*! \brief Method to only free resources related to a specific ICE stream allocated by a Janus ICE handle
 * @param[in] stream The Janus ICE stream instance to free */
void janus_ice_stream_destroy(janus_ice_stream *stream);
/*! \brief Method to only free resources related to a specific ICE component allocated by a Janus ICE handle
 * @param[in] component The Janus ICE component instance to free */
void janus_ice_component_destroy(janus_ice_component *component);
///@}


/** @name Janus ICE media relaying callbacks
 */
///@{
/*! \brief Core RTP callback, called when a plugin has an RTP packet to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] video Whether this is an audio or a video frame
 * @param[in] buf The packet data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len);
/*! \brief Core RTCP callback, called when a plugin has an RTCP message to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] video Whether this is related to an audio or a video stream
 * @param[in] buf The message data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_rtcp(janus_ice_handle *handle, int video, char *buf, int len);
/*! \brief Core SCTP/DataChannel callback, called when a plugin has data to send to a peer
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] buf The message data (buffer)
 * @param[in] len The buffer lenght */
void janus_ice_relay_data(janus_ice_handle *handle, char *buf, int len);
/*! \brief Plugin SCTP/DataChannel callback, called by the SCTP stack when when there's data for a plugin
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] buffer The message data (buffer)
 * @param[in] length The buffer lenght */
void janus_ice_incoming_data(janus_ice_handle *handle, char *buffer, int length);
/*! \brief Core SCTP/DataChannel callback, called by the SCTP stack when when there's data to send.
 * @param[in] handle The Janus ICE handle associated with the peer
 * @param[in] buffer The message data (buffer)
 * @param[in] length The buffer lenght */
void janus_ice_relay_sctp(janus_ice_handle *handle, char *buffer, int length);
///@}


/** @name Janus ICE handle helpers
 */
///@{
/*! \brief Method to locally set up the ICE candidates (initialization and gathering)
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] offer Whether this is for an OFFER or an ANSWER
 * @param[in] audio Whether audio is enabled
 * @param[in] video Whether video is enabled
 * @param[in] data Whether SCTP data channels are enabled
 * @param[in] trickle Whether ICE trickling is supported or not
 * @returns 0 in case of success, a negative integer otherwise */
int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video, int data, int trickle);
/*! \brief Method to add local candidates to a janus_sdp SDP object representation
 * @param[in] handle The Janus ICE handle this method refers to
 * @param[in] mline The Janus SDP m-line object to add candidates to
 * @param[in] stream_id The stream ID of the candidate to add to the SDP
 * @param[in] component_id The component ID of the candidate to add to the SDP */
void janus_ice_candidates_to_sdp(janus_ice_handle *handle, janus_sdp_mline *mline, guint stream_id, guint component_id);
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
/*! \brief Method to restart ICE and the connectivity checks
 * @param[in] handle The Janus ICE handle this method refers to */
void janus_ice_restart(janus_ice_handle *handle);
/*! \brief Method to resend all the existing candidates via trickle (e.g., after an ICE restart)
 * @param[in] handle The Janus ICE handle this method refers to */
void janus_ice_resend_trickles(janus_ice_handle *handle);
///@}

#endif
