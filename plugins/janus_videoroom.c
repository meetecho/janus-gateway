/*! \file   janus_videoroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VideoRoom plugin
 * \details  This is a plugin implementing a videoconferencing SFU
 * (Selective Forwarding Unit) for Janus, that is an audio/video router.
 * This means that the plugin implements a virtual conferencing room peers
 * can join and leave at any time. This room is based on a Publish/Subscribe
 * pattern. Each peer can publish his/her own live audio/video feeds: this
 * feed becomes an available stream in the room the other participants can
 * attach to. This means that this plugin allows the realization of several
 * different scenarios, ranging from a simple webinar (one speaker, several
 * watchers) to a fully meshed video conference (each peer sending and
 * receiving to and from all the others).
 * 
 * Considering that this plugin allows for several different WebRTC PeerConnections
 * to be on at the same time for the same peer (specifically, each peer
 * potentially has 1 PeerConnection on for publishing and N on for subscriptions
 * from other peers), each peer may need to attach several times to the same
 * plugin for every stream: this means that each peer needs to have at least one
 * handle active for managing its relation with the plugin (joining a room,
 * leaving a room, muting/unmuting, publishing, receiving events), and needs
 * to open a new one each time he/she wants to subscribe to a feed from
 * another publisher participant. The handle used for a subscription,
 * however, would be logically a "slave" to the master one used for
 * managing the room: this means that it cannot be used, for instance,
 * to unmute in the room, as its only purpose would be to provide a
 * context in which creating the recvonly PeerConnection for the
 * subscription to an active publisher participant.
 * 
 * \note Work is going on to implement SSRC multiplexing (Unified Plan),
 * meaning that in the future you'll be able to use the same
 * Janus handle/VideoRoom subscriber/PeerConnection to receive multiple
 * publishers at the same time.
 * 
 * Rooms to make available are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.videoroom.cfg
 * and includes a demo room for testing. The same plugin is also used
 * dynamically (that is, with rooms created on the fly via API) in the
 * Screen Sharing demo as well.
 * 
 * To add more rooms or modify the existing one, you can use the following
 * syntax:
 * 
 * \verbatim
[<unique room ID>]
description = This is my awesome room
is_private = yes|no (private rooms don't appear when you do a 'list' request)
secret = <optional password needed for manipulating (e.g. destroying) the room>
pin = <optional password needed for joining the room>
publishers = <max number of concurrent senders> (e.g., 6 for a video
             conference or 1 for a webinar)
bitrate = <max video bitrate for senders> (e.g., 128000)
fir_freq = <send a FIR to publishers every fir_freq seconds> (0=disable)
audiocodec = opus|isac32|isac16|pcmu|pcma (audio codec to force on publishers, default=opus)
videocodec = vp8|vp9|h264 (video codec to force on publishers, default=vp8)
record = true|false (whether this room should be recorded, default=false)
rec_dir = <folder where recordings should be stored, when enabled>
\endverbatim
 *
 * Note that recording will work with all codecs except iSAC.
 *
 * \section sfuapi Video Room API
 * 
 * The Video Room API supports several requests, some of which are
 * synchronous and some asynchronous. There are some situations, though,
 * (invalid JSON, invalid request) which will always result in a
 * synchronous error response even for asynchronous requests. 
 * 
 * \c create , \c destroy , \c exists, \c list and \c listparticipants
 * are synchronous requests, which means you'll
 * get a response directly within the context of the transaction.
 * \c create allows you to create a new video room dynamically, as an
 * alternative to using the configuration file; \c destroy removes a
 * video room and destroys it, kicking all the users out as part of the
 * process; \c exists allows you to check whether a specific video room
 * exists; finally, \c list lists all the available rooms, while \c
 * listparticipants lists all the active (as in currentòy publishing
 * something) participants of a specific room and their details.
 * 
 * The \c join , \c joinandconfigure , \c configure , \c publish ,
 * \c unpublish , \c start , \c pause , \c switch , \c stop and \c leave
 * requests instead are all asynchronous, which
 * means you'll get a notification about their success or failure in
 * an event. \c join allows you to join a specific video room, specifying
 * whether that specific PeerConnection will be used for publishing or
 * watching; \c configure can be used to modify some of the participation
 * settings (e.g., bitrate cap); \c joinandconfigure combines the previous
 * two requests in a single one (just for publishers); \c publish can be
 * used to start sending media to broadcast to the other participants,
 * while \c unpublish does the opposite; \c start allows you to start
 * receiving media from a publisher you've subscribed to previously by
 * means of a \c join , while \c pause pauses the delivery of the media;
 * the \c switch request can be used to change the source of the media
 * flowing over a specific PeerConnection (e.g., I was watching Alice,
 * I want to watch Bob now) without having to create a new handle for
 * that; \c stop interrupts a viewer instance; finally, \c leave allows
 * you to leave a video room for good.
 * 
 * Notice that, in general, all users can create rooms. If you want to
 * limit this functionality, you can configure an admin \c admin_key in
 * the plugin settings. When configured, only "create" requests that
 * include the correct \c admin_key value in an "admin_key" property
 * will succeed, and will be rejected otherwise.
 * 
 * Actual API docs: TBD.
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../record.h"
#include "../sdp-utils.h"
#include "../utils.h"
#include <sys/types.h>
#include <sys/socket.h>

#ifdef JANUS_THREAD_DEBUG
static volatile gint handler_thread_count = 0;
#endif

/* Plugin information */
#define JANUS_VIDEOROOM_VERSION			7
#define JANUS_VIDEOROOM_VERSION_STRING	"0.0.7"
#define JANUS_VIDEOROOM_DESCRIPTION		"This is a plugin implementing a videoconferencing SFU (Selective Forwarding Unit) for Janus, that is an audio/video router."
#define JANUS_VIDEOROOM_NAME			"JANUS VideoRoom plugin"
#define JANUS_VIDEOROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_VIDEOROOM_PACKAGE			"janus.plugin.videoroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_videoroom_init(janus_callbacks *callback, const char *config_path);
void janus_videoroom_destroy(void);
int janus_videoroom_get_api_compatibility(void);
int janus_videoroom_get_version(void);
const char *janus_videoroom_get_version_string(void);
const char *janus_videoroom_get_description(void);
const char *janus_videoroom_get_name(void);
const char *janus_videoroom_get_author(void);
const char *janus_videoroom_get_package(void);
void janus_videoroom_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_videoroom_setup_media(janus_plugin_session *handle);
void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_videoroom_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_videoroom_hangup_media(janus_plugin_session *handle);
void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_videoroom_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_videoroom_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_videoroom_init,
		.destroy = janus_videoroom_destroy,

		.get_api_compatibility = janus_videoroom_get_api_compatibility,
		.get_version = janus_videoroom_get_version,
		.get_version_string = janus_videoroom_get_version_string,
		.get_description = janus_videoroom_get_description,
		.get_name = janus_videoroom_get_name,
		.get_author = janus_videoroom_get_author,
		.get_package = janus_videoroom_get_package,
		
		.create_session = janus_videoroom_create_session,
		.handle_message = janus_videoroom_handle_message,
		.setup_media = janus_videoroom_setup_media,
		.incoming_rtp = janus_videoroom_incoming_rtp,
		.incoming_rtcp = janus_videoroom_incoming_rtcp,
		.incoming_data = janus_videoroom_incoming_data,
		.slow_link = janus_videoroom_slow_link,
		.hangup_media = janus_videoroom_hangup_media,
		.destroy_session = janus_videoroom_destroy_session,
		.query_session = janus_videoroom_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VIDEOROOM_NAME);
	return &janus_videoroom_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter create_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"description", JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0},
	{"secret", JSON_STRING, 0},
	{"pin", JSON_STRING, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"fir_freq", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"publishers", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audiocodec", JSON_STRING, 0},
	{"videocodec", JSON_STRING, 0},
	{"record", JANUS_JSON_BOOL, 0},
	{"rec_dir", JSON_STRING, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter room_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter destroy_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter join_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"ptype", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0}
};
static struct janus_json_parameter publish_parameters[] = {
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0}
};
static struct janus_json_parameter rtp_forward_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"publisher_id", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"video_port", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audio_port", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"host", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter stop_rtp_forward_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"publisher_id", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"stream_id", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter publisher_parameters[] = {
	{"id", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"display", JSON_STRING, 0}
};
static struct janus_json_parameter configure_parameters[] = {
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"data", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter subscriber_parameters[] = {
	{"feed", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"data", JANUS_JSON_BOOL, 0}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videoroom_handler(void *data);
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data);
static void janus_videoroom_relay_data_packet(gpointer data, gpointer user_data);

typedef enum janus_videoroom_p_type {
	janus_videoroom_p_type_none = 0,
	janus_videoroom_p_type_subscriber,			/* Generic subscriber */
	janus_videoroom_p_type_publisher,			/* Participant (for receiving events) and optionally publisher */
} janus_videoroom_p_type;

typedef struct janus_videoroom_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_videoroom_message;
static GAsyncQueue *messages = NULL;
static janus_videoroom_message exit_message;


typedef enum janus_videoroom_audiocodec {
	JANUS_VIDEOROOM_OPUS,		/* Publishers will have to use OPUS 	*/
	JANUS_VIDEOROOM_ISAC_32K,	/* Publishers will have to use ISAC 32K */
	JANUS_VIDEOROOM_ISAC_16K,	/* Publishers will have to use ISAC 16K */
	JANUS_VIDEOROOM_PCMU,		/* Publishers will have to use PCMU 8K 	*/
	JANUS_VIDEOROOM_PCMA		/* Publishers will have to use PCMA 8K 	*/
} janus_videoroom_audiocodec;
static const char *janus_videoroom_audiocodec_name(janus_videoroom_audiocodec acodec) {
	switch(acodec) {
		case JANUS_VIDEOROOM_OPUS:
			return "opus";
		case JANUS_VIDEOROOM_ISAC_32K:
			return "isac32";
		case JANUS_VIDEOROOM_ISAC_16K:
			return "isac16";
		case JANUS_VIDEOROOM_PCMU:
			return "pcmu";
		case JANUS_VIDEOROOM_PCMA:
			return "pcma";
		default:
			/* Shouldn't happen */
			return "opus";
	}
}

typedef enum janus_videoroom_videocodec {
	JANUS_VIDEOROOM_VP8,	/* Publishers will have to use VP8 */
	JANUS_VIDEOROOM_VP9,	/* Publishers will have to use VP9 */
	JANUS_VIDEOROOM_H264	/* Publishers will have to use H264 */
} janus_videoroom_videocodec;
static const char *janus_videoroom_videocodec_name(janus_videoroom_videocodec vcodec) {
	switch(vcodec) {
		case JANUS_VIDEOROOM_VP8:
			return "vp8";
		case JANUS_VIDEOROOM_VP9:
			return "vp9";
		case JANUS_VIDEOROOM_H264:
			return "h264";
		default:
			/* Shouldn't happen */
			return "vp8";
	}
}

typedef struct janus_videoroom {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	int max_publishers;			/* Maximum number of concurrent publishers */
	uint64_t bitrate;			/* Global bitrate limit */
	uint16_t fir_freq;			/* Regular FIR frequency (0=disabled) */
	janus_videoroom_audiocodec acodec;	/* Audio codec to force on publishers*/
	janus_videoroom_videocodec vcodec;	/* Video codec to force on publishers*/
	gboolean record;			/* Whether the feeds from publishers in this room should be recorded */
	char *rec_dir;				/* Where to save the recordings of this room, if enabled */
	GHashTable *participants;	/* Map of potential publishers (we get subscribers from them) */
	volatile gint destroyed;	/* Whether this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */
	janus_refcount ref;			/* Reference counter for this room */
} janus_videoroom;
static GHashTable *rooms;
static janus_mutex rooms_mutex;
static char *admin_key = NULL;

typedef struct janus_videoroom_session {
	janus_plugin_session *handle;
	janus_videoroom_p_type participant_type;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_mutex mutex;
	janus_refcount ref;
} janus_videoroom_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex;


/* A host whose ports gets streamed rtp packets of the corresponding type. */
typedef struct rtp_forwarder {
	int is_video;
	struct sockaddr_in serv_addr;
} rtp_forwarder;

typedef struct janus_videoroom_publisher {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	guint64 user_id;	/* Unique ID in the room */
	gchar *display;	/* Display name (just for fun) */
	gchar *sdp;			/* The SDP this publisher negotiated, if any */
	gboolean audio, video, data;		/* Whether audio, video and/or data is going to be sent by this publisher */
	guint32 audio_pt;		/* Audio payload type (Opus) */
	guint32 video_pt;		/* Video payload type (depends on room configuration) */
	guint32 audio_ssrc;		/* Audio SSRC of this publisher */
	guint32 video_ssrc;		/* Video SSRC of this publisher */
	gboolean audio_active;
	gboolean video_active;
	gboolean firefox;	/* We send Firefox users a different kind of FIR */
	uint64_t bitrate;
	gint64 remb_startup;/* Incremental changes on REMB to reach the target at startup */
	gint64 remb_latest;	/* Time of latest sent REMB (to avoid flooding) */
	gint64 fir_latest;	/* Time of latest sent FIR (to avoid flooding) */
	gint fir_seq;		/* FIR sequence number */
	gboolean recording_active;	/* Whether this publisher has to be recorded or not */
	gchar *recording_base;	/* Base name for the recording (e.g., /path/to/filename, will generate /path/to/filename-audio.mjr and/or /path/to/filename-video.mjr */
	janus_recorder *arc;	/* The Janus recorder instance for this publisher's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this publisher's video, if enabled */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	GSList *subscribers;
	janus_mutex subscribers_mutex;
	GHashTable *rtp_forwarders;
	janus_mutex rtp_forwarders_mutex;
	int udp_sock; /* The udp socket on which to forward rtp packets */
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_publisher;
static void janus_rtp_forwarder_free_helper(gpointer data);
static guint32 janus_rtp_forwarder_add_helper(janus_videoroom_publisher *p, const gchar* host, int port, int is_video);
typedef struct janus_videoroom_subscriber_context {
	/* Needed to fix seq and ts in case of publisher switching */
	uint32_t a_last_ssrc, a_last_ts, a_base_ts, a_base_ts_prev,
			v_last_ssrc, v_last_ts, v_base_ts, v_base_ts_prev;
	uint16_t a_last_seq, a_base_seq, a_base_seq_prev,
			v_last_seq, v_base_seq, v_base_seq_prev;
	gboolean a_seq_reset, v_seq_reset;
} janus_videoroom_subscriber_context;

typedef struct janus_videoroom_subscriber {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	janus_videoroom_publisher *feed;	/* Participant this subscriber is subscribed to */
	janus_videoroom_subscriber_context context;	/* Needed in case there are publisher switches on this subscriber */
	gboolean audio, video, data;		/* Whether audio, video and/or data must be sent to this publisher */
	gboolean paused;
	volatile gint destroyed;
	janus_refcount ref;
} janus_videoroom_subscriber;

typedef struct janus_videoroom_rtp_relay_packet {
	rtp_header *data;
	gint length;
	gint is_video;
	uint32_t timestamp;
	uint16_t seq_number;
} janus_videoroom_rtp_relay_packet;


/* Freeing stuff */
static void janus_videoroom_subscriber_dereference(janus_videoroom_subscriber *s) {
	/* No need to test for NULL in conjunction with g_clear_pointer. */
	janus_refcount_decrease(&s->ref);
}

static void janus_videoroom_subscriber_destroy(janus_videoroom_subscriber *s) {
	if(s && g_atomic_int_compare_and_exchange(&s->destroyed, 0, 1))
		janus_refcount_decrease(&s->ref);
}

static void janus_videoroom_subscriber_free(const janus_refcount *s_ref) {
	janus_videoroom_subscriber *s = janus_refcount_containerof(s_ref, janus_videoroom_subscriber, ref);
	/* This subscriber can be destroyed, free all the resources */
	g_free(s);
}

static void janus_videoroom_publisher_dereference(janus_videoroom_publisher *p) {
	/* This is used by g_pointer_clear and g_hash_table_new_full so that NULL is only possible if that was inserted into the hash table. */
	janus_refcount_decrease(&p->ref);
}

static void janus_videoroom_publisher_dereference_nodebug(janus_videoroom_publisher *p) {
	janus_refcount_decrease_nodebug(&p->ref);
}

static void janus_videoroom_publisher_destroy(janus_videoroom_publisher *p) {
	if(p && g_atomic_int_compare_and_exchange(&p->destroyed, 0, 1))
		janus_refcount_decrease(&p->ref);
}

static void janus_videoroom_publisher_free(const janus_refcount *p_ref) {
	janus_videoroom_publisher *p = janus_refcount_containerof(p_ref, janus_videoroom_publisher, ref);
	g_free(p->display);
	g_free(p->sdp);

	g_free(p->recording_base);
	janus_recorder_free(p->arc);
	janus_recorder_free(p->vrc);

	if(p->udp_sock > 0)
		close(p->udp_sock);
	g_hash_table_destroy(p->rtp_forwarders);
	p->rtp_forwarders = NULL;
	g_slist_free(p->subscribers);

	janus_mutex_destroy(&p->subscribers_mutex);
	janus_mutex_destroy(&p->rtp_forwarders_mutex);
	g_free(p);
}

static void janus_videoroom_session_dereference(janus_videoroom_session *session) {
	janus_refcount_decrease(&session->ref);
}

static void janus_videoroom_session_destroy(janus_videoroom_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_videoroom_session_free(const janus_refcount *session_ref) {
	janus_videoroom_session *session = janus_refcount_containerof(session_ref, janus_videoroom_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	janus_mutex_destroy(&session->mutex);
	g_free(session);
}

static void janus_videoroom_room_dereference(janus_videoroom *room) {
	janus_refcount_decrease(&room->ref);
}

static void janus_videoroom_room_destroy(janus_videoroom *room) {
	if(room && g_atomic_int_compare_and_exchange(&room->destroyed, 0, 1))
		janus_refcount_decrease(&room->ref);
}

static void janus_videoroom_room_free(const janus_refcount *room_ref) {
	janus_videoroom *room = janus_refcount_containerof(room_ref, janus_videoroom, ref);
	/* This room can be destroyed, free all the resources */
	g_free(room->room_name);
	g_free(room->room_secret);
	g_free(room->room_pin);
	g_free(room->rec_dir);
	g_hash_table_destroy(room->participants);
}

static void janus_videoroom_message_free(janus_videoroom_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_videoroom_session *session = (janus_videoroom_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}


/* SDP offer/answer templates */
#define OPUS_PT	111
#define ISAC32_PT	104
#define ISAC16_PT	103
#define PCMU_PT	0
#define PCMA_PT	8
#define VP8_PT		100
#define VP9_PT		101
#define H264_PT	107
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=%s\r\n"							/* Video room name */ \
		"t=0 0\r\n" \
		"%s%s%s"				/* Audio, video and/or data channel m-lines */
#define sdp_a_template_opus \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */
#define sdp_a_template_isac32 \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* ISAC32_PT payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d ISAC/32000\r\n"		/* ISAC32_PT payload type */
#define sdp_a_template_isac16 \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* ISAC16_PT payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d ISAC/16000\r\n"		/* ISAC16_PT payload type */
#define sdp_a_template_pcmu \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* PCMU_PT payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d PCMU/8000\r\n"		    /* PCMU_PT payload type */
#define sdp_a_template_pcma \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* PCMA_PT payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d PCMA/8000\r\n"		    /* PCMA_PT payload type */
#define sdp_v_template_vp8 \
		"m=video 1 RTP/SAVPF %d\r\n"		/* VP8 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"b=AS:%d\r\n"						/* Bandwidth */ \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d VP8/90000\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d ccm fir\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* VP8 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* VP8 payload type */
#define sdp_v_template_vp9 \
		"m=video 1 RTP/SAVPF %d\r\n"		/* VP9 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"b=AS:%d\r\n"						/* Bandwidth */ \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d VP9/90000\r\n"			/* VP9 payload type */ \
		"a=rtcp-fb:%d ccm fir\r\n"			/* VP9 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* VP9 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* VP9 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* VP9 payload type */
#define sdp_v_template_h264 \
		"m=video 1 RTP/SAVPF %d\r\n"		/* H264 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"b=AS:%d\r\n"						/* Bandwidth */ \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d H264/90000\r\n"		/* H264 payload type */ \
		"a=fmtp:%d profile-level-id=42e01f;packetization-mode=1\r\n" \
		"a=rtcp-fb:%d ccm fir\r\n"			/* H264 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* H264 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* H264 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* H264 payload type */
#ifdef HAVE_SCTP
#define sdp_d_template \
		"m=application 1 DTLS/SCTP 5000\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctpmap:5000 webrtc-datachannel 16\r\n"
#else
#define sdp_d_template \
		"m=application 0 DTLS/SCTP 0\r\n" \
		"c=IN IP4 1.1.1.1\r\n"
#endif


/* Error codes */
#define JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR		499
#define JANUS_VIDEOROOM_ERROR_NO_MESSAGE		421
#define JANUS_VIDEOROOM_ERROR_INVALID_JSON		422
#define JANUS_VIDEOROOM_ERROR_INVALID_REQUEST	423
#define JANUS_VIDEOROOM_ERROR_JOIN_FIRST		424
#define JANUS_VIDEOROOM_ERROR_ALREADY_JOINED	425
#define JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM		426
#define JANUS_VIDEOROOM_ERROR_ROOM_EXISTS		427
#define JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED		428
#define JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT	429
#define JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT	430
#define JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE	431
#define JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL	432
#define JANUS_VIDEOROOM_ERROR_UNAUTHORIZED		433
#define JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED	434
#define JANUS_VIDEOROOM_ERROR_NOT_PUBLISHED		435
#define JANUS_VIDEOROOM_ERROR_ID_EXISTS			436
#define JANUS_VIDEOROOM_ERROR_INVALID_SDP		437


static guint32 janus_rtp_forwarder_add_helper(janus_videoroom_publisher *p, const gchar* host, int port, int is_video) {
	if(!p || !host) {
		return 0;
	}
	rtp_forwarder *forward = g_malloc0(sizeof(rtp_forwarder));
	forward->is_video = is_video;
	forward->serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, host, &(forward->serv_addr.sin_addr));
	forward->serv_addr.sin_port = htons(port);
	janus_mutex_lock(&p->rtp_forwarders_mutex);
	guint32 stream_id = janus_random_uint32();
	while(g_hash_table_lookup(p->rtp_forwarders, GUINT_TO_POINTER(stream_id)) != NULL) {
		stream_id = janus_random_uint32();
	}
	g_hash_table_insert(p->rtp_forwarders, GUINT_TO_POINTER(stream_id), forward);
	janus_mutex_unlock(&p->rtp_forwarders_mutex);
	JANUS_LOG(LOG_VERB, "Added %s rtp_forward to participant %"SCNu64" host: %s:%d stream_id: %"SCNu32"\n", is_video ? "video":"audio", p->user_id, host, port, stream_id);
	return stream_id;
}

static void janus_rtp_forwarder_free_helper(gpointer data) {
	if(data) {
		rtp_forwarder* forward = (rtp_forwarder*)data;
		g_free(forward);
		forward = NULL;
	}
}


/* Plugin implementation */
int janus_videoroom_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_VIDEOROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);
	janus_mutex_init(&config_mutex);

	rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify) janus_videoroom_room_destroy);
	janus_mutex_init(&rooms_mutex);
	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_videoroom_session_destroy);
	janus_mutex_init(&sessions_mutex);

	messages = g_async_queue_new_full((GDestroyNotify) janus_videoroom_message_free);

	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		/* Any admin key to limit who can "create"? */
		janus_config_item *key = janus_config_get_item_drilldown(config, "general", "admin_key");
		if(key != NULL && key->value != NULL)
			admin_key = g_strdup(key->value);
		/* Iterate on all rooms */
		GList *cl = janus_config_get_categories(config);
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL || !strcasecmp(cat->name, "general")) {
				cl = cl->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding video room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get_item(cat, "description");
			janus_config_item *priv = janus_config_get_item(cat, "is_private");
			janus_config_item *secret = janus_config_get_item(cat, "secret");
			janus_config_item *pin = janus_config_get_item(cat, "pin");
			janus_config_item *bitrate = janus_config_get_item(cat, "bitrate");
			janus_config_item *maxp = janus_config_get_item(cat, "publishers");
			janus_config_item *firfreq = janus_config_get_item(cat, "fir_freq");
			janus_config_item *audiocodec = janus_config_get_item(cat, "audiocodec");
			janus_config_item *videocodec = janus_config_get_item(cat, "videocodec");
			janus_config_item *record = janus_config_get_item(cat, "record");
			janus_config_item *rec_dir = janus_config_get_item(cat, "rec_dir");
			/* Create the video room */
			janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
			videoroom->room_id = g_ascii_strtoull(cat->name, NULL, 0);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			videoroom->room_name = description;
			if(secret != NULL && secret->value != NULL) {
				videoroom->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				videoroom->room_pin = g_strdup(pin->value);
			}
			videoroom->is_private = priv && priv->value && janus_is_true(priv->value);
			videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			if(maxp != NULL && maxp->value != NULL)
				videoroom->max_publishers = atol(maxp->value);
			if(videoroom->max_publishers < 0)
				videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			videoroom->bitrate = 0;
			if(bitrate != NULL && bitrate->value != NULL)
				videoroom->bitrate = atol(bitrate->value);
			if(videoroom->bitrate > 0 && videoroom->bitrate < 64000)
				videoroom->bitrate = 64000;	/* Don't go below 64k */
			videoroom->fir_freq = 0;
			if(firfreq != NULL && firfreq->value != NULL)
				videoroom->fir_freq = atol(firfreq->value);
			videoroom->acodec = JANUS_VIDEOROOM_OPUS;
			if(audiocodec && audiocodec->value) {
				if(!strcasecmp(audiocodec->value, "opus"))
					videoroom->acodec = JANUS_VIDEOROOM_OPUS;
				else if(!strcasecmp(audiocodec->value, "isac32"))
					videoroom->acodec = JANUS_VIDEOROOM_ISAC_32K;
				else if(!strcasecmp(audiocodec->value, "isac16"))
					videoroom->acodec = JANUS_VIDEOROOM_ISAC_16K;
				else if(!strcasecmp(audiocodec->value, "pcmu"))
					videoroom->acodec = JANUS_VIDEOROOM_PCMU;
				else if(!strcasecmp(audiocodec->value, "pcma"))
					videoroom->acodec = JANUS_VIDEOROOM_PCMA;
				else {
					JANUS_LOG(LOG_WARN, "Unsupported audio codec '%s', falling back to OPUS\n", audiocodec->value);
					videoroom->acodec = JANUS_VIDEOROOM_OPUS;
				}
			}
			videoroom->vcodec = JANUS_VIDEOROOM_VP8;
			if(videocodec && videocodec->value) {
				if(!strcasecmp(videocodec->value, "vp8"))
					videoroom->vcodec = JANUS_VIDEOROOM_VP8;
				else if(!strcasecmp(videocodec->value, "vp9"))
					videoroom->vcodec = JANUS_VIDEOROOM_VP9;
				else if(!strcasecmp(videocodec->value, "h264"))
					videoroom->vcodec = JANUS_VIDEOROOM_H264;
				else {
					JANUS_LOG(LOG_WARN, "Unsupported video codec '%s', falling back to VP8\n", videocodec->value);
					videoroom->vcodec = JANUS_VIDEOROOM_VP8;
				}
			}
			if(record && record->value) {
				videoroom->record = janus_is_true(record->value);
			}
			if(rec_dir && rec_dir->value) {
				videoroom->rec_dir = g_strdup(rec_dir->value);
			}
			g_atomic_int_set(&videoroom->destroyed, 0);
			janus_mutex_init(&videoroom->mutex);
			janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
			videoroom->participants = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_videoroom_publisher_dereference);
			janus_mutex_lock(&rooms_mutex);
			g_hash_table_insert(rooms, janus_uint64_dup(videoroom->room_id), videoroom);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, %s/%s codecs, secret: %s, pin: %s)\n",
				videoroom->room_id, videoroom->room_name,
				videoroom->is_private ? "private" : "public",
				janus_videoroom_audiocodec_name(videoroom->acodec),
				janus_videoroom_videocodec_name(videoroom->vcodec),
				videoroom->room_secret ? videoroom->room_secret : "no secret",
				videoroom->room_pin ? videoroom->room_pin : "no pin");
			if(videoroom->record) {
				JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
			}
			cl = cl->next;
		}
		/* Done: we keep the configuration file open in case we get a "create" or "destroy" with permanent=true */
	}

	/* Show available rooms */
	janus_mutex_lock(&rooms_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, rooms);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_videoroom *vr = value;
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers, FIR frequency of %d seconds, %s audio codec, %s video codec\n",
			vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->fir_freq,
			janus_videoroom_audiocodec_name(vr->acodec), janus_videoroom_videocodec_name(vr->vcodec));
	}
	janus_mutex_unlock(&rooms_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("videoroom handler", janus_videoroom_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VideoRoom handler thread...\n", error->code, error->message ? error->message : "??");
		janus_config_destroy(config);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VIDEOROOM_NAME);
	return 0;
}

void janus_videoroom_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);

	janus_mutex_lock(&rooms_mutex);
	g_hash_table_destroy(rooms);
	janus_mutex_unlock(&rooms_mutex);

	g_async_queue_unref(messages);
	messages = NULL;

	janus_config_destroy(config);
	g_free(admin_key);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VIDEOROOM_NAME);
}

int janus_videoroom_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_videoroom_get_version(void) {
	return JANUS_VIDEOROOM_VERSION;
}

const char *janus_videoroom_get_version_string(void) {
	return JANUS_VIDEOROOM_VERSION_STRING;
}

const char *janus_videoroom_get_description(void) {
	return JANUS_VIDEOROOM_DESCRIPTION;
}

const char *janus_videoroom_get_name(void) {
	return JANUS_VIDEOROOM_NAME;
}

const char *janus_videoroom_get_author(void) {
	return JANUS_VIDEOROOM_AUTHOR;
}

const char *janus_videoroom_get_package(void) {
	return JANUS_VIDEOROOM_PACKAGE;
}

void janus_videoroom_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)g_malloc0(sizeof(janus_videoroom_session));
	session->handle = handle;
	session->participant_type = janus_videoroom_p_type_none;
	session->participant = NULL;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_mutex_init(&session->mutex);
	janus_refcount_init(&session->ref, janus_videoroom_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

static janus_videoroom_publisher *janus_videoroom_session_get_publisher(janus_videoroom_session *session) {
	janus_mutex_lock(&session->mutex);
	janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)session->participant;
	if(publisher)
		janus_refcount_increase(&publisher->ref);
	janus_mutex_unlock(&session->mutex);
	return publisher;
}

static janus_videoroom_publisher *janus_videoroom_session_get_publisher_nodebug(janus_videoroom_session *session) {
	janus_mutex_lock(&session->mutex);
	janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)session->participant;
	if(publisher)
		janus_refcount_increase_nodebug(&publisher->ref);
	janus_mutex_unlock(&session->mutex);
	return publisher;
}

static void janus_videoroom_notify_participants(janus_videoroom_publisher *participant, json_t *msg) {
	/* participant->room->mutex has to be locked. */
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, participant->room->participants);
	while (!g_atomic_int_get(&participant->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_videoroom_publisher *p = value;
		if(p && p->session && p != participant) {
			JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, msg, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		}
	}
}

static void janus_videoroom_leave_or_unpublish(janus_videoroom_publisher *participant, gboolean is_leaving) {
	/* we need to check if the room still exists, may have been destroyed already */
	if(!participant->room || g_atomic_int_get(&participant->room->destroyed))
		return;
	janus_mutex_lock(&participant->room->mutex);
	json_t *event = json_object();
	json_object_set_new(event, "videoroom", json_string("event"));
	json_object_set_new(event, "room", json_integer(participant->room->room_id));
	json_object_set_new(event, is_leaving ? "leaving" : "unpublished", json_integer(participant->user_id));
	janus_videoroom_notify_participants(participant, event);
	if(is_leaving) {
		g_hash_table_remove(participant->room->participants, &participant->user_id);
	}
	json_decref(event);
	janus_mutex_unlock(&participant->room->mutex);
}

void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No VideoRoom session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_WARN, "VideoRoom session already marked as destroyed...\n");
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing VideoRoom session...\n");
	/* Cleaning up and removing the session is done in a lazy way */
	janus_mutex_lock(&sessions_mutex);
	if(!g_atomic_int_get(&session->destroyed)) {
		/* Any related WebRTC PeerConnection is not available anymore either */
		janus_videoroom_hangup_media(handle);
		handle->plugin_handle = NULL;
		if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Get rid of publisher */
			janus_mutex_lock(&session->mutex);
			janus_videoroom_publisher *p = (janus_videoroom_publisher *)session->participant;
			if(p)
				janus_refcount_increase(&p->ref);
			session->participant = NULL;
			janus_mutex_unlock(&session->mutex);
			if(p && p->room) {
				janus_videoroom_leave_or_unpublish(p, TRUE);
				/* Don't clear p->room.  Another thread calls janus_videoroom_leave_or_unpublish,
					 too, and there is no mutex to protect this change. */
				janus_refcount_decrease(&p->room->ref);
			}
			janus_videoroom_publisher_destroy(p);
			g_clear_pointer(&p, janus_videoroom_publisher_dereference);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
			session->participant = NULL;
			if(s->room) {
				janus_refcount_decrease(&s->room->ref);
			}
			janus_videoroom_subscriber_destroy(s);
		}
		g_hash_table_remove(sessions, handle);
	}
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_videoroom_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	/* Show the participant/room info, if any */
	json_t *info = json_object();
	if(session->participant) {
		if(session->participant_type == janus_videoroom_p_type_none) {
			json_object_set_new(info, "type", json_string("none"));
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			json_object_set_new(info, "type", json_string("publisher"));
			janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
			if(participant) {
				janus_videoroom *room = participant->room; 
				json_object_set_new(info, "room", room ? json_integer(room->room_id) : NULL);
				json_object_set_new(info, "id", json_integer(participant->user_id));
				if(participant->display)
					json_object_set_new(info, "display", json_string(participant->display));
				if(participant->subscribers)
					json_object_set_new(info, "viewers", json_integer(g_slist_length(participant->subscribers)));
				json_t *media = json_object();
				json_object_set_new(media, "audio", json_integer(participant->audio));
				json_object_set_new(media, "video", json_integer(participant->video));
				json_object_set_new(media, "data", json_integer(participant->data));
				json_object_set_new(info, "media", media);
				json_object_set_new(info, "bitrate", json_integer(participant->bitrate));
				if(participant->arc || participant->vrc) {
					json_t *recording = json_object();
					if(participant->arc && participant->arc->filename)
						json_object_set_new(recording, "audio", json_string(participant->arc->filename));
					if(participant->vrc && participant->vrc->filename)
						json_object_set_new(recording, "video", json_string(participant->vrc->filename));
					json_object_set_new(info, "recording", recording);
				}
				g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			json_object_set_new(info, "type", json_string("subscriber"));
			janus_videoroom_subscriber *participant = (janus_videoroom_subscriber *)session->participant;
			if(participant) {
				janus_videoroom_publisher *feed = (janus_videoroom_publisher *)participant->feed;
				if(feed) {
					janus_videoroom *room = feed->room; 
					json_object_set_new(info, "room", room ? json_integer(room->room_id) : NULL);
					json_object_set_new(info, "feed_id", json_integer(feed->user_id));
					if(feed->display)
						json_object_set_new(info, "feed_display", json_string(feed->display));
				}
				json_t *media = json_object();
				json_object_set_new(media, "audio", json_integer(participant->audio));
				json_object_set_new(media, "video", json_integer(participant->video));
				json_object_set_new(media, "data", json_integer(participant->data));
				json_object_set_new(info, "media", media);
			}
		}
	}
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	g_clear_pointer(&session, janus_videoroom_session_dereference);
	return info;
}

static int janus_videoroom_access_room(json_t *root, gboolean check_secret, gboolean check_pin, janus_videoroom **videoroom, char *error_cause, int error_cause_size) {
	/* rooms_mutex has to be locked */
	int error_code = 0;
	json_t *room = json_object_get(root, "room");
	guint64 room_id = json_integer_value(room);
	*videoroom = g_hash_table_lookup(rooms, &room_id);
	if(*videoroom == NULL) {
		JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
		error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%"SCNu64")", room_id);
		return error_code;
	}
	if((*videoroom)->destroyed) {
		JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
		error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
		if(error_cause)
			g_snprintf(error_cause, error_cause_size, "No such room (%"SCNu64")", room_id);
		return error_code;
	}
	if(check_secret) {
		char error_cause2[100];
		JANUS_CHECK_SECRET((*videoroom)->room_secret, root, "secret", error_code, error_cause2,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	if(check_pin) {
		char error_cause2[100];
		JANUS_CHECK_SECRET((*videoroom)->room_pin, root, "pin", error_code, error_cause2,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			g_strlcpy(error_cause, error_cause2, error_cause_size);
			return error_code;
		}
	}
	return 0;
}

struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	
	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}

	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been marked as destroyed...\n");
		error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been marked as destroyed...");
		goto plugin_response;
	}

	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);

	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request = json_object_get(root, "request");
	/* Some requests ('create', 'destroy', 'exists', 'list') can be handled synchronously */
	const char *request_text = json_string_value(request);
	if(!strcasecmp(request_text, "create")) {
		/* Create a new videoroom */
		JANUS_LOG(LOG_VERB, "Creating a new videoroom\n");
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto plugin_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto plugin_response;
		}
		json_t *desc = json_object_get(root, "description");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *bitrate = json_object_get(root, "bitrate");
		json_t *fir_freq = json_object_get(root, "fir_freq");
		json_t *publishers = json_object_get(root, "publishers");
		json_t *audiocodec = json_object_get(root, "audiocodec");
		if(audiocodec) {
			const char *audiocodec_value = json_string_value(audiocodec);
			if(!strcasecmp(audiocodec_value, "opus") && !strcasecmp(audiocodec_value, "isac32") && !strcasecmp(audiocodec_value, "isac16") && !strcasecmp(audiocodec_value, "pcmu") && !strcasecmp(audiocodec_value, "pcma")) {
				JANUS_LOG(LOG_ERR, "Invalid element (audiocodec can only be opus, isac32, isac16, pcmu, or pcma)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (audiocodec can only be opus, isac32, isac16, pcmu, or pcma)");
				goto plugin_response;
			}
		}
		json_t *videocodec = json_object_get(root, "videocodec");
		if(videocodec) {
			const char *videocodec_value = json_string_value(videocodec);
			if(!strcasecmp(videocodec_value, "vp8") && !strcasecmp(videocodec_value, "vp9") && !strcasecmp(videocodec_value, "h264")) {
				JANUS_LOG(LOG_ERR, "Invalid element (videocodec can only be vp8, vp9 or h264)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (videocodec can only be vp8, vp9 or h264)");
				goto plugin_response;
			}
		}
		json_t *record = json_object_get(root, "record");
		json_t *rec_dir = json_object_get(root, "rec_dir");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto plugin_response;
		}
		guint64 room_id = 0;
		json_t *room = json_object_get(root, "room");
		if(room) {
			room_id = json_integer_value(room);
			if(room_id == 0) {
				JANUS_LOG(LOG_WARN, "Desired room ID is 0, which is not allowed... picking random ID instead\n");
			}
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, &room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Room %"SCNu64" already exists!\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_ROOM_EXISTS;
				g_snprintf(error_cause, 512, "Room %"SCNu64" already exists", room_id);
				goto plugin_response;
			}
		}
		/* Create the room */
		janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
		/* Generate a random ID */
		if(room_id == 0) {
			while(room_id == 0) {
				room_id = janus_random_uint64();
				if(g_hash_table_lookup(rooms, &room_id) != NULL) {
					/* Room ID already taken, try another one */
					room_id = 0;
				}
			}
		}
		videoroom->room_id = room_id;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %"SCNu64"", videoroom->room_id);
			description = g_strdup(roomname);
		}
		videoroom->room_name = description;
		videoroom->is_private = is_private ? json_is_true(is_private) : FALSE;
		if(secret)
			videoroom->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			videoroom->room_pin = g_strdup(json_string_value(pin));
		videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
		if(publishers)
			videoroom->max_publishers = json_integer_value(publishers);
		if(videoroom->max_publishers < 0)
			videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
		videoroom->bitrate = 0;
		if(bitrate)
			videoroom->bitrate = json_integer_value(bitrate);
		if(videoroom->bitrate > 0 && videoroom->bitrate < 64000)
			videoroom->bitrate = 64000;	/* Don't go below 64k */
		videoroom->fir_freq = 0;
		if(fir_freq)
			videoroom->fir_freq = json_integer_value(fir_freq);
		videoroom->acodec = JANUS_VIDEOROOM_OPUS;
		if(audiocodec) {
			const char *audiocodec_value = json_string_value(audiocodec);
			if(!strcasecmp(audiocodec_value, "opus"))
				videoroom->acodec = JANUS_VIDEOROOM_OPUS;
			else if(!strcasecmp(audiocodec_value, "isac32"))
				videoroom->acodec = JANUS_VIDEOROOM_ISAC_32K;
			else if(!strcasecmp(audiocodec_value, "isac16"))
				videoroom->acodec = JANUS_VIDEOROOM_ISAC_16K;
			else if(!strcasecmp(audiocodec_value, "pcmu"))
				videoroom->acodec = JANUS_VIDEOROOM_PCMU;
			else if(!strcasecmp(audiocodec_value, "pcma"))
				videoroom->acodec = JANUS_VIDEOROOM_PCMA;
			else {
				JANUS_LOG(LOG_WARN, "Unsupported audio codec '%s', falling back to OPUS\n", audiocodec_value);
				videoroom->acodec = JANUS_VIDEOROOM_OPUS;
			}
		}
		videoroom->vcodec = JANUS_VIDEOROOM_VP8;
		if(videocodec) {
			const char *videocodec_value = json_string_value(videocodec);
			if(!strcasecmp(videocodec_value, "vp8"))
				videoroom->vcodec = JANUS_VIDEOROOM_VP8;
			else if(!strcasecmp(videocodec_value, "vp9"))
				videoroom->vcodec = JANUS_VIDEOROOM_VP9;
			else if(!strcasecmp(videocodec_value, "h264"))
				videoroom->vcodec = JANUS_VIDEOROOM_H264;
			else {
				JANUS_LOG(LOG_WARN, "Unsupported video codec '%s', falling back to VP8\n", videocodec_value);
				videoroom->vcodec = JANUS_VIDEOROOM_VP8;
			}
		}
		if(record) {
			videoroom->record = json_is_true(record);
		}
		if(rec_dir) {
			videoroom->rec_dir = g_strdup(json_string_value(rec_dir));
		}
		g_atomic_int_set(&videoroom->destroyed, 0);
		janus_mutex_init(&videoroom->mutex);
		janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
		videoroom->participants = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
		JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, %s/%s codecs, secret: %s, pin: %s)\n",
			videoroom->room_id, videoroom->room_name,
			videoroom->is_private ? "private" : "public",
			janus_videoroom_audiocodec_name(videoroom->acodec),
			janus_videoroom_videocodec_name(videoroom->vcodec),
			videoroom->room_secret ? videoroom->room_secret : "no secret",
			videoroom->room_pin ? videoroom->room_pin : "no pin");
		if(videoroom->record) {
			JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
		}
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %"SCNu64" permanently in config file\n", videoroom->room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category */
			g_snprintf(cat, BUFSIZ, "%"SCNu64, videoroom->room_id);
			janus_config_add_category(config, cat);
			/* Now for the values */
			janus_config_add_item(config, cat, "description", videoroom->room_name);
			if(videoroom->is_private)
				janus_config_add_item(config, cat, "is_private", "yes");
			g_snprintf(value, BUFSIZ, "%"SCNu64, videoroom->bitrate);
			janus_config_add_item(config, cat, "bitrate", value);
			g_snprintf(value, BUFSIZ, "%d", videoroom->max_publishers);
			janus_config_add_item(config, cat, "publishers", value);
			if(videoroom->fir_freq) {
				g_snprintf(value, BUFSIZ, "%"SCNu16, videoroom->fir_freq);
				janus_config_add_item(config, cat, "fir_freq", value);
			}
			janus_config_add_item(config, cat, "audiocodec", janus_videoroom_audiocodec_name(videoroom->acodec));
			janus_config_add_item(config, cat, "videocodec", janus_videoroom_videocodec_name(videoroom->vcodec));
			if(videoroom->room_secret)
				janus_config_add_item(config, cat, "secret", videoroom->room_secret);
			if(videoroom->room_pin)
				janus_config_add_item(config, cat, "pin", videoroom->room_pin);
			if(videoroom->record)
				janus_config_add_item(config, cat, "record", "yes");
			if(videoroom->rec_dir)
				janus_config_add_item(config, cat, "rec_dir", videoroom->rec_dir);
			/* Save modified configuration */
			janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE);
			janus_mutex_unlock(&config_mutex);
		}
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_insert(rooms, janus_uint64_dup(videoroom->room_id), videoroom);
		g_hash_table_iter_init(&iter, rooms);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom *vr = value;
			JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers, FIR frequency of %d seconds\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->fir_freq);
		}
		janus_mutex_unlock(&rooms_mutex);
		/* Send info back */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("created"));
		json_object_set_new(response, "room", json_integer(videoroom->room_id));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "destroy")) {
		JANUS_LOG(LOG_VERB, "Attempt to destroy an existing videoroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, destroy_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto plugin_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto plugin_response;
		}
		/* Remove room */
		g_hash_table_remove(rooms, GUINT_TO_POINTER(room_id));
		/* Notify all participants that the fun is over, and that they'll be kicked */
		JANUS_LOG(LOG_VERB, "Notifying all participants\n");
		json_t *destroyed = json_object();
		json_object_set_new(destroyed, "videoroom", json_string("destroyed"));
		json_object_set_new(destroyed, "room", json_integer(videoroom->room_id));
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			if(p && p->session) {
				/* Notify the user we're going to destroy the room... */
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, destroyed, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				/* ... and then ask the core to remove the handle */
				gateway->end_session(p->session->handle);
			}
		}
		json_decref(destroyed);
		janus_mutex_unlock(&videoroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Destroying room %"SCNu64" permanently in config file\n", room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category */
			g_snprintf(cat, BUFSIZ, "%"SCNu64, room_id);
			janus_config_remove_category(config, cat);
			/* Save modified configuration */
			janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE);
			janus_mutex_unlock(&config_mutex);
		}
		/* Done */
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("destroyed"));
		json_object_set_new(response, "room", json_integer(room_id));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		json_t *list = json_array();
		JANUS_LOG(LOG_VERB, "Getting the list of video rooms\n");
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom *room = value;
			if(!room)
				continue;
			janus_refcount_increase(&room->ref);
			if(room->is_private) {
				/* Skip private room */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				g_clear_pointer(&room, janus_videoroom_room_dereference);
				continue;
			}
			if(!g_atomic_int_get(&room->destroyed)) {
				json_t *rl = json_object();
				json_object_set_new(rl, "room", json_integer(room->room_id));
				json_object_set_new(rl, "description", json_string(room->room_name));
				json_object_set_new(rl, "max_publishers", json_integer(room->max_publishers));
				json_object_set_new(rl, "bitrate", json_integer(room->bitrate));
				json_object_set_new(rl, "fir_freq", json_integer(room->fir_freq));
				json_object_set_new(rl, "audiocodec", json_string(janus_videoroom_audiocodec_name(room->acodec)));
				json_object_set_new(rl, "videocodec", json_string(janus_videoroom_videocodec_name(room->vcodec)));
				json_object_set_new(rl, "record", room->record ? json_true() : json_false());
				json_object_set_new(rl, "rec_dir", json_string(room->rec_dir));
				/* TODO: Should we list participants as well? or should there be a separate API call on a specific room for this? */
				json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
				json_array_append_new(list, rl);
			}
			g_clear_pointer(&room, janus_videoroom_room_dereference);
		}
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "list", list);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		json_t *pub_id = json_object_get(root, "publisher_id");
		int video_port = -1;
		int audio_port = -1;
		json_t *vid_port = json_object_get(root, "video_port");
		if(vid_port) {
			video_port = json_integer_value(vid_port);
		}
		json_t *au_port = json_object_get(root, "audio_port");
		if(au_port) {
			audio_port = json_integer_value(au_port);
		}
		json_t *json_host = json_object_get(root, "host");
		
		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		const gchar* host = json_string_value(json_host);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto plugin_response;
		janus_refcount_increase(&videoroom->ref);
		janus_mutex_lock(&videoroom->mutex);
		janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &publisher_id);
		if(publisher == NULL) {
			janus_mutex_unlock(&videoroom->mutex);
			g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto plugin_response;
		}
		janus_refcount_increase(&publisher->ref);	/* This is just to handle the request for now */
		if(publisher->udp_sock <= 0) {
			publisher->udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(publisher->udp_sock <= 0) {
				g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
				janus_mutex_unlock(&videoroom->mutex);
				g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
				JANUS_LOG(LOG_ERR, "Could not open UDP socket for rtp stream for publisher (%"SCNu64")\n", publisher_id);
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Could not open UDP socket for rtp stream");
				goto plugin_response;
			}
		}
		guint32 audio_handle = 0;
		guint32 video_handle = 0;
		if(audio_port > 0) {
			audio_handle = janus_rtp_forwarder_add_helper(publisher, host, audio_port, 0);
		}
		if(video_port > 0) {
			video_handle = janus_rtp_forwarder_add_helper(publisher, host, video_port, 1);
		}
		janus_mutex_unlock(&videoroom->mutex);
		response = json_object();
		json_t* rtp_stream = json_object();
		if(audio_handle > 0) {
			json_object_set_new(rtp_stream, "audio_stream_id", json_integer(audio_handle));
			json_object_set_new(rtp_stream, "audio", json_integer(audio_port));
		}
		if(video_handle > 0) {
			/* Send a FIR to the new RTP forward publisher */
			char buf[20];
			memset(buf, 0, 20);
			janus_rtcp_fir((char *)&buf, 20, &publisher->fir_seq);
			JANUS_LOG(LOG_VERB, "New RTP forward publisher, sending FIR to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
			gateway->relay_rtcp(publisher->session->handle, 1, buf, 20);
			/* Send a PLI too, just in case... */
			memset(buf, 0, 12);
			janus_rtcp_pli((char *)&buf, 12);
			JANUS_LOG(LOG_VERB, "New RTP forward publisher, sending PLI to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
			gateway->relay_rtcp(publisher->session->handle, 1, buf, 12);
			/* Done */
			json_object_set_new(rtp_stream, "video_stream_id", json_integer(video_handle));
			json_object_set_new(rtp_stream, "video", json_integer(video_port));
		}
		/* These two unrefs are related to the message handling */
		g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
		g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
		json_object_set_new(rtp_stream, "host", json_string(host));
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "rtp_stream", rtp_stream);
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "videoroom", json_string("rtp_forward"));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "stop_rtp_forward")) {
		JANUS_VALIDATE_JSON_OBJECT(root, stop_rtp_forward_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		json_t *pub_id = json_object_get(root, "publisher_id");
		json_t *id = json_object_get(root, "stream_id");

		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		guint32 stream_id = json_integer_value(id);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, TRUE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto plugin_response;
		janus_mutex_lock(&videoroom->mutex);
		janus_refcount_increase(&videoroom->ref);
		janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &publisher_id);
		if(publisher == NULL) {
			janus_mutex_unlock(&videoroom->mutex);
			g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto plugin_response;
		}
		janus_refcount_increase(&publisher->ref);	/* Just to handle the message now */
		janus_mutex_lock(&publisher->rtp_forwarders_mutex);
		if(!g_hash_table_remove(publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id))) {
			janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
			g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
			janus_mutex_unlock(&videoroom->mutex);
			g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
			JANUS_LOG(LOG_ERR, "No such stream (%"SCNu32")\n", stream_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such stream (%"SCNu32")", stream_id);
			goto plugin_response;
		}
		janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
		g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
		janus_mutex_unlock(&videoroom->mutex);
		g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("stop_rtp_forward"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "stream_id", json_integer(stream_id));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "exists")) {
		/* Check whether a given room exists or not, returns true/false */	
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, &room_id);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "exists", room_exists ? json_true() : json_false());
		goto plugin_response;
	} else if(!strcasecmp(request_text, "listparticipants")) {
		/* List all participants in a room, specifying whether they're publishers or just attendees */	
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = NULL;
		error_code = janus_videoroom_access_room(root, FALSE, FALSE, &videoroom, error_cause, sizeof(error_cause));
		janus_mutex_unlock(&rooms_mutex);
		if(error_code != 0)
			goto plugin_response;
		janus_refcount_increase(&videoroom->ref);
		/* Return a list of all participants (whether they're publishing or not) */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_integer(p->user_id));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_object_set_new(pl, "publisher", (p->sdp && p->session->started) ? json_true() : json_false());
			json_array_append_new(list, pl);
		}
		janus_mutex_unlock(&videoroom->mutex);
		g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("participants"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "participants", list);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "listforwarders")) {
		/* List all forwarders in a room */	
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, &room_id);
		if(videoroom == NULL) {
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			janus_mutex_unlock(&rooms_mutex);
			goto plugin_response;
		}
		if(g_atomic_int_get(&videoroom->destroyed)) {
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			janus_mutex_unlock(&rooms_mutex);
			goto plugin_response;
		}
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(videoroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT, JANUS_VIDEOROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&rooms_mutex);
			goto plugin_response;
		}
		/* Return a list of all forwarders */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			if(g_hash_table_size(p->rtp_forwarders) == 0)
				continue;
			json_t *pl = json_object();
			json_object_set_new(pl, "publisher_id", json_integer(p->user_id));
			if(p->display)
				json_object_set_new(pl, "display", json_string(p->display));
			json_t *flist = json_array();
			GHashTableIter iter_f;
			gpointer key_f, value_f;			
			g_hash_table_iter_init(&iter_f, p->rtp_forwarders);
			janus_mutex_lock(&p->rtp_forwarders_mutex);
			while(g_hash_table_iter_next(&iter_f, &key_f, &value_f)) {				
				json_t *fl = json_object();
				guint32 rpk = GPOINTER_TO_UINT(key_f);
				rtp_forwarder *rpv = value_f;
				json_object_set_new(fl, "ip", json_string(inet_ntoa(rpv->serv_addr.sin_addr)));
				if(rpv->is_video > 0) {
					json_object_set_new(fl, "video_stream_id", json_integer(rpk));
					json_object_set_new(fl, "port", json_integer(ntohs(rpv->serv_addr.sin_port)));
				} else {
					json_object_set_new(fl, "audio_stream_id", json_integer(rpk));
					json_object_set_new(fl, "port", json_integer(ntohs(rpv->serv_addr.sin_port)));
				}
				json_array_append_new(flist, fl);
			}		
			janus_mutex_unlock(&p->rtp_forwarders_mutex);
			json_object_set_new(pl, "rtp_forwarder", flist);
			json_array_append_new(list, pl);
		}
		janus_mutex_unlock(&videoroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "rtp_forwarders", list);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "joinandconfigure")
			|| !strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish") || !strcasecmp(request_text, "unpublish")
			|| !strcasecmp(request_text, "start") || !strcasecmp(request_text, "pause") || !strcasecmp(request_text, "switch")
			|| !strcasecmp(request_text, "stop") || !strcasecmp(request_text, "leave")) {
		/* These messages are handled asynchronously */

		janus_videoroom_message *msg = g_malloc0(sizeof(janus_videoroom_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;
		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code == 0 && !response) {
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
			}
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_t *event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "error_code", json_integer(error_code));
				json_object_set_new(event, "error", json_string(error_cause));
				response = event;
			}
			if(root != NULL)
				json_decref(root);
			if(jsep != NULL)
				json_decref(jsep);
			g_free(transaction);

			g_clear_pointer(&session, janus_videoroom_session_dereference);
			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

void janus_videoroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_VIDEOROOM_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	g_atomic_int_set(&session->hangingup, 0);

	/* Media relaying can start now */
	session->started = TRUE;
	if(session->participant) {
		/* If this is a publisher, notify all subscribers about the fact they can
		 * now subscribe; if this is a subscriber, instead, ask the publisher a FIR */
		if(session->participant_type == janus_videoroom_p_type_publisher) {
			janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
			/* Notify all other participants that there's a new boy in town */
			json_t *list = json_array();
			json_t *pl = json_object();
			json_object_set_new(pl, "id", json_integer(participant->user_id));
			if(participant->display)
				json_object_set_new(pl, "display", json_string(participant->display));
			json_array_append_new(list, pl);
			json_t *pub = json_object();
			json_object_set_new(pub, "videoroom", json_string("event"));
			json_object_set_new(pub, "room", json_integer(participant->room->room_id));
			json_object_set_new(pub, "publishers", list);
			GHashTableIter iter;
			gpointer value;
			janus_videoroom *videoroom = participant->room;
			janus_mutex_lock(&videoroom->mutex);
			g_hash_table_iter_init(&iter, videoroom->participants);
			while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_videoroom_publisher *p = value;
				if(p == participant) {
					continue;	/* Skip the new publisher itself */
				}
				JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, pub, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(pub);
			janus_mutex_unlock(&videoroom->mutex);
			g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
			if(s && s->feed) {
				janus_videoroom_publisher *p = s->feed;
				if(p && p->session) {
					/* Send a FIR */
					char buf[20];
					memset(buf, 0, 20);
					janus_rtcp_fir((char *)&buf, 20, &p->fir_seq);
					JANUS_LOG(LOG_VERB, "New subscriber available, sending FIR to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, buf, 20);
					/* Send a PLI too, just in case... */
					memset(buf, 0, 12);
					janus_rtcp_pli((char *)&buf, 12);
					JANUS_LOG(LOG_VERB, "New subscriber available, sending PLI to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, buf, 12);
				}
			}
		}
	}
}

void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher_nodebug(session);
	if(participant == NULL || g_atomic_int_get(&participant->destroyed)) {
		g_clear_pointer(&participant, janus_videoroom_publisher_dereference_nodebug);
		return;
	}
	if((!video && participant->audio_active) || (video && participant->video_active)) {
		/* Update payload type and SSRC */
		rtp_header *rtp = (rtp_header *)buf;
		rtp->type = video ? participant->video_pt : participant->audio_pt;
		rtp->ssrc = htonl(video ? participant->video_ssrc : participant->audio_ssrc);
		/* Forward RTP to the appropriate port for the rtp_forwarders associated with this publisher, if there are any */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, participant->rtp_forwarders);
		janus_mutex_lock(&participant->rtp_forwarders_mutex);
		while(participant->udp_sock > 0 && g_hash_table_iter_next(&iter, NULL, &value)) {
			rtp_forwarder* rtp_forward = (rtp_forwarder*)value;
			if(video && rtp_forward->is_video) {
				sendto(participant->udp_sock, buf, len, 0, (struct sockaddr*)&rtp_forward->serv_addr, sizeof(rtp_forward->serv_addr));
			}
			else if(!video && !rtp_forward->is_video) {
				sendto(participant->udp_sock, buf, len, 0, (struct sockaddr*)&rtp_forward->serv_addr, sizeof(rtp_forward->serv_addr));
			}
		}
		janus_mutex_unlock(&participant->rtp_forwarders_mutex);
		/* Save the frame if we're recording */
		janus_recorder_save_frame(video ? participant->vrc : participant->arc, buf, len);
		/* Done, relay it */
		janus_videoroom_rtp_relay_packet packet;
		packet.data = rtp;
		packet.length = len;
		packet.is_video = video;
		/* Backup the actual timestamp and sequence number set by the publisher, in case switching is involved */
		packet.timestamp = ntohl(packet.data->timestamp);
		packet.seq_number = ntohs(packet.data->seq_number);
		/* Go */
		janus_mutex_lock(&participant->subscribers_mutex);
		g_slist_foreach(participant->subscribers, janus_videoroom_relay_rtp_packet, &packet);
		
		/* Check if we need to send any REMB, FIR or PLI back to this publisher */
		if(video && participant->video_active) {
			/* Did we send a REMB already, or is it time to send one? */
			gboolean send_remb = FALSE;
			if(participant->remb_latest == 0 && participant->remb_startup > 0) {
				/* Still in the starting phase, send the ramp-up REMB feedback */
				send_remb = TRUE;
			} else if(participant->remb_latest > 0 && janus_get_monotonic_time()-participant->remb_latest >= 5*G_USEC_PER_SEC) {
				/* 5 seconds have passed since the last REMB, send a new one */
				send_remb = TRUE;
			}		
			if(send_remb) {
				/* We send a few incremental REMB messages at startup */
				uint64_t bitrate = (participant->bitrate ? participant->bitrate : 256*1024);
				if(participant->remb_startup > 0) {
					bitrate = bitrate/participant->remb_startup;
					participant->remb_startup--;
				}
				JANUS_LOG(LOG_VERB, "Sending REMB (%s, %"SCNu64")\n", participant->display, bitrate);
				char rtcpbuf[24];
				janus_rtcp_remb((char *)(&rtcpbuf), 24, bitrate);
				gateway->relay_rtcp(handle, video, rtcpbuf, 24);
				if(participant->remb_startup == 0)
					participant->remb_latest = janus_get_monotonic_time();
			}
			/* Generate FIR/PLI too, if needed */
			if(video && participant->video_active && (participant->room->fir_freq > 0)) {
				/* FIXME Very ugly hack to generate RTCP every tot seconds/frames */
				gint64 now = janus_get_monotonic_time();
				if((now-participant->fir_latest) >= (participant->room->fir_freq*G_USEC_PER_SEC)) {
					/* FIXME We send a FIR every tot seconds */
					participant->fir_latest = now;
					char rtcpbuf[24];
					memset(rtcpbuf, 0, 24);
					janus_rtcp_fir((char *)&rtcpbuf, 20, &participant->fir_seq);
					JANUS_LOG(LOG_VERB, "Sending FIR to %"SCNu64" (%s)\n", participant->user_id, participant->display ? participant->display : "??");
					gateway->relay_rtcp(handle, video, rtcpbuf, 20);
					/* Send a PLI too, just in case... */
					memset(rtcpbuf, 0, 12);
					janus_rtcp_pli((char *)&rtcpbuf, 12);
					JANUS_LOG(LOG_VERB, "Sending PLI to %"SCNu64" (%s)\n", participant->user_id, participant->display ? participant->display : "??");
					gateway->relay_rtcp(handle, video, rtcpbuf, 12);
				}
			}
		}
		janus_mutex_unlock(&participant->subscribers_mutex);
	}
	g_clear_pointer(&participant, janus_videoroom_publisher_dereference_nodebug);
}

void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* A subscriber sent some RTCP, check what it is and if we need to forward it to the publisher */
		janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
		if(s == NULL || g_atomic_int_get(&s->destroyed))
			return;
		if(!s->video)
			return;	/* The only feedback we handle is video related anyway... */
		if(janus_rtcp_has_fir(buf, len)) {
			/* We got a FIR, forward it to the publisher */
			if(s && s->feed) {
				janus_videoroom_publisher *p = s->feed;
				if(p && p->session) {
					char rtcpbuf[20];
					memset(rtcpbuf, 0, 20);
					janus_rtcp_fir((char *)&rtcpbuf, 20, &p->fir_seq);
					JANUS_LOG(LOG_VERB, "Got a FIR from a subscriber, forwarding it to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, rtcpbuf, 20);
				}
			}
		}
		if(janus_rtcp_has_pli(buf, len)) {
			/* We got a PLI, forward it to the publisher */
			if(s && s->feed) {
				janus_videoroom_publisher *p = s->feed;
				if(p && p->session) {
					char rtcpbuf[12];
					memset(rtcpbuf, 0, 12);
					janus_rtcp_pli((char *)&rtcpbuf, 12);
					JANUS_LOG(LOG_VERB, "Got a PLI from a subscriber, forwarding it to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, rtcpbuf, 12);
				}
			}
		}
		uint64_t bitrate = janus_rtcp_get_remb(buf, len);
		if(bitrate > 0) {
			/* FIXME We got a REMB from this subscriber, should we do something about it? */
		}
	}
}

void janus_videoroom_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	if(buf == NULL || len <= 0)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher_nodebug(session);
	if(participant == NULL || g_atomic_int_get(&participant->destroyed)) {
		g_clear_pointer(&participant, janus_videoroom_publisher_dereference_nodebug);
		return;
	}
	/* Get a string out of the data */
	char *text = g_malloc0(len+1);
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
	janus_mutex_lock(&participant->subscribers_mutex);
	g_slist_foreach(participant->subscribers, janus_videoroom_relay_data_packet, text);
	janus_mutex_unlock(&participant->subscribers_mutex);
	g_free(text);
	g_clear_pointer(&participant, janus_videoroom_publisher_dereference_nodebug);
}

void janus_videoroom_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* The core is informing us that our peer got too many NACKs, are we pushing media too hard? */
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || !session->participant)
		return;
	/* Check if it's an uplink (publisher) or downlink (viewer) issue */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		if(!uplink) {
			janus_videoroom_publisher *publisher = janus_videoroom_session_get_publisher(session);
			if(publisher == NULL || g_atomic_int_get(&publisher->destroyed)) {
				g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
				return;
			}
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("slow_link"));
			/* Also add info on what the current bitrate cap is */
			uint64_t bitrate = (publisher->bitrate ? publisher->bitrate : 256*1024);
			json_object_set_new(event, "current-bitrate", json_integer(bitrate));
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
			json_decref(event);
			g_clear_pointer(&publisher, janus_videoroom_publisher_dereference);
		} else {
			JANUS_LOG(LOG_WARN, "Got a slow uplink on a VideoRoom publisher? Weird, because it doesn't receive media...\n");
		}
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		if(uplink) {
			janus_videoroom_subscriber *viewer = (janus_videoroom_subscriber *)session->participant;
			if(viewer == NULL || g_atomic_int_get(&viewer->destroyed))
				return;
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("slow_link"));
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event, NULL);
			json_decref(event);
		} else {
			JANUS_LOG(LOG_WARN, "Got a slow downlink on a VideoRoom viewer? Weird, because it doesn't send media...\n");
		}
	}
}

static void janus_videoroom_recorder_create(janus_videoroom_publisher *participant, gboolean audio, gboolean video) {
	char filename[255];
	gint64 now = janus_get_real_time();
	if(audio) {
		memset(filename, 0, 255);
		if(participant->recording_base) {
			/* Use the filename and path we have been provided */
			g_snprintf(filename, 255, "%s-audio", participant->recording_base);
			participant->arc = janus_recorder_create(participant->room->rec_dir,
				janus_videoroom_audiocodec_name(participant->room->acodec), filename);
			if(participant->arc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
			}
		} else {
			/* Build a filename */
			g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-audio",
				participant->room->room_id, participant->user_id, now);
			participant->arc = janus_recorder_create(participant->room->rec_dir,
				janus_videoroom_audiocodec_name(participant->room->acodec), filename);
			if(participant->arc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
			}
		}
	}
	if(video) {
		memset(filename, 0, 255);
		if(participant->recording_base) {
			/* Use the filename and path we have been provided */
			g_snprintf(filename, 255, "%s-video", participant->recording_base);
			participant->vrc = janus_recorder_create(participant->room->rec_dir,
				janus_videoroom_videocodec_name(participant->room->vcodec), filename);
			if(participant->vrc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
			}
		} else {
			/* Build a filename */
			g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-video",
				participant->room->room_id, participant->user_id, now);
			participant->vrc = janus_recorder_create(participant->room->rec_dir,
				janus_videoroom_videocodec_name(participant->room->vcodec), filename);
			if(participant->vrc == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
			}
		}
	}
}

static void janus_videoroom_recorder_close(janus_videoroom_publisher *participant) {
	if(participant->arc) {
		janus_recorder_close(participant->arc);
		JANUS_LOG(LOG_INFO, "Closed audio recording %s\n", participant->arc->filename ? participant->arc->filename : "??");
		janus_recorder_free(participant->arc);
	}
	participant->arc = NULL;
	if(participant->vrc) {
		janus_recorder_close(participant->vrc);
		JANUS_LOG(LOG_INFO, "Closed video recording %s\n", participant->vrc->filename ? participant->vrc->filename : "??");
		janus_recorder_free(participant->vrc);
	}
	participant->vrc = NULL;
}

void janus_videoroom_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore; %p %p\n", JANUS_VIDEOROOM_PACKAGE, handle, handle->gateway_handle, handle->plugin_handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	session->started = FALSE;
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	/* Send an event to the browser and tell the PeerConnection is over */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* This publisher just 'unpublished' */
		janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher(session);
		/* Get rid of the recorders, if available */
		janus_mutex_lock(&participant->rec_mutex);
		g_free(participant->recording_base);
		janus_videoroom_recorder_close(participant);
		janus_mutex_unlock(&participant->rec_mutex);
		/* Use subscribers_mutex to protect fields used in janus_videoroom_incoming_rtp */
		janus_mutex_lock(&participant->subscribers_mutex);
		g_free(participant->sdp);
		participant->sdp = NULL;
		participant->firefox = FALSE;
		participant->audio_active = FALSE;
		participant->video_active = FALSE;
		participant->remb_startup = 4;
		participant->remb_latest = 0;
		participant->fir_latest = 0;
		participant->fir_seq = 0;
		while(participant->subscribers) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)participant->subscribers->data;
			if(s) {
				participant->subscribers = g_slist_remove(participant->subscribers, s);
				janus_refcount_decrease(&participant->session->ref);
				g_clear_pointer(&s->feed, janus_videoroom_publisher_dereference);
				g_clear_pointer(&s, janus_videoroom_subscriber_dereference);
			}
		}
		janus_mutex_unlock(&participant->subscribers_mutex);
		janus_videoroom_leave_or_unpublish(participant, FALSE);
		g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Get rid of subscriber */
		janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
		if(subscriber) {
			subscriber->paused = TRUE;
			janus_videoroom_publisher *publisher = subscriber->feed;
			if(publisher != NULL) {
				janus_mutex_lock(&publisher->subscribers_mutex);
				publisher->subscribers = g_slist_remove(publisher->subscribers, subscriber);
				janus_mutex_unlock(&publisher->subscribers_mutex);
				janus_refcount_decrease(&publisher->session->ref);
				g_clear_pointer(&subscriber->feed, janus_videoroom_publisher_dereference);
				g_clear_pointer(&subscriber, janus_videoroom_subscriber_dereference);
			}
		}
		/* TODO Should we close the handle as well? */
	}
}

static void janus_videoroom_sdp_a_format(char *mline, int mline_size, janus_videoroom_audiocodec acodec, int pt, const char *audio_mode) {
	switch(acodec) {
		case JANUS_VIDEOROOM_OPUS:
			g_snprintf(mline, mline_size, sdp_a_template_opus,
				pt,						/* Opus payload type */
				audio_mode,
				pt); 						/* Opus payload type */
			break;
		case JANUS_VIDEOROOM_ISAC_32K:
			g_snprintf(mline, mline_size, sdp_a_template_isac32,
				pt,						/* ISAC 32K payload type */
				audio_mode,
				pt); 					/* ISAC 32K payload type */
			break;
		case JANUS_VIDEOROOM_ISAC_16K:
			g_snprintf(mline, mline_size, sdp_a_template_isac16,
				pt,						/* ISAC 16K payload type */
				audio_mode,
				pt);						/* ISAC 16K payload type */
			break;
		case JANUS_VIDEOROOM_PCMU:
			g_snprintf(mline, mline_size, sdp_a_template_pcmu,
				pt,						/* PCMU payload type */
				audio_mode,
				pt);						/* PCMU payload type */
			break;
		case JANUS_VIDEOROOM_PCMA:
			g_snprintf(mline, mline_size, sdp_a_template_pcma,
				pt,						/* PCMA payload type */
				audio_mode,
				pt);						/* PCMA payload type */
			break;
		default:
			/* Shouldn't happen */
			mline[0] = '\0';
			break;
	}
}

static void janus_videoroom_sdp_v_format(char *mline, int mline_size, janus_videoroom_videocodec vcodec, int pt, int b, const char *video_mode) {
	switch(vcodec) {
		case JANUS_VIDEOROOM_VP8:
			g_snprintf(mline, mline_size, sdp_v_template_vp8,
				pt,							/* payload type */
				b,								/* Bandwidth */
				video_mode,						/* The publisher gets a recvonly or inactive back */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt); 						/* payload type */
			break;
		case JANUS_VIDEOROOM_VP9:
			g_snprintf(mline, mline_size, sdp_v_template_vp9,
				pt,							/* payload type */
				b,								/* Bandwidth */
				video_mode,						/* The publisher gets a recvonly or inactive back */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt); 						/* payload type */
			break;
		case JANUS_VIDEOROOM_H264:
			g_snprintf(mline, mline_size, sdp_v_template_h264,
				pt,							/* payload type */
				b,								/* Bandwidth */
				video_mode,						/* The publisher gets a recvonly or inactive back */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt, 						/* payload type */
				pt); 						/* payload type */
			break;
		default:
			/* Shouldn't happen */
			mline[0] = '\0';
			break;
	}
}

/* Thread to handle incoming messages */
static void *janus_videoroom_handler(void *data) {
#ifdef JANUS_THREAD_DEBUG
	JANUS_LOG(LOG_INFO, "Joining VideoRoom handler thread; %d\n", g_atomic_int_add(&handler_thread_count, 1) + 1);
#else
	JANUS_LOG(LOG_VERB, "Joining VideoRoom handler thread\n");
#endif
	janus_videoroom_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == NULL)
			continue;
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_videoroom_message_free(msg);
			continue;
		}
		janus_videoroom_session *session = NULL;
		janus_videoroom *videoroom = NULL;
		janus_videoroom_publisher *participant = NULL;
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_lookup(sessions, msg->handle) != NULL ) {
			session = (janus_videoroom_session *)msg->handle->plugin_handle;
		}
		janus_mutex_unlock(&sessions_mutex);
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_videoroom_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_videoroom_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = NULL;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		root = msg->message;
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		/* 'create' and 'destroy' are handled synchronously: what kind of participant is this session referring to? */
		if(session->participant_type == janus_videoroom_p_type_none) {
			JANUS_LOG(LOG_VERB, "Configuring new participant\n");
			/* Not configured yet, we need to do this now */
			if(strcasecmp(request_text, "join") && strcasecmp(request_text, "joinandconfigure")) {
				JANUS_LOG(LOG_ERR, "Invalid request on unconfigured participant\n");
				error_code = JANUS_VIDEOROOM_ERROR_JOIN_FIRST;
				g_snprintf(error_cause, 512, "Invalid request on unconfigured participant");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			janus_mutex_lock(&rooms_mutex);
			error_code = janus_videoroom_access_room(root, FALSE, TRUE, &videoroom, error_cause, sizeof(error_cause));
			janus_mutex_unlock(&rooms_mutex);
			if(error_code != 0)
				goto error;
			janus_refcount_increase(&videoroom->ref);
			json_t *ptype = json_object_get(root, "ptype");
			const char *ptype_text = json_string_value(ptype);
			if(!strcasecmp(ptype_text, "publisher")) {
				JANUS_LOG(LOG_VERB, "Configuring new publisher\n");
				JANUS_VALIDATE_JSON_OBJECT(root, publisher_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *display = json_object_get(root, "display");
				const char *display_text = display ? json_string_value(display) : NULL;
				guint64 user_id = 0;
				json_t *id = json_object_get(root, "id");
				if(id) {
					user_id = json_integer_value(id);
					janus_mutex_lock(&videoroom->mutex);
					if(g_hash_table_lookup(videoroom->participants, &user_id) != NULL) {
						janus_mutex_unlock(&videoroom->mutex);
						/* User ID already taken */
						JANUS_LOG(LOG_ERR, "User ID %"SCNu64" already exists\n", user_id);
						error_code = JANUS_VIDEOROOM_ERROR_ID_EXISTS;
						g_snprintf(error_cause, 512, "User ID %"SCNu64" already exists", user_id);
						goto error;
					}
					janus_mutex_unlock(&videoroom->mutex);
				}
				if(user_id == 0) {
					/* Generate a random ID */
					janus_mutex_lock(&videoroom->mutex);
					while(user_id == 0) {
						user_id = janus_random_uint64();
						if(g_hash_table_lookup(videoroom->participants, &user_id) != NULL) {
							/* User ID already taken, try another one */
							user_id = 0;
						}
					}
					janus_mutex_unlock(&videoroom->mutex);
				}
				JANUS_LOG(LOG_VERB, "  -- Publisher ID: %"SCNu64"\n", user_id);
				json_t *audio = NULL, *video = NULL, *bitrate = NULL, *record = NULL, *recfile = NULL;
				if(!strcasecmp(request_text, "joinandconfigure")) {
					/* Also configure (or publish a new feed) audio/video/bitrate for this new publisher */
					/* join_parameters were validated earlier. */
					audio = json_object_get(root, "audio");
					video = json_object_get(root, "video");
					bitrate = json_object_get(root, "bitrate");
					record = json_object_get(root, "record");
					recfile = json_object_get(root, "filename");
				}
				janus_videoroom_publisher *publisher = g_malloc0(sizeof(janus_videoroom_publisher));
				publisher->session = session;
				publisher->room = videoroom;
				videoroom = NULL;
				publisher->user_id = user_id;
				publisher->display = display_text ? g_strdup(display_text) : NULL;
				publisher->sdp = NULL;		/* We'll deal with this later */
				publisher->audio = FALSE;	/* We'll deal with this later */
				publisher->video = FALSE;	/* We'll deal with this later */
				publisher->data = FALSE;	/* We'll deal with this later */
				publisher->audio_active = FALSE;
				publisher->video_active = FALSE;
				publisher->recording_active = FALSE;
				publisher->recording_base = NULL;
				publisher->arc = NULL;
				publisher->vrc = NULL;
				janus_mutex_init(&publisher->rec_mutex);
				publisher->firefox = FALSE;
				publisher->bitrate = publisher->room->bitrate;
				publisher->subscribers = NULL;
				janus_mutex_init(&publisher->subscribers_mutex);
				publisher->audio_pt = OPUS_PT;
				switch(publisher->room->acodec) {
					case JANUS_VIDEOROOM_OPUS:
						publisher->audio_pt = OPUS_PT;
						break;
					case JANUS_VIDEOROOM_ISAC_32K:
						publisher->audio_pt = ISAC32_PT;
						break;
					case JANUS_VIDEOROOM_ISAC_16K:
						publisher->audio_pt = ISAC16_PT;
						break;
					case JANUS_VIDEOROOM_PCMU:
						publisher->audio_pt = PCMU_PT;
						break;
					case JANUS_VIDEOROOM_PCMA:
						publisher->audio_pt = PCMA_PT;
						break;
					default:
						/* Shouldn't happen */
						publisher->audio_pt = OPUS_PT;
						break;
				}
				switch(publisher->room->vcodec) {
					case JANUS_VIDEOROOM_VP8:
						publisher->video_pt = VP8_PT;
						break;
					case JANUS_VIDEOROOM_VP9:
						publisher->video_pt = VP9_PT;
						break;
					case JANUS_VIDEOROOM_H264:
						publisher->video_pt = H264_PT;
						break;
					default:
						/* Shouldn't happen */
						publisher->video_pt = VP8_PT;
						break;
				}
				publisher->audio_ssrc = janus_random_uint32();
				publisher->video_ssrc = janus_random_uint32();
				publisher->remb_startup = 4;
				publisher->remb_latest = 0;
				publisher->fir_latest = 0;
				publisher->fir_seq = 0;
				janus_mutex_init(&publisher->rtp_forwarders_mutex);
				publisher->rtp_forwarders = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_rtp_forwarder_free_helper);
				publisher->udp_sock = -1;
				g_atomic_int_set(&publisher->destroyed, 0);
				janus_refcount_init(&publisher->ref, janus_videoroom_publisher_free);
				/* In case we also wanted to configure */
				if(audio) {
					publisher->audio_active = json_is_true(audio);
					JANUS_LOG(LOG_VERB, "Setting audio property: %s (room %"SCNu64", user %"SCNu64")\n", publisher->audio_active ? "true" : "false", publisher->room->room_id, publisher->user_id);
				}
				if(video) {
					publisher->video_active = json_is_true(video);
					JANUS_LOG(LOG_VERB, "Setting video property: %s (room %"SCNu64", user %"SCNu64")\n", publisher->video_active ? "true" : "false", publisher->room->room_id, publisher->user_id);
				}
				if(bitrate) {
					publisher->bitrate = json_integer_value(bitrate);
					JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu64" (room %"SCNu64", user %"SCNu64")\n", publisher->bitrate, publisher->room->room_id, publisher->user_id);
				}
				if(record) {
					publisher->recording_active = json_is_true(record);
					JANUS_LOG(LOG_VERB, "Setting record property: %s (room %"SCNu64", user %"SCNu64")\n", publisher->recording_active ? "true" : "false", publisher->room->room_id, publisher->user_id);
				}
				if(recfile) {
					publisher->recording_base = g_strdup(json_string_value(recfile));
					JANUS_LOG(LOG_VERB, "Setting recording basename: %s (room %"SCNu64", user %"SCNu64")\n", publisher->recording_base, publisher->room->room_id, publisher->user_id);
				}
				/* Done */
				janus_mutex_lock(&session->mutex);
				session->participant_type = janus_videoroom_p_type_publisher;
				session->participant = publisher;
				janus_mutex_unlock(&session->mutex);
				/* Return a list of all available publishers (those with an SDP available, that is) */
				json_t *list = json_array();
				GHashTableIter iter;
				gpointer value;
				janus_mutex_lock(&publisher->room->mutex);
				janus_refcount_increase(&publisher->ref);
				g_hash_table_insert(publisher->room->participants, janus_uint64_dup(publisher->user_id), publisher);
				g_hash_table_iter_init(&iter, publisher->room->participants);
				while (!g_atomic_int_get(&publisher->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_videoroom_publisher *p = value;
					if(p == publisher || !p->sdp || !p->session->started) {
						continue;
					}
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(p->user_id));
					if(p->display)
						json_object_set_new(pl, "display", json_string(p->display));
					json_array_append_new(list, pl);
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("joined"));
				json_object_set_new(event, "room", json_integer(publisher->room->room_id));
				json_object_set_new(event, "description", json_string(publisher->room->room_name));
				json_object_set_new(event, "id", json_integer(user_id));
				json_object_set_new(event, "publishers", list);
				janus_mutex_unlock(&publisher->room->mutex);
			} else if(!strcasecmp(ptype_text, "subscriber") || !strcasecmp(ptype_text, "listener")) {
				JANUS_LOG(LOG_VERB, "Configuring new subscriber\n");
				/* This is a new subscriber */
				JANUS_VALIDATE_JSON_OBJECT(root, subscriber_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *feed = json_object_get(root, "feed");
				guint64 feed_id = json_integer_value(feed);
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *data = json_object_get(root, "data");
				janus_mutex_lock(&videoroom->mutex);
				janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, &feed_id);
				if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || publisher->sdp == NULL) {
					JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
					g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
					janus_mutex_unlock(&videoroom->mutex);
					goto error;
				} else {
					/* Increase the refcount before unlocking so that nobody can remove and free the publisher in the meantime. */
					janus_refcount_increase(&publisher->ref);
					janus_refcount_increase(&publisher->session->ref);
					janus_mutex_unlock(&videoroom->mutex);
					janus_videoroom_subscriber *subscriber = g_malloc0(sizeof(janus_videoroom_subscriber));
					subscriber->session = session;
					subscriber->room = videoroom;
					videoroom = NULL;
					subscriber->feed = publisher;
					/* Initialize the subscriber context */
					subscriber->context.a_last_ssrc = 0;
					subscriber->context.a_last_ssrc = 0;
					subscriber->context.a_last_ts = 0;
					subscriber->context.a_base_ts = 0;
					subscriber->context.a_base_ts_prev = 0;
					subscriber->context.v_last_ssrc = 0;
					subscriber->context.v_last_ts = 0;
					subscriber->context.v_base_ts = 0;
					subscriber->context.v_base_ts_prev = 0;
					subscriber->context.a_last_seq = 0;
					subscriber->context.a_base_seq = 0;
					subscriber->context.a_base_seq_prev = 0;
					subscriber->context.v_last_seq = 0;
					subscriber->context.v_base_seq = 0;
					subscriber->context.v_base_seq_prev = 0;
					subscriber->context.a_seq_reset = FALSE;
					subscriber->context.v_seq_reset = FALSE;
					subscriber->audio = audio ? json_is_true(audio) : TRUE;	/* True by default */
					if(!publisher->audio)
						subscriber->audio = FALSE;	/* ... unless the publisher isn't sending any audio */
					subscriber->video = video ? json_is_true(video) : TRUE;	/* True by default */
					if(!publisher->video)
						subscriber->video = FALSE;	/* ... unless the publisher isn't sending any video */
					subscriber->data = data ? json_is_true(data) : TRUE;	/* True by default */
					if(!publisher->data)
						subscriber->data = FALSE;	/* ... unless the publisher isn't sending any data */
					subscriber->paused = TRUE;	/* We need an explicit start from the subscriber */
					g_atomic_int_set(&subscriber->destroyed, 0);
					janus_refcount_init(&subscriber->ref, janus_videoroom_subscriber_free);
					janus_refcount_increase(&subscriber->ref);	/* The publisher references the new subscriber too */
					session->participant = subscriber;
					janus_mutex_lock(&publisher->subscribers_mutex);
					publisher->subscribers = g_slist_append(publisher->subscribers, subscriber);
					janus_mutex_unlock(&publisher->subscribers_mutex);
					event = json_object();
					json_object_set_new(event, "videoroom", json_string("attached"));
					json_object_set_new(event, "room", json_integer(subscriber->room->room_id));
					json_object_set_new(event, "id", json_integer(feed_id));
					if(publisher->display)
						json_object_set_new(event, "display", json_string(publisher->display));
					session->participant_type = janus_videoroom_p_type_subscriber;
					JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
					/* Negotiate by sending the selected publisher SDP back */
					if(publisher->sdp != NULL) {
						json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", publisher->sdp);
						/* How long will the gateway take to push the event? */
						g_atomic_int_set(&session->hangingup, 0);
						gint64 start = janus_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
						JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
						json_decref(event);
						json_decref(jsep);
						janus_videoroom_message_free(msg);
						continue;
					}
				}
			} else {
				JANUS_LOG(LOG_ERR, "Invalid element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (ptype)");
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Handle this publisher */
			participant = janus_videoroom_session_get_publisher(session);
			if(participant == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid participant instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid participant instance");
				goto error;
			}
			if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "joinandconfigure")) {
				JANUS_LOG(LOG_ERR, "Already in as a publisher on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in as a publisher on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish")) {
				if(!strcasecmp(request_text, "publish") && participant->sdp) {
					JANUS_LOG(LOG_ERR, "Can't publish, already published\n");
					error_code = JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED;
					g_snprintf(error_cause, 512, "Can't publish, already published");
					goto error;
				}
				/* Configure (or publish a new feed) audio/video/bitrate for this publisher */
				JANUS_VALIDATE_JSON_OBJECT(root, publish_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *bitrate = json_object_get(root, "bitrate");
				json_t *record = json_object_get(root, "record");
				json_t *recfile = json_object_get(root, "filename");
				if(audio) {
					gboolean audio_active = json_is_true(audio);
					if(session->started && audio_active && !participant->audio_active) {
						/* Audio was just resumed, try resetting the RTP headers for viewers */
						janus_mutex_lock(&participant->subscribers_mutex);
						GSList *ps = participant->subscribers;
						while(ps) {
							janus_videoroom_subscriber *l = (janus_videoroom_subscriber *)ps->data;
							if(l)
								l->context.a_seq_reset = TRUE;
							ps = ps->next;
						}
						janus_mutex_unlock(&participant->subscribers_mutex);
					}
					participant->audio_active = audio_active;
					JANUS_LOG(LOG_VERB, "Setting audio property: %s (room %"SCNu64", user %"SCNu64")\n", participant->audio_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(video) {
					gboolean video_active = json_is_true(video);
					if(session->started && video_active && !participant->video_active) {
						/* Video was just resumed, try resetting the RTP headers for viewers */
						janus_mutex_lock(&participant->subscribers_mutex);
						GSList *ps = participant->subscribers;
						while(ps) {
							janus_videoroom_subscriber *l = (janus_videoroom_subscriber *)ps->data;
							if(l)
								l->context.v_seq_reset = TRUE;
							ps = ps->next;
						}
						janus_mutex_unlock(&participant->subscribers_mutex);
					}
					participant->video_active = video_active;
					JANUS_LOG(LOG_VERB, "Setting video property: %s (room %"SCNu64", user %"SCNu64")\n", participant->video_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(bitrate) {
					participant->bitrate = json_integer_value(bitrate);
					JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu64" (room %"SCNu64", user %"SCNu64")\n", participant->bitrate, participant->room->room_id, participant->user_id);
					/* Send a new REMB */
					if(session->started)
						participant->remb_latest = janus_get_monotonic_time();
					char rtcpbuf[24];
					janus_rtcp_remb((char *)(&rtcpbuf), 24, participant->bitrate ? participant->bitrate : 256*1024);
					gateway->relay_rtcp(msg->handle, 1, rtcpbuf, 24);
				}
				janus_mutex_lock(&participant->rec_mutex);
				gboolean prev_recording_active = participant->recording_active;
				if(record) {
					participant->recording_active = json_is_true(record);
					JANUS_LOG(LOG_VERB, "Setting record property: %s (room %"SCNu64", user %"SCNu64")\n", participant->recording_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(recfile) {
					participant->recording_base = g_strdup(json_string_value(recfile));
					JANUS_LOG(LOG_VERB, "Setting recording basename: %s (room %"SCNu64", user %"SCNu64")\n", participant->recording_base, participant->room->room_id, participant->user_id);
				}
				/* Do we need to do something with the recordings right now? */
				if(participant->recording_active != prev_recording_active) {
					/* Something changed */
					if(!participant->recording_active) {
						/* Not recording (anymore?) */
						janus_videoroom_recorder_close(participant);
					} else if(participant->recording_active && participant->sdp) {
						/* We've started recording, send a PLI/FIR and go on */
						janus_videoroom_recorder_create(participant, strstr(participant->sdp, "m=audio") != NULL, strstr(participant->sdp, "m=video") != NULL);
						if(strstr(participant->sdp, "m=video")) {
							/* Send a FIR */
							char buf[20];
							memset(buf, 0, 20);
							janus_rtcp_fir((char *)&buf, 20, &participant->fir_seq);
							JANUS_LOG(LOG_VERB, "Recording video, sending FIR to %"SCNu64" (%s)\n",
								participant->user_id, participant->display ? participant->display : "??");
							gateway->relay_rtcp(participant->session->handle, 1, buf, 20);
							/* Send a PLI too, just in case... */
							memset(buf, 0, 12);
							janus_rtcp_pli((char *)&buf, 12);
							JANUS_LOG(LOG_VERB, "Recording video, sending PLI to %"SCNu64" (%s)\n",
								participant->user_id, participant->display ? participant->display : "??");
							gateway->relay_rtcp(participant->session->handle, 1, buf, 12);
						}
					}
				}
				janus_mutex_unlock(&participant->rec_mutex);
				/* Done */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room->room_id));
				json_object_set_new(event, "configured", json_string("ok"));
			} else if(!strcasecmp(request_text, "unpublish")) {
				/* This participant wants to unpublish */
				if(!participant->sdp) {
					JANUS_LOG(LOG_ERR, "Can't unpublish, not published\n");
					error_code = JANUS_VIDEOROOM_ERROR_NOT_PUBLISHED;
					g_snprintf(error_cause, 512, "Can't unpublish, not published");
					goto error;
				}
				/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
				janus_videoroom_hangup_media(session->handle);
				gateway->close_pc(session->handle);
				/* Done */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room->room_id));
				json_object_set_new(event, "unpublished", json_string("ok"));
			} else if(!strcasecmp(request_text, "leave")) {
				/* Prepare an event to confirm the request */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room->room_id));
				json_object_set_new(event, "leaving", json_string("ok"));
				/* This publisher is leaving, tell everybody */
				janus_videoroom_leave_or_unpublish(participant, TRUE);
				/* Done */
				participant->audio_active = FALSE;
				participant->video_active = FALSE;
				session->started = FALSE;
				//~ session->destroy = TRUE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
				goto error;
			}
			g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			/* Handle this subscriber */
			janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
			if(subscriber == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid subscriber instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid subscriber instance");
				goto error;
			}
			if(!strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Already in as a subscriber on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				g_snprintf(error_cause, 512, "Already in as a subscriber on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "start")) {
				/* Start/restart receiving the publisher streams */
				janus_videoroom_publisher *publisher = subscriber->feed;
				subscriber->paused = FALSE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room->room_id));
				json_object_set_new(event, "started", json_string("ok"));
				if(publisher) {
					/* Send a FIR */
					char buf[20];
					memset(buf, 0, 20);
					janus_rtcp_fir((char *)&buf, 20, &publisher->fir_seq);
					JANUS_LOG(LOG_VERB, "Resuming publisher, sending FIR to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
					gateway->relay_rtcp(publisher->session->handle, 1, buf, 20);
					/* Send a PLI too, just in case... */
					memset(buf, 0, 12);
					janus_rtcp_pli((char *)&buf, 12);
					JANUS_LOG(LOG_VERB, "Resuming publisher, sending PLI to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
					gateway->relay_rtcp(publisher->session->handle, 1, buf, 12);
				}
			} else if(!strcasecmp(request_text, "configure")) {
				JANUS_VALIDATE_JSON_OBJECT(root, configure_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *data = json_object_get(root, "data");
				/* Update the audio/video/data flags, if set */
				janus_videoroom_publisher *publisher = subscriber->feed;
				if(publisher) {
					if(audio && publisher->audio)
						subscriber->audio = json_is_true(audio);
					if(video && publisher->video)
						subscriber->video = json_is_true(video);
					if(data && publisher->data)
						subscriber->data = json_is_true(data);
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room->room_id));
				json_object_set_new(event, "configured", json_string("ok"));
			} else if(!strcasecmp(request_text, "pause")) {
				/* Stop receiving the publisher streams for a while */
				subscriber->paused = TRUE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(subscriber->room->room_id));
				json_object_set_new(event, "paused", json_string("ok"));
			} else if(!strcasecmp(request_text, "switch")) {
				/* This subscriber wants to switch to a different publisher */
				JANUS_VALIDATE_JSON_OBJECT(root, subscriber_parameters,
					error_code, error_cause, TRUE,
					JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT, JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				json_t *feed = json_object_get(root, "feed");
				guint64 feed_id = json_integer_value(feed);
				json_t *audio = json_object_get(root, "audio");
				json_t *video = json_object_get(root, "video");
				json_t *data = json_object_get(root, "data");
				if(!subscriber->room) {
					JANUS_LOG(LOG_ERR, "Room Destroyed \n");
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					g_snprintf(error_cause, 512, "No such room ");
					goto error;
				}
				if(g_atomic_int_get(&subscriber->room->destroyed)) {
					JANUS_LOG(LOG_ERR, "Room Destroyed (%"SCNu64")\n", subscriber->room->room_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					g_snprintf(error_cause, 512, "No such room (%"SCNu64")", subscriber->room->room_id);
					goto error;
				}
				janus_mutex_lock(&subscriber->room->mutex);
				janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, &feed_id);
				if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || publisher->sdp == NULL) {
					JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
					g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
					janus_mutex_unlock(&subscriber->room->mutex);
					goto error;
				}
				janus_refcount_increase(&publisher->ref);
				janus_refcount_increase(&publisher->session->ref);
				janus_mutex_unlock(&subscriber->room->mutex);
				gboolean paused = subscriber->paused;
				subscriber->paused = TRUE;
				/* Unsubscribe from the previous publisher */
				janus_videoroom_publisher *prev_feed = subscriber->feed;
				if(prev_feed) {
					janus_mutex_lock(&prev_feed->subscribers_mutex);
					prev_feed->subscribers = g_slist_remove(prev_feed->subscribers, subscriber);
					janus_mutex_unlock(&prev_feed->subscribers_mutex);
					janus_refcount_decrease(&prev_feed->session->ref);
					g_clear_pointer(&subscriber->feed, janus_videoroom_publisher_dereference);
				}
				/* Subscribe to the new one */
				subscriber->audio = audio ? json_is_true(audio) : TRUE;	/* True by default */
				if(!publisher->audio)
					subscriber->audio = FALSE;	/* ... unless the publisher isn't sending any audio */
				subscriber->video = video ? json_is_true(video) : TRUE;	/* True by default */
				if(!publisher->video)
					subscriber->video = FALSE;	/* ... unless the publisher isn't sending any video */
				subscriber->data = data ? json_is_true(data) : TRUE;	/* True by default */
				if(!publisher->data)
					subscriber->data = FALSE;	/* ... unless the publisher isn't sending any data */
				janus_mutex_lock(&publisher->subscribers_mutex);
				publisher->subscribers = g_slist_append(publisher->subscribers, subscriber);
				janus_mutex_unlock(&publisher->subscribers_mutex);
				subscriber->feed = publisher;
				/* Send a FIR to the new publisher */
				char buf[20];
				memset(buf, 0, 20);
				janus_rtcp_fir((char *)&buf, 20, &publisher->fir_seq);
				JANUS_LOG(LOG_VERB, "Switching existing subscriber to new publisher, sending FIR to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				gateway->relay_rtcp(publisher->session->handle, 1, buf, 20);
				/* Send a PLI too, just in case... */
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				JANUS_LOG(LOG_VERB, "Switching existing subscriber to new publisher, sending PLI to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				gateway->relay_rtcp(publisher->session->handle, 1, buf, 12);
				/* Done */
				subscriber->paused = paused;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "switched", json_string("ok"));
				json_object_set_new(event, "room", json_integer(subscriber->room->room_id));
				json_object_set_new(event, "id", json_integer(feed_id));
				if(publisher->display)
					json_object_set_new(event, "display", json_string(publisher->display));
			} else if(!strcasecmp(request_text, "leave")) {
				guint64 room_id = subscriber && subscriber->room ? subscriber->room->room_id : 0;
				/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
				janus_videoroom_hangup_media(session->handle);
				gateway->close_pc(session->handle);
				/* Send an event back */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(room_id));
				json_object_set_new(event, "left", json_string("ok"));
				session->started = FALSE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
				goto error;
			}
		}

		/* Prepare JSON event */
		JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
		/* Any SDP to handle? */
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		if(!msg_sdp) {
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			const char *type = NULL;
			if(!strcasecmp(msg_sdp_type, "offer")) {
				/* We need to answer */
				type = "answer";
			} else if(!strcasecmp(msg_sdp_type, "answer")) {
				/* We got an answer (from a subscriber?), no need to negotiate */
				g_atomic_int_set(&session->hangingup, 0);
				int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(event);
				janus_videoroom_message_free(msg);
				continue;
			} else {
				/* TODO We don't support anything else right now... */
				JANUS_LOG(LOG_ERR, "Unknown SDP type '%s'\n", msg_sdp_type);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				g_snprintf(error_cause, 512, "Unknown SDP type '%s'", msg_sdp_type);
				goto error;
			}
			if(session->participant_type != janus_videoroom_p_type_publisher) {
				/* We shouldn't be here, we always offer ourselves */
				JANUS_LOG(LOG_ERR, "Only publishers send offers\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				g_snprintf(error_cause, 512, "Only publishers send offers");
				goto error;
			} else {
				/* This is a new publisher: is there room? */
				participant = janus_videoroom_session_get_publisher(session);
				janus_videoroom *videoroom = participant->room;
				int count = 0;
				GHashTableIter iter;
				gpointer value;
				if(!videoroom) {
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					goto error;
				}
				if(g_atomic_int_get(&videoroom->destroyed)) {
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
					goto error;
				}
				janus_mutex_lock(&videoroom->mutex);
				g_hash_table_iter_init(&iter, videoroom->participants);
				while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_videoroom_publisher *p = value;
					if(p != participant && p->sdp)
						count++;
				}
				janus_mutex_unlock(&videoroom->mutex);
				if(count == videoroom->max_publishers) {
					participant->audio_active = FALSE;
					participant->video_active = FALSE;
					JANUS_LOG(LOG_ERR, "Maximum number of publishers (%d) already reached\n", videoroom->max_publishers);
					error_code = JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL;
					g_snprintf(error_cause, 512, "Maximum number of publishers (%d) already reached", videoroom->max_publishers);
					goto error;
				}
				/* Now prepare the SDP to give back */
				if(strstr(msg_sdp, "Mozilla")) {
					participant->firefox = TRUE;
				}
				/* Which media are available? */
				int audio = 0, video = 0, data = 0;
				const char *audio_mode = NULL, *video_mode = NULL;
				char error_str[100];
				janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				if(!parsed_sdp) {
					/* Invalid SDP */
					JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", error_str);
					error_code = JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL;
					g_snprintf(error_cause, 512, "Error parsing SDP: %s", error_str);
					goto error;
				}
				GList *temp = parsed_sdp->m_lines;
				while(temp) {
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					if(m->type == JANUS_SDP_AUDIO && m->port > 0) {
						audio++;
						participant->audio = TRUE;
						if(audio > 1) {
							temp = temp->next;
							continue;
						}
					} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
						video++;
						participant->video = TRUE;
						if(video > 1) {
							temp = temp->next;
							continue;
						}
					} else if(m->type == JANUS_SDP_APPLICATION && m->port > 0) {
						data++;
						participant->data = TRUE;
						if(data > 1) {
							temp = temp->next;
							continue;
						}
					}
					if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
						/* What is the direction? */
						switch(m->direction) {
							case JANUS_SDP_RECVONLY:
								/* If we're getting a 'recvonly' publisher, we're going to answer with 'inactive' */
							case JANUS_SDP_INACTIVE:
								if(m->type == JANUS_SDP_AUDIO) {
									audio_mode = "inactive";
								} else {
									video_mode = "inactive";
								}
								break;
							case JANUS_SDP_SENDONLY:
								/* What we expect, turn this into 'recvonly' */
							case JANUS_SDP_SENDRECV:
							default:
								if(m->type == JANUS_SDP_AUDIO) {
									audio_mode = "recvonly";
								} else {
									video_mode = "recvonly";
								}
								break;
						}
					}
					temp = temp->next;
				}
				janus_sdp_free(parsed_sdp);
				JANUS_LOG(LOG_VERB, "The publisher %s going to send an audio stream\n", audio ? "is" : "is NOT");
				int opus_pt = 0, isac32_pt = 0, isac16_pt = 0, pcmu_pt = 0, pcma_pt = 0,
					vp8_pt = 0, vp9_pt = 0, h264_pt = 0;
				if(audio) {
					JANUS_LOG(LOG_VERB, "  -- Will answer with media direction '%s'\n", audio_mode);
					opus_pt = janus_get_codec_pt(msg_sdp, "opus");
					if(opus_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- Opus payload type is %d\n", opus_pt);
					}
					isac32_pt = janus_get_codec_pt(msg_sdp, "isac32");
					if(isac32_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- ISAC 32K payload type is %d\n", isac32_pt);
					}
					isac16_pt = janus_get_codec_pt(msg_sdp, "isac16");
					if(isac16_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- ISAC 16K payload type is %d\n", isac16_pt);
					}
					pcmu_pt = janus_get_codec_pt(msg_sdp, "pcmu");
					if(pcmu_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- PCMU payload type is %d\n", pcmu_pt);
					}
					pcma_pt = janus_get_codec_pt(msg_sdp, "pcma");
					if(pcma_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- PCMA payload type is %d\n", pcma_pt);
					}
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to send a video stream\n", video ? "is" : "is NOT");
				if(video) {
					JANUS_LOG(LOG_VERB, "  -- Will answer with media direction '%s'\n", video_mode);
					vp8_pt = janus_get_codec_pt(msg_sdp, "vp8");
					if(vp8_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- VP8 payload type is %d\n", vp8_pt);
					}
					vp9_pt = janus_get_codec_pt(msg_sdp, "vp9");
					if(vp9_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- VP9 payload type is %d\n", vp9_pt);
					}
					h264_pt = janus_get_codec_pt(msg_sdp, "h264");
					if(h264_pt > 0) {
						JANUS_LOG(LOG_VERB, "  -- -- H264 payload type is %d\n", h264_pt);
					}
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to open a data channel\n", data ? "is" : "is NOT");
				/* Also add a bandwidth SDP attribute if we're capping the bitrate in the room */
				int b = 0;
				if(participant->firefox)	/* Don't add any b=AS attribute for Chrome */
					b = (int)(videoroom->bitrate/1000);
				char sdp[1280], audio_mline[256], video_mline[512], data_mline[256];
				char *newsdp = NULL;
				int res = 0;
				int pass = 0;
				for(pass = 1; pass <= 2; pass++) {
					if(pass == 2) {
						/* Now turn the SDP into what we'll send subscribers, using the static payload types for making switching easier */
						if(audio_mode && strcmp(audio_mode, "inactive"))
							/* The publisher gets a recvonly or inactive back */
							/* Subscribers gets a sendonly or inactive back */
							audio_mode = "sendonly";
						if(video_mode && strcmp(video_mode, "inactive"))
							video_mode = "sendonly";
					}
					audio_mline[0] = '\0';
					if(audio) {
						int pt = -1;
						switch(videoroom->acodec) {
							case JANUS_VIDEOROOM_OPUS:
								if(opus_pt >= 0)
									pt = (pass == 1 ? opus_pt : OPUS_PT);
								break;
							case JANUS_VIDEOROOM_ISAC_32K:
								if(isac32_pt >= 0)
									pt = (pass == 1 ? isac32_pt : ISAC32_PT);
								break;
							case JANUS_VIDEOROOM_ISAC_16K:
								if(isac16_pt >= 0)
									pt = (pass == 1 ? isac16_pt : ISAC16_PT);
								break;
							case JANUS_VIDEOROOM_PCMU:
								if(pcmu_pt >= 0)
									pt = (pass == 1 ? pcmu_pt : PCMU_PT);
								break;
							case JANUS_VIDEOROOM_PCMA:
								if(pcma_pt >= 0)
									pt = (pass == 1 ? pcma_pt : PCMA_PT);
								break;
							default:
								/* Shouldn't happen */
								break;
						}
						if(pass == 1 && pt < 0)
							JANUS_LOG(LOG_WARN, "Videoroom is forcing %s, but publisher didn't offer any... rejecting audio\n", janus_videoroom_audiocodec_name(videoroom->acodec));
						if(pt >= 0)
							janus_videoroom_sdp_a_format(audio_mline, 256, videoroom->acodec, pt, audio_mode);
						if(audio_mline[0] == '\0' && pass == 1) {
							/* Remove "pass == 1" if the subscriber also should get a line with port=0. */
							g_snprintf(audio_mline, 256, "m=audio 0 RTP/SAVPF 0\r\n");
						}
					}
					video_mline[0] = '\0';
					if(video) {
						int pt = -1;
						switch(videoroom->vcodec) {
							case JANUS_VIDEOROOM_VP8:
								if(vp8_pt >= 0)
									pt = (pass == 1 ? vp8_pt : VP8_PT);
								break;
							case JANUS_VIDEOROOM_VP9:
								if(vp9_pt >= 0)
									pt = (pass == 1 ? vp9_pt : VP9_PT);
								break;
							case JANUS_VIDEOROOM_H264:
								if(h264_pt >= 0)
									pt = (pass == 1 ? h264_pt : H264_PT);
								break;
							default:
								/* Shouldn't happen */
								break;
						}
						if(pass == 1 && pt < 0)
							JANUS_LOG(LOG_WARN, "Videoroom is forcing %s, but publisher didn't offer any... rejecting video\n", janus_videoroom_videocodec_name(videoroom->vcodec));
						if(pt >= 0)
							janus_videoroom_sdp_v_format(video_mline, 512, videoroom->vcodec, pt, b, video_mode);
						if(video_mline[0] == '\0' && pass == 1) {
							/* Remove "pass == 1" if the subscriber also should get a line with port=0. */
							g_snprintf(video_mline, 512, "m=video 0 RTP/SAVPF 0\r\n");
						}
					}
					if(data) {
						g_snprintf(data_mline, 256, sdp_d_template);
					} else {
						data_mline[0] = '\0';
					}
					g_snprintf(sdp, 1280, sdp_template,
						janus_get_real_time(),			/* We need current time here */
						janus_get_real_time(),			/* We need current time here */
						participant->room->room_name,	/* Video room name */
						audio_mline,					/* Audio m-line, if any */
						video_mline,					/* Video m-line, if any */
						data_mline);					/* Data channel m-line, if any */
					newsdp = g_strdup(sdp);
					if(video && b == 0) {
						/* Remove useless bandwidth attribute */
						newsdp = janus_string_replace(newsdp, "b=AS:0\r\n", "");
					}
					if(pass == 2)
						break;
					/* Is this room recorded? */
					janus_mutex_lock(&participant->rec_mutex);
					if(videoroom->record || participant->recording_active) {
						janus_videoroom_recorder_create(participant, audio, video);
					}
					janus_mutex_unlock(&participant->rec_mutex);

					JANUS_LOG(LOG_VERB, "Handling publisher: turned this into an '%s':\n%s\n", type, newsdp);
					json_t *jsep = json_pack("{ssss}", "type", type, "sdp", newsdp);
					/* How long will the gateway take to push the event? */
					g_atomic_int_set(&session->hangingup, 0);
					gint64 start = janus_get_monotonic_time();
					res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
					JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
					json_decref(event);
					json_decref(jsep);
					g_free(newsdp);
				}
				/* Done */
				if(res != JANUS_OK) {
					/* TODO Failed to negotiate? We should remove this publisher */
					g_free(newsdp);
				} else {
					/* Store the participant's SDP for interested subscribers */
					participant->sdp = newsdp;
					/* We'll wait for the setup_media event before actually telling subscribers */
				}
				g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
			}
		}
		g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
		janus_videoroom_message_free(msg);

		continue;
		
error:
		{
			g_clear_pointer(&videoroom, janus_videoroom_room_dereference);
			g_clear_pointer(&participant, janus_videoroom_publisher_dereference);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_videoroom_message_free(msg);
		}
	}
#ifdef JANUS_THREAD_DEBUG
	JANUS_LOG(LOG_INFO, "THREAD_DEBUG: Leaving VideoRoom handler thread; %d\n", g_atomic_int_add(&handler_thread_count, -1) - 1);
#else
	JANUS_LOG(LOG_VERB, "Leaving VideoRoom handler thread\n");
#endif
	return NULL;
}


/* Helper to quickly relay RTP packets from publishers to subscribers */
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_videoroom_rtp_relay_packet *packet = (janus_videoroom_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)data;
	if(!subscriber || !subscriber->session) {
		// JANUS_LOG(LOG_ERR, "Invalid session...\n");
		return;
	}
	if(subscriber->paused) {
		// JANUS_LOG(LOG_ERR, "This subscriber paused the stream...\n");
		return;
	}
	janus_videoroom_session *session = subscriber->session;
	if(!session || !session->handle) {
		// JANUS_LOG(LOG_ERR, "Invalid session...\n");
		return;
	}
	if(!session->started) {
		// JANUS_LOG(LOG_ERR, "Streaming not started yet for this session...\n");
		return;
	}
	
	/* Make sure there hasn't been a publisher switch by checking the SSRC */
	if(packet->is_video) {
		/* Check if this subscriber is subscribed to this medium */
		if(!subscriber->video) {
			/* Nope, don't relay */
			return;
		}
		if(ntohl(packet->data->ssrc) != subscriber->context.v_last_ssrc) {
			/* Publisher switch? Fix sequence numbers and timestamps */
			subscriber->context.v_last_ssrc = ntohl(packet->data->ssrc);
			subscriber->context.v_base_ts_prev = subscriber->context.v_last_ts;
			subscriber->context.v_base_ts = packet->timestamp;
			subscriber->context.v_base_seq_prev = subscriber->context.v_last_seq;
			subscriber->context.v_base_seq = packet->seq_number;
		}
		if(subscriber->context.v_seq_reset) {
			/* video_active false-->true? Fix sequence numbers */
			subscriber->context.v_seq_reset = FALSE;
			subscriber->context.v_base_seq_prev = subscriber->context.v_last_seq;
			subscriber->context.v_base_seq = packet->seq_number;
		}
		/* Compute a coherent timestamp and sequence number */
		subscriber->context.v_last_ts = (packet->timestamp-subscriber->context.v_base_ts)
			+ subscriber->context.v_base_ts_prev+4500;	/* FIXME When switching, we assume 15fps */
		subscriber->context.v_last_seq = (packet->seq_number-subscriber->context.v_base_seq)+subscriber->context.v_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet, and send it */
		packet->data->timestamp = htonl(subscriber->context.v_last_ts);
		packet->data->seq_number = htons(subscriber->context.v_last_seq);
		if(gateway != NULL)
			gateway->relay_rtp(session->handle, packet->is_video, (char *)packet->data, packet->length);
		/* Restore the timestamp and sequence number to what the publisher set them to */
		packet->data->timestamp = htonl(packet->timestamp);
		packet->data->seq_number = htons(packet->seq_number);
	} else {
		/* Check if this subscriber is subscribed to this medium */
		if(!subscriber->audio) {
			/* Nope, don't relay */
			return;
		}
		if(ntohl(packet->data->ssrc) != subscriber->context.a_last_ssrc) {
			/* Publisher switch? Fix sequence numbers and timestamps */
			subscriber->context.a_last_ssrc = ntohl(packet->data->ssrc);
			subscriber->context.a_base_ts_prev = subscriber->context.a_last_ts;
			subscriber->context.a_base_ts = packet->timestamp;
			subscriber->context.a_base_seq_prev = subscriber->context.a_last_seq;
			subscriber->context.a_base_seq = packet->seq_number;
		}
		if(subscriber->context.a_seq_reset) {
			/* audio_active false-->true? Fix sequence numbers */
			subscriber->context.a_seq_reset = FALSE;
			subscriber->context.a_base_seq_prev = subscriber->context.a_last_seq;
			subscriber->context.a_base_seq = packet->seq_number;
		}
		/* Compute a coherent timestamp and sequence number */
		subscriber->context.a_last_ts = (packet->timestamp-subscriber->context.a_base_ts)
			+ subscriber->context.a_base_ts_prev+960;	/* FIXME When switching, we assume Opus and so a 960 ts step */
		subscriber->context.a_last_seq = (packet->seq_number-subscriber->context.a_base_seq)+subscriber->context.a_base_seq_prev+1;
		/* Update the timestamp and sequence number in the RTP packet, and send it */
		packet->data->timestamp = htonl(subscriber->context.a_last_ts);
		packet->data->seq_number = htons(subscriber->context.a_last_seq);
		if(gateway != NULL)
			gateway->relay_rtp(session->handle, packet->is_video, (char *)packet->data, packet->length);
		/* Restore the timestamp and sequence number to what the publisher set them to */
		packet->data->timestamp = htonl(packet->timestamp);
		packet->data->seq_number = htons(packet->seq_number);
	}

	return;
}

static void janus_videoroom_relay_data_packet(gpointer data, gpointer user_data) {
	char *text = (char *)user_data;
	janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)data;
	if(!subscriber || !subscriber->session || !subscriber->data || subscriber->paused) {
		return;
	}
	janus_videoroom_session *session = subscriber->session;
	if(!session || !session->handle) {
		return;
	}
	if(!session->started) {
		return;
	}
	if(gateway != NULL && text != NULL) {
		JANUS_LOG(LOG_VERB, "Forwarding DataChannel message (%zu bytes) to viewer: %s\n", strlen(text), text);
		gateway->relay_data(session->handle, text, strlen(text));
	}
	return;
}
