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
record = true|false (whether this room should be recorded, default=false)
rec_dir = <folder where recordings should be stored, when enabled>
\endverbatim
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
 * Actual API docs: TBD.
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>
#include <sofia-sip/sdp.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../record.h"
#include "../utils.h"
#include <sys/types.h>
#include <sys/socket.h>


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
struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_videoroom_setup_media(janus_plugin_session *handle);
void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_videoroom_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_videoroom_hangup_media(janus_plugin_session *handle);
void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error);
char *janus_videoroom_query_session(janus_plugin_session *handle);

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


/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static su_home_t *sdphome = NULL;
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
	char *sdp_type;
	char *sdp;
} janus_videoroom_message;
static GAsyncQueue *messages = NULL;
static janus_videoroom_message exit_message;


typedef struct janus_videoroom {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;			/* Whether this room is 'private' (as in hidden) or not */
	int max_publishers;			/* Maximum number of concurrent publishers */
	uint64_t bitrate;			/* Global bitrate limit */
	uint16_t fir_freq;			/* Regular FIR frequency (0=disabled) */
	gboolean record;			/* Whether the feeds from publishers in this room should be recorded */
	char *rec_dir;				/* Where to save the recordings of this room, if enabled */
	GHashTable *participants;	/* Map of potential publishers (we get subscribers from them) */
	volatile gint destroyed;	/* Whether this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */
	janus_refcount ref;			/* Reference counter for this room */
} janus_videoroom;
static GHashTable *rooms;
static janus_mutex rooms_mutex;

typedef struct janus_videoroom_session {
	janus_plugin_session *handle;
	janus_videoroom_p_type participant_type;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	volatile gint hangingup;
	volatile gint destroyed;
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
static void janus_videoroom_subscriber_destroy(janus_videoroom_subscriber *s) {
	if(!s)
		return;
	if(!g_atomic_int_compare_and_exchange(&s->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&s->ref);
}

static void janus_videoroom_subscriber_free(const janus_refcount *s_ref) {
	janus_videoroom_subscriber *s = janus_refcount_containerof(s_ref, janus_videoroom_subscriber, ref);
	JANUS_LOG(LOG_WARN, "Freeing videoroom subscriber: %p\n", s_ref);
	/* This subscriber can be destroyed, free all the resources */
	g_free(s);
}

static void janus_videoroom_publisher_destroy(janus_videoroom_publisher *p) {
	if(!p)
		return;
	if(!g_atomic_int_compare_and_exchange(&p->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&p->ref);
}

static void janus_videoroom_publisher_free(const janus_refcount *p_ref) {
	janus_videoroom_publisher *p = janus_refcount_containerof(p_ref, janus_videoroom_publisher, ref);
	JANUS_LOG(LOG_WARN, "Freeing videoroom participant/publisher: %p\n", p_ref);
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

static void janus_videoroom_session_destroy(janus_videoroom_session *session) {
	if(!session)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&session->ref);
}

static void janus_videoroom_session_free(const janus_refcount *session_ref) {
	janus_videoroom_session *session = janus_refcount_containerof(session_ref, janus_videoroom_session, ref);
	JANUS_LOG(LOG_WARN, "Freeing videoroom session: %p\n", session_ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session);
}


static void janus_videoroom_room_destroy(janus_videoroom *room) {
	if(!room)
		return;
	if(!g_atomic_int_compare_and_exchange(&room->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&room->ref);
}

static void janus_videoroom_room_free(const janus_refcount *room_ref) {
	janus_videoroom *room = janus_refcount_containerof(room_ref, janus_videoroom, ref);
	JANUS_LOG(LOG_WARN, "Freeing videoroom room: %p\n", room_ref);
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
	g_free(msg->sdp_type);
	msg->sdp_type = NULL;
	g_free(msg->sdp);
	msg->sdp = NULL;

	g_free(msg);
}


/* SDP offer/answer templates */
#define OPUS_PT		111
#define VP8_PT		100
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=%s\r\n"							/* Video room name */ \
		"t=0 0\r\n" \
		"%s%s%s"				/* Audio, video and/or data channel m-lines */
#define sdp_a_template \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */
#define sdp_v_template \
		"m=video 1 RTP/SAVPF %d\r\n"		/* VP8 payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"b=AS:%d\r\n"						/* Bandwidth */ \
		"a=%s\r\n"							/* Media direction */ \
		"a=rtpmap:%d VP8/90000\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d ccm fir\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d nack\r\n"				/* VP8 payload type */ \
		"a=rtcp-fb:%d nack pli\r\n"			/* VP8 payload type */ \
		"a=rtcp-fb:%d goog-remb\r\n"		/* VP8 payload type */
#define sdp_d_template \
		"m=application 1 DTLS/SCTP 5000\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctpmap:5000 webrtc-datachannel 16\r\n"


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
	guint32 stream_id = g_random_int();
	while(g_hash_table_lookup(p->rtp_forwarders, GUINT_TO_POINTER(stream_id)) != NULL) {
		stream_id = g_random_int();
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
	sdphome = su_home_new(sizeof(su_home_t));
	if(su_home_init(sdphome) < 0) {
		JANUS_LOG(LOG_FATAL, "Ops, error setting up sofia-sdp?\n");
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

	rooms = g_hash_table_new_full(NULL, NULL, NULL,
	                              (GDestroyNotify) janus_videoroom_room_destroy);
	janus_mutex_init(&rooms_mutex);
	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_videoroom_session_destroy);
	janus_mutex_init(&sessions_mutex);

	messages = g_async_queue_new_full((GDestroyNotify) janus_videoroom_message_free);

	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		GList *cl = janus_config_get_categories(config);
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL) {
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
			janus_config_item *record = janus_config_get_item(cat, "record");
			janus_config_item *rec_dir = janus_config_get_item(cat, "rec_dir");
			/* Create the video room */
			janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
			if(videoroom == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				continue;
			}
			videoroom->room_id = atol(cat->name);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			if(description == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				continue;
			}
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
			if(record && record->value) {
				videoroom->record = janus_is_true(record->value);
				if(rec_dir && rec_dir->value) {
					videoroom->rec_dir = g_strdup(rec_dir->value);
				}
			}
			g_atomic_int_set(&videoroom->destroyed, 0);
			janus_mutex_init(&videoroom->mutex);
			janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
			videoroom->participants = g_hash_table_new(NULL, NULL);
			janus_mutex_lock(&rooms_mutex);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(videoroom->room_id), videoroom);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
				videoroom->room_id, videoroom->room_name,
				videoroom->is_private ? "private" : "public",
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
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers, FIR frequency of %d seconds\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->fir_freq);
	}
	janus_mutex_unlock(&rooms_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus videoroom handler", janus_videoroom_handler, NULL, &error);
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
	su_home_deinit(sdphome);
	su_home_unref(sdphome);
	sdphome = NULL;

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
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->participant_type = janus_videoroom_p_type_none;
	session->participant = NULL;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_videoroom_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
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
		if(session->participant_type == janus_videoroom_p_type_publisher) {
			janus_videoroom_publisher *p = (janus_videoroom_publisher *)session->participant;
			if(p->room) {
				janus_refcount_decrease(&p->room->ref);
			}
			janus_videoroom_publisher_destroy(p);
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)session->participant;
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

char *janus_videoroom_query_session(janus_plugin_session *handle) {
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
			janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
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
				if(participant->arc || participant->vrc) {
					json_t *recording = json_object();
					if(participant->arc && participant->arc->filename)
						json_object_set_new(recording, "audio", json_string(participant->arc->filename));
					if(participant->vrc && participant->vrc->filename)
						json_object_set_new(recording, "video", json_string(participant->vrc->filename));
					json_object_set_new(info, "recording", recording);
				}
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
	char *info_text = json_dumps(info, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(info);
	janus_refcount_decrease(&session->ref);
	return info_text;
}

struct janus_plugin_result *janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized");
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle");
	
	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	json_t *response = NULL;

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto error;
	}
	JANUS_LOG(LOG_VERB, "Handling message: %s\n", message);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been marked as destroyed...\n");
		error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been marked as destroyed...");
		goto error;
	}

	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);

	json_error_t error;
	root = json_loads(message, 0, &error);
	if(!root) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: on line %d: %s", error.line, error.text);
		goto error;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto error;
	}
	/* Get the request first */
	json_t *request = json_object_get(root, "request");
	if(!request) {
		JANUS_LOG(LOG_ERR, "Missing element (request)\n");
		error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
		g_snprintf(error_cause, 512, "Missing element (request)");
		goto error;
	}
	if(!json_is_string(request)) {
		JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
		g_snprintf(error_cause, 512, "Invalid element (request should be a string)");
		goto error;
	}
	/* Some requests ('create', 'destroy', 'exists', 'list') can be handled synchronously */
	const char *request_text = json_string_value(request);
	if(!strcasecmp(request_text, "create")) {
		/* Create a new videoroom */
		JANUS_LOG(LOG_VERB, "Creating a new videoroom\n");
		json_t *desc = json_object_get(root, "description");
		if(desc && !json_is_string(desc)) {
			JANUS_LOG(LOG_ERR, "Invalid element (description should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (description should be a string)");
			goto error;
		}
		json_t *is_private = json_object_get(root, "is_private");
		if(is_private && !json_is_boolean(is_private)) {
			JANUS_LOG(LOG_ERR, "Invalid element (is_private should be a boolean)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (is_private should be a boolean)");
			goto error;
		}
		json_t *secret = json_object_get(root, "secret");
		if(secret && !json_is_string(secret)) {
			JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (secret should be a string)");
			goto error;
		}
		json_t *pin = json_object_get(root, "pin");
		if(pin && !json_is_string(pin)) {
			JANUS_LOG(LOG_ERR, "Invalid element (pin should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (pin should be a string)");
			goto error;
		}
		json_t *bitrate = json_object_get(root, "bitrate");
		if(bitrate && (!json_is_integer(bitrate) || json_integer_value(bitrate) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (bitrate should be a positive integer)");
			goto error;
		}
		json_t *fir_freq = json_object_get(root, "fir_freq");
		if(fir_freq && (!json_is_integer(fir_freq) || json_integer_value(fir_freq) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (fir_freq should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (fir_freq should be a positive integer)");
			goto error;
		}
		json_t *publishers = json_object_get(root, "publishers");
		if(publishers && (!json_is_integer(publishers) || json_integer_value(publishers) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (publishers should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (publishers should be a positive integer)");
			goto error;
		}
		json_t *record = json_object_get(root, "record");
		if(record && !json_is_boolean(record)) {
			JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (record should be a boolean)");
			goto error;
		}
		json_t *rec_dir = json_object_get(root, "rec_dir");
		if(rec_dir && !json_is_string(rec_dir)) {
			JANUS_LOG(LOG_ERR, "Invalid element (rec_dir should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (rec_dir should be a string)");
			goto error;
		}
		json_t *permanent = json_object_get(root, "permanent");
		if(permanent && !json_is_boolean(permanent)) {
			JANUS_LOG(LOG_ERR, "Invalid element (permanent should be a boolean)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (permanent should be a boolean)");
			goto error;
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto error;
		}
		guint64 room_id = 0;
		json_t *room = json_object_get(root, "room");
		if(room && (!json_is_integer(room) || json_integer_value(room) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (room should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (room should be a positive integer)");
			goto error;
		} else {
			room_id = json_integer_value(room);
			if(room_id == 0) {
				JANUS_LOG(LOG_WARN, "Desired room ID is 0, which is not allowed... picking random ID instead\n");
			}
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id)) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Room %"SCNu64" already exists!\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_ROOM_EXISTS;
				g_snprintf(error_cause, 512, "Room %"SCNu64" already exists", room_id);
				goto error;
			}
		}
		/* Create the room */
		janus_videoroom *videoroom = g_malloc0(sizeof(janus_videoroom));
		if(videoroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Memory error");
			goto error;
		}
		/* Generate a random ID */
		if(room_id == 0) {
			while(room_id == 0) {
				room_id = g_random_int();
				if(g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id)) != NULL) {
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
		if(description == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Memory error");
			goto error;
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
		if(record) {
			videoroom->record = json_is_true(record);
			if(videoroom->record && rec_dir) {
				videoroom->rec_dir = g_strdup(json_string_value(rec_dir));
			}
		}
		g_atomic_int_set(&videoroom->destroyed, 0);
		janus_mutex_init(&videoroom->mutex);
		janus_refcount_init(&videoroom->ref, janus_videoroom_room_free);
		videoroom->participants = g_hash_table_new(NULL, NULL);
		JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
			videoroom->room_id, videoroom->room_name,
			videoroom->is_private ? "private" : "public",
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
			if(videoroom->room_secret)
				janus_config_add_item(config, cat, "secret", videoroom->room_secret);
			if(videoroom->room_pin)
				janus_config_add_item(config, cat, "pin", videoroom->room_pin);
			if(videoroom->rec_dir) {
				janus_config_add_item(config, cat, "record", "yes");
				janus_config_add_item(config, cat, "rec_dir", videoroom->rec_dir);
			}
			/* Save modified configuration */
			janus_config_save(config, config_folder, JANUS_VIDEOROOM_PACKAGE);
			janus_mutex_unlock(&config_mutex);
		}
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_insert(rooms, GUINT_TO_POINTER(videoroom->room_id), videoroom);
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
		json_t *room = json_object_get(root, "room");
		if(!room) {
			JANUS_LOG(LOG_ERR, "Missing element (room)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (room)");
			goto error;
		}
		if(!json_is_integer(room) || json_integer_value(room) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid element (room should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (room should be a positive integer)");
			goto error;
		}
		json_t *permanent = json_object_get(root, "permanent");
		if(permanent && !json_is_boolean(permanent)) {
			JANUS_LOG(LOG_ERR, "Invalid element (permanent should be a boolean)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (permanent should be a boolean)");
			goto error;
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto error;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
		if(videoroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		
		if(g_atomic_int_get(&videoroom->destroyed)) {
			janus_mutex_unlock(&rooms_mutex)
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", videoroom->room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "Videoroom (%"SCNu64")", videoroom->room_id);
			goto error;
		}
		if(videoroom->room_secret) {
			/* A secret is required for this action */
			json_t *secret = json_object_get(root, "secret");
			if(!secret) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (secret)");
				goto error;
			}
			if(!json_is_string(secret)) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (secret should be a string)");
				goto error;
			}
			if(!janus_strcmp_const_time(videoroom->room_secret, json_string_value(secret))) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Unauthorized (wrong secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
				g_snprintf(error_cause, 512, "Unauthorized (wrong secret)");
				goto error;
			}
		}
		/* Remove room */
		g_hash_table_remove(rooms, GUINT_TO_POINTER(room_id));
		/* Notify all participants that the fun is over, and that they'll be kicked */
		JANUS_LOG(LOG_VERB, "Notifying all participants\n");
		json_t *destroyed = json_object();
		json_object_set_new(destroyed, "videoroom", json_string("destroyed"));
		json_object_set_new(destroyed, "room", json_integer(videoroom->room_id));
		char *destroyed_text = json_dumps(destroyed, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&videoroom->mutex);
		g_hash_table_iter_init(&iter, videoroom->participants);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			if(p && p->session) {
				/* Notify the user we're going to destroy the room... */
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, destroyed_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				/* ... and then ask the core to remove the handle */
				gateway->end_session(p->session->handle);
			}
		}
		json_decref(destroyed);
		g_free(destroyed_text);
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
				janus_refcount_decrease(&room->ref);
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				continue;
			}
			if(!g_atomic_int_get(&room->destroyed)) {
				json_t *rl = json_object();
				json_object_set_new(rl, "room", json_integer(room->room_id));
				json_object_set_new(rl, "description", json_string(room->room_name));
				json_object_set_new(rl, "max_publishers", json_integer(room->max_publishers));
				json_object_set_new(rl, "bitrate", json_integer(room->bitrate));
				json_object_set_new(rl, "fir_freq", json_integer(room->fir_freq));
				json_object_set_new(rl, "record", json_string(room->record ? "true" : "false"));
				json_object_set_new(rl, "rec_dir", json_string(room->rec_dir));
				/* TODO: Should we list participants as well? or should there be a separate API call on a specific room for this? */
				json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
				json_array_append_new(list, rl);
			}
			janus_refcount_decrease(&room->ref);
		}
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "list", list);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "rtp_forward")) {
		json_t *room = json_object_get(root, "room");
		if(!room) {
			JANUS_LOG(LOG_ERR, "Missing element (room)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (room)");
			goto error;
		}
		if(!json_is_integer(room) || json_integer_value(room) < 0 ) {
			JANUS_LOG(LOG_ERR, "Invalid element (room should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (room should be a positive integer)");
			goto error;
		}
		json_t *pub_id = json_object_get(root, "publisher_id");
		if(!pub_id) {
			JANUS_LOG(LOG_ERR, "Missing element (publisher_id)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (publisher_id)");
			goto error;
		}
		if(!json_is_integer(pub_id) || json_integer_value(pub_id) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid element (publisher_id should be a postive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (publisher_id should be a positive integer)");
			goto error;
		}
		int video_port = -1;
		int audio_port = -1;
		json_t *vid_port = json_object_get(root, "video_port");
		if(vid_port && (!json_is_integer(vid_port) || json_integer_value(vid_port) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (video_port should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (video_port should be a positive integer)");
			goto error;
		}
		if(vid_port) {
			video_port = json_integer_value(vid_port);
		}
		json_t *au_port = json_object_get(root, "audio_port");
		if(au_port && (!json_is_integer(au_port) || json_integer_value(au_port) <0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (audio_port should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (audio_port should be a positive integer)");
			goto error;
		}
		if(au_port) {
			audio_port = json_integer_value(au_port);
		}
		json_t *json_host = json_object_get(root, "host");
		if(!json_host) {
			JANUS_LOG(LOG_ERR, "Missing element (host)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (host)");
			goto error;
		}
		if(!json_is_string(json_host)) {
			JANUS_LOG(LOG_ERR, "Invalid element (host should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (host should be a string)");
			goto error;
		}
		
		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		const gchar* host = json_string_value(json_host);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
		janus_mutex_unlock(&rooms_mutex);
		if(videoroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_refcount_increase(&videoroom->ref);
		if(g_atomic_int_get(&videoroom->destroyed)) {
			janus_refcount_decrease(&videoroom->ref);
			janus_mutex_unlock(&rooms_mutex)
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", videoroom->room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "Videoroom (%"SCNu64")", videoroom->room_id);
			goto error;
		}
		if(videoroom->room_secret) {
			/* A secret is required for this action */
			json_t *secret = json_object_get(root, "secret");
			if(!secret) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (secret)");
				goto error;
			}
			if(!json_is_string(secret)) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (secret should be a string)");
				goto error;
			}
			if(!janus_strcmp_const_time(videoroom->room_secret, json_string_value(secret))) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Unauthorized (wrong secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
				g_snprintf(error_cause, 512, "Unauthorized (wrong secret)");
				goto error;
			}
		}
		janus_mutex_lock(&videoroom->mutex);
		janus_videoroom_publisher* publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(publisher_id));
		if(publisher == NULL || g_atomic_int_get(&publisher->destroyed)) {
			janus_refcount_decrease(&videoroom->ref);
			janus_mutex_unlock(&videoroom->mutex);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto error;
		}
		janus_refcount_increase(&publisher->ref);	/* This is just to handle the request for now */
		if(publisher->udp_sock <= 0) {
			publisher->udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(publisher->udp_sock <= 0) {
				janus_refcount_decrease(&publisher->ref);
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&videoroom->mutex);
				JANUS_LOG(LOG_ERR, "Could not open UDP socket for rtp stream for publisher (%"SCNu64")\n", publisher_id);
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Could not open UDP socket for rtp stream");
				goto error;
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
			janus_refcount_increase(&publisher->ref);
			json_object_set_new(rtp_stream, "audio_stream_id", json_integer(audio_handle));
			json_object_set_new(rtp_stream, "audio", json_integer(audio_port));
		}
		if(video_handle > 0) {
			janus_refcount_increase(&publisher->ref);
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
		janus_refcount_decrease(&publisher->ref);	/* These two unrefs are related to the message handling */
		janus_refcount_decrease(&videoroom->ref);
		json_object_set_new(rtp_stream, "host", json_string(host));
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "rtp_stream", rtp_stream);
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "videoroom", json_string("rtp_forward"));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "stop_rtp_forward")) {
		json_t *room = json_object_get(root, "room");
		if(!room) {
			JANUS_LOG(LOG_ERR, "Missing element (room)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (room)");
			goto error;
		}
		if(!json_is_integer(room) || json_integer_value(room) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid element (room should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (room should be a positive integer)");
			goto error;
		}
		json_t *pub_id = json_object_get(root, "publisher_id");
		if(!pub_id) {
			JANUS_LOG(LOG_ERR, "Missing element (publisher_id)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (publisher_id)");
			goto error;
		}
		if(!json_is_integer(pub_id) || json_integer_value(pub_id) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid element (publisher_id should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (publisher_id should be a positive integer)");
			goto error;
		}
		json_t *id = json_object_get(root, "stream_id");
		if(!id) {
			JANUS_LOG(LOG_ERR, "Missing element (stream_id)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (stream_id)");
			goto error;
		}
		if(!json_is_integer(id) || json_integer_value(id) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid element (stream_id should be a positive integer)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (stream_id should be a positive integer)");
			goto error;
		}

		guint64 room_id = json_integer_value(room);
		guint64 publisher_id = json_integer_value(pub_id);
		guint32 stream_id = json_integer_value(id);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
		janus_mutex_unlock(&rooms_mutex);
		if(videoroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_refcount_increase(&videoroom->ref);
		if(g_atomic_int_get(&videoroom->destroyed)) {
			janus_refcount_decrease(&videoroom->ref);
			janus_mutex_unlock(&rooms_mutex)
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", videoroom->room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "Videoroom (%"SCNu64")", videoroom->room_id);
			goto error;
		}
		if(videoroom->room_secret) {
			/* A secret is required for this action */
			json_t *secret = json_object_get(root, "secret");
			if(!secret) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (secret)");
				goto error;
			}
			if(!json_is_string(secret)) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (secret should be a string)");
				goto error;
			}
			if(!janus_strcmp_const_time(videoroom->room_secret, json_string_value(secret))) {
				janus_refcount_decrease(&videoroom->ref);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Unauthorized (wrong secret)\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
				g_snprintf(error_cause, 512, "Unauthorized (wrong secret)");
				goto error;
			}
		}
		janus_mutex_lock(&videoroom->mutex);
		janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(publisher_id));
		if(publisher == NULL || g_atomic_int_get(&publisher->destroyed)) {
			janus_refcount_decrease(&videoroom->ref);
			janus_mutex_unlock(&videoroom->mutex);
			JANUS_LOG(LOG_ERR, "No such publisher (%"SCNu64")\n", publisher_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", publisher_id);
			goto error;
		}
		janus_refcount_increase(&publisher->ref);	/* Just to handle the message now */
		janus_mutex_lock(&publisher->rtp_forwarders_mutex);
		if(g_hash_table_lookup(publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id)) == NULL) {
			janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
			janus_refcount_decrease(&videoroom->ref);
			janus_mutex_unlock(&videoroom->mutex);
			JANUS_LOG(LOG_ERR, "No such stream (%"SCNu32")\n", stream_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
			g_snprintf(error_cause, 512, "No such stream (%"SCNu32")", stream_id);
			goto error;
		}
		g_hash_table_remove(publisher->rtp_forwarders, GUINT_TO_POINTER(stream_id));
		janus_mutex_unlock(&publisher->rtp_forwarders_mutex);
		/* This unref is for the stopped forwarder */
		janus_refcount_decrease(&publisher->ref);
		/* These two unrefs are related to the message handling */
		janus_refcount_decrease(&publisher->ref);
		janus_refcount_decrease(&videoroom->ref);
		janus_mutex_unlock(&videoroom->mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("stop_rtp_forward"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "publisher_id", json_integer(publisher_id));
		json_object_set_new(response, "stream_id", json_integer(stream_id));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "exists")) {
		/* Check whether a given room exists or not, returns true/false */	
		json_t *room = json_object_get(root, "room");
		if(!room || !json_is_integer(room) || json_integer_value(room) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid request, room number must be included in request and must be a positive integer\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (room)");
			goto error;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, GUINT_TO_POINTER(room_id));
		janus_mutex_unlock(&rooms_mutex);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("success"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "exists", json_string(room_exists ? "true" : "false"));
		goto plugin_response;
	} else if(!strcasecmp(request_text, "listparticipants")) {
		/* List all participants in a room, specifying whether they're publishers or just attendees */	
		json_t *room = json_object_get(root, "room");
		if(!room || !json_is_integer(room) || json_integer_value(room) < 0) {
			JANUS_LOG(LOG_ERR, "Invalid request, room number must be included in request and must be a positive integer\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (room)");
			goto error;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
		janus_mutex_unlock(&rooms_mutex);
		if(videoroom == NULL) {
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_refcount_increase(&videoroom->ref);
		if(g_atomic_int_get(&videoroom->destroyed)) {
			janus_refcount_decrease(&videoroom->ref);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
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
			json_object_set_new(pl, "publisher", json_string(p->sdp ? "true" : "false"));
			json_array_append_new(list, pl);
		}
		janus_mutex_unlock(&videoroom->mutex);
		janus_refcount_decrease(&videoroom->ref);
		response = json_object();
		json_object_set_new(response, "videoroom", json_string("participants"));
		json_object_set_new(response, "room", json_integer(room_id));
		json_object_set_new(response, "participants", list);
		goto plugin_response;
	} else if(!strcasecmp(request_text, "join") || !strcasecmp(request_text, "joinandconfigure")
			|| !strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish") || !strcasecmp(request_text, "unpublish")
			|| !strcasecmp(request_text, "start") || !strcasecmp(request_text, "pause") || !strcasecmp(request_text, "switch")
			|| !strcasecmp(request_text, "stop") || !strcasecmp(request_text, "leave")) {
		/* These messages are handled asynchronously */

		janus_videoroom_message *msg = g_malloc0(sizeof(janus_videoroom_message));
		if(msg == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "Memory error");
			goto error;
		}

		g_free(message);
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->sdp_type = sdp_type;
		msg->sdp = sdp;
		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
		goto error;
	}

plugin_response:
		{
			if (!response) {
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Invalid response");
				goto error;
			}
			if(root != NULL)
				json_decref(root);
			g_free(transaction);
			g_free(message);
			g_free(sdp_type);
			g_free(sdp);

			char *response_text = json_dumps(response, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(response);
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, response_text);
			g_free(response_text);
			janus_refcount_decrease(&session->ref);
			return result;
		}

error:
		{
			if(root != NULL)
				json_decref(root);
			g_free(transaction);
			g_free(message);
			g_free(sdp_type);
			g_free(sdp);

			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			janus_plugin_result *result = janus_plugin_result_new(JANUS_PLUGIN_OK, event_text);
			g_free(event_text);
			janus_refcount_decrease(&session->ref);
			return result;
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
	/* If this is a subscriber, ask the publisher a FIR */
	if(session->participant) {
		if(session->participant_type == janus_videoroom_p_type_subscriber) {
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
	janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
	if(participant == NULL || g_atomic_int_get(&participant->destroyed))
		return;
	if((!video && participant->audio_active) || (video && participant->video_active)) {
		/* Update payload type and SSRC */
		rtp_header *rtp = (rtp_header *)buf;
		rtp->type = video ? VP8_PT : OPUS_PT;
		rtp->ssrc = htonl(video ? participant->video_ssrc : participant->audio_ssrc);
		/* Forward RTP to the appropriate port for the rtp_forwarders associated wih this publisher, if there are any */
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
		if(video && participant->vrc)
			janus_recorder_save_frame(participant->vrc, buf, len);
		else if(!video && participant->arc)
			janus_recorder_save_frame(participant->arc, buf, len);
		/* Done, relay it */
		janus_videoroom_rtp_relay_packet packet;
		packet.data = rtp;
		packet.length = len;
		packet.is_video = video;
		/* Backup the actual timestamp and sequence number set by the publisher, in case switching is involved */
		packet.timestamp = ntohl(packet.data->timestamp);
		packet.seq_number = ntohs(packet.data->seq_number);
		/* Go */
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
				char rtcpbuf[200];
				memset(rtcpbuf, 0, 200);
				/* FIXME First put a RR (fake)... */
				int rrlen = 32;
				rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 1;
				rr->header.length = htons((rrlen/4)-1);
				/* ... then put a SDES... */
				int sdeslen = janus_rtcp_sdes((char *)(&rtcpbuf)+rrlen, 200-rrlen, "janusvideo", 10);
				if(sdeslen > 0) {
					/* ... and then finally a REMB */
					janus_rtcp_remb((char *)(&rtcpbuf)+rrlen+sdeslen, 24, bitrate);
					gateway->relay_rtcp(handle, video, rtcpbuf, rrlen+sdeslen+24);
				}
				JANUS_LOG(LOG_VERB, "Sending REMB\n");
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
	}
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
	janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
	if(participant == NULL || g_atomic_int_get(&participant->destroyed))
		return;
	/* Get a string out of the data */
	char *text = g_malloc0(len+1);
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
	g_slist_foreach(participant->subscribers, janus_videoroom_relay_data_packet, text);
	g_free(text);
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
			janus_videoroom_publisher *publisher = (janus_videoroom_publisher *)session->participant;
			if(publisher == NULL || g_atomic_int_get(&publisher->destroyed))
				return;
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("slow_link"));
			/* Also add info on what the current bitrate cap is */
			uint64_t bitrate = (publisher->bitrate ? publisher->bitrate : 256*1024);
			json_object_set_new(event, "current-bitrate", json_integer(bitrate));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			event = NULL;
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event_text, NULL, NULL);
			g_free(event_text);
			event_text = NULL;
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
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			event = NULL;
			gateway->push_event(session->handle, &janus_videoroom_plugin, NULL, event_text, NULL, NULL);
			g_free(event_text);
			event_text = NULL;
		} else {
			JANUS_LOG(LOG_WARN, "Got a slow downlink on a VideoRoom viewer? Weird, because it doesn't send media...\n");
		}
	}
}

void janus_videoroom_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_VIDEOROOM_PACKAGE, handle);
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
		janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
		if(participant == NULL || g_atomic_int_get(&participant->destroyed))
			return;
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
		/* Get rid of the recorders, if available */
		g_free(participant->recording_base);
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
		while(participant->subscribers) {
			janus_videoroom_subscriber *s = (janus_videoroom_subscriber *)participant->subscribers->data;
			if(s) {
				participant->subscribers = g_slist_remove(participant->subscribers, s);
				s->feed = NULL;
				janus_refcount_decrease(&s->ref);
				janus_refcount_decrease(&participant->ref);
				janus_refcount_decrease(&participant->session->ref);
			}
		}
		janus_mutex_unlock(&participant->subscribers_mutex);
		janus_mutex_lock(&participant->room->mutex);
		json_t *event = json_object();
		json_object_set_new(event, "videoroom", json_string("event"));
		json_object_set_new(event, "room", json_integer(participant->room->room_id));
		json_object_set_new(event, "unpublished", json_integer(participant->user_id));
		char *unpub_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, participant->room->participants);
		while (!g_atomic_int_get(&participant->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_videoroom_publisher *p = value;
			if(p && p->session && p != participant) {
				JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, unpub_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
		}
		g_hash_table_remove(participant->room->participants, GUINT_TO_POINTER(participant->user_id));
		janus_mutex_unlock(&participant->room->mutex);
		g_free(unpub_text);
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Get rid of subscriber */
		janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)session->participant;
		if(subscriber) {
			subscriber->paused = TRUE;
			janus_videoroom_publisher *publisher = subscriber->feed;
			if(publisher != NULL) {
				janus_mutex_lock(&publisher->subscribers_mutex);
				publisher->subscribers = g_slist_remove(publisher->subscribers, subscriber);
				subscriber->feed = NULL;
				janus_refcount_decrease(&subscriber->ref);
				janus_refcount_decrease(&publisher->ref);
				janus_refcount_decrease(&publisher->session->ref);
				janus_mutex_unlock(&publisher->subscribers_mutex);
			}
		}
		/* TODO Should we close the handle as well? */
	}
}

/* Thread to handle incoming messages */
static void *janus_videoroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining VideoRoom handler thread\n");
	janus_videoroom_message *msg = NULL;
	int error_code = 0;
	char *error_cause = g_malloc0(512);
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
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
		json_t *request = json_object_get(root, "request");
		if(!request) {
			JANUS_LOG(LOG_ERR, "Missing element (request)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (request)");
			goto error;
		}
		if(!json_is_string(request)) {
			JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (request should be a string)");
			goto error;
		}
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
			json_t *room = json_object_get(root, "room");
			if(!room) {
				JANUS_LOG(LOG_ERR, "Missing element (room)\n");
				g_snprintf(error_cause, 512, "Missing element (room)");
				goto error;
			}
			if(!json_is_integer(room) || json_integer_value(room) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid element (room should be a positive integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (room should be a positive integer)");
				goto error;
			}
			guint64 room_id = json_integer_value(room);
			janus_mutex_lock(&rooms_mutex);
			janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
			if(videoroom == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			if(g_atomic_int_get(&videoroom->destroyed)) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			janus_refcount_increase(&videoroom->ref);
			if(videoroom->room_pin) {
				/* A pin is required to join this room */
				json_t *pin = json_object_get(root, "pin");
				if(!pin) {
					janus_refcount_decrease(&videoroom->ref);
					janus_mutex_unlock(&rooms_mutex);
					JANUS_LOG(LOG_ERR, "Missing element (pin)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, 512, "Missing element (pin)");
					goto error;
				}
				if(!json_is_string(pin)) {
					janus_refcount_decrease(&videoroom->ref);
					janus_mutex_unlock(&rooms_mutex);
					JANUS_LOG(LOG_ERR, "Invalid element (pin should be a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (pin should be a string)");
					goto error;
				}
				if(!janus_strcmp_const_time(videoroom->room_pin, json_string_value(pin))) {
					janus_refcount_decrease(&videoroom->ref);
					janus_mutex_unlock(&rooms_mutex);
					JANUS_LOG(LOG_ERR, "Unauthorized (wrong pin)\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
					g_snprintf(error_cause, 512, "Unauthorized (wrong pin)");
					goto error;
				}
			}
			janus_mutex_unlock(&rooms_mutex);
			json_t *ptype = json_object_get(root, "ptype");
			if(!ptype) {
				janus_refcount_decrease(&videoroom->ref);
				JANUS_LOG(LOG_ERR, "Missing element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (ptype)");
				goto error;
			}
			if(!json_is_string(ptype)) {
				janus_refcount_decrease(&videoroom->ref);
				JANUS_LOG(LOG_ERR, "Invalid element (ptype should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (ptype should be a string)");
				goto error;
			}
			const char *ptype_text = json_string_value(ptype);
			if(!strcasecmp(ptype_text, "publisher")) {
				JANUS_LOG(LOG_VERB, "Configuring new publisher\n");
				json_t *display = json_object_get(root, "display");
				if(display && !json_is_string(display)) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Invalid element (display should be a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (display should be a string)");
					goto error;
				}
				const char *display_text = display ? json_string_value(display) : NULL;
				guint64 user_id = 0;
				json_t *id = json_object_get(root, "id");
				if(id) {
					if(!json_is_integer(id) || json_integer_value(id) < 0) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (id should be a positive integer)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (id should be a positive integer)");
						goto error;
					}
					user_id = json_integer_value(id);
					janus_mutex_lock(&videoroom->mutex);
					if(g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(user_id)) != NULL) {
						janus_refcount_decrease(&videoroom->ref);
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
						user_id = g_random_int();
						if(g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(user_id)) != NULL) {
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
					audio = json_object_get(root, "audio");
					if(audio && !json_is_boolean(audio)) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
						goto error;
					}
					video = json_object_get(root, "video");
					if(video && !json_is_boolean(video)) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
						goto error;
					}
					bitrate = json_object_get(root, "bitrate");
					if(bitrate && (!json_is_integer(bitrate) || json_integer_value(bitrate) < 0)) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be a positive integer)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (bitrate should be a positive integer)");
						goto error;
					}
					record = json_object_get(root, "record");
					if(record && !json_is_boolean(record)) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (record should be a boolean)");
						goto error;
					}
					recfile = json_object_get(root, "filename");
					if(recfile && !json_is_string(recfile)) {
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_ERR, "Invalid element (filename should be a string)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid value (filename should be a string)");
						goto error;
					}
				}
				janus_videoroom_publisher *publisher = g_malloc0(sizeof(janus_videoroom_publisher));
				if(publisher == NULL) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Memory error");
					goto error;
				}
				publisher->session = session;
				publisher->room = videoroom;
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
				publisher->firefox = FALSE;
				publisher->bitrate = videoroom->bitrate;
				publisher->subscribers = NULL;
				janus_mutex_init(&publisher->subscribers_mutex);
				publisher->audio_ssrc = g_random_int();
				publisher->video_ssrc = g_random_int();
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
				session->participant_type = janus_videoroom_p_type_publisher;
				session->participant = publisher;
				/* Return a list of all available publishers (those with an SDP available, that is) */
				json_t *list = json_array();
				GHashTableIter iter;
				gpointer value;
				janus_mutex_lock(&videoroom->mutex);
				g_hash_table_insert(videoroom->participants, GUINT_TO_POINTER(user_id), publisher);
				g_hash_table_iter_init(&iter, videoroom->participants);
				while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_videoroom_publisher *p = value;
					if(p == publisher || !p->sdp) {
						continue;
					}
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(p->user_id));
					if(p->display)
						json_object_set_new(pl, "display", json_string(p->display));
					json_array_append_new(list, pl);
				}
				janus_mutex_unlock(&videoroom->mutex);
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("joined"));
				json_object_set_new(event, "room", json_integer(videoroom->room_id));
				json_object_set_new(event, "description", json_string(videoroom->room_name));
				json_object_set_new(event, "id", json_integer(user_id));
				json_object_set_new(event, "publishers", list);
			} else if(!strcasecmp(ptype_text, "subscriber") || !strcasecmp(ptype_text, "listener")) {
				JANUS_LOG(LOG_VERB, "Configuring new subscriber\n");
				/* This is a new subscriber */
				json_t *feed = json_object_get(root, "feed");
				if(!feed) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Missing element (feed)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, 512, "Missing element (feed)");
					goto error;
				}
				if(!json_is_integer(feed) || json_integer_value(feed) < 0) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Invalid element (feed should be a positive integer)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (feed should be a positive integer)");
					goto error;
				}
				guint64 feed_id = json_integer_value(feed);
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
					goto error;
				}
				json_t *data = json_object_get(root, "data");
				if(data && !json_is_boolean(data)) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "Invalid element (data should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (data should be a boolean)");
					goto error;
				}
				janus_mutex_lock(&videoroom->mutex);
				janus_videoroom_publisher *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(feed_id));
				janus_mutex_unlock(&videoroom->mutex);
				if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || publisher->sdp == NULL) {
					janus_refcount_decrease(&videoroom->ref);
					JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
					g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
					goto error;
				} else {
					janus_refcount_increase(&publisher->ref);
					janus_refcount_increase(&publisher->session->ref);
					janus_videoroom_subscriber *subscriber = g_malloc0(sizeof(janus_videoroom_subscriber));
					if(subscriber == NULL) {
						janus_refcount_decrease(&publisher->ref);
						janus_refcount_decrease(&publisher->session->ref);
						janus_refcount_decrease(&videoroom->ref);
						JANUS_LOG(LOG_FATAL, "Memory error!\n");
						error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
						g_snprintf(error_cause, 512, "Memory error");
						goto error;
					}
					subscriber->session = session;
					subscriber->room = videoroom;
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
					json_object_set_new(event, "room", json_integer(videoroom->room_id));
					json_object_set_new(event, "id", json_integer(feed_id));
					if(publisher->display)
						json_object_set_new(event, "display", json_string(publisher->display));
					session->participant_type = janus_videoroom_p_type_subscriber;
					JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
					char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
					json_decref(event);
					/* Negotiate by sending the selected publisher SDP back */
					if(publisher->sdp != NULL) {
						/* How long will the gateway take to push the event? */
						g_atomic_int_set(&session->hangingup, 0);
						gint64 start = janus_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, "offer", publisher->sdp);
						JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
						JANUS_LOG(LOG_VERB, "  >> %d\n", res);
						g_free(event_text);
						root = NULL;
						janus_videoroom_message_free(msg);
						continue;
					}
					g_free(event_text);
				}
			} else {
				janus_refcount_decrease(&videoroom->ref);
				JANUS_LOG(LOG_ERR, "Invalid element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (ptype)");
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Handle this publisher */
			janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
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
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
					goto error;
				}
				json_t *bitrate = json_object_get(root, "bitrate");
				if(bitrate && (!json_is_integer(bitrate) || json_integer_value(bitrate) < 0)) {
					JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be a positive integer)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (bitrate should be a positive integer)");
					goto error;
				}
				json_t *record = json_object_get(root, "record");
				if(record && !json_is_boolean(record)) {
					JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (record should be a boolean)");
					goto error;
				}
				json_t *recfile = json_object_get(root, "filename");
				if(recfile && !json_is_string(recfile)) {
					JANUS_LOG(LOG_ERR, "Invalid element (filename should be a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (filename should be a string)");
					goto error;
				}
				if(audio) {
					participant->audio_active = json_is_true(audio);
					JANUS_LOG(LOG_VERB, "Setting audio property: %s (room %"SCNu64", user %"SCNu64")\n", participant->audio_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(video) {
					participant->video_active = json_is_true(video);
					JANUS_LOG(LOG_VERB, "Setting video property: %s (room %"SCNu64", user %"SCNu64")\n", participant->video_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(bitrate) {
					participant->bitrate = json_integer_value(bitrate);
					JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu64" (room %"SCNu64", user %"SCNu64")\n", participant->bitrate, participant->room->room_id, participant->user_id);
					/* Send a new REMB */
					participant->remb_latest = janus_get_monotonic_time();
					char rtcpbuf[200];
					memset(rtcpbuf, 0, 200);
					/* FIXME First put a RR (fake)... */
					int rrlen = 32;
					rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
					rr->header.version = 2;
					rr->header.type = RTCP_RR;
					rr->header.rc = 1;
					rr->header.length = htons((rrlen/4)-1);
					/* ... then put a SDES... */
					int sdeslen = janus_rtcp_sdes((char *)(&rtcpbuf)+rrlen, 200-rrlen, "janusvideo", 10);
					if(sdeslen > 0) {
						/* ... and then finally a REMB */
						janus_rtcp_remb((char *)(&rtcpbuf)+rrlen+sdeslen, 24, participant->bitrate ? participant->bitrate : 256*1024);
						gateway->relay_rtcp(msg->handle, 1, rtcpbuf, rrlen+sdeslen+24);
					}
				}
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
					} else if(participant->recording_active && participant->sdp) {
						/* We've started recording, send a PLI/FIR and go on */
						char filename[255];
						gint64 now = janus_get_real_time();
						if(strstr(participant->sdp, "m=audio")) {
							memset(filename, 0, 255);
							if(participant->recording_base) {
								/* Use the filename and path we have been provided */
								g_snprintf(filename, 255, "%s-audio", participant->recording_base);
								participant->arc = janus_recorder_create(participant->room->rec_dir, 0, filename);
								if(participant->arc == NULL) {
									JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
								}
							} else {
								/* Build a filename */
								g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-audio",
									participant->room->room_id, participant->user_id, now);
								participant->arc = janus_recorder_create(participant->room->rec_dir, 0, filename);
								if(participant->arc == NULL) {
									JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
								}
							}
						}
						if(strstr(participant->sdp, "m=video")) {
							memset(filename, 0, 255);
							if(participant->recording_base) {
								/* Use the filename and path we have been provided */
								g_snprintf(filename, 255, "%s-video", participant->recording_base);
								participant->vrc = janus_recorder_create(participant->room->rec_dir, 1, filename);
								if(participant->vrc == NULL) {
									JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
								}
							} else {
								/* Build a filename */
								g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-video",
									participant->room->room_id, participant->user_id, now);
								participant->vrc = janus_recorder_create(participant->room->rec_dir, 1, filename);
								if(participant->vrc == NULL) {
									JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
								}
							}
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
				/* This publisher is leaving, tell everybody */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(participant->room->room_id));
				json_object_set_new(event, "leaving", json_integer(participant->user_id));
				char *leaving_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				GHashTableIter iter;
				gpointer value;
				if(participant->room) {
					if(!g_atomic_int_get(&participant->room->destroyed)) {
						janus_mutex_lock(&participant->room->mutex);
						g_hash_table_iter_init(&iter, participant->room->participants);
						while (!g_atomic_int_get(&participant->room->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
							janus_videoroom_publisher *p = value;
							if(p == participant) {
								continue;	/* Skip the new publisher itself */
							}
							JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
							int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, leaving_text, NULL, NULL);
							JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
						}
						janus_mutex_unlock(&participant->room->mutex);
					}
				}
				g_free(leaving_text);
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
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
					goto error;
				}
				json_t *data = json_object_get(root, "data");
				if(data && !json_is_boolean(data)) {
					JANUS_LOG(LOG_ERR, "Invalid element (data should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (data should be a boolean)");
					goto error;
				}
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
				json_t *feed = json_object_get(root, "feed");
				if(!feed) {
					JANUS_LOG(LOG_ERR, "Missing element (feed)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, 512, "Missing element (feed)");
					goto error;
				}
				if(!json_is_integer(feed) || json_integer_value(feed) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid element (feed should be a positive integer)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (feed should be a positive integer)");
					goto error;
				}
				guint64 feed_id = json_integer_value(feed);
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
					goto error;
				}
				json_t *data = json_object_get(root, "data");
				if(data && !json_is_boolean(data)) {
					JANUS_LOG(LOG_ERR, "Invalid element (data should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid value (data should be a boolean)");
					goto error;
				}
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
				janus_videoroom_publisher *publisher = g_hash_table_lookup(subscriber->room->participants, GUINT_TO_POINTER(feed_id));
				janus_mutex_unlock(&subscriber->room->mutex);
				if(publisher == NULL || g_atomic_int_get(&publisher->destroyed) || publisher->sdp == NULL) {
					JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
					g_snprintf(error_cause, 512, "No such feed (%"SCNu64")", feed_id);
					goto error;
				}
				janus_refcount_increase(&publisher->ref);
				janus_refcount_increase(&publisher->session->ref);
				gboolean paused = subscriber->paused;
				subscriber->paused = TRUE;
				/* Unsubscribe from the previous publisher */
				janus_videoroom_publisher *prev_feed = subscriber->feed;
				if(prev_feed) {
					janus_mutex_lock(&prev_feed->subscribers_mutex);
					prev_feed->subscribers = g_slist_remove(prev_feed->subscribers, subscriber);
					janus_mutex_unlock(&prev_feed->subscribers_mutex);
					subscriber->feed = NULL;
					janus_refcount_decrease(&prev_feed->ref);
					janus_refcount_decrease(&prev_feed->session->ref);
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
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		/* Any SDP to handle? */
		if(!msg->sdp) {
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		} else {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			const char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer")) {
				/* We need to answer */
				type = "answer";
			} else if(!strcasecmp(msg->sdp_type, "answer")) {
				/* We got an answer (from a subscriber?), no need to negotiate */
				g_atomic_int_set(&session->hangingup, 0);
				int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(event_text);
				root = NULL;
				janus_videoroom_message_free(msg);
				continue;
			} else {
				/* TODO We don't support anything else right now... */
				JANUS_LOG(LOG_ERR, "Unknown SDP type '%s'\n", msg->sdp_type);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				g_snprintf(error_cause, 512, "Unknown SDP type '%s'", msg->sdp_type);
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
				janus_videoroom_publisher *participant = (janus_videoroom_publisher *)session->participant;
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
				if(strstr(msg->sdp, "Mozilla")) {
					participant->firefox = TRUE;
				}
				/* Which media are available? */
				int audio = 0, video = 0, data = 0;
				const char *audio_mode = NULL, *video_mode = NULL;
				sdp_parser_t *parser = sdp_parse(sdphome, msg->sdp, strlen(msg->sdp), 0);
				sdp_session_t *parsed_sdp = sdp_session(parser);
				if(!parsed_sdp) {
					/* Invalid SDP */
					JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdp_parsing_error(parser));
					error_code = JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL;
					g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdp_parsing_error(parser));
					sdp_parser_free(parser);
					goto error;
				}
				sdp_media_t *m = parsed_sdp->sdp_media;
				while(m) {
					if(m->m_type == sdp_media_audio && m->m_port > 0) {
						audio++;
						participant->audio = TRUE;
						if(audio > 1) {
							m = m->m_next;
							continue;
						}
					} else if(m->m_type == sdp_media_video && m->m_port > 0) {
						video++;
						participant->video = TRUE;
						if(video > 1) {
							m = m->m_next;
							continue;
						}
#ifdef HAVE_SCTP
					} else if(m->m_type == sdp_media_application && m->m_port > 0) {
						data++;
						participant->data = TRUE;
						if(data > 1) {
							m = m->m_next;
							continue;
						}
#endif
					}
					if(m->m_type != sdp_media_application) {
						/* What is the direction? */
						switch(m->m_mode) {
							case sdp_recvonly:
								/* If we're getting a 'recvonly' publisher, we're going to answer with 'inactive' */
							case sdp_inactive:
								if(m->m_type == sdp_media_audio) {
									audio_mode = "inactive";
								} else {
									video_mode = "inactive";
								}
								break;
							case sdp_sendonly:
								/* What we expect, turn this into 'recvonly' */
							case sdp_sendrecv:
							default:
								if(m->m_type == sdp_media_audio) {
									audio_mode = "recvonly";
								} else {
									video_mode = "recvonly";
								}
								break;
						}
					}
					m = m->m_next;
				}
				sdp_parser_free(parser);
				JANUS_LOG(LOG_VERB, "The publisher %s going to send an audio stream\n", audio ? "is" : "is NOT");
				if(audio) {
					JANUS_LOG(LOG_VERB, "  -- Will answer with media direction '%s'\n", audio_mode);
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to send a video stream\n", video ? "is" : "is NOT");
				if(video) {
					JANUS_LOG(LOG_VERB, "  -- Will answer with media direction '%s'\n", video_mode);
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to open a data channel\n", data ? "is" : "is NOT");
				/* Also add a bandwidth SDP attribute if we're capping the bitrate in the room */
				int b = 0;
				if(participant->firefox)	/* Don't add any b=AS attribute for Chrome */
					b = (int)(videoroom->bitrate/1000);
				char sdp[1280], audio_mline[256], video_mline[512], data_mline[256];
				if(audio) {
					g_snprintf(audio_mline, 256, sdp_a_template,
						OPUS_PT,						/* Opus payload type */
						audio_mode,						/* The publisher gets a recvonly or inactive back */
						OPUS_PT); 						/* Opus payload type */
				} else {
					audio_mline[0] = '\0';
				}
				if(video) {
					g_snprintf(video_mline, 512, sdp_v_template,
						VP8_PT,							/* VP8 payload type */
						b,								/* Bandwidth */
						video_mode,						/* The publisher gets a recvonly or inactive back */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT); 						/* VP8 payload type */
				} else {
					video_mline[0] = '\0';
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

				char *newsdp = g_strdup(sdp);
				if(video && b == 0) {
					/* Remove useless bandwidth attribute */
					newsdp = janus_string_replace(newsdp, "b=AS:0\r\n", "");
				}
				/* Is this room recorded? */
				if(videoroom->record || participant->recording_active) {
					char filename[255];
					gint64 now = janus_get_real_time();
					if(audio) {
						memset(filename, 0, 255);
						if(participant->recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-audio", participant->recording_base);
							participant->arc = janus_recorder_create(videoroom->rec_dir, 0, filename);
							if(participant->arc == NULL) {
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-audio",
								videoroom->room_id, participant->user_id, now);
							participant->arc = janus_recorder_create(videoroom->rec_dir, 0, filename);
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
							participant->vrc = janus_recorder_create(videoroom->rec_dir, 1, filename);
							if(participant->vrc == NULL) {
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-video",
								videoroom->room_id, participant->user_id, now);
							participant->vrc = janus_recorder_create(videoroom->rec_dir, 1, filename);
							if(participant->vrc == NULL) {
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this publisher!\n");
							}
						}
					}
				}

				JANUS_LOG(LOG_VERB, "Handling publisher: turned this into an '%s':\n%s\n", type, newsdp);
				/* How long will the gateway take to push the event? */
				g_atomic_int_set(&session->hangingup, 0);
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, type, newsdp);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				if(strstr(newsdp, "recvonly"))
					newsdp = janus_string_replace(newsdp, "recvonly", "sendonly");
				if(res != JANUS_OK) {
					/* TODO Failed to negotiate? We should remove this publisher */
				} else {
					/* Store the participant's SDP for interested subscribers */
					participant->sdp = newsdp;
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
					char *pub_text = json_dumps(pub, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
					json_decref(pub);
					GHashTableIter iter;
					gpointer value;
					janus_mutex_lock(&videoroom->mutex);
					g_hash_table_iter_init(&iter, videoroom->participants);
					while (!g_atomic_int_get(&videoroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
						janus_videoroom_publisher *p = value;
						if(p == participant) {
							continue;	/* Skip the new publisher itself */
						}
						JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
						int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, pub_text, NULL, NULL);
						JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					}
					g_free(pub_text);
					janus_mutex_unlock(&videoroom->mutex);
					/* Let's wait for the setup_media event */
				}
			}
		}
		g_free(event_text);
		janus_videoroom_message_free(msg);

		continue;
		
error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videoroom", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
			int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(event_text);
			janus_videoroom_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving VideoRoom handler thread\n");
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
			subscriber->context.v_last_ssrc = ntohl(packet->data->ssrc);
			subscriber->context.v_base_ts_prev = subscriber->context.v_last_ts;
			subscriber->context.v_base_ts = packet->timestamp;
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
			subscriber->context.a_last_ssrc = ntohl(packet->data->ssrc);
			subscriber->context.a_base_ts_prev = subscriber->context.a_last_ts;
			subscriber->context.a_base_ts = packet->timestamp;
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
