/*! \file   janus_videoroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VideoRoom plugin
 * \details  This is a plugin implementing a videoconferencing MCU for Janus.
 * This means that the plugin implements a virtual conferencing room peers
 * can join and leave at any time. This room is based on a Publish/Subscribe
 * pattern. Each peer can publish his/her own live audio/video feeds: this
 * feed becomes an available stream in the room the other participants can
 * attach to. This means that this plugin allows the realization of several
 * different scenarios, ranging from a simple webinar (one speaker, several
 * listeners) to a fully meshed video conference (each peer sending and
 * receiving to and from all the others).
 * 
 * For what concerns the subscriber side, there are two different ways to
 * attach to a publisher's feed: a generic 'listener', which can attach to
 * a single feed, and a more complex 'Multiplexed listener', which instead can
 * attach to more feeds using the same PeerConnection. The generic 'listener'
 * is the default, which means that if you want to watch more feeds at the
 * same time, you'll need to create multiple 'listeners' to attach at any
 * of them. The 'Multiplexed listener', instead, is a more complex alternative
 * that exploits the so called RTCWEB 'Plan B', which multiplexes more
 * streams on a single PeerConnection and in the SDP: while more efficient in terms of
 * resources, though, this approach is experimental, and currently only
 * available on Google Chrome, so use it wisely.
 * \note As of now, work on Plan B is still going on, and as such its support in Janus
 * is flaky to say the least. Don't try to attach as a Multiplexed listener or bad
 * things will probably happen!
 * 
 * Considering that this plugin allows for several different WebRTC PeerConnections
 * to be on at the same time for the same peer (specifically, each peer
 * potentially has 1 PeerConnection on for publishing and N on for subscriptions
 * from other peers), each peer may need to attach several times to the same
 * plugin for every stream: this means that each peer needs to have at least one
 * handle active for managing its relation with the plugin (joining a room,
 * leaving a room, muting/unmuting, publishing, receiving events), and needs
 * to open a new one each time he/she wants to subscribe to a feed from
 * another participant (or a single one in case a 'Multiplexed listener is used).
 * The handle used for a subscription, however, would be logically a "slave"
 * to the master one used for managing the room: this means that it cannot
 * be used, for instance, to unmute in the room, as its only purpose would
 * be to provide a context in which creating the sendonly PeerConnection
 * for the subscription to the active participant.
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
secret = <password needed for manipulating (e.g. destroying) the room>
publishers = <max number of concurrent senders> (e.g., 6 for a video
             conference or 1 for a webinar)
bitrate = <max video bitrate for senders> (e.g., 128000)
fir_freq = <send a FIR to publishers every fir_freq seconds> (0=disable)
record = true|false (whether this room should be recorded, default=false)
rec_dir = <folder where recordings should be stored, when enabled>
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../record.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_VIDEOROOM_VERSION			3
#define JANUS_VIDEOROOM_VERSION_STRING	"0.0.3"
#define JANUS_VIDEOROOM_DESCRIPTION		"This is a plugin implementing a videoconferencing MCU for Janus, something like Licode."
#define JANUS_VIDEOROOM_NAME			"JANUS VideoRoom plugin"
#define JANUS_VIDEOROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_VIDEOROOM_PACKAGE			"janus.plugin.videoroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_videoroom_init(janus_callbacks *callback, const char *config_path);
void janus_videoroom_destroy(void);
int janus_videoroom_get_version(void);
const char *janus_videoroom_get_version_string(void);
const char *janus_videoroom_get_description(void);
const char *janus_videoroom_get_name(void);
const char *janus_videoroom_get_author(void);
const char *janus_videoroom_get_package(void);
void janus_videoroom_create_session(janus_plugin_session *handle, int *error);
void janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_videoroom_setup_media(janus_plugin_session *handle);
void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videoroom_hangup_media(janus_plugin_session *handle);
void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error);

/* Plugin setup */
static janus_plugin janus_videoroom_plugin =
	{
		.init = janus_videoroom_init,
		.destroy = janus_videoroom_destroy,

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
		.hangup_media = janus_videoroom_hangup_media,
		.destroy_session = janus_videoroom_destroy_session,
	}; 

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VIDEOROOM_NAME);
	return &janus_videoroom_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videoroom_handler(void *data);
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data);

typedef enum janus_videoroom_p_type {
	janus_videoroom_p_type_none = 0,
	janus_videoroom_p_type_subscriber,			/* Generic listener/subscriber */
	janus_videoroom_p_type_subscriber_muxed,	/* Multiplexed listener/subscriber */
	janus_videoroom_p_type_publisher,			/* Participant/publisher */
} janus_videoroom_p_type;

typedef struct janus_videoroom_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_videoroom_message;
static GAsyncQueue *messages = NULL;

static void janus_videoroom_message_free(janus_videoroom_message *msg) {
	if(!msg)
		return;

	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	g_free(msg->message);
	msg->message = NULL;
	g_free(msg->sdp_type);
	msg->sdp_type = NULL;
	g_free(msg->sdp);
	msg->sdp = NULL;

	g_free(msg);
}


typedef struct janus_videoroom {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	int max_publishers;			/* Maximum number of concurrent publishers */
	uint64_t bitrate;			/* Global bitrate limit */
	uint16_t fir_freq;			/* Regular FIR frequency (0=disabled) */
	gboolean record;			/* Whether the feeds from publishers in this room should be recorded */
	char *rec_dir;				/* Where to save the recordings of this room, if enabled */
	gboolean destroy;			/* Value to flag the room for destruction */
	GHashTable *participants;	/* Map of potential publishers (we get listeners from them) */
} janus_videoroom;
GHashTable *rooms;
janus_mutex rooms_mutex;

static void janus_videoroom_free(janus_videoroom *room);

typedef struct janus_videoroom_session {
	janus_plugin_session *handle;
	janus_videoroom_p_type participant_type;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	gboolean destroy;
} janus_videoroom_session;
GHashTable *sessions;
janus_mutex sessions_mutex;

typedef struct janus_videoroom_participant {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	guint64 user_id;	/* Unique ID in the room */
	gchar *display;	/* Display name (just for fun) */
	gchar *sdp;			/* The SDP this publisher negotiated, if any */
	guint32 audio_ssrc;		/* Audio SSRC of this publisher */
	guint32 video_ssrc;		/* Video SSRC of this publisher */
	gboolean audio_active;
	gboolean video_active;
	gboolean firefox;	/* We send Firefox users a different kind of FIR */
	uint64_t bitrate;
	gint64 fir_latest;	/* Time of latest sent FIR (to avoid flooding) */
	gint fir_seq;		/* FIR sequence number */
	janus_recorder *arc;	/* The Janus recorder instance for this publisher's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this publisher's video, if enabled */
	GSList *listeners;
	janus_mutex listeners_mutex;
} janus_videoroom_participant;

static void janus_videoroom_participant_free(janus_videoroom_participant *p);

typedef struct janus_videoroom_listener {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	janus_videoroom_participant *feed;	/* Participant this listener is subscribed to */
	struct janus_videoroom_listener_muxed *parent;	/* Overall subscriber, if this is a sub-listener in a Multiplexed one */
	gboolean paused;
} janus_videoroom_listener;

static void janus_videoroom_listener_free(janus_videoroom_listener *l);

typedef struct janus_videoroom_listener_muxed {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	GSList *listeners;	/* List of listeners (as a Multiplexed listener can be subscribed to more publishers at the same time) */
	janus_mutex listeners_mutex;
} janus_videoroom_listener_muxed;

typedef struct janus_videoroom_rtp_relay_packet {
	char *data;
	gint length;
	gint is_video;
} janus_videoroom_rtp_relay_packet;

/* SDP offer/answer templates */
#define OPUS_PT		111
#define VP8_PT		100
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=%s\r\n"							/* Video room name */ \
		"t=0 0\r\n" \
		"%s%s"								/* Audio and/or video m-lines */
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


/* Multiplexing helpers */
int janus_videoroom_muxed_subscribe(janus_videoroom_listener_muxed *muxed_listener, GList *feeds, char *transaction);
int janus_videoroom_muxed_unsubscribe(janus_videoroom_listener_muxed *muxed_listener, GList *feeds, char *transaction);
int janus_videoroom_muxed_offer(janus_videoroom_listener_muxed *muxed_listener, char *transaction, char *event_text);


/* Plugin implementation */
int janus_videoroom_init(janus_callbacks *callback, const char *config_path) {
	if(stopping) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	sprintf(filename, "%s/%s.cfg", config_path, JANUS_VIDEOROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	rooms = g_hash_table_new_full(NULL, NULL, NULL,
	                              (GDestroyNotify) janus_videoroom_free);
	janus_mutex_init(&rooms_mutex);
	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);

	messages = g_async_queue_new_full((GDestroyNotify) janus_videoroom_message_free);

	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_category *cat = janus_config_get_categories(config);
		while(cat != NULL) {
			if(cat->name == NULL) {
				cat = cat->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding video room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get_item(cat, "description");
			janus_config_item *secret = janus_config_get_item(cat, "secret");
			janus_config_item *bitrate = janus_config_get_item(cat, "bitrate");
			janus_config_item *maxp = janus_config_get_item(cat, "publishers");
			janus_config_item *firfreq = janus_config_get_item(cat, "fir_freq");
			janus_config_item *record = janus_config_get_item(cat, "record");
			janus_config_item *rec_dir = janus_config_get_item(cat, "rec_dir");
			/* Create the video mcu room */
			janus_videoroom *videoroom = calloc(1, sizeof(janus_videoroom));
			if(videoroom == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				continue;
			}
			videoroom->room_id = atoi(cat->name);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL)
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
				if(!strcasecmp(record->value, "true"))
					videoroom->record = TRUE;
				else if(!strcasecmp(record->value, "false"))
					videoroom->record = FALSE;
				else {
					JANUS_LOG(LOG_WARN, "Invalid value '%s' for 'record', recording disabled\n", record->value);
					videoroom->record = FALSE;
				}
				if(rec_dir && rec_dir->value) {
					videoroom->rec_dir = g_strdup(rec_dir->value);
				}
			}
			videoroom->destroy = 0;
			videoroom->participants = g_hash_table_new_full(NULL, NULL, NULL,
			                                                (GDestroyNotify) janus_videoroom_participant_free);
			janus_mutex_lock(&rooms_mutex);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(videoroom->room_id), videoroom);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, secret: %s)\n", videoroom->room_id, videoroom->room_name, videoroom->room_secret ? videoroom->room_secret : "no secret");
			if(videoroom->record) {
				JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
			}
			cat = cat->next;
		}
		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}

	/* Show available rooms */
	janus_mutex_lock(&rooms_mutex);
	GList *rooms_list = g_hash_table_get_values(rooms);
	GList *r = rooms_list;
	while(r) {
		janus_videoroom *vr = (janus_videoroom *)r->data;
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers, FIR frequency of %d seconds\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->fir_freq);
		r = r->next;
	}
	g_list_free(rooms_list);
	janus_mutex_unlock(&rooms_mutex);

	initialized = 1;
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus videoroom handler", janus_videoroom_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VIDEOROOM_NAME);
	return 0;
}

void janus_videoroom_destroy(void) {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);

	janus_mutex_lock(&rooms_mutex);
	g_hash_table_destroy(rooms);
	rooms = NULL;
	janus_mutex_unlock(&rooms_mutex);
	janus_mutex_destroy(&rooms_mutex);

	g_async_queue_unref(messages);
	messages = NULL;

	initialized = 0;
	stopping = 0;
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VIDEOROOM_NAME);
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
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)calloc(1, sizeof(janus_videoroom_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->participant_type = janus_videoroom_p_type_none;
	session->participant = NULL;
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_videoroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroy) {
		JANUS_LOG(LOG_WARN, "Session already destroyed...\n");
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Video Room session...\n");
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	/* Any related WebRTC PeerConnection is not available anymore either */
	janus_videoroom_hangup_media(handle);
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* Get rid of publisher */
		janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
		participant->audio_active = FALSE;
		participant->video_active = FALSE;
		json_t *event = json_object();
		json_object_set_new(event, "videoroom", json_string("event"));
		json_object_set_new(event, "room", json_integer(participant->room->room_id));
		json_object_set_new(event, "leaving", json_integer(participant->user_id));
		char *leaving_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		g_hash_table_remove(participant->room->participants, GUINT_TO_POINTER(participant->user_id));
		GList *participants_list = g_hash_table_get_values(participant->room->participants);
		GList *ps = participants_list;
		while(ps) {
			janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
			if(p == participant) {
				ps = ps->next;
				continue;	/* Skip the leaving publisher itself */
			}
			JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
			int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, leaving_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			ps = ps->next;
		}
		g_free(leaving_text);
		g_list_free(participants_list);
		/* Get rid of the recorders, if available */
		if(participant->arc) {
			janus_recorder_close(participant->arc);
			JANUS_LOG(LOG_INFO, "Closed audio recording %s\n", participant->arc->filename ? participant->arc->filename : "??");
		}
		if(participant->vrc) {
			janus_recorder_close(participant->vrc);
			JANUS_LOG(LOG_INFO, "Closed video recording %s\n", participant->vrc->filename ? participant->vrc->filename : "??");
		}
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Detaching this listener from its publisher is already done by hangup_media */
	} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
		/* Detaching this listener from its publishers is already done by hangup_media */
	}
	/* Cleaning up and removing the session is done in a lazy way */
	session->destroy = TRUE;

	return;
}

void janus_videoroom_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_LOG(LOG_VERB, "%s\n", message);
	janus_videoroom_message *msg = calloc(1, sizeof(janus_videoroom_message));
	if(msg == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;

	g_async_queue_push(messages, msg);
}

void janus_videoroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* Media relaying can start now */
	session->started = TRUE;
	/* If this is a listener, ask the publisher a FIR */
	if(session->participant) {
		if(session->participant_type == janus_videoroom_p_type_subscriber) {
			janus_videoroom_listener *l = (janus_videoroom_listener *)session->participant;
			if(l && l->feed) {
				janus_videoroom_participant *p = l->feed;
				if(p && p->session) {
					/* Send a FIR */
					char buf[20];
					memset(buf, 0, 20);
					if(!p->firefox)
						janus_rtcp_fir((char *)&buf, 20, &p->fir_seq);
					else
						janus_rtcp_fir_legacy((char *)&buf, 20, &p->fir_seq);
					JANUS_LOG(LOG_VERB, "New listener available, sending FIR to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, buf, 20);
					/* Send a PLI too, just in case... */
					memset(buf, 0, 12);
					janus_rtcp_pli((char *)&buf, 12);
					JANUS_LOG(LOG_VERB, "New listener available, sending PLI to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					gateway->relay_rtcp(p->session->handle, 1, buf, 12);
				}
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
			/* Do the same, but for all feeds */
			janus_videoroom_listener_muxed *listener = (janus_videoroom_listener_muxed *)session->participant;
			if(listener == NULL)
				return;
			GSList *ps = listener->listeners;
			while(ps) {
				janus_videoroom_listener *l = (janus_videoroom_listener *)ps->data;
				if(l && l->feed) {
					janus_videoroom_participant *p = l->feed;
					if(p && p->session) {
						/* Send a FIR */
						char buf[20];
						memset(buf, 0, 20);
						if(!p->firefox)
							janus_rtcp_fir((char *)&buf, 20, &p->fir_seq);
						else
							janus_rtcp_fir_legacy((char *)&buf, 20, &p->fir_seq);
						JANUS_LOG(LOG_VERB, "New Multiplexed listener available, sending FIR to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
						gateway->relay_rtcp(p->session->handle, 1, buf, 20);
						/* Send a PLI too, just in case... */
						memset(buf, 0, 12);
						janus_rtcp_pli((char *)&buf, 12);
						JANUS_LOG(LOG_VERB, "New Multiplexed listener available, sending PLI to %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
						gateway->relay_rtcp(p->session->handle, 1, buf, 12);
					}
				}
				ps = ps->next;
			}
		}
	}
}

void janus_videoroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || session->destroy || !session->participant || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
	if((!video && participant->audio_active) || (video && participant->video_active)) {
		/* Update payload type and SSRC */
		rtp_header *rtp = (rtp_header *)buf;
		rtp->type = video ? VP8_PT : OPUS_PT;
		rtp->ssrc = htonl(video ? participant->video_ssrc : participant->audio_ssrc);
		/* Save the frame if we're recording */
		if(participant->room->record) {
			if(video && participant->vrc)
				janus_recorder_save_frame(participant->vrc, buf, len);
			else if(!video && participant->arc)
				janus_recorder_save_frame(participant->arc, buf, len);
		}
		/* Done, relay it */
		janus_videoroom_rtp_relay_packet packet;
		packet.data = buf;
		packet.length = len;
		packet.is_video = video;
		g_slist_foreach(participant->listeners, janus_videoroom_relay_rtp_packet, &packet);
		if(video && participant->video_active && (participant->room->fir_freq > 0)) {
			/* FIXME Very ugly hack to generate RTCP every tot seconds/frames */
			gint64 now = janus_get_monotonic_time();
			if((now-participant->fir_latest) >= (participant->room->fir_freq*G_USEC_PER_SEC)) {
				/* FIXME We send a FIR every tot seconds */
				participant->fir_latest = now;
				char buf[20];
				memset(buf, 0, 20);
				janus_rtcp_fir((char *)&buf, 20, &participant->fir_seq);
				//~ if(!participant->firefox)
					//~ janus_rtcp_fir((char *)&buf, 20, &participant->fir_seq);
				//~ else
					//~ janus_rtcp_fir_legacy((char *)&buf, 20, &participant->fir_seq);
				JANUS_LOG(LOG_VERB, "Sending FIR to %"SCNu64" (%s)\n", participant->user_id, participant->display ? participant->display : "??");
				gateway->relay_rtcp(handle, video, buf, 20);
				/* Send a PLI too, just in case... */
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				JANUS_LOG(LOG_VERB, "Sending PLI to %"SCNu64" (%s)\n", participant->user_id, participant->display ? participant->display : "??");
				gateway->relay_rtcp(handle, video, buf, 12);
				if(participant->firefox && participant->bitrate > 0) {
					/* Now that we're there, let's send a REMB as well */
					janus_rtcp_remb((char *)&buf, 24, participant->bitrate);
					gateway->relay_rtcp(handle, video, buf, 24);
				}
			}
		}
	}
}

void janus_videoroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || session->destroy || !session->participant || !video)
		return;
	if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* FIXME Badly: we're blinding forwarding the listener RTCP to the publisher: this probably means confusing him... */
		janus_videoroom_listener *l = (janus_videoroom_listener *)session->participant;
		if(l && l->feed) {
			janus_videoroom_participant *p = l->feed;
			if(p && p->session) {
				if((!video && p->audio_active) || (video && p->video_active)) {
					if(p->bitrate > 0)
						janus_rtcp_cap_remb(buf, len, p->bitrate);
					gateway->relay_rtcp(p->session->handle, video, buf, len);
				}
			}
		}
	} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
		/* TODO What should we do here? */
	} else if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* FIXME Badly: we're just bouncing the incoming RTCP back with modified REMB, we need to improve this... */
		janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
		if(participant && participant->session) {
			if((!video && participant->audio_active) || (video && participant->video_active)) {
				janus_rtcp_fix_ssrc(buf, len, 1, video ? participant->video_ssrc : participant->audio_ssrc, 0);
				if(participant->bitrate > 0)
					janus_rtcp_cap_remb(buf, len, participant->bitrate);
				gateway->relay_rtcp(handle, video, buf, len);
				//~ /* FIXME Badly: we're also blinding forwarding the publisher RTCP to all the listeners: this probably means confusing them... */
				//~ if(participant->listeners != NULL) {
					//~ GSList *ps = participant->listeners;
					//~ while(ps) {
						//~ janus_videoroom_listener *l = (janus_videoroom_listener *)ps->data;
						//~ if(l->session && l->session->handle) {
							//~ gateway->relay_rtcp(l->session->handle, video, buf, len);
						//~ }
						//~ ps = ps->next;
					//~ }
				//~ }
			}
		}
	}
}

void janus_videoroom_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	session->started = FALSE;
	/* Send an event to the browser and tell the PeerConnection is over */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* This publisher just 'unpublished' */
		janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
		if(participant->sdp)
			g_free(participant->sdp);
		participant->sdp = NULL;
		participant->firefox = FALSE;
		participant->audio_active = FALSE;
		participant->video_active = FALSE;
		participant->fir_latest = 0;
		participant->fir_seq = 0;
		json_t *event = json_object();
		json_object_set_new(event, "videoroom", json_string("event"));
		json_object_set_new(event, "room", json_integer(participant->room->room_id));
		json_object_set_new(event, "unpublished", json_integer(participant->user_id));
		char *unpub_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		GList *participants_list = g_hash_table_get_values(participant->room->participants);
		GList *ps = participants_list;
		while(ps) {
			janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
			if(p && p->session) {
				JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
				int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, unpub_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			}
			ps = ps->next;
		}
		g_free(unpub_text);
		g_list_free(participants_list);
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Get rid of listener */
		janus_videoroom_listener *listener = (janus_videoroom_listener *)session->participant;
		if(listener) {
			listener->paused = TRUE;
			janus_videoroom_participant *publisher = listener->feed;
			if(publisher != NULL) {
				janus_mutex_lock(&publisher->listeners_mutex);
				publisher->listeners = g_slist_remove(publisher->listeners, listener);
				janus_mutex_unlock(&publisher->listeners_mutex);
				listener->feed = NULL;
			}
		}
		/* TODO Should we close the handle as well? */
	} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
		/* Do the same, but for all sub-listener */
		janus_videoroom_listener_muxed *listener = (janus_videoroom_listener_muxed *)session->participant;
		GSList *ps = listener->listeners;
		while(ps) {
			janus_videoroom_listener *l = (janus_videoroom_listener *)ps->data;
			if(l) {
				l->paused = TRUE;
				janus_videoroom_participant *publisher = l->feed;
				if(publisher != NULL) {
					janus_mutex_lock(&publisher->listeners_mutex);
					publisher->listeners = g_slist_remove(publisher->listeners, listener);
					janus_mutex_unlock(&publisher->listeners_mutex);
					l->feed = NULL;
				}
			}
			/* TODO Should we close the handle as well? */
			ps = ps->next;
		}
		/* TODO Should we close the handle as well? */
	}
}

/* Thread to handle incoming messages */
static void *janus_videoroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining thread\n");
	janus_videoroom_message *msg = NULL;
	int error_code = 0;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	while(initialized && !stopping) {
		if(!messages || (msg = g_async_queue_try_pop(messages)) == NULL) {
			usleep(50000);
			continue;
		}

		janus_videoroom_session *session = (janus_videoroom_session *)msg->handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_videoroom_message_free(msg);
			continue;
		}
		if(session->destroy) {
			janus_videoroom_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOROOM_ERROR_NO_MESSAGE;
			sprintf(error_cause, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		json_t *root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
			sprintf(error_cause, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_JSON;
			sprintf(error_cause, "JSON error: not an object");
			goto error;
		}
		/* Get the request first */
		json_t *request = json_object_get(root, "request");
		if(!request) {
			JANUS_LOG(LOG_ERR, "Missing element (request)\n");
			error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
			sprintf(error_cause, "Missing element (request)");
			goto error;
		}
		if(!json_is_string(request)) {
			JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
			error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
			sprintf(error_cause, "Invalid element (request should be a string)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		if(!strcasecmp(request_text, "create")) {
			/* Create a new videoroom */
			JANUS_LOG(LOG_VERB, "Creating a new videoroom\n");
			json_t *desc = json_object_get(root, "description");
			if(desc && !json_is_string(desc)) {
				JANUS_LOG(LOG_ERR, "Invalid element (description should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (description should be a string)");
				goto error;
			}
			json_t *secret = json_object_get(root, "secret");
			if(secret && !json_is_string(secret)) {
				JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (secret should be a string)");
				goto error;
			}
			json_t *bitrate = json_object_get(root, "bitrate");
			if(bitrate && !json_is_integer(bitrate)) {
				JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (bitrate should be an integer)");
				goto error;
			}
			json_t *fir_freq = json_object_get(root, "fir_freq");
			if(fir_freq && !json_is_integer(fir_freq)) {
				JANUS_LOG(LOG_ERR, "Invalid element (fir_freq should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (fir_freq should be an integer)");
				goto error;
			}
			json_t *publishers = json_object_get(root, "publishers");
			if(publishers && !json_is_integer(publishers)) {
				JANUS_LOG(LOG_ERR, "Invalid element (publishers should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (publishers should be an integer)");
				goto error;
			}
			json_t *record = json_object_get(root, "record");
			if(record && !json_is_boolean(record)) {
				JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (record should be a boolean)");
				goto error;
			}
			json_t *rec_dir = json_object_get(root, "rec_dir");
			if(rec_dir && !json_is_string(rec_dir)) {
				JANUS_LOG(LOG_ERR, "Invalid element (rec_dir should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (rec_dir should be a string)");
				goto error;
			}
			guint64 room_id = 0;
			json_t *room = json_object_get(root, "room");
			if(room && !json_is_integer(room)) {
				JANUS_LOG(LOG_ERR, "Invalid element (room should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (room should be an integer)");
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
					sprintf(error_cause, "Room %"SCNu64" already exists", room_id);
					goto error;
				}
			}
			/* Create the audio bridge room */
			janus_videoroom *videoroom = calloc(1, sizeof(janus_videoroom));
			if(videoroom == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Memory error");
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
			if(desc != NULL) {
				description = g_strdup(json_string_value(desc));
			} else {
				char roomname[255];
				sprintf(roomname, "Room %"SCNu64"", videoroom->room_id);
				description = g_strdup(roomname);
			}
			if(description == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				continue;
			}
			videoroom->room_name = description;
			if(secret)
				videoroom->room_secret = g_strdup(json_string_value(secret));
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
			videoroom->destroy = 0;
			videoroom->participants = g_hash_table_new(NULL, NULL);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(videoroom->room_id), videoroom);
			JANUS_LOG(LOG_VERB, "Created videoroom: %"SCNu64" (%s, secret: %s)\n", videoroom->room_id, videoroom->room_name, videoroom->room_secret ? videoroom->room_secret : "no secret");
			if(videoroom->record) {
				JANUS_LOG(LOG_VERB, "  -- Room is going to be recorded in %s\n", videoroom->rec_dir ? videoroom->rec_dir : "the current folder");
			}
			/* Show updated rooms list */
			GList *rooms_list = g_hash_table_get_values(rooms);
			GList *r = rooms_list;
			while(r) {
				janus_videoroom *vr = (janus_videoroom *)r->data;
				JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers, FIR frequency of %d seconds\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers, vr->fir_freq);
				r = r->next;
			}
			g_list_free(rooms_list);
			janus_mutex_unlock(&rooms_mutex);
			/* Send info back */
			event = json_object();
			json_object_set_new(event, "videoroom", json_string("created"));
			json_object_set_new(event, "room", json_integer(videoroom->room_id));
		} else if(!strcasecmp(request_text, "destroy")) {
			JANUS_LOG(LOG_VERB, "Attempt to destroy an existing videoroom room\n");
			json_t *room = json_object_get(root, "room");
			if(!room) {
				JANUS_LOG(LOG_ERR, "Missing element (room)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				sprintf(error_cause, "Missing element (room)");
				goto error;
			}
			if(!json_is_integer(room)) {
				JANUS_LOG(LOG_ERR, "Invalid element (room should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (room should be an integer)");
				goto error;
			}
			guint64 room_id = json_integer_value(room);
			janus_mutex_lock(&rooms_mutex);
			janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
			if(videoroom == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				sprintf(error_cause, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			janus_mutex_unlock(&rooms_mutex);
			if(videoroom->room_secret) {
				/* A secret is required for this action */
				json_t *secret = json_object_get(root, "secret");
				if(!secret) {
					JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (secret)");
					goto error;
				}
				if(!json_is_string(secret)) {
					JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (secret should be a string)");
					goto error;
				}
				if(strcmp(videoroom->room_secret, json_string_value(secret))) {
					JANUS_LOG(LOG_ERR, "Unauthorized (wrong secret)\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNAUTHORIZED;
					sprintf(error_cause, "Unauthorized (wrong secret)");
					goto error;
				}
			}
			/* Remove room */
			janus_mutex_lock(&rooms_mutex);
			g_hash_table_remove(rooms, GUINT_TO_POINTER(room_id));
			janus_mutex_unlock(&rooms_mutex);
			/* Notify all participants that the fun is over, and that they'll be kicked */
			JANUS_LOG(LOG_VERB, "Notifying all participants\n");
			json_t *destroyed = json_object();
			char *destroyed_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_object_set_new(destroyed, "videoroom", json_string("destroyed"));
			json_object_set_new(destroyed, "room", json_integer(videoroom->room_id));
			janus_mutex_lock(&rooms_mutex);
			GList *participants_list = g_hash_table_get_values(videoroom->participants);
			janus_mutex_unlock(&rooms_mutex);
			GList *ps = participants_list;
			while(ps) {
				janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
				if(p && p->session) {
					/* Notify the user we're going to destroy the room... */
					int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, msg->transaction, destroyed_text, NULL, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					/* ... and then ask the core to remove the handle */
					gateway->end_session(p->session->handle);
				}
				ps = ps->next;
			}
			json_decref(destroyed);
			g_list_free(participants_list);
			/* Done */
			event = json_object();
			json_object_set_new(event, "videoroom", json_string("destroyed"));
			json_object_set_new(event, "room", json_integer(room_id));
		} else
		/* What kind of participant is this session referring to? */
		if(session->participant_type == janus_videoroom_p_type_none) {
			JANUS_LOG(LOG_VERB, "Configuring new participant\n");
			/* Not configured yet, we need to do this now */
			if(strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Invalid request on unconfigured participant\n");
				error_code = JANUS_VIDEOROOM_ERROR_JOIN_FIRST;
				sprintf(error_cause, "Invalid request on unconfigured participant");
				goto error;
			}
			json_t *room = json_object_get(root, "room");
			if(!room) {
				JANUS_LOG(LOG_ERR, "Missing element (room)\n");
				sprintf(error_cause, "Missing element (room)");
				goto error;
			}
			if(!json_is_integer(room)) {
				JANUS_LOG(LOG_ERR, "Invalid element (room should be an integer)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (room should be an integer)");
				goto error;
			}
			guint64 room_id = json_integer_value(room);
			janus_mutex_lock(&rooms_mutex);
			janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
			if(videoroom == NULL) {
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
				error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_ROOM;
				sprintf(error_cause, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			janus_mutex_unlock(&rooms_mutex);
			json_t *ptype = json_object_get(root, "ptype");
			if(!ptype) {
				JANUS_LOG(LOG_ERR, "Missing element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
				sprintf(error_cause, "Missing element (ptype)");
				goto error;
			}
			if(!json_is_string(ptype)) {
				JANUS_LOG(LOG_ERR, "Invalid element (ptype should be a string)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (ptype should be a string)");
				goto error;
			}
			const char *ptype_text = json_string_value(ptype);
			if(!strcasecmp(ptype_text, "publisher")) {
				JANUS_LOG(LOG_VERB, "Configuring new publisher\n");
				json_t *display = json_object_get(root, "display");
				if(display && !json_is_string(display)) {
					JANUS_LOG(LOG_ERR, "Invalid element (display should be a string)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (display should be a string)");
					goto error;
				}
				const char *display_text = display ? json_string_value(display) : NULL;
				guint64 user_id = 0;
				json_t *id = json_object_get(root, "id");
				if(id) {
					if(!json_is_integer(id)) {
						JANUS_LOG(LOG_ERR, "Invalid element (id should be an integer)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						sprintf(error_cause, "Invalid element (id should be an integer)");
						goto error;
					}
					user_id = json_integer_value(id);
					if(g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(user_id)) != NULL) {
						/* User ID already taken */
						JANUS_LOG(LOG_ERR, "User ID %"SCNu64" already exists\n", user_id);
						error_code = JANUS_VIDEOROOM_ERROR_ID_EXISTS;
						sprintf(error_cause, "User ID %"SCNu64" already exists", user_id);
						goto error;
					}
				}
				if(user_id == 0) {
					/* Generate a random ID */
					while(user_id == 0) {
						user_id = g_random_int();
						if(g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(user_id)) != NULL) {
							/* User ID already taken, try another one */
							user_id = 0;
						}
					}
				}
				JANUS_LOG(LOG_VERB, "  -- Publisher ID: %"SCNu64"\n", user_id);
				janus_videoroom_participant *publisher = calloc(1, sizeof(janus_videoroom_participant));
				if(publisher == NULL) {
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
					sprintf(error_cause, "Memory error");
					goto error;
				}
				publisher->session = session;
				publisher->room = videoroom;
				publisher->user_id = user_id;
				publisher->display = display_text ? g_strdup(display_text) : NULL;
				publisher->sdp = NULL;	/* We'll deal with this later */
				publisher->audio_active = FALSE;
				publisher->video_active = FALSE;
				publisher->firefox = FALSE;
				publisher->bitrate = videoroom->bitrate;
				publisher->listeners = NULL;
				janus_mutex_init(&publisher->listeners_mutex);
				publisher->audio_ssrc = g_random_int();
				publisher->video_ssrc = g_random_int();
				publisher->fir_latest = 0;
				publisher->fir_seq = 0;
				/* Done */
				session->participant_type = janus_videoroom_p_type_publisher;
				session->participant = publisher;
				g_hash_table_insert(videoroom->participants, GUINT_TO_POINTER(user_id), publisher);
				/* Return a list of all available publishers (those with an SDP available, that is) */
				json_t *list = json_array();
				GList *participants_list = g_hash_table_get_values(videoroom->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
					if(p == publisher || !p->sdp) {
						ps = ps->next;
						continue;
					}
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(p->user_id));
					if(p->display)
						json_object_set_new(pl, "display", json_string(p->display));
					json_array_append_new(list, pl);
					ps = ps->next;
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("joined"));
				json_object_set_new(event, "room", json_integer(videoroom->room_id));
				json_object_set_new(event, "description", json_string(videoroom->room_name));
				json_object_set_new(event, "id", json_integer(user_id));
				json_object_set_new(event, "publishers", list);
				g_list_free(participants_list);
			} else if(!strcasecmp(ptype_text, "listener")) {
				JANUS_LOG(LOG_VERB, "Configuring new listener\n");
				/* This is a new listener */
				json_t *feed = json_object_get(root, "feed");
				if(!feed) {
					JANUS_LOG(LOG_ERR, "Missing element (feed)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (feed)");
					goto error;
				}
				if(!json_is_integer(feed)) {
					JANUS_LOG(LOG_ERR, "Invalid element (feed should be an integer)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (feed should be an integer)");
					goto error;
				}
				guint64 feed_id = json_integer_value(feed);
				janus_videoroom_participant *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(feed_id));
				if(publisher == NULL || publisher->sdp == NULL) {
					JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
					error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
					sprintf(error_cause, "No such feed (%"SCNu64")", feed_id);
					goto error;
				} else {
					janus_videoroom_listener *listener = calloc(1, sizeof(janus_videoroom_listener));
					if(listener == NULL) {
						JANUS_LOG(LOG_FATAL, "Memory error!\n");
						error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
						sprintf(error_cause, "Memory error");
						goto error;
					}
					listener->session = session;
					listener->room = videoroom;
					listener->feed = publisher;
					listener->paused = TRUE;	/* We need an explicit start from the listener */
					listener->parent = NULL;
					session->participant = listener;
					janus_mutex_lock(&publisher->listeners_mutex);
					publisher->listeners = g_slist_append(publisher->listeners, listener);
					janus_mutex_unlock(&publisher->listeners_mutex);
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
						gint64 start = janus_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, "offer", publisher->sdp);
						JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
						JANUS_LOG(LOG_VERB, "  >> %d\n", res);
						g_free(event_text);
						json_decref(root);
						continue;
					}
					g_free(event_text);
				}
			} else if(!strcasecmp(ptype_text, "muxed-listener")) {
				/* This is a new Multiplexed listener */
				JANUS_LOG(LOG_INFO, "Configuring new Multiplexed listener\n");
				/* Any feed we want to attach to already? */
				GList *list = NULL;
				json_t *feeds = json_object_get(root, "feeds");
				if(feeds && !json_is_array(feeds)) {
					JANUS_LOG(LOG_ERR, "Invalid element (feeds should be an array)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (feeds should be an array)");
					goto error;
				}
				if(feeds && json_array_size(feeds) > 0) {
					unsigned int i = 0;
					int problem = 0;
					for(i=0; i<json_array_size(feeds); i++) {
						json_t *feed = json_array_get(feeds, i);
						if(!feed || !json_is_integer(feed)) {
							problem = 1;
							JANUS_LOG(LOG_ERR, "Invalid element (feeds in the array must be integers)\n");
							error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
							sprintf(error_cause, "Invalid element (feeds in the array must be integers)");
							break;
						}
						uint64_t feed_id = json_integer_value(feed);
						janus_videoroom_participant *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(feed_id));
						if(publisher == NULL || publisher->sdp == NULL) {
							problem = 1;
							JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
							error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
							sprintf(error_cause, "No such feed (%"SCNu64")", feed_id);
							break;
						}
						list = g_list_prepend(list, GUINT_TO_POINTER(feed_id));
						JANUS_LOG(LOG_INFO, "  -- Subscribing to feed %"SCNu64"\n", feed_id);
					}
					if(problem) {
						goto error;
					}
				}
				/* Allocate listener */
				janus_videoroom_listener_muxed *listener = calloc(1, sizeof(janus_videoroom_listener_muxed));
				if(listener == NULL) {
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
					sprintf(error_cause, "Memory error");
					goto error;
				}
				listener->session = session;
				listener->room = videoroom;
				session->participant_type = janus_videoroom_p_type_subscriber_muxed;
				session->participant = listener;
				/* Ack that we created the listener */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("muxed-created"));
				json_object_set_new(event, "room", json_integer(videoroom->room_id));
				JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
				char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(event);
				/* How long will the gateway take to push the event? */
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				JANUS_LOG(LOG_VERB, "  >> %d\n", res);
				g_free(event_text);
				json_decref(root);
				/* Attach to feeds if needed */
				if(list != NULL) {
					JANUS_LOG(LOG_INFO, "Subscribing to %d feeds\n", g_list_length(list));
					list = g_list_reverse(list);
					if(janus_videoroom_muxed_subscribe(listener, list, msg->transaction) < 0) {
						JANUS_LOG(LOG_ERR, "Error subscribing!\n");
						error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;	/* FIXME */
						sprintf(error_cause, "Error subscribing!");
						goto error;
					}
				}
				continue;
			} else {
				JANUS_LOG(LOG_ERR, "Invalid element (ptype)\n");
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (ptype)");
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Handle this publisher */
			janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
			if(participant == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid participant instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Invalid participant instance");
				goto error;
			}
			if(!strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Already in as a publisher on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				sprintf(error_cause, "Already in as a publisher on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "configure") || !strcasecmp(request_text, "publish")) {
				if(!strcasecmp(request_text, "publish") && participant->sdp) {
					JANUS_LOG(LOG_ERR, "Can't publish, already published\n");
					error_code = JANUS_VIDEOROOM_ERROR_ALREADY_PUBLISHED;
					sprintf(error_cause, "Can't publish, already published");
					goto error;
				}
				/* Configure (or publish a new feed) audio/video/bitrate for this publisher */
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid value (audio should be a boolean)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid value (video should be a boolean)");
					goto error;
				}
				json_t *bitrate = json_object_get(root, "bitrate");
				if(bitrate && !json_is_integer(bitrate)) {
					JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be an integer)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid value (bitrate should be an integer)");
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
					sprintf(error_cause, "Can't unpublish, not published");
					goto error;
				}
				/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
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
				GList *participants_list = g_hash_table_get_values(participant->room->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
					if(p == participant) {
						ps = ps->next;
						continue;	/* Skip the new publisher itself */
					}
					JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
					int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, leaving_text, NULL, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					ps = ps->next;
				}
				g_free(leaving_text);
				g_list_free(participants_list);
				/* Done */
				participant->audio_active = 0;
				participant->video_active = 0;
				session->started = FALSE;
				session->destroy = TRUE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				sprintf(error_cause, "Unknown request '%s'", request_text);
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			/* Handle this listener */
			janus_videoroom_listener *listener = (janus_videoroom_listener *)session->participant;
			if(listener == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid listener instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Invalid listener instance");
				goto error;
			}
			if(!strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Already in as a listener on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				sprintf(error_cause, "Already in as a listener on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "start")) {
				/* Start/restart receiving the publisher streams */
				janus_videoroom_participant *publisher = listener->feed;
				listener->paused = FALSE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(publisher->room->room_id));
				json_object_set_new(event, "started", json_string("ok"));
				/* Send a FIR */
				char buf[20];
				memset(buf, 0, 20);
				if(!publisher->firefox)
					janus_rtcp_fir((char *)&buf, 20, &publisher->fir_seq);
				else
					janus_rtcp_fir_legacy((char *)&buf, 20, &publisher->fir_seq);
				JANUS_LOG(LOG_VERB, "Resuming publisher, sending FIR to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				gateway->relay_rtcp(publisher->session->handle, 1, buf, 20);
				/* Send a PLI too, just in case... */
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				JANUS_LOG(LOG_VERB, "Resuming publisher, sending PLI to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				gateway->relay_rtcp(publisher->session->handle, 1, buf, 12);
			} else if(!strcasecmp(request_text, "pause")) {
				/* Stop receiving the publisher streams for a while */
				janus_videoroom_participant *publisher = listener->feed;
				listener->paused = TRUE;
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(publisher->room->room_id));
				json_object_set_new(event, "paused", json_string("ok"));
			} else if(!strcasecmp(request_text, "leave")) {
				janus_videoroom_participant *publisher = listener->feed;
				if(publisher != NULL) {
					janus_mutex_lock(&publisher->listeners_mutex);
					publisher->listeners = g_slist_remove(publisher->listeners, listener);
					janus_mutex_unlock(&publisher->listeners_mutex);
					listener->feed = NULL;
				}
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(publisher->room->room_id));
				json_object_set_new(event, "left", json_string("ok"));
				session->started = FALSE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				sprintf(error_cause, "Unknown request '%s'", request_text);
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
			/* Handle this Multiplexed listener */
			janus_videoroom_listener_muxed *listener = (janus_videoroom_listener_muxed *)session->participant;
			if(listener == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid Multiplexed listener instance\n");
				error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Invalid Multiplexed listener instance");
				goto error;
			}
			if(!strcasecmp(request_text, "join")) {
				JANUS_LOG(LOG_ERR, "Already in as a Multiplexed listener on this handle\n");
				error_code = JANUS_VIDEOROOM_ERROR_ALREADY_JOINED;
				sprintf(error_cause, "Already in as a Multiplexed listener on this handle");
				goto error;
			} else if(!strcasecmp(request_text, "add")) {
				/* Add new streams to subscribe to */
				GList *list = NULL;
				json_t *feeds = json_object_get(root, "feeds");
				if(!feeds) {
					JANUS_LOG(LOG_ERR, "Missing element (feeds)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (feeds)");
					goto error;
				}
				if(!json_is_array(feeds) || json_array_size(feeds) == 0) {
					JANUS_LOG(LOG_ERR, "Invalid element (feeds should be a non-empty array)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (feeds should be a non-empty array)");
					goto error;
				}
				unsigned int i = 0;
				int problem = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *feed = json_array_get(feeds, i);
					if(!feed || !json_is_integer(feed)) {
						problem = 1;
						JANUS_LOG(LOG_ERR, "Invalid element (feeds in the array must be integers)\n");
						error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
						sprintf(error_cause, "Invalid element (feeds in the array must be integers)");
						break;
					}
					uint64_t feed_id = json_integer_value(feed);
					janus_videoroom_participant *publisher = g_hash_table_lookup(listener->room->participants, GUINT_TO_POINTER(feed_id));
					if(publisher == NULL || publisher->sdp == NULL) {
						problem = 1;
						JANUS_LOG(LOG_ERR, "No such feed (%"SCNu64")\n", feed_id);
						error_code = JANUS_VIDEOROOM_ERROR_NO_SUCH_FEED;
						sprintf(error_cause, "No such feed (%"SCNu64")", feed_id);
						break;
					}
					list = g_list_prepend(list, GUINT_TO_POINTER(feed_id));
				}
				if(problem) {
					goto error;
				}
				list = g_list_reverse(list);
				if(janus_videoroom_muxed_subscribe(listener, list, msg->transaction) < 0) {
					JANUS_LOG(LOG_ERR, "Error subscribing!\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;	/* FIXME */
					sprintf(error_cause, "Error subscribing!");
					goto error;
				}
				continue;
			} else if(!strcasecmp(request_text, "remove")) {
				/* Remove subscribed streams */
				GList *list = NULL;
				json_t *feeds = json_object_get(root, "feeds");
				if(!feeds) {
					JANUS_LOG(LOG_ERR, "Missing element (feeds)\n");
					error_code = JANUS_VIDEOROOM_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (feeds)");
					goto error;
				}
				if(!json_is_array(feeds) || json_array_size(feeds) == 0) {
					JANUS_LOG(LOG_ERR, "Invalid element (feeds should be a non-empty array)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (feeds should be a non-empty array)");
					goto error;
				}
				unsigned int i = 0;
				int error = 0;
				for(i=0; i<json_array_size(feeds); i++) {
					json_t *feed = json_array_get(feeds, i);
					if(!feed || !json_is_integer(feed)) {
						error = 1;
						break;
					}
					list = g_list_prepend(list, GUINT_TO_POINTER(json_integer_value(feed)));
				}
				if(error) {
					JANUS_LOG(LOG_ERR, "Invalid element (feeds in the array must be integers)\n");
					error_code = JANUS_VIDEOROOM_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (feeds in the array must be integers)");
					goto error;
				}
				list = g_list_reverse(list);
				if(janus_videoroom_muxed_unsubscribe(listener, list, msg->transaction) < 0) {
					JANUS_LOG(LOG_ERR, "Error subscribing!\n");
					error_code = JANUS_VIDEOROOM_ERROR_UNKNOWN_ERROR;	/* FIXME */
					sprintf(error_cause, "Error subscribing!");
					goto error;
				}
				continue;
			} else if(!strcasecmp(request_text, "start")) {
				/* Start/restart receiving the publishers streams */
				/* TODO */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(listener->room->room_id));
				json_object_set_new(event, "started", json_string("ok"));
				//~ /* Send a FIR */
				//~ char buf[20];
				//~ memset(buf, 0, 20);
				//~ if(!publisher->firefox)
					//~ janus_rtcp_fir((char *)&buf, 20, &publisher->fir_seq);
				//~ else
					//~ janus_rtcp_fir_legacy((char *)&buf, 20, &publisher->fir_seq);
				//~ JANUS_LOG(LOG_VERB, "Resuming publisher, sending FIR to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				//~ gateway->relay_rtcp(publisher->session->handle, 1, buf, 20);
				//~ /* Send a PLI too, just in case... */
				//~ memset(buf, 0, 12);
				//~ janus_rtcp_pli((char *)&buf, 12);
				//~ JANUS_LOG(LOG_VERB, "Resuming publisher, sending PLI to %"SCNu64" (%s)\n", publisher->user_id, publisher->display ? publisher->display : "??");
				//~ gateway->relay_rtcp(publisher->session->handle, 1, buf, 12);
			} else if(!strcasecmp(request_text, "pause")) {
				/* Stop receiving the publishers streams for a while */
				/* TODO */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(listener->room->room_id));
				json_object_set_new(event, "paused", json_string("ok"));
			} else if(!strcasecmp(request_text, "leave")) {
				/* TODO */
				event = json_object();
				json_object_set_new(event, "videoroom", json_string("event"));
				json_object_set_new(event, "room", json_integer(listener->room->room_id));
				json_object_set_new(event, "left", json_string("ok"));
				session->started = FALSE;
			} else {
				JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_REQUEST;
				sprintf(error_cause, "Unknown request '%s'", request_text);
				goto error;
			}
		}

		json_decref(root);
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
				/* We got an answer (from a listener?), no need to negotiate */
				int ret = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			} else {
				/* TODO We don't support anything else right now... */
				JANUS_LOG(LOG_ERR, "Unknown SDP type '%s'\n", msg->sdp_type);
				error_code = JANUS_VIDEOROOM_ERROR_INVALID_SDP_TYPE;
				sprintf(error_cause, "Unknown SDP type '%s'", msg->sdp_type);
				goto error;
			}
			if(session->participant_type == janus_videoroom_p_type_publisher) {
				/* This is a new publisher: is there room? */
				janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
				janus_videoroom *videoroom = participant->room;
				GList *participants_list = g_hash_table_get_values(videoroom->participants);
				GList *ps = participants_list;
				int count = 0;
				while(ps) {
					janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
					if(p != participant && p->sdp)
						count++;
					ps = ps->next;
				}
				if(count == videoroom->max_publishers) {
					g_list_free(participants_list);
					participant->audio_active = FALSE;
					participant->video_active = FALSE;
					JANUS_LOG(LOG_ERR, "Maximum number of publishers (%d) already reached\n", videoroom->max_publishers);
					error_code = JANUS_VIDEOROOM_ERROR_PUBLISHERS_FULL;
					sprintf(error_cause, "Maximum number of publishers (%d) already reached", videoroom->max_publishers);
					goto error;
				}
				/* Now prepare the SDP to give back */
				if(strstr(msg->sdp, "Mozilla")) {
					participant->firefox = TRUE;
				}
				/* Which media are available? */
				int audio = 0, video = 0;
				if(strstr(msg->sdp, "m=audio")) {
					audio++;
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to send an audio stream\n", audio ? "is" : "is NOT"); 
				if(strstr(msg->sdp, "m=video")) {
					video++;
				}
				JANUS_LOG(LOG_VERB, "The publisher %s going to send a video stream\n", video ? "is" : "is NOT"); 
				/* Also add a bandwidth SDP attribute if we're capping the bitrate in the room */
				int b = (int)(videoroom->bitrate/1000);
				char sdp[1024], audio_mline[256], video_mline[512];
				if(audio) {
					g_sprintf(audio_mline, sdp_a_template,
						OPUS_PT,						/* Opus payload type */
						"recvonly",						/* The publisher gets a recvonly back */
						OPUS_PT); 						/* Opus payload type */
				} else {
					audio_mline[0] = '\0';
				}
				if(video) {
					g_sprintf(video_mline, sdp_v_template,
						VP8_PT,							/* VP8 payload type */
						b,								/* Bandwidth */
						"recvonly",						/* The publisher gets a recvonly back */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT, 						/* VP8 payload type */
						VP8_PT); 						/* VP8 payload type */
				} else {
					video_mline[0] = '\0';
				}
				g_sprintf(sdp, sdp_template,
					janus_get_monotonic_time(),		/* We need current time here */
					janus_get_monotonic_time(),		/* We need current time here */
					participant->room->room_name,	/* Video room name */
					audio_mline,					/* Audio m-line, if any */
					video_mline);					/* Video m-line, if any */

				char *newsdp = g_strdup(sdp);
				if(video && b == 0) {
					/* Remove useless bandwidth attribute */
					newsdp = janus_string_replace(newsdp, "b=AS:0\r\n", "");
				}
				/* Is this room recorded? */
				if(videoroom->record) {
					char filename[255];
					memset(filename, 0, 255);
					sprintf(filename, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-audio",
						videoroom->room_id, participant->user_id, janus_get_monotonic_time());
					participant->arc = janus_recorder_create(videoroom->rec_dir, 0, filename);
					if(participant->arc == NULL) {
						JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this publisher!\n");
					}
					memset(filename, 0, 255);
					sprintf(filename, "videoroom-%"SCNu64"-user-%"SCNu64"-%"SCNi64"-video",
						videoroom->room_id, participant->user_id, janus_get_monotonic_time());
					participant->vrc = janus_recorder_create(videoroom->rec_dir, 1, filename);
					if(participant->vrc == NULL) {
						JANUS_LOG(LOG_ERR, "Couldn't open a video recording file for this publisher!\n");
					}
				}

				JANUS_LOG(LOG_VERB, "Handling publisher: turned this into an '%s':\n%s\n", type, newsdp);
				/* How long will the gateway take to push the event? */
				gint64 start = janus_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, type, newsdp);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
				newsdp = janus_string_replace(newsdp, "recvonly", "sendonly");
				if(res != JANUS_OK) {
					/* TODO Failed to negotiate? We should remove this publisher */
				} else {
					/* Store the participant's SDP for interested listeners */
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
					GList *participants_list = g_hash_table_get_values(participant->room->participants);
					GList *ps = participants_list;
					while(ps) {
						janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
						if(p == participant) {
							ps = ps->next;
							continue;	/* Skip the new publisher itself */
						}
						JANUS_LOG(LOG_VERB, "Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display ? p->display : "??");
						int ret = gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, pub_text, NULL, NULL);
						JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
						ps = ps->next;
					}
					g_list_free(participants_list);
					/* Let's wait for the setup_media event */
				}
			} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
				/* Negotiate by sending the selected publisher SDP back */
				janus_videoroom_listener *listener = (janus_videoroom_listener *)session->participant;
				/* FIXME We should handle the case where the participant has no SDP... */
				if(listener != NULL) {
					janus_videoroom_participant *feed = (janus_videoroom_participant *)listener->feed;
					if(feed != NULL && feed->sdp != NULL) {
						/* How long will the gateway take to push the event? */
						gint64 start = janus_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, type, feed->sdp);
						JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
						if(res != JANUS_OK) {
							/* TODO Failed to negotiate? We should remove this listener */
						} else {
							/* Let's wait for the setup_media event */
						}
					}
				}
			} else if(session->participant_type == janus_videoroom_p_type_subscriber_muxed) {
				/* FIXME We shouldn't be here, we always offer ourselves */
			}
		}
		g_free(event_text);
		janus_videoroom_message_free(msg);

		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
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
	JANUS_LOG(LOG_VERB, "Leaving thread\n");
	return NULL;
}


/* Multiplexing helpers */
int janus_videoroom_muxed_subscribe(janus_videoroom_listener_muxed *muxed_listener, GList *feeds, char *transaction) {
	if(!muxed_listener || !feeds)
		return -1;
	JANUS_LOG(LOG_INFO, "Subscribing to %d feeds\n", g_list_length(feeds));
	janus_videoroom *videoroom = muxed_listener->room;
	GList *ps = feeds;
	json_t *list = json_array();
	while(ps) {
		uint64_t feed_id = GPOINTER_TO_UINT(ps->data);
		janus_videoroom_participant *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(feed_id));
		if(publisher == NULL || publisher->sdp == NULL) {
			JANUS_LOG(LOG_WARN, "No such feed (%"SCNu64"), skipping\n", feed_id);
			ps = ps->next;
			continue;
		}
		janus_videoroom_listener *listener = calloc(1, sizeof(janus_videoroom_listener));
		if(listener == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ps = ps->next;
			continue;
		}
		listener->session = muxed_listener->session;
		listener->room = videoroom;
		listener->feed = publisher;
		//~ listener->paused = TRUE;	/* We need an explicit start from the listener */
		listener->paused = FALSE;
		listener->parent = muxed_listener;
		janus_mutex_lock(&publisher->listeners_mutex);
		publisher->listeners = g_slist_append(publisher->listeners, listener);
		janus_mutex_unlock(&publisher->listeners_mutex);
		janus_mutex_lock(&muxed_listener->listeners_mutex);
		muxed_listener->listeners = g_slist_append(muxed_listener->listeners, listener);
		janus_mutex_unlock(&muxed_listener->listeners_mutex);
		/* Add to feeds in the answer */
		json_t *f = json_object();
		json_object_set_new(f, "id", json_integer(feed_id));
		if(publisher->display)
			json_object_set_new(f, "display", json_string(publisher->display));
		json_array_append_new(list, f);
		ps = ps->next;
	}
	/* Prepare event */
	json_t *event = json_object();
	json_object_set_new(event, "videoroom", json_string("muxed-attached"));
	json_object_set_new(event, "room", json_integer(videoroom->room_id));
	json_object_set_new(event, "feeds", list);
	JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the updated offer */
	return janus_videoroom_muxed_offer(muxed_listener, transaction, event_text);
}

int janus_videoroom_muxed_unsubscribe(janus_videoroom_listener_muxed *muxed_listener, GList *feeds, char *transaction) {
	janus_videoroom *videoroom = muxed_listener->room;
	GList *ps = feeds;
	json_t *list = json_array();
	while(ps) {
		uint64_t feed_id = GPOINTER_TO_UINT(ps->data);
		GSList *ls = muxed_listener->listeners;
		while(ls) {
			janus_videoroom_listener *listener = (janus_videoroom_listener *)ls->data;
			if(listener) {
				janus_videoroom_participant *publisher = listener->feed;
				if(publisher != NULL) {
					janus_mutex_lock(&publisher->listeners_mutex);
					publisher->listeners = g_slist_remove(publisher->listeners, listener);
					janus_mutex_unlock(&publisher->listeners_mutex);
					listener->feed = NULL;
				}
				janus_mutex_lock(&muxed_listener->listeners_mutex);
				muxed_listener->listeners = g_slist_remove(muxed_listener->listeners, listener);
				janus_mutex_unlock(&muxed_listener->listeners_mutex);
				/* Add to feeds in the answer */
				json_t *f = json_object();
				json_object_set_new(f, "id", json_integer(feed_id));
				if(publisher->display)
					json_object_set_new(f, "display", json_string(publisher->display));
				json_array_append_new(list, f);
				break;
			}
			ls = ls->next;
		}
		ps = ps->next;
	}
	/* Prepare event */
	json_t *event = json_object();
	json_object_set_new(event, "videoroom", json_string("muxed-detached"));
	json_object_set_new(event, "room", json_integer(videoroom->room_id));
	json_object_set_new(event, "feeds", list);
	JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the updated offer */
	return janus_videoroom_muxed_offer(muxed_listener, transaction, event_text);
}

int janus_videoroom_muxed_offer(janus_videoroom_listener_muxed *muxed_listener, char *transaction, char *event_text) {
	if(muxed_listener == NULL)
		return -1;
	/* Negotiate by placing a 'muxed' fake attribute for each publisher we subscribed to,
	 * that will translate to multiple SSRCs when merging the SDP */
	int audio = 0, video = 0;
	char audio_muxed[1024], video_muxed[1024], temp[255];
	memset(audio_muxed, 0, 1024);
	memset(video_muxed, 0, 1024);
	GSList *ps = muxed_listener->listeners;
	while(ps) {
		janus_videoroom_listener *l = (janus_videoroom_listener *)ps->data;
		if(l && l->feed && l->feed->sdp) {
			if(strstr(l->feed->sdp, "m=audio")) {
				audio++;
				g_sprintf(temp, "a=planb:mcu%"SCNu64" %"SCNu32"\r\n", l->feed->user_id, l->feed->audio_ssrc);
				g_strlcat(audio_muxed, temp, 1024);
			}
			if(strstr(l->feed->sdp, "m=video")) {
				video++;
				g_sprintf(temp, "a=planb:mcu%"SCNu64" %"SCNu32"\r\n", l->feed->user_id, l->feed->video_ssrc);
				g_strlcat(video_muxed, temp, 1024);
			}
		}
		ps = ps->next;
	}
	/* Also add a bandwidth SDP attribute if we're capping the bitrate in the room */
	char sdp[2048], audio_mline[256], video_mline[512];
	if(audio) {
		g_sprintf(audio_mline, sdp_a_template,
			OPUS_PT,						/* Opus payload type */
			"sendonly",						/* The publisher gets a recvonly back */
			OPUS_PT); 						/* Opus payload type */
		g_strlcat(audio_mline, audio_muxed, 2048);
	} else {
		audio_mline[0] = '\0';
	}
	if(video) {
		g_sprintf(video_mline, sdp_v_template,
			VP8_PT,							/* VP8 payload type */
			0,								/* Bandwidth */
			"sendonly",						/* The publisher gets a recvonly back */
			VP8_PT, 						/* VP8 payload type */
			VP8_PT, 						/* VP8 payload type */
			VP8_PT, 						/* VP8 payload type */
			VP8_PT, 						/* VP8 payload type */
			VP8_PT); 						/* VP8 payload type */
		g_strlcat(video_mline, video_muxed, 2048);
	} else {
		video_mline[0] = '\0';
	}
	g_sprintf(sdp, sdp_template,
		janus_get_monotonic_time(),		/* We need current time here */
		janus_get_monotonic_time(),		/* We need current time here */
		muxed_listener->room->room_name,	/* Video room name */
		audio_mline,					/* Audio m-line, if any */
		video_mline);					/* Video m-line, if any */
	char *newsdp = g_strdup(sdp);
	if(video) {
		/* Remove useless bandwidth attribute */
		newsdp = janus_string_replace(newsdp, "b=AS:0\r\n", "");
	}
	/* How long will the gateway take to push the event? */
	gint64 start = janus_get_monotonic_time();
	int res = gateway->push_event(muxed_listener->session->handle, &janus_videoroom_plugin, transaction, event_text, "offer", newsdp);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
	if(res != JANUS_OK) {
		/* TODO Failed to negotiate? We should remove this listener */
	} else {
		/* Let's wait for the setup_media event */
	}
	return 0;
}


/* Helper to quickly relay RTP packets from publishers to subscribers */
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_videoroom_rtp_relay_packet *packet = (janus_videoroom_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_videoroom_listener *listener = (janus_videoroom_listener *)data;
	if(!listener || !listener->session) {
		// JANUS_LOG(LOG_ERR, "Invalid session...\n");
		return;
	}
	if(listener->paused) {
		// JANUS_LOG(LOG_ERR, "This listener paused the stream...\n");
		return;
	}
	janus_videoroom_session *session = listener->session;
	if(!session || !session->handle) {
		// JANUS_LOG(LOG_ERR, "Invalid session...\n");
		return;
	}
	if(!session->started) {
		// JANUS_LOG(LOG_ERR, "Streaming not started yet for this session...\n");
		return;
	}
	if(gateway != NULL)	/* FIXME What about RTCP? */
		gateway->relay_rtp(session->handle, packet->is_video, (char *)packet->data, packet->length);
	return;
}


/* Helper to free janus_videoroom structs. */
static void janus_videoroom_free(janus_videoroom *room)
{
	g_free(room->room_name);
	g_free(room->room_secret);
	g_free(room->rec_dir);
	g_hash_table_unref(room->participants);

	free(room);
}

static void janus_videoroom_listener_free(janus_videoroom_listener *l)
{
	free(l);
}

static void janus_videoroom_participant_free(janus_videoroom_participant *p)
{
	g_free(p->display);
	g_free(p->sdp);

	if (p->arc) {
		janus_recorder_free(p->arc);
	}
	if (p->vrc) {
		janus_recorder_free(p->vrc);
	}

	g_slist_free_full(p->listeners,
	                  (GDestroyNotify) janus_videoroom_listener_free);

	janus_mutex_destroy(&p->listeners_mutex);

	free(p);
}
