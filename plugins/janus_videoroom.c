/*! \file   janus_videoroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
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
 * Considering that this plugin allows for several different WebRTC PeerConnections
 * to be on at the same time for the same peer (specifically, each peer
 * potentially has 1 PeerConnection on for publishing and N on for subscriptions
 * from other peers), each peer may need to attach several times to the same
 * plugin for every stream: this means that each peer needs to have at least one
 * handle active for managing its relation with the plugin (joining a room,
 * leaving a room, muting/unmuting, publishing, receiving events), and needs
 * to open a new one each time he/she wants to subscribe to a feed from
 * another participant. The handle used for a subscription, however, would
 * be logically a "slave" to the master one used for managing the room: this
 * means that it cannot be used, for instance, to unmute in the room, as its
 * only purpose would be to provide a context in which creating the sendonly
 * PeerConnection for the subscription to the active participant.
 * 
 * Rooms to make available are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.videoroom.cfg
 * and includes a demo room for testing.
 * 
 * To add more rooms or modify the existing one, you can use the following
 * syntax:
 * 
 * \verbatim
[<unique room ID>]
description = This is my awesome room
publishers = <max number of concurrent senders> (e.g., 6 for a video
             conference or 1 for a webinar)
bitrate = <max video bitrate for senders> (e.g., 128000)
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../config.h"
#include "../rtcp.h"


/* Plugin information */
#define JANUS_VIDEOROOM_VERSION			1
#define JANUS_VIDEOROOM_VERSION_STRING	"0.0.1"
#define JANUS_VIDEOROOM_DESCRIPTION		"This is a plugin implementing a videoconferencing MCU for Janus, something like Licode."
#define JANUS_VIDEOROOM_NAME			"JANUS VideoRoom plugin"
#define JANUS_VIDEOROOM_PACKAGE			"janus.plugin.videoroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_videoroom_init(janus_callbacks *callback, const char *config_path);
void janus_videoroom_destroy(void);
int janus_videoroom_get_version(void);
const char *janus_videoroom_get_version_string(void);
const char *janus_videoroom_get_description(void);
const char *janus_videoroom_get_name(void);
const char *janus_videoroom_get_package(void);
void janus_videoroom_create_session(janus_pluginession *handle, int *error);
void janus_videoroom_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_videoroom_setup_media(janus_pluginession *handle);
void janus_videoroom_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len);
void janus_videoroom_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len);
void janus_videoroom_hangup_media(janus_pluginession *handle);
void janus_videoroom_destroy_session(janus_pluginession *handle, int *error);

/* Plugin setup */
static janus_plugin janus_videoroom_plugin =
	{
		.init = janus_videoroom_init,
		.destroy = janus_videoroom_destroy,

		.get_version = janus_videoroom_get_version,
		.get_version_string = janus_videoroom_get_version_string,
		.get_description = janus_videoroom_get_description,
		.get_name = janus_videoroom_get_name,
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
	JANUS_PRINT("%s created!\n", JANUS_VIDEOROOM_NAME);
	return &janus_videoroom_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videoroom_handler(void *data);
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data);
char *string_replace(char *message, char *old, char *new, int *modified);

typedef enum janus_videoroom_p_type {
	janus_videoroom_p_type_none = 0,
	janus_videoroom_p_type_subscriber,
	janus_videoroom_p_type_publisher,
} janus_videoroom_p_type;

typedef struct janus_videoroom_message {
	janus_pluginession *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_videoroom_message;
GQueue *messages;

typedef struct janus_videoroom {
	guint64 room_id;	/* Unique room ID */
	gchar *room_name;	/* Room description */
	int max_publishers;	/* Maximum number of concurrent publishers */
	uint64_t bitrate;	/* Global bitrate limit */
	gboolean destroy;
	GHashTable *participants;	/* Map of potential publishers (we get listeners from them) */
} janus_videoroom;
GHashTable *rooms;

typedef struct janus_videoroom_session {
	janus_pluginession *handle;
	janus_videoroom_p_type participant_type;
	gpointer participant;
	gboolean started;
	gboolean stopping;
	gboolean destroy;
} janus_videoroom_session;
GHashTable *sessions;

typedef struct janus_videoroom_participant {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	guint64 user_id;	/* Unique ID in the room */
	gchar *display;	/* Display name (just for fun) */
	gchar *sdp;			/* The SDP this publisher negotiated, if any */
	gboolean audio_active;
	gboolean video_active;
	uint64_t bitrate;
	gint64 fir_latest;	/* Time of latest sent FIR (to avoid flooding) */
	gint fir_seq;		/* FIR sequence number */
	GSList *listeners;
} janus_videoroom_participant;

typedef struct janus_videoroom_listener {
	janus_videoroom_session *session;
	janus_videoroom *room;	/* Room */
	janus_videoroom_participant *feed;	/* Participant this listener is subscribed to */
	gboolean paused;
} janus_videoroom_listener;

typedef struct janus_videoroom_rtp_relay_packet {
	char *data;
	gint length;
	gint is_video;
} janus_videoroom_rtp_relay_packet;


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
	JANUS_PRINT("Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	rooms = g_hash_table_new(NULL, NULL);
	sessions = g_hash_table_new(NULL, NULL);
	messages = g_queue_new();
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
			JANUS_PRINT("Adding video room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get_item(cat, "description");
			janus_config_item *bitrate = janus_config_get_item(cat, "bitrate");
			janus_config_item *maxp = janus_config_get_item(cat, "publishers");
			/* Create the video mcu room */
			janus_videoroom *videoroom = calloc(1, sizeof(janus_videoroom));
			if(videoroom == NULL) {
				JANUS_DEBUG("Memory error!\n");
				continue;
			}
			videoroom->room_id = atoi(cat->name);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			if(description == NULL) {
				JANUS_DEBUG("Memory error!\n");
				continue;
			}
			videoroom->room_name = description;
			videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			if(maxp != NULL && maxp->value != NULL)
				videoroom->max_publishers = atol(maxp->value);
			if(videoroom->max_publishers < 0)
				videoroom->max_publishers = 3;	/* FIXME How should we choose a default? */
			videoroom->bitrate = 0;
			if(bitrate != NULL && bitrate->value != NULL)
				videoroom->bitrate = atol(bitrate->value);
			videoroom->destroy = 0;
			videoroom->participants = g_hash_table_new(NULL, NULL);
			g_hash_table_insert(rooms, GUINT_TO_POINTER(videoroom->room_id), videoroom);
			JANUS_PRINT("Created videoroom: %"SCNu64" (%s)\n", videoroom->room_id, videoroom->room_name);
			cat = cat->next;
		}
		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}

	/* Show available rooms */
	GList *rooms_list = g_hash_table_get_values(rooms);
	GList *r = rooms_list;
	while(r) {
		janus_videoroom *vr = (janus_videoroom *)r->data;
		JANUS_PRINT("  ::: [%"SCNu64"][%s] %"SCNu64", max %d publishers\n", vr->room_id, vr->room_name, vr->bitrate, vr->max_publishers);
		r = r->next;
	}
	g_list_free(rooms_list);

	initialized = 1;
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus videoroom handler", janus_videoroom_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_DEBUG("Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_PRINT("%s initialized!\n", JANUS_VIDEOROOM_NAME);
	return 0;
}

void janus_videoroom_destroy() {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	/* TODO Actually remove rooms and its participants */
	g_hash_table_destroy(sessions);
	g_hash_table_destroy(rooms);
	g_queue_free(messages);
	rooms = NULL;
	initialized = 0;
	stopping = 0;
	JANUS_PRINT("%s destroyed!\n", JANUS_VIDEOROOM_NAME);
}

int janus_videoroom_get_version() {
	return JANUS_VIDEOROOM_VERSION;
}

const char *janus_videoroom_get_version_string() {
	return JANUS_VIDEOROOM_VERSION_STRING;
}

const char *janus_videoroom_get_description() {
	return JANUS_VIDEOROOM_DESCRIPTION;
}

const char *janus_videoroom_get_name() {
	return JANUS_VIDEOROOM_NAME;
}

const char *janus_videoroom_get_package() {
	return JANUS_VIDEOROOM_PACKAGE;
}

void janus_videoroom_create_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)calloc(1, sizeof(janus_videoroom_session));
	if(session == NULL) {
		JANUS_DEBUG("Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->participant_type = janus_videoroom_p_type_none;
	session->participant = NULL;
	handle->plugin_handle = session;
	g_hash_table_insert(sessions, handle, session);

	return;
}

void janus_videoroom_destroy_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroy) {
		JANUS_PRINT("Session already destroyed...\n");
		g_free(session);
		return;
	}
	JANUS_PRINT("Removing Video Room session...\n");
	/* TODO Actually clean up session, e.g., removing listener from publisher and viceversa */
	g_hash_table_remove(sessions, handle);
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* TODO Get rid of this publisher and its listeners */
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* TODO Detach this listener from its subscriber */
	}
	janus_videoroom_hangup_media(handle);
	session->destroy = TRUE;
	g_free(session);

	return;
}

void janus_videoroom_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_PRINT("%s\n", message);
	janus_videoroom_message *msg = calloc(1, sizeof(janus_videoroom_message));
	if(msg == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->transaction = transaction ? g_strdup(transaction) : NULL;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_queue_push_tail(messages, msg);
}

void janus_videoroom_setup_media(janus_pluginession *handle) {
	JANUS_DEBUG("WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* Media relaying can start now */
	session->started = TRUE;
	/* If this is a listener, ask the publisher a FIR */
	if(session->participant && session->participant_type == janus_videoroom_p_type_subscriber) {
		janus_videoroom_listener *l = (janus_videoroom_listener *)session->participant;
		if(l && l->feed) {
			janus_videoroom_participant *p = l->feed;
			if(p && p->session) {
				/* Send a FIR */
				char buf[20];
				memset(buf, 0, 20);
				janus_rtcp_fir((char *)&buf, 20, &p->fir_seq);
				JANUS_PRINT("New listener available, sending FIR to %s\n", p->display);
				gateway->relay_rtcp(p->session->handle, 1, buf, 20);
				/* Send a PLI too, just in case... */
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				JANUS_PRINT("New listener available, sending PLI to %s\n", p->display);
				gateway->relay_rtcp(p->session->handle, 1, buf, 12);
			}
		}
	}
}

void janus_videoroom_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || session->destroy || !session->participant || session->participant_type != janus_videoroom_p_type_publisher)
		return;
	janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
	if((!video && participant->audio_active) || (video && participant->video_active)) {
		janus_videoroom_rtp_relay_packet packet;
		packet.data = buf;
		packet.length = len;
		packet.is_video = video;
		g_slist_foreach(participant->listeners, janus_videoroom_relay_rtp_packet, &packet);
		if(video) {
			/* FIXME Very ugly hack to generate RTCP every tot seconds/frames */
			gint64 now = g_get_monotonic_time();
			if((now-participant->fir_latest) >= (10*G_USEC_PER_SEC)) {
				/* FIXME We send a FIR every 10 seconds */
				participant->fir_latest = now;
				char buf[20];
				memset(buf, 0, 20);
				janus_rtcp_fir((char *)&buf, 20, &participant->fir_seq);
				JANUS_PRINT("Sending FIR to %s\n", participant->display);
				gateway->relay_rtcp(handle, video, buf, 20);
				/* Send a PLI too, just in case... */
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				JANUS_PRINT("New listener available, sending PLI to %s\n", participant->display);
				gateway->relay_rtcp(handle, video, buf, 12);
			}
		}
	}
}

void janus_videoroom_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized || !gateway)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;
	if(!session || session->destroy || !session->participant || !video)
		return;
	if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* FIXME Badly: we're blinding forwarding the listener RTCP t the publisher: this probably means confusing him... */
		janus_videoroom_listener *l = (janus_videoroom_listener *)session->participant;
		if(l && l->feed) {
			janus_videoroom_participant *p = l->feed;
			if(p && p->session) {
				gateway->relay_rtcp(p->session->handle, 1, buf, 20);
			}
		}
	} else if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* FIXME Badly: we're just bouncing the incoming RTCP back with modified REMB, we need to improve this... */
		janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
		if(participant->bitrate > 0)
			janus_rtcp_cap_remb(buf, len, participant->bitrate);
		gateway->relay_rtcp(handle, video, buf, len);
	}
}

void janus_videoroom_hangup_media(janus_pluginession *handle) {
	JANUS_PRINT("No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_videoroom_session *session = (janus_videoroom_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* Send an event to the browser and tell it's over */
	if(session->participant_type == janus_videoroom_p_type_publisher) {
		/* Get rid of publisher */
		janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
		json_t *event = json_object();
		json_object_set(event, "videoroom", json_string("event"));
		json_object_set(event, "room", json_integer(participant->room->room_id));
		json_object_set(event, "leaving", json_integer(participant->user_id));
		char *leaving_text = json_dumps(event, JSON_INDENT(3));
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
			JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
			JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, leaving_text, NULL, NULL));
			ps = ps->next;
		}
		g_free(leaving_text);
		g_list_free(participants_list);
	} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
		/* Get rid of listener */
		janus_videoroom_listener *listener = (janus_videoroom_listener *)session->participant;
		janus_videoroom_participant *publisher = listener->feed;
		if(publisher != NULL) {
			publisher->listeners = g_slist_remove(publisher->listeners, listener);
			listener->feed = NULL;
		}
	}
}

/* Thread to handle incoming messages */
static void *janus_videoroom_handler(void *data) {
	JANUS_DEBUG("Joining thread\n");
	janus_videoroom_message *msg = NULL;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	while(initialized && !stopping) {
		if(!messages || (msg = g_queue_pop_head(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_videoroom_session *session = (janus_videoroom_session *)msg->handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			continue;
		}
		if(session->destroy)
			continue;
		/* Handle request */
		JANUS_PRINT("Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_DEBUG("No message??\n");
			sprintf(error_cause, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		json_t *root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_DEBUG("JSON error: on line %d: %s\n", error.line, error.text);
			sprintf(error_cause, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_DEBUG("JSON error: not an object\n");
			sprintf(error_cause, "JSON error: not an object");
			goto error;
		}
		/* Get the request first */
		json_t *request = json_object_get(root, "request");
		if(!request || !json_is_string(request)) {
			JANUS_DEBUG("JSON error: invalid element (request)\n");
			sprintf(error_cause, "JSON error: invalid element (request)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		/* What kind of participant is this session referring to? */
		if(session->participant_type == janus_videoroom_p_type_none) {
			JANUS_PRINT("Configuring new participant\n");
			/* Not configured yet, we need to do this now */
			if(strcasecmp(request_text, "join")) {
				JANUS_DEBUG("Invalid request on unconfigured participant\n");
				sprintf(error_cause, "Invalid request on unconfigured participant");
				goto error;
			}
			json_t *room = json_object_get(root, "room");
			if(!room || !json_is_integer(room)) {
				JANUS_DEBUG("JSON error: invalid element (room)\n");
				sprintf(error_cause, "JSON error: invalid element (room)");
				goto error;
			}
			guint64 room_id = json_integer_value(room);
			janus_videoroom *videoroom = g_hash_table_lookup(rooms, GUINT_TO_POINTER(room_id));
			if(videoroom == NULL) {
				JANUS_DEBUG("No such room (%"SCNu64")\n", room_id);
				sprintf(error_cause, "No such room (%"SCNu64")", room_id);
				goto error;
			}
			json_t *ptype = json_object_get(root, "ptype");
			if(!ptype || !json_is_string(ptype)) {
				JANUS_DEBUG("JSON error: invalid element (ptype)\n");
				sprintf(error_cause, "JSON error: invalid element (ptype)");
				goto error;
			}
			const char *ptype_text = json_string_value(ptype);
			if(!strcasecmp(ptype_text, "publisher")) {
				JANUS_PRINT("Configuring new publisher\n");
				/* This is a new publisher: is there room? */
				GList *participants_list = g_hash_table_get_values(videoroom->participants);
				if(g_list_length(participants_list) == videoroom->max_publishers) {
					JANUS_DEBUG("Maximum number of publishers (%d) already reached\n", videoroom->max_publishers);
					sprintf(error_cause, "Maximum number of publishers (%d) already reached", videoroom->max_publishers);
					g_list_free(participants_list);
					goto error;
				}
				g_list_free(participants_list);
				json_t *display = json_object_get(root, "display");
				if(!display || !json_is_string(display)) {
					JANUS_DEBUG("JSON error: invalid element (display)\n");
					sprintf(error_cause, "JSON error: invalid element (display)");
					goto error;
				}
				const char *display_text = json_string_value(display);
				/* Generate a random ID */
				guint64 user_id = 0;
				while(user_id == 0) {
					user_id = g_random_int();
					if(g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(user_id)) != NULL) {
						/* User ID already taken, try another one */
						user_id = 0;
					}
				}
				JANUS_PRINT("  -- Publisher ID: %"SCNu64"\n", user_id);
				janus_videoroom_participant *publisher = calloc(1, sizeof(janus_videoroom_participant));
				if(publisher == NULL) {
					JANUS_DEBUG("Memory error!\n");
					sprintf(error_cause, "Memory error");
					goto error;
				}
				publisher->session = session;
				publisher->room = videoroom;
				publisher->user_id = user_id;
				publisher->display = g_strdup(display_text);
				if(publisher->display == NULL) {
					JANUS_DEBUG("Memory error!\n");
					sprintf(error_cause, "Memory error");
					g_free(publisher);
					goto error;
				}
				publisher->sdp = NULL;	/* We'll deal with this later */
				publisher->audio_active = FALSE;
				publisher->video_active = FALSE;
				publisher->bitrate = videoroom->bitrate;
				publisher->listeners = NULL;
				publisher->fir_latest = 0;
				publisher->fir_seq = 0;
				/* Done */
				session->participant_type = janus_videoroom_p_type_publisher;
				session->participant = publisher;
				g_hash_table_insert(videoroom->participants, GUINT_TO_POINTER(user_id), publisher);
				/* Return a list of all available publishers (those with an SDP available, that is) */
				json_t *list = json_array();
				participants_list = g_hash_table_get_values(videoroom->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
					if(p == publisher || !p->sdp) {
						ps = ps->next;
						continue;
					}
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(p->user_id));
					json_object_set_new(pl, "display", json_string(p->display));
					json_array_append_new(list, pl);
					ps = ps->next;
				}
				event = json_object();
				json_object_set(event, "videoroom", json_string("joined"));
				json_object_set(event, "room", json_integer(videoroom->room_id));
				json_object_set(event, "id", json_integer(user_id));
				json_object_set_new(event, "publishers", list);
				g_list_free(participants_list);
			} else if(!strcasecmp(ptype_text, "listener")) {
				JANUS_PRINT("Configuring new listener\n");
				/* This is a new listener */
				json_t *feed = json_object_get(root, "feed");
				if(!feed || !json_is_integer(feed)) {
					JANUS_DEBUG("JSON error: invalid element (feed)\n");
					sprintf(error_cause, "JSON error: invalid element (feed)");
					goto error;
				}
				guint64 feed_id = json_integer_value(feed);
				janus_videoroom_participant *publisher = g_hash_table_lookup(videoroom->participants, GUINT_TO_POINTER(feed_id));
				if(publisher == NULL || publisher->sdp == NULL) {
					JANUS_DEBUG("No such feed (%"SCNu64")\n", feed_id);
					sprintf(error_cause, "No such feed (%"SCNu64")", feed_id);
					goto error;
				} else {
					janus_videoroom_listener *listener = calloc(1, sizeof(janus_videoroom_listener));
					if(listener == NULL) {
						JANUS_DEBUG("Memory error!\n");
						sprintf(error_cause, "Memory error");
						goto error;
					}
					listener->session = session;
					listener->room = videoroom;
					listener->feed = publisher;
					listener->paused = TRUE;	/* We need an explicit start from the listener */
					session->participant = listener;
					publisher->listeners = g_slist_append(publisher->listeners, listener);
					event = json_object();
					json_object_set(event, "videoroom", json_string("attached"));
					json_object_set(event, "room", json_integer(videoroom->room_id));
					json_object_set(event, "id", json_integer(feed_id));
					json_object_set(event, "display", json_string(publisher->display));
					session->participant_type = janus_videoroom_p_type_subscriber;
					JANUS_PRINT("Preparing JSON event as a reply\n");
					char *event_text = json_dumps(event, JSON_INDENT(3));
					json_decref(event);
					/* Negotiate by sending the selected publisher SDP back */
					if(publisher->sdp != NULL) {
						/* How long will the gateway take to push the event? */
						gint64 start = g_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, "offer", publisher->sdp);
						JANUS_PRINT("  >> Pushing event: %d (took %"SCNu64" ms)\n", res, g_get_monotonic_time()-start);
						if(res != JANUS_OK) {
							/* TODO Failed to negotiate? We should remove this listener */
						} else {
							/* Let's wait for the setup_media event */
						}
						continue;
					}
				}
			} else {
				JANUS_DEBUG("JSON error: invalid element (ptype)\n");
				sprintf(error_cause, "JSON error: invalid element (ptype)");
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_publisher) {
			/* Handle this publisher */
			janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant; 
			if(!strcasecmp(request_text, "configure")) {
				/* Configure audio/video/bitrate for this publisher */
				json_t *audio = json_object_get(root, "audio");
				if(audio && !json_is_boolean(audio)) {
					JANUS_DEBUG("JSON error: invalid element (audio)\n");
					sprintf(error_cause, "JSON error: invalid value (audio)");
					goto error;
				}
				json_t *video = json_object_get(root, "video");
				if(video && !json_is_boolean(video)) {
					JANUS_DEBUG("JSON error: invalid element (video)\n");
					sprintf(error_cause, "JSON error: invalid value (video)");
					goto error;
				}
				json_t *bitrate = json_object_get(root, "bitrate");
				if(bitrate && !json_is_integer(bitrate)) {
					JANUS_DEBUG("JSON error: invalid element (bitrate)\n");
					sprintf(error_cause, "JSON error: invalid value (bitrate)");
					goto error;
				}
				if(audio) {
					participant->audio_active = json_is_true(audio);
					JANUS_PRINT("Setting audio property: %s (room %"SCNu64", user %"SCNu64")\n", participant->audio_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(video) {
					participant->video_active = json_is_true(video);
					JANUS_PRINT("Setting video property: %s (room %"SCNu64", user %"SCNu64")\n", participant->video_active ? "true" : "false", participant->room->room_id, participant->user_id);
				}
				if(bitrate) {
					participant->bitrate = json_integer_value(bitrate);
					JANUS_PRINT("Setting video bitrate: %"SCNu64" (room %"SCNu64", user %"SCNu64")\n", participant->bitrate, participant->room->room_id, participant->user_id);
				}
				/* Done */
				event = json_object();
				json_object_set(event, "videoroom", json_string("event"));
				json_object_set(event, "room", json_integer(participant->room->room_id));
				json_object_set(event, "result", json_string("ok"));
			} else if(!strcasecmp(request_text, "leave")) {
				/* This publisher is leaving, tell everybody */
				event = json_object();
				json_object_set(event, "videoroom", json_string("event"));
				json_object_set(event, "room", json_integer(participant->room->room_id));
				json_object_set(event, "leaving", json_integer(participant->user_id));
				char *leaving_text = json_dumps(event, JSON_INDENT(3));
				GList *participants_list = g_hash_table_get_values(participant->room->participants);
				GList *ps = participants_list;
				while(ps) {
					janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
					if(p == participant) {
						ps = ps->next;
						continue;	/* Skip the new publisher itself */
					}
					JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
					JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, leaving_text, NULL, NULL));
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
				JANUS_DEBUG("Unknown request '%s'\n", request_text);
				sprintf(error_cause, "Unknown request '%s'", request_text);
				goto error;
			}
		} else if(session->participant_type == janus_videoroom_p_type_subscriber) {
			/* Handle this listener */
			janus_videoroom_listener *listener = (janus_videoroom_listener *)session->participant;
			if(!strcasecmp(request_text, "start")) {
				/* Start/restart receiving the publisher streams */
				listener->paused = FALSE;
			} else if(!strcasecmp(request_text, "pause")) {
				/* Stop receiving the publisher streams for a while */
				listener->paused = TRUE;
			} else if(!strcasecmp(request_text, "leave")) {
				janus_videoroom_participant *publisher = listener->feed;
				if(publisher != NULL) {
					publisher->listeners = g_slist_remove(publisher->listeners, listener);
					listener->feed = NULL;
				}
				event = json_object();
				json_object_set(event, "videoroom", json_string("event"));
				json_object_set(event, "room", json_integer(publisher->room->room_id));
				json_object_set(event, "result", json_string("ok"));
				session->started = FALSE;
			} else {
				JANUS_DEBUG("Unknown request '%s'\n", request_text);
				sprintf(error_cause, "Unknown request '%s'", request_text);
				goto error;
			}
		}

		/* Prepare JSON event */
		JANUS_PRINT("Preparing JSON event as a reply\n");
		char *event_text = json_dumps(event, JSON_INDENT(3));
		json_decref(event);
		/* Any SDP to handle? */
		if(!msg->sdp) {
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL));
		} else {
			JANUS_PRINT("This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer")) {
				/* We need to answer */
				type = "answer";
			} else if(!strcasecmp(msg->sdp_type, "answer")) {
				/* We got an answer (from a listener?), no need to negotiate */
				JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL));
			} else {
				/* TODO We don't support anything else right now... */
				JANUS_DEBUG("Unknown SDP type '%s'\n", msg->sdp_type);
				sprintf(error_cause, "Unknown SDP type '%s'", msg->sdp_type);
				goto error;
			}
			if(session->participant_type == janus_videoroom_p_type_publisher) {
				/* Negotiate by sending the own publisher SDP back (just to negotiate the same media stuff) */
				int modified = 0;
				msg->sdp = string_replace(msg->sdp, "sendrecv", "sendonly", &modified);	/* FIXME In case the browser doesn't set it correctly */
				msg->sdp = string_replace(msg->sdp, "sendonly", "recvonly", &modified);
				janus_videoroom_participant *participant = (janus_videoroom_participant *)session->participant;
				/* How long will the gateway take to push the event? */
				gint64 start = g_get_monotonic_time();
				int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, type, msg->sdp);
				JANUS_PRINT("  >> Pushing event: %d (took %"SCNu64" ms)\n", res, g_get_monotonic_time()-start);
				msg->sdp = string_replace(msg->sdp, "recvonly", "sendonly", &modified);
				if(res != JANUS_OK) {
					/* TODO Failed to negotiate? We should remove this publisher */
				} else {
					/* Store the participant's SDP for interested listeners */
					participant->sdp = g_strdup(msg->sdp);
					/* Notify all other participants that there's a new boy in town */
					json_t *list = json_array();
					json_t *pl = json_object();
					json_object_set_new(pl, "id", json_integer(participant->user_id));
					json_object_set_new(pl, "display", json_string(participant->display));
					json_array_append_new(list, pl);
					json_t *pub = json_object();
					json_object_set(pub, "videoroom", json_string("event"));
					json_object_set(event, "room", json_integer(participant->room->room_id));
					json_object_set_new(pub, "publishers", list);
					char *pub_text = json_dumps(pub, JSON_INDENT(3));
					json_decref(list);
					json_decref(pub);
					GList *participants_list = g_hash_table_get_values(participant->room->participants);
					GList *ps = participants_list;
					while(ps) {
						janus_videoroom_participant *p = (janus_videoroom_participant *)ps->data;
						if(p == participant) {
							ps = ps->next;
							continue;	/* Skip the new publisher itself */
						}
						JANUS_PRINT("Notifying participant %"SCNu64" (%s)\n", p->user_id, p->display);
						JANUS_PRINT("  >> %d\n", gateway->push_event(p->session->handle, &janus_videoroom_plugin, NULL, pub_text, NULL, NULL));
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
						gint64 start = g_get_monotonic_time();
						int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, type, feed->sdp);
						JANUS_PRINT("  >> Pushing event: %d (took %"SCNu64" ms)\n", res, g_get_monotonic_time()-start);
						if(res != JANUS_OK) {
							/* TODO Failed to negotiate? We should remove this listener */
						} else {
							/* Let's wait for the setup_media event */
						}
					}
				}
			}
		}

		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set(event, "videoroom", json_string("event"));
			json_object_set(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3));
			json_decref(event);
			JANUS_PRINT("Pushing event: %s\n", event_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event_text, NULL, NULL));
		}
	}
	JANUS_DEBUG("Leaving thread\n");
	return NULL;
}

static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_videoroom_rtp_relay_packet *packet = (janus_videoroom_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_PRINT("Invalid packet...\n");
		return;
	}
	janus_videoroom_listener *listener = (janus_videoroom_listener *)data;
	if(!listener || !listener->session) {
		// JANUS_PRINT("Invalid session...\n");
		return;
	}
	if(listener->paused) {
		// JANUS_PRINT("This listener paused the stream...\n");
		return;
	}
	janus_videoroom_session *session = listener->session;
	if(!session || !session->handle) {
		// JANUS_PRINT("Invalid session...\n");
		return;
	}
	if(!session->started) {
		// JANUS_PRINT("Streaming not started yet for this session...\n");
		return;
	}
	if(gateway != NULL)	/* FIXME What about RTCP? */
		gateway->relay_rtp(session->handle, packet->is_video, (char *)packet->data, packet->length);
	return;
}

/* Easy way to replace multiple occurrences of a string with another: ALWAYS creates a NEW string */
char *string_replace(char *message, char *old, char *new, int *modified)
{
	if(!message || !old || !new || !modified)
		return NULL;
	*modified = 0;
	if(!strstr(message, old)) {	/* Nothing to be done (old is not there) */
		return message;
	}
	if(!strcmp(old, new)) {	/* Nothing to be done (old=new) */
		return message;
	}
	if(strlen(old) == strlen(new)) {	/* Just overwrite */
		char *outgoing = message;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		int i = 0;
		while(pos) {
			i++;
			memcpy(pos, new, strlen(new));
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		return outgoing;
	} else {	/* We need to resize */
		*modified = 1;
		char *outgoing = strdup(message);
		if(outgoing == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		int diff = strlen(new) - strlen(old);
		/* Count occurrences */
		int counter = 0;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		while(pos) {
			counter++;
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		uint16_t oldlen = strlen(outgoing)+1, newlen = oldlen + diff*counter;
		*modified = diff*counter;
		if(diff > 0) {	/* Resize now */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		/* Replace string */
		pos = strstr(outgoing, old);
		while(pos) {
			if(diff > 0) {	/* Move to the right (new is larger than old) */
				uint16_t len = strlen(pos)+1;
				memmove(pos + diff, pos, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(new);
				tmp = strstr(pos, old);
			} else {	/* Move to the left (new is smaller than old) */
				uint16_t len = strlen(pos - diff)+1;
				memmove(pos, pos - diff, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(old);
				tmp = strstr(pos, old);
			}
			pos = tmp;
		}
		if(diff < 0) {	/* We skipped the resize previously (shrinking memory) */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}
