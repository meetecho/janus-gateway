/*! \file   janus_textroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus TextRoom plugin
 * \details This is a plugin implementing a DataChannel only text room.
 * As such, it does NOT support or negotiate audio or video, but only
 * data channels, in order to provide text broadcasting features. The
 * plugin allows users to join multiple text-only rooms via a single
 * PeerConnection. Users can send messages either to a room in general
 * (broadcasting), or to individual users (whispers). This plugin can be
 * used within the context of any application that needs real-time text
 * broadcasting (e.g., chatrooms, but not only).
 *
 * The only message that is sent to the plugin through the Janus API is
 * a "setup" message, by which the user initializes the PeerConnection
 * itself. Apart from that, all other messages are exchanged directly
 * via Data Channels.
 *
 * Each room can also be configured with an HTTP backend to contact for
 * incoming messages. If configured, messages addressed to that room will
 * also be forwarded, by means of an HTTP POST, to the specified address.
 * Notice that this will only work if libcurl was available when
 * configuring and installing Janus.
 *
 * \note This plugin is only meant to showcase what you can do with
 * data channels involving multiple participants at the same time. While
 * functional, it's not inherently better or faster than doing the same
 * thing using the Janus API messaging itself (e.g., as part of the
 * plugin API messaging) or using existing instant messaging protocols
 * (e.g., Jabber). In fact, while data channels are being used, you're
 * still going through a server, so it's not really peer-to-peer. That
 * said, the plugin can be useful if you don't plan to use any other
 * infrastructure than Janus, and yet you also want to have text-based
 * communication (e.g., to add a chatroom to an audio or video conference).
 *
 * Notice that, in general, all users can create rooms. If you want to
 * limit this functionality, you can configure an admin \c admin_key in
 * the plugin settings. When configured, only "create" requests that
 * include the correct \c admin_key value in an "admin_key" property
 * will succeed, and will be rejected otherwise.
 *
 * \section textroomapi Text Room API
 * TBD.
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugins/plugin.h"

#include <jansson.h>

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#endif

#include "debug.h"
#include "apierror.h"
#include "config.h"
#include "mutex.h"
#include "utils.h"


/* Plugin information */
#define JANUS_TEXTROOM_VERSION			2
#define JANUS_TEXTROOM_VERSION_STRING	"0.0.2"
#define JANUS_TEXTROOM_DESCRIPTION		"This is a plugin implementing a text-only room for Janus, using DataChannels."
#define JANUS_TEXTROOM_NAME				"JANUS TextRoom plugin"
#define JANUS_TEXTROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_TEXTROOM_PACKAGE			"janus.plugin.textroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_textroom_init(janus_callbacks *callback, const char *config_path);
void janus_textroom_destroy(void);
int janus_textroom_get_api_compatibility(void);
int janus_textroom_get_version(void);
const char *janus_textroom_get_version_string(void);
const char *janus_textroom_get_description(void);
const char *janus_textroom_get_name(void);
const char *janus_textroom_get_author(void);
const char *janus_textroom_get_package(void);
void janus_textroom_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_textroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_textroom_setup_media(janus_plugin_session *handle);
void janus_textroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_textroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_textroom_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_textroom_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_textroom_hangup_media(janus_plugin_session *handle);
void janus_textroom_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_textroom_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_textroom_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_textroom_init,
		.destroy = janus_textroom_destroy,

		.get_api_compatibility = janus_textroom_get_api_compatibility,
		.get_version = janus_textroom_get_version,
		.get_version_string = janus_textroom_get_version_string,
		.get_description = janus_textroom_get_description,
		.get_name = janus_textroom_get_name,
		.get_author = janus_textroom_get_author,
		.get_package = janus_textroom_get_package,

		.create_session = janus_textroom_create_session,
		.handle_message = janus_textroom_handle_message,
		.setup_media = janus_textroom_setup_media,
		.incoming_rtp = janus_textroom_incoming_rtp,
		.incoming_rtcp = janus_textroom_incoming_rtcp,
		.incoming_data = janus_textroom_incoming_data,
		.slow_link = janus_textroom_slow_link,
		.hangup_media = janus_textroom_hangup_media,
		.destroy_session = janus_textroom_destroy_session,
		.query_session = janus_textroom_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_TEXTROOM_NAME);
	return &janus_textroom_plugin;
}


/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter transaction_parameters[] = {
	{"textroom", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"transaction", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter room_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter create_parameters[] = {
	{"description", JSON_STRING, 0},
	{"secret", JSON_STRING, 0},
	{"pin", JSON_STRING, 0},
	{"post", JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter join_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"display", JSON_STRING, 0}
};
static struct janus_json_parameter message_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"text", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"to", JSON_STRING, 0},
	{"tos", JSON_ARRAY, 0},
	{"ack", JANUS_JSON_BOOL, 0}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static void *janus_textroom_handler(void *data);

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


typedef struct janus_textroom_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_textroom_message;
static GAsyncQueue *messages = NULL;
static janus_textroom_message exit_message;

static void janus_textroom_message_free(janus_textroom_message *msg) {
	if(!msg || msg == &exit_message)
		return;

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

typedef struct janus_textroom_room {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	gchar *http_backend;		/* Server to contact via HTTP POST for incoming messages, if any */
	GHashTable *participants;	/* Map of participants */
	gint64 destroyed;			/* When this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */
} janus_textroom_room;
static GHashTable *rooms;
static janus_mutex rooms_mutex;
static GList *old_rooms;
static char *admin_key = NULL;

typedef struct janus_textroom_session {
	janus_plugin_session *handle;
	GHashTable *rooms;			/* Map of rooms this user is in, and related participant instance */
	janus_mutex mutex;			/* Mutex to lock this session */
	volatile gint setup;
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_textroom_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;

typedef struct janus_textroom_participant {
	janus_textroom_session *session;
	janus_textroom_room *room;	/* Room this participant is in */
	gchar *username;			/* Unique username in the room */
	gchar *display;				/* Display name in the room, if any */
	janus_mutex mutex;			/* Mutex to lock this session */
	gint64 destroyed;			/* When this participant was destroyed */
} janus_textroom_participant;


/* SDP template: we only offer data channels */
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=Janus TextRoom plugin\r\n" \
		"t=0 0\r\n" \
		"m=application 1 DTLS/SCTP 5000\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctpmap:5000 webrtc-datachannel 16\r\n"


/* Error codes */
#define JANUS_TEXTROOM_ERROR_NO_MESSAGE			411
#define JANUS_TEXTROOM_ERROR_INVALID_JSON		412
#define JANUS_TEXTROOM_ERROR_MISSING_ELEMENT	413
#define JANUS_TEXTROOM_ERROR_INVALID_ELEMENT	414
#define JANUS_TEXTROOM_ERROR_INVALID_REQUEST	415
#define JANUS_TEXTROOM_ERROR_ALREADY_SETUP		416
#define JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM		417
#define JANUS_TEXTROOM_ERROR_ROOM_EXISTS		418
#define JANUS_TEXTROOM_ERROR_UNAUTHORIZED		419
#define JANUS_TEXTROOM_ERROR_USERNAME_EXISTS	420
#define JANUS_TEXTROOM_ERROR_ALREADY_IN_ROOM	421
#define JANUS_TEXTROOM_ERROR_NOT_IN_ROOM		422
#define JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR		499

/* TextRoom watchdog/garbage collector (sort of) */
static void *janus_textroom_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "TextRoom watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old TextRoom sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_textroom_session *session = (janus_textroom_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old TextRoom session\n");
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					session->handle = NULL;
					/* TODO Free session stuff */
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		janus_mutex_lock(&rooms_mutex);
		if(old_rooms != NULL) {
			GList *rl = old_rooms;
			now = janus_get_monotonic_time();
			while(rl) {
				janus_textroom_room *textroom = (janus_textroom_room*)rl->data;
				if(!g_atomic_int_get(&initialized) || g_atomic_int_get(&stopping)){
					break;
				}
				if(!textroom) {
					rl = rl->next;
					continue;
				}
				if(now - textroom->destroyed >= 5*G_USEC_PER_SEC) {
					/* Free resources */
					JANUS_LOG(LOG_VERB, "Freeing old TextRoom room %"SCNu64"\n", textroom->room_id);
					g_free(textroom->room_name);
					g_free(textroom->room_secret);
					g_free(textroom->room_pin);
					g_hash_table_destroy(textroom->participants);
					g_free(textroom);
					/* Move on */
					GList *rm = rl->next;
					old_rooms = g_list_delete_link(old_rooms, rl);
					rl = rm;
					continue;
				}
				rl = rl->next;
			}
		}
		janus_mutex_unlock(&rooms_mutex);
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "TextRoom watchdog stopped\n");
	return NULL;
}

#ifdef HAVE_LIBCURL
static size_t janus_textroom_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	return size*nmemb;
}
#endif

void janus_textroom_handle_incoming_request(janus_plugin_session *handle, char *text, gboolean internal);


/* Plugin implementation */
int janus_textroom_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_TEXTROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);
	janus_mutex_init(&config_mutex);

	rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	janus_mutex_init(&rooms_mutex);
	sessions = g_hash_table_new(NULL, NULL);
	messages = g_async_queue_new_full((GDestroyNotify) janus_textroom_message_free);
	janus_mutex_init(&sessions_mutex);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "json");
		if(item && item->value) {
			/* Check how we need to format/serialize the JSON output */
			if(!strcasecmp(item->value, "indented")) {
				/* Default: indented, we use three spaces for that */
				json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(item->value, "plain")) {
				/* Not indented and no new lines, but still readable */
				json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(item->value, "compact")) {
				/* Compact, so no spaces between separators */
				json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
			} else {
				JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", item->value);
				json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
			}
		}
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
			JANUS_LOG(LOG_VERB, "Adding text room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get_item(cat, "description");
			janus_config_item *priv = janus_config_get_item(cat, "is_private");
			janus_config_item *secret = janus_config_get_item(cat, "secret");
			janus_config_item *pin = janus_config_get_item(cat, "pin");
			janus_config_item *post = janus_config_get_item(cat, "post");
			/* Create the text room */
			janus_textroom_room *textroom = g_malloc0(sizeof(janus_textroom_room));
			textroom->room_id = g_ascii_strtoull(cat->name, NULL, 0);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			textroom->room_name = description;
			textroom->is_private = priv && priv->value && janus_is_true(priv->value);
			if(secret != NULL && secret->value != NULL) {
				textroom->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				textroom->room_pin = g_strdup(pin->value);
			}
			if(post != NULL && post->value != NULL) {
#ifdef HAVE_LIBCURL
				/* FIXME Should we check if this is a valid HTTP address? */
				textroom->http_backend = g_strdup(post->value);
#else
				JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
			}
			textroom->participants = g_hash_table_new(g_str_hash, g_str_equal);
			textroom->destroyed = 0;
			janus_mutex_init(&textroom->mutex);
			JANUS_LOG(LOG_VERB, "Created textroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
				textroom->room_id, textroom->room_name,
				textroom->is_private ? "private" : "public",
				textroom->room_secret ? textroom->room_secret : "no secret",
				textroom->room_pin ? textroom->room_pin : "no pin");
			g_hash_table_insert(rooms, janus_uint64_dup(textroom->room_id), textroom);
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
		janus_textroom_room *tr = value;
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s]\n", tr->room_id, tr->room_name);
	}
	janus_mutex_unlock(&rooms_mutex);

#ifdef HAVE_LIBCURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("textroom watchdog", &janus_textroom_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the TextRoom watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("textroom handler", janus_textroom_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_TEXTROOM_NAME);
	return 0;
}

void janus_textroom_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	if(watchdog != NULL) {
		g_thread_join(watchdog);
		watchdog = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;

#ifdef HAVE_LIBCURL
	curl_global_cleanup();
#endif

	janus_config_destroy(config);
	g_free(admin_key);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_TEXTROOM_NAME);
}

int janus_textroom_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_textroom_get_version(void) {
	return JANUS_TEXTROOM_VERSION;
}

const char *janus_textroom_get_version_string(void) {
	return JANUS_TEXTROOM_VERSION_STRING;
}

const char *janus_textroom_get_description(void) {
	return JANUS_TEXTROOM_DESCRIPTION;
}

const char *janus_textroom_get_name(void) {
	return JANUS_TEXTROOM_NAME;
}

const char *janus_textroom_get_author(void) {
	return JANUS_TEXTROOM_AUTHOR;
}

const char *janus_textroom_get_package(void) {
	return JANUS_TEXTROOM_PACKAGE;
}

void janus_textroom_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_textroom_session *session = (janus_textroom_session *)g_malloc0(sizeof(janus_textroom_session));
	session->handle = handle;
	session->rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	session->destroyed = 0;
	janus_mutex_init(&session->mutex);
	g_atomic_int_set(&session->setup, 0);
	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_textroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Echo Test session...\n");
	janus_mutex_lock(&sessions_mutex);
	if(!session->destroyed) {
		g_hash_table_remove(sessions, handle);
		janus_textroom_hangup_media(handle);
		session->destroyed = janus_get_monotonic_time();
		/* Cleaning up and removing the session is done in a lazy way */
		old_sessions = g_list_append(old_sessions, session);
	}
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_textroom_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* TODO Return meaningful info: participant details, rooms they're in, etc. */
	json_t *info = json_object();
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	return info;
}

struct janus_plugin_result *janus_textroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_textroom_message *msg = g_malloc0(sizeof(janus_textroom_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, "I'm taking my time!", NULL);
}

void janus_textroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	g_atomic_int_set(&session->hangingup, 0);
}

void janus_textroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	/* We don't do audio/video */
}

void janus_textroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	/* We don't do audio/video */
}

void janus_textroom_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Incoming request from this user: what should we do? */
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(buf == NULL || len <= 0)
		return;
	char *text = g_malloc0(len+1);
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes): %s\n", strlen(text), text);
	janus_textroom_handle_incoming_request(handle, text, FALSE);
}

/* Helper method to handle incoming messages from the data channel */
void janus_textroom_handle_incoming_request(janus_plugin_session *handle, char *text, gboolean internal) {
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	/* Parse JSON */
	json_error_t error;
	json_t *root = json_loads(text, 0, &error);
	g_free(text);
	if(!root) {
		JANUS_LOG(LOG_ERR, "Error parsing data channel message (JSON error: on line %d: %s)\n", error.line, error.text);
		return;
	}
	/* Handle request */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(root, transaction_parameters,
		error_code, error_cause, TRUE,
		JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
	const char *transaction_text = NULL;
	if(error_code != 0)
		goto error;
	json_t *request = json_object_get(root, "textroom");
	json_t *transaction = json_object_get(root, "transaction");
	const char *request_text = json_string_value(request);
	transaction_text = json_string_value(transaction);
	if(!strcasecmp(request_text, "message")) {
		JANUS_VALIDATE_JSON_OBJECT(root, message_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_textroom_participant *participant = g_hash_table_lookup(session->rooms, &room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&textroom->mutex);
			JANUS_LOG(LOG_ERR, "Not in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %"SCNu64, room_id);
			goto error;
		}
		json_t *username = json_object_get(root, "to");
		json_t *usernames = json_object_get(root, "tos");
		if(username && usernames) {
			janus_mutex_unlock(&textroom->mutex);
			JANUS_LOG(LOG_ERR, "Both to and tos array provided\n");
			error_code = JANUS_TEXTROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Both to and tos array provided");
			goto error;
		}
		json_t *text = json_object_get(root, "text");
		const char *message = json_string_value(text);
		/* Prepare outgoing message */
		json_t *msg = json_object();
		json_object_set_new(msg, "textroom", json_string("message"));
		json_object_set_new(msg, "room", json_integer(room_id));
		json_object_set_new(msg, "from", json_string(participant->username));
		time_t timer;
		time(&timer);
		struct tm *tm_info = localtime(&timer);
		char msgTime[64];
#ifdef _WIN32
		strftime(msgTime, sizeof(msgTime), "%Y-%m-%dT%H:%M:%S%z", tm_info);
#else
		strftime(msgTime, sizeof(msgTime), "%FT%T%z", tm_info);
#endif
		json_object_set_new(msg, "date", json_string(msgTime));
		json_object_set_new(msg, "text", json_string(message));
		if(username || usernames)
			json_object_set_new(msg, "whisper", json_true());
		char *msg_text = json_dumps(msg, json_format);
		json_decref(msg);
		/* Start preparing the response too */
		json_t *reply = json_object();
		json_object_set_new(reply, "textroom", json_string("success"));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Who should we send this message to? */
		if(username) {
			/* A single user */
			json_t *sent = json_object();
			const char *to = json_string_value(username);
			JANUS_LOG(LOG_VERB, "To %s in %"SCNu64": %s\n", to, room_id, message);
			janus_textroom_participant *top = g_hash_table_lookup(textroom->participants, to);
			if(top) {
				gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
				json_object_set_new(sent, to, json_true());
			} else {
				JANUS_LOG(LOG_WARN, "User %s is not in room %"SCNu64", failed to send message\n", to, room_id);
				json_object_set_new(sent, to, json_false());
			}
			json_object_set_new(reply, "sent", sent);
		} else if(usernames) {
			/* A limited number of users */
			json_t *sent = json_object();
			size_t i = 0;
			for(i=0; i<json_array_size(usernames); i++) {
				json_t *u = json_array_get(usernames, i);
				const char *to = json_string_value(u);
				JANUS_LOG(LOG_VERB, "To %s in %"SCNu64": %s\n", to, room_id, message);
				janus_textroom_participant *top = g_hash_table_lookup(textroom->participants, to);
				if(top) {
					gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
					json_object_set_new(sent, to, json_true());
				} else {
					JANUS_LOG(LOG_WARN, "User %s is not in room %"SCNu64", failed to send message\n", to, room_id);
					json_object_set_new(sent, to, json_false());
				}
			}
			json_object_set_new(reply, "sent", sent);
		} else {
			/* Everybody in the room */
			JANUS_LOG(LOG_VERB, "To everybody in %"SCNu64": %s\n", room_id, message);
			if(textroom->participants) {
				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, textroom->participants);
				while(g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_textroom_participant *top = value;
					JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64": %s\n", top->username, room_id, message);
					gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
				}
			}
#ifdef HAVE_LIBCURL
			/* Is there a backend waiting for this message too? */
			if(textroom->http_backend) {
				/* Prepare the libcurl context */
				CURLcode res;
				CURL *curl = curl_easy_init();
				if(curl == NULL) {
					JANUS_LOG(LOG_ERR, "Error initializing CURL context\n");
				} else {
					curl_easy_setopt(curl, CURLOPT_URL, textroom->http_backend);
					struct curl_slist *headers = NULL;
					headers = curl_slist_append(headers, "Accept: application/json");
					headers = curl_slist_append(headers, "Content-Type: application/json");
					headers = curl_slist_append(headers, "charsets: utf-8");
					curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
					curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg_text);
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, janus_textroom_write_data);
					/* Send the request */
					res = curl_easy_perform(curl);
					if(res != CURLE_OK) {
						JANUS_LOG(LOG_ERR, "Couldn't relay event to the backend: %s\n", curl_easy_strerror(res));
					} else {
						JANUS_LOG(LOG_DBG, "Event sent!\n");
					}
				}
			}
#endif
		}
		g_free(msg_text);
		janus_mutex_unlock(&textroom->mutex);
		/* By default we send a confirmation back to the user that sent this message:
		 * if the user passed an ack=false, though, we don't do that */
		json_t *ack = json_object_get(root, "ack");
		if(!internal && (ack == NULL || json_is_true(ack))) {
			/* Send response back */
			char *reply_text = json_dumps(reply, json_format);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
		json_decref(reply);
	} else if(!strcasecmp(request_text, "join")) {
		JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&session->mutex);
		if(g_hash_table_lookup(session->rooms, &room_id) != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			JANUS_LOG(LOG_ERR, "Already in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_ALREADY_IN_ROOM;
			g_snprintf(error_cause, 512, "Already in room %"SCNu64, room_id);
			goto error;
		}
		json_t *username = json_object_get(root, "username");
		const char *username_text = json_string_value(username);
		janus_textroom_participant *participant = g_hash_table_lookup(textroom->participants, username_text);
		if(participant != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			JANUS_LOG(LOG_ERR, "Username already taken\n");
			error_code = JANUS_TEXTROOM_ERROR_USERNAME_EXISTS;
			g_snprintf(error_cause, 512, "Username already taken");
			goto error;
		}
		json_t *display = json_object_get(root, "display");
		const char *display_text = json_string_value(display);
		/* Create a participant instance */
		participant = g_malloc0(sizeof(janus_textroom_participant));
		participant->session = session;
		participant->room = textroom;
		participant->username = g_strdup(username_text);
		participant->display = display_text ? g_strdup(display_text) : NULL;
		participant->destroyed = 0;
		janus_mutex_init(&participant->mutex);
		g_hash_table_insert(session->rooms, janus_uint64_dup(textroom->room_id), participant);
		g_hash_table_insert(textroom->participants, participant->username, participant);
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new join\n");
		json_t *list = json_array();
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("join"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			json_object_set_new(event, "username", json_string(username_text));
			if(display_text != NULL)
				json_object_set_new(event, "display", json_string(display_text));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
				/* Take note of this user */
				json_t *p = json_object();
				json_object_set_new(p, "username", json_string(top->username));
				if(top->display != NULL)
					json_object_set_new(p, "display", json_string(top->display));
				json_array_append_new(list, p);
			}
			g_free(event_text);
		}
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&textroom->mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "participants", list);
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
	} else if(!strcasecmp(request_text, "leave")) {
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&session->mutex);
		janus_textroom_participant *participant = g_hash_table_lookup(session->rooms, &room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			JANUS_LOG(LOG_ERR, "Not in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %"SCNu64, room_id);
			goto error;
		}
		g_hash_table_remove(session->rooms, &room_id);
		g_hash_table_remove(textroom->participants, participant->username);
		participant->session = NULL;
		participant->room = NULL;
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new leave\n");
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("leave"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			json_object_set_new(event, "username", json_string(participant->username));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
			}
			g_free(event_text);
		}
		g_free(participant->username);
		g_free(participant->display);
		g_free(participant);
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&textroom->mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
	} else if(!strcasecmp(request_text, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		json_t *list = json_array();
		JANUS_LOG(LOG_VERB, "Request for the list for all video rooms\n");
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_room *room = value;
			if(!room)
				continue;
			janus_mutex_lock(&room->mutex);
			if(room->is_private) {
				/* Skip private room */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				janus_mutex_unlock(&room->mutex);
				continue;
			}
			json_t *rl = json_object();
			json_object_set_new(rl, "room", json_integer(room->room_id));
			json_object_set_new(rl, "description", json_string(room->room_name));
			/* TODO: Possibly list participant details... or make it a separate API call for a specific room */
			json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
			json_array_append_new(list, rl);
			janus_mutex_unlock(&room->mutex);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "list", list);
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
	} else if(!strcasecmp(request_text, "create")) {
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto error;
		}
		json_t *room = json_object_get(root, "room");
		json_t *desc = json_object_get(root, "description");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *post = json_object_get(root, "post");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto error;
		}
		guint64 room_id = 0;
		room_id = json_integer_value(room);
		if(room_id == 0) {
			JANUS_LOG(LOG_WARN, "Desired room ID is 0, which is not allowed... picking random ID instead\n");
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, &room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Room %"SCNu64" already exists!\n", room_id);
				error_code = JANUS_TEXTROOM_ERROR_ROOM_EXISTS;
				g_snprintf(error_cause, 512, "Room %"SCNu64" already exists", room_id);
				goto error;
			}
		}
		/* Create the text room */
		janus_textroom_room *textroom = g_malloc0(sizeof(janus_textroom_room));
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
		textroom->room_id = room_id;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %"SCNu64"", textroom->room_id);
			description = g_strdup(roomname);
		}
		textroom->room_name = description;
		textroom->is_private = is_private ? json_is_true(is_private) : FALSE;
		if(secret)
			textroom->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			textroom->room_pin = g_strdup(json_string_value(pin));
		if(post) {
#ifdef HAVE_LIBCURL
			/* FIXME Should we check if this is a valid HTTP address? */
			textroom->http_backend = g_strdup(json_string_value(post));
#else
			JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
		}
		textroom->participants = g_hash_table_new(g_str_hash, g_str_equal);
		textroom->destroyed = 0;
		janus_mutex_init(&textroom->mutex);
		g_hash_table_insert(rooms, janus_uint64_dup(textroom->room_id), textroom);
		JANUS_LOG(LOG_VERB, "Created textroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
			textroom->room_id, textroom->room_name,
			textroom->is_private ? "private" : "public",
			textroom->room_secret ? textroom->room_secret : "no secret",
			textroom->room_pin ? textroom->room_pin : "no pin");
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %"SCNu64" permanently in config file\n", textroom->room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category */
			g_snprintf(cat, BUFSIZ, "%"SCNu64, textroom->room_id);
			janus_config_add_category(config, cat);
			/* Now for the values */
			janus_config_add_item(config, cat, "description", textroom->room_name);
			if(textroom->is_private)
				janus_config_add_item(config, cat, "is_private", "yes");
			if(textroom->room_secret)
				janus_config_add_item(config, cat, "secret", textroom->room_secret);
			if(textroom->room_pin)
				janus_config_add_item(config, cat, "pin", textroom->room_pin);
			if(textroom->http_backend)
				janus_config_add_item(config, cat, "post", textroom->http_backend);
			/* Save modified configuration */
			janus_config_save(config, config_folder, JANUS_TEXTROOM_PACKAGE);
			janus_mutex_unlock(&config_mutex);
		}
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_room *tr = value;
			JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s]\n", tr->room_id, tr->room_name);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "room", json_integer(textroom->room_id));
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
	} else if(!strcasecmp(request_text, "exists")) {
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, &room_id);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "room", json_integer(room_id));
			json_object_set_new(reply, "exists", room_exists ? json_true() : json_false());
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
	} else if(!strcasecmp(request_text, "destroy")) {
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto error;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto error;
		}
		janus_mutex_lock(&textroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto error;
		}
		/* Remove room */
		g_hash_table_remove(rooms, &room_id);
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
			janus_config_save(config, config_folder, JANUS_TEXTROOM_PACKAGE);
			janus_mutex_unlock(&config_mutex);
		}
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the destroy\n");
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("destroyed"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
				janus_mutex_unlock(&top->session->mutex);
				g_hash_table_remove(top->session->rooms, &room_id);
				janus_mutex_unlock(&top->session->mutex);
				g_free(top->username);
				g_free(top->display);
				g_free(top);
			}
			g_free(event_text);
		}
		janus_mutex_unlock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			json_t *reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			char *reply_text = json_dumps(reply, json_format);
			json_decref(reply);
			gateway->relay_data(handle, reply_text, strlen(reply_text));
			g_free(reply_text);
		}
		/* We'll let the watchdog worry about freeing resources */
		old_rooms = g_list_append(old_rooms, textroom);
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported request %s\n", request_text);
		error_code = JANUS_TEXTROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unsupported request %s", request_text);
		goto error;
	}

	json_decref(root);
	return;

error:
		{
			if(!internal) {
				/* Prepare JSON error response */
				json_t *reply = json_object();
				json_object_set_new(reply, "textroom", json_string("error"));
				if(transaction_text)
					json_object_set_new(reply, "transaction", json_string(transaction_text));
				json_object_set_new(reply, "error_code", json_integer(error_code));
				json_object_set_new(reply, "error", json_string(error_cause));
				char *reply_text = json_dumps(reply, json_format);
				json_decref(reply);
				gateway->relay_data(handle, reply_text, strlen(reply_text));
				g_free(reply_text);
			}
			if(root != NULL)
				json_decref(root);
		}
}

void janus_textroom_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* We don't do audio/video */
}

void janus_textroom_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	/* Get rid of all participants */
	janus_mutex_lock(&session->mutex);
	GList *list = NULL;
	if(session->rooms) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, session->rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_participant *p = value;
			janus_mutex_lock(&p->mutex);
			if(p->room)
				list = g_list_append(list, janus_uint64_dup(p->room->room_id));
			janus_mutex_unlock(&p->mutex);
		}
		janus_mutex_unlock(&rooms_mutex);
	}
	janus_mutex_unlock(&session->mutex);
	JANUS_LOG(LOG_VERB, "Leaving %d rooms\n", g_list_length(list));
	char request[100];
	GList *first = list;
	while(list) {
		guint64 room_id = *((guint64 *)list->data);
		g_snprintf(request, sizeof(request), "{\"textroom\":\"leave\",\"transaction\":\"internal\",\"room\":%"SCNu64"}", room_id);
		janus_textroom_handle_incoming_request(handle, g_strdup(request), TRUE);
		list = list->next;
	}
	g_list_free_full(first, (GDestroyNotify)g_free);
}

/* Thread to handle incoming messages */
static void *janus_textroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining TextRoom handler thread\n");
	janus_textroom_message *msg = NULL;
	int error_code = 0;
	char *error_cause = g_malloc0(512);
	json_t *root = NULL;
	gboolean do_offer = FALSE;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == NULL)
			continue;
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_textroom_message_free(msg);
			continue;
		}
		janus_textroom_session *session = NULL;
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_lookup(sessions, msg->handle) != NULL ) {
			session = (janus_textroom_session *)msg->handle->plugin_handle;
		}
		janus_mutex_unlock(&sessions_mutex);
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_textroom_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_textroom_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_TEXTROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_TEXTROOM_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		if(!strcasecmp(request_text, "setup")) {
			if(!g_atomic_int_compare_and_exchange(&session->setup, 0, 1)) {
				JANUS_LOG(LOG_ERR, "PeerConnection already setup\n");
				error_code = JANUS_TEXTROOM_ERROR_ALREADY_SETUP;
				g_snprintf(error_cause, 512, "PeerConnection already setup");
				goto error;
			}
			do_offer = TRUE;
		} else if(!strcasecmp(request_text, "ack")) {
			/* The peer send their answer back: do nothing */
			do_offer = FALSE;
		} else {
			JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
			error_code = JANUS_TEXTROOM_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "textroom", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		if(!do_offer) {
			int ret = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		} else {
			/* Send an offer */
			char sdp[500];
			g_snprintf(sdp, sizeof(sdp), sdp_template,
				janus_get_real_time(),			/* We need current time here */
				janus_get_real_time());			/* We need current time here */
			json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp);
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			json_decref(jsep);
		}
		json_decref(event);
		janus_textroom_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("error"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_textroom_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving TextRoom handler thread\n");
	return NULL;
}
