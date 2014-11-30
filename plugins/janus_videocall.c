/*! \file   janus_videocall.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VideoCall plugin
 * \details  This is a simple video call plugin for Janus, allowing two
 * WebRTC peers to call each other through the gateway. The idea is to
 * provide a similar service as the well known AppRTC demo (https://apprtc.appspot.com),
 * but with the media flowing through the gateway rather than being peer-to-peer.
 * 
 * The plugin provides a simple fake registration mechanism. A peer attaching
 * to the plugin needs to specify a username, which acts as a "phone number":
 * if the username is free, it is associated with the peer, which means
 * he/she can be "called" using that username by another peer. Peers can
 * either "call" another peer, by specifying their username, or wait for a call.
 * The approach used by this plugin is similar to the one employed by the
 * echo test one: all frames (RTP/RTCP) coming from one peer are relayed
 * to the other.
 * 
 * Just as in the janus_echotest.c plugin, there are knobs to control
 * whether audio and/or video should be muted or not, and if the bitrate
 * of the peer needs to be capped by means of REMB messages.
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_VIDEOCALL_VERSION			3
#define JANUS_VIDEOCALL_VERSION_STRING	"0.0.3"
#define JANUS_VIDEOCALL_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through the gateway."
#define JANUS_VIDEOCALL_NAME			"JANUS VideoCall plugin"
#define JANUS_VIDEOCALL_AUTHOR			"Meetecho s.r.l."
#define JANUS_VIDEOCALL_PACKAGE			"janus.plugin.videocall"

/* Plugin methods */
janus_plugin *create(void);
int janus_videocall_init(janus_callbacks *callback, const char *config_path);
void janus_videocall_destroy(void);
int janus_videocall_get_version(void);
const char *janus_videocall_get_version_string(void);
const char *janus_videocall_get_description(void);
const char *janus_videocall_get_name(void);
const char *janus_videocall_get_author(void);
const char *janus_videocall_get_package(void);
void janus_videocall_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_videocall_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_videocall_setup_media(janus_plugin_session *handle);
void janus_videocall_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videocall_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videocall_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_videocall_hangup_media(janus_plugin_session *handle);
void janus_videocall_destroy_session(janus_plugin_session *handle, int *error);

/* Plugin setup */
static janus_plugin janus_videocall_plugin =
	{
		.init = janus_videocall_init,
		.destroy = janus_videocall_destroy,

		.get_version = janus_videocall_get_version,
		.get_version_string = janus_videocall_get_version_string,
		.get_description = janus_videocall_get_description,
		.get_name = janus_videocall_get_name,
		.get_author = janus_videocall_get_author,
		.get_package = janus_videocall_get_package,
		
		.create_session = janus_videocall_create_session,
		.handle_message = janus_videocall_handle_message,
		.setup_media = janus_videocall_setup_media,
		.incoming_rtp = janus_videocall_incoming_rtp,
		.incoming_rtcp = janus_videocall_incoming_rtcp,
		.incoming_data = janus_videocall_incoming_data,
		.hangup_media = janus_videocall_hangup_media,
		.destroy_session = janus_videocall_destroy_session,
	}; 

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VIDEOCALL_NAME);
	return &janus_videocall_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videocall_handler(void *data);

typedef struct janus_videocall_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_videocall_message;
static GAsyncQueue *messages = NULL;

void janus_videocall_message_free(janus_videocall_message *msg);
void janus_videocall_message_free(janus_videocall_message *msg) {
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

typedef struct janus_videocall_session {
	janus_plugin_session *handle;
	gchar *username;
	gboolean audio_active;
	gboolean video_active;
	uint64_t bitrate;
	struct janus_videocall_session *peer;
	guint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_videocall_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;


/* Error codes */
#define JANUS_VIDEOCALL_ERROR_UNKNOWN_ERROR			499
#define JANUS_VIDEOCALL_ERROR_NO_MESSAGE			470
#define JANUS_VIDEOCALL_ERROR_INVALID_JSON			471
#define JANUS_VIDEOCALL_ERROR_INVALID_REQUEST		472
#define JANUS_VIDEOCALL_ERROR_REGISTER_FIRST		473
#define JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT		474
#define JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT		475
#define JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN		476
#define JANUS_VIDEOCALL_ERROR_ALREADY_REGISTERED	477
#define JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME		478
#define JANUS_VIDEOCALL_ERROR_USE_ECHO_TEST			479
#define JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL		480
#define JANUS_VIDEOCALL_ERROR_NO_CALL				481
#define JANUS_VIDEOCALL_ERROR_MISSING_SDP			482


/* VideoCall watchdog/garbage collector (sort of) */
void *janus_videocall_watchdog(void *data);
void *janus_videocall_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "VideoCall watchdog started\n");
	gint64 now = 0;
	while(initialized && !stopping) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_VERB, "Checking %d old sessions\n", g_list_length(old_sessions));
			while(sl) {
				janus_videocall_session *session = (janus_videocall_session *)sl->data;
				if(!session || !initialized || stopping) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					session->handle = NULL;
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(2000000);
	}
	JANUS_LOG(LOG_INFO, "VideoCall watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_videocall_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_VIDEOCALL_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	sessions = g_hash_table_new(g_str_hash, g_str_equal);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_videocall_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	initialized = 1;
	/* Start the sessions watchdog */
	GThread *watchdog = g_thread_new("vcall watchdog", &janus_videocall_watchdog, NULL);
	if(!watchdog) {
		JANUS_LOG(LOG_FATAL, "Couldn't start VideoCall watchdog...\n");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus videocall handler", janus_videocall_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VIDEOCALL_NAME);
	return 0;
}

void janus_videocall_destroy(void) {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	/* FIXME We should destroy the sessions cleanly */
	g_hash_table_destroy(sessions);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;
	initialized = 0;
	stopping = 0;
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VIDEOCALL_NAME);
}

int janus_videocall_get_version(void) {
	return JANUS_VIDEOCALL_VERSION;
}

const char *janus_videocall_get_version_string(void) {
	return JANUS_VIDEOCALL_VERSION_STRING;
}

const char *janus_videocall_get_description(void) {
	return JANUS_VIDEOCALL_DESCRIPTION;
}

const char *janus_videocall_get_name(void) {
	return JANUS_VIDEOCALL_NAME;
}

const char *janus_videocall_get_author(void) {
	return JANUS_VIDEOCALL_AUTHOR;
}

const char *janus_videocall_get_package(void) {
	return JANUS_VIDEOCALL_PACKAGE;
}

void janus_videocall_create_session(janus_plugin_session *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_videocall_session *session = (janus_videocall_session *)calloc(1, sizeof(janus_videocall_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	session->peer = NULL;
	session->username = NULL;
	session->destroyed = 0;
	handle->plugin_handle = session;

	return;
}

void janus_videocall_destroy_session(janus_plugin_session *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroyed) {
		JANUS_LOG(LOG_VERB, "Session already destroyed...\n");
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing user %s session...\n", session->username ? session->username : "'unknown'");
	janus_videocall_hangup_media(handle);
	if(session->username != NULL) {
		janus_mutex_lock(&sessions_mutex);
		int res = g_hash_table_remove(sessions, (gpointer)session->username);
		JANUS_LOG(LOG_VERB, "  -- Removed: %d\n", res);
		janus_mutex_unlock(&sessions_mutex);
	}
	/* Cleaning up and removing the session is done in a lazy way */
	session->destroyed = janus_get_monotonic_time();
	janus_mutex_lock(&sessions_mutex);
	old_sessions = g_list_append(old_sessions, session);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

struct janus_plugin_result *janus_videocall_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, stopping ? "Shutting down" : "Plugin not initialized");
	JANUS_LOG(LOG_VERB, "%s\n", message);
	janus_videocall_message *msg = calloc(1, sizeof(janus_videocall_message));
	if(msg == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Memory error");
	}
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL);
}

void janus_videocall_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	/* We really don't care, as we only relay RTP/RTCP we get in the first place anyway */
}

void janus_videocall_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized)
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(!session->peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(session->destroyed || session->peer->destroyed)
			return;
		if((!video && session->audio_active) || (video && session->video_active)) {
			gateway->relay_rtp(session->peer->handle, video, buf, len);
		}
	}
}

void janus_videocall_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized)
		return;
	if(gateway) {
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(!session->peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(session->destroyed || session->peer->destroyed)
			return;
		if(session->bitrate > 0)
			janus_rtcp_cap_remb(buf, len, session->bitrate);
		gateway->relay_rtcp(session->peer->handle, video, buf, len);
	}
}

void janus_videocall_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized)
		return;
	if(gateway) {
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(!session->peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(session->destroyed || session->peer->destroyed)
			return;
		if(buf == NULL || len <= 0)
			return;
		char text[1<<16];
		memset(text, 0, 1<<16);
		memcpy(text, buf, len);
		text[len] = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
		gateway->relay_data(session->peer->handle, text, strlen(text));
	}
}

void janus_videocall_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	janus_mutex_lock(&sessions_mutex);
	if(session->peer) {
		/* Send event to our peer too */
		json_t *call = json_object();
		json_object_set_new(call, "videocall", json_string("event"));
		json_t *calling = json_object();
		json_object_set_new(calling, "event", json_string("hangup"));
		json_object_set_new(calling, "username", json_string(session->username));
		json_object_set_new(calling, "reason", json_string("Remote hangup"));
		json_object_set_new(call, "result", calling);
		char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(call);
		JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
		int ret = gateway->push_event(session->peer->handle, &janus_videocall_plugin, NULL, call_text, NULL, NULL);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		g_free(call_text);
	}
	session->peer = NULL;
	/* Reset controls */
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;
	janus_mutex_unlock(&sessions_mutex);
}

/* Thread to handle incoming messages */
static void *janus_videocall_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining thread\n");
	janus_videocall_message *msg = NULL;
	int error_code = 0;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	json_t *root = NULL;
	while(initialized && !stopping) {
		if(!messages || (msg = g_async_queue_try_pop(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_videocall_session *session = (janus_videocall_session *)msg->handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_videocall_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_videocall_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = NULL;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOCALL_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		json_t *request = json_object_get(root, "request");
		if(!request) {
			JANUS_LOG(LOG_ERR, "Missing element (request)\n");
			error_code = JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (request)");
			goto error;
		}
		if(!json_is_string(request)) {
			JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (request should be a string)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *result = NULL;
		char *sdp_type = NULL, *sdp = NULL;
		if(!strcasecmp(request_text, "list")) {
			result = json_object();
			json_t *list = json_array();
			JANUS_LOG(LOG_VERB, "Request for the list of peers\n");
			/* Return a list of all available mountpoints */
			janus_mutex_lock(&sessions_mutex);
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, sessions);
			while (g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_videocall_session *user = value;
				if(user != NULL && user->username != NULL)
					json_array_append_new(list, json_string(user->username));
			}
			json_object_set_new(result, "list", list);
			janus_mutex_unlock(&sessions_mutex);
		} else if(!strcasecmp(request_text, "register")) {
			/* Map this handle to a username */
			if(session->username != NULL) {
				JANUS_LOG(LOG_ERR, "Already registered (%s)\n", session->username);
				error_code = JANUS_VIDEOCALL_ERROR_ALREADY_REGISTERED;
				g_snprintf(error_cause, 512, "Already registered (%s)", session->username);
				goto error;
			}
			json_t *username = json_object_get(root, "username");
			if(!username) {
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (username)");
				goto error;
			}
			if(!json_is_string(username)) {
				JANUS_LOG(LOG_ERR, "Invalid element (username should be a string)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (username should be a string)");
				goto error;
			}
			const char *username_text = json_string_value(username);
			janus_mutex_lock(&sessions_mutex);
			if(g_hash_table_lookup(sessions, username_text) != NULL) {
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_ERR, "Username '%s' already taken\n", username_text);
				error_code = JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN;
				g_snprintf(error_cause, 512, "Username '%s' already taken", username_text);
				goto error;
			}
			janus_mutex_unlock(&sessions_mutex);
			session->username = g_strdup(username_text);
			if(session->username == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				error_code = JANUS_VIDEOCALL_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Memory error");
				goto error;
			}
			janus_mutex_lock(&sessions_mutex);
			g_hash_table_insert(sessions, (gpointer)session->username, session);
			janus_mutex_unlock(&sessions_mutex);
			result = json_object();
			json_object_set_new(result, "event", json_string("registered"));
			json_object_set_new(result, "username", json_string(username_text));
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->username == NULL) {
				JANUS_LOG(LOG_ERR, "Register a username first\n");
				error_code = JANUS_VIDEOCALL_ERROR_REGISTER_FIRST;
				g_snprintf(error_cause, 512, "Register a username first");
				goto error;
			}
			if(session->peer != NULL) {
				JANUS_LOG(LOG_ERR, "Already in a call\n");
				error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
				g_snprintf(error_cause, 512, "Already in a call");
				goto error;
			}
			json_t *username = json_object_get(root, "username");
			if(!username) {
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (username)");
				goto error;
			}
			if(!json_is_string(username)) {
				JANUS_LOG(LOG_ERR, "Invalid element (username should be a string)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (username should be a string)");
				goto error;
			}
			const char *username_text = json_string_value(username);
			if(!strcmp(username_text, session->username)) {
				JANUS_LOG(LOG_ERR, "You can't call yourself... use the EchoTest for that\n");
				error_code = JANUS_VIDEOCALL_ERROR_USE_ECHO_TEST;
				g_snprintf(error_cause, 512, "You can't call yourself... use the EchoTest for that");
				goto error;
			}
			janus_mutex_lock(&sessions_mutex);
			janus_videocall_session *peer = g_hash_table_lookup(sessions, username_text);
			if(peer == NULL || peer->destroyed) {
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_ERR, "Username '%s' doesn't exist\n", username_text);
				error_code = JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME;
				g_snprintf(error_cause, 512, "Username '%s' doesn't exist", username_text);
				goto error;
			}
			if(peer->peer != NULL) {
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_VERB, "%s is busy\n", username_text);
				result = json_object();
				json_object_set_new(result, "event", json_string("hangup"));
				json_object_set_new(result, "username", json_string(session->username));
				json_object_set_new(result, "reason", json_string("User busy"));
			} else {
				janus_mutex_unlock(&sessions_mutex);
				/* Any SDP to handle? if not, something's wrong */
				if(!msg->sdp) {
					JANUS_LOG(LOG_ERR, "Missing SDP\n");
					error_code = JANUS_VIDEOCALL_ERROR_MISSING_SDP;
					g_snprintf(error_cause, 512, "Missing SDP");
					goto error;
				}
				janus_mutex_lock(&sessions_mutex);
				session->peer = peer;
				peer->peer = session;
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_VERB, "%s is calling %s\n", session->username, session->peer->username);
				JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
				/* Send SDP to our peer */
				json_t *call = json_object();
				json_object_set_new(call, "videocall", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("incomingcall"));
				json_object_set_new(calling, "username", json_string(session->username));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
				int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call_text, msg->sdp_type, msg->sdp);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
				/* Send an ack back */
				result = json_object();
				json_object_set_new(result, "event", json_string("calling"));
			}
		} else if(!strcasecmp(request_text, "accept")) {
			/* Accept a call from another peer */
			if(session->peer == NULL) {
				JANUS_LOG(LOG_ERR, "No incoming call to accept\n");
				error_code = JANUS_VIDEOCALL_ERROR_NO_CALL;
				g_snprintf(error_cause, 512, "No incoming call to accept");
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_VIDEOCALL_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			JANUS_LOG(LOG_VERB, "%s is accepting a call from %s\n", session->username, session->peer->username);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			/* Send SDP to our peer */
			json_t *call = json_object();
			json_object_set_new(call, "videocall", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("accepted"));
			json_object_set_new(calling, "username", json_string(session->username));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
			int ret = gateway->push_event(session->peer->handle, &janus_videocall_plugin, NULL, call_text, msg->sdp_type, msg->sdp);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("accepted"));
		} else if(!strcasecmp(request_text, "set")) {
			/* Update the local configuration (audio/video mute/unmute, or bitrate cap) */
			json_t *audio = json_object_get(root, "audio");
			if(audio && !json_is_boolean(audio)) {
				JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
				goto error;
			}
			json_t *video = json_object_get(root, "video");
			if(video && !json_is_boolean(video)) {
				JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
				goto error;
			}
			json_t *bitrate = json_object_get(root, "bitrate");
			if(bitrate && !json_is_integer(bitrate)) {
				JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be an integer)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (bitrate should be an integer)");
				goto error;
			}
			if(audio) {
				session->audio_active = json_is_true(audio);
				JANUS_LOG(LOG_VERB, "Setting audio property: %s\n", session->audio_active ? "true" : "false");
			}
			if(video) {
				session->video_active = json_is_true(video);
				JANUS_LOG(LOG_VERB, "Setting video property: %s\n", session->video_active ? "true" : "false");
			}
			if(bitrate) {
				session->bitrate = json_integer_value(bitrate);
				JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu64"\n", session->bitrate);
				if(session->bitrate > 0) {
					/* FIXME Generate a new REMB (especially useful for Firefox, which doesn't send any we can cap later) */
					char buf[24];
					memset(buf, 0, 24);
					janus_rtcp_remb((char *)&buf, 24, session->bitrate);
					JANUS_LOG(LOG_VERB, "Sending REMB\n");
					gateway->relay_rtcp(session->handle, 1, buf, 24);
					/* FIXME How should we handle a subsequent "no limit" bitrate? */
				}
			}
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("set"));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call or reject an incoming one */
			janus_mutex_lock(&sessions_mutex);
			janus_videocall_session *peer = session->peer;
			if(peer == NULL) {
				JANUS_LOG(LOG_WARN, "No call to hangup\n");
			} else {
				JANUS_LOG(LOG_VERB, "%s is hanging up the call with %s\n", session->username, peer->username);
				session->peer = NULL;
				peer->peer = NULL;
			}
			janus_mutex_unlock(&sessions_mutex);
			/* Notify the success as an hangup message */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangup"));
			json_object_set_new(result, "username", json_string(session->username));
			json_object_set_new(result, "reason", json_string("We did the hangup"));
			if(peer != NULL) {
				/* Send event to our peer too */
				json_t *call = json_object();
				json_object_set_new(call, "videocall", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "username", json_string(session->username));
				json_object_set_new(calling, "reason", json_string("Remote hangup"));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
				int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "videocall", json_string("event"));
		if(result != NULL)
			json_object_set(event, "result", result);
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		if(result != NULL)
			json_decref(result);
		JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
		int ret = gateway->push_event(msg->handle, &janus_videocall_plugin, msg->transaction, event_text, sdp_type, sdp);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		g_free(event_text);
		if(sdp)
			g_free(sdp);
		janus_videocall_message_free(msg);
		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videocall", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
			int ret = gateway->push_event(msg->handle, &janus_videocall_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(event_text);
			janus_videocall_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving thread\n");
	return NULL;
}
