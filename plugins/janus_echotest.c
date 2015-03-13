/*! \file   janus_echotest.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus EchoTest plugin
 * \details  This is a trivial EchoTest plugin for Janus, just used to
 * showcase the plugin interface. A peer attaching to this plugin will
 * receive back the same RTP packets and RTCP messages he sends: the
 * RTCP messages, of course, would be modified on the way by the gateway
 * to make sure they are coherent with the involved SSRCs. In order to
 * demonstrate how peer-provided messages can change the behaviour of a
 * plugin, this plugin implements a simple API based on three messages:
 * 
 * 1. a message to enable/disable audio (that is, to tell the plugin
 * whether incoming audio RTP packets need to be sent back or discarded);
 * 2. a message to enable/disable video (that is, to tell the plugin
 * whether incoming video RTP packets need to be sent back or discarded);
 * 3. a message to cap the bitrate (which would modify incoming RTCP
 * REMB messages before sending them back, in order to trick the peer into
 * thinking the available bandwidth is different).
 * 
 * \section echoapi Echo Test API
 * 
 * There's a single unnamed request you can send and it's asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction. 
 * 
 * The request has to be formatted as follows:
 *
\verbatim
{
	"audio" : true|false,
	"video" : true|false,
	"bitrate" : <numeric bitrate value>
}
\endverbatim
 *
 * \c audio instructs the plugin to do or do not bounce back audio
 * frames; \c video does the same for video; \c bitrate caps the
 * bandwidth to force on the browser encoding side (e.g., 128000 for
 * 128kbps).
 * 
 * The first request must be sent together with a JSEP offer to
 * negotiate a PeerConnection: a JSEP answer will be provided with
 * the asynchronous response notification. Subsequent requests (e.g., to
 * dynamically manipulate the bitrate while testing) have to be sent
 * without any JSEP payload attached.
 * 
 * A successful request will result in an \c ok event:
 * 
\verbatim
{
	"echotest" : "event",
	"result": "ok"
}
\endverbatim
 * 
 * An error instead will provide both an error code and a more verbose
 * description of the cause of the issue:
 * 
\verbatim
{
	"echotest" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * If the plugin detects a loss of the associated PeerConnection, a
 * "done" notification is triggered to inform the application the Echo
 * Test session is over:
 * 
\verbatim
{
	"echotest" : "event",
	"result": "done"
}
\endverbatim
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
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_ECHOTEST_VERSION			6
#define JANUS_ECHOTEST_VERSION_STRING	"0.0.6"
#define JANUS_ECHOTEST_DESCRIPTION		"This is a trivial EchoTest plugin for Janus, just used to showcase the plugin interface."
#define JANUS_ECHOTEST_NAME				"JANUS EchoTest plugin"
#define JANUS_ECHOTEST_AUTHOR			"Meetecho s.r.l."
#define JANUS_ECHOTEST_PACKAGE			"janus.plugin.echotest"

/* Plugin methods */
janus_plugin *create(void);
int janus_echotest_init(janus_callbacks *callback, const char *config_path);
void janus_echotest_destroy(void);
int janus_echotest_get_api_compatibility(void);
int janus_echotest_get_version(void);
const char *janus_echotest_get_version_string(void);
const char *janus_echotest_get_description(void);
const char *janus_echotest_get_name(void);
const char *janus_echotest_get_author(void);
const char *janus_echotest_get_package(void);
void janus_echotest_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_echotest_setup_media(janus_plugin_session *handle);
void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_echotest_hangup_media(janus_plugin_session *handle);
void janus_echotest_destroy_session(janus_plugin_session *handle, int *error);
char *janus_echotest_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_echotest_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_echotest_init,
		.destroy = janus_echotest_destroy,

		.get_api_compatibility = janus_echotest_get_api_compatibility,
		.get_version = janus_echotest_get_version,
		.get_version_string = janus_echotest_get_version_string,
		.get_description = janus_echotest_get_description,
		.get_name = janus_echotest_get_name,
		.get_author = janus_echotest_get_author,
		.get_package = janus_echotest_get_package,
		
		.create_session = janus_echotest_create_session,
		.handle_message = janus_echotest_handle_message,
		.setup_media = janus_echotest_setup_media,
		.incoming_rtp = janus_echotest_incoming_rtp,
		.incoming_rtcp = janus_echotest_incoming_rtcp,
		.incoming_data = janus_echotest_incoming_data,
		.slow_link = janus_echotest_slow_link,
		.hangup_media = janus_echotest_hangup_media,
		.destroy_session = janus_echotest_destroy_session,
		.query_session = janus_echotest_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_ECHOTEST_NAME);
	return &janus_echotest_plugin;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static void *janus_echotest_handler(void *data);

typedef struct janus_echotest_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_echotest_message;
static GAsyncQueue *messages = NULL;

typedef struct janus_echotest_session {
	janus_plugin_session *handle;
	gboolean audio_active;
	gboolean video_active;
	uint64_t bitrate;
	guint16 slowlink_count;
	guint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_echotest_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;

void janus_echotest_message_free(janus_echotest_message *msg);
void janus_echotest_message_free(janus_echotest_message *msg) {
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


/* Error codes */
#define JANUS_ECHOTEST_ERROR_NO_MESSAGE			411
#define JANUS_ECHOTEST_ERROR_INVALID_JSON		412
#define JANUS_ECHOTEST_ERROR_INVALID_ELEMENT	413


/* EchoTest watchdog/garbage collector (sort of) */
void *janus_echotest_watchdog(void *data);
void *janus_echotest_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "EchoTest watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old EchoTest sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_echotest_session *session = (janus_echotest_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old EchoTest session\n");
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
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "EchoTest watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_echotest_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_ECHOTEST_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_echotest_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;
	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("etest watchdog", &janus_echotest_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("janus echotest handler", janus_echotest_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_ECHOTEST_NAME);
	return 0;
}

void janus_echotest_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

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

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_ECHOTEST_NAME);
}

int janus_echotest_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_echotest_get_version(void) {
	return JANUS_ECHOTEST_VERSION;
}

const char *janus_echotest_get_version_string(void) {
	return JANUS_ECHOTEST_VERSION_STRING;
}

const char *janus_echotest_get_description(void) {
	return JANUS_ECHOTEST_DESCRIPTION;
}

const char *janus_echotest_get_name(void) {
	return JANUS_ECHOTEST_NAME;
}

const char *janus_echotest_get_author(void) {
	return JANUS_ECHOTEST_AUTHOR;
}

const char *janus_echotest_get_package(void) {
	return JANUS_ECHOTEST_PACKAGE;
}

void janus_echotest_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)calloc(1, sizeof(janus_echotest_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	session->destroyed = 0;
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_echotest_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Echo Test session...\n");
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	/* Cleaning up and removing the session is done in a lazy way */
	session->destroyed = janus_get_monotonic_time();
	janus_mutex_lock(&sessions_mutex);
	old_sessions = g_list_append(old_sessions, session);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

char *janus_echotest_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}	
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "audio_active", json_string(session->audio_active ? "true" : "false"));
	json_object_set_new(info, "video_active", json_string(session->video_active ? "true" : "false"));
	json_object_set_new(info, "bitrate", json_integer(session->bitrate));
	json_object_set_new(info, "slowlink_count", json_integer(session->slowlink_count));
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	char *info_text = json_dumps(info, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(info);
	return info_text;
}

struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized");
	janus_echotest_message *msg = calloc(1, sizeof(janus_echotest_message));
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
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, "I'm taking my time!");
}

void janus_echotest_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	/* We really don't care, as we only send RTP/RTCP we get in the first place back anyway */
}

void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if((!video && session->audio_active) || (video && session->video_active)) {
			gateway->relay_rtp(handle, video, buf, len);
		}
	}
}

void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if(session->bitrate > 0)
			janus_rtcp_cap_remb(buf, len, session->bitrate);
		gateway->relay_rtcp(handle, video, buf, len);
	}
}

void janus_echotest_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if(buf == NULL || len <= 0)
			return;
		char *text = calloc(len+1, sizeof(char));
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to bounce back: %s\n", strlen(text), text);
		char reply[1<<16];
		memset(reply, 0, 1<<16);
		g_snprintf(reply, 1<<16, "Janus EchoTest here! You wrote: %s", text);
		free(text);
		gateway->relay_data(handle, reply, strlen(reply));
	}
}

void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* The core is informing us that our peer got or sent too many NACKs, are we pushing media too hard? */
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	session->slowlink_count++;
	if(uplink && !video && !session->audio_active) {
		/* We're not relaying audio and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for audio, but that's expected, a configure disabled the audio forwarding\n");
	} else if(uplink && video && !session->video_active) {
		/* We're not relaying video and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for video, but that's expected, a configure disabled the video forwarding\n");
	} else {
		/* Slow uplink or downlink, maybe we set the bitrate cap too high? */
		if(video) {
			/* Halve the bitrate, but don't go too low... */
			session->bitrate = session->bitrate > 0 ? session->bitrate : 512*1024;
			session->bitrate = session->bitrate/2;
			if(session->bitrate < 64*1024)
				session->bitrate = 64*1024;
			JANUS_LOG(LOG_WARN, "Getting a lot of NACKs (slow %s) for %s, forcing a lower REMB: %"SCNu64"\n",
				uplink ? "uplink" : "downlink", video ? "video" : "audio", session->bitrate);
			/* ... and send a new REMB back */
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
				janus_rtcp_remb((char *)(&rtcpbuf)+rrlen+sdeslen, 24, session->bitrate);
				gateway->relay_rtcp(handle, 1, rtcpbuf, rrlen+sdeslen+24);
			}
			/* As a last thing, notify the user about this */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "status", json_string("slow_link"));
			json_object_set_new(result, "bitrate", json_integer(session->bitrate));
			json_object_set_new(event, "result", result);
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			json_decref(result);
			event = NULL;
			gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event_text, NULL, NULL);
			g_free(event_text);
		}
	}
}

void janus_echotest_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "echotest", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
	int ret = gateway->push_event(handle, &janus_echotest_plugin, NULL, event_text, NULL, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	g_free(event_text);
	/* Reset controls */
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;
}

/* Thread to handle incoming messages */
static void *janus_echotest_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining EchoTest handler thread\n");
	janus_echotest_message *msg = NULL;
	int error_code = 0;
	char *error_cause = calloc(512, sizeof(char));
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		if(!messages || (msg = g_async_queue_try_pop(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_echotest_session *session = (janus_echotest_session *)msg->handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_echotest_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_echotest_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = NULL;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_ECHOTEST_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_ECHOTEST_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		json_t *audio = json_object_get(root, "audio");
		if(audio && !json_is_boolean(audio)) {
			JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
			goto error;
		}
		json_t *video = json_object_get(root, "video");
		if(video && !json_is_boolean(video)) {
			JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
			goto error;
		}
		json_t *bitrate = json_object_get(root, "bitrate");
		if(bitrate && !json_is_integer(bitrate)) {
			JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be an integer)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (bitrate should be an integer)");
			goto error;
		}
		if(audio) {
			session->audio_active = json_is_true(audio);
			JANUS_LOG(LOG_VERB, "Setting audio property: %s\n", session->audio_active ? "true" : "false");
		}
		if(video) {
			if(!session->video_active && json_is_true(video)) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "Just (re-)enabled video, sending a PLI to recover it\n");
				char buf[12];
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				gateway->relay_rtcp(session->handle, 1, buf, 12);
			}
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
		/* Any SDP to handle? */
		if(msg->sdp) {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "echotest", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
		if(!msg->sdp) {
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		} else {
			/* Forward the same offer to the gateway, to start the echo test */
			const char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer"))
				type = "answer";
			if(!strcasecmp(msg->sdp_type, "answer"))
				type = "offer";
			/* Any media direction that needs to be fixed? */
			char *sdp = g_strdup(msg->sdp);
			if(strstr(sdp, "a=recvonly")) {
				/* Turn recvonly to inactive, as we simply bounce media back */
				sdp = janus_string_replace(sdp, "a=recvonly", "a=inactive");
			} else if(strstr(sdp, "a=sendonly")) {
				/* Turn sendonly to recvonly */
				sdp = janus_string_replace(sdp, "a=sendonly", "a=recvonly");
				/* FIXME We should also actually not echo this media back, though... */
			}
			/* How long will the gateway take to push the event? */
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, type, sdp);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			g_free(sdp);
		}
		g_free(event_text);
		janus_echotest_message_free(msg);
		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(event_text);
			janus_echotest_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving EchoTest handler thread\n");
	return NULL;
}
