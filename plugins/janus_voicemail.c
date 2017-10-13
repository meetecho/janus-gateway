/*! \file   janus_voicemail.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VoiceMail plugin
 * \details  This is a plugin implementing a very simple VoiceMail service
 * for Janus, specifically recording Opus streams. This means that it replies
 * by providing in the SDP only support for Opus, and disabling video.
 * When a peer contacts the plugin, the plugin starts recording the audio
 * frames it receives and, after 10 seconds, it shuts the PeerConnection
 * down and returns an URL to the recorded file.
 * 
 * Since an URL is returned, the plugin allows you to configure where the
 * recordings whould be stored (e.g., a folder in your web server, writable
 * by the plugin) and the base path to use when returning URLs (e.g.,
 * /my/recordings/ or http://www.example.com/my/recordings).
 * 
 * By default the plugin saves the recordings in the \c html folder of
 * this project, meaning that it can work out of the box with the VoiceMail
 * demo we provide in the same folder.
 *
 * \section vmailapi VoiceMail API
 * 
 * The VoiceMail API supports just two requests, \c record and \c stop 
 * and they're both asynchronous, which means all responses (successes
 * and errors) will be delivered as events with the same transaction. 
 * 
 * \c record will instruct the plugin to start recording, while \c stop
 * will make the recording stop before the 10 seconds have passed.
 * Never send a JSEP offer with any of these requests: it's always the
 * VoiceMail plugin that originates a JSEP offer, in response to a
 * \c record request, which means your application will only have to
 * send a JSEP answer when that happens.
 * 
 * The \c record request has to be formatted as follows:
 *
\verbatim
{
	"request" : "record"
}
\endverbatim
 *
 * A successful request will result in an \c starting status event:
 * 
\verbatim
{
	"voicemail" : "event",
	"status": "starting"
}
\endverbatim
 * 
 * which will be followed by a \c started as soon as the associated
 * PeerConnection has been made available to the plugin: 
 * 
\verbatim
{
	"voicemail" : "event",
	"status": "started"
}
\endverbatim
 * 
 * An error instead would provide both an error code and a more verbose
 * description of the cause of the issue:
 * 
\verbatim
{
	"voicemail" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 * 
 * The \c stop request instead has to be formatted as follows:
 *
\verbatim
{
	"request" : "stop"
}
\endverbatim
 *
 * If the plugin detects a loss of the associated PeerConnection, whether
 * as a result of a \c stop request or because the 10 seconds passed, a
 * \c done status notification is triggered to inform the application
 * the recording session is over, together with the path to the
 * recording file itself:
 * 
\verbatim
{
	"voicemail" : "event",
	"status" : "done",
	"recording : "<path to the .opus file>"
}
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ogg/ogg.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_VOICEMAIL_VERSION			6
#define JANUS_VOICEMAIL_VERSION_STRING	"0.0.6"
#define JANUS_VOICEMAIL_DESCRIPTION		"This is a plugin implementing a very simple VoiceMail service for Janus, recording Opus streams."
#define JANUS_VOICEMAIL_NAME			"JANUS VoiceMail plugin"
#define JANUS_VOICEMAIL_AUTHOR			"Meetecho s.r.l."
#define JANUS_VOICEMAIL_PACKAGE			"janus.plugin.voicemail"

/* Plugin methods */
janus_plugin *create(void);
int janus_voicemail_init(janus_callbacks *callback, const char *config_path);
void janus_voicemail_destroy(void);
int janus_voicemail_get_api_compatibility(void);
int janus_voicemail_get_version(void);
const char *janus_voicemail_get_version_string(void);
const char *janus_voicemail_get_description(void);
const char *janus_voicemail_get_name(void);
const char *janus_voicemail_get_author(void);
const char *janus_voicemail_get_package(void);
void janus_voicemail_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_voicemail_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_voicemail_setup_media(janus_plugin_session *handle);
void janus_voicemail_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_voicemail_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_voicemail_hangup_media(janus_plugin_session *handle);
void janus_voicemail_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_voicemail_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_voicemail_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_voicemail_init,
		.destroy = janus_voicemail_destroy,

		.get_api_compatibility = janus_voicemail_get_api_compatibility,
		.get_version = janus_voicemail_get_version,
		.get_version_string = janus_voicemail_get_version_string,
		.get_description = janus_voicemail_get_description,
		.get_name = janus_voicemail_get_name,
		.get_author = janus_voicemail_get_author,
		.get_package = janus_voicemail_get_package,
		
		.create_session = janus_voicemail_create_session,
		.handle_message = janus_voicemail_handle_message,
		.setup_media = janus_voicemail_setup_media,
		.incoming_rtp = janus_voicemail_incoming_rtp,
		.incoming_rtcp = janus_voicemail_incoming_rtcp,
		.hangup_media = janus_voicemail_hangup_media,
		.destroy_session = janus_voicemail_destroy_session,
		.query_session = janus_voicemail_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VOICEMAIL_NAME);
	return &janus_voicemail_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static void *janus_voicemail_handler(void *data);

typedef struct janus_voicemail_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_voicemail_message;
static GAsyncQueue *messages = NULL;
static janus_voicemail_message exit_message;

static void janus_voicemail_message_free(janus_voicemail_message *msg) {
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


typedef struct janus_voicemail_session {
	janus_plugin_session *handle;
	guint64 recording_id;
	gint64 start_time;
	char *filename;
	FILE *file;
	ogg_stream_state *stream;
	int seq;
	gboolean started;
	gboolean stopping;
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_voicemail_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static char *recordings_path = NULL;
static char *recordings_base = NULL;

/* SDP offer/answer template */
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=VoiceMail %"SCNu64"\r\n"						/* VoiceMail recording ID */ \
		"t=0 0\r\n" \
		"m=audio 1 RTP/SAVPF %d\r\n"		/* Opus payload type */ \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=rtpmap:%d opus/48000/2\r\n"		/* Opus payload type */ \
		"a=recvonly\r\n"					/* This plugin doesn't send any frames */


/* OGG/Opus helpers */
void le32(unsigned char *p, int v);
void le16(unsigned char *p, int v);
ogg_packet *op_opushead(void);
ogg_packet *op_opustags(void);
ogg_packet *op_from_pkt(const unsigned char *pkt, int len);
void op_free(ogg_packet *op);
int ogg_write(janus_voicemail_session *session);
int ogg_flush(janus_voicemail_session *session);


/* Error codes */
#define JANUS_VOICEMAIL_ERROR_UNKNOWN_ERROR		499
#define JANUS_VOICEMAIL_ERROR_NO_MESSAGE		460
#define JANUS_VOICEMAIL_ERROR_INVALID_JSON		461
#define JANUS_VOICEMAIL_ERROR_INVALID_REQUEST	462
#define JANUS_VOICEMAIL_ERROR_MISSING_ELEMENT	463
#define JANUS_VOICEMAIL_ERROR_INVALID_ELEMENT	464
#define JANUS_VOICEMAIL_ERROR_ALREADY_RECORDING	465
#define JANUS_VOICEMAIL_ERROR_IO_ERROR			466
#define JANUS_VOICEMAIL_ERROR_LIBOGG_ERROR		467


/* VoiceMail watchdog/garbage collector (sort of) */
static void *janus_voicemail_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "VoiceMail watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old VoiceMail sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_voicemail_session *session = (janus_voicemail_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old VoiceMail session\n");
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
	JANUS_LOG(LOG_INFO, "VoiceMail watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_voicemail_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_VOICEMAIL_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	
	sessions = g_hash_table_new(NULL, NULL);
	messages = g_async_queue_new_full((GDestroyNotify) janus_voicemail_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Parse configuration */
	if(config != NULL) {
		janus_config_item *path = janus_config_get_item_drilldown(config, "general", "path");
		if(path && path->value)
			recordings_path = g_strdup(path->value);
		janus_config_item *base = janus_config_get_item_drilldown(config, "general", "base");
		if(base && base->value)
			recordings_base = g_strdup(base->value);
		janus_config_item *events = janus_config_get_item_drilldown(config, "general", "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_VOICEMAIL_NAME);
		}
		/* Done */
		janus_config_destroy(config);
		config = NULL;
	}
	if(recordings_path == NULL)
		recordings_path = g_strdup("./html/recordings/");
	if(recordings_base == NULL)
		recordings_base = g_strdup("/recordings/");
	JANUS_LOG(LOG_VERB, "Recordings path: %s\n", recordings_path);
	JANUS_LOG(LOG_VERB, "Recordings base: %s\n", recordings_base);
	/* Create the folder, if needed */
	struct stat st = {0};
	if(stat(recordings_path, &st) == -1) {
		int res = janus_mkdir(recordings_path, 0755);
		JANUS_LOG(LOG_VERB, "Creating folder: %d\n", res);
		if(res != 0) {
			JANUS_LOG(LOG_ERR, "%s", strerror(errno));
			return -1;	/* No point going on... */
		}
	}
	
	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("voicemail watchdog", &janus_voicemail_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VoiceMail watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("voicemail handler", janus_voicemail_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VoiceMail handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VOICEMAIL_NAME);
	return 0;
}

void janus_voicemail_destroy(void) {
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
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VOICEMAIL_NAME);
}

int janus_voicemail_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_voicemail_get_version(void) {
	return JANUS_VOICEMAIL_VERSION;
}

const char *janus_voicemail_get_version_string(void) {
	return JANUS_VOICEMAIL_VERSION_STRING;
}

const char *janus_voicemail_get_description(void) {
	return JANUS_VOICEMAIL_DESCRIPTION;
}

const char *janus_voicemail_get_name(void) {
	return JANUS_VOICEMAIL_NAME;
}

const char *janus_voicemail_get_author(void) {
	return JANUS_VOICEMAIL_AUTHOR;
}

const char *janus_voicemail_get_package(void) {
	return JANUS_VOICEMAIL_PACKAGE;
}

void janus_voicemail_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_voicemail_session *session = (janus_voicemail_session *)g_malloc0(sizeof(janus_voicemail_session));
	session->handle = handle;
	session->recording_id = janus_random_uint64();
	session->start_time = 0;
	session->stream = NULL;
	char f[255];
	g_snprintf(f, 255, "%s/janus-voicemail-%"SCNu64".opus", recordings_path, session->recording_id);
	session->filename = g_strdup(f);
	session->file = NULL;
	session->seq = 0;
	session->started = FALSE;
	session->stopping = FALSE;
	session->destroyed = 0;
	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_voicemail_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_voicemail_session *session = (janus_voicemail_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No VoiceMail session associated with this handle...\n");
		*error = -2;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	if(!session->destroyed) {
		JANUS_LOG(LOG_VERB, "Removing VoiceMail session...\n");
		g_hash_table_remove(sessions, handle);
		janus_voicemail_hangup_media(handle);
		session->destroyed = janus_get_monotonic_time();
		/* Cleaning up and removing the session is done in a lazy way */
		old_sessions = g_list_append(old_sessions, session);
	}
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_voicemail_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}	
	janus_voicemail_session *session = (janus_voicemail_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "state", json_string(session->stream ? "recording" : "idle"));
	if(session->stream) {
		json_object_set_new(info, "id", json_integer(session->recording_id));
		json_object_set_new(info, "start_time", json_integer(session->start_time));
		json_object_set_new(info, "filename", session->filename ? json_string(session->filename) : NULL);
	}
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	return info;
}

struct janus_plugin_result *janus_voicemail_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_voicemail_message *msg = g_malloc0(sizeof(janus_voicemail_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_voicemail_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_voicemail_session *session = (janus_voicemail_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	g_atomic_int_set(&session->hangingup, 0);
	/* Only start recording this peer when we get this event */
	session->start_time = janus_get_monotonic_time();
	session->started = TRUE;
	/* Prepare JSON event */
	json_t *event = json_object();
	json_object_set_new(event, "voicemail", json_string("event"));
	json_object_set_new(event, "status", json_string("started"));
	int ret = gateway->push_event(handle, &janus_voicemail_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
}

void janus_voicemail_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_voicemail_session *session = (janus_voicemail_session *)handle->plugin_handle;	
	if(!session || session->destroyed || session->stopping || !session->started || session->start_time == 0)
		return;
	gint64 now = janus_get_monotonic_time();
	/* Have 10 seconds passed? */
	if((now-session->start_time) >= 10*G_USEC_PER_SEC) {
		/* FIXME Simulate a "stop" coming from the browser */
		session->started = FALSE;
		janus_voicemail_message *msg = g_malloc0(sizeof(janus_voicemail_message));
		msg->handle = handle;
		msg->message = json_pack("{ss}", "request", "stop");
		msg->transaction = NULL;
		msg->jsep = NULL;
		g_async_queue_push(messages, msg);
		return;
	}
	/* Save the frame */
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	uint16_t seq = ntohs(rtp->seq_number);
	if(session->seq == 0)
		session->seq = seq;
	int plen = 0;
	const unsigned char *payload = (const unsigned char *)janus_rtp_payload(buf, len, &plen);
	if(!payload) {
		JANUS_LOG(LOG_ERR, "Ops! got an error accessing the RTP payload\n");
		return;
	}
	ogg_packet *op = op_from_pkt(payload, plen);
	//~ JANUS_LOG(LOG_VERB, "\tWriting at position %d (%d)\n", seq-session->seq+1, 960*(seq-session->seq+1));
	op->granulepos = 960*(seq-session->seq+1); // FIXME: get this from the toc byte
	ogg_stream_packetin(session->stream, op);
	g_free(op);
	ogg_write(session);
}

void janus_voicemail_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* FIXME Should we care? */
}

void janus_voicemail_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_voicemail_session *session = (janus_voicemail_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	session->started = FALSE;
	if(session->destroyed)
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	/* Close and reset stuff */
	if(session->file)
		fclose(session->file);
	session->file = NULL;
	if(session->stream)
		ogg_stream_destroy(session->stream);
	session->stream = NULL;
}

/* Thread to handle incoming messages */
static void *janus_voicemail_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining VoiceMail handler thread\n");
	janus_voicemail_message *msg = NULL;
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
			janus_voicemail_message_free(msg);
			continue;
		}
		janus_voicemail_session *session = NULL;
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_lookup(sessions, msg->handle) != NULL ) {
			session = (janus_voicemail_session *)msg->handle->plugin_handle;
		}
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_voicemail_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_mutex_unlock(&sessions_mutex);
			janus_voicemail_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VOICEMAIL_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_VOICEMAIL_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Get the request first */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_VOICEMAIL_ERROR_MISSING_ELEMENT, JANUS_VOICEMAIL_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *event = NULL;
		if(!strcasecmp(request_text, "record")) {
			JANUS_LOG(LOG_VERB, "Starting new recording\n");
			if(session->file != NULL) {
				JANUS_LOG(LOG_ERR, "Already recording (%s)\n", session->filename ? session->filename : "??");
				error_code = JANUS_VOICEMAIL_ERROR_ALREADY_RECORDING;
				g_snprintf(error_cause, 512, "Already recording");
				goto error;
			}
			session->stream = g_malloc0(sizeof(ogg_stream_state));
			if(session->stream == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't allocate stream struct\n");
				error_code = JANUS_VOICEMAIL_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Couldn't allocate stream struct");
				goto error;
			}
			if(ogg_stream_init(session->stream, rand()) < 0) {
				JANUS_LOG(LOG_ERR, "Couldn't initialize Ogg stream state\n");
				error_code = JANUS_VOICEMAIL_ERROR_LIBOGG_ERROR;
				g_snprintf(error_cause, 512, "Couldn't initialize Ogg stream state\n");
				goto error;
			}
			session->file = fopen(session->filename, "wb");
			if(session->file == NULL) {
				JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
				error_code = JANUS_VOICEMAIL_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Couldn't open output file");
				goto error;
			}
			session->seq = 0;
			/* Write stream headers */
			ogg_packet *op = op_opushead();
			ogg_stream_packetin(session->stream, op);
			op_free(op);
			op = op_opustags();
			ogg_stream_packetin(session->stream, op);
			op_free(op);
			ogg_flush(session);
			/* Done: now wait for the setup_media callback to be called */
			event = json_object();
			json_object_set_new(event, "voicemail", json_string("event"));
			json_object_set_new(event, "status", json_string(session->started ? "started" : "starting"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("starting"));
				gateway->notify_event(&janus_voicemail_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "stop")) {
			/* Stop the recording */
			session->started = FALSE;
			session->stopping = TRUE;
			if(session->file)
				fclose(session->file);
			session->file = NULL;
			if(session->stream)
				ogg_stream_destroy(session->stream);
			session->stream = NULL;
			/* Done: send the event and close the handle */
			event = json_object();
			json_object_set_new(event, "voicemail", json_string("event"));
			json_object_set_new(event, "status", json_string("done"));
			char url[1024];
			g_snprintf(url, 1024, "%s/janus-voicemail-%"SCNu64".opus", recordings_base, session->recording_id);
			json_object_set_new(event, "recording", json_string(url));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("done"));
				gateway->notify_event(&janus_voicemail_plugin, session->handle, info);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request '%s'\n", request_text);
			error_code = JANUS_VOICEMAIL_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		JANUS_LOG(LOG_VERB, "Preparing JSON event as a reply\n");
		/* Any SDP to handle? */
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		if(!msg_sdp) {
			int ret = gateway->push_event(msg->handle, &janus_voicemail_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			const char *type = NULL;
			if(!strcasecmp(msg_sdp_type, "offer"))
				type = "answer";
			if(!strcasecmp(msg_sdp_type, "answer"))
				type = "offer";
			/* Fill the SDP template and use that as our answer */
			char sdp[1024];
			/* What is the Opus payload type? */
			int opus_pt = janus_get_codec_pt(msg_sdp, "opus");
			JANUS_LOG(LOG_VERB, "Opus payload type is %d\n", opus_pt);
			g_snprintf(sdp, 1024, sdp_template,
				janus_get_real_time(),			/* We need current time here */
				janus_get_real_time(),			/* We need current time here */
				session->recording_id,			/* Recording ID */
				opus_pt,						/* Opus payload type */
				opus_pt							/* Opus payload type */);
			/* Did the peer negotiate video? */
			if(strstr(msg_sdp, "m=video") != NULL) {
				/* If so, reject it */
				g_strlcat(sdp, "m=video 0 RTP/SAVPF 0\r\n", 1024);				
			}
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_voicemail_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
			json_decref(event);
			json_decref(jsep);
			if(res != JANUS_OK) {
				/* TODO Failed to negotiate? We should remove this participant */
			}
		}
		janus_voicemail_message_free(msg);
		
		if(session->stopping) {
			gateway->end_session(session->handle);
		}

		continue;
		
error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "voicemail", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_voicemail_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_voicemail_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving VoiceMail handler thread\n");
	return NULL;
}


/* OGG/Opus helpers */
/* Write a little-endian 32 bit int to memory */
void le32(unsigned char *p, int v) {
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}


/* Write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v) {
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

/* ;anufacture a generic OpusHead packet */
ogg_packet *op_opushead(void) {
	int size = 19;
	unsigned char *data = g_malloc0(size);
	ogg_packet *op = g_malloc0(sizeof(*op));

	if(!data) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate data buffer...\n");
		return NULL;
	}
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet...\n");
		return NULL;
	}

	memcpy(data, "OpusHead", 8);  /* identifier */
	data[8] = 1;                  /* version */
	data[9] = 2;                  /* channels */
	le16(data+10, 0);             /* pre-skip */
	le32(data + 12, 48000);       /* original sample rate */
	le16(data + 16, 0);           /* gain */
	data[18] = 0;                 /* channel mapping family */

	op->packet = data;
	op->bytes = size;
	op->b_o_s = 1;
	op->e_o_s = 0;
	op->granulepos = 0;
	op->packetno = 0;

	return op;
}

/* Manufacture a generic OpusTags packet */
ogg_packet *op_opustags(void) {
	const char *identifier = "OpusTags";
	const char *vendor = "Janus VoiceMail plugin";
	int size = strlen(identifier) + 4 + strlen(vendor) + 4;
	unsigned char *data = g_malloc0(size);
	ogg_packet *op = g_malloc0(sizeof(*op));

	if(!data) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate data buffer...\n");
		return NULL;
	}
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet...\n");
		return NULL;
	}

	memcpy(data, identifier, 8);
	le32(data + 8, strlen(vendor));
	memcpy(data + 12, vendor, strlen(vendor));
	le32(data + 12 + strlen(vendor), 0);

	op->packet = data;
	op->bytes = size;
	op->b_o_s = 0;
	op->e_o_s = 0;
	op->granulepos = 0;
	op->packetno = 1;

	return op;
}

/* Allocate an ogg_packet */
ogg_packet *op_from_pkt(const unsigned char *pkt, int len) {
	ogg_packet *op = g_malloc0(sizeof(*op));
	if(!op) {
		JANUS_LOG(LOG_ERR, "Couldn't allocate Ogg packet.\n");
		return NULL;
	}

	op->packet = (unsigned char *)pkt;
	op->bytes = len;
	op->b_o_s = 0;
	op->e_o_s = 0;

	return op;
}

/* Free a packet and its contents */
void op_free(ogg_packet *op) {
	if(op) {
		if(op->packet) {
			g_free(op->packet);
		}
		g_free(op);
	}
}

/* Write out available ogg pages */
int ogg_write(janus_voicemail_session *session) {
	ogg_page page;
	size_t written;

	if(!session || !session->stream || !session->file) {
		return -1;
	}

	while (ogg_stream_pageout(session->stream, &page)) {
		written = fwrite(page.header, 1, page.header_len, session->file);
		if(written != (size_t)page.header_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page header\n");
			return -2;
		}
		written = fwrite(page.body, 1, page.body_len, session->file);
		if(written != (size_t)page.body_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page body\n");
			return -3;
		}
	}
	return 0;
}

/* Flush remaining ogg data */
int ogg_flush(janus_voicemail_session *session) {
	ogg_page page;
	size_t written;

	if(!session || !session->stream || !session->file) {
		return -1;
	}

	while (ogg_stream_flush(session->stream, &page)) {
		written = fwrite(page.header, 1, page.header_len, session->file);
		if(written != (size_t)page.header_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page header\n");
			return -2;
		}
		written = fwrite(page.body, 1, page.body_len, session->file);
		if(written != (size_t)page.body_len) {
			JANUS_LOG(LOG_ERR, "Error writing Ogg page body\n");
			return -3;
		}
	}
	return 0;
}
