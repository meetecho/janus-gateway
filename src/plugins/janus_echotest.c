/*! \file   janus_echotest.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus EchoTest plugin
 * \details Check the \ref echotest for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page echotest EchoTest plugin documentation
 * This is a trivial EchoTest plugin for Janus, just used to
 * showcase the plugin interface. A peer attaching to this plugin will
 * receive back the same RTP packets and RTCP messages he sends: the
 * RTCP messages, of course, would be modified on the way by the Janus core
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
 * The request has to be formatted as follows. All the attributes are
 * optional, so any request can contain a subset of them:
 *
\verbatim
{
	"audio" : true|false,
	"audiocodec" : "<optional codec name; only used when creating a PeerConnection>",
	"video" : true|false,
	"videocodec" : "<optional codec name; only used when creating a PeerConnection>",
	"videoprofile" : "<optional codec profile to force; only used when creating a PeerConnection, only valid for VP9 (0 or 2) and H.264 (e.g., 42e01f)>",
	"bitrate" : <numeric bitrate value>,
	"record" : true|false,
	"filename" : <base path/filename to use for the recording>,
	"substream" : <substream to receive (0-2), in case simulcasting is enabled>,
	"temporal" : <temporal layers to receive (0-2), in case simulcasting is enabled>,
	"svc" : true|false,
	"spatial_layer" : <spatial layer to receive (0-2), in case SVC is enabled>,
	"temporal_layer" : <temporal layers to receive (0-2), in case SVC is enabled>
}
\endverbatim
 *
 * When negotiating a new PeerConnection, by default the EchoTest tries to
 * use the preferred audio codecs as set by the user; if for any reason you
 * want to override what the browsers offered first and use a different
 * codec instead (e.g., to try VP9 instead of VP8), you can use the
 * \c audiocodec property for audio, and \c videocodec for video. For video
 * codecs supporting a specific profile negotiation (VP9 and H.264), you can
 * specify which profile you're interested in using the \c videoprofile property.
 *
 * All the other settings can be applied dynamically during the session:
 * \c audio instructs the plugin to do or do not bounce back audio
 * frames; \c video does the same for video; \c bitrate caps the
 * bandwidth to force on the browser encoding side (e.g., 128000 for
 * 128kbps); \c record enables or disables the recording of this peer;
 * in case recording is enabled, \c filename allows to specify a base
 * path/filename to use for the files (-audio.mjr, -video.mjr and -data.mjr
 * are automatically appended); finally, in case the session uses
 * simulcasting, \c substream and \c temporal can be used to manually
 * pick which substream and/or temporal layer should be received back,
 * while \c spatial_layer and \c temporal_layer provide the same
 * functionality but within the context of SVC.
 *
 * A JSEP offer can be sent along any request to negotiate a PeerConnection:
 * in that case, a JSEP answer will be provided with the asynchronous
 * response notification. Other requests (e.g., to dynamically manipulate
 * the bitrate while testing) have to be sent without any JSEP payload
 * attached, unless you want to renegotiate a session (e.g., to add/remove
 * a media stream, or force an ICE restart): in case of renegotiations,
 * the same rules as the first JSEP offer apply.
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
 */

#include "plugin.h"

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../sdp-utils.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_ECHOTEST_VERSION			7
#define JANUS_ECHOTEST_VERSION_STRING	"0.0.7"
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
struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_echotest_handle_admin_message(json_t *message);
void janus_echotest_setup_media(janus_plugin_session *handle);
void janus_echotest_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_echotest_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
void janus_echotest_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet);
void janus_echotest_data_ready(janus_plugin_session *handle);
void janus_echotest_slow_link(janus_plugin_session *handle, int mindex, gboolean video, gboolean uplink);
void janus_echotest_hangup_media(janus_plugin_session *handle);
void janus_echotest_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_echotest_query_session(janus_plugin_session *handle);

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
		.handle_admin_message = janus_echotest_handle_admin_message,
		.setup_media = janus_echotest_setup_media,
		.incoming_rtp = janus_echotest_incoming_rtp,
		.incoming_rtcp = janus_echotest_incoming_rtcp,
		.incoming_data = janus_echotest_incoming_data,
		.data_ready = janus_echotest_data_ready,
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

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0},
	{"substream", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"fallback", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"svc", JANUS_JSON_BOOL, 0},
	{"spatial_layer", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"temporal_layer", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"audiocodec", JSON_STRING, 0},
	{"videocodec", JSON_STRING, 0},
	{"videoprofile", JSON_STRING, 0},
	{"opusred", JANUS_JSON_BOOL, 0},
	{"min_delay", JSON_INTEGER, 0},
	{"max_delay", JSON_INTEGER, 0},
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_echotest_handler(void *data);
static void janus_echotest_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_echotest_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_echotest_message;
static GAsyncQueue *messages = NULL;
static janus_echotest_message exit_message;

typedef struct janus_echotest_session {
	janus_plugin_session *handle;
	gboolean has_audio;
	gboolean has_video;
	gboolean has_data;
	gboolean audio_active;
	gboolean video_active;
	janus_audiocodec acodec;/* Codec used for audio, if available */
	janus_videocodec vcodec;/* Codec used for video, if available */
	char *vfmtp;
	int opusred_pt;
	uint32_t bitrate, peer_bitrate;
	janus_rtp_switching_context context;
	uint32_t ssrc[3];		/* Only needed in case VP8 (or H.264) simulcasting is involved */
	char *rid[3];			/* Only needed if simulcasting is rid-based */
	janus_mutex rid_mutex;	/* Mutex to protect access to the rid array */
	janus_rtp_simulcasting_context sim_context;
	janus_vp8_simulcast_context vp8_context;
	gboolean svc;
	janus_rtp_svc_context svc_context;
	janus_recorder *arc;	/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *drc;	/* The Janus recorder instance for this user's data, if enabled */
	gboolean e2ee;			/* Whether media is encrypted, e.g., using Insertable Streams */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	guint16 slowlink_count;
	int16_t min_delay, max_delay;
	int8_t spatial_layers, temporal_layers;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_echotest_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_echotest_session_destroy(janus_echotest_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_echotest_session_free(const janus_refcount *session_ref) {
	janus_echotest_session *session = janus_refcount_containerof(session_ref, janus_echotest_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session->vfmtp);
	janus_mutex_destroy(&session->rid_mutex);
	janus_mutex_destroy(&session->rec_mutex);
	janus_rtp_simulcasting_cleanup(NULL, NULL, session->rid, NULL);
	janus_rtp_svc_context_reset(&session->svc_context);
	g_free(session);
}

static void janus_echotest_message_free(janus_echotest_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_echotest_session *session = (janus_echotest_session *)msg->handle->plugin_handle;
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


/* Error codes */
#define JANUS_ECHOTEST_ERROR_NO_MESSAGE			411
#define JANUS_ECHOTEST_ERROR_INVALID_JSON		412
#define JANUS_ECHOTEST_ERROR_INVALID_ELEMENT	413
#define JANUS_ECHOTEST_ERROR_INVALID_SDP		414


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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_ECHOTEST_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_ECHOTEST_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_ECHOTEST_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_ECHOTEST_NAME);
		}
	}
	janus_config_destroy(config);
	config = NULL;

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_echotest_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_echotest_message_free);
	/* This is the callback we'll need to invoke to contact the server */
	gateway = callback;
	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("echotest handler", janus_echotest_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest handler thread...\n", error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_ECHOTEST_NAME);
	return 0;
}

void janus_echotest_destroy(void) {
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
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;

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

static janus_echotest_session *janus_echotest_lookup_session(janus_plugin_session *handle) {
	janus_echotest_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_echotest_session *)handle->plugin_handle;
	}
	return session;
}

void janus_echotest_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_echotest_session *session = g_malloc0(sizeof(janus_echotest_session));
	session->handle = handle;
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	janus_mutex_init(&session->rec_mutex);
	session->bitrate = 0;	/* No limit */
	session->peer_bitrate = 0;
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	janus_rtp_svc_context_reset(&session->svc_context);
	janus_mutex_init(&session->rid_mutex);
	session->min_delay = -1;
	session->max_delay = -1;
	session->spatial_layers = -1;
	session->temporal_layers = -1;
	session->destroyed = 0;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_echotest_session_free);
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
	janus_mutex_lock(&sessions_mutex);
	janus_echotest_session *session = janus_echotest_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Echo Test session...\n");
	janus_echotest_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_echotest_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_echotest_session *session = janus_echotest_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "audio_active", session->audio_active ? json_true() : json_false());
	json_object_set_new(info, "video_active", session->video_active ? json_true() : json_false());
	if(session->acodec != JANUS_AUDIOCODEC_NONE) {
		json_object_set_new(info, "audio_codec", json_string(janus_audiocodec_name(session->acodec)));
		if(session->opusred_pt)
			json_object_set_new(info, "audio_red", json_true());
	}
	if(session->vcodec != JANUS_VIDEOCODEC_NONE)
		json_object_set_new(info, "video_codec", json_string(janus_videocodec_name(session->vcodec)));
	json_object_set_new(info, "bitrate", json_integer(session->bitrate));
	json_object_set_new(info, "peer-bitrate", json_integer(session->peer_bitrate));
	if(session->ssrc[0] != 0 || session->rid[0] != NULL) {
		json_object_set_new(info, "simulcast", json_true());
		json_object_set_new(info, "substream", json_integer(session->sim_context.substream));
		json_object_set_new(info, "substream-target", json_integer(session->sim_context.substream_target));
		json_object_set_new(info, "temporal-layer", json_integer(session->sim_context.templayer));
		json_object_set_new(info, "temporal-layer-target", json_integer(session->sim_context.templayer_target));
		if(session->sim_context.drop_trigger > 0)
			json_object_set_new(info, "fallback", json_integer(session->sim_context.drop_trigger));
	}
	if(session->svc) {
		json_object_set_new(info, "svc", json_true());
		json_object_set_new(info, "spatial-layer", json_integer(session->svc_context.spatial));
		json_object_set_new(info, "spatial-layer-target", json_integer(session->svc_context.spatial_target));
		json_object_set_new(info, "temporal-layer", json_integer(session->svc_context.temporal));
		json_object_set_new(info, "temporal-layer-target", json_integer(session->svc_context.temporal_target));
	}
	if(session->arc || session->vrc || session->drc) {
		json_t *recording = json_object();
		if(session->arc && session->arc->filename)
			json_object_set_new(recording, "audio", json_string(session->arc->filename));
		if(session->vrc && session->vrc->filename)
			json_object_set_new(recording, "video", json_string(session->vrc->filename));
		if(session->drc && session->drc->filename)
			json_object_set_new(recording, "data", json_string(session->drc->filename));
		json_object_set_new(info, "recording", recording);
	}
	if(session->e2ee)
		json_object_set_new(info, "e2ee", json_true());
	json_object_set_new(info, "slowlink_count", json_integer(session->slowlink_count));
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	janus_echotest_message *msg = g_malloc(sizeof(janus_echotest_message));
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);

	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously: we add a comment
	 * (a JSON object with a "hint" string in it, that's what the core expects),
	 * but we don't have to: other plugins don't put anything in there */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, "I'm taking my time!", NULL);
}

json_t *janus_echotest_handle_admin_message(json_t *message) {
	/* Just here as a proof of concept: since there's nothing to configure,
	 * as an EchoTest plugin we echo this Admin request back as well */
	json_t *response = json_deep_copy(message);
	return response;
}

void janus_echotest_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_ECHOTEST_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_echotest_session *session = janus_echotest_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_unlock(&sessions_mutex);
	/* We really don't care, as we only send RTP/RTCP we get in the first place back anyway */
}

void janus_echotest_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		gboolean video = packet->video;
		char *buf = packet->buffer;
		uint16_t len = packet->length;
		if(session->min_delay > -1 && session->max_delay > -1) {
			packet->extensions.min_delay = session->min_delay;
			packet->extensions.max_delay = session->max_delay;
		}
		gboolean new_vla = FALSE;
		if(packet->extensions.spatial_layers > -1 || packet->extensions.temporal_layers > -1) {
			/* We have info from the video-layers-allocation RTP extension */
			if(packet->extensions.spatial_layers != session->spatial_layers ||
					packet->extensions.temporal_layers != session->temporal_layers) {
				/* It's new information, keep track of it */
				new_vla = TRUE;
				session->spatial_layers = packet->extensions.spatial_layers;
				session->temporal_layers = packet->extensions.temporal_layers;
			}
		}
		gboolean simulcast = (session->ssrc[0] != 0 || session->rid[0] != NULL);
		if(video && session->video_active && (simulcast || session->svc)) {
			/* Handle simulcast or SVC: backup the header information first */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			uint32_t seq_number = ntohs(header->seq_number);
			uint32_t timestamp = ntohl(header->timestamp);
			uint32_t ssrc = ntohl(header->ssrc);
			gboolean relay = FALSE;
			if(simulcast) {
				/* Process this simulcast packet: don't relay if it's not the SSRC/layer we wanted to handle */
				relay = janus_rtp_simulcasting_context_process_rtp(&session->sim_context,
					buf, len, packet->extensions.dd_content, packet->extensions.dd_len,
					session->ssrc, session->rid, session->vcodec, &session->context, &session->rid_mutex);
			} else {
				/* Process this SVC packet: don't relay if it's not the layer we wanted to handle */
				relay = janus_rtp_svc_context_process_rtp(&session->svc_context,
					buf, len, packet->extensions.dd_content, packet->extensions.dd_len, session->vcodec, NULL, &session->context);
			}
			if(session->sim_context.need_pli || session->svc_context.need_pli) {
				/* Send a PLI */
				gateway->send_pli(handle);
			}
			/* Do we need to drop this? */
			if(!relay)
				return;
			/* Any event we should notify? */
			if(simulcast && (new_vla || session->sim_context.changed_substream || session->sim_context.changed_temporal)) {
				/* Notify the user about the substream change */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "substream", json_integer(session->sim_context.substream));
				json_object_set_new(event, "temporal", json_integer(session->sim_context.templayer));
				if(session->temporal_layers > -1)
					json_object_set_new(event, "tot_temporal_layers", json_integer(session->temporal_layers));
				gateway->push_event(handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			}
			if(session->svc && (new_vla || session->svc_context.changed_spatial || session->svc_context.changed_temporal)) {
				/* Notify the user about the spatial layer change */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "spatial_layer", json_integer(session->svc_context.spatial));
				json_object_set_new(event, "temporal_layer", json_integer(session->svc_context.temporal));
				if(session->spatial_layers > -1)
					json_object_set_new(event, "tot_spatial_layers", json_integer(session->spatial_layers));
				if(session->temporal_layers > -1)
					json_object_set_new(event, "tot_temporal_layers", json_integer(session->temporal_layers));
				gateway->push_event(handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			}
			/* If we got here, update the RTP header and send the packet */
			janus_rtp_header_update(header, &session->context, TRUE, 0);
			if(session->vcodec == JANUS_VIDEOCODEC_VP8) {
				int plen = 0;
				char *payload = janus_rtp_payload(buf, len, &plen);
				janus_vp8_simulcast_descriptor_update(payload, plen, &session->vp8_context, session->sim_context.changed_substream);
			}
			/* Save the frame if we're recording (and make sure the SSRC never changes even if the substream does) */
			header->ssrc = htonl(1);
			janus_recorder_save_frame(session->vrc, buf, len);
			/* Send the frame back */
			gateway->relay_rtp(handle, packet);
			/* Restore header or core statistics will be messed up */
			header->ssrc = htonl(ssrc);
			header->timestamp = htonl(timestamp);
			header->seq_number = htons(seq_number);
		} else {
			if((!video && session->audio_active) || (video && session->video_active)) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
				/* Send the frame back */
				gateway->relay_rtp(handle, packet);
			}
		}
	}
}

void janus_echotest_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		guint32 bitrate = janus_rtcp_get_remb(packet->buffer, packet->length);
		if(bitrate > 0) {
			/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
			session->peer_bitrate = bitrate;
			/* No limit ~= 10000000 */
			gateway->send_remb(handle, session->bitrate ? session->bitrate : 10000000);
			return;
		}
		gateway->relay_rtcp(handle, packet);
	}
}

void janus_echotest_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		if(packet->buffer == NULL || packet->length == 0)
			return;
		char *label = packet->label;
		char *protocol = packet->protocol;
		char *buf = packet->buffer;
		uint16_t len = packet->length;
		if(packet->binary) {
			JANUS_LOG(LOG_VERB, "Got a binary DataChannel message (label=%s, protocol=%s, %d bytes) to bounce back\n",
				label, protocol, len);
			/* Save the frame if we're recording */
			janus_recorder_save_frame(session->drc, buf, len);
			/* Binary data, shoot back as it is */
			gateway->relay_data(handle, packet);
			return;
		}
		/* Text data */
		char *text = g_malloc(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (label=%s, protocol=%s, %zu bytes) to bounce back: %s\n",
			label, protocol, strlen(text), text);
		/* Save the frame if we're recording */
		janus_recorder_save_frame(session->drc, text, strlen(text));
		/* We send back the same text with a custom prefix */
		const char *prefix = "Janus EchoTest here! You wrote: ";
		char *reply = g_malloc(strlen(prefix)+len+1);
		g_snprintf(reply, strlen(prefix)+len+1, "%s%s", prefix, text);
		g_free(text);
		/* Prepare the packet and send it back */
		janus_plugin_data r = {
			.label = label,
			.protocol = protocol,
			.binary = FALSE,
			.buffer = reply,
			.length = strlen(reply)
		};
		gateway->relay_data(handle, &r);
		g_free(reply);
	}
}

void janus_echotest_data_ready(janus_plugin_session *handle) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) ||
			g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	/* Data channels are writable */
}

void janus_echotest_slow_link(janus_plugin_session *handle, int mindex, gboolean video, gboolean uplink) {
	/* The core is informing us that our peer got or sent too many NACKs, are we pushing media too hard? */
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_echotest_session *session = janus_echotest_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	session->slowlink_count++;
	if(uplink && !video && !session->audio_active) {
		/* We're not relaying audio and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for audio, but that's expected, a configure disabled the audio forwarding\n");
	} else if(uplink && video && !session->video_active) {
		/* We're not relaying video and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for video, but that's expected, a configure disabled the video forwarding\n");
	} else {
		JANUS_LOG(LOG_WARN, "Getting a lot of NACKs (slow %s) for %s\n",
			uplink ? "uplink" : "downlink", video ? "video" : "audio");
		if(!uplink) {
			/* Send an event on the handle to notify the application: it's
			 * up to the application to then choose a policy and enforce it */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_object_set_new(event, "event", json_string("slow_link"));
			json_object_set_new(event, "media", json_string(video ? "video" : "audio"));
			if(video) {
				/* Also add info on what the current bitrate cap is */
				json_object_set_new(event, "current-bitrate", json_integer(session->bitrate));
			}
			gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
			json_decref(event);
		}
	}
	janus_refcount_decrease(&session->ref);
}

static void janus_echotest_recorder_close(janus_echotest_session *session) {
	if(session->arc) {
		janus_recorder *rc = session->arc;
		session->arc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed audio recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	if(session->vrc) {
		janus_recorder *rc = session->vrc;
		session->vrc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed video recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	if(session->drc) {
		janus_recorder *rc = session->drc;
		session->drc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed data recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
}

void janus_echotest_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_ECHOTEST_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_echotest_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_echotest_hangup_media_internal(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = janus_echotest_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "echotest", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_echotest_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	janus_echotest_recorder_close(session);
	janus_mutex_unlock(&session->rec_mutex);
	/* Reset controls */
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->acodec = JANUS_AUDIOCODEC_NONE;
	session->vcodec = JANUS_VIDEOCODEC_NONE;
	g_free(session->vfmtp);
	session->vfmtp = NULL;
	session->opusred_pt = -1;
	session->e2ee = FALSE;
	session->bitrate = 0;
	session->peer_bitrate = 0;
	janus_rtp_simulcasting_cleanup(NULL, session->ssrc, session->rid, &session->rid_mutex);
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	session->min_delay = -1;
	session->max_delay = -1;
	session->spatial_layers = -1;
	session->temporal_layers = -1;
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_echotest_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining EchoTest handler thread\n");
	janus_echotest_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_echotest_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_echotest_session *session = janus_echotest_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_echotest_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_echotest_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_ECHOTEST_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			0, JANUS_ECHOTEST_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
		if(msg_simulcast && json_array_size(msg_simulcast) > 0) {
			size_t i = 0;
			for(i=0; i<json_array_size(msg_simulcast); i++) {
				json_t *s = json_array_get(msg_simulcast, i);
				int mindex = json_integer_value(json_object_get(s, "mindex"));
				JANUS_LOG(LOG_VERB, "EchoTest client is going to do simulcasting (#%d)\n", mindex);
				int rid_ext_id = -1;
				janus_mutex_lock(&session->rid_mutex);
				/* Clear existing RIDs in case this is a renegotiation */
				janus_rtp_simulcasting_cleanup(NULL, NULL, session->rid, NULL);
				janus_rtp_simulcasting_prepare(s, &rid_ext_id, session->ssrc, session->rid);
				session->sim_context.rid_ext_id = rid_ext_id;
				janus_mutex_unlock(&session->rid_mutex);
				session->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
				session->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
				/* FIXME We're stopping at the first item, there may be more */
				break;
			}
		}
		json_t *msg_svc = json_object_get(msg->jsep, "svc");
		if(msg_svc && json_array_size(msg_svc) > 0) {
			size_t i = 0;
			for(i=0; i<json_array_size(msg_svc); i++) {
				json_t *s = json_array_get(msg_svc, i);
				int mindex = json_integer_value(json_object_get(s, "mindex"));
				JANUS_LOG(LOG_VERB, "EchoTest client is going to do SVC (#%d)\n", mindex);
				if(!session->svc) {
					janus_rtp_svc_context_reset(&session->svc_context);
					session->svc_context.spatial_target = 2;	/* FIXME Actually depends on the scalabilityMode */
					session->svc_context.temporal_target = 2;	/* FIXME Actually depends on the scalabilityMode */
					session->svc = TRUE;
				}
				/* FIXME We're stopping at the first item, there may be more */
				break;
			}
		}
		json_t *msg_e2ee = json_object_get(msg->jsep, "e2ee");
		if(json_is_true(msg_e2ee))
			session->e2ee = TRUE;
		json_t *audio = json_object_get(root, "audio");
		json_t *video = json_object_get(root, "video");
		json_t *bitrate = json_object_get(root, "bitrate");
		json_t *substream = json_object_get(root, "substream");
		if(substream && json_integer_value(substream) > 2) {
			JANUS_LOG(LOG_ERR, "Invalid element (substream should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (substream should be 0, 1 or 2)");
			goto error;
		}
		json_t *temporal = json_object_get(root, "temporal");
		if(temporal && json_integer_value(temporal) > 2) {
			JANUS_LOG(LOG_ERR, "Invalid element (temporal should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (temporal should be 0, 1 or 2)");
			goto error;
		}
		json_t *spatial_layer = json_object_get(root, "spatial_layer");
		if(spatial_layer && json_integer_value(spatial_layer) > 2) {
			JANUS_LOG(LOG_ERR, "Invalid element (spatial_layer should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (spatial_layer should be 0, 1 or 2)");
			goto error;
		}
		json_t *temporal_layer = json_object_get(root, "temporal_layer");
		if(temporal_layer && json_integer_value(temporal_layer) > 2) {
			JANUS_LOG(LOG_ERR, "Invalid element (temporal_layer should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (temporal_layer should be 0, 1 or 2)");
			goto error;
		}
		json_t *fallback = json_object_get(root, "fallback");
		json_t *record = json_object_get(root, "record");
		json_t *recfile = json_object_get(root, "filename");
		json_t *audiocodec = json_object_get(root, "audiocodec");
		json_t *videocodec = json_object_get(root, "videocodec");
		json_t *videoprofile = json_object_get(root, "videoprofile");
		json_t *opusred = json_object_get(root, "opusred");
		json_t *min_delay = json_object_get(root, "min_delay");
		json_t *max_delay = json_object_get(root, "max_delay");
		/* Enforce request */
		if(audio) {
			session->audio_active = json_is_true(audio);
			JANUS_LOG(LOG_VERB, "Setting audio property: %s\n", session->audio_active ? "true" : "false");
		}
		if(video) {
			if(!session->video_active && json_is_true(video)) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "Just (re-)enabled video, sending a PLI to recover it\n");
				gateway->send_pli(session->handle);
			}
			session->video_active = json_is_true(video);
			JANUS_LOG(LOG_VERB, "Setting video property: %s\n", session->video_active ? "true" : "false");
		}
		if(bitrate) {
			session->bitrate = json_integer_value(bitrate);
			JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu32"\n", session->bitrate);
			gateway->send_remb(session->handle, session->bitrate ? session->bitrate : 10000000);
		}
		if(fallback) {
			JANUS_LOG(LOG_VERB, "Setting fallback timer (simulcast): %lld (was %"SCNu32")\n",
				json_integer_value(fallback) ? json_integer_value(fallback) : 250000,
				session->sim_context.drop_trigger ? session->sim_context.drop_trigger : 250000);
			session->sim_context.drop_trigger = json_integer_value(fallback);
		}
		if(substream) {
			session->sim_context.substream_target = json_integer_value(substream);
			if(session->sim_context.substream_target >= 0 && session->sim_context.substream_target <= 2) {
				JANUS_LOG(LOG_VERB, "Setting video SSRC to let through (simulcast): %"SCNu32" (index %d, was %d)\n",
					session->ssrc[session->sim_context.substream_target], session->sim_context.substream_target, session->sim_context.substream);
			}
			if(session->sim_context.substream_target == session->sim_context.substream) {
				/* No need to do anything, we're already getting the right substream, so notify the user */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "substream", json_integer(session->sim_context.substream));
				gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			} else {
				/* We need to change substream, send a PLI */
				JANUS_LOG(LOG_VERB, "Simulcasting substream change, sending a PLI to kickstart it\n");
				gateway->send_pli(session->handle);
			}
		}
		if(temporal) {
			session->sim_context.templayer_target = json_integer_value(temporal);
			JANUS_LOG(LOG_VERB, "Setting video temporal layer to let through (simulcast): %d (was %d)\n",
				session->sim_context.templayer_target, session->sim_context.templayer);
			if(session->sim_context.templayer_target == session->sim_context.templayer) {
				/* No need to do anything, we're already getting the right temporal, so notify the user */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "temporal", json_integer(session->sim_context.templayer));
				gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			} else {
				/* We need to change temporal, send a PLI */
				JANUS_LOG(LOG_VERB, "Simulcasting temporal layer change, sending a PLI to kickstart it\n");
				gateway->send_pli(session->handle);
			}
		}
		if(spatial_layer) {
			session->svc_context.spatial_target = json_integer_value(spatial_layer);
			if(session->svc_context.spatial_target == session->svc_context.spatial) {
				/* No need to do anything, we're already getting the right spatial layer, so notify the user */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "spatial_layer", json_integer(session->svc_context.spatial));
				gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			} else {
				/* We need to change spatial layer, send a PLI */
				JANUS_LOG(LOG_VERB, "SVC spatial layer change, sending a PLI to kickstart it\n");
				gateway->send_pli(session->handle);
			}
		}
		if(temporal_layer) {
			session->svc_context.temporal_target = json_integer_value(temporal_layer);
			if(session->svc_context.temporal_target == session->svc_context.temporal) {
				/* No need to do anything, we're already getting the right temporal layer, so notify the user */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "temporal_layer", json_integer(session->svc_context.temporal));
				gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			} else {
				/* We need to change temporal layer, send a PLI */
				JANUS_LOG(LOG_VERB, "SVC temporal layer change, sending a PLI to kickstart it\n");
				gateway->send_pli(session->handle);
			}
		}
		if(min_delay) {
			int16_t md = json_integer_value(min_delay);
			if(md < 0) {
				session->min_delay = -1;
				session->max_delay = -1;
			} else {
				session->min_delay = md;
				if(session->min_delay > session->max_delay)
					session->max_delay = session->min_delay;
			}
		}
		if(max_delay) {
			int16_t md = json_integer_value(max_delay);
			if(md < 0) {
				session->min_delay = -1;
				session->max_delay = -1;
			} else {
				session->max_delay = md;
				if(session->max_delay < session->min_delay)
					session->min_delay = session->max_delay;
			}
		}

		/* Any SDP to handle? */
		if(msg_sdp) {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
			session->has_video = (strstr(msg_sdp, "m=video") != NULL);
			session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);
		}

		if(!audio && !video && !videocodec && !videoprofile && !opusred && !bitrate &&
				!substream && !temporal && !fallback && !spatial_layer && !temporal_layer &&
				!record && !min_delay && !max_delay && !msg_sdp) {
			JANUS_LOG(LOG_ERR, "No supported attributes found\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Message error: no supported attributes found");
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "echotest", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		if(!msg_sdp) {
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
		} else {
			/* Answer the offer and pass it to the core, to start the echo test */
			const char *type = "answer";
			char error_str[512];
			janus_sdp *offer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
			if(offer == NULL) {
				json_decref(event);
				JANUS_LOG(LOG_ERR, "Error parsing offer: %s\n", error_str);
				error_code = JANUS_ECHOTEST_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Error parsing offer: %s", error_str);
				goto error;
			}
			/* Check if we need to negotiate Opus FEC and/or DTX */
			gboolean opus_fec = FALSE, opus_dtx = FALSE, opus_stereo = FALSE;
			char custom_fmtp[256];
			custom_fmtp[0] = '\0';
			GList *temp = offer->m_lines;
			while(temp) {
				/* Which media are available? */
				janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
				if((m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) && m->port > 0) {
					/* Are the extmaps we care about there? */
					GList *ma = m->attributes;
					while(ma) {
						janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
						if(a->value) {
							if(m->type == JANUS_SDP_AUDIO && !strcasecmp(a->name, "fmtp")) {
								if(strstr(a->value, "useinbandfec=1")) {
									opus_fec = TRUE;
									if(strlen(custom_fmtp) == 0) {
										g_snprintf(custom_fmtp, sizeof(custom_fmtp), "useinbandfec=1");
									} else {
										janus_strlcat(custom_fmtp, ";useinbandfec=1", sizeof(custom_fmtp));
									}
								}
								if(strstr(a->value, "usedtx=1")) {
									opus_dtx = TRUE;
									if(strlen(custom_fmtp) == 0) {
										g_snprintf(custom_fmtp, sizeof(custom_fmtp), "usedtx=1");
									} else {
										janus_strlcat(custom_fmtp, ";usedtx=1", sizeof(custom_fmtp));
									}
								}
								if(strstr(a->value, "stereo=1")) {
									opus_stereo = TRUE;
									if(strlen(custom_fmtp) == 0) {
										g_snprintf(custom_fmtp, sizeof(custom_fmtp), "stereo=1");
									} else {
										g_strlcat(custom_fmtp, ";stereo=1", sizeof(custom_fmtp));
									}
								}
							}
						}
						ma = ma->next;
					}
				}
				temp = temp->next;
			}
			janus_sdp *answer = janus_sdp_generate_answer(offer);
			temp = offer->m_lines;
			while(temp) {
				janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
				janus_sdp_generate_answer_mline(offer, answer, m,
					JANUS_SDP_OA_MLINE, m->type,
					JANUS_SDP_OA_CODEC, (m->type == JANUS_SDP_AUDIO ? json_string_value(audiocodec) :
						(m->type == JANUS_SDP_VIDEO ? json_string_value(videocodec) : NULL)),
					JANUS_SDP_OA_FMTP, ((m->type == JANUS_SDP_AUDIO && (opus_fec || opus_dtx || opus_stereo)) ? custom_fmtp : NULL),
					JANUS_SDP_OA_ACCEPT_OPUSRED, (m->type == JANUS_SDP_AUDIO && json_is_true(opusred)),
					JANUS_SDP_OA_VP9_PROFILE, json_string_value(videoprofile),
					JANUS_SDP_OA_H264_PROFILE, json_string_value(videoprofile),
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_RID,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_REPAIRED_RID,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_AUDIO_LEVEL,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_PLAYOUT_DELAY,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_DEPENDENCY_DESC,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_ABS_SEND_TIME,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME,
					JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_VIDEO_LAYERS,
					JANUS_SDP_OA_DONE);
				temp = temp->next;
			}
			/* If we ended up sendonly, switch to inactive (as we don't really send anything ourselves) */
			janus_sdp_mline *m = janus_sdp_mline_find(answer, JANUS_SDP_AUDIO);
			if(m && m->direction == JANUS_SDP_SENDONLY)
				m->direction = JANUS_SDP_INACTIVE;
			m = janus_sdp_mline_find(answer, JANUS_SDP_VIDEO);
			if(m && m->direction == JANUS_SDP_SENDONLY)
				m->direction = JANUS_SDP_INACTIVE;
			/* Check which codecs we ended up with */
			const char *acodec = NULL, *vcodec = NULL;
			janus_sdp_find_first_codec(answer, JANUS_SDP_AUDIO, -1, &acodec);
			if(acodec)
				session->acodec = janus_audiocodec_from_name(acodec);
			janus_sdp_find_first_codec(answer, JANUS_SDP_VIDEO, -1, &vcodec);
			if(vcodec)
				session->vcodec = janus_videocodec_from_name(vcodec);
			session->has_audio = session->acodec != JANUS_AUDIOCODEC_NONE;
			session->has_video = session->vcodec != JANUS_VIDEOCODEC_NONE;
			g_free(session->vfmtp);
			session->vfmtp = NULL;
			if(session->has_video) {
				const char *vfmtp = janus_sdp_get_fmtp(answer, -1, janus_sdp_get_codec_pt(answer, -1, vcodec));
				if(vfmtp != NULL)
					session->vfmtp = g_strdup(vfmtp);
			}
			if(json_is_true(opusred))
				session->opusred_pt = janus_sdp_get_opusred_pt(answer, -1);
			/* Done */
			char *sdp = janus_sdp_write(answer);
			janus_sdp_destroy(offer);
			janus_sdp_destroy(answer);
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
			if(session->e2ee)
				json_object_set_new(jsep, "e2ee", json_true());
			/* How long will the core take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			g_free(sdp);
			/* We don't need the event and jsep anymore */
			json_decref(event);
			json_decref(jsep);
		}
		if(record) {
			gboolean recording = json_is_true(record);
			const char *recording_base = json_string_value(recfile);
			JANUS_LOG(LOG_VERB, "Recording %s (base filename: %s)\n", recording ? "enabled" : "disabled", recording_base ? recording_base : "not provided");
			janus_mutex_lock(&session->rec_mutex);
			if(!recording) {
				janus_echotest_recorder_close(session);
			} else {
				/* We've started recording, send a PLI and go on */
				char filename[255];
				gint64 now = janus_get_real_time();
				if(session->has_audio) {
					/* Prepare an audio recording */
					janus_recorder *rc = NULL;
					memset(filename, 0, 255);
					if(recording_base) {
						/* Use the filename and path we have been provided */
						g_snprintf(filename, 255, "%s-audio", recording_base);
						rc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-audio", session, now);
						rc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this EchoTest user!\n");
						}
					}
					/* If RED is in use, take note of it */
					if(session->opusred_pt > 0)
						janus_recorder_opusred(rc, session->opusred_pt);
					/* If media is encrypted, mark it in the recording */
					if(session->e2ee)
						janus_recorder_encrypted(rc);
					session->arc = rc;
				}
				if(session->has_video) {
					/* Prepare a video recording */
					janus_recorder *rc = NULL;
					memset(filename, 0, 255);
					if(recording_base) {
						/* Use the filename and path we have been provided */
						g_snprintf(filename, 255, "%s-video", recording_base);
						rc = janus_recorder_create_full(NULL,
							janus_videocodec_name(session->vcodec), session->vfmtp, filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-video", session, now);
						rc = janus_recorder_create_full(NULL,
							janus_videocodec_name(session->vcodec), session->vfmtp, filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this EchoTest user!\n");
						}
					}
					/* Send a PLI */
					JANUS_LOG(LOG_VERB, "Recording video, sending a PLI to kickstart it\n");
					gateway->send_pli(session->handle);
					/* If media is encrypted, mark it in the recording */
					if(session->e2ee)
						janus_recorder_encrypted(rc);
					session->vrc = rc;
				}
				if(session->has_data) {
					/* Prepare a data recording */
					janus_recorder *rc = NULL;
					memset(filename, 0, 255);
					if(recording_base) {
						/* Use the filename and path we have been provided */
						g_snprintf(filename, 255, "%s-data", recording_base);
						rc = janus_recorder_create(NULL, "text", filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open a text data recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-data", session, now);
						rc = janus_recorder_create(NULL, "text", filename);
						if(rc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open a text data recording file for this EchoTest user!\n");
						}
					}
					/* Media encryption doesn't apply to data channels */
					session->drc = rc;
				}
			}
			janus_mutex_unlock(&session->rec_mutex);
		}
		janus_echotest_message_free(msg);

		if(notify_events && gateway->events_is_enabled()) {
			/* Just to showcase how you can notify handlers, let's update them on our configuration */
			json_t *info = json_object();
			json_object_set_new(info, "audio_active", session->audio_active ? json_true() : json_false());
			json_object_set_new(info, "video_active", session->video_active ? json_true() : json_false());
			json_object_set_new(info, "bitrate", json_integer(session->bitrate));
			if(session->ssrc[0] || session->rid[0]) {
				json_t *simulcast = json_object();
				json_object_set_new(simulcast, "substream", json_integer(session->sim_context.substream));
				json_object_set_new(simulcast, "temporal-layer", json_integer(session->sim_context.templayer));
				json_object_set_new(info, "simulcast", simulcast);
			}
			if(session->arc || session->vrc || session->drc) {
				json_t *recording = json_object();
				if(session->arc && session->arc->filename)
					json_object_set_new(recording, "audio", json_string(session->arc->filename));
				if(session->vrc && session->vrc->filename)
					json_object_set_new(recording, "video", json_string(session->vrc->filename));
				if(session->drc && session->drc->filename)
					json_object_set_new(recording, "data", json_string(session->drc->filename));
				json_object_set_new(info, "recording", recording);
			}
			gateway->notify_event(&janus_echotest_plugin, session->handle, info);
		}

		/* Done, on to the next request */
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			janus_echotest_message_free(msg);
			/* We don't need the event anymore */
			json_decref(event);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving EchoTest handler thread\n");
	return NULL;
}
