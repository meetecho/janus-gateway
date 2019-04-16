/*! \file   janus_videocall.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus VideoCall plugin
 * \details Check the \ref videocall for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page videocall VideoCall plugin documentation
 * This is a simple video call plugin for Janus, allowing two
 * WebRTC peers to call each other through the Janus core. The idea is to
 * provide a similar service as the well known AppRTC demo (https://apprtc.appspot.com),
 * but with the media flowing through a server rather than being peer-to-peer.
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
 * Just as in the janus_videocall.c plugin, there are knobs to control
 * whether audio and/or video should be muted or not, and if the bitrate
 * of the peer needs to be capped by means of REMB messages.
 *
 * \section vcallapi Video Call API
 *
 * All requests you can send in the Video Call API are asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction.
 *
 * The supported requests are \c list , \c register , \c call ,
 * \c accept , \c set and \c hangup . \c list allows you to get a list
 * of all the registered peers; \c register can be used to register
 * a username to call and be called; \c call is used to start a video
 * call with somebody through the plugin, while \c accept is used to
 * accept the call in case one is invited instead of inviting; \c set
 * can be used to configure some call-related settings (e.g., a cap on
 * the send bandwidth); finally, \c hangup can be used to terminate the
 * communication at any time, either to hangup an ongoing call or to
 * cancel/decline a call that hasn't started yet.
 *
 * The \c list request has to be formatted as follows:
 *
\verbatim
{
	"request" : "list"
}
\endverbatim
 *
 * A successful request will result in an array of peers to be returned:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"list": [	// Array of peers
			"alice78",
			"bob51",
			// others
		]
	}
}
\endverbatim
 *
 * An error instead (and the same applies to all other requests, so this
 * won't be repeated) would provide both an error code and a more verbose
 * description of the cause of the issue:
 *
\verbatim
{
	"videocall" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * To register a username to call and be called, the \c register request
 * can be used. This works on a "first come, first served" basis: there's
 * no authentication involved, you just specify the username you'd like
 * to use and, if free, it's assigned to you. Notice that there's no
 * way to unregister: you have to close the handle to free the username.
 * The \c register request has to be formatted as follows:
 *
\verbatim
{
	"request" : "register",
	"username" : "<desired unique username>"
}
\endverbatim
 *
 * If successul, this will result in a \c registered event:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "registered",
		"username" : "<same username, registered>"
	}
}
\endverbatim
 *
 * Once you're registered, you can either start a new call or wait to
 * be called by someone else who knows your username. To start a new
 * call, the \c call request can be used: this request must be attached
 * to a JSEP offer containing the WebRTC-related info to setup a new
 * media session. A \c call request has to be formatted as follows:
 *
\verbatim
{
	"request" : "call",
	"username" : "<username to call>"
}
\endverbatim
 *
 * If successul, this will result in a \c calling event:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "calling",
		"username" : "<same username, registered>"
	}
}
\endverbatim
 *
 * At the same time, the user being called will receive an
 * \c incomingcall event
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "incomingcall",
		"username" : "<your username>"
	}
}
\endverbatim
 *
 * To accept the call, the \c accept request can be used. This request
 * must be attached to a JSEP answer containing the WebRTC-related
 * information to complete the actual PeerConnection setup. A \c accept
 * request has to be formatted as follows:
 *
\verbatim
{
	"request" : "accept"
}
\endverbatim
 *
 * If successul, both the caller and the callee will receive an
 * \c accepted event to notify them about the success of the signalling:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "accepted",
		"username" : "<caller username>"
	}
}
\endverbatim
 *
 * At this point, the media-related settings of the call can be modified
 * on either side by means of a \c set request, which acts pretty much
 * as the one in the \ref echoapi . The \c set request has to be
 * formatted as follows. All the attributes (except \c request) are
 * optional, so any request can contain a subset of them:
 *
\verbatim
{
	"request" : "set",
	"audio" : true|false,
	"video" : true|false,
	"bitrate" : <numeric bitrate value>,
	"record" : true|false,
	"filename" : <base path/filename to use for the recording>,
	"substream" : <substream to receive (0-2), in case simulcasting is enabled>,
	"temporal" : <temporal layers to receive (0-2), in case simulcasting is enabled>
}
\endverbatim
 *
 * \c audio instructs the plugin to do or do not relay audio frames;
 * \c video does the same for video; \c bitrate caps the bandwidth to
 * force on the browser encoding side (e.g., 128000 for 128kbps);
 * \c record enables or disables the recording of this peer; in case
 * recording is enabled, \c filename allows to specify a base
 * path/filename to use for the files (-audio.mjr, -video.mjr and -data.mjr
 * are automatically appended). Beware that enabling the recording only
 * records this user's contribution, and not the whole call: to record
 * both sides, you need to enable recording for both the peers in the
 * call. Finally, in case the call uses simulcasting, \c substream and
 * \c temporal can be used to manually pick which substream and/or temporal
 * layer should be received from the peer.
 *
 * A successful request will result in a \c set event:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "set"
	}
}
\endverbatim
 *
 * Notice that the \c set request is also what you use when you want
 * to renegotiate a session, e.g., for the purpose of adding/removing
 * media streams or forcing an ICE restart. In that case, even an empty
 * \c set request is fine, as long as it accompanies a new JSEP offer
 * or answer (depending on who originated the session update). The user
 * receiving the updated JSEP offer/answer will get an \c update event:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "update",
	}
}
\endverbatim
 *
 * To decline an incoming call, cancel an attempt to call or simply
 * hangup an ongoing conversation, the \c hangup request can be used,
 * which has to be formatted as follows:
 *
\verbatim
{
	"request" : "hangup"
}
\endverbatim
 *
 * Whatever the reason of a call being closed (e.g., a \c hangup request,
 * a PeerConnection being closed, or something else), both parties in
 * the communication will receive a \c hangup event:
 *
\verbatim
{
	"videocall" : "event",
	"result" : {
		"event" : "hangup",
		"username" : "<username of who closed the communication>",
		"reason" : "<description of what happened>"
	}
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
#define JANUS_VIDEOCALL_VERSION			6
#define JANUS_VIDEOCALL_VERSION_STRING	"0.0.6"
#define JANUS_VIDEOCALL_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through a server."
#define JANUS_VIDEOCALL_NAME			"JANUS VideoCall plugin"
#define JANUS_VIDEOCALL_AUTHOR			"Meetecho s.r.l."
#define JANUS_VIDEOCALL_PACKAGE			"janus.plugin.videocall"

/* Plugin methods */
janus_plugin *create(void);
int janus_videocall_init(janus_callbacks *callback, const char *config_path);
void janus_videocall_destroy(void);
int janus_videocall_get_api_compatibility(void);
int janus_videocall_get_version(void);
const char *janus_videocall_get_version_string(void);
const char *janus_videocall_get_description(void);
const char *janus_videocall_get_name(void);
const char *janus_videocall_get_author(void);
const char *janus_videocall_get_package(void);
void janus_videocall_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_videocall_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_videocall_setup_media(janus_plugin_session *handle);
void janus_videocall_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videocall_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_videocall_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len);
void janus_videocall_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_videocall_hangup_media(janus_plugin_session *handle);
void janus_videocall_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_videocall_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_videocall_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_videocall_init,
		.destroy = janus_videocall_destroy,

		.get_api_compatibility = janus_videocall_get_api_compatibility,
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
		.slow_link = janus_videocall_slow_link,
		.hangup_media = janus_videocall_hangup_media,
		.destroy_session = janus_videocall_destroy_session,
		.query_session = janus_videocall_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_VIDEOCALL_NAME);
	return &janus_videocall_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter username_parameters[] = {
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter set_parameters[] = {
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"bitrate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"record", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0},
	{"restart", JANUS_JSON_BOOL, 0}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_videocall_handler(void *data);

typedef struct janus_videocall_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_videocall_message;
static GAsyncQueue *messages = NULL;
static janus_videocall_message exit_message;

typedef struct janus_videocall_session {
	janus_plugin_session *handle;
	gchar *username;
	gboolean has_audio;
	gboolean has_video;
	gboolean has_data;
	gboolean audio_active;
	gboolean video_active;
	janus_audiocodec acodec;/* Codec used for audio, if available */
	janus_videocodec vcodec;/* Codec used for video, if available */
	uint32_t bitrate;
	guint16 slowlink_count;
	struct janus_videocall_session *peer;
	janus_rtp_switching_context context;
	uint32_t ssrc[3];		/* Only needed in case VP8 (or H.264) simulcasting is involved */
	char *rid[3];			/* Only needed if simulcasting is rid-based */
	janus_rtp_simulcasting_context sim_context;
	janus_vp8_simulcast_context vp8_context;
	janus_recorder *arc;	/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *drc;	/* The Janus recorder instance for this user's data, if enabled */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	volatile gint incall;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_videocall_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_videocall_session_destroy(janus_videocall_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_videocall_session_free(const janus_refcount *session_ref) {
	janus_videocall_session *session = janus_refcount_containerof(session_ref, janus_videocall_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session->username);
	g_free(session);
}

static void janus_videocall_message_free(janus_videocall_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_videocall_session *session = (janus_videocall_session *)msg->handle->plugin_handle;
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
#define JANUS_VIDEOCALL_ERROR_INVALID_SDP			483


/* Plugin implementation */
int janus_videocall_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_VIDEOCALL_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_VIDEOCALL_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_VIDEOCALL_PACKAGE);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_VIDEOCALL_NAME);
		}
	}
	janus_config_destroy(config);
	config = NULL;

	sessions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_videocall_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_videocall_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("videocall handler", janus_videocall_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the VideoCall handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_VIDEOCALL_NAME);
	return 0;
}

void janus_videocall_destroy(void) {
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
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_VIDEOCALL_NAME);
}

int janus_videocall_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
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
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_videocall_session *session = g_malloc0(sizeof(janus_videocall_session));
	session->handle = handle;
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	session->peer = NULL;
	session->username = NULL;
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->incall, 0);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_videocall_session_free);

	return;
}

void janus_videocall_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No VideoCall session associated with this handle...\n");
		*error = -2;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	JANUS_LOG(LOG_VERB, "Removing VideoCall user %s session...\n", session->username ? session->username : "'unknown'");
	janus_videocall_hangup_media(handle);
	if(session->username != NULL) {
		int res = g_hash_table_remove(sessions, (gpointer)session->username);
		JANUS_LOG(LOG_VERB, "  -- Removed: %d\n", res);
	} else {
		janus_videocall_session_destroy(session);
	}
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_videocall_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	/* Provide some generic info, e.g., if we're in a call and with whom */
	janus_videocall_session *peer = session->peer;
	json_t *info = json_object();
	json_object_set_new(info, "state", json_string(session->peer ? "incall" : "idle"));
	json_object_set_new(info, "username", session->username ? json_string(session->username) : NULL);
	if(peer) {
		json_object_set_new(info, "peer", peer->username ? json_string(peer->username) : NULL);
		json_object_set_new(info, "audio_active", session->audio_active ? json_true() : json_false());
		json_object_set_new(info, "video_active", session->video_active ? json_true() : json_false());
		if(session->acodec != JANUS_AUDIOCODEC_NONE)
			json_object_set_new(info, "audio_codec", json_string(janus_audiocodec_name(session->acodec)));
		if(session->vcodec != JANUS_VIDEOCODEC_NONE)
			json_object_set_new(info, "video_codec", json_string(janus_videocodec_name(session->vcodec)));
		json_object_set_new(info, "video_active", session->video_active ? json_true() : json_false());
		json_object_set_new(info, "bitrate", json_integer(session->bitrate));
		json_object_set_new(info, "slowlink_count", json_integer(session->slowlink_count));
	}
	if(session->ssrc[0] != 0 || session->rid[0] != NULL) {
		json_object_set_new(info, "simulcast", json_true());
	}
	if(peer && (peer->ssrc[0] != 0 || peer->rid[0] != NULL)) {
		json_object_set_new(info, "simulcast-peer", json_true());
		json_object_set_new(info, "substream", json_integer(session->sim_context.substream));
		json_object_set_new(info, "substream-target", json_integer(session->sim_context.substream_target));
		json_object_set_new(info, "temporal-layer", json_integer(session->sim_context.templayer));
		json_object_set_new(info, "temporal-layer-target", json_integer(session->sim_context.templayer_target));
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
	json_object_set_new(info, "incall", json_integer(g_atomic_int_get(&session->incall)));
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_videocall_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);

	janus_videocall_message *msg = g_malloc(sizeof(janus_videocall_message));
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);

	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_videocall_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_VIDEOCALL_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	g_atomic_int_set(&session->hangingup, 0);
	/* We really don't care, as we only relay RTP/RTCP we get in the first place anyway */
}

void janus_videocall_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		if(video && session->video_active && (session->ssrc[0] != 0 || session->rid[0] != NULL)) {
			/* Handle simulcast: backup the header information first */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			uint32_t seq_number = ntohs(header->seq_number);
			uint32_t timestamp = ntohl(header->timestamp);
			uint32_t ssrc = ntohl(header->ssrc);
			/* Process this packet: don't relay if it's not the SSRC/layer we wanted to handle
			 * The caveat is that the targets in OUR simulcast context are the PEER's targets */
			gboolean relay = janus_rtp_simulcasting_context_process_rtp(&peer->sim_context,
				buf, len, session->ssrc, session->rid, session->vcodec, &peer->context);
			/* Do we need to drop this? */
			if(!relay)
				return;
			/* Any event we should notify? */
			if(peer->sim_context.changed_substream) {
				/* Notify the user about the substream change */
				json_t *event = json_object();
				json_object_set_new(event, "videocall", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("simulcast"));
				json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(result, "substream", json_integer(session->sim_context.substream));
				json_object_set_new(event, "result", result);
				gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, event, NULL);
				json_decref(event);
			}
			if(peer->sim_context.need_pli) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "We need a PLI for the simulcast context\n");
				char rtcpbuf[12];
				memset(rtcpbuf, 0, 12);
				janus_rtcp_pli((char *)&rtcpbuf, 12);
				gateway->relay_rtcp(session->handle, 1, rtcpbuf, 12);
			}
			if(peer->sim_context.changed_temporal) {
				/* Notify the user about the temporal layer change */
				json_t *event = json_object();
				json_object_set_new(event, "videocall", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("simulcast"));
				json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(result, "temporal", json_integer(session->sim_context.templayer));
				json_object_set_new(event, "result", result);
				gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, event, NULL);
				json_decref(event);
			}
			/* If we got here, update the RTP header and send the packet */
			janus_rtp_header_update(header, &peer->context, TRUE, 4500);
			if(session->vcodec == JANUS_VIDEOCODEC_VP8) {
				int plen = 0;
				char *payload = janus_rtp_payload(buf, len, &plen);
				janus_vp8_simulcast_descriptor_update(payload, plen, &peer->vp8_context, peer->sim_context.changed_substream);
			}
			/* Save the frame if we're recording (and make sure the SSRC never changes even if the substream does) */
			header->ssrc = htonl(1);
			janus_recorder_save_frame(session->vrc, buf, len);
			/* Send the frame back */
			gateway->relay_rtp(peer->handle, video, buf, len);
			/* Restore header or core statistics will be messed up */
			header->ssrc = htonl(ssrc);
			header->timestamp = htonl(timestamp);
			header->seq_number = htons(seq_number);
		} else {
			if((!video && session->audio_active) || (video && session->video_active)) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
				/* Forward the packet to the peer */
				gateway->relay_rtp(peer->handle, video, buf, len);
			}
		}
	}
}

void janus_videocall_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		guint32 bitrate = janus_rtcp_get_remb(buf, len);
		if(bitrate > 0) {
			/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
			if(session->bitrate == 0)	/* No limit ~= 10000000 */
				janus_rtcp_cap_remb(buf, len, 10000000);
			else
				janus_rtcp_cap_remb(buf, len, session->bitrate);
			gateway->relay_rtcp(peer->handle, 1, buf, len);
			return;
		}
		gateway->relay_rtcp(peer->handle, video, buf, len);
	}
}

void janus_videocall_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		janus_videocall_session *peer = session->peer;
		if(!peer) {
			JANUS_LOG(LOG_ERR, "Session has no peer...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&peer->destroyed))
			return;
		if(buf == NULL || len <= 0)
			return;
		char *text = g_malloc(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
		/* Save the frame if we're recording */
		janus_recorder_save_frame(session->drc, buf, len);
		/* Forward the packet to the peer */
		gateway->relay_data(peer->handle, label, text, strlen(text));
		g_free(text);
	}
}

void janus_videocall_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* The core is informing us that our peer got or sent too many NACKs, are we pushing media too hard? */
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
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
			json_object_set_new(event, "videocall", json_string("event"));
			/* Also add info on what the current bitrate cap is */
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("slow_link"));
			json_object_set_new(result, "current-bitrate", json_integer(session->bitrate));
			json_object_set_new(event, "result", result);
			gateway->push_event(session->handle, &janus_videocall_plugin, NULL, event, NULL);
			json_decref(event);
		}
	}
}

static void janus_videocall_recorder_close(janus_videocall_session *session) {
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

void janus_videocall_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_VIDEOCALL_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_videocall_session *session = (janus_videocall_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	janus_videocall_recorder_close(session);
	janus_mutex_unlock(&session->rec_mutex);
	janus_videocall_session *peer = session->peer;
	session->peer = NULL;
	if(peer) {
		/* Send event to our peer too */
		json_t *call = json_object();
		json_object_set_new(call, "videocall", json_string("event"));
		json_t *calling = json_object();
		json_object_set_new(calling, "event", json_string("hangup"));
		json_object_set_new(calling, "username", json_string(session->username));
		json_object_set_new(calling, "reason", json_string("Remote WebRTC hangup"));
		json_object_set_new(call, "result", calling);
		gateway->close_pc(peer->handle);
		int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(call);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("hangup"));
			json_object_set_new(info, "reason", json_string("Remote WebRTC hangup"));
			gateway->notify_event(&janus_videocall_plugin, peer->handle, info);
		}
	}
	/* Reset controls */
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->acodec = JANUS_AUDIOCODEC_NONE;
	session->vcodec = JANUS_VIDEOCODEC_NONE;
	session->bitrate = 0;
	int i=0;
	for(i=0; i<3; i++) {
		session->ssrc[i] = 0;
		g_free(session->rid[i]);
		session->rid[i] = NULL;
	}
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
		janus_refcount_decrease(&peer->ref);
	}
	janus_rtp_switching_context_reset(&session->context);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_videocall_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining VideoCall handler thread\n");
	janus_videocall_message *msg = NULL;
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
			janus_videocall_message_free(msg);
			continue;
		}
		janus_videocall_session *session = (janus_videocall_session *)msg->handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_videocall_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_videocall_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_VIDEOCALL_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT, JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *result = NULL;
		gboolean sdp_update = FALSE;
		if(json_object_get(msg->jsep, "update") != NULL)
			sdp_update = json_is_true(json_object_get(msg->jsep, "update"));
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
				if(user != NULL) {
					janus_refcount_increase(&user->ref);
					if(user->username != NULL)
						json_array_append_new(list, json_string(user->username));
					janus_refcount_decrease(&user->ref);
				}
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
			JANUS_VALIDATE_JSON_OBJECT(root, username_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT, JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *username = json_object_get(root, "username");
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
			janus_mutex_lock(&sessions_mutex);
			g_hash_table_insert(sessions, (gpointer)session->username, session);
			janus_mutex_unlock(&sessions_mutex);
			result = json_object();
			json_object_set_new(result, "event", json_string("registered"));
			json_object_set_new(result, "username", json_string(username_text));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("registered"));
				json_object_set_new(info, "username", json_string(username_text));
				gateway->notify_event(&janus_videocall_plugin, session->handle, info);
			}
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->username == NULL) {
				JANUS_LOG(LOG_ERR, "Register a username first\n");
				error_code = JANUS_VIDEOCALL_ERROR_REGISTER_FIRST;
				g_snprintf(error_cause, 512, "Register a username first");
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
				goto error;
			}
			if(session->peer != NULL) {
				JANUS_LOG(LOG_ERR, "Already in a call\n");
				error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
				g_snprintf(error_cause, 512, "Already in a call");
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
				goto error;
			}
			if(!g_atomic_int_compare_and_exchange(&session->incall, 0, 1)) {
				JANUS_LOG(LOG_ERR, "Already in a call (but no peer?)\n");
				error_code = JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL;
				g_snprintf(error_cause, 512, "Already in a call (but no peer)");
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, username_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT, JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT);
			if(error_code != 0) {
				/* Hangup the call attempt of the user */
				g_atomic_int_set(&session->incall, 0);
				gateway->close_pc(session->handle);
				goto error;
			}
			json_t *username = json_object_get(root, "username");
			const char *username_text = json_string_value(username);
			if(!strcmp(username_text, session->username)) {
				g_atomic_int_set(&session->incall, 0);
				JANUS_LOG(LOG_ERR, "You can't call yourself... use the EchoTest for that\n");
				error_code = JANUS_VIDEOCALL_ERROR_USE_ECHO_TEST;
				g_snprintf(error_cause, 512, "You can't call yourself... use the EchoTest for that");
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
				goto error;
			}
			janus_mutex_lock(&sessions_mutex);
			janus_videocall_session *peer = g_hash_table_lookup(sessions, username_text);
			if(peer == NULL || g_atomic_int_get(&peer->destroyed)) {
				g_atomic_int_set(&session->incall, 0);
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_ERR, "Username '%s' doesn't exist\n", username_text);
				error_code = JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME;
				g_snprintf(error_cause, 512, "Username '%s' doesn't exist", username_text);
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
				goto error;
			}
			/* If the call attempt proceeds we keep the references */
			janus_refcount_increase(&session->ref);
			janus_refcount_increase(&peer->ref);
			if(g_atomic_int_get(&peer->incall) || peer->peer != NULL) {
				if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
					janus_refcount_decrease(&session->ref);
					janus_refcount_decrease(&peer->ref);
				}
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_VERB, "%s is busy\n", username_text);
				result = json_object();
				json_object_set_new(result, "event", json_string("hangup"));
				json_object_set_new(result, "username", json_string(session->username));
				json_object_set_new(result, "reason", json_string("User busy"));
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("hangup"));
					json_object_set_new(info, "reason", json_string("User busy"));
					gateway->notify_event(&janus_videocall_plugin, session->handle, info);
				}
				/* Hangup the call attempt of the user */
				gateway->close_pc(session->handle);
			} else {
				/* Any SDP to handle? if not, something's wrong */
				if(!msg_sdp) {
					if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
						janus_refcount_decrease(&session->ref);
						janus_refcount_decrease(&peer->ref);
					}
					janus_mutex_unlock(&sessions_mutex);
					JANUS_LOG(LOG_ERR, "Missing SDP\n");
					error_code = JANUS_VIDEOCALL_ERROR_MISSING_SDP;
					g_snprintf(error_cause, 512, "Missing SDP");
					goto error;
				}
				char error_str[512];
				janus_sdp *offer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				if(offer == NULL) {
					if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
						janus_refcount_decrease(&session->ref);
						janus_refcount_decrease(&peer->ref);
					}
					janus_mutex_unlock(&sessions_mutex);
					JANUS_LOG(LOG_ERR, "Error parsing offer: %s\n", error_str);
					error_code = JANUS_VIDEOCALL_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "Error parsing offer: %s", error_str);
					goto error;
				}
				janus_sdp_destroy(offer);
				g_atomic_int_set(&peer->incall, 1);
				session->peer = peer;
				peer->peer = session;
				session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
				session->has_video = (strstr(msg_sdp, "m=video") != NULL);
				session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);
				janus_mutex_unlock(&sessions_mutex);
				JANUS_LOG(LOG_VERB, "%s is calling %s\n", session->username, peer->username);
				JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
				/* Check if this user will simulcast */
				json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
				if(msg_simulcast) {
					JANUS_LOG(LOG_VERB, "VideoCall caller (%s) is going to do simulcasting\n", session->username);
					int rid_ext_id = -1;
					janus_rtp_simulcasting_prepare(msg_simulcast, &rid_ext_id, session->ssrc, session->rid);
					session->sim_context.rid_ext_id = rid_ext_id;
				}
				/* Send SDP to our peer */
				json_t *call = json_object();
				json_object_set_new(call, "videocall", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("incomingcall"));
				json_object_set_new(calling, "username", json_string(session->username));
				json_object_set_new(call, "result", calling);
				json_t *jsep = json_pack("{ssss}", "type", msg_sdp_type, "sdp", msg_sdp);
				g_atomic_int_set(&session->hangingup, 0);
				int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(call);
				json_decref(jsep);
				/* Send an ack back */
				result = json_object();
				json_object_set_new(result, "event", json_string("calling"));
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("calling"));
					gateway->notify_event(&janus_videocall_plugin, session->handle, info);
				}
			}
		} else if(!strcasecmp(request_text, "accept")) {
			/* Accept a call from another peer */
			janus_videocall_session *peer = session->peer;
			if(peer == NULL || !g_atomic_int_get(&session->incall) || !g_atomic_int_get(&peer->incall)) {
				JANUS_LOG(LOG_ERR, "No incoming call to accept\n");
				error_code = JANUS_VIDEOCALL_ERROR_NO_CALL;
				g_snprintf(error_cause, 512, "No incoming call to accept");
				goto error;
			}
			janus_refcount_increase(&peer->ref);
			/* Any SDP to handle? if not, something's wrong */
			if(!msg_sdp) {
				janus_refcount_decrease(&peer->ref);
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_VIDEOCALL_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			char error_str[512];
			janus_sdp *answer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
			if(answer == NULL) {
				janus_refcount_decrease(&peer->ref);
				JANUS_LOG(LOG_ERR, "Error parsing answer: %s\n", error_str);
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Error parsing answer: %s", error_str);
				goto error;
			}
			JANUS_LOG(LOG_VERB, "%s is accepting a call from %s\n", session->username, peer->username);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
			session->has_video = (strstr(msg_sdp, "m=video") != NULL);
			session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);
			/* Check if this user will simulcast */
			json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
			if(msg_simulcast && janus_get_codec_pt(msg_sdp, "vp8") > 0) {
				JANUS_LOG(LOG_VERB, "VideoCall callee (%s) is going to do simulcasting\n", session->username);
				session->ssrc[0] = json_integer_value(json_object_get(msg_simulcast, "ssrc-0"));
				session->ssrc[1] = json_integer_value(json_object_get(msg_simulcast, "ssrc-1"));
				session->ssrc[2] = json_integer_value(json_object_get(msg_simulcast, "ssrc-2"));
			} else {
				int i=0;
				for(i=0; i<3; i++) {
					session->ssrc[i] = 0;
					g_free(session->rid[0]);
					session->rid[0] = NULL;
					if(peer) {
						peer->ssrc[i] = 0;
						g_free(peer->rid[0]);
						peer->rid[0] = NULL;
					}
				}
			}
			/* Check which codecs we ended up using */
			const char *acodec = NULL, *vcodec = NULL;
			janus_sdp_find_first_codecs(answer, &acodec, &vcodec);
			session->acodec = janus_audiocodec_from_name(acodec);
			session->vcodec = janus_videocodec_from_name(vcodec);
			if(session->acodec == JANUS_AUDIOCODEC_NONE) {
				session->has_audio = FALSE;
				if(peer)
					peer->has_audio = FALSE;
			} else if(peer) {
				peer->acodec = session->acodec;
			}
			if(session->vcodec == JANUS_VIDEOCODEC_NONE) {
				session->has_video = FALSE;
				if(peer)
					peer->has_video = FALSE;
			} else if(peer) {
				peer->vcodec = session->vcodec;
			}
			janus_sdp_destroy(answer);
			/* Send SDP to our peer */
			json_t *jsep = json_pack("{ssss}", "type", msg_sdp_type, "sdp", msg_sdp);
			json_t *call = json_object();
			json_object_set_new(call, "videocall", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("accepted"));
			json_object_set_new(calling, "username", json_string(session->username));
			json_object_set_new(call, "result", calling);
			g_atomic_int_set(&session->hangingup, 0);
			int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(call);
			json_decref(jsep);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("accepted"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("accepted"));
				gateway->notify_event(&janus_videocall_plugin, session->handle, info);
			}
			/* Is simulcasting involved on either side? */
			if(session->ssrc[0] || session->rid[0]) {
				peer->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
				peer->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
			}
			if(peer->ssrc[0] || peer->rid[0]) {
				session->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
				session->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
			}
			/* We don't need this reference anymore, it was already increased by the peer calling us */
			janus_refcount_decrease(&peer->ref);
		} else if(!strcasecmp(request_text, "set")) {
			/* Update the local configuration (audio/video mute/unmute, bitrate cap or recording) */
			JANUS_VALIDATE_JSON_OBJECT(root, set_parameters,
				error_code, error_cause, TRUE,
				JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT, JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *audio = json_object_get(root, "audio");
			json_t *video = json_object_get(root, "video");
			json_t *bitrate = json_object_get(root, "bitrate");
			json_t *record = json_object_get(root, "record");
			json_t *recfile = json_object_get(root, "filename");
			json_t *restart = json_object_get(root, "restart");
			json_t *substream = json_object_get(root, "substream");
			if(substream && (!json_is_integer(substream) || json_integer_value(substream) < 0 || json_integer_value(substream) > 2)) {
				JANUS_LOG(LOG_ERR, "Invalid element (substream should be 0, 1 or 2)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (substream should be 0, 1 or 2)");
				goto error;
			}
			json_t *temporal = json_object_get(root, "temporal");
			if(temporal && (!json_is_integer(temporal) || json_integer_value(temporal) < 0 || json_integer_value(temporal) > 2)) {
				JANUS_LOG(LOG_ERR, "Invalid element (temporal should be 0, 1 or 2)\n");
				error_code = JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (temporal should be 0, 1 or 2)");
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
					janus_rtcp_pli((char *)&buf, 12);
					gateway->relay_rtcp(session->handle, 1, buf, 12);
				}
				session->video_active = json_is_true(video);
				JANUS_LOG(LOG_VERB, "Setting video property: %s\n", session->video_active ? "true" : "false");
			}
			if(bitrate) {
				session->bitrate = json_integer_value(bitrate);
				JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu32"\n", session->bitrate);
				if(session->bitrate > 0) {
					/* FIXME Generate a new REMB (especially useful for Firefox, which doesn't send any we can cap later) */
					char buf[24];
					janus_rtcp_remb((char *)&buf, 24, session->bitrate);
					JANUS_LOG(LOG_VERB, "Sending REMB\n");
					gateway->relay_rtcp(session->handle, 1, buf, 24);
					/* FIXME How should we handle a subsequent "no limit" bitrate? */
				}
			}
			janus_videocall_session *peer = session->peer;
			if(substream) {
				session->sim_context.substream_target = json_integer_value(substream);
				JANUS_LOG(LOG_VERB, "Setting video SSRC to let through (simulcast): %"SCNu32" (index %d, was %d)\n",
					session->ssrc[session->sim_context.substream], session->sim_context.substream_target, session->sim_context.substream);
				if(session->sim_context.substream_target == session->sim_context.substream) {
					/* No need to do anything, we're already getting the right substream, so notify the user */
					json_t *event = json_object();
					json_object_set_new(event, "videocall", json_string("event"));
					json_t *result = json_object();
					json_object_set_new(result, "event", json_string("simulcast"));
					json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
					json_object_set_new(result, "substream", json_integer(session->sim_context.substream));
					json_object_set_new(event, "result", result);
					gateway->push_event(session->handle, &janus_videocall_plugin, NULL, event, NULL);
					json_decref(event);
				} else {
					/* We need to change substream, send the peer a PLI */
					JANUS_LOG(LOG_VERB, "Simulcasting substream change, sending a PLI to kickstart it\n");
					char buf[12];
					memset(buf, 0, 12);
					janus_rtcp_pli((char *)&buf, 12);
					if(peer && peer->handle)
						gateway->relay_rtcp(session->handle, 1, buf, 12);
				}
			}
			if(temporal) {
				session->sim_context.templayer_target = json_integer_value(temporal);
				JANUS_LOG(LOG_VERB, "Setting video temporal layer to let through (simulcast): %d (was %d)\n",
					session->sim_context.templayer_target, session->sim_context.templayer);
				if(session->vcodec == JANUS_VIDEOCODEC_VP8 && session->sim_context.templayer_target == session->sim_context.templayer) {
					/* No need to do anything, we're already getting the right temporal, so notify the user */
					json_t *event = json_object();
					json_object_set_new(event, "videocall", json_string("event"));
					json_t *result = json_object();
					json_object_set_new(result, "event", json_string("simulcast"));
					json_object_set_new(result, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
					json_object_set_new(result, "temporal", json_integer(session->sim_context.templayer));
					json_object_set_new(event, "result", result);
					gateway->push_event(session->handle, &janus_videocall_plugin, NULL, event, NULL);
					json_decref(event);
				} else {
					/* We need to change temporal, send a PLI */
					JANUS_LOG(LOG_VERB, "Simulcasting temporal layer change, sending a PLI to kickstart it\n");
					char buf[12];
					memset(buf, 0, 12);
					janus_rtcp_pli((char *)&buf, 12);
					if(peer && peer->handle)
						gateway->relay_rtcp(session->handle, 1, buf, 12);
				}
			}
			if(record) {
				if(msg_sdp) {
					session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
					session->has_video = (strstr(msg_sdp, "m=video") != NULL);
					session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);
				}
				gboolean recording = json_is_true(record);
				const char *recording_base = json_string_value(recfile);
				JANUS_LOG(LOG_VERB, "Recording %s (base filename: %s)\n", recording ? "enabled" : "disabled", recording_base ? recording_base : "not provided");
				janus_mutex_lock(&session->rec_mutex);
				if(!recording) {
					/* Not recording (anymore?) */
					janus_videocall_recorder_close(session);
				} else {
					/* We've started recording, send a PLI and go on */
					char filename[255];
					gint64 now = janus_get_real_time();
					if(session->has_audio) {
						/* FIXME We assume we're recording Opus, here */
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-audio", recording_base);
							session->arc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
							if(session->arc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this VideoCall user!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "videocall-%s-%s-%"SCNi64"-audio",
								session->username ? session->username : "unknown",
								(peer && peer->username) ? peer->username : "unknown",
								now);
							session->arc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
							if(session->arc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this VideoCall user!\n");
							}
						}
					}
					if(session->has_video) {
						/* FIXME We assume we're recording VP8, here */
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-video", recording_base);
							session->vrc = janus_recorder_create(NULL, janus_videocodec_name(session->vcodec), filename);
							if(session->vrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this VideoCall user!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "videocall-%s-%s-%"SCNi64"-video",
								session->username ? session->username : "unknown",
								(peer && peer->username) ? peer->username : "unknown",
								now);
							session->vrc = janus_recorder_create(NULL, janus_videocodec_name(session->vcodec), filename);
							if(session->vrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this VideoCall user!\n");
							}
						}
						/* Send a PLI */
						JANUS_LOG(LOG_VERB, "Recording video, sending a PLI to kickstart it\n");
						char buf[12];
						janus_rtcp_pli((char *)&buf, 12);
						gateway->relay_rtcp(session->handle, 1, buf, 12);
					}
					if(session->has_data) {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-data", recording_base);
							session->drc = janus_recorder_create(NULL, "text", filename);
							if(session->drc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open a data recording file for this VideoCall user!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "videocall-%s-%s-%"SCNi64"-data",
								session->username ? session->username : "unknown",
								(peer && peer->username) ? peer->username : "unknown",
								now);
							session->drc = janus_recorder_create(NULL, "text", filename);
							if(session->drc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open a data recording file for this VideoCall user!\n");
							}
						}
					}
				}
				janus_mutex_unlock(&session->rec_mutex);
			}
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("configured"));
				json_object_set_new(info, "audio_active", session->audio_active ? json_true() : json_false());
				json_object_set_new(info, "video_active", session->video_active ? json_true() : json_false());
				json_object_set_new(info, "bitrate", json_integer(session->bitrate));
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
				gateway->notify_event(&janus_videocall_plugin, session->handle, info);
			}
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("set"));
			/* If this is for an ICE restart, prepare the SDP to send back too */
			gboolean do_restart = restart ? json_is_true(restart) : FALSE;
			if(do_restart && !sdp_update) {
				JANUS_LOG(LOG_WARN, "Got a 'restart' request, but no SDP update? Ignoring...\n");
			}
			if(sdp_update && peer != NULL) {
				/* Forward new SDP to the peer */
				json_t *event = json_object();
				json_object_set_new(event, "videocall", json_string("event"));
				json_t *update = json_object();
				json_object_set_new(update, "event", json_string("update"));
				json_object_set_new(event, "result", update);
				json_t *jsep = json_pack("{ssss}", "type", msg_sdp_type, "sdp", msg_sdp);
				int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, event, jsep);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(event);
				json_decref(jsep);
			}
		} else if(!strcasecmp(request_text, "hangup")) {
			json_t *hangup = json_object_get(root, "reason");
			if(hangup && !json_is_string(hangup)) {
				JANUS_LOG(LOG_WARN, "Invalid element (hangup should be a string), ignoring\n");
				hangup = NULL;
			}
			const char *hangup_text = hangup ? json_string_value(hangup) : "We did the hangup";
			/* Hangup an ongoing call or reject an incoming one */
			janus_videocall_session *peer = session->peer;
			if(peer == NULL) {
				JANUS_LOG(LOG_WARN, "No call to hangup\n");
			} else {
				JANUS_LOG(LOG_VERB, "%s is hanging up the call with %s (%s)\n", session->username, peer->username, hangup_text);
			}
			/* Check if we still need to remove any reference */
			if(peer && g_atomic_int_compare_and_exchange(&peer->incall, 1, 0)) {
				janus_refcount_decrease(&session->ref);
			}
			if(g_atomic_int_compare_and_exchange(&session->incall, 1, 0) && peer) {
				janus_refcount_decrease(&peer->ref);
			}
			/* Notify the success as an hangup message */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangup"));
			json_object_set_new(result, "username", json_string(session->username));
			json_object_set_new(result, "reason", json_string(hangup_text));
			json_object_set_new(result, "reason", json_string("Explicit hangup"));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("hangup"));
				json_object_set_new(info, "reason", json_string("Explicit hangup"));
				gateway->notify_event(&janus_videocall_plugin, session->handle, info);
			}
			/* Hangup the call on the user, if it's still up */
			gateway->close_pc(session->handle);
			if(peer != NULL) {
				/* Send event to our peer too */
				json_t *call = json_object();
				json_object_set_new(call, "videocall", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "username", json_string(session->username));
				json_object_set_new(calling, "reason", json_string(hangup_text));
				json_object_set_new(call, "result", calling);
				gateway->close_pc(peer->handle);
				int ret = gateway->push_event(peer->handle, &janus_videocall_plugin, NULL, call, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(call);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("hangup"));
					json_object_set_new(info, "reason", json_string("Remote hangup"));
					gateway->notify_event(&janus_videocall_plugin, peer->handle, info);
				}
				/* Hangup the call on the peer, if it's still up */
				gateway->close_pc(peer->handle);
			}
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_VIDEOCALL_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "videocall", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		int ret = gateway->push_event(msg->handle, &janus_videocall_plugin, msg->transaction, event, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(event);
		janus_videocall_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "videocall", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_videocall_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_videocall_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving VideoCall handler thread\n");
	return NULL;
}
