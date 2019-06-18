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
	"bitrate" : <numeric bitrate value>,
	"record" : true|false,
	"filename" : <base path/filename to use for the recording>,
	"substream" : <substream to receive (0-2), in case simulcasting is enabled>,
	"temporal" : <temporal layers to receive (0-2), in case simulcasting is enabled>
}
\endverbatim
 *
 * When negotiating a new PeerConnection, by default the EchoTest tries to
 * use the preferred audio codecs as set by the user; if for any reason you
 * want to override what the browsers offered first and use a different
 * codec instead (e.g., to try VP9 instead of VP8), you can use the
 * \c audiocodec property for audio, and \c videocodec for video.
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
 * pick which substream and/or temporal layer should be received back.
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
void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len);
void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video);
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
	uint32_t bitrate, peer_bitrate;
	janus_rtp_switching_context context;
	uint32_t ssrc[3];		/* Only needed in case VP8 (or H.264) simulcasting is involved */
	char *rid[3];			/* Only needed if simulcasting is rid-based */
	janus_rtp_simulcasting_context sim_context;
	janus_vp8_simulcast_context vp8_context;
	janus_recorder *arc;	/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *drc;	/* The Janus recorder instance for this user's data, if enabled */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	guint16 slowlink_count;
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
	if(session->acodec != JANUS_AUDIOCODEC_NONE)
		json_object_set_new(info, "audio_codec", json_string(janus_audiocodec_name(session->acodec)));
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

void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
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
		if(video && session->video_active && (session->ssrc[0] != 0 || session->rid[0] != NULL)) {
			/* Handle simulcast: backup the header information first */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			uint32_t seq_number = ntohs(header->seq_number);
			uint32_t timestamp = ntohl(header->timestamp);
			uint32_t ssrc = ntohl(header->ssrc);
			/* Process this packet: don't relay if it's not the SSRC/layer we wanted to handle */
			gboolean relay = janus_rtp_simulcasting_context_process_rtp(&session->sim_context,
				buf, len, session->ssrc, session->rid, session->vcodec, &session->context);
			/* Do we need to drop this? */
			if(!relay)
				return;
			/* Any event we should notify? */
			if(session->sim_context.changed_substream) {
				/* Notify the user about the substream change */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "substream", json_integer(session->sim_context.substream));
				gateway->push_event(handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			}
			if(session->sim_context.need_pli) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "We need a PLI for the simulcast context\n");
				char rtcpbuf[12];
				memset(rtcpbuf, 0, 12);
				janus_rtcp_pli((char *)&rtcpbuf, 12);
				gateway->relay_rtcp(handle, 1, rtcpbuf, 12);
			}
			if(session->sim_context.changed_temporal) {
				/* Notify the user about the temporal layer change */
				json_t *event = json_object();
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "temporal", json_integer(session->sim_context.templayer));
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
			gateway->relay_rtp(handle, video, buf, len);
			/* Restore header or core statistics will be messed up */
			header->ssrc = htonl(ssrc);
			header->timestamp = htonl(timestamp);
			header->seq_number = htons(seq_number);
		} else {
			if((!video && session->audio_active) || (video && session->video_active)) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
				/* Send the frame back */
				gateway->relay_rtp(handle, video, buf, len);
			}
		}
	}
}

void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
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
		guint32 bitrate = janus_rtcp_get_remb(buf, len);
		if(bitrate > 0) {
			/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
			session->peer_bitrate = bitrate;
			if(session->bitrate == 0)	/* No limit ~= 10000000 */
				janus_rtcp_cap_remb(buf, len, 10000000);
			else
				janus_rtcp_cap_remb(buf, len, session->bitrate);
			gateway->relay_rtcp(handle, 1, buf, len);
			return;
		}
		gateway->relay_rtcp(handle, video, buf, len);
	}
}

void janus_echotest_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len) {
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
		if(buf == NULL || len <= 0)
			return;
		char *text = g_malloc(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (label=%s, %zu bytes) to bounce back: %s\n", label, strlen(text), text);
		/* Save the frame if we're recording */
		janus_recorder_save_frame(session->drc, text, strlen(text));
		/* We send back the same text with a custom prefix */
		const char *prefix = "Janus EchoTest here! You wrote: ";
		char *reply = g_malloc(strlen(prefix)+len+1);
		g_snprintf(reply, strlen(prefix)+len+1, "%s%s", prefix, text);
		g_free(text);
		gateway->relay_data(handle, label, reply, strlen(reply));
		g_free(reply);
	}
}

void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video) {
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
			/* Also add info on what the current bitrate cap is */
			json_object_set_new(event, "current-bitrate", json_integer(session->bitrate));
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
	session->bitrate = 0;
	session->peer_bitrate = 0;
	int i=0;
	for(i=0; i<3; i++) {
		session->ssrc[i] = 0;
		g_free(session->rid[i]);
		session->rid[i] = NULL;
	}
	janus_rtp_switching_context_reset(&session->context);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_echotest_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining EchoTest handler thread\n");
	janus_echotest_message *msg = NULL;
	int error_code = 0;
	char *error_cause = g_malloc(512);
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
		const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
		const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
		json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
		if(msg_simulcast) {
			JANUS_LOG(LOG_VERB, "EchoTest client is going to do simulcasting\n");
			int rid_ext_id = -1, framemarking_ext_id = -1;
			janus_rtp_simulcasting_prepare(msg_simulcast, &rid_ext_id, &framemarking_ext_id, session->ssrc, session->rid);
			session->sim_context.rid_ext_id = rid_ext_id;
			session->sim_context.framemarking_ext_id = framemarking_ext_id;
			session->sim_context.substream_target = 2;	/* Let's aim for the highest quality */
			session->sim_context.templayer_target = 2;	/* Let's aim for all temporal layers */
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
		if(bitrate && (!json_is_integer(bitrate) || json_integer_value(bitrate) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be a positive integer)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (bitrate should be a positive integer)");
			goto error;
		}
		json_t *substream = json_object_get(root, "substream");
		if(substream && (!json_is_integer(substream) || json_integer_value(substream) < 0 || json_integer_value(substream) > 2)) {
			JANUS_LOG(LOG_ERR, "Invalid element (substream should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (substream should be 0, 1 or 2)");
			goto error;
		}
		json_t *temporal = json_object_get(root, "temporal");
		if(temporal && (!json_is_integer(temporal) || json_integer_value(temporal) < 0 || json_integer_value(temporal) > 2)) {
			JANUS_LOG(LOG_ERR, "Invalid element (temporal should be 0, 1 or 2)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (temporal should be 0, 1 or 2)");
			goto error;
		}
		json_t *record = json_object_get(root, "record");
		if(record && !json_is_boolean(record)) {
			JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (record should be a boolean)");
			goto error;
		}
		json_t *recfile = json_object_get(root, "filename");
		if(recfile && !json_is_string(recfile)) {
			JANUS_LOG(LOG_ERR, "Invalid element (filename should be a string)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (filename should be a string)");
			goto error;
		}
		json_t *audiocodec = json_object_get(root, "audiocodec");
		if(audiocodec && !json_is_string(audiocodec)) {
			JANUS_LOG(LOG_ERR, "Invalid element (audiocodec should be a string)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (audiocodec should be a string)");
			goto error;
		}
		json_t *videocodec = json_object_get(root, "videocodec");
		if(videocodec && !json_is_string(videocodec)) {
			JANUS_LOG(LOG_ERR, "Invalid element (videocodec should be a string)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (videocodec should be a string)");
			goto error;
		}
		/* Enforce request */
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
			JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu32"\n", session->bitrate);
			if(session->bitrate > 0) {
				char buf[24];
				janus_rtcp_remb((char *)&buf, 24, session->bitrate);
				JANUS_LOG(LOG_VERB, "Sending REMB\n");
				gateway->relay_rtcp(session->handle, 1, buf, 24);
			}
		}
		if(substream) {
			session->sim_context.substream_target = json_integer_value(substream);
			JANUS_LOG(LOG_VERB, "Setting video SSRC to let through (simulcast): %"SCNu32" (index %d, was %d)\n",
				session->ssrc[session->sim_context.substream], session->sim_context.substream_target, session->sim_context.substream);
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
				char buf[12];
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
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
				json_object_set_new(event, "echotest", json_string("event"));
				json_object_set_new(event, "videocodec", json_string(janus_videocodec_name(session->vcodec)));
				json_object_set_new(event, "temporal", json_integer(session->sim_context.templayer));
				gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event, NULL);
				json_decref(event);
			} else {
				/* We need to change temporal, send a PLI */
				JANUS_LOG(LOG_VERB, "Simulcasting temporal layer change, sending a PLI to kickstart it\n");
				char buf[12];
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				gateway->relay_rtcp(session->handle, 1, buf, 12);
			}
		}

		/* Any SDP to handle? */
		if(msg_sdp) {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			session->has_audio = (strstr(msg_sdp, "m=audio") != NULL);
			session->has_video = (strstr(msg_sdp, "m=video") != NULL);
			session->has_data = (strstr(msg_sdp, "DTLS/SCTP") != NULL);
		}

		if(!audio && !video && !bitrate && !substream && !temporal && !record && !msg_sdp) {
			JANUS_LOG(LOG_ERR, "No supported attributes (audio, video, bitrate, substream, temporal, record, jsep) found\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Message error: no supported attributes (audio, video, bitrate, simulcast, temporal, record, jsep) found");
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
			/* Check if we need to negotiate Opus FEC */
			gboolean opus_fec = FALSE;
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
							if(m->type == JANUS_SDP_AUDIO && !strcasecmp(a->name, "fmtp") &&
									strstr(a->value, "useinbandfec=1")) {
								opus_fec = TRUE;
							}
						}
						ma = ma->next;
					}
				}
				temp = temp->next;
			}
			janus_sdp *answer = janus_sdp_generate_answer(offer,
				JANUS_SDP_OA_AUDIO_CODEC, json_string_value(audiocodec),
				JANUS_SDP_OA_AUDIO_FMTP, opus_fec ? "useinbandfec=1" : NULL,
				JANUS_SDP_OA_VIDEO_CODEC, json_string_value(videocodec),
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_RID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_REPAIRED_RID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_FRAME_MARKING,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC,
				JANUS_SDP_OA_DONE);
			/* If we ended up sendonly, switch to inactive (as we don't really send anything ourselves) */
			janus_sdp_mline *m = janus_sdp_mline_find(answer, JANUS_SDP_AUDIO);
			if(m && m->direction == JANUS_SDP_SENDONLY)
				m->direction = JANUS_SDP_INACTIVE;
			m = janus_sdp_mline_find(answer, JANUS_SDP_VIDEO);
			if(m && m->direction == JANUS_SDP_SENDONLY)
				m->direction = JANUS_SDP_INACTIVE;
			/* Check which codecs we ended up with */
			const char *acodec = NULL, *vcodec = NULL;
			janus_sdp_find_first_codecs(answer, &acodec, &vcodec);
			if(acodec)
				session->acodec = janus_audiocodec_from_name(acodec);
			if(vcodec)
				session->vcodec = janus_videocodec_from_name(vcodec);
			session->has_audio = session->acodec != JANUS_AUDIOCODEC_NONE;
			session->has_video = session->vcodec != JANUS_VIDEOCODEC_NONE;
			if(session->vcodec != JANUS_VIDEOCODEC_VP8 && session->vcodec != JANUS_VIDEOCODEC_H264) {
				/* VP8 r H.264 were not negotiated, if simulcasting was enabled then disable it here */
				int i=0;
				for(i=0; i<3; i++) {
					session->ssrc[i] = 0;
					g_free(session->rid[0]);
					session->rid[0] = NULL;
				}
			}
			/* Done */
			char *sdp = janus_sdp_write(answer);
			janus_sdp_destroy(offer);
			janus_sdp_destroy(answer);
			json_t *jsep = json_pack("{ssss}", "type", type, "sdp", sdp);
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
					/* FIXME We assume we're recording Opus, here */
					memset(filename, 0, 255);
					if(recording_base) {
						/* Use the filename and path we have been provided */
						g_snprintf(filename, 255, "%s-audio", recording_base);
						session->arc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
						if(session->arc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-audio", session, now);
						session->arc = janus_recorder_create(NULL, janus_audiocodec_name(session->acodec), filename);
						if(session->arc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this EchoTest user!\n");
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
							JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-video", session, now);
						session->vrc = janus_recorder_create(NULL, janus_videocodec_name(session->vcodec), filename);
						if(session->vrc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this EchoTest user!\n");
						}
					}
					/* Send a PLI */
					JANUS_LOG(LOG_VERB, "Recording video, sending a PLI to kickstart it\n");
					char buf[12];
					memset(buf, 0, 12);
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
							JANUS_LOG(LOG_ERR, "Couldn't open a text data recording file for this EchoTest user!\n");
						}
					} else {
						/* Build a filename */
						g_snprintf(filename, 255, "echotest-%p-%"SCNi64"-data", session, now);
						session->drc = janus_recorder_create(NULL, "text", filename);
						if(session->drc == NULL) {
							/* FIXME We should notify the fact the recorder could not be created */
							JANUS_LOG(LOG_ERR, "Couldn't open a text data recording file for this EchoTest user!\n");
						}
					}
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
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving EchoTest handler thread\n");
	return NULL;
}
