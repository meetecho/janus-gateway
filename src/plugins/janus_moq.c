/*! \file   janus_moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus MoQ gateway plugin
 * \details Check the \ref moq for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page moq MoQ gateway plugin documentation
 *
 * TBD.
 */

#include "plugins/plugin.h"

#include <jansson.h>
#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../sdp-utils.h"
#include "../record.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_MOQ_VERSION			1
#define JANUS_MOQ_VERSION_STRING	"0.0.1"
#define JANUS_MOQ_DESCRIPTION		"This is a sample MoQ/WebRTC gateway plugin for Janus, using the imquic library."
#define JANUS_MOQ_NAME				"JANUS MoQ plugin (imquic)"
#define JANUS_MOQ_AUTHOR			"Meetecho s.r.l."
#define JANUS_MOQ_PACKAGE			"janus.plugin.moq"

/* Plugin methods */
janus_plugin *create(void);
int janus_moq_init(janus_callbacks *callback, const char *config_path);
void janus_moq_destroy(void);
int janus_moq_get_api_compatibility(void);
int janus_moq_get_version(void);
const char *janus_moq_get_version_string(void);
const char *janus_moq_get_description(void);
const char *janus_moq_get_name(void);
const char *janus_moq_get_author(void);
const char *janus_moq_get_package(void);
void janus_moq_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_moq_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_moq_handle_admin_message(json_t *message);
void janus_moq_setup_media(janus_plugin_session *handle);
void janus_moq_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_moq_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
void janus_moq_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet);
void janus_moq_data_ready(janus_plugin_session *handle);
void janus_moq_hangup_media(janus_plugin_session *handle);
void janus_moq_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_moq_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_moq_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_moq_init,
		.destroy = janus_moq_destroy,

		.get_api_compatibility = janus_moq_get_api_compatibility,
		.get_version = janus_moq_get_version,
		.get_version_string = janus_moq_get_version_string,
		.get_description = janus_moq_get_description,
		.get_name = janus_moq_get_name,
		.get_author = janus_moq_get_author,
		.get_package = janus_moq_get_package,

		.create_session = janus_moq_create_session,
		.handle_message = janus_moq_handle_message,
		.handle_admin_message = janus_moq_handle_admin_message,
		.setup_media = janus_moq_setup_media,
		.incoming_rtp = janus_moq_incoming_rtp,
		.incoming_rtcp = janus_moq_incoming_rtcp,
		.incoming_data = janus_moq_incoming_data,
		.data_ready = janus_moq_data_ready,
		.hangup_media = janus_moq_hangup_media,
		.destroy_session = janus_moq_destroy_session,
		.query_session = janus_moq_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_MOQ_NAME);
	return &janus_moq_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter bridge_parameters[] = {
	{"port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"remote_host", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"remote_port", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"rawquic", JANUS_JSON_BOOL, 0},
	{"webtransport", JANUS_JSON_BOOL, 0},
	{"path", JANUS_JSON_STRING, 0},
	{"role", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"namespace", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"audio_track", JANUS_JSON_STRING, 0},
	{"video_track", JANUS_JSON_STRING, 0},
	{"auth_info", JANUS_JSON_STRING, 0},
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_moq_handler(void *data);
static void janus_moq_hangup_media_internal(janus_plugin_session *handle);

/* MTU to assume when (optionally) packetizing H.264 in RTP (for MoQ subscribers) */
static int mtu = 1200;

typedef struct janus_moq_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_moq_message;
static GAsyncQueue *messages = NULL;
static janus_moq_message exit_message;

/* Helper struct for mapping RTP to MoQ */
typedef struct janus_moq_moq_rtp {
	char *track;
	gboolean active;
	uint64_t request_id, track_alias, group_id, object_id;
	uint32_t ssrc;
	uint32_t last_ts;
	uint64_t seq;
	uint64_t timestamp, timestamp_start;
	uint8_t *buffer;
	size_t offset;
	size_t size;
	gboolean keyframe;
	int width, height;
	gboolean nal_added;
	size_t nal_offset;
	uint8_t extradata[50];
	size_t extradata_len;
} janus_moq_moq_rtp;

/* Plugin session */
typedef struct janus_moq_session {
	janus_plugin_session *handle;
	imquic_endpoint *quic_endpoint;
	gboolean moqsub, moqpub;
	char *track_namespace, *auth_info;
	janus_moq_moq_rtp audio_track, video_track;
	GHashTable *media, *ptypes;
	GList *connections;
	janus_mutex mutex;
	uint16_t pli_freq;
	gint64 pli_latest;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_moq_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_moq_session_destroy(janus_moq_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_moq_session_free(const janus_refcount *session_ref) {
	janus_moq_session *session = janus_refcount_containerof(session_ref, janus_moq_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_free(session->track_namespace);
	g_free(session->audio_track.track);
	g_free(session->audio_track.buffer);
	g_free(session->video_track.track);
	g_free(session->video_track.buffer);
	g_free(session->auth_info);
	g_hash_table_unref(session->media);
	g_hash_table_unref(session->ptypes);
	g_list_free(session->connections);
	janus_mutex_destroy(&session->mutex);
	g_free(session);
}

static void janus_moq_message_free(janus_moq_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_moq_session *session = (janus_moq_session *)msg->handle->plugin_handle;
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

/* imquic stuff */
static GHashTable *connections = NULL;
static janus_mutex connections_mutex = JANUS_MUTEX_INITIALIZER;
/* Callbacks */
static void janus_moq_new_connection(imquic_connection *conn, void *user_data);
static void janus_moq_connection_gone(imquic_connection *conn);
/* MoQ specific */
static void janus_moq_moq_ready(imquic_connection *conn);
static void janus_moq_moq_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *params);
static void janus_moq_moq_publish_namespace_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason);
static void janus_moq_moq_incoming_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
	imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters);
static void janus_moq_moq_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id);
static void janus_moq_moq_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, imquic_moq_request_parameters *parameters);
static void janus_moq_moq_subscribe_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias);
static void janus_moq_moq_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason);
static void janus_moq_moq_incoming_object(imquic_connection *conn, imquic_moq_object *object);

/* Helper to destroy an object extension */
static void imquic_moq_object_extension_free(imquic_moq_object_extension *extension) {
	if(extension != NULL) {
		if(extension->value.data.buffer != NULL)
			g_free(extension->value.data.buffer);
		g_free(extension);
	}
}

/* LOC processing */
typedef enum janus_moq_loc_media_type {
	JANUS_MOQ_LOC_MEDIA_NONE = 0xFF,		/* Unknown */
	JANUS_MOQ_LOC_MEDIA_H264 = 0x0,		/* H264/AVCC video */
	JANUS_MOQ_LOC_MEDIA_OPUS = 0x1,		/* Opus audio */
	JANUS_MOQ_LOC_MEDIA_TEXT = 0x2,		/* UTF-8 text */
	JANUS_MOQ_LOC_MEDIA_AAC = 0x3,		/* AAC-LC audio */
} janus_moq_loc_media_type;
static const char *janus_moq_loc_media_type_str(janus_moq_loc_media_type type) {
	switch(type) {
		case JANUS_MOQ_LOC_MEDIA_NONE:
			return "none";
		case JANUS_MOQ_LOC_MEDIA_H264:
			return "H.264 video (AVCC)";
		case JANUS_MOQ_LOC_MEDIA_OPUS:
			return "Opus bitstream";
		case JANUS_MOQ_LOC_MEDIA_TEXT:
			return "UTF-8 text";
		case JANUS_MOQ_LOC_MEDIA_AAC:
			return "AAC-LC audio";
		default:
			break;
	}
	return NULL;
}

typedef enum janus_moq_loc_extension {
	JANUS_MOQ_LOC_MEDIA_TYPE = 0x0A,		/* Media type header extension */
	JANUS_MOQ_LOC_H264_HEADER = 0x0B,	/* Video H264 in AVCC metadata (TODO change to 0x15) */
	JANUS_MOQ_LOC_H264_EXTRADATA = 0x0D,	/* Video H264 in AVCC extradata */
	JANUS_MOQ_LOC_OPUS_HEADER = 0x0F,	/* Audio Opus bitstream data */
	JANUS_MOQ_LOC_AAC_HEADER = 0x13,		/* Audio AAC-LC in MPEG4 bitstream data */
} janus_moq_loc_extension;
static const char *janus_moq_loc_extension_str(janus_moq_loc_extension type) {
	switch(type) {
		case JANUS_MOQ_LOC_MEDIA_TYPE:
			return "Media type header extension";
		case JANUS_MOQ_LOC_H264_HEADER:
			return "Video H264 in AVCC metadata";
		case JANUS_MOQ_LOC_H264_EXTRADATA:
			return "Video H264 in AVCC extradata";
		case JANUS_MOQ_LOC_OPUS_HEADER:
			return "Audio Opus bitstream data";
		case JANUS_MOQ_LOC_AAC_HEADER:
			return "Audio AAC-LC in MPEG4 bitstream data";
		default:
			break;
	}
	return NULL;
}

/* Helpers to parse SPS/PPS (needed for Annex-B to AVC1 translation) */
static uint32_t janus_moq_h264_eg_getbit(uint8_t *base, uint32_t offset);
static uint32_t janus_moq_h264_eg_decode(uint8_t *base, uint32_t *offset);
static size_t janus_moq_h264_parse_sps(uint8_t *avcc_data, char *buffer, int len, int *width, int *height);

/* Error codes */
#define JANUS_MOQ_ERROR_NO_MESSAGE		410
#define JANUS_MOQ_ERROR_INVALID_JSON		412
#define JANUS_MOQ_ERROR_INVALID_REQUEST	412
#define JANUS_MOQ_ERROR_MISSING_ELEMENT	413
#define JANUS_MOQ_ERROR_INVALID_ELEMENT	414
#define JANUS_MOQ_ERROR_MISSING_SDP		415
#define JANUS_MOQ_ERROR_INVALID_SDP		416
#define JANUS_MOQ_ERROR_WRONG_STATE		417
#define JANUS_MOQ_ERROR_IMQUIC_ERROR		418


/* Plugin implementation */
int janus_moq_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	if(!imquic_is_inited()) {
		/* imquic wasn't initialized */
		JANUS_LOG(LOG_FATAL, "imquic not initialized (has Janus been built with imquic support?\n");
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_MOQ_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_MOQ_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_MOQ_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	char *sslkeylog = NULL;
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *skl = janus_config_get(config, config_general, janus_config_type_item, "sslkeylog");
		if(skl != NULL && skl->value != NULL)
			sslkeylog = g_strdup(skl->value);
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_MOQ_NAME);
		}
	}
	janus_config_destroy(config);
	config = NULL;

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_moq_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_moq_message_free);
	/* imquic */
	//~ imquic_init(sslkeylog);
	//~ imquic_set_log_level(IMQUIC_LOG_INFO);
	connections = g_hash_table_new_full(NULL, NULL, NULL, NULL);
	g_free(sslkeylog);

	/* This is the callback we'll need to invoke to contact the server */
	gateway = callback;
	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("quic handler", janus_moq_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the QUIC handler thread...\n", error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_MOQ_NAME);
	return 0;
}

void janus_moq_destroy(void) {
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
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_MOQ_NAME);
}

int janus_moq_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_moq_get_version(void) {
	return JANUS_MOQ_VERSION;
}

const char *janus_moq_get_version_string(void) {
	return JANUS_MOQ_VERSION_STRING;
}

const char *janus_moq_get_description(void) {
	return JANUS_MOQ_DESCRIPTION;
}

const char *janus_moq_get_name(void) {
	return JANUS_MOQ_NAME;
}

const char *janus_moq_get_author(void) {
	return JANUS_MOQ_AUTHOR;
}

const char *janus_moq_get_package(void) {
	return JANUS_MOQ_PACKAGE;
}

static janus_moq_session *janus_moq_lookup_session(janus_plugin_session *handle) {
	janus_moq_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_moq_session *)handle->plugin_handle;
	}
	return session;
}

void janus_moq_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_moq_session *session = g_malloc0(sizeof(janus_moq_session));
	session->handle = handle;
	session->media = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	session->ptypes = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_mutex_init(&session->mutex);
	janus_refcount_init(&session->ref, janus_moq_session_free);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_moq_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_moq_session *session = janus_moq_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing QUIC session...\n");
	janus_moq_hangup_media_internal(handle);
	/* If there's a QUIC server running, get rid of it */
	if(session->quic_endpoint != NULL)
		imquic_shutdown_endpoint(session->quic_endpoint);
	session->quic_endpoint = NULL;
	/* Done */
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_moq_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_moq_session *session = janus_moq_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	/* TODO */
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_moq_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_moq_session *session = (janus_moq_session *)handle->plugin_handle;
	if(!session)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	janus_moq_message *msg = g_malloc(sizeof(janus_moq_message));
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

json_t *janus_moq_handle_admin_message(json_t *message) {
	/* Just here as a proof of concept: since there's nothing to configure,
	 * as an QUIC plugin we echo this Admin request back as well */
	json_t *response = json_deep_copy(message);
	return response;
}

void janus_moq_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_MOQ_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_moq_session *session = janus_moq_lookup_session(handle);
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

void janus_moq_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_moq_session *session = (janus_moq_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		if(!session->moqpub || session->connections == NULL || packet->buffer == NULL || packet->length == 0)
			return;
		int plen = 0;
		char *payload = janus_rtp_payload((char *)packet->buffer, packet->length, &plen);
		if(payload == NULL || plen == 0)
			return;
		GList *temp = session->connections;
		imquic_connection *conn = NULL;
		while(temp) {
			conn = (imquic_connection *)temp->data;
			/* Send as a MoQ object */
			if(!packet->video && session->audio_track.track && session->audio_track.active) {
				/* Each audio frame is self contained, write the LOC info first as extensions */
				uint8_t extensions[256];
				size_t extensions_len = 0;
				GList *exts = NULL;
				imquic_moq_object_extension type = { 0 };
				type.id = JANUS_MOQ_LOC_MEDIA_TYPE;
				type.value.number = JANUS_MOQ_LOC_MEDIA_OPUS;
				exts = g_list_append(exts, &type);
				imquic_moq_object_extension header = { 0 };
				header.id = JANUS_MOQ_LOC_OPUS_HEADER;
				uint8_t buffer[200];
				size_t offset = 0, blen = sizeof(buffer);
				offset += imquic_varint_write(session->audio_track.seq, &buffer[offset], blen-offset);
				session->audio_track.seq++;
				offset += imquic_varint_write(session->audio_track.timestamp, &buffer[offset], blen-offset);
				session->audio_track.timestamp += 20000;
				offset += imquic_varint_write(1000000, &buffer[offset], blen-offset);
				offset += imquic_varint_write(48000, &buffer[offset], blen-offset);
				offset += imquic_varint_write(1, &buffer[offset], blen-offset);
				offset += imquic_varint_write(20000, &buffer[offset], blen-offset);
				offset += imquic_varint_write(janus_get_real_time() / 1000, &buffer[offset], blen-offset);
				header.value.data.buffer = buffer;
				header.value.data.length = offset;
				exts = g_list_append(exts, &header);
				extensions_len = imquic_moq_build_object_extensions(exts, extensions, sizeof(extensions));
				g_list_free(exts);
				/* Prepare a MoQ object and send it */
				imquic_moq_object object = {
					.request_id = session->audio_track.request_id,
					.track_alias = session->audio_track.track_alias,
					.group_id = session->audio_track.group_id++,
					.subgroup_id = 0,	/* FIXME */
					.object_id = session->audio_track.object_id,
					.payload = (uint8_t *)payload,
					.payload_len = plen,
					.extensions = extensions,
					.extensions_len = extensions_len,
					.delivery = IMQUIC_MOQ_USE_SUBGROUP,
					.end_of_stream = TRUE
				};
				imquic_moq_send_object(conn, &object);
			} else if(packet->video && session->video_track.track && session->video_track.active) {
				/* Buffer until we have a complete frame */
				if(session->video_track.buffer == NULL) {
					session->video_track.size = 10000;
					session->video_track.buffer = g_malloc(session->video_track.size);
					session->video_track.offset = 0;
					session->video_track.timestamp = session->video_track.timestamp_start = janus_get_monotonic_time();
					session->video_track.group_id = 0;
					session->video_track.object_id = 0;
				}
				janus_rtp_header *rtp = (janus_rtp_header *)packet->buffer;
				uint32_t ts = ntohl(rtp->timestamp);
				if(session->video_track.last_ts == 0)
					session->video_track.last_ts = ts;
				if(session->video_track.last_ts != ts && session->video_track.offset > 0) {
					/* Buffer is complete, convert Annex-B to AVC1 and send */
					if(session->video_track.nal_added) {
						uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
						JANUS_LOG(LOG_HUGE, "NAL has size %"SCNu32"\n", nal_size);
						nal_size = htonl(nal_size);
						memcpy(session->video_track.buffer + session->video_track.nal_offset, &nal_size, 4);
					}
					JANUS_LOG(LOG_HUGE, "[%s] Need to send video frame of %zu bytes\n",
						imquic_get_connection_name(conn), session->video_track.offset);
					/* Write the LOC info first as extensions */
					uint8_t extensions[256];
					size_t extensions_len = 0;
					GList *exts = NULL;
					imquic_moq_object_extension type = { 0 };
					type.id = JANUS_MOQ_LOC_MEDIA_TYPE;
					type.value.number = JANUS_MOQ_LOC_MEDIA_H264;
					exts = g_list_append(exts, &type);
					imquic_moq_object_extension header = { 0 };
					header.id = JANUS_MOQ_LOC_H264_HEADER;
					uint8_t buffer[200];
					size_t offset = 0, blen = sizeof(buffer);
					offset += imquic_varint_write(session->video_track.seq, &buffer[offset], blen-offset);
					session->video_track.seq++;
					gint64 now = janus_get_monotonic_time();
					uint64_t pts = now - session->video_track.timestamp_start, dts = pts;
					offset += imquic_varint_write(pts, &buffer[offset], blen-offset);
					offset += imquic_varint_write(dts, &buffer[offset], blen-offset);
					offset += imquic_varint_write(1000000, &buffer[offset], blen-offset);
					uint64_t duration = 30000;	/* FIXME */
					offset += imquic_varint_write(duration, &buffer[offset], blen-offset);
					session->video_track.timestamp = now;
					offset += imquic_varint_write(janus_get_real_time() / 1000, &buffer[offset], blen-offset);
					header.value.data.buffer = buffer;
					header.value.data.length = offset;
					exts = g_list_append(exts, &header);
					imquic_moq_object_extension extradata = { 0 };
					if(session->video_track.extradata_len > 0) {
						extradata.id = JANUS_MOQ_LOC_H264_EXTRADATA;
						extradata.value.data.buffer = session->video_track.extradata;
						extradata.value.data.length = session->video_track.extradata_len;
						exts = g_list_append(exts, &extradata);
						session->video_track.extradata_len = 0;
					}
					extensions_len = imquic_moq_build_object_extensions(exts, extensions, sizeof(extensions));
					g_list_free(exts);
					/* Prepare a MoQ object and send it */
					imquic_moq_object object = {
						.request_id = session->video_track.request_id,
						.track_alias = session->video_track.track_alias,
						.group_id = session->video_track.group_id,
						.subgroup_id = 0,	/* FIXME */
						.object_id = session->video_track.object_id,
						.payload = session->video_track.buffer,
						.payload_len = session->video_track.offset,
						.extensions = extensions,
						.extensions_len = extensions_len,
						.delivery = IMQUIC_MOQ_USE_SUBGROUP,
						.end_of_stream = TRUE
					};
					session->video_track.object_id++;
					imquic_moq_send_object(conn, &object);
					/* Done, process the new packet */
					session->video_track.last_ts = ts;
					session->video_track.offset = 0;
					session->video_track.keyframe = FALSE;
					session->video_track.nal_added = FALSE;
					session->video_track.nal_offset = 0;
				}
				/* If we're here, we're just buffering */
				if(session->video_track.offset + plen > session->video_track.size) {
					session->video_track.size = session->video_track.offset + plen;
					session->video_track.buffer = g_realloc(session->video_track.buffer, session->video_track.size);
				}
				/* Depacketize H.264 */
				JANUS_LOG(LOG_HUGE, "[%s] Depacketizing payload (%d bytes)\n", imquic_get_connection_name(conn), plen);
				uint8_t fragment = *payload & 0x1F;
				uint8_t nal = *(payload+1) & 0x1F;
				uint8_t start_bit = *(payload+1) & 0x80;
				int len = plen, jump = 0;
				if(fragment == 7) {
					/* SPS, see if we can extract the width/height as well */
					//~ session->video_track.metadata = janus_moq_h264_parse_sps(payload, plen, &session->video_track.width, &session->video_track.height);
					//~ JANUS_LOG(LOG_INFO, "[%s] Video has resolution %dx%d (%p)\n", imquic_get_connection_name(conn),
						//~ session->video_track.width, session->video_track.height, session->video_track.metadata);
				} else if(fragment == 24) {
					/* May we find an SPS in this STAP-A? */
					char *temp = payload;
					temp++;
					int tot = len-1;
					uint16_t psize = 0;
					while(tot > 0) {
						memcpy(&psize, temp, 2);
						psize = ntohs(psize);
						temp += 2;
						tot -= 2;
						int nal = *temp & 0x1F;
						if(nal == 7) {
							session->video_track.extradata_len = janus_moq_h264_parse_sps(session->video_track.extradata,
								temp - 2, tot + 2, &session->video_track.width, &session->video_track.height);
							JANUS_LOG(LOG_HUGE, "[%s]   -- Video has resolution %dx%d (%zu bytes of extradata)\n", imquic_get_connection_name(conn),
								session->video_track.width, session->video_track.height, session->video_track.extradata_len);
						}
						temp += psize;
						tot -= psize;
					}
					len = tot;
				}
				if(fragment == 28 || fragment == 29) {
					JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d, NAL=%d, Start=%d (len=%d, frame_len=%zu)\n",
						imquic_get_connection_name(conn), fragment, nal, start_bit, len, session->video_track.offset);
				} else {
					JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d (len=%d, frame_len=%zu)\n",
						imquic_get_connection_name(conn), fragment, len, session->video_track.offset);
				}
				if(fragment == 5 ||
						((fragment == 28 || fragment == 29) && nal == 5 && start_bit == 128)) {
					JANUS_LOG(LOG_HUGE, "[%s]   -- Key frame (seq=%"SCNu16", ts=%"SCNu32", fragment=%d)\n",
						imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), fragment);
					session->video_track.keyframe = TRUE;
					session->video_track.group_id++;
					session->video_track.object_id = 0;
				}
				/* Frame manipulation */
				if((fragment > 0) && (fragment < 24)) {
					/* Add a start code */
					JANUS_LOG(LOG_HUGE, "[%s]   -- -- Adding a start code (fragment=%d)\n",
						imquic_get_connection_name(conn), fragment);
					uint8_t *temp = session->video_track.buffer + session->video_track.offset;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x00, 1);
					memset(temp + 3, 0x01, 1);
					if(session->video_track.nal_added) {
						uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
						JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
							imquic_get_connection_name(conn), nal_size);
						nal_size = htonl(nal_size);
						memcpy(session->video_track.buffer + session->video_track.nal_offset, &nal_size, 4);
					}
					if(!session->video_track.nal_added)
						session->video_track.nal_added = TRUE;
					session->video_track.nal_offset = session->video_track.offset;
					session->video_track.offset += 4;
				} else if(fragment == 24) {	/* STAP-A */
					/* De-aggregate the NALs and write each of them separately */
					payload++;
					int tot = len-1;
					uint16_t psize = 0;
					while(tot > 0) {
						memcpy(&psize, payload, 2);
						psize = ntohs(psize);
						payload += 2;
						tot -= 2;
						/* Now we have a single NAL */
						JANUS_LOG(LOG_HUGE, "[%s]   -- -- Adding a start code (aggregated fragment=%d)\n",
							imquic_get_connection_name(conn), fragment);
						uint8_t *temp = session->video_track.buffer + session->video_track.offset;
						memset(temp, 0x00, 1);
						memset(temp + 1, 0x00, 1);
						memset(temp + 2, 0x00, 1);
						memset(temp + 3, 0x01, 1);
						if(session->video_track.nal_added) {
							uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
							JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
								imquic_get_connection_name(conn), nal_size);
							nal_size = htonl(nal_size);
							memcpy(session->video_track.buffer + session->video_track.nal_offset, &nal_size, 4);
						}
						if(!session->video_track.nal_added)
							session->video_track.nal_added = TRUE;
						session->video_track.nal_offset = session->video_track.offset;
						session->video_track.offset += 4;
						memcpy(session->video_track.buffer + session->video_track.offset, payload, psize);
						session->video_track.offset += psize;
						/* Go on */
						payload += psize;
						tot -= psize;
					}
				} else if((fragment == 28) || (fragment == 29)) {	/* FIXME true fr FU-A, not FU-B */
					uint8_t indicator = *payload;
					uint8_t header = *(payload+1);
					jump = 2;
					len -= 2;
					if(header & 0x80) {
						/* First part of fragmented packet (S bit set) */
						JANUS_LOG(LOG_HUGE, "[%s]   -- -- Adding a start code (fragmented fragment=%d)\n",
							imquic_get_connection_name(conn), fragment);
						uint8_t *temp = session->video_track.buffer + session->video_track.offset;
						memset(temp, 0x00, 1);
						memset(temp + 1, 0x00, 1);
						memset(temp + 2, 0x00, 1);
						memset(temp + 3, 0x01, 1);
						memset(temp + 4, (indicator & 0xE0) | (header & 0x1F), 1);
						if(session->video_track.nal_added) {
							uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
							JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
								imquic_get_connection_name(conn), nal_size);
							nal_size = htonl(nal_size);
							memcpy(session->video_track.buffer + session->video_track.nal_offset, &nal_size, 4);
						}
						if(!session->video_track.nal_added)
							session->video_track.nal_added = TRUE;
						session->video_track.nal_offset = session->video_track.offset;
						session->video_track.offset += 5;
					} else if (header & 0x40) {
						/* Last part of fragmented packet (E bit set) */
					}
				}
				/* Frame manipulation: append the actual payload to the buffer */
				if(len > 0) {
					if(session->video_track.offset + len > session->video_track.size) {
						JANUS_LOG(LOG_HUGE, "[%s]   -- Frame exceeds buffer size...\n",
							imquic_get_connection_name(conn));
					} else {
						memcpy(session->video_track.buffer + session->video_track.offset, payload+jump, len);
						session->video_track.offset += len;
					}
				}
			}
			temp = temp->next;
		}
		gint64 now = janus_get_monotonic_time();
		if(session->pli_freq > 0 && ((now-session->pli_latest) >= ((gint64)session->pli_freq*G_USEC_PER_SEC))) {
			/* FIXME We send a FIR every tot seconds */
			session->pli_latest = now;
			JANUS_LOG(LOG_HUGE, "Sending PLI\n");
			gateway->send_pli(session->handle);
		}
	}
}

void janus_moq_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_moq_session *session = (janus_moq_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		if(packet->buffer == NULL || packet->length == 0)
			return;
		/* TODO Should we do something with RTCP? */
	}
}

void janus_moq_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_moq_session *session = (janus_moq_session *)handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(g_atomic_int_get(&session->destroyed))
			return;
		if(packet->buffer == NULL || packet->length == 0)
			return;
		char *label = packet->label;
		if(label == NULL)
			label = (char *)"datagram";
		char *protocol = packet->protocol;
		char *buf = packet->buffer;
		uint16_t len = packet->length;
		if(packet->binary) {
			/* TODO */
			JANUS_LOG(LOG_WARN, "Got a binary DataChannel message (label=%s, protocol=%s, %u bytes), ignoring\n",
				label, protocol, len);
			return;
		}
		/* Text data, send it to the QUIC connections as datagrams */
		JANUS_LOG(LOG_INFO, "Relaying text (%.*s, %d) to %d QUIC connections via %s\n",
			len, buf, len, g_list_length(session->connections), label);
		gboolean datagram = !strcasecmp(label, "datagram");
		GList *temp = session->connections;
		imquic_connection *conn = NULL;
		uint8_t data[1500];
		data[0] = 0;	/* FIXME */
		memcpy(&data[1], buf, len);
		while(temp) {
			conn = (imquic_connection *)temp->data;
			if(datagram) {
				imquic_send_on_datagram(conn, data, len + 1);
			} else {
				uint64_t stream_id = 0;
				imquic_new_stream_id(conn, FALSE, &stream_id);
				imquic_send_on_stream(conn, stream_id, (uint8_t *)buf, 0, len, TRUE);
			}
			temp = temp->next;
		}
	}
}

void janus_moq_data_ready(janus_plugin_session *handle) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) ||
			g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	/* Data channels are writable */
}

void janus_moq_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_MOQ_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_moq_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_moq_hangup_media_internal(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_moq_session *session = janus_moq_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* If there's a QUIC server running, get rid of it */
	if(session->quic_endpoint != NULL)
		imquic_shutdown_endpoint(session->quic_endpoint);
	session->quic_endpoint = NULL;
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "quic", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_moq_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining QUIC handler thread\n");
	janus_moq_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_moq_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_moq_session *session = janus_moq_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_moq_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_moq_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_MOQ_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_MOQ_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			0, JANUS_MOQ_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *result = NULL, *localjsep = NULL;

		if(!strcasecmp(request_text, "bridge")) {
			JANUS_VALIDATE_JSON_OBJECT(root, bridge_parameters,
				error_code, error_cause, TRUE,
				JANUS_MOQ_ERROR_MISSING_ELEMENT, JANUS_MOQ_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			/* Any SDP to handle? If not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_MOQ_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			if(!msg_sdp_type || strcasecmp(msg_sdp_type, "offer")) {
				JANUS_LOG(LOG_ERR, "Not an SDP offer\n");
				error_code = JANUS_MOQ_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Missing or invalid SDP type");
				goto error;
			}
			janus_mutex_lock(&session->mutex);
			if(session->quic_endpoint) {
				janus_mutex_unlock(&session->mutex);
				/* Already connected, or still cleaning up */
				JANUS_LOG(LOG_ERR, "Session already established\n");
				error_code = JANUS_MOQ_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Session already established");
				goto error;
			}
			/* Initiate the QUIC endpoint */
			uint16_t port = json_integer_value(json_object_get(root, "port"));
			const char *remote_host = json_string_value(json_object_get(root, "remote_host"));
			uint16_t remote_port = json_integer_value(json_object_get(root, "remote_port"));
			gboolean raw_quic = json_is_true(json_object_get(root, "rawquic"));
			gboolean webtransport = json_is_true(json_object_get(root, "webtransport"));
			if(!raw_quic && !webtransport)
				raw_quic = TRUE;
			const char *path = json_string_value(json_object_get(root, "path"));
			const char *role = json_string_value(json_object_get(root, "role"));
			const char *namespace = json_string_value(json_object_get(root, "namespace"));
			const char *audio_track = json_string_value(json_object_get(root, "audio_track"));
			const char *video_track = json_string_value(json_object_get(root, "video_track"));
			const char *auth_info = json_string_value(json_object_get(root, "auth_info"));
			if(role == NULL) {
				/* Missing role */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Missing MoQ role\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing MoQ role");
				goto error;
			}
			if(strcasecmp(role, "publisher") && strcasecmp(role, "subscriber")) {
				/* Invalid role */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Invalid MoQ role\n");
				error_code = JANUS_MOQ_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid MoQ role");
				goto error;
			}
			if(namespace == NULL) {
				/* Missing namespace */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Missing MoQ namespace\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing MoQ namespace");
				goto error;
			}
			if(audio_track == NULL && video_track == NULL) {
				/* Missing audio or video track */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "At least one track (audio or video) must be provided\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "At least one track (audio or video) must be provided");
				goto error;
			}
			char name[50];
			/* Create the imquic endpoint (client) */
			imquic_endpoint *quic_endpoint = NULL;
			session->moqpub = !strcasecmp(role, "publisher");
			session->moqsub = !session->moqpub;
			memset(&session->audio_track, 0, sizeof(session->audio_track));
			memset(&session->video_track, 0, sizeof(session->video_track));
			session->track_namespace = g_strdup(namespace);
			if(audio_track != NULL) {
				session->audio_track.track = g_strdup(audio_track);
				if(session->moqsub) {
					/* FIXME We assume audio is the first m-line */
					session->audio_track.request_id = 0;
					session->audio_track.track_alias = 0;
				}
				session->audio_track.ssrc = janus_random_uint32();
			}
			if(video_track != NULL) {
				session->video_track.track = g_strdup(video_track);
				if(session->moqsub) {
					/* FIXME We assume video is the second m-line */
					session->video_track.request_id = audio_track ? 2 : 0;
					session->video_track.track_alias = 1;
				}
				session->video_track.ssrc = janus_random_uint32();
			}
			session->auth_info = auth_info ? g_strdup(auth_info) : NULL;
			g_snprintf(name, sizeof(name), "janus-moq%s-%"SCNu32,
				session->moqpub ? "pub" : "sub", janus_random_uint32());
			quic_endpoint = imquic_create_moq_client(name,
				IMQUIC_CONFIG_INIT,
				IMQUIC_CONFIG_LOCAL_PORT, port,
				IMQUIC_CONFIG_REMOTE_HOST, remote_host,
				IMQUIC_CONFIG_REMOTE_PORT, remote_port,
				IMQUIC_CONFIG_WEBTRANSPORT, webtransport,
				IMQUIC_CONFIG_HTTP3_PATH, path,
				IMQUIC_CONFIG_USER_DATA, session,
				IMQUIC_CONFIG_MOQ_VERSION, IMQUIC_MOQ_VERSION_ANY,
				IMQUIC_CONFIG_DONE, NULL);
			if(quic_endpoint == NULL) {
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Error creating imquic MoQ %s\n", session->moqpub ? "publisher" : "subscriber");
				error_code = JANUS_MOQ_ERROR_IMQUIC_ERROR;
				g_snprintf(error_cause, 512, "Error creating imquic MoQ %s\n", session->moqpub ? "publisher" : "subscriber");
				goto error;
			}
			/* Configure callbacks */
			if(session->moqpub) {
				imquic_set_new_moq_connection_cb(quic_endpoint, janus_moq_new_connection);
				imquic_set_moq_ready_cb(quic_endpoint, janus_moq_moq_ready);
				imquic_set_publish_namespace_accepted_cb(quic_endpoint, janus_moq_moq_publish_namespace_accepted);
				imquic_set_publish_namespace_error_cb(quic_endpoint, janus_moq_moq_publish_namespace_error);
				imquic_set_incoming_subscribe_cb(quic_endpoint, janus_moq_moq_incoming_subscribe);
				imquic_set_incoming_unsubscribe_cb(quic_endpoint, janus_moq_moq_incoming_unsubscribe);
				imquic_set_moq_connection_gone_cb(quic_endpoint, janus_moq_connection_gone);
			} else if(session->moqsub) {
				imquic_set_new_moq_connection_cb(quic_endpoint, janus_moq_new_connection);
				imquic_set_moq_ready_cb(quic_endpoint, janus_moq_moq_ready);
				imquic_set_subscribe_accepted_cb(quic_endpoint, janus_moq_moq_subscribe_accepted);
				imquic_set_subscribe_error_cb(quic_endpoint, janus_moq_moq_subscribe_error);
				imquic_set_publish_done_cb(quic_endpoint, janus_moq_moq_publish_done);
				imquic_set_incoming_object_cb(quic_endpoint, janus_moq_moq_incoming_object);
				imquic_set_moq_connection_gone_cb(quic_endpoint, janus_moq_connection_gone);
			}
			session->quic_endpoint = quic_endpoint;
			imquic_start_endpoint(quic_endpoint);
			janus_mutex_unlock(&session->mutex);
			/* Parse the SDP we got one */
			char sdperror[100];
			janus_sdp *offer = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!offer) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_MOQ_ERROR_INVALID_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			/* Generate an answer */
			janus_sdp *answer = janus_sdp_generate_answer(offer);
			GList *temp = offer->m_lines;
			while(temp) {
				janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
				if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
					janus_sdp_generate_answer_mline(offer, answer, m,
						JANUS_SDP_OA_MLINE, m->type,
							JANUS_SDP_OA_DIRECTION, (session->moqsub ? JANUS_SDP_SENDONLY : JANUS_SDP_RECVONLY),
							JANUS_SDP_OA_CODEC, (m->type == JANUS_SDP_VIDEO ? "h264" : NULL),
							JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
							JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC,
						JANUS_SDP_OA_DONE);
					janus_sdp_mline *am = janus_sdp_mline_find_by_index(answer, m->index);
					int pt = am->ptypes ? GPOINTER_TO_INT(am->ptypes->data) : -1;
					g_hash_table_insert(session->ptypes, janus_uint64_dup(am->index), GINT_TO_POINTER(pt));
				}
				temp = temp->next;
			}
			janus_sdp_destroy(offer);
			char *sdp = janus_sdp_write(answer);
			janus_sdp_destroy(answer);
			JANUS_LOG(LOG_VERB, "Prepared SDP answer\n%s", sdp);
			g_atomic_int_set(&session->hangingup, 0);
			/* Send SDP to the browser */
			result = json_object();
			json_object_set_new(result, "event", json_string("bridging"));
			localjsep = json_pack("{ssss}", "type", "answer", "sdp", sdp);
			g_free(sdp);
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Get rid of an ongoing session */
			gateway->close_pc(session->handle);
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_MOQ_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "quic", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		int ret = gateway->push_event(msg->handle, &janus_moq_plugin, msg->transaction, event, localjsep);
		JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(event);
		if(localjsep)
			json_decref(localjsep);
		janus_moq_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "quic", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_moq_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			janus_moq_message_free(msg);
			/* We don't need the event anymore */
			json_decref(event);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving QUIC handler thread\n");
	return NULL;
}

/* imquic callbacks */
static void janus_moq_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	JANUS_LOG(LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
	janus_moq_session *session = (janus_moq_session *)user_data;
	janus_mutex_lock(&connections_mutex);
	janus_refcount_increase(&session->ref);
	session->connections = g_list_prepend(session->connections, conn);
	g_hash_table_insert(connections, conn, session);
	janus_mutex_unlock(&connections_mutex);
	if(session->moqpub || session->moqsub)
		imquic_moq_set_max_request_id(conn, 100);	/* FIXME */
}

static void janus_moq_connection_gone(imquic_connection *conn) {
	/* Connection has gone away */
	JANUS_LOG(LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		imquic_connection_unref(conn);
		if(session)
			janus_refcount_decrease(&session->ref);
		return;
	}
	session->connections = g_list_remove(session->connections, conn);
	g_hash_table_remove(connections, conn);
	janus_mutex_unlock(&connections_mutex);
	imquic_connection_unref(conn);
	janus_refcount_decrease(&session->ref);
}

/* MoQ Specific */
static void janus_moq_moq_ready(imquic_connection *conn) {
	/* MoQ negotiation was done */
	JANUS_LOG(LOG_INFO, "[%s] MoQ connection ready\n", imquic_get_connection_name(conn));
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	JANUS_LOG(LOG_INFO, "[%s] Advertising as a MoQ %s\n", imquic_get_connection_name(conn), session->moqpub ? "publisher" : "subscriber");
	if(session->moqpub) {
		/* Let's publish_namespace our namespace */
		JANUS_LOG(LOG_INFO, "[%s] Announcing namespace '%s'\n", imquic_get_connection_name(conn), session->track_namespace);
		imquic_moq_namespace tns = {
			.buffer = (uint8_t *)session->track_namespace,
			.length = strlen(session->track_namespace)
		};
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		imquic_moq_publish_namespace(conn, imquic_moq_get_next_request_id(conn), &tns, &params);
	} else {
		/* Let's subscribe to the provided namespace/name(s) */
		imquic_moq_namespace tns = {
			.buffer = (uint8_t *)session->track_namespace,
			.length = strlen(session->track_namespace),
			.next = NULL
		};
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.subscription_filter_set = TRUE;
		params.subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
		if(session->audio_track.track) {
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s/%s, using ID %"SCNu64"/%"SCNu64"\n", imquic_get_connection_name(conn),
				session->track_namespace, session->audio_track.track, session->audio_track.request_id, session->audio_track.track_alias);
			imquic_moq_name tn = {
				.buffer = (uint8_t *)session->audio_track.track,
				.length = strlen(session->audio_track.track)
			};
			imquic_moq_subscribe(conn, session->audio_track.request_id, session->audio_track.track_alias, &tns, &tn, &params);
		}
		if(session->video_track.track) {
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s/%s, using ID %"SCNu64"/%"SCNu64"\n", imquic_get_connection_name(conn),
				session->track_namespace, session->video_track.track, session->video_track.request_id, session->video_track.track_alias);
			imquic_moq_name tn = {
				.buffer = (uint8_t *)session->video_track.track,
				.length = strlen(session->video_track.track)
			};
			imquic_moq_subscribe(conn, session->video_track.request_id, session->video_track.track_alias, &tns, &tn, &params);
		}
	}
}

static void janus_moq_moq_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *params) {
	JANUS_LOG(LOG_INFO, "[%s] Publish Namespace '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
}

static void janus_moq_moq_publish_namespace_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
	JANUS_LOG(LOG_INFO, "[%s] Got an error publishing namespace via ID '%"SCNu64"': error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* TODO Stop here */
}

static void janus_moq_moq_incoming_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	/* Accept the subscription, if it's for something we know */
	char namespace[100], track[100];
	namespace[0] = '\0';
	if(tns->buffer && tns->length > 0)
		g_snprintf(namespace, sizeof(namespace), "%.*s", (int)tns->length, tns->buffer);
	track[0] = '\0';
	if(tn->buffer && tn->length > 0)
		g_snprintf(track, sizeof(track), "%.*s", (int)tn->length, tn->buffer);
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12) {
		/* Older versions of MoQ expect the track alias in the SUBSCRIBE */
		JANUS_LOG(LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
			imquic_get_connection_name(conn), namespace, track, request_id, track_alias);
	} else {
		JANUS_LOG(LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64")\n",
			imquic_get_connection_name(conn), namespace, track, request_id);
	}
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	if(session->track_namespace == NULL || strcasecmp(session->track_namespace, namespace)) {
		JANUS_LOG(LOG_WARN, "Unknown namespace '%s'\n", namespace);
		return;
	}
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order_ascending = TRUE;
	if(session->audio_track.track && !strcasecmp(session->audio_track.track, track)) {
		/* FIXME Subscription for the audio track */
		session->audio_track.request_id = request_id;
		session->audio_track.track_alias = imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12 ? track_alias : 0;
		imquic_moq_accept_subscribe(conn, request_id, session->audio_track.track_alias, &rparams);
		session->audio_track.active = TRUE;
	} else if(session->video_track.track && !strcasecmp(session->video_track.track, track)) {
		/* FIXME Subscription for the video track */
		session->video_track.request_id = request_id;
		session->video_track.track_alias = imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12 ? track_alias : 1;
		imquic_moq_accept_subscribe(conn, request_id, session->video_track.track_alias, &rparams);
		session->video_track.active = TRUE;
		gateway->send_pli(session->handle);
		session->pli_latest = janus_get_monotonic_time();
		session->pli_freq = 5;
	} else {
		JANUS_LOG(LOG_WARN, "Unknown track '%s'\n", track);
	}
}

static void janus_moq_moq_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	JANUS_LOG(LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), request_id);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	/* FIXME Stop sending objects */
	if(session->audio_track.track && session->audio_track.request_id == request_id) {
		/* Audio track */
		session->audio_track.active = FALSE;
		session->audio_track.request_id = 0;
		session->audio_track.track_alias = 0;
	} else if(session->video_track.track && session->video_track.request_id == request_id) {
		/* Video track */
		session->video_track.active = FALSE;
		session->video_track.request_id = 0;
		session->video_track.track_alias = 0;
		session->pli_freq = 0;
		session->pli_latest = 0;
	}
}

static void janus_moq_moq_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	JANUS_LOG(LOG_INFO, "[%s] Subscription %"SCNu64" accepted\n",
		imquic_get_connection_name(conn), request_id);
}

static void janus_moq_moq_subscribe_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias) {
	JANUS_LOG(LOG_INFO, "[%s] Got an error subscribing to ID %"SCNu64"/%"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, track_alias, error_code, reason);
	/* TODO Stop here */
}

static void janus_moq_moq_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason) {
	/* Our subscription is done */
	JANUS_LOG(LOG_INFO, "[%s] Subscription to ID %"SCNu64" is done: status %d (%s)\n",
		imquic_get_connection_name(conn), request_id, status_code, reason);
	/* TODO Stop here */
}

static void janus_moq_moq_incoming_object(imquic_connection *conn, imquic_moq_object *object) {
	/* We received an object */
	JANUS_LOG(LOG_HUGE, "[%s] Incoming object: reqid=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64", id=%"SCNu64", payload=%zu bytes, extensions=%zu bytes, delivery=%s, status=%s, eos=%d\n",
		imquic_get_connection_name(conn), object->request_id, object->track_alias,
		object->group_id, object->subgroup_id, object->object_id,
		object->payload_len, object->extensions_len, imquic_moq_delivery_str(object->delivery),
		imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	/* FIXME Assuming LOC from https://github.com/facebookexperimental/moq-encoder-player/
	 * which uses the MoQ-MI draft: https://datatracker.ietf.org/doc/html/draft-cenzano-moq-media-interop */
	uint64_t duration = 0, seq_id = 0;
	GList *extensions = NULL;
	struct imquic_moq_object_extension_data *loc_header = NULL, *loc_extradata = NULL;
	if(object->extensions != NULL && object->extensions_len > 0) {
		/* Parse the extensions to get access to the LOC info */
		JANUS_LOG(LOG_HUGE, "  -- Extensions (%zu bytes):\n", object->extensions_len);
		janus_moq_loc_media_type media_type = JANUS_MOQ_LOC_MEDIA_NONE;
		extensions = imquic_moq_parse_object_extensions(object->extensions, object->extensions_len);
		GList *temp = extensions;
		while(temp) {
			imquic_moq_object_extension *ext = (imquic_moq_object_extension *)temp->data;
			switch(ext->id) {
				case JANUS_MOQ_LOC_MEDIA_TYPE: {
					media_type = ext->value.number;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %s\n",
						janus_moq_loc_extension_str(ext->id),
						janus_moq_loc_media_type_str(media_type));
					break;
				}
				case JANUS_MOQ_LOC_H264_HEADER: {
					loc_header = &ext->value.data;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %zu bytes\n",
						janus_moq_loc_extension_str(ext->id),
						loc_header->length);
					break;
				}
				case JANUS_MOQ_LOC_H264_EXTRADATA: {
					loc_extradata = &ext->value.data;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %zu bytes\n",
						janus_moq_loc_extension_str(ext->id),
						loc_extradata->length);
					break;
				}
				case JANUS_MOQ_LOC_OPUS_HEADER: {
					loc_header = &ext->value.data;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %zu bytes\n",
						janus_moq_loc_extension_str(ext->id),
						loc_header->length);
					break;
				}
				case JANUS_MOQ_LOC_AAC_HEADER: {
					loc_header = &ext->value.data;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %zu bytes\n",
						janus_moq_loc_extension_str(ext->id),
						loc_header->length);
					break;
				}
				default: {
					JANUS_LOG(LOG_HUGE, "  -- -- Unknown extension '%"SCNu32"'\n", ext->id);
					break;
				}
			}
			temp = temp->next;
		}
		if(loc_header != NULL && media_type != JANUS_MOQ_LOC_MEDIA_NONE && media_type != JANUS_MOQ_LOC_MEDIA_TEXT) {
			JANUS_LOG(LOG_HUGE, "  -- LOC header (%zu bytes):\n", loc_header->length);
			uint8_t length = 0;
			size_t offset = 0;
			seq_id = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			JANUS_LOG(LOG_HUGE, "  -- -- Sequence ID: %"SCNu64"\n", seq_id);
			offset += length;
			uint64_t pts = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			JANUS_LOG(LOG_HUGE, "  -- -- PTS: %"SCNu64"\n", pts);
			offset += length;
			if(media_type == JANUS_MOQ_LOC_MEDIA_H264) {
				uint64_t dts = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				JANUS_LOG(LOG_HUGE, "  -- -- DTS: %"SCNu64"\n", dts);
				offset += length;
			}
			uint64_t timebase = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			JANUS_LOG(LOG_HUGE, "  -- -- Timebase: %"SCNu64"\n", timebase);
			offset += length;
			if(media_type == JANUS_MOQ_LOC_MEDIA_OPUS || media_type == JANUS_MOQ_LOC_MEDIA_AAC) {
				uint64_t sample_freq = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				JANUS_LOG(LOG_HUGE, "  -- -- Sample Frequency: %"SCNu64"\n", sample_freq);
				offset += length;
				uint64_t channels = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				JANUS_LOG(LOG_HUGE, "  -- -- Channels: %"SCNu64"\n", channels);
				offset += length;
			}
			duration = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			JANUS_LOG(LOG_HUGE, "  -- -- Duration: %"SCNu64"\n", duration);
			offset += length;
			uint64_t Wallclock = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			JANUS_LOG(LOG_HUGE, "  -- -- Wallclock: %"SCNu64"\n", Wallclock);
			offset += length;
		}
		if(loc_extradata != NULL && media_type == JANUS_MOQ_LOC_MEDIA_H264) {
			JANUS_LOG(LOG_HUGE, "  -- LOC extradata (%zu bytes):\n", loc_extradata->length);
			for(size_t i=0; i<loc_extradata->length; ++i)
				JANUS_LOG(LOG_HUGE, "%02x", loc_extradata->buffer[i]);
			JANUS_LOG(LOG_HUGE, "\n");
		}
		JANUS_LOG(LOG_HUGE, "  -- Payload: %zu bytes\n", object->payload_len);
	}
	if(duration == 0) {
		g_list_free_full(extensions, (GDestroyNotify)imquic_moq_object_extension_free);
		return;
	}
	/* Convert LOC to RTP */
	size_t hsize = 12;
	if(session->audio_track.track && object->track_alias == session->audio_track.track_alias) {
		/* This is audio */
		int pt = GPOINTER_TO_INT(g_hash_table_lookup(session->ptypes, &object->track_alias));
		if(pt == -1) {
			JANUS_LOG(LOG_HUGE, "[%s]  -- Can't find payload type associated to track alias %"SCNu64"\n",
				imquic_get_connection_name(conn), object->track_alias);
			g_list_free_full(extensions, (GDestroyNotify)imquic_moq_object_extension_free);
			return;
		}
		uint32_t ts_diff = 48000/(1000000/duration);
		char buffer[1500];
		size_t length = hsize + object->payload_len;
		/* Craft the RTP packet */
		janus_rtp_header *rtp = (janus_rtp_header *)buffer;
		rtp->version = 2;
		rtp->markerbit = (session->audio_track.seq == 0);	/* Should be 1 for the first packet */
		rtp->type = pt;
		rtp->seq_number = htons(seq_id);
		rtp->timestamp = htonl(session->audio_track.seq == 0 ? 0 : (session->audio_track.timestamp + ts_diff));
		rtp->ssrc = htonl(session->audio_track.ssrc);
		session->audio_track.seq = seq_id;
		session->audio_track.timestamp = ntohl(rtp->timestamp);
		memcpy(&buffer[hsize], object->payload, object->payload_len);
		/* Send the RTP packet */
		janus_plugin_rtp pkt = { .mindex = 0, .video = FALSE, .buffer = buffer, .length = length };
		janus_plugin_rtp_extensions_reset(&pkt.extensions);
		gateway->relay_rtp(session->handle, &pkt);
	} else if(session->video_track.track && object->track_alias == session->video_track.track_alias) {
		/* This is video */
		int pt = GPOINTER_TO_INT(g_hash_table_lookup(session->ptypes, &object->track_alias));
		if(pt == -1) {
			JANUS_LOG(LOG_HUGE, "[%s]  -- Can't find payload type associated to track_alias %"SCNu64"\n",
				imquic_get_connection_name(conn), object->track_alias);
			g_list_free_full(extensions, (GDestroyNotify)imquic_moq_object_extension_free);
			return;
		}
		uint32_t ts_diff = 90000/(1000000/duration);
		char buffer[1500];
		size_t length = 0;
		/* Craft the base RTP packet */
		janus_rtp_header *rtp = (janus_rtp_header *)buffer;
		rtp->version = 2;
		rtp->markerbit = 0;	/* Should be 1 for the last packet of a frame */
		rtp->type = pt;
		rtp->timestamp = htonl(session->video_track.seq == 0 ? 0 : (session->video_track.timestamp + ts_diff));
		rtp->ssrc = htonl(session->video_track.ssrc);
		/* Create all the RTP packets we need */
		uint16_t seq = session->video_track.seq;
		uint8_t *data = object->payload, *start = data, *end = object->payload + object->payload_len, *tmp = start;
		if(loc_extradata && loc_extradata->length > 0) {
			/* We have AVCC metadata, extract the SPS/PPS and send that first */
			uint8_t *avcc_data = loc_extradata->buffer;
			size_t avcc_len = loc_extradata->length;
			JANUS_LOG(LOG_HUGE, "AVCC data is %zu bytes\n  -- ", avcc_len);
			for(size_t i=0; i<avcc_len; ++i)
				JANUS_LOG(LOG_HUGE, "%02x", avcc_data[i]);
			JANUS_LOG(LOG_HUGE, "\n");
			/* Read extradata */
			JANUS_LOG(LOG_HUGE, "Extradata:\n");
			JANUS_LOG(LOG_HUGE, "  -- Version:       %"SCNu8"\n", avcc_data[0]);
			JANUS_LOG(LOG_HUGE, "  -- Profile:       %"SCNu8"\n", avcc_data[1]);
			JANUS_LOG(LOG_HUGE, "  -- Compatibility: %"SCNu8"\n", avcc_data[2]);
			JANUS_LOG(LOG_HUGE, "  -- Level:         %"SCNu8"\n", avcc_data[3]);
			JANUS_LOG(LOG_HUGE, "  -- NAL length -1: %"SCNu8"\n", avcc_data[4] & 0x03);
			JANUS_LOG(LOG_HUGE, "  -- SPS number:    %"SCNu8"\n", avcc_data[5] & 0x1F);
			/* Add NAL */
			length = hsize;
			buffer[length] = 0x18;
			length++;
			/* Extract SPS */
			uint16_t sps_len = 0;
			memcpy(&sps_len, &avcc_data[6], 2);
			uint8_t *sps = &avcc_data[8];
			JANUS_LOG(LOG_HUGE, "SPS len: %"SCNu16"\n", ntohs(sps_len));
			/* Add SPS to the RTP packet */
			memcpy(&buffer[length], &sps_len, 2);
			length += 2;
			sps_len = ntohs(sps_len);
			memcpy(&buffer[length], sps, sps_len);
			length += sps_len;
			/* Extract PPS */
			uint8_t *pps = sps + sps_len;
			size_t pps_len = avcc_len - (pps - avcc_data);
			JANUS_LOG(LOG_HUGE, "PPS(s) len: %zu\n", pps_len);
			JANUS_LOG(LOG_HUGE, "  -- Num of PPS: %"SCNu8"\n", pps[0]);
			size_t pps_index = 1;
			for(size_t i=0; i<pps[0]; i++) {
				size_t pps_i_len = 0;
				memcpy(&pps_i_len, &pps[pps_index], 2);
				pps_index += 2;
				JANUS_LOG(LOG_HUGE, "  -- -- PPS[%zu] len %"SCNu16"/%zu\n", i, ntohs(pps_i_len), pps_len - pps_index);
				/* Add PPS to the RTP packet */
				memcpy(&buffer[length], &pps_i_len, 2);
				length += 2;
				pps_i_len = ntohs(pps_i_len);
				memcpy(&buffer[length], &pps[pps_index], pps_i_len);
				length += pps_i_len;
				/* Go to the next PPS */
				pps_index += pps_i_len;
			}
			/* Send the packet */
			seq++;
			rtp->seq_number = htons(seq);
			janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
			janus_plugin_rtp_extensions_reset(&pkt.extensions);
			gateway->relay_rtp(session->handle, &pkt);
			length = 0;
		}
		/* Switch from AVCC to Annex-B */
		size_t avcc_offset = 0, nal_size = 0;
		while(object->payload_len >= avcc_offset + 4) {
			memcpy(&nal_size, object->payload + avcc_offset, 4);
			nal_size = ntohl(nal_size);
			if(nal_size > 0) {
				*(object->payload + avcc_offset) = 0x00;
				*(object->payload + avcc_offset + 1) = 0x00;
				*(object->payload + avcc_offset + 2) = 0x00;
				*(object->payload + avcc_offset + 3) = 0x01;
			}
			avcc_offset += 4 + nal_size;
		}
		/* Check if we need to fragment the frame in multiple RTP packets */
		while(TRUE) {
			if((end-tmp) < 3)
				break;
			if(tmp[0] == 0 && tmp[1] == 0 && tmp[2] == 1) {
				/* Found a start code (00 00 01) */
				JANUS_LOG(LOG_HUGE, "[%s]   -- Found start code (offset %ld, size %ld)\n",
					imquic_get_connection_name(conn), tmp-data, tmp-start);
				if(tmp-start > 1) {
					if(tmp-start > mtu)
						break;
					/* Create a new RTP packet */
					seq++;
					rtp->seq_number = htons(seq);
					memcpy(&buffer[hsize], start, tmp-start);
					/* Send the packet */
					length = tmp-start+hsize;
					janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
					janus_plugin_rtp_extensions_reset(&pkt.extensions);
					gateway->relay_rtp(session->handle, &pkt);
				}
				/* Go on */
				tmp += 3;
				start = tmp;
				continue;
			} else {
				tmp++;
			}
		}
		/* Create the last RTP packet(s?) */
		int total = end-start;
		JANUS_LOG(LOG_HUGE, "[%s] Evaluating remaining data: %d bytes\n",
			imquic_get_connection_name(conn), total);
		if(total < mtu) {
			/* The NAL fits in one RTP packet */
			JANUS_LOG(LOG_HUGE, "[%s]   -- NAL fits (offset %ld, size %ld)\n",
				imquic_get_connection_name(conn), start-data, tmp-start);
			seq++;
			rtp->seq_number = htons(seq);
			rtp->markerbit = 1;
			memcpy(&buffer[hsize], start, total);
			/* Send the packet */
			length = total+hsize;
			janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
			janus_plugin_rtp_extensions_reset(&pkt.extensions);
			gateway->relay_rtp(session->handle, &pkt);
		} else {
			/* We need to fragment the NAL (FU-A), start with the
			 * FU indicator, common to all fragmented packets */
			uint8_t type = *start & 0x1F;
			uint8_t nri = *start & 0x60;
			uint8_t indicator = nri | 28;
			/* The first fragmented packet needs the S bit set in the FU Header */
			uint8_t header = 0x80 + type;
			JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %d)\n",
				imquic_get_connection_name(conn), indicator, type, header, start-data, mtu);
			seq++;
			rtp->seq_number = htons(seq);
			rtp->markerbit = 0;
			memcpy(&buffer[hsize+1], start, mtu);
			memset(&buffer[hsize], indicator, 1);
			memset(&buffer[hsize+1], header, 1);
			/* Send the packet */
			length = mtu+1+hsize;
			janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
			janus_plugin_rtp_extensions_reset(&pkt.extensions);
			gateway->relay_rtp(session->handle, &pkt);
			/* Go on */
			start += mtu;
			total -= mtu;
			while(TRUE) {
				if(total < mtu) {
					/* Last packet, set the E bit */
					header = 0x40 + type;
					JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %d, last)\n",
						imquic_get_connection_name(conn), indicator, type, header, start-data, total);
					seq++;
					rtp->seq_number = htons(seq);
					rtp->markerbit = 1;
					memset(&buffer[hsize], indicator, 1);
					memset(&buffer[hsize+1], header, 1);
					memcpy(&buffer[hsize+2], start, total);
					/* Send the packet */
					length = total+2+hsize;
					janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
					janus_plugin_rtp_extensions_reset(&pkt.extensions);
					gateway->relay_rtp(session->handle, &pkt);
					break;
				} else {
					header = 0x00 + type;	/* Unset the S and E bits */
					JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %d)\n",
						imquic_get_connection_name(conn), indicator, type, header, start-data, mtu);
					seq++;
					rtp->seq_number = htons(seq);
					rtp->markerbit = 0;
					memset(&buffer[hsize], indicator, 1);
					memset(&buffer[hsize+1], header, 1);
					memcpy(&buffer[hsize+2], start, mtu);
					/* Send the packet */
					length = mtu+2+hsize;
					janus_plugin_rtp pkt = { .mindex = 1, .video = TRUE, .buffer = buffer, .length = length };
					janus_plugin_rtp_extensions_reset(&pkt.extensions);
					gateway->relay_rtp(session->handle, &pkt);
					/* Move on */
					start += mtu;
					total -= mtu;
				}
			}
		}
		session->video_track.seq = seq;
		session->video_track.timestamp = ntohl(rtp->timestamp);
	}
	g_list_free_full(extensions, (GDestroyNotify)imquic_moq_object_extension_free);
}

/* Helpers to decode Exp-Golomb */
static uint32_t janus_moq_h264_eg_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}

static uint32_t janus_moq_h264_eg_decode(uint8_t *base, uint32_t *offset) {
	uint32_t zeros = 0;
	while(janus_moq_h264_eg_getbit(base, (*offset)++) == 0)
		zeros++;
	uint32_t res = 1 << zeros;
	int32_t i = 0;
	for(i=zeros-1; i>=0; i--) {
		res |= janus_moq_h264_eg_getbit(base, (*offset)++) << i;
	}
	return res-1;
}

/* Helper to parse a SPS (only to get the video resolution) */
static size_t janus_moq_h264_parse_sps(uint8_t *avcc_data, char *buffer, int len, int *width, int *height) {
	/* We use this function to return a metadata JSON object for AVC1 */
	avcc_data[0] = 1;
	/* Let's check if it's the right profile, first */
	int index = 3;
	int profile_idc = *(buffer+index);
	if(profile_idc != 66) {
		JANUS_LOG(LOG_HUGE, "Profile is not baseline (%d != 66)\n", profile_idc);
	}
	avcc_data[1] = 66;	/* FIXME */
	avcc_data[2] = 3;	/* FIXME */
	avcc_data[3] = 31;	/* FIXME */
	avcc_data[4] = 3;
	avcc_data[5] = 1;
	size_t avcc_size = 6;
	/* Then let's skip 2 bytes and evaluate/skip the rest */
	index += 3;
	uint32_t offset = 0;
	uint8_t *base = (uint8_t *)(buffer+index);
	/* Skip seq_parameter_set_id */
	janus_moq_h264_eg_decode(base, &offset);
	if(profile_idc >= 100) {
		/* Skip chroma_format_idc */
		janus_moq_h264_eg_decode(base, &offset);
		/* Skip bit_depth_luma_minus8 */
		janus_moq_h264_eg_decode(base, &offset);
		/* Skip bit_depth_chroma_minus8 */
		janus_moq_h264_eg_decode(base, &offset);
		/* Skip qpprime_y_zero_transform_bypass_flag */
		janus_moq_h264_eg_getbit(base, offset++);
		/* Skip seq_scaling_matrix_present_flag */
		janus_moq_h264_eg_getbit(base, offset++);
	}
	/* Skip log2_max_frame_num_minus4 */
	janus_moq_h264_eg_decode(base, &offset);
	/* Evaluate pic_order_cnt_type */
	int pic_order_cnt_type = janus_moq_h264_eg_decode(base, &offset);
	if(pic_order_cnt_type == 0) {
		/* Skip log2_max_pic_order_cnt_lsb_minus4 */
		janus_moq_h264_eg_decode(base, &offset);
	} else if(pic_order_cnt_type == 1) {
		/* Skip delta_pic_order_always_zero_flag, offset_for_non_ref_pic,
		 * offset_for_top_to_bottom_field and num_ref_frames_in_pic_order_cnt_cycle */
		janus_moq_h264_eg_getbit(base, offset++);
		janus_moq_h264_eg_decode(base, &offset);
		janus_moq_h264_eg_decode(base, &offset);
		int num_ref_frames_in_pic_order_cnt_cycle = janus_moq_h264_eg_decode(base, &offset);
		int i = 0;
		for(i=0; i<num_ref_frames_in_pic_order_cnt_cycle; i++) {
			janus_moq_h264_eg_decode(base, &offset);
		}
	}
	/* Skip max_num_ref_frames and gaps_in_frame_num_value_allowed_flag */
	janus_moq_h264_eg_decode(base, &offset);
	janus_moq_h264_eg_getbit(base, offset++);
	/* We need the following three values */
	int pic_width_in_mbs_minus1 = janus_moq_h264_eg_decode(base, &offset);
	int pic_height_in_map_units_minus1 = janus_moq_h264_eg_decode(base, &offset);
	int frame_mbs_only_flag = janus_moq_h264_eg_getbit(base, offset++);
	if(!frame_mbs_only_flag) {
		/* Skip mb_adaptive_frame_field_flag */
		janus_moq_h264_eg_getbit(base, offset++);
	}
	/* Skip direct_8x8_inference_flag */
	janus_moq_h264_eg_getbit(base, offset++);
	/* We need the following value to evaluate offsets, if any */
	int frame_cropping_flag = janus_moq_h264_eg_getbit(base, offset++);
	int frame_crop_left_offset = 0, frame_crop_right_offset = 0,
		frame_crop_top_offset = 0, frame_crop_bottom_offset = 0;
	if(frame_cropping_flag) {
		frame_crop_left_offset = janus_moq_h264_eg_decode(base, &offset);
		frame_crop_right_offset = janus_moq_h264_eg_decode(base, &offset);
		frame_crop_top_offset = janus_moq_h264_eg_decode(base, &offset);
		frame_crop_bottom_offset = janus_moq_h264_eg_decode(base, &offset);
	}
	/* Skip vui_parameters_present_flag */
	janus_moq_h264_eg_getbit(base, offset++);

	/* We skipped what we didn't care about and got what we wanted, compute width/height */
	if(width)
		*width = ((pic_width_in_mbs_minus1 +1)*16) - frame_crop_left_offset*2 - frame_crop_right_offset*2;
	if(height)
		*height = ((2 - frame_mbs_only_flag)* (pic_height_in_map_units_minus1 +1) * 16) - (frame_crop_top_offset * 2) - (frame_crop_bottom_offset * 2);

	/* Append SPS to the AVCC buffer */
	uint16_t sps_size = 0;
	memcpy(&sps_size, buffer, 2);
	sps_size = ntohs(sps_size);
	JANUS_LOG(LOG_HUGE, "SPS size: %"SCNu16"\n", sps_size);
	memcpy(&avcc_data[avcc_size], buffer, 2);
	avcc_size += 2;
	memcpy(&avcc_data[avcc_size], buffer + 2, sps_size);
	avcc_size += sps_size;
	/* Append PPS to the AVCC buffer */
	avcc_data[avcc_size] = 1;
	avcc_size++;
	uint16_t pps_size = 0;
	memcpy(&pps_size, buffer + 2 + sps_size, 2);
	pps_size = ntohs(pps_size);
	JANUS_LOG(LOG_HUGE, "PPS size: %"SCNu16"\n", pps_size);
	memcpy(&avcc_data[avcc_size], buffer + 2 + sps_size, 2);
	avcc_size += 2;
	memcpy(&avcc_data[avcc_size], buffer + 2 + sps_size + 2, pps_size);
	avcc_size += pps_size;

	/* Done */
	return avcc_size;
}
