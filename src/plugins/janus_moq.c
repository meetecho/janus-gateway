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
	{"use_catalog", JANUS_JSON_BOOL, 0},
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
	gboolean moqsub, moqpub, use_catalog;
	imquic_moq_catalog *catalog;
	char *track_namespace, *auth_info;
	janus_moq_moq_rtp catalog_track, audio_track, video_track;
	GHashTable *media, *ptypes;
	int audio_pt, video_pt;
	imquic_connection *conn;
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
	imquic_moq_catalog_destroy(session->catalog);
	g_free(session->track_namespace);
	g_free(session->catalog_track.track);
	g_free(session->catalog_track.buffer);
	g_free(session->audio_track.track);
	g_free(session->audio_track.buffer);
	g_free(session->video_track.track);
	g_free(session->video_track.buffer);
	g_free(session->auth_info);
	g_hash_table_unref(session->media);
	g_hash_table_unref(session->ptypes);
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
static void janus_moq_connection_gone(imquic_connection *conn, uint64_t error_code, const char *reason);
/* MoQ specific */
static void janus_moq_moq_ready(imquic_connection *conn);
static void janus_moq_moq_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *params);
static void janus_moq_moq_publish_namespace_error(imquic_connection *conn, uint64_t request_id,
	imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect);
static void janus_moq_moq_incoming_subscribe(imquic_connection *conn, uint64_t request_id,
	imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_request_parameters *parameters);
static void janus_moq_moq_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id);
static void janus_moq_moq_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
	imquic_moq_request_parameters *parameters, GList *track_extensions);
static void janus_moq_moq_subscribe_error(imquic_connection *conn, uint64_t request_id,
	imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect);
static void janus_moq_moq_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason);
static void janus_moq_moq_incoming_object(imquic_connection *conn, imquic_moq_object *object);

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
	session->audio_pt = -1;
	session->video_pt = -1;
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
	/* If this related to a subscriber, actually subscribe to the audio/video tracks now */
	if(session->moqsub && session->conn) {
		imquic_moq_namespace tns = {
			.buffer = (uint8_t *)session->track_namespace,
			.length = strlen(session->track_namespace),
			.next = NULL
		};
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.subscription_filter_set = TRUE;
		params.subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
		/* Audio track, if any */
		if(session->audio_track.track) {
			session->audio_track.request_id = imquic_moq_get_next_request_id(session->conn);
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s/%s, using ID %"SCNu64"\n",
				imquic_get_connection_name(session->conn),
				session->track_namespace, session->audio_track.track, session->audio_track.request_id);
			imquic_moq_track tn = {
				.buffer = (uint8_t *)session->audio_track.track,
				.length = strlen(session->audio_track.track)
			};
			imquic_moq_subscribe(session->conn, session->audio_track.request_id, &tns, &tn, &params);
		}
		/* Video track, if any */
		if(session->video_track.track) {
			session->video_track.request_id = imquic_moq_get_next_request_id(session->conn);
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s/%s, using ID %"SCNu64"\n",
				imquic_get_connection_name(session->conn),
				session->track_namespace, session->video_track.track, session->video_track.request_id);
			imquic_moq_track tn = {
				.buffer = (uint8_t *)session->video_track.track,
				.length = strlen(session->video_track.track)
			};
			imquic_moq_subscribe(session->conn, session->video_track.request_id, &tns, &tn, &params);
		}
	}
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
		if(!session->moqpub || session->conn == NULL || packet->buffer == NULL || packet->length == 0)
			return;
		int plen = 0;
		char *payload = janus_rtp_payload((char *)packet->buffer, packet->length, &plen);
		if(payload == NULL || plen == 0)
			return;
		/* Send as a MoQ object */
		if(!packet->video && session->audio_track.track && session->audio_track.active) {
			/* Each audio frame is self contained, write the LOC info first as properties */
			GList *props = NULL;
			imquic_moq_property timescale = { 0 };
			timescale.id = IMQUIC_MOQ_LOC_TIMESCALE;
			timescale.value.number = G_USEC_PER_SEC;
			props = g_list_append(props, &timescale);
			imquic_moq_property timestamp = { 0 };
			timestamp.id = IMQUIC_MOQ_LOC_TIMESTAMP;
			timestamp.value.number = session->audio_track.timestamp;
			props = g_list_append(props, &timestamp);
			session->audio_track.timestamp += 20000;	/* FIXME */
			/* Prepare a MoQ object and send it */
			imquic_moq_object object = {
				.request_id = session->audio_track.request_id,
				.track_alias = session->audio_track.track_alias,
				.group_id = session->audio_track.group_id++,
				.subgroup_id = 0,	/* FIXME */
				.object_id = session->audio_track.object_id,
				.payload = (uint8_t *)payload,
				.payload_len = plen,
				.properties = props,
				.delivery = IMQUIC_MOQ_USE_DATAGRAM,
				.end_of_stream = TRUE
			};
			imquic_moq_send_object(session->conn, &object);
			g_list_free(props);
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
					imquic_get_connection_name(session->conn), session->video_track.offset);
				/* Write the LOC info first as properties */
				GList *props = NULL;
				imquic_moq_property timescale = { 0 };
				timescale.id = IMQUIC_MOQ_LOC_TIMESCALE;
				timescale.value.number = G_USEC_PER_SEC;
				props = g_list_append(props, &timescale);
				int64_t now = g_get_monotonic_time();
				uint64_t pts = now - session->video_track.timestamp_start;
				imquic_moq_property timestamp = { 0 };
				timestamp.id = IMQUIC_MOQ_LOC_TIMESTAMP;
				timestamp.value.number = pts;
				props = g_list_append(props, &timestamp);
				imquic_moq_property extradata = { 0 };
				if(session->video_track.extradata_len > 0) {
					extradata.id = IMQUIC_MOQ_LOC_VIDEO_CONFIG;
					extradata.value.data.buffer = session->video_track.extradata;
					extradata.value.data.length = session->video_track.extradata_len;
					props = g_list_append(props, &extradata);
					session->video_track.extradata_len = 0;
				}
				/* Prepare a MoQ object and send it */
				imquic_moq_object object = {
					.request_id = session->video_track.request_id,
					.track_alias = session->video_track.track_alias,
					.group_id = session->video_track.group_id,
					.subgroup_id = 0,	/* FIXME */
					.object_id = session->video_track.object_id,
					.payload = session->video_track.buffer,
					.payload_len = session->video_track.offset,
					.properties = props,
					.delivery = IMQUIC_MOQ_USE_SUBGROUP,
					.end_of_stream = TRUE
				};
				session->video_track.object_id++;
				imquic_moq_send_object(session->conn, &object);
				g_list_free(props);
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
			JANUS_LOG(LOG_HUGE, "[%s] Depacketizing payload (%d bytes)\n",
				imquic_get_connection_name(session->conn), plen);
			uint8_t fragment = *payload & 0x1F;
			uint8_t nal = *(payload+1) & 0x1F;
			uint8_t start_bit = *(payload+1) & 0x80;
			int len = plen, jump = 0;
			if(fragment == 7) {
				/* SPS, see if we can extract the width/height as well */
				//~ session->video_track.metadata = janus_moq_h264_parse_sps(payload, plen, &session->video_track.width, &session->video_track.height);
				//~ JANUS_LOG(LOG_INFO, "[%s] Video has resolution %dx%d (%p)\n", imquic_get_connection_name(session->conn),
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
						JANUS_LOG(LOG_HUGE, "[%s]   -- Video has resolution %dx%d (%zu bytes of extradata)\n",
							imquic_get_connection_name(session->conn),
							session->video_track.width, session->video_track.height, session->video_track.extradata_len);
					}
					temp += psize;
					tot -= psize;
				}
				len = tot;
			}
			if(fragment == 28 || fragment == 29) {
				JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d, NAL=%d, Start=%d (len=%d, frame_len=%zu)\n",
					imquic_get_connection_name(session->conn), fragment, nal, start_bit, len, session->video_track.offset);
			} else {
				JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d (len=%d, frame_len=%zu)\n",
					imquic_get_connection_name(session->conn), fragment, len, session->video_track.offset);
			}
			if(fragment == 5 ||
					((fragment == 28 || fragment == 29) && nal == 5 && start_bit == 128)) {
				JANUS_LOG(LOG_HUGE, "[%s]   -- Key frame (seq=%"SCNu16", ts=%"SCNu32", fragment=%d)\n",
					imquic_get_connection_name(session->conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), fragment);
				session->video_track.keyframe = TRUE;
				session->video_track.group_id++;
				session->video_track.object_id = 0;
			}
			/* Frame manipulation */
			if((fragment > 0) && (fragment < 24)) {
				/* Add a start code */
				JANUS_LOG(LOG_HUGE, "[%s]   -- -- Adding a start code (fragment=%d)\n",
					imquic_get_connection_name(session->conn), fragment);
				uint8_t *temp = session->video_track.buffer + session->video_track.offset;
				memset(temp, 0x00, 1);
				memset(temp + 1, 0x00, 1);
				memset(temp + 2, 0x00, 1);
				memset(temp + 3, 0x01, 1);
				if(session->video_track.nal_added) {
					uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
					JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
						imquic_get_connection_name(session->conn), nal_size);
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
						imquic_get_connection_name(session->conn), fragment);
					uint8_t *temp = session->video_track.buffer + session->video_track.offset;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x00, 1);
					memset(temp + 3, 0x01, 1);
					if(session->video_track.nal_added) {
						uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
						JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
							imquic_get_connection_name(session->conn), nal_size);
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
						imquic_get_connection_name(session->conn), fragment);
					uint8_t *temp = session->video_track.buffer + session->video_track.offset;
					memset(temp, 0x00, 1);
					memset(temp + 1, 0x00, 1);
					memset(temp + 2, 0x00, 1);
					memset(temp + 3, 0x01, 1);
					memset(temp + 4, (indicator & 0xE0) | (header & 0x1F), 1);
					if(session->video_track.nal_added) {
						uint32_t nal_size = session->video_track.offset - session->video_track.nal_offset - 4;
						JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
							imquic_get_connection_name(session->conn), nal_size);
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
						imquic_get_connection_name(session->conn));
				} else {
					memcpy(session->video_track.buffer + session->video_track.offset, payload+jump, len);
					session->video_track.offset += len;
				}
			}
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
	g_hash_table_remove_all(session->media);
	g_hash_table_remove_all(session->ptypes);
	session->audio_pt = -1;
	session->video_pt = -1;
	/* If there's a QUIC server running, get rid of it */
	if(session->quic_endpoint != NULL)
		imquic_shutdown_endpoint(session->quic_endpoint);
	session->quic_endpoint = NULL;
	imquic_moq_catalog_destroy(session->catalog);
	g_free(session->track_namespace);
	session->track_namespace = NULL;
	g_free(session->auth_info);
	session->auth_info = NULL;
	session->catalog = NULL;
	g_free(session->catalog_track.track);
	session->catalog_track.track = NULL;
	memset(&session->catalog_track, 0, sizeof(session->catalog_track));
	g_free(session->audio_track.track);
	session->audio_track.track = NULL;
	memset(&session->audio_track, 0, sizeof(session->audio_track));
	g_free(session->video_track.track);
	session->video_track.track = NULL;
	memset(&session->video_track, 0, sizeof(session->video_track));
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
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
			json_t *uc = json_object_get(root, "use_catalog");
			gboolean use_catalog = uc ? json_is_true(uc) : TRUE;
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
			gboolean moqpub = !strcasecmp(role, "publisher");
			gboolean moqsub = !strcasecmp(role, "subscriber");
			if(!moqpub && !moqsub) {
				/* Invalid role */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Invalid MoQ role\n");
				error_code = JANUS_MOQ_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid MoQ role");
				goto error;
			}
			const char *msg_sdp_type = NULL, *msg_sdp = NULL;
			if(moqpub) {
				/* Any SDP to handle? If not, something's wrong */
				msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
				msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
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
			}
			if(namespace == NULL) {
				/* Missing namespace */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Missing MoQ namespace\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing MoQ namespace");
				goto error;
			}
			if(moqpub && audio_track == NULL && video_track == NULL) {
				/* Missing audio or video track */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "At least one track (audio or video) must be provided for publishers\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "At least one track (audio or video) must be provided for publishers");
				goto error;
			} else if(moqsub && !use_catalog && audio_track == NULL && video_track == NULL) {
				/* Missing audio or video track */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "At least one track (audio or video) must be provided for subscribers not using the catalog\n");
				error_code = JANUS_MOQ_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "At least one track (audio or video) must be provided for subscribers not using the catalog");
				goto error;
			}
			char name[50];
			/* Create the imquic endpoint (client) */
			imquic_endpoint *quic_endpoint = NULL;
			session->moqpub = moqpub;
			session->moqsub = moqsub;
			session->use_catalog = moqsub && use_catalog;
			session->track_namespace = g_strdup(namespace);
			/* Catalog track */
			memset(&session->catalog_track, 0, sizeof(session->catalog_track));
			session->catalog_track.track = g_strdup("catalog");
			/* Audio track, if any */
			memset(&session->audio_track, 0, sizeof(session->audio_track));
			if(audio_track != NULL && (moqpub || (moqsub && !use_catalog))) {
				session->audio_track.track = g_strdup(audio_track);
				session->audio_track.ssrc = janus_random_uint32();
			}
			/* Video track, if any */
			memset(&session->video_track, 0, sizeof(session->video_track));
			if(video_track != NULL && (moqpub || (moqsub && !use_catalog))) {
				session->video_track.track = g_strdup(video_track);
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
			/* If this is a MoQ publisher, we parse the SDP in order to provide an
			 * answer back: for subscribers, we'll generate an offer ourselves later */
			if(moqpub) {
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
						if(m->type == JANUS_SDP_AUDIO)
							session->audio_pt = pt;
						else
							session->video_pt = pt;
					}
					temp = temp->next;
				}
				janus_sdp_destroy(offer);
				char *sdp = janus_sdp_write(answer);
				janus_sdp_destroy(answer);
				JANUS_LOG(LOG_VERB, "Prepared SDP answer\n%s", sdp);
				g_atomic_int_set(&session->hangingup, 0);
				/* Prepare a MoQ catalog too, if we're publishing */
				if(session->moqpub && session->catalog == NULL) {
					session->catalog = imquic_moq_catalog_create(1);
					if(session->audio_track.track != NULL) {
						/* FIXME Add the audio track to the catalog */
						imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(session->track_namespace,
							session->audio_track.track, "loc", TRUE);
						track->role = g_strdup("audio");
						track->render_group = 1;
						track->target_latency = 200;
						track->codec = g_strdup("opus");
						track->samplerate = 48000;
						imquic_moq_catalog_add_track(session->catalog, track);
					}
					if(session->video_track.track != NULL) {
						/* FIXME Add the video track to the catalog */
						imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(session->track_namespace,
							session->video_track.track, "loc", TRUE);
						track->role = g_strdup("video");
						track->render_group = 1;
						track->target_latency = 200;
						track->codec = g_strdup("avc1.42001F");
						imquic_moq_catalog_add_track(session->catalog, track);
					}
				}
				localjsep = json_pack("{ssss}", "type", "answer", "sdp", sdp);
				g_free(sdp);
			}
			/* Send an answer back to the browser */
			result = json_object();
			json_object_set_new(result, "event", json_string("bridging"));
		} else if(!strcasecmp(request_text, "start")) {
			if(!session->moqsub) {
				/* This command can only be sent by subscriberss */
				janus_mutex_unlock(&session->mutex);
				JANUS_LOG(LOG_ERR, "Invalid MoQ role request\n");
				error_code = JANUS_MOQ_ERROR_INVALID_REQUEST;
				g_snprintf(error_cause, 512, "Invalid MoQ role request");
				goto error;
			}
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(msg_sdp) {
				if(!msg_sdp_type || strcasecmp(msg_sdp_type, "answer")) {
					JANUS_LOG(LOG_ERR, "Not an SDP answer\n");
					error_code = JANUS_MOQ_ERROR_INVALID_SDP;
					g_snprintf(error_cause, 512, "Missing or invalid SDP type");
					goto error;
				}
				char error_str[512];
				janus_sdp *answer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
				GList *temp = answer->m_lines;
				while(temp) {
					janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
					if(m->direction != JANUS_SDP_INACTIVE) {
						int pt = m->ptypes ? GPOINTER_TO_INT(m->ptypes->data) : -1;
						if(m->type == JANUS_SDP_AUDIO)
							session->audio_pt = pt;
						else
							session->video_pt = pt;
					}
					temp = temp->next;
				}
				janus_sdp_destroy(answer);
			}
			/* Send an answer back to the browser */
			result = json_object();
			json_object_set_new(result, "event", json_string("starting"));
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
		json_object_set_new(event, "moq", json_string("event"));
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
			json_object_set_new(event, "moq", json_string("event"));
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
	session->conn = conn;
	g_hash_table_insert(connections, conn, session);
	janus_mutex_unlock(&connections_mutex);
	if(session->moqpub || session->moqsub)
		imquic_moq_set_max_request_id(conn, 100);	/* FIXME */
}

static void janus_moq_connection_gone(imquic_connection *conn, uint64_t error_code, const char *reason) {
	/* Connection has gone away */
	JANUS_LOG(LOG_INFO, "[%s] Connection gone: %"SCNu64" (%s)\n",
		imquic_get_connection_name(conn), error_code, reason);
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		imquic_connection_unref(conn);
		if(session)
			janus_refcount_decrease(&session->ref);
		return;
	}
	session->conn = NULL;
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
	JANUS_LOG(LOG_INFO, "[%s] Connected as a MoQ %s\n", imquic_get_connection_name(conn), session->moqpub ? "publisher" : "subscriber");
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
		/* Let's subscribe to the catalog track: we may want to only subscribe
		 * to the audio/video track when we've obtained a catalog back */
		imquic_moq_namespace tns = {
			.buffer = (uint8_t *)session->track_namespace,
			.length = strlen(session->track_namespace),
			.next = NULL
		};
		/* Catalog track */
		session->catalog_track.request_id = imquic_moq_get_next_request_id(conn);
		JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s/%s, using ID %"SCNu64"\n", imquic_get_connection_name(conn),
			session->track_namespace, session->catalog_track.track, session->catalog_track.request_id);
		imquic_moq_track ctn = {
			.buffer = (uint8_t *)session->catalog_track.track,
			.length = strlen(session->catalog_track.track)
		};
		imquic_moq_subscribe(conn, session->catalog_track.request_id, &tns, &ctn, NULL);
		if(session->use_catalog) {
			/* We'll wait for the catalog to know what tracks to subscribe to */
			JANUS_LOG(LOG_INFO, "[%s]   -- Waiting for catalog\n", imquic_get_connection_name(conn));
		} else {
			/* We've been asked not to use the catalog: let's prepare
			 * an SDP offer for the track names we've been told about */
			JANUS_LOG(LOG_INFO, "[%s]   -- Preparing SDP offer to kickstart subscriptions\n",
				imquic_get_connection_name(conn));
			janus_sdp *offer = janus_sdp_generate_offer("imquic",
				"0.0.0.0", JANUS_SDP_OA_DONE);
			if(session->audio_track.track) {
				/* FIXME Audio track */
				session->audio_pt = janus_audiocodec_pt(JANUS_AUDIOCODEC_OPUS);
				janus_sdp_generate_offer_mline(offer,
					JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
					JANUS_SDP_OA_MID, "a",
					JANUS_SDP_OA_PT, session->audio_pt,
					JANUS_SDP_OA_CODEC, janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS),
					JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
					JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, janus_rtp_extension_id(JANUS_RTP_EXTMAP_MID),
					JANUS_SDP_OA_DONE);
			}
			if(session->video_track.track) {
				/* FIXME Video track */
				session->video_pt = janus_videocodec_pt(JANUS_VIDEOCODEC_H264);
				janus_sdp_generate_offer_mline(offer,
					JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
					JANUS_SDP_OA_MID, "v",
					JANUS_SDP_OA_PT, session->video_pt,
					JANUS_SDP_OA_CODEC, janus_videocodec_name(JANUS_VIDEOCODEC_H264),
					JANUS_SDP_OA_H264_PROFILE, "42e01f",
					JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
					JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, janus_rtp_extension_id(JANUS_RTP_EXTMAP_MID),
					JANUS_SDP_OA_DONE);
			}
			/* Send the offer to the WebRTC subscriber */
			char *sdp = janus_sdp_write(offer);
			janus_sdp_destroy(offer);
			json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp);
			g_free(sdp);
			json_t *event = json_object();
			json_object_set_new(event, "moq", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("offering"));
			json_object_set_new(event, "result", result);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
			json_decref(event);
			json_decref(jsep);
		}
	}
}

static void janus_moq_moq_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *params) {
	JANUS_LOG(LOG_INFO, "[%s] Publish Namespace '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
}

static void janus_moq_moq_publish_namespace_error(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	JANUS_LOG(LOG_INFO, "[%s] Got an error publishing namespace via ID '%"SCNu64"': error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* TODO Stop here */
}

static void janus_moq_moq_incoming_subscribe(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_request_parameters *parameters) {
	/* Accept the subscription, if it's for something we know */
	char namespace[100], track[100];
	namespace[0] = '\0';
	if(tns->buffer && tns->length > 0)
		g_snprintf(namespace, sizeof(namespace), "%.*s", (int)tns->length, tns->buffer);
	track[0] = '\0';
	if(tn->buffer && tn->length > 0)
		g_snprintf(track, sizeof(track), "%.*s", (int)tn->length, tn->buffer);
	JANUS_LOG(LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64")\n",
		imquic_get_connection_name(conn), namespace, track, request_id);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	if(session->track_namespace == NULL || strcasecmp(session->track_namespace, namespace)) {
		JANUS_LOG(LOG_WARN, "Unknown namespace '%s'\n", namespace);
		return;
	}
	if(session->catalog_track.track && !strcasecmp(session->catalog_track.track, track)) {
		/* Catalog track, accept the subscription */
		session->catalog_track.request_id = request_id;
		session->catalog_track.track_alias = 0;
		imquic_moq_accept_subscribe(conn, request_id, session->catalog_track.track_alias, NULL, NULL);
		session->catalog_track.active = TRUE;
		/* Send the catalog right away */
		char *json = imquic_moq_catalog_serialize(session->catalog);
		if(json != NULL) {
			imquic_moq_object object = {
				.request_id = session->catalog_track.request_id,
				.track_alias = session->catalog_track.track_alias,
				.group_id = 0,	/* FIXME */
				.subgroup_id = 0,
				.object_id = 0,
				.payload = (uint8_t *)json,
				.payload_len = strlen(json),
				.delivery = IMQUIC_MOQ_USE_SUBGROUP,
				.end_of_stream = TRUE
			};
			imquic_moq_send_object(conn, &object);
			g_free(json);
		}
		return;
	}
	/* Audio or video */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	if(session->audio_track.track && !strcasecmp(session->audio_track.track, track)) {
		/* FIXME Subscription for the audio track */
		session->audio_track.request_id = request_id;
		session->audio_track.track_alias = 1;
		imquic_moq_accept_subscribe(conn, request_id, session->audio_track.track_alias, &rparams, NULL);
		session->audio_track.active = TRUE;
	} else if(session->video_track.track && !strcasecmp(session->video_track.track, track)) {
		/* FIXME Subscription for the video track */
		session->video_track.request_id = request_id;
		session->video_track.track_alias = 2;
		imquic_moq_accept_subscribe(conn, request_id, session->video_track.track_alias, &rparams, NULL);
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
	if(session->catalog_track.track && session->catalog_track.request_id == request_id) {
		/* Catalog track */
		session->catalog_track.active = FALSE;
		session->catalog_track.request_id = 0;
		session->catalog_track.track_alias = 0;
	} else if(session->audio_track.track && session->audio_track.request_id == request_id) {
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

static void janus_moq_moq_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_request_parameters *parameters, GList *track_extensions) {
	JANUS_LOG(LOG_INFO, "[%s] Subscription %"SCNu64" accepted\n",
		imquic_get_connection_name(conn), request_id);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	if(session->catalog_track.track && session->catalog_track.request_id == request_id) {
		/* Catalog track */
		JANUS_LOG(LOG_INFO, "[%s]   -- Catalog track will use track alias '%"SCNu64"\n",
			imquic_get_connection_name(conn), track_alias);
		session->catalog_track.track_alias = track_alias;
		if(parameters && parameters->largest_object_set) {
			/* There's a largest object, send a Joining FETCH */
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Largest Location: %"SCNu64"/%"SCNu64"\n",
				imquic_get_connection_name(conn),
				parameters->largest_object.group, parameters->largest_object.object);
			/* Send a Joining Fetch referencing this subscription */
			imquic_moq_request_parameters fparams;
			imquic_moq_request_parameters_init_defaults(&fparams);
			uint64_t catalog_fetch_request_id = imquic_moq_get_next_request_id(conn);
			int join_offset = parameters->largest_object.group;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Sending Joining Fetch for subscription %"SCNu64", using ID %"SCNu64" (offset=%d)\n",
				imquic_get_connection_name(conn), request_id, catalog_fetch_request_id, join_offset);
			imquic_moq_joining_fetch(conn, catalog_fetch_request_id, request_id, FALSE, join_offset, &fparams);
		}
	} else if(session->audio_track.track && session->audio_track.request_id == request_id) {
		/* Audio track */
		JANUS_LOG(LOG_INFO, "[%s]   -- Audio track will use track alias '%"SCNu64"\n",
			imquic_get_connection_name(conn), track_alias);
		session->audio_track.track_alias = track_alias;
		if(session->audio_pt != -1)
			g_hash_table_insert(session->ptypes, janus_uint64_dup(track_alias), GINT_TO_POINTER(session->audio_pt));
	} else if(session->video_track.track && session->video_track.request_id == request_id) {
		/* Video track */
		JANUS_LOG(LOG_INFO, "[%s]   -- Video track will use track alias '%"SCNu64"\n",
			imquic_get_connection_name(conn), track_alias);
		session->video_track.track_alias = track_alias;
		if(session->video_pt != -1)
			g_hash_table_insert(session->ptypes, janus_uint64_dup(track_alias), GINT_TO_POINTER(session->video_pt));
	}
}

static void janus_moq_moq_subscribe_error(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	JANUS_LOG(LOG_INFO, "[%s] Got an error subscribing to ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
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
	int num_props = g_list_length(object->properties);
	JANUS_LOG(LOG_HUGE, "[%s] Incoming object: reqid=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64", id=%"SCNu64", payload=%zu bytes, properties=%d, delivery=%s, status=%s, eos=%d\n",
		imquic_get_connection_name(conn), object->request_id, object->track_alias,
		object->group_id, object->subgroup_id, object->object_id,
		object->payload_len, num_props, imquic_moq_delivery_str(object->delivery),
		imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	imquic_moq_version moq_version = imquic_moq_get_version(conn);
	if(object->track_alias == session->catalog_track.track_alias || object->delivery == IMQUIC_MOQ_USE_FETCH) {
		/* This is from the catalog track */
		JANUS_LOG(LOG_INFO, "[%s] Catalog: %.*s\n",
			imquic_get_connection_name(conn), (int)object->payload_len, (char *)object->payload);
		if(session->catalog) {
			/* We have a catalog already, and we don't support deltas yet */
			return;
		}
		/* Let's parse the catalog to see if there are tracks we can subscribe to */
		char *json = g_malloc(object->payload_len + 1);
		memcpy(json, object->payload, object->payload_len);
		json[object->payload_len] = '\0';
		session->catalog = imquic_moq_catalog_parse(json);
		g_free(json);
		if(session->catalog == NULL) {
			/* Something went wrong */
			return;
		}
		/* Check if we're relying on the catalog to discover tracks */
		if(session->moqsub && session->use_catalog) {
			/* Use catalog to generate an offer for this subscriber */
			JANUS_LOG(LOG_INFO, "[%s]   -- Using catalog to prepare SDP offer\n",
				imquic_get_connection_name(conn));
			janus_sdp *offer = janus_sdp_generate_offer("imquic",
				"0.0.0.0", JANUS_SDP_OA_DONE);
			GList *temp = session->catalog->tracks;
			while(temp) {
				imquic_moq_catalog_track *track = (imquic_moq_catalog_track *)temp->data;
				if(track->role && !strcasecmp(track->role, "audio")) {
					/* FIXME Audio track */
					session->audio_track.track = g_strdup(track->track_name);
					session->audio_track.ssrc = janus_random_uint32();
					session->audio_pt = janus_audiocodec_pt(JANUS_AUDIOCODEC_OPUS);
					janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
						JANUS_SDP_OA_MID, "a",
						JANUS_SDP_OA_PT, session->audio_pt,
						JANUS_SDP_OA_CODEC, janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS),
						JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
						JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, janus_rtp_extension_id(JANUS_RTP_EXTMAP_MID),
						JANUS_SDP_OA_DONE);
				} else if(track->role && !strcasecmp(track->role, "video")) {
					/* FIXME Video track */
					session->video_track.track = g_strdup(track->track_name);
					session->video_track.ssrc = janus_random_uint32();
					session->video_pt = janus_videocodec_pt(JANUS_VIDEOCODEC_H264);
					janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
						JANUS_SDP_OA_MID, "v",
						JANUS_SDP_OA_PT, session->video_pt,
						JANUS_SDP_OA_CODEC, janus_videocodec_name(JANUS_VIDEOCODEC_H264),
						JANUS_SDP_OA_H264_PROFILE, "42e01f",
						JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
						JANUS_SDP_OA_EXTENSION, JANUS_RTP_EXTMAP_MID, janus_rtp_extension_id(JANUS_RTP_EXTMAP_MID),
						JANUS_SDP_OA_DONE);
				}
				temp = temp->next;
			}
			/* Send the offer to the WebRTC subscriber */
			char *sdp = janus_sdp_write(offer);
			janus_sdp_destroy(offer);
			json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp);
			g_free(sdp);
			json_t *event = json_object();
			json_object_set_new(event, "moq", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("offering"));
			json_object_set_new(event, "result", result);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
			json_decref(event);
			json_decref(jsep);
		}
		return;
	}
	/* FIXME Assuming LOC from https://www.ietf.org/archive/id/draft-ietf-moq-loc-02.html */
	uint64_t timestamp = 0, timescale = 0;
	struct imquic_moq_property_data *loc_extradata = NULL;
	if((session->audio_track.track && object->track_alias == session->audio_track.track_alias) ||
			(session->video_track.track && object->track_alias == session->video_track.track_alias)) {
		/* Parse the properties to get access to the LOC info */
		JANUS_LOG(LOG_HUGE, "  -- Processing %d properties:\n", num_props);
		GList *temp = object->properties;
		while(temp) {
			imquic_moq_property *prop = (imquic_moq_property *)temp->data;
			switch(prop->id) {
				case IMQUIC_MOQ_LOC_TIMESCALE: {
					timescale = prop->value.number;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %"SCNu64"\n",
						imquic_moq_property_type_str(moq_version, prop->id), timescale);
					break;
				}
				case IMQUIC_MOQ_LOC_TIMESTAMP: {
					timestamp = prop->value.number;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %"SCNu64"\n",
						imquic_moq_property_type_str(moq_version, prop->id), timestamp);
					break;
				}
				case IMQUIC_MOQ_LOC_VIDEO_CONFIG: {
					loc_extradata = &prop->value.data;
					JANUS_LOG(LOG_HUGE, "  -- -- %s: %zu bytes\n",
						imquic_moq_property_type_str(moq_version, prop->id),
						loc_extradata->length);
					for(size_t i=0; i<loc_extradata->length; ++i)
						JANUS_LOG(LOG_HUGE, "%02x", loc_extradata->buffer[i]);
					JANUS_LOG(LOG_HUGE, "\n");
					break;
				}
				default: {
					JANUS_LOG(LOG_WARN, "  -- -- Unknown property '%"SCNu32"'\n", prop->id);
					break;
				}
			}
			temp = temp->next;
		}
		JANUS_LOG(LOG_HUGE, "  -- Payload: %zu bytes\n", object->payload_len);
	}
	/* FIXME We currently require the timestamp to be there */
	if(object->payload == NULL || object->payload_len == 0 || timestamp == 0)
		return;
	/* Convert LOC to RTP */
	size_t hsize = 12;
	if(session->audio_track.track && object->track_alias == session->audio_track.track_alias) {
		/* This is audio */
		int pt = GPOINTER_TO_INT(g_hash_table_lookup(session->ptypes, &object->track_alias));
		if(pt == -1) {
			JANUS_LOG(LOG_HUGE, "[%s]  -- Can't find payload type associated to track alias %"SCNu64"\n",
				imquic_get_connection_name(conn), object->track_alias);
			return;
		}
		char buffer[1500];
		size_t length = hsize + object->payload_len;
		/* Craft the RTP packet */
		if(session->audio_track.seq == 0) {
			session->audio_track.timestamp = timestamp;
			session->audio_track.timestamp_start = timestamp;
		}
		uint64_t lts_diff = timestamp - session->audio_track.timestamp;
		uint32_t ts_diff = lts_diff ? (48000 / (G_USEC_PER_SEC / lts_diff)) : 0;
		session->audio_track.timestamp = timestamp;
		janus_rtp_header *rtp = (janus_rtp_header *)buffer;
		rtp->version = 2;
		rtp->markerbit = (session->audio_track.seq == 0);	/* Should be 1 for the first packet */
		rtp->type = pt;
		session->audio_track.seq++;
		rtp->seq_number = htons(session->audio_track.seq);
		/* FIXME This is quite broken now */
		session->audio_track.last_ts += ts_diff;
		rtp->timestamp = htonl(session->audio_track.last_ts);
		rtp->ssrc = htonl(session->audio_track.ssrc);
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
			return;
		}
		char buffer[1500];
		size_t length = 0;
		/* Craft the base RTP packet */
		if(session->video_track.seq == 0) {
			session->video_track.timestamp = timestamp;
			session->video_track.timestamp_start = timestamp;
		}
		uint64_t lts_diff = timestamp - session->video_track.timestamp;
		uint32_t ts_diff = lts_diff ? (90000 / (G_USEC_PER_SEC / lts_diff)) : 0;
		session->video_track.timestamp = timestamp;
		janus_rtp_header *rtp = (janus_rtp_header *)buffer;
		rtp->version = 2;
		rtp->markerbit = 0;	/* Should be 1 for the last packet of a frame */
		rtp->type = pt;
		/* FIXME This is quite broken now */
		session->video_track.last_ts += ts_diff;
		rtp->timestamp = htonl(session->video_track.timestamp);
		rtp->ssrc = htonl(session->video_track.ssrc);
		/* Create all the RTP packets we need */
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
			session->video_track.seq++;
			rtp->seq_number = htons(session->video_track.seq);
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
					session->video_track.seq++;
					rtp->seq_number = htons(session->video_track.seq);
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
			session->video_track.seq++;
			rtp->seq_number = htons(session->video_track.seq);
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
			session->video_track.seq++;
			rtp->seq_number = htons(session->video_track.seq);
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
					session->video_track.seq++;
					rtp->seq_number = htons(session->video_track.seq);
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
					session->video_track.seq++;
					rtp->seq_number = htons(session->video_track.seq);
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
	}
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
