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
	{"namespace", JANUS_JSON_ARRAY, JANUS_JSON_PARAM_REQUIRED},
	{"use_catalog", JANUS_JSON_BOOL, 0},
	{"audio_track", JANUS_JSON_STRING, 0},
	{"video_track", JANUS_JSON_STRING, 0},
	{"video_codec", JANUS_JSON_STRING, 0},
	{"annexb", JANUS_JSON_BOOL, 0},
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
static size_t mtu = 1200;

/* Default buffer size in ms */
static int64_t buffer_size = 200000;

/* Buffered audio/video packet */
typedef struct janus_moq_buffer_packet {
	char *buffer;			/* Pointer to the packet data, if RTP */
	int len;				/* Size of the packet */
	uint32_t timestamp;		/* RTP timestamp of the packet */
	uint16_t seq_number;	/* RTP sequence number of the packet */
	int64_t inserted;		/* Monotonic insert time */
} janus_moq_buffer_packet;
static janus_moq_buffer_packet *janus_moq_buffer_packet_create(char *buffer, int len) {
	janus_moq_buffer_packet *pkt = g_malloc(sizeof(janus_moq_buffer_packet));
	pkt->buffer = g_malloc(len);
	pkt->len = len;
	memcpy(pkt->buffer, buffer, len);
	janus_rtp_header *rtp = (janus_rtp_header *)buffer;
	pkt->timestamp = ntohl(rtp->timestamp);
	pkt->seq_number = ntohs(rtp->seq_number);
	pkt->inserted = g_get_monotonic_time();
	return pkt;
}
static void janus_moq_buffer_packet_destroy(janus_moq_buffer_packet *pkt) {
	if(!pkt)
		return;
	g_free(pkt->buffer);
	g_free(pkt);
}
static gint janus_moq_buffer_packet_compare(gconstpointer a, gconstpointer b, gpointer user_data) {
	janus_moq_buffer_packet *bpa = (janus_moq_buffer_packet *)a;
	janus_moq_buffer_packet *bpb = (janus_moq_buffer_packet *)b;
	if(bpa->timestamp == bpb->timestamp) {
		/* Check the sequence numbers */
		if(bpa->seq_number == bpb->seq_number) {
			/* Same packet? */
			return 0;
		} else if(bpa->seq_number < bpb->seq_number) {
			if(bpb->seq_number - bpa->seq_number < 30000) {
				/* Sequence number wrapped */
				return -1;
			} else {
				/* Regular ordering */
				return 1;
			}
		} else if(bpa->seq_number > bpb->seq_number) {
			if(bpa->seq_number - bpb->seq_number < 30000) {
				/* Sequence number wrapped */
				return 1;
			} else {
				/* Regular ordering */
				return -1;
			}
		}
	} else if(bpa->timestamp < bpb->timestamp) {
		if(bpb->timestamp - bpa->timestamp < 2*1000*1000*1000) {
			/* Timestamp wrapped */
			return -1;
		} else {
			/* Regular ordering */
			return 1;
		}
	} else if(bpa->timestamp > bpb->timestamp) {
		if(bpa->timestamp - bpb->timestamp < 2*1000*1000*1000) {
			/* Timestamp wrapped */
			return 1;
		} else {
			/* Regular ordering */
			return -1;
		}
	}
	return 0;
}

/* MoQ plugin message */
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
	imquic_moq_track *track;
	char *track_name;
	gboolean active;
	gboolean got_first;
	uint32_t ssrc;
	uint32_t last_ts;
	uint64_t seq;
	uint64_t request_id, track_alias, group_id, object_id;
	uint64_t timestamp, timestamp_start;
	int width, height;
} janus_moq_moq_rtp;

/* Plugin session */
typedef struct janus_moq_session {
	janus_plugin_session *handle;
	/* QUIC/MoQ */
	imquic_endpoint *quic_endpoint;
	imquic_connection *conn;
	gboolean moqsub, moqpub, use_catalog;
	imquic_moq_catalog *catalog;
	char *catalog_orig;
	imquic_moq_namespace *track_namespace;
	char *track_namespace_str, *auth_info;
	janus_moq_moq_rtp catalog_track, audio_track, video_track;
	/* RTP/RTCP */
	GHashTable *media, *ptypes;
	int audio_pt, video_pt;
	gint64 pli_latest;
	GQueue *audio_buffered_packets, *video_buffered_packets;
#if (JANUS_PLUGIN_API_VERSION < 100)
	janus_rtp_switching_context rtpctx;		/* RTP context */
#else
	janus_rtp_switching_context artpctx, vrtpctx;	/* RTP contexts */
#endif
	uint16_t a_max_seq_nr, v_max_seq_nr;	/* Max sequence numbers */
	/* Encoding */
	janus_videocodec vcodec;
	gboolean annexb;
	uint16_t pid;
	/* Publisher thread, if required */
	GThread *thread;
	/* Utils */
	janus_mutex mutex;
	volatile gint hangingup;
	volatile gint hangup;
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
	g_free(session->catalog_orig);
	imquic_moq_namespace_free(session->track_namespace);
	g_free(session->track_namespace_str);
	imquic_moq_track_free(session->catalog_track.track);
	g_free(session->catalog_track.track_name);
	imquic_moq_track_free(session->audio_track.track);
	g_free(session->audio_track.track_name);
	imquic_moq_track_free(session->video_track.track);
	g_free(session->video_track.track_name);
	g_free(session->auth_info);
	g_hash_table_unref(session->media);
	g_hash_table_unref(session->ptypes);
	if(session->audio_buffered_packets)
		g_queue_free_full(session->audio_buffered_packets, (GDestroyNotify)janus_moq_buffer_packet_destroy);
	if(session->video_buffered_packets)
		g_queue_free_full(session->video_buffered_packets, (GDestroyNotify)janus_moq_buffer_packet_destroy);
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

/* Helper to check if an RTP packet is out of order */
static gboolean janus_moq_rtp_is_outoforder(janus_moq_session *session, janus_rtp_header *header, gboolean video) {
	if(header == NULL || session == NULL)
		return FALSE;
	uint16_t seq = ntohs(header->seq_number);
	uint16_t max_seq_nr = (video ? session->v_max_seq_nr : session->a_max_seq_nr);
	if((int16_t)(seq - max_seq_nr) > 0) {
		/* Packet is in order, update max_seq_nr */
		if(video)
			session->v_max_seq_nr = seq;
		else
			session->a_max_seq_nr = seq;
		return FALSE;
	} else {
		/* Packet is out of order */
		JANUS_LOG(LOG_WARN, "Out of order packet (%"SCNu16", expecting %"SCNu16")\n",
			seq, (max_seq_nr+1));
		return TRUE;
	}
}

/* imquic stuff */
static GHashTable *connections = NULL;
static janus_mutex connections_mutex = JANUS_MUTEX_INITIALIZER;
/* Callbacks */
static void janus_moq_new_connection(imquic_connection *conn, void *user_data);
static void janus_moq_connection_failed(void *user_data);
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
static void janus_moq_moq_request_updated(imquic_connection *conn, uint64_t request_id,
	uint64_t sub_request_id, imquic_moq_request_parameters *parameters);
static void janus_moq_moq_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason);
static void janus_moq_moq_incoming_object(imquic_connection *conn, imquic_moq_object *object);

/* Helpers to parse SPS/PPS (needed for Annex-B to AVC1 translation) */
static uint32_t janus_moq_h264_eg_getbit(uint8_t *base, uint32_t offset);
static uint32_t janus_moq_h264_eg_decode(uint8_t *base, uint32_t *offset);
static size_t janus_moq_h264_parse_sps(uint8_t *extradata, size_t extradata_len,
	gboolean annexb, uint8_t *buffer, size_t len, gboolean stap, int *width, int *height);

/* Helpers to parse AV1 frames */
static uint32_t janus_moq_av1_lev128_decode(uint8_t *base, uint16_t maxlen, size_t *read);
static void janus_moq_av1_lev128_encode(uint32_t value, uint8_t *base, size_t *written);
static uint32_t janus_moq_av1_getbit(uint8_t *base, uint32_t offset);
static uint32_t janus_moq_av1_getbits(uint8_t *base, uint8_t num, uint32_t *offset);
static void janus_moq_av1_parse_sh(char *buffer, uint16_t *width, uint16_t *height);

/* Audio/video processing thread, for MoQ publishers */
static void *janus_moq_processing_thread(void *data);

/* Error codes */
#define JANUS_MOQ_ERROR_NO_MESSAGE		410
#define JANUS_MOQ_ERROR_INVALID_JSON	412
#define JANUS_MOQ_ERROR_INVALID_REQUEST	412
#define JANUS_MOQ_ERROR_MISSING_ELEMENT	413
#define JANUS_MOQ_ERROR_INVALID_ELEMENT	414
#define JANUS_MOQ_ERROR_MISSING_SDP		415
#define JANUS_MOQ_ERROR_INVALID_SDP		416
#define JANUS_MOQ_ERROR_WRONG_STATE		417
#define JANUS_MOQ_ERROR_IMQUIC_ERROR	418


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
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		/* Check if we need to enforce a custom buffer size */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "buffer_size");
		if(item && item->value) {
			/* Enforce buffer size */
			int bs = atoi(item->value);
			if(bs < 0) {
				JANUS_LOG(LOG_WARN, "Invalid buffer size %s, falling back to %"SCNi64"\n", item->value, buffer_size);
			} else {
				buffer_size = bs*1000;
				JANUS_LOG(LOG_INFO, "Setting buffer size to %dms\n", bs);
			}
		}
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
	connections = g_hash_table_new_full(NULL, NULL, NULL, NULL);

	/* This is the callback we'll need to invoke to contact the server */
	gateway = callback;
	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("moq handler", janus_moq_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the MoQ handler thread...\n", error->code, error->message ? error->message : "??");
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
	session->vcodec = JANUS_VIDEOCODEC_H264;
	session->annexb = FALSE;	/* By default we use AVCC */
	session->audio_buffered_packets = g_queue_new();
	session->video_buffered_packets = g_queue_new();
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
	JANUS_LOG(LOG_VERB, "Removing MoQ session...\n");
	janus_moq_hangup_media_internal(handle);
	/* If there's an imquic endpoint running, get rid of it */
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
	/* TODO We should return some more info here */
	json_t *info = json_object();
	if(session->moqpub || session->moqsub) {
		json_object_set_new(info, "role", json_string(session->moqpub ? "publisher" : "subscriber"));
	}
	json_object_set_new(info, "buffer-size", json_integer(buffer_size));
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
	 * as a test plugin we simply echo this Admin request back as well */
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
#if (JANUS_PLUGIN_API_VERSION < 100)
	janus_rtp_switching_context_reset(&session->rtpctx);
#else
	janus_rtp_switching_context_reset(&session->artpctx);
	janus_rtp_switching_context_reset(&session->vrtpctx);
#endif
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->hangup, 0);
	janus_mutex_unlock(&sessions_mutex);
	/* If this related to a subscriber, actually subscribe to the audio/video tracks now */
	if(session->moqsub && session->conn) {
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.subscription_filter_set = TRUE;
		params.subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
		if(session->auth_info) {
			/* Serialize the token using the USE_VALUE alias type */
			params.auth_token_set = TRUE;
			params.auth_token_len = sizeof(params.auth_token);
			imquic_moq_auth_token token = { 0 };
			token.alias_type = IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE;
			token.token_type_set = TRUE;
			token.token_type = 0;	/* FIXME */
			token.token_value.buffer = (uint8_t *)session->auth_info;
			token.token_value.length = strlen(session->auth_info);
			size_t offset = imquic_moq_build_auth_token(imquic_moq_get_version(session->conn),
				&token, params.auth_token, params.auth_token_len);
			if(offset == 0) {
				params.auth_token_set = FALSE;
				JANUS_LOG(LOG_WARN, "[%s] Error serializing the auth token\n",
					imquic_get_connection_name(session->conn));
			}
			params.auth_token_len = offset;
		}
		/* Audio track, if any */
		if(session->audio_track.track) {
			session->audio_track.request_id = imquic_moq_get_next_request_id(session->conn);
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s--%s, using ID %"SCNu64"\n",
				imquic_get_connection_name(session->conn),
				session->track_namespace_str, session->audio_track.track_name, session->audio_track.request_id);
			imquic_moq_subscribe(session->conn, session->audio_track.request_id, session->track_namespace, session->audio_track.track, &params);
		}
		/* Video track, if any */
		if(session->video_track.track) {
			session->video_track.request_id = imquic_moq_get_next_request_id(session->conn);
			JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s--%s, using ID %"SCNu64"\n",
				imquic_get_connection_name(session->conn),
				session->track_namespace_str, session->video_track.track_name, session->video_track.request_id);
			imquic_moq_subscribe(session->conn, session->video_track.request_id, session->track_namespace, session->video_track.track, &params);
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
		/* First of all, check if we have a catalog to send */
		if(session->catalog_track.active && !session->catalog_track.got_first) {
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
				imquic_moq_send_object(session->conn, &object);
				g_free(json);
			}
			session->catalog_track.got_first = TRUE;
		}
		/* Now process the RTP payload */
		janus_rtp_header *rtp = (janus_rtp_header *)packet->buffer;
		int plen = 0;
		char *payload = janus_rtp_payload((char *)packet->buffer, packet->length, &plen);
		if(payload == NULL || plen == 0)
			return;
		if(!packet->video && session->audio_track.track && session->audio_track.active) {
			/* Fix the RTP header, if needed */
#if (JANUS_PLUGIN_API_VERSION < 100)
			janus_rtp_header_update(rtp, &session->rtpctx, FALSE, 0);
#else
			janus_rtp_header_update(rtp, &session->artpctx, FALSE, 0);
#endif
			/* Queue the audio packet (we won't decode now, there might be buffering involved) */
			janus_moq_buffer_packet *pkt = janus_moq_buffer_packet_create(packet->buffer, packet->length);
			janus_mutex_lock(&session->mutex);
			g_queue_insert_sorted(session->audio_buffered_packets, pkt, (GCompareDataFunc)janus_moq_buffer_packet_compare, NULL);
			/* If this packet is out-of-order, fix the inserted time */
			if(janus_moq_rtp_is_outoforder(session, rtp, FALSE)) {
				/* Out of order */
				JANUS_LOG(LOG_WARN, "[%s] Out of order audio packet\n",
					imquic_get_connection_name(session->conn));
				GList *item = g_queue_find(session->audio_buffered_packets, pkt);
				janus_moq_buffer_packet *prev = NULL;
				if(item && item->prev && item->prev->data)
					prev = (janus_moq_buffer_packet *)item->prev->data;
				else if(item && item->next && item->next->data)
					prev = (janus_moq_buffer_packet *)item->next->data;
				if(prev != NULL) {
					JANUS_LOG(LOG_HUGE, "[%s]   >> Fixing inserted time: %"SCNi64" --> %"SCNi64"\n",
						imquic_get_connection_name(session->conn), pkt->inserted, prev->inserted);
					pkt->inserted = prev->inserted;
				}
			}
			janus_mutex_unlock(&session->mutex);
		} else if(packet->video && session->video_track.track && session->video_track.active) {
			/* If this is the first packet we receive, ignore it and wait for a keyframe */
			if(!session->video_track.got_first) {
				gint64 now = janus_get_monotonic_time();
				if(session->pli_latest == 0 || (now-session->pli_latest >= 100000)) {
					gateway->send_pli(session->handle);
					session->pli_latest = janus_get_monotonic_time();
				}
				if(!janus_is_keyframe(session->vcodec, payload, plen)) {
					JANUS_LOG(LOG_VERB, "[%s] Waiting for a keyframe\n",
						imquic_get_connection_name(session->conn));
					return;
				}
				session->video_track.got_first = TRUE;
			}
			/* Fix the RTP header, if needed */
#if (JANUS_PLUGIN_API_VERSION < 100)
			janus_rtp_header_update(rtp, &session->rtpctx, TRUE, 0);
#else
			janus_rtp_header_update(rtp, &session->vrtpctx, TRUE, 0);
#endif
			/* Queue the video packet (we won't decode now, there might be buffering involved) */
			janus_moq_buffer_packet *pkt = janus_moq_buffer_packet_create(packet->buffer, packet->length);
			janus_mutex_lock(&session->mutex);
			g_queue_insert_sorted(session->video_buffered_packets, pkt, (GCompareDataFunc)janus_moq_buffer_packet_compare, NULL);
			/* If this packet is out-of-order, fix the inserted time */
			if(janus_moq_rtp_is_outoforder(session, rtp, TRUE)) {
				/* Out of order */
				JANUS_LOG(LOG_WARN, "[%s] Out of order video packet\n",
					imquic_get_connection_name(session->conn));
				GList *item = g_queue_find(session->video_buffered_packets, pkt);
				janus_moq_buffer_packet *prev = NULL;
				if(item && item->prev && item->prev->data)
					prev = (janus_moq_buffer_packet *)item->prev->data;
				else if(item && item->next && item->next->data)
					prev = (janus_moq_buffer_packet *)item->next->data;
				if(prev != NULL) {
					JANUS_LOG(LOG_HUGE, "[%s]   >> Fixing inserted time: %"SCNi64" --> %"SCNi64"\n",
						imquic_get_connection_name(session->conn), pkt->inserted, prev->inserted);
					pkt->inserted = prev->inserted;
				}
			}
			janus_mutex_unlock(&session->mutex);
		}
	}
}

/* Audio/video processing thread */
static void *janus_moq_processing_thread(void *data) {
	janus_moq_session *session = (janus_moq_session *)data;
	if(!session) {
		JANUS_LOG(LOG_ERR, "Invalid session, leaving thread...\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_INFO, "[%s] Starting session thread\n",
		imquic_get_connection_name(session->conn));

	/* Stuff */
	char *packet = NULL, *payload = NULL;
	int bytes = 0, plen = 0;

	/* Video decoding stuff */
	size_t canvas_size = 256000;	/* FIXME */
	uint8_t *received_frame = g_malloc0(canvas_size);
	uint8_t *obu_data = (session->vcodec == JANUS_VIDEOCODEC_AV1 ? g_malloc0(canvas_size) : NULL);
	size_t frame_len = 0, data_len = 0;
	guint32 prev_ts = 0, last_ts = 0;
	gboolean prevts_set = FALSE, ts_changed = FALSE, got_video = FALSE, got_keyframe = FALSE, key_frame = FALSE;
	uint16_t max_seq_nr = 0;
	uint8_t gaps = 0;
	gboolean waiting_kf = FALSE;
	gint64 last_pli = 0;
	gboolean need_pli = FALSE;

	/* H.264 stuff */
	gboolean nal_added = FALSE;
	size_t nal_offset = 0;
	uint8_t extradata[50] = { 0 };
	size_t extradata_len = 0;

	/* Timers*/
	gboolean done_something = TRUE;
	gint64 now = 0, destroyed = 0;

	while(session) {
		/* If the user has been removed, we need to wrap up */
		now = g_get_monotonic_time();
		if((g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangup)) && destroyed == 0) {
			JANUS_LOG(LOG_INFO, "[%s] Marking session thread as destroyed\n",
				imquic_get_connection_name(session->conn));
			destroyed = now;
		}
		if(destroyed && (now - destroyed) >= buffer_size)
			break;
		if(!done_something) {
			/* No packet in the previous iteration, sleep a bit */
			g_usleep(5000);
		}
		done_something = FALSE;

		/* Do we have a PLI to send? */
		if(need_pli && (now-last_pli >= G_USEC_PER_SEC)) {
			JANUS_LOG(LOG_INFO, "[%s] Sending PLI\n",
				imquic_get_connection_name(session->conn));
			last_pli = now;
			need_pli = FALSE;
			gateway->send_pli(session->handle);
		}

		/* We may have MoQ objects to send: let's start with audio */
		janus_mutex_lock(&session->mutex);
		janus_moq_buffer_packet *pkt = session->audio_buffered_packets ? g_queue_peek_head(session->audio_buffered_packets) : NULL;
		janus_mutex_unlock(&session->mutex);
		while(pkt != NULL && ((now - pkt->inserted) >= buffer_size)) {
			JANUS_LOG(LOG_HUGE, "[%s] Processing audio RTP packet: ts=%"SCNu32", seq=%"SCNu16", ins=%"SCNu64"\n",
				imquic_get_connection_name(session->conn), pkt->timestamp, pkt->seq_number, pkt->inserted);
			packet = NULL;
			bytes = 0;
			done_something = TRUE;
			janus_mutex_lock(&session->mutex);
			pkt = g_queue_pop_head(session->audio_buffered_packets);
			janus_mutex_unlock(&session->mutex);
			packet = pkt->buffer;
			bytes = pkt->len;
			payload = janus_rtp_payload(packet, bytes, &plen);
			/* Each audio frame is self contained, write the LOC info first as properties */
			GList *props = NULL;
			imquic_moq_property timescale = { 0 };
			timescale.id = IMQUIC_MOQ_LOC_TIMESCALE;
			timescale.value.number = G_USEC_PER_SEC;
			props = g_list_append(props, &timescale);
			/* FIXME We should take into account RTP timestamps, but
			 * for simplicity for now we simply increase 20ms every time */
			imquic_moq_property timestamp = { 0 };
			timestamp.id = IMQUIC_MOQ_LOC_TIMESTAMP;
			timestamp.value.number = session->audio_track.timestamp;
			props = g_list_append(props, &timestamp);
			session->audio_track.timestamp += 20000;
			/* FIXME We currently don't support LOC private properties, so
			 * we always send a 0x00 as a payload prefix to signal it's empty */
			uint8_t loc_pvt_props = 0;
			/* Prepare a MoQ object and send it */
			imquic_moq_object object = {
				.request_id = session->audio_track.request_id,
				.track_alias = session->audio_track.track_alias,
				.group_id = session->audio_track.group_id++,
				.subgroup_id = 0,	/* FIXME */
				.object_id = session->audio_track.object_id,
				.payload_prefix = &loc_pvt_props,
				.payload_prefix_len = 1,
				.payload = (uint8_t *)payload,
				.payload_len = plen,
				.properties = props,
				.delivery = IMQUIC_MOQ_USE_DATAGRAM
			};
			imquic_moq_send_object(session->conn, &object);
			g_list_free(props);
			/* Get rid of the buffered packet */
			janus_moq_buffer_packet_destroy(pkt);
			/* Peek the next packet */
			janus_mutex_lock(&session->mutex);
			pkt = g_queue_peek_head(session->audio_buffered_packets);
			janus_mutex_unlock(&session->mutex);
		}
		/* Now move to video */
		janus_mutex_lock(&session->mutex);
		pkt = session->video_buffered_packets ? g_queue_peek_head(session->video_buffered_packets) : NULL;
		janus_mutex_unlock(&session->mutex);
		if(pkt != NULL && ((now - pkt->inserted) >= buffer_size)) {
			/* Time to handle this packet(s), get all those with the same timestamp */
			last_ts = pkt->timestamp;
			if(prevts_set) {
				/* The previous round didn't give us a complete frame, keep looking for the same timestamp */
				prevts_set = FALSE;
				last_ts = prev_ts;
			} else {
				gaps = 0;
			}
			while(pkt != NULL) {
				packet = NULL;
				bytes = 0;
				janus_mutex_lock(&session->mutex);
				pkt = g_queue_peek_head(session->video_buffered_packets);
				janus_mutex_unlock(&session->mutex);
				if(pkt == NULL || ((now - pkt->inserted) < buffer_size))
					break;
				/* Decode the packet */
				packet = pkt->buffer;
				bytes = pkt->len;
				janus_rtp_header *rtp = (janus_rtp_header *)packet;
				if(ntohl(rtp->timestamp) == last_ts) {
					/* Timestamp we're interested in, pop the packet */
					done_something = TRUE;
					janus_mutex_lock(&session->mutex);
					(void)g_queue_pop_head(session->video_buffered_packets);
					janus_mutex_unlock(&session->mutex);
					JANUS_LOG(LOG_HUGE, "[%s] Processing video RTP packet: ts=%"SCNu32", seq=%"SCNu16", ins=%"SCNu64"\n",
						imquic_get_connection_name(session->conn), pkt->timestamp, pkt->seq_number, pkt->inserted);
					if(!prevts_set) {
						/* Let's keep track of this timestamp */
						prevts_set = TRUE;
						prev_ts = last_ts;
					}
					/* Also check if there's gaps in the sequence number */
					if((int16_t)(pkt->seq_number - max_seq_nr) > 1) {
						/* FIXME Should we drop this packet? */
						gaps++;
						JANUS_LOG(LOG_WARN, "[%s] Detected missing packet (%"SCNu16", expecting %"SCNu16")\n",
							imquic_get_connection_name(session->conn), pkt->seq_number, (max_seq_nr+1));
					}
					max_seq_nr = pkt->seq_number;
				} else {
					/* Timestamp of another packet, stop here after we've decoded the previous one */
					pkt = NULL;
					packet = NULL;
					bytes = 0;
					ts_changed = TRUE;
					prevts_set = FALSE;
					JANUS_LOG(LOG_HUGE, "[%s]   >> Got new video timestamp (%"SCNu32" != %"SCNu32"), stopping here\n",
						imquic_get_connection_name(session->conn), ntohl(rtp->timestamp), last_ts);
				}
				/* FIXME Check if the timestamp changed and we need to decode */
				if(got_video && ts_changed && frame_len == 0) {
					ts_changed = FALSE;
				} else if(got_video && ts_changed && frame_len > 0) {
					/* Timestamp changed: we have a whole packet to decode */
					ts_changed = FALSE;
					JANUS_LOG(LOG_HUGE, "[%s]   >> Decoding video frame: ts=%"SCNu32"\n",
						imquic_get_connection_name(session->conn), last_ts);
					/* FIXME Do we have gaps in this packet? */
					if(gaps > 0) {
						/* Should we stop here, or just show a warning? */
						JANUS_LOG(LOG_WARN, "[%s] We're missing at least %"SCNu8" packets in this frame, skipping it\n",
							imquic_get_connection_name(session->conn), gaps);
						if(got_keyframe) {
							/* Wait for a keyframe */
							waiting_kf = TRUE;
							need_pli = TRUE;
						}
						/* Reset the offset and stop here */
						frame_len = 0;
						data_len = 0;
						janus_moq_buffer_packet_destroy(pkt);
						break;
					}
					if(got_keyframe && waiting_kf && !key_frame) {
						/* We're waiting for a keyframe from a previous glitch */
						JANUS_LOG(LOG_WARN, "[%s] Still waiting for a keyframe to fix the glitch\n",
							imquic_get_connection_name(session->conn));
						/* Reset the offset and stop here */
						frame_len = 0;
						data_len = 0;
						janus_moq_buffer_packet_destroy(pkt);
						break;
					}
					if(data_len > 0) {
						/* AV1 only: we have a buffered OBU, write the OBU size */
						size_t written = 0;
						uint8_t leb[8];
						janus_moq_av1_lev128_encode(data_len, leb, &written);
						JANUS_LOG(LOG_HUGE, "[%s] OBU size (%zu): %zu\n",
							imquic_get_connection_name(session->conn), data_len, written);
						memcpy(received_frame + frame_len, leb, written);
						frame_len += written;
						/* Copy the actual data */
						JANUS_LOG(LOG_HUGE, "[%s] OBU data: %zu\n",
							imquic_get_connection_name(session->conn), data_len);
						memcpy(received_frame + frame_len, obu_data, data_len);
						frame_len += data_len;
					}
					/* Buffer is complete, convert Annex-B to AVC1 (if needed) and send */
					if(nal_added) {
						uint32_t nal_size = frame_len - nal_offset - 4;
						JANUS_LOG(LOG_HUGE, "NAL has size %"SCNu32"\n", nal_size);
						nal_size = htonl(nal_size);
						memcpy(received_frame + nal_offset, &nal_size, 4);
					}
					JANUS_LOG(LOG_HUGE, "[%s] Need to send video frame of %zu bytes\n",
						imquic_get_connection_name(session->conn), frame_len);
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
					imquic_moq_property loc_extradata = { 0 };
					if(extradata_len > 0) {
						loc_extradata.id = IMQUIC_MOQ_LOC_VIDEO_CONFIG;
						loc_extradata.value.data.buffer = extradata;
						loc_extradata.value.data.length = extradata_len;
						props = g_list_append(props, &loc_extradata);
						extradata_len = 0;
					}
					/* FIXME We currently don't support LOC private properties, so
					 * we always send a 0x00 as a payload prefix to signal it's empty */
					uint8_t loc_pvt_props = 0;
					/* Prepare a MoQ object and send it */
					imquic_moq_object object = {
						.request_id = session->video_track.request_id,
						.track_alias = session->video_track.track_alias,
						.group_id = session->video_track.group_id,
						.subgroup_id = 0,	/* FIXME */
						.object_id = session->video_track.object_id,
						.payload_prefix = &loc_pvt_props,
						.payload_prefix_len = 1,
						.payload = received_frame,
						.payload_len = frame_len,
						.properties = props,
						.delivery = IMQUIC_MOQ_USE_SUBGROUP,
						.end_of_stream = FALSE
					};
					session->video_track.object_id++;
					imquic_moq_send_object(session->conn, &object);
					g_list_free(props);
					/* Reset the offset and stop here */
					nal_added = FALSE;
					nal_offset = 0;
					frame_len = 0;
					data_len = 0;
					janus_moq_buffer_packet_destroy(pkt);
					continue;
				}
				/* If we're here, we're still reconstructing the video frame */
				if(packet == NULL) {
					janus_moq_buffer_packet_destroy(pkt);
					continue;
				}
				got_video = TRUE;
				/* Check what needs to be skipped before getting to the payload */
				payload = janus_rtp_payload(packet, bytes, &plen);
				if(!payload || plen < 1) {
					/* Nothing to do here */
					JANUS_LOG(LOG_VERB, "[%s] Nothing to decode (%d bytes)\n",
						imquic_get_connection_name(session->conn), plen);
					/* Get rid of the buffered packet */
					janus_moq_buffer_packet_destroy(pkt);
					continue;
				}
				/* Depacketization depends on the codec */
				if(session->vcodec == JANUS_VIDEOCODEC_VP8) {
					/* Depacketize VP8 */
					JANUS_LOG(LOG_HUGE, "[%s] Depacketizing VP8 payload (%d bytes)\n",
						imquic_get_connection_name(session->conn), plen);
					/* Read the first octet (VP8 Payload Descriptor) */
					char *buffer = payload;
					int bytes = plen-1;
					uint8_t vp8pd = *buffer;
					uint8_t xbit = (vp8pd & 0x80);
					uint8_t sbit = (vp8pd & 0x10);
					/* Read the Extended control bits octet */
					if(xbit) {
						buffer++;
						bytes--;
						vp8pd = *buffer;
						uint8_t ibit = (vp8pd & 0x80);
						uint8_t lbit = (vp8pd & 0x40);
						uint8_t tbit = (vp8pd & 0x20);
						uint8_t kbit = (vp8pd & 0x10);
						if(ibit) {
							/* Read the PictureID octet */
							buffer++;
							bytes--;
							vp8pd = *buffer;
							uint16_t picid = vp8pd, wholepicid = picid;
							uint8_t mbit = (vp8pd & 0x80);
							if(mbit) {
								memcpy(&picid, buffer, sizeof(uint16_t));
								wholepicid = ntohs(picid);
								picid = (wholepicid & 0x7FFF);
								buffer++;
								bytes--;
							}
						}
						if(lbit) {
							/* Read the TL0PICIDX octet */
							buffer++;
							bytes--;
						}
						if(tbit || kbit) {
							/* Read the TID/KEYIDX octet */
							buffer++;
							bytes--;
						}
					}
					buffer++;
					if(sbit) {
						unsigned long int vp8ph = 0;
						memcpy(&vp8ph, buffer, 4);
						vp8ph = ntohl(vp8ph);
						uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
						if(!pbit) {
							/* Keyframe? */
							unsigned char *c = (unsigned char *)buffer+3;
							/* vet via sync code */
							if(c[0]!=0x9d||c[1]!=0x01||c[2]!=0x2a) {
								JANUS_LOG(LOG_WARN, "[%s] First 3-bytes after header not what they're supposed to be?\n",
									imquic_get_connection_name(session->conn));
							} else {
								/* This is a keyframe */
								key_frame = TRUE;
								if(!got_keyframe)
									got_keyframe = TRUE;
								JANUS_LOG(LOG_HUGE, "[%s]   -- Key frame (seq=%"SCNu16", ts=%"SCNu32")\n",
									imquic_get_connection_name(session->conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp));
								if(session->video_track.group_id > 0) {
									/* Close the previous stream first */
									imquic_moq_object object = {
										.request_id = session->video_track.request_id,
										.track_alias = session->video_track.track_alias,
										.group_id = session->video_track.group_id,
										.subgroup_id = 0,	/* FIXME */
										.object_id = session->video_track.object_id,
										.payload = NULL,
										.payload_len = 0,
										.properties = NULL,
										.delivery = IMQUIC_MOQ_USE_SUBGROUP,
										.end_of_stream = TRUE
									};
									imquic_moq_send_object(session->conn, &object);
								}
								session->video_track.group_id++;
								session->video_track.object_id = 0;
							}
						}
					}
					/* Frame manipulation: append the actual payload to the buffer */
					if(bytes > 0) {
						if(frame_len + bytes > canvas_size) {
							JANUS_LOG(LOG_WARN, "[%s] Frame exceeds buffer size...\n",
								imquic_get_connection_name(session->conn));
						} else {
							memcpy(received_frame + frame_len, buffer, bytes);
							frame_len += bytes;
						}
					}
				} else if(session->vcodec == JANUS_VIDEOCODEC_VP9) {
					/* Depacketize VP9 */
					JANUS_LOG(LOG_HUGE, "[%s] Depacketizing VP9 payload (%d bytes)\n",
						imquic_get_connection_name(session->conn), plen);
					/* Read the first octet (VP9 Payload Descriptor) */
					char *buffer = payload;
					int bytes = plen;
					uint8_t vp9pd = *buffer;
					uint8_t ibit = (vp9pd & 0x80);
					uint8_t pbit = (vp9pd & 0x40);
					uint8_t lbit = (vp9pd & 0x20);
					uint8_t fbit = (vp9pd & 0x10);
					uint8_t vbit = (vp9pd & 0x02);
					/* Move to the next octet and see what's there */
					buffer++;
					bytes--;
					if(ibit) {
						/* Read the PictureID octet */
						vp9pd = *buffer;
						uint16_t picid = vp9pd, wholepicid = picid;
						uint8_t mbit = (vp9pd & 0x80);
						if(!mbit) {
							buffer++;
							bytes--;
						} else {
							memcpy(&picid, buffer, sizeof(uint16_t));
							wholepicid = ntohs(picid);
							picid = (wholepicid & 0x7FFF);
							buffer += 2;
							bytes -= 2;
						}
					}
					if(lbit) {
						buffer++;
						bytes--;
						if(!fbit) {
							/* Non-flexible mode, skip TL0PICIDX */
							buffer++;
							bytes--;
						}
					}
					if(fbit && pbit) {
						/* Skip reference indices */
						uint8_t nbit = 1;
						while(nbit) {
							vp9pd = *buffer;
							nbit = (vp9pd & 0x01);
							buffer++;
							bytes--;
						}
					}
					if(vbit) {
						/* Parse and skip SS */
						vp9pd = *buffer;
						uint n_s = (vp9pd & 0xE0) >> 5;
						n_s++;
						uint8_t ybit = (vp9pd & 0x10);
						uint8_t gbit = (vp9pd & 0x08);
						if(ybit) {
							/* Iterate on all spatial layers and get resolution */
							buffer++;
							bytes--;
							uint i=0;
							gboolean kf = FALSE;
							for(i=0; i<n_s; i++) {
								buffer += 4;
								bytes -= 4;
								kf = TRUE;
							}
							if(kf) {
								/* This is a keyframe */
								key_frame = TRUE;
								if(!got_keyframe)
									got_keyframe = TRUE;
								JANUS_LOG(LOG_HUGE, "[%s]   -- Key frame (seq=%"SCNu16", ts=%"SCNu32")\n",
									imquic_get_connection_name(session->conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp));
								if(session->video_track.group_id > 0) {
									/* Close the previous stream first */
									imquic_moq_object object = {
										.request_id = session->video_track.request_id,
										.track_alias = session->video_track.track_alias,
										.group_id = session->video_track.group_id,
										.subgroup_id = 0,	/* FIXME */
										.object_id = session->video_track.object_id,
										.payload = NULL,
										.payload_len = 0,
										.properties = NULL,
										.delivery = IMQUIC_MOQ_USE_SUBGROUP,
										.end_of_stream = TRUE
									};
									imquic_moq_send_object(session->conn, &object);
								}
								session->video_track.group_id++;
								session->video_track.object_id = 0;
							}
						}
						if(gbit) {
							if(!ybit) {
								buffer++;
								bytes--;
							}
							uint8_t n_g = *buffer;
							buffer++;
							bytes--;
							if(n_g > 0) {
								uint i=0;
								for(i=0; i<n_g; i++) {
									/* Read the R bits */
									vp9pd = *buffer;
									int r = (vp9pd & 0x0C) >> 2;
									if(r > 0) {
										/* Skip reference indices */
										buffer += r;
										bytes -= r;
									}
									buffer++;
									bytes--;
								}
							}
						}
					}
					/* Frame manipulation: append the actual payload to the buffer */
					if(bytes > 0) {
						if(frame_len + bytes > canvas_size) {
							JANUS_LOG(LOG_WARN, "[%s] Frame exceeds buffer size...\n",
								imquic_get_connection_name(session->conn));
						} else {
							memcpy(received_frame + frame_len, buffer, bytes);
							frame_len += bytes;
						}
					}
				} else if(session->vcodec == JANUS_VIDEOCODEC_H264) {
					/* Depacketize H.264 */
					JANUS_LOG(LOG_HUGE, "[%s] Depacketizing H.264 payload (%d bytes)\n",
						imquic_get_connection_name(session->conn), plen);
					uint8_t fragment = *payload & 0x1F;
					uint8_t nal = *(payload+1) & 0x1F;
					uint8_t start_bit = *(payload+1) & 0x80;
					int len = plen, jump = 0;
					if(fragment == 7) {
						/* We're using AVCC, so create an extradata for the video config */
						char *temp = payload;
						temp++;
						int tot = len-1;
						extradata_len = janus_moq_h264_parse_sps(extradata,
							extradata_len, session->annexb, (uint8_t *)temp, tot, FALSE,
							&session->video_track.width, &session->video_track.height);
						JANUS_LOG(LOG_HUGE, "[%s]   -- Video has resolution %dx%d (%zu bytes of extradata)\n",
							imquic_get_connection_name(session->conn),
							session->video_track.width, session->video_track.height, extradata_len);
					}
					if(fragment == 24) {
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
								/* We're using AVCC, so create an extradata for the video config */
								extradata_len = janus_moq_h264_parse_sps(extradata,
									extradata_len, session->annexb, (uint8_t *)temp - 2, tot + 2, TRUE,
									&session->video_track.width, &session->video_track.height);
								JANUS_LOG(LOG_HUGE, "[%s]   -- Video has resolution %dx%d (%zu bytes of extradata)\n",
									imquic_get_connection_name(session->conn),
									session->video_track.width, session->video_track.height, extradata_len);
							}
							temp += psize;
							tot -= psize;
						}
						len = tot;
					}
					if(fragment == 28 || fragment == 29) {
						JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d, NAL=%d, Start=%d (len=%d, frame_len=%zu)\n",
							imquic_get_connection_name(session->conn), fragment, nal, start_bit, len, frame_len);
					} else {
						JANUS_LOG(LOG_HUGE, "[%s]   -- Fragment=%d (len=%d, frame_len=%zu)\n",
							imquic_get_connection_name(session->conn), fragment, len, frame_len);
					}
					if(fragment == 5 ||
							((fragment == 28 || fragment == 29) && nal == 5 && start_bit == 128)) {
						key_frame = TRUE;
						if(!got_keyframe)
							got_keyframe = TRUE;
						JANUS_LOG(LOG_HUGE, "[%s]   -- Key frame (seq=%"SCNu16", ts=%"SCNu32", fragment=%d)\n",
							imquic_get_connection_name(session->conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), fragment);
						if(session->video_track.group_id > 0) {
							/* Close the previous stream first */
							imquic_moq_object object = {
								.request_id = session->video_track.request_id,
								.track_alias = session->video_track.track_alias,
								.group_id = session->video_track.group_id,
								.subgroup_id = 0,	/* FIXME */
								.object_id = session->video_track.object_id,
								.payload = NULL,
								.payload_len = 0,
								.properties = NULL,
								.delivery = IMQUIC_MOQ_USE_SUBGROUP,
								.end_of_stream = TRUE
							};
							imquic_moq_send_object(session->conn, &object);
						}
						session->video_track.group_id++;
						session->video_track.object_id = 0;
					}
					/* Frame manipulation */
					if((fragment > 0) && (fragment < 24)) {
						/* Add a start code */
						JANUS_LOG(LOG_HUGE, "[%s]   -- -- Adding a start code (fragment=%d)\n",
							imquic_get_connection_name(session->conn), fragment);
						uint8_t *temp = received_frame + frame_len;
						memset(temp, 0x00, 1);
						memset(temp + 1, 0x00, 1);
						memset(temp + 2, 0x00, 1);
						memset(temp + 3, 0x01, 1);
						if(!session->annexb && nal_added) {
							uint32_t nal_size = frame_len - nal_offset - 4;
							JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
								imquic_get_connection_name(session->conn), nal_size);
							nal_size = htonl(nal_size);
							memcpy(received_frame + nal_offset, &nal_size, 4);
						}
						if(!session->annexb && !nal_added)
							nal_added = TRUE;
						nal_offset = frame_len;
						frame_len += 4;
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
							uint8_t *temp = received_frame + frame_len;
							memset(temp, 0x00, 1);
							memset(temp + 1, 0x00, 1);
							memset(temp + 2, 0x00, 1);
							memset(temp + 3, 0x01, 1);
							if(!session->annexb && nal_added) {
								uint32_t nal_size = frame_len - nal_offset - 4;
								JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
									imquic_get_connection_name(session->conn), nal_size);
								nal_size = htonl(nal_size);
								memcpy(received_frame + nal_offset, &nal_size, 4);
							}
							if(!session->annexb && !nal_added)
								nal_added = TRUE;
							nal_offset = frame_len;
							frame_len += 4;
							memcpy(received_frame + frame_len, payload, psize);
							frame_len += psize;
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
							uint8_t *temp = received_frame + frame_len;
							memset(temp, 0x00, 1);
							memset(temp + 1, 0x00, 1);
							memset(temp + 2, 0x00, 1);
							memset(temp + 3, 0x01, 1);
							memset(temp + 4, (indicator & 0xE0) | (header & 0x1F), 1);
							if(!session->annexb && nal_added) {
								uint32_t nal_size = frame_len - nal_offset - 4;
								JANUS_LOG(LOG_HUGE, "[%s]  -- NAL has size %"SCNu32"\n",
									imquic_get_connection_name(session->conn), nal_size);
								nal_size = htonl(nal_size);
								memcpy(received_frame + nal_offset, &nal_size, 4);
							}
							if(!session->annexb && !nal_added)
								nal_added = TRUE;
							nal_offset = frame_len;
							frame_len += 5;
						} else if (header & 0x40) {
							/* Last part of fragmented packet (E bit set) */
						}
					}
					/* Frame manipulation: append the actual payload to the buffer */
					if(len > 0) {
						if(frame_len + len > canvas_size) {
							JANUS_LOG(LOG_WARN, "[%s] Frame exceeds buffer size...\n",
								imquic_get_connection_name(session->conn));
						} else {
							memcpy(received_frame + frame_len, payload+jump, len);
							frame_len += len;
						}
					}
				} else if(session->vcodec == JANUS_VIDEOCODEC_AV1) {
					/* Depacketize AV1 */
					JANUS_LOG(LOG_HUGE, "[%s] Depacketizing AV1 payload (%d bytes)\n",
						imquic_get_connection_name(session->conn), plen);
					char *buffer = payload;
					int len = plen;
					uint8_t aggrh = *buffer;
					uint8_t zbit = (aggrh & 0x80) >> 7;
					uint8_t ybit = (aggrh & 0x40) >> 6;
					uint8_t w = (aggrh & 0x30) >> 4;
					uint8_t nbit = (aggrh & 0x08) >> 3;
					JANUS_LOG(LOG_HUGE, "[%s]  -- OBU aggregation header: z=%u, y=%u, w=%u, n=%u\n",
						imquic_get_connection_name(session->conn), zbit, ybit, w, nbit);
					/* FIXME Ugly hack: we consider a packet with Z=0 and N=1 a keyframe */
					key_frame = (!zbit && nbit);
					if(key_frame && !got_keyframe)
						got_keyframe = TRUE;
					buffer++;
					len--;
					uint8_t obus = 0;
					uint32_t obusize = 0;
					while(!zbit && len > 0) {
						obus++;
						if(w == 0 || w > obus) {
							/* Read the OBU size (leb128) */
							size_t read = 0;
							obusize = janus_moq_av1_lev128_decode((uint8_t *)buffer, len, &read);
							buffer += read;
							len -= read;
						} else {
							obusize = len;
						}
						/* Then we have the OBU header */
						char *payload = buffer;
						uint8_t obuh = *payload;
						uint8_t fbit = (obuh & 0x80) >> 7;
						uint8_t type = (obuh & 0x78) >> 3;
						uint8_t ebit = (obuh & 0x04) >> 2;
						uint8_t sbit = (obuh & 0x02) >> 1;
						JANUS_LOG(LOG_HUGE, "[%s]  -- OBU header: f=%u, type=%u, e=%u, s=%u\n",
							imquic_get_connection_name(session->conn), fbit, type, ebit, sbit);
						if(ebit) {
							/* Skip the extension, if present */
							payload++;
							len--;
							obusize--;
						}
						if(type == 1) {
							/* Sequence header */
							uint16_t av1w = 0, av1h = 0;
							/* TODO Fix currently broken parsing of SH */
							janus_moq_av1_parse_sh(payload+1, &av1w, &av1h);
							if(session->video_track.width != av1w || session->video_track.height != av1h) {
								/* It is: take note of the new resolution */
								JANUS_LOG(LOG_INFO, "[%s] AV1 resolution changed (was %dx%d, now is %dx%d)\n",
									imquic_get_connection_name(session->conn),
									session->video_track.width, session->video_track.height, av1w, av1h);
								session->video_track.width = av1w;
								session->video_track.height = av1h;
							}
						}
						/* Update the OBU header to set the S bit */
						obuh = *buffer;
						obuh |= (1 << 1);
						JANUS_LOG(LOG_HUGE, "[%s] OBU header: 1\n",
							imquic_get_connection_name(session->conn));
						memcpy(received_frame + frame_len, &obuh, sizeof(uint8_t));
						frame_len++;
						buffer++;
						len--;
						obusize--;
						if(w == 0 || w > obus || !ybit) {
							/* We have the whole OBU, write the OBU size */
							size_t written = 0;
							uint8_t leb[8];
							janus_moq_av1_lev128_encode(obusize, leb, &written);
							JANUS_LOG(LOG_HUGE, "[%s] OBU size (%"SCNu32"): %zu\n",
								imquic_get_connection_name(session->conn), obusize, written);
							memcpy(received_frame + frame_len, leb, written);
							frame_len += written;
							/* Copy the actual data */
							JANUS_LOG(LOG_HUGE, "[%s] OBU data: %"SCNu32"\n",
								imquic_get_connection_name(session->conn), obusize);
							memcpy(received_frame + frame_len, buffer, obusize);
							frame_len += obusize;
						} else {
							/* OBU will continue in another packet, buffer the data */
							JANUS_LOG(LOG_HUGE, "[%s] OBU data (part.): %d\n",
								imquic_get_connection_name(session->conn), obusize);
							memcpy(obu_data + data_len, buffer, obusize);
							data_len += obusize;
						}
						/* Move to the next OBU, if any */
						buffer += obusize;
						len -= obusize;
					}
					/* Frame manipulation */
					if(data_len > 0) {
						if(frame_len + len > canvas_size) {
							JANUS_LOG(LOG_WARN, "[%s] Frame exceeds buffer size...\n",
								imquic_get_connection_name(session->conn));
						} else {
							JANUS_LOG(LOG_HUGE, "[%s] OBU data (cont.): %d\n",
								imquic_get_connection_name(session->conn), len);
							memcpy(obu_data + data_len, buffer, len);
							data_len += len;
						}
					}
				}
				/* Get rid of the buffered packet */
				janus_moq_buffer_packet_destroy(pkt);
			}
		}
	}

	JANUS_LOG(LOG_INFO, "[%s] Leaving session thread\n",
		imquic_get_connection_name(session->conn));

	/* Cleanup resources */
	g_free(received_frame);
	/* Remove the reference to the session that the thread had */
	janus_refcount_decrease(&session->ref);

	g_thread_unref(g_thread_self());
	return NULL;
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
	/* If there's an imquic endpoint running, get rid of it */
	if(session->quic_endpoint != NULL)
		imquic_shutdown_endpoint(session->quic_endpoint);
	session->quic_endpoint = NULL;
	imquic_moq_catalog_destroy(session->catalog);
	imquic_moq_namespace_free(session->track_namespace);
	g_free(session->track_namespace_str);
	session->track_namespace = NULL;
	session->track_namespace_str = NULL;
	g_free(session->auth_info);
	session->auth_info = NULL;
	session->catalog = NULL;
	imquic_moq_track_free(session->catalog_track.track);
	g_free(session->catalog_track.track_name);
	memset(&session->catalog_track, 0, sizeof(session->catalog_track));
	imquic_moq_track_free(session->audio_track.track);
	g_free(session->audio_track.track_name);
	memset(&session->audio_track, 0, sizeof(session->audio_track));
	imquic_moq_track_free(session->video_track.track);
	g_free(session->video_track.track_name);
	memset(&session->video_track, 0, sizeof(session->video_track));
	janus_mutex_lock(&session->mutex);
	if(session->audio_buffered_packets)
		g_queue_clear_full(session->audio_buffered_packets, (GDestroyNotify)janus_moq_buffer_packet_destroy);
	if(session->video_buffered_packets)
		g_queue_clear_full(session->video_buffered_packets, (GDestroyNotify)janus_moq_buffer_packet_destroy);
	janus_mutex_unlock(&session->mutex);
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	int ret = gateway->push_event(handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
	g_atomic_int_set(&session->hangup, 1);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_moq_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining MoQ handler thread\n");
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
			/* Initiate the imquic endpoint */
			uint16_t port = json_integer_value(json_object_get(root, "port"));
			const char *remote_host = json_string_value(json_object_get(root, "remote_host"));
			uint16_t remote_port = json_integer_value(json_object_get(root, "remote_port"));
			gboolean raw_quic = json_object_get(root, "rawquic") ?
				json_is_true(json_object_get(root, "rawquic")) : TRUE;
			gboolean webtransport = json_object_get(root, "webtransport") ?
				json_is_true(json_object_get(root, "webtransport")) : TRUE;
			if(!raw_quic && !webtransport)
				raw_quic = TRUE;
			const char *path = json_string_value(json_object_get(root, "path"));
			const char *role = json_string_value(json_object_get(root, "role"));
			json_t *namespace = json_object_get(root, "namespace");
			json_t *uc = json_object_get(root, "use_catalog");
			gboolean use_catalog = uc ? json_is_true(uc) : TRUE;
			const char *audio_track = json_string_value(json_object_get(root, "audio_track"));
			const char *video_track = json_string_value(json_object_get(root, "video_track"));
			const char *video_codec = json_string_value(json_object_get(root, "video_codec"));
			json_t *ab = json_object_get(root, "annexb");
			gboolean annexb = ab ? json_is_true(ab) : FALSE;
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
			size_t i = 0;
			for(i=0; i<json_array_size(namespace); i++) {
				json_t *n = json_array_get(namespace, i);
				if(n == NULL || json_is_null(n) || !json_is_string(n)) {
					/* Invalid namespace */
					janus_mutex_unlock(&session->mutex);
					JANUS_LOG(LOG_ERR, "Invalid MoQ namespace field\n");
					error_code = JANUS_MOQ_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid MoQ namespace field");
					goto error;
				}
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
			/* Check if we're overriding the video codec */
			if(video_codec && (moqpub || (moqsub && !use_catalog))) {
				janus_videocodec vcodec = janus_videocodec_from_name(video_codec);
				if(vcodec == JANUS_VIDEOCODEC_NONE || vcodec == JANUS_VIDEOCODEC_AV1) {
					/* Unsupported video codec */
					janus_mutex_unlock(&session->mutex);
					JANUS_LOG(LOG_ERR, "Unsupported video codec\n");
					error_code = JANUS_MOQ_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Unsupported video codec");
					goto error;
				}
				session->vcodec = vcodec;
			}
			session->annexb = annexb;	/* Ignored unless it's H.264 */
			char name[50];
			/* Create the imquic endpoint (client) */
			imquic_endpoint *quic_endpoint = NULL;
			session->moqpub = moqpub;
			session->moqsub = moqsub;
			session->use_catalog = moqsub && use_catalog;
			/* FIXME We don't currently support providing a tuple */
			imquic_moq_namespace *last = NULL;
			for(i=0; i<json_array_size(namespace); i++) {
				const char *n = json_string_value(json_array_get(namespace, i));
				imquic_moq_namespace *tns = g_malloc(sizeof(imquic_moq_namespace));
				tns->length = strlen(n);
				if(tns->length > 0) {
					tns->buffer = g_malloc(tns->length);
					memcpy(tns->buffer, n, tns->length);
				}
				tns->next = NULL;
				if(session->track_namespace == NULL)
					session->track_namespace = tns;
				if(last)
					last->next = tns;
				last = tns;
			}
			char tns_buf[4096];
			const char *tns = imquic_moq_namespace_str(session->track_namespace, tns_buf, sizeof(tns_buf), TRUE);
			session->track_namespace_str = tns ? g_strdup(tns) : NULL;
			/* Catalog track */
			memset(&session->catalog_track, 0, sizeof(session->catalog_track));
			const char *catalog = "catalog";
			session->catalog_track.track = imquic_moq_track_create((uint8_t *)catalog, strlen(catalog));
			session->catalog_track.track_name = g_strdup(catalog);
			/* Audio track, if any */
			memset(&session->audio_track, 0, sizeof(session->audio_track));
			if(audio_track != NULL && (moqpub || (moqsub && !use_catalog))) {
				session->audio_track.track = imquic_moq_track_create((uint8_t *)audio_track, strlen(audio_track));
				char tn_buf[4096];
				const char *tn = imquic_moq_track_str(session->audio_track.track, tn_buf, sizeof(tn_buf));
				session->audio_track.track_name = tn ? g_strdup(tn) : NULL;
				session->audio_track.ssrc = janus_random_uint32();
			}
			/* Video track, if any */
			memset(&session->video_track, 0, sizeof(session->video_track));
			if(video_track != NULL && (moqpub || (moqsub && !use_catalog))) {
				session->video_track.track = imquic_moq_track_create((uint8_t *)video_track, strlen(video_track));
				char tn_buf[4096];
				const char *tn = imquic_moq_track_str(session->video_track.track, tn_buf, sizeof(tn_buf));
				session->video_track.track_name = tn ? g_strdup(tn) : NULL;
				session->video_track.ssrc = janus_random_uint32();
			}
			session->auth_info = auth_info ? g_strdup(auth_info) : NULL;
			g_snprintf(name, sizeof(name), "janus-moq%s-%"SCNu32,
				session->moqpub ? "pub" : "sub", janus_random_uint32());
			JANUS_LOG(LOG_INFO, "Creating new MoQ client (%s, %sraw QUIC, %sWebTransport)\n",
				session->moqpub ? "publisher" : "subscriber",
				raw_quic ? "" : "no ", webtransport ? "" : "no ");
			quic_endpoint = imquic_create_moq_client(name,
				IMQUIC_CONFIG_INIT,
				IMQUIC_CONFIG_LOCAL_PORT, port,
				IMQUIC_CONFIG_REMOTE_HOST, remote_host,
				IMQUIC_CONFIG_REMOTE_PORT, remote_port,
				IMQUIC_CONFIG_RAW_QUIC, raw_quic,
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
				imquic_set_request_updated_cb(quic_endpoint, janus_moq_moq_request_updated);
				imquic_set_connection_failed_cb(quic_endpoint, janus_moq_connection_failed);
				imquic_set_moq_connection_gone_cb(quic_endpoint, janus_moq_connection_gone);
			} else if(session->moqsub) {
				imquic_set_new_moq_connection_cb(quic_endpoint, janus_moq_new_connection);
				imquic_set_moq_ready_cb(quic_endpoint, janus_moq_moq_ready);
				imquic_set_subscribe_accepted_cb(quic_endpoint, janus_moq_moq_subscribe_accepted);
				imquic_set_subscribe_error_cb(quic_endpoint, janus_moq_moq_subscribe_error);
				imquic_set_publish_done_cb(quic_endpoint, janus_moq_moq_publish_done);
				imquic_set_incoming_object_cb(quic_endpoint, janus_moq_moq_incoming_object);
				imquic_set_connection_failed_cb(quic_endpoint, janus_moq_connection_failed);
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
								JANUS_SDP_OA_DIRECTION, JANUS_SDP_RECVONLY,
								JANUS_SDP_OA_CODEC, (m->type == JANUS_SDP_VIDEO ?
									janus_videocodec_name(session->vcodec) : janus_audiocodec_name(JANUS_AUDIOCODEC_OPUS)),
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
				if(session->catalog == NULL) {
					session->catalog = imquic_moq_catalog_create("draft-01");
					if(session->audio_track.track != NULL) {
						/* FIXME Add the audio track to the catalog */
						imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(session->track_namespace_str,
							session->audio_track.track_name, "loc", TRUE);
						track->role = g_strdup("audio");
						track->render_group = 1;
						track->target_latency = 200;
						track->codec = g_strdup("opus");
						track->samplerate = 48000;
						imquic_moq_catalog_add_track(session->catalog, track);
					}
					if(session->video_track.track != NULL && session->vcodec != JANUS_VIDEOCODEC_NONE) {
						/* FIXME Add the video track to the catalog */
						imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(session->track_namespace_str,
							session->video_track.track_name, "loc", TRUE);
						track->role = g_strdup("video");
						track->render_group = 1;
						track->target_latency = 200;
						/* FIXME Codec name */
						if(session->vcodec == JANUS_VIDEOCODEC_H264)
							track->codec = g_strdup(session->annexb ? "annexb.42001F" : "avc1.42001F");
						else
							track->codec = g_strdup(janus_videocodec_name(session->vcodec));
						imquic_moq_catalog_add_track(session->catalog, track);
					}
				}
				localjsep = json_pack("{ssss}", "type", "answer", "sdp", sdp);
				g_free(sdp);
				/* Finally, we spawn a thread we'll use to process audio/video frames */
				g_atomic_int_set(&session->hangup, 0);
				janus_refcount_increase(&session->ref);
				GError *thread_error = NULL;
				session->thread = g_thread_try_new(name, &janus_moq_processing_thread, session, &thread_error);
				if(thread_error != NULL) {
					/* FIXME We ignore this error for now, should we? */
					JANUS_LOG(LOG_ERR, "[%s] Got error %d (%s) trying to launch the thread...\n",
						imquic_get_connection_name(session->conn), thread_error->code, thread_error->message ? thread_error->message : "??");
					janus_refcount_decrease(&session->ref);
					g_error_free(thread_error);
				}
			}
			/* Send an answer back to the browser */
			result = json_object();
			json_object_set_new(result, "event", json_string("bridging"));
			if(moqpub) {
				json_t *json = imquic_moq_catalog_serialize_obj(session->catalog);
				json_object_set_new(result, "catalog", json);
			};
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
	JANUS_LOG(LOG_VERB, "Leaving MoQ handler thread\n");
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

static void janus_moq_connection_failed(void *user_data) {
	janus_moq_session *session = (janus_moq_session *)user_data;
	if(session == NULL)
		return;
	/* Connection has failed */
	JANUS_LOG(LOG_INFO, "Connection failed\n");
	/* Notify the application */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
	json_object_set_new(event, "error_space", json_string("connection"));
	json_object_set_new(event, "error_code", json_integer(0));
	json_object_set_new(event, "error", json_string("Connection failed"));
	int ret = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
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
	/* Notify the application */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
	json_object_set_new(event, "error_space", json_string("connection"));
	json_object_set_new(event, "error_code", json_integer(error_code));
	if(reason)
		json_object_set_new(event, "error", json_string(reason));
	int ret = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
	janus_refcount_decrease(&session->ref);
}

/* MoQ Specific */
static void janus_moq_moq_ready(imquic_connection *conn) {
	/* MoQ negotiation was done */
	JANUS_LOG(LOG_INFO, "[%s] MoQ connection ready\n", imquic_get_connection_name(conn));
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
	JANUS_LOG(LOG_INFO, "[%s] Connected as a MoQ %s\n", imquic_get_connection_name(conn), session->moqpub ? "publisher" : "subscriber");
	imquic_moq_request_parameters params;
	imquic_moq_request_parameters_init_defaults(&params);
	if(session->auth_info) {
		/* Serialize the token using the USE_VALUE alias type */
		params.auth_token_set = TRUE;
		params.auth_token_len = sizeof(params.auth_token);
		imquic_moq_auth_token token = { 0 };
		token.alias_type = IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE;
		token.token_type_set = TRUE;
		token.token_type = 0;	/* FIXME */
		token.token_value.buffer = (uint8_t *)session->auth_info;
		token.token_value.length = strlen(session->auth_info);
		size_t offset = imquic_moq_build_auth_token(imquic_moq_get_version(conn),
			&token, params.auth_token, params.auth_token_len);
		if(offset == 0) {
			params.auth_token_set = FALSE;
			JANUS_LOG(LOG_WARN, "[%s] Error serializing the auth token\n",
				imquic_get_connection_name(conn));
		}
		params.auth_token_len = offset;
	}
	if(session->moqpub) {
		/* Let's publish_namespace our namespace */
		JANUS_LOG(LOG_INFO, "[%s] Announcing namespace '%s'\n", imquic_get_connection_name(conn), session->track_namespace_str);
		imquic_moq_publish_namespace(conn, imquic_moq_get_next_request_id(conn), session->track_namespace, &params);
	} else {
		/* Let's subscribe to the catalog track: we may want to only subscribe
		 * to the audio/video track when we've obtained a catalog back */
		/* Catalog track */
		session->catalog_track.request_id = imquic_moq_get_next_request_id(conn);
		JANUS_LOG(LOG_INFO, "[%s] Subscribing to %s--%s, using ID %"SCNu64"\n", imquic_get_connection_name(conn),
			session->track_namespace_str, session->catalog_track.track_name, session->catalog_track.request_id);
		imquic_moq_subscribe(conn, session->catalog_track.request_id, session->track_namespace, session->catalog_track.track, &params);
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
			if(session->catalog_orig) {
				json_t *catalog = json_loads(session->catalog_orig, 0, NULL);
				json_object_set_new(result, "catalog", catalog);
			}
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
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
	/* Notify the application */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
	json_object_set_new(event, "error_space", json_string("publish_namespace"));
	json_object_set_new(event, "error_code", json_integer(error_code));
	if(reason)
		json_object_set_new(event, "error", json_string(reason));
	int ret = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
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
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
	if(session->track_namespace == NULL || !imquic_moq_namespace_equals(tns, session->track_namespace)) {
		JANUS_LOG(LOG_WARN, "Unknown namespace '%s'\n", namespace);
		return;
	}
	if(session->catalog_track.track && imquic_moq_track_equals(tn, session->catalog_track.track)) {
		/* Catalog track, accept the subscription */
		session->catalog_track.request_id = request_id;
		session->catalog_track.track_alias = 0;
		imquic_moq_accept_subscribe(conn, request_id, session->catalog_track.track_alias, NULL, NULL);
		/* Mark the track as active */
		session->catalog_track.active = TRUE;
		return;
	}
	/* Audio or video */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	if(session->audio_track.track && imquic_moq_track_equals(tn, session->audio_track.track)) {
		/* Subscription for the audio track */
		session->audio_track.request_id = request_id;
		session->audio_track.track_alias = 1;
		imquic_moq_accept_subscribe(conn, request_id, session->audio_track.track_alias, &rparams, NULL);
		/* Mark the track as active */
		session->audio_track.active = TRUE;
	} else if(session->video_track.track && imquic_moq_track_equals(tn, session->video_track.track)) {
		/* Subscription for the video track */
		session->video_track.request_id = request_id;
		session->video_track.track_alias = 2;
		/* Advertise support for DYNAMIC_GROUPS: if we receive a
		 * NEW_GROUP_REQUEST, we'll send an RTCP PLI via WebRTC */
		imquic_moq_property dynamic_groups = {
			.id = IMQUIC_MOQ_PROPERTY_DYNAMIC_GROUPS,
			.value = {
				.number = 1
			}
		};
		GList *props = g_list_append(NULL, &dynamic_groups);
		imquic_moq_accept_subscribe(conn, request_id, session->video_track.track_alias, &rparams, props);
		g_list_free(props);
		/* Mark the track as active */
		session->video_track.active = TRUE;
	} else {
		JANUS_LOG(LOG_WARN, "Unknown track '%s'\n", track);
	}
}

static void janus_moq_moq_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	JANUS_LOG(LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), request_id);
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
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
		session->pli_latest = 0;
	}
}

static void janus_moq_moq_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_request_parameters *parameters, GList *track_extensions) {
	JANUS_LOG(LOG_INFO, "[%s] Subscription %"SCNu64" accepted\n",
		imquic_get_connection_name(conn), request_id);
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
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
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
	/* Notify the application */
	json_t *event = json_object();
	json_object_set_new(event, "moq", json_string("event"));
	json_object_set_new(event, "error_space", json_string("subscribe"));
	json_object_set_new(event, "error_code", json_integer(error_code));
	if(reason)
		json_object_set_new(event, "error", json_string(reason));
	int ret = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(event);
}

static void janus_moq_moq_request_updated(imquic_connection *conn, uint64_t request_id,
		uint64_t sub_request_id, imquic_moq_request_parameters *parameters) {
	JANUS_LOG(LOG_INFO, "[%s] Incoming update (%"SCNu64") for request %"SCNu64"\n",
		imquic_get_connection_name(conn), request_id, sub_request_id);
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed) || !session->moqpub) {
		janus_mutex_unlock(&connections_mutex);
		JANUS_LOG(LOG_WARN, "[%s] Ignoring REQUEST_UPDATE, unrecognized subscription\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_request_update(conn, request_id,
			IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "No such subscription", 0, NULL);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
	/* Check if it's a NEW_GROUP_REQUEST for the video track */
	if(parameters->new_group_request_set && parameters->new_group_request &&
			session->video_track.active && session->video_track.request_id == sub_request_id) {
		/* Send a PLI */
		JANUS_LOG(LOG_INFO, "[%s] Got a NEW_GROUP_REQUEST, sending PLI\n",
			imquic_get_connection_name(conn));
		gateway->send_pli(session->handle);
		session->pli_latest = janus_get_monotonic_time();
	}
	/* FIXME We always send a REQUEST_OK back, but we should check if we
	 * actually recognize the request ID the update is for */
	imquic_moq_accept_request_update(conn, request_id, NULL);
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
	janus_mutex_lock(&connections_mutex);
	janus_moq_session *session = g_hash_table_lookup(connections, conn);
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&connections_mutex);
		return;
	}
	janus_mutex_unlock(&connections_mutex);
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
		if(session->catalog == NULL) {
			/* Something went wrong */
			g_free(json);
			return;
		}
		session->catalog_orig = g_strdup(json);
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
					session->audio_track.track = imquic_moq_track_from_str(track->track_name);
					if(session->audio_track.track == NULL || !imquic_moq_track_is_valid(session->audio_track.track)) {
						/* Unsupported codec */
						JANUS_LOG(LOG_WARN, "Invalid audio track '%s', skipping audio subscription\n", track->track_name);
						imquic_moq_track_free(session->audio_track.track);
						session->audio_track.track = NULL;
						temp = temp->next;
						continue;
					}
					session->audio_track.track_name = g_strdup(track->track_name);
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
					if(track->codec) {
						if(strstr(track->codec, "avc1") != NULL) {
							session->vcodec = JANUS_VIDEOCODEC_H264;
							session->annexb = FALSE;
						} else if(strstr(track->codec, "annexb") != NULL) {
							session->vcodec = JANUS_VIDEOCODEC_H264;
							session->annexb = TRUE;
						} else if(strstr(track->codec, "vp8") != NULL) {
							session->vcodec = JANUS_VIDEOCODEC_VP8;
						} else if(strstr(track->codec, "vp9") != NULL) {
							session->vcodec = JANUS_VIDEOCODEC_VP9;
						}
					}
					if(session->vcodec == JANUS_VIDEOCODEC_NONE || session->vcodec == JANUS_VIDEOCODEC_AV1) {
						/* Unsupported codec */
						JANUS_LOG(LOG_WARN, "Unsupported video codec '%s', skipping video subscription\n", track->codec);
						temp = temp->next;
						continue;
					}
					session->video_track.track = imquic_moq_track_from_str(track->track_name);
					if(session->video_track.track == NULL || !imquic_moq_track_is_valid(session->video_track.track)) {
						/* Unsupported codec */
						JANUS_LOG(LOG_WARN, "Invalid video track '%s', skipping video subscription\n", track->track_name);
						imquic_moq_track_free(session->video_track.track);
						session->video_track.track = NULL;
						temp = temp->next;
						continue;
					}
					session->video_track.track_name = g_strdup(track->track_name);
					session->video_track.ssrc = janus_random_uint32();
					session->video_pt = janus_videocodec_pt(session->vcodec);
					janus_sdp_generate_offer_mline(offer,
						JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
						JANUS_SDP_OA_MID, "v",
						JANUS_SDP_OA_PT, session->video_pt,
						JANUS_SDP_OA_CODEC, janus_videocodec_name(session->vcodec),
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
			json_t *catalog = json_loads(session->catalog_orig, 0, NULL);
			json_object_set_new(result, "catalog", catalog);
			json_object_set_new(event, "result", result);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(session->handle, &janus_moq_plugin, NULL, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n", res, janus_get_monotonic_time()-start);
			json_decref(event);
			json_decref(jsep);
		}
		g_free(json);
		return;
	}
	if((session->audio_track.track && object->track_alias != session->audio_track.track_alias) &&
			(session->video_track.track && object->track_alias != session->video_track.track_alias)) {
		/* We don't know this track alias (yet?), for now we drop the object
		 * but we should really buffer it (it may be, e.g., a video keyframe) */
		JANUS_LOG(LOG_WARN, "[%s] Unknown track_alias %"SCNu64", dropping object\n",
			imquic_get_connection_name(conn), object->track_alias);
		return;
	}
	/* FIXME Assuming LOC from https://www.ietf.org/archive/id/draft-ietf-moq-loc-02.html */
	uint64_t timestamp = 0, timescale = 0;
	struct imquic_moq_property_data *loc_extradata = NULL;
	/* Parse the properties to get access to the LOC info */
	JANUS_LOG(LOG_HUGE, "[%s] Processing %d properties:\n",
		imquic_get_connection_name(conn), num_props);
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
	/* FIXME We currently require the timestamp to be in the properties */
	if(object->payload == NULL || object->payload_len == 0)
		return;
	/* TODO Check if there are private properties too */
	if(*(object->payload) != 0x00) {
		JANUS_LOG(LOG_WARN, "We don't support private properties yet, ignoring object\n");
		return;
	}
	size_t skip = 1;
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
		size_t length = hsize + object->payload_len - skip;
		/* Craft the RTP packet */
		if(session->audio_track.seq == 0) {
			session->audio_track.timestamp = timestamp;
			session->audio_track.timestamp_start = timestamp;
		}
		uint64_t lts_diff = (timestamp >= session->audio_track.timestamp) ?
			timestamp - session->audio_track.timestamp : 0;
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
		memcpy(&buffer[hsize], object->payload + skip, object->payload_len - skip);
		/* Send the RTP packet */
		janus_plugin_rtp pkt = { .mindex = -1, .video = FALSE, .buffer = buffer, .length = length };
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
		uint64_t lts_diff = (timestamp >= session->video_track.timestamp) ?
			timestamp - session->video_track.timestamp : 0;
		uint32_t ts_diff = lts_diff ? (90000 / (G_USEC_PER_SEC / lts_diff)) : 0;
		session->video_track.timestamp = timestamp;
		janus_rtp_header *rtp = (janus_rtp_header *)buffer;
		rtp->version = 2;
		rtp->markerbit = 0;	/* Should be 1 for the last packet of a frame */
		rtp->type = pt;
		/* FIXME This is quite broken now */
		session->video_track.last_ts += ts_diff;
		rtp->timestamp = htonl(session->video_track.last_ts);
		rtp->ssrc = htonl(session->video_track.ssrc);
		/* Create all the RTP packets we need */
		uint8_t *payload = object->payload + skip;
		size_t payload_len = object->payload_len - skip;
		uint8_t *data = payload + skip, *start = data, *end = payload + payload_len, *tmp = start;
		/* Packetization depends on the codec */
		if(session->vcodec == JANUS_VIDEOCODEC_VP8) {
			/* We're using VP8 */
			session->pid++;
			if(session->pid == 32768)	/* PictureID is limited to 15 bits */
				session->pid = 0;
			/* Check if we need to split the frame in multiple RTP packets */
			if(payload_len < mtu) {
				JANUS_LOG(LOG_HUGE, "[%s] Sending packet, payload is %zu bytes\n",
					imquic_get_connection_name(conn), payload_len);
				/* Add a payload descriptor: first octet */
				char *pd = buffer+hsize;
				*pd |= 1 << 7;		/* X=1 */
				*pd |= 1 << 4;		/* S=1 */
				hsize++;
				/* Second octet */
				pd++;
				*pd |= 1 << 7;		/* I=1 */
				hsize++;
				/* Third and fourth octet */
				pd++;
				uint16_t cpid = htons(session->pid);
				memcpy(pd, &cpid, sizeof(uint16_t));
				*pd |= 1 << 7;		/* M=1 */
				hsize += 2;
				/* Copy the frame data now */
				memcpy(buffer + hsize, data, payload_len);
				/* Self-contained packet, set the Marker Bit to 1 */
				rtp->markerbit = 1;
				/* Send the packet */
				length = hsize + payload_len;
				session->video_track.seq++;
				rtp->seq_number = htons(session->video_track.seq);
				janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
				janus_plugin_rtp_extensions_reset(&pkt.extensions);
				gateway->relay_rtp(session->handle, &pkt);
			} else {
				size_t rest_len = payload_len, first_byte = 0, packet_len = 0;
				JANUS_LOG(LOG_HUGE, "[%s] Sending all that remains, payload is %zu bytes\n",
					imquic_get_connection_name(conn), rest_len);
				while(rest_len > 0) {
					/* Take part of the whole frame: not more than 'mtu' bytes */
					packet_len = rest_len;
					if(rest_len > mtu)
						packet_len = mtu;
					JANUS_LOG(LOG_HUGE, "[%s] Sending packet, payload is %zu/%zu bytes\n",
						imquic_get_connection_name(conn), packet_len, payload_len);
					/* Add a payload descriptor: first octet */
					hsize = 12;
					memset(buffer + hsize, 0, 4);
					char *pd = buffer + hsize;
					*pd = 0;
					*pd |= 1 << 7;		/* X=1 */
					if(rest_len == payload_len)
						*pd |= 1 << 4;	/* S=1 only for the first packet */
					hsize++;
					/* Second octet */
					pd++;
					*pd |= 1 << 7;		/* I=1 */
					hsize++;
					/* Third and fourth octet */
					pd++;
					if(rest_len == payload_len) {
						uint16_t cpid = htons(session->pid);
						memcpy(pd, &cpid, sizeof(uint16_t));
					}
					*pd |= 1 << 7;		/* M=1 */
					hsize += 2;
					/* Copy the frame data now */
					memcpy(buffer + hsize, payload + first_byte, packet_len);
					/* Update counters */
					first_byte += packet_len;
					rest_len -= packet_len;
					/* Marker Bit depends on whether this is the last packet or not */
					rtp->markerbit = rest_len > 0 ? 0 : 1;
					/* Send the packet */
					length = hsize + packet_len;
					session->video_track.seq++;
					rtp->seq_number = htons(session->video_track.seq);
					janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
					janus_plugin_rtp_extensions_reset(&pkt.extensions);
					gateway->relay_rtp(session->handle, &pkt);
				}
			}
		} else if(session->vcodec == JANUS_VIDEOCODEC_VP9) {
			/* We're using VP9 */
			session->pid++;
			if(session->pid == 32768)	/* PictureID is limited to 15 bits */
				session->pid = 0;
			/* Check if we need to split the frame in multiple RTP packets */
			if(payload_len < mtu) {
				JANUS_LOG(LOG_HUGE, "[%s] Sending packet, payload is %zu bytes\n",
					imquic_get_connection_name(conn), payload_len);
				/* Add a payload descriptor: first octet */
				char *pd = buffer+hsize;
				*pd |= 1 << 7;		/* I=1 (PictureID present) */
				*pd |= 1 << 3;		/* B=1 (Start of a frame) */
				hsize++;
				/* Second and third octet */
				pd++;
				uint16_t cpid = htons(session->pid);
				memcpy(pd, &cpid, sizeof(uint16_t));
				*pd |= 1 << 7;		/* M=1 */
				hsize += 2;
				/* Copy the frame data now */
				memcpy(buffer+hsize, payload, payload_len);
				/* Self-contained packet, set the Marker Bit to 1 */
				rtp->markerbit = 1;
				/* Send the packet */
				length = hsize + payload_len;
				session->video_track.seq++;
				rtp->seq_number = htons(session->video_track.seq);
				janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
				janus_plugin_rtp_extensions_reset(&pkt.extensions);
				gateway->relay_rtp(session->handle, &pkt);
			} else {
				size_t rest_len = payload_len, first_byte = 0, packet_len = 0;
				JANUS_LOG(LOG_HUGE, "[%s] Sending all that remains, payload is %zu bytes\n",
					imquic_get_connection_name(conn), rest_len);
				while(rest_len > 0) {
					/* Take part of the whole frame: not more than 'mtu' bytes */
					packet_len = rest_len;
					if(rest_len > mtu)
						packet_len = mtu;
					JANUS_LOG(LOG_HUGE, "[%s]    Sending packet, payload is %zu/%zu bytes\n",
						imquic_get_connection_name(conn), packet_len, payload_len);
					/* Add a payload descriptor: first octet */
					hsize = 12;
					char *pd = buffer+hsize;
					*pd = 0;
					*pd |= 1 << 7;		/* I=1 (PictureID present) */
					if(rest_len == payload_len)
						*pd |= 1 << 3;		/* B=1 (Start of a frame) */
					else if(rest_len <= mtu)
						*pd |= 1 << 2;		/* E=1 (End of a frame) */
					hsize++;
					/* Second and third octet */
					pd++;
					if(rest_len == payload_len) {
						uint16_t cpid = htons(session->pid);
						memcpy(pd, &cpid, sizeof(uint16_t));
					}
					*pd |= 1 << 7;		/* M=1 */
					hsize += 2;
					/* Copy the frame data now */
					memcpy(buffer+hsize, payload + first_byte, packet_len);
					/* Update counters */
					first_byte += packet_len;
					rest_len -= packet_len;
					/* Marker Bit depends on whether this is the last packet or not */
					rtp->markerbit = rest_len > 0 ? 0 : 1;
					/* Send the packet */
					length = hsize + packet_len;
					session->video_track.seq++;
					rtp->seq_number = htons(session->video_track.seq);
					janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
					janus_plugin_rtp_extensions_reset(&pkt.extensions);
					gateway->relay_rtp(session->handle, &pkt);
				}
			}
		} else if(session->vcodec == JANUS_VIDEOCODEC_H264) {
			/* We're using H.264 (AVCC or Annex-B) */
			if(loc_extradata && loc_extradata->length > 0) {
				/* We have extradata, extract the SPS/PPS and send that first */
				uint8_t *extradata = loc_extradata->buffer;
				size_t extradata_len = loc_extradata->length;
				JANUS_LOG(LOG_HUGE, "[%s] %s data is %zu bytes\n  -- ",
					imquic_get_connection_name(conn), (session->annexb ? "Annex-B" : "AVCC"), extradata_len);
				for(size_t i=0; i<extradata_len; ++i)
					JANUS_LOG(LOG_HUGE, "%02x", extradata[i]);
				JANUS_LOG(LOG_HUGE, "\n");
				/* Add NAL */
				length = hsize;
				buffer[length] = 0x18;
				length++;
				size_t offset = 0, pps_index = 0;
				uint16_t sps_len = 0, pps_len = 0;
				if(!session->annexb) {
					/* Read AVCC extradata */
					JANUS_LOG(LOG_HUGE, "Extradata:\n");
					JANUS_LOG(LOG_HUGE, "  -- Version:       %"SCNu8"\n", extradata[0]);
					JANUS_LOG(LOG_HUGE, "  -- Profile:       %"SCNu8"\n", extradata[1]);
					JANUS_LOG(LOG_HUGE, "  -- Compatibility: %"SCNu8"\n", extradata[2]);
					JANUS_LOG(LOG_HUGE, "  -- Level:         %"SCNu8"\n", extradata[3]);
					JANUS_LOG(LOG_HUGE, "  -- NAL length -1: %"SCNu8"\n", extradata[4] & 0x03);
					JANUS_LOG(LOG_HUGE, "  -- SPS number:    %"SCNu8"\n", extradata[5] & 0x1F);
					offset = 6;
					/* Extract SPS */
					memcpy(&sps_len, &extradata[offset], 2);
					sps_len = ntohs(sps_len);
					offset += 2;
				} else {
					/* Skip the start code */
					offset = 4;
					/* Find the next NAL to figure out the SPS size */
					size_t sps_index = offset, index = offset;
					while((index + 3) < extradata_len) {
						if(extradata[index] == 0x00 && extradata[index+1] == 0x00 && extradata[index+2] == 0x01) {
							sps_len = index - sps_index;
							index += 3;
							break;
						} else if(extradata[index] == 0x00 && extradata[index+1] == 0x00 && extradata[index+2] == 0x00 && extradata[index+3] == 0x01) {
							sps_len = index - sps_index;
							index += 4;
							break;
						}
						index++;
					}
					pps_index = index;
					pps_len = extradata_len - pps_index;
				}
				uint8_t *sps = &extradata[offset];
				JANUS_LOG(LOG_HUGE, "[%s] SPS len: %"SCNu16"\n",
					imquic_get_connection_name(conn), sps_len);
				if(sps_len > (sizeof(buffer)-length)) {
					/* Shouldn't happen */
					JANUS_LOG(LOG_WARN, "[%s] Broken SPS (len: %"SCNu16")\n",
						imquic_get_connection_name(conn), sps_len);
					return;
				}
				/* Add SPS to the RTP packet */
				sps_len = htons(sps_len);
				memcpy(&buffer[length], &sps_len, 2);
				length += 2;
				sps_len = ntohs(sps_len);
				memcpy(&buffer[length], sps, sps_len);
				length += sps_len;
				offset += sps_len;
				if(offset < extradata_len) {
					/* Extract PPS */
					if(!session->annexb) {
						uint8_t *pps = sps + sps_len;
						size_t pps_len = extradata_len - (pps - extradata);
						JANUS_LOG(LOG_HUGE, "[%s] PPS(s) len: %zu\n",
							imquic_get_connection_name(conn), pps_len);
						JANUS_LOG(LOG_HUGE, "  -- Num of PPS: %"SCNu8"\n", pps[0]);
						pps_index = 1;
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
					} else {
						pps_len = ntohs(pps_len);
						memcpy(&buffer[length], &pps_len, 2);
						length += 2;
						pps_len = htons(pps_len);
						memcpy(&buffer[length], &extradata[pps_index], pps_len);
						length += pps_len;
					}
				}
				/* Send the packet */
				JANUS_LOG(LOG_HUGE, "[%s] RTP packet is %zu bytes\n",
					imquic_get_connection_name(conn), length);
				for(size_t i=0; i<length; ++i)
					JANUS_LOG(LOG_HUGE, "%02x", (uint8_t)buffer[i]);
				JANUS_LOG(LOG_HUGE, "\n");
				session->video_track.seq++;
				rtp->seq_number = htons(session->video_track.seq);
				JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
					imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), length-hsize);
				janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
				janus_plugin_rtp_extensions_reset(&pkt.extensions);
				gateway->relay_rtp(session->handle, &pkt);
				length = 0;
			}
			/* Check if we need to switch from AVCC to Annex-B */
			if(!session->annexb) {
				size_t avcc_offset = 0, nal_size = 0;
				while(payload_len >= avcc_offset + 4) {
					memcpy(&nal_size, payload + avcc_offset, 4);
					nal_size = ntohl(nal_size);
					if(nal_size > 0) {
						*(payload + avcc_offset) = 0x00;
						*(payload + avcc_offset + 1) = 0x00;
						*(payload + avcc_offset + 2) = 0x00;
						*(payload + avcc_offset + 3) = 0x01;
					}
					avcc_offset += 4 + nal_size;
				}
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
						if((size_t)(tmp-start) > mtu)
							break;
						/* Create a new RTP packet */
						session->video_track.seq++;
						rtp->seq_number = htons(session->video_track.seq);
						memcpy(&buffer[hsize], start, tmp-start);
						/* Send the packet */
						length = tmp-start+hsize;
						JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
							imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), tmp-start);
						janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
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
			size_t total = end-start;
			JANUS_LOG(LOG_HUGE, "[%s] Evaluating remaining data: %zu bytes\n",
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
				JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
					imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), total);
				janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
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
				JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %zu)\n",
					imquic_get_connection_name(conn), indicator, type, header, start-data, mtu);
				session->video_track.seq++;
				rtp->seq_number = htons(session->video_track.seq);
				rtp->markerbit = 0;
				memcpy(&buffer[hsize+1], start, mtu);
				memset(&buffer[hsize], indicator, 1);
				memset(&buffer[hsize+1], header, 1);
				/* Send the packet */
				length = mtu+1+hsize;
				JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
					imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), mtu+1);
				janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
				janus_plugin_rtp_extensions_reset(&pkt.extensions);
				gateway->relay_rtp(session->handle, &pkt);
				/* Go on */
				start += mtu;
				total -= mtu;
				while(TRUE) {
					if(total < mtu) {
						/* Last packet, set the E bit */
						header = 0x40 + type;
						JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %zu, last)\n",
							imquic_get_connection_name(conn), indicator, type, header, start-data, total);
						session->video_track.seq++;
						rtp->seq_number = htons(session->video_track.seq);
						rtp->markerbit = 1;
						memset(&buffer[hsize], indicator, 1);
						memset(&buffer[hsize+1], header, 1);
						memcpy(&buffer[hsize+2], start, total);
						/* Send the packet */
						length = total+2+hsize;
						JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
							imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), total+2);
						janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
						janus_plugin_rtp_extensions_reset(&pkt.extensions);
						gateway->relay_rtp(session->handle, &pkt);
						break;
					} else {
						header = 0x00 + type;	/* Unset the S and E bits */
						JANUS_LOG(LOG_HUGE, "[%s]   -- FU-A: %d/%d/%d (offset %ld, size %zu)\n",
							imquic_get_connection_name(conn), indicator, type, header, start-data, mtu);
						session->video_track.seq++;
						rtp->seq_number = htons(session->video_track.seq);
						rtp->markerbit = 0;
						memset(&buffer[hsize], indicator, 1);
						memset(&buffer[hsize+1], header, 1);
						memcpy(&buffer[hsize+2], start, mtu);
						/* Send the packet */
						length = mtu+2+hsize;
						JANUS_LOG(LOG_HUGE, "[%s] >> Sending RTP packet (seq=%"SCNu16", ts=%"SCNu32", payload=%zu)\n",
							imquic_get_connection_name(conn), ntohs(rtp->seq_number), ntohl(rtp->timestamp), mtu+2);
						janus_plugin_rtp pkt = { .mindex = -1, .video = TRUE, .buffer = buffer, .length = length };
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

/* Helper to parse a SPS to width/height and return extradata we can send via LOC */
static size_t janus_moq_h264_parse_sps(uint8_t *extradata, size_t extradata_len,
		gboolean annexb, uint8_t *buffer, size_t len, gboolean stap, int *width, int *height) {
	/* We may need the extradata to be either AVCC or Annex-B */
	size_t index = 0, extradata_size = 0;
	if(!annexb) {
		/* AVCC, prepare the header */
		extradata[0] = 1;
		index = 3;
	} else {
		/* Annex-B */
		index = 1;
	}
	/* Let's check if it's the right profile, first */
	int profile_idc = *(buffer+index);
	if(profile_idc != 66) {
		JANUS_LOG(LOG_HUGE, "Profile is not baseline (%d != 66)\n", profile_idc);
	}
	if(!annexb) {
		extradata[1] = 66;	/* FIXME */
		extradata[2] = 3;	/* FIXME */
		extradata[3] = 31;	/* FIXME */
		extradata[4] = 3;
		extradata[5] = 1;
		extradata_size = 6;
	}
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

	/* Append SPS to the extradata buffer */
	uint16_t sps_size = len - 1;
	if(stap) {
		memcpy(&sps_size, buffer, 2);
		sps_size = ntohs(sps_size);
	}
	JANUS_LOG(LOG_HUGE, "SPS size: %"SCNu16"\n", sps_size);
	if(!annexb) {
		sps_size = htons(sps_size);
		memcpy(extradata + extradata_size, &sps_size, 2);
		sps_size = ntohs(sps_size);
		extradata_size += 2;
	} else {
		memset(extradata + extradata_size, 0x00, 1);
		memset(extradata + extradata_size + 1, 0x00, 1);
		memset(extradata + extradata_size + 2, 0x00, 1);
		memset(extradata + extradata_size + 3, 0x01, 1);
		extradata_size += 4;
	}
	if(stap)
		buffer += 2;
	memcpy(extradata + extradata_size, buffer, sps_size);
	buffer += sps_size;
	extradata_size += sps_size;

	if(!stap) {
		/* This only contained the SPS */
		return extradata_size;
	}

	/* Append PPS to the extradata buffer */
	uint16_t pps_size = 0;
	memcpy(&pps_size, buffer, 2);
	pps_size = ntohs(pps_size);
	JANUS_LOG(LOG_HUGE, "PPS size: %"SCNu16"\n", pps_size);
	if(!annexb) {
		extradata[extradata_size] = 1;	/* FIXME */
		extradata_size++;
		memcpy(extradata + extradata_size, buffer, 2);
		extradata_size += 2;
	} else {
		memset(extradata + extradata_size, 0x00, 1);
		memset(extradata + extradata_size + 1, 0x00, 1);
		memset(extradata + extradata_size + 2, 0x00, 1);
		memset(extradata + extradata_size + 3, 0x01, 1);
		extradata_size += 4;
	}
	buffer += 2;
	memcpy(extradata + extradata_size, buffer, pps_size);
	buffer += pps_size;
	extradata_size += pps_size;

	/* Done */
	return extradata_size;
}

/* Helper to decode a leb128 integer  */
static uint32_t janus_moq_av1_lev128_decode(uint8_t *base, uint16_t maxlen, size_t *read) {
	uint32_t val = 0;
	uint8_t *cur = base;
	while((cur-base) < maxlen) {
		/* We only read the 7 least significant bits of each byte */
		val |= ((uint32_t)(*cur & 0x7f)) << ((cur-base)*7);
		if((*cur & 0x80) == 0) {
			/* Most significant bit is 0, we're done */
			*read = (cur-base)+1;
			return val;
		}
		cur++;
	}
	/* If we got here, we read all bytes, but no one with 0 as MSB? */
	return 0;
}
/* Helper to encode a leb128 integer  */
static void janus_moq_av1_lev128_encode(uint32_t value, uint8_t *base, size_t *written) {
	uint8_t *cur = base;
	while(value >= 0x80) {
		/* All these bytes need MSB=1 */
		*cur = (0x80 | (value & 0x7F));
		cur++;
		value >>= 7;
	}
	/* Last byte will have MSB=0 */
	*cur = value;
	*written = (cur-base)+1;
}
/* Helpers to read a bit, or group of bits, in a Sequence Header */
static uint32_t janus_moq_av1_getbit(uint8_t *base, uint32_t offset) {
	return ((*(base + (offset >> 0x3))) >> (0x7 - (offset & 0x7))) & 0x1;
}
static uint32_t janus_moq_av1_getbits(uint8_t *base, uint8_t num, uint32_t *offset) {
	uint32_t res = 0;
	int32_t i = 0;
	for(i=num-1; i>=0; i--) {
		res |= janus_moq_av1_getbit(base, (*offset)++) << i;
	}
	return res;
}
/* Helper to parse a Sequence Header (only to get the video resolution) */
static void janus_moq_av1_parse_sh(char *buffer, uint16_t *width, uint16_t *height) {
	/* Evaluate/skip everything until we get to the resolution */
	uint32_t offset = 0, value = 0, i = 0;
	uint8_t *base = (uint8_t *)(buffer);
	/* Skip seq_profile (3 bits) */
	janus_moq_av1_getbits(base, 3, &offset);
	/* Skip still_picture (1 bit) */
	janus_moq_av1_getbit(base, offset++);
	/* Skip reduced_still_picture_header (1 bit) */
	value = janus_moq_av1_getbit(base, offset++);
	if(value) {
		/* Skip seq_level_idx (5 bits) */
		janus_moq_av1_getbits(base, 5, &offset);
	} else {
		gboolean decoder_model_info = FALSE, initial_display_delay = FALSE;
		uint32_t bdlm1 = 0;
		/* Skip timing_info_present_flag (1 bit) */
		value = janus_moq_av1_getbit(base, offset++);
		if(value) {
			/* Skip num_units_in_display_tick (32 bits) */
			janus_moq_av1_getbits(base, 32, &offset);
			/* Skip time_scale (32 bits) */
			janus_moq_av1_getbits(base, 32, &offset);
			/* Skip equal_picture_interval (1 bit)*/
			value = janus_moq_av1_getbit(base, offset++);
			if(value) {
				/* TODO Skip num_ticks_per_picture_minus_1 (uvlc) */
			}
			/* Skip decoder_model_info_present_flag (1 bit) */
			value = janus_moq_av1_getbit(base, offset++);
			if(value) {
				decoder_model_info = TRUE;
				/* Skip buffer_delay_length_minus_1 (5 bits) */
				bdlm1 = janus_moq_av1_getbits(base, 5, &offset);
				/* Skip num_units_in_decoding_tick (32 bits) */
				janus_moq_av1_getbits(base, 32, &offset);
				/* Skip buffer_removal_time_length_minus_1 (5 bits) */
				janus_moq_av1_getbits(base, 5, &offset);
				/* Skip frame_presentation_time_length_minus_1 (5 bits) */
				janus_moq_av1_getbits(base, 5, &offset);
			}
		}
		/* Skip initial_display_delay_present_flag (1 bit) */
		value = janus_moq_av1_getbit(base, offset++);
		if(value)
			initial_display_delay = TRUE;
		/* Skip operating_points_cnt_minus_1 (5 bits) */
		uint32_t opcm1 = janus_moq_av1_getbits(base, 5, &offset)+1;
		for(i=0; i<opcm1; i++) {
			/* Skip operating_point_idc[i] (12 bits) */
			janus_moq_av1_getbits(base, 12, &offset);
			/* Skip seq_level_idx[i] (5 bits) */
			value = janus_moq_av1_getbits(base, 5, &offset);
			if(value > 7) {
				/* Skip seq_tier[i] (1 bit) */
				janus_moq_av1_getbit(base, offset++);
			}
			if(decoder_model_info) {
				/* Skip decoder_model_present_for_this_op[i] (1 bit) */
				value = janus_moq_av1_getbit(base, offset++);
				if(value) {
					/* Skip operating_parameters_info(i) */
					janus_moq_av1_getbits(base, (2*bdlm1)+1, &offset);
				}
			}
			if(initial_display_delay) {
				/* Skip initial_display_delay_present_for_this_op[i] (1 bit) */
				value = janus_moq_av1_getbit(base, offset++);
				if(value) {
					/* Skip initial_display_delay_minus_1[i] (4 bits) */
					janus_moq_av1_getbits(base, 4, &offset);
				}
			}
		}
	}
	/* Read frame_width_bits_minus_1 (4 bits) */
	uint32_t fwbm1 = janus_moq_av1_getbits(base, 4, &offset);
	/* Read frame_height_bits_minus_1 (4 bits) */
	uint32_t fhbm1 = janus_moq_av1_getbits(base, 4, &offset);
	/* Read max_frame_width_minus_1 (n bits) */
	*width = janus_moq_av1_getbits(base, fwbm1+1, &offset)+1;
	/* Read max_frame_height_minus_1 (n bits) */
	*height = janus_moq_av1_getbits(base, fhbm1+1, &offset)+1;
}
