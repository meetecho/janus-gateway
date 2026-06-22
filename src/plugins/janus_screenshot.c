/*! \file   janus_screenshot.c
 * \brief  Janus Screenshot plugin
 * \details This is a plugin that grabs single still images (screenshots)
 * out of an H.264 video stream, saving them as PNG, JPEG or WebP files. It
 * can obtain the video in two different ways:
 *
 * - over a WebRTC PeerConnection negotiated directly with the plugin (much
 *   like the Record&Play plugin owns its own PeerConnection), by sending a
 *   \c configure request with a JSEP offer; or
 * - over plain RTP, by forwarding an H.264 stream to one of the UDP ports
 *   the plugin can be configured to listen on. Each such listener is a
 *   "stream" identified by a numeric \c id and bound to its own \c videoport,
 *   configured in the \c rtp section of the configuration file:
 *
\verbatim
rtp: {
    enabled = true
    streams = (
        { id = 1; videoport = 8004 }
        { id = 2; videoport = 8006 }
    )
}
\endverbatim
 *
 * Once a video source is available, a \c take request asks the plugin to
 * capture the next keyframe. When capturing from a forwarded RTP stream, the
 * \c id of the stream to grab from must be provided (it can be omitted only
 * if a single stream is configured); when capturing from a WebRTC
 * PeerConnection, no \c id is needed, as the handle itself is the source:
 *
\verbatim
{
	"request" : "take",
	"id" : <numeric id of the RTP stream to capture from; required in RTP mode>,
	"format" : "<png (default), jpg or webp; optional>",
	"filename" : "<path/filename to save the image to; optional>"
}
\endverbatim
 *
 * The plugin replies with a \c requested status, and later pushes a
 * \c captured (or \c error) event once the keyframe has been processed. The
 * \c get request can then be used to retrieve the last saved image, optionally
 * including its base64-encoded data.
 *
 * \note If all you need is a screenshot of a Streaming plugin mountpoint, the
 * Streaming plugin provides its own \c screenshot request that taps the media
 * it already owns, with no need to forward RTP to this plugin.
 */

#include "plugin.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <jansson.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libswscale/swscale.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../apierror.h"
#include "../config.h"
#include "../debug.h"
#include "../mutex.h"
#include "../rtcp.h"
#include "../rtp.h"
#include "../sdp-utils.h"
#include "../utils.h"

#define JANUS_SCREENSHOT_VERSION			1
#define JANUS_SCREENSHOT_VERSION_STRING	"0.0.1"
#define JANUS_SCREENSHOT_DESCRIPTION		"Video screenshot plugin for Janus"
#define JANUS_SCREENSHOT_NAME			"JANUS Screenshot plugin"
#define JANUS_SCREENSHOT_AUTHOR			"Meetecho s.r.l."
#define JANUS_SCREENSHOT_PACKAGE			"janus.plugin.screenshot"

#define JANUS_SCREENSHOT_ERROR_UNKNOWN_ERROR		470
#define JANUS_SCREENSHOT_ERROR_INVALID_JSON		471
#define JANUS_SCREENSHOT_ERROR_INVALID_REQUEST	472
#define JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT	473
#define JANUS_SCREENSHOT_ERROR_INVALID_STATE		474
#define JANUS_SCREENSHOT_ERROR_INVALID_SDP		475

janus_plugin *create(void);
int janus_screenshot_init(janus_callbacks *callback, const char *config_path);
void janus_screenshot_destroy(void);
int janus_screenshot_get_api_compatibility(void);
int janus_screenshot_get_version(void);
const char *janus_screenshot_get_version_string(void);
const char *janus_screenshot_get_description(void);
const char *janus_screenshot_get_name(void);
const char *janus_screenshot_get_author(void);
const char *janus_screenshot_get_package(void);
void janus_screenshot_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_screenshot_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_screenshot_setup_media(janus_plugin_session *handle);
void janus_screenshot_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_screenshot_hangup_media(janus_plugin_session *handle);
void janus_screenshot_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_screenshot_query_session(janus_plugin_session *handle);

static janus_plugin janus_screenshot_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_screenshot_init,
		.destroy = janus_screenshot_destroy,
		.get_api_compatibility = janus_screenshot_get_api_compatibility,
		.get_version = janus_screenshot_get_version,
		.get_version_string = janus_screenshot_get_version_string,
		.get_description = janus_screenshot_get_description,
		.get_name = janus_screenshot_get_name,
		.get_author = janus_screenshot_get_author,
		.get_package = janus_screenshot_get_package,
		.create_session = janus_screenshot_create_session,
		.handle_message = janus_screenshot_handle_message,
		.setup_media = janus_screenshot_setup_media,
		.incoming_rtp = janus_screenshot_incoming_rtp,
		.hangup_media = janus_screenshot_hangup_media,
		.destroy_session = janus_screenshot_destroy_session,
		.query_session = janus_screenshot_query_session,
	);

janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SCREENSHOT_NAME);
	return &janus_screenshot_plugin;
}

typedef struct janus_screenshot_rtp_stream {
	guint64 id;
	uint16_t port;
	int fd;
} janus_screenshot_rtp_stream;

typedef struct janus_screenshot_session {
	janus_plugin_session *handle;
	janus_videocodec vcodec;
	char *vfmtp;
	gboolean has_video;
	gboolean started;
	gboolean pending;
	gboolean capturing;
	char *format;
	char *filename;
	gboolean capture_rtp;
	guint64 capture_id;
	char *transaction;
	char *last_format;
	char *last_filename;
	char *last_content_type;
	guint32 capture_ts;
	GByteArray *frame;
	janus_mutex mutex;
	volatile gint destroyed;
	janus_refcount ref;
} janus_screenshot_session;

static janus_callbacks *gateway = NULL;
static GHashTable *sessions = NULL;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;
static volatile gint initialized = 0;
static volatile gint stopping = 0;
static gboolean notify_events = TRUE;
static char *screenshots_path = NULL;
static gboolean rtp_enabled = FALSE;
static GList *rtp_streams = NULL;	/* List of janus_screenshot_rtp_stream*, populated at init and read-only afterwards */
static GThread *rtp_thread = NULL;

static void *janus_screenshot_rtp_relay_thread(void *data);

/* Resolve a configured RTP stream by its numeric id */
static janus_screenshot_rtp_stream *janus_screenshot_find_stream(guint64 id) {
	GList *l = rtp_streams;
	while(l) {
		janus_screenshot_rtp_stream *stream = (janus_screenshot_rtp_stream *)l->data;
		if(stream->id == id)
			return stream;
		l = l->next;
	}
	return NULL;
}

static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter take_parameters[] = {
	{"format", JSON_STRING, 0},
	{"filename", JSON_STRING, 0},
	{"id", JSON_INTEGER, 0}
};
static struct janus_json_parameter get_parameters[] = {
	{"include_data", JANUS_JSON_BOOL, 0}
};

int janus_screenshot_get_api_compatibility(void) { return JANUS_PLUGIN_API_VERSION; }
int janus_screenshot_get_version(void) { return JANUS_SCREENSHOT_VERSION; }
const char *janus_screenshot_get_version_string(void) { return JANUS_SCREENSHOT_VERSION_STRING; }
const char *janus_screenshot_get_description(void) { return JANUS_SCREENSHOT_DESCRIPTION; }
const char *janus_screenshot_get_name(void) { return JANUS_SCREENSHOT_NAME; }
const char *janus_screenshot_get_author(void) { return JANUS_SCREENSHOT_AUTHOR; }
const char *janus_screenshot_get_package(void) { return JANUS_SCREENSHOT_PACKAGE; }

static janus_screenshot_session *janus_screenshot_lookup_session(janus_plugin_session *handle) {
	janus_screenshot_session *session = NULL;
	if(handle == NULL || sessions == NULL)
		return NULL;
	janus_mutex_lock(&sessions_mutex);
	session = g_hash_table_lookup(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

static void janus_screenshot_session_free(const janus_refcount *session_ref) {
	janus_screenshot_session *session = janus_refcount_containerof(session_ref, janus_screenshot_session, ref);
	if(session->frame)
		g_byte_array_unref(session->frame);
	g_free(session->vfmtp);
	g_free(session->format);
	g_free(session->filename);
	g_free(session->transaction);
	g_free(session->last_format);
	g_free(session->last_filename);
	g_free(session->last_content_type);
	janus_mutex_destroy(&session->mutex);
	janus_refcount_decrease(&session->handle->ref);
	g_free(session);
}

int janus_screenshot_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&initialized))
		return 0;
	if(callback == NULL || config_path == NULL)
		return -1;
	char filename[255];
	g_snprintf(filename, sizeof(filename), "%s/%s.jcfg", config_path, JANUS_SCREENSHOT_PACKAGE);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		g_snprintf(filename, sizeof(filename), "%s/%s.cfg", config_path, JANUS_SCREENSHOT_PACKAGE);
		config = janus_config_parse(filename);
	}
	g_free(screenshots_path);
	screenshots_path = g_strdup("./screenshots");
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *events = janus_config_get(config, general, janus_config_type_item, "events");
		if(events && events->value)
			notify_events = janus_is_true(events->value);
		janus_config_item *path = janus_config_get(config, general, janus_config_type_item, "path");
		if(path && path->value) {
			g_free(screenshots_path);
			screenshots_path = g_strdup(path->value);
		}
		janus_config_category *rtp = janus_config_get_create(config, NULL, janus_config_type_category, "rtp");
		janus_config_item *enabled = janus_config_get(config, rtp, janus_config_type_item, "enabled");
		if(enabled && enabled->value)
			rtp_enabled = janus_is_true(enabled->value);
		if(rtp_enabled) {
			/* Each RTP stream is identified by a unique "id" and listens on its own "videoport" */
			janus_config_array *streams = janus_config_get(config, rtp, janus_config_type_array, "streams");
			GList *sl = streams ? streams->list : NULL;
			while(sl) {
				janus_config_item *s = (janus_config_item *)sl->data;
				sl = sl->next;
				if(s == NULL || s->type != janus_config_type_category)
					continue;
				janus_config_item *id = janus_config_get(config, s, janus_config_type_item, "id");
				janus_config_item *port = janus_config_get(config, s, janus_config_type_item, "videoport");
				if(id == NULL || id->value == NULL || port == NULL || port->value == NULL) {
					JANUS_LOG(LOG_WARN, "Skipping RTP stream with no id/videoport\n");
					continue;
				}
				guint64 stream_id = g_ascii_strtoull(id->value, NULL, 10);
				if(janus_screenshot_find_stream(stream_id) != NULL) {
					JANUS_LOG(LOG_WARN, "Skipping RTP stream with duplicate id %"SCNu64"\n", stream_id);
					continue;
				}
				janus_screenshot_rtp_stream *stream = g_malloc0(sizeof(janus_screenshot_rtp_stream));
				stream->id = stream_id;
				stream->port = (uint16_t)atoi(port->value);
				stream->fd = -1;
				rtp_streams = g_list_append(rtp_streams, stream);
			}
			if(rtp_streams == NULL) {
				JANUS_LOG(LOG_WARN, "RTP enabled but no valid streams configured, disabling RTP listener\n");
				rtp_enabled = FALSE;
			}
		}
	}
	janus_config_destroy(config);
	if(g_mkdir_with_parents(screenshots_path, 0755) < 0)
		JANUS_LOG(LOG_WARN, "Could not create screenshots folder %s: %s\n", screenshots_path, g_strerror(errno));
	sessions = g_hash_table_new(NULL, NULL);
	if(rtp_enabled && rtp_streams != NULL) {
		GList *sl = rtp_streams;
		while(sl) {
			janus_screenshot_rtp_stream *stream = (janus_screenshot_rtp_stream *)sl->data;
			sl = sl->next;
			stream->fd = socket(AF_INET, SOCK_DGRAM, 0);
			if(stream->fd < 0) {
				JANUS_LOG(LOG_ERR, "Could not create Screenshot RTP socket for stream %"SCNu64": %s\n",
					stream->id, g_strerror(errno));
				return -1;
			}
			struct sockaddr_in addr = { 0 };
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port = htons(stream->port);
			if(bind(stream->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
				JANUS_LOG(LOG_ERR, "Could not bind Screenshot RTP socket for stream %"SCNu64" on port %u: %s\n",
					stream->id, stream->port, g_strerror(errno));
				close(stream->fd);
				stream->fd = -1;
				return -1;
			}
			JANUS_LOG(LOG_INFO, "Screenshot RTP listener for stream %"SCNu64" enabled on UDP port %u\n",
				stream->id, stream->port);
		}
		GError *thread_error = NULL;
		rtp_thread = g_thread_try_new("screenshot rtp", janus_screenshot_rtp_relay_thread, NULL, &thread_error);
		if(thread_error != NULL) {
			JANUS_LOG(LOG_ERR, "Could not start Screenshot RTP thread: %s\n", thread_error->message);
			g_error_free(thread_error);
			return -1;
		}
	}
	gateway = callback;
	g_atomic_int_set(&initialized, 1);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_SCREENSHOT_NAME);
	return 0;
}

void janus_screenshot_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	if(rtp_thread != NULL) {
		g_thread_join(rtp_thread);
		rtp_thread = NULL;
	}
	GList *sl = rtp_streams;
	while(sl) {
		janus_screenshot_rtp_stream *stream = (janus_screenshot_rtp_stream *)sl->data;
		sl = sl->next;
		if(stream->fd >= 0)
			close(stream->fd);
		g_free(stream);
	}
	g_list_free(rtp_streams);
	rtp_streams = NULL;
	g_free(screenshots_path);
	screenshots_path = NULL;
	g_atomic_int_set(&initialized, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SCREENSHOT_NAME);
}

void janus_screenshot_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_screenshot_session *session = g_malloc0(sizeof(janus_screenshot_session));
	session->handle = handle;
	janus_refcount_increase(&handle->ref);
	session->vcodec = JANUS_VIDEOCODEC_NONE;
	session->format = g_strdup("png");
	session->frame = g_byte_array_new();
	janus_mutex_init(&session->mutex);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_screenshot_session_free);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);
}

void janus_screenshot_destroy_session(janus_plugin_session *handle, int *error) {
	janus_screenshot_session *session = janus_screenshot_lookup_session(handle);
	if(session == NULL) {
		*error = -2;
		return;
	}
	g_atomic_int_set(&session->destroyed, 1);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	janus_refcount_decrease(&session->ref);
}

json_t *janus_screenshot_query_session(janus_plugin_session *handle) {
	janus_screenshot_session *session = janus_screenshot_lookup_session(handle);
	if(session == NULL)
		return NULL;
	json_t *info = json_object();
	janus_mutex_lock(&session->mutex);
	json_object_set_new(info, "started", session->started ? json_true() : json_false());
	json_object_set_new(info, "pending", session->pending ? json_true() : json_false());
	if(session->vcodec != JANUS_VIDEOCODEC_NONE)
		json_object_set_new(info, "video_codec", json_string(janus_videocodec_name(session->vcodec)));
	if(session->capture_rtp)
		json_object_set_new(info, "id", json_integer(session->capture_id));
	if(session->last_filename)
		json_object_set_new(info, "last_filename", json_string(session->last_filename));
	janus_mutex_unlock(&session->mutex);
	return info;
}

void janus_screenshot_setup_media(janus_plugin_session *handle) {
	janus_screenshot_session *session = janus_screenshot_lookup_session(handle);
	if(session == NULL)
		return;
	janus_mutex_lock(&session->mutex);
	session->started = TRUE;
	janus_mutex_unlock(&session->mutex);
}

void janus_screenshot_hangup_media(janus_plugin_session *handle) {
	janus_screenshot_session *session = janus_screenshot_lookup_session(handle);
	if(session == NULL)
		return;
	janus_mutex_lock(&session->mutex);
	session->started = FALSE;
	session->pending = FALSE;
	session->capturing = FALSE;
	session->capture_ts = 0;
	g_free(session->transaction);
	session->transaction = NULL;
	session->capture_rtp = FALSE;
	session->capture_id = 0;
	g_byte_array_set_size(session->frame, 0);
	janus_mutex_unlock(&session->mutex);
}

static const char *janus_screenshot_content_type(const char *format) {
	if(!strcasecmp(format, "jpg") || !strcasecmp(format, "jpeg"))
		return "image/jpeg";
	if(!strcasecmp(format, "webp"))
		return "image/webp";
	return "image/png";
}

static const char *janus_screenshot_extension(const char *format) {
	if(!strcasecmp(format, "jpg") || !strcasecmp(format, "jpeg"))
		return "jpg";
	if(!strcasecmp(format, "webp"))
		return "webp";
	return "png";
}

static gboolean janus_screenshot_valid_format(const char *format) {
	return format != NULL && (!strcasecmp(format, "png") || !strcasecmp(format, "jpg") ||
		!strcasecmp(format, "jpeg") || !strcasecmp(format, "webp"));
}

static void janus_screenshot_append_start_code(GByteArray *frame) {
	static const guint8 start_code[] = { 0x00, 0x00, 0x00, 0x01 };
	g_byte_array_append(frame, start_code, sizeof(start_code));
}

static gboolean janus_screenshot_append_h264_payload(GByteArray *frame, const char *payload, int plen) {
	if(frame == NULL || payload == NULL || plen < 1)
		return FALSE;
	uint8_t nal = payload[0] & 0x1F;
	if(nal > 0 && nal < 24) {
		janus_screenshot_append_start_code(frame);
		g_byte_array_append(frame, (const guint8 *)payload, plen);
		return TRUE;
	} else if(nal == 24) {
		const char *pos = payload + 1;
		int left = plen - 1;
		while(left > 2) {
			uint16_t nsize = 0;
			memcpy(&nsize, pos, sizeof(uint16_t));
			nsize = ntohs(nsize);
			pos += 2;
			left -= 2;
			if(nsize == 0 || nsize > left)
				return FALSE;
			janus_screenshot_append_start_code(frame);
			g_byte_array_append(frame, (const guint8 *)pos, nsize);
			pos += nsize;
			left -= nsize;
		}
		return TRUE;
	} else if(nal == 28 && plen > 2) {
		uint8_t indicator = payload[0];
		uint8_t fu = payload[1];
		gboolean start = (fu & 0x80) != 0;
		uint8_t reconstructed = (indicator & 0xE0) | (fu & 0x1F);
		if(start) {
			janus_screenshot_append_start_code(frame);
			g_byte_array_append(frame, &reconstructed, 1);
		}
		g_byte_array_append(frame, (const guint8 *)payload + 2, plen - 2);
		return TRUE;
	}
	return FALSE;
}

static gboolean janus_screenshot_write_image(const guint8 *data, gsize size, const char *format,
		const char *filename, char *error, size_t error_len) {
	gboolean success = FALSE;
	const AVCodec *decoder = avcodec_find_decoder(AV_CODEC_ID_H264);
	const AVCodec *encoder = NULL;
	enum AVPixelFormat out_fmt = AV_PIX_FMT_RGB24;
	if(!strcasecmp(format, "png")) {
		encoder = avcodec_find_encoder(AV_CODEC_ID_PNG);
		out_fmt = AV_PIX_FMT_RGB24;
	} else if(!strcasecmp(format, "webp")) {
		encoder = avcodec_find_encoder_by_name("libwebp");
		if(encoder == NULL)
			encoder = avcodec_find_encoder(AV_CODEC_ID_WEBP);
		out_fmt = AV_PIX_FMT_BGRA;
	} else {
		encoder = avcodec_find_encoder(AV_CODEC_ID_MJPEG);
		out_fmt = AV_PIX_FMT_YUVJ420P;
	}
	if(decoder == NULL || encoder == NULL) {
		g_snprintf(error, error_len, "Required decoder/encoder not available");
		return FALSE;
	}
	AVCodecContext *dctx = avcodec_alloc_context3(decoder);
	AVCodecContext *ectx = NULL;
	AVFrame *frame = av_frame_alloc(), *out = av_frame_alloc();
	AVPacket *pkt = av_packet_alloc(), *opkt = av_packet_alloc();
	struct SwsContext *sws = NULL;
	if(dctx == NULL || frame == NULL || out == NULL || pkt == NULL || opkt == NULL) {
		g_snprintf(error, error_len, "Out of memory");
		goto done;
	}
	if(avcodec_open2(dctx, decoder, NULL) < 0) {
		g_snprintf(error, error_len, "Could not open H.264 decoder");
		goto done;
	}
	pkt->data = (uint8_t *)data;
	pkt->size = (int)size;
	if(avcodec_send_packet(dctx, pkt) < 0 || avcodec_receive_frame(dctx, frame) < 0) {
		g_snprintf(error, error_len, "Could not decode H.264 keyframe");
		goto done;
	}
	ectx = avcodec_alloc_context3(encoder);
	if(ectx == NULL) {
		g_snprintf(error, error_len, "Could not allocate image encoder");
		goto done;
	}
	ectx->width = frame->width;
	ectx->height = frame->height;
	ectx->pix_fmt = out_fmt;
	ectx->time_base = (AVRational){1, 1};
	if(!strcasecmp(format, "webp"))
		av_opt_set_int(ectx->priv_data, "lossless", 1, 0);
	if(avcodec_open2(ectx, encoder, NULL) < 0) {
		g_snprintf(error, error_len, "Could not open image encoder for %s", format);
		goto done;
	}
	out->format = ectx->pix_fmt;
	out->width = ectx->width;
	out->height = ectx->height;
	if(av_frame_get_buffer(out, 32) < 0) {
		g_snprintf(error, error_len, "Could not allocate converted image frame");
		goto done;
	}
	sws = sws_getContext(frame->width, frame->height, frame->format,
		out->width, out->height, out->format, SWS_BILINEAR, NULL, NULL, NULL);
	if(sws == NULL) {
		g_snprintf(error, error_len, "Could not allocate image converter");
		goto done;
	}
	sws_scale(sws, (const uint8_t * const *)frame->data, frame->linesize, 0, frame->height, out->data, out->linesize);
	out->pts = 0;
	if(avcodec_send_frame(ectx, out) < 0) {
		g_snprintf(error, error_len, "Could not encode %s image", format);
		goto done;
	}
	int encres = avcodec_receive_packet(ectx, opkt);
	if(encres < 0) {
		avcodec_send_frame(ectx, NULL);
		encres = avcodec_receive_packet(ectx, opkt);
	}
	if(encres < 0) {
		g_snprintf(error, error_len, "Could not encode %s image", format);
		goto done;
	}
	if(!g_file_set_contents(filename, (const char *)opkt->data, opkt->size, NULL)) {
		g_snprintf(error, error_len, "Could not write image file");
		goto done;
	}
	success = TRUE;
done:
	if(sws)
		sws_freeContext(sws);
	if(ectx)
		avcodec_free_context(&ectx);
	if(dctx)
		avcodec_free_context(&dctx);
	if(frame)
		av_frame_free(&frame);
	if(out)
		av_frame_free(&out);
	if(pkt)
		av_packet_free(&pkt);
	if(opkt)
		av_packet_free(&opkt);
	return success;
}

static void janus_screenshot_push_capture_event(janus_screenshot_session *session, const char *transaction,
		const char *status, const char *error_text) {
	json_t *event = json_object();
	json_object_set_new(event, "screenshot", json_string("event"));
	json_object_set_new(event, "status", json_string(status));
	janus_mutex_lock(&session->mutex);
	if(session->last_filename)
		json_object_set_new(event, "filename", json_string(session->last_filename));
	if(session->last_format)
		json_object_set_new(event, "format", json_string(session->last_format));
	if(session->last_content_type)
		json_object_set_new(event, "content_type", json_string(session->last_content_type));
	janus_mutex_unlock(&session->mutex);
	if(error_text)
		json_object_set_new(event, "error", json_string(error_text));
	gateway->push_event(session->handle, &janus_screenshot_plugin, transaction, event, NULL);
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_deep_copy(event);
		gateway->notify_event(&janus_screenshot_plugin, session->handle, info);
	}
	json_decref(event);
}

/* from_rtp is TRUE when the packet came from an RTP listener (identified by
 * stream_id), FALSE when it arrived on the session's own WebRTC PeerConnection */
static void janus_screenshot_process_rtp(janus_screenshot_session *session, char *buf, int len,
		gboolean from_rtp, guint64 stream_id) {
	if(session == NULL || buf == NULL || len < 12 || g_atomic_int_get(&session->destroyed))
		return;
	janus_mutex_lock(&session->mutex);
	if(!session->pending || session->vcodec != JANUS_VIDEOCODEC_H264) {
		janus_mutex_unlock(&session->mutex);
		return;
	}
	/* Only capture from the source this session asked for */
	if(session->capture_rtp != from_rtp || (from_rtp && session->capture_id != stream_id)) {
		janus_mutex_unlock(&session->mutex);
		return;
	}
	int plen = 0;
	char *payload = janus_rtp_payload(buf, len, &plen);
	if(payload == NULL || plen < 1) {
		janus_mutex_unlock(&session->mutex);
		return;
	}
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	uint32_t ts = ntohl(rtp->timestamp);
	if(!session->capturing) {
		if(!janus_h264_is_keyframe(payload, plen) && !janus_h264_is_i_frame(payload, plen)) {
			janus_mutex_unlock(&session->mutex);
			return;
		}
		session->capturing = TRUE;
		session->capture_ts = ts;
		g_byte_array_set_size(session->frame, 0);
	} else if(ts != session->capture_ts) {
		char *transaction = g_strdup(session->transaction);
		session->pending = FALSE;
		session->capturing = FALSE;
		g_free(session->transaction);
		session->transaction = NULL;
		g_byte_array_set_size(session->frame, 0);
		janus_mutex_unlock(&session->mutex);
		janus_screenshot_push_capture_event(session, transaction, "error", "Frame changed before marker bit");
		g_free(transaction);
		return;
	}
	janus_screenshot_append_h264_payload(session->frame, payload, plen);
	if(!rtp->markerbit) {
		janus_mutex_unlock(&session->mutex);
		return;
	}
	char *format = g_strdup(session->format);
	char *filename = g_strdup(session->filename);
	char *transaction = g_strdup(session->transaction);
	GByteArray *frame = g_byte_array_ref(session->frame);
	session->pending = FALSE;
	session->capturing = FALSE;
	session->capture_ts = 0;
	g_free(session->transaction);
	session->transaction = NULL;
	janus_mutex_unlock(&session->mutex);
	char error[256] = {0};
	if(!janus_screenshot_write_image(frame->data, frame->len, format, filename, error, sizeof(error))) {
		janus_screenshot_push_capture_event(session, transaction, "error", error);
	} else {
		janus_mutex_lock(&session->mutex);
		g_free(session->last_filename);
		g_free(session->last_format);
		g_free(session->last_content_type);
		session->last_filename = g_strdup(filename);
		session->last_format = g_strdup(format);
		session->last_content_type = g_strdup(janus_screenshot_content_type(format));
		janus_mutex_unlock(&session->mutex);
		janus_screenshot_push_capture_event(session, transaction, "captured", NULL);
	}
	g_byte_array_unref(frame);
	g_free(format);
	g_free(filename);
	g_free(transaction);
}

void janus_screenshot_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	if(handle == NULL || packet == NULL || !packet->video || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_screenshot_session *session = (janus_screenshot_session *)handle->plugin_handle;
	janus_screenshot_process_rtp(session, packet->buffer, packet->length, FALSE, 0);
}

static void *janus_screenshot_rtp_relay_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Starting Screenshot RTP listener thread\n");
	char buffer[1500];
	/* Build a pollfd array from the configured streams (read-only after init) */
	guint nstreams = g_list_length(rtp_streams);
	struct pollfd *pfds = g_malloc0(nstreams * sizeof(struct pollfd));
	janus_screenshot_rtp_stream **smap = g_malloc0(nstreams * sizeof(janus_screenshot_rtp_stream *));
	guint i = 0;
	for(GList *sl = rtp_streams; sl != NULL; sl = sl->next, i++) {
		janus_screenshot_rtp_stream *stream = (janus_screenshot_rtp_stream *)sl->data;
		pfds[i].fd = stream->fd;
		pfds[i].events = POLLIN;
		smap[i] = stream;
	}
	while(!g_atomic_int_get(&stopping)) {
		int res = poll(pfds, nstreams, 1000);
		if(res <= 0)
			continue;
		for(i = 0; i < nstreams; i++) {
			if(!(pfds[i].revents & POLLIN))
				continue;
			ssize_t bytes = recv(pfds[i].fd, buffer, sizeof(buffer), 0);
			if(bytes < 12 || !janus_is_rtp(buffer, bytes))
				continue;
			guint64 stream_id = smap[i]->id;
			janus_mutex_lock(&sessions_mutex);
			GHashTableIter iter;
			gpointer key = NULL, value = NULL;
			g_hash_table_iter_init(&iter, sessions);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				janus_screenshot_session *session = value;
				janus_refcount_increase(&session->ref);
				janus_mutex_unlock(&sessions_mutex);
				janus_screenshot_process_rtp(session, buffer, bytes, TRUE, stream_id);
				janus_refcount_decrease(&session->ref);
				janus_mutex_lock(&sessions_mutex);
			}
			janus_mutex_unlock(&sessions_mutex);
		}
	}
	g_free(pfds);
	g_free(smap);
	JANUS_LOG(LOG_VERB, "Leaving Screenshot RTP listener thread\n");
	return NULL;
}

static struct janus_plugin_result *janus_screenshot_error(const char *transaction, int code, const char *cause) {
	json_t *event = json_object();
	json_object_set_new(event, "screenshot", json_string("event"));
	json_object_set_new(event, "error_code", json_integer(code));
	json_object_set_new(event, "error", json_string(cause));
	return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, event);
}

struct janus_plugin_result *janus_screenshot_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Plugin not initialized", NULL);
	janus_screenshot_session *session = janus_screenshot_lookup_session(handle);
	if(session == NULL)
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	if(message == NULL)
		return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_JSON, "Missing message");
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters, error_code, error_cause, TRUE,
		JANUS_SCREENSHOT_ERROR_INVALID_REQUEST, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		return janus_screenshot_error(transaction, error_code, error_cause);
	const char *request = json_string_value(json_object_get(message, "request"));
	if(!strcasecmp(request, "configure")) {
		if(jsep == NULL)
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_SDP, "Missing JSEP offer");
		const char *msg_sdp = json_string_value(json_object_get(jsep, "sdp"));
		if(msg_sdp == NULL)
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_SDP, "Missing SDP");
		char error_str[512];
		janus_sdp *offer = janus_sdp_parse(msg_sdp, error_str, sizeof(error_str));
		if(offer == NULL)
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_SDP, error_str);
		janus_sdp *answer = janus_sdp_generate_answer(offer);
		GList *temp = offer->m_lines;
		while(temp) {
			janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
			janus_sdp_generate_answer_mline(offer, answer, m,
				JANUS_SDP_OA_MLINE, m->type,
				JANUS_SDP_OA_CODEC, (m->type == JANUS_SDP_VIDEO ? "h264" : NULL),
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_MID,
				JANUS_SDP_OA_ACCEPT_EXTMAP, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION,
				JANUS_SDP_OA_DONE);
			temp = temp->next;
		}
		janus_sdp_mline *m = janus_sdp_mline_find(answer, JANUS_SDP_AUDIO);
		if(m)
			m->direction = JANUS_SDP_INACTIVE;
		const char *vcodec = NULL;
		janus_sdp_find_first_codec(answer, JANUS_SDP_VIDEO, -1, &vcodec);
		janus_mutex_lock(&session->mutex);
		session->vcodec = vcodec ? janus_videocodec_from_name(vcodec) : JANUS_VIDEOCODEC_NONE;
		session->has_video = session->vcodec == JANUS_VIDEOCODEC_H264;
		g_free(session->vfmtp);
		session->vfmtp = NULL;
		if(session->has_video) {
			const char *vfmtp = janus_sdp_get_fmtp(answer, -1, janus_sdp_get_codec_pt(answer, -1, vcodec));
			if(vfmtp)
				session->vfmtp = g_strdup(vfmtp);
		}
		janus_mutex_unlock(&session->mutex);
		if(!session->has_video) {
			janus_sdp_destroy(offer);
			janus_sdp_destroy(answer);
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_SDP, "Could not negotiate H.264 video");
		}
		char *sdp = janus_sdp_write(answer);
		janus_sdp_destroy(offer);
		janus_sdp_destroy(answer);
		json_t *event = json_object();
		json_object_set_new(event, "screenshot", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		json_t *local_jsep = json_pack("{ssss}", "type", "answer", "sdp", sdp);
		gateway->push_event(handle, &janus_screenshot_plugin, transaction, event, local_jsep);
		g_free(sdp);
		json_decref(event);
		json_decref(local_jsep);
		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else if(!strcasecmp(request, "take") || !strcasecmp(request, "take_screenshot")) {
		JANUS_VALIDATE_JSON_OBJECT(message, take_parameters, error_code, error_cause, TRUE,
			JANUS_SCREENSHOT_ERROR_INVALID_REQUEST, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			return janus_screenshot_error(transaction, error_code, error_cause);
		const char *format = json_string_value(json_object_get(message, "format"));
		if(format == NULL)
			format = "png";
		if(!janus_screenshot_valid_format(format))
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT, "Unsupported format");
		const char *filename = json_string_value(json_object_get(message, "filename"));
		char generated[1024];
		if(filename == NULL) {
			g_snprintf(generated, sizeof(generated), "%s/screenshot-%"SCNi64".%s",
				screenshots_path, janus_get_real_time(), janus_screenshot_extension(format));
			filename = generated;
		}
		json_t *id_req = json_object_get(message, "id");
		janus_mutex_lock(&session->mutex);
		gboolean webrtc_ready = session->started && session->has_video;
		gboolean capture_rtp = FALSE;
		guint64 capture_id = 0;
		if(webrtc_ready) {
			/* Capture from the negotiated WebRTC PeerConnection */
		} else if(rtp_enabled) {
			/* Capture from a forwarded RTP stream, selected by id */
			if(id_req == NULL) {
				janus_mutex_unlock(&session->mutex);
				return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT, "Missing stream id");
			}
			capture_id = json_integer_value(id_req);
			if(janus_screenshot_find_stream(capture_id) == NULL) {
				janus_mutex_unlock(&session->mutex);
				return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT, "Unknown stream id");
			}
			session->vcodec = JANUS_VIDEOCODEC_H264;
			capture_rtp = TRUE;
		} else {
			janus_mutex_unlock(&session->mutex);
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_STATE, "No active H.264 video session");
		}
		if(session->pending) {
			janus_mutex_unlock(&session->mutex);
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_STATE, "Screenshot already pending");
		}
		g_free(session->format);
		g_free(session->filename);
		g_free(session->transaction);
		session->format = g_strdup(format);
		session->filename = g_strdup(filename);
		session->transaction = g_strdup(transaction);
		session->capture_rtp = capture_rtp;
		session->capture_id = capture_id;
		session->pending = TRUE;
		session->capturing = FALSE;
		g_byte_array_set_size(session->frame, 0);
		janus_mutex_unlock(&session->mutex);
		gateway->send_pli(handle);
		json_t *event = json_object();
		json_object_set_new(event, "screenshot", json_string("event"));
		json_object_set_new(event, "status", json_string("requested"));
		json_object_set_new(event, "format", json_string(format));
		json_object_set_new(event, "filename", json_string(filename));
		if(capture_rtp)
			json_object_set_new(event, "id", json_integer(capture_id));
		return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, event);
	} else if(!strcasecmp(request, "get") || !strcasecmp(request, "get_screenshot")) {
		JANUS_VALIDATE_JSON_OBJECT(message, get_parameters, error_code, error_cause, TRUE,
			JANUS_SCREENSHOT_ERROR_INVALID_REQUEST, JANUS_SCREENSHOT_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			return janus_screenshot_error(transaction, error_code, error_cause);
		gboolean include_data = json_object_get(message, "include_data") == NULL || json_is_true(json_object_get(message, "include_data"));
		janus_mutex_lock(&session->mutex);
		char *filename = g_strdup(session->last_filename);
		char *format = g_strdup(session->last_format);
		char *content_type = g_strdup(session->last_content_type);
		janus_mutex_unlock(&session->mutex);
		if(filename == NULL) {
			g_free(format);
			g_free(content_type);
			return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_STATE, "No screenshot available");
		}
		json_t *event = json_object();
		json_object_set_new(event, "screenshot", json_string("event"));
		json_object_set_new(event, "status", json_string("ok"));
		json_object_set_new(event, "filename", json_string(filename));
		json_object_set_new(event, "format", json_string(format ? format : ""));
		json_object_set_new(event, "content_type", json_string(content_type ? content_type : ""));
		if(include_data) {
			gchar *contents = NULL;
			gsize len = 0;
			if(g_file_get_contents(filename, &contents, &len, NULL)) {
				gchar *encoded = g_base64_encode((const guchar *)contents, len);
				json_object_set_new(event, "data", json_string(encoded));
				g_free(encoded);
				g_free(contents);
			}
		}
		g_free(filename);
		g_free(format);
		g_free(content_type);
		return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, event);
	}
	return janus_screenshot_error(transaction, JANUS_SCREENSHOT_ERROR_INVALID_REQUEST, "Unknown request");
}
