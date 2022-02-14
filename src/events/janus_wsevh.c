/*! \file   janus_wsevh.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus WebSockets EventHandler plugin
 * \details  This is a trivial WebSockets event handler plugin for Janus
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>

#include <libwebsockets.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"


/* Plugin information */
#define JANUS_WSEVH_VERSION			1
#define JANUS_WSEVH_VERSION_STRING	"0.0.1"
#define JANUS_WSEVH_DESCRIPTION		"This is a trivial WebSockets event handler plugin for Janus."
#define JANUS_WSEVH_NAME			"JANUS WebSocketsEventHandler plugin"
#define JANUS_WSEVH_AUTHOR			"Meetecho s.r.l."
#define JANUS_WSEVH_PACKAGE			"janus.eventhandler.wsevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_wsevh_init(const char *config_path);
void janus_wsevh_destroy(void);
int janus_wsevh_get_api_compatibility(void);
int janus_wsevh_get_version(void);
const char *janus_wsevh_get_version_string(void);
const char *janus_wsevh_get_description(void);
const char *janus_wsevh_get_name(void);
const char *janus_wsevh_get_author(void);
const char *janus_wsevh_get_package(void);
void janus_wsevh_incoming_event(json_t *event);
json_t *janus_wsevh_handle_request(json_t *request);

/* Event handler setup */
static janus_eventhandler janus_wsevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_wsevh_init,
		.destroy = janus_wsevh_destroy,

		.get_api_compatibility = janus_wsevh_get_api_compatibility,
		.get_version = janus_wsevh_get_version,
		.get_version_string = janus_wsevh_get_version_string,
		.get_description = janus_wsevh_get_description,
		.get_name = janus_wsevh_get_name,
		.get_author = janus_wsevh_get_author,
		.get_package = janus_wsevh_get_package,

		.incoming_event = janus_wsevh_incoming_event,
		.handle_request = janus_wsevh_handle_request,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_WSEVH_NAME);
	return &janus_wsevh;
}

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *ws_thread, *handler_thread;
static void *janus_wsevh_thread(void *data);
static void *janus_wsevh_handler(void *data);

/* Connection related helper methods */
static void janus_wsevh_schedule_connect_attempt(void);
static void janus_wsevh_calculate_reconnect_delay_on_fail(void);
/* lws_sorted_usec_list_t is defined starting with lws 3.2 */
#if !(((LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || LWS_LIBRARY_VERSION_MAJOR >= 4))
	#define lws_sorted_usec_list_t void
#endif
static void janus_wsevh_connect_attempt(lws_sorted_usec_list_t *sul);

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static gboolean group_events = TRUE;
static json_t exit_event;
static void janus_wsevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
	{"grouping", JANUS_JSON_BOOL, 0}
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_WSEVH_ERROR_INVALID_REQUEST		411
#define JANUS_WSEVH_ERROR_MISSING_ELEMENT		412
#define JANUS_WSEVH_ERROR_INVALID_ELEMENT		413
#define JANUS_WSEVH_ERROR_UNKNOWN_ERROR			499

/* Logging */
static int wsevh_log_level = 0;
static const char *janus_wsevh_get_level_str(int level) {
	switch(level) {
		case LLL_ERR:
			return "ERR";
		case LLL_WARN:
			return "WARN";
		case LLL_NOTICE:
			return "NOTICE";
		case LLL_INFO:
			return "INFO";
		case LLL_DEBUG:
			return "DEBUG";
		case LLL_PARSER:
			return "PARSER";
		case LLL_HEADER:
			return "HEADER";
		case LLL_EXT:
			return "EXT";
		case LLL_CLIENT:
			return "CLIENT";
		case LLL_LATENCY:
			return "LATENCY";
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
		case LLL_USER:
			return "USER";
#endif
		case LLL_COUNT:
			return "COUNT";
		default:
			return NULL;
	}
}
static void janus_wsevh_log_emit_function(int level, const char *line) {
	/* FIXME Do we want to use different Janus debug levels according to the level here? */
	JANUS_LOG(LOG_INFO, "[libwebsockets][wsevh][%s] %s", janus_wsevh_get_level_str(level), line);
}


/* WebSockets properties */
static char *backend = NULL;
static const char *protocol = NULL, *address = NULL;
static char path[256];
static int port = 0;
static struct lws_context *context = NULL;
#if ((LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || LWS_LIBRARY_VERSION_MAJOR >= 4)
static lws_sorted_usec_list_t sul_stagger = { 0 };
#endif
static gint64 disconnected = 0;
static gboolean reconnect = FALSE;
static int reconnect_delay = 0;
#define JANUS_WSEVH_MAX_RETRY_SECS	8

typedef struct janus_wsevh_client {
	struct lws *wsi;		/* The libwebsockets client instance */
	unsigned char *buffer;	/* Buffer containing the message to send */
	int buflen;				/* Length of the buffer (may be resized after re-allocations) */
	int bufpending;			/* Data an interrupted previous write couldn't send */
	int bufoffset;			/* Offset from where the interrupted previous write should resume */
	janus_mutex mutex;		/* Mutex to lock/unlock this instance */
} janus_wsevh_client;
static janus_wsevh_client *ws_client = NULL;
static struct lws *wsi = NULL;
static GAsyncQueue *messages = NULL;	/* Queue of outgoing messages to push */
static janus_mutex writable_mutex;

static int janus_wsevh_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
static struct lws_protocols protocols[] = {
	{ "janus-event-handlers", janus_wsevh_callback, sizeof(janus_wsevh_client), 0 },	/* Subprotocol will be configurable */
	{ NULL, NULL, 0, 0 }
};
static const struct lws_extension exts[] = {
#ifndef LWS_WITHOUT_EXTENSIONS
	{ "permessage-deflate", lws_extension_callback_pm_deflate, "permessage-deflate; client_max_window_bits" },
	{ "deflate-frame", lws_extension_callback_pm_deflate, "deflate_frame" },
#endif
	{ NULL, NULL, NULL }
};

/* WebSockets error management */
#define CASE_STR(name) case name: return #name
static const char *janus_wsevh_reason_string(enum lws_callback_reasons reason) {
	switch(reason) {
		CASE_STR(LWS_CALLBACK_ESTABLISHED);
		CASE_STR(LWS_CALLBACK_CLIENT_CONNECTION_ERROR);
		CASE_STR(LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH);
		CASE_STR(LWS_CALLBACK_CLIENT_ESTABLISHED);
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		CASE_STR(LWS_CALLBACK_CLIENT_CLOSED);
#endif
		CASE_STR(LWS_CALLBACK_CLOSED);
		CASE_STR(LWS_CALLBACK_CLOSED_HTTP);
		CASE_STR(LWS_CALLBACK_RECEIVE);
		CASE_STR(LWS_CALLBACK_CLIENT_RECEIVE);
		CASE_STR(LWS_CALLBACK_CLIENT_RECEIVE_PONG);
		CASE_STR(LWS_CALLBACK_CLIENT_WRITEABLE);
		CASE_STR(LWS_CALLBACK_SERVER_WRITEABLE);
		CASE_STR(LWS_CALLBACK_HTTP);
		CASE_STR(LWS_CALLBACK_HTTP_BODY);
		CASE_STR(LWS_CALLBACK_HTTP_BODY_COMPLETION);
		CASE_STR(LWS_CALLBACK_HTTP_FILE_COMPLETION);
		CASE_STR(LWS_CALLBACK_HTTP_WRITEABLE);
		CASE_STR(LWS_CALLBACK_FILTER_NETWORK_CONNECTION);
		CASE_STR(LWS_CALLBACK_FILTER_HTTP_CONNECTION);
		CASE_STR(LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED);
		CASE_STR(LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION);
		CASE_STR(LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS);
		CASE_STR(LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS);
		CASE_STR(LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION);
		CASE_STR(LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER);
		CASE_STR(LWS_CALLBACK_CONFIRM_EXTENSION_OKAY);
		CASE_STR(LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED);
		CASE_STR(LWS_CALLBACK_PROTOCOL_INIT);
		CASE_STR(LWS_CALLBACK_PROTOCOL_DESTROY);
		CASE_STR(LWS_CALLBACK_WSI_CREATE);
		CASE_STR(LWS_CALLBACK_WSI_DESTROY);
		CASE_STR(LWS_CALLBACK_GET_THREAD_ID);
		CASE_STR(LWS_CALLBACK_ADD_POLL_FD);
		CASE_STR(LWS_CALLBACK_DEL_POLL_FD);
		CASE_STR(LWS_CALLBACK_CHANGE_MODE_POLL_FD);
		CASE_STR(LWS_CALLBACK_LOCK_POLL);
		CASE_STR(LWS_CALLBACK_UNLOCK_POLL);
		CASE_STR(LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY);
		CASE_STR(LWS_CALLBACK_USER);
		default:
			break;
	}
	return NULL;
}


/* Plugin implementation */
int janus_wsevh_init(const char *config_path) {
	gboolean success = TRUE;
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}
	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_WSEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_WSEVH_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_WSEVH_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL)
		janus_config_print(config);
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

	/* Setup the event handler, if required */
	janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "WebSockets event handler disabled\n");
		goto error;
	}

	item = janus_config_get(config, config_general, janus_config_type_item, "json");
	if(item && item->value) {
		/* Check how we need to format/serialize the JSON output */
		if(!strcasecmp(item->value, "indented")) {
			/* Default: indented, we use three spaces for that */
			json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(item->value, "plain")) {
			/* Not indented and no new lines, but still readable */
			json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
		} else if(!strcasecmp(item->value, "compact")) {
			/* Compact, so no spaces between separators */
			json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", item->value);
			json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
		}
	}

	item = janus_config_get(config, config_general, janus_config_type_item, "ws_logging");
	if(item && item->value) {
		/* libwebsockets uses a mask to set log levels, as documented here:
		 * https://libwebsockets.org/lws-api-doc-master/html/group__log.html */
		if(strstr(item->value, "none")) {
			/* Disable libwebsockets logging completely (the default) */
		} else if(strstr(item->value, "all")) {
			/* Enable all libwebsockets logging */
			wsevh_log_level = LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
				LLL_DEBUG | LLL_PARSER | LLL_HEADER | LLL_EXT |
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
				LLL_CLIENT | LLL_LATENCY | LLL_USER | LLL_COUNT;
#else
				LLL_CLIENT | LLL_LATENCY | LLL_COUNT;
#endif
		} else {
			/* Only enable some of the properties */
			if(strstr(item->value, "err"))
				wsevh_log_level |= LLL_ERR;
			if(strstr(item->value, "warn"))
				wsevh_log_level |= LLL_WARN;
			if(strstr(item->value, "notice"))
				wsevh_log_level |= LLL_NOTICE;
			if(strstr(item->value, "info"))
				wsevh_log_level |= LLL_INFO;
			if(strstr(item->value, "debug"))
				wsevh_log_level |= LLL_DEBUG;
			if(strstr(item->value, "parser"))
				wsevh_log_level |= LLL_PARSER;
			if(strstr(item->value, "header"))
				wsevh_log_level |= LLL_HEADER;
			if(strstr(item->value, "ext"))
				wsevh_log_level |= LLL_EXT;
			if(strstr(item->value, "client"))
				wsevh_log_level |= LLL_CLIENT;
			if(strstr(item->value, "latency"))
				wsevh_log_level |= LLL_LATENCY;
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
			if(strstr(item->value, "user"))
				wsevh_log_level |= LLL_USER;
#endif
			if(strstr(item->value, "count"))
				wsevh_log_level |= LLL_COUNT;
		}
	}
	if(wsevh_log_level > 0)
		JANUS_LOG(LOG_INFO, "WebSockets event handler libwebsockets logging: %d\n", wsevh_log_level);
	lws_set_log_level(wsevh_log_level, janus_wsevh_log_emit_function);

	/* Which events should we subscribe to? */
	item = janus_config_get(config, config_general, janus_config_type_item, "events");
	if(item && item->value)
		janus_events_edit_events_mask(item->value, &janus_wsevh.events_mask);

	/* Is grouping of events ok? */
	item = janus_config_get(config, config_general, janus_config_type_item, "grouping");
	if(item && item->value)
		group_events = janus_is_true(item->value);

	/* Handle the rest of the configuration, starting from the server details */
	item = janus_config_get(config, config_general, janus_config_type_item, "backend");
	if(item && item->value)
		backend = g_strdup(item->value);
	if(backend == NULL) {
		JANUS_LOG(LOG_FATAL, "Missing WebSockets backend\n");
		goto error;
	}
	const char *p = NULL;
	if(lws_parse_uri(backend, &protocol, &address, &port, &p)) {
		JANUS_LOG(LOG_FATAL, "Error parsing address\n");
		goto error;
	}
	if((strcasecmp(protocol, "ws") && strcasecmp(protocol, "wss")) || !strlen(address)) {
		JANUS_LOG(LOG_FATAL, "Invalid address (only ws:// and wss:// addresses are supported)\n");
		JANUS_LOG(LOG_FATAL, "  -- Protocol: %s\n", protocol);
		JANUS_LOG(LOG_FATAL, "  -- Address:  %s\n", address);
		JANUS_LOG(LOG_FATAL, "  -- Path:     %s\n", p);
		goto error;
	}
	path[0] = '/';
	if(strlen(p) > 1)
		g_strlcpy(path + 1, p, sizeof(path)-2);
	/* Before connecting, let's check if the server expects a subprotocol */
	item = janus_config_get(config, config_general, janus_config_type_item, "subprotocol");
	if(item && item->value)
		protocols[0].name = g_strdup(item->value);

	/* Connect */
	gboolean secure = !strcasecmp(protocol, "wss");
	struct lws_context_creation_info info = { 0 };
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;
#if ((LWS_LIBRARY_VERSION_MAJOR == 4 && LWS_LIBRARY_VERSION_MINOR >= 1) || LWS_LIBRARY_VERSION_MAJOR >= 5)
	info.connect_timeout_secs = 5;
#endif
	if(secure)
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	context = lws_create_context(&info);
	if(context == NULL) {
		JANUS_LOG(LOG_FATAL, "Creating libwebsocket context failed\n");
		goto error;
	}
	janus_wsevh_connect_attempt(NULL);
	if(wsi == NULL) {
		JANUS_LOG(LOG_FATAL, "Error initializing WebSocket connection\n");
		goto error;
	}
	janus_mutex_init(&writable_mutex);

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_wsevh_event_free);
	messages = g_async_queue_new();
	g_atomic_int_set(&initialized, 1);

	/* Start a thread to handle the WebSockets event loop */
	GError *error = NULL;
	ws_thread = g_thread_try_new("janus wsevh client", janus_wsevh_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the WebSocketsEventHandler client thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		goto error;
	}
	/* Start another thread to handle incoming events */
	error = NULL;
	handler_thread = g_thread_try_new("janus wsevh handler", janus_wsevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the WebSocketsEventHandler handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		goto error;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Setup of WebSockets event handler completed\n");
	goto done;

error:
	/* If we got here, something went wrong */
	success = FALSE;
	/* Fall through */
done:
	if(config)
		janus_config_destroy(config);
	if(!success) {
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_WSEVH_NAME);
	return 0;
}

void janus_wsevh_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);
#if ((LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || LWS_LIBRARY_VERSION_MAJOR >= 4)
	lws_cancel_service(context);
#endif

	if(ws_thread != NULL) {
		g_thread_join(ws_thread);
		ws_thread = NULL;
	}

	g_async_queue_push(events, &exit_event);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	g_async_queue_unref(events);
	events = NULL;

	char *message = NULL;
	while((message = g_async_queue_try_pop(messages)) != NULL) {
		g_free(message);
	}
	g_async_queue_unref(messages);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_WSEVH_NAME);
}

int janus_wsevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_wsevh_get_version(void) {
	return JANUS_WSEVH_VERSION;
}

const char *janus_wsevh_get_version_string(void) {
	return JANUS_WSEVH_VERSION_STRING;
}

const char *janus_wsevh_get_description(void) {
	return JANUS_WSEVH_DESCRIPTION;
}

const char *janus_wsevh_get_name(void) {
	return JANUS_WSEVH_NAME;
}

const char *janus_wsevh_get_author(void) {
	return JANUS_WSEVH_AUTHOR;
}

const char *janus_wsevh_get_package(void) {
	return JANUS_WSEVH_PACKAGE;
}

void janus_wsevh_incoming_event(json_t *event) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		/* Janus is closing or the plugin is */
		return;
	}

	/* Do NOT handle the event here in this callback! Since Janus notifies you right
	 * away when something happens, these events are triggered from working threads and
	 * not some sort of message bus. As such, performing I/O or network operations in
	 * here could dangerously slow Janus down. Let's just reference and enqueue the event,
	 * and handle it in our own thread: the event contains a monotonic time indicator of
	 * when the event actually happened on this machine, so that, if relevant, we can compute
	 * any delay in the actual event processing ourselves. */
	json_incref(event);
	g_async_queue_push(events, event);
}

json_t *janus_wsevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_WSEVH_ERROR_MISSING_ELEMENT, JANUS_WSEVH_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_WSEVH_ERROR_MISSING_ELEMENT, JANUS_WSEVH_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Events */
		if(json_object_get(request, "events"))
			janus_events_edit_events_mask(json_string_value(json_object_get(request, "events")), &janus_wsevh.events_mask);
		/* Grouping */
		if(json_object_get(request, "grouping"))
			group_events = json_is_true(json_object_get(request, "grouping"));
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_WSEVH_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			json_t *response = json_object();
			if(error_code == 0) {
				/* Return a success */
				json_object_set_new(response, "result", json_integer(200));
			} else {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}

#if (LWS_LIBRARY_VERSION_MAJOR >= 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 4)
/* Websocket thread loop for websocket library newer than 3.2
 * The reconnect is handled in a dedicated lws scheduler janus_wsevh_schedule_connect_attempt */
static void *janus_wsevh_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining WebSocketsEventHandler (lws>=3.2) client thread\n");
	int nLast = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		int n = lws_service(context, 0);
		if((n < 0 || nLast < 0) && nLast != n) {
			JANUS_LOG(LOG_ERR, "lws_service returned %d\n", n);
			nLast = n;
		}
	}
	lws_context_destroy(context);
	JANUS_LOG(LOG_VERB, "Leaving WebSocketsEventHandler (lws>=3.2) client thread\n");
	return NULL;
}
#else
/* Websocket thread loop for websocket library prior to (less than) 3.2
 * The reconnect is handled in the loop for lws < 3.2 */
static void *janus_wsevh_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining WebSocketsEventHandler (lws<3.2) client thread\n");
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Loop until we have to stop */
		if(!reconnect) {
			lws_service(context, 50);
		} else {
			/* We should reconnect, get rid of the previous context */
			if(reconnect_delay > 0) {
				/* Wait a few seconds before retrying */
				gint64 now = janus_get_monotonic_time();
				if((now-disconnected) < (gint64)reconnect_delay*G_USEC_PER_SEC) {
					/* Try again later */
					g_usleep(100000);
					continue;
				}
			}
			ws_client = NULL;
			janus_wsevh_connect_attempt(NULL);
			if(!wsi) {
				janus_wsevh_calculate_reconnect_delay_on_fail();
				JANUS_LOG(LOG_WARN, "WebSocketsEventHandler: Error attempting connection... (next retry in %ds)\n", reconnect_delay);
			}
		}
	}
	lws_context_destroy(context);
	JANUS_LOG(LOG_VERB, "Leaving WebSocketsEventHandler (lws<3.2) client thread\n");
	return NULL;
}
#endif

/* Thread to handle incoming events */
static void *janus_wsevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining WebSocketsEventHandler handler thread\n");
	json_t *event = NULL, *output = NULL;
	char *event_text = NULL;
	int count = 0, max = group_events ? 100 : 1;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {

		event = g_async_queue_pop(events);
		if(event == &exit_event)
			break;
		count = 0;
		output = NULL;

		while(TRUE) {
			/* Handle event: just for fun, let's see how long it took for us to take care of this */
			json_t *created = json_object_get(event, "timestamp");
			if(created && json_is_integer(created)) {
				gint64 then = json_integer_value(created);
				gint64 now = janus_get_monotonic_time();
				JANUS_LOG(LOG_DBG, "Handled event after %"SCNu64" us\n", now-then);
			}
			if(!group_events) {
				/* We're done here, we just need a single event */
				output = event;
				break;
			}
			/* If we got here, we're grouping */
			if(output == NULL)
				output = json_array();
			json_array_append_new(output, event);
			/* Never group more than a maximum number of events, though, or we might stay here forever */
			count++;
			if(count == max)
				break;
			event = g_async_queue_try_pop(events);
			if(event == NULL || event == &exit_event)
				break;
		}

		if(!g_atomic_int_get(&stopping)) {
			/* Since this a simple plugin, it does the same for all events: so just convert to string... */
			event_text = json_dumps(output, json_format);
			if(event_text == NULL) {
				JANUS_LOG(LOG_WARN, "Failed to stringify event, event lost...\n");
				/* Nothing we can do... get rid of the event */
				json_decref(output);
				output = NULL;
				continue;
			}
			g_async_queue_push(messages, event_text);
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
			if(context != NULL)
				lws_cancel_service(context);
#else
			/* On libwebsockets < 3.x we use lws_callback_on_writable */
			janus_mutex_lock(&writable_mutex);
			if(wsi != NULL)
				lws_callback_on_writable(wsi);
			janus_mutex_unlock(&writable_mutex);
#endif
		}

		/* Done, let's unref the event */
		json_decref(output);
		output = NULL;
	}
	JANUS_LOG(LOG_VERB, "Leaving WebSocketsEventHandler handler thread\n");
	return NULL;
}

static int janus_wsevh_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
	switch(reason) {
		case LWS_CALLBACK_CLIENT_ESTABLISHED: {
			/* Prepare the session */
			if(ws_client == NULL)
				ws_client = (janus_wsevh_client *)user;
			ws_client->wsi = wsi;
			ws_client->buffer = NULL;
			ws_client->buflen = 0;
			ws_client->bufpending = 0;
			ws_client->bufoffset = 0;
			reconnect_delay = 0;
			reconnect = FALSE;
			janus_mutex_init(&ws_client->mutex);
			lws_callback_on_writable(wsi);
			JANUS_LOG(LOG_INFO, "WebSocketsEventHandler connected\n");
			return 0;
		}
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
			janus_wsevh_calculate_reconnect_delay_on_fail();
			JANUS_LOG(LOG_ERR, "WebSocketsEventHandler: Error connecting to backend (%s) (next retry in %ds)\n",
				in ? (char *)in : "unknown error",
				reconnect_delay);
			disconnected = janus_get_monotonic_time();
			reconnect = TRUE;
			janus_wsevh_schedule_connect_attempt();
			return 1;
		}
		case LWS_CALLBACK_CLIENT_RECEIVE: {
			/* We don't care */
			return 0;
		}
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		/* On libwebsockets >= 3.x, we use this event to mark connections as writable in the event loop */
		case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
			if(ws_client != NULL && ws_client->wsi != NULL)
				lws_callback_on_writable(ws_client->wsi);
			return 0;
		}
#endif
		case LWS_CALLBACK_CLIENT_WRITEABLE: {
			if(ws_client == NULL || ws_client->wsi == NULL) {
				JANUS_LOG(LOG_ERR, "Invalid WebSocket client instance...\n");
				return -1;
			}
			if(!g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->mutex);
				/* Check if we have a pending/partial write to complete first */
				if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0
						&& !g_atomic_int_get(&stopping)) {
					JANUS_LOG(LOG_VERB, "Completing pending WebSocket write (still need to write last %d bytes)...\n",
						ws_client->bufpending);
					int sent = lws_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
					JANUS_LOG(LOG_VERB, "  -- Sent %d/%d bytes\n", sent, ws_client->bufpending);
					if(sent > -1 && sent < ws_client->bufpending) {
						/* We still couldn't send everything that was left, we'll try and complete this in the next round */
						ws_client->bufpending -= sent;
						ws_client->bufoffset += sent;
					} else {
						/* Clear the pending/partial write queue */
						ws_client->bufpending = 0;
						ws_client->bufoffset = 0;
					}
					/* Done for this round, check the next response/notification later */
					lws_callback_on_writable(wsi);
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				/* Shoot all the pending messages */
				char *event = g_async_queue_try_pop(messages);
				if(event && !g_atomic_int_get(&stopping)) {
					/* Gotcha! */
					int buflen = LWS_PRE + strlen(event);
					if(ws_client->buffer == NULL) {
						/* Let's allocate a shared buffer */
						JANUS_LOG(LOG_VERB, "Allocating %d bytes (event is %zu bytes)\n", buflen, strlen(event));
						ws_client->buflen = buflen;
						ws_client->buffer = g_malloc0(buflen);
					} else if(buflen > ws_client->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_VERB, "Re-allocating to %d bytes (was %d, event is %zu bytes)\n",
							buflen, ws_client->buflen, strlen(event));
						ws_client->buflen = buflen;
						ws_client->buffer = g_realloc(ws_client->buffer, buflen);
					}
					memcpy(ws_client->buffer + LWS_PRE, event, strlen(event));
					JANUS_LOG(LOG_VERB, "Sending WebSocket message (%zu bytes)...\n", strlen(event));
					int sent = lws_write(wsi, ws_client->buffer + LWS_PRE, strlen(event), LWS_WRITE_TEXT);
					JANUS_LOG(LOG_VERB, "  -- Sent %d/%zu bytes\n", sent, strlen(event));
					if(sent > -1 && sent < (int)strlen(event)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						ws_client->bufpending = strlen(event) - sent;
						ws_client->bufoffset = LWS_PRE + sent;
						JANUS_LOG(LOG_VERB, "  -- Couldn't write all bytes (%d missing), setting offset %d\n",
							ws_client->bufpending, ws_client->bufoffset);
					}
					/* We can get rid of the message */
					free(event);
					/* Done for this round, check the next response/notification later */
					lws_callback_on_writable(wsi);
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				janus_mutex_unlock(&ws_client->mutex);
			}
			return 0;
		}
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		case LWS_CALLBACK_CLIENT_CLOSED: {
#else
		case LWS_CALLBACK_CLOSED: {
#endif
			reconnect_delay = 1;
			JANUS_LOG(LOG_INFO, "Connection to WebSocketsEventHandler backend closed (next connection attempt in %ds)\n", reconnect_delay);
			if(ws_client != NULL) {
				/* Cleanup */
				janus_mutex_lock(&ws_client->mutex);
				JANUS_LOG(LOG_INFO, "Destroying WebSocketsEventHandler client\n");
				ws_client->wsi = NULL;
				/* Free the shared buffers */
				g_free(ws_client->buffer);
				ws_client->buffer = NULL;
				ws_client->buflen = 0;
				ws_client->bufpending = 0;
				ws_client->bufoffset = 0;
				janus_mutex_unlock(&ws_client->mutex);
			}
			/* Check if we should reconnect */
			ws_client = NULL;
			wsi = NULL;
			disconnected = janus_get_monotonic_time();
			reconnect = TRUE;
			janus_wsevh_schedule_connect_attempt();
			return 0;
		}
		default:
			if(wsi)
				JANUS_LOG(LOG_HUGE, "%d (%s)\n", reason, janus_wsevh_reason_string(reason));
			break;
	}
	return 0;
}

/* Implements the connecting attempt to the backend websocket server
 * sets the connection result (lws_client_connect_info) to static wsi */
static void janus_wsevh_connect_attempt(lws_sorted_usec_list_t *sul) {
	struct lws_client_connect_info i = { 0 };
	i.host = address;
	i.origin = address;
	i.address = address;
	i.port = port;
	i.path = path;
	i.context = context;
	if(!strcasecmp(protocol, "wss"))
		i.ssl_connection = 1;
	i.ietf_version_or_minus_one = -1;
	i.client_exts = exts;
	i.protocol = protocols[0].name;
	JANUS_LOG(LOG_INFO, "WebSocketsEventHandler: Connecting to backend websocket server %s:%d...\n", address, port);
	wsi = lws_client_connect_via_info(&i);
	if(!wsi) {
		/* As we specified a callback pointer in the context the NULL result is unlikely to happen */
		disconnected = janus_get_monotonic_time();
		reconnect = TRUE;
		JANUS_LOG(LOG_ERR, "WebSocketsEventHandler: Connecting to backend websocket server %s:%d failed\n", address, port);
		return;
	}
	reconnect = FALSE;
}

/* Adopts the reconnect_delay value in case of an error
 * Increases the value up to JANUS_WSEVH_MAX_RETRY_SECS */
static void janus_wsevh_calculate_reconnect_delay_on_fail(void) {
	if(reconnect_delay == 0)
		reconnect_delay = 1;
	else if(reconnect_delay < JANUS_WSEVH_MAX_RETRY_SECS) {
		reconnect_delay += reconnect_delay;
		if(reconnect_delay > JANUS_WSEVH_MAX_RETRY_SECS)
			reconnect_delay = JANUS_WSEVH_MAX_RETRY_SECS;
	}
}

/* Schedules a connect attempt using the lws scheduler as */
static void janus_wsevh_schedule_connect_attempt(void) {
	#if (LWS_LIBRARY_VERSION_MAJOR >= 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 4)
		lws_sul_schedule(context, 0, &sul_stagger, janus_wsevh_connect_attempt, reconnect_delay * LWS_US_PER_SEC);
	#endif
}
