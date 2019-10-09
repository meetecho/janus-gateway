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


/* WebSockets properties */
static char *backend = NULL;
static const char *protocol = NULL, *address = NULL, *path = NULL;
static int port = 0;
static struct lws_context *context = NULL;
static gint64 disconnected = 0;
static gboolean reconnect = FALSE;
static int reconnect_retries = 0;

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
	{ NULL, janus_wsevh_callback, sizeof(janus_wsevh_client), 0 },	/* Subprotocol will be configurable */
	{ NULL, NULL, 0, 0 }
};
static const struct lws_extension exts[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate, "permessage-deflate; client_max_window_bits" },
	{ "deflate-frame", lws_extension_callback_pm_deflate, "deflate_frame" },
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
	if(lws_parse_uri(backend, &protocol, &address, &port, &path)) {
		JANUS_LOG(LOG_FATAL, "Error parsing address\n");
		goto error;
	}
	if(strcasecmp(protocol, "ws") || !strlen(address)) {
		JANUS_LOG(LOG_FATAL, "Invalid address (only ws:// and wss:// addresses are supported)\n");
		JANUS_LOG(LOG_FATAL, "  -- Protocol: %s\n", protocol);
		JANUS_LOG(LOG_FATAL, "  -- Address:  %s\n", address);
		JANUS_LOG(LOG_FATAL, "  -- Path:     %s\n", path);
		goto error;
	}
	/* Before connecting, let's check if the server expects a subprotocol */
	item = janus_config_get(config, config_general, janus_config_type_item, "subprotocol");
	if(item && item->value)
		protocols[0].name = g_strdup(item->value);

	/* Connect */
	JANUS_LOG(LOG_VERB, "WebSocketsEventHandler: Connecting to WebSockets server...\n");
	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;
	info.options = 0;
	context = lws_create_context(&info);
	if(context == NULL) {
		JANUS_LOG(LOG_FATAL, "Creating libwebsocket context failed\n");
		goto error;
	}
	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.host = address;
	i.origin = address;
	i.address = address;
	i.port = port;
	i.path = path;
	i.context = context;
	i.ssl_connection = 0;
	i.ietf_version_or_minus_one = -1;
	i.client_exts = exts;
	i.protocol = protocols[0].name;
	i.method = NULL;
	wsi = lws_client_connect_via_info(&i);
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
		goto error;
	}
	/* Start another thread to handle incoming events */
	error = NULL;
	handler_thread = g_thread_try_new("janus wsevh handler", janus_wsevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the WebSocketsEventHandler handler thread...\n",
			error->code, error->message ? error->message : "??");
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

/* Thread to implement the WebSockets loop */
static void *janus_wsevh_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining WebSocketsEventHandler client thread\n");
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Loop until we have to stop */
		lws_service(context, 50);
		if(reconnect) {
			/* We should reconnect, get rid of the previous context */
			if(reconnect_retries > 0) {
				/* Wait a few seconds before retrying */
				gint64 now = janus_get_monotonic_time();
				if((now-disconnected) < reconnect_retries*G_USEC_PER_SEC) {
					/* Try again later */
					g_usleep(100000);
					continue;
				}
			}
			if(reconnect_retries == 0)
				reconnect_retries++;
			else
				reconnect_retries += reconnect_retries;
			JANUS_LOG(LOG_WARN, "Reconnecting to WebSockets event handler backend... (next retry in %ds)\n",
				reconnect_retries);
			ws_client = NULL;
			wsi = NULL;
			struct lws_client_connect_info i;
			memset(&i, 0, sizeof(i));
			i.host = address;
			i.origin = address;
			i.address = address;
			i.port = port;
			i.path = path;
			i.context = context;
			i.ssl_connection = 0;
			i.ietf_version_or_minus_one = -1;
			i.client_exts = exts;
			i.protocol = protocols[0].name;
			i.method = NULL;
			wsi = lws_client_connect_via_info(&i);
			if(wsi == NULL) {
				JANUS_LOG(LOG_WARN, "Error attempting reconnection...\n");
				continue;
			}
			reconnect = FALSE;
		}
	}
	lws_context_destroy(context);
	JANUS_LOG(LOG_VERB, "Leaving WebSocketsEventHandler client thread\n");
	return NULL;
}

/* Thread to handle incoming events */
static void *janus_wsevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining WebSocketsEventHandler handler thread\n");
	json_t *event = NULL, *output = NULL;
	char *event_text = NULL;
	int count = 0, max = group_events ? 100 : 1;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {

		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
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
	if(ws_client == NULL)
		ws_client = (janus_wsevh_client *)user;
	switch(reason) {
		case LWS_CALLBACK_CLIENT_ESTABLISHED: {
			/* Prepare the session */
			ws_client->wsi = wsi;
			ws_client->buffer = NULL;
			ws_client->buflen = 0;
			ws_client->bufpending = 0;
			ws_client->bufoffset = 0;
			reconnect_retries = 0;
			janus_mutex_init(&ws_client->mutex);
			return 0;
		}
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
			JANUS_LOG(LOG_ERR, "Error connecting to backend\n");
			/* Should we reconnect? */
			disconnected = janus_get_monotonic_time();
			reconnect = TRUE;
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
					int buflen = LWS_SEND_BUFFER_PRE_PADDING + strlen(event) + LWS_SEND_BUFFER_POST_PADDING;
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
					memcpy(ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, event, strlen(event));
					JANUS_LOG(LOG_VERB, "Sending WebSocket message (%zu bytes)...\n", strlen(event));
					int sent = lws_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(event), LWS_WRITE_TEXT);
					JANUS_LOG(LOG_VERB, "  -- Sent %d/%zu bytes\n", sent, strlen(event));
					if(sent > -1 && sent < (int)strlen(event)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						ws_client->bufpending = strlen(event) - sent;
						ws_client->bufoffset = LWS_SEND_BUFFER_PRE_PADDING + sent;
						JANUS_LOG(LOG_VERB, "  -- Couldn't write all bytes (%d missing), setting offset %d\n",
							ws_client->bufpending, ws_client->bufoffset);
					}
					/* We can get rid of the message */
					g_free(event);
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
			JANUS_LOG(LOG_INFO, "WebSockets event handler connection closed\n");
			if(ws_client != NULL) {
				/* Cleanup */
				janus_mutex_lock(&ws_client->mutex);
				JANUS_LOG(LOG_INFO, "Destroying WebSockets event handler client\n");
				ws_client->wsi = NULL;
				/* Free the shared buffers */
				g_free(ws_client->buffer);
				ws_client->buffer = NULL;
				ws_client->buflen = 0;
				ws_client->bufpending = 0;
				ws_client->bufoffset = 0;
				janus_mutex_unlock(&ws_client->mutex);
			}
			JANUS_LOG(LOG_INFO, "Connection to WebSockets event handler backend closed\n");
			/* Check if we should reconnect */
			ws_client = NULL;
			wsi = NULL;
			disconnected = janus_get_monotonic_time();
			reconnect = TRUE;
			return 0;
		}
		default:
			if(wsi)
				JANUS_LOG(LOG_HUGE, "%d (%s)\n", reason, janus_wsevh_reason_string(reason));
			break;
	}
	return 0;
}
