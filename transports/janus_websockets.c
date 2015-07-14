/*! \file   janus_websockets.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus WebSockets transport plugin
 * \details  This is an implementation of a WebSockets transport for the
 * Janus API, using the libwebsockets library (http://libwebsockets.org).
 * This means that, with the help of this module, browsers or applications
 * (e.g., nodejs server side implementations) can also make use of
 * WebSockets to make requests to the gateway. In that case, the same
 * WebSocket can be used for both sending requests and receiving
 * notifications, without the need for long polls. At the same time,
 * without the concept of a REST path, requests sent through the
 * WebSockets interface will need to include, when needed, additional
 * pieces of information like \c session_id and \c handle_id. That is,
 * where you'd send a Janus request related to a specific session to the
 * \c /janus/<session> path, with WebSockets you'd have to send the same
 * request with an additional \c session_id field in the JSON payload.
 * The same applies for the handle. The JavaScript library (janus.js)
 * implements all of this on the client side automatically.
 * \note When you create a session using WebSockets, a subscription to
 * the events related to it is done automatically, so no need for an
 * explicit request as the GET in the plain HTTP API. Closing a WebSocket
 * will also destroy all the sessions it created.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <libwebsockets.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_WEBSOCKETS_VERSION			1
#define JANUS_WEBSOCKETS_VERSION_STRING		"0.0.1"
#define JANUS_WEBSOCKETS_DESCRIPTION		"This transport plugin adds WebSockets support to the Janus API via libwebsockets."
#define JANUS_WEBSOCKETS_NAME				"JANUS WebSockets transport plugin"
#define JANUS_WEBSOCKETS_AUTHOR				"Meetecho s.r.l."
#define JANUS_WEBSOCKETS_PACKAGE			"janus.transport.websockets"

/* Transport methods */
janus_transport *create(void);
int janus_websockets_init(janus_transport_callbacks *callback, const char *config_path);
void janus_websockets_destroy(void);
int janus_websockets_get_api_compatibility(void);
int janus_websockets_get_version(void);
const char *janus_websockets_get_version_string(void);
const char *janus_websockets_get_description(void);
const char *janus_websockets_get_name(void);
const char *janus_websockets_get_author(void);
const char *janus_websockets_get_package(void);
int janus_websockets_send_message(void *transport, void *request_id, gboolean admin, json_t *message);
void janus_websockets_session_created(void *transport, guint64 session_id);
void janus_websockets_session_over(void *transport, guint64 session_id, gboolean timeout);


/* Transport setup */
static janus_transport janus_websockets_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_websockets_init,
		.destroy = janus_websockets_destroy,

		.get_api_compatibility = janus_websockets_get_api_compatibility,
		.get_version = janus_websockets_get_version,
		.get_version_string = janus_websockets_get_version_string,
		.get_description = janus_websockets_get_description,
		.get_name = janus_websockets_get_name,
		.get_author = janus_websockets_get_author,
		.get_package = janus_websockets_get_package,
		
		.send_message = janus_websockets_send_message,
		.session_created = janus_websockets_session_created,
		.session_over = janus_websockets_session_over,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_WEBSOCKETS_NAME);
	return &janus_websockets_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static int ws_log_level = 0;

/* WebSockets single thread */
static GThread *thread = NULL;
void *janus_websockets_thread(void *data);


/* WebSocket client session */
typedef struct janus_websockets_client {
	struct libwebsocket_context *context;	/* The libwebsock client context */
	struct libwebsocket *wsi;				/* The libwebsock client instance */
	GAsyncQueue *messages;					/* Queue of outgoing messages to push */
	janus_mutex mutex;						/* Mutex to lock/unlock this session */
	gint session_timeout:1;					/* Whether a Janus session timeout occurred in the core */
	gint destroy:1;							/* Flag to trigger a lazy session destruction */
} janus_websockets_client;


/* libwebsockets WS context(s) */
static struct libwebsocket_context *wss = NULL, *swss = NULL;
/* libwebsockets sessions that have been closed */
static GList *old_wss;
static janus_mutex old_wss_mutex;
/* Callback for HTTP-related events (automatically rejected) */
static int janus_wss_callback_http(struct libwebsocket_context *this, 
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user, void *in, size_t len);
/* Callback for WebSockets-related events */
static int janus_wss_callback(struct libwebsocket_context *this, 
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user, void *in, size_t len);
/* Protocol mapping */
static struct libwebsocket_protocols wss_protocols[] = {
	{ "http-only", janus_wss_callback_http, 0, 0 },
	{ "janus-protocol", janus_wss_callback, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
/* Helper for debugging reasons */
const char *janus_wss_reason_string(enum libwebsocket_callback_reasons reason);
const char *janus_wss_reason_string(enum libwebsocket_callback_reasons reason) {
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED:
			return "LWS_CALLBACK_ESTABLISHED";
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			return "LWS_CALLBACK_CLIENT_CONNECTION_ERROR";
		case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
			return "LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH";
		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			return "LWS_CALLBACK_CLIENT_ESTABLISHED";
		case LWS_CALLBACK_CLOSED:
			return "LWS_CALLBACK_CLOSED";
		case LWS_CALLBACK_CLOSED_HTTP:
			return "LWS_CALLBACK_CLOSED_HTTP";
		case LWS_CALLBACK_RECEIVE:
			return "LWS_CALLBACK_RECEIVE";
		case LWS_CALLBACK_CLIENT_RECEIVE:
			return "LWS_CALLBACK_CLIENT_RECEIVE";
		case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
			return "LWS_CALLBACK_CLIENT_RECEIVE_PONG";
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			return "LWS_CALLBACK_CLIENT_WRITEABLE";
		case LWS_CALLBACK_SERVER_WRITEABLE:
			return "LWS_CALLBACK_SERVER_WRITEABLE";
		case LWS_CALLBACK_HTTP:
			return "LWS_CALLBACK_HTTP";
		case LWS_CALLBACK_HTTP_BODY:
			return "LWS_CALLBACK_HTTP_BODY";
		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
			return "LWS_CALLBACK_HTTP_BODY_COMPLETION";
		case LWS_CALLBACK_HTTP_FILE_COMPLETION:
			return "LWS_CALLBACK_HTTP_FILE_COMPLETION";
		case LWS_CALLBACK_HTTP_WRITEABLE:
			return "LWS_CALLBACK_HTTP_WRITEABLE";
		case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
			return "LWS_CALLBACK_FILTER_NETWORK_CONNECTION";
		case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
			return "LWS_CALLBACK_FILTER_HTTP_CONNECTION";
		case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
			return "LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED";
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			return "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION";
		case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
			return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS";
		case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
			return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS";
		case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
			return "LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION";
		case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
			return "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER";
		case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
			return "LWS_CALLBACK_CONFIRM_EXTENSION_OKAY";
		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
			return "LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED";
		case LWS_CALLBACK_PROTOCOL_INIT:
			return "LWS_CALLBACK_PROTOCOL_INIT";
		case LWS_CALLBACK_PROTOCOL_DESTROY:
			return "LWS_CALLBACK_PROTOCOL_DESTROY";
		case LWS_CALLBACK_WSI_CREATE:
			return "LWS_CALLBACK_WSI_CREATE";
		case LWS_CALLBACK_WSI_DESTROY:
			return "LWS_CALLBACK_WSI_DESTROY";
		case LWS_CALLBACK_GET_THREAD_ID:
			return "LWS_CALLBACK_GET_THREAD_ID";
		case LWS_CALLBACK_ADD_POLL_FD:
			return "LWS_CALLBACK_ADD_POLL_FD";
		case LWS_CALLBACK_DEL_POLL_FD:
			return "LWS_CALLBACK_DEL_POLL_FD";
		case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
			return "LWS_CALLBACK_CHANGE_MODE_POLL_FD";
		case LWS_CALLBACK_LOCK_POLL:
			return "LWS_CALLBACK_LOCK_POLL";
		case LWS_CALLBACK_UNLOCK_POLL:
			return "LWS_CALLBACK_UNLOCK_POLL";
		case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
			return "LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY";
		case LWS_CALLBACK_USER:
			return "LWS_CALLBACK_USER = 1000";
		default:
			break;
	}
	return NULL;
}


/* Transport implementation */
int janus_websockets_init(janus_transport_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_WEBSOCKETS_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL) {
		janus_config_print(config);

		/* Handle configuration */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "ws_logging");
		if(item && item->value) {
			ws_log_level = atoi(item->value);
			if(ws_log_level < 0)
				ws_log_level = 0;
		}
		JANUS_LOG(LOG_VERB, "libwebsockets logging: %d\n", ws_log_level);
		lws_set_log_level(ws_log_level, NULL);
		old_wss = NULL;
		janus_mutex_init(&old_wss_mutex);
		item = janus_config_get_item_drilldown(config, "general", "ws");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "WebSockets server disabled\n");
		} else {
			int wsport = 8188;
			item = janus_config_get_item_drilldown(config, "general", "ws_port");
			if(item && item->value)
				wsport = atoi(item->value);
			/* Prepare context */
			struct lws_context_creation_info info;
			memset(&info, 0, sizeof info);
			info.port = wsport;
			info.iface = NULL;
			info.protocols = wss_protocols;
			info.extensions = libwebsocket_get_internal_extensions();
			info.ssl_cert_filepath = NULL;
			info.ssl_private_key_filepath = NULL;
			info.gid = -1;
			info.uid = -1;
			info.options = 0;
			/* Create the WebSocket context */
			wss = libwebsocket_create_context(&info);
			if(wss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
			} else {
				JANUS_LOG(LOG_INFO, "WebSockets server started (port %d)...\n", wsport);
			}
		}
		item = janus_config_get_item_drilldown(config, "general", "ws_ssl");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure WebSockets server disabled\n");
		} else {
			int wsport = 8989;
			item = janus_config_get_item_drilldown(config, "general", "ws_secure_port");
			if(item && item->value)
				wsport = atoi(item->value);
			item = janus_config_get_item_drilldown(config, "certificates", "cert_pem");
			if(!item || !item->value) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				char *server_pem = (char *)item->value;
				char *server_key = (char *)item->value;
				item = janus_config_get_item_drilldown(config, "certificates", "cert_key");
				if(item && item->value)
					server_key = (char *)item->value;
				JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
				/* Prepare secure context */
				struct lws_context_creation_info info;
				memset(&info, 0, sizeof info);
				info.port = wsport;
				info.iface = NULL;
				info.protocols = wss_protocols;
				info.extensions = libwebsocket_get_internal_extensions();
				info.ssl_cert_filepath = server_pem;
				info.ssl_private_key_filepath = server_key;
				info.gid = -1;
				info.uid = -1;
				info.options = 0;
				/* Create the secure WebSocket context */
				swss = libwebsocket_create_context(&info);
				if(swss == NULL) {
					JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
				} else {
					JANUS_LOG(LOG_INFO, "Secure WebSockets server started (port %d)...\n", wsport);
				}
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(!wss && !swss) {
		JANUS_LOG(LOG_FATAL, "No WebSockets server started, giving up...\n"); 
		return -1;	/* No point in keeping the plugin loaded */
	}

	GError *error = NULL;
	/* Start the WebSockets thread */
	thread = g_thread_try_new("websockets thread", &janus_websockets_thread, NULL, &error);
	if(!thread) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the WebSockets thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_WEBSOCKETS_NAME);
	return 0;
}

void janus_websockets_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	if(thread != NULL) {
		g_thread_join(thread);
		thread = NULL;
	}

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_WEBSOCKETS_NAME);
}

int janus_websockets_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_websockets_get_version(void) {
	return JANUS_WEBSOCKETS_VERSION;
}

const char *janus_websockets_get_version_string(void) {
	return JANUS_WEBSOCKETS_VERSION_STRING;
}

const char *janus_websockets_get_description(void) {
	return JANUS_WEBSOCKETS_DESCRIPTION;
}

const char *janus_websockets_get_name(void) {
	return JANUS_WEBSOCKETS_NAME;
}

const char *janus_websockets_get_author(void) {
	return JANUS_WEBSOCKETS_AUTHOR;
}

const char *janus_websockets_get_package(void) {
	return JANUS_WEBSOCKETS_PACKAGE;
}

int janus_websockets_send_message(void *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL) {
		g_free(message);
		return -1;
	}
	janus_websockets_client *client = (janus_websockets_client *)transport;
	/* Make sure this is not related to a closed WebSocket session */
	janus_mutex_lock(&old_wss_mutex);
	if(g_list_find(old_wss, client) == NULL) {
		janus_mutex_lock(&client->mutex);
		/* Convert to string and enqueue */
		char *payload = json_dumps(message, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		g_async_queue_push(client->messages, payload);
		libwebsocket_callback_on_writable(client->context, client->wsi);
		janus_mutex_unlock(&client->mutex);
	}
	janus_mutex_unlock(&old_wss_mutex);
	json_decref(message);
	return 0;
}

void janus_websockets_session_created(void *transport, guint64 session_id) {
	/* We don't care */
}

void janus_websockets_session_over(void *transport, guint64 session_id, gboolean timeout) {
	if(transport == NULL || !timeout)
		return;
	/* We only care if it's a timeout: if so, close the connection */
	janus_websockets_client *client = (janus_websockets_client *)transport;
	/* Make sure this is not related to a closed WebSocket session */
	janus_mutex_lock(&old_wss_mutex);
	if(g_list_find(old_wss, client) == NULL) {
		janus_mutex_lock(&client->mutex);
		client->session_timeout = 1;
		libwebsocket_callback_on_writable(client->context, client->wsi);
		janus_mutex_unlock(&client->mutex);
	}
	janus_mutex_unlock(&old_wss_mutex);
}


/* Thread */
void *janus_websockets_thread(void *data) {
	JANUS_LOG(LOG_INFO, "WebSocket thread started\n");
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* libwebsockets is single thread, we cycle through events here */
		if(wss != NULL)
			libwebsocket_service(wss, 100);
		if(swss != NULL)
			libwebsocket_service(swss, 100);
	}
	JANUS_LOG(LOG_INFO, "WebSocket thread ended\n");
	return NULL;
}


/* WebSockets */
static int janus_wss_callback_http(struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user, void *in, size_t len)
{
	/* This endpoint cannot be used for HTTP */
	switch(reason) {
		case LWS_CALLBACK_HTTP:
			JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint\n");
			libwebsockets_return_http_status(this, wsi, 403, NULL);
			/* Close and free connection */
			return 1;
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			if (!in) {
				JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint: no sub-protocol specified\n");
				return 1;
			}
			break;
		default:
			break;
	}
	return 0;
}

static int janus_wss_callback(struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user, void *in, size_t len)
{
	janus_websockets_client *ws_client = (janus_websockets_client *)user;
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED: {
			JANUS_LOG(LOG_VERB, "[WSS-%p] WebSocket connection accepted\n", wsi);
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return 1;
			}
			/* Clean the old sessions list, in case this pointer was used before */
			janus_mutex_lock(&old_wss_mutex);
			if(g_list_find(old_wss, ws_client) != NULL)
				old_wss = g_list_remove(old_wss, ws_client);
			janus_mutex_unlock(&old_wss_mutex);
			/* Prepare the session */
			ws_client->context = this;
			ws_client->wsi = wsi;
			ws_client->messages = g_async_queue_new();
			ws_client->session_timeout = 0;
			ws_client->destroy = 0;
			janus_mutex_init(&ws_client->mutex);
			/* Let us know when the WebSocket channel becomes writeable */
			libwebsocket_callback_on_writable(this, wsi);
			JANUS_LOG(LOG_VERB, "[WSS-%p]   -- Ready to be used!\n", wsi);
			return 0;
		}
		case LWS_CALLBACK_RECEIVE: {
			JANUS_LOG(LOG_VERB, "[WSS-%p] Got %zu bytes:\n", wsi, len);
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return 1;
			}
			char *payload = calloc(len+1, sizeof(char));
			memcpy(payload, in, len);
			payload[len] = '\0';
			JANUS_LOG(LOG_HUGE, "%s\n", payload);
			/* Parse the JSON payload */
			json_error_t error;
			json_t *root = json_loads(payload, 0, &error);
			g_free(payload);
			/* Notify the core, passing both the object and, since it may be needed, the error */
			gateway->incoming_request(&janus_websockets_transport, ws_client, NULL, FALSE, root, &error);
			return 0;
		}
		case LWS_CALLBACK_SERVER_WRITEABLE: {
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return 1;
			}
			if(!ws_client->destroy && !g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->mutex);
				/* Shoot all the pending messages first */
				char *response = g_async_queue_try_pop(ws_client->messages);
				if(response && !ws_client->destroy && !g_atomic_int_get(&stopping)) {
					/* Gotcha! */
					unsigned char *buf = calloc(LWS_SEND_BUFFER_PRE_PADDING + strlen(response) + LWS_SEND_BUFFER_POST_PADDING, sizeof(char));
					memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, response, strlen(response));
					JANUS_LOG(LOG_VERB, "Sending WebSocket message (%zu bytes)...\n", strlen(response));
					int sent = libwebsocket_write(wsi, buf+LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
					JANUS_LOG(LOG_VERB, "  -- Sent %d/%zu bytes\n", sent, strlen(response));
					g_free(buf);
					g_free(response);
					/* Done for this round, check the next response/notification later */
					libwebsocket_callback_on_writable(this, wsi);
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				janus_mutex_unlock(&ws_client->mutex);
			}
			return 0;
		}
		case LWS_CALLBACK_CLOSED: {
			JANUS_LOG(LOG_VERB, "[WSS-%p] WS connection closed\n", wsi);
			if(ws_client != NULL) {
				/* Notify core */
				gateway->transport_gone(&janus_websockets_transport, ws_client);
				/* Mark the session as closed */
				janus_mutex_lock(&old_wss_mutex);
				old_wss = g_list_append(old_wss, ws_client);
				janus_mutex_unlock(&old_wss_mutex);
				/* Cleanup */
				janus_mutex_lock(&ws_client->mutex);
				JANUS_LOG(LOG_INFO, "[WSS-%p] Destroying WebSocket client\n", wsi);
				ws_client->destroy = 1;
				ws_client->context = NULL;
				ws_client->wsi = NULL;
				/* Remove messages queue too, if needed */
				if(ws_client->messages != NULL) {
					char *response = NULL;
					while((response = g_async_queue_try_pop(ws_client->messages)) != NULL) {
						g_free(response);
					}
					g_async_queue_unref(ws_client->messages);
				}
				janus_mutex_unlock(&ws_client->mutex);
			}
			JANUS_LOG(LOG_VERB, "[WSS-%p]   -- closed\n", wsi);
			return 0;
		}
		default:
			if(wsi != NULL) {
				JANUS_LOG(LOG_VERB, "[WSS-%p] %d (%s)\n", wsi, reason, janus_wss_reason_string(reason));
			} else {
				JANUS_LOG(LOG_VERB, "[WSS] %d (%s)\n", reason, janus_wss_reason_string(reason));
			}
			break;
	}
	return 0;
}
