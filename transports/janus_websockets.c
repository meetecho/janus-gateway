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
gboolean janus_websockets_is_janus_api_enabled(void);
gboolean janus_websockets_is_admin_api_enabled(void);
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

		.is_janus_api_enabled = janus_websockets_is_janus_api_enabled,
		.is_admin_api_enabled = janus_websockets_is_admin_api_enabled,

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
static gboolean wss_janus_api_enabled = FALSE;
static gboolean wss_admin_api_enabled = FALSE;


/* Logging */
static int ws_log_level = 0;

/* WebSockets per-service thread */
static GThread *wss_thread = NULL, *swss_thread = NULL,
		*admin_wss_thread = NULL, *admin_swss_thread = NULL;
void *janus_websockets_thread(void *data);


/* WebSocket client session */
typedef struct janus_websockets_client {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	struct lws *wsi;						/* The libwebsockets client instance */
#else
	struct libwebsocket_context *context;	/* The libwebsockets client context */
	struct libwebsocket *wsi;				/* The libwebsockets client instance */
#endif
	GAsyncQueue *messages;					/* Queue of outgoing messages to push */
	char *incoming;							/* Buffer containing the incoming message to process (in case there are fragments) */
	unsigned char *buffer;					/* Buffer containing the message to send */
	int buflen;								/* Length of the buffer (may be resized after re-allocations) */
	int bufpending;							/* Data an interrupted previous write couldn't send */
	int bufoffset;							/* Offset from where the interrupted previous write should resume */
	janus_mutex mutex;						/* Mutex to lock/unlock this session */
	gint session_timeout:1;					/* Whether a Janus session timeout occurred in the core */
	gint destroy:1;							/* Flag to trigger a lazy session destruction */
} janus_websockets_client;


/* libwebsockets WS context(s) */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static struct lws_context *wss = NULL, *swss = NULL,
	*admin_wss = NULL, *admin_swss = NULL;
#else
static struct libwebsocket_context *wss = NULL, *swss = NULL,
	*admin_wss = NULL, *admin_swss = NULL;
#endif
/* libwebsockets sessions that have been closed */
static GList *old_wss;
static janus_mutex old_wss_mutex;
/* Callbacks for HTTP-related events (automatically rejected) */
static int janus_websockets_callback_http(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
static int janus_websockets_callback_https(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
/* Callbacks for WebSockets-related events */
static int janus_websockets_callback(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
static int janus_websockets_callback_secure(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
static int janus_websockets_admin_callback(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
static int janus_websockets_admin_callback_secure(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len);
/* Protocol mappings */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static struct lws_protocols wss_protocols[] = {
#else
static struct libwebsocket_protocols wss_protocols[] = {
#endif
	{ "http-only", janus_websockets_callback_http, 0, 0 },
	{ "janus-protocol", janus_websockets_callback, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static struct lws_protocols swss_protocols[] = {
#else
static struct libwebsocket_protocols swss_protocols[] = {
#endif
	{ "http-only", janus_websockets_callback_https, 0, 0 },
	{ "janus-protocol", janus_websockets_callback_secure, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static struct lws_protocols admin_wss_protocols[] = {
#else
static struct libwebsocket_protocols admin_wss_protocols[] = {
#endif
	{ "http-only", janus_websockets_callback_http, 0, 0 },
	{ "janus-admin-protocol", janus_websockets_admin_callback, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static struct lws_protocols admin_swss_protocols[] = {
#else
static struct libwebsocket_protocols admin_swss_protocols[] = {
#endif
	{ "http-only", janus_websockets_callback_https, 0, 0 },
	{ "janus-admin-protocol", janus_websockets_admin_callback_secure, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
/* Helper for debugging reasons */
#define CASE_STR(name) case name: return #name
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
static const char *janus_websockets_reason_string(enum lws_callback_reasons reason) {
#else
static const char *janus_websockets_reason_string(enum libwebsocket_callback_reasons reason) {
#endif
	switch(reason) {
		CASE_STR(LWS_CALLBACK_ESTABLISHED);
		CASE_STR(LWS_CALLBACK_CLIENT_CONNECTION_ERROR);
		CASE_STR(LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH);
		CASE_STR(LWS_CALLBACK_CLIENT_ESTABLISHED);
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

/* WebSockets ACL list for both Janus and Admin API */
GList *janus_websockets_access_list = NULL, *janus_websockets_admin_access_list = NULL;
janus_mutex access_list_mutex;
static void janus_websockets_allow_address(const char *ip, gboolean admin) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&access_list_mutex);
	if(!admin)
		janus_websockets_access_list = g_list_append(janus_websockets_access_list, (gpointer)ip);
	else
		janus_websockets_admin_access_list = g_list_append(janus_websockets_admin_access_list, (gpointer)ip);
	janus_mutex_unlock(&access_list_mutex);
}
static gboolean janus_websockets_is_allowed(const char *ip, gboolean admin) {
	JANUS_LOG(LOG_VERB, "Checking if %s is allowed to contact %s interface\n", ip, admin ? "admin" : "janus");
	if(ip == NULL)
		return FALSE;
	if(!admin && janus_websockets_access_list == NULL) {
		JANUS_LOG(LOG_VERB, "Yep\n");
		return TRUE;
	}
	if(admin && janus_websockets_admin_access_list == NULL) {
		JANUS_LOG(LOG_VERB, "Yeah\n");
		return TRUE;
	}
	janus_mutex_lock(&access_list_mutex);
	GList *temp = admin ? janus_websockets_admin_access_list : janus_websockets_access_list;
	while(temp) {
		const char *allowed = (const char *)temp->data;
		if(allowed != NULL && strstr(ip, allowed)) {
			janus_mutex_unlock(&access_list_mutex);
			return TRUE;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&access_list_mutex);
	JANUS_LOG(LOG_VERB, "Nope...\n");
	return FALSE;
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

#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	JANUS_LOG(LOG_INFO, "libwebsockets >= 1.6 available, using new API\n");
#else
	JANUS_LOG(LOG_INFO, "libwebsockets < 1.6 available, using old API\n");
#endif

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

		/* Any ACL for either the Janus or Admin API? */
		item = janus_config_get_item_drilldown(config, "general", "ws_acl");
		if(item && item->value) {
			gchar **list = g_strsplit(item->value, ",", -1);
			gchar *index = list[0];
			if(index != NULL) {
				int i=0;
				while(index != NULL) {
					if(strlen(index) > 0) {
						JANUS_LOG(LOG_INFO, "Adding '%s' to the Janus API allowed list...\n", index);
						janus_websockets_allow_address(g_strdup(index), FALSE);
					}
					i++;
					index = list[i];
				}
			}
			g_strfreev(list);
			list = NULL;
		}
		item = janus_config_get_item_drilldown(config, "admin", "admin_ws_acl");
		if(item && item->value) {
			gchar **list = g_strsplit(item->value, ",", -1);
			gchar *index = list[0];
			if(index != NULL) {
				int i=0;
				while(index != NULL) {
					if(strlen(index) > 0) {
						JANUS_LOG(LOG_INFO, "Adding '%s' to the Admin/monitor allowed list...\n", index);
						janus_websockets_allow_address(g_strdup(index), TRUE);
					}
					i++;
					index = list[i];
				}
			}
			g_strfreev(list);
			list = NULL;
		}

		/* Setup the Janus API WebSockets server(s) */
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
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			info.extensions = lws_get_internal_extensions();
#else
			info.extensions = libwebsocket_get_internal_extensions();
#endif
			info.ssl_cert_filepath = NULL;
			info.ssl_private_key_filepath = NULL;
			info.gid = -1;
			info.uid = -1;
			info.options = 0;
			/* Create the WebSocket context */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			wss = lws_create_context(&info);
#else
			wss = libwebsocket_create_context(&info);
#endif
			if(wss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
			} else {
				JANUS_LOG(LOG_INFO, "WebSockets server started (port %d)...\n", wsport);
			}
		}
		item = janus_config_get_item_drilldown(config, "general", "wss");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure WebSockets server disabled\n");
		} else {
			int wsport = 8989;
			item = janus_config_get_item_drilldown(config, "general", "wss_port");
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
				info.protocols = swss_protocols;
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				info.extensions = lws_get_internal_extensions();
#else
				info.extensions = libwebsocket_get_internal_extensions();
#endif
				info.ssl_cert_filepath = server_pem;
				info.ssl_private_key_filepath = server_key;
				info.gid = -1;
				info.uid = -1;
				info.options = 0;
				/* Create the secure WebSocket context */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				swss = lws_create_context(&info);
#else
				swss = libwebsocket_create_context(&info);
#endif
				if(swss == NULL) {
					JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
				} else {
					JANUS_LOG(LOG_INFO, "Secure WebSockets server started (port %d)...\n", wsport);
				}
			}
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get_item_drilldown(config, "admin", "admin_ws");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Admin WebSockets server disabled\n");
		} else {
			int wsport = 7188;
			item = janus_config_get_item_drilldown(config, "admin", "admin_ws_port");
			if(item && item->value)
				wsport = atoi(item->value);
			/* Prepare context */
			struct lws_context_creation_info info;
			memset(&info, 0, sizeof info);
			info.port = wsport;
			info.iface = NULL;
			info.protocols = admin_wss_protocols;
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			info.extensions = lws_get_internal_extensions();
#else
			info.extensions = libwebsocket_get_internal_extensions();
#endif
			info.ssl_cert_filepath = NULL;
			info.ssl_private_key_filepath = NULL;
			info.gid = -1;
			info.uid = -1;
			info.options = 0;
			/* Create the WebSocket context */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			admin_wss = lws_create_context(&info);
#else
			admin_wss = libwebsocket_create_context(&info);
#endif
			if(admin_wss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
			} else {
				JANUS_LOG(LOG_INFO, "Admin WebSockets server started (port %d)...\n", wsport);
			}
		}
		item = janus_config_get_item_drilldown(config, "admin", "admin_wss");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure Admin WebSockets server disabled\n");
		} else {
			int wsport = 7989;
			item = janus_config_get_item_drilldown(config, "admin", "admin_wss_port");
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
				info.protocols = admin_swss_protocols;
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				info.extensions = lws_get_internal_extensions();
#else
				info.extensions = libwebsocket_get_internal_extensions();
#endif
				info.ssl_cert_filepath = server_pem;
				info.ssl_private_key_filepath = server_key;
				info.gid = -1;
				info.uid = -1;
				info.options = 0;
				/* Create the secure WebSocket context */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				admin_swss = lws_create_context(&info);
#else
				admin_swss = libwebsocket_create_context(&info);
#endif
				if(admin_swss == NULL) {
					JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
				} else {
					JANUS_LOG(LOG_INFO, "Secure Admin WebSockets server started (port %d)...\n", wsport);
				}
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(!wss && !swss && !admin_wss && !admin_swss) {
		JANUS_LOG(LOG_FATAL, "No WebSockets server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}
	wss_janus_api_enabled = wss || swss;
	wss_admin_api_enabled = admin_wss || admin_swss;

	GError *error = NULL;
	/* Start the WebSocket service threads */
	if(wss != NULL) {
		wss_thread = g_thread_try_new("websockets thread", &janus_websockets_thread, wss, &error);
		if(!wss_thread) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the WebSockets thread...\n", error->code, error->message ? error->message : "??");
			return -1;
		}
	}
	if(swss != NULL) {
		swss_thread = g_thread_try_new("secure websockets thread", &janus_websockets_thread, swss, &error);
		if(!swss_thread) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Secure WebSockets thread...\n", error->code, error->message ? error->message : "??");
			return -1;
		}
	}
	if(admin_wss != NULL) {
		admin_wss_thread = g_thread_try_new("admin websockets thread", &janus_websockets_thread, admin_wss, &error);
		if(!admin_wss_thread) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Admin WebSockets thread...\n", error->code, error->message ? error->message : "??");
			return -1;
		}
	}
	if(admin_swss != NULL) {
		admin_swss_thread = g_thread_try_new("secure admin websockets thread", &janus_websockets_thread, admin_swss, &error);
		if(!admin_swss_thread) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Secure Admin WebSockets thread...\n", error->code, error->message ? error->message : "??");
			return -1;
		}
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

	/* Stop the service threads */
	if(wss_thread != NULL) {
		g_thread_join(wss_thread);
		wss_thread = NULL;
	}
	if(swss_thread != NULL) {
		g_thread_join(swss_thread);
		swss_thread = NULL;
	}
	if(admin_wss_thread != NULL) {
		g_thread_join(admin_wss_thread);
		admin_wss_thread = NULL;
	}
	if(admin_swss_thread != NULL) {
		g_thread_join(admin_swss_thread);
		admin_swss_thread = NULL;
	}

	/* Destroy the contexts */
	if(wss != NULL) {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_context_destroy(wss);
#else
		libwebsocket_context_destroy(wss);
#endif
		wss = NULL;
	}
	if(swss != NULL) {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_context_destroy(swss);
#else
		libwebsocket_context_destroy(swss);
#endif
		swss = NULL;
	}
	if(admin_wss != NULL) {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_context_destroy(admin_wss);
#else
		libwebsocket_context_destroy(admin_wss);
#endif
		admin_wss = NULL;
	}
	if(admin_swss != NULL) {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_context_destroy(admin_swss);
#else
		libwebsocket_context_destroy(admin_swss);
#endif
		admin_swss = NULL;
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

gboolean janus_websockets_is_janus_api_enabled(void) {
	return wss_janus_api_enabled;
}

gboolean janus_websockets_is_admin_api_enabled(void) {
	return wss_admin_api_enabled;
}

int janus_websockets_send_message(void *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL) {
		g_free(message);
		return -1;
	}
	/* Make sure this is not related to a closed /freed WebSocket session */
	janus_mutex_lock(&old_wss_mutex);
	janus_websockets_client *client = (janus_websockets_client *)transport;
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	if(g_list_find(old_wss, client) != NULL || !client->wsi) {
#else
	if(g_list_find(old_wss, client) != NULL || !client->context || !client->wsi) {
#endif
		g_free(message);
		message = NULL;
		transport = NULL;
		janus_mutex_unlock(&old_wss_mutex);
		return -1;
	}
	janus_mutex_lock(&client->mutex);
	/* Convert to string and enqueue */
	char *payload = json_dumps(message, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	g_async_queue_push(client->messages, payload);
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	lws_callback_on_writable(client->wsi);
#else
	libwebsocket_callback_on_writable(client->context, client->wsi);
#endif
	janus_mutex_unlock(&client->mutex);
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
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	if(g_list_find(old_wss, client) == NULL && client->wsi){
#else
	if(g_list_find(old_wss, client) == NULL && client->context && client->wsi){
#endif
		janus_mutex_lock(&client->mutex);
		client->session_timeout = 1;
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_callback_on_writable(client->wsi);
#else
		libwebsocket_callback_on_writable(client->context, client->wsi);
#endif
		janus_mutex_unlock(&client->mutex);
	}
	janus_mutex_unlock(&old_wss_mutex);
}


/* Thread */
void *janus_websockets_thread(void *data) {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	struct lws_context *service = (struct lws_context *)data;
#else
	struct libwebsocket_context *service = (struct libwebsocket_context *)data;
#endif
	if(service == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid service\n");
		return NULL;
	}

	const char *type = NULL;
	if(service == wss)
		type = "WebSocket (Janus API)";
	else if(service == swss)
		type = "Secure WebSocket (Janus API)";
	else if(service == admin_wss)
		type = "WebSocket (Admin API)";
	else if(service == admin_swss)
		type = "Secure WebSocket (Admin API)";

	JANUS_LOG(LOG_INFO, "%s thread started\n", type);

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* libwebsockets is single thread, we cycle through events here */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		lws_service(service, 50);
#else
		libwebsocket_service(service, 50);
#endif
	}

	/* Get rid of the WebSockets server */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	lws_cancel_service(service);
#else
	libwebsocket_cancel_service(service);
#endif
	/* Done */
	JANUS_LOG(LOG_INFO, "%s thread ended\n", type);
	return NULL;
}


/* WebSockets */
static int janus_websockets_callback_http(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	/* This endpoint cannot be used for HTTP */
	switch(reason) {
		case LWS_CALLBACK_HTTP:
			JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint\n");
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			lws_return_http_status(wsi, 403, NULL);
#else
			libwebsockets_return_http_status(this, wsi, 403, NULL);
#endif
			/* Close and free connection */
			return -1;
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			if (!in) {
				JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint: no sub-protocol specified\n");
				return -1;
			}
			break;
		default:
			break;
	}
	return 0;
}

static int janus_websockets_callback_https(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	/* We just forward the event to the HTTP handler */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	return janus_websockets_callback_http(wsi, reason, user, in, len);
#else
	return janus_websockets_callback_http(this, wsi, reason, user, in, len);
#endif
}

/* This callback handles Janus API requests */
static int janus_websockets_callback(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	janus_websockets_client *ws_client = (janus_websockets_client *)user;
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED: {
			/* Is there any filtering we should apply? */
			char name[256], ip[256];
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, 256, ip, 256);
#else
			libwebsockets_get_peer_addresses(this, wsi, libwebsocket_get_socket_fd(wsi), name, 256, ip, 256);
#endif
			JANUS_LOG(LOG_VERB, "[WSS-%p] WebSocket connection opened from %s by %s\n", wsi, ip, name);
			if(!janus_websockets_is_allowed(ip, FALSE)) {
				JANUS_LOG(LOG_ERR, "[WSS-%p] IP %s is unauthorized to connect to the WebSockets Janus API interface\n", wsi, ip);
				/* Close the connection */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				lws_callback_on_writable(wsi);
#else
				libwebsocket_callback_on_writable(this, wsi);
#endif
				return -1;
			}
			JANUS_LOG(LOG_VERB, "[WSS-%p] WebSocket connection accepted\n", wsi);
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			/* Clean the old sessions list, in case this pointer was used before */
			janus_mutex_lock(&old_wss_mutex);
			if(g_list_find(old_wss, ws_client) != NULL)
				old_wss = g_list_remove(old_wss, ws_client);
			janus_mutex_unlock(&old_wss_mutex);
			/* Prepare the session */
#ifndef HAVE_LIBWEBSOCKETS_NEWAPI
			ws_client->context = this;
#endif
			ws_client->wsi = wsi;
			ws_client->messages = g_async_queue_new();
			ws_client->buffer = NULL;
			ws_client->buflen = 0;
			ws_client->bufpending = 0;
			ws_client->bufoffset = 0;
			ws_client->session_timeout = 0;
			ws_client->destroy = 0;
			janus_mutex_init(&ws_client->mutex);
			/* Let us know when the WebSocket channel becomes writeable */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			lws_callback_on_writable(wsi);
#else
			libwebsocket_callback_on_writable(this, wsi);
#endif
			JANUS_LOG(LOG_VERB, "[WSS-%p]   -- Ready to be used!\n", wsi);
			return 0;
		}
		case LWS_CALLBACK_RECEIVE: {
			JANUS_LOG(LOG_VERB, "[WSS-%p] Got %zu bytes:\n", wsi, len);
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(ws_client == NULL || ws_client->wsi == NULL) {
#else
			if(ws_client == NULL || ws_client->context == NULL || ws_client->wsi == NULL) {
#endif
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			/* Is this a new message, or part of a fragmented one? */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			const size_t remaining = lws_remaining_packet_payload(wsi);
#else
			const size_t remaining = libwebsockets_remaining_packet_payload(wsi);
#endif
			if(ws_client->incoming == NULL) {
				JANUS_LOG(LOG_VERB, "[WSS-%p] First fragment: %zu bytes, %zu remaining\n", wsi, len, remaining);
				ws_client->incoming = g_malloc0(len+1);
				memcpy(ws_client->incoming, in, len);
				ws_client->incoming[len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming);
			} else {
				size_t offset = strlen(ws_client->incoming);
				JANUS_LOG(LOG_VERB, "[WSS-%p] Appending fragment: offset %zu, %zu bytes, %zu remaining\n", wsi, offset, len, remaining);
				ws_client->incoming = g_realloc(ws_client->incoming, offset+len+1);
				memcpy(ws_client->incoming+offset, in, len);
				ws_client->incoming[offset+len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming+offset);
			}
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(remaining > 0 || !lws_is_final_fragment(wsi)) {
#else
			if(remaining > 0 || !libwebsocket_is_final_fragment(wsi)) {
#endif
				/* Still waiting for some more fragments */
				JANUS_LOG(LOG_VERB, "[WSS-%p] Waiting for more fragments\n", wsi);
				return 0;
			}
			JANUS_LOG(LOG_VERB, "[WSS-%p] Done, parsing message: %zu bytes\n", wsi, strlen(ws_client->incoming));
			/* If we got here, the message is complete: parse the JSON payload */
			json_error_t error;
			json_t *root = json_loads(ws_client->incoming, 0, &error);
			g_free(ws_client->incoming);
			ws_client->incoming = NULL;
			/* Notify the core, passing both the object and, since it may be needed, the error */
			gateway->incoming_request(&janus_websockets_transport, ws_client, NULL, FALSE, root, &error);
			return 0;
		}
		case LWS_CALLBACK_SERVER_WRITEABLE: {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(ws_client == NULL || ws_client->wsi == NULL) {
#else
			if(ws_client == NULL || ws_client->context == NULL || ws_client->wsi == NULL) {
#endif
				JANUS_LOG(LOG_ERR, "[WSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			if(!ws_client->destroy && !g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->mutex);
				/* Check if we have a pending/partial write to complete first */
				if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0
						&& !ws_client->destroy && !g_atomic_int_get(&stopping)) {
					JANUS_LOG(LOG_VERB, "[WSS-%p] Completing pending WebSocket write (still need to write last %d bytes)...\n",
						wsi, ws_client->bufpending);
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					int sent = lws_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
#else
					int sent = libwebsocket_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
#endif
					JANUS_LOG(LOG_VERB, "[WSS-%p]   -- Sent %d/%d bytes\n", wsi, sent, ws_client->bufpending);
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
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					lws_callback_on_writable(wsi);
#else
					libwebsocket_callback_on_writable(this, wsi);
#endif
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				/* Shoot all the pending messages */
				char *response = g_async_queue_try_pop(ws_client->messages);
				if(response && !ws_client->destroy && !g_atomic_int_get(&stopping)) {
					/* Gotcha! */
					int buflen = LWS_SEND_BUFFER_PRE_PADDING + strlen(response) + LWS_SEND_BUFFER_POST_PADDING;
					if(ws_client->buffer == NULL) {
						/* Let's allocate a shared buffer */
						JANUS_LOG(LOG_VERB, "[WSS-%p] Allocating %d bytes (response is %zu bytes)\n", wsi, buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_malloc0(buflen);
					} else if(buflen > ws_client->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_VERB, "[WSS-%p] Re-allocating to %d bytes (was %d, response is %zu bytes)\n", wsi, buflen, ws_client->buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_realloc(ws_client->buffer, buflen);
					}
					memcpy(ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, response, strlen(response));
					JANUS_LOG(LOG_VERB, "[WSS-%p] Sending WebSocket message (%zu bytes)...\n", wsi, strlen(response));
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					int sent = lws_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
#else
					int sent = libwebsocket_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
#endif
					JANUS_LOG(LOG_VERB, "[WSS-%p]   -- Sent %d/%zu bytes\n", wsi, sent, strlen(response));
					if(sent > -1 && sent < (int)strlen(response)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						ws_client->bufpending = strlen(response) - sent;
						ws_client->bufoffset = LWS_SEND_BUFFER_PRE_PADDING + sent;
						JANUS_LOG(LOG_VERB, "[WSS-%p]   -- Couldn't write all bytes (%d missing), setting offset %d\n",
							wsi, ws_client->bufpending, ws_client->bufoffset);
					}
					/* We can get rid of the message */
					g_free(response);
					/* Done for this round, check the next response/notification later */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					lws_callback_on_writable(wsi);
#else
					libwebsocket_callback_on_writable(this, wsi);
#endif
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
#ifndef HAVE_LIBWEBSOCKETS_NEWAPI
				ws_client->context = NULL;
#endif
				ws_client->wsi = NULL;
				/* Remove messages queue too, if needed */
				if(ws_client->messages != NULL) {
					char *response = NULL;
					while((response = g_async_queue_try_pop(ws_client->messages)) != NULL) {
						g_free(response);
					}
					g_async_queue_unref(ws_client->messages);
				}
				/* ... and the shared buffers */
				g_free(ws_client->incoming);
				ws_client->incoming = NULL;
				g_free(ws_client->buffer);
				ws_client->buffer = NULL;
				ws_client->buflen = 0;
				ws_client->bufpending = 0;
				ws_client->bufoffset = 0;
				janus_mutex_unlock(&ws_client->mutex);
			}
			JANUS_LOG(LOG_VERB, "[WSS-%p]   -- closed\n", wsi);
			return 0;
		}
		default:
			if(wsi != NULL) {
				JANUS_LOG(LOG_VERB, "[WSS-%p] %d (%s)\n", wsi, reason, janus_websockets_reason_string(reason));
			} else {
				JANUS_LOG(LOG_VERB, "[WSS] %d (%s)\n", reason, janus_websockets_reason_string(reason));
			}
			break;
	}
	return 0;
}

static int janus_websockets_callback_secure(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	/* We just forward the event to the Janus API handler */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	return janus_websockets_callback(wsi, reason, user, in, len);
#else
	return janus_websockets_callback(this, wsi, reason, user, in, len);
#endif
}

/* This callback handles Admin API requests */
static int janus_websockets_admin_callback(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	janus_websockets_client *ws_client = (janus_websockets_client *)user;
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED: {
			/* Is there any filtering we should apply? */
			char name[256], ip[256];
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, 256, ip, 256);
#else
			libwebsockets_get_peer_addresses(this, wsi, libwebsocket_get_socket_fd(wsi), name, 256, ip, 256);
#endif
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p] WebSocket connection opened from %s by %s\n", wsi, ip, name);
			if(!janus_websockets_is_allowed(ip, TRUE)) {
				JANUS_LOG(LOG_ERR, "[AdminWSS-%p] IP %s is unauthorized to connect to the WebSockets Admin API interface\n", wsi, ip);
				/* Close the connection */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
				lws_callback_on_writable(wsi);
#else
				libwebsocket_callback_on_writable(this, wsi);
#endif
				return -1;
			}
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p] WebSocket connection accepted\n", wsi);
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[AdminWSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			/* Clean the old sessions list, in case this pointer was used before */
			janus_mutex_lock(&old_wss_mutex);
			if(g_list_find(old_wss, ws_client) != NULL)
				old_wss = g_list_remove(old_wss, ws_client);
			janus_mutex_unlock(&old_wss_mutex);
			/* Prepare the session */
#ifndef HAVE_LIBWEBSOCKETS_NEWAPI
			ws_client->context = this;
#endif
			ws_client->wsi = wsi;
			ws_client->messages = g_async_queue_new();
			ws_client->buffer = NULL;
			ws_client->buflen = 0;
			ws_client->bufpending = 0;
			ws_client->bufoffset = 0;
			ws_client->session_timeout = 0;
			ws_client->destroy = 0;
			janus_mutex_init(&ws_client->mutex);
			/* Let us know when the WebSocket channel becomes writeable */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			lws_callback_on_writable(wsi);
#else
			libwebsocket_callback_on_writable(this, wsi);
#endif
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p]   -- Ready to be used!\n", wsi);
			return 0;
		}
		case LWS_CALLBACK_RECEIVE: {
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Got %zu bytes:\n", wsi, len);
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(ws_client == NULL || ws_client->wsi == NULL) {
#else
			if(ws_client == NULL || ws_client->context == NULL || ws_client->wsi == NULL) {
#endif
				JANUS_LOG(LOG_ERR, "[AdminWSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			/* Is this a new message, or part of a fragmented one? */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			const size_t remaining = lws_remaining_packet_payload(wsi);
#else
			const size_t remaining = libwebsockets_remaining_packet_payload(wsi);
#endif
			if(ws_client->incoming == NULL) {
				JANUS_LOG(LOG_VERB, "[AdminWSS-%p] First fragment: %zu bytes, %zu remaining\n", wsi, len, remaining);
				ws_client->incoming = g_malloc0(len+1);
				memcpy(ws_client->incoming, in, len);
				ws_client->incoming[len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming);
			} else {
				size_t offset = strlen(ws_client->incoming);
				JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Appending fragment: offset %zu, %zu bytes, %zu remaining\n", wsi, offset, len, remaining);
				ws_client->incoming = g_realloc(ws_client->incoming, offset+len+1);
				memcpy(ws_client->incoming+offset, in, len);
				ws_client->incoming[offset+len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming+offset);
			}
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(remaining > 0 || !lws_is_final_fragment(wsi)) {
#else
			if(remaining > 0 || !libwebsocket_is_final_fragment(wsi)) {
#endif
				/* Still waiting for some more fragments */
				JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Waiting for more fragments\n", wsi);
				return 0;
			}
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Done, parsing message: %zu bytes\n", wsi, strlen(ws_client->incoming));
			/* If we got here, the message is complete: parse the JSON payload */
			json_error_t error;
			json_t *root = json_loads(ws_client->incoming, 0, &error);
			g_free(ws_client->incoming);
			ws_client->incoming = NULL;
			/* Notify the core, passing both the object and, since it may be needed, the error */
			gateway->incoming_request(&janus_websockets_transport, ws_client, NULL, TRUE, root, &error);
			return 0;
		}
		case LWS_CALLBACK_SERVER_WRITEABLE: {
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
			if(ws_client == NULL || ws_client->wsi == NULL) {
#else
			if(ws_client == NULL || ws_client->context == NULL || ws_client->wsi == NULL) {
#endif
				JANUS_LOG(LOG_ERR, "[AdminWSS-%p] Invalid WebSocket client instance...\n", wsi);
				return -1;
			}
			if(!ws_client->destroy && !g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->mutex);
				/* Check if we have a pending/partial write to complete first */
				if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0
						&& !ws_client->destroy && !g_atomic_int_get(&stopping)) {
					JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Completing pending WebSocket write (still need to write last %d bytes)...\n",
						wsi, ws_client->bufpending);
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					int sent = lws_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
#else
					int sent = libwebsocket_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
#endif
					JANUS_LOG(LOG_VERB, "[AdminWSS-%p]   -- Sent %d/%d bytes\n", wsi, sent, ws_client->bufpending);
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
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					lws_callback_on_writable(wsi);
#else
					libwebsocket_callback_on_writable(this, wsi);
#endif
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				/* Shoot all the pending messages */
				char *response = g_async_queue_try_pop(ws_client->messages);
				if(response && !ws_client->destroy && !g_atomic_int_get(&stopping)) {
					/* Gotcha! */
					int buflen = LWS_SEND_BUFFER_PRE_PADDING + strlen(response) + LWS_SEND_BUFFER_POST_PADDING;
					if(ws_client->buffer == NULL) {
						/* Let's allocate a shared buffer */
						JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Allocating %d bytes (response is %zu bytes)\n", wsi, buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_malloc0(buflen);
					} else if(buflen > ws_client->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Re-allocating to %d bytes (was %d, response is %zu bytes)\n", wsi, buflen, ws_client->buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_realloc(ws_client->buffer, buflen);
					}
					memcpy(ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, response, strlen(response));
					JANUS_LOG(LOG_VERB, "[AdminWSS-%p] Sending WebSocket message (%zu bytes)...\n", wsi, strlen(response));
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					int sent = lws_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
#else
					int sent = libwebsocket_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
#endif
					JANUS_LOG(LOG_VERB, "[AdminWSS-%p]   -- Sent %d/%zu bytes\n", wsi, sent, strlen(response));
					if(sent > -1 && sent < (int)strlen(response)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						ws_client->bufpending = strlen(response) - sent;
						ws_client->bufoffset = LWS_SEND_BUFFER_PRE_PADDING + sent;
						JANUS_LOG(LOG_VERB, "[AdminWSS-%p]   -- Couldn't write all bytes (%d missing), setting offset %d\n",
							wsi, ws_client->bufpending, ws_client->bufoffset);
					}
					/* We can get rid of the message */
					g_free(response);
					/* Done for this round, check the next response/notification later */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
					lws_callback_on_writable(wsi);
#else
					libwebsocket_callback_on_writable(this, wsi);
#endif
					janus_mutex_unlock(&ws_client->mutex);
					return 0;
				}
				janus_mutex_unlock(&ws_client->mutex);
			}
			return 0;
		}
		case LWS_CALLBACK_CLOSED: {
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p] WS connection closed\n", wsi);
			if(ws_client != NULL) {
				/* Notify core */
				gateway->transport_gone(&janus_websockets_transport, ws_client);
				/* Mark the session as closed */
				janus_mutex_lock(&old_wss_mutex);
				old_wss = g_list_append(old_wss, ws_client);
				janus_mutex_unlock(&old_wss_mutex);
				/* Cleanup */
				janus_mutex_lock(&ws_client->mutex);
				JANUS_LOG(LOG_INFO, "[AdminWSS-%p] Destroying WebSocket client\n", wsi);
				ws_client->destroy = 1;
#ifndef HAVE_LIBWEBSOCKETS_NEWAPI
				ws_client->context = NULL;
#endif
				ws_client->wsi = NULL;
				/* Remove messages queue too, if needed */
				if(ws_client->messages != NULL) {
					char *response = NULL;
					while((response = g_async_queue_try_pop(ws_client->messages)) != NULL) {
						g_free(response);
					}
					g_async_queue_unref(ws_client->messages);
				}
				/* ... and the shared buffers */
				g_free(ws_client->incoming);
				ws_client->incoming = NULL;
				g_free(ws_client->buffer);
				ws_client->buffer = NULL;
				ws_client->buflen = 0;
				ws_client->bufpending = 0;
				ws_client->bufoffset = 0;
				janus_mutex_unlock(&ws_client->mutex);
			}
			JANUS_LOG(LOG_VERB, "[AdminWSS-%p]   -- closed\n", wsi);
			return 0;
		}
		default:
			if(wsi != NULL) {
				JANUS_LOG(LOG_VERB, "[AdminWSS-%p] %d (%s)\n", wsi, reason, janus_websockets_reason_string(reason));
			} else {
				JANUS_LOG(LOG_VERB, "[AdminWSS] %d (%s)\n", reason, janus_websockets_reason_string(reason));
			}
			break;
	}
	return 0;
}

static int janus_websockets_admin_callback_secure(
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
		struct lws *wsi,
		enum lws_callback_reasons reason,
#else
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
#endif
		void *user, void *in, size_t len)
{
	/* We just forward the event to the Admin API handler */
#ifdef HAVE_LIBWEBSOCKETS_NEWAPI
	return janus_websockets_admin_callback(wsi, reason, user, in, len);
#else
	return janus_websockets_admin_callback(this, wsi, reason, user, in, len);
#endif
}
