/*! \file   janus_websockets.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus WebSockets transport plugin
 * \details  This is an implementation of a WebSockets transport for the
 * Janus API, using the libwebsockets library (http://libwebsockets.org).
 * This means that, with the help of this module, browsers or applications
 * (e.g., nodejs server side implementations) can also make use of
 * WebSockets to make requests to Janus. In that case, the same
 * WebSocket can be used for both sending requests and receiving
 * notifications, without the need for long polls. At the same time,
 * without the concept of a REST path, requests sent through the
 * WebSockets interface will need to include, when needed, additional
 * pieces of information like \c session_id and \c handle_id. That is,
 * where you'd send a Janus request related to a specific session to the
 * \c /janus/\<session> path, with WebSockets you'd have to send the same
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

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

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
int janus_websockets_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_websockets_session_created(janus_transport_session *transport, guint64 session_id);
void janus_websockets_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_websockets_session_claimed(janus_transport_session *transport, guint64 session_id);
json_t *janus_websockets_query_transport(json_t *request);


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
		.session_claimed = janus_websockets_session_claimed,

		.query_transport = janus_websockets_query_transport,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_WEBSOCKETS_NAME);
	return &janus_websockets_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean ws_janus_api_enabled = FALSE;
static gboolean ws_admin_api_enabled = FALSE;
static gboolean notify_events = TRUE;

/* Clients maps */
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
static GHashTable *clients = NULL, *writable_clients = NULL;
#endif
static janus_mutex writable_mutex;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* Parameter validation (for tweaking and queries via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter configure_parameters[] = {
	{"events", JANUS_JSON_BOOL, 0},
	{"json", JSON_STRING, 0},
	{"logging", JSON_STRING, 0},
};
/* Error codes (for the tweaking and queries via Admin API) */
#define JANUS_WEBSOCKETS_ERROR_INVALID_REQUEST		411
#define JANUS_WEBSOCKETS_ERROR_MISSING_ELEMENT		412
#define JANUS_WEBSOCKETS_ERROR_INVALID_ELEMENT		413
#define JANUS_WEBSOCKETS_ERROR_UNKNOWN_ERROR		499


/* Logging */
static int ws_log_level = 0;
static const char *janus_websockets_get_level_str(int level) {
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
static void janus_websockets_log_emit_function(int level, const char *line) {
	/* FIXME Do we want to use different Janus debug levels according to the level here? */
	JANUS_LOG(LOG_INFO, "[libwebsockets][%s] %s", janus_websockets_get_level_str(level), line);
}

/* WebSockets service thread */
static GThread *ws_thread = NULL;
void *janus_websockets_thread(void *data);


/* WebSocket client session */
typedef struct janus_websockets_client {
	struct lws *wsi;						/* The libwebsockets client instance */
	GAsyncQueue *messages;					/* Queue of outgoing messages to push */
	char *incoming;							/* Buffer containing the incoming message to process (in case there are fragments) */
	unsigned char *buffer;					/* Buffer containing the message to send */
	size_t buflen;								/* Length of the buffer (may be resized after re-allocations) */
	size_t bufpending;							/* Data an interrupted previous write couldn't send */
	size_t bufoffset;							/* Offset from where the interrupted previous write should resume */
	volatile gint destroyed;				/* Whether this libwebsockets client instance has been closed */
	janus_transport_session *ts;			/* Janus core-transport session */
} janus_websockets_client;


/* libwebsockets WS context */
static struct lws_context *wsc = NULL;
/* Callbacks for HTTP-related events (automatically rejected) */
static int janus_websockets_callback_http(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
static int janus_websockets_callback_https(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
/* Callbacks for WebSockets-related events */
static int janus_websockets_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
static int janus_websockets_callback_secure(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
static int janus_websockets_admin_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
static int janus_websockets_admin_callback_secure(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len);
/* Protocol mappings */
static struct lws_protocols ws_protocols[] = {
	{ "http-only", janus_websockets_callback_http, 0, 0 },
	{ "janus-protocol", janus_websockets_callback, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
static struct lws_protocols sws_protocols[] = {
	{ "http-only", janus_websockets_callback_https, 0, 0 },
	{ "janus-protocol", janus_websockets_callback_secure, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
static struct lws_protocols admin_ws_protocols[] = {
	{ "http-only", janus_websockets_callback_http, 0, 0 },
	{ "janus-admin-protocol", janus_websockets_admin_callback, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
static struct lws_protocols admin_sws_protocols[] = {
	{ "http-only", janus_websockets_callback_https, 0, 0 },
	{ "janus-admin-protocol", janus_websockets_admin_callback_secure, sizeof(janus_websockets_client), 0 },
	{ NULL, NULL, 0 }
};
/* Helper for debugging reasons */
#define CASE_STR(name) case name: return #name
static const char *janus_websockets_reason_string(enum lws_callback_reasons reason) {
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
		CASE_STR(LWS_CALLBACK_ADD_HEADERS);
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
		CASE_STR(LWS_CALLBACK_RECEIVE_PONG);
		default:
			break;
	}
	return NULL;
}

#if (LWS_LIBRARY_VERSION_MAJOR >= 4)
static lws_retry_bo_t pingpong = { 0 };
#endif

/* Helper method to return the interface associated with a local IP address */
static char *janus_websockets_get_interface_name(const char *ip) {
	struct ifaddrs *addrs = NULL, *iap = NULL;
	if(getifaddrs(&addrs) == -1)
		return NULL;
	for(iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if(iap->ifa_addr && (iap->ifa_flags & IFF_UP)) {
			if(iap->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sa = (struct sockaddr_in *)(iap->ifa_addr);
				char buffer[16];
				inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buffer, sizeof(buffer));
				if(!strcmp(ip, buffer)) {
					char *iface = g_strdup(iap->ifa_name);
					freeifaddrs(addrs);
					return iface;
				}
			} else if(iap->ifa_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sa = (struct sockaddr_in6 *)(iap->ifa_addr);
				char buffer[48];
				inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin6_addr), buffer, sizeof(buffer));
				if(!strcmp(ip, buffer)) {
					char *iface = g_strdup(iap->ifa_name);
					freeifaddrs(addrs);
					return iface;
				}
			}
		}
	}
	freeifaddrs(addrs);
	return NULL;
}

/* Custom Access-Control-Allow-Origin value, if specified */
static char *allow_origin = NULL;
static gboolean enforce_cors = FALSE;

/* WebSockets ACL list for both Janus and Admin API */
static GList *janus_websockets_access_list = NULL, *janus_websockets_admin_access_list = NULL;
static janus_mutex access_list_mutex;
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

static struct lws_vhost* janus_websockets_create_ws_server(
		janus_config *config,
		janus_config_container *config_container,
		janus_config_container *config_certs,
		const char *prefix,
		const char *name,
		struct lws_protocols ws_protocols[],
		gboolean secure,
		uint16_t default_port)
{
	janus_config_item *item;
	char item_name[255];

	item = janus_config_get(config, config_container, janus_config_type_item, prefix);
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_VERB, "%s server disabled\n", name);
		return NULL;
	}

	uint16_t wsport = default_port;
	g_snprintf(item_name, 255, "%s_port", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
	if(item && item->value && janus_string_to_uint16(item->value, &wsport) < 0) {
		JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
		wsport = default_port;
	}

	char *interface = NULL;
	g_snprintf(item_name, 255, "%s_interface", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
	if(item && item->value)
		interface = (char *)item->value;

	char *ip = NULL;
	g_snprintf(item_name, 255, "%s_ip", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
	if(item && item->value) {
		ip = (char *)item->value;
#ifdef __FreeBSD__
		struct in_addr addr;
		if(inet_net_pton(AF_INET, ip, &addr, sizeof(addr)) > 0)
			ipv4_only = 1;
#endif
		char *iface = janus_websockets_get_interface_name(ip);
		if(iface == NULL) {
			JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
		}
		ip = iface;
	}

	g_snprintf(item_name, 255, "%s_unix", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
#if defined(LWS_USE_UNIX_SOCK) || defined(LWS_WITH_UNIX_SOCK)
	char *unixpath = NULL;
	if(item && item->value)
		unixpath = (char *)item->value;
#else
	if(item && item->value)
		JANUS_LOG(LOG_WARN, "WebSockets option '%s' is not supported because libwebsockets compiled without UNIX sockets\n", item_name);
#endif

	char *server_pem = NULL;
	char *server_key = NULL;
	char *password = NULL;
	char *ciphers = NULL;

	if (secure) {
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			return NULL;
		}
		server_pem = (char *)item->value;
		server_key = (char *)item->value;
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
		if(item && item->value)
			server_key = (char *)item->value;
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
		if(item && item->value)
			password = (char *)item->value;
		JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
		item = janus_config_get(config, config_certs, janus_config_type_item, "ciphers");
		if(item && item->value)
			ciphers = (char *)item->value;
	}

	/* Prepare context */
	struct lws_context_creation_info info;
	memset(&info, 0, sizeof info);
#if defined(LWS_USE_UNIX_SOCK) || defined(LWS_WITH_UNIX_SOCK)
	info.port = unixpath ? 0 : wsport;
	info.iface = unixpath ? unixpath : (ip ? ip : interface);
#else
	info.port = wsport;
	info.iface = ip ? ip : interface;
#endif
	info.protocols = ws_protocols;
	info.extensions = NULL;
	info.ssl_cert_filepath = server_pem;
	info.ssl_private_key_filepath = server_key;
	info.ssl_private_key_password = password;
	info.ssl_cipher_list = ciphers;
	info.gid = -1;
	info.uid = -1;
	info.options = 0;

	if (server_pem) {
#if (LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR > 3)
		info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND;
#elif LWS_LIBRARY_VERSION_MAJOR >= 2
		info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif
	}

#ifdef __FreeBSD__
	if (ipv4_only) {
		info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
		ipv4_only = 0;
	}
#endif
#if defined(LWS_USE_UNIX_SOCK) || defined(LWS_WITH_UNIX_SOCK)
	if (unixpath)
		info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
#endif
#if (LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR > 3)
	info.options |= LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND;

#endif
	/* Create the WebSocket context */
	struct lws_vhost *vhost = lws_create_vhost(wsc, &info);
	if(vhost == NULL) {
		JANUS_LOG(LOG_FATAL, "Error creating vhost for %s server...\n", name);
#if defined(LWS_USE_UNIX_SOCK) || defined(LWS_WITH_UNIX_SOCK)
	} else if (unixpath) {
		JANUS_LOG(LOG_INFO, "%s server started (UNIX socket %s)...\n", name, unixpath);
#endif
	} else {
		JANUS_LOG(LOG_INFO, "%s server started (port %d)...\n", name, wsport);
	}
	g_free(ip);
	return vhost;
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

#ifndef LWS_WITH_IPV6
	JANUS_LOG(LOG_WARN, "libwebsockets has been built without IPv6 support, will bind to IPv4 only\n");
#endif

#ifdef __FreeBSD__
	int ipv4_only = 0;
#endif
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Prepare the common context */
	struct lws_context_creation_info wscinfo;
	memset(&wscinfo, 0, sizeof wscinfo);
	wscinfo.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	/* We use vhosts on the same context to address both APIs, secure or not */
	struct lws_vhost *wss = NULL, *swss = NULL,
		*admin_wss = NULL, *admin_swss = NULL;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_WEBSOCKETS_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_WEBSOCKETS_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_WEBSOCKETS_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_category *config_admin = janus_config_get_create(config, NULL, janus_config_type_category, "admin");
		janus_config_category *config_cors = janus_config_get_create(config, NULL, janus_config_type_category, "cors");
		janus_config_category *config_certs = janus_config_get_create(config, NULL, janus_config_type_category, "certificates");

		/* Handle configuration */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "json");
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

		/* Check if we need to send events to handlers */
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_WEBSOCKETS_NAME);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "ws_logging");
		if(item && item->value) {
			/* libwebsockets uses a mask to set log levels, as documented here:
			 * https://libwebsockets.org/lws-api-doc-master/html/group__log.html */
			if(strstr(item->value, "none")) {
				/* Disable libwebsockets logging completely (the default) */
			} else if(strstr(item->value, "all")) {
				/* Enable all libwebsockets logging */
				ws_log_level = LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
					LLL_DEBUG | LLL_PARSER | LLL_HEADER | LLL_EXT |
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
					LLL_CLIENT | LLL_LATENCY | LLL_USER | LLL_COUNT;
#else
					LLL_CLIENT | LLL_LATENCY | LLL_COUNT;
#endif
			} else {
				/* Only enable some of the properties */
				if(strstr(item->value, "err"))
					ws_log_level |= LLL_ERR;
				if(strstr(item->value, "warn"))
					ws_log_level |= LLL_WARN;
				if(strstr(item->value, "notice"))
					ws_log_level |= LLL_NOTICE;
				if(strstr(item->value, "info"))
					ws_log_level |= LLL_INFO;
				if(strstr(item->value, "debug"))
					ws_log_level |= LLL_DEBUG;
				if(strstr(item->value, "parser"))
					ws_log_level |= LLL_PARSER;
				if(strstr(item->value, "header"))
					ws_log_level |= LLL_HEADER;
				if(strstr(item->value, "ext"))
					ws_log_level |= LLL_EXT;
				if(strstr(item->value, "client"))
					ws_log_level |= LLL_CLIENT;
				if(strstr(item->value, "latency"))
					ws_log_level |= LLL_LATENCY;
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
				if(strstr(item->value, "user"))
					ws_log_level |= LLL_USER;
#endif
				if(strstr(item->value, "count"))
					ws_log_level |= LLL_COUNT;
			}
		}
		JANUS_LOG(LOG_INFO, "libwebsockets logging: %d\n", ws_log_level);
		lws_set_log_level(ws_log_level, janus_websockets_log_emit_function);

		/* Any ACL for either the Janus or Admin API? */
		item = janus_config_get(config, config_general, janus_config_type_item, "ws_acl");
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
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ws_acl");
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

		/* Any custom value for the Access-Control-Allow-Origin header? */
		item = janus_config_get(config, config_cors, janus_config_type_item, "allow_origin");
		if(item && item->value) {
			allow_origin = g_strdup(item->value);
			JANUS_LOG(LOG_INFO, "Restricting Access-Control-Allow-Origin to '%s'\n", allow_origin);
		}
		if(allow_origin != NULL) {
			item = janus_config_get(config, config_cors, janus_config_type_item, "enforce_cors");
			if(item && item->value && janus_is_true(item->value)) {
				enforce_cors = TRUE;
				JANUS_LOG(LOG_INFO, "Going to enforce CORS by rejecting WebSocket connections\n");
			}
		}

		/* Check if we need to enable the transport level ping/pong mechanism */
		int pingpong_trigger = 0, pingpong_timeout = 0;
		item = janus_config_get(config, config_general, janus_config_type_item, "pingpong_trigger");
		if(item && item->value) {
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
			pingpong_trigger = atoi(item->value);
			if(pingpong_trigger < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value for pingpong_trigger (%d), ignoring...\n", pingpong_trigger);
				pingpong_trigger = 0;
			}
#else
			JANUS_LOG(LOG_WARN, "WebSockets ping/pong only supported in libwebsockets >= 2.1\n");
#endif
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "pingpong_timeout");
		if(item && item->value) {
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
			pingpong_timeout = atoi(item->value);
			if(pingpong_timeout < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value for pingpong_timeout (%d), ignoring...\n", pingpong_timeout);
				pingpong_timeout = 0;
			}
#else
			JANUS_LOG(LOG_WARN, "WebSockets ping/pong only supported in libwebsockets >= 2.1\n");
#endif
		}
		if((pingpong_trigger && !pingpong_timeout) || (!pingpong_trigger && pingpong_timeout)) {
			JANUS_LOG(LOG_WARN, "pingpong_trigger and pingpong_timeout not both set, ignoring...\n");
		}
#if (LWS_LIBRARY_VERSION_MAJOR >= 4)
		/* libwebsockets 4 has a different API, that works differently
		 * https://github.com/warmcat/libwebsockets/blob/master/READMEs/README.lws_retry.md */
		if(pingpong_trigger > 0 && pingpong_timeout > 0) {
			pingpong.secs_since_valid_ping = pingpong_trigger;
			pingpong.secs_since_valid_hangup = pingpong_trigger + pingpong_timeout;
			wscinfo.retry_and_idle_policy = &pingpong;
		}
#else
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR == 3)
		if(pingpong_trigger > 0 && pingpong_timeout > 0) {
			wscinfo.ws_ping_pong_interval = pingpong_trigger;
			wscinfo.timeout_secs = pingpong_timeout;
		}
#endif
#endif
		/* Force single-thread server */
		wscinfo.count_threads = 1;

		/* Create the base context */
		wsc = lws_create_context(&wscinfo);
		if(wsc == NULL) {
			JANUS_LOG(LOG_ERR, "Error creating libwebsockets context...\n");
			janus_config_destroy(config);
			return -1;	/* No point in keeping the plugin loaded */
		}

		/* Setup the Janus API WebSockets server(s) */
		wss = janus_websockets_create_ws_server(config, config_general, NULL, "ws",
				"Websockets", ws_protocols, FALSE, 8188);
		swss = janus_websockets_create_ws_server(config, config_general, config_certs, "wss",
				"Secure Websockets", sws_protocols, TRUE, 8989);
		/* Do the same for the Admin API, if enabled */
		admin_wss = janus_websockets_create_ws_server(config, config_admin, NULL, "admin_ws",
				"Admin Websockets", admin_ws_protocols, FALSE, 7188);
		admin_swss = janus_websockets_create_ws_server(config, config_admin, config_certs, "admin_wss",
				"Secure Admin Websockets", admin_sws_protocols, TRUE, 7989);
	}
	janus_config_destroy(config);
	config = NULL;
	if(!wss && !swss && !admin_wss && !admin_swss) {
		JANUS_LOG(LOG_WARN, "No WebSockets server started, giving up...\n");
		lws_context_destroy(wsc);
		return -1;	/* No point in keeping the plugin loaded */
	}
	ws_janus_api_enabled = wss || swss;
	ws_admin_api_enabled = admin_wss || admin_swss;

#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
	clients = g_hash_table_new(NULL, NULL);
	writable_clients = g_hash_table_new(NULL, NULL);
#endif
	janus_mutex_init(&writable_mutex);

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the WebSocket service thread */
	if(ws_janus_api_enabled || ws_admin_api_enabled) {
		ws_thread = g_thread_try_new("ws thread", &janus_websockets_thread, wsc, &error);
		if(error != NULL) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the WebSockets thread...\n",
				error->code, error->message ? error->message : "??");
			g_error_free(error);
			return -1;
		}
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_WEBSOCKETS_NAME);
	return 0;
}

void janus_websockets_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);
#if ((LWS_LIBRARY_VERSION_MAJOR == 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || LWS_LIBRARY_VERSION_MAJOR >= 4)
	lws_cancel_service(wsc);
#endif

	/* Stop the service thread */
	if(ws_thread != NULL) {
		g_thread_join(ws_thread);
		ws_thread = NULL;
	}

	/* Destroy the context */
	if(wsc != NULL) {
		lws_context_destroy(wsc);
		wsc = NULL;
	}

#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
	janus_mutex_lock(&writable_mutex);
	g_hash_table_destroy(clients);
	clients = NULL;
	g_hash_table_destroy(writable_clients);
	writable_clients = NULL;
	janus_mutex_unlock(&writable_mutex);
#endif

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_WEBSOCKETS_NAME);
}

static void janus_websockets_destroy_client(
		janus_websockets_client *ws_client,
		struct lws *wsi,
		const char *log_prefix) {
	if(!ws_client || !ws_client->ts)
		return;
	janus_mutex_lock(&ws_client->ts->mutex);
	if(!g_atomic_int_compare_and_exchange(&ws_client->destroyed, 0, 1)) {
		janus_mutex_unlock(&ws_client->ts->mutex);
		return;
	}
	/* Cleanup */
	JANUS_LOG(LOG_INFO, "[%s-%p] Destroying WebSocket client\n", log_prefix, wsi);
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
	janus_mutex_lock(&writable_mutex);
	g_hash_table_remove(clients, ws_client);
	g_hash_table_remove(writable_clients, ws_client);
	janus_mutex_unlock(&writable_mutex);
#endif
	ws_client->wsi = NULL;
	/* Notify handlers about this transport being gone */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("disconnected"));
		gateway->notify_event(&janus_websockets_transport, ws_client->ts, info);
	}
	ws_client->ts->transport_p = NULL;
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
	janus_mutex_unlock(&ws_client->ts->mutex);
	/* Notify core */
	gateway->transport_gone(&janus_websockets_transport, ws_client->ts);
	janus_transport_session_destroy(ws_client->ts);
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
	return ws_janus_api_enabled;
}

gboolean janus_websockets_is_admin_api_enabled(void) {
	return ws_admin_api_enabled;
}

int janus_websockets_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL || g_atomic_int_get(&transport->destroyed)) {
		json_decref(message);
		return -1;
	}
	janus_mutex_lock(&transport->mutex);
	janus_websockets_client *client = (janus_websockets_client *)transport->transport_p;
	if(!client || !client->wsi || g_atomic_int_get(&client->destroyed)) {
		json_decref(message);
		janus_mutex_unlock(&transport->mutex);
		return -1;
	}
	/* Convert to string and enqueue */
	char *payload = json_dumps(message, json_format);
	if(payload == NULL) {
		JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
		json_decref(message);
		janus_mutex_unlock(&transport->mutex);
		return -1;
	}
	g_async_queue_push(client->messages, payload);
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
	/* On libwebsockets >= 3.x we use lws_cancel_service */
	janus_mutex_lock(&writable_mutex);
	if(g_hash_table_lookup(clients, client) == client)
		g_hash_table_insert(writable_clients, client, client);
	janus_mutex_unlock(&writable_mutex);
	lws_cancel_service(wsc);
#else
	/* On libwebsockets < 3.x we use lws_callback_on_writable */
	janus_mutex_lock(&writable_mutex);
	lws_callback_on_writable(client->wsi);
	janus_mutex_unlock(&writable_mutex);
#endif
	janus_mutex_unlock(&transport->mutex);
	json_decref(message);
	return 0;
}

void janus_websockets_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_websockets_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We don't care either: transport timeouts can be detected using the ping/pong mechanism */
}

void janus_websockets_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}

json_t *janus_websockets_query_transport(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this request to dynamically change the behaviour of
	 * the transport plugin, and/or query for some specific information */
	json_t *response = json_object();
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_WEBSOCKETS_ERROR_MISSING_ELEMENT, JANUS_WEBSOCKETS_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "configure")) {
		/* We only allow for the configuration of some basic properties:
		 * changing more complex things (e.g., port to bind to, etc.)
		 * would likely require restarting backends, so just too much */
		JANUS_VALIDATE_JSON_OBJECT(request, configure_parameters,
			error_code, error_cause, TRUE,
			JANUS_WEBSOCKETS_ERROR_MISSING_ELEMENT, JANUS_WEBSOCKETS_ERROR_INVALID_ELEMENT);
		/* Check if we now need to send events to handlers */
		json_object_set_new(response, "result", json_integer(200));
		json_t *notes = NULL;
		gboolean events = json_is_true(json_object_get(request, "events"));
		if(events && !gateway->events_is_enabled()) {
			/* Notify that this will be ignored */
			notes = json_array();
			json_array_append_new(notes, json_string("Event handlers disabled at the core level"));
			json_object_set_new(response, "notes", notes);
		}
		if(events != notify_events) {
			notify_events = events;
			if(!notify_events && gateway->events_is_enabled()) {
				JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_WEBSOCKETS_NAME);
			}
		}
		const char *indentation = json_string_value(json_object_get(request, "json"));
		if(indentation != NULL) {
			if(!strcasecmp(indentation, "indented")) {
				/* Default: indented, we use three spaces for that */
				json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(indentation, "plain")) {
				/* Not indented and no new lines, but still readable */
				json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
			} else if(!strcasecmp(indentation, "compact")) {
				/* Compact, so no spaces between separators */
				json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
			} else {
				JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', ignoring tweak\n", indentation);
				/* Notify that this will be ignored */
				if(notes == NULL) {
					notes = json_array();
					json_object_set_new(response, "notes", notes);
				}
				json_array_append_new(notes, json_string("Ignored unsupported indentation format"));
			}
		}
		const char *logging = json_string_value(json_object_get(request, "logging"));
		if(logging != NULL) {
			/* libwebsockets uses a mask to set log levels, as documented here:
			 * https://libwebsockets.org/lws-api-doc-master/html/group__log.html */
			if(strstr(logging, "none")) {
				/* Disable libwebsockets logging completely (the default) */
			} else if(strstr(logging, "all")) {
				/* Enable all libwebsockets logging */
				ws_log_level = LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO |
					LLL_DEBUG | LLL_PARSER | LLL_HEADER | LLL_EXT |
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
					LLL_CLIENT | LLL_LATENCY | LLL_USER | LLL_COUNT;
#else
					LLL_CLIENT | LLL_LATENCY | LLL_COUNT;
#endif
			} else {
				/* Only enable some of the properties */
				ws_log_level = 0;
				if(strstr(logging, "err"))
					ws_log_level |= LLL_ERR;
				if(strstr(logging, "warn"))
					ws_log_level |= LLL_WARN;
				if(strstr(logging, "notice"))
					ws_log_level |= LLL_NOTICE;
				if(strstr(logging, "info"))
					ws_log_level |= LLL_INFO;
				if(strstr(logging, "debug"))
					ws_log_level |= LLL_DEBUG;
				if(strstr(logging, "parser"))
					ws_log_level |= LLL_PARSER;
				if(strstr(logging, "header"))
					ws_log_level |= LLL_HEADER;
				if(strstr(logging, "ext"))
					ws_log_level |= LLL_EXT;
				if(strstr(logging, "client"))
					ws_log_level |= LLL_CLIENT;
				if(strstr(logging, "latency"))
					ws_log_level |= LLL_LATENCY;
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
				if(strstr(logging, "user"))
					ws_log_level |= LLL_USER;
#endif
				if(strstr(logging, "count"))
					ws_log_level |= LLL_COUNT;
			}
			JANUS_LOG(LOG_INFO, "libwebsockets logging: %d\n", ws_log_level);
			lws_set_log_level(ws_log_level, janus_websockets_log_emit_function);
		}
	} else if(!strcasecmp(request_text, "connections")) {
		/* Return the number of active connections currently handled by the plugin */
		json_object_set_new(response, "result", json_integer(200));
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		janus_mutex_lock(&writable_mutex);
		guint connections = g_hash_table_size(clients);
		janus_mutex_unlock(&writable_mutex);
		json_object_set_new(response, "connections", json_integer(connections));
#endif
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_WEBSOCKETS_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}


/* Thread */
void *janus_websockets_thread(void *data) {
	struct lws_context *service = (struct lws_context *)data;
	if(service == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid service\n");
		return NULL;
	}

	JANUS_LOG(LOG_INFO, "WebSockets thread started\n");

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* libwebsockets is single thread, we cycle through events here */
		lws_service(service, 50);
	}

	/* Get rid of the WebSockets server */
	lws_cancel_service(service);
	/* Done */
	JANUS_LOG(LOG_INFO, "WebSockets thread ended\n");
	return NULL;
}


/* WebSockets */
static int janus_websockets_callback_http(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	/* This endpoint cannot be used for HTTP */
	switch(reason) {
		case LWS_CALLBACK_HTTP:
			JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint\n");
			lws_return_http_status(wsi, 403, NULL);
			/* Close and free connection */
			return -1;
		case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
			if (!in) {
				JANUS_LOG(LOG_VERB, "Rejecting incoming HTTP request on WebSockets endpoint: no sub-protocol specified\n");
				return -1;
			}
			break;
		case LWS_CALLBACK_GET_THREAD_ID:
			return (uint64_t)pthread_self();
		default:
			break;
	}
	return 0;
}

static int janus_websockets_callback_https(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	/* We just forward the event to the HTTP handler */
	return janus_websockets_callback_http(wsi, reason, user, in, len);
}

/* Use ~ 2xMTU as chunk size */
#define MESSAGE_CHUNK_SIZE 2800

/* This callback handles Janus API requests */
static int janus_websockets_common_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len, gboolean admin)
{
	const char *log_prefix = admin ? "AdminWSS" : "WSS";
	janus_websockets_client *ws_client = (janus_websockets_client *)user;
	switch(reason) {
		case LWS_CALLBACK_ESTABLISHED: {
			/* Is there any filtering we should apply? */
			char ip[256];
#ifdef HAVE_LIBWEBSOCKETS_PEER_SIMPLE
			lws_get_peer_simple(wsi, ip, 256);
			JANUS_LOG(LOG_VERB, "[%s-%p] WebSocket connection opened from %s\n", log_prefix, wsi, ip);
#else
			char name[256];
			lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, 256, ip, 256);
			JANUS_LOG(LOG_VERB, "[%s-%p] WebSocket connection opened from %s by %s\n", log_prefix, wsi, ip, name);
#endif
			if(!janus_websockets_is_allowed(ip, admin)) {
				JANUS_LOG(LOG_ERR, "[%s-%p] IP %s is unauthorized to connect to the WebSockets %s API interface\n", log_prefix, wsi, ip, admin ? "Admin" : "Janus");
				/* Close the connection */
				lws_callback_on_writable(wsi);
				return -1;
			}
			JANUS_LOG(LOG_VERB, "[%s-%p] WebSocket connection accepted\n", log_prefix, wsi);
			if(ws_client == NULL) {
				JANUS_LOG(LOG_ERR, "[%s-%p] Invalid WebSocket client instance...\n", log_prefix, wsi);
				return -1;
			}
			/* Prepare the session */
			ws_client->wsi = wsi;
			ws_client->messages = g_async_queue_new();
			ws_client->buffer = NULL;
			ws_client->buflen = 0;
			ws_client->bufpending = 0;
			ws_client->bufoffset = 0;
			g_atomic_int_set(&ws_client->destroyed, 0);
			ws_client->ts = janus_transport_session_create(ws_client, NULL);
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
			janus_mutex_lock(&writable_mutex);
			g_hash_table_insert(clients, ws_client, ws_client);
			janus_mutex_unlock(&writable_mutex);
#endif
			/* Let us know when the WebSocket channel becomes writeable */
			lws_callback_on_writable(wsi);
			JANUS_LOG(LOG_VERB, "[%s-%p]   -- Ready to be used!\n", log_prefix, wsi);
			/* Notify handlers about this new transport */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("connected"));
				json_object_set_new(info, "admin_api", admin ? json_true() : json_false());
				json_object_set_new(info, "ip", json_string(ip));
				gateway->notify_event(&janus_websockets_transport, ws_client->ts, info);
			}
			return 0;
		}
		case LWS_CALLBACK_ADD_HEADERS: {
			/* If CORS is enabled, check the headers and add our own */
			struct lws_process_html_args *args = (struct lws_process_html_args *)in;
			if(allow_origin == NULL) {
				/* Return a wildcard for the Access-Control-Allow-Origin header */
				if(lws_add_http_header_by_name(wsi,
						(unsigned char *)"Access-Control-Allow-Origin:",
						(unsigned char *)"*", 1,
						(unsigned char **)&args->p,
						(unsigned char *)args->p + args->max_len))
					return 1;
			} else {
				/* Return the configured origin in the header */
				if(lws_add_http_header_by_name(wsi,
						(unsigned char *)"Access-Control-Allow-Origin:",
						(unsigned char *)allow_origin, strlen(allow_origin),
						(unsigned char **)&args->p,
						(unsigned char *)args->p + args->max_len))
					return 1;
				char origin[256], headers[256], methods[256];
				origin[0] = '\0';
				headers[0] = '\0';
				methods[0] = '\0';
				int olen = lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN);
				if(olen > 0 && olen < 255) {
					lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN);
				}
				int hlen = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AC_REQUEST_HEADERS);
				if(hlen > 0 && hlen < 255) {
					lws_hdr_copy(wsi, headers, sizeof(headers), WSI_TOKEN_HTTP_AC_REQUEST_HEADERS);
					if(lws_add_http_header_by_name(wsi,
							(unsigned char *)"Access-Control-Allow-Headers:",
							(unsigned char *)headers, strlen(headers),
							(unsigned char **)&args->p,
							(unsigned char *)args->p + args->max_len))
						return 1;
				}
#if (LWS_LIBRARY_VERSION_MAJOR >= 3 && LWS_LIBRARY_VERSION_MINOR >= 2) || (LWS_LIBRARY_VERSION_MAJOR >= 4)
				int mlen = lws_hdr_custom_length(wsi, "Access-Control-Request-Methods", strlen("Access-Control-Request-Methods"));
				if(mlen > 0 && mlen < 255) {
					lws_hdr_custom_copy(wsi, methods, sizeof(methods),
						"Access-Control-Request-Methods", strlen("Access-Control-Request-Methods"));
					if(lws_add_http_header_by_name(wsi,
							(unsigned char *)"Access-Control-Allow-Methods:",
							(unsigned char *)methods, strlen(methods),
							(unsigned char **)&args->p,
							(unsigned char *)args->p + args->max_len))
						return 1;
				}
#endif
				/* WebSockets are not bound by CORS, but we can enforce this */
				if(enforce_cors) {
					if(strlen(origin) == 0 || strstr(origin, allow_origin) != origin) {
						JANUS_LOG(LOG_ERR, "[%s-%p] Invalid origin, rejecting...\n", log_prefix, wsi);
						return -1;
					}
				}
			}
			return 0;
		}
		case LWS_CALLBACK_RECEIVE: {
			JANUS_LOG(LOG_HUGE, "[%s-%p] Got %zu bytes:\n", log_prefix, wsi, len);
			if(ws_client == NULL || ws_client->wsi == NULL) {
				JANUS_LOG(LOG_ERR, "[%s-%p] Invalid WebSocket client instance...\n", log_prefix, wsi);
				return -1;
			}
			if(g_atomic_int_get(&ws_client->destroyed))
				return 0;
#if (LWS_LIBRARY_VERSION_MAJOR >= 4)
			/* Refresh the lws connection validity (avoid sending a ping) */
			lws_validity_confirmed(ws_client->wsi);
#endif
			/* Is this a new message, or part of a fragmented one? */
			const size_t remaining = lws_remaining_packet_payload(wsi);
			if(ws_client->incoming == NULL) {
				JANUS_LOG(LOG_HUGE, "[%s-%p] First fragment: %zu bytes, %zu remaining\n", log_prefix, wsi, len, remaining);
				ws_client->incoming = g_malloc(len+1);
				memcpy(ws_client->incoming, in, len);
				ws_client->incoming[len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming);
			} else {
				size_t offset = strlen(ws_client->incoming);
				JANUS_LOG(LOG_HUGE, "[%s-%p] Appending fragment: offset %zu, %zu bytes, %zu remaining\n", log_prefix, wsi, offset, len, remaining);
				ws_client->incoming = g_realloc(ws_client->incoming, offset+len+1);
				memcpy(ws_client->incoming+offset, in, len);
				ws_client->incoming[offset+len] = '\0';
				JANUS_LOG(LOG_HUGE, "%s\n", ws_client->incoming+offset);
			}
			if(remaining > 0 || !lws_is_final_fragment(wsi)) {
				/* Still waiting for some more fragments */
				JANUS_LOG(LOG_HUGE, "[%s-%p] Waiting for more fragments\n", log_prefix, wsi);
				return 0;
			}
			JANUS_LOG(LOG_HUGE, "[%s-%p] Done, parsing message: %zu bytes\n", log_prefix, wsi, strlen(ws_client->incoming));
			/* If we got here, the message is complete: parse the JSON payload */
			json_error_t error;
			json_t *root = json_loads(ws_client->incoming, 0, &error);
			g_free(ws_client->incoming);
			ws_client->incoming = NULL;
			/* Notify the core, passing both the object and, since it may be needed, the error */
			gateway->incoming_request(&janus_websockets_transport, ws_client->ts, NULL, admin, root, &error);
			return 0;
		}
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		/* On libwebsockets >= 3.x, we use this event to mark connections as writable in the event loop */
		case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
			janus_mutex_lock(&writable_mutex);
			/* We iterate on all the clients we marked as writable and act on them */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, writable_clients);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_websockets_client *client = value;
				if(client == NULL || client->wsi == NULL)
					continue;
				lws_callback_on_writable(client->wsi);
			}
			g_hash_table_remove_all(writable_clients);
			janus_mutex_unlock(&writable_mutex);
			return 0;
		}
#endif
		case LWS_CALLBACK_SERVER_WRITEABLE: {
			if(ws_client == NULL || ws_client->wsi == NULL) {
				JANUS_LOG(LOG_ERR, "[%s-%p] Invalid WebSocket client instance...\n", log_prefix, wsi);
				return -1;
			}
			if(!g_atomic_int_get(&ws_client->destroyed) && !g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->ts->mutex);

				/* Check if Websockets send pipe is choked */
				if(lws_send_pipe_choked(wsi)) {
					if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0) {
						JANUS_LOG(LOG_WARN, "Websockets choked with buffer: %zu, trying again\n", ws_client->bufpending);
						lws_callback_on_writable(wsi);
					} else {
						gint qlen = g_async_queue_length(ws_client->messages);
						JANUS_LOG(LOG_WARN, "Websockets choked with queue: %d, trying again\n", qlen);
						if(qlen > 0) {
							lws_callback_on_writable(wsi);
						}
					}
					janus_mutex_unlock(&ws_client->ts->mutex);
					return 0;
				}

				/* Check if we have a pending/partial write to complete first */
				if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0) {
					JANUS_LOG(LOG_HUGE, "[%s-%p] Completing pending WebSocket write (still need to write last %zu bytes)...\n",
						log_prefix, wsi, ws_client->bufpending);
				} else {
					/* Shoot all the pending messages */
					char *response = g_async_queue_try_pop(ws_client->messages);
					if (!response) {
						/* No messages found */
						janus_mutex_unlock(&ws_client->ts->mutex);
						return 0;
					}
					if (g_atomic_int_get(&ws_client->destroyed) || g_atomic_int_get(&stopping)) {
						free(response);
						janus_mutex_unlock(&ws_client->ts->mutex);
						return 0;
					}
					/* Gotcha! */
					JANUS_LOG(LOG_HUGE, "[%s-%p] Sending WebSocket message (%zu bytes)...\n", log_prefix, wsi, strlen(response));
					size_t buflen = LWS_PRE + strlen(response);
					if (buflen > ws_client->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_HUGE, "[%s-%p] Re-allocating to %zu bytes (was %zu, response is %zu bytes)\n", log_prefix, wsi, buflen, ws_client->buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_realloc(ws_client->buffer, buflen);
					}
					memcpy(ws_client->buffer + LWS_PRE, response, strlen(response));
					/* Initialize pending bytes count and buffer offset */
					ws_client->bufpending = strlen(response);
					ws_client->bufoffset = LWS_PRE;
					/* We can get rid of the message */
					free(response);
				}

				if (g_atomic_int_get(&ws_client->destroyed) || g_atomic_int_get(&stopping)) {
					janus_mutex_unlock(&ws_client->ts->mutex);
					return 0;
				}

				/* Evaluate amount of data to send according to MESSAGE_CHUNK_SIZE */
				int amount = ws_client->bufpending <= MESSAGE_CHUNK_SIZE ? ws_client->bufpending : MESSAGE_CHUNK_SIZE;
				/* Set fragment flags */
				int flags = lws_write_ws_flags(LWS_WRITE_TEXT, ws_client->bufoffset == LWS_PRE, ws_client->bufpending <= (size_t)amount);
				/* Send the fragment with proper flags */
				int sent = lws_write(wsi, ws_client->buffer + ws_client->bufoffset, (size_t)amount, flags);
				JANUS_LOG(LOG_HUGE, "[%s-%p]   -- First=%d, Last=%d, Requested=%d bytes, Sent=%d bytes, Missing=%zu bytes\n", log_prefix, wsi, ws_client->bufoffset <= LWS_PRE, ws_client->bufpending <= (size_t)amount, amount, sent, ws_client->bufpending - amount);
				if(sent < amount) {
					/* Error on sending, abort operation */
					JANUS_LOG(LOG_ERR, "Websocket sent only %d bytes (expected %d)\n", sent, amount);
					ws_client->bufpending = 0;
					ws_client->bufoffset = 0;
				} else {
					/* Fragment successfully sent, update status */
					ws_client->bufpending -= amount;
					ws_client->bufoffset += amount;
					if(ws_client->bufpending > 0) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						JANUS_LOG(LOG_HUGE, "[%s-%p]   -- Couldn't write all bytes (%zu missing), setting offset %zu\n",
							log_prefix, wsi, ws_client->bufpending, ws_client->bufoffset);
					}
				}
				/* Done for this round, check the next response/notification later */
				lws_callback_on_writable(wsi);
				janus_mutex_unlock(&ws_client->ts->mutex);
				return 0;
			}
			return 0;
		}
		case LWS_CALLBACK_CLOSED: {
			JANUS_LOG(LOG_VERB, "[%s-%p] WS connection down, closing\n", log_prefix, wsi);
			janus_websockets_destroy_client(ws_client, wsi, log_prefix);
			JANUS_LOG(LOG_VERB, "[%s-%p]   -- closed\n", log_prefix, wsi);
			return 0;
		}
		case LWS_CALLBACK_WSI_DESTROY: {
			JANUS_LOG(LOG_VERB, "[%s-%p] WS connection down, destroying\n", log_prefix, wsi);
			janus_websockets_destroy_client(ws_client, wsi, log_prefix);
			JANUS_LOG(LOG_VERB, "[%s-%p]   -- destroyed\n", log_prefix, wsi);
			return 0;
		}
		default:
			if(wsi != NULL) {
				JANUS_LOG(LOG_HUGE, "[%s-%p] %d (%s)\n", log_prefix, wsi, reason, janus_websockets_reason_string(reason));
			} else {
				JANUS_LOG(LOG_HUGE, "[%s] %d (%s)\n", log_prefix, reason, janus_websockets_reason_string(reason));
			}
			break;
	}
	return 0;
}

/* This callback handles Janus API requests */
static int janus_websockets_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	return janus_websockets_common_callback(wsi, reason, user, in, len, FALSE);
}

static int janus_websockets_callback_secure(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	/* We just forward the event to the Janus API handler */
	return janus_websockets_callback(wsi, reason, user, in, len);
}

/* This callback handles Admin API requests */
static int janus_websockets_admin_callback(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	return janus_websockets_common_callback(wsi, reason, user, in, len, TRUE);
}

static int janus_websockets_admin_callback_secure(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	/* We just forward the event to the Admin API handler */
	return janus_websockets_admin_callback(wsi, reason, user, in, len);
}
