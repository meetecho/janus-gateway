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

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


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
	int buflen;								/* Length of the buffer (may be resized after re-allocations) */
	int bufpending;							/* Data an interrupted previous write couldn't send */
	int bufoffset;							/* Offset from where the interrupted previous write should resume */
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

#ifndef LWS_WITH_IPV6
	JANUS_LOG(LOG_WARN, "libwebsockets has been built without IPv6 support, will bind to IPv4 only\n");
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
#if (LWS_LIBRARY_VERSION_MAJOR >= 2 && LWS_LIBRARY_VERSION_MINOR >= 1) || (LWS_LIBRARY_VERSION_MAJOR >= 3)
		if(pingpong_trigger > 0 && pingpong_timeout > 0) {
			wscinfo.ws_ping_pong_interval = pingpong_trigger;
			wscinfo.timeout_secs = pingpong_timeout;
		}
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
		item = janus_config_get(config, config_general, janus_config_type_item, "ws");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "WebSockets server disabled\n");
		} else {
			int wsport = 8188;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "ws_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}
			/* Prepare context */
			struct lws_context_creation_info info;
			memset(&info, 0, sizeof info);
			info.port = wsport;
			info.iface = ip ? ip : interface;
			info.protocols = ws_protocols;
			info.extensions = NULL;
			info.ssl_cert_filepath = NULL;
			info.ssl_private_key_filepath = NULL;
			info.ssl_private_key_password = NULL;
			info.gid = -1;
			info.uid = -1;
			info.options = 0;
			/* Create the WebSocket context */
			wss = lws_create_vhost(wsc, &info);
			if(wss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error creating vhost for WebSockets server...\n");
			} else {
				JANUS_LOG(LOG_INFO, "WebSockets server started (port %d)...\n", wsport);
			}
			g_free(ip);
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "wss");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure WebSockets server disabled\n");
		} else {
			int wsport = 8989;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "wss_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}
			item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
			if(!item || !item->value) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				char *server_pem = (char *)item->value;
				char *server_key = (char *)item->value;
				char *password = NULL;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
				if(item && item->value)
					server_key = (char *)item->value;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
				if(item && item->value)
					password = (char *)item->value;
				JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
				/* Prepare secure context */
				struct lws_context_creation_info info;
				memset(&info, 0, sizeof info);
				info.port = wsport;
				info.iface = ip ? ip : interface;
				info.protocols = sws_protocols;
				info.extensions = NULL;
				info.ssl_cert_filepath = server_pem;
				info.ssl_private_key_filepath = server_key;
				info.ssl_private_key_password = password;
				info.gid = -1;
				info.uid = -1;
#if LWS_LIBRARY_VERSION_MAJOR >= 2
				info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#else
				info.options = 0;
#endif
				/* Create the secure WebSocket context */
				swss = lws_create_vhost(wsc, &info);
				if(swss == NULL) {
					JANUS_LOG(LOG_FATAL, "Error creating vhost for Secure WebSockets server...\n");
				} else {
					JANUS_LOG(LOG_INFO, "Secure WebSockets server started (port %d)...\n", wsport);
				}
			}
			g_free(ip);
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ws");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Admin WebSockets server disabled\n");
		} else {
			int wsport = 7188;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ws_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ws_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ws_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}
			/* Prepare context */
			struct lws_context_creation_info info;
			memset(&info, 0, sizeof info);
			info.port = wsport;
			info.iface = ip ? ip : interface;
			info.protocols = admin_ws_protocols;
			info.extensions = NULL;
			info.ssl_cert_filepath = NULL;
			info.ssl_private_key_filepath = NULL;
			info.ssl_private_key_password = NULL;
			info.gid = -1;
			info.uid = -1;
			info.options = 0;
			/* Create the WebSocket context */
			admin_wss = lws_create_vhost(wsc, &info);
			if(admin_wss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error creating vhost for Admin WebSockets server...\n");
			} else {
				JANUS_LOG(LOG_INFO, "Admin WebSockets server started (port %d)...\n", wsport);
			}
			g_free(ip);
		}
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_wss");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Secure Admin WebSockets server disabled\n");
		} else {
			int wsport = 7989;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_wss_port");
			if(item && item->value)
				wsport = atoi(item->value);
			char *interface = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_wss_interface");
			if(item && item->value)
				interface = (char *)item->value;
			char *ip = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_wss_ip");
			if(item && item->value) {
				ip = (char *)item->value;
				char *iface = janus_websockets_get_interface_name(ip);
				if(iface == NULL) {
					JANUS_LOG(LOG_WARN, "No interface associated with %s? Falling back to no interface...\n", ip);
				}
				ip = iface;
			}
			item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
			if(!item || !item->value) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				char *server_pem = (char *)item->value;
				char *server_key = (char *)item->value;
				char *password = NULL;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
				if(item && item->value)
					server_key = (char *)item->value;
				item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
				if(item && item->value)
					password = (char *)item->value;
				JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
				/* Prepare secure context */
				struct lws_context_creation_info info;
				memset(&info, 0, sizeof info);
				info.port = wsport;
				info.iface = ip ? ip : interface;
				info.protocols = admin_sws_protocols;
				info.extensions = NULL;
				info.ssl_cert_filepath = server_pem;
				info.ssl_private_key_filepath = server_key;
				info.ssl_private_key_password = password;
				info.gid = -1;
				info.uid = -1;
#if LWS_LIBRARY_VERSION_MAJOR >= 2
				info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#else
				info.options = 0;
#endif
				/* Create the secure WebSocket context */
				admin_swss = lws_create_vhost(wsc, &info);
				if(admin_swss == NULL) {
					JANUS_LOG(LOG_FATAL, "Error creating vhost for Secure Admin WebSockets server...\n");
				} else {
					JANUS_LOG(LOG_INFO, "Secure Admin WebSockets server started (port %d)...\n", wsport);
				}
			}
			g_free(ip);
		}
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

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the WebSocket service thread */
	if(ws_janus_api_enabled || ws_admin_api_enabled) {
		ws_thread = g_thread_try_new("ws thread", &janus_websockets_thread, wsc, &error);
		if(!ws_thread) {
			g_atomic_int_set(&initialized, 0);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the WebSockets thread...\n", error->code, error->message ? error->message : "??");
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

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_WEBSOCKETS_NAME);
}

static void janus_websockets_destroy_client(
		janus_websockets_client *ws_client,
		struct lws *wsi,
		const char *log_prefix) {
	if(!ws_client || !g_atomic_int_compare_and_exchange(&ws_client->destroyed, 0, 1))
		return;
	/* Cleanup */
	janus_mutex_lock(&ws_client->ts->mutex);
	JANUS_LOG(LOG_INFO, "[%s-%p] Destroying WebSocket client\n", log_prefix, wsi);
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
	if(!client) {
		json_decref(message);
		janus_mutex_unlock(&transport->mutex);
		return -1;
	}
	/* Convert to string and enqueue */
	char *payload = json_dumps(message, json_format);
	g_async_queue_push(client->messages, payload);
	lws_callback_on_writable(client->wsi);
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
		case LWS_CALLBACK_RECEIVE: {
			JANUS_LOG(LOG_HUGE, "[%s-%p] Got %zu bytes:\n", log_prefix, wsi, len);
			if(ws_client == NULL || ws_client->wsi == NULL) {
				JANUS_LOG(LOG_ERR, "[%s-%p] Invalid WebSocket client instance...\n", log_prefix, wsi);
				return -1;
			}
			if(g_atomic_int_get(&ws_client->destroyed))
				return 0;
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
		case LWS_CALLBACK_SERVER_WRITEABLE: {
			if(ws_client == NULL || ws_client->wsi == NULL) {
				JANUS_LOG(LOG_ERR, "[%s-%p] Invalid WebSocket client instance...\n", log_prefix, wsi);
				return -1;
			}
			if(!g_atomic_int_get(&ws_client->destroyed) && !g_atomic_int_get(&stopping)) {
				janus_mutex_lock(&ws_client->ts->mutex);
				/* Check if we have a pending/partial write to complete first */
				if(ws_client->buffer && ws_client->bufpending > 0 && ws_client->bufoffset > 0
						&& !g_atomic_int_get(&ws_client->destroyed) && !g_atomic_int_get(&stopping)) {
					JANUS_LOG(LOG_HUGE, "[%s-%p] Completing pending WebSocket write (still need to write last %d bytes)...\n",
						log_prefix, wsi, ws_client->bufpending);
					int sent = lws_write(wsi, ws_client->buffer + ws_client->bufoffset, ws_client->bufpending, LWS_WRITE_TEXT);
					JANUS_LOG(LOG_HUGE, "[%s-%p]   -- Sent %d/%d bytes\n", log_prefix, wsi, sent, ws_client->bufpending);
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
					janus_mutex_unlock(&ws_client->ts->mutex);
					return 0;
				}
				/* Shoot all the pending messages */
				char *response = g_async_queue_try_pop(ws_client->messages);
				if(response && !g_atomic_int_get(&ws_client->destroyed) && !g_atomic_int_get(&stopping)) {
					/* Gotcha! */
					int buflen = LWS_SEND_BUFFER_PRE_PADDING + strlen(response) + LWS_SEND_BUFFER_POST_PADDING;
					if (buflen > ws_client->buflen) {
						/* We need a larger shared buffer */
						JANUS_LOG(LOG_HUGE, "[%s-%p] Re-allocating to %d bytes (was %d, response is %zu bytes)\n", log_prefix, wsi, buflen, ws_client->buflen, strlen(response));
						ws_client->buflen = buflen;
						ws_client->buffer = g_realloc(ws_client->buffer, buflen);
					}
					memcpy(ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, response, strlen(response));
					JANUS_LOG(LOG_HUGE, "[%s-%p] Sending WebSocket message (%zu bytes)...\n", log_prefix, wsi, strlen(response));
					int sent = lws_write(wsi, ws_client->buffer + LWS_SEND_BUFFER_PRE_PADDING, strlen(response), LWS_WRITE_TEXT);
					JANUS_LOG(LOG_HUGE, "[%s-%p]   -- Sent %d/%zu bytes\n", log_prefix, wsi, sent, strlen(response));
					if(sent > -1 && sent < (int)strlen(response)) {
						/* We couldn't send everything in a single write, we'll complete this in the next round */
						ws_client->bufpending = strlen(response) - sent;
						ws_client->bufoffset = LWS_SEND_BUFFER_PRE_PADDING + sent;
						JANUS_LOG(LOG_HUGE, "[%s-%p]   -- Couldn't write all bytes (%d missing), setting offset %d\n",
							log_prefix, wsi, ws_client->bufpending, ws_client->bufoffset);
					}
					/* We can get rid of the message */
					free(response);
					/* Done for this round, check the next response/notification later */
					lws_callback_on_writable(wsi);
					janus_mutex_unlock(&ws_client->ts->mutex);
					return 0;
				}
				janus_mutex_unlock(&ws_client->ts->mutex);
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
