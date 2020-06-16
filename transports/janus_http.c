/*! \file   janus_http.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus RESTs transport plugin
 * \details  This is an implementation of a RESTs transport for the
 * Janus API, using the libmicrohttpd library (http://www.gnu.org/software/libmicrohttpd/).
 * This module allows browsers to make use of HTTP to talk to the Janus core.
 * Since a Janus instance may be deployed on a different domain than the web
 * server hosting the web applications using it, the plugin automatically
 * handles OPTIONS request to comply with the CORS specification.
 * POST requests can be used to ask for the management of a session with
 * the server, to attach to a plugin, to send messages to the plugin
 * itself and so on. GET requests instead are used for getting events
 * associated to a Janus session (and as such to all its plugin handles
 * and the events plugins push in the session itself), using a long poll
 * approach. A JavaScript library (janus.js) implements all of this on
 * the client side automatically.
 * \note There's a well known bug in libmicrohttpd that may cause it to
 * spike to 100% of the CPU when using HTTPS on some distributions. In
 * case you're interested in HTTPS support, it's better to just rely on
 * HTTP in Janus, and put a frontend like Apache HTTPD or nginx to take
 * care of securing the traffic. More details are available in \ref deploy.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <microhttpd.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../ip-utils.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_REST_VERSION			2
#define JANUS_REST_VERSION_STRING	"0.0.2"
#define JANUS_REST_DESCRIPTION		"This transport plugin adds REST (HTTP/HTTPS) support to the Janus API via libmicrohttpd."
#define JANUS_REST_NAME				"JANUS REST (HTTP/HTTPS) transport plugin"
#define JANUS_REST_AUTHOR			"Meetecho s.r.l."
#define JANUS_REST_PACKAGE			"janus.transport.http"

/* Transport methods */
janus_transport *create(void);
int janus_http_init(janus_transport_callbacks *callback, const char *config_path);
void janus_http_destroy(void);
int janus_http_get_api_compatibility(void);
int janus_http_get_version(void);
const char *janus_http_get_version_string(void);
const char *janus_http_get_description(void);
const char *janus_http_get_name(void);
const char *janus_http_get_author(void);
const char *janus_http_get_package(void);
gboolean janus_http_is_janus_api_enabled(void);
gboolean janus_http_is_admin_api_enabled(void);
int janus_http_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_http_session_created(janus_transport_session *transport, guint64 session_id);
void janus_http_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_http_session_claimed(janus_transport_session *transport, guint64 session_id);


/* Transport setup */
static janus_transport janus_http_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_http_init,
		.destroy = janus_http_destroy,

		.get_api_compatibility = janus_http_get_api_compatibility,
		.get_version = janus_http_get_version,
		.get_version_string = janus_http_get_version_string,
		.get_description = janus_http_get_description,
		.get_name = janus_http_get_name,
		.get_author = janus_http_get_author,
		.get_package = janus_http_get_package,

		.is_janus_api_enabled = janus_http_is_janus_api_enabled,
		.is_admin_api_enabled = janus_http_is_admin_api_enabled,

		.send_message = janus_http_send_message,
		.session_created = janus_http_session_created,
		.session_over = janus_http_session_over,
		.session_claimed = janus_http_session_claimed,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_REST_NAME);
	return &janus_http_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean http_janus_api_enabled = FALSE;
static gboolean http_admin_api_enabled = FALSE;
static gboolean notify_events = TRUE;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


/* Incoming HTTP message */
typedef struct janus_http_msg {
	struct MHD_Connection *connection;	/* The MHD connection this message came from */
	volatile int suspended;				/* Whether this connection is currently suspended */
	volatile void *longpoll;			/* Whether this is a long poll connection for a session */
	int max_events;						/* In case this is a long poll, how many events we should send back */
	char *acrh;							/* Value of the Access-Control-Request-Headers HTTP header, if any (needed for CORS) */
	char *acrm;							/* Value of the Access-Control-Request-Method HTTP header, if any (needed for CORS) */
	char *contenttype;					/* Content-Type of the payload */
	char *payload;						/* Payload of the message */
	size_t len;							/* Length of the message in octets */
	gint64 session_id;					/* Janus-Client session identifier this message belongs to */
	char *response;						/* The response from the core as a string */
	size_t resplen;						/* Length of the response in octets */
	GSource *timeout;					/* Timeout monitor, if any */
	volatile gint timeout_flag;			/* Whether a timeout hasn't fired yet */
	volatile gint destroyed;			/* Whether this session has been destroyed */
	janus_refcount ref;					/* Reference counter for this message */
} janus_http_msg;
static GHashTable *messages = NULL;
static janus_mutex messages_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_http_msg_free(const janus_refcount *msg_ref) {
	janus_http_msg *request = janus_refcount_containerof(msg_ref, janus_http_msg, ref);
	/* This message can be destroyed, free all the resources */
	if(!request)
		return;
	g_free(request->payload);
	g_free(request->contenttype);
	g_free(request->acrh);
	g_free(request->acrm);
	g_free(request->response);
	g_free(request);
}

static void janus_http_msg_destroy(void *msg) {
	janus_http_msg *request = (janus_http_msg *)msg;
	if(request && g_atomic_int_compare_and_exchange(&request->destroyed, 0, 1))
		janus_refcount_decrease(&request->ref);
}


/* Helper for long poll: HTTP events to push per session */
typedef struct janus_http_session {
	guint64 session_id;			/* Core session identifier */
	GAsyncQueue *events;		/* Events to notify for this session */
	GList *longpolls;			/* Long poll connection */
	janus_mutex mutex;			/* Mutex to lock this instance */
	volatile gint destroyed;	/* Whether this session has been destroyed */
	janus_refcount ref;			/* Reference counter for this session */
} janus_http_session;
/* We keep track of created sessions as we handle long polls */
static const char *keepalive_id = "keepalive";
static GHashTable *sessions = NULL;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_http_session_destroy(janus_http_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_http_session_free(const janus_refcount *session_ref) {
	janus_http_session *session = janus_refcount_containerof(session_ref, janus_http_session, ref);
	/* This session can be destroyed, free all the resources */
	if(session->events) {
		json_t *event = NULL;
		while((event = g_async_queue_try_pop(session->events)) != NULL)
			json_decref(event);
		g_async_queue_unref(session->events);
	}
	g_free(session);
}


/* Custom GSource for tracking request timeouts (including long polls) */
typedef struct janus_http_request_timeout {
	GSource source;
	janus_transport_session *ts;
	janus_http_session *session;
} janus_http_request_timeout;
/* Helper to handle timeouts */
static void janus_http_timeout(janus_transport_session *ts, janus_http_session *session);
/* GSource Functions */
static gboolean janus_http_request_timeout_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	JANUS_LOG(LOG_DBG, "[%p] dispatch\n", source);
	janus_http_request_timeout *t = (janus_http_request_timeout *)source;
	/* Timeout fired, invoke the function */
	janus_http_timeout(t->ts, t->session);
	/* We're done */
	g_source_destroy(source);
	g_source_unref(source);
	return G_SOURCE_REMOVE;
}
static void janus_http_request_timeout_finalize(GSource *source) {
	JANUS_LOG(LOG_DBG, "[%p] finalize\n", source);
	janus_http_request_timeout *timeout = (janus_http_request_timeout *)source;
	if(timeout) {
		if(timeout->session)
			janus_refcount_decrease(&timeout->session->ref);
		if(timeout->ts)
			janus_refcount_decrease(&timeout->ts->ref);
	}
}
static GSourceFuncs janus_http_request_timeout_funcs = {
	NULL, NULL,
	janus_http_request_timeout_dispatch,
	janus_http_request_timeout_finalize,
	NULL, NULL
};
static GSource *janus_http_request_timeout_create(janus_transport_session *ts, janus_http_session *session, gint timeout) {
	GSource *source = g_source_new(&janus_http_request_timeout_funcs, sizeof(janus_http_request_timeout));
	janus_http_request_timeout *t = (janus_http_request_timeout *)source;
	t->ts = ts;
	t->session = session;
	g_source_set_ready_time(source, janus_get_monotonic_time() + timeout*G_USEC_PER_SEC);
	JANUS_LOG(LOG_DBG, "[%p] create (%d)\n", source, timeout);
	return source;
}


/* Callback (libmicrohttpd) invoked when a new connection is attempted on the REST API */
static int janus_http_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen);
/* Callback (libmicrohttpd) invoked when a new connection is attempted on the admin/monitor webserver */
static int janus_http_admin_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen);
/* Callback (libmicrohttpd) invoked when an HTTP message (GET, POST, OPTIONS, etc.) is available */
static int janus_http_handler(void *cls, struct MHD_Connection *connection,
	const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
/* Callback (libmicrohttpd) invoked when an admin/monitor HTTP message (GET, POST, OPTIONS, etc.) is available */
static int janus_http_admin_handler(void *cls, struct MHD_Connection *connection,
	const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
/* Callback (libmicrohttpd) invoked when headers of an incoming HTTP message have been parsed */
static int janus_http_headers(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
/* Callback (libmicrohttpd) invoked when a request has been processed and can be freed */
static void janus_http_request_completed(void *cls, struct MHD_Connection *connection,
	void **con_cls, enum MHD_RequestTerminationCode toe);
/* Callback to send data back after resuming a connection */
static ssize_t janus_http_response_callback(void *cls, uint64_t pos, char *buf, size_t max);
/* Worker to handle requests that are actually long polls */
static int janus_http_notifier(janus_http_msg *msg);
/* Helper to quickly send a success response */
static int janus_http_return_success(janus_transport_session *ts, char *payload);
/* Helper to quickly send an error response */
static int janus_http_return_error(janus_transport_session *ts, uint64_t session_id,
	const char *transaction, gint error, const char *format, ...) G_GNUC_PRINTF(5, 6);


/* MHD Web Server */
static struct MHD_Daemon *ws = NULL, *sws = NULL;
static char *ws_path = NULL;
static char *cert_pem_bytes = NULL, *cert_key_bytes = NULL;

/* Admin/Monitor MHD Web Server */
static struct MHD_Daemon *admin_ws = NULL, *admin_sws = NULL;
static char *admin_ws_path = NULL;

/* Custom Access-Control-Allow-Origin value, if specified */
static char *allow_origin = NULL;

/* REST and Admin/Monitor ACL list */
static GList *janus_http_access_list = NULL, *janus_http_admin_access_list = NULL;
static janus_mutex access_list_mutex;
static void janus_http_allow_address(const char *ip, gboolean admin) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&access_list_mutex);
	if(!admin)
		janus_http_access_list = g_list_append(janus_http_access_list, (gpointer)ip);
	else
		janus_http_admin_access_list = g_list_append(janus_http_admin_access_list, (gpointer)ip);
	janus_mutex_unlock(&access_list_mutex);
}
static gboolean janus_http_is_allowed(const char *ip, gboolean admin) {
	if(ip == NULL)
		return FALSE;
	if(!admin && janus_http_access_list == NULL)
		return TRUE;
	if(admin && janus_http_admin_access_list == NULL)
		return TRUE;
	janus_mutex_lock(&access_list_mutex);
	GList *temp = admin ? janus_http_admin_access_list : janus_http_access_list;
	while(temp) {
		const char *allowed = (const char *)temp->data;
		if(allowed != NULL && strstr(ip, allowed)) {
			janus_mutex_unlock(&access_list_mutex);
			return TRUE;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&access_list_mutex);
	return FALSE;
}

/* Helper method to get the port from a struct sockaddr */
static uint16_t janus_http_sockaddr_to_port(struct sockaddr *address) {
	if(address == NULL)
		return 0;
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	switch(address->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)address;
			return ntohs(sin->sin_port);
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)address;
			return ntohs(sin6->sin6_port);
		default:
			/* Unknown family */
			break;
	}
	return 0;
}

/* Random string helper (for transactions) */
static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static void janus_http_random_string(int length, char *buffer) {
	if(length > 0 && buffer) {
		int l = (int)(sizeof(charset)-1);
		int i=0;
		for(i=0; i<length; i++) {
			int key = rand() % l;
			buffer[i] = charset[key];
		}
		buffer[length-1] = '\0';
	}
}

/* Event loop for timeout monitoring purposes */
static GThread *httptimer = NULL;
static GMainLoop *httploop = NULL;
static GMainContext *httpctx = NULL;
static gpointer janus_http_timer(gpointer user_data) {
	JANUS_LOG(LOG_INFO, "HTTP transport timer started\n");
	g_main_loop_run(httploop);
	return NULL;
}


/* Helper to create a MHD daemon */
static struct MHD_Daemon *janus_http_create_daemon(gboolean admin, char *path,
		const char *interface, const char *ip, int port,
		const char *server_pem, const char *server_key, const char *password, const char *ciphers) {
	struct MHD_Daemon *daemon = NULL;
	gboolean secure = server_pem && server_key;
	/* Any interface or IP address we need to limit ourselves to?
	 * NOTE WELL: specifying an interface does NOT bind to all IPs associated
	 * with that interface, but only to the first one that's detected */
	static struct sockaddr_in addr = { 0 };
	struct sockaddr_in6 addr6 = { 0 };
	gboolean ipv6 = FALSE;
	if(ip && strstr(ip, ":"))
		ipv6 = TRUE;
	gboolean found = FALSE;
	if(ip) {
		/* Do a quick check to see if we need to bind on all addresses of a specific family */
		if(!strcasecmp(ip, "0.0.0.0")) {
			/* Bind on all IPv4 addresses */
			found = TRUE;
			memset(&addr, 0, sizeof (struct sockaddr_in));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = INADDR_ANY;
		} else if(!strcasecmp(ip, "::")) {
			/* Bind on all IPv6 addresses */
			found = TRUE;
			memset(&addr6, 0, sizeof (struct sockaddr_in6));
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port = htons(port);
			addr6.sin6_addr = in6addr_any;
		}
	}
	if(!found && (ip || interface)) {
		struct ifaddrs *ifaddr = NULL, *ifa = NULL;
		int family = 0, s = 0, n = 0;
		char host[NI_MAXHOST];
		if(getifaddrs(&ifaddr) == -1) {
			JANUS_LOG(LOG_ERR, "Error getting list of interfaces to bind %s API %s webserver...\n",
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			return NULL;
		} else {
			for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
				if(ifa->ifa_addr == NULL)
					continue;
				family = ifa->ifa_addr->sa_family;
				if(interface && strcasecmp(ifa->ifa_name, interface))
					continue;
				if(ifa->ifa_addr == NULL)
					continue;
				/* Skip interfaces which are not up and running */
				if(!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
					continue;
				/* FIXME When being explicit about the interface only, we only bind IPv4 for now:
				 * specifying or adding a precise IPv6 address gets you an IPv6 binding instead */
				if(!ipv6 && family == AF_INET) {
					s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
					if(s != 0) {
						JANUS_LOG(LOG_ERR, "Error doing a getnameinfo() to bind %s API %s webserver to '%s'...\n",
							admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP", ip ? ip : interface);
						return NULL;
					}
					if(ip && strcmp(host, ip))
						continue;
					found = TRUE;
					break;
				} else if(ipv6 && family == AF_INET6) {
					s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
					if(s != 0) {
						JANUS_LOG(LOG_ERR, "Error doing a getnameinfo() to bind %s API %s webserver to '%s'...\n",
							admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP", ip ? ip : interface);
						return NULL;
					}
					if(ip && strcmp(host, ip))
						continue;
					found = TRUE;
					break;
				}
			}
			freeifaddrs(ifaddr);
		}
		if(!found) {
			JANUS_LOG(LOG_ERR, "Error binding to %s '%s' for %s API %s webserver...\n",
				ip ? "IP" : "interface", ip ? ip : interface,
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			return NULL;
		}
		JANUS_LOG(LOG_VERB, "Going to bind the %s API %s webserver to %s (asked for %s)\n",
			admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP", host, ip ? ip : interface);
		if(!ipv6) {
			memset(&addr, 0, sizeof(struct sockaddr_in));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			int res = inet_pton(AF_INET, host, &addr.sin_addr);
			if(res != 1) {
				JANUS_LOG(LOG_ERR, "Failed to convert address '%s' (%d)\n", host, res);
				return NULL;
			}
		} else {
			memset(&addr6, 0, sizeof(struct sockaddr_in6));
			addr6.sin6_family = AF_INET6;
			addr6.sin6_port = htons(port);
			int res = inet_pton(AF_INET6, host, &addr6.sin6_addr);
			if(res != 1) {
				JANUS_LOG(LOG_ERR, "Failed to convert address '%s' (%d)\n", host, res);
				return NULL;
			}
		}
	}

	if(!secure) {
		/* HTTP web server */
		if(!interface && !ip) {
			/* Bind to all interfaces */
			JANUS_LOG(LOG_VERB, "Binding to all interfaces for the %s API %s webserver\n",
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			daemon = MHD_start_daemon(
				MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_AUTO | MHD_USE_SUSPEND_RESUME | MHD_USE_DUAL_STACK,
				port,
				admin ? janus_http_admin_client_connect : janus_http_client_connect,
				NULL,
				admin ? &janus_http_admin_handler : &janus_http_handler,
				path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_http_request_completed, NULL,
				MHD_OPTION_END);
		} else {
			/* Bind to the interface that was specified */
			JANUS_LOG(LOG_VERB, "Binding to %s '%s' for the %s API %s webserver\n",
				ip ? "IP" : "interface", ip ? ip : interface,
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			daemon = MHD_start_daemon(
				MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_AUTO | MHD_USE_SUSPEND_RESUME | (ipv6 ? MHD_USE_IPv6 : 0),
				port,
				admin ? janus_http_admin_client_connect : janus_http_client_connect,
				NULL,
				admin ? &janus_http_admin_handler : &janus_http_handler,
				path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_http_request_completed, NULL,
				MHD_OPTION_SOCK_ADDR, ipv6 ? (struct sockaddr *)&addr6 : (struct sockaddr *)&addr,
				MHD_OPTION_END);
		}
	} else {
		/* HTTPS web server, read certificate and key */
		g_file_get_contents(server_pem, &cert_pem_bytes, NULL, NULL);
		g_file_get_contents(server_key, &cert_key_bytes, NULL, NULL);

		/* Start webserver */
		if(!interface && !ip) {
			/* Bind to all interfaces */
			JANUS_LOG(LOG_VERB, "Binding to all interfaces for the %s API %s webserver\n",
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			daemon = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_AUTO | MHD_USE_SUSPEND_RESUME | MHD_USE_DUAL_STACK,
				port,
				admin ? janus_http_admin_client_connect : janus_http_client_connect,
				NULL,
				admin ? &janus_http_admin_handler : &janus_http_handler,
				path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_http_request_completed, NULL,
				MHD_OPTION_HTTPS_PRIORITIES, ciphers,
				MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
				MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_HTTPS_KEY_PASSWORD, password,
				MHD_OPTION_END);
		} else {
			/* Bind to the interface that was specified */
			JANUS_LOG(LOG_VERB, "Binding to %s '%s' for the %s API %s webserver\n",
				ip ? "IP" : "interface", ip ? ip : interface,
				admin ? "Admin" : "Janus", secure ? "HTTPS" : "HTTP");
			daemon = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_AUTO | MHD_USE_SUSPEND_RESUME | (ipv6 ? MHD_USE_IPv6 : 0),
				port,
				admin ? janus_http_admin_client_connect : janus_http_client_connect,
				NULL,
				admin ? &janus_http_admin_handler : &janus_http_handler,
				path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_http_request_completed, NULL,
				MHD_OPTION_HTTPS_PRIORITIES, ciphers,
				MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
				MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_HTTPS_KEY_PASSWORD, password,
				MHD_OPTION_SOCK_ADDR, ipv6 ? (struct sockaddr *)&addr6 : (struct sockaddr *)&addr,
				MHD_OPTION_END);
		}
	}
	return daemon;
}

/* Static helper method to fill in the CORS headers */
static void janus_http_add_cors_headers(janus_http_msg *msg, struct MHD_Response *response) {
	if(msg == NULL || g_atomic_int_get(&msg->destroyed) || response == NULL)
		return;
	janus_refcount_increase(&msg->ref);
	MHD_add_response_header(response, "Access-Control-Allow-Origin", allow_origin ? allow_origin : "*");
	if(allow_origin) {
		/* We need these two headers as well, in case Access-Control-Allow-Origin is custom */
		MHD_add_response_header(response, "Access-Control-Allow-Credentials", "true");
		MHD_add_response_header(response, "Vary", "Origin");
	}
	MHD_add_response_header(response, "Access-Control-Max-Age", "86400");
	if(msg->acrm)
		MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
	if(msg->acrh)
		MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
	janus_refcount_decrease(&msg->ref);
}

/* Static callback that we register to */
static void janus_http_mhd_panic(void *cls, const char *file, unsigned int line, const char *reason) {
	JANUS_LOG(LOG_WARN, "[%s]: Error in GNU libmicrohttpd %s:%u: %s\n",
		JANUS_REST_PACKAGE, file, line, reason);
}

/* Transport implementation */
int janus_http_init(janus_transport_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Register a function to detect problems for which MHD would typically abort */
	MHD_set_panic_func(&janus_http_mhd_panic, NULL);

	/* Start the timer */
	httpctx = g_main_context_new();
	httploop = g_main_loop_new(httpctx, FALSE);
	GError *error = NULL;
	httptimer = g_thread_try_new("http timer", &janus_http_timer, NULL, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start HTTP timer...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_REST_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_REST_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_REST_PACKAGE);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_REST_NAME);
		}

		/* Check the base paths */
		item = janus_config_get(config, config_general, janus_config_type_item, "base_path");
		if(item && item->value) {
			if(item->value[0] != '/') {
				JANUS_LOG(LOG_FATAL, "Invalid base path %s (it should start with a /, e.g., /janus\n", item->value);
				return -1;
			}
			ws_path = g_strdup(item->value);
			if(strlen(ws_path) > 1 && ws_path[strlen(ws_path)-1] == '/') {
				/* Remove the trailing slash, it makes things harder when we parse requests later */
				ws_path[strlen(ws_path)-1] = '\0';
			}
		} else {
			ws_path = g_strdup("/janus");
		}
		/* Do the same for the admin/monitor interface */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_base_path");
		if(item && item->value) {
			if(item->value[0] != '/') {
				JANUS_LOG(LOG_FATAL, "Invalid admin/monitor base path %s (it should start with a /, e.g., /admin\n", item->value);
				return -1;
			}
			admin_ws_path = g_strdup(item->value);
			if(strlen(admin_ws_path) > 1 && admin_ws_path[strlen(admin_ws_path)-1] == '/') {
				/* Remove the trailing slash, it makes things harder when we parse requests later */
				admin_ws_path[strlen(admin_ws_path)-1] = '\0';
			}
		} else {
			admin_ws_path = g_strdup("/admin");
		}

		/* Any ACL for either the Janus or Admin API? */
		item = janus_config_get(config, config_general, janus_config_type_item, "acl");
		if(item && item->value) {
			char **list = g_strsplit(item->value, ",", -1);
			char *index = list[0];
			if(index != NULL) {
				int i=0;
				while(index != NULL) {
					if(strlen(index) > 0) {
						JANUS_LOG(LOG_INFO, "Adding '%s' to the Janus API allowed list...\n", index);
						janus_http_allow_address(g_strdup(index), FALSE);
					}
					i++;
					index = list[i];
				}
			}
			g_strfreev(list);
			list = NULL;
		}
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_acl");
		if(item && item->value) {
			char **list = g_strsplit(item->value, ",", -1);
			char *index = list[0];
			if(index != NULL) {
				int i=0;
				while(index != NULL) {
					if(strlen(index) > 0) {
						JANUS_LOG(LOG_INFO, "Adding '%s' to the Admin/monitor allowed list...\n", index);
						janus_http_allow_address(g_strdup(index), TRUE);
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

		/* Start with the Janus API web server now */
		item = janus_config_get(config, config_general, janus_config_type_item, "http");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "HTTP webserver disabled\n");
		} else {
			uint16_t wsport = 8088;
			item = janus_config_get(config, config_general, janus_config_type_item, "port");
			if(item && item->value && janus_string_to_uint16(item->value, &wsport) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
				wsport = 8088;
			}
			const char *interface = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "interface");
			if(item && item->value)
				interface = item->value;
			const char *ip = NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "ip");
			if(item && item->value)
				ip = item->value;
			ws = janus_http_create_daemon(FALSE, ws_path, interface, ip, wsport,
				NULL, NULL, NULL, NULL);
			if(ws == NULL) {
				JANUS_LOG(LOG_FATAL, "Couldn't start webserver on port %d...\n", wsport);
			} else {
				JANUS_LOG(LOG_INFO, "HTTP webserver started (port %d, %s path listener)...\n", wsport, ws_path);
			}
		}
		/* Do we also have to provide an HTTPS one? */
		char *server_pem = NULL;
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
		if(item && item->value)
			server_pem = (char *)item->value;
		char *server_key = NULL;
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
		if(item && item->value)
			server_key = (char *)item->value;
		char *password = NULL;
		item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
		if(item && item->value)
			password = (char *)item->value;
		const char *ciphers = "NORMAL";
		item = janus_config_get(config, config_certs, janus_config_type_item, "ciphers");
		if(item && item->value)
			ciphers = item->value;
		if(server_key)
			JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
		item = janus_config_get(config, config_general, janus_config_type_item, "https");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "HTTPS webserver disabled\n");
		} else {
			if(!server_key || !server_pem) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				uint16_t swsport = 8089;
				item = janus_config_get(config, config_general, janus_config_type_item, "secure_port");
				if(item && item->value && janus_string_to_uint16(item->value, &swsport) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
					swsport = 8089;
				}
				const char *interface = NULL;
				item = janus_config_get(config, config_general, janus_config_type_item, "secure_interface");
				if(item && item->value)
					interface = item->value;
				const char *ip = NULL;
				item = janus_config_get(config, config_general, janus_config_type_item, "secure_ip");
				if(item && item->value)
					ip = item->value;
				sws = janus_http_create_daemon(FALSE, ws_path, interface, ip, swsport,
					server_pem, server_key, password, ciphers);
				if(sws == NULL) {
					JANUS_LOG(LOG_FATAL, "Couldn't start secure webserver on port %d...\n", swsport);
				} else {
					JANUS_LOG(LOG_INFO, "HTTPS webserver started (port %d, %s path listener)...\n", swsport, ws_path);
				}
			}
		}
		/* Admin/monitor time: start web server, if enabled */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_http");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Admin/monitor HTTP webserver disabled\n");
		} else {
			uint16_t wsport = 7088;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_port");
			if(item && item->value && janus_string_to_uint16(item->value, &wsport) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
				wsport = 7088;
			}
			const char *interface = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_interface");
			if(item && item->value)
				interface = item->value;
			const char *ip = NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_ip");
			if(item && item->value)
				ip = item->value;
			admin_ws = janus_http_create_daemon(TRUE, admin_ws_path, interface, ip, wsport,
				NULL, NULL, NULL, NULL);
			if(admin_ws == NULL) {
				JANUS_LOG(LOG_FATAL, "Couldn't start admin/monitor webserver on port %d...\n", wsport);
			} else {
				JANUS_LOG(LOG_INFO, "Admin/monitor HTTP webserver started (port %d, %s path listener)...\n", wsport, admin_ws_path);
			}
		}
		/* Do we also have to provide an HTTPS one? */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_https");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Admin/monitor HTTPS webserver disabled\n");
		} else {
			if(!server_key) {
				JANUS_LOG(LOG_FATAL, "Missing certificate/key path\n");
			} else {
				uint16_t swsport = 7889;
				item = janus_config_get(config, config_admin, janus_config_type_item, "admin_secure_port");
				if(item && item->value && janus_string_to_uint16(item->value, &swsport) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
					swsport = 7889;
				}
				const char *interface = NULL;
				item = janus_config_get(config, config_admin, janus_config_type_item, "admin_secure_interface");
				if(item && item->value)
					interface = item->value;
				const char *ip = NULL;
				item = janus_config_get(config, config_admin, janus_config_type_item, "admin_secure_ip");
				if(item && item->value)
					ip = item->value;
				admin_sws = janus_http_create_daemon(TRUE, admin_ws_path, interface, ip, swsport,
					server_pem, server_key, password, ciphers);
				if(admin_sws == NULL) {
					JANUS_LOG(LOG_FATAL, "Couldn't start secure admin/monitor webserver on port %d...\n", swsport);
				} else {
					JANUS_LOG(LOG_INFO, "Admin/monitor HTTPS webserver started (port %d, %s path listener)...\n",
						swsport, admin_ws_path);
				}
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(!ws && !sws && !admin_ws && !admin_sws) {
		JANUS_LOG(LOG_WARN, "No HTTP/HTTPS server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}
	http_janus_api_enabled = ws || sws;
	http_admin_api_enabled = admin_ws || admin_sws;

	messages = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_transport_session_destroy);
	sessions = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_http_session_destroy);

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_REST_NAME);
	return 0;
}

void janus_http_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_main_loop_quit(httploop);
	g_thread_join(httptimer);
	g_main_context_unref(httpctx);

	/* Resume all pending connections, before stopping the webservers */
	janus_mutex_lock(&messages_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, messages);
	while(g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_transport_session *transport = value;
		janus_http_msg *msg = (janus_http_msg *)transport->transport_p;
		if(msg != NULL && !g_atomic_int_get(&msg->destroyed)) {
			MHD_resume_connection(msg->connection);
		}
	}
	janus_mutex_unlock(&messages_mutex);

	JANUS_LOG(LOG_INFO, "Stopping webserver(s)...\n");
	if(ws)
		MHD_stop_daemon(ws);
	ws = NULL;
	if(sws)
		MHD_stop_daemon(sws);
	sws = NULL;
	if(admin_ws)
		MHD_stop_daemon(admin_ws);
	admin_ws = NULL;
	if(admin_sws)
		MHD_stop_daemon(admin_sws);
	admin_sws = NULL;
	g_free((gpointer)cert_pem_bytes);
	cert_pem_bytes = NULL;
	g_free((gpointer)cert_key_bytes);
	cert_key_bytes = NULL;
	g_free(allow_origin);
	allow_origin = NULL;

	janus_mutex_lock(&messages_mutex);
	g_hash_table_destroy(messages);
	messages = NULL;
	janus_mutex_unlock(&messages_mutex);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_REST_NAME);
}

int janus_http_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_http_get_version(void) {
	return JANUS_REST_VERSION;
}

const char *janus_http_get_version_string(void) {
	return JANUS_REST_VERSION_STRING;
}

const char *janus_http_get_description(void) {
	return JANUS_REST_DESCRIPTION;
}

const char *janus_http_get_name(void) {
	return JANUS_REST_NAME;
}

const char *janus_http_get_author(void) {
	return JANUS_REST_AUTHOR;
}

const char *janus_http_get_package(void) {
	return JANUS_REST_PACKAGE;
}

gboolean janus_http_is_janus_api_enabled(void) {
	return http_janus_api_enabled;
}

gboolean janus_http_is_admin_api_enabled(void) {
	return http_admin_api_enabled;
}

int janus_http_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	JANUS_LOG(LOG_HUGE, "Got a %s API %s to send (%p)\n", admin ? "admin" : "Janus", request_id ? "response" : "event", transport);
	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message...\n");
		return -1;
	}
	if(request_id == NULL) {
		/* This is an event, add to the session queue */
		json_t *s = json_object_get(message, "session_id");
		if(!s || !json_is_integer(s)) {
			JANUS_LOG(LOG_ERR, "Can't notify event, no session_id...\n");
			json_decref(message);
			return -1;
		}
		guint64 session_id = json_integer_value(s);
		janus_mutex_lock(&sessions_mutex);
		janus_http_session *session = g_hash_table_lookup(sessions, &session_id);
		if(session == NULL || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "Can't notify event, no session object...\n");
			janus_mutex_unlock(&sessions_mutex);
			json_decref(message);
			return -1;
		}
		janus_refcount_increase(&session->ref);
		g_async_queue_push(session->events, message);
		janus_mutex_unlock(&sessions_mutex);
		/* Are there long polls waiting? */
		janus_mutex_lock(&session->mutex);
		janus_http_msg *msg = NULL;
		while(session->longpolls) {
			transport = (janus_transport_session *)session->longpolls->data;
			msg = (janus_http_msg *)(transport ? transport->transport_p : NULL);
			/* Is this connection ready to send a response back? */
			if(msg && g_atomic_pointer_compare_and_exchange(&msg->longpoll, session, NULL)) {
				janus_refcount_increase(&msg->ref);
				/* Send the events back */
				if(g_atomic_int_compare_and_exchange(&msg->timeout_flag, 1, 0)) {
					g_source_destroy(msg->timeout);
					g_source_unref(msg->timeout);
				}
				msg->timeout = NULL;
				janus_http_notifier(msg);
				janus_refcount_decrease(&msg->ref);
			}
			session->longpolls = g_list_remove(session->longpolls, transport);
		}
		janus_mutex_unlock(&session->mutex);
		janus_refcount_decrease(&session->ref);
	} else {
		if(request_id == keepalive_id) {
			/* It's a response from our fake long-poll related keepalive, ignore */
			json_decref(message);
			return 0;
		}
		/* This is a response, we need a valid transport instance */
		if(transport == NULL || transport->transport_p == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid HTTP instance...\n");
			json_decref(message);
			return -1;
		}
		/* We have a response */
		janus_transport_session *session = (janus_transport_session *)transport;
		janus_mutex_lock(&messages_mutex);
		if(g_hash_table_lookup(messages, session) == NULL) {
			janus_mutex_unlock(&messages_mutex);
			JANUS_LOG(LOG_ERR, "Invalid HTTP connection...\n");
			json_decref(message);
			return -1;
		}
		janus_http_msg *msg = (janus_http_msg *)transport->transport_p;
		janus_refcount_increase(&msg->ref);
		janus_mutex_unlock(&messages_mutex);
		if(!msg->connection) {
			JANUS_LOG(LOG_ERR, "Invalid HTTP connection...\n");
			json_decref(message);
			janus_refcount_decrease(&msg->ref);
			return -1;
		}
		if(g_atomic_int_compare_and_exchange(&msg->timeout_flag, 1, 0)) {
			g_source_destroy(msg->timeout);
			g_source_unref(msg->timeout);
		}
		msg->timeout = NULL;
		char *response_text = json_dumps(message, json_format);
		json_decref(message);
		msg->response = response_text;
		msg->resplen = strlen(response_text);
		MHD_resume_connection(msg->connection);
		janus_refcount_decrease(&msg->ref);
	}
	return 0;
}

void janus_http_session_created(janus_transport_session *transport, guint64 session_id) {
	if(transport == NULL || transport->transport_p == NULL)
		return;
	JANUS_LOG(LOG_VERB, "Session created (%"SCNu64"), create a queue for the long poll\n", session_id);
	/* Create a queue of events for this session */
	janus_mutex_lock(&sessions_mutex);
	if(g_hash_table_lookup(sessions, &session_id) != NULL) {
		JANUS_LOG(LOG_WARN, "Ignoring created session, apparently we're already handling it?\n");
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	janus_http_session *session = g_malloc(sizeof(janus_http_session));
	session->session_id = session_id;
	session->events = g_async_queue_new();
	session->longpolls = NULL;
	janus_mutex_init(&session->mutex);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_http_session_free);
	g_hash_table_insert(sessions, janus_uint64_dup(session_id), session);
	janus_mutex_unlock(&sessions_mutex);
}

void janus_http_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	JANUS_LOG(LOG_VERB, "Session %s %s (%"SCNu64"), getting rid of the queue for the long poll\n",
		timeout ? "has timed out" : "is over",
		claimed ? "but has been claimed" : "and has not been claimed", session_id);
	/* Get rid of the session's queue of events */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, &session_id);
	janus_mutex_unlock(&sessions_mutex);
}

void janus_http_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* Session has been claimed -- is there anything to do here? */
	JANUS_LOG(LOG_VERB, "Session has been claimed: (%"SCNu64"), adding to hash table\n", session_id);
	janus_mutex_lock(&sessions_mutex);
	janus_http_session *old_session = g_hash_table_lookup(sessions, &session_id);
	if(old_session != NULL)
		janus_refcount_increase(&old_session->ref);
	janus_mutex_unlock(&sessions_mutex);
	janus_http_session *session = g_malloc(sizeof(janus_http_session));
	session->session_id = session_id;
	session->events = g_async_queue_new();
	session->longpolls = NULL;
	janus_mutex_init(&session->mutex);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_http_session_free);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, janus_uint64_dup(session_id), session);
	janus_mutex_unlock(&sessions_mutex);
	if(old_session == NULL)
		return;
	/* Were there long polls waiting? */
	janus_mutex_lock(&old_session->mutex);
	janus_http_msg *msg = NULL;
	while(old_session->longpolls) {
		transport = (janus_transport_session *)old_session->longpolls->data;
		msg = (janus_http_msg *)(transport ? transport->transport_p : NULL);
		if(msg != NULL) {
			janus_refcount_increase(&msg->ref);
			if(g_atomic_int_compare_and_exchange(&msg->timeout_flag, 1, 0)) {
				g_source_destroy(msg->timeout);
				g_source_unref(msg->timeout);
			}
			msg->timeout = NULL;
			if(g_atomic_pointer_compare_and_exchange(&msg->longpoll, session, NULL)) {
				/* Return an error on the long poll right away */
				janus_http_timeout(transport, old_session);
			}
			janus_refcount_decrease(&msg->ref);
		}
		session->longpolls = g_list_remove(old_session->longpolls, transport);
	}
	janus_mutex_unlock(&old_session->mutex);
	janus_refcount_decrease(&old_session->ref);
}

/* Connection notifiers */
static int janus_http_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen) {
	janus_network_address naddr;
	janus_network_address_string_buffer naddr_buf;
	if(janus_network_address_from_sockaddr((struct sockaddr *)addr, &naddr) != 0 ||
			janus_network_address_to_string_buffer(&naddr, &naddr_buf) != 0) {
		JANUS_LOG(LOG_WARN, "Error trying to resolve connection address...\n");
		/* Should this be MHD_NO instead? */
		return MHD_YES;
	}
	const char *ip = janus_network_address_string_from_buffer(&naddr_buf);
	JANUS_LOG(LOG_HUGE, "New connection on REST API: %s\n", ip);
	/* Any access limitation based on this IP address? */
	if(!janus_http_is_allowed(ip, FALSE)) {
		JANUS_LOG(LOG_ERR, "IP %s is unauthorized to connect to the Janus API interface\n", ip);
		return MHD_NO;
	}
	return MHD_YES;
}

static int janus_http_admin_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen) {
	janus_network_address naddr;
	janus_network_address_string_buffer naddr_buf;
	if(janus_network_address_from_sockaddr((struct sockaddr *)addr, &naddr) != 0 ||
			janus_network_address_to_string_buffer(&naddr, &naddr_buf) != 0) {
		JANUS_LOG(LOG_WARN, "Error trying to resolve Admin connection address...\n");
		/* Should this be MHD_NO instead? */
		return MHD_YES;
	}
	const char *ip = janus_network_address_string_from_buffer(&naddr_buf);
	JANUS_LOG(LOG_HUGE, "New connection on admin/monitor: %s\n", ip);
	/* Any access limitation based on this IP address? */
	if(!janus_http_is_allowed(ip, TRUE)) {
		JANUS_LOG(LOG_ERR, "IP %s is unauthorized to connect to the admin/monitor interface\n", ip);
		return MHD_NO;
	}
	return MHD_YES;
}


/* WebServer requests handler */
static int janus_http_handler(void *cls, struct MHD_Connection *connection,
		const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size, void **ptr) {
	if(!g_atomic_int_get(&initialized) || g_atomic_int_get(&stopping))
		return MHD_NO;
	char *payload = NULL;
	json_t *root = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;
	char *session_path = NULL, *handle_path = NULL;
	char **basepath = NULL, **path = NULL;
	guint64 session_id = 0, handle_id = 0;

	/* Is this the first round? */
	int firstround = 0;
	janus_transport_session *ts = (janus_transport_session *)*ptr;
	janus_http_msg *msg = NULL;
	if(ts == NULL) {
		firstround = 1;
		JANUS_LOG(LOG_DBG, "Got a HTTP %s request on %s...\n", method, url);
		JANUS_LOG(LOG_DBG, " ... Just parsing headers for now...\n");
		msg = g_malloc0(sizeof(janus_http_msg));
		msg->connection = connection;
		janus_refcount_init(&msg->ref, janus_http_msg_free);
		ts = janus_transport_session_create(msg, janus_http_msg_destroy);
		janus_mutex_lock(&messages_mutex);
		g_hash_table_insert(messages, ts, ts);
		janus_mutex_unlock(&messages_mutex);
		*ptr = ts;
		MHD_get_connection_values(connection, MHD_HEADER_KIND, &janus_http_headers, msg);
		ret = MHD_YES;
		/* Notify handlers about this new transport instance */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("request"));
			json_object_set_new(info, "admin_api", json_false());
			const union MHD_ConnectionInfo *conninfo = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
			if(conninfo != NULL) {
				janus_network_address addr;
				janus_network_address_string_buffer addr_buf;
				if(janus_network_address_from_sockaddr((struct sockaddr *)conninfo->client_addr, &addr) == 0 &&
						janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
					const char *ip = janus_network_address_string_from_buffer(&addr_buf);
					json_object_set_new(info, "ip", json_string(ip));
				}
				uint16_t port = janus_http_sockaddr_to_port((struct sockaddr *)conninfo->client_addr);
				json_object_set_new(info, "port", json_integer(port));
			}
			gateway->notify_event(&janus_http_transport, ts, info);
		}
	} else {
		JANUS_LOG(LOG_DBG, "Processing HTTP %s request on %s...\n", method, url);
		janus_refcount_increase(&ts->ref);
		msg = (janus_http_msg *)ts->transport_p;
	}
	/* Parse request */
	if(strcasecmp(method, "GET") && strcasecmp(method, "POST") && strcasecmp(method, "OPTIONS")) {
		if(firstround)
			return ret;
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_TRANSPORT_SPECIFIC, "Unsupported method %s", method);
		goto done;
	}
	if(!strcasecmp(method, "OPTIONS")) {
		response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
	}
	/* Get path components */
	if(strcasecmp(url, ws_path)) {
		if(strlen(ws_path) > 1) {
			basepath = g_strsplit(url, ws_path, -1);
		} else {
			/* The base path is the web server too itself, we process the url itself */
			basepath = g_malloc_n(3, sizeof(char *));
			basepath[0] = g_strdup("/");
			basepath[1] = g_strdup(url);
			basepath[2] = NULL;
		}
		if(basepath[0] == NULL || basepath[1] == NULL || basepath[1][0] != '/') {
			JANUS_LOG(LOG_ERR, "Invalid url %s\n", url);
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
		if(firstround) {
			g_strfreev(basepath);
			return ret;
		}
		path = g_strsplit(basepath[1], "/", -1);
		if(path == NULL || path[1] == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid path %s (%s)\n", basepath[1], path ? path[1] : "");
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			g_strfreev(basepath);
			g_strfreev(path);
			return ret;
		}
	}
	if(firstround) {
		g_strfreev(basepath);
		g_strfreev(path);
		return ret;
	}
	JANUS_LOG(LOG_DBG, " ... parsing request...\n");
	if(path != NULL && path[1] != NULL && strlen(path[1]) > 0) {
		session_path = g_strdup(path[1]);
		JANUS_LOG(LOG_HUGE, "Session: %s\n", session_path);
	}
	if(session_path != NULL && path[2] != NULL && strlen(path[2]) > 0) {
		handle_path = g_strdup(path[2]);
		JANUS_LOG(LOG_HUGE, "Handle: %s\n", handle_path);
	}
	if(session_path != NULL && handle_path != NULL && path[3] != NULL && strlen(path[3]) > 0) {
		JANUS_LOG(LOG_ERR, "Too many components...\n");
		response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		goto done;
	}
	/* Get payload, if any */
	if(!strcasecmp(method, "POST")) {
		JANUS_LOG(LOG_HUGE, "Processing POST data (%s) (%zu bytes)...\n", msg->contenttype, *upload_data_size);
		if(*upload_data_size != 0) {
			msg->payload = g_realloc(msg->payload, msg->len+*upload_data_size+1);
			memcpy(msg->payload+msg->len, upload_data, *upload_data_size);
			msg->len += *upload_data_size;
			memset(msg->payload + msg->len, '\0', 1);
			JANUS_LOG(LOG_DBG, "  -- Data we have now (%zu bytes)\n", msg->len);
			*upload_data_size = 0;	/* Go on */
			ret = MHD_YES;
			goto done;
		}
		JANUS_LOG(LOG_DBG, "Done getting payload, we can answer\n");
		if(msg->payload == NULL) {
			JANUS_LOG(LOG_ERR, "No payload :-(\n");
			ret = MHD_NO;
			goto done;
		}
		payload = msg->payload;
		JANUS_LOG(LOG_HUGE, "%s\n", payload);
	}

	/* Is this a generic request for info? */
	if(session_path != NULL && !strcmp(session_path, "info")) {
		/* The info REST endpoint, if contacted through a GET, provides information on the Janus core */
		if(strcasecmp(method, "GET")) {
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
			MHD_destroy_response(response);
			goto done;
		}
		/* Turn this into a fake "info" request */
		method = "POST";
		char tr[12];
		janus_http_random_string(12, (char *)&tr);
		root = json_object();
		json_object_set_new(root, "janus", json_string("info"));
		json_object_set_new(root, "transaction", json_string(tr));
		goto parsingdone;
	}

	/* Or maybe a long poll */
	if(!strcasecmp(method, "GET") || !payload) {
		session_id = session_path ? g_ascii_strtoull(session_path, NULL, 10) : 0;
		if(session_id < 1) {
			JANUS_LOG(LOG_ERR, "Invalid session %s\n", session_path);
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			goto done;
		}
		msg->session_id = session_id;

		/* Since we handle long polls ourselves, the core isn't involved (if not for providing us with events)
		 * A long poll, though, can act as a keepalive, so we pass a fake one to the core to avoid undesirable timeouts */

		/* First of all, though, API secret and token based authentication may be enabled in the core, so since
		 * we're bypassing it for notifications we'll have to check those ourselves */
		const char *secret = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "apisecret");
		const char *token = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "token");
		gboolean secret_authorized = FALSE, token_authorized = FALSE;
		if(!gateway->is_api_secret_needed(&janus_http_transport) && !gateway->is_auth_token_needed(&janus_http_transport)) {
			/* Nothing to check */
			secret_authorized = TRUE;
			token_authorized = TRUE;
		} else {
			if(gateway->is_api_secret_valid(&janus_http_transport, secret)) {
				/* API secret is valid */
				secret_authorized = TRUE;
			}
			if(gateway->is_auth_token_valid(&janus_http_transport, token)) {
				/* Token is valid */
				token_authorized = TRUE;
			}
			/* We consider a request authorized if either the proper API secret or a valid token has been provided */
			if(!secret_authorized && !token_authorized) {
				response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
				janus_http_add_cors_headers(msg, response);
				ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
				MHD_destroy_response(response);
				goto done;
			}
		}
		/* Ok, go on with the keepalive */
		char tr[12];
		janus_http_random_string(12, (char *)&tr);
		root = json_object();
		json_object_set_new(root, "janus", json_string("keepalive"));
		json_object_set_new(root, "session_id", json_integer(session_id));
		json_object_set_new(root, "transaction", json_string(tr));
		if(secret)
			json_object_set_new(root, "apisecret", json_string(secret));
		if(token)
			json_object_set_new(root, "token", json_string(token));
		gateway->incoming_request(&janus_http_transport, ts, (void *)keepalive_id, FALSE, root, NULL);
		/* Ok, go on */
		if(handle_path) {
			char *location = g_malloc(strlen(ws_path) + strlen(session_path) + 2);
			g_sprintf(location, "%s/%s", ws_path, session_path);
			JANUS_LOG(LOG_ERR, "Invalid GET to %s, redirecting to %s\n", url, location);
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response, "Location", location);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, 302, response);
			MHD_destroy_response(response);
			g_free(location);
			goto done;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_http_session *session = g_hash_table_lookup(sessions, &session_id);
		if(!session || g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			goto done;
		}
		janus_refcount_increase(&session->ref);
		janus_mutex_unlock(&sessions_mutex);
		/* How many messages can we send back in a single response? (just one by default) */
		int max_events = 1;
		const char *maxev = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "maxev");
		if(maxev != NULL) {
			max_events = atoi(maxev);
			if(max_events < 1) {
				JANUS_LOG(LOG_WARN, "Invalid maxev parameter passed (%d), defaulting to 1\n", max_events);
				max_events = 1;
			}
		}
		JANUS_LOG(LOG_VERB, "Session %"SCNu64" found... returning up to %d messages\n", session_id, max_events);
		/* Handle GET, taking the first message from the list */
		janus_mutex_lock(&session->mutex);
		json_t *event = g_async_queue_try_pop(session->events);
		if(event != NULL) {
			if(max_events == 1) {
				/* Return just this message and leave */
				char *event_text = json_dumps(event, json_format);
				json_decref(event);
				ret = janus_http_return_success(ts, event_text);
			} else {
				/* The application is willing to receive more events at the same time, anything to report? */
				json_t *list = json_array();
				json_array_append_new(list, event);
				int events = 1;
				while(events < max_events) {
					event = g_async_queue_try_pop(session->events);
					if(event == NULL)
						break;
					json_array_append_new(list, event);
					events++;
				}
				/* Return the array of messages and leave */
				char *list_text = json_dumps(list, json_format);
				json_decref(list);
				ret = janus_http_return_success(ts, list_text);
			}
		} else {
			/* Still no message, wait */
			response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
				500, &janus_http_response_callback, msg, NULL);
			if(response == NULL) {
				ret = MHD_NO;
			} else {
				g_atomic_int_set(&msg->suspended, 1);
				MHD_suspend_connection(msg->connection);
				MHD_add_response_header(response, "Content-Type", "application/json");
				janus_http_add_cors_headers(msg, response);
				ret = MHD_queue_response(msg->connection, MHD_HTTP_OK, response);
				MHD_destroy_response(response);
				/* We won't wait forever for an answer (about 30 seconds) */
				janus_refcount_increase(&ts->ref);
				janus_refcount_increase(&session->ref);
				g_atomic_int_set(&msg->timeout_flag, 1);
				msg->timeout = janus_http_request_timeout_create(ts, session, 30);
				g_source_attach(msg->timeout, httpctx);
				/* Mark this connection as the long poll for this session */
				msg->max_events = max_events;
				session->longpolls = g_list_append(session->longpolls, ts);
				g_atomic_pointer_set(&msg->longpoll, session);
			}
		}
		janus_mutex_unlock(&session->mutex);
		janus_refcount_decrease(&session->ref);
		goto done;
	}

	json_error_t error;
	/* Parse the JSON payload */
	root = json_loads(payload, 0, &error);
	if(!root) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s",
			error.line, error.text);
		goto done;
	}
	if(!json_is_object(root)) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		json_decref(root);
		goto done;
	}

parsingdone:
	/* Check if we have session and handle identifiers, and how they were provided */
	session_id = json_integer_value(json_object_get(root, "session_id"));
	if(session_id && session_path && g_ascii_strtoull(session_path, NULL, 10) != session_id) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_REQUEST_PATH, "Conflicting session ID (payload and path)");
		json_decref(root);
		goto done;
	}
	if(!session_id) {
		/* No session ID in the JSON object, maybe in the path? */
		session_id = session_path ? g_ascii_strtoull(session_path, NULL, 10) : 0;
		if(session_id > 0)
			json_object_set_new(root, "session_id", json_integer(session_id));
	}
	handle_id = json_integer_value(json_object_get(root, "handle_id"));
	if(handle_id && handle_path && g_ascii_strtoull(handle_path, NULL, 10) != handle_id) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_REQUEST_PATH, "Conflicting handle ID (payload and path)");
		json_decref(root);
		goto done;
	}
	if(!handle_id) {
		/* No session ID in the JSON object, maybe in the path? */
		handle_id = handle_path ? g_ascii_strtoull(handle_path, NULL, 10) : 0;
		if(handle_id > 0)
			json_object_set_new(root, "handle_id", json_integer(handle_id));
	}

	response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		500, &janus_http_response_callback, msg, NULL);
	if(response == NULL) {
		ret = MHD_NO;
	} else {
		g_atomic_int_set(&msg->suspended, 1);
		/* Suspend the connection */
		MHD_suspend_connection(msg->connection);
		MHD_add_response_header(response, "Content-Type", "application/json");
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(msg->connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		/* We won't wait forever for an answer (about 10 seconds) */
		janus_refcount_increase(&ts->ref);
		g_atomic_int_set(&msg->timeout_flag, 1);
		msg->timeout = janus_http_request_timeout_create(ts, NULL, 10);
		g_source_attach(msg->timeout, httpctx);
		/* Pass the ball to the core */
		JANUS_LOG(LOG_HUGE, "Forwarding request to the core (%p)\n", msg);
		gateway->incoming_request(&janus_http_transport, ts, ts, FALSE, root, &error);
	}

done:
	janus_refcount_decrease(&ts->ref);
	g_strfreev(basepath);
	g_strfreev(path);
	g_free(session_path);
	g_free(handle_path);
	return ret;
}

/* Admin/monitor WebServer requests handler */
static int janus_http_admin_handler(void *cls, struct MHD_Connection *connection,
		const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size, void **ptr) {
	if(!g_atomic_int_get(&initialized) || g_atomic_int_get(&stopping))
		return MHD_NO;
	char *payload = NULL;
	json_t *root = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;
	char *session_path = NULL, *handle_path = NULL;
	char **basepath = NULL, **path = NULL;
	guint64 session_id = 0, handle_id = 0;

	/* Is this the first round? */
	int firstround = 0;
	janus_transport_session *ts = (janus_transport_session *)*ptr;
	janus_http_msg *msg = NULL;
	if(ts == NULL) {
		firstround = 1;
		JANUS_LOG(LOG_VERB, "Got an admin/monitor HTTP %s request on %s...\n", method, url);
		JANUS_LOG(LOG_DBG, " ... Just parsing headers for now...\n");
		msg = g_malloc0(sizeof(janus_http_msg));
		msg->connection = connection;
		janus_refcount_init(&msg->ref, janus_http_msg_free);
		ts = janus_transport_session_create(msg, janus_http_msg_destroy);
		janus_mutex_lock(&messages_mutex);
		g_hash_table_insert(messages, ts, ts);
		janus_mutex_unlock(&messages_mutex);
		*ptr = ts;
		MHD_get_connection_values(connection, MHD_HEADER_KIND, &janus_http_headers, msg);
		ret = MHD_YES;
		/* Notify handlers about this new transport instance */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("request"));
			json_object_set_new(info, "admin_api", json_true());
			const union MHD_ConnectionInfo *conninfo = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
			if(conninfo != NULL) {
				janus_network_address addr;
				janus_network_address_string_buffer addr_buf;
				if(janus_network_address_from_sockaddr((struct sockaddr *)conninfo->client_addr, &addr) == 0 &&
						janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
					const char *ip = janus_network_address_string_from_buffer(&addr_buf);
					json_object_set_new(info, "ip", json_string(ip));
				}
				uint16_t port = janus_http_sockaddr_to_port((struct sockaddr *)conninfo->client_addr);
				json_object_set_new(info, "port", json_integer(port));
			}
			gateway->notify_event(&janus_http_transport, ts, info);
		}
	} else {
		JANUS_LOG(LOG_DBG, "Processing HTTP %s request on %s...\n", method, url);
		janus_refcount_increase(&ts->ref);
		msg = (janus_http_msg *)ts->transport_p;
	}
	/* Parse request */
	if(strcasecmp(method, "GET") && strcasecmp(method, "POST") && strcasecmp(method, "OPTIONS")) {
		if(firstround)
			return ret;
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_TRANSPORT_SPECIFIC, "Unsupported method %s", method);
		goto done;
	}
	if(!strcasecmp(method, "OPTIONS")) {
		response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
	}
	/* Get path components */
	if(strcasecmp(url, admin_ws_path)) {
		if(strlen(admin_ws_path) > 1) {
			basepath = g_strsplit(url, admin_ws_path, -1);
		} else {
			/* The base path is the web server too itself, we process the url itself */
			basepath = g_malloc_n(3, sizeof(char *));
			basepath[0] = g_strdup("/");
			basepath[1] = g_strdup(url);
			basepath[2] = NULL;
		}
		if(basepath[0] == NULL || basepath[1] == NULL || basepath[1][0] != '/') {
			JANUS_LOG(LOG_ERR, "Invalid url %s\n", url);
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
		if(firstround) {
			g_strfreev(basepath);
			return ret;
		}
		path = g_strsplit(basepath[1], "/", -1);
		if(path == NULL || path[1] == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid path %s (%s)\n", basepath[1], path ? path[1] : "");
			response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
			janus_http_add_cors_headers(msg, response);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			g_strfreev(basepath);
			g_strfreev(path);
			return ret;
		}
	}
	if(firstround) {
		g_strfreev(basepath);
		g_strfreev(path);
		return ret;
	}
	JANUS_LOG(LOG_DBG, " ... parsing request...\n");
	if(path != NULL && path[1] != NULL && strlen(path[1]) > 0) {
		session_path = g_strdup(path[1]);
		JANUS_LOG(LOG_HUGE, "Session: %s\n", session_path);
	}
	if(session_path != NULL && path[2] != NULL && strlen(path[2]) > 0) {
		handle_path = g_strdup(path[2]);
		JANUS_LOG(LOG_HUGE, "Handle: %s\n", handle_path);
	}
	if(session_path != NULL && handle_path != NULL && path[3] != NULL && strlen(path[3]) > 0) {
		JANUS_LOG(LOG_ERR, "Too many components...\n");
		response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		goto done;
	}
	/* Get payload, if any */
	if(!strcasecmp(method, "POST")) {
		JANUS_LOG(LOG_HUGE, "Processing POST data (%s) (%zu bytes)...\n", msg->contenttype, *upload_data_size);
		if(*upload_data_size != 0) {
			msg->payload = g_realloc(msg->payload, msg->len+*upload_data_size+1);
			memcpy(msg->payload+msg->len, upload_data, *upload_data_size);
			msg->len += *upload_data_size;
			memset(msg->payload + msg->len, '\0', 1);
			JANUS_LOG(LOG_DBG, "  -- Data we have now (%zu bytes)\n", msg->len);
			*upload_data_size = 0;	/* Go on */
			ret = MHD_YES;
			goto done;
		}
		JANUS_LOG(LOG_DBG, "Done getting payload, we can answer\n");
		if(msg->payload == NULL) {
			JANUS_LOG(LOG_ERR, "No payload :-(\n");
			ret = MHD_NO;
			goto done;
		}
		payload = msg->payload;
		JANUS_LOG(LOG_HUGE, "%s\n", payload);
	}

	/* Is this a generic request for info? */
	if(session_path != NULL && !strcmp(session_path, "info")) {
		/* The info REST endpoint, if contacted through a GET, provides information on the Janus core */
		if(strcasecmp(method, "GET")) {
			ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_TRANSPORT_SPECIFIC, "Use GET for the info endpoint");
			goto done;
		}
		/* Turn this into a fake "info" request */
		method = "POST";
		char tr[12];
		janus_http_random_string(12, (char *)&tr);
		root = json_object();
		json_object_set_new(root, "janus", json_string("info"));
		json_object_set_new(root, "transaction", json_string(tr));
		goto parsingdone;
	}

	/* Without a payload we don't know what to do */
	if(!payload) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_JSON, "Request payload missing");
		goto done;
	}
	json_error_t error;
	/* Parse the JSON payload */
	root = json_loads(payload, 0, &error);
	if(!root) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s",
			error.line, error.text);
		goto done;
	}
	if(!json_is_object(root)) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		json_decref(root);
		goto done;
	}

parsingdone:
	/* Check if we have session and handle identifiers, and how they were provided */
	session_id = json_integer_value(json_object_get(root, "session_id"));
	if(session_id && session_path && g_ascii_strtoull(session_path, NULL, 10) != session_id) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_REQUEST_PATH, "Conflicting session ID (payload and path)");
		json_decref(root);
		goto done;
	}
	if(!session_id) {
		/* No session ID in the JSON object, maybe in the path? */
		session_id = session_path ? g_ascii_strtoull(session_path, NULL, 10) : 0;
		if(session_id > 0)
			json_object_set_new(root, "session_id", json_integer(session_id));
	}
	handle_id = json_integer_value(json_object_get(root, "handle_id"));
	if(handle_id && handle_path && g_ascii_strtoull(handle_path, NULL, 10) != handle_id) {
		ret = janus_http_return_error(ts, 0, NULL, JANUS_ERROR_INVALID_REQUEST_PATH, "Conflicting handle ID (payload and path)");
		json_decref(root);
		goto done;
	}
	if(!handle_id) {
		/* No session ID in the JSON object, maybe in the path? */
		handle_id = handle_path ? g_ascii_strtoull(handle_path, NULL, 10) : 0;
		if(handle_id > 0)
			json_object_set_new(root, "handle_id", json_integer(handle_id));
	}

	response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN,
		500, &janus_http_response_callback, msg, NULL);
	if(response == NULL) {
		ret = MHD_NO;
	} else {
		g_atomic_int_set(&msg->suspended, 1);
		/* Suspend the connection */
		MHD_suspend_connection(msg->connection);
		MHD_add_response_header(response, "Content-Type", "application/json");
		janus_http_add_cors_headers(msg, response);
		ret = MHD_queue_response(msg->connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		/* We won't wait forever for an answer (about 10 seconds) */
		janus_refcount_increase(&ts->ref);
		g_atomic_int_set(&msg->timeout_flag, 1);
		msg->timeout = janus_http_request_timeout_create(ts, NULL, 10);
		g_source_attach(msg->timeout, httpctx);
		/* Pass the ball to the core */
		JANUS_LOG(LOG_HUGE, "Forwarding admin request to the core (%p)\n", msg);
		gateway->incoming_request(&janus_http_transport, ts, ts, TRUE, root, &error);
	}

done:
	janus_refcount_decrease(&ts->ref);
	g_strfreev(basepath);
	g_strfreev(path);
	g_free(session_path);
	g_free(handle_path);
	return ret;
}

static int janus_http_headers(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
	janus_http_msg *request = (janus_http_msg *)cls;
	JANUS_LOG(LOG_DBG, "%s: %s\n", key, value);
	if(!request)
		return MHD_YES;
	janus_refcount_increase(&request->ref);
	if(!strcasecmp(key, MHD_HTTP_HEADER_CONTENT_TYPE)) {
		request->contenttype = g_strdup(value);
	} else if(!strcasecmp(key, "Access-Control-Request-Method")) {
		request->acrm = g_strdup(value);
	} else if(!strcasecmp(key, "Access-Control-Request-Headers")) {
		request->acrh = g_strdup(value);
	}
	janus_refcount_decrease(&request->ref);
	return MHD_YES;
}

static void janus_http_request_completed(void *cls, struct MHD_Connection *connection,
		void **con_cls, enum MHD_RequestTerminationCode toe) {
	JANUS_LOG(LOG_DBG, "Request completed, freeing data\n");
	janus_transport_session *ts = (janus_transport_session *)*con_cls;
	if(!ts)
		return;
	janus_http_msg *request = (janus_http_msg *)ts->transport_p;
	if(request != NULL) {
		janus_refcount_increase(&request->ref);
		janus_http_session *session = (janus_http_session *)g_atomic_pointer_get(&request->longpoll);
		if(session != NULL)
			janus_refcount_increase(&session->ref);
		if(g_atomic_int_compare_and_exchange(&request->timeout_flag, 1, 0)) {
			g_source_destroy(request->timeout);
			g_source_unref(request->timeout);
		}
		request->timeout = NULL;
		if(session) {
			janus_mutex_lock(&session->mutex);
			session->longpolls = g_list_remove(session->longpolls, ts);
			janus_mutex_unlock(&session->mutex);
			janus_refcount_decrease(&session->ref);
		}
		janus_refcount_decrease(&request->ref);
	}
	janus_mutex_lock(&messages_mutex);
	g_hash_table_remove(messages, ts);
	janus_mutex_unlock(&messages_mutex);
	*con_cls = NULL;
}

static ssize_t janus_http_response_callback(void *cls, uint64_t pos, char *buf, size_t max) {
	janus_http_msg *request = (janus_http_msg *)cls;
	if(request == NULL || request->response == NULL)
		return MHD_CONTENT_READER_END_WITH_ERROR;
	if(pos >= request->resplen)
		return MHD_CONTENT_READER_END_OF_STREAM;
	janus_refcount_increase(&request->ref);
	size_t bytes = request->resplen - pos;
	if(bytes > max)
		bytes = max;
	memcpy(buf, request->response + pos, bytes);
	janus_refcount_decrease(&request->ref);
	return bytes;
}

/* Worker to handle notifications */
static int janus_http_notifier(janus_http_msg *msg) {
	if(!msg || !msg->connection)
		return MHD_NO;
	int max_events = msg->max_events;
	if(max_events < 1)
		max_events = 1;
	JANUS_LOG(LOG_DBG, "... handling long poll...\n");
	guint64 session_id = msg->session_id;
	janus_mutex_lock(&sessions_mutex);
	janus_http_session *session = g_hash_table_lookup(sessions, &session_id);
	if(!session || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		/* TODO return error */
		MHD_resume_connection(msg->connection);
		return -1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	json_t *event = NULL, *list = NULL;
	int events = 0;
	while((event = g_async_queue_try_pop(session->events)) != NULL) {
		if(session->destroyed || g_atomic_int_get(&stopping)) {
			/* TODO return error */
			JANUS_LOG(LOG_ERR, "Session %"SCNu64" destroyed...\n", session_id);
			MHD_resume_connection(msg->connection);
			janus_refcount_decrease(&session->ref);
			return -1;
		}
		if(max_events == 1) {
			break;
		} else {
			/* The application is willing to receive more events at the same time, anything to report? */
			if(list == NULL)
				list = json_array();
			json_array_append_new(list, event);
			events++;
			if(events == max_events)
				break;
		}
	}
	if(event == NULL && list == NULL) {
		JANUS_LOG(LOG_VERB, "No events available for session %"SCNu64"...\n", session_id);
		/* Turn this into a "keepalive" response */
		char tr[12];
		janus_http_random_string(12, (char *)&tr);
		if(max_events == 1) {
			event = json_object();
			json_object_set_new(event, "janus", json_string("keepalive"));
		} else {
			list = json_array();
			event = json_object();
			json_object_set_new(event, "janus", json_string("keepalive"));
			json_array_append_new(list, event);
		}
		/* FIXME Improve the Janus protocol keep-alive mechanism in JavaScript */
	}
	char *payload_text = json_dumps(max_events == 1 ? event : list, json_format);
	json_decref(max_events == 1 ? event : list);
	/* Finish the request by sending the response */
	JANUS_LOG(LOG_HUGE, "We have a message to serve...\n\t%s\n", payload_text);
	/* Send event back */
	msg->response = payload_text;
	msg->resplen = strlen(payload_text);
	MHD_resume_connection(msg->connection);
	janus_refcount_decrease(&session->ref);
	return 0;
}

/* Helper to quickly send a success response */
static int janus_http_return_success(janus_transport_session *ts, char *payload) {
	if(!ts) {
		g_free(payload);
		return MHD_NO;
	}
	janus_http_msg *msg = (janus_http_msg *)ts->transport_p;
	if(!msg || !msg->connection) {
		g_free(payload);
		return MHD_NO;
	}
	janus_refcount_increase(&msg->ref);
	struct MHD_Response *response = MHD_create_response_from_buffer(
		payload ? strlen(payload) : 0,
		(void*)payload,
		MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "application/json");
	janus_http_add_cors_headers(msg, response);
	int ret = MHD_queue_response(msg->connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	janus_refcount_decrease(&msg->ref);
	return ret;
}

/* Helper to quickly send an error response */
static int janus_http_return_error(janus_transport_session *ts, uint64_t session_id,
		const char *transaction, gint error, const char *format, ...) {
	gchar *error_string = NULL;
	gchar error_buf[512];
	if(format == NULL) {
		/* No error string provided, use the default one */
		error_string = (char *)janus_get_api_error(error);
	} else {
		/* This callback has variable arguments (error string) */
		va_list ap;
		va_start(ap, format);
		g_vsnprintf(error_buf, 512, format, ap);
		va_end(ap);
		error_string = error_buf;
	}
	/* Done preparing error */
	JANUS_LOG(LOG_VERB, "[%s] Returning error %d (%s)\n", transaction, error, error_string ? error_string : "no text");
	/* Prepare JSON error */
	json_t *reply = json_object();
	json_object_set_new(reply, "janus", json_string("error"));
	if(session_id > 0)
		json_object_set_new(reply, "session_id", json_integer(session_id));
	if(transaction != NULL)
		json_object_set_new(reply, "transaction", json_string(transaction));
	json_t *error_data = json_object();
	json_object_set_new(error_data, "code", json_integer(error));
	json_object_set_new(error_data, "reason", json_string(error_string));
	json_object_set_new(reply, "error", error_data);
	char *reply_text = json_dumps(reply, json_format);
	json_decref(reply);
	/* Use janus_http_return_error to send the error response */
	return janus_http_return_success(ts, reply_text);
}

/* Helper to handle timeouts */
void janus_http_timeout(janus_transport_session *ts, janus_http_session *session) {
	if(g_atomic_int_get(&ts->destroyed))
		return;
	janus_refcount_increase(&ts->ref);
	janus_http_msg *request = (janus_http_msg *)ts->transport_p;
	if(!g_atomic_int_compare_and_exchange(&request->timeout_flag, 1, 0)) {
		request->timeout = NULL;
		janus_refcount_decrease(&ts->ref);
		return;
	}
	request->timeout = NULL;
	/* Is this a long poll timeout, simply meaning we had nothing to send so far? */
	if(session != NULL) {
		janus_refcount_increase(&session->ref);
		g_atomic_pointer_set(&request->longpoll, NULL);
		/* Long poll, turn this into a "keepalive" response */
		json_t *event = NULL;
		if(request->max_events == 1) {
			event = json_object();
			json_object_set_new(event, "janus", json_string("keepalive"));
		} else {
			json_t *list = json_array();
			event = json_object();
			json_object_set_new(event, "janus", json_string("keepalive"));
			json_array_append_new(list, event);
			event = list;
		}
		char *payload_text = json_dumps(event, json_format);
		json_decref(event);
		/* Finish the request by sending the response */
		JANUS_LOG(LOG_HUGE, "We have a message to serve...\n\t%s\n", payload_text);
		/* Send event back */
		request->response = payload_text;
		request->resplen = strlen(payload_text);
		MHD_resume_connection(request->connection);
		janus_mutex_lock(&session->mutex);
		session->longpolls = g_list_remove(session->longpolls, ts);
		janus_mutex_unlock(&session->mutex);
		janus_refcount_decrease(&session->ref);
	} else {
		/* Not a long poll, a request is taking way too much time */
		g_free(request->response);
		request->response = NULL;
		request->resplen = 0;
		MHD_resume_connection(request->connection);
	}
	janus_refcount_decrease(&ts->ref);
}
