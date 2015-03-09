/*! \file   janus.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus core
 * \details Implementation of the gateway core. This code takes care of
 * the gateway initialization (command line/configuration) and setup,
 * and implements the web server (based on libmicrohttpd) and Janus protocol
 * (a JSON protocol implemented with Jansson) to interact with the web
 * applications. The core also takes care of bridging peers and plugins
 * accordingly. 
 * 
 * \ingroup core
 * \ref core
 */
 
#include <dlfcn.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <getopt.h>
#include <sys/resource.h>

#include "janus.h"
#include "cmdline.h"
#include "config.h"
#include "apierror.h"
#include "debug.h"
#include "rtcp.h"
#include "sdp.h"
#include "utils.h"


#define JANUS_NAME				"Janus WebRTC Gateway"
#define JANUS_AUTHOR			"Meetecho s.r.l."
#define JANUS_VERSION			8
#define JANUS_VERSION_STRING	"0.0.8"

#ifdef __MACH__
#define SHLIB_EXT "0.dylib"
#else
#define SHLIB_EXT ".so"
#endif


static janus_config *config = NULL;
static char *config_file = NULL;
static char *configs_folder = NULL;

static GHashTable *plugins = NULL;
static GHashTable *plugins_so = NULL;

/* MHD Web Server */
static struct MHD_Daemon *ws = NULL, *sws = NULL;
static char *ws_path = NULL;
static char *ws_api_secret = NULL;

#ifdef HAVE_WEBSOCKETS
/* libwebsock WS server */
static libwebsock_context *wss = NULL, *swss = NULL;
#endif

#ifdef HAVE_RABBITMQ
/* RabbitMQ support */
amqp_connection_state_t rmq_conn = NULL;
amqp_channel_t rmq_channel = 0;
amqp_bytes_t to_janus_queue, from_janus_queue;
#endif


/* Admin/Monitor MHD Web Server */
static struct MHD_Daemon *admin_ws = NULL, *admin_sws = NULL;
static char *admin_ws_path = NULL;
static char *admin_ws_api_secret = NULL;

/* Admin/Monitor ACL list */
GList *janus_admin_access_list = NULL;
janus_mutex access_list_mutex;
void janus_admin_allow_address(const char *ip);
void janus_admin_allow_address(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&access_list_mutex);
	janus_admin_access_list = g_list_append(janus_admin_access_list, (gpointer)ip);
	janus_mutex_unlock(&access_list_mutex);
}
gboolean janus_admin_is_allowed(const char *ip);
gboolean janus_admin_is_allowed(const char *ip) {
	if(ip == NULL)
		return FALSE;
	if(janus_admin_access_list == NULL)
		return TRUE;
	janus_mutex_lock(&access_list_mutex);
	GList *temp = janus_admin_access_list;
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

/* Admin/Monitor helpers */
json_t *janus_admin_stream_summary(janus_ice_stream *stream);
json_t *janus_admin_component_summary(janus_ice_component *component);


/* Certificates */
static char *server_pem = NULL;
gchar *janus_get_server_pem(void) {
	return server_pem;
}
static char *server_key = NULL;
gchar *janus_get_server_key(void) {
	return server_key;
}


/* Information */
char *janus_info(const char *transaction);
char *janus_info(const char *transaction) {
	/* Prepare a summary on the gateway */
	json_t *info = json_object();
	json_object_set_new(info, "janus", json_string("server_info"));
	if(transaction != NULL)
		json_object_set_new(info, "transaction", json_string(transaction));
	json_object_set_new(info, "name", json_string(JANUS_NAME));
	json_object_set_new(info, "version", json_integer(JANUS_VERSION));
	json_object_set_new(info, "version_string", json_string(JANUS_VERSION_STRING));
	json_object_set_new(info, "author", json_string(JANUS_AUTHOR));
#ifdef HAVE_SCTP
	json_object_set_new(info, "data_channels", json_string("true"));
#else
	json_object_set_new(info, "data_channels", json_string("false"));
#endif
#ifdef HAVE_WEBSOCKETS
	json_object_set_new(info, "websockets", json_string("true"));
#else
	json_object_set_new(info, "websockets", json_string("false"));
#endif
#ifdef HAVE_RABBITMQ
	json_object_set_new(info, "rabbitmq", json_string("true"));
#else
	json_object_set_new(info, "rabbitmq", json_string("false"));
#endif
	json_object_set_new(info, "ipv6", json_string(janus_ice_is_ipv6_enabled() ? "true" : "false"));
	json_object_set_new(info, "ice-tcp", json_string(janus_ice_is_ice_tcp_enabled() ? "true" : "false"));
	if(janus_ice_get_stun_server() != NULL) {
		char server[255];
		g_snprintf(server, 255, "%s:%"SCNu16, janus_ice_get_stun_server(), janus_ice_get_stun_port());
		json_object_set_new(info, "stun-server", json_string(server));
	}
	if(janus_ice_get_turn_server() != NULL) {
		char server[255];
		g_snprintf(server, 255, "%s:%"SCNu16, janus_ice_get_turn_server(), janus_ice_get_turn_port());
		json_object_set_new(info, "turn-server", json_string(server));
	}
	json_t *data = json_object();
	if(plugins && g_hash_table_size(plugins) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, plugins);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_plugin *p = value;
			if(p == NULL) {
				continue;
			}
			json_t *plugin = json_object();
			json_object_set_new(plugin, "name", json_string(p->get_name()));
			json_object_set_new(plugin, "author", json_string(p->get_author()));
			json_object_set_new(plugin, "description", json_string(p->get_description()));
			json_object_set_new(plugin, "version_string", json_string(p->get_version_string()));
			json_object_set_new(plugin, "version", json_integer(p->get_version()));
			json_object_set_new(data, p->get_package(), plugin);
		}
	}
	json_object_set_new(info, "plugins", data);
	/* Convert to a string */
	char *info_text = json_dumps(info, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(info);
	
	return info_text;
}

static gchar *local_ip = NULL;
gchar *janus_get_local_ip(void) {
	return local_ip;
}
static gchar *public_ip = NULL;
gchar *janus_get_public_ip(void) {
	/* Fallback to the local IP, if we have no public one */
	return public_ip ? public_ip : local_ip;
}
void janus_set_public_ip(const char *ip) {
	if(ip == NULL)
		return;
	if(public_ip != NULL)
		g_free(public_ip);
	public_ip = g_strdup(ip);
}
static volatile gint stop = 0;
gint janus_is_stopping(void) {
	return g_atomic_int_get(&stop);
}


/* Logging */
int log_level = 0;
int lock_debug = 0;


/*! \brief Signal handler (just used to intercept CTRL+C) */
void janus_handle_signal(int signum);
void janus_handle_signal(int signum)
{
	switch(g_atomic_int_get(&stop)) {
		case 0:
			JANUS_PRINT("Stopping gateway, please wait...\n");
			break;
		case 1:
			JANUS_PRINT("In a hurry? I'm trying to free resources cleanly, here!\n");
			break;
		default:
			JANUS_PRINT("Ok, leaving immediately...\n");
			break;
	}
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
}


/** @name Plugin callback interface
 * These are the callbacks implemented by the gateway core, as part of
 * the janus_callbacks interface. Everything the plugins send the
 * gateway is handled here.
 */
///@{
int janus_push_event(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *transaction, const char *message, const char *sdp_type, const char *sdp);
json_t *janus_handle_sdp(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *sdp_type, const char *sdp);
void janus_relay_rtp(janus_plugin_session *plugin_session, int video, char *buf, int len);
void janus_relay_rtcp(janus_plugin_session *plugin_session, int video, char *buf, int len);
void janus_relay_data(janus_plugin_session *plugin_session, char *buf, int len);
void janus_close_pc(janus_plugin_session *plugin_session);
void janus_end_session(janus_plugin_session *plugin_session);
static janus_callbacks janus_handler_plugin =
	{
		.push_event = janus_push_event,
		.relay_rtp = janus_relay_rtp,
		.relay_rtcp = janus_relay_rtcp,
		.relay_data = janus_relay_data,
		.close_pc = janus_close_pc,
		.end_session = janus_end_session,
	}; 
///@}


#ifdef HAVE_WEBSOCKETS
/* WebSocket sessions */
static janus_mutex wss_mutex;
static GHashTable *wss_sessions = NULL;
#endif

#ifdef HAVE_RABBITMQ
/* FIXME RabbitMQ session (always 1 at the moment) */
janus_rabbitmq_client *rmq_client = NULL;
#endif

/* Gateway Sessions */
static janus_mutex sessions_mutex;
static GHashTable *sessions = NULL, *old_sessions = NULL;
static GMainContext *sessions_watchdog_context = NULL;


#define SESSION_TIMEOUT		60		/* FIXME Should this be higher, e.g., 120 seconds? */

static gboolean janus_cleanup_session(gpointer user_data) {
	janus_session *session = (janus_session *) user_data;

	JANUS_LOG(LOG_INFO, "Cleaning up session %"SCNu64"...\n", session->session_id);
	janus_session_destroy(session->session_id);

	return G_SOURCE_REMOVE;
}

static gboolean janus_check_sessions(gpointer user_data) {
	GMainContext *watchdog_context = (GMainContext *) user_data;
	janus_mutex_lock(&sessions_mutex);
	if(sessions && g_hash_table_size(sessions) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_session *session = (janus_session *) value;
			if (!session || session->destroy) {
				continue;
			}
			gint64 now = janus_get_monotonic_time();
			if (now - session->last_activity >= SESSION_TIMEOUT * G_USEC_PER_SEC && !session->timeout) {
				JANUS_LOG(LOG_INFO, "Timeout expired for session %"SCNu64"...\n", session->session_id);

				json_t *event = json_object();
				json_object_set_new(event, "janus", json_string("timeout"));
				json_object_set_new(event, "session_id", json_integer(session->session_id));
				gchar *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(event);

				janus_http_event *notification = calloc(1, sizeof(janus_http_event));
				notification->code = 200;
				notification->payload = event_text;
				notification->allocated = 1;
				g_async_queue_push(session->messages, notification);
				session->timeout = 1;

				g_hash_table_iter_remove(&iter);
				g_hash_table_insert(old_sessions, GUINT_TO_POINTER(session->session_id), session);

				/* Schedule the session for deletion */
				GSource *timeout_source = g_timeout_source_new_seconds(3);
				g_source_set_callback(timeout_source, janus_cleanup_session, session, NULL);
				g_source_attach(timeout_source, watchdog_context);
				g_source_unref(timeout_source);
			}
		}
	}
	janus_mutex_unlock(&sessions_mutex);

	return G_SOURCE_CONTINUE;
}

static gpointer janus_sessions_watchdog(gpointer user_data) {
	GMainLoop *loop = (GMainLoop *) user_data;
	GMainContext *watchdog_context = g_main_loop_get_context(loop);
	GSource *timeout_source;

	timeout_source = g_timeout_source_new_seconds(2);
	g_source_set_callback(timeout_source, janus_check_sessions, watchdog_context, NULL);
	g_source_attach(timeout_source, watchdog_context);
	g_source_unref(timeout_source);

	JANUS_LOG(LOG_INFO, "Sessions watchdog started\n");

	g_main_loop_run(loop);

	return NULL;
}

janus_session *janus_session_create(guint64 session_id) {
	if(session_id == 0) {
		while(session_id == 0) {
			session_id = g_random_int();
			if(janus_session_find(session_id) != NULL) {
				/* Session ID already taken, try another one */
				session_id = 0;
			}
		}
	}
	JANUS_LOG(LOG_INFO, "Creating new session: %"SCNu64"\n", session_id);
	janus_session *session = (janus_session *)calloc(1, sizeof(janus_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	session->session_id = session_id;
	session->messages = g_async_queue_new_full((GDestroyNotify) janus_http_event_free);
	session->destroy = 0;
	session->last_activity = janus_get_monotonic_time();
	janus_mutex_init(&session->mutex);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, GUINT_TO_POINTER(session_id), session);
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

janus_session *janus_session_find(guint64 session_id) {
	janus_mutex_lock(&sessions_mutex);
	janus_session *session = g_hash_table_lookup(sessions, GUINT_TO_POINTER(session_id));
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

janus_session *janus_session_find_destroyed(guint64 session_id) {
	janus_mutex_lock(&sessions_mutex);
	janus_session *session = g_hash_table_lookup(old_sessions, GUINT_TO_POINTER(session_id));
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

/* Destroys a session but does not remove it from the sessions hash table. */
gint janus_session_destroy(guint64 session_id) {
	janus_session *session = janus_session_find_destroyed(session_id);
	if(session == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't find session to destroy: %"SCNu64"\n", session_id);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "Destroying session %"SCNu64"\n", session_id);
	session->destroy = 1;
	if (session->ice_handles != NULL && g_hash_table_size(session->ice_handles) > 0) {
		GHashTableIter iter;
		gpointer value;
		/* Remove all handles */
		g_hash_table_iter_init(&iter, session->ice_handles);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_ice_handle *handle = value;
			if(!handle || g_atomic_int_get(&stop)) {
				continue;
			}
			janus_ice_handle_destroy(session, handle->handle_id);
			g_hash_table_iter_remove(&iter);
		}
	}

	/* TODO Actually destroy session */
	janus_session_free(session);

	return 0;
}

void janus_session_free(janus_session *session) {
	if(session == NULL)
		return;
	janus_mutex_lock(&session->mutex);
	if(session->ice_handles != NULL) {
		g_hash_table_destroy(session->ice_handles);
		session->ice_handles = NULL;
	}
	if(session->messages != NULL) {
		g_async_queue_unref (session->messages);
		session->messages = NULL;
	}
	janus_mutex_unlock(&session->mutex);
	session = NULL;
}


/* Connection notifiers */
int janus_ws_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen) {
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	char *ip = inet_ntoa(sin->sin_addr);
	JANUS_LOG(LOG_VERB, "New connection on REST API: %s\n", ip);
	/* TODO Implement access limitation based on IP addresses */
	return MHD_YES;
}

int janus_admin_ws_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen) {
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	char *ip = inet_ntoa(sin->sin_addr);
	JANUS_LOG(LOG_VERB, "New connection on admin/monitor: %s\n", ip);
	/* Any access limitation based on this IP address? */
	if(!janus_admin_is_allowed(ip)) {
		JANUS_LOG(LOG_ERR, "IP %s is unauthorized to connect to the admin/monitor interface\n", ip);
		return MHD_NO;
	}
	return MHD_YES;
}


/* WebServer requests handler */
int janus_ws_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
	char *payload = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;
	gchar *session_path = NULL, *handle_path = NULL;
	gchar **basepath = NULL, **path = NULL;

	JANUS_LOG(LOG_VERB, "Got a HTTP %s request on %s...\n", method, url);
	/* Is this the first round? */
	int firstround = 0;
	janus_http_msg *msg = (janus_http_msg *)*ptr;
	if (msg == NULL) {
		firstround = 1;
		JANUS_LOG(LOG_VERB, " ... Just parsing headers for now...\n");
		msg = calloc(1, sizeof(janus_http_msg));
		if(msg == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		msg->acrh = NULL;
		msg->acrm = NULL;
		msg->payload = NULL;
		msg->len = 0;
		msg->session_id = 0;
		*ptr = msg;
		MHD_get_connection_values(connection, MHD_HEADER_KIND, &janus_ws_headers, msg);
		ret = MHD_YES;
	}
	/* Parse request */
	if (strcasecmp(method, "GET") && strcasecmp(method, "POST") && strcasecmp(method, "OPTIONS")) {
		JANUS_LOG(LOG_ERR, "Unsupported method...\n");
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_IMPLEMENTED, response);
		MHD_destroy_response(response);
		return ret;
	}
	if (!strcasecmp(method, "OPTIONS")) {
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO); 
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
	}
	/* Get path components */
	if(strcasecmp(url, ws_path)) {
		if(strlen(ws_path) > 1) {
			basepath = g_strsplit(url, ws_path, -1);
		} else {
			/* The base path is the web server too itself, we process the url itself */
			basepath = calloc(3, sizeof(char *));
			basepath[0] = g_strdup("/");
			basepath[1] = g_strdup(url);
		}
		if(basepath[1] == NULL || basepath[1][0] != '/') {
			JANUS_LOG(LOG_ERR, "Invalid url %s (%s)\n", url, basepath[1]);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
		if(firstround) {
			g_strfreev(basepath);
			return ret;
		}
		path = g_strsplit(basepath[1], "/", -1);
		if(path == NULL || path[1] == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid path %s (%s)\n", basepath[1], path[1]);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
	}
	if(firstround)
		return ret;
	JANUS_LOG(LOG_VERB, " ... parsing request...\n");
	if(path != NULL && path[1] != NULL && strlen(path[1]) > 0) {
		session_path = g_strdup(path[1]);
		if(session_path == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Session: %s\n", session_path);
	}
	if(session_path != NULL && path[2] != NULL && strlen(path[2]) > 0) {
		handle_path = g_strdup(path[2]);
		if(handle_path == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Handle: %s\n", handle_path);
	}
	if(session_path != NULL && handle_path != NULL && path[3] != NULL && strlen(path[3]) > 0) {
		JANUS_LOG(LOG_ERR, "Too many components...\n");
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		goto done;
	}
	/* Get payload, if any */
	if(!strcasecmp(method, "POST")) {
		JANUS_LOG(LOG_VERB, "Processing POST data (%s)...\n", msg->contenttype);
		if(*upload_data_size != 0) {
			JANUS_LOG(LOG_VERB, "  -- Uploaded data (%zu bytes)\n", *upload_data_size);
			if(msg->payload == NULL)
				msg->payload = calloc(1, *upload_data_size+1);
			else
				msg->payload = realloc(msg->payload, msg->len+*upload_data_size+1);
			if(msg->payload == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
				MHD_destroy_response(response);
				goto done;
			}
			memcpy(msg->payload+msg->len, upload_data, *upload_data_size);
			memset(msg->payload+msg->len+*upload_data_size, '\0', 1);
			msg->len += *upload_data_size;
			JANUS_LOG(LOG_VERB, "  -- Data we have now (%zu bytes)\n", msg->len);
			*upload_data_size = 0;	/* Go on */
			ret = MHD_YES;
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Done getting payload, we can answer\n");
		if(msg->payload == NULL) {
			JANUS_LOG(LOG_ERR, "No payload :-(\n");
			ret = MHD_NO;
			goto done;
		}
		payload = msg->payload;
		JANUS_LOG(LOG_VERB, "%s\n", payload);
	}

	/* Process the request, specifying this HTTP connection is the source */
	janus_request_source source = {
		.type = JANUS_SOURCE_PLAIN_HTTP,
		.source = (void *)connection,
		.msg = (void *)msg,
	};
	
	/* Is this a generic request for info? */
	if(session_path != NULL && !strcmp(session_path, "info")) {
		/* The info REST endpoint, if contacted through a GET, provides information on the gateway */
		if(strcasecmp(method, "GET")) {
			ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_USE_GET, "Use GET for the info endpoint");
			goto done;
		}
		/* Send the success reply */
		ret = janus_process_success(&source, "application/json", janus_info(NULL));
		goto done;
	}
	
	/* Or maybe a long poll */
	if(!strcasecmp(method, "GET") || !payload) {
		guint64 session_id = session_path ? g_ascii_strtoll(session_path, NULL, 10) : 0;
		if(session_id < 1) {
			JANUS_LOG(LOG_ERR, "Invalid session %s\n", session_path);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			goto done;
		}
		msg->session_id = session_id;
		if(handle_path) {
			char *location = (char *)calloc(strlen(ws_path) + strlen(session_path) + 2, sizeof(char));
			g_sprintf(location, "%s/%s", ws_path, session_path);
			JANUS_LOG(LOG_ERR, "Invalid GET to %s, redirecting to %s\n", url, location);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Location", location);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, 302, response);
			MHD_destroy_response(response);
			g_free(location);
			goto done;
		}
		janus_session *session = janus_session_find(session_id);
		if(!session) {
			JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
			goto done;
		}
		if(ws_api_secret != NULL) {
			/* There's an API secret, check that the client provided it */
			const char *secret = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "apisecret");
			if(!secret || !janus_strcmp_const_time(secret, ws_api_secret)) {
				response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
				MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
				if(msg->acrm)
					MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
				if(msg->acrh)
					MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
				ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
				MHD_destroy_response(response);
				goto done;
			}
		}
		/* Update the last activity timer */
		session->last_activity = janus_get_monotonic_time();
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
		JANUS_LOG(LOG_VERB, "Session %"SCNu64" found... returning up to %d messages\n", session->session_id, max_events);
		/* Handle GET, taking the first message from the list */
		janus_http_event *event = g_async_queue_try_pop(session->messages);
		if(event != NULL) {
			if(max_events == 1) {
				/* Return just this message and leave */
				ret = janus_process_success(&source, "application/json", event->payload);
			} else {
				/* The application is willing to receive more events at the same time, anything to report? */
				json_t *list = json_array();
				json_error_t error;
				if(event->payload) {
					json_t *ev = json_loads(event->payload, 0, &error);
					if(ev && json_is_object(ev))	/* FIXME Should we fail if this is not valid JSON? */
						json_array_append_new(list, ev);
					g_free(event->payload);
					event->payload = NULL;
				}
				g_free(event);
				event = NULL;
				int events = 1;
				while(events < max_events) {
					event = g_async_queue_try_pop(session->messages);
					if(event == NULL)
						break;
					if(event->payload) {
						json_t *ev = json_loads(event->payload, 0, &error);
						if(ev && json_is_object(ev))	/* FIXME Should we fail if this is not valid JSON? */
							json_array_append_new(list, ev);
						g_free(event->payload);
						event->payload = NULL;
					}
					g_free(event);
					event = NULL;
					events++;
				}
				/* Return the array of messages and leave */
				char *event_text = json_dumps(list, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(list);
				ret = janus_process_success(&source, "application/json", event_text);
			}
		} else {
			/* Still no message, wait */
			ret = janus_ws_notifier(&source, max_events);
		}
		goto done;
	}
	
	/* Parse the JSON payload */
	json_error_t error;
	json_t *root = json_loads(payload, 0, &error);
	if(!root) {
		ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s", error.line, error.text);
		goto done;
	}
	if(!json_is_object(root)) {
		ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		json_decref(root);
		goto done;
	}
	/* Check if we have session and handle identifiers */
	guint64 session_id = session_path ? g_ascii_strtoll(session_path, NULL, 10) : 0;
	guint64 handle_id = handle_path ? g_ascii_strtoll(handle_path, NULL, 10) : 0;
	if(session_id > 0)
		json_object_set_new(root, "session_id", json_integer(session_id));
	if(handle_id > 0)
		json_object_set_new(root, "handle_id", json_integer(handle_id));
	ret = janus_process_incoming_request(&source, root);

done:
	g_strfreev(basepath);
	g_strfreev(path);
	g_free(session_path);
	g_free(handle_path);
	return ret;
}

janus_request_source *janus_request_source_new(int type, void *source, void *msg) {
	janus_request_source *req_source = (janus_request_source *)calloc(1, sizeof(janus_request_source));
	req_source->type = type;
	req_source->source = source;
	req_source->msg = msg;
	return req_source;
}

void janus_request_source_destroy(janus_request_source *req_source) {
	if(req_source == NULL)
		return;
	req_source->source = NULL;
	req_source->msg = NULL;
	g_free(req_source);
}

int janus_process_incoming_request(janus_request_source *source, json_t *root) {
	int ret = MHD_NO;
	if(source == NULL || root == NULL) {
		JANUS_LOG(LOG_ERR, "Missing source or payload to process, giving up...\n");
		return ret;
	}
	/* Ok, let's start with the ids */
	guint64 session_id = 0, handle_id = 0;
	json_t *s = json_object_get(root, "session_id");
	if(s && json_is_integer(s))
		session_id = json_integer_value(s);
	json_t *h = json_object_get(root, "handle_id");
	if(h && json_is_integer(h))
		handle_id = json_integer_value(h);

	/* Get transaction and message request */
	json_t *transaction = json_object_get(root, "transaction");
	if(!transaction) {
		ret = janus_process_error(source, session_id, NULL, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (transaction)");
		goto jsondone;
	}
	if(!json_is_string(transaction)) {
		ret = janus_process_error(source, session_id, NULL, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (transaction should be a string)");
		goto jsondone;
	}
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	if(!message) {
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (janus)");
		goto jsondone;
	}
	if(!json_is_string(message)) {
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (janus should be a string)");
		goto jsondone;
	}
	const gchar *message_text = json_string_value(message);
	
	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Create new session', a 'Get info' or a 'Ping/Pong' request */
		if(!strcasecmp(message_text, "info")) {
			ret = janus_process_success(source, "application/json", janus_info(transaction_text));
			goto jsondone;
		}
		if(!strcasecmp(message_text, "ping")) {
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("pong"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			ret = janus_process_success(source, "application/json", g_strdup(reply_text));
			goto jsondone;
		}
		if(strcasecmp(message_text, "create")) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(ws_api_secret != NULL) {
			/* There's an API secret, check that the client provided it */
			json_t *secret = json_object_get(root, "apisecret");
			if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), ws_api_secret)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
				goto jsondone;
			}
		}
		session_id = 0;
		json_t *id = json_object_get(root, "id");
		if(id != NULL) {
			/* The application provided the session ID to use */
			if(!json_is_integer(id)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (id should be an integer)");
				goto jsondone;
			}
			session_id = json_integer_value(id);
			if(session_id > 0 && janus_session_find(session_id) != NULL) {
				/* Session ID already taken */
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_CONFLICT, "Session ID already in use");
				goto jsondone;
			}
		}
		/* Handle it */
		janus_session *session = janus_session_create(session_id);
		if(session == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
			goto jsondone;
		}
		session_id = session->session_id;
#ifdef HAVE_WEBSOCKETS
		if(source->type == JANUS_SOURCE_WEBSOCKETS) {
			/* Add the new session to the list of sessions created by this WS client */
			janus_websocket_client *client = (janus_websocket_client *)source->source;
			if(client) {
				janus_mutex_lock(&client->mutex);
				if(client->sessions == NULL)
					client->sessions = g_hash_table_new(NULL, NULL);
				g_hash_table_insert(client->sessions, GUINT_TO_POINTER(session_id), session);
				janus_mutex_unlock(&client->mutex);
			}
		}
#endif
#ifdef HAVE_RABBITMQ
		if(source->type == JANUS_SOURCE_RABBITMQ) {
			/* Add the new session to the list of sessions created by this WS client */
			janus_rabbitmq_client *client = (janus_rabbitmq_client *)source->source;
			if(client) {
				janus_mutex_lock(&client->mutex);
				if(client->sessions == NULL)
					client->sessions = g_hash_table_new(NULL, NULL);
				g_hash_table_insert(client->sessions, GUINT_TO_POINTER(session_id), session);
				janus_mutex_unlock(&client->mutex);
			}
		}
#endif
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(session_id));
		json_object_set(reply, "data", data);
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(data);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
		goto jsondone;
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
		janus_http_msg *msg = (janus_http_msg *)source->msg;
		if(msg != NULL)
			msg->session_id = session_id;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	if(ws_api_secret != NULL) {
		/* There's an API secret, check that the client provided it */
		json_t *secret = json_object_get(root, "apisecret");
		if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), ws_api_secret)) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	janus_session *session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	janus_ice_handle *handle = NULL;
	if(handle_id > 0) {
		handle = janus_ice_handle_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}
	/* Update the last activity timer */
	session->last_activity = janus_get_monotonic_time();

	/* What is this? */
	if(!strcasecmp(message_text, "keepalive")) {
		/* Just a keep-alive message, reply with an ack */
		JANUS_LOG(LOG_VERB, "Got a keep-alive on session %"SCNu64"\n", session_id);
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
	} else if(!strcasecmp(message_text, "attach")) {
		if(handle != NULL) {
			/* Attach is a session-level command */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		json_t *plugin = json_object_get(root, "plugin");
		if(!plugin) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (plugin)");
			goto jsondone;
		}
		if(!json_is_string(plugin)) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (plugin should be a string)");
			goto jsondone;
		}
		const gchar *plugin_text = json_string_value(plugin);
		janus_plugin *plugin_t = janus_plugin_find(plugin_text);
		if(plugin_t == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, "No such plugin '%s'", plugin_text);
			goto jsondone;
		}
		/* Create handle */
		handle = janus_ice_handle_create(session);
		if(handle == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
			goto jsondone;
		}
		handle_id = handle->handle_id;
		/* Attach to the plugin */
		int error = 0;
		if((error = janus_ice_handle_attach_plugin(session, handle_id, plugin_t)) != 0) {
			/* TODO Make error struct to pass verbose information */
			janus_ice_handle_destroy(session, handle_id);
			janus_mutex_lock(&session->mutex);
			g_hash_table_remove(session->ice_handles, GUINT_TO_POINTER(handle_id));
			janus_mutex_unlock(&session->mutex);

			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_ATTACH, "Couldn't attach to plugin: error '%d'", error);
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(handle_id));
		json_object_set(reply, "data", data);
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(data);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
	} else if(!strcasecmp(message_text, "destroy")) {
		if(handle != NULL) {
			/* Query is a session-level command */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
#ifdef HAVE_WEBSOCKETS
		if(source->type == JANUS_SOURCE_WEBSOCKETS) {
			/* Remove the session from the list of sessions created by this WS client */
			janus_websocket_client *client = (janus_websocket_client *)source->source;
			if(client) {
				janus_mutex_lock(&client->mutex);
				if(client->sessions)
					g_hash_table_remove(client->sessions, GUINT_TO_POINTER(session_id));
				janus_mutex_unlock(&client->mutex);
			}
		}
#endif
		//~ janus_session_destroy(session_id);	/* FIXME Should we check if this actually succeeded, or can we ignore it? */

		/* Schedule the session for deletion */
		session->destroy = 1;
		janus_mutex_lock(&sessions_mutex);
		g_hash_table_remove(sessions, GUINT_TO_POINTER(session->session_id));
		g_hash_table_insert(old_sessions, GUINT_TO_POINTER(session->session_id), session);
		GSource *timeout_source = g_timeout_source_new_seconds(3);
		g_source_set_callback(timeout_source, janus_cleanup_session, session, NULL);
		g_source_attach(timeout_source, sessions_watchdog_context);
		g_source_unref(timeout_source);
		janus_mutex_unlock(&sessions_mutex);

		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
	} else if(!strcasecmp(message_text, "detach")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin to detach from");
			goto jsondone;
		}
		int error = janus_ice_handle_destroy(session, handle_id);
		janus_mutex_lock(&session->mutex);
		g_hash_table_remove(session->ice_handles, GUINT_TO_POINTER(handle_id));
		janus_mutex_unlock(&session->mutex);

		if(error != 0) {
			/* TODO Make error struct to pass verbose information */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "Couldn't detach from plugin: error '%d'", error);
			/* TODO Delete handle instance */
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
	} else if(!strcasecmp(message_text, "message")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this message");
			goto jsondone;
		}
		janus_plugin *plugin_t = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_INFO, "[%"SCNu64"] There's a message for %s\n", handle->handle_id, plugin_t->get_name());
		json_t *body = json_object_get(root, "body");
		if(body == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (body)");
			goto jsondone;
		}
		if(!json_is_object(body)) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_JSON_OBJECT, "Invalid body object");
			goto jsondone;
		}
		/* Is there an SDP attached? */
		json_t *jsep = json_object_get(root, "jsep");
		char *jsep_type = NULL;
		char *jsep_sdp = NULL, *jsep_sdp_stripped = NULL;
		if(jsep != NULL) {
			if(!json_is_object(jsep)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_JSON_OBJECT, "Invalid jsep object");
				goto jsondone;
			}
			json_t *type = json_object_get(jsep, "type");
			if(!type) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "JSEP error: missing mandatory element (type)");
				goto jsondone;
			}
			if(!json_is_string(type)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "JSEP error: invalid element type (type should be a string)");
				goto jsondone;
			}
			jsep_type = g_strdup(json_string_value(type));
			if(jsep_type == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
				goto jsondone;
			}
			type = NULL;
			/* Are we still cleaning up from a previous media session? */
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
				JANUS_LOG(LOG_INFO, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", handle->handle_id);
				gint64 waited = 0;
				while(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", handle->handle_id);
					g_usleep(100000);
					waited += 100000;
					if(waited >= 3*G_USEC_PER_SEC) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", handle->handle_id);
						break;
					}
				}
			}
			/* Check the JSEP type */
			int offer = 0;
			if(!strcasecmp(jsep_type, "offer")) {
				offer = 1;
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
			} else if(!strcasecmp(jsep_type, "answer")) {
				offer = 0;
			} else {
				/* TODO Handle other message types as well */
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_JSEP_UNKNOWN_TYPE, "JSEP error: unknown message type '%s'", jsep_type);
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			json_t *sdp = json_object_get(jsep, "sdp");
			if(!sdp) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "JSEP error: missing mandatory element (sdp)");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			if(!json_is_string(sdp)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "JSEP error: invalid element type (sdp should be a string)");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			jsep_sdp = (char *)json_string_value(sdp);
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote SDP:\n%s", handle->handle_id, jsep_sdp);
			/* Is this valid SDP? */
			int audio = 0, video = 0, data = 0, bundle = 0, rtcpmux = 0, trickle = 0;
			janus_sdp *parsed_sdp = janus_sdp_preparse(jsep_sdp, &audio, &video, &data, &bundle, &rtcpmux, &trickle);
			if(parsed_sdp == NULL) {
				/* Invalid SDP */
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "JSEP error: invalid SDP");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			/* FIXME We're only handling single audio/video lines for now... */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio %s been negotiated\n", handle->handle_id, audio ? "has" : "has NOT");
			if(audio > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one audio line? only going to negotiate one...\n", handle->handle_id);
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video %s been negotiated\n", handle->handle_id, video ? "has" : "has NOT");
			if(video > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one video line? only going to negotiate one...\n", handle->handle_id);
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] SCTP/DataChannels %s been negotiated\n", handle->handle_id, data ? "have" : "have NOT");
			if(data > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one data line? only going to negotiate one...\n", handle->handle_id);
			}
#ifndef HAVE_SCTP
			if(data) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"]   -- DataChannels have been negotiated, but support for them has not been compiled...\n", handle->handle_id);
			}
#endif
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] The browser %s BUNDLE\n", handle->handle_id, bundle ? "supports" : "does NOT support");
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] The browser %s rtcp-mux\n", handle->handle_id, rtcpmux ? "supports" : "does NOT support");
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] The browser %s doing Trickle ICE\n", handle->handle_id, trickle ? "is" : "is NOT");
			/* Check if it's a new session, or an update... */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)
					|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				/* New session */
				if(offer) {
					/* Setup ICE locally (we received an offer) */
					if(janus_ice_setup_local(handle, offer, audio, video, data, bundle, rtcpmux, trickle) < 0) {
						JANUS_LOG(LOG_ERR, "Error setting ICE locally\n");
						ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error setting ICE locally");
						goto jsondone;
					}
				} else {
					/* Make sure we're waiting for an ANSWER in the first place */
					if(!handle->agent) {
						JANUS_LOG(LOG_ERR, "Unexpected ANSWER (did we offer?)\n");
						ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNEXPECTED_ANSWER, "Unexpected ANSWER (did we offer?)");
						goto jsondone;
					}
				}
				janus_sdp_parse(handle, parsed_sdp);
				janus_sdp_free(parsed_sdp);
				if(!offer) {
					/* Set remote candidates now (we received an answer) */
					if(bundle) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
					}
					if(rtcpmux) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX);
					}
					if(trickle) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
					}
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- bundle is supported by the browser, getting rid of one of the RTP/RTCP components, if any...\n", handle->handle_id);
						if(audio) {
							/* Get rid of video and data, if present */
							if(handle->streams && handle->video_stream) {
								handle->audio_stream->video_ssrc = handle->video_stream->video_ssrc;
								handle->audio_stream->video_ssrc_peer = handle->video_stream->video_ssrc_peer;
								janus_ice_stream_free(handle->streams, handle->video_stream);
							}
							handle->video_stream = NULL;
							if(handle->video_id > 0) {
								nice_agent_attach_recv (handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
								nice_agent_attach_recv (handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							}
							handle->video_id = 0;
							if(handle->streams && handle->data_stream) {
								janus_ice_stream_free(handle->streams, handle->data_stream);
							}
							handle->data_stream = NULL;
							if(handle->data_id > 0) {
								nice_agent_attach_recv (handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							}
							handle->data_id = 0;
						} else if(video) {
							/* Get rid of data, if present */
							if(handle->streams && handle->data_stream) {
								janus_ice_stream_free(handle->streams, handle->data_stream);
							}
							handle->data_stream = NULL;
							if(handle->data_id > 0) {
								nice_agent_attach_recv (handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							}
							handle->data_id = 0;
						}
					}
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- rtcp-mux is supported by the browser, getting rid of RTCP components, if any...\n", handle->handle_id);
						if(handle->audio_stream && handle->audio_stream->components != NULL) {
							nice_agent_attach_recv (handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							janus_ice_component_free(handle->audio_stream->components, handle->audio_stream->rtcp_component);
							handle->audio_stream->rtcp_component = NULL;
						}
						if(handle->video_stream && handle->video_stream->components != NULL) {
							nice_agent_attach_recv (handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							janus_ice_component_free(handle->video_stream->components, handle->video_stream->rtcp_component);
							handle->video_stream->rtcp_component = NULL;
						}
					}
					/* FIXME Any disabled m-line? */
					if(strstr(jsep_sdp, "m=audio 0")) {
						JANUS_LOG(LOG_VERB, "Audio disabled via SDP\n");
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!video && !data)) {
							JANUS_LOG(LOG_VERB, "  -- Marking audio stream as disabled\n");
							janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
							if(stream)
								stream->disabled = TRUE;
						}
					}
					if(strstr(jsep_sdp, "m=video 0")) {
						JANUS_LOG(LOG_VERB, "Video disabled via SDP\n");
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!audio && !data)) {
							JANUS_LOG(LOG_VERB, "  -- Marking video stream as disabled\n");
							janus_ice_stream *stream = NULL;
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
								stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->video_id));
							} else {
								gint id = handle->audio_id > 0 ? handle->audio_id : handle->video_id;
								stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
							}
							if(stream)
								stream->disabled = TRUE;
						}
					}
					if(strstr(jsep_sdp, "m=application 0 DTLS/SCTP")) {
						JANUS_LOG(LOG_VERB, "Data Channel disabled via SDP\n");
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!audio && !video)) {
							JANUS_LOG(LOG_VERB, "  -- Marking data channel stream as disabled\n");
							janus_ice_stream *stream = NULL;
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
								stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->data_id));
							} else {
								gint id = handle->audio_id > 0 ? handle->audio_id : (handle->video_id > 0 ? handle->video_id : handle->data_id);
								stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(id));
							}
							if(stream)
								stream->disabled = TRUE;
						}
					}
					janus_mutex_lock(&handle->mutex);
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) &&
							!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
						JANUS_LOG(LOG_INFO, "[%"SCNu64"]   -- ICE Trickling is supported by the browser, waiting for remote candidates...\n", handle->handle_id);
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
					} else {
						JANUS_LOG(LOG_INFO, "[%"SCNu64"] Done! Sending connectivity checks...\n", handle->handle_id);
						if(handle->audio_id > 0) {
							janus_ice_setup_remote_candidates(handle, handle->audio_id, 1);
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
								janus_ice_setup_remote_candidates(handle, handle->audio_id, 2);
						}
						if(handle->video_id > 0) {
							janus_ice_setup_remote_candidates(handle, handle->video_id, 1);
							if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
								janus_ice_setup_remote_candidates(handle, handle->video_id, 2);
						}
						if(handle->data_id > 0) {
							janus_ice_setup_remote_candidates(handle, handle->data_id, 1);
						}
					}
					janus_mutex_unlock(&handle->mutex);
					/* We got our answer */
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				}
			} else {
				/* TODO Actually handle session updates: for now we ignore them, and just relay them to plugins */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Ignoring negotiation update, we don't support them yet...\n", handle->handle_id);
			}
			handle->remote_sdp = g_strdup(jsep_sdp);
			/* Anonymize SDP */
			jsep_sdp_stripped = janus_sdp_anonymize(jsep_sdp);
			if(jsep_sdp_stripped == NULL) {
				/* Invalid SDP */
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "JSEP error: invalid SDP");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			sdp = NULL;
			janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
		}
		char *body_text = json_dumps(body, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		/* Send the message to the plugin */
		janus_plugin_result *result = plugin_t->handle_message(handle->app_handle, g_strdup((char *)transaction_text), body_text, jsep_type, jsep_sdp_stripped);
		if(result == NULL) {
			/* Something went horribly wrong! */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin didn't give a result");
			goto jsondone;
		}
		if(result->type == JANUS_PLUGIN_OK) {
			/* The plugin gave a result already (synchronous request/response) */
			if(result->content == NULL) {
				/* Missing content... */
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin didn't provide any content for this synchronous response");
				janus_plugin_result_destroy(result);
				goto jsondone;
			}
			json_error_t error;
			json_t *event = json_loads(result->content, 0, &error);
			if(!event) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot send response from plugin (JSON error: on line %d: %s)\n", handle->handle_id, error.line, error.text);
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin returned an invalid JSON response");
				janus_plugin_result_destroy(result);
				goto jsondone;
			}
			if(!json_is_object(event)) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot send response from plugin (JSON error: not an object)\n", handle->handle_id);
				json_decref(event);
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin returned an invalid JSON response");
				janus_plugin_result_destroy(result);
				goto jsondone;
			}
			/* Prepare JSON response */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "session_id", json_integer(session->session_id));
			json_object_set_new(reply, "sender", json_integer(handle->handle_id));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *plugin_data = json_object();
			json_object_set_new(plugin_data, "plugin", json_string(plugin_t->get_package()));
			json_object_set(plugin_data, "data", event);
			json_object_set(reply, "plugindata", plugin_data);
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			json_decref(plugin_data);
			if(jsep != NULL)
				json_decref(jsep);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
		} else if(result->type == JANUS_PLUGIN_OK_WAIT) {
			/* The plugin received the request but didn't process it yet, send an ack (asynchronous notifications may follow) */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("ack"));
			json_object_set_new(reply, "session_id", json_integer(session_id));
			if(result->content)
				json_object_set_new(reply, "hint", json_string(result->content));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
		} else {
			/* Something went horribly wrong! */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "%s", result->content ? g_strdup(result->content) : "Plugin returned a severe (unknown) error");
			janus_plugin_result_destroy(result);
			goto jsondone;
		}			
		janus_plugin_result_destroy(result);
	} else if(!strcasecmp(message_text, "trickle")) {
		if(handle == NULL) {
			/* Trickle is an handle-level command */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this trickle candidate");
			goto jsondone;
		}
		json_t *candidate = json_object_get(root, "candidate");
		json_t *candidates = json_object_get(root, "candidates");
		if(candidate == NULL && candidates == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (candidate|candidates)");
			goto jsondone;
		}
		if(candidate != NULL && candidates != NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_JSON, "Can't have both candidate and candidates");
			goto jsondone;
		}
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)) {
			/* It looks like this peer supports Trickle, after all */
			JANUS_LOG(LOG_VERB, "Handle %"SCNu64" supports trickle even if it didn't negotiate it...\n", handle->handle_id);
			janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
		}
		if(candidate != NULL) {
			/* We got a single candidate */
			if(!json_is_object(candidate) || json_object_get(candidate, "completed") != NULL) {
				JANUS_LOG(LOG_INFO, "No more remote candidates for handle %"SCNu64"!\n", handle->handle_id);
				janus_mutex_lock(&handle->mutex);
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
				janus_mutex_unlock(&handle->mutex);
			} else {
				/* Handle remote candidate */
				json_t *mid = json_object_get(candidate, "sdpMid");
				if(!mid) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Trickle error: missing mandatory element (sdpMid)");
					goto jsondone;
				}
				if(!json_is_string(mid)) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Trickle error: invalid element type (sdpMid should be a string)");
					goto jsondone;
				}
				json_t *mline = json_object_get(candidate, "sdpMLineIndex");
				if(!mline) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Trickle error: missing mandatory element (sdpMLineIndex)");
					goto jsondone;
				}
				if(!json_is_integer(mline)) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Trickle error: invalid element type (sdpMLineIndex should be an integer)");
					goto jsondone;
				}
				json_t *rc = json_object_get(candidate, "candidate");
				if(!rc) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Trickle error: missing mandatory element (candidate)");
					goto jsondone;
				}
				if(!json_is_string(rc)) {
					ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Trickle error: invalid element type (candidate should be a string)");
					goto jsondone;
				}
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Trickle candidate (%s): %s\n", handle->handle_id, json_string_value(mid), json_string_value(rc));
				/* Is there any stream ready? this trickle may get here before the SDP it relates to */
				if(handle->audio_stream == NULL && handle->video_stream == NULL && handle->data_stream == NULL) {
					/* No stream available, wait a bit */
					gint64 waited = 0;
					while(handle->audio_stream == NULL && handle->video_stream == NULL && handle->data_stream == NULL) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] No stream, wait a bit in case this trickle got here before the SDP...\n", handle->handle_id);
						g_usleep(100000);
						waited += 100000;
						if(waited >= 3*G_USEC_PER_SEC) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", handle->handle_id);
							break;
						}
					}
				}
				/* Is the ICE stack ready already? */
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)) {
					/* Still processing the offer, wait a bit */
					gint64 waited = 0;
					while(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still processing the offer, waiting until we're done there...\n", handle->handle_id);
						g_usleep(100000);
						waited += 100000;
						if(waited >= 5*G_USEC_PER_SEC) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 5 seconds, that's enough!\n", handle->handle_id);
							break;
						}
					}
				}
				/* Parse it */
				int sdpMLineIndex = json_integer_value(mline);
				int video = 0, data = 0;
				/* FIXME badly, we should have an array of m-lines in the handle object */
				switch(sdpMLineIndex) {
					case 0:
						if(handle->audio_stream == NULL) {
							video = handle->video_stream ? 1 : 0;
							data = !video;
						}
						break;
					case 1:
						if(handle->audio_stream == NULL) {
							data = 1;
						} else {
							video = handle->video_stream ? 1 : 0;
							data = !video;
						}
						break;
					case 2:
						data = 1;
						break;
					default:
						/* FIXME We don't support more than 3 m-lines right now */
						ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Trickle error: invalid element type (sdpMLineIndex not [0,2])");
						goto jsondone;
						break;
				}
#ifndef HAVE_SCTP
				data = 0;
#endif
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
						&& (
							((video || data) && handle->audio_stream != NULL) || 
								((data) && handle->video_stream != NULL))
							) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a %s candidate but we're bundling, ignoring...\n", handle->handle_id, json_string_value(mid));
				} else {
					janus_ice_stream *stream = video ? handle->video_stream : (data ? handle->data_stream : handle->audio_stream);
					if(stream == NULL) {
						ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_TRICKE_INVALID_STREAM, "Trickle error: no %s stream", json_string_value(mid));
						goto jsondone;
					}
					int res = janus_sdp_parse_candidate(stream, json_string_value(rc), 1);
					if(res != 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
					}
				}
			}
		} else {
			/* We got multiple candidates in an array */
			if(!json_is_array(candidates)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Can't have both candidate and candidates");
				goto jsondone;
			}
			JANUS_LOG(LOG_INFO, "Got multiple candidates (%zu)\n", json_array_size(candidates));
			gboolean last_candidate = FALSE;
			if(json_array_size(candidates) > 0) {
				/* Handle remote candidates */
				size_t i = 0;
				for(i=0; i<json_array_size(candidates); i++) {
					json_t *candidate = json_array_get(candidates, i);
					if(candidate == NULL || !json_is_object(candidate) || json_object_get(candidate, "completed") != NULL) {
						/* A 'NULL' candidate is our cue */
						last_candidate = TRUE;
						continue;
					}
					json_t *mid = json_object_get(candidate, "sdpMid");
					if(!mid) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, missing mandatory element (sdpMid)", i);
						continue;
					}
					if(!json_is_string(mid)) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, invalid element type (sdpMid should be a string)", i);
						continue;
					}
					json_t *mline = json_object_get(candidate, "sdpMLineIndex");
					if(!mline) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, missing mandatory element (sdpMLineIndex)", i);
						continue;
					}
					if(!json_is_integer(mline)) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, invalid element type (sdpMLineIndex should be an integer)", i);
						continue;
					}
					json_t *rc = json_object_get(candidate, "candidate");
					if(!rc) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, missing mandatory element (candidate)", i);
						continue;
					}
					if(!json_is_string(rc)) {
						/* Invalid candidate but we don't return an error, we just ignore it */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, invalid element type (candidate should be a string)", i);
						continue;
					}
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Trickle candidate at index %zu (%s): %s\n", handle->handle_id, i, json_string_value(mid), json_string_value(rc));
					/* Parse it */
					int sdpMLineIndex = json_integer_value(mline);
					if(sdpMLineIndex < 0 || sdpMLineIndex > 2) {
						/* FIXME We don't support more than 3 m-lines right now */
						JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, invalid element type (sdpMLineIndex not [0,2])", i);
						continue;
					}
					/* Is there any stream ready? this trickle may get here before the SDP it relates to */
					if(handle->audio_stream == NULL && handle->video_stream == NULL && handle->data_stream == NULL) {
						/* No stream available, wait a bit */
						gint64 waited = 0;
						while(handle->audio_stream == NULL && handle->video_stream == NULL && handle->data_stream == NULL) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] No stream, wait a bit in case this trickle got here before the SDP...\n", handle->handle_id);
							g_usleep(100000);
							waited += 100000;
							if(waited >= 3*G_USEC_PER_SEC) {
								JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", handle->handle_id);
								break;
							}
						}
					}
					/* Is the ICE stack ready already? */
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)) {
						/* Still processing the offer, wait a bit */
						gint64 waited = 0;
						while(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still processing the offer, waiting until we're done there...\n", handle->handle_id);
							g_usleep(100000);
							waited += 100000;
							if(waited >= 5*G_USEC_PER_SEC) {
								JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 5 seconds, that's enough!\n", handle->handle_id);
								break;
							}
						}
					}
					int video = 0, data = 0;
					/* FIXME badly, we should have an array of m-lines in the handle object */
					switch(sdpMLineIndex) {
						case 0:
							if(handle->audio_stream == NULL) {
								video = handle->video_stream ? 1 : 0;
								data = !video;
							}
							break;
						case 1:
							if(handle->audio_stream == NULL) {
								data = 1;
							} else {
								video = handle->video_stream ? 1 : 0;
								data = !video;
							}
							break;
						case 2:
							data = 1;
							break;
						default:
							break;
					}
#ifndef HAVE_SCTP
					data = 0;
#endif
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
							&& (
								((video || data) && handle->audio_stream != NULL) || 
									((data) && handle->video_stream != NULL))
								) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a %s candidate but we're bundling, ignoring...\n", handle->handle_id, json_string_value(mid));
					} else {
						janus_ice_stream *stream = video ? handle->video_stream : (data ? handle->data_stream : handle->audio_stream);
						if(stream == NULL) {
							JANUS_LOG(LOG_WARN, "Trickle error: ignoring candidate at index %zu, no %s stream", i, json_string_value(mid));
							continue;
						}
						int res = janus_sdp_parse_candidate(stream, json_string_value(rc), 1);
						if(res != 0) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate at index %zu... (%d)\n", handle->handle_id, i, res);
						}
					}
				}
			}
			if(last_candidate) {
				JANUS_LOG(LOG_INFO, "No more remote candidates for handle %"SCNu64"!\n", handle->handle_id);
				janus_mutex_lock(&handle->mutex);
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
				janus_mutex_unlock(&handle->mutex);
			}
		}
		/* We reply right away, not to block the web server... */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
	} else {
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNKNOWN_REQUEST, "Unknown request '%s'", message_text);
	}
	goto jsondone;

jsondone:
	json_decref(root);
	
	return ret;
}

/* Admin/monitor WebServer requests handler */
int janus_admin_ws_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
	char *payload = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;
	gchar *session_path = NULL, *handle_path = NULL;
	gchar **basepath = NULL, **path = NULL;

	JANUS_LOG(LOG_VERB, "Got an admin/monitor HTTP %s request on %s...\n", method, url);
	/* Is this the first round? */
	int firstround = 0;
	janus_http_msg *msg = (janus_http_msg *)*ptr;
	if (msg == NULL) {
		firstround = 1;
		JANUS_LOG(LOG_VERB, " ... Just parsing headers for now...\n");
		msg = calloc(1, sizeof(janus_http_msg));
		if(msg == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		msg->acrh = NULL;
		msg->acrm = NULL;
		msg->payload = NULL;
		msg->len = 0;
		msg->session_id = 0;
		*ptr = msg;
		MHD_get_connection_values(connection, MHD_HEADER_KIND, &janus_ws_headers, msg);
		ret = MHD_YES;
	}
	/* Parse request */
	if (strcasecmp(method, "GET") && strcasecmp(method, "POST") && strcasecmp(method, "OPTIONS")) {
		JANUS_LOG(LOG_ERR, "Unsupported method...\n");
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_IMPLEMENTED, response);
		MHD_destroy_response(response);
		return ret;
	}
	if (!strcasecmp(method, "OPTIONS")) {
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO); 
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
	}
	/* Get path components */
	if(strcasecmp(url, admin_ws_path)) {
		if(strlen(admin_ws_path) > 1) {
			basepath = g_strsplit(url, admin_ws_path, -1);
		} else {
			/* The base path is the web server too itself, we process the url itself */
			basepath = calloc(3, sizeof(char *));
			basepath[0] = g_strdup("/");
			basepath[1] = g_strdup(url);
		}
		if(basepath[1] == NULL || basepath[1][0] != '/') {
			JANUS_LOG(LOG_ERR, "Invalid url %s (%s)\n", url, basepath[1]);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
		if(firstround) {
			g_strfreev(basepath);
			return ret;
		}
		path = g_strsplit(basepath[1], "/", -1);
		if(path == NULL || path[1] == NULL) {
			JANUS_LOG(LOG_ERR, "Invalid path %s (%s)\n", basepath[1], path[1]);
			response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
			MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
			if(msg->acrm)
				MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
			if(msg->acrh)
				MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
			ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response(response);
		}
	}
	if(firstround)
		return ret;
	JANUS_LOG(LOG_VERB, " ... parsing request...\n");
	if(path != NULL && path[1] != NULL && strlen(path[1]) > 0) {
		session_path = g_strdup(path[1]);
		if(session_path == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Session: %s\n", session_path);
	}
	if(session_path != NULL && path[2] != NULL && strlen(path[2]) > 0) {
		handle_path = g_strdup(path[2]);
		if(handle_path == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Handle: %s\n", handle_path);
	}
	if(session_path != NULL && handle_path != NULL && path[3] != NULL && strlen(path[3]) > 0) {
		JANUS_LOG(LOG_ERR, "Too many components...\n");
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		goto done;
	}
	/* Get payload, if any */
	if(!strcasecmp(method, "POST")) {
		JANUS_LOG(LOG_VERB, "Processing POST data (%s)...\n", msg->contenttype);
		if(*upload_data_size != 0) {
			JANUS_LOG(LOG_VERB, "  -- Uploaded data (%zu bytes)\n", *upload_data_size);
			if(msg->payload == NULL)
				msg->payload = calloc(1, *upload_data_size+1);
			else
				msg->payload = realloc(msg->payload, msg->len+*upload_data_size+1);
			if(msg->payload == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
				MHD_destroy_response(response);
				goto done;
			}
			memcpy(msg->payload+msg->len, upload_data, *upload_data_size);
			memset(msg->payload+msg->len+*upload_data_size, '\0', 1);
			msg->len += *upload_data_size;
			JANUS_LOG(LOG_VERB, "  -- Data we have now (%zu bytes)\n", msg->len);
			*upload_data_size = 0;	/* Go on */
			ret = MHD_YES;
			goto done;
		}
		JANUS_LOG(LOG_VERB, "Done getting payload, we can answer\n");
		if(msg->payload == NULL) {
			JANUS_LOG(LOG_ERR, "No payload :-(\n");
			ret = MHD_NO;
			goto done;
		}
		payload = msg->payload;
		JANUS_LOG(LOG_VERB, "%s\n", payload);
	}

	/* Process the request, specifying this HTTP connection is the source */
	janus_request_source source = {
		.type = JANUS_SOURCE_PLAIN_HTTP,
		.source = (void *)connection,
		.msg = (void *)msg,
	};
	
	/* Is this a generic request for info? */
	if(session_path != NULL && !strcmp(session_path, "info")) {
		/* The info REST endpoint, if contacted through a GET, provides information on the gateway */
		if(strcasecmp(method, "GET")) {
			ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_USE_GET, "Use GET for the info endpoint");
			goto done;
		}
		/* Send the success reply */
		ret = janus_process_success(&source, "application/json", janus_info(NULL));
		goto done;
	}
	
	/* Without a payload we don't know what to do */
	if(!payload) {
		ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON, "Request payload missing");
		goto done;
	}
	
	/* Parse the JSON payload */
	json_error_t error;
	json_t *root = json_loads(payload, 0, &error);
	if(!root) {
		ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s", error.line, error.text);
		goto done;
	}
	if(!json_is_object(root)) {
		ret = janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		json_decref(root);
		goto done;
	}
	/* Check if we have session and handle identifiers */
	guint64 session_id = session_path ? g_ascii_strtoll(session_path, NULL, 10) : 0;
	guint64 handle_id = handle_path ? g_ascii_strtoll(handle_path, NULL, 10) : 0;
	if(session_id > 0)
		json_object_set_new(root, "session_id", json_integer(session_id));
	if(handle_id > 0)
		json_object_set_new(root, "handle_id", json_integer(handle_id));
	ret = janus_process_incoming_admin_request(&source, root);

done:
	g_strfreev(basepath);
	g_strfreev(path);
	g_free(session_path);
	g_free(handle_path);
	return ret;
}

int janus_process_incoming_admin_request(janus_request_source *source, json_t *root) {
	int ret = MHD_NO;
	if(source == NULL || root == NULL) {
		JANUS_LOG(LOG_ERR, "Missing source or payload to process, giving up...\n");
		return ret;
	}
	/* Ok, let's start with the ids */
	guint64 session_id = 0, handle_id = 0;
	json_t *s = json_object_get(root, "session_id");
	if(s && json_is_integer(s))
		session_id = json_integer_value(s);
	json_t *h = json_object_get(root, "handle_id");
	if(h && json_is_integer(h))
		handle_id = json_integer_value(h);

	/* Get transaction and message request */
	json_t *transaction = json_object_get(root, "transaction");
	if(!transaction) {
		ret = janus_process_error(source, session_id, NULL, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (transaction)");
		goto jsondone;
	}
	if(!json_is_string(transaction)) {
		ret = janus_process_error(source, session_id, NULL, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (transaction should be a string)");
		goto jsondone;
	}
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	if(!message) {
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (janus)");
		goto jsondone;
	}
	if(!json_is_string(message)) {
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (janus should be a string)");
		goto jsondone;
	}
	const gchar *message_text = json_string_value(message);
	
	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Get all sessions' or some general setting manipulation request */
		if(!strcasecmp(message_text, "info")) {
			/* The generic info request */
			ret = janus_process_success(source, "application/json", janus_info(transaction_text));
			goto jsondone;
		}
		if(admin_ws_api_secret != NULL) {
			/* There's an admin/monitor secret, check that the client provided it */
			json_t *secret = json_object_get(root, "admin_secret");
			if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_ws_api_secret)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
				goto jsondone;
			}
		}
		if(!strcasecmp(message_text, "get_status")) {
			/* Return some info on the settings (mostly debug-related, at the moment) */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *status = json_object();
			json_object_set_new(status, "log_level", json_integer(log_level));
			json_object_set_new(status, "locking_debug", json_integer(lock_debug));
			json_object_set_new(status, "libnice_debug", json_integer(janus_ice_is_ice_debugging_enabled()));
			json_object_set_new(status, "max_nack_queue", json_integer(janus_get_max_nack_queue()));
			json_object_set_new(reply, "status", status);
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_level")) {
			/* Change the debug logging level */
			json_t *level = json_object_get(root, "level");
			if(!level) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (level)");
				goto jsondone;
			}
			if(!json_is_integer(level)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (level should be an integer)");
				goto jsondone;
			}
			int level_num = json_integer_value(level);
			if(level_num < LOG_NONE || level_num > LOG_MAX) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (level should be between %d and %d)", LOG_NONE, LOG_MAX);
				goto jsondone;
			}
			log_level = level_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "level", json_integer(log_level));
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_locking_debug")) {
			/* Enable/disable the locking debug (would show a message on the console for every lock attempt) */
			json_t *debug = json_object_get(root, "debug");
			if(!debug) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (debug)");
				goto jsondone;
			}
			if(!json_is_integer(debug)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be an integer)");
				goto jsondone;
			}
			int debug_num = json_integer_value(debug);
			if(debug_num < 0 || debug_num > 1) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be either 0 or 1)");
				goto jsondone;
			}
			lock_debug = debug_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "debug", json_integer(lock_debug));
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_libnice_debug")) {
			/* Enable/disable the libnice debugging (http://nice.freedesktop.org/libnice/libnice-Debug-messages.html) */
			json_t *debug = json_object_get(root, "debug");
			if(!debug) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (debug)");
				goto jsondone;
			}
			if(!json_is_integer(debug)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be an integer)");
				goto jsondone;
			}
			int debug_num = json_integer_value(debug);
			if(debug_num < 0 || debug_num > 1) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be either 0 or 1)");
				goto jsondone;
			}
			if(debug_num) {
				janus_ice_debugging_enable();
			} else {
				janus_ice_debugging_disable();
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "debug", json_integer(janus_ice_is_ice_debugging_enabled()));
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_max_nack_queue")) {
			/* Change the current value for the max NACK queue */
			json_t *mnq = json_object_get(root, "max_nack_queue");
			if(!mnq) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (max_nack_queue)");
				goto jsondone;
			}
			if(!json_is_integer(mnq)) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (max_nack_queue should be an integer)");
				goto jsondone;
			}
			int mnq_num = json_integer_value(mnq);
			if(mnq_num < 0) {
				ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (max_nack_queue should be a positive integer)");
				goto jsondone;
			}
			janus_set_max_nack_queue(mnq_num);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "max_nack_queue", json_integer(janus_get_max_nack_queue()));
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else if(!strcasecmp(message_text, "list_sessions")) {
			/* List sessions */
			session_id = 0;
			json_t *list = json_array();
			if(sessions != NULL && g_hash_table_size(sessions) > 0) {
				janus_mutex_lock(&sessions_mutex);
				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, sessions);
				while (g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_session *session = value;
					if(session == NULL) {
						continue;
					}
					json_array_append_new(list, json_integer(session->session_id));
				}
				janus_mutex_unlock(&sessions_mutex);
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "sessions", list);
			/* Convert to a string */
			char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(reply);
			/* Send the success reply */
			ret = janus_process_success(source, "application/json", reply_text);
			goto jsondone;
		} else {
			/* No message we know of */
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
		janus_http_msg *msg = (janus_http_msg *)source->msg;
		if(msg != NULL)
			msg->session_id = session_id;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	if(admin_ws_api_secret != NULL) {
		/* There's an API secret, check that the client provided it */
		json_t *secret = json_object_get(root, "admin_secret");
		if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_ws_api_secret)) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	janus_session *session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	janus_ice_handle *handle = NULL;
	if(handle_id > 0) {
		handle = janus_ice_handle_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}

	/* What is this? */
	if(handle == NULL) {
		/* Session-related */
		if(strcasecmp(message_text, "list_handles")) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		/* List handles */
		json_t *list = json_array();
		if(session->ice_handles != NULL && g_hash_table_size(session->ice_handles) > 0) {
			GHashTableIter iter;
			gpointer value;
			janus_mutex_lock(&session->mutex);
			g_hash_table_iter_init(&iter, session->ice_handles);
			while (g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_ice_handle *handle = value;
				if(handle == NULL) {
					continue;
				}
				json_array_append_new(list, json_integer(handle->handle_id));
			}
			janus_mutex_unlock(&session->mutex);
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "handles", list);
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
		goto jsondone;
	} else {
		/* Handle-related */
		if(strcasecmp(message_text, "handle_info")) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		/* Prepare info */
		janus_mutex_lock(&handle->mutex);
		json_t *info = json_object();
		json_object_set_new(info, "session_id", json_integer(session_id));
		json_object_set_new(info, "handle_id", json_integer(handle_id));
		if(handle->app) {
			janus_plugin *plugin = (janus_plugin *)handle->app;
			json_object_set_new(info, "plugin", json_string(plugin->get_package()));
			if(plugin->query_session) {
				/* FIXME This check will NOT work with legacy plugins that were compiled BEFORE the method was specified in plugin.h */
				char *query = plugin->query_session(handle->app_handle);
				if(query != NULL) {
					/* Make sure this is JSON */
					json_error_t error;
					json_t *query_info = json_loads(query, 0, &error);
					if(!query_info || !json_is_object(query_info)) {
						JANUS_LOG(LOG_WARN, "Ignoring invalid query response from the plugin\n");
					} else {
						json_object_set_new(info, "plugin_specific", query_info);
					}
					g_free(query);
					query = NULL;
				}
			}
		}
		json_t *flags = json_object();
		json_object_set_new(flags, "processing-offer", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER)));
		json_object_set_new(flags, "starting", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START)));
		json_object_set_new(flags, "ready", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)));
		json_object_set_new(flags, "stopped", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)));
		json_object_set_new(flags, "alert", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)));
		json_object_set_new(flags, "bundle", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)));
		json_object_set_new(flags, "rtcp-mux", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)));
		json_object_set_new(flags, "trickle", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)));
		json_object_set_new(flags, "all-trickles", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)));
		json_object_set_new(flags, "trickle-synced", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED)));
		json_object_set_new(flags, "data-channels", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)));
		json_object_set_new(flags, "plan-b", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)));
		json_object_set_new(flags, "cleaning", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)));
		json_object_set_new(info, "flags", flags);
		json_t *sdps = json_object();
		if(handle->local_sdp)
			json_object_set_new(sdps, "local", json_string(handle->local_sdp));
		if(handle->remote_sdp)
			json_object_set_new(sdps, "remote", json_string(handle->remote_sdp));
		json_object_set_new(info, "sdps", sdps);
		//~ json_object_set_new(info, "candidates-gathered", json_integer(handle->cdone));
		json_t *streams = json_array();
		if(handle->audio_stream) {
			json_t *s = janus_admin_stream_summary(handle->audio_stream);
			if(s)
				json_array_append_new(streams, s);
		}
		if(handle->video_stream) {
			json_t *s = janus_admin_stream_summary(handle->video_stream);
			if(s)
				json_array_append_new(streams, s);
		}
		if(handle->data_stream) {
			json_t *s = janus_admin_stream_summary(handle->data_stream);
			if(s)
				json_array_append_new(streams, s);
		}
		json_object_set_new(info, "streams", streams);
		janus_mutex_unlock(&handle->mutex);
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "handle_id", json_integer(handle_id));
		json_object_set_new(reply, "info", info);
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(reply);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
		goto jsondone;
	}

jsondone:
	json_decref(root);
	
	return ret;
}

int janus_ws_headers(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
	janus_http_msg *request = cls;
	JANUS_LOG(LOG_HUGE, "%s: %s\n", key, value);
	if(!strcasecmp(key, MHD_HTTP_HEADER_CONTENT_TYPE)) {
		if(request)
			request->contenttype = strdup(value);
	} else if(!strcasecmp(key, "Access-Control-Request-Method")) {
		if(request)
			request->acrm = strdup(value);
	} else if(!strcasecmp(key, "Access-Control-Request-Headers")) {
		if(request)
			request->acrh = strdup(value);
	}
	return MHD_YES;
}

void janus_ws_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
	JANUS_LOG(LOG_VERB, "Request completed, freeing data\n");
	janus_http_msg *request = *con_cls;
	if(!request)
		return;
	if(request->payload != NULL)
		free(request->payload);
	if(request->contenttype != NULL)
		free(request->contenttype);
	if(request->acrh != NULL)
		free(request->acrh);
	if(request->acrm != NULL)
		free(request->acrm);
	free(request);
	*con_cls = NULL;   
}

/* Worker to handle notifications */
int janus_ws_notifier(janus_request_source *source, int max_events) {
	if(!source || source->type != JANUS_SOURCE_PLAIN_HTTP)
		return MHD_NO;
	struct MHD_Connection *connection = (struct MHD_Connection *)source->source;
	janus_http_msg *msg = (janus_http_msg *)source->msg;
	if(!connection || !msg)
		return MHD_NO;
	if(max_events < 1)
		max_events = 1;
	JANUS_LOG(LOG_VERB, "... handling long poll...\n");
	janus_http_event *event = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;
	guint64 session_id = msg->session_id;
	janus_session *session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response(response);
		return ret;
	}
	gint64 start = janus_get_monotonic_time();
	gint64 end = 0;
	json_t *list = NULL;
	gboolean found = FALSE;
	/* We have a timeout for the long poll: 30 seconds */
	while(end-start < 30*G_USEC_PER_SEC) {
		event = g_async_queue_try_pop(session->messages);
		if(!session || session->destroy || g_atomic_int_get(&stop) || event != NULL) {
			if(event == NULL)
				break;
			/* Gotcha! */
			found = TRUE;
			if(max_events == 1) {
				break;
			} else {
				/* The application is willing to receive more events at the same time, anything to report? */
				list = json_array();
				json_error_t error;
				if(event->payload) {
					json_t *ev = json_loads(event->payload, 0, &error);
					if(ev && json_is_object(ev))	/* FIXME Should we fail if this is not valid JSON? */
						json_array_append_new(list, ev);
					g_free(event->payload);
					event->payload = NULL;
				}
				g_free(event);
				event = NULL;
				int events = 1;
				while(events < max_events) {
					event = g_async_queue_try_pop(session->messages);
					if(event == NULL)
						break;
					if(event->payload) {
						json_t *ev = json_loads(event->payload, 0, &error);
						if(ev && json_is_object(ev))	/* FIXME Should we fail if this is not valid JSON? */
							json_array_append_new(list, ev);
						g_free(event->payload);
						event->payload = NULL;
					}
					g_free(event);
					event = NULL;
					events++;
				}
				break;
			}
		}
		/* Sleep 100ms */
		g_usleep(100000);
		end = janus_get_monotonic_time();
	}
	if(!found) {
		JANUS_LOG(LOG_VERB, "Long poll time out for session %"SCNu64"...\n", session_id);
		event = (janus_http_event *)calloc(1, sizeof(janus_http_event));
		if(event == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			return ret;
		}
		event->code = 200;
		/*! \todo Improve the Janus protocol keep-alive mechanism in JavaScript */
		event->payload = g_strdup (max_events == 1 ? "{\"janus\" : \"keepalive\"}" : "[{\"janus\" : \"keepalive\"}]");
		event->allocated = 0;
	}
	if(list != NULL) {
		event = (janus_http_event *)calloc(1, sizeof(janus_http_event));
		if(event == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response(response);
			return ret;
		}
		event->code = 200;
		char *event_text = json_dumps(list, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(list);
		event->payload = event_text;
		event->allocated = 1;
	}
	/* Finish the request by sending the response */
	JANUS_LOG(LOG_VERB, "We have a message to serve...\n\t%s\n", event->payload);
	/* Send event */
	char *payload = g_strdup(event ? (event->payload ? event->payload : "") : "");
	if(payload == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response(response);
		if(event->payload && event->allocated) {
			g_free(event->payload);
			event->payload = NULL;
		}
		g_free(event);
		return ret;
	}
	ret = janus_process_success(source, NULL, payload);
	if(event != NULL) {
		if(event->payload && event->allocated) {
			g_free(event->payload);
			event->payload = NULL;
		}
		g_free(event);
	}
	return ret;
}

int janus_process_success(janus_request_source *source, const char *transaction, char *payload)
{
	if(!source || !payload)
		return MHD_NO;
	if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
		struct MHD_Connection *connection = (struct MHD_Connection *)source->source;
		janus_http_msg *msg = (janus_http_msg *)source->msg;
		if(!connection || !msg) {
			g_free(payload);
			return MHD_NO;
		}
		/* Send the reply */
		struct MHD_Response *response = MHD_create_response_from_data(
			strlen(payload),
			(void*) payload,
			MHD_YES,
			MHD_NO);
		MHD_add_response_header(response, "Content-Type", "application/json");
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	} else if(source->type == JANUS_SOURCE_WEBSOCKETS) {
#ifdef HAVE_WEBSOCKETS
		janus_websocket_client *client = (janus_websocket_client *)source->source;
		g_async_queue_push(client->responses, payload);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "WebSockets support not compiled\n");
		g_free(payload);
		return MHD_NO;
#endif
	} else if(source->type == JANUS_SOURCE_RABBITMQ) {
#ifdef HAVE_RABBITMQ
		/* FIXME Add to the queue of outgoing responses */
		janus_rabbitmq_response *response = (janus_rabbitmq_response *)calloc(1, sizeof(janus_rabbitmq_response));
		response->payload = payload;
		response->correlation_id = (char *)source->msg;
		g_async_queue_push(rmq_client->responses, response);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "RabbitMQ support not compiled\n");
		g_free(payload);
		return MHD_NO;
#endif
	} else {
		/* WTF? */
		g_free(payload);
		return MHD_NO;
	}
}

int janus_process_error(janus_request_source *source, uint64_t session_id, const char *transaction, gint error, const char *format, ...)
{
	if(!source)
		return MHD_NO;
	gchar *error_string = NULL;
	if(format == NULL) {
		/* No error string provided, use the default one */
		error_string = (gchar *)janus_get_api_error(error);
	} else {
		/* This callback has variable arguments (error string) */
		va_list ap;
		va_start(ap, format);
		/* FIXME 512 should be enough, but anyway... */
		error_string = calloc(512, sizeof(char));
		if(error_string == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
				struct MHD_Connection *connection = (struct MHD_Connection *)source->source;
				janus_http_msg *msg = (janus_http_msg *)source->msg;
				if(!connection || !msg)
					return MHD_NO;
				struct MHD_Response *response = MHD_create_response_from_data(0, NULL, MHD_NO, MHD_NO);
				int ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
				MHD_destroy_response(response);
				return ret;
			} else if(source->type == JANUS_SOURCE_WEBSOCKETS || source->type == JANUS_SOURCE_RABBITMQ) {
				/* TODO We should send an error to the client... */
				return MHD_NO;
			} else {
				/* WTF? */
				return MHD_NO;
			}
		}
		vsprintf(error_string, format, ap);
		va_end(ap);
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
	json_object_set_new(error_data, "reason", json_string(error_string ? error_string : "no text"));
	json_object_set_new(reply, "error", error_data);
	/* Convert to a string */
	char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(reply);
	if(format != NULL && error_string != NULL)
		free(error_string);
	/* Send the error */
	if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
		struct MHD_Connection *connection = (struct MHD_Connection *)source->source;
		janus_http_msg *msg = (janus_http_msg *)source->msg;
		if(!connection || !msg) {
			g_free(reply_text);
			return MHD_NO;
		}
		struct MHD_Response *response = MHD_create_response_from_data(
			strlen(reply_text),
			(void*)reply_text,
			MHD_YES,
			MHD_NO);
		MHD_add_response_header(response, "Content-Type", "application/json");
		MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
		if(msg->acrm)
			MHD_add_response_header(response, "Access-Control-Allow-Methods", msg->acrm);
		if(msg->acrh)
			MHD_add_response_header(response, "Access-Control-Allow-Headers", msg->acrh);
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	} else if(source->type == JANUS_SOURCE_WEBSOCKETS) {
#ifdef HAVE_WEBSOCKETS
		janus_websocket_client *client = (janus_websocket_client *)source->source;
		g_async_queue_push(client->responses, reply_text);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "WebSockets support not compiled\n");
		g_free(reply_text);
		return MHD_NO;
#endif
	} else if(source->type == JANUS_SOURCE_RABBITMQ) {
#ifdef HAVE_RABBITMQ
		/* FIXME Add to the queue of outgoing responses */
		janus_rabbitmq_response *response = (janus_rabbitmq_response *)calloc(1, sizeof(janus_rabbitmq_response));
		response->payload = reply_text;
		response->correlation_id = (char *)source->msg;
		g_async_queue_push(rmq_client->responses, response);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "RabbitMQ support not compiled\n");
		g_free(reply_text);
		return MHD_NO;
#endif
	} else {
		/* WTF? */
		g_free(reply_text);
		return MHD_NO;
	}
}


#ifdef HAVE_WEBSOCKETS
/* WebSockets */
int janus_wss_onopen(libwebsock_client_state *state) {
	JANUS_LOG(LOG_INFO, "WebSocket onopen: #%d\n", state->sockfd);
	janus_mutex_lock(&wss_mutex);
	if(g_hash_table_lookup(wss_sessions, state) != NULL) {
		JANUS_LOG(LOG_WARN, "  -- Client already handled\n");
		janus_mutex_unlock(&wss_mutex);
		return 0;
	}
	/* Create a new janus_websocket_client instance */
	janus_websocket_client *ws_client = calloc(1, sizeof(janus_websocket_client));
	if(ws_client == NULL) {
		janus_mutex_unlock(&wss_mutex);
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		libwebsock_close(state);
		return 0;
	}
	/* Create a thread pool to handle incoming requests */
	GError *error = NULL;
	GThreadPool *thread_pool = g_thread_pool_new(janus_wss_task, ws_client, -1, FALSE, &error);
	if(error != NULL) {
		/* Something went wrong... */
		g_free(ws_client);
		janus_mutex_unlock(&wss_mutex);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the pool thread...\n", error->code, error->message ? error->message : "??");
		libwebsock_close(state);
		return 0;
	}
	ws_client->thread_pool = thread_pool;
	ws_client->state = state;
	ws_client->responses = g_async_queue_new();
	ws_client->sessions = NULL;
	/* Create a thread for notifications related to this session as well */
	ws_client->thread = g_thread_try_new("wss_client", &janus_wss_thread, ws_client, &error);
	if(error != NULL) {
		/* Something went wrong... */
		g_free(ws_client);
		janus_mutex_unlock(&wss_mutex);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the notifications thread...\n", error->code, error->message ? error->message : "??");
		libwebsock_close(state);
		return 0;
 	}
	ws_client->destroy = 0;
	janus_mutex_init(&ws_client->mutex);
	
	g_hash_table_insert(wss_sessions, state, ws_client);
	janus_mutex_unlock(&wss_mutex);

	return 0;
}

int janus_wss_onmessage(libwebsock_client_state *state, libwebsock_message *msg) {
	JANUS_LOG(LOG_VERB, "WebSocket onmessage: #%d\n", state->sockfd);
	JANUS_LOG(LOG_HUGE, "  -- Message opcode: %d\n", msg->opcode);
	JANUS_LOG(LOG_HUGE, "  -- Payload Length: %llu\n", msg->payload_len);
	JANUS_LOG(LOG_HUGE, "  -- Payload: %s\n", msg->payload);

	janus_mutex_lock(&wss_mutex);
	janus_websocket_client *client = g_hash_table_lookup(wss_sessions, state);
	janus_mutex_unlock(&wss_mutex);
	if(client == NULL) {
		/* Sometimes we get onmessage before onclose */
		JANUS_LOG(LOG_INFO, "Received a WebSocket message, but can't find a client associated to it, creating it now...\n");
		janus_wss_onopen(state);
		/* Let's try again */
		janus_mutex_lock(&wss_mutex);
		client = g_hash_table_lookup(wss_sessions, state);
		janus_mutex_unlock(&wss_mutex);
		if(client == NULL) {
			JANUS_LOG(LOG_ERR, "Still no client, giving up...\n");
			libwebsock_close(state);
			return 0;
		}
	}
	/* Parse it */
	janus_request_source *source = janus_request_source_new(JANUS_SOURCE_WEBSOCKETS, (void *)client, (void *)msg);
	/* Parse the JSON payload */
	json_error_t error;
	json_t *root = json_loads(msg->payload, 0, &error);
	if(!root) {
		janus_process_error(source, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s", error.line, error.text);
		janus_request_source_destroy(source);
		return 0;
	}
	if(!json_is_object(root)) {
		janus_process_error(source, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		janus_request_source_destroy(source);
		json_decref(root);
		return 0;
	}
	/* Parse the request now */
	janus_websocket_request *request = (janus_websocket_request *)calloc(1, sizeof(janus_websocket_request));
	request->source = source;
	request->request = root;
	GError *tperror = NULL;
	g_thread_pool_push(client->thread_pool, request, &tperror);
	if(tperror != NULL) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to push task in thread pool...\n", tperror->code, tperror->message ? tperror->message : "??");
		json_t *transaction = json_object_get(root, "transaction");
		const char *transaction_text = json_is_string(transaction) ? json_string_value(transaction) : NULL;
		janus_process_error(source, 0, transaction_text, JANUS_ERROR_UNKNOWN, "Thread pool error");
		janus_request_source_destroy(source);
		json_decref(root);
	}
	return 0;
}

int janus_wss_onclose(libwebsock_client_state *state) {
	JANUS_LOG(LOG_INFO, "WebSocket onclose: #%d\n", state->sockfd);

	janus_mutex_lock(&wss_mutex);
	janus_websocket_client *client = g_hash_table_lookup(wss_sessions, state);
	g_hash_table_remove(wss_sessions, state);
	if(client != NULL) {
		JANUS_LOG(LOG_INFO, "Destroying WebSocket client #%d\n", state->sockfd);
		client->destroy = 1;
		g_thread_pool_free(client->thread_pool, FALSE, FALSE);
		if(client->thread != NULL) {
			JANUS_LOG(LOG_INFO, "Joining thread #%d\n", state->sockfd);
			g_thread_join(client->thread);
		}
		client->thread = NULL;
		client->state = NULL;
		if(client->sessions != NULL && g_hash_table_size(client->sessions) > 0) {
			/* Remove all sessions (and handles) created by this client */
			janus_mutex_lock(&sessions_mutex);
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, client->sessions);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_session *session = value;
				if(!session)
					continue;
				session->last_activity = 0;	/* This will trigger a timeout */
			}
			janus_mutex_unlock(&sessions_mutex);
			g_hash_table_destroy(client->sessions);
		}
		/* Remove responses queue too, if needed */
		if(client->responses != NULL) {
			char *response = NULL;
			while((response = g_async_queue_try_pop(client->responses)) != NULL) {
				g_free(response);
			}
			g_async_queue_unref(client->responses);
		}
		client->sessions = NULL;
		g_free(client);
		client = NULL;
	}
	janus_mutex_unlock(&wss_mutex);
	
	JANUS_LOG(LOG_INFO, "  -- closed\n");
	return 0;
}

void *janus_wss_thread(void *data) {
	janus_websocket_client *client = (janus_websocket_client *)data;
	if(client == NULL) {
		JANUS_LOG(LOG_ERR, "No WebSocket client??\n");
		return NULL;
	}
	int fd = client->state->sockfd;
	JANUS_LOG(LOG_INFO, "Joining WebSocket thread: #%d\n", fd);
	while(!client->destroy && !g_atomic_int_get(&stop)) {
		janus_mutex_lock(&client->mutex);
		/* Responses first */
		char *response = NULL;
		while ((response = g_async_queue_try_pop(client->responses)) != NULL) {
			if(!client->destroy && !g_atomic_int_get(&stop) && response) {
				/* Gotcha! */
				JANUS_LOG(LOG_VERB, "#%d: Sending response (%zu bytes)...\n", fd, strlen(response));
				int res = libwebsock_send_text(client->state, response);
				JANUS_LOG(LOG_VERB, "#%d  -- Sent (res=%d)\n", fd, res);
			}
			g_free(response);
		}
		/* Now iterate on all the sessions handled by this WebSocket client */
		if(client->sessions != NULL && g_hash_table_size(client->sessions) > 0) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, client->sessions);
			while (g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_session *session = value;
				if(client->destroy || !session || session->destroy || g_atomic_int_get(&stop)) {
					continue;
				}
				janus_http_event *event;
				while ((event = g_async_queue_try_pop(session->messages)) != NULL) {
					if(!client->destroy && session && !session->destroy && !g_atomic_int_get(&stop) && event && event->payload) {
						/* Gotcha! */
						JANUS_LOG(LOG_VERB, "#%d: Sending event (%zu bytes)...\n", fd, strlen(event->payload));
						int res = libwebsock_send_text(client->state, event->payload);
						JANUS_LOG(LOG_VERB, "#%d  -- Sent (res=%d)\n", fd, res);
					}
				}
				if(session->timeout) {
					/* Close the websocket */
					libwebsock_close(client->state);
					//~ janus_wss_onclose(client->state);
					break;
				}
			}
		}
		janus_mutex_unlock(&client->mutex);
		/* Sleep 100ms */
		g_usleep(100000);
	}
	JANUS_LOG(LOG_INFO, "Leaving WebSocket thread: #%d\n", fd);
	return NULL;
}

void janus_wss_task(gpointer data, gpointer user_data) {
	JANUS_LOG(LOG_VERB, "Thread pool, serving request\n");
	janus_websocket_request *request = (janus_websocket_request *)data;
	janus_websocket_client *client = (janus_websocket_client *)data;
	if(request == NULL || client == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or client\n");
		return;
	}
	janus_request_source *source = (janus_request_source *)request->source;
	json_t *root = (json_t *)request->request;
	janus_process_incoming_request(source, root);
	janus_request_source_destroy(source);
	request->source = NULL;
	request->request = NULL;
	g_free(request);
}
#endif


#ifdef HAVE_RABBITMQ
void *janus_rmq_in_thread(void *data) {
	if(rmq_client == NULL) {
		JANUS_LOG(LOG_ERR, "No RabbitMQ connection??\n");
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Joining RabbitMQ in thread\n");

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 20000;
	amqp_frame_t frame;
	while(!rmq_client->destroy && !g_atomic_int_get(&stop)) {
		amqp_maybe_release_buffers(rmq_conn);
		/* Wait for a frame */
		int res = amqp_simple_wait_frame_noblock(rmq_conn, &frame, &timeout);
		if(res != AMQP_STATUS_OK) {
			/* No data */
			if(res == AMQP_STATUS_TIMEOUT)
				continue;
			JANUS_LOG(LOG_VERB, "Error on amqp_simple_wait_frame_noblock: %d (%s)\n", res, amqp_error_string2(res));
			break;
		}
		/* We expect method first */
		JANUS_LOG(LOG_VERB, "Frame type %d, channel %d\n", frame.frame_type, frame.channel);
		if(frame.frame_type != AMQP_FRAME_METHOD)
			continue;
		JANUS_LOG(LOG_VERB, "Method %s\n", amqp_method_name(frame.payload.method.id));
		if(frame.payload.method.id == AMQP_BASIC_DELIVER_METHOD) {
			amqp_basic_deliver_t *d = (amqp_basic_deliver_t *)frame.payload.method.decoded;
			JANUS_LOG(LOG_VERB, "Delivery #%u, %.*s\n", (unsigned) d->delivery_tag, (int) d->routing_key.len, (char *) d->routing_key.bytes);
		}
		/* Then the header */
		amqp_simple_wait_frame(rmq_conn, &frame);
		JANUS_LOG(LOG_VERB, "Frame type %d, channel %d\n", frame.frame_type, frame.channel);
		if(frame.frame_type != AMQP_FRAME_HEADER)
			continue;
		amqp_basic_properties_t *p = (amqp_basic_properties_t *)frame.payload.properties.decoded;
		if(p->_flags & AMQP_BASIC_REPLY_TO_FLAG) {
			JANUS_LOG(LOG_VERB, "  -- Reply-to: %.*s\n", (int) p->reply_to.len, (char *) p->reply_to.bytes);
		}
		char *correlation = NULL;
		if(p->_flags & AMQP_BASIC_CORRELATION_ID_FLAG) {
			correlation = (char *)calloc(p->correlation_id.len+1, sizeof(char));
			sprintf(correlation, "%.*s", (int) p->correlation_id.len, (char *) p->correlation_id.bytes);
			JANUS_LOG(LOG_VERB, "  -- Correlation-id: %s\n", correlation);
		}
		if(p->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
			JANUS_LOG(LOG_VERB, "  -- Content-type: %.*s\n", (int) p->content_type.len, (char *) p->content_type.bytes);
		}
		/* And the body */
		uint64_t total = frame.payload.properties.body_size, received = 0;
		char *payload = (char *)calloc(total+1, sizeof(char)), *index = payload;
		while(received < total) {
			amqp_simple_wait_frame(rmq_conn, &frame);
			JANUS_LOG(LOG_VERB, "Frame type %d, channel %d\n", frame.frame_type, frame.channel);
			if(frame.frame_type != AMQP_FRAME_BODY)
				break;
			sprintf(index, "%.*s", (int) frame.payload.body_fragment.len, (char *) frame.payload.body_fragment.bytes);
			received += frame.payload.body_fragment.len;
			index = payload+received;
		}
		JANUS_LOG(LOG_VERB, "Got %"SCNu64"/%"SCNu64" bytes (%"SCNu64")\n", received, total, frame.payload.body_fragment.len);
		JANUS_LOG(LOG_HUGE, "%s\n", payload);
		/* Parse it */
		janus_request_source *source = janus_request_source_new(JANUS_SOURCE_RABBITMQ, (void *)rmq_client, (void *)correlation);
		/* Parse the JSON payload */
		json_error_t error;
		json_t *root = json_loads(payload, 0, &error);
		if(!root) {
			janus_process_error(source, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s", error.line, error.text);
			g_free(payload);
			continue;
		}
		if(!json_is_object(root)) {
			janus_process_error(source, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
			g_free(payload);
			json_decref(root);
			continue;
		}
		g_free(payload);
		/* Parse the request now */
		janus_rabbitmq_request *request = (janus_rabbitmq_request *)calloc(1, sizeof(janus_rabbitmq_request));
		request->source = source;
		request->request = root;
		GError *tperror = NULL;
		g_thread_pool_push(rmq_client->thread_pool, request, &tperror);
		if(tperror != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to push task in thread pool...\n", tperror->code, tperror->message ? tperror->message : "??");
		}
	}
	JANUS_LOG(LOG_INFO, "Leaving RabbitMQ in thread\n");
	return NULL;
}

void *janus_rmq_out_thread(void *data) {
	if(rmq_client == NULL) {
		JANUS_LOG(LOG_ERR, "No RabbitMQ connection??\n");
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Joining RabbitMQ out thread\n");
	while(!rmq_client->destroy && !g_atomic_int_get(&stop)) {
		janus_mutex_lock(&rmq_client->mutex);
		/* We send responses from here as well, not only notifications */
		janus_rabbitmq_response *response = NULL;
		while ((response = g_async_queue_try_pop(rmq_client->responses)) != NULL) {
			if(!g_atomic_int_get(&stop) && response && response->payload) {
				/* Gotcha! */
				JANUS_LOG(LOG_VERB, "Sending response to RabbitMQ (%zu bytes)...\n", strlen(response->payload));
				JANUS_LOG(LOG_HUGE, "%s\n", response->payload);
				amqp_basic_properties_t props;
				props._flags = 0;
				props._flags |= AMQP_BASIC_REPLY_TO_FLAG;
				props.reply_to = amqp_cstring_bytes("Janus");
				if(response->correlation_id) {
					props._flags |= AMQP_BASIC_CORRELATION_ID_FLAG;
					props.correlation_id = amqp_cstring_bytes(response->correlation_id);
				}
				props._flags |= AMQP_BASIC_CONTENT_TYPE_FLAG;
				props.content_type = amqp_cstring_bytes("application/json");
				amqp_bytes_t message = amqp_cstring_bytes(response->payload);
				int status = amqp_basic_publish(rmq_conn, rmq_channel, amqp_empty_bytes, from_janus_queue, 0, 0, &props, message);
				if(status != AMQP_STATUS_OK) {
					JANUS_LOG(LOG_ERR, "Error publishing... %d, %s\n", status, amqp_error_string2(status));
				}
				g_free(response->correlation_id);
				response->correlation_id = NULL;
				g_free(response->payload);
				response->payload = NULL;
				g_free(response);
				response = NULL;
			}
		}
		if(rmq_client->sessions != NULL && g_hash_table_size(rmq_client->sessions) > 0) {
			/* Iterate on all the sessions handled by this rmq_client */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, rmq_client->sessions);
			while (g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_session *session = value;
				if(rmq_client->destroy || !session || session->destroy || g_atomic_int_get(&stop)) {
					continue;
				}
				janus_http_event *event;
				while ((event = g_async_queue_try_pop(session->messages)) != NULL) {
					if(!rmq_client->destroy && session && !session->destroy && !g_atomic_int_get(&stop) && event && event->payload) {
						/* Gotcha! */
						JANUS_LOG(LOG_VERB, "Sending event to RabbitMQ (%zu bytes)...\n", strlen(event->payload));
						JANUS_LOG(LOG_HUGE, "%s\n", event->payload);
						amqp_basic_properties_t props;
						props._flags = 0;
						props._flags |= AMQP_BASIC_REPLY_TO_FLAG;
						props.reply_to = amqp_cstring_bytes("Janus");
						props._flags |= AMQP_BASIC_CONTENT_TYPE_FLAG;
						props.content_type = amqp_cstring_bytes("application/json");
						amqp_bytes_t message = amqp_cstring_bytes(event->payload);
						int status = amqp_basic_publish(rmq_conn, rmq_channel, amqp_empty_bytes, from_janus_queue, 0, 0, &props, message);
						if(status != AMQP_STATUS_OK) {
							JANUS_LOG(LOG_ERR, "Error publishing... %d, %s\n", status, amqp_error_string2(status));
						}
					}
				}
				if(session->timeout) {
					/* A session timed out, anything we should do? */
					continue;
				}
			}
		}
		janus_mutex_unlock(&rmq_client->mutex);
		/* Sleep 100ms */
		g_usleep(100000);
	}
	JANUS_LOG(LOG_INFO, "Leaving RabbitMQ out thread\n");
	return NULL;
}

void janus_rmq_task(gpointer data, gpointer user_data) {
	JANUS_LOG(LOG_VERB, "Thread pool, serving request\n");
	janus_rabbitmq_request *request = (janus_rabbitmq_request *)data;
	janus_rabbitmq_client *client = (janus_rabbitmq_client *)data;
	if(request == NULL || client == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or client\n");
		return;
	}
	janus_request_source *source = (janus_request_source *)request->source;
	json_t *root = (json_t *)request->request;
	janus_process_incoming_request(source, root);
	janus_request_source_destroy(source);
	request->source = NULL;
	request->request = NULL;
	g_free(request);
}
#endif


/* Admin/monitor helpers */
json_t *janus_admin_stream_summary(janus_ice_stream *stream) {
	if(stream == NULL)
		return NULL;
	json_t *s = json_object();
	json_object_set_new(s, "id", json_integer(stream->stream_id));
	json_object_set_new(s, "ready", json_integer(stream->cdone));
	json_object_set_new(s, "disabled", json_string(stream->disabled ? "true" : "false"));
	json_t *ss = json_object();
	if(stream->audio_ssrc)
		json_object_set_new(ss, "audio", json_integer(stream->audio_ssrc));
	if(stream->video_ssrc)
		json_object_set_new(ss, "video", json_integer(stream->video_ssrc));
	if(stream->audio_ssrc_peer)
		json_object_set_new(ss, "audio-peer", json_integer(stream->audio_ssrc_peer));
	if(stream->video_ssrc_peer)
		json_object_set_new(ss, "video-peer", json_integer(stream->video_ssrc_peer));
	json_object_set_new(s, "ssrc", ss);
	json_t *components = json_array();
	if(stream->rtp_component) {
		json_t *c = janus_admin_component_summary(stream->rtp_component);
		if(c)
			json_array_append_new(components, c);
	}
	if(stream->rtcp_component) {
		json_t *c = janus_admin_component_summary(stream->rtcp_component);
		if(c)
			json_array_append_new(components, c);
	}
	json_object_set_new(s, "components", components);
	return s;
}

json_t *janus_admin_component_summary(janus_ice_component *component) {
	if(component == NULL)
		return NULL;
	json_t *c = json_object();
	json_object_set_new(c, "id", json_integer(component->component_id));
	json_object_set_new(c, "state", json_string(janus_get_ice_state_name(component->state)));
	if(component->local_candidates) {
		json_t *cs = json_array();
		GSList *candidates = component->local_candidates, *i = NULL;
		for (i = candidates; i; i = i->next) {
			gchar *lc = (gchar *) i->data;
			if(lc)
				json_array_append_new(cs, json_string(lc));
		}
		json_object_set_new(c, "local-candidates", cs);
	}
	if(component->remote_candidates) {
		json_t *cs = json_array();
		GSList *candidates = component->remote_candidates, *i = NULL;
		for (i = candidates; i; i = i->next) {
			gchar *rc = (gchar *) i->data;
			if(rc)
				json_array_append_new(cs, json_string(rc));
		}
		json_object_set_new(c, "remote-candidates", cs);
	}
	if(component->selected_pair) {
		json_object_set_new(c, "selected-pair", json_string(component->selected_pair));
	}
	json_t *d = json_object();
	json_t *in_stats = json_object();
	json_t *out_stats = json_object();
	if(component->dtls) {
		janus_dtls_srtp *dtls = component->dtls;
		json_object_set_new(d, "fingerprint", json_string(janus_dtls_get_local_fingerprint()));
		json_object_set_new(d, "remote-fingerprint", json_string(component->stream->handle->remote_fingerprint));
		json_object_set_new(d, "dtls-role", json_string(janus_get_dtls_srtp_role(component->stream->dtls_role)));
		json_object_set_new(d, "dtls-state", json_string(janus_get_dtls_srtp_state(dtls->dtls_state)));
		json_object_set_new(d, "valid", json_integer(dtls->srtp_valid));
		json_object_set_new(d, "ready", json_integer(dtls->ready));
		json_object_set_new(in_stats, "audio_bytes", json_integer(component->in_stats.audio_bytes));
		json_object_set_new(in_stats, "video_bytes", json_integer(component->in_stats.video_bytes));
		json_object_set_new(in_stats, "data_bytes", json_integer(component->in_stats.data_bytes));
		json_object_set_new(in_stats, "audio_nacks", json_integer(component->in_stats.audio_nacks));
		json_object_set_new(in_stats, "video_nacks", json_integer(component->in_stats.video_nacks));
		json_object_set_new(out_stats, "audio_bytes", json_integer(component->out_stats.audio_bytes));
		json_object_set_new(out_stats, "video_bytes", json_integer(component->out_stats.video_bytes));
		json_object_set_new(out_stats, "data_bytes", json_integer(component->out_stats.data_bytes));
		json_object_set_new(out_stats, "audio_nacks", json_integer(component->out_stats.audio_nacks));
		json_object_set_new(out_stats, "video_nacks", json_integer(component->out_stats.video_nacks));
		/* Compute the last second stuff too */
		gint64 now = janus_get_monotonic_time();
		guint64 bytes = 0;
		if(component->in_stats.audio_bytes_lastsec) {
			GList *lastsec = component->in_stats.audio_bytes_lastsec;
			while(lastsec) {
				janus_ice_stats_item *s = (janus_ice_stats_item *)lastsec->data;
				if(s && now-s->when < G_USEC_PER_SEC)
					bytes += s->bytes;
				lastsec = lastsec->next;
			}
		}
		json_object_set_new(in_stats, "audio_bytes_lastsec", json_integer(bytes));
		bytes = 0;
		if(component->in_stats.video_bytes_lastsec) {
			GList *lastsec = component->in_stats.video_bytes_lastsec;
			while(lastsec) {
				janus_ice_stats_item *s = (janus_ice_stats_item *)lastsec->data;
				if(s && now-s->when < G_USEC_PER_SEC)
					bytes += s->bytes;
				lastsec = lastsec->next;
			}
		}
		json_object_set_new(in_stats, "video_bytes_lastsec", json_integer(bytes));
#ifdef HAVE_SCTP
		if(dtls->sctp)	/* FIXME */
			json_object_set_new(d, "sctp-association", json_integer(1));
#endif
	}
	json_object_set_new(c, "dtls", d);
	json_object_set_new(c, "in_stats", in_stats);
	json_object_set_new(c, "out_stats", out_stats);
	return c;
}

/* Plugins */
void janus_plugin_close(gpointer key, gpointer value, gpointer user_data) {
	janus_plugin *plugin = (janus_plugin *)value;
	if(!plugin)
		return;
	plugin->destroy();
}

void janus_pluginso_close(gpointer key, gpointer value, gpointer user_data) {
	void *plugin = (janus_plugin *)value;
	if(!plugin)
		return;
	//~ dlclose(plugin);
}

janus_plugin *janus_plugin_find(const gchar *package) {
	if(package != NULL && plugins != NULL)	/* FIXME Do we need to fix the key pointer? */
		return g_hash_table_lookup(plugins, package);
	return NULL;
}


/* Plugin callback interface */
int janus_push_event(janus_plugin_session *handle, janus_plugin *plugin, const char *transaction, const char *message, const char *sdp_type, const char *sdp) {
	if(!plugin || !message)
		return -1;
	if(!handle || handle->stopped)
		return -2;
	janus_ice_handle *ice_handle = (janus_ice_handle *)handle->gateway_handle;
	if(!ice_handle || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP))
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = ice_handle->session;
	if(!session || session->destroy)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	/* Make sure this is JSON */
	json_error_t error;
	json_t *event = json_loads(message, 0, &error);
	if(!event) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: on line %d: %s)\n", ice_handle->handle_id, error.line, error.text);
		return JANUS_ERROR_INVALID_JSON;
	}
	if(!json_is_object(event)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: not an object)\n", ice_handle->handle_id);
		return JANUS_ERROR_INVALID_JSON_OBJECT;
	}
	/* Attach JSEP if possible? */
	json_t *jsep = NULL;
	if(sdp_type != NULL && sdp != NULL) {
		jsep = janus_handle_sdp(handle, plugin, sdp_type, sdp);
		if(jsep == NULL) {
			if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
					|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (handle not available anymore or negotiation stopped)\n", ice_handle->handle_id);
				return JANUS_ERROR_HANDLE_NOT_FOUND;
			} else {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: problem with the SDP)\n", ice_handle->handle_id);
				return JANUS_ERROR_JSEP_INVALID_SDP;
			}
		}
	}
	/* Prepare JSON event */
	json_t *reply = json_object();
	json_object_set_new(reply, "janus", json_string("event"));
	json_object_set_new(reply, "session_id", json_integer(session->session_id));
	json_object_set_new(reply, "sender", json_integer(ice_handle->handle_id));
	if(transaction != NULL)
		json_object_set_new(reply, "transaction", json_string(transaction));
	json_t *plugin_data = json_object();
	json_object_set_new(plugin_data, "plugin", json_string(plugin->get_package()));
	json_object_set(plugin_data, "data", event);
	json_object_set(reply, "plugindata", plugin_data);
	if(jsep != NULL)
		json_object_set(reply, "jsep", jsep);
	/* Convert to a string */
	char *reply_text = json_dumps(reply, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	json_decref(plugin_data);
	if(jsep != NULL)
		json_decref(jsep);
	json_decref(reply);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", ice_handle->handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return JANUS_ERROR_UNKNOWN;	/* FIXME Do we need something like "Internal Server Error"? */
	}
	notification->code = 200;
	notification->payload = reply_text;
	notification->allocated = 1;

	g_async_queue_push(session->messages, notification);

	return JANUS_OK;
}

json_t *janus_handle_sdp(janus_plugin_session *handle, janus_plugin *plugin, const char *sdp_type, const char *sdp) {
	if(handle == NULL || handle->stopped || plugin == NULL || sdp_type == NULL || sdp == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid arguments\n");
		return NULL;
	}
	int offer = 0;
	if(!strcasecmp(sdp_type, "offer")) {
		/* This is an offer from a plugin */
		offer = 1;
	} else if(!strcasecmp(sdp_type, "answer")) {
		/* This is an answer from a plugin */
	} else {
		/* TODO Handle other messages */
		JANUS_LOG(LOG_ERR, "Unknown type '%s'\n", sdp_type);
		return NULL;
	}
	janus_ice_handle *ice_handle = (janus_ice_handle *)handle->gateway_handle;
	//~ if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
	if(ice_handle == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid ICE handle\n");
		return NULL;
	}
	/* Is this valid SDP? */
	int audio = 0, video = 0, data = 0, bundle = 0, rtcpmux = 0, trickle = 0;
	janus_sdp *parsed_sdp = janus_sdp_preparse(sdp, &audio, &video, &data, &bundle, &rtcpmux, &trickle);
	if(parsed_sdp == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Couldn't parse SDP...\n", ice_handle->handle_id);
		return NULL;
	}
	janus_sdp_free(parsed_sdp);
	gboolean updating = FALSE;
	if(offer) {
		/* We still don't have a local ICE setup */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio %s been negotiated\n", ice_handle->handle_id, audio ? "has" : "has NOT");
		if(audio > 1) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one audio line? only going to negotiate one...\n", ice_handle->handle_id);
		}
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video %s been negotiated\n", ice_handle->handle_id, video ? "has" : "has NOT");
		if(video > 1) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one video line? only going to negotiate one...\n", ice_handle->handle_id);
		}
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] SCTP/DataChannels %s been negotiated\n", ice_handle->handle_id, data ? "have" : "have NOT");
		if(data > 1) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one data line? only going to negotiate one...\n", ice_handle->handle_id);
		}
#ifndef HAVE_SCTP
		if(data) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]   -- DataChannels have been negotiated, but support for them has not been compiled...\n", ice_handle->handle_id);
		}
#endif
		/* Are we still cleaning up from a previous media session? */
		if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", ice_handle->handle_id);
			gint64 waited = 0;
			while(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", ice_handle->handle_id);
				g_usleep(100000);
				waited += 100000;
				if(waited >= 3*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", ice_handle->handle_id);
					break;
				}
			}
		}
		if(ice_handle->agent == NULL) {
			/* Process SDP in order to setup ICE locally (this is going to result in an answer from the browser) */
			if(janus_ice_setup_local(ice_handle, 0, audio, video, data, bundle, rtcpmux, trickle) < 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error setting ICE locally\n", ice_handle->handle_id);
				return NULL;
			}
		} else {
			updating = TRUE;
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Updating existing session\n", ice_handle->handle_id);
		}
	}
	if(!updating) {
		/* Wait for candidates-done callback */
		while(ice_handle->cdone < ice_handle->streams_num) {
			if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
					|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Handle detached or PC closed, giving up...!\n", ice_handle ? ice_handle->handle_id : 0);
				return NULL;
			}
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Waiting for candidates-done callback...\n", ice_handle->handle_id);
			g_usleep(100000);
			if(ice_handle->cdone < 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates!\n", ice_handle->handle_id);
				return NULL;
			}
		}
	}
	/* Anonymize SDP */
	char *sdp_stripped = janus_sdp_anonymize(sdp);
	if(sdp_stripped == NULL) {
		/* Invalid SDP */
		JANUS_LOG(LOG_ERR, "Invalid SDP\n");
		return NULL;
	}
	/* Add our details */
	char *sdp_merged = janus_sdp_merge(ice_handle, sdp_stripped);
	if(sdp_merged == NULL) {
		/* Couldn't merge SDP */
		JANUS_LOG(LOG_ERR, "Error merging SDP\n");
		g_free(sdp_stripped);
		return NULL;
	}
	/* FIXME Any disabled m-line? */
	if(strstr(sdp_merged, "m=audio 0")) {
		JANUS_LOG(LOG_VERB, "Audio disabled via SDP\n");
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!video && !data)) {
			JANUS_LOG(LOG_VERB, "  -- Marking audio stream as disabled\n");
			janus_ice_stream *stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(ice_handle->audio_id));
			if(stream)
				stream->disabled = TRUE;
		}
	}
	if(strstr(sdp_merged, "m=video 0")) {
		JANUS_LOG(LOG_VERB, "Video disabled via SDP\n");
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!audio && !data)) {
			JANUS_LOG(LOG_VERB, "  -- Marking video stream as disabled\n");
			janus_ice_stream *stream = NULL;
			if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
				stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(ice_handle->video_id));
			} else {
				gint id = ice_handle->audio_id > 0 ? ice_handle->audio_id : ice_handle->video_id;
				stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(id));
			}
			if(stream)
				stream->disabled = TRUE;
		}
	}
	if(strstr(sdp_merged, "m=application 0 DTLS/SCTP")) {
		JANUS_LOG(LOG_VERB, "Data Channel disabled via SDP\n");
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!audio && !video)) {
			JANUS_LOG(LOG_VERB, "  -- Marking data channel stream as disabled\n");
			janus_ice_stream *stream = NULL;
			if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
				stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(ice_handle->data_id));
			} else {
				gint id = ice_handle->audio_id > 0 ? ice_handle->audio_id : (ice_handle->video_id > 0 ? ice_handle->video_id : ice_handle->data_id);
				stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(id));
			}
			if(stream)
				stream->disabled = TRUE;
		}
	}

	if(!updating) {
		if(offer) {
			/* We set the flag to wait for an answer before handling trickle candidates */
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
		} else {
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Done! Ready to setup remote candidates and send connectivity checks...\n", ice_handle->handle_id);
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) && audio && video) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- bundle is supported by the browser, getting rid of one of the RTP/RTCP components, if any...\n", ice_handle->handle_id);
				if(audio) {
					/* Get rid of video and data, if present */
					if(ice_handle->streams && ice_handle->video_stream) {
						ice_handle->audio_stream->video_ssrc = ice_handle->video_stream->video_ssrc;
						ice_handle->audio_stream->video_ssrc_peer = ice_handle->video_stream->video_ssrc_peer;
						janus_ice_stream_free(ice_handle->streams, ice_handle->video_stream);
					}
					ice_handle->video_stream = NULL;
					if(ice_handle->video_id > 0) {
						nice_agent_attach_recv (ice_handle->agent, ice_handle->video_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
						nice_agent_attach_recv (ice_handle->agent, ice_handle->video_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					}
					ice_handle->video_id = 0;
					if(ice_handle->streams && ice_handle->data_stream) {
						janus_ice_stream_free(ice_handle->streams, ice_handle->data_stream);
					}
					ice_handle->data_stream = NULL;
					if(ice_handle->data_id > 0) {
						nice_agent_attach_recv (ice_handle->agent, ice_handle->data_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					}
					ice_handle->data_id = 0;
				} else if(video) {
					/* Get rid of data, if present */
					if(ice_handle->streams && ice_handle->data_stream) {
						janus_ice_stream_free(ice_handle->streams, ice_handle->data_stream);
					}
					ice_handle->data_stream = NULL;
					if(ice_handle->data_id > 0) {
						nice_agent_attach_recv (ice_handle->agent, ice_handle->data_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					}
					ice_handle->data_id = 0;
				}
			}
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- rtcp-mux is supported by the browser, getting rid of RTCP components, if any...\n", ice_handle->handle_id);
				if(ice_handle->audio_stream && ice_handle->audio_stream->rtcp_component && ice_handle->audio_stream->components != NULL) {
					nice_agent_attach_recv (ice_handle->agent, ice_handle->audio_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					janus_ice_component_free(ice_handle->audio_stream->components, ice_handle->audio_stream->rtcp_component);
					ice_handle->audio_stream->rtcp_component = NULL;
				}
				if(ice_handle->video_stream && ice_handle->video_stream->rtcp_component && ice_handle->video_stream->components != NULL) {
					nice_agent_attach_recv (ice_handle->agent, ice_handle->video_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					janus_ice_component_free(ice_handle->video_stream->components, ice_handle->video_stream->rtcp_component);
					ice_handle->video_stream->rtcp_component = NULL;
				}
			}
			janus_mutex_lock(&ice_handle->mutex);
			/* Not trickling (anymore?), set remote candidates now */
			if(ice_handle->audio_id > 0) {
				janus_ice_setup_remote_candidates(ice_handle, ice_handle->audio_id, 1);
				if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
					janus_ice_setup_remote_candidates(ice_handle, ice_handle->audio_id, 2);
			}
			if(ice_handle->video_id > 0) {
				janus_ice_setup_remote_candidates(ice_handle, ice_handle->video_id, 1);
				if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))	/* http://tools.ietf.org/html/rfc5761#section-5.1.3 */
					janus_ice_setup_remote_candidates(ice_handle, ice_handle->video_id, 2);
			}
			if(ice_handle->data_id > 0) {
				janus_ice_setup_remote_candidates(ice_handle, ice_handle->data_id, 1);
			}
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) &&
					!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
				/* Still trickling, but take note of the fact ICE has started now */
				JANUS_LOG(LOG_VERB, "Still trickling, but we can start send connectivity checks already, now\n");
				janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
			}
			janus_mutex_unlock(&ice_handle->mutex);
		}
	}
	
	/* Prepare JSON event */
	json_t *jsep = json_object();
	json_object_set_new(jsep, "type", json_string(sdp_type));
	json_object_set_new(jsep, "sdp", json_string(sdp_merged));
	g_free(sdp_stripped);
	//~ g_free(sdp_merged);
	ice_handle->local_sdp = sdp_merged;
	return jsep;
}

void janus_relay_rtp(janus_plugin_session *plugin_session, int video, char *buf, int len) {
	if(!plugin_session || plugin_session->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtp(handle, video, buf, len);
}

void janus_relay_rtcp(janus_plugin_session *plugin_session, int video, char *buf, int len) {
	if(!plugin_session || plugin_session->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtcp(handle, video, buf, len);
}

void janus_relay_data(janus_plugin_session *plugin_session, char *buf, int len) {
	if(!plugin_session || plugin_session->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
#ifdef HAVE_SCTP
	janus_ice_relay_data(handle, buf, len);
#else
	JANUS_LOG(LOG_WARN, "Asked to relay data, but Data Channels support has not been compiled...\n");
#endif
}

void janus_close_pc(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a PeerConnection */
	if(!plugin_session)
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle)
		return;
	if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_session *session = (janus_session *)ice_handle->session;
	if(!session)
		return;
		
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Plugin asked to hangup PeerConnection: sending alert\n", ice_handle->handle_id);
	/* Send an alert on all the DTLS connections */
	janus_ice_webrtc_hangup(ice_handle);
	/* Get rid of the PeerConnection */
	if(ice_handle->iceloop) {
		gint64 waited = 0;
		while(ice_handle->iceloop && !g_main_loop_is_running(ice_handle->iceloop)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE loop exists but is not running, waiting for it to run\n", ice_handle->handle_id);
			g_usleep (100000);
			waited += 100000;
			if(waited >= G_USEC_PER_SEC) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited a second, that's enough!\n", ice_handle->handle_id);
				break;
			}
		}
		if(ice_handle->iceloop) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forcing ICE loop to quit (%s)\n", ice_handle->handle_id, g_main_loop_is_running(ice_handle->iceloop) ? "running" : "NOT running");
			g_main_loop_quit(ice_handle->iceloop);
			g_main_context_wakeup(ice_handle->icectx);
		}
	}
}

void janus_end_session(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a handle */
	if(!plugin_session)
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle)
		return;
	/* Destroy the handle */
	janus_ice_handle_destroy(ice_handle->session, ice_handle->handle_id);
}


/* Main */
gint main(int argc, char *argv[])
{
	/* Core dumps may be disallowed by parent of this process; change that */
	struct rlimit core_limits;
	core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &core_limits);

	struct gengetopt_args_info args_info;
	/* Let's call our cmdline parser */
	if(cmdline_parser(argc, argv, &args_info) != 0)
		exit(1);
	
	JANUS_PRINT("---------------------------------------------------\n");
	JANUS_PRINT("  Starting Meetecho Janus (WebRTC Gateway) v%s\n", JANUS_VERSION_STRING);
	JANUS_PRINT("---------------------------------------------------\n\n");
	
	/* Handle SIGINT */
	signal(SIGINT, janus_handle_signal);

	/* Setup Glib */
#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	
	/* Logging level: default is info */
	log_level = LOG_INFO;
	if(args_info.debug_level_given) {
		if(args_info.debug_level_arg < LOG_NONE)
			args_info.debug_level_arg = 0;
		else if(args_info.debug_level_arg > LOG_MAX)
			args_info.debug_level_arg = LOG_MAX;
		log_level = args_info.debug_level_arg;
	}

	/* Any configuration to open? */
	if(args_info.config_given) {
		config_file = g_strdup(args_info.config_arg);
		if(config_file == NULL) {
			JANUS_PRINT("Memory error!\n");
			exit(1);
		}
	}
	if(args_info.configs_folder_given) {
		configs_folder = g_strdup(args_info.configs_folder_arg);
		if(configs_folder == NULL) {
			JANUS_PRINT("Memory error!\n");
			exit(1);
		}
	} else {
		configs_folder = g_strdup (CONFDIR);
	}
	if(config_file == NULL) {
		char file[255];
		g_snprintf(file, 255, "%s/janus.cfg", configs_folder);
		config_file = g_strdup(file);
		if(config_file == NULL) {
			JANUS_PRINT("Memory error!\n");
			exit(1);
		}
	}
	JANUS_PRINT("Reading configuration from %s\n", config_file);
	if((config = janus_config_parse(config_file)) == NULL) {
		if(args_info.config_given) {
			/* We only give up if the configuration file was explicitly provided */
			exit(1);
		}
		JANUS_PRINT("Error reading/parsing the configuration file, going on with the defaults and the command line arguments\n");
		config = janus_config_create("janus.cfg");
		if(config == NULL) {
			/* If we can't even create an empty configuration, something's definitely wrong */
			exit(1);
		}
	}
	janus_config_print(config);
	if(args_info.debug_level_given) {
		char debug[5];
		g_snprintf(debug, 5, "%d", args_info.debug_level_arg);
		janus_config_add_item(config, "general", "debug_level", debug);
	} else {
		/* No command line directive on logging, try the configuration file */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "debug_level");
		if(item && item->value) {
			int temp_level = atoi(item->value);
			if(temp_level == 0 && strcmp(item->value, "0")) {
				JANUS_PRINT("Invalid debug level %s (configuration), using default (info=4)\n", item->value);
			} else {
				log_level = temp_level;
				if(log_level < LOG_NONE)
					log_level = 0;
				else if(log_level > LOG_MAX)
					log_level = LOG_MAX;
			}
		}
	}
	/* Any command line argument that should overwrite the configuration? */
	JANUS_PRINT("Checking command line arguments...\n");
	if(args_info.interface_given) {
		janus_config_add_item(config, "general", "interface", args_info.interface_arg);
	}
	if(args_info.configs_folder_given) {
		janus_config_add_item(config, "general", "configs_folder", args_info.configs_folder_arg);
	}
	if(args_info.plugins_folder_given) {
		janus_config_add_item(config, "general", "plugins_folder", args_info.plugins_folder_arg);
	}
	if(args_info.apisecret_given) {
		janus_config_add_item(config, "general", "api_secret", args_info.apisecret_arg);
	}
	if(args_info.no_http_given) {
		janus_config_add_item(config, "webserver", "http", "no");
	}
	if(args_info.port_given) {
		char port[20];
		g_snprintf(port, 20, "%d", args_info.port_arg);
		janus_config_add_item(config, "webserver", "port", port);
	}
	if(args_info.secure_port_given) {
		janus_config_add_item(config, "webserver", "https", "yes");
		char port[20];
		g_snprintf(port, 20, "%d", args_info.secure_port_arg);
		janus_config_add_item(config, "webserver", "secure_port", port);
	}
	if(args_info.base_path_given) {
		janus_config_add_item(config, "webserver", "base_path", args_info.base_path_arg);
	}
	if(args_info.no_websockets_given) {
		janus_config_add_item(config, "webserver", "ws", "no");
	}
	if(args_info.ws_port_given) {
		char port[20];
		g_snprintf(port, 20, "%d", args_info.port_arg);
		janus_config_add_item(config, "webserver", "ws_port", port);
	}
	if(args_info.ws_secure_port_given) {
		janus_config_add_item(config, "webserver", "ws_ssl", "yes");
		char port[20];
		g_snprintf(port, 20, "%d", args_info.ws_secure_port_arg);
		janus_config_add_item(config, "webserver", "ws_secure_port", port);
	}
	if(args_info.enable_rabbitmq_given) {
		janus_config_add_item(config, "rabbitmq", "enable", "yes");
	}
#ifdef HAVE_RABBITMQ
	if(args_info.rabbitmq_server_given) {
		/* Split in server and port (if port missing, use AMQP_PROTOCOL_PORT as default) */
		char *rmqport = strrchr(args_info.stun_server_arg, ':');
		if(rmqport != NULL) {
			*rmqport = '\0';
			rmqport++;
			janus_config_add_item(config, "rabbitmq", "host", args_info.rabbitmq_server_arg);
			janus_config_add_item(config, "rabbitmq", "port", rmqport);
		} else {
			janus_config_add_item(config, "rabbitmq", "host", args_info.rabbitmq_server_arg);
			char port[10];
			g_snprintf(port, 10, "%d", AMQP_PROTOCOL_PORT);
			janus_config_add_item(config, "rabbitmq", "port", port);
		}
	}
	if(args_info.rabbitmq_in_queue_given) {
		janus_config_add_item(config, "rabbitmq", "to_janus", args_info.rabbitmq_in_queue_arg);
	}
	if(args_info.rabbitmq_out_queue_given) {
		janus_config_add_item(config, "rabbitmq", "from_janus", args_info.rabbitmq_out_queue_arg);
	}
#endif
	if(args_info.admin_secret_given) {
		janus_config_add_item(config, "admin", "admin_secret", args_info.admin_secret_arg);
	}
	if(args_info.no_admin_given) {
		janus_config_add_item(config, "admin", "admin_http", "no");
	}
	if(args_info.admin_port_given) {
		char port[20];
		g_snprintf(port, 20, "%d", args_info.admin_port_arg);
		janus_config_add_item(config, "admin", "admin_port", port);
	}
	if(args_info.admin_secure_port_given) {
		janus_config_add_item(config, "admin", "admin_https", "yes");
		char port[20];
		g_snprintf(port, 20, "%d", args_info.admin_secure_port_arg);
		janus_config_add_item(config, "admin", "admin_secure_port", port);
	}
	if(args_info.admin_base_path_given) {
		janus_config_add_item(config, "admin", "admin_base_path", args_info.admin_base_path_arg);
	}
	if(args_info.admin_acl_given) {
		janus_config_add_item(config, "admin", "admin_acl", args_info.admin_acl_arg);
	}
	if(args_info.cert_pem_given) {
		janus_config_add_item(config, "certificates", "cert_pem", args_info.cert_pem_arg);
	}
	if(args_info.cert_key_given) {
		janus_config_add_item(config, "certificates", "cert_key", args_info.cert_key_arg);
	}
	if(args_info.stun_server_given) {
		/* Split in server and port (if port missing, use 3478 as default) */
		char *stunport = strrchr(args_info.stun_server_arg, ':');
		if(stunport != NULL) {
			*stunport = '\0';
			stunport++;
			janus_config_add_item(config, "nat", "stun_server", args_info.stun_server_arg);
			janus_config_add_item(config, "nat", "stun_port", stunport);
		} else {
			janus_config_add_item(config, "nat", "stun_server", args_info.stun_server_arg);
			janus_config_add_item(config, "nat", "stun_port", "3478");
		}
	}
	if(args_info.public_ip_given) {
		janus_config_add_item(config, "nat", "public_ip", args_info.public_ip_arg);
	}
	if(args_info.ice_ignore_list_given) {
		janus_config_add_item(config, "nat", "ice_ignore_list", args_info.ice_ignore_list_arg);
	}
	if(args_info.libnice_debug_given) {
		janus_config_add_item(config, "nat", "nice_debug", "true");
	}
	if(args_info.ice_lite_given) {
		janus_config_add_item(config, "nat", "ice_lite", "true");
	}
	if(args_info.ice_tcp_given) {
		janus_config_add_item(config, "nat", "ice_tcp", "true");
	}
	if(args_info.ipv6_candidates_given) {
		janus_config_add_item(config, "media", "ipv6", "true");
	}
	if(args_info.max_nack_queue_given) {
		char mnq[20];
		g_snprintf(mnq, 20, "%d", args_info.max_nack_queue_arg);
		janus_config_add_item(config, "media", "max_nack_queue", mnq);
	}
	if(args_info.rtp_port_range_given) {
		janus_config_add_item(config, "media", "rtp_port_range", args_info.rtp_port_range_arg);
	}
	janus_config_print(config);
	
	JANUS_PRINT("Debug/log level is %d\n", log_level);

	/* Any IP/interface to ignore? */
	janus_config_item *item = janus_config_get_item_drilldown(config, "nat", "ice_ignore_list");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_INFO, "Adding '%s' to the ICE ignore list...\n", index);
					janus_ice_ignore_interface(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_strfreev(list);
		list = NULL;
	}
	/* What is the local public IP? */
	JANUS_LOG(LOG_VERB, "Available interfaces:\n");
	item = janus_config_get_item_drilldown(config, "general", "interface");
	if(item && item->value) {
		JANUS_LOG(LOG_VERB, "  -- Will try to use %s\n", item->value);
	}
	struct ifaddrs *myaddrs, *ifa;
	int status = getifaddrs(&myaddrs);
	char *tmp = NULL;
	if (status == 0) {
		for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
			if(ifa->ifa_addr == NULL) {
				continue;
			}
			if((ifa->ifa_flags & IFF_UP) == 0) {
				continue;
			}
			/* Check the interface name first: we can ignore that as well */
			if(ifa->ifa_name != NULL && janus_ice_is_ignored(ifa->ifa_name))
				continue;
			if(ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *ip = (struct sockaddr_in *)(ifa->ifa_addr);
				char buf[16];
				if(inet_ntop(ifa->ifa_addr->sa_family, (void *)&(ip->sin_addr), buf, sizeof(buf)) == NULL) {
					JANUS_LOG(LOG_ERR, "\t%s:\tinet_ntop failed!\n", ifa->ifa_name);
				} else {
					JANUS_LOG(LOG_VERB, "\t%s:\t%s\n", ifa->ifa_name, buf);
					/* Check if this IP address is in the ignore list, now */
					if(janus_ice_is_ignored(buf))
						continue;
					if(item && item->value && !strcasecmp(buf, item->value)) {
						local_ip = strdup(buf);
						if(local_ip == NULL) {
							JANUS_LOG(LOG_FATAL, "Memory error!\n");
							exit(1);
						}
					} else if(strcasecmp(buf, "127.0.0.1")) {	/* FIXME Check private IP addresses as well */
						if(tmp == NULL)	/* FIXME Take note of the first IP we find, we'll use it as a backup */
							tmp = strdup(buf);
					}
				}
			}
			/* TODO IPv6! */
		}
		freeifaddrs(myaddrs);
	}
	if(local_ip == NULL) {
		if(tmp != NULL) {
			local_ip = tmp;
		} else {
			JANUS_LOG(LOG_WARN, "Couldn't find any address! using 127.0.0.1 as local IP... (which is NOT going to work out of your machine)\n");
			local_ip = g_strdup("127.0.0.1");
		}
	}
	JANUS_LOG(LOG_INFO, "Using %s as local IP...\n", local_ip);

	/* Pre-parse the web server path, if any */
	item = janus_config_get_item_drilldown(config, "webserver", "base_path");
	if(item && item->value) {
		if(item->value[0] != '/') {
			JANUS_LOG(LOG_FATAL, "Invalid base path %s (it should start with a /, e.g., /janus\n", item->value);
			exit(1);
		}
		ws_path = g_strdup(item->value);
		if(strlen(ws_path) > 1 && ws_path[strlen(ws_path)-1] == '/') {
			/* Remove the trailing slash, it makes things harder when we parse requests later */
			ws_path[strlen(ws_path)-1] = '\0';
		}
	} else {
		ws_path = g_strdup("/janus");
	}
	/* Is there any API secret to consider? */
	ws_api_secret = NULL;
	item = janus_config_get_item_drilldown(config, "general", "api_secret");
	if(item && item->value) {
		ws_api_secret = g_strdup(item->value);
	}

	/* Do the same for the admin/monitor interface */
	/* Pre-parse the web server path, if any */
	item = janus_config_get_item_drilldown(config, "admin", "admin_base_path");
	if(item && item->value) {
		if(item->value[0] != '/') {
			JANUS_LOG(LOG_FATAL, "Invalid admin/monitor base path %s (it should start with a /, e.g., /admin\n", item->value);
			exit(1);
		}
		admin_ws_path = g_strdup(item->value);
		if(strlen(admin_ws_path) > 1 && ws_path[strlen(admin_ws_path)-1] == '/') {
			/* Remove the trailing slash, it makes things harder when we parse requests later */
			admin_ws_path[strlen(admin_ws_path)-1] = '\0';
		}
	} else {
		admin_ws_path = g_strdup("/admin");
	}
	/* Is there any API secret to consider? */
	admin_ws_api_secret = NULL;
	item = janus_config_get_item_drilldown(config, "admin", "admin_secret");
	if(item && item->value) {
		admin_ws_api_secret = g_strdup(item->value);
	}
	/* Any ACL? */
	item = janus_config_get_item_drilldown(config, "admin", "admin_acl");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_INFO, "Adding '%s' to the Admin/monitor allowed list...\n", index);
					janus_admin_allow_address(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_strfreev(list);
		list = NULL;
	}

	/* Setup ICE stuff (e.g., checking if the provided STUN server is correct) */
	char *stun_server = NULL, *turn_server = NULL;
	uint16_t stun_port = 0, turn_port = 0;
	char *turn_type = NULL, *turn_user = NULL, *turn_pwd = NULL;
	uint16_t rtp_min_port = 0, rtp_max_port = 0;
	gboolean ice_lite = FALSE, ice_tcp = FALSE, ipv6 = FALSE;
	item = janus_config_get_item_drilldown(config, "media", "ipv6");
	ipv6 = (item && item->value) ? janus_is_true(item->value) : FALSE;
	item = janus_config_get_item_drilldown(config, "media", "rtp_port_range");
	if(item && item->value) {
		/* Split in min and max port */
		char *maxport = strrchr(item->value, '-');
		if(maxport != NULL) {
			*maxport = '\0';
			maxport++;
			rtp_min_port = atoi(item->value);
			rtp_max_port = atoi(maxport);
			maxport--;
			*maxport = '-';
		}
		if(rtp_min_port > rtp_max_port) {
			int temp_port = rtp_min_port;
			rtp_min_port = rtp_max_port;
			rtp_max_port = temp_port;
		}
		if(rtp_max_port == 0)
			rtp_max_port = 65535;
		JANUS_LOG(LOG_INFO, "RTP port range: %u -- %u\n", rtp_min_port, rtp_max_port);
	}
	/* Check if we need to enable the ICE Lite mode */
	item = janus_config_get_item_drilldown(config, "nat", "ice_lite");
	ice_lite = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Check if we need to enable ICE-TCP support (warning: still broken, for debugging only) */
	item = janus_config_get_item_drilldown(config, "nat", "ice_tcp");
	ice_tcp = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Any STUN server to use in Janus? */
	item = janus_config_get_item_drilldown(config, "nat", "stun_server");
	if(item && item->value)
		stun_server = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "stun_port");
	if(item && item->value)
		stun_port = atoi(item->value);
	/* Any TURN server to use in Janus? */
	item = janus_config_get_item_drilldown(config, "nat", "turn_server");
	if(item && item->value)
		turn_server = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "turn_port");
	if(item && item->value)
		turn_port = atoi(item->value);
	item = janus_config_get_item_drilldown(config, "nat", "turn_type");
	if(item && item->value)
		turn_type = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "turn_user");
	if(item && item->value)
		turn_user = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "turn_pwd");
	if(item && item->value)
		turn_pwd = (char *)item->value;
	/* Initialize the ICE stack now */
	janus_ice_init(ice_lite, ice_tcp, ipv6, rtp_min_port, rtp_max_port);
	if(janus_ice_set_stun_server(stun_server, stun_port) < 0) {
		JANUS_LOG(LOG_FATAL, "Invalid STUN address %s:%u\n", stun_server, stun_port);
		exit(1);
	}
	if(janus_ice_set_turn_server(turn_server, turn_port, turn_type, turn_user, turn_pwd) < 0) {
		JANUS_LOG(LOG_FATAL, "Invalid TURN address %s:%u\n", turn_server, turn_port);
		exit(1);
	}
	item = janus_config_get_item_drilldown(config, "nat", "nice_debug");
	if(item && item->value && janus_is_true(item->value)) {
		/* Enable libnice debugging */
		janus_ice_debugging_enable();
	}
	item = janus_config_get_item_drilldown(config, "media", "max_nack_queue");
	if(item && item->value) {
		int mnq = atoi(item->value);
		if(mnq < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring max_nack_queue value as it's not a positive integer\n");
		} else {
			janus_set_max_nack_queue(mnq);
		}
	}

	/* Is there a public_ip value to be used for NAT traversal instead? */
	item = janus_config_get_item_drilldown(config, "nat", "public_ip");
	if(item && item->value) {
		if(public_ip != NULL)
			g_free(public_ip);
		public_ip = g_strdup((char *)item->value);
		if(public_ip == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error\n");
			exit(1);
		}
		JANUS_LOG(LOG_INFO, "Using %s as our public IP in SDP\n", public_ip);
	}
	
	/* Setup OpenSSL stuff */
	item = janus_config_get_item_drilldown(config, "certificates", "cert_pem");
	if(!item || !item->value) {
		JANUS_LOG(LOG_FATAL, "Missing certificate/key path, use the command line or the configuration to provide one\n");
		exit(1);
	}
	server_pem = (char *)item->value;
	server_key = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "certificates", "cert_key");
	if(item && item->value)
		server_key = (char *)item->value;
	JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	/* ... and DTLS-SRTP in particular */
	if(janus_dtls_srtp_init(server_pem, server_key) < 0) {
		exit(1);
	}

#ifdef HAVE_SCTP
	/* Initialize SCTP for DataChannels */
	if(janus_sctp_init() < 0) {
		exit(1);
	}
#else
	JANUS_LOG(LOG_WARN, "Data Channels support not compiled\n");
#endif

	/* Initialize Sofia-SDP */
	if(janus_sdp_init() < 0) {
		exit(1);
	}

	/* Load plugins */
	const char *path = PLUGINDIR;
	item = janus_config_get_item_drilldown(config, "general", "plugins_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Plugins folder: %s\n", path);
	DIR *dir = opendir(path);
	if(!dir) {
		JANUS_LOG(LOG_FATAL, "\tCouldn't access plugins folder...\n");
		exit(1);
	}
	/* Any plugin to ignore? */
	gchar **disabled_plugins = NULL;
	item = janus_config_get_item_drilldown(config, "plugins", "disable");
	if(item && item->value)
		disabled_plugins = g_strsplit(item->value, ",", -1);
	/* Open the shared objects */
	struct dirent *pluginent = NULL;
	char pluginpath[1024];
	while((pluginent = readdir(dir))) {
		int len = strlen(pluginent->d_name);
		if (len < 4) {
			continue;
		}
		if (strcasecmp(pluginent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
			continue;
		}
		/* Check if this plugins has been disabled in the configuration file */
		if(disabled_plugins != NULL) {
			gchar *index = disabled_plugins[0];
			if(index != NULL) {
				int i=0;
				gboolean skip = FALSE;
				while(index != NULL) {
					while(isspace(*index))
						index++;
					if(strlen(index) && !strcmp(index, pluginent->d_name)) {
						JANUS_LOG(LOG_WARN, "Plugin '%s' has been disabled, skipping...\n", pluginent->d_name);
						skip = TRUE;
						break;
					}
					i++;
					index = disabled_plugins[i];
				}
				if(skip)
					continue;
			}
		}
		JANUS_LOG(LOG_INFO, "Loading plugin '%s'...\n", pluginent->d_name);
		memset(pluginpath, 0, 1024);
		g_snprintf(pluginpath, 1024, "%s/%s", path, pluginent->d_name);
		void *plugin = dlopen(pluginpath, RTLD_LAZY);
		if (!plugin) {
			JANUS_LOG(LOG_ERR, "\tCouldn't load plugin '%s': %s\n", pluginent->d_name, dlerror());
		} else {
			create_p *create = (create_p*) dlsym(plugin, "create");
			const char *dlsym_error = dlerror();
			if (dlsym_error) {
				JANUS_LOG(LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
				continue;
			}
			janus_plugin *janus_plugin = create();
			if(!janus_plugin) {
				JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
				continue;
			}
			/* Are all the mandatory methods and callbacks implemented? */
			if(!janus_plugin->init || !janus_plugin->destroy ||
					!janus_plugin->get_api_compatibility ||
					!janus_plugin->get_version ||
					!janus_plugin->get_version_string ||
					!janus_plugin->get_description ||
					!janus_plugin->get_package ||
					!janus_plugin->get_name ||
					!janus_plugin->create_session ||
					!janus_plugin->query_session ||
					!janus_plugin->destroy_session ||
					!janus_plugin->handle_message ||
					!janus_plugin->setup_media ||
					!janus_plugin->hangup_media) {
				JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this plugin...\n");
				continue;
			}
			if(janus_plugin->get_api_compatibility() < JANUS_PLUGIN_API_VERSION) {
				JANUS_LOG(LOG_ERR, "The '%s' plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
					janus_plugin->get_package(), janus_plugin->get_api_compatibility(), JANUS_PLUGIN_API_VERSION);
				continue;
			}
			janus_plugin->init(&janus_handler_plugin, configs_folder);
			JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_plugin->get_version(), janus_plugin->get_version_string());
			JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_plugin->get_package(), janus_plugin->get_name());
			JANUS_LOG(LOG_VERB, "\t   %s\n", janus_plugin->get_description());
			JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_plugin->get_api_compatibility());
			if(!janus_plugin->incoming_rtp && !janus_plugin->incoming_rtcp && !janus_plugin->incoming_data) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin doesn't implement any callback for RTP/RTCP/data... is this on purpose?\n",
					janus_plugin->get_package());
			}
			if(!janus_plugin->incoming_rtp && !janus_plugin->incoming_rtcp && janus_plugin->incoming_data) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin will only handle data channels (no RTP/RTCP)... is this on purpose?\n",
					janus_plugin->get_package());
			}
			if(plugins == NULL)
				plugins = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins, (gpointer)janus_plugin->get_package(), janus_plugin);
			if(plugins_so == NULL)
				plugins_so = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins_so, (gpointer)janus_plugin->get_package(), plugin);
		}
	}
	closedir(dir);
	if(disabled_plugins != NULL)
		g_strfreev(disabled_plugins);
	disabled_plugins = NULL;

	/* Start web server, if enabled */
	sessions = g_hash_table_new(NULL, NULL);
	old_sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	gint64 threads = 0;
	item = janus_config_get_item_drilldown(config, "webserver", "threads");
	if(item && item->value) {
		if(!strcasecmp(item->value, "unlimited")) {
			/* No limit on threads, use a thread per connection */
			threads = 0;
		} else {
			/* Use a thread pool */
			threads = atoll(item->value);
			if(threads == 0) {
				JANUS_LOG(LOG_WARN, "Chose '0' as size for the thread pool, which is equivalent to 'unlimited'\n");
			} else if(threads < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value '%"SCNi64"' as size for the thread pool, falling back to to 'unlimited'\n", threads);
				threads = 0;
			}
		}
	}
	item = janus_config_get_item_drilldown(config, "webserver", "http");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "HTTP webserver disabled\n");
	} else {
		int wsport = 8088;
		item = janus_config_get_item_drilldown(config, "webserver", "port");
		if(item && item->value)
			wsport = atoi(item->value);
		if(threads == 0) {
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the HTTP webserver\n");
			ws = MHD_start_daemon(
				MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				wsport,
				janus_ws_client_connect,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the HTTP webserver\n", threads);
			ws = MHD_start_daemon(
				MHD_USE_SELECT_INTERNALLY,
				wsport,
				janus_ws_client_connect,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_THREAD_POOL_SIZE, threads,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
				MHD_OPTION_END);
		}
		if(ws == NULL) {
			JANUS_LOG(LOG_FATAL, "Couldn't start webserver on port %d...\n", wsport);
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_INFO, "HTTP webserver started (port %d, %s path listener)...\n", wsport, ws_path);
	}
	/* Do we also have to provide an HTTPS one? */
	char *cert_pem_bytes = NULL, *cert_key_bytes = NULL; 
	item = janus_config_get_item_drilldown(config, "webserver", "https");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "HTTPS webserver disabled\n");
	} else {
		item = janus_config_get_item_drilldown(config, "webserver", "secure_port");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "  -- HTTPS port missing\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		int swsport = atoi(item->value);
		/* Read certificate and key */
		FILE *pem = fopen(server_pem, "rb");
		if(!pem) {
			JANUS_LOG(LOG_FATAL, "Could not open certificate file '%s'...\n", server_pem);
			exit(1);	/* FIXME Should we really give up? */
		}
		fseek(pem, 0L, SEEK_END);
		size_t size = ftell(pem);
		fseek(pem, 0L, SEEK_SET);
		cert_pem_bytes = calloc(size, sizeof(char));
		if(cert_pem_bytes == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			exit(1);
		}
		char *index = cert_pem_bytes;
		int read = 0, tot = size;
		while((read = fread(index, sizeof(char), tot, pem)) > 0) {
			tot -= read;
			index += read;
		}
		fclose(pem);
		FILE *key = fopen(server_key, "rb");
		if(!key) {
			JANUS_LOG(LOG_FATAL, "Could not open key file '%s'...\n", server_key);
			exit(1);	/* FIXME Should we really give up? */
		}
		fseek(key, 0L, SEEK_END);
		size = ftell(key);
		fseek(key, 0L, SEEK_SET);
		cert_key_bytes = calloc(size, sizeof(char));
		if(cert_key_bytes == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			exit(1);
		}
		index = cert_key_bytes;
		read = 0;
		tot = size;
		while((read = fread(index, sizeof(char), tot, key)) > 0) {
			tot -= read;
			index += read;
		}
		fclose(key);
		/* Start webserver */
		if(threads == 0) {
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the HTTPS webserver\n");
			sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				swsport,
				janus_ws_client_connect,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
					/* FIXME We're using the same certificates as those for DTLS */
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
					MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the HTTPS webserver\n", threads);
			sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_SELECT_INTERNALLY,
				swsport,
				janus_ws_client_connect,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_THREAD_POOL_SIZE, threads,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
					/* FIXME We're using the same certificates as those for DTLS */
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
					MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_END);
		}
		if(sws == NULL) {
			JANUS_LOG(LOG_FATAL, "Couldn't start secure webserver on port %d...\n", swsport);
			exit(1);	/* FIXME Should we really give up? */
		} else {
			JANUS_LOG(LOG_INFO, "HTTPS webserver started (port %d, %s path listener)...\n", swsport, ws_path);
		}
	}
	/* Enable the websockets server, if enabled */
#ifndef HAVE_WEBSOCKETS
	JANUS_LOG(LOG_WARN, "WebSockets support not compiled\n");
#else
	item = janus_config_get_item_drilldown(config, "webserver", "ws");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "WebSockets server disabled\n");
	} else {
		int wsport = 8188;
		item = janus_config_get_item_drilldown(config, "webserver", "ws_port");
		if(item && item->value)
			wsport = atoi(item->value);
		wss = libwebsock_init();
		if(wss == NULL) {
			JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		char port[50];
		g_snprintf(port, 50, "%d", wsport);
		libwebsock_bind(wss, (char *)"0.0.0.0", port);
		JANUS_LOG(LOG_INFO, "WebSockets server started (port %d)...\n", wsport);
		wss->onopen = janus_wss_onopen;
		wss->onmessage = janus_wss_onmessage;
		wss->onclose = janus_wss_onclose;
		wss_sessions = g_hash_table_new(NULL, NULL);
		janus_mutex_init(&wss_mutex);
	}
	item = janus_config_get_item_drilldown(config, "webserver", "ws_ssl");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Secure WebSockets server disabled\n");
	} else {
		if(wss != NULL) {
			/* FIXME Due to the blocking libwebsock_wait, we only support a single WS server instance at a time */
			JANUS_LOG(LOG_WARN, "Can't start Secure WebSockets server: the plain WebSockets server is already enabled and we only support one for now, disable that one to enable to secure version\n");
		} else {
			int wsport = 8989;
			item = janus_config_get_item_drilldown(config, "webserver", "ws_secure_port");
			if(item && item->value)
				wsport = atoi(item->value);
			swss = libwebsock_init();
			if(swss == NULL) {
				JANUS_LOG(LOG_FATAL, "Error initializing libwebsock...\n");
				exit(1);	/* FIXME Should we really give up? */
			}
			char port[50];
			g_snprintf(port, 50, "%d", wsport);
			libwebsock_bind_ssl(swss, (char *)"0.0.0.0", port, server_key, server_pem);
			JANUS_LOG(LOG_INFO, "Secure WebSockets server started (port %d)...\n", wsport);
			swss->onopen = janus_wss_onopen;
			swss->onmessage = janus_wss_onmessage;
			swss->onclose = janus_wss_onclose;
			wss_sessions = g_hash_table_new(NULL, NULL);
			janus_mutex_init(&wss_mutex);
		}
	}
#endif
	/* Enable the RabbitMQ integration, if enabled */
#ifndef HAVE_RABBITMQ
	JANUS_LOG(LOG_WARN, "RabbitMQ support not compiled\n");
#else
	item = janus_config_get_item_drilldown(config, "rabbitmq", "enable");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "RabbitMQ support disabled\n");
	} else {
		/* Parse configuration */
		char *rmqhost = NULL;
		item = janus_config_get_item_drilldown(config, "rabbitmq", "host");
		if(item && item->value)
			rmqhost = g_strdup(item->value);
		else
			rmqhost = g_strdup("localhost");
		int rmqport = AMQP_PROTOCOL_PORT;
		item = janus_config_get_item_drilldown(config, "rabbitmq", "port");
		if(item && item->value)
			rmqport = atoi(item->value);
		item = janus_config_get_item_drilldown(config, "rabbitmq", "to_janus");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of incoming queue for RabbitMQ integration...\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		const char *to_janus = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "rabbitmq", "from_janus");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of outgoing queue for RabbitMQ integration...\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		const char *from_janus = g_strdup(item->value);
		JANUS_LOG(LOG_INFO, "RabbitMQ support enabled, %s:%d (%s/%s)\n", rmqhost, rmqport, to_janus, from_janus);
		/* Connect */
		rmq_conn = amqp_new_connection();
		JANUS_LOG(LOG_VERB, "Creating RabbitMQ socket...\n");
		amqp_socket_t *socket = amqp_tcp_socket_new(rmq_conn);
		if(socket == NULL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error creating socket...\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_VERB, "Connecting to RabbitMQ server...\n");
		int status = amqp_socket_open(socket, rmqhost, rmqport);
		g_free(rmqhost);
		if(status != AMQP_STATUS_OK) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error opening socket... (%s)\n", amqp_error_string2(status));
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_VERB, "Logging in...\n");
		amqp_rpc_reply_t result = amqp_login(rmq_conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error logging in... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			exit(1);	/* FIXME Should we really give up? */
		}
		rmq_channel = 1;
		JANUS_LOG(LOG_VERB, "Opening channel...\n");
		amqp_channel_open(rmq_conn, rmq_channel);
		result = amqp_get_rpc_reply(rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error opening channel... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_VERB, "Declaring incoming queue... (%s)\n", to_janus);
		to_janus_queue = amqp_cstring_bytes(to_janus);
		amqp_queue_declare(rmq_conn, rmq_channel, to_janus_queue, 0, 0, 0, 0, amqp_empty_table);
		result = amqp_get_rpc_reply(rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_VERB, "Declaring outgoing queue... (%s)\n", from_janus);
		from_janus_queue = amqp_cstring_bytes(from_janus);
		amqp_queue_declare(rmq_conn, rmq_channel, from_janus_queue, 0, 0, 0, 0, amqp_empty_table);
		result = amqp_get_rpc_reply(rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			exit(1);	/* FIXME Should we really give up? */
		}
		amqp_basic_consume(rmq_conn, rmq_channel, to_janus_queue, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
		result = amqp_get_rpc_reply(rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error consuming... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			exit(1);	/* FIXME Should we really give up? */
		}
		/* FIXME We currently support a single application, create a new janus_rabbitmq_client instance */
		rmq_client = calloc(1, sizeof(janus_rabbitmq_client));
		if(rmq_client == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		rmq_client->sessions = NULL;
		rmq_client->responses = g_async_queue_new();
		rmq_client->destroy = 0;
		GError *error = NULL;
		rmq_client->in_thread = g_thread_try_new("rmq_in_thread", &janus_rmq_in_thread, rmq_client, &error);
		if(error != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the RabbitMQ incoming thread...\n", error->code, error->message ? error->message : "??");
			exit(1);	/* FIXME Should we really give up? */
		}
		rmq_client->out_thread = g_thread_try_new("rmq_out_thread", &janus_rmq_out_thread, rmq_client, &error);
		if(error != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the RabbitMQ outgoing thread...\n", error->code, error->message ? error->message : "??");
			exit(1);	/* FIXME Should we really give up? */
		}
		/* rabbitmq-c is single threaded, we need a thread pool to serve requests */
		rmq_client->thread_pool = g_thread_pool_new(janus_rmq_task, rmq_client, -1, FALSE, &error);
		if(error != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the pool thread...\n", error->code, error->message ? error->message : "??");
			exit(1);	/* FIXME Should we really give up? */
		}
		janus_mutex_init(&rmq_client->mutex);
		/* Done */
		JANUS_LOG(LOG_INFO, "Setup of RabbitMQ integration completed\n");
	}
#endif
	/* Do we have anything up? */
	int something = 0;
	if(ws || sws)
		something++;
#ifdef HAVE_WEBSOCKETS
	if(wss || swss)
		something++;
#endif
#ifdef HAVE_RABBITMQ
	if(rmq_channel)	/* FIXME */
		something++;
#endif
	if(something == 0) {
		JANUS_LOG(LOG_FATAL, "No transport (HTTP/HTTPS/WebSockets/RabbitMQ) started, giving up...\n"); 
		exit(1);
	}

	/* Start the sessions watchdog */
	sessions_watchdog_context = g_main_context_new();
	GMainLoop *watchdog_loop = g_main_loop_new(sessions_watchdog_context, FALSE);
	GError *error = NULL;
	GThread *watchdog = g_thread_try_new("watchdog", &janus_sessions_watchdog, watchdog_loop, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start sessions watchdog...\n", error->code, error->message ? error->message : "??");
		exit(1);
	}

	/* Admin/monitor time: start web server, if enabled */
	threads = 0;
	item = janus_config_get_item_drilldown(config, "admin", "admin_threads");
	if(item && item->value) {
		if(!strcasecmp(item->value, "unlimited")) {
			/* No limit on threads, use a thread per connection */
			threads = 0;
		} else {
			/* Use a thread pool */
			threads = atoll(item->value);
			if(threads == 0) {
				JANUS_LOG(LOG_WARN, "Chose '0' as size for the admin/monitor thread pool, which is equivalent to 'unlimited'\n");
			} else if(threads < 0) {
				JANUS_LOG(LOG_WARN, "Invalid value '%"SCNi64"' as size for the admin/monitor thread pool, falling back to to 'unlimited'\n", threads);
				threads = 0;
			}
		}
	}
	item = janus_config_get_item_drilldown(config, "admin", "admin_http");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Admin/monitor HTTP webserver disabled\n");
	} else {
		int wsport = 7088;
		item = janus_config_get_item_drilldown(config, "admin", "admin_port");
		if(item && item->value)
			wsport = atoi(item->value);
		if(threads == 0) {
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the admin/monitor HTTP webserver\n");
			admin_ws = MHD_start_daemon(
				MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				wsport,
				janus_admin_ws_client_connect,
				NULL,
				&janus_admin_ws_handler,
				admin_ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the admin/monitor HTTP webserver\n", threads);
			admin_ws = MHD_start_daemon(
				MHD_USE_SELECT_INTERNALLY,
				wsport,
				janus_admin_ws_client_connect,
				NULL,
				&janus_admin_ws_handler,
				admin_ws_path,
				MHD_OPTION_THREAD_POOL_SIZE, threads,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
				MHD_OPTION_END);
		}
		if(admin_ws == NULL) {
			JANUS_LOG(LOG_FATAL, "Couldn't start admin/monitor webserver on port %d...\n", wsport);
			exit(1);	/* FIXME Should we really give up? */
		}
		JANUS_LOG(LOG_INFO, "Admin/monitor HTTP webserver started (port %d, %s path listener)...\n", wsport, admin_ws_path);
	}
	/* Do we also have to provide an HTTPS one? */
	item = janus_config_get_item_drilldown(config, "admin", "admin_https");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Admin/monitor HTTPS webserver disabled\n");
	} else {
		item = janus_config_get_item_drilldown(config, "admin", "admin_secure_port");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "  -- Admin/monitor HTTPS port missing\n");
			exit(1);	/* FIXME Should we really give up? */
		}
		int swsport = atoi(item->value);
		/* Read certificate and key */
		if(cert_pem_bytes == NULL) {
			FILE *pem = fopen(server_pem, "rb");
			if(!pem) {
				JANUS_LOG(LOG_FATAL, "Could not open certificate file '%s'...\n", server_pem);
				exit(1);	/* FIXME Should we really give up? */
			}
			fseek(pem, 0L, SEEK_END);
			size_t size = ftell(pem);
			fseek(pem, 0L, SEEK_SET);
			cert_pem_bytes = calloc(size, sizeof(char));
			if(cert_pem_bytes == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				exit(1);
			}
			char *index = cert_pem_bytes;
			int read = 0, tot = size;
			while((read = fread(index, sizeof(char), tot, pem)) > 0) {
				tot -= read;
				index += read;
			}
			fclose(pem);
		}
		if(cert_key_bytes == NULL) {
			FILE *key = fopen(server_key, "rb");
			if(!key) {
				JANUS_LOG(LOG_FATAL, "Could not open key file '%s'...\n", server_key);
				exit(1);	/* FIXME Should we really give up? */
			}
			fseek(key, 0L, SEEK_END);
			size_t size = ftell(key);
			fseek(key, 0L, SEEK_SET);
			cert_key_bytes = calloc(size, sizeof(char));
			if(cert_key_bytes == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				exit(1);
			}
			char *index = cert_key_bytes;
			int read = 0;
			int tot = size;
			while((read = fread(index, sizeof(char), tot, key)) > 0) {
				tot -= read;
				index += read;
			}
			fclose(key);
		}
		/* Start webserver */
		if(threads == 0) {
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the admin/monitor HTTPS webserver\n");
			admin_sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				swsport,
				janus_admin_ws_client_connect,
				NULL,
				&janus_admin_ws_handler,
				admin_ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
					/* FIXME We're using the same certificates as those for DTLS */
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
					MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the admin/monitor HTTPS webserver\n", threads);
			admin_sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_SELECT_INTERNALLY,
				swsport,
				janus_admin_ws_client_connect,
				NULL,
				&janus_admin_ws_handler,
				admin_ws_path,
				MHD_OPTION_THREAD_POOL_SIZE, threads,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
					/* FIXME We're using the same certificates as those for DTLS */
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
					MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_END);
		}
		if(admin_sws == NULL) {
			JANUS_LOG(LOG_FATAL, "Couldn't start secure admin/monitor webserver on port %d...\n", swsport);
			exit(1);	/* FIXME Should we really give up? */
		} else {
			JANUS_LOG(LOG_INFO, "Admin/monitor HTTPS webserver started (port %d, %s path listener)...\n", swsport, admin_ws_path);
		}
	}

#ifdef HAVE_WEBSOCKETS
	if(wss || swss) {
		/* The libwebsock wait is our loop */
		libwebsock_wait(wss ? wss : swss);
		if(!g_atomic_int_get(&stop))
			g_atomic_int_inc(&stop);
	} else {
		while(!g_atomic_int_get(&stop)) {
			/* Loop until we have to stop */
			g_usleep(250000);
		}
	}
#else
	while(!g_atomic_int_get(&stop)) {
		/* Loop until we have to stop */
		g_usleep(250000);
	}
#endif

	/* Done */
	JANUS_LOG(LOG_INFO, "Ending watchdog mainloop...\n");
	g_main_loop_quit(watchdog_loop);
	g_thread_join(watchdog);
	watchdog = NULL;
	g_main_loop_unref(watchdog_loop);
	g_main_context_unref(sessions_watchdog_context);

	if(config)
		janus_config_destroy(config);
	JANUS_LOG(LOG_INFO, "Closing webserver(s)...\n");
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
#ifdef HAVE_RABBITMQ
	if(rmq_channel) {
		if(rmq_client) {
			g_thread_join(rmq_client->in_thread);
			g_thread_join(rmq_client->out_thread);
		}
		amqp_channel_close(rmq_conn, rmq_channel, AMQP_REPLY_SUCCESS);
		amqp_connection_close(rmq_conn, AMQP_REPLY_SUCCESS);
		amqp_destroy_connection(rmq_conn);
	}
#endif
	if(cert_pem_bytes != NULL)
		g_free((gpointer)cert_pem_bytes);
	cert_pem_bytes = NULL;
	if(cert_key_bytes != NULL)
		g_free((gpointer)cert_key_bytes);
	cert_key_bytes = NULL;
	JANUS_LOG(LOG_INFO, "Destroying sessions...\n");
	if(sessions != NULL)
		g_hash_table_destroy(sessions);
	if(old_sessions != NULL)
		g_hash_table_destroy(old_sessions);
#ifdef HAVE_WEBSOCKETS
	if(wss_sessions != NULL)
		g_hash_table_destroy(wss_sessions);
#endif
	JANUS_LOG(LOG_INFO, "Freeing crypto resources...\n");
	SSL_CTX_free(janus_dtls_get_ssl_ctx());
	EVP_cleanup();
	ERR_free_strings();
	JANUS_LOG(LOG_INFO, "Cleaning SDP structures...\n");
	janus_sdp_deinit();
#ifdef HAVE_SCTP
	JANUS_LOG(LOG_INFO, "De-initializing SCTP...\n");
	janus_sctp_deinit();
#endif
	
	JANUS_LOG(LOG_INFO, "Closing plugins:\n");
	if(plugins != NULL) {
		g_hash_table_foreach(plugins, janus_plugin_close, NULL);
		g_hash_table_destroy(plugins);
	}
	if(plugins_so != NULL) {
		g_hash_table_foreach(plugins_so, janus_pluginso_close, NULL);
		g_hash_table_destroy(plugins_so);
	}

	JANUS_PRINT("Bye!\n");
	exit(0);
}


void janus_http_event_free(janus_http_event *event)
{
	if (event == NULL) {
		return;
	}

	if (event->payload && event->allocated) {
		g_free(event->payload);
	}

	free(event);
}
