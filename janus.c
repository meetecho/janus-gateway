/*! \file   janus.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus core
 * \details Implementation of the gateway core. This code takes care of
 * the gateway initialization (command line/configuration) and setup,
 * and makes use of the available transport plugins (by default HTTP,
 * WebSockets, RabbitMQ, if compiled) and Janus protocol (a JSON-based
 * protocol) to interact with the applications, whether they're web based
 * or not. The core also takes care of bridging peers and plugins
 * accordingly, in terms of both messaging and real-time media transfer
 * via WebRTC. 
 * 
 * \ingroup core
 * \ref core
 */
 
#include <dlfcn.h>
#include <dirent.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "janus.h"
#include "cmdline.h"
#include "config.h"
#include "apierror.h"
#include "log.h"
#include "debug.h"
#include "rtcp.h"
#include "sdp.h"
#include "auth.h"
#include "utils.h"


#define JANUS_NAME				"Janus WebRTC Gateway"
#define JANUS_AUTHOR			"Meetecho s.r.l."
#define JANUS_VERSION			10
#define JANUS_VERSION_STRING	"0.1.0"

#ifdef __MACH__
#define SHLIB_EXT "0.dylib"
#else
#define SHLIB_EXT ".so"
#endif


static janus_config *config = NULL;
static char *config_file = NULL;
static char *configs_folder = NULL;

static GHashTable *transports = NULL;
static GHashTable *transports_so = NULL;

static GHashTable *plugins = NULL;
static GHashTable *plugins_so = NULL;


/* Certificates */
static char *server_pem = NULL;
gchar *janus_get_server_pem(void) {
	return server_pem;
}
static char *server_key = NULL;
gchar *janus_get_server_key(void) {
	return server_key;
}


/* API secrets */
static char *api_secret = NULL, *admin_api_secret = NULL;


/* Admin/Monitor helpers */
json_t *janus_admin_stream_summary(janus_ice_stream *stream);
json_t *janus_admin_component_summary(janus_ice_component *component);


/* IP addresses */
static gchar local_ip[INET6_ADDRSTRLEN];
gchar *janus_get_local_ip(void) {
	return local_ip;
}
static gchar *public_ip = NULL;
gchar *janus_get_public_ip(void) {
	/* Fallback to the local IP, if we have no public one */
	return public_ip ? public_ip : local_ip;
}
void janus_set_public_ip(const char *ip) {
	/* once set do not override */
	if(ip == NULL || public_ip != NULL)
		return;
	public_ip = g_strdup(ip);
}
static volatile gint stop = 0;
gint janus_is_stopping(void) {
	return g_atomic_int_get(&stop);
}


/* Information */
json_t *janus_info(const char *transaction);
json_t *janus_info(const char *transaction) {
	/* Prepare a summary on the gateway */
	json_t *info = json_object();
	json_object_set_new(info, "janus", json_string("server_info"));
	if(transaction != NULL)
		json_object_set_new(info, "transaction", json_string(transaction));
	json_object_set_new(info, "name", json_string(JANUS_NAME));
	json_object_set_new(info, "version", json_integer(JANUS_VERSION));
	json_object_set_new(info, "version_string", json_string(JANUS_VERSION_STRING));
	json_object_set_new(info, "author", json_string(JANUS_AUTHOR));
	json_object_set_new(info, "log-to-stdout", json_string(janus_log_is_stdout_enabled() ? "true" : "false"));
	json_object_set_new(info, "log-to-file", json_string(janus_log_is_logfile_enabled() ? "true" : "false"));
	if(janus_log_is_logfile_enabled())
		json_object_set_new(info, "log-path", json_string(janus_log_get_logfile_path()));
#ifdef HAVE_SCTP
	json_object_set_new(info, "data_channels", json_string("true"));
#else
	json_object_set_new(info, "data_channels", json_string("false"));
#endif
	json_object_set_new(info, "local-ip", json_string(local_ip));
	if(public_ip != NULL)
		json_object_set_new(info, "public-ip", json_string(public_ip));
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
	json_object_set_new(info, "api_secret", json_string(api_secret != NULL ? "true" : "false"));
	json_object_set_new(info, "auth_token", json_string(janus_auth_is_enabled() ? "true" : "false"));
	/* Available transports */
	json_t *t_data = json_object();
	if(transports && g_hash_table_size(transports) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, transports);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_transport *t = value;
			if(t == NULL) {
				continue;
			}
			json_t *transport = json_object();
			json_object_set_new(transport, "name", json_string(t->get_name()));
			json_object_set_new(transport, "author", json_string(t->get_author()));
			json_object_set_new(transport, "description", json_string(t->get_description()));
			json_object_set_new(transport, "version_string", json_string(t->get_version_string()));
			json_object_set_new(transport, "version", json_integer(t->get_version()));
			json_object_set_new(t_data, t->get_package(), transport);
		}
	}
	json_object_set_new(info, "transports", t_data);
	/* Available plugins */
	json_t *p_data = json_object();
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
			json_object_set_new(p_data, p->get_package(), plugin);
		}
	}
	json_object_set_new(info, "plugins", p_data);
	
	return info;
}


/* Logging */
int janus_log_level = LOG_INFO;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
int lock_debug = 0;


/*! \brief Signal handler (just used to intercept CTRL+C and SIGTERM) */
static void janus_handle_signal(int signum) {
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

/*! \brief Termination handler (atexit) */
static void janus_termination_handler(void) {
	/* Remove the PID file if we created it */
	janus_pidfile_remove();
	/* Close the logger */
	janus_log_destroy();
}


/** @name Transport plugin callback interface
 * These are the callbacks implemented by the gateway core, as part of
 * the janus_transport_callbacks interface. Everything the transport
 * plugins send the gateway is handled here.
 */
///@{
void janus_transport_incoming_request(janus_transport *plugin, void *transport, void *request_id, gboolean admin, json_t *message, json_error_t *error);
void janus_transport_gone(janus_transport *plugin, void *transport);
gboolean janus_transport_is_api_secret_needed(janus_transport *plugin);
gboolean janus_transport_is_api_secret_valid(janus_transport *plugin, const char *apisecret);
gboolean janus_transport_is_auth_token_needed(janus_transport *plugin);
gboolean janus_transport_is_auth_token_valid(janus_transport *plugin, const char *token);

static janus_transport_callbacks janus_handler_transport =
	{
		.incoming_request = janus_transport_incoming_request,
		.transport_gone = janus_transport_gone,
		.is_api_secret_needed = janus_transport_is_api_secret_needed,
		.is_api_secret_valid = janus_transport_is_api_secret_valid,
		.is_auth_token_needed = janus_transport_is_auth_token_needed,
		.is_auth_token_valid = janus_transport_is_auth_token_valid,
	}; 
GThreadPool *tasks = NULL;
void janus_transport_task(gpointer data, gpointer user_data);
///@}


/** @name Plugin callback interface
 * These are the callbacks implemented by the gateway core, as part of
 * the janus_callbacks interface. Everything the plugins send the
 * gateway is handled here.
 */
///@{
int janus_plugin_push_event(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *transaction, const char *message, const char *sdp_type, const char *sdp);
json_t *janus_plugin_handle_sdp(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *sdp_type, const char *sdp);
void janus_plugin_relay_rtp(janus_plugin_session *plugin_session, int video, char *buf, int len);
void janus_plugin_relay_rtcp(janus_plugin_session *plugin_session, int video, char *buf, int len);
void janus_plugin_relay_data(janus_plugin_session *plugin_session, char *buf, int len);
void janus_plugin_close_pc(janus_plugin_session *plugin_session);
void janus_plugin_end_session(janus_plugin_session *plugin_session);
static janus_callbacks janus_handler_plugin =
	{
		.push_event = janus_plugin_push_event,
		.relay_rtp = janus_plugin_relay_rtp,
		.relay_rtcp = janus_plugin_relay_rtcp,
		.relay_data = janus_plugin_relay_data,
		.close_pc = janus_plugin_close_pc,
		.end_session = janus_plugin_end_session,
	}; 
///@}


/* Gateway Sessions */
static janus_mutex sessions_mutex;
static GHashTable *sessions = NULL, *old_sessions = NULL;
static GMainContext *sessions_watchdog_context = NULL;


#define SESSION_TIMEOUT		60		/* FIXME Should this be higher, e.g., 120 seconds? */

static gboolean janus_cleanup_session(gpointer user_data) {
	janus_session *session = (janus_session *) user_data;

	JANUS_LOG(LOG_DBG, "Cleaning up session %"SCNu64"...\n", session->session_id);
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

				/* Notify the transport */
				if(session->source) {
					json_t *event = json_object();
					json_object_set_new(event, "janus", json_string("timeout"));
					json_object_set_new(event, "session_id", json_integer(session->session_id));
					/* Send this to the transport client */
					session->source->transport->send_message(session->source->instance, NULL, FALSE, event);
					/* Notify the transport plugin about the session timeout */
					session->source->transport->session_over(session->source->instance, session->session_id, TRUE);
				}
				
				/* Mark the session as over, we'll deal with it later */
				session->timeout = 1;
				/* FIXME Is this safe? apparently it causes hash table errors on the console */
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
	janus_session *session = (janus_session *)g_malloc0(sizeof(janus_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	session->session_id = session_id;
	session->source = NULL;
	session->destroy = 0;
	session->timeout = 0;
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

void janus_session_notify_event(guint64 session_id, json_t *event) {
	janus_mutex_lock(&sessions_mutex);
	janus_session *session = sessions ? g_hash_table_lookup(sessions, GUINT_TO_POINTER(session_id)) : NULL;
	if(session != NULL && !session->destroy && session->source != NULL && session->source->transport != NULL) {
		janus_mutex_unlock(&sessions_mutex);
		/* Send this to the transport client */
		JANUS_LOG(LOG_HUGE, "Sending event to %s (%p)\n", session->source->transport->get_package(), session->source->instance);
		session->source->transport->send_message(session->source->instance, NULL, FALSE, event);
	} else {
		janus_mutex_unlock(&sessions_mutex);
		/* No transport, free the event */
		json_decref(event);
	}
}


/* Destroys a session but does not remove it from the sessions hash table. */
gint janus_session_destroy(guint64 session_id) {
	janus_session *session = janus_session_find_destroyed(session_id);
	if(session == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't find session to destroy: %"SCNu64"\n", session_id);
		return -1;
	}
	JANUS_LOG(LOG_VERB, "Destroying session %"SCNu64"\n", session_id);
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

	/* FIXME Actually destroy session */
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
	if(session->source != NULL) {
		janus_request_destroy(session->source);
		session->source = NULL;
	}
	janus_mutex_unlock(&session->mutex);
	g_free(session);
	session = NULL;
}


/* Requests management */
janus_request *janus_request_new(janus_transport *transport, void *instance, void *request_id, gboolean admin, json_t *message) {
	janus_request *request = (janus_request *)g_malloc0(sizeof(janus_request));
	request->transport = transport;
	request->instance = instance;
	request->request_id = request_id;
	request->admin = admin;
	request->message = message;
	return request;
}

void janus_request_destroy(janus_request *request) {
	if(request == NULL)
		return;
	request->transport = NULL;
	request->instance = NULL;
	request->request_id = NULL;
	if(request->message)
		json_decref(request->message);
	request->message = NULL;
	g_free(request);
}

int janus_process_incoming_request(janus_request *request) {
	int ret = -1;
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or payload to process, giving up...\n");
		return ret;
	}
	json_t *root = request->message;
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
		ret = janus_process_error(request, session_id, NULL, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (transaction)");
		goto jsondone;
	}
	if(!json_is_string(transaction)) {
		ret = janus_process_error(request, session_id, NULL, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (transaction should be a string)");
		goto jsondone;
	}
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	if(!message) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (janus)");
		goto jsondone;
	}
	if(!json_is_string(message)) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (janus should be a string)");
		goto jsondone;
	}
	const gchar *message_text = json_string_value(message);
	
	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Create new session', a 'Get info' or a 'Ping/Pong' request */
		if(!strcasecmp(message_text, "info")) {
			ret = janus_process_success(request, janus_info(transaction_text));
			goto jsondone;
		}
		if(!strcasecmp(message_text, "ping")) {
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("pong"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			ret = janus_process_success(request, reply);
			goto jsondone;
		}
		if(strcasecmp(message_text, "create")) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		/* Any secret/token to check? */
		gboolean secret_authorized = FALSE, token_authorized = FALSE;
		if(api_secret == NULL && !janus_auth_is_enabled()) {
			/* Nothing to check */
			secret_authorized = TRUE;
			token_authorized = TRUE;
		} else {
			if(api_secret != NULL) {
				/* There's an API secret, check that the client provided it */
				json_t *secret = json_object_get(root, "apisecret");
				if(secret && json_is_string(secret) && janus_strcmp_const_time(json_string_value(secret), api_secret)) {
					secret_authorized = TRUE;
				}
			}
			if(janus_auth_is_enabled()) {
				/* The token based authentication mechanism is enabled, check that the client provided it */
				json_t *token = json_object_get(root, "token");
				if(token && json_is_string(token) && janus_auth_check_token(json_string_value(token))) {
					token_authorized = TRUE;
				}
			}
			/* We consider a request authorized if either the proper API secret or a valid token has been provided */
			if(!secret_authorized && !token_authorized) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
				goto jsondone;
			}
		}
		session_id = 0;
		json_t *id = json_object_get(root, "id");
		if(id != NULL) {
			/* The application provided the session ID to use */
			if(!json_is_integer(id) || json_integer_value(id) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (id should be a positive integer)");
				goto jsondone;
			}
			session_id = json_integer_value(id);
			if(session_id > 0 && janus_session_find(session_id) != NULL) {
				/* Session ID already taken */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_CONFLICT, "Session ID already in use");
				goto jsondone;
			}
		}
		/* Handle it */
		janus_session *session = janus_session_create(session_id);
		if(session == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
			goto jsondone;
		}
		session_id = session->session_id;
		/* Take note of the request source that originated this session (HTTP, WebSockets, RabbitMQ?) */
		session->source = janus_request_new(request->transport, request->instance, NULL, FALSE, NULL);
		/* Notify the source that a new session has been created */
		request->transport->session_created(request->instance, session->session_id);
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(session_id));
		json_object_set_new(reply, "data", data);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	gboolean secret_authorized = FALSE, token_authorized = FALSE;
	if(api_secret == NULL && !janus_auth_is_enabled()) {
		/* Nothing to check */
		secret_authorized = TRUE;
		token_authorized = TRUE;
	} else {
		if(api_secret != NULL) {
			/* There's an API secret, check that the client provided it */
			json_t *secret = json_object_get(root, "apisecret");
			if(secret && json_is_string(secret) && janus_strcmp_const_time(json_string_value(secret), api_secret)) {
				secret_authorized = TRUE;
			}
		}
		if(janus_auth_is_enabled()) {
			/* The token based authentication mechanism is enabled, check that the client provided it */
			json_t *token = json_object_get(root, "token");
			if(token && json_is_string(token) && janus_auth_check_token(json_string_value(token))) {
				token_authorized = TRUE;
			}
		}
		/* We consider a request authorized if either the proper API secret or a valid token has been provided */
		if(!secret_authorized && !token_authorized) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	janus_session *session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	/* Update the last activity timer */
	session->last_activity = janus_get_monotonic_time();
	janus_ice_handle *handle = NULL;
	if(handle_id > 0) {
		handle = janus_ice_handle_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}

	/* What is this? */
	if(!strcasecmp(message_text, "keepalive")) {
		/* Just a keep-alive message, reply with an ack */
		JANUS_LOG(LOG_VERB, "Got a keep-alive on session %"SCNu64"\n", session_id);
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "attach")) {
		if(handle != NULL) {
			/* Attach is a session-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		json_t *plugin = json_object_get(root, "plugin");
		if(!plugin) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (plugin)");
			goto jsondone;
		}
		if(!json_is_string(plugin)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (plugin should be a string)");
			goto jsondone;
		}
		const gchar *plugin_text = json_string_value(plugin);
		janus_plugin *plugin_t = janus_plugin_find(plugin_text);
		if(plugin_t == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, "No such plugin '%s'", plugin_text);
			goto jsondone;
		}
		/* If the auth token mechanism is enabled, we should check if this token can access this plugin */
		if(janus_auth_is_enabled()) {
			json_t *token = json_object_get(root, "token");
			if(token != NULL) {
				const char *token_value = json_string_value(token);
				if(token_value && !janus_auth_check_plugin(token_value, plugin_t)) {
					JANUS_LOG(LOG_ERR, "Token '%s' can't access plugin '%s'\n", token_value, plugin_text);
					ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED_PLUGIN, "Provided token can't access plugin '%s'", plugin_text);
					goto jsondone;
				}
			}
		}
		/* Create handle */
		handle = janus_ice_handle_create(session);
		if(handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
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

			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_ATTACH, "Couldn't attach to plugin: error '%d'", error);
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(handle_id));
		json_object_set_new(reply, "data", data);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "destroy")) {
		if(handle != NULL) {
			/* Query is a session-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
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
		/* Notify the source that the session has been destroyed */
		if(session->source && session->source->transport)
			session->source->transport->session_over(session->source->instance, session->session_id, FALSE);

		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "detach")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin to detach from");
			goto jsondone;
		}
		int error = janus_ice_handle_destroy(session, handle_id);
		janus_mutex_lock(&session->mutex);
		g_hash_table_remove(session->ice_handles, GUINT_TO_POINTER(handle_id));
		janus_mutex_unlock(&session->mutex);

		if(error != 0) {
			/* TODO Make error struct to pass verbose information */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "Couldn't detach from plugin: error '%d'", error);
			/* TODO Delete handle instance */
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "message")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this message");
			goto jsondone;
		}
		janus_plugin *plugin_t = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] There's a message for %s\n", handle->handle_id, plugin_t->get_name());
		json_t *body = json_object_get(root, "body");
		if(body == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (body)");
			goto jsondone;
		}
		if(!json_is_object(body)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_JSON_OBJECT, "Invalid body object");
			goto jsondone;
		}
		/* Is there an SDP attached? */
		json_t *jsep = json_object_get(root, "jsep");
		char *jsep_type = NULL;
		char *jsep_sdp = NULL, *jsep_sdp_stripped = NULL;
		if(jsep != NULL) {
			if(!json_is_object(jsep)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_JSON_OBJECT, "Invalid jsep object");
				goto jsondone;
			}
			json_t *type = json_object_get(jsep, "type");
			if(!type) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "JSEP error: missing mandatory element (type)");
				goto jsondone;
			}
			if(!json_is_string(type)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "JSEP error: invalid element type (type should be a string)");
				goto jsondone;
			}
			jsep_type = g_strdup(json_string_value(type));
			type = NULL;
			/* Are we still cleaning up from a previous media session? */
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", handle->handle_id);
				gint64 waited = 0;
				while(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
					g_usleep(100000);
					waited += 100000;
					if(waited >= 3*G_USEC_PER_SEC) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", handle->handle_id);
						break;
					}
				}
			}
			/* Check the JSEP type */
			janus_mutex_lock(&handle->mutex);
			int offer = 0;
			if(!strcasecmp(jsep_type, "offer")) {
				offer = 1;
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
			} else if(!strcasecmp(jsep_type, "answer")) {
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
				offer = 0;
			} else {
				/* TODO Handle other message types as well */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_UNKNOWN_TYPE, "JSEP error: unknown message type '%s'", jsep_type);
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			json_t *sdp = json_object_get(jsep, "sdp");
			if(!sdp) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "JSEP error: missing mandatory element (sdp)");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			if(!json_is_string(sdp)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "JSEP error: invalid element type (sdp should be a string)");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			jsep_sdp = (char *)json_string_value(sdp);
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote SDP:\n%s", handle->handle_id, jsep_sdp);
			/* Is this valid SDP? */
			int audio = 0, video = 0, data = 0, bundle = 0, rtcpmux = 0, trickle = 0;
			janus_sdp *parsed_sdp = janus_sdp_preparse(jsep_sdp, &audio, &video, &data, &bundle, &rtcpmux, &trickle);
			if(parsed_sdp == NULL) {
				/* Invalid SDP */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "JSEP error: invalid SDP");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			/* FIXME We're only handling single audio/video lines for now... */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio %s been negotiated, Video %s been negotiated, SCTP/DataChannels %s been negotiated\n",
			                    handle->handle_id,
			                    audio ? "has" : "has NOT",
			                    video ? "has" : "has NOT",
			                    data ? "have" : "have NOT");
			if(audio > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one audio line? only going to negotiate one...\n", handle->handle_id);
			}
			if(video > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one video line? only going to negotiate one...\n", handle->handle_id);
			}
			if(data > 1) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] More than one data line? only going to negotiate one...\n", handle->handle_id);
			}
#ifndef HAVE_SCTP
			if(data) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"]   -- DataChannels have been negotiated, but support for them has not been compiled...\n", handle->handle_id);
			}
#endif
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] The browser: %s BUNDLE, %s rtcp-mux, %s doing Trickle ICE\n", handle->handle_id,
			                    bundle  ? "supports" : "does NOT support",
			                    rtcpmux ? "supports" : "does NOT support",
			                    trickle ? "is"       : "is NOT");
			/* Check if it's a new session, or an update... */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)
					|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				/* New session */
				if(offer) {
					/* Setup ICE locally (we received an offer) */
					if(janus_ice_setup_local(handle, offer, audio, video, data, bundle, rtcpmux, trickle) < 0) {
						JANUS_LOG(LOG_ERR, "Error setting ICE locally\n");
						g_free(jsep_type);
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
						ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error setting ICE locally");
						janus_mutex_unlock(&handle->mutex);
						goto jsondone;
					}
				} else {
					/* Make sure we're waiting for an ANSWER in the first place */
					if(!handle->agent) {
						JANUS_LOG(LOG_ERR, "Unexpected ANSWER (did we offer?)\n");
						g_free(jsep_type);
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
						ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNEXPECTED_ANSWER, "Unexpected ANSWER (did we offer?)");
						janus_mutex_unlock(&handle->mutex);
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
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   -- bundle is supported by the browser, getting rid of one of the RTP/RTCP components, if any...\n", handle->handle_id);
						if(audio) {
							/* Get rid of video and data, if present */
							if(handle->streams && handle->video_stream) {
								handle->audio_stream->video_ssrc = handle->video_stream->video_ssrc;
								handle->audio_stream->video_ssrc_peer = handle->video_stream->video_ssrc_peer;
								handle->audio_stream->video_ssrc_peer_rtx = handle->video_stream->video_ssrc_peer_rtx;
								nice_agent_attach_recv(handle->agent, handle->video_stream->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
								if(!janus_ice_is_rtcpmux_forced())
									nice_agent_attach_recv(handle->agent, handle->video_stream->stream_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
								nice_agent_remove_stream(handle->agent, handle->video_stream->stream_id);
								janus_ice_stream_free(handle->streams, handle->video_stream);
							}
							handle->video_stream = NULL;
							handle->video_id = 0;
							if(handle->streams && handle->data_stream) {
								nice_agent_attach_recv(handle->agent, handle->data_stream->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
								nice_agent_remove_stream(handle->agent, handle->data_stream->stream_id);
								janus_ice_stream_free(handle->streams, handle->data_stream);
							}
							handle->data_stream = NULL;
							handle->data_id = 0;
						} else if(video) {
							/* Get rid of data, if present */
							if(handle->streams && handle->data_stream) {
								nice_agent_attach_recv(handle->agent, handle->data_stream->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
								nice_agent_remove_stream(handle->agent, handle->data_stream->stream_id);
								janus_ice_stream_free(handle->streams, handle->data_stream);
							}
							handle->data_stream = NULL;
							handle->data_id = 0;
						}
					}
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && !janus_ice_is_rtcpmux_forced()) {
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   -- rtcp-mux is supported by the browser, getting rid of RTCP components, if any...\n", handle->handle_id);
						if(handle->audio_stream && handle->audio_stream->components != NULL) {
							nice_agent_attach_recv(handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							/* Free the component */
							janus_ice_component_free(handle->audio_stream->components, handle->audio_stream->rtcp_component);
							handle->audio_stream->rtcp_component = NULL;
							/* Create a dummy candidate and enforce it as the one to use for this now unneeded component */
							NiceCandidate *c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
							c->component_id = 2;
							c->stream_id = handle->audio_stream->stream_id;
#ifndef HAVE_LIBNICE_TCP
							c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
#endif
							strncpy(c->foundation, "1", NICE_CANDIDATE_MAX_FOUNDATION);
							c->priority = 1;
							nice_address_set_from_string(&c->addr, "127.0.0.1");
							nice_address_set_port(&c->addr, janus_ice_get_rtcpmux_blackhole_port());
							c->username = g_strdup(handle->audio_stream->ruser);
							c->password = g_strdup(handle->audio_stream->rpass);
							if(!nice_agent_set_selected_remote_candidate(handle->agent, handle->audio_stream->stream_id, 2, c)) {
								JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error forcing dummy candidate on RTCP component of stream %d\n", handle->handle_id, handle->audio_stream->stream_id);
								nice_candidate_free(c);
							}
						}
						if(handle->video_stream && handle->video_stream->components != NULL) {
							nice_agent_attach_recv(handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
							/* Free the component */
							janus_ice_component_free(handle->video_stream->components, handle->video_stream->rtcp_component);
							handle->video_stream->rtcp_component = NULL;
							/* Create a dummy candidate and enforce it as the one to use for this now unneeded component */
							NiceCandidate *c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
							c->component_id = 2;
							c->stream_id = handle->video_stream->stream_id;
#ifndef HAVE_LIBNICE_TCP
							c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
#endif
							strncpy(c->foundation, "1", NICE_CANDIDATE_MAX_FOUNDATION);
							c->priority = 1;
							nice_address_set_from_string(&c->addr, "127.0.0.1");
							nice_address_set_port(&c->addr, janus_ice_get_rtcpmux_blackhole_port());
							c->username = g_strdup(handle->video_stream->ruser);
							c->password = g_strdup(handle->video_stream->rpass);
							if(!nice_agent_set_selected_remote_candidate(handle->agent, handle->video_stream->stream_id, 2, c)) {
								JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error forcing dummy candidate on RTCP component of stream %d\n", handle->handle_id, handle->video_stream->stream_id);
								nice_candidate_free(c);
							}
						}
					}
					/* FIXME Any disabled m-line? */
					if(strstr(jsep_sdp, "m=audio 0")) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio disabled via SDP\n", handle->handle_id);
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!video && !data)) {
							JANUS_LOG(LOG_HUGE, "  -- Marking audio stream as disabled\n");
							janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(handle->audio_id));
							if(stream)
								stream->disabled = TRUE;
						}
					}
					if(strstr(jsep_sdp, "m=video 0")) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video disabled via SDP\n", handle->handle_id);
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!audio && !data)) {
							JANUS_LOG(LOG_HUGE, "  -- Marking video stream as disabled\n");
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
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data Channel disabled via SDP\n", handle->handle_id);
						if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
								|| (!audio && !video)) {
							JANUS_LOG(LOG_HUGE, "  -- Marking data channel stream as disabled\n");
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
					/* We got our answer */
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
					/* Any pending trickles? */
					if(handle->pending_trickles) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Processing %d pending trickle candidates\n", handle->handle_id, g_list_length(handle->pending_trickles));
						GList *temp = NULL;
						while(handle->pending_trickles) {
							temp = g_list_first(handle->pending_trickles);
							handle->pending_trickles = g_list_remove_link(handle->pending_trickles, temp);
							janus_ice_trickle *trickle = (janus_ice_trickle *)temp->data;
							g_list_free(temp);
							if(trickle == NULL)
								continue;
							if((janus_get_monotonic_time() - trickle->received) > 15*G_USEC_PER_SEC) {
								/* FIXME Candidate is too old, discard it */
								janus_ice_trickle_destroy(trickle);
								/* FIXME We should report that */
								continue;
							}
							json_t *candidate = trickle->candidate;
							if(candidate == NULL) {
								janus_ice_trickle_destroy(trickle);
								continue;
							}
							if(json_is_object(candidate)) {
								/* We got a single candidate */
								int error = 0;
								const char *error_string = NULL;
								if((error = janus_ice_trickle_parse(handle, candidate, &error_string)) != 0) {
									/* FIXME We should report the error parsing the trickle candidate */
								}
							} else if(json_is_array(candidate)) {
								/* We got multiple candidates in an array */
								JANUS_LOG(LOG_VERB, "Got multiple candidates (%zu)\n", json_array_size(candidate));
								if(json_array_size(candidate) > 0) {
									/* Handle remote candidates */
									size_t i = 0;
									for(i=0; i<json_array_size(candidate); i++) {
										json_t *c = json_array_get(candidate, i);
										/* FIXME We don't care if any trickle fails to parse */
										janus_ice_trickle_parse(handle, c, NULL);
									}
								}
							}
							/* Done, free candidate */
							janus_ice_trickle_destroy(trickle);
						}
					}
					/* This was an answer, check if it's time to start ICE */
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) &&
							!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- ICE Trickling is supported by the browser, waiting for remote candidates...\n", handle->handle_id);
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
					} else {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Done! Sending connectivity checks...\n", handle->handle_id);
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
				}
			} else {
				/* TODO Actually handle session updates: for now we ignore them, and just relay them to plugins */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Ignoring negotiation update, we don't support them yet...\n", handle->handle_id);
			}
			handle->remote_sdp = g_strdup(jsep_sdp);
			janus_mutex_unlock(&handle->mutex);
			/* Anonymize SDP */
			jsep_sdp_stripped = janus_sdp_anonymize(jsep_sdp);
			if(jsep_sdp_stripped == NULL) {
				/* Invalid SDP */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "JSEP error: invalid SDP");
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			sdp = NULL;
			janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
		}

		/* Make sure the app handle is still valid */
		if(handle->app == NULL || handle->app_handle == NULL || !janus_plugin_session_is_alive(handle->app_handle)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this message");
			if(jsep_type)
				g_free(jsep_type);
			if(jsep_sdp_stripped)
				g_free(jsep_sdp_stripped);
			janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
			goto jsondone;
		}

		/* Send the message to the plugin (which must eventually free transaction_text, body_text, jsep_type and sdp) */
		char *body_text = json_dumps(body, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		janus_plugin_result *result = plugin_t->handle_message(handle->app_handle, g_strdup((char *)transaction_text), body_text, jsep_type, jsep_sdp_stripped);
		if(result == NULL) {
			/* Something went horribly wrong! */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin didn't give a result");
			goto jsondone;
		}
		if(result->type == JANUS_PLUGIN_OK) {
			/* The plugin gave a result already (synchronous request/response) */
			if(result->content == NULL) {
				/* Missing content... */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin didn't provide any content for this synchronous response");
				janus_plugin_result_destroy(result);
				goto jsondone;
			}
			json_error_t error;
			json_t *event = json_loads(result->content, 0, &error);
			if(!event) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot send response from plugin (JSON error: on line %d: %s)\n", handle->handle_id, error.line, error.text);
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin returned an invalid JSON response");
				janus_plugin_result_destroy(result);
				goto jsondone;
			}
			if(!json_is_object(event)) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot send response from plugin (JSON error: not an object)\n", handle->handle_id);
				json_decref(event);
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin returned an invalid JSON response");
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
			json_object_set_new(plugin_data, "data", event);
			json_object_set_new(reply, "plugindata", plugin_data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
		} else if(result->type == JANUS_PLUGIN_OK_WAIT) {
			/* The plugin received the request but didn't process it yet, send an ack (asynchronous notifications may follow) */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("ack"));
			json_object_set_new(reply, "session_id", json_integer(session_id));
			if(result->content)
				json_object_set_new(reply, "hint", json_string(result->content));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
		} else {
			/* Something went horribly wrong! */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "%s", result->content ? g_strdup(result->content) : "Plugin returned a severe (unknown) error");
			janus_plugin_result_destroy(result);
			goto jsondone;
		}			
		janus_plugin_result_destroy(result);
	} else if(!strcasecmp(message_text, "trickle")) {
		if(handle == NULL) {
			/* Trickle is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL || !janus_plugin_session_is_alive(handle->app_handle)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this trickle candidate");
			goto jsondone;
		}
		json_t *candidate = json_object_get(root, "candidate");
		json_t *candidates = json_object_get(root, "candidates");
		if(candidate == NULL && candidates == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (candidate|candidates)");
			goto jsondone;
		}
		if(candidate != NULL && candidates != NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_JSON, "Can't have both candidate and candidates");
			goto jsondone;
		}
		janus_mutex_lock(&handle->mutex);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)) {
			/* It looks like this peer supports Trickle, after all */
			JANUS_LOG(LOG_VERB, "Handle %"SCNu64" supports trickle even if it didn't negotiate it...\n", handle->handle_id);
			janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
		}
		/* Is there any stream ready? this trickle may get here before the SDP it relates to */
		if(handle->audio_stream == NULL && handle->video_stream == NULL && handle->data_stream == NULL) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] No stream, queueing this trickle as it got here before the SDP...\n", handle->handle_id);
			/* Enqueue this trickle candidate(s), we'll process this later */
			janus_ice_trickle *early_trickle = janus_ice_trickle_new(handle, transaction_text, candidate ? candidate : candidates);
			handle->pending_trickles = g_list_append(handle->pending_trickles, early_trickle);
			/* Send the ack right away, an event will tell the application if the candidate(s) failed */
			goto trickledone;
		}
		/* Is the ICE stack ready already? */
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER) ||
				!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER) ||
				!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER)) {
			const char *cause = NULL;
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER))
				cause = "processing the offer";
			else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER))
				cause = "waiting for the answer";
			else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER))
				cause = "waiting for the offer";
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still %s, queueing this trickle to wait until we're done there...\n",
				handle->handle_id, cause);
			/* Enqueue this trickle candidate(s), we'll process this later */
			janus_ice_trickle *early_trickle = janus_ice_trickle_new(handle, transaction_text, candidate ? candidate : candidates);
			handle->pending_trickles = g_list_append(handle->pending_trickles, early_trickle);
			/* Send the ack right away, an event will tell the application if the candidate(s) failed */
			goto trickledone;
		}
		if(candidate != NULL) {
			/* We got a single candidate */
			int error = 0;
			const char *error_string = NULL;
			if((error = janus_ice_trickle_parse(handle, candidate, &error_string)) != 0) {
				ret = janus_process_error(request, session_id, transaction_text, error, "%s", error_string);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
		} else {
			/* We got multiple candidates in an array */
			if(!json_is_array(candidates)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "candidates is not an array");
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			JANUS_LOG(LOG_VERB, "Got multiple candidates (%zu)\n", json_array_size(candidates));
			if(json_array_size(candidates) > 0) {
				/* Handle remote candidates */
				size_t i = 0;
				for(i=0; i<json_array_size(candidates); i++) {
					json_t *c = json_array_get(candidates, i);
					/* FIXME We don't care if any trickle fails to parse */
					janus_ice_trickle_parse(handle, c, NULL);
				}
			}
		}

trickledone:
		janus_mutex_unlock(&handle->mutex);
		/* We reply right away, not to block the web server... */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN_REQUEST, "Unknown request '%s'", message_text);
	}

jsondone:
	/* Done processing */
	return ret;
}

/* Admin/monitor WebServer requests handler */
int janus_process_incoming_admin_request(janus_request *request) {
	int ret = -1;
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or payload to process, giving up...\n");
		return ret;
	}
	json_t *root = request->message;
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
		ret = janus_process_error(request, session_id, NULL, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (transaction)");
		goto jsondone;
	}
	if(!json_is_string(transaction)) {
		ret = janus_process_error(request, session_id, NULL, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (transaction should be a string)");
		goto jsondone;
	}
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	if(!message) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (janus)");
		goto jsondone;
	}
	if(!json_is_string(message)) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (janus should be a string)");
		goto jsondone;
	}
	const gchar *message_text = json_string_value(message);
	
	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Get all sessions' or some general setting manipulation request */
		if(!strcasecmp(message_text, "info")) {
			/* The generic info request */
			ret = janus_process_success(request, janus_info(transaction_text));
			goto jsondone;
		}
		if(admin_api_secret != NULL) {
			/* There's an admin/monitor secret, check that the client provided it */
			json_t *secret = json_object_get(root, "admin_secret");
			if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_api_secret)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
				goto jsondone;
			}
		}
		if(!strcasecmp(message_text, "get_status")) {
			/* Return some info on the settings (mostly debug-related, at the moment) */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *status = json_object();
			json_object_set_new(status, "token_auth", json_integer(janus_auth_is_enabled()));
			json_object_set_new(status, "log_level", json_integer(janus_log_level));
			json_object_set_new(status, "log_timestamps", json_integer(janus_log_timestamps));
			json_object_set_new(status, "log_colors", json_integer(janus_log_colors));
			json_object_set_new(status, "locking_debug", json_integer(lock_debug));
			json_object_set_new(status, "libnice_debug", json_integer(janus_ice_is_ice_debugging_enabled()));
			json_object_set_new(status, "max_nack_queue", json_integer(janus_get_max_nack_queue()));
			json_object_set_new(reply, "status", status);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_level")) {
			/* Change the debug logging level */
			json_t *level = json_object_get(root, "level");
			if(!level) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (level)");
				goto jsondone;
			}
			if(!json_is_integer(level) || json_integer_value(level) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (level should be a positive integer)");
				goto jsondone;
			}
			int level_num = json_integer_value(level);
			if(level_num < LOG_NONE || level_num > LOG_MAX) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (level should be between %d and %d)", LOG_NONE, LOG_MAX);
				goto jsondone;
			}
			janus_log_level = level_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "level", json_integer(janus_log_level));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_locking_debug")) {
			/* Enable/disable the locking debug (would show a message on the console for every lock attempt) */
			json_t *debug = json_object_get(root, "debug");
			if(!debug) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (debug)");
				goto jsondone;
			}
			if(!json_is_integer(debug) || json_integer_value(debug) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be a positive integer)");
				goto jsondone;
			}
			int debug_num = json_integer_value(debug);
			if(debug_num < 0 || debug_num > 1) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be either 0 or 1)");
				goto jsondone;
			}
			lock_debug = debug_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "locking_debug", json_integer(lock_debug));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_timestamps")) {
			/* Enable/disable the log timestamps */
			json_t *timestamps = json_object_get(root, "timestamps");
			if(!timestamps) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (timestamps)");
				goto jsondone;
			}
			if(!json_is_integer(timestamps) || json_integer_value(timestamps) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (timestamps should be a positive integer)");
				goto jsondone;
			}
			int timestamps_num = json_integer_value(timestamps);
			if(timestamps_num < 0 || timestamps_num > 1) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (timestamps should be either 0 or 1)");
				goto jsondone;
			}
			janus_log_timestamps = timestamps_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "log_timestamps", json_integer(janus_log_timestamps));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_colors")) {
			/* Enable/disable the log colors */
			json_t *colors = json_object_get(root, "colors");
			if(!colors) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (colors)");
				goto jsondone;
			}
			if(!json_is_integer(colors) || json_integer_value(colors) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (colors should be a positive integer)");
				goto jsondone;
			}
			int colors_num = json_integer_value(colors);
			if(colors_num < 0 || colors_num > 1) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (colors should be either 0 or 1)");
				goto jsondone;
			}
			janus_log_colors = colors_num;
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "log_colors", json_integer(janus_log_colors));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_libnice_debug")) {
			/* Enable/disable the libnice debugging (http://nice.freedesktop.org/libnice/libnice-Debug-messages.html) */
			json_t *debug = json_object_get(root, "debug");
			if(!debug) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (debug)");
				goto jsondone;
			}
			if(!json_is_integer(debug) || json_integer_value(debug) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be a positive integer)");
				goto jsondone;
			}
			int debug_num = json_integer_value(debug);
			if(debug_num < 0 || debug_num > 1) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (debug should be either 0 or 1)");
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
			json_object_set_new(reply, "libnice_debug", json_integer(janus_ice_is_ice_debugging_enabled()));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_max_nack_queue")) {
			/* Change the current value for the max NACK queue */
			json_t *mnq = json_object_get(root, "max_nack_queue");
			if(!mnq) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (max_nack_queue)");
				goto jsondone;
			}
			if(!json_is_integer(mnq) || json_integer_value(mnq) < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (max_nack_queue should be a positive integer)");
				goto jsondone;
			}
			int mnq_num = json_integer_value(mnq);
			if(mnq_num < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (max_nack_queue should be a positive integer)");
				goto jsondone;
			}
			janus_set_max_nack_queue(mnq_num);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "max_nack_queue", json_integer(janus_get_max_nack_queue()));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
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
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "add_token")) {
			/* Add a token valid for authentication */
			if(!janus_auth_is_enabled()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Token based authentication disabled");
				goto jsondone;
			}
			json_t *token = json_object_get(root, "token");
			if(!token) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (token)");
				goto jsondone;
			}
			if(!json_is_string(token)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (token should be a string)");
				goto jsondone;
			}
			const char *token_value = json_string_value(token);
			/* Any plugin this token should be limited to? */
			json_t *allowed = json_object_get(root, "plugins");
			if(allowed && !json_is_array(allowed)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (plugins should be an array)");
				goto jsondone;
			}
			/* First of all, add the new token */
			if(!janus_auth_add_token(token_value)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error adding token");
				goto jsondone;
			}
			/* Then take care of the plugins access limitations, if any */
			if(allowed && json_array_size(allowed) > 0) {
				/* Specify which plugins this token has access to */
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					json_t *p = json_array_get(allowed, i);
					if(!p || !json_is_string(p)) {
						/* FIXME Should we fail here? */
						JANUS_LOG(LOG_WARN, "Invalid plugin passed to the new token request, skipping...\n");
						continue;
					}
					const gchar *plugin_text = json_string_value(p);
					janus_plugin *plugin_t = janus_plugin_find(plugin_text);
					if(plugin_t == NULL) {
						/* FIXME Should we fail here? */
						JANUS_LOG(LOG_WARN, "No such plugin '%s' passed to the new token request, skipping...\n", plugin_text);
						continue;
					}
					if(!janus_auth_allow_plugin(token_value, plugin_t)) {
						JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_text);
					}
				}
			} else {
				/* No plugin limitation specified, allow all plugins */
				if(plugins && g_hash_table_size(plugins) > 0) {
					GHashTableIter iter;
					gpointer value;
					g_hash_table_iter_init(&iter, plugins);
					while (g_hash_table_iter_next(&iter, NULL, &value)) {
						janus_plugin *plugin_t = value;
						if(plugin_t == NULL)
							continue;
						if(!janus_auth_allow_plugin(token_value, plugin_t)) {
							JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_t->get_package());
						}
					}
				}
			}
			/* Get the list of plugins this new token can access */
			json_t *plugins_list = json_array();
			GList *plugins = janus_auth_list_plugins(token_value);
			if(plugins != NULL) {
				GList *tmp = plugins;
				while(tmp) {
					janus_plugin *p = (janus_plugin *)tmp->data;
					if(p != NULL)
						json_array_append_new(plugins_list, json_string(p->get_package()));
					tmp = tmp->next;
				}
				g_list_free(plugins);
				plugins = NULL;
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *data = json_object();
			json_object_set_new(data, "plugins", plugins_list);
			json_object_set_new(reply, "data", data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "list_tokens")) {
			/* List all the valid tokens */
			if(!janus_auth_is_enabled()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Token based authentication disabled");
				goto jsondone;
			}
			json_t *tokens_list = json_array();
			GList *list = janus_auth_list_tokens();
			if(list != NULL) {
				GList *tmp = list;
				while(tmp) {
					char *token = (char *)tmp->data;
					if(token != NULL) {
						GList *plugins = janus_auth_list_plugins(token);
						if(plugins != NULL) {
							json_t *t = json_object();
							json_object_set_new(t, "token", json_string(token));
							json_t *plugins_list = json_array();
							GList *tmp2 = plugins;
							while(tmp2) {
								janus_plugin *p = (janus_plugin *)tmp2->data;
								if(p != NULL)
									json_array_append_new(plugins_list, json_string(p->get_package()));
								tmp2 = tmp2->next;
							}
							g_list_free(plugins);
							plugins = NULL;
							json_object_set_new(t, "allowed_plugins", plugins_list);
							json_array_append_new(tokens_list, t);
						}
						tmp->data = NULL;
						g_free(token);
					}
					tmp = tmp->next;
				}
				g_list_free(list);
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *data = json_object();
			json_object_set_new(data, "tokens", tokens_list);
			json_object_set_new(reply, "data", data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "allow_token")) {
			/* Allow a valid token valid to access a plugin */
			if(!janus_auth_is_enabled()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Token based authentication disabled");
				goto jsondone;
			}
			json_t *token = json_object_get(root, "token");
			if(!token) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (token)");
				goto jsondone;
			}
			if(!json_is_string(token)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (token should be a string)");
				goto jsondone;
			}
			const char *token_value = json_string_value(token);
			/* Check if the token is valid, first */
			if(!janus_auth_check_token(token_value)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_TOKEN_NOT_FOUND, "Token %s not found", token_value);
				goto jsondone;
			}
			/* Any plugin this token should be limited to? */
			json_t *allowed = json_object_get(root, "plugins");
			if(!allowed) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (plugins)");
				goto jsondone;
			}
			if(!json_is_array(allowed) || json_array_size(allowed) == 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (plugins should be an array)");
				goto jsondone;
			}
			/* Check the list first */
			size_t i = 0;
			gboolean ok = TRUE;
			for(i=0; i<json_array_size(allowed); i++) {
				json_t *p = json_array_get(allowed, i);
				if(!p || !json_is_string(p)) {
					/* FIXME Should we fail here? */
					JANUS_LOG(LOG_ERR, "Invalid plugin passed to the new token request...\n");
					ok = FALSE;
					break;
				}
				const gchar *plugin_text = json_string_value(p);
				janus_plugin *plugin_t = janus_plugin_find(plugin_text);
				if(plugin_t == NULL) {
					/* FIXME Should we fail here? */
					JANUS_LOG(LOG_ERR, "No such plugin '%s' passed to the new token request...\n", plugin_text);
					ok = FALSE;
					break;
				}
			}
			if(!ok) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (some of the provided plugins are invalid)");
				goto jsondone;
			}
			/* Take care of the plugins access limitations */
			i = 0;
			for(i=0; i<json_array_size(allowed); i++) {
				json_t *p = json_array_get(allowed, i);
				const gchar *plugin_text = json_string_value(p);
				janus_plugin *plugin_t = janus_plugin_find(plugin_text);
				if(!janus_auth_allow_plugin(token_value, plugin_t)) {
					/* FIXME Should we notify individual failures? */
					JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_text);
				}
			}
			/* Get the list of plugins this new token can now access */
			json_t *plugins_list = json_array();
			GList *plugins = janus_auth_list_plugins(token_value);
			if(plugins != NULL) {
				GList *tmp = plugins;
				while(tmp) {
					janus_plugin *p = (janus_plugin *)tmp->data;
					if(p != NULL)
						json_array_append_new(plugins_list, json_string(p->get_package()));
					tmp = tmp->next;
				}
				g_list_free(plugins);
				plugins = NULL;
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *data = json_object();
			json_object_set_new(data, "plugins", plugins_list);
			json_object_set_new(reply, "data", data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "disallow_token")) {
			/* Disallow a valid token valid from accessing a plugin */
			if(!janus_auth_is_enabled()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Token based authentication disabled");
				goto jsondone;
			}
			json_t *token = json_object_get(root, "token");
			if(!token) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (token)");
				goto jsondone;
			}
			if(!json_is_string(token)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (token should be a string)");
				goto jsondone;
			}
			const char *token_value = json_string_value(token);
			/* Check if the token is valid, first */
			if(!janus_auth_check_token(token_value)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_TOKEN_NOT_FOUND, "Token %s not found", token_value);
				goto jsondone;
			}
			/* Any plugin this token should be prevented access to? */
			json_t *allowed = json_object_get(root, "plugins");
			if(!allowed) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (plugins)");
				goto jsondone;
			}
			if(!json_is_array(allowed) || json_array_size(allowed) == 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (plugins should be an array)");
				goto jsondone;
			}
			/* Check the list first */
			size_t i = 0;
			gboolean ok = TRUE;
			for(i=0; i<json_array_size(allowed); i++) {
				json_t *p = json_array_get(allowed, i);
				if(!p || !json_is_string(p)) {
					/* FIXME Should we fail here? */
					JANUS_LOG(LOG_ERR, "Invalid plugin passed to the new token request...\n");
					ok = FALSE;
					break;
				}
				const gchar *plugin_text = json_string_value(p);
				janus_plugin *plugin_t = janus_plugin_find(plugin_text);
				if(plugin_t == NULL) {
					/* FIXME Should we fail here? */
					JANUS_LOG(LOG_ERR, "No such plugin '%s' passed to the new token request...\n", plugin_text);
					ok = FALSE;
					break;
				}
			}
			if(!ok) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (some of the provided plugins are invalid)");
				goto jsondone;
			}
			/* Take care of the plugins access limitations */
			i = 0;
			for(i=0; i<json_array_size(allowed); i++) {
				json_t *p = json_array_get(allowed, i);
				const gchar *plugin_text = json_string_value(p);
				janus_plugin *plugin_t = janus_plugin_find(plugin_text);
				if(!janus_auth_disallow_plugin(token_value, plugin_t)) {
					/* FIXME Should we notify individual failures? */
					JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_text);
				}
			}
			/* Get the list of plugins this new token can now access */
			json_t *plugins_list = json_array();
			GList *plugins = janus_auth_list_plugins(token_value);
			if(plugins != NULL) {
				GList *tmp = plugins;
				while(tmp) {
					janus_plugin *p = (janus_plugin *)tmp->data;
					if(p != NULL)
						json_array_append_new(plugins_list, json_string(p->get_package()));
					tmp = tmp->next;
				}
				g_list_free(plugins);
				plugins = NULL;
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_t *data = json_object();
			json_object_set_new(data, "plugins", plugins_list);
			json_object_set_new(reply, "data", data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "remove_token")) {
			/* Invalidate a token for authentication purposes */
			if(!janus_auth_is_enabled()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Token based authentication disabled");
				goto jsondone;
			}
			json_t *token = json_object_get(root, "token");
			if(!token) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (token)");
				goto jsondone;
			}
			if(!json_is_string(token)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (token should be a string)");
				goto jsondone;
			}
			const char *token_value = json_string_value(token);
			if(!janus_auth_remove_token(token_value)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error removing token");
				goto jsondone;
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else {
			/* No message we know of */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	if(admin_api_secret != NULL) {
		/* There's an API secret, check that the client provided it */
		json_t *secret = json_object_get(root, "admin_secret");
		if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_api_secret)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	janus_session *session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	janus_ice_handle *handle = NULL;
	if(handle_id > 0) {
		handle = janus_ice_handle_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}

	/* What is this? */
	if(handle == NULL) {
		/* Session-related */
		if(strcasecmp(message_text, "list_handles")) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
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
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	} else {
		/* Handle-related */
		if(strcasecmp(message_text, "handle_info")) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		/* Prepare info */
		janus_mutex_lock(&handle->mutex);
		json_t *info = json_object();
		json_object_set_new(info, "session_id", json_integer(session_id));
		json_object_set_new(info, "session_last_activity", json_integer(session->last_activity));
		if(session->source && session->source->transport)
			json_object_set_new(info, "session_transport", json_string(session->source->transport->get_package()));
		json_object_set_new(info, "handle_id", json_integer(handle_id));
		json_object_set_new(info, "created", json_integer(handle->created));
		json_object_set_new(info, "current_time", json_integer(janus_get_monotonic_time()));
		if(handle->app && handle->app_handle && janus_plugin_session_is_alive(handle->app_handle)) {
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
		json_object_set_new(flags, "got-offer", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER)));
		json_object_set_new(flags, "got-answer", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER)));
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
		json_object_set_new(flags, "has-audio", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)));
		json_object_set_new(flags, "has-video", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)));
		json_object_set_new(flags, "plan-b", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)));
		json_object_set_new(flags, "cleaning", json_integer(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)));
		json_object_set_new(info, "flags", flags);
		if(handle->agent) {
			json_object_set_new(info, "agent-created", json_integer(handle->agent_created));
			json_object_set_new(info, "ice-mode", json_string(janus_ice_is_ice_lite_enabled() ? "lite" : "full"));
			json_object_set_new(info, "ice-role", json_string(handle->controlling ? "controlling" : "controlled"));
		}
		json_t *sdps = json_object();
		if(handle->local_sdp)
			json_object_set_new(sdps, "local", json_string(handle->local_sdp));
		if(handle->remote_sdp)
			json_object_set_new(sdps, "remote", json_string(handle->remote_sdp));
		json_object_set_new(info, "sdps", sdps);
		if(handle->pending_trickles)
			json_object_set_new(info, "pending-trickles", json_integer(g_list_length(handle->pending_trickles)));
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
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	}

jsondone:
	/* Done processing */
	return ret;
}

int janus_process_success(janus_request *request, json_t *payload)
{
	if(!request || !payload)
		return -1;
	/* Pass to the right transport plugin */
	JANUS_LOG(LOG_HUGE, "Sending %s API response to %s (%p)\n", request->admin ? "admin" : "Janus", request->transport->get_package(), request->instance);
	return request->transport->send_message(request->instance, request->request_id, request->admin, payload);
}

int janus_process_error(janus_request *request, uint64_t session_id, const char *transaction, gint error, const char *format, ...)
{
	if(!request)
		return -1;
	gchar *error_string = NULL;
	gchar error_buf[512];
	if(format == NULL) {
		/* No error string provided, use the default one */
		error_string = (gchar *)janus_get_api_error(error);
	} else {
		/* This callback has variable arguments (error string) */
		va_list ap;
		va_start(ap, format);
		g_vsnprintf(error_buf, sizeof(error_buf), format, ap);
		va_end(ap);
		error_string = error_buf;
	}
	/* Done preparing error */
	JANUS_LOG(LOG_VERB, "[%s] Returning %s API error %d (%s)\n", transaction, request->admin ? "admin" : "Janus", error, error_string);
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
	/* Pass to the right transport plugin */
	return request->transport->send_message(request->instance, request->request_id, request->admin, reply);
}


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
	if(stream->video_ssrc_peer_rtx)
		json_object_set_new(ss, "video-peer-rtx", json_integer(stream->video_ssrc_peer_rtx));
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
	if(component->component_connected > 0)
		json_object_set_new(c, "connected", json_integer(component->component_connected));
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
		json_object_set_new(d, "remote-fingerprint", json_string(component->stream->remote_fingerprint));
		json_object_set_new(d, "remote-fingerprint-hash", json_string(component->stream->remote_hashing));
		json_object_set_new(d, "dtls-role", json_string(janus_get_dtls_srtp_role(component->stream->dtls_role)));
		json_object_set_new(d, "dtls-state", json_string(janus_get_dtls_srtp_state(dtls->dtls_state)));
		json_object_set_new(d, "valid", json_integer(dtls->srtp_valid));
		json_object_set_new(d, "ready", json_integer(dtls->ready));
		if(dtls->dtls_connected > 0)
			json_object_set_new(d, "connected", json_integer(dtls->dtls_connected));
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


/* Transports */
void janus_transport_close(gpointer key, gpointer value, gpointer user_data) {
	janus_transport *transport = (janus_transport *)value;
	if(!transport)
		return;
	transport->destroy();
}

void janus_transportso_close(gpointer key, gpointer value, gpointer user_data) {
	void *transport = (janus_transport *)value;
	if(!transport)
		return;
	//~ dlclose(transport);
}

/* Transport callback interface */
void janus_transport_incoming_request(janus_transport *plugin, void *transport, void *request_id, gboolean admin, json_t *message, json_error_t *error) {
	JANUS_LOG(LOG_VERB, "Got %s API request from %s (%p)\n", admin ? "an admin" : "a Janus", plugin->get_package(), transport);
	/* Create a janus_request instance to handle the request */
	janus_request *request = janus_request_new(plugin, transport, request_id, admin, message);
	GError *tperror = NULL;
	g_thread_pool_push(tasks, request, &tperror);
	if(tperror != NULL) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to push task in thread pool...\n", tperror->code, tperror->message ? tperror->message : "??");
		json_t *transaction = json_object_get(message, "transaction");
		const char *transaction_text = json_is_string(transaction) ? json_string_value(transaction) : NULL;
		janus_process_error(request, 0, transaction_text, JANUS_ERROR_UNKNOWN, "Thread pool error");
		janus_request_destroy(request);
	}
}

void janus_transport_gone(janus_transport *plugin, void *transport) {
	/* Get rid of sessions this transport was handling */
	JANUS_LOG(LOG_VERB, "A %s transport instance has gone away (%p)\n", plugin->get_package(), transport);
	janus_mutex_lock(&sessions_mutex);
	if(sessions && g_hash_table_size(sessions) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, sessions);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_session *session = (janus_session *) value;
			if(!session || session->destroy || session->timeout || session->last_activity == 0)
				continue;
			if(session->source && session->source->instance == transport) {
				JANUS_LOG(LOG_VERB, "  -- Marking Session %"SCNu64" as over\n", session->session_id);
				session->last_activity = 0;	/* This will trigger a timeout */
			}
		}
	}
	janus_mutex_unlock(&sessions_mutex);
}

gboolean janus_transport_is_api_secret_needed(janus_transport *plugin) {
	return api_secret != NULL;
}

gboolean janus_transport_is_api_secret_valid(janus_transport *plugin, const char *apisecret) {
	if(api_secret == NULL)
		return TRUE;
	return apisecret && janus_strcmp_const_time(apisecret, api_secret);
}

gboolean janus_transport_is_auth_token_needed(janus_transport *plugin) {
	return janus_auth_is_enabled();
}

gboolean janus_transport_is_auth_token_valid(janus_transport *plugin, const char *token) {
	if(!janus_auth_is_enabled())
		return TRUE;
	return token && janus_auth_check_token(token);
}

void janus_transport_task(gpointer data, gpointer user_data) {
	JANUS_LOG(LOG_VERB, "Transport task pool, serving request\n");
	janus_request *request = (janus_request *)data;
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request\n");
		return;
	}
	if(!request->admin)
		janus_process_incoming_request(request);
	else
		janus_process_incoming_admin_request(request);
	/* Done */
	janus_request_destroy(request);
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
int janus_plugin_push_event(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *transaction, const char *message, const char *sdp_type, const char *sdp) {
	if(!plugin || !message)
		return -1;
	if(!plugin_session || plugin_session < (janus_plugin_session *)0x1000 ||
			!janus_plugin_session_is_alive(plugin_session) || plugin_session->stopped)
		return -2;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP))
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = ice_handle->session;
	if(!session || session->destroy)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	/* Make sure this is JSON */
	json_error_t error;
	json_t *plugin_event = json_loads(message, 0, &error);
	if(!plugin_event) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: on line %d: %s)\n", ice_handle->handle_id, error.line, error.text);
		return JANUS_ERROR_INVALID_JSON;
	}
	if(!json_is_object(plugin_event)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: not an object)\n", ice_handle->handle_id);
		return JANUS_ERROR_INVALID_JSON_OBJECT;
	}
	/* Attach JSEP if possible? */
	json_t *jsep = NULL;
	if(sdp_type != NULL && sdp != NULL) {
		jsep = janus_plugin_handle_sdp(plugin_session, plugin, sdp_type, sdp);
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
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("event"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(ice_handle->handle_id));
	if(transaction != NULL)
		json_object_set_new(event, "transaction", json_string(transaction));
	json_t *plugin_data = json_object();
	json_object_set_new(plugin_data, "plugin", json_string(plugin->get_package()));
	json_object_set_new(plugin_data, "data", plugin_event);
	json_object_set_new(event, "plugindata", plugin_data);
	if(jsep != NULL)
		json_object_set_new(event, "jsep", jsep);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", ice_handle->handle_id);
	janus_session_notify_event(session->session_id, event);
	
	return JANUS_OK;
}

json_t *janus_plugin_handle_sdp(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *sdp_type, const char *sdp) {
	if(!plugin_session || plugin_session < (janus_plugin_session *)0x1000 ||
			!janus_plugin_session_is_alive(plugin_session) || plugin_session->stopped ||
			plugin == NULL || sdp_type == NULL || sdp == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid arguments\n");
		return NULL;
	}
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	//~ if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
	if(ice_handle == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid ICE handle\n");
		return NULL;
	}
	int offer = 0;
	if(!strcasecmp(sdp_type, "offer")) {
		/* This is an offer from a plugin */
		offer = 1;
		janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
		janus_flags_clear(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	} else if(!strcasecmp(sdp_type, "answer")) {
		/* This is an answer from a plugin */
		janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	} else {
		/* TODO Handle other messages */
		JANUS_LOG(LOG_ERR, "Unknown type '%s'\n", sdp_type);
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
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", ice_handle->handle_id);
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
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Waiting for candidates-done callback...\n", ice_handle->handle_id);
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
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid SDP\n", ice_handle->handle_id);
		return NULL;
	}
	/* Add our details */
	char *sdp_merged = janus_sdp_merge(ice_handle, sdp_stripped);
	if(sdp_merged == NULL) {
		/* Couldn't merge SDP */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error merging SDP\n", ice_handle->handle_id);
		g_free(sdp_stripped);
		return NULL;
	}
	/* FIXME Any disabled m-line? */
	if(strstr(sdp_merged, "m=audio 0")) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Audio disabled via SDP\n", ice_handle->handle_id);
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!video && !data)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Marking audio stream as disabled\n", ice_handle->handle_id);
			janus_ice_stream *stream = g_hash_table_lookup(ice_handle->streams, GUINT_TO_POINTER(ice_handle->audio_id));
			if(stream)
				stream->disabled = TRUE;
		}
	}
	if(strstr(sdp_merged, "m=video 0")) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video disabled via SDP\n", ice_handle->handle_id);
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!audio && !data)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Marking video stream as disabled\n", ice_handle->handle_id);
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
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Data Channel disabled via SDP\n", ice_handle->handle_id);
		if(!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				|| (!audio && !video)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Marking data channel stream as disabled\n", ice_handle->handle_id);
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
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Done! Ready to setup remote candidates and send connectivity checks...\n", ice_handle->handle_id);
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) && audio && video) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- bundle is supported by the browser, getting rid of one of the RTP/RTCP components, if any...\n", ice_handle->handle_id);
				if(audio) {
					/* Get rid of video and data, if present */
					if(ice_handle->streams && ice_handle->video_stream) {
						ice_handle->audio_stream->video_ssrc = ice_handle->video_stream->video_ssrc;
						ice_handle->audio_stream->video_ssrc_peer = ice_handle->video_stream->video_ssrc_peer;
						ice_handle->audio_stream->video_ssrc_peer_rtx = ice_handle->video_stream->video_ssrc_peer_rtx;
						nice_agent_attach_recv(ice_handle->agent, ice_handle->video_stream->stream_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
						if(!janus_ice_is_rtcpmux_forced())
							nice_agent_attach_recv(ice_handle->agent, ice_handle->video_stream->stream_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
						nice_agent_remove_stream(ice_handle->agent, ice_handle->video_stream->stream_id);
						janus_ice_stream_free(ice_handle->streams, ice_handle->video_stream);
					}
					ice_handle->video_stream = NULL;
					ice_handle->video_id = 0;
					if(ice_handle->streams && ice_handle->data_stream) {
						nice_agent_attach_recv(ice_handle->agent, ice_handle->data_stream->stream_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
						nice_agent_remove_stream(ice_handle->agent, ice_handle->data_stream->stream_id);
						janus_ice_stream_free(ice_handle->streams, ice_handle->data_stream);
					}
					ice_handle->data_stream = NULL;
					ice_handle->data_id = 0;
				} else if(video) {
					/* Get rid of data, if present */
					if(ice_handle->streams && ice_handle->data_stream) {
						nice_agent_attach_recv(ice_handle->agent, ice_handle->data_stream->stream_id, 1, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
						nice_agent_remove_stream(ice_handle->agent, ice_handle->data_stream->stream_id);
						janus_ice_stream_free(ice_handle->streams, ice_handle->data_stream);
					}
					ice_handle->data_stream = NULL;
					ice_handle->data_id = 0;
				}
			}
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && !janus_ice_is_rtcpmux_forced()) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- rtcp-mux is supported by the browser, getting rid of RTCP components, if any...\n", ice_handle->handle_id);
				if(ice_handle->audio_stream && ice_handle->audio_stream->rtcp_component && ice_handle->audio_stream->components != NULL) {
					nice_agent_attach_recv(ice_handle->agent, ice_handle->audio_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					/* Free the component */
					janus_ice_component_free(ice_handle->audio_stream->components, ice_handle->audio_stream->rtcp_component);
					ice_handle->audio_stream->rtcp_component = NULL;
					/* Create a dummy candidate and enforce it as the one to use for this now unneeded component */
					NiceCandidate *c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
					c->component_id = 2;
					c->stream_id = ice_handle->audio_stream->stream_id;
#ifndef HAVE_LIBNICE_TCP
					c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
#endif
					strncpy(c->foundation, "1", NICE_CANDIDATE_MAX_FOUNDATION);
					c->priority = 1;
					nice_address_set_from_string(&c->addr, "127.0.0.1");
					nice_address_set_port(&c->addr, janus_ice_get_rtcpmux_blackhole_port());
					c->username = g_strdup(ice_handle->audio_stream->ruser);
					c->password = g_strdup(ice_handle->audio_stream->rpass);
					if(!nice_agent_set_selected_remote_candidate(ice_handle->agent, ice_handle->audio_stream->stream_id, 2, c)) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error forcing dummy candidate on RTCP component of stream %d\n", ice_handle->handle_id, ice_handle->audio_stream->stream_id);
						nice_candidate_free(c);
					}
				}
				if(ice_handle->video_stream && ice_handle->video_stream->rtcp_component && ice_handle->video_stream->components != NULL) {
					nice_agent_attach_recv(ice_handle->agent, ice_handle->video_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
					/* Free the component */
					janus_ice_component_free(ice_handle->video_stream->components, ice_handle->video_stream->rtcp_component);
					ice_handle->video_stream->rtcp_component = NULL;
					/* Create a dummy candidate and enforce it as the one to use for this now unneeded component */
					NiceCandidate *c = nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
					c->component_id = 2;
					c->stream_id = ice_handle->video_stream->stream_id;
#ifndef HAVE_LIBNICE_TCP
					c->transport = NICE_CANDIDATE_TRANSPORT_UDP;
#endif
					strncpy(c->foundation, "1", NICE_CANDIDATE_MAX_FOUNDATION);
					c->priority = 1;
					nice_address_set_from_string(&c->addr, "127.0.0.1");
					nice_address_set_port(&c->addr, janus_ice_get_rtcpmux_blackhole_port());
					c->username = g_strdup(ice_handle->video_stream->ruser);
					c->password = g_strdup(ice_handle->video_stream->rpass);
					if(!nice_agent_set_selected_remote_candidate(ice_handle->agent, ice_handle->video_stream->stream_id, 2, c)) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error forcing dummy candidate on RTCP component of stream %d\n", ice_handle->handle_id, ice_handle->video_stream->stream_id);
						nice_candidate_free(c);
					}
				}
			}
			janus_mutex_lock(&ice_handle->mutex);
			/* We got our answer */
			janus_flags_clear(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
			/* Any pending trickles? */
			if(ice_handle->pending_trickles) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Processing %d pending trickle candidates\n", ice_handle->handle_id, g_list_length(ice_handle->pending_trickles));
				GList *temp = NULL;
				while(ice_handle->pending_trickles) {
					temp = g_list_first(ice_handle->pending_trickles);
					ice_handle->pending_trickles = g_list_remove_link(ice_handle->pending_trickles, temp);
					janus_ice_trickle *trickle = (janus_ice_trickle *)temp->data;
					g_list_free(temp);
					if(trickle == NULL)
						continue;
					if((janus_get_monotonic_time() - trickle->received) > 15*G_USEC_PER_SEC) {
						/* FIXME Candidate is too old, discard it */
						janus_ice_trickle_destroy(trickle);
						/* FIXME We should report that */
						continue;
					}
					json_t *candidate = trickle->candidate;
					if(candidate == NULL) {
						janus_ice_trickle_destroy(trickle);
						continue;
					}
					if(json_is_object(candidate)) {
						/* We got a single candidate */
						int error = 0;
						const char *error_string = NULL;
						if((error = janus_ice_trickle_parse(ice_handle, candidate, &error_string)) != 0) {
							/* FIXME We should report the error parsing the trickle candidate */
						}
					} else if(json_is_array(candidate)) {
						/* We got multiple candidates in an array */
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got multiple candidates (%zu)\n", ice_handle->handle_id, json_array_size(candidate));
						if(json_array_size(candidate) > 0) {
							/* Handle remote candidates */
							size_t i = 0;
							for(i=0; i<json_array_size(candidate); i++) {
								json_t *c = json_array_get(candidate, i);
								/* FIXME We don't care if any trickle fails to parse */
								janus_ice_trickle_parse(ice_handle, c, NULL);
							}
						}
					}
					/* Done, free candidate */
					janus_ice_trickle_destroy(trickle);
				}
			}
			/* This was an answer, check if it's time to start ICE */
			if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) &&
					!janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- ICE Trickling is supported by the browser, waiting for remote candidates...\n", ice_handle->handle_id);
				janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
			} else {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Done! Sending connectivity checks...\n", ice_handle->handle_id);
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

void janus_plugin_relay_rtp(janus_plugin_session *plugin_session, int video, char *buf, int len) {
	if((plugin_session < (janus_plugin_session *)0x1000) || plugin_session->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtp(handle, video, buf, len);
}

void janus_plugin_relay_rtcp(janus_plugin_session *plugin_session, int video, char *buf, int len) {
	if((plugin_session < (janus_plugin_session *)0x1000) || plugin_session->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtcp(handle, video, buf, len);
}

void janus_plugin_relay_data(janus_plugin_session *plugin_session, char *buf, int len) {
	if((plugin_session < (janus_plugin_session *)0x1000) || plugin_session->stopped || buf == NULL || len < 1)
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

void janus_plugin_close_pc(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a PeerConnection */
	if((plugin_session < (janus_plugin_session *)0x1000) || !janus_plugin_session_is_alive(plugin_session) || plugin_session->stopped)
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
}

void janus_plugin_end_session(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a handle */
	if((plugin_session < (janus_plugin_session *)0x1000) || !janus_plugin_session_is_alive(plugin_session) || plugin_session->stopped)
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle)
		return;
	janus_session *session = (janus_session *)ice_handle->session;
	if(!session)
		return;
	/* Destroy the handle */
	janus_ice_handle_destroy(session, ice_handle->handle_id);
	janus_mutex_lock(&session->mutex);
	g_hash_table_remove(session->ice_handles, GUINT_TO_POINTER(ice_handle->handle_id));
	janus_mutex_unlock(&session->mutex);
}


static void janus_detect_local_ip(gchar *buf, size_t buflen) {
	JANUS_LOG(LOG_VERB, "Autodetecting local IP...\n");
	struct sockaddr_in addr;
	socklen_t len;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		goto error;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1);
	inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr.s_addr);
	if (connect(fd, (const struct sockaddr*) &addr, sizeof(addr)) < 0)
		goto error;
	len = sizeof(addr);
	if (getsockname(fd, (struct sockaddr*) &addr, &len) < 0)
		goto error;
	if (getnameinfo((const struct sockaddr*) &addr, sizeof(addr),
			buf, buflen,
			NULL, 0, NI_NUMERICHOST) != 0)
		goto error;
	close(fd);
	return;
error:
	if (fd != -1)
		close(fd);
	JANUS_LOG(LOG_VERB, "Couldn't find any address! using 127.0.0.1 as the local IP... (which is NOT going to work out of your machine)\n");
	g_strlcpy(buf, "127.0.0.1", buflen);
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
	
	/* Any configuration to open? */
	if(args_info.config_given) {
		config_file = g_strdup(args_info.config_arg);
	}
	if(args_info.configs_folder_given) {
		configs_folder = g_strdup(args_info.configs_folder_arg);
	} else {
		configs_folder = g_strdup (CONFDIR);
	}
	if(config_file == NULL) {
		char file[255];
		g_snprintf(file, 255, "%s/janus.cfg", configs_folder);
		config_file = g_strdup(file);
	}
	if((config = janus_config_parse(config_file)) == NULL) {
		if(args_info.config_given) {
			/* We only give up if the configuration file was explicitly provided */
			g_print("Error reading configuration from %s\n", config_file);
			exit(1);
		}
		g_print("Error reading/parsing the configuration file, going on with the defaults and the command line arguments\n");
		config = janus_config_create("janus.cfg");
		if(config == NULL) {
			/* If we can't even create an empty configuration, something's definitely wrong */
			exit(1);
		}
	}

	/* Check if we need to log to console and/or file */
	gboolean use_stdout = TRUE;
	if(args_info.disable_stdout_given) {
		use_stdout = FALSE;
		janus_config_add_item(config, "general", "log_to_stdout", "no");
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "log_to_stdout");
		if(item && item->value && !janus_is_true(item->value))
			use_stdout = FALSE;
	}
	const char *logfile = NULL;
	if(args_info.log_file_given) {
		logfile = args_info.log_file_arg;
		janus_config_add_item(config, "general", "log_to_file", "no");
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "log_to_file");
		if(item && item->value)
			logfile = item->value;
	}

	/* Check if we're going to daemonize Janus */
	gboolean daemonize = FALSE;
	if(args_info.daemon_given) {
		daemonize = TRUE;
		janus_config_add_item(config, "general", "daemonize", "yes");
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "daemonize");
		if(item && item->value && janus_is_true(item->value))
			daemonize = TRUE;
	}
	/* If we're going to daemonize, make sure logging to stdout is disabled and a log file has been specified */
	if(daemonize && use_stdout) {
		use_stdout = FALSE;
	}
	if(daemonize && logfile == NULL) {
		g_print("Running Janus as a daemon but no log file provided, giving up...\n");
		exit(1);
	}
	/* Daemonize now, if we need to */
	if(daemonize) {
		g_print("Running Janus as a daemon\n");

		/* Fork off the parent process */
		pid_t pid = fork();
		if(pid < 0) {
			g_print("Fork error!\n");
			exit(1);
		}
		if(pid > 0) {
			exit(0);
		}
		/* Change the file mode mask */
		umask(0);

		/* Create a new SID for the child process */
		pid_t sid = setsid();
		if(sid < 0) {
			g_print("Error setting SID!\n");
			exit(1);
		}
		/* Change the current working directory */
		if((chdir("/")) < 0) {
			g_print("Error changing the current working directory!\n");
			exit(1);
		}
		/* We close stdin/stdout/stderr when initializing the logger */
	}

	/* Initialize logger */
	if(janus_log_init(daemonize, use_stdout, logfile) < 0)
		exit(1);

	JANUS_PRINT("---------------------------------------------------\n");
	JANUS_PRINT("  Starting Meetecho Janus (WebRTC Gateway) v%s\n", JANUS_VERSION_STRING);
	JANUS_PRINT("---------------------------------------------------\n\n");

	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, janus_handle_signal);
	signal(SIGTERM, janus_handle_signal);
	atexit(janus_termination_handler);

	/* Setup Glib */
#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif

	/* Logging level: default is info and no timestamps */
	janus_log_level = LOG_INFO;
	janus_log_timestamps = FALSE;
	janus_log_colors = TRUE;
	if(args_info.debug_level_given) {
		if(args_info.debug_level_arg < LOG_NONE)
			args_info.debug_level_arg = 0;
		else if(args_info.debug_level_arg > LOG_MAX)
			args_info.debug_level_arg = LOG_MAX;
		janus_log_level = args_info.debug_level_arg;
	}

	/* Any PID we need to create? */
	const char *pidfile = NULL;
	if(args_info.pid_file_given) {
		pidfile = args_info.pid_file_arg;
		janus_config_add_item(config, "general", "pid_file", pidfile);
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "pid_file");
		if(item && item->value)
			pidfile = item->value;
	}
	if(janus_pidfile_create(pidfile) < 0)
		exit(1);

	/* Proceed with the rest of the configuration */
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
				janus_log_level = temp_level;
				if(janus_log_level < LOG_NONE)
					janus_log_level = 0;
				else if(janus_log_level > LOG_MAX)
					janus_log_level = LOG_MAX;
			}
		}
	}
	/* Any command line argument that should overwrite the configuration? */
	JANUS_PRINT("Checking command line arguments...\n");
	if(args_info.debug_timestamps_given) {
		janus_config_add_item(config, "general", "debug_timestamps", "yes");
	}
	if(args_info.disable_colors_given) {
		janus_config_add_item(config, "general", "debug_colors", "no");
	}
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
	if(args_info.token_auth_given) {
		janus_config_add_item(config, "general", "token_auth", "yes");
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
	if(args_info.nat_1_1_given) {
		janus_config_add_item(config, "nat", "nat_1_1_mapping", args_info.nat_1_1_arg);
	}
	if(args_info.ice_enforce_list_given) {
		janus_config_add_item(config, "nat", "ice_enforce_list", args_info.ice_enforce_list_arg);
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
	if(args_info.force_bundle_given) {
		janus_config_add_item(config, "media", "force-bundle", "true");
	}
	if(args_info.force_rtcp_mux_given) {
		janus_config_add_item(config, "media", "force-rtcp-mux", "true");
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

	/* Logging/debugging */
	JANUS_PRINT("Debug/log level is %d\n", janus_log_level);
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "debug_timestamps");
	if(item && item->value)
		janus_log_timestamps = janus_is_true(item->value);
	JANUS_PRINT("Debug/log timestamps are %s\n", janus_log_timestamps ? "enabled" : "disabled");
	item = janus_config_get_item_drilldown(config, "general", "debug_colors");
	if(item && item->value)
		janus_log_colors = janus_is_true(item->value);
	JANUS_PRINT("Debug/log colors are %s\n", janus_log_colors ? "enabled" : "disabled");

	/* Any IP/interface to enforce/ignore? */
	item = janus_config_get_item_drilldown(config, "nat", "ice_enforce_list");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_INFO, "Adding '%s' to the ICE enforce list...\n", index);
					janus_ice_enforce_interface(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_strfreev(list);
		list = NULL;
	}
	item = janus_config_get_item_drilldown(config, "nat", "ice_ignore_list");
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
	/* What is the local IP? */
	JANUS_LOG(LOG_VERB, "Selecting local IP address...\n");
	gboolean local_ip_set = FALSE;
	item = janus_config_get_item_drilldown(config, "general", "interface");
	if(item && item->value) {
		JANUS_LOG(LOG_VERB, "  -- Will try to use %s\n", item->value);
		int family;
		if (!janus_is_ip_valid(item->value, &family)) {
			JANUS_LOG(LOG_WARN, "Invalid local IP specified: %s, guessing the default...\n", item->value);
		} else {
			/* Verify that we can actually bind to that address */
			int fd = socket(family, SOCK_DGRAM, 0);
			if (fd == -1) {
				JANUS_LOG(LOG_WARN, "Error creating test socket, falling back to detecting IP address...\n");
			} else {
				int r;
				struct sockaddr_storage ss;
				socklen_t addrlen;
				memset(&ss, 0, sizeof(ss));
				if (family == AF_INET) {
					struct sockaddr_in *addr4 = (struct sockaddr_in*)&ss;
					addr4->sin_family = AF_INET;
					addr4->sin_port = 0;
					inet_pton(AF_INET, item->value, &(addr4->sin_addr.s_addr));
					addrlen = sizeof(struct sockaddr_in);
				} else {
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&ss;
					addr6->sin6_family = AF_INET6;
					addr6->sin6_port = 0;
					inet_pton(AF_INET6, item->value, &(addr6->sin6_addr.s6_addr));
					addrlen = sizeof(struct sockaddr_in6);
				}
				r = bind(fd, (const struct sockaddr*)&ss, addrlen);
				close(fd);
				if (r < 0) {
					JANUS_LOG(LOG_WARN, "Error setting local IP address to %s, falling back to detecting IP address...\n", item->value);
				} else {
					g_strlcpy(local_ip, item->value, sizeof(local_ip));
					local_ip_set = TRUE;
				}
			}
		}
	}
	if (!local_ip_set)
		janus_detect_local_ip(local_ip, sizeof(local_ip));
	JANUS_LOG(LOG_INFO, "Using %s as local IP...\n", local_ip);

	/* Is there any API secret to consider? */
	api_secret = NULL;
	item = janus_config_get_item_drilldown(config, "general", "api_secret");
	if(item && item->value) {
		api_secret = g_strdup(item->value);
	}
	/* Is there any API secret to consider? */
	admin_api_secret = NULL;
	item = janus_config_get_item_drilldown(config, "general", "admin_secret");
	if(item && item->value) {
		admin_api_secret = g_strdup(item->value);
	}
	/* Also check if the token based authentication mechanism needs to be enabled */
	item = janus_config_get_item_drilldown(config, "general", "token_auth");
	janus_auth_init(item && item->value && janus_is_true(item->value));

	/* Setup ICE stuff (e.g., checking if the provided STUN server is correct) */
	char *stun_server = NULL, *turn_server = NULL;
	uint16_t stun_port = 0, turn_port = 0;
	char *turn_type = NULL, *turn_user = NULL, *turn_pwd = NULL;
	char *turn_rest_api = NULL, *turn_rest_api_key = NULL;
	const char *nat_1_1_mapping = NULL;
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
	/* Any 1:1 NAT mapping to take into account? */
	item = janus_config_get_item_drilldown(config, "nat", "nat_1_1_mapping");
	if(item && item->value) {
		JANUS_LOG(LOG_VERB, "Using nat_1_1_mapping for public ip - %s\n", item->value);
		nat_1_1_mapping = item->value;
		janus_set_public_ip(item->value);
		janus_ice_enable_nat_1_1();
	}
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
	/* Check if there's any TURN REST API backend to use */
	item = janus_config_get_item_drilldown(config, "nat", "turn_rest_api");
	if(item && item->value)
		turn_rest_api = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "turn_rest_api_key");
	if(item && item->value)
		turn_rest_api_key = (char *)item->value;
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
#ifndef HAVE_LIBCURL
	if(turn_rest_api != NULL || turn_rest_api_key != NULL) {
		JANUS_LOG(LOG_WARN, "A TURN REST API backend specified in the settings, but libcurl support has not been built\n");
	}
#else
	if(janus_ice_set_turn_rest_api(turn_rest_api, turn_rest_api_key) < 0) {
		JANUS_LOG(LOG_FATAL, "Invalid TURN REST API configuration: %s (%s)\n", turn_rest_api, turn_rest_api_key);
		exit(1);
	}
#endif
	item = janus_config_get_item_drilldown(config, "nat", "nice_debug");
	if(item && item->value && janus_is_true(item->value)) {
		/* Enable libnice debugging */
		janus_ice_debugging_enable();
	}
	if(stun_server == NULL && turn_server == NULL) {
		/* No STUN and TURN server provided for Janus: make sure it isn't on a private address */
		gboolean private_address = FALSE;
		const char *test_ip = nat_1_1_mapping ? nat_1_1_mapping : local_ip;
		struct sockaddr_in addr;
		if(inet_pton(AF_INET, test_ip, &addr) > 0) {
			unsigned short int ip[4];
			sscanf(test_ip, "%hu.%hu.%hu.%hu", &ip[0], &ip[1], &ip[2], &ip[3]);
			if(ip[0] == 10) {
				/* Class A private address */
				private_address = TRUE;
			} else if(ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) {
				/* Class B private address */
				private_address = TRUE;
			} else if(ip[0] == 192 && ip[1] == 168) {
				/* Class C private address */
				private_address = TRUE;
			}
		}
		if(private_address) {
			JANUS_LOG(LOG_WARN, "Janus is deployed on a private address (%s) but you didn't specify any STUN server!"
			                    " Expect trouble if this is supposed to work over the internet and not just in a LAN...\n", test_ip);
		}
	}
	/* Are we going to force BUNDLE and/or rtcp-mux? */
	gboolean force_bundle = FALSE, force_rtcpmux = FALSE;
	item = janus_config_get_item_drilldown(config, "media", "force-bundle");
	force_bundle = (item && item->value) ? janus_is_true(item->value) : FALSE;
	janus_ice_force_bundle(force_bundle);
	item = janus_config_get_item_drilldown(config, "media", "force-rtcp-mux");
	force_rtcpmux = (item && item->value) ? janus_is_true(item->value) : FALSE;
	janus_ice_force_rtcpmux(force_rtcpmux);
	/* NACK related stuff */
	item = janus_config_get_item_drilldown(config, "media", "max_nack_queue");
	if(item && item->value) {
		int mnq = atoi(item->value);
		if(mnq < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring max_nack_queue value as it's not a positive integer\n");
		} else {
			janus_set_max_nack_queue(mnq);
		}
	}

	/* Setup OpenSSL stuff */
	item = janus_config_get_item_drilldown(config, "certificates", "cert_pem");
	if(!item || !item->value) {
		JANUS_LOG(LOG_FATAL, "Missing certificate/key path, use the command line or the configuration to provide one\n");
		exit(1);
	}
	server_pem = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "certificates", "cert_key");
	if(!item || !item->value) {
		JANUS_LOG(LOG_FATAL, "Missing certificate/key path, use the command line or the configuration to provide one\n");
		exit(1);
	}
	server_key = (char *)item->value;
	JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	/* ... and DTLS-SRTP in particular */
	if(janus_dtls_srtp_init(server_pem, server_key) < 0) {
		exit(1);
	}
	/* Check if there's any custom value for the starting MTU to use in the BIO filter */
	item = janus_config_get_item_drilldown(config, "media", "dtls_mtu");
	if(item && item->value)
		janus_dtls_bio_filter_set_mtu(atoi(item->value));

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

	/* Create a thread pool to handle incoming requests, no matter what the transport */
	GError *error = NULL;
	tasks = g_thread_pool_new(janus_transport_task, NULL, -1, FALSE, &error);
	if(error != NULL) {
		/* Something went wrong... */
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the request pool task thread...\n", error->code, error->message ? error->message : "??");
		exit(1);
	}

	/* Load transports */
	gboolean janus_api_enabled = FALSE, admin_api_enabled = FALSE;
	path = TRANSPORTDIR;
	item = janus_config_get_item_drilldown(config, "general", "transports_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Transport plugins folder: %s\n", path);
	dir = opendir(path);
	if(!dir) {
		JANUS_LOG(LOG_FATAL, "\tCouldn't access transport plugins folder...\n");
		exit(1);
	}
	/* Any transport to ignore? */
	gchar **disabled_transports = NULL;
	item = janus_config_get_item_drilldown(config, "transports", "disable");
	if(item && item->value)
		disabled_transports = g_strsplit(item->value, ",", -1);
	/* Open the shared objects */
	struct dirent *transportent = NULL;
	char transportpath[1024];
	while((transportent = readdir(dir))) {
		int len = strlen(transportent->d_name);
		if (len < 4) {
			continue;
		}
		if (strcasecmp(transportent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
			continue;
		}
		/* Check if this transports has been disabled in the configuration file */
		if(disabled_transports != NULL) {
			gchar *index = disabled_transports[0];
			if(index != NULL) {
				int i=0;
				gboolean skip = FALSE;
				while(index != NULL) {
					while(isspace(*index))
						index++;
					if(strlen(index) && !strcmp(index, transportent->d_name)) {
						JANUS_LOG(LOG_WARN, "Transport plugin '%s' has been disabled, skipping...\n", transportent->d_name);
						skip = TRUE;
						break;
					}
					i++;
					index = disabled_transports[i];
				}
				if(skip)
					continue;
			}
		}
		JANUS_LOG(LOG_INFO, "Loading transport plugin '%s'...\n", transportent->d_name);
		memset(transportpath, 0, 1024);
		g_snprintf(transportpath, 1024, "%s/%s", path, transportent->d_name);
		void *transport = dlopen(transportpath, RTLD_LAZY);
		if (!transport) {
			JANUS_LOG(LOG_ERR, "\tCouldn't load transport plugin '%s': %s\n", transportent->d_name, dlerror());
		} else {
			create_t *create = (create_t*) dlsym(transport, "create");
			const char *dlsym_error = dlerror();
			if (dlsym_error) {
				JANUS_LOG(LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
				continue;
			}
			janus_transport *janus_transport = create();
			if(!janus_transport) {
				JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
				continue;
			}
			/* Are all the mandatory methods and callbacks implemented? */
			if(!janus_transport->init || !janus_transport->destroy ||
					!janus_transport->get_api_compatibility ||
					!janus_transport->get_version ||
					!janus_transport->get_version_string ||
					!janus_transport->get_description ||
					!janus_transport->get_package ||
					!janus_transport->get_name ||
					!janus_transport->send_message ||
					!janus_transport->is_janus_api_enabled ||
					!janus_transport->is_admin_api_enabled ||
					!janus_transport->session_created ||
					!janus_transport->session_over) {
				JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this transport plugin...\n");
				continue;
			}
			if(janus_transport->get_api_compatibility() < JANUS_TRANSPORT_API_VERSION) {
				JANUS_LOG(LOG_ERR, "The '%s' transport plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
					janus_transport->get_package(), janus_transport->get_api_compatibility(), JANUS_TRANSPORT_API_VERSION);
				continue;
			}
			janus_transport->init(&janus_handler_transport, configs_folder);
			JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_transport->get_version(), janus_transport->get_version_string());
			JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_transport->get_package(), janus_transport->get_name());
			JANUS_LOG(LOG_VERB, "\t   %s\n", janus_transport->get_description());
			JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_transport->get_api_compatibility());
			JANUS_LOG(LOG_VERB, "\t   Janus API: %s\n", janus_transport->is_janus_api_enabled() ? "enabled" : "disabled");
			JANUS_LOG(LOG_VERB, "\t   Admin API: %s\n", janus_transport->is_admin_api_enabled() ? "enabled" : "disabled");
			janus_api_enabled = janus_api_enabled || janus_transport->is_janus_api_enabled();
			admin_api_enabled = admin_api_enabled || janus_transport->is_admin_api_enabled();
			if(transports == NULL)
				transports = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(transports, (gpointer)janus_transport->get_package(), janus_transport);
			if(transports_so == NULL)
				transports_so = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(transports_so, (gpointer)janus_transport->get_package(), transport);
		}
	}
	closedir(dir);
	if(disabled_transports != NULL)
		g_strfreev(disabled_transports);
	disabled_transports = NULL;
	/* Make sure at least a Janus API transport is available */
	if(!janus_api_enabled) {
		JANUS_LOG(LOG_FATAL, "No Janus API transport is available... enable at least one and restart Janus\n");
		exit(1);	/* FIXME Should we really give up? */
	}
	/* Make sure at least an admin API transport is available, if the auth mechanism is enabled */
	if(!admin_api_enabled && janus_auth_is_enabled()) {
		JANUS_LOG(LOG_FATAL, "No Admin/monitor transport is available, but the token based authentication mechanism is enabled... this will cause all requests to fail, giving up! If you want to use tokens, enable the Admin/monitor API and restart Janus\n");
		exit(1);	/* FIXME Should we really give up? */
	}

	/* Sessions */
	sessions = g_hash_table_new(NULL, NULL);
	old_sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	/* Start the sessions watchdog */
	sessions_watchdog_context = g_main_context_new();
	GMainLoop *watchdog_loop = g_main_loop_new(sessions_watchdog_context, FALSE);
	error = NULL;
	GThread *watchdog = g_thread_try_new("watchdog", &janus_sessions_watchdog, watchdog_loop, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start sessions watchdog...\n", error->code, error->message ? error->message : "??");
		exit(1);
	}

	while(!g_atomic_int_get(&stop)) {
		/* Loop until we have to stop */
		usleep(250000); /* A signal will cancel usleep() but not g_usleep() */
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Ending watchdog mainloop...\n");
	g_main_loop_quit(watchdog_loop);
	g_thread_join(watchdog);
	watchdog = NULL;
	g_main_loop_unref(watchdog_loop);
	g_main_context_unref(sessions_watchdog_context);

	if(config)
		janus_config_destroy(config);

	JANUS_LOG(LOG_INFO, "Closing transport plugins:\n");
	if(transports != NULL) {
		g_hash_table_foreach(transports, janus_transport_close, NULL);
		g_hash_table_destroy(transports);
	}
	if(transports_so != NULL) {
		g_hash_table_foreach(transports_so, janus_transportso_close, NULL);
		g_hash_table_destroy(transports_so);
	}
	g_thread_pool_free(tasks, FALSE, FALSE);

	JANUS_LOG(LOG_INFO, "Destroying sessions...\n");
	if(sessions != NULL)
		g_hash_table_destroy(sessions);
	if(old_sessions != NULL)
		g_hash_table_destroy(old_sessions);
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
	janus_ice_deinit();
	janus_auth_deinit();

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
