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
#include "rtcp.h"
#include "sdp.h"
#include "utils.h"


#define JANUS_NAME				"Janus WebRTC Gateway"
#define JANUS_AUTHOR			"Meetecho s.r.l."
#define JANUS_VERSION			4
#define JANUS_VERSION_STRING	"0.0.4"


static janus_config *config = NULL;
static char *config_file = NULL;
static char *configs_folder = NULL;

static GHashTable *plugins = NULL;
static GHashTable *plugins_so = NULL;

/* MHD Web Server */
static struct MHD_Daemon *ws = NULL, *sws = NULL;
static char *ws_path = NULL;
static char *ws_api_secret = NULL;

#ifdef HAVE_WS
/* libwebsock WS server */
static libwebsock_context *wss = NULL, *swss = NULL;
#endif

/* Certificates */
static char *server_pem = NULL;
gchar *janus_get_server_pem() {
	return server_pem;
}
static char *server_key = NULL;
gchar *janus_get_server_key() {
	return server_key;
}


/* Information */
static gchar *info_text = NULL;
static gchar *local_ip = NULL;
gchar *janus_get_local_ip() {
	return local_ip;
}
static gchar *public_ip = NULL;
gchar *janus_get_public_ip() {
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
static gint stop = 0;
gint janus_is_stopping() {
	return stop;
}


/* Logging */
int log_level = 0;


/*! \brief Signal handler (just used to intercept CTRL+C) */
void janus_handle_signal(int signum);
void janus_handle_signal(int signum)
{
	switch(stop) {
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
	stop++;
	if(stop > 2)
		exit(1);
}


/** @name Plugin callback interface
 * These are the callbacks implemented by the gateway core, as part of
 * the janus_callbacks interface. Everything the plugins send the
 * gateway is handled here.
 */
///@{
int janus_push_event(janus_plugin_session *handle, janus_plugin *plugin, char *transaction, char *message, char *sdp_type, char *sdp);
json_t *janus_handle_sdp(janus_plugin_session *handle, janus_plugin *plugin, char *sdp_type, char *sdp);
void janus_relay_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_relay_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_relay_data(janus_plugin_session *handle, char *buf, int len);
void janus_close_pc(janus_plugin_session *handle);
void janus_end_session(janus_plugin_session *handle);
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


#ifdef HAVE_WS
/* WebSocket sessions */
static janus_mutex wss_mutex;
static GHashTable *wss_sessions = NULL;
#endif

/* Gateway Sessions */
static janus_mutex sessions_mutex;
static GHashTable *sessions = NULL;

#define SESSION_TIMEOUT		60		/* FIXME Should this be higher, e.g., 120 seconds? */
void *janus_sessions_watchdog(void *data);
void *janus_sessions_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "Sessions watchdog started\n");
	gint64 now = 0;
	while(!stop) {
		janus_mutex_lock(&sessions_mutex);
		if(sessions != NULL && g_hash_table_size(sessions) > 0) {
			/* Iterate on all the sessions and check the last activity */
			now = janus_get_monotonic_time();
			GList *sessions_list = g_hash_table_get_values(sessions);
			GList *s = sessions_list;
			while(s) {
				janus_session *session = (janus_session *)s->data;
				if(!session || session->destroy || stop) {
					s = s->next;
					continue;
				}
				if(now-session->last_activity >= (SESSION_TIMEOUT+3)*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the session only after a few seconds */
					janus_mutex_unlock(&sessions_mutex);
					janus_session_destroy(session->session_id);
					janus_mutex_lock(&sessions_mutex);
				} else if(now-session->last_activity >= SESSION_TIMEOUT*G_USEC_PER_SEC && !session->timeout) {
					/* Timeout! */
					JANUS_LOG(LOG_INFO, "Timeout expired for session %"SCNu64"...\n", session->session_id);
					/* Prepare JSON event to notify user/application */
					json_t *event = json_object();
					json_object_set_new(event, "janus", json_string("timeout"));
					json_object_set_new(event, "session_id", json_integer(session->session_id));
					/* Convert to a string */
					char *event_text = json_dumps(event, JSON_INDENT(3));
					json_decref(event);
					/* Send the event */
					janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
					if(notification == NULL) {
						JANUS_LOG(LOG_FATAL, "Memory error!\n");
						s = s->next;
						continue;
					}
					notification->code = 200;
					notification->payload = event_text;
					notification->allocated = 1;
					janus_mutex_lock(&session->qmutex);
					g_queue_push_tail(session->messages, notification);
					session->timeout = 1;
					janus_mutex_unlock(&session->qmutex);
				}
				s = s->next;
			}
			g_list_free(sessions_list);
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(2000000);
	}
	JANUS_LOG(LOG_INFO, "Sessions watchdog stopped\n");
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
	session->messages = g_queue_new();
	session->destroy = 0;
	session->last_activity = janus_get_monotonic_time();
	janus_mutex_init(&session->qmutex);
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

gint janus_session_destroy(guint64 session_id) {
	janus_session *session = janus_session_find(session_id);
	if(session == NULL)
		return -1;
	JANUS_LOG(LOG_INFO, "Destroying session %"SCNu64"\n", session_id);
	session->destroy = 1;
	if(session->ice_handles != NULL && g_hash_table_size(session->ice_handles) > 0) {
		/* Remove all handles */
		GList *handles_list = g_hash_table_get_values(session->ice_handles);
		GList *h = handles_list;
		while(h) {
			janus_ice_handle *handle = (janus_ice_handle *)h->data;
			if(!handle || stop) {
				h = h->next;
				continue;
			}
			janus_ice_handle_destroy(session, handle->handle_id);
			h = h->next;
		}
		g_list_free(handles_list);
	}
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, GUINT_TO_POINTER(session_id));
	janus_mutex_unlock(&sessions_mutex);
	/* TODO Actually destroy session */
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
		janus_mutex_lock(&session->qmutex);
		if(!g_queue_is_empty(session->messages)) {
			janus_http_event *event = NULL;
			while(!g_queue_is_empty(session->messages)) {
				event = g_queue_pop_head(session->messages);
				if(event != NULL) {
					if(event->payload && event->allocated) {
						g_free(event->payload);
						event->payload = NULL;
					}
					g_free(event);
				}
			}
		}
		g_queue_free (session->messages);
		janus_mutex_unlock(&session->qmutex);
		session->messages = NULL;
	}
	janus_mutex_unlock(&session->mutex);
	session = NULL;
}


/* WebServer requests handler */
int janus_ws_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
	char *payload = NULL;
	struct MHD_Response *response = NULL;
	int ret = MHD_NO;

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
	gchar **basepath = NULL, **path = NULL;
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
	gchar *session_path = NULL, *handle_path = NULL;
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
		ret = janus_process_success(&source, "application/json", g_strdup(info_text));
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
			char location[50];
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
			if(!secret || strcmp(secret, ws_api_secret)) {
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
		janus_mutex_lock(&session->qmutex);
		janus_http_event *event = g_queue_pop_head(session->messages);
		janus_mutex_unlock(&session->qmutex);
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
					janus_mutex_lock(&session->qmutex);
					event = g_queue_pop_head(session->messages);
					janus_mutex_unlock(&session->qmutex);
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
				char *event_text = json_dumps(list, JSON_INDENT(3));
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
		/* Can only be a 'Create new session' or 'Get info' request */
		if(!strcasecmp(message_text, "info")) {
			ret = janus_process_success(source, "application/json", info_text);
			goto jsondone;
		}
		if(strcasecmp(message_text, "create")) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(ws_api_secret != NULL) {
			/* There's an API secret, check that the client provided it */
			json_t *secret = json_object_get(root, "apisecret");
			if(!secret || !json_is_string(secret) || strcmp(json_string_value(secret), ws_api_secret)) {
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
#ifdef HAVE_WS
		if(source->type == JANUS_SOURCE_WEBSOCKETS) {
			/* Add the new session to the list of sessions created by this WS client */
			janus_websocket_client *client = (janus_websocket_client *)source->source;
			if(client) {
				janus_mutex_lock(&client->mutex);
				if(client->sessions == NULL)
					client->sessions = g_hash_table_new(NULL, NULL);
				g_hash_table_insert(client->sessions, GUINT_TO_POINTER(session_id), session);
				if(client->thread == NULL) {
					/* Create a thread for notifications related to this session as well */
					client->thread = g_thread_new("wss_client", &janus_wss_thread, client);
				}
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
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
		if(!secret || !json_is_string(secret) || strcmp(json_string_value(secret), ws_api_secret)) {
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
		JANUS_LOG(LOG_VERB, "Got a keep-alive on session %"SCNu64"\n", session->session_id);
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session->session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_PLUGIN_ATTACH, "Couldn't attach to plugin: error '%d'", error);
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session->session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(handle_id));
		json_object_set(reply, "data", data);
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
#ifdef HAVE_WS
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
		janus_session_destroy(session_id);	/* FIXME Should we check if this actually succeeded, or can we ignore it? */
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
		int error = 0;
		if((error = janus_ice_handle_destroy(session, handle_id)) != 0) {
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
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_JSON, "Missing mandatory element (body)");
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
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one audio line? only going to negotiate one...\n", handle->handle_id);
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Video %s been negotiated\n", handle->handle_id, video ? "has" : "has NOT");
			if(video > 1) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one video line? only going to negotiate one...\n", handle->handle_id);
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] SCTP/DataChannels %s been negotiated\n", handle->handle_id, video ? "have" : "have NOT");
			if(data > 1) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one data line? only going to negotiate one...\n", handle->handle_id);
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
					janus_ice_setup_local(handle, offer, audio, video, data, bundle, rtcpmux, trickle);
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
								nice_agent_attach_recv (handle->agent, handle->data_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
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
								nice_agent_attach_recv (handle->agent, handle->data_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
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
					}
					janus_mutex_unlock(&handle->mutex);
					/* We got our answer */
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				}
			} else {
				/* TODO Actually handle session updates: for now we ignore them, and just relay them to plugins */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Ignoring negotiation update, we don't support them yet...\n", handle->handle_id);
			}
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
		char *body_text = json_dumps(body, JSON_INDENT(3));
		/* We reply right away, not to block the web server... */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
		json_decref(reply);
		/* Send the message to the plugin */
		plugin_t->handle_message(handle->app_handle, g_strdup((char *)transaction_text), body_text, jsep_type, jsep_sdp_stripped);
		/* Send the success reply */
		ret = janus_process_success(source, "application/json", reply_text);
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
		if(candidate == NULL) {
			ret = janus_process_error(source, session_id, transaction_text, JANUS_ERROR_INVALID_JSON, "Missing mandatory element (candidate)");
			goto jsondone;
		}
		if(!json_is_object(candidate)) {
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
			if(handle->audio_stream == NULL && handle->video_stream == NULL) {
				/* No stream available, wait a bit */
				gint64 waited = 0;
				while(handle->audio_stream == NULL && handle->video_stream == NULL) {
					JANUS_LOG(LOG_INFO, "[%"SCNu64"] No stream, wait a bit in case this trickle got here before the SDP...\n", handle->handle_id);
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
			int video = (strcmp(json_string_value(mid), "video") == 0);
#ifdef HAVE_SCTP
			int data = (strcmp(json_string_value(mid), "data") == 0);
#else
			int data = 0;
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
		/* We reply right away, not to block the web server... */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("ack"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Convert to a string */
		char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
		janus_mutex_lock(&session->qmutex);
		event = g_queue_pop_head(session->messages);
		janus_mutex_unlock(&session->qmutex);
		if(!session || session->destroy || stop || event != NULL) {
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
					janus_mutex_lock(&session->qmutex);
					event = g_queue_pop_head(session->messages);
					janus_mutex_unlock(&session->qmutex);
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
		event->payload = max_events == 1 ? "{\"janus\" : \"keepalive\"}" : "[{\"janus\" : \"keepalive\"}]";
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
		char *event_text = json_dumps(list, JSON_INDENT(3));
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
		if(!connection || !msg)
			return MHD_NO;
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
#ifdef HAVE_WS
		/* FIXME We should check the return value */
		janus_websocket_client *client = (janus_websocket_client *)source->source;
		libwebsock_send_text(client->state, payload);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "WebSockets support not compiled\n");
		return MHD_NO;
#endif
	} else {
		/* WTF? */
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
			} else if(source->type == JANUS_SOURCE_WEBSOCKETS) {
#ifdef HAVE_WS
				/* TODO We should send an error to the client... */
				return MHD_NO;
#else
				JANUS_LOG(LOG_ERR, "WebSockets support not compiled\n");
				return MHD_NO;
#endif
			} else {
				/* WTF? */
				return MHD_NO;
			}
		}
		vsprintf(error_string, format, ap);
		va_end(ap);
	}
	/* Done preparing error */
	JANUS_LOG(LOG_VERB, "[ws][%s] Returning error %d (%s)\n", transaction, error, error_string ? error_string : "no text");
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
	char *reply_text = json_dumps(reply, JSON_INDENT(3));
	json_decref(reply);
	if(format != NULL && error_string != NULL)
		free(error_string);
	/* Send the error */
	if(source->type == JANUS_SOURCE_PLAIN_HTTP) {
		struct MHD_Connection *connection = (struct MHD_Connection *)source->source;
		janus_http_msg *msg = (janus_http_msg *)source->msg;
		if(!connection || !msg)
			return MHD_NO;
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
#ifdef HAVE_WS
		janus_websocket_client *client = (janus_websocket_client *)source->source;
		/* FIXME We should check the return value */
		libwebsock_send_text(client->state, reply_text);
		return MHD_YES;
#else
		JANUS_LOG(LOG_ERR, "WebSockets support not compiled\n");
		return MHD_NO;
#endif
	} else {
		/* WTF? */
		return MHD_NO;
	}
}


#ifdef HAVE_WS
/* WebSockets */
int janus_wss_onopen(libwebsock_client_state *state) {
	JANUS_LOG(LOG_INFO, "WebSocket onopen: #%d\n", state->sockfd);
	janus_mutex_lock(&wss_mutex);
	if(g_hash_table_lookup(wss_sessions, state) != NULL) {
		JANUS_LOG(LOG_INFO, "  -- Client already handled\n");
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
	ws_client->state = state;
	ws_client->sessions = NULL;
	ws_client->thread = NULL;
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
	janus_request_source source = {
		.type = JANUS_SOURCE_WEBSOCKETS,
		.source = (void *)client,
		.msg = (void *)msg
	};
	/* Parse the JSON payload */
	json_error_t error;
	json_t *root = json_loads(msg->payload, 0, &error);
	if(!root) {
		janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON, "JSON error: on line %d: %s", error.line, error.text);
		return 0;
	}
	if(!json_is_object(root)) {
		janus_process_error(&source, 0, NULL, JANUS_ERROR_INVALID_JSON_OBJECT, "JSON error: not an object");
		json_decref(root);
		return 0;
	}
	/* Parse the request now */
	janus_process_incoming_request(&source, root);
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
		if(client->thread != NULL) {
			JANUS_LOG(LOG_INFO, "Joining thread #%d\n", state->sockfd);
			g_thread_join(client->thread);
		}
		client->thread = NULL;
		client->state = NULL;
		/* TODO: Remove all sessions (and handles) created by this client */
		if(client->sessions != NULL)
			g_hash_table_destroy(client->sessions);
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
	while(!client->destroy && !stop) {
		janus_mutex_lock(&client->mutex);
		if(client->sessions != NULL && g_hash_table_size(client->sessions) > 0) {
			/* Iterate on all the sessions handled by this WebSocket client */
			GList *sessions_list = g_hash_table_get_values(client->sessions);
			GList *s = sessions_list;
			while(s) {
				janus_session *session = (janus_session *)s->data;
				if(client->destroy || !session || session->destroy || stop) {
					s = s->next;
					continue;
				}
				janus_mutex_lock(&session->qmutex);
				if(!g_queue_is_empty(session->messages)) {
					while(!g_queue_is_empty(session->messages)) {
						janus_http_event *event = g_queue_pop_head(session->messages);
						if(!client->destroy && session && !session->destroy && !stop && event && event->payload) {
							/* Gotcha! */
							JANUS_LOG(LOG_VERB, "#%d: Sending event (%zu bytes)...\n", fd, strlen(event->payload));
							int res = libwebsock_send_text(client->state, event->payload);
							JANUS_LOG(LOG_VERB, "#%d  -- Sent (res=%d)\n", fd, res);
						}
					}
				}
				if(g_queue_is_empty(session->messages) && session->timeout) {
					/* Close the websocket */
					janus_mutex_unlock(&session->qmutex);
					libwebsock_close(client->state);
					//~ janus_wss_onclose(client->state);
					break;
				}
				janus_mutex_unlock(&session->qmutex);
				s = s->next;
			}
			g_list_free(sessions_list);
		}
		janus_mutex_unlock(&client->mutex);
		/* Sleep 100ms */
		g_usleep(100000);
	}
	JANUS_LOG(LOG_INFO, "Leaving WebSocket thread: #%d\n", fd);
	return NULL;
}
#endif


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
int janus_push_event(janus_plugin_session *handle, janus_plugin *plugin, char *transaction, char *message, char *sdp_type, char *sdp) {
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
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: problem with the SDP)\n", ice_handle->handle_id);
			return JANUS_ERROR_JSEP_INVALID_SDP;
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
	char *reply_text = json_dumps(reply, JSON_INDENT(3));
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
	janus_mutex_lock(&session->qmutex);
	g_queue_push_tail(session->messages, notification);
	janus_mutex_unlock(&session->qmutex);
	return JANUS_OK;
}

json_t *janus_handle_sdp(janus_plugin_session *handle, janus_plugin *plugin, char *sdp_type, char *sdp) {
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
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] SCTP/DataChannels %s been negotiated\n", ice_handle->handle_id, video ? "have" : "have NOT");
		if(data > 1) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] More than one data line? only going to negotiate one...\n", ice_handle->handle_id);
		}
#ifndef HAVE_SCTP
		if(data) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]   -- DataChannels have been negotiated, but support for them has not been compiled...\n", ice_handle->handle_id);
		}
#endif
		if(ice_handle->agent == NULL) {
			/* Process SDP in order to setup ICE locally (this is going to result in an answer from the browser) */
			janus_ice_setup_local(ice_handle, 0, audio, video, data, bundle, rtcpmux, trickle);
		} else {
			updating = TRUE;
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Updating existing session\n", ice_handle->handle_id);
		}
	}
	if(!updating) {
		/* Wait for candidates-done callback */
		while(ice_handle->cdone < ice_handle->streams_num) {
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
						nice_agent_attach_recv (ice_handle->agent, ice_handle->data_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
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
						nice_agent_attach_recv (ice_handle->agent, ice_handle->data_id, 2, g_main_loop_get_context (ice_handle->iceloop), NULL, NULL);
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
	g_free(sdp_merged);
	return jsep;
}

void janus_relay_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(!handle || handle->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *session = (janus_ice_handle *)handle->gateway_handle;
	if(!session || janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtp(session, video, buf, len);
}

void janus_relay_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(!handle || handle->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *session = (janus_ice_handle *)handle->gateway_handle;
	if(!session || janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtcp(session, video, buf, len);
}

void janus_relay_data(janus_plugin_session *handle, char *buf, int len) {
	if(!handle || handle->stopped || buf == NULL || len < 1)
		return;
	janus_ice_handle *session = (janus_ice_handle *)handle->gateway_handle;
	if(!session || janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&session->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
#ifdef HAVE_SCTP
	janus_ice_relay_data(session, buf, len);
#else
	JANUS_LOG(LOG_WARN, "Asked to relay data, but Data Channels support has not been compiled...\n");
#endif
}

void janus_close_pc(janus_plugin_session *handle) {
	/* A plugin asked to get rid of a PeerConnection */
	if(!handle)
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)handle->gateway_handle;
	if(!ice_handle)
		return;
	janus_session *session = (janus_session *)ice_handle->session;
	if(!session)
		return;
		
	/* Send an alert on all the DTLS connections */
	janus_ice_webrtc_hangup(ice_handle);
	/* Get rid of the PeerConnection */
	janus_ice_webrtc_free(ice_handle);
	
	/* Prepare JSON event to notify user/application */
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("hangup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(ice_handle->handle_id));
	/* Convert to a string */
	char *event_text = json_dumps(event, JSON_INDENT(3));
	json_decref(event);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", ice_handle->handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	notification->code = 200;
	notification->payload = event_text;
	notification->allocated = 1;
	janus_mutex_lock(&session->qmutex);
	g_queue_push_tail(session->messages, notification);
	janus_mutex_unlock(&session->qmutex);
	
	/* Notify the plugin */
	janus_plugin *plugin = (janus_plugin *)ice_handle->app;
	if(plugin && plugin->hangup_media)
		plugin->hangup_media(handle);
}

void janus_end_session(janus_plugin_session *handle) {
	/* A plugin asked to get rid of a handle */
	if(!handle)
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)handle->gateway_handle;
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
	g_type_init();
	
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
		configs_folder = "./conf";	/* FIXME This is a relative path to where the executable is, not from where it was started... */
	}
	if(config_file == NULL) {
		char file[255];
		sprintf(file, "%s/janus.cfg", configs_folder);
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
		sprintf(debug, "%d", args_info.debug_level_arg);
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
		sprintf(port, "%d", args_info.port_arg);
		janus_config_add_item(config, "webserver", "port", port);
	}
	if(args_info.secure_port_given) {
		janus_config_add_item(config, "webserver", "https", "yes");
		char port[20];
		sprintf(port, "%d", args_info.secure_port_arg);
		janus_config_add_item(config, "webserver", "secure_port", port);
	}
	if(args_info.no_websockets_given) {
		janus_config_add_item(config, "webserver", "ws", "no");
	}
	if(args_info.ws_port_given) {
		char port[20];
		sprintf(port, "%d", args_info.port_arg);
		janus_config_add_item(config, "webserver", "ws_port", port);
	}
	if(args_info.ws_secure_port_given) {
		janus_config_add_item(config, "webserver", "ws_ssl", "yes");
		char port[20];
		sprintf(port, "%d", args_info.ws_secure_port_arg);
		janus_config_add_item(config, "webserver", "ws_secure_port", port);
	}
	if(args_info.base_path_given) {
		janus_config_add_item(config, "webserver", "base_path", args_info.base_path_arg);
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
	ws_path = "/janus";
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
	}
	/* Is there any API secret to consider? */
	ws_api_secret = NULL;
	item = janus_config_get_item_drilldown(config, "general", "api_secret");
	if(item && item->value) {
		ws_api_secret = g_strdup(item->value);
		if(ws_api_secret != NULL) {
			JANUS_LOG(LOG_WARN, "An API secret has been specified: %s (make sure your requests will contain it or they will fail!)\n", ws_api_secret);
		}
	}

	/* Setup ICE stuff (e.g., checking if the provided STUN server is correct) */
	char *stun_server = NULL;
	uint16_t stun_port = 0;
	uint16_t rtp_min_port = 0, rtp_max_port = 0;
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
	item = janus_config_get_item_drilldown(config, "nat", "stun_server");
	if(item && item->value)
		stun_server = (char *)item->value;
	item = janus_config_get_item_drilldown(config, "nat", "stun_port");
	if(item && item->value)
		stun_port = atoi(item->value);
	if(janus_ice_init(stun_server, stun_port, rtp_min_port, rtp_max_port) < 0) {
		JANUS_LOG(LOG_FATAL, "Invalid STUN address %s:%u\n", stun_server, stun_port);
		exit(1);
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
	char *path = "./plugins";	/* FIXME This is a relative path to where the executable is, not from where it was started... */
	item = janus_config_get_item_drilldown(config, "general", "plugins_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Plugins folder: %s\n", path);
	DIR *dir = opendir(path);
	if(!dir) {
		JANUS_LOG(LOG_FATAL, "\tCouldn't access plugins folder...\n");
		exit(1);
	}
	struct dirent *pluginent = NULL;
	char pluginpath[255];
	while((pluginent = readdir(dir))) {
		int len = strlen(pluginent->d_name);
		if (len < 4) {
			continue;
		}
		if (strcasecmp(pluginent->d_name+len-3, ".so")) {
			continue;
		}
		JANUS_LOG(LOG_INFO, "Loading plugin '%s'...\n", pluginent->d_name);
		memset(pluginpath, 0, 255);
		sprintf(pluginpath, "%s/%s", path, pluginent->d_name);
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
			/* Are all methods and callbacks implemented? */
			if(!janus_plugin->init || !janus_plugin->destroy ||
					!janus_plugin->get_version ||
					!janus_plugin->get_version_string ||
					!janus_plugin->get_description ||
					!janus_plugin->get_package ||
					!janus_plugin->get_name ||
					!janus_plugin->get_name ||
					!janus_plugin->create_session ||
					!janus_plugin->handle_message ||
					!janus_plugin->setup_media ||
					!janus_plugin->incoming_rtp ||	/* FIXME Does this have to be mandatory? (e.g., sendonly plugins) */
					!janus_plugin->incoming_rtcp ||
					!janus_plugin->hangup_media) {
				JANUS_LOG(LOG_ERR, "\tMissing some methods/callbacks, skipping this plugin...\n");
				continue;
			}
			janus_plugin->init(&janus_handler_plugin, configs_folder);
			JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_plugin->get_version(), janus_plugin->get_version_string());
			JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_plugin->get_package(), janus_plugin->get_name());
			JANUS_LOG(LOG_VERB, "\t   %s\n", janus_plugin->get_description());
			if(plugins == NULL)
				plugins = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins, (gpointer)janus_plugin->get_package(), janus_plugin);
			if(plugins_so == NULL)
				plugins_so = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins_so, (gpointer)janus_plugin->get_package(), plugin);
		}
	}
	closedir(dir);

	/* Prepare a summary on the gateway */
	json_t *info = json_object();
	json_object_set_new(info, "name", json_string(JANUS_NAME));
	json_object_set_new(info, "version", json_integer(JANUS_VERSION));
	json_object_set_new(info, "version_string", json_string(JANUS_VERSION_STRING));
	json_object_set_new(info, "author", json_string(JANUS_AUTHOR));
#ifdef HAVE_SCTP
	json_object_set_new(info, "data_channels", json_integer(1));
#else
	json_object_set_new(info, "data_channels", json_integer(0));
#endif
#ifdef HAVE_WS
	json_object_set_new(info, "websockets", json_integer(1));
#else
	json_object_set_new(info, "websockets", json_integer(0));
#endif
	json_t *data = json_object();
	GList *plugins_list = g_hash_table_get_values(plugins);
	GList *ps = plugins_list;
	while(ps) {
		janus_plugin *p = (janus_plugin *)ps->data;
		if(p == NULL) {
			ps = ps->next;
			continue;
		}
		json_t *plugin = json_object();
		json_object_set_new(plugin, "name", json_string(p->get_name()));
		json_object_set_new(plugin, "author", json_string(p->get_author()));
		json_object_set_new(plugin, "description", json_string(p->get_description()));
		json_object_set_new(plugin, "version_string", json_string(p->get_version_string()));
		json_object_set_new(plugin, "version", json_integer(p->get_version()));
		ps = ps->next;
		json_object_set_new(data, p->get_package(), plugin);
	}
	g_list_free(plugins_list);
	json_object_set_new(info, "plugins", data);
	/* Convert to a string */
	info_text = json_dumps(info, JSON_INDENT(3));
	json_decref(info);

	/* Start web server, if enabled */
	sessions = g_hash_table_new(NULL, NULL);
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
	if(item && item->value && !strcasecmp(item->value, "no")) {
		JANUS_LOG(LOG_WARN, "HTTP webserver disabled\n");
	} else {
		int wsport = 8088;
		item = janus_config_get_item_drilldown(config, "webserver", "port");
		if(item && item->value)
			wsport = atoi(item->value);
		if(threads == 0) {
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the HTTP web server\n");
			ws = MHD_start_daemon(
				MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				wsport,
				NULL,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the HTTP web server\n", threads);
			ws = MHD_start_daemon(
				MHD_USE_SELECT_INTERNALLY,
				wsport,
				NULL,
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
	if(item && item->value && !strcasecmp(item->value, "no")) {
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
			JANUS_LOG(LOG_VERB, "Using a thread per connection for the HTTPS web server\n");
			sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
				swsport,
				NULL,
				NULL,
				&janus_ws_handler,
				ws_path,
				MHD_OPTION_NOTIFY_COMPLETED, &janus_ws_request_completed, NULL,
					/* FIXME We're using the same certificates as those for DTLS */
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem_bytes,
					MHD_OPTION_HTTPS_MEM_KEY, cert_key_bytes,
				MHD_OPTION_END);
		} else {
			JANUS_LOG(LOG_VERB, "Using a thread pool of size %"SCNi64" the HTTPS web server\n", threads);
			sws = MHD_start_daemon(
				MHD_USE_SSL | MHD_USE_SELECT_INTERNALLY,
				swsport,
				NULL,
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
#ifndef HAVE_WS
	JANUS_LOG(LOG_WARN, "WebSockets support not compiled\n");
#else
	item = janus_config_get_item_drilldown(config, "webserver", "ws");
	if(item && item->value && !strcasecmp(item->value, "no")) {
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
		g_sprintf(port, "%d", wsport);
		libwebsock_bind(wss, "0.0.0.0", port);
		JANUS_LOG(LOG_INFO, "WebSockets server started (port %d)...\n", wsport);
		wss->onopen = janus_wss_onopen;
		wss->onmessage = janus_wss_onmessage;
		wss->onclose = janus_wss_onclose;
		wss_sessions = g_hash_table_new(NULL, NULL);
		janus_mutex_init(&wss_mutex);
	}
	item = janus_config_get_item_drilldown(config, "webserver", "ws_ssl");
	if(item && item->value && !strcasecmp(item->value, "no")) {
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
			g_sprintf(port, "%d", wsport);
			libwebsock_bind_ssl(swss, "0.0.0.0", port, server_key, server_pem);
			JANUS_LOG(LOG_INFO, "Secure WebSockets server started (port %d)...\n", wsport);
			swss->onopen = janus_wss_onopen;
			swss->onmessage = janus_wss_onmessage;
			swss->onclose = janus_wss_onclose;
			wss_sessions = g_hash_table_new(NULL, NULL);
			janus_mutex_init(&wss_mutex);
		}
	}
#endif
	/* Do we have anything up? */
#ifdef HAVE_WS
	if(!ws && !sws && !wss && !swss) {
#else
	if(!ws && !sws) {
#endif
		JANUS_LOG(LOG_FATAL, "No webserver (HTTP/HTTPS/WS) started, giving up...\n"); 
		exit(1);
	}

	/* Start the sessions watchdog */
	GThread *watchdog = g_thread_new("watchdog", &janus_sessions_watchdog, NULL);
	if(!watchdog) {
		JANUS_LOG(LOG_FATAL, "Couldn't start sessions watchdog...\n");
		exit(1);
	}
	
#ifdef HAVE_WS
	if(wss || swss) {
		/* The libwebsock wait is our loop */
		libwebsock_wait(wss ? wss : swss);
		if(!stop)
			janus_handle_signal(SIGINT);
	} else {
		while(!stop) {
			/* Loop until we have to stop */
			g_usleep(250000);
		}
	}
#else
	while(!stop) {
		/* Loop until we have to stop */
		g_usleep(250000);
	}
#endif

	/* Done */
	g_thread_join(watchdog);
	watchdog = NULL;
	if(config)
		janus_config_destroy(config);
	JANUS_LOG(LOG_INFO, "Closing webserver...\n");
	if(ws)
		MHD_stop_daemon(ws);
	ws = NULL;
	if(sws)
		MHD_stop_daemon(sws);
	sws = NULL;
	if(cert_pem_bytes != NULL)
		g_free((gpointer)cert_pem_bytes);
	cert_pem_bytes = NULL;
	if(cert_key_bytes != NULL)
		g_free((gpointer)cert_key_bytes);
	cert_key_bytes = NULL;
	JANUS_LOG(LOG_INFO, "Destroying sessions...\n");
	if(sessions != NULL)
		g_hash_table_destroy(sessions);
#ifdef HAVE_WS
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
