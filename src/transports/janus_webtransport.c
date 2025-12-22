/*! \file   janus_webtransport.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus WebTransport transport plugin
 * \details  This is an experimental implementation of a WebTransport
 * transport for the Janus API, using the imquic library
 * (https://imquic.conf.meetecho.com/). The way it works is very similar
 * to the WebSocket transport plugin, as in once a connection is
 * established, it can be used for requests, responses and asynchronous
 * notifications originated by the associated sessions.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include <imquic/imquic.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_WEBTRANSPORT_VERSION			1
#define JANUS_WEBTRANSPORT_VERSION_STRING	"0.0.1"
#define JANUS_WEBTRANSPORT_DESCRIPTION		"This transport plugin adds WebTransport support to the Janus API via imquic."
#define JANUS_WEBTRANSPORT_NAME				"JANUS WebTransport transport plugin"
#define JANUS_WEBTRANSPORT_AUTHOR			"Meetecho s.r.l."
#define JANUS_WEBTRANSPORT_PACKAGE			"janus.transport.webtransport"

/* Transport methods */
janus_transport *create(void);
int janus_webtransport_init(janus_transport_callbacks *callback, const char *config_path);
void janus_webtransport_destroy(void);
int janus_webtransport_get_api_compatibility(void);
int janus_webtransport_get_version(void);
const char *janus_webtransport_get_version_string(void);
const char *janus_webtransport_get_description(void);
const char *janus_webtransport_get_name(void);
const char *janus_webtransport_get_author(void);
const char *janus_webtransport_get_package(void);
gboolean janus_webtransport_is_janus_api_enabled(void);
gboolean janus_webtransport_is_admin_api_enabled(void);
int janus_webtransport_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_webtransport_session_created(janus_transport_session *transport, guint64 session_id);
void janus_webtransport_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_webtransport_session_claimed(janus_transport_session *transport, guint64 session_id);
json_t *janus_webtransport_query_transport(json_t *request);

/* Transport setup */
static janus_transport janus_webtransport_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_webtransport_init,
		.destroy = janus_webtransport_destroy,

		.get_api_compatibility = janus_webtransport_get_api_compatibility,
		.get_version = janus_webtransport_get_version,
		.get_version_string = janus_webtransport_get_version_string,
		.get_description = janus_webtransport_get_description,
		.get_name = janus_webtransport_get_name,
		.get_author = janus_webtransport_get_author,
		.get_package = janus_webtransport_get_package,

		.is_janus_api_enabled = janus_webtransport_is_janus_api_enabled,
		.is_admin_api_enabled = janus_webtransport_is_admin_api_enabled,

		.send_message = janus_webtransport_send_message,
		.session_created = janus_webtransport_session_created,
		.session_over = janus_webtransport_session_over,
		.session_claimed = janus_webtransport_session_claimed,

		.query_transport = janus_webtransport_query_transport,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_WEBTRANSPORT_NAME);
	return &janus_webtransport_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean wt_janus_api_enabled = FALSE;
static gboolean wt_admin_api_enabled = FALSE;
static gboolean notify_events = TRUE;

/* Connections maps */
static GHashTable *connections = NULL;
static janus_mutex wt_mutex = JANUS_MUTEX_INITIALIZER;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* Parameter validation (for tweaking and queries via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter configure_parameters[] = {
	{"events", JANUS_JSON_BOOL, 0},
	{"json", JSON_STRING, 0},
};
/* Error codes (for the tweaking and queries via Admin API) */
#define JANUS_WEBTRANSPORT_ERROR_INVALID_REQUEST	411
#define JANUS_WEBTRANSPORT_ERROR_MISSING_ELEMENT	412
#define JANUS_WEBTRANSPORT_ERROR_INVALID_ELEMENT	413
#define JANUS_WEBTRANSPORT_ERROR_UNKNOWN_ERROR		499

/* imquic servers */
static imquic_server *wt = NULL, *admin_wt = NULL;

/* imquic callbacks */
static void janus_webtransport_new_connection(imquic_connection *conn, void *user_data);
static void janus_webtransport_stream_incoming(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete);
static void janus_webtransport_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length);
static void janus_webtransport_connection_gone(imquic_connection *conn);

/* WebTransport client session */
typedef struct janus_webtransport_client_message {
	uint64_t stream_id;				/* Stream ID this message belongs to */
	char *buffer;					/* Buffer containing the incoming message to process (in case there are fragments) */
	size_t bufsize;					/* Current offset of the buffer */
} janus_webtransport_client_message;
static void janus_webtransport_client_message_free(janus_webtransport_client_message *message) {
	if(message) {
		g_free(message->buffer);
		g_free(message);
	}
}
typedef struct janus_webtransport_client {
	gboolean admin;					/* Whether this is a Janus or Admin API client */
	imquic_connection *conn;		/* imquic connection */
	GHashTable *incoming;			/* Table of partial incoming messages, indexed by stream ID s*/
	volatile gint destroyed;		/* Whether this WebTransport client instance has been closed */
	janus_transport_session *ts;	/* Janus core-transport session */
} janus_webtransport_client;

static imquic_server *janus_webtransport_create_wt_server(
		gboolean admin, janus_config *config,
		janus_config_container *config_container,
		janus_config_container *config_certs, uint16_t default_port)
{
	/* Is this for the Janus or Admin API? */
	const char *prefix = (admin ? "admin_wt" : "wt");
	const char *name = (admin ? "WT-Admin" : "WT-Janus");
	const char *type = (admin ? "Admin API" : "Janus API");

	/* Parse the configuration */
	janus_config_item *item = NULL;
	char item_name[255];

	item = janus_config_get(config, config_container, janus_config_type_item, prefix);
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_VERB, "%s server disabled\n", type);
		return NULL;
	}

	uint16_t port = default_port;
	g_snprintf(item_name, 255, "%s_port", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
	if(item && item->value && janus_string_to_uint16(item->value, &port) < 0) {
		JANUS_LOG(LOG_ERR, "Invalid port (%s), falling back to default\n", item->value);
		port = default_port;
	}

	char *ip = NULL;
	g_snprintf(item_name, 255, "%s_ip", prefix);
	item = janus_config_get(config, config_container, janus_config_type_item, item_name);
	if(item && item->value)
		ip = (char *)item->value;

	char *server_pem = NULL;
	char *server_key = NULL;
	char *password = NULL;

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

	/* Prepare server */
	imquic_server *server = imquic_create_server(name,
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, server_pem,
		IMQUIC_CONFIG_TLS_KEY, server_key,
		IMQUIC_CONFIG_TLS_PASSWORD, password,
		IMQUIC_CONFIG_LOCAL_BIND, ip,
		IMQUIC_CONFIG_LOCAL_PORT, port,
		IMQUIC_CONFIG_WEBTRANSPORT, TRUE,
		IMQUIC_CONFIG_USER_DATA, (admin ? GUINT_TO_POINTER(1) : NULL),
		IMQUIC_CONFIG_DONE, NULL);
	if(server == NULL) {
		JANUS_LOG(LOG_FATAL, "Error creating %s WebTransport server...\n", type);
	} else {
		imquic_set_new_connection_cb(server, janus_webtransport_new_connection);
		imquic_set_stream_incoming_cb(server, janus_webtransport_stream_incoming);
		imquic_set_datagram_incoming_cb(server, janus_webtransport_datagram_incoming);
		imquic_set_connection_gone_cb(server, janus_webtransport_connection_gone);
		imquic_start_endpoint(server);
		JANUS_LOG(LOG_INFO, "WebTransport %s server started (port %d)...\n", type, port);
	}
	g_free(ip);
	return server;
}

/* Transport implementation */
int janus_webtransport_init(janus_transport_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	if(!imquic_is_inited()) {
		/* imquic wasn't initialized */
		JANUS_LOG(LOG_FATAL, "imquic not initialized (has Janus been built with imquic support?\n");
		return -1;
	}

	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_WEBTRANSPORT_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_WEBTRANSPORT_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_WEBTRANSPORT_PACKAGE);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_WEBTRANSPORT_NAME);
		}

		/* Setup the Janus API WebTransport server */
		wt = janus_webtransport_create_wt_server(FALSE,
			config, config_general, config_certs, 9088);
		/* Do the same for the Admin API, if enabled */
		admin_wt = janus_webtransport_create_wt_server(TRUE,
			config, config_admin, config_certs, 9188);
	}
	janus_config_destroy(config);
	config = NULL;
	wt_janus_api_enabled = (wt != NULL);
	wt_admin_api_enabled = (admin_wt != NULL);
	if(!wt_janus_api_enabled && !wt_admin_api_enabled) {
		JANUS_LOG(LOG_WARN, "No WebTransport server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Connections maps */
	connections = g_hash_table_new(NULL, NULL);

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_WEBTRANSPORT_NAME);
	return 0;
}

void janus_webtransport_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	/* Stop the servers */
	if(wt)
		imquic_shutdown_endpoint(wt);
	if(admin_wt)
		imquic_shutdown_endpoint(admin_wt);

	janus_mutex_lock(&wt_mutex);
	g_hash_table_destroy(connections);
	janus_mutex_unlock(&wt_mutex);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_WEBTRANSPORT_NAME);
}

int janus_webtransport_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_webtransport_get_version(void) {
	return JANUS_WEBTRANSPORT_VERSION;
}

const char *janus_webtransport_get_version_string(void) {
	return JANUS_WEBTRANSPORT_VERSION_STRING;
}

const char *janus_webtransport_get_description(void) {
	return JANUS_WEBTRANSPORT_DESCRIPTION;
}

const char *janus_webtransport_get_name(void) {
	return JANUS_WEBTRANSPORT_NAME;
}

const char *janus_webtransport_get_author(void) {
	return JANUS_WEBTRANSPORT_AUTHOR;
}

const char *janus_webtransport_get_package(void) {
	return JANUS_WEBTRANSPORT_PACKAGE;
}

gboolean janus_webtransport_is_janus_api_enabled(void) {
	return wt_janus_api_enabled;
}

gboolean janus_webtransport_is_admin_api_enabled(void) {
	return wt_admin_api_enabled;
}

int janus_webtransport_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL || g_atomic_int_get(&transport->destroyed)) {
		json_decref(message);
		return -1;
	}
	janus_mutex_lock(&transport->mutex);
	janus_webtransport_client *client = (janus_webtransport_client *)transport->transport_p;
	if(!client || !client->conn || g_atomic_int_get(&client->destroyed)) {
		json_decref(message);
		janus_mutex_unlock(&transport->mutex);
		return -1;
	}
	imquic_connection_ref(client->conn);
	janus_mutex_unlock(&transport->mutex);
	/* Convert to string and enqueue */
	char *payload = json_dumps(message, json_format);
	if(payload == NULL) {
		JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
		imquic_connection_unref(client->conn);
		json_decref(message);
		return -1;
	}
	/* Send the message: we create a new stream for each message */
	uint64_t stream_id = 0;
	imquic_new_stream_id(client->conn, FALSE, &stream_id);
	imquic_send_on_stream(client->conn, stream_id, (uint8_t *)payload, 0, strlen(payload), TRUE);
	/* Done */
	imquic_connection_unref(client->conn);
	json_decref(message);
	return 0;
}

void janus_webtransport_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_webtransport_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We don't care either: transport timeouts can be detected via imquic */
}

void janus_webtransport_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}

json_t *janus_webtransport_query_transport(json_t *request) {
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
		JANUS_WEBTRANSPORT_ERROR_MISSING_ELEMENT, JANUS_WEBTRANSPORT_ERROR_INVALID_ELEMENT);
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
			JANUS_WEBTRANSPORT_ERROR_MISSING_ELEMENT, JANUS_WEBTRANSPORT_ERROR_INVALID_ELEMENT);
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
				JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_WEBTRANSPORT_NAME);
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
	} else if(!strcasecmp(request_text, "connections")) {
		/* Return the number of active connections currently handled by the plugin */
		json_object_set_new(response, "result", json_integer(200));
#if (LWS_LIBRARY_VERSION_MAJOR >= 3)
		janus_mutex_lock(&wt_mutex);
		guint connections = g_hash_table_size(connections);
		janus_mutex_unlock(&wt_mutex);
		json_object_set_new(response, "connections", json_integer(connections));
#endif
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_WEBTRANSPORT_ERROR_INVALID_REQUEST;
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

/* imquic callbacks */
static void janus_webtransport_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	JANUS_LOG(LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
	imquic_connection_ref(conn);
	/* Track connection */
	janus_webtransport_client *wt_client = g_malloc0(sizeof(janus_webtransport_client));
	wt_client->admin = (user_data != NULL);
	wt_client->conn = conn;
	wt_client->incoming = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_webtransport_client_message_free);
	wt_client->ts = janus_transport_session_create(wt_client, NULL);
	janus_mutex_lock(&wt_mutex);
	g_hash_table_insert(connections, conn, wt_client);
	janus_mutex_unlock(&wt_mutex);
	/* Notify handlers about this new transport */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("connected"));
		json_object_set_new(info, "admin_api", wt_client->admin ? json_true() : json_false());
		json_object_set_new(info, "connection", json_string(imquic_get_connection_name(conn)));
		gateway->notify_event(&janus_webtransport_transport, wt_client->ts, info);
	}
}

static void janus_webtransport_stream_incoming(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	/* Got incoming data via STREAM */
	JANUS_LOG(LOG_INFO, "[%s] [STREAM-%"SCNu64"] Got data: %"SCNu64"--%"SCNu64" (%s)\n",
		imquic_get_connection_name(conn),
		stream_id, offset, offset+length, (complete ? "complete" : "not complete"));
	if(length > 0) {
		int len = length;
		JANUS_LOG(LOG_INFO, "  -- %.*s\n", len, (char *)(bytes));
	}
	/* Get the associated client */
	janus_mutex_lock(&wt_mutex);
	janus_webtransport_client *wt_client = g_hash_table_lookup(connections, conn);
	janus_mutex_unlock(&wt_mutex);
	if(wt_client == NULL || g_atomic_int_get(&wt_client->destroyed))
		return;
	janus_webtransport_client_message *message = g_hash_table_lookup(wt_client->incoming, &stream_id);
	if(message == NULL) {
		message = g_malloc0(sizeof(janus_webtransport_client_message));
		message->stream_id = stream_id;
		message->buffer = g_malloc(length + 1);
		memcpy(message->buffer, bytes, length);
		message->bufsize = length;
		*(message->buffer + message->bufsize) = '\0';
		g_hash_table_insert(wt_client->incoming, janus_uint64_dup(stream_id), message);
	} else if(length > 0) {
		message->buffer = g_realloc(message->buffer, message->bufsize + length + 1);
		memcpy(message->buffer + message->bufsize, bytes, length);
		*(message->buffer + message->bufsize) = '\0';
		message->bufsize += length;
	}
	if(!complete) {
		/* Nothing we can do for now */
		JANUS_LOG(LOG_INFO, "[%s] [STREAM-%"SCNu64"] Waiting for more data\n",
			imquic_get_connection_name(conn), stream_id);
		return;
	}
	/* If we got here, the message is complete: parse the JSON payload */
	JANUS_LOG(LOG_INFO, "[%s] [STREAM-%"SCNu64"] Done, parsing message: %zu bytes\n",
		imquic_get_connection_name(conn), stream_id, message->bufsize);
	const char *incoming_curr = message->buffer;
	const char *incoming_end = message->buffer + message->bufsize;
	int json_buffer_count = 0;
	json_t **json_buffer = NULL;
	/* Load all JSON messages from the WebTransport incoming */
	do {
		json_error_t error;
		json_t *json = json_loads(incoming_curr, JSON_DISABLE_EOF_CHECK, &error);
		if(json != NULL) {
			/* Position is set to bytes read on success when EOF_CHECK is disabled as above. */
			incoming_curr += error.position;
			JANUS_LOG(LOG_INFO, "[%s] [STREAM-%"SCNu64"] Parsed JSON message - consumed %zu/%zu bytes\n",
				imquic_get_connection_name(conn), stream_id, (size_t)(incoming_curr - message->buffer), message->bufsize);
			/* Trailing whitespace after the last message results in invalid JSON error */
			while (incoming_curr < incoming_end && isspace(*incoming_curr))
				incoming_curr++;
			if(incoming_curr == incoming_end) {
				if(json_buffer != NULL) {
					/* Process messages in order */
					json_t **msg = json_buffer;
					json_t **msg_end = json_buffer + json_buffer_count;
					while(msg != msg_end) {
						/* Notify the core, no error since we know there weren't any */
						gateway->incoming_request(&janus_webtransport_transport, wt_client->ts, NULL, wt_client->admin, *msg++, NULL);
					}
				}
				/* Notify the core, no error since we know there weren't any */
				gateway->incoming_request(&janus_webtransport_transport, wt_client->ts, NULL, wt_client->admin, json, NULL);
				break;
			} else {
				/* Buffer the message */
				json_buffer = (json_t**)g_realloc(json_buffer, sizeof(json_t*) * (json_buffer_count + 1));
				json_buffer[json_buffer_count++] = json;
			}
		} else {
			if(json_buffer != NULL) {
				/* Release any buffered messages */
				json_t **msg = json_buffer;
				json_t **msg_end = json_buffer + json_buffer_count;
				while(msg != msg_end) {
					json_decref(*msg++);
				}
			}
			/* Notify the core, passing the error since we have no message */
			gateway->incoming_request(&janus_webtransport_transport, wt_client->ts, NULL, wt_client->admin, NULL, &error);
			break;
		}
	} while(incoming_curr < incoming_end);
	/* Get rid of the message */
	g_free(json_buffer);
	g_hash_table_remove(wt_client->incoming, &stream_id);
}

static void janus_webtransport_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	/* Got incoming data via DATAGRAM (we only accept STREAM for now) */
	JANUS_LOG(LOG_WARN, "[%s] [DATAGRAM] Got data: %"SCNu64" (ignored)\n", imquic_get_connection_name(conn), length);
}

static void janus_webtransport_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	JANUS_LOG(LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	/* Get the associated client */
	janus_mutex_lock(&wt_mutex);
	janus_webtransport_client *wt_client = g_hash_table_lookup(connections, conn);
	g_hash_table_remove(connections, conn);
	janus_mutex_unlock(&wt_mutex);
	if(!wt_client || !wt_client->ts)
		return;
	janus_mutex_lock(&wt_client->ts->mutex);
	if(!g_atomic_int_compare_and_exchange(&wt_client->destroyed, 0, 1)) {
		janus_mutex_unlock(&wt_client->ts->mutex);
		return;
	}
	/* Cleanup */
	JANUS_LOG(LOG_INFO, "[%s] Destroying WebTransport client\n", imquic_get_connection_name(conn));
	/* Notify handlers about this transport being gone */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("disconnected"));
		json_object_set_new(info, "admin_api", wt_client->admin ? json_true() : json_false());
		json_object_set_new(info, "connection", json_string(imquic_get_connection_name(conn)));
		gateway->notify_event(&janus_webtransport_transport, wt_client->ts, info);
	}
	imquic_connection_unref(conn);
	g_hash_table_destroy(wt_client->incoming);
	janus_mutex_unlock(&wt_client->ts->mutex);
	/* Notify core */
	gateway->transport_gone(&janus_webtransport_transport, wt_client->ts);
	janus_transport_session_destroy(wt_client->ts);
	g_free(wt_client);
}
