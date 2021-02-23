/*! \file   janus_pfunix.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Unix Sockets transport plugin
 * \details  This is an implementation of a Unix Sockets transport for the
 * Janus API. This means that, with the help of this module, local
 * applications can use Unix Sockets to make requests to Janus.
 * This plugin can make use of either the \c SOCK_SEQPACKET or the
 * \c SOCK_DGRAM socket type according to what you configure, so make
 * sure you're using the right one when writing a client application.
 * Pretty much as it happens with WebSockets, the same client socket can
 * be used for both sending requests and receiving notifications, without
 * any need for long polls. At the same time, without the concept of a
 * REST path, requests sent through the Unix Sockets interface will need
 * to include, when needed, additional pieces of information like
 * \c session_id and \c handle_id. That is, where you'd send a Janus
 * request related to a specific session to the \c /janus/\<session> path,
 * with Unix Sockets you'd have to send the same request with an additional
 * \c session_id field in the JSON payload. The same applies for the handle.
 * \note When you create a session using Unix Sockets, a subscription to
 * the events related to it is done automatically, so no need for an
 * explicit request as the GET in the plain HTTP API. Closing a client
 * Unix Socket will also destroy all the sessions it created.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>

#ifdef  HAVE_LIBSYSTEMD
#include "systemd/sd-daemon.h"
#endif /* HAVE_LIBSYSTEMD */

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_PFUNIX_VERSION			1
#define JANUS_PFUNIX_VERSION_STRING		"0.0.1"
#define JANUS_PFUNIX_DESCRIPTION		"This transport plugin adds Unix Sockets support to the Janus API."
#define JANUS_PFUNIX_NAME				"JANUS Unix Sockets transport plugin"
#define JANUS_PFUNIX_AUTHOR				"Meetecho s.r.l."
#define JANUS_PFUNIX_PACKAGE			"janus.transport.pfunix"

/* Transport methods */
janus_transport *create(void);
int janus_pfunix_init(janus_transport_callbacks *callback, const char *config_path);
void janus_pfunix_destroy(void);
int janus_pfunix_get_api_compatibility(void);
int janus_pfunix_get_version(void);
const char *janus_pfunix_get_version_string(void);
const char *janus_pfunix_get_description(void);
const char *janus_pfunix_get_name(void);
const char *janus_pfunix_get_author(void);
const char *janus_pfunix_get_package(void);
gboolean janus_pfunix_is_janus_api_enabled(void);
gboolean janus_pfunix_is_admin_api_enabled(void);
int janus_pfunix_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_pfunix_session_created(janus_transport_session *transport, guint64 session_id);
void janus_pfunix_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_pfunix_session_claimed(janus_transport_session *transport, guint64 session_id);
json_t *janus_pfunix_query_transport(json_t *request);


/* Transport setup */
static janus_transport janus_pfunix_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_pfunix_init,
		.destroy = janus_pfunix_destroy,

		.get_api_compatibility = janus_pfunix_get_api_compatibility,
		.get_version = janus_pfunix_get_version,
		.get_version_string = janus_pfunix_get_version_string,
		.get_description = janus_pfunix_get_description,
		.get_name = janus_pfunix_get_name,
		.get_author = janus_pfunix_get_author,
		.get_package = janus_pfunix_get_package,

		.is_janus_api_enabled = janus_pfunix_is_janus_api_enabled,
		.is_admin_api_enabled = janus_pfunix_is_admin_api_enabled,

		.send_message = janus_pfunix_send_message,
		.session_created = janus_pfunix_session_created,
		.session_over = janus_pfunix_session_over,
		.session_claimed = janus_pfunix_session_claimed,

		.query_transport = janus_pfunix_query_transport,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_PFUNIX_NAME);
	return &janus_pfunix_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean notify_events = TRUE;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

#define BUFFER_SIZE		8192

/* Parameter validation (for tweaking and queries via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter configure_parameters[] = {
	{"events", JANUS_JSON_BOOL, 0},
	{"json", JSON_STRING, 0},
};
/* Error codes (for the tweaking and queries via Admin API) */
#define JANUS_PFUNIX_ERROR_INVALID_REQUEST		411
#define JANUS_PFUNIX_ERROR_MISSING_ELEMENT		412
#define JANUS_PFUNIX_ERROR_INVALID_ELEMENT		413
#define JANUS_PFUNIX_ERROR_UNKNOWN_ERROR		499


struct sockaddr_un sizecheck;
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

/* Unix Sockets server thread */
static GThread *pfunix_thread = NULL;
void *janus_pfunix_thread(void *data);

/* Unix Sockets servers (and whether they should be SOCK_SEQPACKET or SOCK_DGRAM) */
static int pfd = -1, admin_pfd = -1;
static gboolean dgram = FALSE, admin_dgram = FALSE;
#ifdef HAVE_LIBSYSTEMD
static gboolean sd_socket = FALSE, admin_sd_socket = FALSE;
#endif /* HAVE_LIBSYSTEMD */
/* Socket pair to notify about the need for outgoing data */
static int write_fd[2];

/* Unix Sockets client session */
typedef struct janus_pfunix_client {
	int fd;							/* Client socket (in case SOCK_SEQPACKET is used) */
	struct sockaddr_un addr;		/* Client address (in case SOCK_DGRAM is used) */
	gboolean admin;					/* Whether this client is for the Admin or Janus API */
	GAsyncQueue *messages;			/* Queue of outgoing messages to push */
	gboolean session_timeout;		/* Whether a Janus session timeout occurred in the core */
	janus_transport_session *ts;	/* Janus core-transport session */
} janus_pfunix_client;
static GHashTable *clients = NULL, *clients_by_fd = NULL, *clients_by_path = NULL;
static janus_mutex clients_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_pfunix_client_free(void *client_ref) {
	if(!client_ref)
		return;
	JANUS_LOG(LOG_INFO, "Freeing unix sockets client\n");
	janus_pfunix_client *client = (janus_pfunix_client *) client_ref;
	if(client->messages != NULL) {
		char *response = NULL;
		while((response = g_async_queue_try_pop(client->messages)) != NULL) {
			g_free(response);
		}
		g_async_queue_unref(client->messages);
	}
	g_free(client);
}


/* Helper to create a named Unix Socket out of the path to link to */
static int janus_pfunix_create_socket(char *pfname, gboolean use_dgram) {
	if(pfname == NULL)
		return -1;
	int fd = -1;
	if(strlen(pfname) > UNIX_PATH_MAX) {
		JANUS_LOG(LOG_WARN, "The provided path name (%s) is longer than %lu characters, it will be truncated\n", pfname, UNIX_PATH_MAX);
		pfname[UNIX_PATH_MAX] = '\0';
	}
	/* Create socket */
	int flags = use_dgram ? SOCK_DGRAM | SOCK_NONBLOCK : SOCK_SEQPACKET | SOCK_NONBLOCK;
	fd = socket(use_dgram ? AF_UNIX : PF_UNIX, flags, 0);
	if(fd < 0) {
		JANUS_LOG(LOG_FATAL, "Unix Sockets %s creation failed: %d, %s\n", pfname, errno, strerror(errno));
	} else {
		/* Unlink before binding */
		unlink(pfname);
		/* Let's bind to the provided path now */
		struct sockaddr_un address;
		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		g_snprintf(address.sun_path, UNIX_PATH_MAX, "%s", pfname);
		JANUS_LOG(LOG_VERB, "Binding Unix Socket %s... (Janus API)\n", pfname);
		if(bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
			JANUS_LOG(LOG_FATAL, "Bind for Unix Socket %s failed: %d, %s\n", pfname, errno, strerror(errno));
			close(fd);
			fd = -1;
			return fd;
		}
		if(!use_dgram) {
			JANUS_LOG(LOG_VERB, "Listening on Unix Socket %s...\n", pfname);
			if(listen(fd, 128) != 0) {
				JANUS_LOG(LOG_FATAL, "Listening on Unix Socket %s failed: %d, %s\n", pfname, errno, strerror(errno));
				close(fd);
				fd = -1;
			}
		}
	}
	return fd;
}

/* Transport implementation */
int janus_pfunix_init(janus_transport_callbacks *callback, const char *config_path) {
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

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_PFUNIX_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_PFUNIX_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_PFUNIX_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_category *config_admin = janus_config_get_create(config, NULL, janus_config_type_category, "admin");

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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_PFUNIX_NAME);
		}

		/* First of all, initialize the socketpair for writeable notifications */
		if(socketpair(PF_LOCAL, SOCK_STREAM, 0, write_fd) < 0) {
			JANUS_LOG(LOG_FATAL, "Error creating socket pair for writeable events: %d, %s\n", errno, strerror(errno));
			return -1;
		}

		/* Setup the Janus API Unix Sockets server(s) */
		item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_VERB, "Unix Sockets server disabled (Janus API)\n");
		} else {
			item = janus_config_get(config, config_general, janus_config_type_item, "path");
			char *pfname = (char *)(item && item->value ? item->value : NULL);
			item = janus_config_get(config, config_general, janus_config_type_item, "type");
			const char *type = item && item->value ? item->value : "SOCK_SEQPACKET";
			dgram = FALSE;
			if(!strcasecmp(type, "SOCK_SEQPACKET")) {
				dgram = FALSE;
			} else if(!strcasecmp(type, "SOCK_DGRAM")) {
				dgram = TRUE;
			} else {
				JANUS_LOG(LOG_WARN, "Unknown type %s, assuming SOCK_SEQPACKET\n", type);
				type = "SOCK_SEQPACKET";
			}
			if(pfname == NULL) {
				JANUS_LOG(LOG_WARN, "No path configured, skipping Unix Sockets server (Janus API)\n");
			} else {
				JANUS_LOG(LOG_INFO, "Configuring %s Unix Sockets server (Janus API)\n", type);
#ifdef HAVE_LIBSYSTEMD
				if (sd_listen_fds(0) > 0) {
					pfd = SD_LISTEN_FDS_START + 0;
					sd_socket = TRUE;
				} else
#endif /* HAVE_LIBSYSTEMD */
				pfd = janus_pfunix_create_socket(pfname, dgram);
			}
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_VERB, "Unix Sockets server disabled (Admin API)\n");
		} else {
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_path");
			char *pfname = (char *)(item && item->value ? item->value : NULL);
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_type");
			const char *type = item && item->value ? item->value : "SOCK_SEQPACKET";
			if(!strcasecmp(type, "SOCK_SEQPACKET")) {
				admin_dgram = FALSE;
			} else if(!strcasecmp(type, "SOCK_DGRAM")) {
				admin_dgram = TRUE;
			} else {
				JANUS_LOG(LOG_WARN, "Unknown type %s, assuming SOCK_SEQPACKET\n", type);
				type = "SOCK_SEQPACKET";
			}
			if(pfname == NULL) {
				JANUS_LOG(LOG_WARN, "No path configured, skipping Unix Sockets server (Admin API)\n");
			} else {
				JANUS_LOG(LOG_INFO, "Configuring %s Unix Sockets server (Admin API)\n", type);
#ifdef HAVE_LIBSYSTEMD
				if (sd_listen_fds(0) > 1) {
					admin_pfd = SD_LISTEN_FDS_START + 1;
					admin_sd_socket = TRUE;
				} else
#endif /* HAVE_LIBSYSTEMD */
				admin_pfd = janus_pfunix_create_socket(pfname, admin_dgram);
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(pfd < 0 && admin_pfd < 0) {
		JANUS_LOG(LOG_WARN, "No Unix Sockets server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Create a couple of hashtables for all clients */
	clients = g_hash_table_new(NULL, NULL);
	clients_by_fd = g_hash_table_new(NULL, NULL);
	clients_by_path = g_hash_table_new(g_str_hash, g_str_equal);

	/* Start the Unix Sockets service thread */
	GError *error = NULL;
	pfunix_thread = g_thread_try_new("pfunix thread", &janus_pfunix_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Unix Sockets thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_PFUNIX_NAME);
	return 0;
}

void janus_pfunix_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	/* Stop the service thread */
	int res = 0;
	do {
		res = write(write_fd[1], "x", 1);
	} while(res == -1 && errno == EINTR);

	if(pfunix_thread != NULL) {
		g_thread_join(pfunix_thread);
		pfunix_thread = NULL;
	}

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_PFUNIX_NAME);
}

int janus_pfunix_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_pfunix_get_version(void) {
	return JANUS_PFUNIX_VERSION;
}

const char *janus_pfunix_get_version_string(void) {
	return JANUS_PFUNIX_VERSION_STRING;
}

const char *janus_pfunix_get_description(void) {
	return JANUS_PFUNIX_DESCRIPTION;
}

const char *janus_pfunix_get_name(void) {
	return JANUS_PFUNIX_NAME;
}

const char *janus_pfunix_get_author(void) {
	return JANUS_PFUNIX_AUTHOR;
}

const char *janus_pfunix_get_package(void) {
	return JANUS_PFUNIX_PACKAGE;
}

gboolean janus_pfunix_is_janus_api_enabled(void) {
	return pfd > -1;
}

gboolean janus_pfunix_is_admin_api_enabled(void) {
	return admin_pfd > -1;
}

int janus_pfunix_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL || transport->transport_p == NULL) {
		json_decref(message);
		return -1;
	}
	/* Make sure this is related to a still valid Unix Sockets session */
	janus_pfunix_client *client = (janus_pfunix_client *)transport->transport_p;
	janus_mutex_lock(&clients_mutex);
	if(g_hash_table_lookup(clients, client) == NULL) {
		janus_mutex_unlock(&clients_mutex);
		JANUS_LOG(LOG_WARN, "Outgoing message for invalid client %p\n", client);
		json_decref(message);
		message = NULL;
		return -1;
	}
	janus_mutex_unlock(&clients_mutex);
	/* Convert to string */
	char *payload = json_dumps(message, json_format);
	json_decref(message);
	if(client->fd != -1) {
		/* SOCK_SEQPACKET, enqueue the packet and have poll tell us when it's time to send it */
		g_async_queue_push(client->messages, payload);
		/* Notify the thread there's data to send */
		int res = 0;
		do {
			res = write(write_fd[1], "x", 1);
		} while(res == -1 && errno == EINTR);
	} else {
		/* SOCK_DGRAM, send it right away */
		int res = 0;
		do {
			res = sendto(client->admin ? admin_pfd : pfd, payload, strlen(payload), 0, (struct sockaddr *)&client->addr, sizeof(struct sockaddr_un));
		} while(res == -1 && errno == EINTR);
		free(payload);
	}
	return 0;
}

void janus_pfunix_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_pfunix_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We only care if it's a timeout: if so, close the connection */
	if(transport == NULL || transport->transport_p == NULL || !timeout)
		return;
	/* FIXME Should we really close the connection in case of a timeout? */
	janus_pfunix_client *client = (janus_pfunix_client *)transport->transport_p;
	janus_mutex_lock(&clients_mutex);
	if(g_hash_table_lookup(clients, client) != NULL) {
		client->session_timeout = TRUE;
		/* Notify the thread about this */
		int res = 0;
		do {
			res = write(write_fd[1], "x", 1);
		} while(res == -1 && errno == EINTR);
	}
	janus_mutex_unlock(&clients_mutex);
}

void janus_pfunix_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}

json_t *janus_pfunix_query_transport(json_t *request) {
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
		JANUS_PFUNIX_ERROR_MISSING_ELEMENT, JANUS_PFUNIX_ERROR_INVALID_ELEMENT);
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
			JANUS_PFUNIX_ERROR_MISSING_ELEMENT, JANUS_PFUNIX_ERROR_INVALID_ELEMENT);
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
				JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_PFUNIX_NAME);
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
		janus_mutex_lock(&clients_mutex);
		guint connections = g_hash_table_size(clients);
		janus_mutex_unlock(&clients_mutex);
		json_object_set_new(response, "connections", json_integer(connections));
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_PFUNIX_ERROR_INVALID_REQUEST;
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
void *janus_pfunix_thread(void *data) {
	JANUS_LOG(LOG_INFO, "Unix Sockets thread started\n");

	int fds = 0;
	struct pollfd poll_fds[1024];	/* FIXME Should we allow for more clients? */
	char buffer[BUFFER_SIZE];
	struct iovec iov[1];
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Prepare poll list of file descriptors */
		fds = 0;
		/* Writeable monitor */
		poll_fds[fds].fd = write_fd[0];
		poll_fds[fds].events = POLLIN;
		fds++;
		if(pfd > -1) {
			/* Janus API */
			poll_fds[fds].fd = pfd;
			poll_fds[fds].events = POLLIN;
			fds++;
		}
		if(admin_pfd > -1) {
			/* Admin API */
			poll_fds[fds].fd = admin_pfd;
			poll_fds[fds].events = POLLIN;
			fds++;
		}
		/* Iterate on available clients, to see if we need to POLLIN or POLLOUT too */
		janus_mutex_lock(&clients_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, clients_by_fd);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_pfunix_client *client = value;
			if(client->fd > -1) {
				poll_fds[fds].fd = client->fd;
				poll_fds[fds].events = g_async_queue_length(client->messages) > 0 ? POLLIN | POLLOUT : POLLIN;
				fds++;
			}
		}
		janus_mutex_unlock(&clients_mutex);

		/* Start polling */
		int res = poll(poll_fds, fds, -1);
		if(res == 0)
			continue;
		if(res < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "Got an EINTR (%s) polling the Unix Sockets descriptors, ignoring...\n", strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "poll() failed: %d (%s)\n", errno, strerror(errno));
			break;
		}
		int i = 0;
		for(i=0; i<fds; i++) {
			if(poll_fds[i].revents & (POLLERR | POLLHUP)) {
				/* Socket error? Shall we do something? */
				if(poll_fds[i].fd == write_fd[0]) {
					/* Error in the wake-up socketpair, that sucks: try recreating it */
					JANUS_LOG(LOG_WARN, "Error polling wake-up socketpair: %s...\n",
						poll_fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
					close(write_fd[0]);
					write_fd[0] = -1;
					close(write_fd[1]);
					write_fd[1] = -1;
					if(socketpair(PF_LOCAL, SOCK_STREAM, 0, write_fd) < 0) {
						JANUS_LOG(LOG_FATAL, "Error creating socket pair for writeable events: %d, %s\n", errno, strerror(errno));
						continue;
					}
				} else if(poll_fds[i].fd == pfd) {
					/* Error in the Janus API socket */
					JANUS_LOG(LOG_WARN, "Error polling Unix Sockets Janus API interface (%s), disabling it\n",
						poll_fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
					close(pfd);
					pfd = -1;
					continue;
				} else if(poll_fds[i].fd == admin_pfd) {
					/* Error in the Admin API socket */
					JANUS_LOG(LOG_WARN, "Error polling Unix Sockets Admin API interface (%s), disabling it\n",
						poll_fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
					close(admin_pfd);
					admin_pfd = -1;
					continue;
				} else {
					/* Error in a client socket, find and remove it */
					janus_mutex_lock(&clients_mutex);
					janus_pfunix_client *client = g_hash_table_lookup(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
					if(client == NULL) {
						/* We're not handling this, ignore */
						janus_mutex_unlock(&clients_mutex);
						continue;
					}
					JANUS_LOG(LOG_INFO, "Unix Sockets client disconnected (%d)\n", poll_fds[i].fd);
					/* Notify core */
					gateway->transport_gone(&janus_pfunix_transport, client->ts);
					/* Notify handlers about this transport being gone */
					if(notify_events && gateway->events_is_enabled()) {
						json_t *info = json_object();
						json_object_set_new(info, "event", json_string("disconnected"));
						gateway->notify_event(&janus_pfunix_transport, client->ts, info);
					}
					/* Close socket */
					shutdown(SHUT_RDWR, poll_fds[i].fd);
					close(poll_fds[i].fd);
					client->fd = -1;
					/* Destroy the client */
					g_hash_table_remove(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
					g_hash_table_remove(clients, client);
					/* Unref the transport instance */
					janus_transport_session_destroy(client->ts);
					janus_mutex_unlock(&clients_mutex);
					continue;
				}
				continue;
			}
			if(poll_fds[i].revents & POLLOUT) {
				/* Find the client from its file descriptor */
				janus_mutex_lock(&clients_mutex);
				janus_pfunix_client *client = g_hash_table_lookup(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
				if(client != NULL) {
					char *payload = NULL;
					while((payload = g_async_queue_try_pop(client->messages)) != NULL) {
						int res = 0;
						do {
							if(client->fd < 0)
								break;
							res = write(client->fd, payload, strlen(payload));
						} while(res == -1 && errno == EINTR);
						/* FIXME Should we check if sent everything? */
						JANUS_LOG(LOG_HUGE, "Written %d/%zu bytes on %d\n", res, strlen(payload), client->fd);
						g_free(payload);
					}
					if(client->session_timeout) {
						/* We should actually get rid of this connection, now */
						shutdown(SHUT_RDWR, poll_fds[i].fd);
						close(poll_fds[i].fd);
						client->fd = -1;
						/* Destroy the client */
						g_hash_table_remove(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
						g_hash_table_remove(clients, client);
						if(client->messages != NULL) {
							char *response = NULL;
							while((response = g_async_queue_try_pop(client->messages)) != NULL) {
								g_free(response);
							}
							g_async_queue_unref(client->messages);
						}
						g_free(client);
					}
				}
				janus_mutex_unlock(&clients_mutex);
			}
			if(poll_fds[i].revents & POLLIN) {
				if(poll_fds[i].fd == write_fd[0]) {
					/* Read and ignore: we use this to unlock the poll if there's data to write */
					(void)read(poll_fds[i].fd, buffer, BUFFER_SIZE);
				} else if(poll_fds[i].fd == pfd || poll_fds[i].fd == admin_pfd) {
					/* Janus/Admin API: accept the new client (SOCK_SEQPACKET) or receive data (SOCK_DGRAM) */
					struct sockaddr_un address;
					socklen_t addrlen = sizeof(address);
					if((poll_fds[i].fd == pfd && !dgram) || (poll_fds[i].fd == admin_pfd && !admin_dgram)) {
						/* SOCK_SEQPACKET */
						int cfd = accept(poll_fds[i].fd, (struct sockaddr *) &address, &addrlen);
						if(cfd > -1) {
							JANUS_LOG(LOG_INFO, "Got new Unix Sockets %s API client: %d\n",
								poll_fds[i].fd == pfd ? "Janus" : "Admin", cfd);
							/* Allocate new client */
							janus_pfunix_client *client = g_malloc(sizeof(janus_pfunix_client));
							client->fd = cfd;
							memset(&client->addr, 0, sizeof(client->addr));
							client->admin = (poll_fds[i].fd == admin_pfd);	/* API client type */
							client->messages = g_async_queue_new();
							client->session_timeout = FALSE;
							/* Create a transport instance as well */
							client->ts = janus_transport_session_create(client, janus_pfunix_client_free);
							/* Take note of this new client */
							janus_mutex_lock(&clients_mutex);
							g_hash_table_insert(clients_by_fd, GINT_TO_POINTER(cfd), client);
							g_hash_table_insert(clients, client, client);
							janus_mutex_unlock(&clients_mutex);
							/* Notify handlers about this new transport */
							if(notify_events && gateway->events_is_enabled()) {
								json_t *info = json_object();
								json_object_set_new(info, "event", json_string("connected"));
								json_object_set_new(info, "admin_api", client->admin ? json_true() : json_false());
								json_object_set_new(info, "fd", json_integer(client->fd));
								gateway->notify_event(&janus_pfunix_transport, client->ts, info);
							}
						}
					} else {
						/* SOCK_DGRAM */
						struct sockaddr_storage address;
						res = recvfrom(poll_fds[i].fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&address, &addrlen);
						if(res < 0) {
							if(errno != EAGAIN && errno != EWOULDBLOCK) {
								JANUS_LOG(LOG_ERR, "Error reading from client (%s API)...\n",
									poll_fds[i].fd == pfd ? "Janus" : "Admin");
							}
							continue;
						}
						buffer[res] = '\0';
						/* Is this a new client, or one we knew about already? */
						struct sockaddr_un *uaddr = (struct sockaddr_un *)&address;
						if(strlen(uaddr->sun_path) == 0) {
							/* No path provided, drop the packet */
							JANUS_LOG(LOG_WARN, "Dropping packet from unknown source (no path provided)\n");
							continue;
						}
						janus_mutex_lock(&clients_mutex);
						janus_pfunix_client *client = g_hash_table_lookup(clients_by_path, uaddr->sun_path);
						if(client == NULL) {
							JANUS_LOG(LOG_INFO, "Got new Unix Sockets %s API client: %s\n",
								poll_fds[i].fd == pfd ? "Janus" : "Admin", uaddr->sun_path);
							/* Allocate new client */
							client = g_malloc(sizeof(janus_pfunix_client));
							client->fd = -1;
							memcpy(&client->addr, uaddr, sizeof(struct sockaddr_un));
							client->admin = (poll_fds[i].fd == admin_pfd);	/* API client type */
							client->messages = g_async_queue_new();
							client->session_timeout = FALSE;
							/* Create a transport instance as well */
							client->ts = janus_transport_session_create(client, janus_pfunix_client_free);
							/* Take note of this new client */
							g_hash_table_insert(clients_by_path, uaddr->sun_path, client);
							g_hash_table_insert(clients, client, client);
							/* Notify handlers about this new transport */
							if(notify_events && gateway->events_is_enabled()) {
								json_t *info = json_object();
								json_object_set_new(info, "event", json_string("connected"));
								json_object_set_new(info, "admin_api", client->admin ? json_true() : json_false());
								json_object_set_new(info, "fd", json_integer(client->fd));
								json_object_set_new(info, "type", json_string("SOCK_DGRAM"));
								gateway->notify_event(&janus_pfunix_transport, client->ts, info);
							}
						}
						janus_mutex_unlock(&clients_mutex);
						JANUS_LOG(LOG_VERB, "Message from client %s (%d bytes)\n", uaddr->sun_path, res);
						JANUS_LOG(LOG_HUGE, "%s\n", buffer);
						/* Parse the JSON payload */
						json_error_t error;
						json_t *root = json_loads(buffer, 0, &error);
						/* Notify the core, passing both the object and, since it may be needed, the error */
						gateway->incoming_request(&janus_pfunix_transport, client->ts, NULL, client->admin, root, &error);
					}
				} else {
					/* Client data: receive message */
					iov[0].iov_len = sizeof(buffer);
					res = recvmsg(poll_fds[i].fd, &msg, MSG_WAITALL);
					if(res < 0) {
						if(errno != EAGAIN && errno != EWOULDBLOCK) {
							JANUS_LOG(LOG_ERR, "Error reading from client %d...\n", poll_fds[i].fd);
						}
						continue;
					}
					if(msg.msg_flags & MSG_TRUNC) {
						/* Apparently our buffer is not large enough? */
						JANUS_LOG(LOG_WARN, "Incoming message from client %d truncated (%d bytes), dropping it...\n", poll_fds[i].fd, res);
						continue;
					}
					/* Find the client from its file descriptor */
					janus_mutex_lock(&clients_mutex);
					janus_pfunix_client *client = g_hash_table_lookup(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
					if(client == NULL) {
						janus_mutex_unlock(&clients_mutex);
						JANUS_LOG(LOG_WARN, "Got data from unknown Unix Sockets client %d, closing connection...\n", poll_fds[i].fd);
						/* Close socket */
						shutdown(SHUT_RDWR, poll_fds[i].fd);
						close(poll_fds[i].fd);
						continue;
					}
					if(res == 0) {
						JANUS_LOG(LOG_INFO, "Unix Sockets client disconnected (%d)\n", poll_fds[i].fd);
						/* Notify core */
						gateway->transport_gone(&janus_pfunix_transport, client->ts);
						/* Notify handlers about this transport being gone */
						if(notify_events && gateway->events_is_enabled()) {
							json_t *info = json_object();
							json_object_set_new(info, "event", json_string("disconnected"));
							gateway->notify_event(&janus_pfunix_transport, client->ts, info);
						}
						/* Close socket */
						shutdown(SHUT_RDWR, poll_fds[i].fd);
						close(poll_fds[i].fd);
						client->fd = -1;
						/* Destroy the client */
						g_hash_table_remove(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
						g_hash_table_remove(clients, client);
						/* Unref the transport instance */
						janus_transport_session_destroy(client->ts);
						janus_mutex_unlock(&clients_mutex);
						continue;
					}
					janus_mutex_unlock(&clients_mutex);
					/* If we got here, there's data to handle */
					buffer[res] = '\0';
					JANUS_LOG(LOG_VERB, "Message from client %d (%d bytes)\n", poll_fds[i].fd, res);
					JANUS_LOG(LOG_HUGE, "%s\n", buffer);
					/* Parse the JSON payload */
					json_error_t error;
					json_t *root = json_loads(buffer, 0, &error);
					/* Notify the core, passing both the object and, since it may be needed, the error */
					gateway->incoming_request(&janus_pfunix_transport, client->ts, NULL, client->admin, root, &error);
				}
			}
		}
	}

	socklen_t addrlen = sizeof(struct sockaddr_un);
	void *addr = g_malloc(addrlen+1);
	if(pfd > -1) {
		/* Unlink the path name first */
#ifdef HAVE_LIBSYSTEMD
		if((getsockname(pfd, (struct sockaddr *)addr, &addrlen) != -1) && (FALSE == sd_socket)) {
#else
		if(getsockname(pfd, (struct sockaddr *)addr, &addrlen) != -1) {
#endif
			JANUS_LOG(LOG_INFO, "Unlinking %s\n", ((struct sockaddr_un *)addr)->sun_path);
			unlink(((struct sockaddr_un *)addr)->sun_path);
		}
		/* Close the socket */
		close(pfd);
	}
	pfd = -1;
	if(admin_pfd > -1) {
		/* Unlink the path name first */
#ifdef HAVE_LIBSYSTEMD
		if((getsockname(admin_pfd, (struct sockaddr *)addr, &addrlen) != -1) && (FALSE == admin_sd_socket)) {
#else
		if(getsockname(admin_pfd, (struct sockaddr *)addr, &addrlen) != -1) {
#endif
			JANUS_LOG(LOG_INFO, "Unlinking %s\n", ((struct sockaddr_un *)addr)->sun_path);
			unlink(((struct sockaddr_un *)addr)->sun_path);
		}
		/* Close the socket */
		close(admin_pfd);
	}
	admin_pfd = -1;
	g_free(addr);

	g_hash_table_destroy(clients_by_path);
	g_hash_table_destroy(clients_by_fd);
	g_hash_table_destroy(clients);

	/* Done */
	JANUS_LOG(LOG_INFO, "Unix Sockets thread ended\n");
	return NULL;
}
