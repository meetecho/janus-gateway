/*! \file   janus_nanomsg.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Nanomsg transport plugin
 * \details  This is an implementation of a Nanomsg transport for the
 * Janus API. This means that, with the help of this module, local and
 * remote applications can use Nanomsg to make requests to Janus.
 * Note that not all the protocols Nanomsg implements are made available
 * in this plugin: specifically, you'll only be able to use the \c NN_PAIR
 * transport mechanism. Future versions may implement more, but for the
 * time being these should be enough to cover most development requirements.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include <nanomsg/inproc.h>
#include <nanomsg/ipc.h>
#include <nanomsg/pipeline.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_NANOMSG_VERSION			1
#define JANUS_NANOMSG_VERSION_STRING	"0.0.1"
#define JANUS_NANOMSG_DESCRIPTION		"This transport plugin adds Nanomsg support to the Janus API."
#define JANUS_NANOMSG_NAME				"JANUS Nanomsg transport plugin"
#define JANUS_NANOMSG_AUTHOR			"Meetecho s.r.l."
#define JANUS_NANOMSG_PACKAGE			"janus.transport.nanomsg"

/* Transport methods */
janus_transport *create(void);
int janus_nanomsg_init(janus_transport_callbacks *callback, const char *config_path);
void janus_nanomsg_destroy(void);
int janus_nanomsg_get_api_compatibility(void);
int janus_nanomsg_get_version(void);
const char *janus_nanomsg_get_version_string(void);
const char *janus_nanomsg_get_description(void);
const char *janus_nanomsg_get_name(void);
const char *janus_nanomsg_get_author(void);
const char *janus_nanomsg_get_package(void);
gboolean janus_nanomsg_is_janus_api_enabled(void);
gboolean janus_nanomsg_is_admin_api_enabled(void);
int janus_nanomsg_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_nanomsg_session_created(janus_transport_session *transport, guint64 session_id);
void janus_nanomsg_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_nanomsg_session_claimed(janus_transport_session *transport, guint64 session_id);
json_t *janus_nanomsg_query_transport(json_t *request);


/* Transport setup */
static janus_transport janus_nanomsg_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_nanomsg_init,
		.destroy = janus_nanomsg_destroy,

		.get_api_compatibility = janus_nanomsg_get_api_compatibility,
		.get_version = janus_nanomsg_get_version,
		.get_version_string = janus_nanomsg_get_version_string,
		.get_description = janus_nanomsg_get_description,
		.get_name = janus_nanomsg_get_name,
		.get_author = janus_nanomsg_get_author,
		.get_package = janus_nanomsg_get_package,

		.is_janus_api_enabled = janus_nanomsg_is_janus_api_enabled,
		.is_admin_api_enabled = janus_nanomsg_is_admin_api_enabled,

		.send_message = janus_nanomsg_send_message,
		.session_created = janus_nanomsg_session_created,
		.session_over = janus_nanomsg_session_over,
		.session_claimed = janus_nanomsg_session_claimed,

		.query_transport = janus_nanomsg_query_transport,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_NANOMSG_NAME);
	return &janus_nanomsg_transport;
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
#define JANUS_NANOMSG_ERROR_INVALID_REQUEST		411
#define JANUS_NANOMSG_ERROR_MISSING_ELEMENT		412
#define JANUS_NANOMSG_ERROR_INVALID_ELEMENT		413
#define JANUS_NANOMSG_ERROR_UNKNOWN_ERROR		499


/* Nanomsg server thread */
static GThread *nanomsg_thread = NULL;
void *janus_nanomsg_thread(void *data);

/* Nanomsg servers */
static int nfd = -1, nfd_addr = -1, admin_nfd = -1, admin_nfd_addr = -1;
/* Pipeline to notify about the need for outgoing data */
static int write_nfd[2];

/* Nanomsg client session */
typedef struct janus_nanomsg_client {
	gboolean admin;					/* Whether this client is for the Admin or Janus API */
	GAsyncQueue *messages;			/* Queue of outgoing messages to push */
	janus_transport_session *ts;	/* Janus core-transport session */
} janus_nanomsg_client;
/* We only handle a single client per API, since we use NN_PAIR and we bind locally */
static janus_nanomsg_client client, admin_client;


/* Transport implementation */
int janus_nanomsg_init(janus_transport_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_NANOMSG_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_NANOMSG_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_NANOMSG_PACKAGE);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_NANOMSG_NAME);
		}

		/* First of all, initialize the pipeline for writeable notifications */
		write_nfd[0] = nn_socket(AF_SP, NN_PULL);
		write_nfd[1] = nn_socket(AF_SP, NN_PUSH);
		if(nn_bind(write_nfd[0], "inproc://janus") < 0) {
			JANUS_LOG(LOG_WARN, "Error configuring internal Nanomsg pipeline... %d (%s)\n", errno, nn_strerror(errno));
			return -1;	/* No point in keeping the plugin loaded */
		}
		if(nn_connect(write_nfd[1], "inproc://janus") < 0) {
			JANUS_LOG(LOG_WARN, "Error configuring internal Nanomsg pipeline...%d (%s)\n", errno, nn_strerror(errno));
			return -1;	/* No point in keeping the plugin loaded */
		}

		/* Setup the Janus API Nanomsg server(s) */
		item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Nanomsg server disabled (Janus API)\n");
		} else {
			item = janus_config_get(config, config_general, janus_config_type_item, "address");
			const char *address = item && item->value ? item->value : NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "mode");
			const char *mode = item && item->value ? item->value : NULL;
			if(mode == NULL)
				mode = "bind";
			nfd = nn_socket(AF_SP, NN_PAIR);
			if(nfd < 0) {
				JANUS_LOG(LOG_ERR, "Error creating Janus API Nanomsg socket: %d (%s)\n", errno, nn_strerror(errno));
			} else {
				if(!strcasecmp(mode, "bind")) {
					/* Bind to this address */
					nfd_addr = nn_bind(nfd, address);
					if(nfd_addr < 0) {
						JANUS_LOG(LOG_ERR, "Error binding Janus API Nanomsg socket to address '%s': %d (%s)\n",
							address, errno, nn_strerror(errno));
						nn_close(nfd);
						nfd = -1;
					}
				} else if(!strcasecmp(mode, "connect")) {
					/* Connect to this address */
					nfd_addr = nn_connect(nfd, address);
					if(nfd_addr < 0) {
						JANUS_LOG(LOG_ERR, "Error connecting Janus API Nanomsg socket to address '%s': %d (%s)\n",
							address, errno, nn_strerror(errno));
						nn_close(nfd);
						nfd = -1;
					}
				} else {
					/* Unsupported mode */
					JANUS_LOG(LOG_ERR, "Unsupported mode '%s'\n", mode);
					nn_close(nfd);
					nfd = -1;
				}
			}
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get(config, config_admin, janus_config_type_item, "admin_enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Nanomsg server disabled (Admin API)\n");
		} else {
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_address");
			const char *address = item && item->value ? item->value : NULL;
			item = janus_config_get(config, config_admin, janus_config_type_item, "admin_mode");
			const char *mode = item && item->value ? item->value : NULL;
			if(mode == NULL)
				mode = "bind";
			admin_nfd = nn_socket(AF_SP, NN_PAIR);
			if(admin_nfd < 0) {
				JANUS_LOG(LOG_ERR, "Error creating Admin API Nanomsg socket: %d (%s)\n", errno, nn_strerror(errno));
			} else {
				if(!strcasecmp(mode, "bind")) {
					/* Bind to this address */
					admin_nfd_addr = nn_bind(admin_nfd, address);
					if(admin_nfd_addr < 0) {
						JANUS_LOG(LOG_ERR, "Error binding Admin API Nanomsg socket to address '%s': %d (%s)\n",
							address, errno, nn_strerror(errno));
						nn_close(admin_nfd);
						admin_nfd = -1;
					}
				} else if(!strcasecmp(mode, "connect")) {
					/* Connect to this address */
					admin_nfd_addr = nn_connect(admin_nfd, address);
					if(admin_nfd_addr < 0) {
						JANUS_LOG(LOG_ERR, "Error connecting Admin API Nanomsg socket to address '%s': %d (%s)\n",
							address, errno, nn_strerror(errno));
						nn_close(admin_nfd);
						admin_nfd = -1;
					}
				} else {
					/* Unsupported mode */
					JANUS_LOG(LOG_ERR, "Unsupported mode '%s'\n", mode);
					nn_close(admin_nfd);
					admin_nfd = -1;
				}
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(nfd < 0 && admin_nfd < 0) {
		JANUS_LOG(LOG_WARN, "No Nanomsg server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Create the clients */
	memset(&client, 0, sizeof(janus_nanomsg_client));
	if(nfd > -1) {
		client.admin = FALSE;
		client.messages = g_async_queue_new();
		/* Create a transport instance as well */
		client.ts = janus_transport_session_create(&client, NULL);
		/* Notify handlers about this new transport */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "admin_api", json_false());
			json_object_set_new(info, "socket", json_integer(nfd));
			gateway->notify_event(&janus_nanomsg_transport, client.ts, info);
		}
	}
	memset(&admin_client, 0, sizeof(janus_nanomsg_client));
	if(admin_nfd > -1) {
		admin_client.admin = TRUE;
		admin_client.messages = g_async_queue_new();
		/* Create a transport instance as well */
		admin_client.ts = janus_transport_session_create(&admin_client, NULL);
		/* Notify handlers about this new transport */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "admin_api", json_true());
			json_object_set_new(info, "socket", json_integer(admin_nfd));
			gateway->notify_event(&janus_nanomsg_transport, admin_client.ts, info);
		}
	}

	/* Start the Nanomsg service thread */
	GError *error = NULL;
	nanomsg_thread = g_thread_try_new("nanomsg thread", &janus_nanomsg_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Nanomsg thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_NANOMSG_NAME);
	return 0;
}

void janus_nanomsg_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	/* Stop the service thread */
	(void)nn_send(write_nfd[1], "x", 1, 0);

	if(nanomsg_thread != NULL) {
		g_thread_join(nanomsg_thread);
		nanomsg_thread = NULL;
	}

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_NANOMSG_NAME);
}

int janus_nanomsg_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_nanomsg_get_version(void) {
	return JANUS_NANOMSG_VERSION;
}

const char *janus_nanomsg_get_version_string(void) {
	return JANUS_NANOMSG_VERSION_STRING;
}

const char *janus_nanomsg_get_description(void) {
	return JANUS_NANOMSG_DESCRIPTION;
}

const char *janus_nanomsg_get_name(void) {
	return JANUS_NANOMSG_NAME;
}

const char *janus_nanomsg_get_author(void) {
	return JANUS_NANOMSG_AUTHOR;
}

const char *janus_nanomsg_get_package(void) {
	return JANUS_NANOMSG_PACKAGE;
}

gboolean janus_nanomsg_is_janus_api_enabled(void) {
	return nfd > -1;
}

gboolean janus_nanomsg_is_admin_api_enabled(void) {
	return admin_nfd > -1;
}

int janus_nanomsg_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	/* Convert to string */
	char *payload = json_dumps(message, json_format);
	json_decref(message);
	/* Enqueue the packet and have poll tell us when it's time to send it */
	g_async_queue_push(admin ? admin_client.messages : client.messages, payload);
	/* Notify the thread there's data to send */
	(void)nn_send(write_nfd[1], "x", 1, 0);
	return 0;
}

void janus_nanomsg_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_nanomsg_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We don't care */
}

void janus_nanomsg_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}

json_t *janus_nanomsg_query_transport(json_t *request) {
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
		JANUS_NANOMSG_ERROR_MISSING_ELEMENT, JANUS_NANOMSG_ERROR_INVALID_ELEMENT);
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
			JANUS_NANOMSG_ERROR_MISSING_ELEMENT, JANUS_NANOMSG_ERROR_INVALID_ELEMENT);
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
				JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_NANOMSG_NAME);
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
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_NANOMSG_ERROR_INVALID_REQUEST;
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
void *janus_nanomsg_thread(void *data) {
	JANUS_LOG(LOG_INFO, "Nanomsg thread started\n");

	int fds = 0;
	struct nn_pollfd poll_nfds[3];	/* FIXME Should we allow for more clients? */
	char buffer[BUFFER_SIZE];

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Prepare poll list of file descriptors */
		fds = 0;
		/* Writeable monitor */
		poll_nfds[fds].fd = write_nfd[0];
		poll_nfds[fds].events = NN_POLLIN;
		fds++;
		if(nfd > -1) {
			/* Janus API */
			poll_nfds[fds].fd = nfd;
			poll_nfds[fds].events = NN_POLLIN;
			if(client.messages != NULL && g_async_queue_length(client.messages) > 0)
				poll_nfds[fds].events |= NN_POLLOUT;
			fds++;
		}
		if(admin_nfd > -1) {
			/* Admin API */
			poll_nfds[fds].fd = admin_nfd;
			poll_nfds[fds].events = NN_POLLIN;
			if(admin_client.messages != NULL && g_async_queue_length(admin_client.messages) > 0)
				poll_nfds[fds].events |= NN_POLLOUT;
			fds++;
		}
		/* Start polling */
		int res = nn_poll(poll_nfds, fds, -1);
		if(res == 0)
			continue;
		if(res < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "Got an EINTR (%s) polling the Nanomsg descriptors, ignoring...\n", nn_strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "poll() failed: %d (%s)\n", errno, nn_strerror(errno));
			break;
		}
		int i = 0;
		for(i=0; i<fds; i++) {
			/* FIXME Is there a Nanomsg equivalent of POLLERR? */
			if(poll_nfds[i].revents & NN_POLLOUT) {
				/* Find the client from its file descriptor */
				if(poll_nfds[i].fd == nfd || poll_nfds[i].fd == admin_nfd) {
					char *payload = NULL;
					while((payload = g_async_queue_try_pop(poll_nfds[i].fd == nfd ? client.messages : admin_client.messages)) != NULL) {
						int res = nn_send(poll_nfds[i].fd, payload, strlen(payload), 0);
						/* FIXME Should we check if sent everything? */
						JANUS_LOG(LOG_HUGE, "Written %d/%zu bytes on %d\n", res, strlen(payload), poll_nfds[i].fd);
						g_free(payload);
					}
				}
			}
			if(poll_nfds[i].revents & NN_POLLIN) {
				if(poll_nfds[i].fd == write_nfd[0]) {
					/* Read and ignore: we use this to unlock the poll if there's data to write */
					(void)nn_recv(poll_nfds[i].fd, buffer, BUFFER_SIZE, 0);
				} else if(poll_nfds[i].fd == nfd || poll_nfds[i].fd == admin_nfd) {
					/* Janus/Admin API: get the message from the client */
					int res = nn_recv(poll_nfds[i].fd, buffer, BUFFER_SIZE, 0);
					if(res < 0) {
						JANUS_LOG(LOG_WARN, "Error receiving %s API message... %d (%s)\n",
							poll_nfds[i].fd == nfd ? "Janus" : "Admin", errno, nn_strerror(errno));
						continue;
					}
					/* If we got here, there's data to handle */
					buffer[res] = '\0';
					JANUS_LOG(LOG_VERB, "Got %s API message (%d bytes)\n",
						poll_nfds[i].fd == nfd ? "Janus" : "Admin", res);
					JANUS_LOG(LOG_HUGE, "%s\n", buffer);
					/* Parse the JSON payload */
					json_error_t error;
					json_t *root = json_loads(buffer, 0, &error);
					/* Notify the core, passing both the object and, since it may be needed, the error */
					gateway->incoming_request(&janus_nanomsg_transport,
						poll_nfds[i].fd == nfd ? client.ts : admin_client.ts,
						NULL,
						poll_nfds[i].fd == nfd ? FALSE : TRUE,
						root, &error);
				}
			}
		}
	}

	nn_close(write_nfd[0]);
	nn_close(write_nfd[1]);
	if(nfd > -1) {
		nn_shutdown(nfd, nfd_addr);
		nn_close(nfd);
		janus_transport_session_destroy(client.ts);
		client.ts = NULL;
	}
	if(admin_nfd > -1) {
		nn_shutdown(admin_nfd, admin_nfd_addr);
		nn_close(admin_nfd);
		janus_transport_session_destroy(admin_client.ts);
		admin_client.ts = NULL;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Nanomsg thread ended\n");
	return NULL;
}
