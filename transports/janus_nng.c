/*! \file   janus_nng.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus NNG transport plugin
 * \details  This is an implementation of a NNG (Nanomsg Next-Generation)
 * transport for the Janus API. This means that, with the help of this
 * module, local and remote applications can use NNG to make requests to Janus.
 * Note that not all the protocols NNG implements are made available
 * in this plugin: specifically, you'll only be able to use the \c NN_PAIR
 * transport mechanism. Future versions may implement more, but for the
 * time being these should be enough to cover most development requirements.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <sys/poll.h>

#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/transport/inproc/inproc.h>
#include <nng/transport/ipc/ipc.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/pipeline0/pull.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_NNG_VERSION			1
#define JANUS_NNG_VERSION_STRING	"0.0.1"
#define JANUS_NNG_DESCRIPTION		"This transport plugin adds NNG support to the Janus API."
#define JANUS_NNG_NAME				"JANUS NNG transport plugin"
#define JANUS_NNG_AUTHOR			"Meetecho s.r.l."
#define JANUS_NNG_PACKAGE			"janus.transport.nng"

/* Transport methods */
janus_transport *create(void);
int janus_nng_init(janus_transport_callbacks *callback, const char *config_path);
void janus_nng_destroy(void);
int janus_nng_get_api_compatibility(void);
int janus_nng_get_version(void);
const char *janus_nng_get_version_string(void);
const char *janus_nng_get_description(void);
const char *janus_nng_get_name(void);
const char *janus_nng_get_author(void);
const char *janus_nng_get_package(void);
gboolean janus_nng_is_janus_api_enabled(void);
gboolean janus_nng_is_admin_api_enabled(void);
int janus_nng_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
void janus_nng_session_created(janus_transport_session *transport, guint64 session_id);
void janus_nng_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
void janus_nng_session_claimed(janus_transport_session *transport, guint64 session_id);


/* Transport setup */
static janus_transport janus_nng_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_nng_init,
		.destroy = janus_nng_destroy,

		.get_api_compatibility = janus_nng_get_api_compatibility,
		.get_version = janus_nng_get_version,
		.get_version_string = janus_nng_get_version_string,
		.get_description = janus_nng_get_description,
		.get_name = janus_nng_get_name,
		.get_author = janus_nng_get_author,
		.get_package = janus_nng_get_package,

		.is_janus_api_enabled = janus_nng_is_janus_api_enabled,
		.is_admin_api_enabled = janus_nng_is_admin_api_enabled,

		.send_message = janus_nng_send_message,
		.session_created = janus_nng_session_created,
		.session_over = janus_nng_session_over,
		.session_claimed = janus_nng_session_claimed,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_NNG_NAME);
	return &janus_nng_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean notify_events = TRUE;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

#define BUFFER_SIZE		8192

/* NNG server thread */
static GThread *nng_thread = NULL;
void *janus_nng_thread(void *data);

/* NNG servers */
static nng_socket nfd = NNG_SOCKET_INITIALIZER,
	admin_nfd = NNG_SOCKET_INITIALIZER;
/* Pipeline to notify about the need for outgoing data */
static nng_socket write_nfd[2];

/* NNG client session */
typedef struct janus_nng_client {
	gboolean admin;					/* Whether this client is for the Admin or Janus API */
	GAsyncQueue *messages;			/* Queue of outgoing messages to push */
	janus_transport_session *ts;	/* Janus core-transport session */
} janus_nng_client;
/* We only handle a single client per API, since we use pairs and we bind locally */
static janus_nng_client client, admin_client;


/* Transport implementation */
int janus_nng_init(janus_transport_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_NNG_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_NNG_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_NNG_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_NNG_NAME);
		}

		/* First of all, initialize the pipeline for writeable notifications */
		int res = 0;
		if((res = nng_pull0_open(&write_nfd[0])) != 0 || (res = nng_push0_open(&write_nfd[1])) != 0) {
			JANUS_LOG(LOG_WARN, "Error creating internal NNG pipeline... %d (%s)\n", res, nng_strerror(res));
			return -1;	/* No point in keeping the plugin loaded */
		}
		if((res = nng_listen(write_nfd[0], "inproc://janus", NULL, 0)) != 0) {
			JANUS_LOG(LOG_WARN, "Error configuring internal NNG pipeline... %d (%s)\n", res, nng_strerror(res));
			return -1;	/* No point in keeping the plugin loaded */
		}
		if((res = nng_dial(write_nfd[1], "inproc://janus", NULL, 0)) != 0) {
			JANUS_LOG(LOG_WARN, "Error configuring internal NNG pipeline...%d (%s)\n", res, nng_strerror(res));
			return -1;	/* No point in keeping the plugin loaded */
		}

		/* Setup the Janus API NNG server(s) */
		item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "NNG server disabled (Janus API)\n");
		} else {
			item = janus_config_get(config, config_general, janus_config_type_item, "address");
			const char *address = item && item->value ? item->value : NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "mode");
			const char *mode = item && item->value ? item->value : NULL;
			if(mode == NULL)
				mode = "listen";
			if((res = nng_pair0_open(&nfd)) != 0) {
				JANUS_LOG(LOG_ERR, "Error creating Janus API NNG socket: %d (%s)\n", res, nng_strerror(res));
			} else {
				if(!strcasecmp(mode, "listen")) {
					/* Listen to this address */
					if((res = nng_listen(nfd, address, NULL, 0)) != 0) {
						JANUS_LOG(LOG_ERR, "Error listening Janus API NNG socket to address '%s': %d (%s)\n",
							address, res, nng_strerror(res));
						nng_close(nfd);
					}
				} else if(!strcasecmp(mode, "dial")) {
					/* Dial this address */
					if((res = nng_dial(nfd, address, NULL, 0)) != 0) {
						JANUS_LOG(LOG_ERR, "Error dialing Janus API NNG socket to address '%s': %d (%s)\n",
							address, res, nng_strerror(res));
						nng_close(nfd);
					}
				} else {
					/* Unsupported mode */
					JANUS_LOG(LOG_ERR, "Unsupported mode '%s'\n", mode);
					nng_close(nfd);
				}
			}
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get(config, config_general, janus_config_type_item, "admin_enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "NNG server disabled (Admin API)\n");
		} else {
			item = janus_config_get(config, config_general, janus_config_type_item, "admin_address");
			const char *address = item && item->value ? item->value : NULL;
			item = janus_config_get(config, config_general, janus_config_type_item, "admin_mode");
			const char *mode = item && item->value ? item->value : NULL;
			if(mode == NULL)
				mode = "listen";
			if((res = nng_pair0_open(&admin_nfd)) != 0) {
				JANUS_LOG(LOG_ERR, "Error creating Admin API NNG socket: %d (%s)\n", res, nng_strerror(res));
			} else {
				if(!strcasecmp(mode, "listen")) {
					/* Listen to this address */
					if((res = nng_listen(admin_nfd, address, NULL, 0)) != 0) {
						JANUS_LOG(LOG_ERR, "Error listening Admin API NNG socket to address '%s': %d (%s)\n",
							address, res, nng_strerror(res));
						nng_close(admin_nfd);
					}
				} else if(!strcasecmp(mode, "dial")) {
					/* Dial this address */
					if((res = nng_dial(admin_nfd, address, NULL, 0)) != 0) {
						JANUS_LOG(LOG_ERR, "Error dialing Admin API NNG socket to address '%s': %d (%s)\n",
							address, res, nng_strerror(res));
						nng_close(admin_nfd);
					}
				} else {
					/* Unsupported mode */
					JANUS_LOG(LOG_ERR, "Unsupported mode '%s'\n", mode);
					nng_close(admin_nfd);
				}
			}
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(nng_socket_id(nfd) < 0 && nng_socket_id(admin_nfd) < 0) {
		JANUS_LOG(LOG_WARN, "No NNG server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Create the clients */
	memset(&client, 0, sizeof(janus_nng_client));
	if(nng_socket_id(nfd) > -1) {
		client.admin = FALSE;
		client.messages = g_async_queue_new();
		/* Create a transport instance as well */
		client.ts = janus_transport_session_create(&client, NULL);
		/* Notify handlers about this new transport */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "admin_api", json_false());
			json_object_set_new(info, "socket", json_integer(nng_socket_id(nfd)));
			gateway->notify_event(&janus_nng_transport, client.ts, info);
		}
	}
	memset(&admin_client, 0, sizeof(janus_nng_client));
	if(nng_socket_id(admin_nfd) > -1) {
		admin_client.admin = TRUE;
		admin_client.messages = g_async_queue_new();
		/* Create a transport instance as well */
		admin_client.ts = janus_transport_session_create(&admin_client, NULL);
		/* Notify handlers about this new transport */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "admin_api", json_true());
			json_object_set_new(info, "socket", json_integer(nng_socket_id(admin_nfd)));
			gateway->notify_event(&janus_nng_transport, admin_client.ts, info);
		}
	}

	/* Start the NNG service thread */
	GError *error = NULL;
	nng_thread = g_thread_try_new("nng thread", &janus_nng_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the NNG thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_NNG_NAME);
	return 0;
}

void janus_nng_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	/* Stop the service thread */
	(void)nng_send(write_nfd[1], (void *)"x", 1, 0);

	if(nng_thread != NULL) {
		g_thread_join(nng_thread);
		nng_thread = NULL;
	}

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_NNG_NAME);
}

int janus_nng_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_nng_get_version(void) {
	return JANUS_NNG_VERSION;
}

const char *janus_nng_get_version_string(void) {
	return JANUS_NNG_VERSION_STRING;
}

const char *janus_nng_get_description(void) {
	return JANUS_NNG_DESCRIPTION;
}

const char *janus_nng_get_name(void) {
	return JANUS_NNG_NAME;
}

const char *janus_nng_get_author(void) {
	return JANUS_NNG_AUTHOR;
}

const char *janus_nng_get_package(void) {
	return JANUS_NNG_PACKAGE;
}

gboolean janus_nng_is_janus_api_enabled(void) {
	return nng_socket_id(nfd) > -1;
}

gboolean janus_nng_is_admin_api_enabled(void) {
	return nng_socket_id(admin_nfd) > -1;
}

int janus_nng_send_message(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	/* Convert to string */
	char *payload = json_dumps(message, json_format);
	json_decref(message);
	/* Enqueue the packet and have poll tell us when it's time to send it */
	g_async_queue_push(admin ? admin_client.messages : client.messages, payload);
	/* Notify the thread there's data to send */
	(void)nng_send(write_nfd[1], (void *)"x", 1, 0);
	return 0;
}

void janus_nng_session_created(janus_transport_session *transport, guint64 session_id) {
	/* We don't care */
}

void janus_nng_session_over(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed) {
	/* We don't care */
}

void janus_nng_session_claimed(janus_transport_session *transport, guint64 session_id) {
	/* We don't care about this. We should start receiving messages from the core about this session: no action necessary */
	/* FIXME Is the above statement accurate? Should we care? Unlike the HTTP transport, there is no hashtable to update */
}


/* Thread */
void *janus_nng_thread(void *data) {
	JANUS_LOG(LOG_INFO, "NNG thread started\n");

	int fds = 0;
	struct pollfd poll_nfds[3];	/* FIXME Should we allow for more clients? */
	char buffer[BUFFER_SIZE];

	int pwnfd = -1, w_pnfd = -1, r_pnfd = -1, w_panfd = -1, r_panfd = -1, res = 0;
	if((res = nng_getopt_int(write_nfd[0], NNG_OPT_RECVFD, &pwnfd)) != 0) {
		JANUS_LOG(LOG_WARN, "Error getting NNG pipeline descriptor... %d (%s)\n", res, nng_strerror(res));
	}
	if(nng_socket_id(nfd) != -1 && (res = nng_getopt_int(nfd, NNG_OPT_RECVFD, &r_pnfd)) != 0) {
		JANUS_LOG(LOG_WARN, "Error getting Janus API NNG descriptor... %d (%s)\n", res, nng_strerror(res));
	}
	if(nng_socket_id(nfd) != -1 && (res = nng_getopt_int(nfd, NNG_OPT_SENDFD, &w_pnfd)) != 0) {
		JANUS_LOG(LOG_WARN, "Error getting Janus API NNG descriptor... %d (%s)\n", res, nng_strerror(res));
	}
	if(nng_socket_id(admin_nfd) != -1 && (res = nng_getopt_int(admin_nfd, NNG_OPT_RECVFD, &r_panfd)) != 0) {
		JANUS_LOG(LOG_WARN, "Error getting Janus API NNG descriptor... %d (%s)\n", res, nng_strerror(res));
	}
	if(nng_socket_id(admin_nfd) != -1 && (res = nng_getopt_int(admin_nfd, NNG_OPT_SENDFD, &w_panfd)) != 0) {
		JANUS_LOG(LOG_WARN, "Error getting Janus API NNG descriptor... %d (%s)\n", res, nng_strerror(res));
	}

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Prepare poll list of file descriptors */
		fds = 0;
		/* Writeable monitor */
		poll_nfds[fds].fd = pwnfd;
		poll_nfds[fds].events = POLLIN;
		fds++;
		if(nng_socket_id(nfd) != -1) {
			/* Janus API */
			poll_nfds[fds].fd = r_pnfd;
			poll_nfds[fds].events = POLLIN;
			fds++;
			if(client.messages != NULL && g_async_queue_length(client.messages) > 0) {
				poll_nfds[fds].fd = w_pnfd;
				poll_nfds[fds].events = POLLOUT;
				fds++;
			}
		}
		if(nng_socket_id(admin_nfd) != -1) {
			/* Admin API */
			poll_nfds[fds].fd = r_panfd;
			poll_nfds[fds].events = POLLIN;
			fds++;
			if(admin_client.messages != NULL && g_async_queue_length(admin_client.messages) > 0) {
				poll_nfds[fds].events |= POLLOUT;
				poll_nfds[fds].fd = w_panfd;
				fds++;
			}
		}
		/* Start polling */
		int res = poll(poll_nfds, fds, -1);
		if(res == 0)
			continue;
		if(res < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "Got an EINTR (%s) polling the NNG descriptors, ignoring...\n", strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "poll() failed: %d (%s)\n", errno, strerror(errno));
			break;
		}
		int i = 0;
		for(i=0; i<fds; i++) {
			if(poll_nfds[i].revents & (POLLERR | POLLHUP)) {
				JANUS_LOG(LOG_ERR, "Error polling: %s... %d (%s)\n",
					poll_nfds[i].revents & POLLERR ? "POLLERR" : "POLLHUP", errno, strerror(errno));
			}
			if(poll_nfds[i].revents & POLLOUT) {
				/* Find the client from its file descriptor */
				if(poll_nfds[i].fd == w_pnfd || poll_nfds[i].fd == w_panfd) {
					char *payload = NULL;
					while((payload = g_async_queue_try_pop(poll_nfds[i].fd == w_pnfd ? client.messages : admin_client.messages)) != NULL) {
						int res = nng_send(poll_nfds[i].fd == w_pnfd ? nfd : admin_nfd, payload, strlen(payload), 0);
						/* FIXME Should we check if sent everything? */
						JANUS_LOG(LOG_HUGE, "Written %d/%zu bytes on %d\n", res, strlen(payload), poll_nfds[i].fd);
						g_free(payload);
					}
				}
			}
			if(poll_nfds[i].revents & POLLIN) {
				if(poll_nfds[i].fd == pwnfd) {
					/* Read and ignore: we use this to unlock the poll if there's data to write */
					size_t buflen = sizeof(buffer);
					(void)nng_recv(write_nfd[0], buffer, &buflen, 0);
				} else if(poll_nfds[i].fd == r_pnfd || poll_nfds[i].fd == r_panfd) {
					/* Janus/Admin API: get the message from the client */
					size_t buflen = sizeof(buffer);
					int res = nng_recv(poll_nfds[i].fd == r_pnfd ? nfd : admin_nfd, buffer, &buflen, 0);
					if(res < 0) {
						JANUS_LOG(LOG_WARN, "Error receiving %s API message... %d (%s)\n",
							poll_nfds[i].fd == r_pnfd ? "Janus" : "Admin", res, nng_strerror(res));
						continue;
					}
					/* If we got here, there's data to handle */
					buffer[res] = '\0';
					JANUS_LOG(LOG_VERB, "Got %s API message (%d bytes)\n",
						poll_nfds[i].fd == r_pnfd ? "Janus" : "Admin", res);
					JANUS_LOG(LOG_HUGE, "%s\n", buffer);
					/* Parse the JSON payload */
					json_error_t error;
					json_t *root = json_loads(buffer, 0, &error);
					/* Notify the core, passing both the object and, since it may be needed, the error */
					gateway->incoming_request(&janus_nng_transport,
						poll_nfds[i].fd == r_pnfd ? client.ts : admin_client.ts,
						NULL,
						poll_nfds[i].fd == r_pnfd ? FALSE : TRUE,
						root, &error);
				}
			}
		}
	}

	nng_close(write_nfd[0]);
	nng_close(write_nfd[1]);
	nng_close(nfd);
	if(client.ts != NULL) {
		janus_transport_session_destroy(client.ts);
		client.ts = NULL;
	}
	nng_close(admin_nfd);
	if(admin_client.ts != NULL) {
		janus_transport_session_destroy(admin_client.ts);
		admin_client.ts = NULL;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "NNG thread ended\n");
	return NULL;
}
