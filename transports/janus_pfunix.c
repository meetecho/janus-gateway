/*! \file   janus_pfunix.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Unix Sockets transport plugin
 * \details  This is an implementation of a Unix Sockets transport for the
 * Janus API. This means that, with the help of this module, local
 * applications can use Unix Sockets to make requests to the gateway.
 * This plugin makes use of the \c SOCK_SEQPACKET socket type, so make
 * sure you're using the right one when writing a client application.
 * Pretty much as it happens with WebSockets, the same client socket can
 * be used for both sending requests and receiving notifications, without
 * any need for long polls. At the same time, without the concept of a
 * REST path, requests sent through the Unix Sockets interface will need
 * to include, when needed, additional pieces of information like
 * \c session_id and \c handle_id. That is, where you'd send a Janus
 * request related to a specific session to the \c /janus/<session> path,
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

#include <poll.h>
#include <sys/un.h>

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
int janus_pfunix_send_message(void *transport, void *request_id, gboolean admin, json_t *message);
void janus_pfunix_session_created(void *transport, guint64 session_id);
void janus_pfunix_session_over(void *transport, guint64 session_id, gboolean timeout);


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
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_PFUNIX_NAME);
	return &janus_pfunix_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;

#define BUFFER_SIZE		8192

struct sockaddr_un sizecheck;
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

/* Unix Sockets server thread */
static GThread *pfunix_thread = NULL;
void *janus_pfunix_thread(void *data);

/* Unix Sockets servers */
static int pfd = -1, admin_pfd = -1;
/* Socket pair to notify about the need for outgoing data */
static int write_fd[2];

/* Unix Sockets client session */
typedef struct janus_pfunix_client {
	int fd;						/* Client socket */
	gboolean admin;				/* Whether this client is for the Admin or Janus API */
	GAsyncQueue *messages;		/* Queue of outgoing messages to push */
	gboolean session_timeout;	/* Whether a Janus session timeout occurred in the core */
} janus_pfunix_client;
static GHashTable *clients = NULL, *clients_by_fd = NULL;
static janus_mutex clients_mutex;


/* Helper to create a named Unix Socket out of the path to link to */
static int janus_pfunix_create_socket(char *pfname) {
	if(pfname == NULL)
		return -1;
	int fd = -1;
	if(strlen(pfname) > UNIX_PATH_MAX) {
		JANUS_LOG(LOG_WARN, "The provided path name (%s) is longer than %lu characters, it will be truncated\n", pfname, UNIX_PATH_MAX);
		pfname[UNIX_PATH_MAX] = '\0';
	}
	/* Create socket */
	fd = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
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
		} else {
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

	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_PFUNIX_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);

		/* First of all Initialize the socketpair for writeable notifications */
		if(socketpair(PF_LOCAL, SOCK_STREAM, 0, write_fd) < 0) {
			JANUS_LOG(LOG_FATAL, "Error creating socket pair for writeable events: %d, %s\n", errno, strerror(errno));
			return -1;
		}

		/* Setup the Janus API Unix Sockets server(s) */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Unix Sockets server disabled (Janus API)\n");
		} else {
			item = janus_config_get_item_drilldown(config, "general", "path");
			char *pfname = (char *)(item && item->value ? item->value : "/tmp/ux-janusapi");
			pfd = janus_pfunix_create_socket(pfname);
		}
		/* Do the same for the Admin API, if enabled */
		item = janus_config_get_item_drilldown(config, "admin", "admin_enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Unix Sockets server disabled (Admin API)\n");
		} else {
			item = janus_config_get_item_drilldown(config, "admin", "admin_path");
			char *pfname = (char *)(item && item->value ? item->value : "/tmp/ux-janusadmin");
			admin_pfd = janus_pfunix_create_socket(pfname);
		}
	}
	janus_config_destroy(config);
	config = NULL;
	if(pfd < 0 && admin_pfd < 0) {
		JANUS_LOG(LOG_FATAL, "No Unix Sockets server started, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Create a couple of hashtables for all clients */
	clients = g_hash_table_new(NULL, NULL);
	clients_by_fd = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&clients_mutex);

	/* Start the Unix Sockets service thread */
	GError *error = NULL;
	pfunix_thread = g_thread_try_new("pfunix thread", &janus_pfunix_thread, NULL, &error);
	if(!pfunix_thread) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Unix Sockets thread...\n", error->code, error->message ? error->message : "??");
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

int janus_pfunix_send_message(void *transport, void *request_id, gboolean admin, json_t *message) {
	if(message == NULL)
		return -1;
	if(transport == NULL) {
		g_free(message);
		return -1;
	}
	/* Make sure this is related to a still valid Unix Sockets session */
	janus_pfunix_client *client = (janus_pfunix_client *)transport;
	janus_mutex_lock(&clients_mutex);
	if(g_hash_table_lookup(clients, client) == NULL || client->fd < 0) {
		janus_mutex_unlock(&clients_mutex);
		JANUS_LOG(LOG_WARN, "Outgoing message for invalid client %p\n", client);
		g_free(message);
		message = NULL;
		return -1;
	}
	janus_mutex_unlock(&clients_mutex);
	/* Convert to string and enqueue */
	char *payload = json_dumps(message, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(message);
	g_async_queue_push(client->messages, payload);
	/* Notify the thread there's data to send */
	int res = 0;
	do {
		res = write(write_fd[1], "x", 1);
	} while(res == -1 && errno == EINTR);
	return 0;
}

void janus_pfunix_session_created(void *transport, guint64 session_id) {
	/* We don't care */
}

void janus_pfunix_session_over(void *transport, guint64 session_id, gboolean timeout) {
	/* We only care if it's a timeout: if so, close the connection */
	if(transport == NULL || !timeout)
		return;
	/* FIXME Should we really close the connection in case of a timeout? */
	janus_pfunix_client *client = (janus_pfunix_client *)transport;
	janus_mutex_lock(&clients_mutex);
	if(g_hash_table_lookup(clients, client) != NULL && client->fd > -1) {
		/* Shutdown the client socket */
		client->session_timeout = TRUE;
		shutdown(client->fd, SHUT_WR);
	}
	janus_mutex_unlock(&clients_mutex);
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
			JANUS_LOG(LOG_ERR, "poll() failed\n");
			break;
		}
		for(int i=0; i<fds; i++) {
			if((poll_fds[i].revents & POLLOUT) == POLLOUT) {
				/* Find the client from its file descriptor */
				janus_mutex_lock(&clients_mutex);
				janus_pfunix_client *client = g_hash_table_lookup(clients_by_fd, GINT_TO_POINTER(poll_fds[i].fd));
				if(client != NULL) {
					char *payload = NULL;
					while((payload = g_async_queue_try_pop(client->messages)) != NULL) {
						int res = 0;
						do {
							res = write(client->fd, payload, strlen(payload));
						} while(res == -1 && errno == EINTR);
						/* FIXME Should we check if sent everything? */
						JANUS_LOG(LOG_HUGE, "Written %d/%zu bytes on %d\n", res, strlen(payload), client->fd);
						g_free(payload);
					}
				}
				janus_mutex_unlock(&clients_mutex);
			}
			if((poll_fds[i].revents & POLLIN) == POLLIN) {
				if(poll_fds[i].fd == write_fd[0]) {
					/* Read and ignore: we use this to unlock the poll if there's data to write */
					res = read(poll_fds[i].fd, buffer, BUFFER_SIZE);
				} else if(poll_fds[i].fd == pfd || poll_fds[i].fd == admin_pfd) {
					/* Janus/Admin API: accept the new client */
					struct sockaddr_un address;
					socklen_t address_length = sizeof(address);
					int cfd = accept(pfd, (struct sockaddr *) &address, &address_length);
					if(cfd > -1) {
						JANUS_LOG(LOG_INFO, "Got new Unix Sockets %s API client: %d\n",
							poll_fds[i].fd == pfd ? "Janus" : "Admin", cfd);
						/* Allocate new client */
						janus_pfunix_client *client = g_malloc0(sizeof(janus_pfunix_client));
						client->fd = cfd;
						client->admin = (poll_fds[i].fd == admin_pfd);	/* API client type */
						client->messages = g_async_queue_new();
						client->session_timeout = FALSE;
						/* Take note of this new client */
						janus_mutex_lock(&clients_mutex);
						g_hash_table_insert(clients_by_fd, GINT_TO_POINTER(cfd), client);
						g_hash_table_insert(clients, client, client);
						janus_mutex_unlock(&clients_mutex);
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
						gateway->transport_gone(&janus_pfunix_transport, client);
						/* Close socket */
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
					gateway->incoming_request(&janus_pfunix_transport, client, NULL, client->admin, root, &error);
				}
			}
		}
	}

	if(pfd > -1)
		close(pfd);
	pfd = -1;
	if(admin_pfd > -1)
		close(admin_pfd);
	admin_pfd = -1;

	/* Done */
	JANUS_LOG(LOG_INFO, "Unix Sockets thread ended\n");
	return NULL;
}
