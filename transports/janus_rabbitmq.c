/*! \file   janus_rabbitmq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus RabbitMQ transport plugin
 * \details  This is an implementation of a RabbitMQ transport for the
 * Janus API, using the rabbitmq-c library (https://github.com/alanxz/rabbitmq-c).
 * This means that this module adds support for RabbitMQ based messaging as
 * an alternative "transport" for API requests, responses and notifications.
 * This is only useful when you're wrapping Janus requests in your server
 * application, and handling the communication with clients your own way.
 * At the moment, only a single "application" can be handled at the same
 * time, meaning that Janus won't implement multiple queues to handle
 * multiple concurrent "application servers" taking advantage of its
 * features. Support for this is planned, though (e.g., through some kind
 * of negotiation to create queues on the fly). Right now, you can only
 * configure the address of the RabbitMQ server to use, and the queues to
 * make use of to receive (to-janus) and send (from-janus) messages
 * from/to an external application. As with WebSockets, considering that
 * requests wouldn't include a path to address some mandatory information,
 * these requests addressed to Janus should include as part of their payload,
 * when needed, additional pieces of information like \c session_id and
 * \c handle_id. That is, where you'd send a Janus request related to a
 * specific session to the \c /janus/<session> path, with RabbitMQ
 * you'd have to send the same request with an additional \c session_id
 * field in the JSON payload.
 * \note When you create a session using RabbitMQ, a subscription to the
 * events related to it is done automatically through the outgoing queue,
 * so no need for an explicit request as the GET in the plain HTTP API.
 *
 * \ingroup transports
 * \ref transports
 */

#include "transport.h"

#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Transport plugin information */
#define JANUS_RABBITMQ_VERSION			1
#define JANUS_RABBITMQ_VERSION_STRING	"0.0.1"
#define JANUS_RABBITMQ_DESCRIPTION		"This transport plugin adds RabbitMQ support to the Janus API via rabbitmq-c."
#define JANUS_RABBITMQ_NAME				"JANUS RabbitMQ transport plugin"
#define JANUS_RABBITMQ_AUTHOR			"Meetecho s.r.l."
#define JANUS_RABBITMQ_PACKAGE			"janus.transport.rabbitmq"

/* Transport methods */
janus_transport *create(void);
int janus_rabbitmq_init(janus_transport_callbacks *callback, const char *config_path);
void janus_rabbitmq_destroy(void);
int janus_rabbitmq_get_api_compatibility(void);
int janus_rabbitmq_get_version(void);
const char *janus_rabbitmq_get_version_string(void);
const char *janus_rabbitmq_get_description(void);
const char *janus_rabbitmq_get_name(void);
const char *janus_rabbitmq_get_author(void);
const char *janus_rabbitmq_get_package(void);
gboolean janus_rabbitmq_is_janus_api_enabled(void);
gboolean janus_rabbitmq_is_admin_api_enabled(void);
int janus_rabbitmq_send_message(void *transport, void *request_id, gboolean admin, json_t *message);
void janus_rabbitmq_session_created(void *transport, guint64 session_id);
void janus_rabbitmq_session_over(void *transport, guint64 session_id, gboolean timeout);


/* Transport setup */
static janus_transport janus_rabbitmq_transport =
	JANUS_TRANSPORT_INIT (
		.init = janus_rabbitmq_init,
		.destroy = janus_rabbitmq_destroy,

		.get_api_compatibility = janus_rabbitmq_get_api_compatibility,
		.get_version = janus_rabbitmq_get_version,
		.get_version_string = janus_rabbitmq_get_version_string,
		.get_description = janus_rabbitmq_get_description,
		.get_name = janus_rabbitmq_get_name,
		.get_author = janus_rabbitmq_get_author,
		.get_package = janus_rabbitmq_get_package,

		.is_janus_api_enabled = janus_rabbitmq_is_janus_api_enabled,
		.is_admin_api_enabled = janus_rabbitmq_is_admin_api_enabled,

		.send_message = janus_rabbitmq_send_message,
		.session_created = janus_rabbitmq_session_created,
		.session_over = janus_rabbitmq_session_over,
	);

/* Transport creator */
janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_RABBITMQ_NAME);
	return &janus_rabbitmq_transport;
}


/* Useful stuff */
static gint initialized = 0, stopping = 0;
static janus_transport_callbacks *gateway = NULL;
static gboolean rmq_janus_api_enabled = FALSE;
static gboolean rmq_admin_api_enabled = FALSE;


/* RabbitMQ client session: we only create a single one as of now */
typedef struct janus_rabbitmq_client {
	amqp_connection_state_t rmq_conn;		/* AMQP connection state */
	amqp_channel_t rmq_channel;				/* AMQP channel */
	gboolean janus_api_enabled;				/* Whether the Janus API via RabbitMQ is enabled */
	amqp_bytes_t to_janus_queue;			/* AMQP outgoing messages queue (Janus API) */
	amqp_bytes_t from_janus_queue;			/* AMQP incoming messages queue (Janus API) */
	gboolean admin_api_enabled;				/* Whether the Janus API via RabbitMQ is enabled */
	amqp_bytes_t to_janus_admin_queue;		/* AMQP outgoing messages queue (Admin API) */
	amqp_bytes_t from_janus_admin_queue;	/* AMQP incoming messages queue (Admin API) */
	GThread *in_thread, *out_thread;		/* Threads to handle incoming and outgoing queues */
	GAsyncQueue *messages;					/* Queue of outgoing messages to push */
	janus_mutex mutex;						/* Mutex to lock/unlock this session */
	gint session_timeout:1;					/* Whether a Janus session timeout occurred in the core */
	gint destroy:1;							/* Flag to trigger a lazy session destruction */
} janus_rabbitmq_client;

/* RabbitMQ response */
typedef struct janus_rabbitmq_response {
	gboolean admin;			/* Whether this is a Janus or Admin API response */
	gchar *correlation_id;	/* Correlation ID, if any */
	json_t *payload;		/* Payload to send to the client */
} janus_rabbitmq_response;
static janus_rabbitmq_response exit_message;

/* Threads */
void *janus_rmq_in_thread(void *data);
void *janus_rmq_out_thread(void *data);


/* We only handle a single client per time, as the queues are fixed */
static janus_rabbitmq_client *rmq_client = NULL;


/* Transport implementation */
int janus_rabbitmq_init(janus_transport_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_RABBITMQ_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	/* Handle configuration, starting from the server details */
	char *rmqhost = NULL;
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "host");
	if(item && item->value)
		rmqhost = g_strdup(item->value);
	else
		rmqhost = g_strdup("localhost");
	int rmqport = AMQP_PROTOCOL_PORT;
	item = janus_config_get_item_drilldown(config, "general", "port");
	if(item && item->value)
		rmqport = atoi(item->value);
	/* Now check if the Janus API must be supported */
	const char *to_janus = NULL, *from_janus = NULL;
	const char *to_janus_admin = NULL, *from_janus_admin = NULL;
	item = janus_config_get_item_drilldown(config, "general", "enable");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "RabbitMQ support disabled (Janus API)\n");
	} else {
		/* Parse configuration */
		item = janus_config_get_item_drilldown(config, "general", "to_janus");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of incoming queue for RabbitMQ integration...\n");
			goto error;
		}
		to_janus = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "general", "from_janus");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of outgoing queue for RabbitMQ integration...\n");
			goto error;
		}
		from_janus = g_strdup(item->value);
		JANUS_LOG(LOG_INFO, "RabbitMQ support for Janus API enabled, %s:%d (%s/%s)\n", rmqhost, rmqport, to_janus, from_janus);
		rmq_janus_api_enabled = TRUE;
	}
	/* Do the same for the admin API */
	item = janus_config_get_item_drilldown(config, "admin", "admin_enable");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "RabbitMQ support disabled (Admin API)\n");
	} else {
		/* Parse configuration */
		item = janus_config_get_item_drilldown(config, "admin", "to_janus_admin");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of incoming queue for RabbitMQ integration...\n");
			goto error;
		}
		to_janus_admin = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "admin", "from_janus_admin");
		if(!item || !item->value) {
			JANUS_LOG(LOG_FATAL, "Missing name of outgoing queue for RabbitMQ integration...\n");
			goto error;
		}
		from_janus_admin = g_strdup(item->value);
		JANUS_LOG(LOG_INFO, "RabbitMQ support for Admin API enabled, %s:%d (%s/%s)\n", rmqhost, rmqport, to_janus_admin, from_janus_admin);
		rmq_admin_api_enabled = TRUE;
	}
	if(!rmq_janus_api_enabled && !rmq_admin_api_enabled) {
		JANUS_LOG(LOG_WARN, "RabbitMQ support disabled for both Janus and Admin API, giving up\n");
		goto error;
	} else {
		/* FIXME We currently support a single application, create a new janus_rabbitmq_client instance */
		rmq_client = g_malloc0(sizeof(janus_rabbitmq_client));
		if(rmq_client == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			goto error;
		}
		/* Connect */
		rmq_client->rmq_conn = amqp_new_connection();
		JANUS_LOG(LOG_VERB, "Creating RabbitMQ socket...\n");
		amqp_socket_t *socket = amqp_tcp_socket_new(rmq_client->rmq_conn);
		if(socket == NULL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error creating socket...\n");
			goto error;
		}
		JANUS_LOG(LOG_VERB, "Connecting to RabbitMQ server...\n");
		int status = amqp_socket_open(socket, rmqhost, rmqport);
		if(status != AMQP_STATUS_OK) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error opening socket... (%s)\n", amqp_error_string2(status));
			goto error;
		}
		JANUS_LOG(LOG_VERB, "Logging in...\n");
		amqp_rpc_reply_t result = amqp_login(rmq_client->rmq_conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error logging in... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			goto error;
		}
		rmq_client->rmq_channel = 1;
		JANUS_LOG(LOG_VERB, "Opening channel...\n");
		amqp_channel_open(rmq_client->rmq_conn, rmq_client->rmq_channel);
		result = amqp_get_rpc_reply(rmq_client->rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error opening channel... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			goto error;
		}
		rmq_client->janus_api_enabled = FALSE;
		if(rmq_janus_api_enabled) {
			rmq_client->janus_api_enabled = TRUE;
			JANUS_LOG(LOG_VERB, "Declaring incoming queue... (%s)\n", to_janus);
			rmq_client->to_janus_queue = amqp_cstring_bytes(to_janus);
			amqp_queue_declare(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->to_janus_queue, 0, 0, 0, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
			JANUS_LOG(LOG_VERB, "Declaring outgoing queue... (%s)\n", from_janus);
			rmq_client->from_janus_queue = amqp_cstring_bytes(from_janus);
			amqp_queue_declare(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->from_janus_queue, 0, 0, 0, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
			amqp_basic_consume(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->to_janus_queue, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error consuming... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
		}
		rmq_client->admin_api_enabled = FALSE;
		if(rmq_admin_api_enabled) {
			rmq_client->admin_api_enabled = TRUE;
			JANUS_LOG(LOG_VERB, "Declaring incoming queue... (%s)\n", to_janus_admin);
			rmq_client->to_janus_admin_queue = amqp_cstring_bytes(to_janus_admin);
			amqp_queue_declare(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->to_janus_admin_queue, 0, 0, 0, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
			JANUS_LOG(LOG_VERB, "Declaring outgoing queue... (%s)\n", from_janus_admin);
			rmq_client->from_janus_admin_queue = amqp_cstring_bytes(from_janus_admin);
			amqp_queue_declare(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->from_janus_admin_queue, 0, 0, 0, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
			amqp_basic_consume(rmq_client->rmq_conn, rmq_client->rmq_channel, rmq_client->to_janus_admin_queue, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
			result = amqp_get_rpc_reply(rmq_client->rmq_conn);
			if(result.reply_type != AMQP_RESPONSE_NORMAL) {
				JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error consuming... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
				goto error;
			}
		}
		rmq_client->messages = g_async_queue_new();
		rmq_client->destroy = 0;
		GError *error = NULL;
		rmq_client->in_thread = g_thread_try_new("rmq_in_thread", &janus_rmq_in_thread, rmq_client, &error);
		if(error != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the RabbitMQ incoming thread...\n", error->code, error->message ? error->message : "??");
			g_free(rmq_client);
			janus_config_destroy(config);
			return -1;
		}
		rmq_client->out_thread = g_thread_try_new("rmq_out_thread", &janus_rmq_out_thread, rmq_client, &error);
		if(error != NULL) {
			/* Something went wrong... */
			JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the RabbitMQ outgoing thread...\n", error->code, error->message ? error->message : "??");
			g_free(rmq_client);
			janus_config_destroy(config);
			return -1;
		}
		janus_mutex_init(&rmq_client->mutex);
		/* Done */
		JANUS_LOG(LOG_INFO, "Setup of RabbitMQ integration completed\n");
	}
	g_free(rmqhost);
	if(to_janus)
		g_free((char *)to_janus);
	if(from_janus)
		g_free((char *)from_janus);
	if(to_janus_admin)
		g_free((char *)to_janus_admin);
	if(from_janus_admin)
		g_free((char *)from_janus_admin);
	janus_config_destroy(config);
	config = NULL;

	/* Done */
	g_atomic_int_set(&initialized, 1);
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_RABBITMQ_NAME);
	return 0;

error:
	/* If we got here, something went wrong */
	if(rmq_client)
		g_free(rmq_client);
	if(rmqhost)
		g_free(rmqhost);
	if(to_janus)
		g_free((char *)to_janus);
	if(from_janus)
		g_free((char *)from_janus);
	if(to_janus_admin)
		g_free((char *)to_janus_admin);
	if(from_janus_admin)
		g_free((char *)from_janus_admin);
	if(config)
		janus_config_destroy(config);
	return -1;
}

void janus_rabbitmq_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	if(rmq_client) {
		rmq_client->destroy = 1;
		g_async_queue_push(rmq_client->messages, &exit_message);
		if(rmq_client->in_thread)
			g_thread_join(rmq_client->in_thread);
		if(rmq_client->in_thread)
			g_thread_join(rmq_client->out_thread);
		if(rmq_client->rmq_conn && rmq_client->rmq_channel) {
			amqp_channel_close(rmq_client->rmq_conn, rmq_client->rmq_channel, AMQP_REPLY_SUCCESS);
			amqp_connection_close(rmq_client->rmq_conn, AMQP_REPLY_SUCCESS);
			amqp_destroy_connection(rmq_client->rmq_conn);
		}
	}
	g_free(rmq_client);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_RABBITMQ_NAME);
}

int janus_rabbitmq_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_TRANSPORT_API_VERSION;
}

int janus_rabbitmq_get_version(void) {
	return JANUS_RABBITMQ_VERSION;
}

const char *janus_rabbitmq_get_version_string(void) {
	return JANUS_RABBITMQ_VERSION_STRING;
}

const char *janus_rabbitmq_get_description(void) {
	return JANUS_RABBITMQ_DESCRIPTION;
}

const char *janus_rabbitmq_get_name(void) {
	return JANUS_RABBITMQ_NAME;
}

const char *janus_rabbitmq_get_author(void) {
	return JANUS_RABBITMQ_AUTHOR;
}

const char *janus_rabbitmq_get_package(void) {
	return JANUS_RABBITMQ_PACKAGE;
}

gboolean janus_rabbitmq_is_janus_api_enabled(void) {
	return rmq_janus_api_enabled;
}

gboolean janus_rabbitmq_is_admin_api_enabled(void) {
	return rmq_admin_api_enabled;
}

int janus_rabbitmq_send_message(void *transport, void *request_id, gboolean admin, json_t *message) {
	if(rmq_client == NULL)
		return -1;
	if(message == NULL)
		return -1;
	if(transport == NULL) {
		json_decref(message);
		return -1;
	}
	JANUS_LOG(LOG_HUGE, "Sending %s API %s via RabbitMQ\n", admin ? "admin" : "Janus", request_id ? "response" : "event");
	/* FIXME Add to the queue of outgoing messages */
	janus_rabbitmq_response *response = (janus_rabbitmq_response *)g_malloc0(sizeof(janus_rabbitmq_response));
	response->admin = admin;
	response->payload = message;
	response->correlation_id = (char *)request_id;
	g_async_queue_push(rmq_client->messages, response);
	return 0;
}

void janus_rabbitmq_session_created(void *transport, guint64 session_id) {
	/* We don't care */
}

void janus_rabbitmq_session_over(void *transport, guint64 session_id, gboolean timeout) {
	/* We don't care, not even if it's a timeout (should we?), our client is always up */
}


/* Threads */
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
	while(!rmq_client->destroy && !g_atomic_int_get(&stopping)) {
		amqp_maybe_release_buffers(rmq_client->rmq_conn);
		/* Wait for a frame */
		int res = amqp_simple_wait_frame_noblock(rmq_client->rmq_conn, &frame, &timeout);
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
		gboolean admin = FALSE;
		if(frame.payload.method.id == AMQP_BASIC_DELIVER_METHOD) {
			amqp_basic_deliver_t *d = (amqp_basic_deliver_t *)frame.payload.method.decoded;
			JANUS_LOG(LOG_VERB, "Delivery #%u, %.*s\n", (unsigned) d->delivery_tag, (int) d->routing_key.len, (char *) d->routing_key.bytes);
			/* Check if this is a Janus or Admin API request */
			if(rmq_client->admin_api_enabled) {
				if(d->routing_key.len == rmq_client->to_janus_admin_queue.len) {
					size_t i=0;
					admin = TRUE;
					char *inq = (char *)d->routing_key.bytes;
					char *expq = (char *)rmq_client->to_janus_admin_queue.bytes;
					for(i=0; i< d->routing_key.len; i++) {
						if(inq[i] != expq[i]) {
							admin = FALSE;
							break;
						}
					}
				}
			}
			JANUS_LOG(LOG_VERB, "  -- This is %s API request\n", admin ? "an admin" : "a Janus");
		}
		/* Then the header */
		amqp_simple_wait_frame(rmq_client->rmq_conn, &frame);
		JANUS_LOG(LOG_VERB, "Frame type %d, channel %d\n", frame.frame_type, frame.channel);
		if(frame.frame_type != AMQP_FRAME_HEADER)
			continue;
		amqp_basic_properties_t *p = (amqp_basic_properties_t *)frame.payload.properties.decoded;
		if(p->_flags & AMQP_BASIC_REPLY_TO_FLAG) {
			JANUS_LOG(LOG_VERB, "  -- Reply-to: %.*s\n", (int) p->reply_to.len, (char *) p->reply_to.bytes);
		}
		char *correlation = NULL;
		if(p->_flags & AMQP_BASIC_CORRELATION_ID_FLAG) {
			correlation = (char *)g_malloc0(p->correlation_id.len+1);
			sprintf(correlation, "%.*s", (int) p->correlation_id.len, (char *) p->correlation_id.bytes);
			JANUS_LOG(LOG_VERB, "  -- Correlation-id: %s\n", correlation);
		}
		if(p->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
			JANUS_LOG(LOG_VERB, "  -- Content-type: %.*s\n", (int) p->content_type.len, (char *) p->content_type.bytes);
		}
		/* And the body */
		uint64_t total = frame.payload.properties.body_size, received = 0;
		char *payload = (char *)g_malloc0(total+1), *index = payload;
		while(received < total) {
			amqp_simple_wait_frame(rmq_client->rmq_conn, &frame);
			JANUS_LOG(LOG_VERB, "Frame type %d, channel %d\n", frame.frame_type, frame.channel);
			if(frame.frame_type != AMQP_FRAME_BODY)
				break;
			sprintf(index, "%.*s", (int) frame.payload.body_fragment.len, (char *) frame.payload.body_fragment.bytes);
			received += frame.payload.body_fragment.len;
			index = payload+received;
		}
		JANUS_LOG(LOG_VERB, "Got %"SCNu64"/%"SCNu64" bytes from the %s queue (%"SCNu64")\n",
			received, total, admin ? "admin API" : "Janus API", frame.payload.body_fragment.len);
		JANUS_LOG(LOG_VERB, "%s\n", payload);
		/* Parse the JSON payload */
		json_error_t error;
		json_t *root = json_loads(payload, 0, &error);
		g_free(payload);
		/* Notify the core, passing both the object and, since it may be needed, the error
		 * We also specify the correlation ID as an opaque request identifier: we'll need it later */
		gateway->incoming_request(&janus_rabbitmq_transport, rmq_client, correlation, admin, root, &error);
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
	while(!rmq_client->destroy && !g_atomic_int_get(&stopping)) {
		/* We send messages from here as well, not only notifications */
		janus_rabbitmq_response *response = g_async_queue_pop(rmq_client->messages);
		if(response == NULL)
			continue;
		if(response == &exit_message)
			break;
		if(!rmq_client->destroy && !g_atomic_int_get(&stopping) && response->payload) {
			janus_mutex_lock(&rmq_client->mutex);
			/* Gotcha! Convert json_t to string */
			char *payload_text = json_dumps(response->payload, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(response->payload);
			response->payload = NULL;
			JANUS_LOG(LOG_VERB, "Sending %s API message to RabbitMQ (%zu bytes)...\n", response->admin ? "Admin" : "Janus", strlen(payload_text));
			JANUS_LOG(LOG_VERB, "%s\n", payload_text);
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
			amqp_bytes_t message = amqp_cstring_bytes(payload_text);
			int status = amqp_basic_publish(rmq_client->rmq_conn, rmq_client->rmq_channel, amqp_empty_bytes,
				response->admin ? rmq_client->from_janus_admin_queue : rmq_client->from_janus_queue,
				0, 0, &props, message);
			if(status != AMQP_STATUS_OK) {
				JANUS_LOG(LOG_ERR, "Error publishing... %d, %s\n", status, amqp_error_string2(status));
			}
			g_free(response->correlation_id);
			response->correlation_id = NULL;
			g_free(payload_text);
			payload_text = NULL;
			g_free(response);
			response = NULL;
			janus_mutex_unlock(&rmq_client->mutex);
		}
	}
	g_async_queue_unref(rmq_client->messages);
	JANUS_LOG(LOG_INFO, "Leaving RabbitMQ out thread\n");
	return NULL;
}
