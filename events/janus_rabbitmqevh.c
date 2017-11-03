/*! \file   janus_rabbitmqevh.c
 * \author Piter Konstantinov <pit.here@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus RabbitMQEventHandler plugin
 * \details  This is a trivial RabbitMQ event handler plugin for Janus
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>

#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_RABBITMQEVH_VERSION			1
#define JANUS_RABBITMQEVH_VERSION_STRING	"0.0.1"
#define JANUS_RABBITMQEVH_DESCRIPTION		"This is a trivial RabbitMQ event handler plugin for Janus."
#define JANUS_RABBITMQEVH_NAME				"JANUS RabbitMQEventHandler plugin"
#define JANUS_RABBITMQEVH_AUTHOR			"Meetecho s.r.l."
#define JANUS_RABBITMQEVH_PACKAGE			"janus.eventhandler.rabbitmqevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_rabbitmqevh_init(const char *config_path);
void janus_rabbitmqevh_destroy(void);
int janus_rabbitmqevh_get_api_compatibility(void);
int janus_rabbitmqevh_get_version(void);
const char *janus_rabbitmqevh_get_version_string(void);
const char *janus_rabbitmqevh_get_description(void);
const char *janus_rabbitmqevh_get_name(void);
const char *janus_rabbitmqevh_get_author(void);
const char *janus_rabbitmqevh_get_package(void);
void janus_rabbitmqevh_incoming_event(json_t *event);

/* Event handler setup */
static janus_eventhandler janus_rabbitmqevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_rabbitmqevh_init,
		.destroy = janus_rabbitmqevh_destroy,

		.get_api_compatibility = janus_rabbitmqevh_get_api_compatibility,
		.get_version = janus_rabbitmqevh_get_version,
		.get_version_string = janus_rabbitmqevh_get_version_string,
		.get_description = janus_rabbitmqevh_get_description,
		.get_name = janus_rabbitmqevh_get_name,
		.get_author = janus_rabbitmqevh_get_author,
		.get_package = janus_rabbitmqevh_get_package,

		.incoming_event = janus_rabbitmqevh_incoming_event,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_RABBITMQEVH_NAME);
	return &janus_rabbitmqevh;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *handler_thread;
static void *janus_rabbitmqevh_handler(void *data);

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static gboolean group_events = TRUE;
static json_t exit_event;
static void janus_rabbitmqevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* FIXME: Should it be configurable? */
#define JANUS_RABBITMQ_EXCHANGE_TYPE "fanout"

/* RabbitMQ session */
static amqp_connection_state_t rmq_conn;
static amqp_channel_t rmq_channel = 0;
static amqp_bytes_t rmq_exchange;
static amqp_bytes_t rmq_route_key;


/* Plugin implementation */
int janus_rabbitmqevh_init(const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}
	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_RABBITMQEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	char *rmqhost = NULL;
	const char *vhost = NULL, *username = NULL, *password = NULL;
	const char *ssl_cacert_file = NULL;
	const char *ssl_cert_file = NULL;
	const char *ssl_key_file = NULL;
	gboolean ssl_enable = FALSE;
	gboolean ssl_verify_peer = FALSE;
	gboolean ssl_verify_hostname = FALSE;
	const char *route_key = NULL, *exchange = NULL;

	/* Setup the event handler, if required */
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "enabled");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "RabbitMQ event handler disabled\n");
		goto error;
	}

	item = janus_config_get_item_drilldown(config, "general", "json");
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

	/* Which events should we subscribe to? */
	item = janus_config_get_item_drilldown(config, "general", "events");
	if(item && item->value) {
		if(!strcasecmp(item->value, "none")) {
			/* Don't subscribe to anything at all */
			janus_flags_reset(&janus_rabbitmqevh.events_mask);
		} else if(!strcasecmp(item->value, "all")) {
			/* Subscribe to everything */
			janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_ALL);
		} else {
			/* Check what we need to subscribe to */
			gchar **subscribe = g_strsplit(item->value, ",", -1);
			if(subscribe != NULL) {
				gchar *index = subscribe[0];
				if(index != NULL) {
					int i=0;
					while(index != NULL) {
						while(isspace(*index))
							index++;
						if(strlen(index)) {
							if(!strcasecmp(index, "sessions")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_SESSION);
							} else if(!strcasecmp(index, "handles")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_HANDLE);
							} else if(!strcasecmp(index, "jsep")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_JSEP);
							} else if(!strcasecmp(index, "webrtc")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_WEBRTC);
							} else if(!strcasecmp(index, "media")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_MEDIA);
							} else if(!strcasecmp(index, "plugins")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_PLUGIN);
							} else if(!strcasecmp(index, "transports")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_TRANSPORT);
							} else if(!strcasecmp(index, "core")) {
								janus_flags_set(&janus_rabbitmqevh.events_mask, JANUS_EVENT_TYPE_CORE);
							} else {
								JANUS_LOG(LOG_WARN, "Unknown event type '%s'\n", index);
							}
						}
						i++;
						index = subscribe[i];
					}
				}
				g_strfreev(subscribe);
			}
		}
	}

	/* Is grouping of events ok? */
	item = janus_config_get_item_drilldown(config, "general", "grouping");
	if(item && item->value)
		group_events = janus_is_true(item->value);

	/* Handle configuration, starting from the server details */
	item = janus_config_get_item_drilldown(config, "general", "host");
	if(item && item->value)
		rmqhost = g_strdup(item->value);
	else
		rmqhost = g_strdup("localhost");
	int rmqport = AMQP_PROTOCOL_PORT;
	item = janus_config_get_item_drilldown(config, "general", "port");
	if(item && item->value)
		rmqport = atoi(item->value);

	/* Credentials and Virtual Host */
	item = janus_config_get_item_drilldown(config, "general", "vhost");
	if(item && item->value)
		vhost = g_strdup(item->value);
	else
	vhost = g_strdup("/");
	item = janus_config_get_item_drilldown(config, "general", "username");
	if(item && item->value)
		username = g_strdup(item->value);
	else
		username = g_strdup("guest");
	item = janus_config_get_item_drilldown(config, "general", "password");
	if(item && item->value)
		password = g_strdup(item->value);
	else
		password = g_strdup("guest");

	/* SSL config*/
	item = janus_config_get_item_drilldown(config, "general", "ssl_enable");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_INFO, "RabbitMQEventHandler: RabbitMQ SSL support disabled\n");
	} else {
		ssl_enable = TRUE;
		item = janus_config_get_item_drilldown(config, "general", "ssl_cacert");
		if(item && item->value)
			ssl_cacert_file = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "general", "ssl_cert");
		if(item && item->value)
			ssl_cert_file = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "general", "ssl_key");
		if(item && item->value)
			ssl_key_file = g_strdup(item->value);
		item = janus_config_get_item_drilldown(config, "general", "ssl_verify_peer");
		if(item && item->value && janus_is_true(item->value))
			ssl_verify_peer = TRUE;
		item = janus_config_get_item_drilldown(config, "general", "ssl_verify_hostname");
		if(item && item->value && janus_is_true(item->value))
			ssl_verify_hostname = TRUE;
	}

	/* Parse configuration */
	item = janus_config_get_item_drilldown(config, "general", "route_key");
	if(!item || !item->value) {
		JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Missing name of outgoing route_key for RabbitMQ...\n");
		goto error;
	}
	route_key = g_strdup(item->value);
	item = janus_config_get_item_drilldown(config, "general", "exchange");
	if(!item || !item->value) {
		JANUS_LOG(LOG_INFO, "RabbitMQEventHandler: Missing name of outgoing exchange for RabbitMQ, using default\n");
	} else {
		exchange = g_strdup(item->value);
	}
	if (exchange == NULL) {
		JANUS_LOG(LOG_INFO, "RabbitMQ event handler enabled, %s:%d (%s)\n", rmqhost, rmqport, route_key);
	} else {
		JANUS_LOG(LOG_INFO, "RabbitMQ event handler enabled, %s:%d (%s) exch: (%s)\n", rmqhost, rmqport, route_key, exchange);
	}

	/* Connect */
	rmq_conn = amqp_new_connection();
	amqp_socket_t *socket = NULL;
	int status;
	JANUS_LOG(LOG_VERB, "RabbitMQEventHandler: Creating RabbitMQ socket...\n");
	if (ssl_enable) {
		socket = amqp_ssl_socket_new(rmq_conn);
		if(socket == NULL) {
			JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error creating socket...\n");
			goto error;
		}
		if(ssl_verify_peer) {
			amqp_ssl_socket_set_verify_peer(socket, 1);
		} else {
			amqp_ssl_socket_set_verify_peer(socket, 0);
		}
		if(ssl_verify_hostname) {
			amqp_ssl_socket_set_verify_hostname(socket, 1);
		} else {
			amqp_ssl_socket_set_verify_hostname(socket, 0);
		}
		if(ssl_cacert_file) {
			status = amqp_ssl_socket_set_cacert(socket, ssl_cacert_file);
			if(status != AMQP_STATUS_OK) {
				JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error setting CA certificate... (%s)\n", amqp_error_string2(status));
				goto error;
			}
		}
		if(ssl_cert_file && ssl_key_file) {
			amqp_ssl_socket_set_key(socket, ssl_cert_file, ssl_key_file);
			if(status != AMQP_STATUS_OK) {
				JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error setting key... (%s)\n", amqp_error_string2(status));
				goto error;
			}
		}
	} else {
		socket = amqp_tcp_socket_new(rmq_conn);
		if(socket == NULL) {
			JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error creating socket...\n");
			goto error;
		}
	}

	JANUS_LOG(LOG_VERB, "RabbitMQEventHandler: Connecting to RabbitMQ server...\n");
	status = amqp_socket_open(socket, rmqhost, rmqport);
	if(status != AMQP_STATUS_OK) {
		JANUS_LOG(LOG_FATAL, "Can't connect to RabbitMQ server: error opening socket... (%s)\n", amqp_error_string2(status));
		goto error;
	}
	JANUS_LOG(LOG_VERB, "RabbitMQEventHandler: Logging in...\n");
	amqp_rpc_reply_t result = amqp_login(rmq_conn, vhost, 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, username, password);
	if(result.reply_type != AMQP_RESPONSE_NORMAL) {
		JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error logging in... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
		goto error;
	}
	rmq_channel = 1;
	JANUS_LOG(LOG_VERB, "Opening channel...\n");
	amqp_channel_open(rmq_conn, rmq_channel);
	result = amqp_get_rpc_reply(rmq_conn);
	if(result.reply_type != AMQP_RESPONSE_NORMAL) {
		JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error opening channel... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
		goto error;
	}
	rmq_exchange = amqp_empty_bytes;
	if(exchange != NULL) {
		JANUS_LOG(LOG_VERB, "RabbitMQEventHandler: Declaring exchange...\n");
		rmq_exchange = amqp_cstring_bytes(exchange);
		amqp_exchange_declare(rmq_conn, rmq_channel, rmq_exchange, amqp_cstring_bytes(JANUS_RABBITMQ_EXCHANGE_TYPE), 0, 0, 0, 0, amqp_empty_table);
		result = amqp_get_rpc_reply(rmq_conn);
		if(result.reply_type != AMQP_RESPONSE_NORMAL) {
			JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error diclaring exchange... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
			goto error;
		}
	}
	JANUS_LOG(LOG_VERB, "Declaring outgoing queue... (%s)\n", route_key);
	rmq_route_key = amqp_cstring_bytes(route_key);
	amqp_queue_declare(rmq_conn, rmq_channel, rmq_route_key, 0, 0, 0, 0, amqp_empty_table);
	result = amqp_get_rpc_reply(rmq_conn);
	if(result.reply_type != AMQP_RESPONSE_NORMAL) {
		JANUS_LOG(LOG_FATAL, "RabbitMQEventHandler: Can't connect to RabbitMQ server: error declaring queue... %s, %s\n", amqp_error_string2(result.library_error), amqp_method_name(result.reply.id));
		goto error;
	}

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_rabbitmqevh_event_free);
	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	handler_thread = g_thread_try_new("janus rabbitmqevh handler", janus_rabbitmqevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the RabbitMQEventHandler handler thread...\n", error->code, error->message ? error->message : "??");
		goto error;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Setup of RabbitMQ event handler completed\n");

	if(rmqhost)
		g_free((char *)rmqhost);
	if(config)
		janus_config_destroy(config);

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_RABBITMQEVH_NAME);
	return 0;

error:
	/* If we got here, something went wrong */
	if(rmqhost)
		g_free((char *)rmqhost);
	if(vhost)
		g_free((char *)vhost);
	if(username)
		g_free((char *)username);
	if(password)
		g_free((char *)password);
	if(route_key)
		g_free((char *)route_key);
	if(exchange)
		g_free((char *)exchange);
	if(ssl_cacert_file)
		g_free((char *)ssl_cacert_file);
	if(ssl_cert_file)
		g_free((char *)ssl_cert_file);
	if(ssl_key_file)
		g_free((char *)ssl_key_file);
	if(config)
		janus_config_destroy(config);
	return -1;
}

void janus_rabbitmqevh_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(events, &exit_event);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	g_async_queue_unref(events);
	events = NULL;

	if(rmq_conn && rmq_channel) {
		amqp_channel_close(rmq_conn, rmq_channel, AMQP_REPLY_SUCCESS);
		amqp_connection_close(rmq_conn, AMQP_REPLY_SUCCESS);
		amqp_destroy_connection(rmq_conn);
	}
	if(rmq_exchange.bytes)
		g_free((char *)rmq_exchange.bytes);
	if(rmq_route_key.bytes)
		g_free((char *)rmq_route_key.bytes);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_RABBITMQEVH_NAME);
}

int janus_rabbitmqevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_rabbitmqevh_get_version(void) {
	return JANUS_RABBITMQEVH_VERSION;
}

const char *janus_rabbitmqevh_get_version_string(void) {
	return JANUS_RABBITMQEVH_VERSION_STRING;
}

const char *janus_rabbitmqevh_get_description(void) {
	return JANUS_RABBITMQEVH_DESCRIPTION;
}

const char *janus_rabbitmqevh_get_name(void) {
	return JANUS_RABBITMQEVH_NAME;
}

const char *janus_rabbitmqevh_get_author(void) {
	return JANUS_RABBITMQEVH_AUTHOR;
}

const char *janus_rabbitmqevh_get_package(void) {
	return JANUS_RABBITMQEVH_PACKAGE;
}

void janus_rabbitmqevh_incoming_event(json_t *event) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		/* Janus is closing or the plugin is: unref the event as we won't handle it */
		json_decref(event);
		return;
	}

	/* Do NOT handle the event here in this callback! Since Janus notifies you right
	 * away when something happens, these events are triggered from working threads and
	 * not some sort of message bus. As such, performing I/O or network operations in
	 * here could dangerously slow Janus down. Let's just reference and enqueue the event,
	 * and handle it in our own thread: the event contains a monotonic time indicator of
	 * when the event actually happened on this machine, so that, if relevant, we can compute
	 * any delay in the actual event processing ourselves. */
	json_incref(event);
	g_async_queue_push(events, event);
}

/* Thread to handle incoming events */
static void *janus_rabbitmqevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining RabbitMQEventHandler handler thread\n");
	json_t *event = NULL, *output = NULL;
	char *event_text = NULL;
	int count = 0, max = group_events ? 100 : 1;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {

		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;
		count = 0;
		output = NULL;

		while(TRUE) {
			/* Handle event: just for fun, let's see how long it took for us to take care of this */
			json_t *created = json_object_get(event, "timestamp");
			if(created && json_is_integer(created)) {
				gint64 then = json_integer_value(created);
				gint64 now = janus_get_monotonic_time();
				JANUS_LOG(LOG_DBG, "Handled event after %"SCNu64" us\n", now-then);
			}

			/* Let's check what kind of event this is: we don't really do anything
			 * with it in this plugin, it's just to show how you can handle
			 * different types of events in an event handler. */
			int type = json_integer_value(json_object_get(event, "type"));
			switch(type) {
				case JANUS_EVENT_TYPE_SESSION:
					/* This is a session related event. The only info that is
					 * required is a name for the event itself: a "created"
					 * event may also contain transport info, in the form of
					 * the transport module that originated the session
					 * (e.g., "janus.transport.http") and an internal unique
					 * ID for the transport instance (which may be associated
					 * to a connection or anything else within the specifics
					 * of the transport module itself). Here's an example of
					 * a new session being created:
						{
						   "type": 1,
						   "timestamp": 3583879627,
						   "session_id": 2004798115,
						   "event": {
							  "name": "created"
						   },
						   "transport": {
						      "transport": "janus.transport.http",
						      "id": "0x7fcb100008c0"
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_HANDLE:
					/* This is a handle related event. The only info that is provided
					 * are the name for the event itself and the package name of the
					 * plugin this handle refers to (e.g., "janus.plugin.echotest").
					 * Here's an example of a new handled being attached in a session
					 * to the EchoTest plugin:
						{
						   "type": 2,
						   "timestamp": 3570304977,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "name": "attached",
							  "plugin: "janus.plugin.echotest"
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_JSEP:
					/* This is a JSEP/SDP related event. It provides information
					 * about an ongoing WebRTC negotiation, and so tells you
					 * about the SDP being sent/received, and who's sending it
					 * ("local" means Janus, "remote" means the user). Here's an
					 * example, where the user originated an offer towards Janus:
						{
						   "type": 8,
						   "timestamp": 3570400208,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "owner": "remote",
							  "jsep": {
								 "type": "offer",
								 "sdp": "v=0[..]\r\n"
							  }
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_WEBRTC:
					/* This is a WebRTC related event, and so the content of
					 * the event may vary quite a bit. In fact, you may be notified
					 * about ICE or DTLS states, or when a WebRTC PeerConnection
					 * goes up or down. Here are some examples, in no particular order:
						{
						   "type": 16,
						   "timestamp": 3570416659,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "ice": "connecting",
							  "stream_id": 1,
							  "component_id": 1
						   }
						}
					 *
						{
						   "type": 16,
						   "timestamp": 3570637554,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "selected-pair": "[..]",
							  "stream_id": 1,
							  "component_id": 1
						   }
						}
					 *
						{
						   "type": 16,
						   "timestamp": 3570656112,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "dtls": "connected",
							  "stream_id": 1,
							  "component_id": 1
						   }
						}
					 *
						{
						   "type": 16,
						   "timestamp": 3570657237,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "connection": "webrtcup"
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_MEDIA:
					/* This is a media related event. This can contain different
					 * information about the health of a media session, or about
					 * what's going on in general (e.g., when Janus started/stopped
					 * receiving media of a certain type, or (TODO) when some media related
					 * statistics are available). Here's an example of Janus getting
					 * video from the peer for the first time, or after a second
					 * of no video at all (which would have triggered a "receiving": false):
						{
						   "type": 32,
						   "timestamp": 3571078797,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "media": "video",
							  "receiving": "true"
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_PLUGIN:
					/* This is a plugin related event. Since each plugin may
					 * provide info in a very custom way, the format of this event
					 * is in general very dynamic. You'll always find, though,
					 * an "event" object containing the package name of the
					 * plugin (e.g., "janus.plugin.echotest") and a "data"
					 * object that contains whatever the plugin decided to
					 * notify you about, that will always vary from plugin to
					 * plugin. Besides, notice that "session_id" and "handle_id"
					 * may or may not be present: when they are, you'll know
					 * the event has been triggered within the context of a
					 * specific handle session with the plugin; when they're
					 * not, the plugin sent an event out of context of a
					 * specific session it is handling. Here's an example:
						{
						   "type": 64,
						   "timestamp": 3570336031,
						   "session_id": 2004798115,
						   "handle_id": 3708519405,
						   "event": {
							  "plugin": "janus.plugin.echotest",
							  "data": {
								 "audio_active": "true",
								 "video_active": "true",
								 "bitrate": 0
							  }
						   }
						}
					*/
					break;
				case JANUS_EVENT_TYPE_TRANSPORT:
					/* This is a transport related event (TODO). The syntax of
					 * the common format (transport specific data aside) is
					 * exactly the same as that of the plugin related events
					 * above, with a "transport" property instead of "plugin"
					 * to contain the transport package name. */
					break;
				case JANUS_EVENT_TYPE_CORE:
					/* This is a core related event. This can contain different
					 * information about the health of the Janus instance, or
					 * more generically on some events in the Janus life cycle
					 * (e.g., when it's just been started or when a shutdown
					 * has been requested). Considering the heterogeneous nature
					 * of the information being reported, the content is always
					 * a JSON object (event). Core events are the only ones
					 * missing a session_id. Here's an example:
						{
						   "type": 256,
						   "timestamp": 28381185382,
						   "event": {
							  "status": "started"
						   }
						}
					*/
					break;
				default:
					JANUS_LOG(LOG_WARN, "Unknown type of event '%d'\n", type);
					break;
			}

			if(!group_events) {
				/* We're done here, we just need a single event */
				output = event;
				break;
			}
			/* If we got here, we're grouping */
			if(output == NULL)
				output = json_array();
			json_array_append_new(output, event);
			/* Never group more than a maximum number of events, though, or we might stay here forever */
			count++;
			if(count == max)
				break;
			event = g_async_queue_try_pop(events);
			if(event == NULL || event == &exit_event)
				break;
		}

		if(!g_atomic_int_get(&stopping)) {
			/* Since this a simple plugin, it does the same for all events: so just convert to string... */
			event_text = json_dumps(output, json_format);
			amqp_basic_properties_t props;
			props._flags = 0;
			props._flags |= AMQP_BASIC_CONTENT_TYPE_FLAG;
			props.content_type = amqp_cstring_bytes("application/json");
			amqp_bytes_t message = amqp_cstring_bytes(event_text);
			int status = amqp_basic_publish(rmq_conn, rmq_channel, rmq_exchange, rmq_route_key, 0, 0, &props, message);
			if(status != AMQP_STATUS_OK) {
				JANUS_LOG(LOG_ERR, "RabbitMQEventHandler: Error publishing... %d, %s\n", status, amqp_error_string2(status));
			}
			free(event_text);
			event_text = NULL;
		}

		/* Done, let's unref the event */
		json_decref(output);
		output = NULL;
	}
	JANUS_LOG(LOG_VERB, "Leaving RabbitMQEventHandler handler thread\n");
	return NULL;
}
