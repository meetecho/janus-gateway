/*! \file   janus_gelfevh.c
 * \author Mirko Brankovic <mirkobrankovic@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus GelfEventHandler plugin
 * \details  This is a GELF event handler plugin for Janus, which is supposed
 * to send json events to GELF
 * (Graylog logger https://docs.graylog.org/en/3.2/pages/gelf.html).
 * Necessary headers are prepended.
 * For sending, you can use TCP which is not recommended in case there will be
 * a lot of messages. There is also UDP support, but you need to limit the payload
 * size with max_message_len and remember to leave room for 12 bytes for special
 * headers. UDP messages will be chunked automatically.
 * There is also compression available for UDP protocol, to save network bandwidth
 * while using a bit more CPU. This is not available for TCP due to GELF limitations
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../ip-utils.h"

/* Plugin information */
#define JANUS_GELFEVH_VERSION			1
#define JANUS_GELFEVH_VERSION_STRING 	"0.0.1"
#define JANUS_GELFEVH_DESCRIPTION 		"This is event handler plugin for Janus, which forwards events via TCP/UDP to GELF server."
#define JANUS_GELFEVH_NAME 				"JANUS GelfEventHandler plugin"
#define JANUS_GELFEVH_AUTHOR 			"Mirko Brankovic <mirkobrankovic@gmail.com>"
#define JANUS_GELFEVH_PACKAGE			"janus.eventhandler.gelfevh"

#define MAX_GELF_CHUNKS 				128

/* Plugin methods */
janus_eventhandler *create(void);
int janus_gelfevh_init(const char *config_path);
void janus_gelfevh_destroy(void);
int janus_gelfevh_get_api_compatibility(void);
int janus_gelfevh_get_version(void);
const char *janus_gelfevh_get_version_string(void);
const char *janus_gelfevh_get_description(void);
const char *janus_gelfevh_get_name(void);
const char *janus_gelfevh_get_author(void);
const char *janus_gelfevh_get_package(void);
void janus_gelfevh_incoming_event(json_t *event);
json_t *janus_gelfevh_handle_request(json_t *request);

/* Event handler setup */
static janus_eventhandler janus_gelfevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_gelfevh_init,
		.destroy = janus_gelfevh_destroy,

		.get_api_compatibility = janus_gelfevh_get_api_compatibility,
		.get_version = janus_gelfevh_get_version,
		.get_version_string = janus_gelfevh_get_version_string,
		.get_description = janus_gelfevh_get_description,
		.get_name = janus_gelfevh_get_name,
		.get_author = janus_gelfevh_get_author,
		.get_package = janus_gelfevh_get_package,

		.incoming_event = janus_gelfevh_incoming_event,
		.handle_request = janus_gelfevh_handle_request,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_GELFEVH_NAME);
	return &janus_gelfevh;
}

/* Compression, if any */
static gboolean compress = FALSE;
static int compression = 6; /* Z_DEFAULT_COMPRESSION */

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *handler_thread;
static void *janus_gelfevh_handler(void *data);
static janus_mutex evh_mutex;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static json_t exit_event;
static void janus_gelfevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* GELF backend to send the events to */
static char *backend = NULL;
static char *port = NULL;

typedef enum janus_gelfevh_socket_type {
	JANUS_GELFEVH_SOCKET_TYPE_TCP = 1,
	JANUS_GELFEVH_SOCKET_TYPE_UDP = 2
} janus_gelfevh_socket_type;

static int max_gelf_msg_len = 500;
static int sockfd;
/* Set TCP as Default transport */
static janus_gelfevh_socket_type transport = JANUS_GELFEVH_SOCKET_TYPE_UDP;

/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
	{"backend", JSON_STRING, 0},
	{"port", JSON_STRING, 0},
	{"max_gelf_msg_len", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"janus_gelfevh_socket_type", JSON_STRING, 0}
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_GELFEVH_ERROR_INVALID_REQUEST		411
#define JANUS_GELFEVH_ERROR_MISSING_ELEMENT		412
#define JANUS_GELFEVH_ERROR_INVALID_ELEMENT		413
#define JANUS_GELFEVH_ERROR_UNKNOWN_ERROR		499

/* Plugin implementation */
static char *randstring(size_t length) {
	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char *randomString = NULL;
	int n;
	if(length) {
		randomString = g_malloc(sizeof(char) * (length + 1));
		if(randomString) {
			for(n = 0; n < (int)length; n++) {
				int key = rand() % (int)(sizeof(charset) - 1);
				randomString[n] = charset[key];
			}
			randomString[length] = '\0';
		}
	}
	return randomString;
}

static int janus_gelfevh_connect(void) {
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	struct sockaddr_in servaddr;

	if(getaddrinfo(backend, NULL, NULL, &res) != 0 ||
				janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
				janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		if(res)
			freeaddrinfo(res);
		JANUS_LOG(LOG_ERR, "Could not resolve address (%s): %d (%s)\n", backend, errno, strerror(errno));
		return -1;
	}
	char *host = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	freeaddrinfo(res);

	if((sockfd = socket(AF_INET, transport, 0)) < 0 ) {
		JANUS_LOG(LOG_ERR, "Socket creation failed: %d (%s)\n", errno, strerror(errno));
		g_free(host);
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(port));
	servaddr.sin_addr.s_addr = inet_addr(host);

	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		JANUS_LOG(LOG_ERR, "Connect to GELF host failed\n");
		g_free(host);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "Connected to GELF backend: [%s:%s]\n", host, port);
	g_free(host);
	return 0;
}

static char compressed_text[8192];
static int janus_gelfevh_send(char *message) {
	if(!message) {
		JANUS_LOG(LOG_WARN, "Message is NULL, not sending to GELF!\n");
		return -1;
	}
	if(transport == JANUS_GELFEVH_SOCKET_TYPE_TCP) {
		/* TCP */
		int out_bytes = 0;
		int length = strlen(message);
		char *buffer = message;
		while(length > 0) {
			out_bytes = send(sockfd, buffer, length + 1, 0);
			if(out_bytes <= 0) {
				JANUS_LOG(LOG_WARN, "Sending TCP message failed, dropping event: %d (%s)\n", errno, strerror(errno));
				close(sockfd);
				return -1;
			}
			buffer += out_bytes;
			length -= out_bytes;
		}
	} else {
		/* UDP chunking with headers. Check if we need to compress the data */
		int len = strlen(message);
		char *buf = message;
		if(compress) {
			size_t compressed_len = 0;
			compressed_len = janus_gzip_compress(compression,
				message, strlen(message),
				compressed_text, sizeof(compressed_text));
			if(compressed_len == 0) {
				JANUS_LOG(LOG_WARN, "Failed to compress event (%zu bytes), sending message uncompressed\n", strlen(message));
				/* Sending message uncompressed */
			} else {
				len = compressed_len;
				buf = compressed_text;
			}
		}

		int total = len / max_gelf_msg_len + 1;
		if(total > MAX_GELF_CHUNKS) {
			JANUS_LOG(LOG_WARN, "Event not sent! GELF allows %d number of chunks, try increasing max_gelf_msg_len\n", MAX_GELF_CHUNKS);
			return -1;
		}
		/* Do we need to chunk the message */
		if(total == 1) {
			int n = send(sockfd, buf, len, 0);
			if(n < 0) {
				JANUS_LOG(LOG_WARN, "Sending UDP message failed, dropping event: %d (%s)\n", errno, strerror(errno));
				return -1;
			}
			return 0;
		} else {
			int offset = 0;
			char *rnd = randstring(8);
			int i;
			for(i = 0; i < total; i++) {
				int bytesToSend = ((offset + max_gelf_msg_len) < len) ? max_gelf_msg_len : (len - offset);
				/* Prepend the necessary headers (imitate TCP) */
				char chunk[bytesToSend + 12];
				chunk[0] = 0x1e;
				chunk[1] = 0x0f;
				memcpy(chunk + 2, rnd, 8);
				chunk[10] = (char)i;
				chunk[11] = (char)total;
				char *head = chunk;
				memcpy(head+12, buf, bytesToSend);
				buf += bytesToSend;
				int n = send(sockfd, head, bytesToSend + 12, 0);
				if(n < 0) {
					JANUS_LOG(LOG_WARN, "Sending UDP message failed: %d (%s)\n", errno, strerror(errno));
					return -1;
				}
				offset += bytesToSend;
				memset(chunk, 0, sizeof chunk);
			}
			g_free(rnd);
		}
	}
	return 0;
}

int janus_gelfevh_init(const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	gboolean enabled = FALSE;
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_GELFEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_GELFEVH_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_GELFEVH_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

		/* Setup the sample event handler, if required */
		janus_config_item *item;
		item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "GELF event handler disabled (Janus API)\n");
			goto done;
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "backend");
		if(!item || !item->value) {
			JANUS_LOG(LOG_WARN, "Missing or invalid backend\n");
			goto done;
		}
		backend = g_strdup(item->value);
		item = janus_config_get(config, config_general, janus_config_type_item, "port");
		if(!item || !item->value) {
			JANUS_LOG(LOG_WARN, "Missing or invalid port\n");
			goto done;
		}
		port = g_strdup(item->value);
		item = janus_config_get(config, config_general, janus_config_type_item, "protocol");
		if(item && item->value) {
			if(strcasecmp(item->value, "udp") == 0) {
				transport = JANUS_GELFEVH_SOCKET_TYPE_UDP;
			} else if(strcasecmp(item->value, "tcp") == 0) {
				transport = JANUS_GELFEVH_SOCKET_TYPE_TCP;
			} else {
				JANUS_LOG(LOG_WARN, "Missing or invalid transport, using default: UDP\n");
			}
		}
		item = janus_config_get(config, config_general, janus_config_type_item, "max_message_len");
		if(item && item->value) {
			if(atoi(item->value) == 0) {
				JANUS_LOG(LOG_WARN, "Missing or invalid max_message_len, using default: %d\n", max_gelf_msg_len);
			} else {
				max_gelf_msg_len = atoi(item->value);
			}
		}
		/* Which events should we subscribe to? */
		item = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(item && item->value)
			janus_events_edit_events_mask(item->value, &janus_gelfevh.events_mask);
		/* Compact, so no spaces between separators */
		json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;

		/* Check if we need any compression */
		item = janus_config_get(config, config_general, janus_config_type_item, "compress");
		if(item && item->value && janus_is_true(item->value)) {
			if(transport == JANUS_GELFEVH_SOCKET_TYPE_TCP) {
				compress = FALSE;
				JANUS_LOG(LOG_WARN, "Compression on TCP Gelf transport not allowed, disabling...\n");
			} else {
				compress = TRUE;
				item = janus_config_get(config, config_general, janus_config_type_item, "compression");
				if(item && item->value) {
					int c = atoi(item->value);
					if(c < 0 || c > 9) {
						JANUS_LOG(LOG_WARN, "Invalid compression factor '%d', falling back to '%d'...\n", c, compression);
					} else {
						compression = c;
					}
				}
			}
		}
		/* Done */
		enabled = TRUE;
	}
done:
	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		JANUS_LOG(LOG_FATAL, "GELF event handler not enabled/needed, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}
	JANUS_LOG(LOG_VERB, "GELF event handler configured: %s:%s\n", backend, port);

	/* Check if connection failed. Error is logged in janus_gelfevh_connect function */
	if(janus_gelfevh_connect() < 0 ) {
		return -1;
	}

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_gelfevh_event_free);
	janus_mutex_init(&evh_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming events */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus gelfevh handler", janus_gelfevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the GelfEventHandler handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_GELFEVH_NAME);
	return 0;
}

void janus_gelfevh_destroy(void) {
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

	g_free(backend);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);

	close(sockfd);

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_GELFEVH_NAME);
}

int janus_gelfevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_gelfevh_get_version(void) {
	return JANUS_GELFEVH_VERSION;
}

const char *janus_gelfevh_get_version_string(void) {
	return JANUS_GELFEVH_VERSION_STRING;
}

const char *janus_gelfevh_get_description(void) {
	return JANUS_GELFEVH_DESCRIPTION;
}

const char *janus_gelfevh_get_name(void) {
	return JANUS_GELFEVH_NAME;
}

const char *janus_gelfevh_get_author(void) {
	return JANUS_GELFEVH_AUTHOR;
}

const char *janus_gelfevh_get_package(void) {
	return JANUS_GELFEVH_PACKAGE;
}

void janus_gelfevh_incoming_event(json_t *event) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		/* Janus is closing or the plugin is */
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

json_t *janus_gelfevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_GELFEVH_ERROR_MISSING_ELEMENT, JANUS_GELFEVH_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_GELFEVH_ERROR_MISSING_ELEMENT, JANUS_GELFEVH_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Parameters we can change */
		const char *req_events = NULL, *req_backend = NULL, *req_port = NULL;
		gboolean req_compress = -1, req_compression = -1;
		/* Events */
		if(json_object_get(request, "events"))
			req_events = json_string_value(json_object_get(request, "events"));
		/* Compression */
		if(json_object_get(request, "compress"))
			req_compress = json_is_true(json_object_get(request, "compress"));
		if(json_object_get(request, "compression"))
			req_compression = json_integer_value(json_object_get(request, "compression"));
		/* Backend stuff */
		if(json_object_get(request, "backend"))
			req_backend = json_string_value(json_object_get(request, "backend"));
		if(json_object_get(request, "port"))
			req_port = json_string_value(json_object_get(request, "port"));
		if(json_object_get(request, "max_message_len"))
			max_gelf_msg_len = json_integer_value(json_object_get(request, "max_message_len"));
		if(strcasecmp(json_string_value(json_object_get(request, "protocol")), "tcp") == 0) {
			transport = JANUS_GELFEVH_SOCKET_TYPE_TCP;
		} else if(strcasecmp(json_string_value(json_object_get(request, "protocol")), "udp") == 0) {
			transport = JANUS_GELFEVH_SOCKET_TYPE_UDP;
		} else {
			JANUS_LOG(LOG_WARN, "Missing or invalid transport, using default: UDP\n");
			transport = JANUS_GELFEVH_SOCKET_TYPE_UDP;
		}
		if(!req_backend || !req_port) {
			/* Invalid backend address or port */
			error_code = JANUS_GELFEVH_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, sizeof(error_cause), "Invalid backend URI '%s:%s'", req_backend, req_port);
			goto plugin_response;
		}
		/* If we got here, we can enforce */
		janus_mutex_lock(&evh_mutex);
		if(req_events)
			janus_events_edit_events_mask(req_events, &janus_gelfevh.events_mask);
		if(req_compress > -1) {
			if(req_compress && transport == JANUS_GELFEVH_SOCKET_TYPE_TCP) {
				compress = FALSE;
				JANUS_LOG(LOG_WARN, "Compression on TCP Gelf transport not allowed, disabling...\n");
			} else {
				compress = req_compress ? TRUE : FALSE;
			}
		}
		if(req_compression > -1 && req_compression < 10)
			compression = req_compression;
		if(req_backend && req_port) {
			g_free(backend);
			g_free(port);
			backend = g_strdup(req_backend);
			port = g_strdup(req_port);
		}
		janus_mutex_unlock(&evh_mutex);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_GELFEVH_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			json_t *response = json_object();
			if(error_code == 0) {
				/* Return a success */
				json_object_set_new(response, "result", json_integer(200));
			} else {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}

/* Thread to handle incoming events */
static void *janus_gelfevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining GelfEventHandler handler thread\n");
	json_t *event = NULL;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;

		/* Handle event */
		while(TRUE) {
			/* Add custom fields */
			json_t *output = json_object();

			int type = json_integer_value(json_object_get(event, "type"));
			const char *short_message = janus_events_type_to_name(type);
			json_t *microtimestamp = json_object_get(event, "timestamp");
			if(microtimestamp && json_is_integer(microtimestamp)) {
				double created_timestamp = (double)json_integer_value(microtimestamp) / 1000000;
				json_object_set(output, "timestamp", json_real(created_timestamp));
			} else {
				json_object_set(output, "timestamp", json_real(janus_get_real_time()));
			}
			json_object_set(output, "host", json_object_get(event, "emitter"));
			json_object_set(output, "version", json_string("1.1"));
			json_object_set(output, "level", json_object_get(event, "type"));
			json_object_set(output, "short_message", json_string(short_message));
			json_object_set(output, "full_message", event);

			if(janus_gelfevh_send(json_dumps(output, json_format)) < 0) {
				JANUS_LOG(LOG_WARN, "Couldn't send event to GELF, reconnect?, or event was null: %s\n",
					json_dumps(output, json_format));
			}
			json_decref(output);
			output = NULL;

			break;
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving GELF Event handler thread\n");
	return NULL;
}
