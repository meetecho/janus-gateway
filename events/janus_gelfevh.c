/*! \file   janus_gelfevh.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus GelfEventHandler plugin
 * \details  This is a trivial event handler plugin for Janus, which is only
 * there to showcase how you can handle an event coming from the Janus core
 * or one of the plugins. This specific plugin forwards every event it receives
 * to a web server via an UDP request, using libcurl.
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>
// #include <curl/curl.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../ip-utils.h"

/* Plugin information */
#define JANUS_GELFEVH_VERSION			1
#define JANUS_GELFEVH_VERSION_STRING 	"0.0.1"
#define JANUS_GELFEVH_DESCRIPTION 		"This is a simple event handler plugin for Janus, which forwards events via UDP to GELF server."
#define JANUS_GELFEVH_NAME 				"JANUS GelfEventHandler plugin"
#define JANUS_GELFEVH_AUTHOR 			"Meetecho s.r.l."
#define JANUS_GELFEVH_PACKAGE			"janus.eventhandler.gelfevh"

#define MAX_GELF_LOG_LEN 8192

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

/* Gelf backend to send the events to */
static char *backend = NULL;
static char *port = NULL;
static int sockfd;
//static struct sockaddr_in servaddr;

/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
	{"backend", JSON_STRING, 0},
	{"port", JSON_STRING, 0}
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_GELFEVH_ERROR_INVALID_REQUEST		411
#define JANUS_GELFEVH_ERROR_MISSING_ELEMENT 	412
#define JANUS_GELFEVH_ERROR_INVALID_ELEMENT 	413
#define JANUS_GELFEVH_ERROR_UNKNOWN_ERROR 		499

/* Plugin implementation */
static void janus_gelfevh_connect(void) {
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	struct sockaddr_in servaddr;

	if(getaddrinfo(backend, NULL, NULL, &res) != 0 ||
		janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
		janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		if(res)
			freeaddrinfo(res);
		JANUS_LOG(LOG_ERR, "Could not resolve address (%s)...\n", backend);
		return;
	}
	const char *host = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	freeaddrinfo(res);

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		JANUS_LOG(LOG_ERR, "Socket creation failed");
		return;
	}

	memset(&servaddr, 0, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(port));
	servaddr.sin_addr.s_addr = inet_addr(host);

	if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		JANUS_LOG(LOG_WARN, "Connect to Gelf host failed\n");
		return;
	}
	JANUS_LOG(LOG_INFO, "Connected to GELF backend: [%s:%s]\n", host, port);
}

static int janus_gelfevh_send(char *message) {
	//JANUS_LOG(LOG_WARN, "Sending event to GELF: %s\n", message);
	if(!message) {
		JANUS_LOG(LOG_WARN, "Message is NULL, not sending to Gelf!\n");
		return -1;
	}
	if (write(sockfd, message, MAX_GELF_LOG_LEN) < 0) {
		//close(sockfd);
		return -1;
	}
	return 1;
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
		janus_config_item *item, *item_backend, *item_port;
		item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Gelf event handler disabled (Janus API)\n");
			goto done;
		}
		item_backend = janus_config_get(config, config_general, janus_config_type_item, "backend");
		if(!item_backend || !item_backend->value) {
			JANUS_LOG(LOG_WARN, "Missing or invalid backend\n");
			goto done;
		}
		item_port = janus_config_get(config, config_general, janus_config_type_item, "port");
		if(!item_port || !item_port->value) {
			JANUS_LOG(LOG_WARN, "Missing or invalid port\n");
			goto done;
		}
		backend = g_strdup(item_backend->value);
		port = g_strdup(item_port->value);
		/* Which events should we subscribe to? */
		item = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(item && item->value)
			janus_events_edit_events_mask(item->value, &janus_gelfevh.events_mask);
		/* Compact, so no spaces between separators */
		json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
		/* Done */
		enabled = TRUE;
	}
done:
	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		JANUS_LOG(LOG_FATAL, "Gelf event handler not enabled/needed, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}
	JANUS_LOG(LOG_VERB, "Gelf event handler configured: %s:%s\n", backend, port);

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_gelfevh_event_free);
	janus_mutex_init(&evh_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming events */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus gelfevh handler", janus_gelfevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the GelfEventHandler handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_GELFEVH_NAME);
	janus_gelfevh_connect();
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
	//JANUS_LOG(LOG_WARN, "Got event: %s\n", json_dumps(event, json_format));
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
		/* Events */
		if(json_object_get(request, "events"))
			req_events = json_string_value(json_object_get(request, "events"));
		/* Backend stuff */
		if(json_object_get(request, "backend"))
			req_backend = json_string_value(json_object_get(request, "backend"));
		if(json_object_get(request, "port"))
			req_port = json_string_value(json_object_get(request, "port"));
		if(req_backend && req_port) {
			/* Invalid backend address, port */
			error_code = JANUS_GELFEVH_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, sizeof(error_cause), "Invalid backend URI '%s:%s'", req_backend, req_port);
			goto plugin_response;
		}
		/* If we got here, we can enforce */
		if(req_events)
			janus_events_edit_events_mask(req_events, &janus_gelfevh.events_mask);
		if(req_backend) {
			janus_mutex_lock(&evh_mutex);
			if(req_backend && req_port) {
				g_free(backend);
				g_free(port);
				backend = g_strdup(req_backend);
				port = g_strdup(req_port);
			}
			janus_mutex_unlock(&evh_mutex);
		}
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
	json_t *event = NULL, *output = NULL;
	static char *event_text = NULL;
	const char *short_message = NULL;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;
		output = NULL;

		while(TRUE) {
			/* Handle event */
			int type = json_integer_value(json_object_get(event, "type"));
			switch(type) {
				case JANUS_EVENT_TYPE_SESSION:
					short_message = "JANUS_EVENT_TYPE_SESSION";
					break;
				case JANUS_EVENT_TYPE_HANDLE:
					short_message = "JANUS_EVENT_TYPE_HANDLE";
					break;
				case JANUS_EVENT_TYPE_JSEP:
					short_message = "JANUS_EVENT_TYPE_JSEP";
					break;
				case JANUS_EVENT_TYPE_WEBRTC:
					short_message = "JANUS_EVENT_TYPE_WEBRTC";
					break;
				case JANUS_EVENT_TYPE_MEDIA:
					short_message = "JANUS_EVENT_TYPE_MEDIA";
					break;
				case JANUS_EVENT_TYPE_PLUGIN:
					short_message = "JANUS_EVENT_TYPE_PLUGIN";
					break;
				case JANUS_EVENT_TYPE_TRANSPORT:
					short_message = "JANUS_EVENT_TYPE_TRANSPORT";
					break;
				case JANUS_EVENT_TYPE_CORE:
				case JANUS_EVENT_TYPE_EXTERNAL:
					short_message = "JANUS_EVENT_TYPE_CORE";
					break;
				default:
					JANUS_LOG(LOG_WARN, "Unknown type of event '%d'\n", type);
					short_message = "UNKNOWN_JANUS_EVENT";
					break;
			}
			output = event;
			/* Add custom fields */
			json_t *microtimestamp = json_object_get(event, "timestamp");
			if(microtimestamp && json_is_integer(microtimestamp)) {
				double created_timestamp = (double)json_integer_value(microtimestamp) / 1000000;
				json_object_set(output, "timestamp", json_real(created_timestamp));
			}
			else {
				struct timeval t;
				gettimeofday(&t, NULL);
				double micro_timestamp = (double)(1000000 * t.tv_sec + t.tv_usec) / 1000000;
				json_object_set(output, "timestamp", json_real(micro_timestamp));
			}
			json_object_set(output, "version", json_string("1.1"));
			json_object_set(output, "host", json_string("janus"));
			json_object_set(output, "level", json_integer(1));
			json_object_set(output, "short_message", json_string(short_message));
			json_object_set(output, "full_message", json_object_get(event, "event"));
			/* Just convert to string... */
			event_text = json_dumps(output, json_format);
			if(janus_gelfevh_send(event_text) < 0) {
				JANUS_LOG(LOG_WARN, "Couldn't send event to GELF reconnect ... ?: %s\n", event_text);
			}
			break;
		}
		/* Done, let's unref the event */
		json_decref(output);
		output = NULL;
	}
	JANUS_LOG(LOG_VERB, "Leaving Gelf Event handler thread\n");
	return NULL;
}
