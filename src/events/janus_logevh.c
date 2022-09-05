/*! \file   janus_logevh.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus SampleEventHandler plugin
 * \details  This is a trivial event handler plugin for Janus, which is only
 * there to showcase how you can handle an event coming from the Janus core
 * or one of the plugins. This specific plugin forwards every event it receives
 * to a web server via an HTTP POST request, using libcurl.
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>
#include <sys/time.h>


#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"


/* Plugin information */
#define JANUS_LOGEVH_VERSION			1
#define JANUS_LOGEVH_VERSION_STRING	"0.0.1"
#define JANUS_LOGEVH_DESCRIPTION    "This is a trivial log event handler plugin for Janus, which prints the events in the log stream"
#define JANUS_LOGEVH_NAME			"JANUS LogEventHandler plugin"
#define JANUS_LOGEVH_AUTHOR			"Nuance"
#define JANUS_LOGEVH_PACKAGE		"janus.eventhandler.logevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_logevh_init(const char *config_path);
void janus_logevh_destroy(void);
int janus_logevh_get_api_compatibility(void);
int janus_logevh_get_version(void);
const char *janus_logevh_get_version_string(void);
const char *janus_logevh_get_description(void);
const char *janus_logevh_get_name(void);
const char *janus_logevh_get_author(void);
const char *janus_logevh_get_package(void);
void janus_logevh_incoming_event(json_t *event);
json_t *janus_logevh_handle_request(json_t *request);

/* Event handler setup */
static janus_eventhandler janus_logevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_logevh_init,
		.destroy = janus_logevh_destroy,

		.get_api_compatibility = janus_logevh_get_api_compatibility,
		.get_version = janus_logevh_get_version,
		.get_version_string = janus_logevh_get_version_string,
		.get_description = janus_logevh_get_description,
		.get_name = janus_logevh_get_name,
		.get_author = janus_logevh_get_author,
		.get_package = janus_logevh_get_package,

		.incoming_event = janus_logevh_incoming_event,
		.handle_request = janus_logevh_handle_request,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_LOGEVH_NAME);
	return &janus_logevh;
}

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *handler_thread;
static void *janus_logevh_handler(void *data);
static janus_mutex evh_mutex;

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static json_t exit_event;
static void janus_logevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_LOGEVH_ERROR_INVALID_REQUEST		411
#define JANUS_LOGEVH_ERROR_MISSING_ELEMENT		412
#define JANUS_LOGEVH_ERROR_INVALID_ELEMENT		413
#define JANUS_LOGEVH_ERROR_UNKNOWN_ERROR			499

/*! \brief Method for logging the event to the console
 * @param[in] event Event to log to the console */
void log_event(json_t* event);

/* Plugin implementation */
int janus_logevh_init(const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_LOGEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_LOGEVH_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_LOGEVH_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

		/* Setup the sample event handler, if required */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Login event handler disabled\n");
		} else {
			/* Which events should we subscribe to? */
			item = janus_config_get(config, config_general, janus_config_type_item, "events");
			if(item && item->value) {
				janus_events_edit_events_mask(item->value, &janus_logevh.events_mask);
				enabled = TRUE;
			}
		}
	}

	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		JANUS_LOG(LOG_FATAL, "Log event handler not enabled/needed, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_logevh_event_free);
	janus_mutex_init(&evh_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming events */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus logevh handler", janus_logevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the LogEventHandler handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_LOGEVH_NAME);
	return 0;
}

void janus_logevh_destroy(void) {
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

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_LOGEVH_NAME);
}

int janus_logevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_logevh_get_version(void) {
	return JANUS_LOGEVH_VERSION;
}

const char *janus_logevh_get_version_string(void) {
	return JANUS_LOGEVH_VERSION_STRING;
}

const char *janus_logevh_get_description(void) {
	return JANUS_LOGEVH_DESCRIPTION;
}

const char *janus_logevh_get_name(void) {
	return JANUS_LOGEVH_NAME;
}

const char *janus_logevh_get_author(void) {
	return JANUS_LOGEVH_AUTHOR;
}

const char *janus_logevh_get_package(void) {
	return JANUS_LOGEVH_PACKAGE;
}

void janus_logevh_incoming_event(json_t *event) {
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

json_t *janus_logevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_LOGEVH_ERROR_MISSING_ELEMENT, JANUS_LOGEVH_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_LOGEVH_ERROR_MISSING_ELEMENT, JANUS_LOGEVH_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Parameters we can change */
		const char *req_events = NULL;
		/* Events */
		if(json_object_get(request, "events"))
			req_events = json_string_value(json_object_get(request, "events"));
		janus_mutex_lock(&evh_mutex);
		if(req_events)
			janus_events_edit_events_mask(req_events, &janus_logevh.events_mask);
		janus_mutex_unlock(&evh_mutex);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_LOGEVH_ERROR_INVALID_REQUEST;
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
static void *janus_logevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining LogEventHandler handler thread\n");
	json_t *event = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;

		log_event(event);
		json_decref(event);
	}
	JANUS_LOG(LOG_VERB, "Leaving LogEventHandler handler thread\n");
	return NULL;
}


/* BB - Log event to the console */
void log_event(json_t* event) {
	/* Create container object */
	json_t *container_event = json_object();

	/* Get timestamp */
	char timestamp[128];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	snprintf(timestamp, sizeof(timestamp), "%ld.%03ld", tv.tv_sec, tv.tv_usec/1000);

	/* Add the timestamp to the object */
	json_object_set_new(container_event, "timestamp", json_string(timestamp));
	json_object_set(container_event, "event", event);

	/* Log the container event by printing it */
	char* event_string = json_dumps(container_event, JSON_COMPACT);
	JANUS_PRINT("[WEBRTC_EVENT] %s\n", event_string);
	/* Delete the container event */
	json_decref(container_event);
	free(event_string);
	container_event = NULL;
}
/* BB end */

