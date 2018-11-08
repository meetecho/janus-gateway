/*! \file   janus_prometheusevh.cc 
 * \author Dmitry Yudin <yudind@gmail.com>
 * \copyright GNU General Public License v3
 * \brief  Janus PrometheusEventHandler plugin
 * \details  This is a Prometheus client-side server implemented as event handler plugin for Janus
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

extern "C" {
#include "eventhandler.h"
#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"
}

#include <math.h>

/* Plugin information */
#define JANUS_PROMETHEUS_VERSION		1
#define JANUS_PROMETHEUS_VERSION_STRING	"0.0.1"
#define JANUS_PROMETHEUS_DESCRIPTION	"This is a Prometheus client-side server implemented as event handler plugin for Janus."
#define JANUS_PROMETHEUS_NAME			"JANUS PrometheusEventHandler plugin"
#define JANUS_PROMETHEUS_AUTHOR			"Meetecho s.r.l."
#define JANUS_PROMETHEUS_PACKAGE		"janus.eventhandler.prometheusevh"

/* Plugin methods */
extern "C" {
janus_eventhandler *create(void);
int janus_promevh_init(const char *config_path);
void janus_promevh_destroy(void);
int janus_promevh_get_api_compatibility(void);
int janus_promevh_get_version(void);
const char *janus_promevh_get_version_string(void);
const char *janus_promevh_get_description(void);
const char *janus_promevh_get_name(void);
const char *janus_promevh_get_author(void);
const char *janus_promevh_get_package(void);
void janus_promevh_incoming_event(json_t *event);
json_t *janus_promevh_handle_request(json_t *request);
}

/* Event handler setup */
static janus_eventhandler janus_promevh = {

// Can't prefill with JANUS_EVENTHANDLER_INIT macro due to g++:
// error: too many initializers for 'janus_eventhandler'
//	JANUS_EVENTHANDLER_INIT (
	.init = janus_promevh_init,
	.destroy = janus_promevh_destroy,
	.get_api_compatibility = janus_promevh_get_api_compatibility,
	.get_version = janus_promevh_get_version,
	.get_version_string = janus_promevh_get_version_string,
	.get_description = janus_promevh_get_description,
	.get_name = janus_promevh_get_name,
	.get_author = janus_promevh_get_author,
	.get_package = janus_promevh_get_package,
	.incoming_event = janus_promevh_incoming_event,
	.handle_request = janus_promevh_handle_request,
	.events_mask = JANUS_EVENT_TYPE_NONE,
};

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_PROMETHEUS_NAME);
	return &janus_promevh;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *handler_thread;
static void *janus_promevh_handler(void *data);

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static json_t exit_event;
static void janus_promevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
#if 0
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
	{"grouping", JANUS_JSON_BOOL, 0}
};
#endif
/* Error codes (for the tweaking via Admin API */
//#define JANUS_PROMETHEUS_ERROR_INVALID_REQUEST		411
#define JANUS_PROMETHEUS_ERROR_MISSING_ELEMENT		412
#define JANUS_PROMETHEUS_ERROR_INVALID_ELEMENT		413
//#define JANUS_PROMETHEUS_ERROR_UNKNOWN_ERROR		499


/* Plugin implementation */
int janus_promevh_init(const char *config_path) {
	gboolean success = TRUE;
	char *host = NULL;
	int port = 9091;

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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_PROMETHEUS_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	/* Setup the event handler, if required */
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "enabled");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Prometheus event handler disabled\n");
		goto error;
	}

	/* Which events should we subscribe to? */
	item = janus_config_get_item_drilldown(config, "general", "events");
	if(item && item->value)
		janus_events_edit_events_mask(item->value, &janus_promevh.events_mask);

	/* Handle configuration, starting from the server details */
	item = janus_config_get_item_drilldown(config, "general", "host");
	if(item && item->value)
		host = g_strdup(item->value);
	else
		host = g_strdup("localhost");

	item = janus_config_get_item_drilldown(config, "general", "port");
	if(item && item->value)
		port = atoi(item->value);

	/* Connect */
	JANUS_LOG(LOG_VERB, "PrometheusEventHandler: Creating Prometheus http server at %s:%u...\n", host, port);

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_promevh_event_free);
	g_atomic_int_set(&initialized, 1);

	GError *error;
	handler_thread = g_thread_try_new("janus promevh handler", janus_promevh_handler, NULL, &error);
	if(!handler_thread) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the PrometheusEventHandler handler thread...\n", error->code, error->message ? error->message : "??");
		goto error;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Setup of Prometheus event handler completed\n");
	goto done;

error:
	/* If we got here, something went wrong */
	success = FALSE;

	/* Fall through */
done:
	if(host)
		g_free((char *)host);
	if(config)
		janus_config_destroy(config);
	if(!success) {
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_PROMETHEUS_NAME);
	return 0;
}

void janus_promevh_destroy(void) {
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

	// destroy here

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_PROMETHEUS_NAME);
}

int janus_promevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_promevh_get_version(void) {
	return JANUS_PROMETHEUS_VERSION;
}

const char *janus_promevh_get_version_string(void) {
	return JANUS_PROMETHEUS_VERSION_STRING;
}

const char *janus_promevh_get_description(void) {
	return JANUS_PROMETHEUS_DESCRIPTION;
}

const char *janus_promevh_get_name(void) {
	return JANUS_PROMETHEUS_NAME;
}

const char *janus_promevh_get_author(void) {
	return JANUS_PROMETHEUS_AUTHOR;
}

const char *janus_promevh_get_package(void) {
	return JANUS_PROMETHEUS_PACKAGE;
}

void janus_promevh_incoming_event(json_t *event) {
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

json_t *janus_promevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	const char *request_text;
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_PROMETHEUS_ERROR_MISSING_ELEMENT, JANUS_PROMETHEUS_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	request_text = json_string_value(json_object_get(request, "request"));
#if 0
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_PROMETHEUS_ERROR_MISSING_ELEMENT, JANUS_PROMETHEUS_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Events */
		if(json_object_get(request, "events"))
			janus_events_edit_events_mask(json_string_value(json_object_get(request, "events")), &janus_promevh.events_mask);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_PROMETHEUS_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}
#endif
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
static void *janus_promevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining PrometheusEventHandler handler thread\n");
	json_t *event = NULL;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		event = (json_t *)g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;

		if(!g_atomic_int_get(&stopping)) {
			// process event here
		}

		/* Done, let's unref the event */
		json_decref(event);
	}
	JANUS_LOG(LOG_VERB, "Leaving PrometheusEventHandler handler thread\n");
	return NULL;
}


#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <stdio.h>

#include <prometheus/exposer.h>
#include <prometheus/registry.h>

// reference test to check library load
int test_prometheus() {
  	// create an http server running on port 8080
  	prometheus::Exposer exposer{"0.0.0.0:9091"};
  	printf("Start listent at 0.0.0.0:9091\n");

  	// create a metrics registry with component=main labels applied to all its metrics
  	auto registry = std::make_shared<prometheus::Registry>();

  	// add a new counter family to the registry (families combine values with the same name, but distinct label dimensions)
	prometheus::Family<prometheus::Counter>& 
	counter_family = prometheus::BuildCounter()
                             .Name("time_running_seconds")
                             .Help("How many seconds is this server running?")
                             .Labels({{"label", "value"}})
                             .Register(*registry);

  	// add a counter to the metric family
	prometheus::Counter&
	second_counter = counter_family.Add(
      {{"another_label", "value"}, {"yet_another_label", "value"}});

  	// ask the exposer to scrape the registry on incoming scrapes
  	exposer.RegisterCollectable(registry);

  	for (;;) {
    	std::this_thread::sleep_for(std::chrono::seconds(2));
    	// increment the counter by one (second)
		second_counter.Increment();
		printf ("increment!!!\n");
  	}
  	return 0;
}
