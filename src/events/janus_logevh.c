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
		if(event == &exit_event)
			break;

		while(TRUE) {

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
				case JANUS_EVENT_TYPE_EXTERNAL:
					/* This is an external event, not originated by Janus itself
					 * or any of its plugins, but from an ad-hoc Admin API request
					 * instead. As such, the content of the event is not bound to
					 * any rules (apart from the fact that it needs to be a JSON
					 * object), but can be whatever the external source thought
					 * appropriate. In order to facilitare life to recipients, all
					 * external events must contain a "schema" property, which anyway
					 * is not bound to any rules either. As an example:
						{
						   "type": 4,
						   "timestamp": 28381185382,
						   "event": {
							  "schema": "my.custom.source",
							  "data": {
								 "whatever": "youwant"
							  }
						   }
						}
					*/
					break;
				default:
					JANUS_LOG(LOG_WARN, "Unknown type of event '%d'\n", type);
					break;
			}
			log_event(event);
			json_decref(event);

			event = g_async_queue_try_pop(events);
			if(event == NULL || event == &exit_event)
				break;
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving LogEventHandler handler thread\n");
	return NULL;
}


/* BB - Log event to the console */
void log_event(json_t* event) {

	/* Get timestamp */
	char timestamp[128];
	struct timeval tv;
	gettimeofday(&tv, NULL);
	snprintf(timestamp, 127, "%ld.%03ld", tv.tv_sec, tv.tv_usec/1000);

	/* Create container object */
	json_t *container_event = json_object();

	/* Add the timestamp to the object */
	json_object_set_new(container_event, "timestamp", json_string(timestamp));
	json_object_set(container_event, "event", event);

	/* Log the container event by printing it */
	char* event_string = json_dumps(container_event, JSON_COMPACT);
	JANUS_PRINT("[WEBRTC_EVENT] %s\n", event_string);

	/* Delete the container event */
	json_decref(container_event);
}
/* BB end */

