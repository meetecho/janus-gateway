/*! \file    events.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Event handler notifications
 * \details  Event handler plugins can receive events from the Janus core
 * and other plugins, in order to handle them somehow. This methods
 * provide helpers to notify events to such handlers. 
 * 
 * \ingroup core
 * \ref core
 */
 
#include <stdarg.h>

#include "events.h"
#include "utils.h"

static gboolean eventsenabled = FALSE;
static GHashTable *eventhandlers = NULL;

static GAsyncQueue *events = NULL;
static json_t exit_event;

static GThread *events_thread;
void *janus_events_thread(void *data);

int janus_events_init(gboolean enabled, GHashTable *handlers) {
	/* We setup a thread for passing events to the handlers */
	GError *error = NULL;
	events_thread = g_thread_try_new("janus events thread", janus_events_thread, NULL, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Events handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	events = g_async_queue_new();
	eventhandlers = handlers;
	eventsenabled = enabled;
	return 0;
}

void janus_events_deinit(void) {
	eventsenabled = FALSE;

	g_async_queue_push(events, &exit_event);
	if(events_thread != NULL) {
		g_thread_join(events_thread);
		events_thread = NULL;
	}
	if(events != NULL)
		g_async_queue_unref(events);
}

gboolean janus_events_is_enabled(void) {
	return eventsenabled;
}

void janus_events_notify_handlers(int type, guint64 session_id, ...) {
	/* This method has a variable list of arguments, depending on the event type */
	va_list args;
	va_start(args, session_id);

	if(!eventsenabled || eventhandlers == NULL || g_hash_table_size(eventhandlers) == 0) {
		/* Event handlers disabled, or no event handler plugins available: free resources, if needed */
		if(type == JANUS_EVENT_TYPE_MEDIA || type == JANUS_EVENT_TYPE_WEBRTC) {
			/* These events allocate a json_t object for their data, skip some arguments and unref it */
			va_arg(args, guint64);
			json_t *body = va_arg(args, json_t *);
			json_decref(body);
		} else if(type == JANUS_EVENT_TYPE_CORE) {
			/* Core events also allocate a json_t object for its data, unref it */
			json_t *body = va_arg(args, json_t *);
			json_decref(body);
		} else if(type == JANUS_EVENT_TYPE_SESSION) {
			/* Session events may allocate a json_t object for transport-related info, unref it */
			va_arg(args, char *);
			json_t *transport = va_arg(args, json_t *);
			if(transport != NULL)
				json_decref(transport);
		} else if(type == JANUS_EVENT_TYPE_PLUGIN) {
			/* Plugin originated events also allocate a json_t object for the plugin data, skip some arguments and unref it */
			va_arg(args, guint64);
			va_arg(args, char *);
			json_t *data = va_arg(args, json_t *);
			json_decref(data);
		} else if(type == JANUS_EVENT_TYPE_TRANSPORT) {
			/* Transport originated events also allocate a json_t object for the transport data, skip some arguments and unref it */
			va_arg(args, char *);
			va_arg(args, void *);
			json_t *data = va_arg(args, json_t *);
			json_decref(data);
		}
		va_end(args);
		return;
	}

	/* Prepare the event to notify as a Jansson json_t object */
	json_t *event = json_object();
	json_object_set_new(event, "type", json_integer(type));
	json_object_set_new(event, "timestamp", json_integer(janus_get_real_time()));
	if(type != JANUS_EVENT_TYPE_CORE) {			/* Core events don't have a session ID */
		if(session_id == 0 && (type == JANUS_EVENT_TYPE_PLUGIN || type == JANUS_EVENT_TYPE_TRANSPORT)) {
			/* ... but plugin/transport events may not have one either */
		} else {
			json_object_set_new(event, "session_id", json_integer(session_id));
		}
	}
	json_t *body = NULL;
	if(type != JANUS_EVENT_TYPE_MEDIA && type != JANUS_EVENT_TYPE_WEBRTC && type != JANUS_EVENT_TYPE_CORE)
		body = json_object();

	/* Each type may require different arguments */
	switch(type) {
		case JANUS_EVENT_TYPE_SESSION: {
			/* For sessions, there's just a generic event name (what happened) */
			char *name = va_arg(args, char *);
			json_object_set_new(body, "name", json_string(name));
			json_t *transport = va_arg(args, json_t *);
			if(transport != NULL)
				json_object_set(body, "transport", transport);
			break;
		}
		case JANUS_EVENT_TYPE_HANDLE: {
			/* For handles, there's the handle ID, a generic event name (what happened)
			 * and the plugin package name this handle is (or was) attached to */
			guint64 handle_id = va_arg(args, guint64);
			json_object_set_new(event, "handle_id", json_integer(handle_id));
			char *name = va_arg(args, char *);
			json_object_set_new(body, "name", json_string(name));
			char *plugin = va_arg(args, char *);
			json_object_set_new(body, "plugin", json_string(plugin));
			/* Handle-related events may include an opaque ID provided by who's using the plugin:
			 * in event handlers, it may be useful for inter-handle mappings or other things */
			char *opaque_id = va_arg(args, char *);
			if(opaque_id != NULL)
				json_object_set_new(body, "opaque_id", json_string(opaque_id));
			break;
		}
		case JANUS_EVENT_TYPE_JSEP: {
			/* For JSEP-related events, there's the handle ID, whether the SDP is local or remote, the JSEP type and the SDP itself */
			guint64 handle_id = va_arg(args, guint64);
			json_object_set_new(event, "handle_id", json_integer(handle_id));
			char *owner = va_arg(args, char *);
			json_object_set_new(body, "owner", json_string(owner));
			json_t *jsep = json_object();
			char *sdp_type = va_arg(args, char *);
			json_object_set_new(jsep, "type", json_string(sdp_type));
			char *sdp = va_arg(args, char *);
			json_object_set_new(jsep, "sdp", json_string(sdp));
			json_object_set_new(body, "jsep", jsep);
			break;
		}
		case JANUS_EVENT_TYPE_WEBRTC:
		case JANUS_EVENT_TYPE_MEDIA: {
			/* For WebRTC and media-related events, there's the handle ID and a json_t object with info on what happened */
			guint64 handle_id = va_arg(args, guint64);
			json_object_set_new(event, "handle_id", json_integer(handle_id));
			/* The body is what we get from the event */
			body = va_arg(args, json_t *);
			break;
		}
		case JANUS_EVENT_TYPE_PLUGIN: {
			/* For plugin-originated events, there's the handle ID, the plugin name, and a generic, plugin specific, json_t object */
			guint64 handle_id = va_arg(args, guint64);
			if(handle_id > 0)	/* Plugins and transports may not specify a session and handle ID for out of context events */
				json_object_set_new(event, "handle_id", json_integer(handle_id));
			char *name = va_arg(args, char *);
			json_object_set_new(body, "plugin", json_string(name));
			json_t *data = va_arg(args, json_t *);
			json_object_set(body, "data", data);
			break;
		}
		case JANUS_EVENT_TYPE_TRANSPORT: {
			char *name = va_arg(args, char *);
			json_object_set_new(body, "transport", json_string(name));
			char *instance = va_arg(args, void *);
			char id[32];
			memset(id, 0, sizeof(id));
			g_snprintf(id, sizeof(id), "%p", instance);
			json_object_set_new(body, "id", json_string(id));
			json_t *data = va_arg(args, json_t *);
			json_object_set(body, "data", data);
			break;
		}
		case JANUS_EVENT_TYPE_CORE: {
			/* For core-related events, there's a json_t object with info on what happened */
			body = va_arg(args, json_t *);
			break;
		}
		default:
			JANUS_LOG(LOG_WARN, "Unknown event type '%d'\n", type);
			json_decref(event);
			json_decref(body);
			return;
	}
	json_object_set_new(event, "event", body);
	va_end(args);

	/* Enqueue the event */
	g_async_queue_push(events, event);
}

void *janus_events_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Events handler thread\n");
	json_t *event = NULL;

	while(eventsenabled) {
		/* Any event in queue? */
		event = g_async_queue_pop(events);
		if(event == NULL)
			continue;
		if(event == &exit_event)
			break;

		/* Notify all interested handlers, increasing the event reference to make sure it's not lost because of errors */
		int type = json_integer_value(json_object_get(event, "type"));
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, eventhandlers);
		json_incref(event);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_eventhandler *e = value;
			if(e == NULL)
				continue;
			if(!janus_flags_is_set(&e->events_mask, type))
				continue;
			e->incoming_event(event);
		}
		json_decref(event);

		/* Unref the final event reference, interested handlers will have their own reference */
		json_decref(event);
	}

	JANUS_LOG(LOG_VERB, "Leaving EchoTest handler thread\n");
	return NULL;
}
