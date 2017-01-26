/*! \file   janus_sampleevh.c
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
#include <curl/curl.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_SAMPLEEVH_VERSION			1
#define JANUS_SAMPLEEVH_VERSION_STRING	"0.0.1"
#define JANUS_SAMPLEEVH_DESCRIPTION		"This is a trivial sample event handler plugin for Janus, which forwards events via HTTP POST."
#define JANUS_SAMPLEEVH_NAME			"JANUS SampleEventHandler plugin"
#define JANUS_SAMPLEEVH_AUTHOR			"Meetecho s.r.l."
#define JANUS_SAMPLEEVH_PACKAGE			"janus.eventhandler.sampleevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_sampleevh_init(const char *config_path);
void janus_sampleevh_destroy(void);
int janus_sampleevh_get_api_compatibility(void);
int janus_sampleevh_get_version(void);
const char *janus_sampleevh_get_version_string(void);
const char *janus_sampleevh_get_description(void);
const char *janus_sampleevh_get_name(void);
const char *janus_sampleevh_get_author(void);
const char *janus_sampleevh_get_package(void);
void janus_sampleevh_incoming_event(json_t *event);

/* Event handler setup */
static janus_eventhandler janus_sampleevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_sampleevh_init,
		.destroy = janus_sampleevh_destroy,

		.get_api_compatibility = janus_sampleevh_get_api_compatibility,
		.get_version = janus_sampleevh_get_version,
		.get_version_string = janus_sampleevh_get_version_string,
		.get_description = janus_sampleevh_get_description,
		.get_name = janus_sampleevh_get_name,
		.get_author = janus_sampleevh_get_author,
		.get_package = janus_sampleevh_get_package,
		
		.incoming_event = janus_sampleevh_incoming_event,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SAMPLEEVH_NAME);
	return &janus_sampleevh;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *handler_thread;
static void *janus_sampleevh_handler(void *data);

/* Queue of events to handle */
static GAsyncQueue *events = NULL;
static gboolean group_events = FALSE;
static json_t exit_event;
static void janus_sampleevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* Retransmission management */
static int max_retransmissions = 5;
static int retransmissions_backoff = 100;

/* Web backend to send the events to */
static char *backend = NULL;
static char *backend_user = NULL, *backend_pwd = NULL;
static size_t janus_sampleehv_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	return size*nmemb;
}

/* Plugin implementation */
int janus_sampleevh_init(const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_SAMPLEEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);

		/* Setup the sample event handler, if required */
		janus_config_item *item = janus_config_get_item_drilldown(config, "general", "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "Sample event handler disabled (Janus API)\n");
		} else {
			/* Backend to send events to */
			item = janus_config_get_item_drilldown(config, "general", "backend");
			if(!item || !item->value || strstr(item->value, "http") != item->value) {
				JANUS_LOG(LOG_WARN, "Missing or invalid backend\n");
			} else {
				backend = g_strdup(item->value);
				/* Any credentials needed? */
				item = janus_config_get_item_drilldown(config, "general", "backend_user");
				backend_user = (item && item->value) ? g_strdup(item->value) : NULL;
				item = janus_config_get_item_drilldown(config, "general", "backend_pwd");
				backend_pwd = (item && item->value) ? g_strdup(item->value) : NULL;
				/* Any specific setting for retransmissions? */
				item = janus_config_get_item_drilldown(config, "general", "max_retransmissions");
				if(item && item->value) {
					int mr = atoi(item->value);
					if(mr < 0) {
						JANUS_LOG(LOG_WARN, "Invalid negative value for 'max_retransmissions', using default (%d)\n", max_retransmissions);
					} else if(mr == 0) {
						JANUS_LOG(LOG_WARN, "Retransmissions disabled (max_retransmissions=0)\n");
						max_retransmissions = 0;
					} else {
						max_retransmissions = mr;
					}
				}
				item = janus_config_get_item_drilldown(config, "general", "retransmissions_backoff");
				if(item && item->value) {
					int rb = atoi(item->value);
					if(rb <= 0) {
						JANUS_LOG(LOG_WARN, "Invalid negative or null value for 'retransmissions_backoff', using default (%d)\n", retransmissions_backoff);
					} else {
						retransmissions_backoff = rb;
					}
				}
				/* Which events should we subscribe to? */
				item = janus_config_get_item_drilldown(config, "general", "events");
				if(item && item->value) {
					if(!strcasecmp(item->value, "none")) {
						/* Don't subscribe to anything at all */
						janus_flags_reset(&janus_sampleevh.events_mask);
					} else if(!strcasecmp(item->value, "all")) {
						/* Subscribe to everything */
						janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_ALL);
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
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_SESSION);
										} else if(!strcasecmp(index, "handles")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_HANDLE);
										} else if(!strcasecmp(index, "jsep")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_JSEP);
										} else if(!strcasecmp(index, "webrtc")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_WEBRTC);
										} else if(!strcasecmp(index, "media")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_MEDIA);
										} else if(!strcasecmp(index, "plugins")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_PLUGIN);
										} else if(!strcasecmp(index, "transports")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_TRANSPORT);
										} else if(!strcasecmp(index, "core")) {
											janus_flags_set(&janus_sampleevh.events_mask, JANUS_EVENT_TYPE_CORE);
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
				group_events = item && item->value && janus_is_true(item->value);
				/* Done */
				enabled = TRUE;
			}
		}
	}

	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		JANUS_LOG(LOG_FATAL, "Sample event handler not enabled/needed, giving up...\n");
		return -1;	/* No point in keeping the plugin loaded */
	}
	JANUS_LOG(LOG_VERB, "Sample event handler configured: %s\n", backend);

	/* Initialize libcurl, needed for forwarding events via HTTP POST */
	curl_global_init(CURL_GLOBAL_ALL);

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_sampleevh_event_free);
	
	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming events */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus sampleevh handler", janus_sampleevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SampleEventHandler handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_SAMPLEEVH_NAME);
	return 0;
}

void janus_sampleevh_destroy(void) {
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
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SAMPLEEVH_NAME);
}

int janus_sampleevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_sampleevh_get_version(void) {
	return JANUS_SAMPLEEVH_VERSION;
}

const char *janus_sampleevh_get_version_string(void) {
	return JANUS_SAMPLEEVH_VERSION_STRING;
}

const char *janus_sampleevh_get_description(void) {
	return JANUS_SAMPLEEVH_DESCRIPTION;
}

const char *janus_sampleevh_get_name(void) {
	return JANUS_SAMPLEEVH_NAME;
}

const char *janus_sampleevh_get_author(void) {
	return JANUS_SAMPLEEVH_AUTHOR;
}

const char *janus_sampleevh_get_package(void) {
	return JANUS_SAMPLEEVH_PACKAGE;
}

void janus_sampleevh_incoming_event(json_t *event) {
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
static void *janus_sampleevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining SampleEventHandler handler thread\n");
	json_t *event = NULL, *output = NULL;
	char *event_text = NULL;
	int count = 0, max = group_events ? 100 : 1;
	int retransmit = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		if(!retransmit) {
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

			/* Since this a simple plugin, it does the same for all events: so just convert to string... */
			event_text = json_dumps(output, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		}
		/* Whether we just prepared the event or this is a retransmission, send it via HTTP POST */
		CURLcode res;
		struct curl_slist *headers = NULL;
		CURL *curl = curl_easy_init();
		if(curl == NULL) {
			JANUS_LOG(LOG_ERR, "Error initializing CURL context\n");
			goto done;
		}
		curl_easy_setopt(curl, CURLOPT_URL, backend);
		headers = curl_slist_append(headers, "Accept: application/json");
		headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, "charsets: utf-8");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, event_text);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, janus_sampleehv_write_data);
		/* Any credentials? */
		if(backend_user != NULL && backend_pwd != NULL) {
			curl_easy_setopt(curl, CURLOPT_USERNAME, backend_user);
			curl_easy_setopt(curl, CURLOPT_PASSWORD, backend_pwd);
		}
		/* Don't wait forever (let's say, 10 seconds) */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
		/* Send the request */
		res = curl_easy_perform(curl);
		if(res != CURLE_OK) {
			JANUS_LOG(LOG_ERR, "Couldn't relay event to the backend: %s\n", curl_easy_strerror(res));
			if(max_retransmissions > 0) {
				/* Retransmissions enabled, let's try again */
				if(retransmit == max_retransmissions) {
					retransmit = 0;
					JANUS_LOG(LOG_WARN, "Maximum number of retransmissions reached (%d), event lost...\n", max_retransmissions);
				} else {
					int next = retransmissions_backoff * (pow(2, retransmit));
					JANUS_LOG(LOG_WARN, "Retransmitting event in %d ms...\n", next);
					g_usleep(next*1000);
					retransmit++;
				}
			} else {
				JANUS_LOG(LOG_WARN, "Retransmissions disabled, event lost...\n");
			}
		} else {
			JANUS_LOG(LOG_DBG, "Event sent!\n");
			retransmit = 0;
		}
done:
		/* Cleanup */
		if(curl)
			curl_easy_cleanup(curl);
		if(headers)
			curl_slist_free_all(headers);
		if(!retransmit)
			g_free(event_text);

		/* Done, let's unref the event */
		json_decref(output);
		output = NULL;
	}
	JANUS_LOG(LOG_VERB, "Leaving SampleEventHandler handler thread\n");
	return NULL;
}
