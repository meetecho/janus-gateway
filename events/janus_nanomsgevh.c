/*! \file   janus_nanomsgevh.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus NanomsgEventHandler plugin
 * \details  This is a trivial Nanomsg event handler plugin for Janus
 *
 * \ingroup eventhandlers
 * \ref eventhandlers
 */

#include "eventhandler.h"

#include <math.h>

#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <nanomsg/inproc.h>
#include <nanomsg/ipc.h>
#include <nanomsg/pipeline.h>

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"
#include "../events.h"


/* Plugin information */
#define JANUS_NANOMSGEVH_VERSION			1
#define JANUS_NANOMSGEVH_VERSION_STRING		"0.0.1"
#define JANUS_NANOMSGEVH_DESCRIPTION		"This is a trivial Nanomsg event handler plugin for Janus."
#define JANUS_NANOMSGEVH_NAME				"JANUS NanomsgEventHandler plugin"
#define JANUS_NANOMSGEVH_AUTHOR				"Meetecho s.r.l."
#define JANUS_NANOMSGEVH_PACKAGE			"janus.eventhandler.nanomsgevh"

/* Plugin methods */
janus_eventhandler *create(void);
int janus_nanomsgevh_init(const char *config_path);
void janus_nanomsgevh_destroy(void);
int janus_nanomsgevh_get_api_compatibility(void);
int janus_nanomsgevh_get_version(void);
const char *janus_nanomsgevh_get_version_string(void);
const char *janus_nanomsgevh_get_description(void);
const char *janus_nanomsgevh_get_name(void);
const char *janus_nanomsgevh_get_author(void);
const char *janus_nanomsgevh_get_package(void);
void janus_nanomsgevh_incoming_event(json_t *event);
json_t *janus_nanomsgevh_handle_request(json_t *request);

/* Event handler setup */
static janus_eventhandler janus_nanomsgevh =
	JANUS_EVENTHANDLER_INIT (
		.init = janus_nanomsgevh_init,
		.destroy = janus_nanomsgevh_destroy,

		.get_api_compatibility = janus_nanomsgevh_get_api_compatibility,
		.get_version = janus_nanomsgevh_get_version,
		.get_version_string = janus_nanomsgevh_get_version_string,
		.get_description = janus_nanomsgevh_get_description,
		.get_name = janus_nanomsgevh_get_name,
		.get_author = janus_nanomsgevh_get_author,
		.get_package = janus_nanomsgevh_get_package,

		.incoming_event = janus_nanomsgevh_incoming_event,
		.handle_request = janus_nanomsgevh_handle_request,

		.events_mask = JANUS_EVENT_TYPE_NONE
	);

/* Plugin creator */
janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_NANOMSGEVH_NAME);
	return &janus_nanomsgevh;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *pub_thread, *handler_thread;
static void *janus_nanomsgevh_thread(void *data);
static void *janus_nanomsgevh_handler(void *data);

/* Queue of events to handle */
static GAsyncQueue *events = NULL, *nfd_queue = NULL;
static gboolean group_events = TRUE;
static json_t exit_event;
static void janus_nanomsgevh_event_free(json_t *event) {
	if(!event || event == &exit_event)
		return;
	json_decref(event);
}

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* Nanomsg stuff */
static int nfd = -1, nfd_addr = -1, write_nfd[2];


/* Parameter validation (for tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter tweak_parameters[] = {
	{"events", JSON_STRING, 0},
	{"grouping", JANUS_JSON_BOOL, 0}
};
/* Error codes (for the tweaking via Admin API */
#define JANUS_NANOMSGEVH_ERROR_INVALID_REQUEST		411
#define JANUS_NANOMSGEVH_ERROR_MISSING_ELEMENT		412
#define JANUS_NANOMSGEVH_ERROR_INVALID_ELEMENT		413
#define JANUS_NANOMSGEVH_ERROR_UNKNOWN_ERROR		499


/* Plugin implementation */
int janus_nanomsgevh_init(const char *config_path) {
	gboolean success = TRUE;
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_NANOMSGEVH_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_NANOMSGEVH_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_NANOMSGEVH_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL)
		janus_config_print(config);
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

	/* Setup the event handler, if required */
	janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
	if(!item || !item->value || !janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Nanomsg event handler disabled\n");
		goto error;
	}

	item = janus_config_get(config, config_general, janus_config_type_item, "json");
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
	item = janus_config_get(config, config_general, janus_config_type_item, "events");
	if(item && item->value)
		janus_events_edit_events_mask(item->value, &janus_nanomsgevh.events_mask);

	/* Is grouping of events ok? */
	item = janus_config_get(config, config_general, janus_config_type_item, "grouping");
	if(item && item->value)
		group_events = janus_is_true(item->value);

	/* First of all, initialize the pipeline for writeable notifications */
	write_nfd[0] = nn_socket(AF_SP, NN_PULL);
	write_nfd[1] = nn_socket(AF_SP, NN_PUSH);
	if(nn_bind(write_nfd[0], "inproc://janusevh") < 0) {
		JANUS_LOG(LOG_ERR, "Error configuring internal Nanomsg pipeline... %d (%s)\n", errno, nn_strerror(errno));
		goto error;
	}
	if(nn_connect(write_nfd[1], "inproc://janusevh") < 0) {
		JANUS_LOG(LOG_ERR, "Error configuring internal Nanomsg pipeline...%d (%s)\n", errno, nn_strerror(errno));
		goto error;
	}
	/* Handle the Nanomsg configuration */
	item = janus_config_get(config, config_general, janus_config_type_item, "address");
	const char *address = item && item->value ? item->value : NULL;
	item = janus_config_get(config, config_general, janus_config_type_item, "mode");
	const char *mode = item && item->value ? item->value : NULL;
	if(mode == NULL)
		mode = "connect";
	nfd = nn_socket(AF_SP, NN_PUB);
	if(nfd < 0) {
		JANUS_LOG(LOG_ERR, "Error creating Nanomsg event handler socket: %d (%s)\n", errno, nn_strerror(errno));
		goto error;
	}
	if(!strcasecmp(mode, "bind")) {
		/* Bind to this address */
		nfd_addr = nn_bind(nfd, address);
		if(nfd_addr < 0) {
			JANUS_LOG(LOG_ERR, "Error binding Nanomsg event handler socket to address '%s': %d (%s)\n",
				address, errno, nn_strerror(errno));
			goto error;
		}
	} else if(!strcasecmp(mode, "connect")) {
		/* Connect to this address */
		nfd_addr = nn_connect(nfd, address);
		if(nfd_addr < 0) {
			JANUS_LOG(LOG_ERR, "Error connecting Nanomsg event handler socket to address '%s': %d (%s)\n",
				address, errno, nn_strerror(errno));
			goto error;
		}
	} else {
		/* Unsupported mode */
		JANUS_LOG(LOG_ERR, "Unsupported mode '%s'\n", mode);
		goto error;
	}

	/* Initialize the events queue */
	events = g_async_queue_new_full((GDestroyNotify) janus_nanomsgevh_event_free);
	nfd_queue = g_async_queue_new_full((GDestroyNotify) g_free);
	g_atomic_int_set(&initialized, 1);

	/* Start the Nanomsg and event handler threads */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus nanomsgevh thread", janus_nanomsgevh_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the NanomsgEventHandler loop thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		goto error;
	}
	error = NULL;
	handler_thread = g_thread_try_new("janus nanomsgevh handler", janus_nanomsgevh_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the NanomsgEventHandler handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		goto error;
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Setup of Nanomsg event handler completed\n");
	goto done;

error:
	/* If we got here, something went wrong */
	success = FALSE;
	if(write_nfd[0] > -1)
		nn_close(write_nfd[0]);
	if(write_nfd[1] > -1)
		nn_close(write_nfd[1]);
	if(nfd > -1) {
		nn_shutdown(nfd, nfd_addr);
		nn_close(nfd);
	}
	/* Fall through */
done:
	if(config)
		janus_config_destroy(config);
	if(!success) {
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_NANOMSGEVH_NAME);
	return 0;
}

void janus_nanomsgevh_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(events, &exit_event);
	(void)nn_send(write_nfd[1], "x", 1, 0);
	if(pub_thread != NULL) {
		g_thread_join(pub_thread);
		pub_thread = NULL;
	}
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	g_async_queue_unref(events);
	events = NULL;
	g_async_queue_unref(nfd_queue);
	nfd_queue = NULL;

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_NANOMSGEVH_NAME);
}

int janus_nanomsgevh_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_EVENTHANDLER_API_VERSION;
}

int janus_nanomsgevh_get_version(void) {
	return JANUS_NANOMSGEVH_VERSION;
}

const char *janus_nanomsgevh_get_version_string(void) {
	return JANUS_NANOMSGEVH_VERSION_STRING;
}

const char *janus_nanomsgevh_get_description(void) {
	return JANUS_NANOMSGEVH_DESCRIPTION;
}

const char *janus_nanomsgevh_get_name(void) {
	return JANUS_NANOMSGEVH_NAME;
}

const char *janus_nanomsgevh_get_author(void) {
	return JANUS_NANOMSGEVH_AUTHOR;
}

const char *janus_nanomsgevh_get_package(void) {
	return JANUS_NANOMSGEVH_PACKAGE;
}

void janus_nanomsgevh_incoming_event(json_t *event) {
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

json_t *janus_nanomsgevh_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to apply tweaks to the logic */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_NANOMSGEVH_ERROR_MISSING_ELEMENT, JANUS_NANOMSGEVH_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "tweak")) {
		/* We only support a request to tweak the current settings */
		JANUS_VALIDATE_JSON_OBJECT(request, tweak_parameters,
			error_code, error_cause, TRUE,
			JANUS_NANOMSGEVH_ERROR_MISSING_ELEMENT, JANUS_NANOMSGEVH_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto plugin_response;
		/* Events */
		if(json_object_get(request, "events"))
			janus_events_edit_events_mask(json_string_value(json_object_get(request, "events")), &janus_nanomsgevh.events_mask);
		/* Grouping */
		if(json_object_get(request, "grouping"))
			group_events = json_is_true(json_object_get(request, "grouping"));
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_NANOMSGEVH_ERROR_INVALID_REQUEST;
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
static void *janus_nanomsgevh_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining NanomsgEventHandler handler thread\n");
	json_t *event = NULL, *output = NULL;
	char *event_text = NULL;
	int count = 0, max = group_events ? 100 : 1;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {

		event = g_async_queue_pop(events);
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
			g_async_queue_push(nfd_queue, event_text);
			(void)nn_send(write_nfd[1], "x", 1, 0);
		}

		/* Done, let's unref the event */
		json_decref(output);
		output = NULL;
	}
	JANUS_LOG(LOG_VERB, "Leaving NanomsgEventHandler handler thread\n");
	return NULL;
}

/* Thread */
void *janus_nanomsgevh_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining NanomsgEventHandler loop thread\n");

	int fds = 0;
	struct nn_pollfd poll_nfds[2];
	char buffer[1];

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Prepare poll list of file descriptors */
		fds = 0;
		/* Writeable monitor */
		poll_nfds[fds].fd = write_nfd[0];
		poll_nfds[fds].events = NN_POLLIN;
		fds++;
		/* Publisher socket */
		if(nfd > -1 && g_async_queue_length(nfd_queue) > 0) {
			poll_nfds[fds].fd = nfd;
			poll_nfds[fds].events |= NN_POLLOUT;
			fds++;
		}
		/* Start polling */
		int res = nn_poll(poll_nfds, fds, -1);
		if(res == 0)
			continue;
		if(res < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "Got an EINTR (%s) polling the Nanomsg descriptors, ignoring...\n", nn_strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "poll() failed: %d (%s)\n", errno, nn_strerror(errno));
			break;
		}
		int i = 0;
		for(i=0; i<fds; i++) {
			/* FIXME Is there a Nanomsg equivalent of POLLERR? */
			if(poll_nfds[i].revents & NN_POLLOUT) {
				/* Find the client from its file descriptor */
				if(poll_nfds[i].fd == nfd) {
					char *payload = NULL;
					while((payload = g_async_queue_try_pop(nfd_queue)) != NULL) {
						int res = nn_send(poll_nfds[i].fd, payload, strlen(payload), 0);
						/* FIXME Should we check if sent everything? */
						JANUS_LOG(LOG_HUGE, "Written %d/%zu bytes on %d\n", res, strlen(payload), poll_nfds[i].fd);
						g_free(payload);
					}
				}
			}
			if(poll_nfds[i].revents & NN_POLLIN) {
				if(poll_nfds[i].fd == write_nfd[0]) {
					/* Read and ignore: we use this to unlock the poll if there's data to write */
					(void)nn_recv(poll_nfds[i].fd, buffer, sizeof(buffer), 0);
				}
			}
		}
	}

	nn_close(write_nfd[0]);
	nn_close(write_nfd[1]);
	if(nfd > -1) {
		nn_shutdown(nfd, nfd_addr);
		nn_close(nfd);
	}

	/* Done */
	JANUS_LOG(LOG_VERB, "Leaving NanomsgEventHandler loop thread\n");
	return NULL;
}
