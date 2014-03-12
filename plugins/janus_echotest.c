/*! \file   janus_echotest.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
 * \brief  Janus EchoTest plugin
 * \details  This is a trivial EchoTest plugin for Janus, just used to
 * showcase the plugin interface. A peer attaching to this plugin will
 * receive back the same RTP packets and RTCP messages he sends: the
 * RTCP messages, of course, would be modified on the way by the gateway
 * to make sure they are coherent with the involved SSRCs. In order to
 * demonstrate how peer-provided messages can change the behaviour of a
 * plugin, this plugin implements a simple API based on three messages:
 * 
 * 1. a message to enable/disable audio (that is, to tell the plugin
 * whether incoming audio RTP packets need to be sent back or discarded);
 * 2. a message to enable/disable video (that is, to tell the plugin
 * whether incoming video RTP packets need to be sent back or discarded);
 * 3. a message to cap the bitrate (which would modify incoming RTCP
 * REMB messages before sending them back, in order to trick the peer into
 * thinking the available bandwidth is different).
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../config.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_ECHOTEST_VERSION			1
#define JANUS_ECHOTEST_VERSION_STRING	"0.0.1"
#define JANUS_ECHOTEST_DESCRIPTION		"This is a trivial EchoTest plugin for Janus, just used to showcase the plugin interface."
#define JANUS_ECHOTEST_NAME				"JANUS EchoTest plugin"
#define JANUS_ECHOTEST_PACKAGE			"janus.plugin.echotest"

/* Plugin methods */
janus_plugin *create(void);
int janus_echotest_init(janus_callbacks *callback, const char *config_path);
void janus_echotest_destroy(void);
int janus_echotest_get_version(void);
const char *janus_echotest_get_version_string(void);
const char *janus_echotest_get_description(void);
const char *janus_echotest_get_name(void);
const char *janus_echotest_get_package(void);
void janus_echotest_create_session(janus_pluginession *handle, int *error);
void janus_echotest_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_echotest_setup_media(janus_pluginession *handle);
void janus_echotest_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len);
void janus_echotest_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len);
void janus_echotest_hangup_media(janus_pluginession *handle);
void janus_echotest_destroy_session(janus_pluginession *handle, int *error);

/* Plugin setup */
static janus_plugin janus_echotest_plugin =
	{
		.init = janus_echotest_init,
		.destroy = janus_echotest_destroy,

		.get_version = janus_echotest_get_version,
		.get_version_string = janus_echotest_get_version_string,
		.get_description = janus_echotest_get_description,
		.get_name = janus_echotest_get_name,
		.get_package = janus_echotest_get_package,
		
		.create_session = janus_echotest_create_session,
		.handle_message = janus_echotest_handle_message,
		.setup_media = janus_echotest_setup_media,
		.incoming_rtp = janus_echotest_incoming_rtp,
		.incoming_rtcp = janus_echotest_incoming_rtcp,
		.hangup_media = janus_echotest_hangup_media,
		.destroy_session = janus_echotest_destroy_session,
	}; 

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_PRINT("%s created!\n", JANUS_ECHOTEST_NAME);
	return &janus_echotest_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_echotest_handler(void *data);

typedef struct janus_echotest_message {
	janus_pluginession *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_echotest_message;
GQueue *messages;

typedef struct janus_echotest_session {
	janus_pluginession *handle;
	gboolean audio_active;
	gboolean video_active;
	uint64_t bitrate;
	gboolean destroy;
} janus_echotest_session;
GHashTable *sessions;


/* Plugin implementation */
int janus_echotest_init(janus_callbacks *callback, const char *config_path) {
	if(stopping) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	sprintf(filename, "%s/%s.cfg", config_path, JANUS_ECHOTEST_PACKAGE);
	JANUS_PRINT("Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	sessions = g_hash_table_new(NULL, NULL);
	messages = g_queue_new();
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	initialized = 1;
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus echotest handler", janus_echotest_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_DEBUG("Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_PRINT("%s initialized!\n", JANUS_ECHOTEST_NAME);
	return 0;
}

void janus_echotest_destroy() {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	g_hash_table_destroy(sessions);
	g_queue_free(messages);
	sessions = NULL;
	initialized = 0;
	stopping = 0;
	JANUS_PRINT("%s destroyed!\n", JANUS_ECHOTEST_NAME);
}

int janus_echotest_get_version() {
	return JANUS_ECHOTEST_VERSION;
}

const char *janus_echotest_get_version_string() {
	return JANUS_ECHOTEST_VERSION_STRING;
}

const char *janus_echotest_get_description() {
	return JANUS_ECHOTEST_DESCRIPTION;
}

const char *janus_echotest_get_name() {
	return JANUS_ECHOTEST_NAME;
}

const char *janus_echotest_get_package() {
	return JANUS_ECHOTEST_PACKAGE;
}

void janus_echotest_create_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)calloc(1, sizeof(janus_echotest_session));
	if(session == NULL) {
		JANUS_DEBUG("Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;	/* No limit */
	handle->plugin_handle = session;
	g_hash_table_insert(sessions, handle, session);

	return;
}

void janus_echotest_destroy_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_PRINT("Removing Echo Test session...\n");
	/* TODO Actually clean up and remove ongoing sessions */
	g_hash_table_remove(sessions, handle);
	session->destroy = TRUE;
	g_free(session);
	return;
}

void janus_echotest_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_PRINT("%s\n", message);
	janus_echotest_message *msg = calloc(1, sizeof(janus_echotest_message));
	if(msg == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->transaction = transaction ? g_strdup(transaction) : NULL;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_queue_push_tail(messages, msg);
}

void janus_echotest_setup_media(janus_pluginession *handle) {
	JANUS_DEBUG("WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* We really don't care, as we only send RTP/RTCP we get in the first place back anyway */
}

void janus_echotest_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	/* Simple echo test */
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			return;
		}
		if(session->destroy)
			return;
		if((!video && session->audio_active) || (video && session->video_active)) {
			gateway->relay_rtp(handle, video, buf, len);
		}
	}
}

void janus_echotest_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			return;
		}
		if(session->destroy)
			return;
		if(session->bitrate > 0)
			janus_rtcp_cap_remb(buf, len, session->bitrate);
		gateway->relay_rtcp(handle, video, buf, len);
	}
}

void janus_echotest_hangup_media(janus_pluginession *handle) {
	JANUS_PRINT("No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set(event, "echotest", json_string("event"));
	json_object_set(event, "result", json_string("done"));
	char *event_text = json_dumps(event, JSON_INDENT(3));
	json_decref(event);
	JANUS_PRINT("Pushing event: %s\n", event_text);
	JANUS_PRINT("  >> %d\n", gateway->push_event(handle, &janus_echotest_plugin, NULL, event_text, NULL, NULL));
	/* Reset controls */
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;
}

/* Thread to handle incoming messages */
static void *janus_echotest_handler(void *data) {
	JANUS_DEBUG("Joining thread\n");
	janus_echotest_message *msg = NULL;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	while(initialized && !stopping) {
		if(!messages || (msg = g_queue_pop_head(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_echotest_session *session = (janus_echotest_session *)msg->handle->plugin_handle;
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			continue;
		}
		if(session->destroy)
			continue;
		/* Handle request */
		JANUS_PRINT("Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_DEBUG("No message??\n");
			sprintf(error_cause, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		json_t *root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_DEBUG("JSON error: on line %d: %s\n", error.line, error.text);
			sprintf(error_cause, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_DEBUG("JSON error: not an object\n");
			sprintf(error_cause, "JSON error: not an object");
			goto error;
		}
		json_t *audio = json_object_get(root, "audio");
		if(audio && !json_is_boolean(audio)) {
			JANUS_DEBUG("JSON error: invalid element (audio)\n");
			sprintf(error_cause, "JSON error: invalid value (audio)");
			goto error;
		}
		json_t *video = json_object_get(root, "video");
		if(video && !json_is_boolean(video)) {
			JANUS_DEBUG("JSON error: invalid element (video)\n");
			sprintf(error_cause, "JSON error: invalid value (video)");
			goto error;
		}
		json_t *bitrate = json_object_get(root, "bitrate");
		if(bitrate && !json_is_integer(bitrate)) {
			JANUS_DEBUG("JSON error: invalid element (bitrate)\n");
			sprintf(error_cause, "JSON error: invalid value (bitrate)");
			goto error;
		}
		if(audio) {
			session->audio_active = json_is_true(audio);
			JANUS_PRINT("Setting audio property: %s\n", session->audio_active ? "true" : "false");
		}
		if(video) {
			session->video_active = json_is_true(video);
			JANUS_PRINT("Setting video property: %s\n", session->video_active ? "true" : "false");
		}
		if(bitrate) {
			session->bitrate = json_integer_value(bitrate);
			JANUS_PRINT("Setting video bitrate: %"SCNu64"\n", session->bitrate);
			if(session->bitrate > 0) {
				/* FIXME Generate a new REMB (especially useful for Firefox, which doesn't send any we can cap later) */
				char buf[24];
				memset(buf, 0, 24);
				janus_rtcp_remb((char *)&buf, 24, session->bitrate);
				JANUS_PRINT("Sending REMB\n");
				gateway->relay_rtcp(session->handle, 1, buf, 24);
				/* FIXME How should we handle a subsequent "no limit" bitrate? */
			}
		}
		/* Any SDP to handle? */
		if(msg->sdp) {
			JANUS_PRINT("This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set(event, "echotest", json_string("event"));
		json_object_set(event, "result", json_string("ok"));
		char *event_text = json_dumps(event, JSON_INDENT(3));
		json_decref(event);
		JANUS_PRINT("Pushing event: %s\n", event_text);
		if(!msg->sdp) {
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL));
		} else {
			/* Forward the same offer to the gateway, to start the echo test */
			char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer"))
				type = "answer";
			if(!strcasecmp(msg->sdp_type, "answer"))
				type = "offer";
			/* How long will the gateway take to push the event? */
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, type, msg->sdp);
			JANUS_PRINT("  >> Pushing event: %d (took %"SCNu64" ms)\n",
				res, janus_get_monotonic_time()-start);
		}
		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set(event, "echotest", json_string("event"));
			json_object_set(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3));
			json_decref(event);
			JANUS_PRINT("Pushing event: %s\n", event_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL));
		}
	}
	JANUS_DEBUG("Leaving thread\n");
	return NULL;
}
