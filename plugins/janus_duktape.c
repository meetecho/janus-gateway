/*! \file   janus_duktape.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus JavaScript plugin (via Duktape)
 * \details Check the \ref duktape for more details.
 *
 * \ingroup plugins
 * \ingroup jspapi
 * \ref plugins
 * \ref jspapi
 *
 * \page duktape JavaScript (Duktape) plugin documentation
 * This is a plugin that implements a simple bridge to JavaScript via
 * Duktape. While the plugin implements low level stuff like media
 * manipulation, routing, recording, etc., all the logic is demanded
 * to an external JavaScript script. This means that the C code exposes functions
 * to the JavaScript script (e.g., to dictate what to do with media, whether
 * recording should be done, sending PLIs, etc.), while JavaScript exposes
 * functions to be notified by the C code about important events (e.g.,
 * new users, WebRTC state, incoming messages, etc.).
 *
 * Considering the C code and the JavaScript script will need some sort of
 * "contract" in order to be able to properly interact with each other,
 * the interface (as in method names) must be consistent, but the logic
 * in the JavaScript script can be completely customized, so that it fits
 * whatever requirement one has (e.g., something like the EchoTest, or
 * something like the VideoRoom).
 *
 * \section jsapi JavaScript interfaces
 *
 * Every JavaScript script that wants to implement a Janus plugin must provide
 * the following functions as callbacks:
 *
 * - \c init(): called when janus_duktape.c is initialized;
 * - \c destroy(): called when janus_duktape.c is deinitialized (Janus shutting down);
 * - \c createSession(): called when a new user attaches to the Janus Duktape plugin;
 * - \c destroySession(): called when an attached user detaches from the Janus Duktape plugin;
 * - \c querySession(): called when an Admin API query for a specific user gets to the Janus Duktape plugin;
 * - \c handleMessage(): called when a user sends a message to the Janus Duktape plugin;
 * - \c setupMedia(): called when a users's WebRTC PeerConnection goes up;
 * - \c hangupMedia(): called when a users's WebRTC PeerConnection goes down;
 * - \c resumeScheduler(): called by the C scheduler to resume coroutines.
 *
 * While \c init() expects a path to a config file (which you can ignore if
 * unneeded), and \c destroy() and \c resumeScheduler() don't need any
 * argument, all other functions expect at the very least a numeric session
 * identifier, that will uniquely address a user in the plugin. Such a
 * value is created dynamically by the C code, and so all the JavaScript script
 * needs to do is track it as a unique session identifier when handling
 * requests and pushing responses/events/actions towards the C code.
 * Refer to the existing examples (e.g., \c echotest.js) to see the
 * exact signature for all the above callbacks.
 *
 * \note Notice that, along the above mentioned callbacks, JavaScript scripts
 * can also implement functions like \c incomingRtp() \c incomingRtcp()
 * \c incomingTextData() and \c incomingBinaryData() to handle those packets
 * directly, instead of letting the C code worry about relaying/processing
 * them. While it might make sense to handle incoming data channel messages
 * with \c incomingTextData() or \c incomingBinaryData
 * though, the performance impact of directly processing and manipulating
 * RTP an RTCP packets is probably too high, and so their usage is currently
 * discouraged. The \c dataReady() callback can be used to figure out when
 * data can be sent. As an additional note, JavaScript scripts can also decide to
 * implement the functions that return information about the plugin itself,
 * namely \c getVersion() \c getVersionString() \c getDescription()
 * \c getName() \c getAuthor() and \c getPackage(). If not implemented,
 * the JavaScript plugin will return its own info (i.e., "janus.plugin.javascript", etc.).
 * Most of the times, JavaScript scripts will not need to override this information,
 * unless they really want to register their own name spaces and versioning.
 * JavaScript scripts can also receive information on slow links via the
 * \c slowLink() callback, in order to react accordingly: e.g., reduce
 * the bitrate of a video sender if they, or their viewers, are experiencing
 * issues. Finally, in case simulcast is used, JavaScript scripts may
 * receive events on substream and/or temporal layer changes happening
 * for receiving sessions via the \c substreamChanged() and the
 * \c temporalLayerChanged() callbacks: this may be useful to track
 * which layer is actually being sent, vs. what was requested.
 *
 * \section dtcapi C interfaces
 *
 * Just as the JavaScript script needs to expose callbacks that the C code can
 * invoke, the C code exposes methods as JavaScript functions accessible from
 * the JavaScript script. This includes means to push events, configure how
 * media should be routed without handling each packet in JavaScript, sending
 * RTCP feedback, start/stop recording and so on.
 *
 * The following are the functions the C code exposes:
 *
 * - \c pushEvent(): push an event to the user via Janus API;
 * - \c eventsIsEnabled(): check if Event Handlers are enabled in the core;
 * - \c notifyEvent(): send an event to Event Handlers;
 * - \c closePc(): force the closure of a PeerConnection;
 * - \c configureMedium(): specify whether audio/video/data can be received/sent;
 * - \c addRecipient(): specify which user should receive a user's media;
 * - \c removeRecipient(): specify which user should not receive a user's media anymore;
 * - \c setBitrate(): specify the bitrate to force on a user via REMB feedback;
 * - \c setPliFreq(): specify how often the plugin should send a PLI to this user;
 * - \c setSubstream(): set the target simulcast substream;
 * - \c setTemporalLayer(): set the target simulcast temporal layer;
 * - \c sendPli(): send a PLI (keyframe request);
 * - \c startRecording(): start recording audio, video and or data for a user;
 * - \c stopRecording(): start recording audio, video and or data for a user;
 * - \c pokeScheduler(): notify the C code that there's a coroutine to resume;
 * - \c timeCallback(): trigger the execution of a JavaScript function after X milliseconds.
 *
 * As anticipated in the previous section, almost all these methods also
 * expect the unique session identifier to address a specific user in the
 * plugin. This is true for all the above methods expect \c eventsIsEnabled
 * and, more importantly, both \c timeCallback() and \c pokeScheduler() which,
 * together with JavaScript's \c resumeScheduler(), will be clearer in the next section.
 *
 * \section jcoroutines JavaScript/C coroutines scheduler
 *
 * Duktape is a single threaded environment. While it has a concept similar
 * to threads called coroutines, these are not threads as known in C.
 * In order to allow for an easy to implement asynchronous behaviour in
 * JavaScript scripts, you can leverage a scheduler implemented in the C code.
 *
 * More specifically, when the plugin starts a dedicated thread is devoted
 * to the only purpose of acting as a scheduler for JavaScript coroutines. This
 * means that, whenever this C scheduler is awaken, it will call the
 * \c resumeScheduler() function in the JavaScript script, thus allowing the
 * JavaScript script to execute one or more pending coroutines. The C scheduler
 * only acts when triggered, which means it's up to the JavaScript script to
 * tell it when to wake up: this is possible via the \c pokeScheduler()
 * function, which does nothing more than sending a simple signal to the
 * C scheduler to wake it up. As such, it's easy for the JavaScript script to
 * implement asynchronous behaviour, e.g.:
 *
 * 1. JavaScript script needs to do something asynchronously;
 * 2. JavaScript script creates coroutine, and takes note of it somewhere;
 * 3. JavaScript script calls \c pokeScheduler();
 * 4. C code sends signal to the thread acting as a scheduler;
 * 5. when the scheduling thread wakes up, it calls \c resumeScheduler();
 * 6. JavaScript script resumes the previously queued coroutine.
 *
 * This simple mechanism is what the sample JavaScript scripts provided in this
 * repo use, for instance, to handle incoming messages asynchronously,
 * so you can refer to those to have an idea of how it can be used. The
 * next section will address \ref jtimers instead.
 *
 * \note You can implement asynchronous behaviour any way you want, and
 * you're not required to use this C scheduler. Anyway, you must implement
 * a method called \c resumeScheduler() anyway, as the C code checks for
 * its presence and fails if it's not there. If you don't need it, just
 * create an empty function that does nothing and you'll be fine.
 *
 * \section jtimers JavaScript/C time-based scheduler
 *
 * Another helpful way to implement asynchronous behaviour is with the
 * help of the \c timeCallback() function. Specifically, this function
 * implements a mechanism to ask for a specific JavaScript method to be invoked
 * after a provided amount of time. To specify the function to invoke,
 * an optional argument to pass (which MUST be a string) and the time to
 * wait to do that. This is particularly helpful when you're handling
 * asynchronous behaviour that you want to inspect on a regular basis.
 *
 * The \c timeCallback() function expects three arguments:
 *
 * \verbatim
timeCallback(function, argument, milliseconds);
\endverbatim
 *
 * The only mandatory parameter is \c function: if you set \c argument
 * to \c null no argument will be passed to \c function when it's executed;
 * it \c milliseconds is 0, \c function will be executed as soon as possible.
 *
 * \verbatim
// This will cause an error (timeCallback needs a function)
timeCallback();
// Invoke test() in 500 milliseconds
timeCallback("test", null, 500);
// Invoke test("ciccio") in 2 seconds
timeCallback("test", "ciccio", 2000);
\endverbatim
 *
 * Notice that \c timeCallback() allows you to formally recreate the
 * mechanism \c pokeScheduler() and \c resumeScheduler() implement, as
 * the following is pretty much an equivalent of that:
 *
 * \verbatim
timeCallback("resumeScheduler", null, 0);
\endverbatim
 *
 * Anyway, \c pokeScheduler() and \c resumeScheduler() is much more
 * compact and less verbose, and as such is preferred in cases where
 * timing and opaque arguments are not needed.
 *
 * Refer to the \ref jspapi section for more information on how you
 * can register your own C functions.
 */

#include <jansson.h>

/* Session definition and hashtable */
#include "janus_duktape_data.h"
/* Extra/custom C hooks and code */
#include "janus_duktape_extra.h"


/* Plugin information */
#define JANUS_DUKTAPE_VERSION			1
#define JANUS_DUKTAPE_VERSION_STRING	"0.0.1"
#define JANUS_DUKTAPE_DESCRIPTION		"A custom plugin for implementing the logic in JavaScript, via Duktape."
#define JANUS_DUKTAPE_NAME				"Janus JavaScript plugin (Duktape)"
#define JANUS_DUKTAPE_AUTHOR			"Meetecho s.r.l."
#define JANUS_DUKTAPE_PACKAGE			"janus.plugin.duktape"

/* Plugin methods */
janus_plugin *create(void);
int janus_duktape_init(janus_callbacks *callback, const char *config_path);
void janus_duktape_destroy(void);
int janus_duktape_get_api_compatibility(void);
int janus_duktape_get_version(void);
const char *janus_duktape_get_version_string(void);
const char *janus_duktape_get_description(void);
const char *janus_duktape_get_name(void);
const char *janus_duktape_get_author(void);
const char *janus_duktape_get_package(void);
void janus_duktape_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_duktape_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_duktape_handle_admin_message(json_t *message);
void janus_duktape_setup_media(janus_plugin_session *handle);
void janus_duktape_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_duktape_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
void janus_duktape_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet);
void janus_duktape_data_ready(janus_plugin_session *handle);
void janus_duktape_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_duktape_hangup_media(janus_plugin_session *handle);
void janus_duktape_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_duktape_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_duktape_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_duktape_init,
		.destroy = janus_duktape_destroy,

		.get_api_compatibility = janus_duktape_get_api_compatibility,
		.get_version = janus_duktape_get_version,
		.get_version_string = janus_duktape_get_version_string,
		.get_description = janus_duktape_get_description,
		.get_name = janus_duktape_get_name,
		.get_author = janus_duktape_get_author,
		.get_package = janus_duktape_get_package,

		.create_session = janus_duktape_create_session,
		.handle_message = janus_duktape_handle_message,
		.handle_admin_message = janus_duktape_handle_admin_message,
		.setup_media = janus_duktape_setup_media,
		.incoming_rtp = janus_duktape_incoming_rtp,
		.incoming_rtcp = janus_duktape_incoming_rtcp,
		.incoming_data = janus_duktape_incoming_data,
		.data_ready = janus_duktape_data_ready,
		.slow_link = janus_duktape_slow_link,
		.hangup_media = janus_duktape_hangup_media,
		.destroy_session = janus_duktape_destroy_session,
		.query_session = janus_duktape_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_DUKTAPE_NAME);
	return &janus_duktape_plugin;
}

/* Useful stuff */
volatile gint duktape_initialized = 0, duktape_stopping = 0;
janus_callbacks *janus_core = NULL;
static char *duktape_folder = NULL;

/* Duktape stuff */
duk_context *duktape_ctx = NULL;
janus_mutex duktape_mutex = JANUS_MUTEX_INITIALIZER;
static const char *duktape_functions[] = {
	"init", "destroy", "resumeScheduler",
	"createSession", "destroySession", "querySession",
	"handleMessage",
	"setupMedia", "hangupMedia"
};
static uint duktape_funcsize = sizeof(duktape_functions)/sizeof(*duktape_functions);
/* Some bindings are optional */
static gboolean has_get_version = FALSE;
static int duktape_script_version = -1;
static gboolean has_get_version_string = FALSE;
static char *duktape_script_version_string = NULL;
static gboolean has_get_description = FALSE;
static char *duktape_script_description = NULL;
static gboolean has_get_name = FALSE;
static char *duktape_script_name = NULL;
static gboolean has_get_author = FALSE;
static char *duktape_script_author = NULL;
static gboolean has_get_package = FALSE;
static char *duktape_script_package = NULL;
static gboolean has_handle_admin_message = FALSE;
static gboolean has_incoming_rtp = FALSE;
static gboolean has_incoming_rtcp = FALSE;
static gboolean has_incoming_data_legacy = FALSE,	/* Legacy callback */
	has_incoming_text_data = FALSE,
	has_incoming_binary_data = FALSE;
static gboolean has_data_ready = FALSE;
static gboolean has_slow_link = FALSE;
static gboolean has_substream_changed = FALSE;
static gboolean has_temporal_changed = FALSE;
/* JavaScript C scheduler (for coroutines) */
static GThread *scheduler_thread = NULL;
static void *janus_duktape_scheduler(void *data);
static GAsyncQueue *events = NULL;
typedef enum janus_duktape_event {
	janus_duktape_event_none = 0,
	janus_duktape_event_resume,		/* Resume one or more pending coroutines */
	janus_duktape_event_exit		/* Break the scheduler loop */
} janus_duktape_event;
/* JavaScript timer loop (for scheduled callbacks) */
static GMainContext *timer_context = NULL;
static GMainLoop *timer_loop = NULL;
static GThread *timer_thread = NULL;
static void *janus_duktape_timer(void *data);
static gboolean janus_duktape_timer_cb(void *data);
typedef struct janus_duktape_callback {
	guint id;
	uint32_t ms;
	GSource *source;
	char *function;
	char *argument;
} janus_duktape_callback;
static GHashTable *callbacks = NULL;
static void janus_duktape_callback_free(janus_duktape_callback *cb) {
	if(!cb)
		return;
	g_source_destroy(cb->source);
	g_source_unref(cb->source);
	g_free(cb->function);
	g_free(cb->argument);
	g_free(cb);
}

/* Helper function to sample the number of occupied slots into JavaScript stack */
static void janus_duktape_stackdump(duk_context *ctx) {
	int top = duk_get_top(ctx);
	JANUS_LOG(LOG_HUGE, "Total in Duktape stack: %d\n", top);
}

/* janus_duktape_session is defined in janus_duktape_data.h, but it's managed here */
GHashTable *duktape_sessions, *duktape_ids;
janus_mutex duktape_sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_duktape_session_destroy(janus_duktape_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1)) {
		janus_refcount_decrease(&session->ref);
	}
}

static void janus_duktape_session_free(const janus_refcount *session_ref) {
	janus_duktape_session *session = janus_refcount_containerof(session_ref, janus_duktape_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_hash_table_remove(duktape_ids, GUINT_TO_POINTER(session->id));
	janus_recorder_destroy(session->arc);
	janus_recorder_destroy(session->vrc);
	janus_recorder_destroy(session->drc);
	g_free(session);
}

/* Packet data and routing */
typedef struct janus_duktape_rtp_relay_packet {
	janus_duktape_session *sender;
	janus_rtp_header *data;
	gint length;
	gboolean is_rtp;	/* This may be a data packet and not RTP */
	gboolean is_video;
	uint32_t ssrc[3];
	uint32_t timestamp;
	uint16_t seq_number;
	/* The following is only relevant for datachannels */
	gboolean textdata;
} janus_duktape_rtp_relay_packet;
static void janus_duktape_relay_rtp_packet(gpointer data, gpointer user_data);
static void janus_duktape_relay_data_packet(gpointer data, gpointer user_data);


/* Helper struct to address outgoing notifications, e.g., involving PeerConnections */
typedef enum janus_duktape_async_event_type {
	janus_duktape_async_event_type_none = 0,
	janus_duktape_async_event_type_pushevent
} janus_duktape_async_event_type;
typedef struct janus_duktape_async_event {
	janus_duktape_session *session;			/* Who this event is for */
	janus_duktape_async_event_type type;	/* What this event is about */
	char *transaction;					/* Notification transaction, if any */
	json_t *event;						/* Content of the notification, if any */
	json_t *jsep;						/* Content of JSEP SDP, if any */
} janus_duktape_async_event;
/* Helper thread to push events that need to be asynchronous, e.g., for those
 * that would keep the Duktape context busy longer than usual and cause delays,
 * or those that might actually result in a deadlock if done synchronously */
static void *janus_duktape_async_event_helper(void *data) {
	janus_duktape_async_event *asev = (janus_duktape_async_event *)data;
	if(asev == NULL)
		return NULL;
	if(asev->type == janus_duktape_async_event_type_pushevent) {
		/* Send the event */
		janus_core->push_event(asev->session->handle, &janus_duktape_plugin, asev->transaction, asev->event, asev->jsep);
	}
	json_decref(asev->event);
	json_decref(asev->jsep);
	g_free(asev->transaction);
	janus_refcount_decrease(&asev->session->ref);
	g_free(asev);
	return NULL;
}


/* Helper method to stringify Duktape types */
#define DUK_CASE_STR(type) case type: return #type
static const char *janus_duktape_type_string(int type) {
	switch(type) {
		DUK_CASE_STR(DUK_TYPE_NONE);
		DUK_CASE_STR(DUK_TYPE_UNDEFINED);
		DUK_CASE_STR(DUK_TYPE_NULL);
		DUK_CASE_STR(DUK_TYPE_BOOLEAN);
		DUK_CASE_STR(DUK_TYPE_NUMBER);
		DUK_CASE_STR(DUK_TYPE_STRING);
		DUK_CASE_STR(DUK_TYPE_OBJECT);
		DUK_CASE_STR(DUK_TYPE_BUFFER);
		DUK_CASE_STR(DUK_TYPE_POINTER);
		DUK_CASE_STR(DUK_TYPE_LIGHTFUNC);
		default:
			break;
	}
	return NULL;
}


/* Methods that we expose to the JavaScript script */
static duk_ret_t janus_duktape_method_getmodulesfolder(duk_context *ctx) {
	/* This method returns the folder that was configured in the settings, for modules */
	duk_push_string(ctx, duktape_folder ? duktape_folder : ".");
	return 1;
}

static duk_ret_t janus_duktape_method_getversion(duk_context *ctx) {
	duk_push_int(ctx, DUK_VERSION);
	return 1;
}

static duk_ret_t janus_duktape_method_readfile(duk_context *ctx) {
	/* Helper method to read a text file and return its content as a string */
	if(duk_get_type(ctx, 0) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	const char *filename = duk_get_string(ctx, 0);
	FILE *f = fopen(filename, "rb");
	if(f == NULL) {
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Error opening file: %s\n", filename);
		return duk_throw(ctx);
	}
	fseek(f, 0, SEEK_END);
	int len = (int)ftell(f);
	if(len < 0) {
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Error opening file: %s\n", strerror(errno));
		return duk_throw(ctx);
	}
	fseek(f, 0, SEEK_SET);
	char *text = g_malloc(len);
	size_t offset = 0, r = 0, t = len;
	while(t > 0) {
		r = fread(text+offset, 1, t, f);
		if(r == 0) {
			fclose(f);
			g_free(text);
			duk_push_error_object(ctx, DUK_ERR_ERROR, "Error reading file: %s\n", filename);
			return duk_throw(ctx);
		}
		t -= r;
	}
	duk_push_lstring(ctx, text, len);
	fclose(f);
	g_free(text);
	return 1;
}

static duk_ret_t janus_duktape_method_pokescheduler(duk_context *ctx) {
	/* This method allows the JavaScript script to poke the scheduler and have it wake up ASAP */
	g_async_queue_push(events, GUINT_TO_POINTER(janus_duktape_event_resume));
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_timecallback(duk_context *ctx) {
	/* This method allows the JS script to schedule a callback after a specified amount of time */
	if(duk_get_type(ctx, 0) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING && duk_get_type(ctx, 1) != DUK_TYPE_UNDEFINED) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_NUMBER && duk_get_type(ctx, 2) != DUK_TYPE_UNDEFINED) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	const char *function = duk_get_string(ctx, 0);
	const char *argument = duk_get_string(ctx, 1);
	uint32_t ms = (uint32_t)duk_get_number(ctx, 2);
	/* Create a callback instance */
	janus_duktape_callback *cb = g_malloc0(sizeof(janus_duktape_callback));
	cb->function = g_strdup(function);
	if(argument != NULL)
		cb->argument = g_strdup(argument);
	cb->ms = ms;
	cb->source = g_timeout_source_new(ms);
	g_source_set_callback(cb->source, janus_duktape_timer_cb, cb, NULL);
	g_hash_table_insert(callbacks, cb, cb);
	cb->id = g_source_attach(cb->source, timer_context);
	JANUS_LOG(LOG_VERB, "Created scheduled callback (%"SCNu32"ms) with ID %u\n", cb->ms, cb->id);
	/* Done */
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_pushevent(duk_context *ctx) {
	/* Get the arguments from the provided context */
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING &&
			duk_get_type(ctx, 1) != DUK_TYPE_UNDEFINED && duk_get_type(ctx, 1) != DUK_TYPE_NULL) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 3) != DUK_TYPE_STRING &&
			duk_get_type(ctx, 3) != DUK_TYPE_UNDEFINED && duk_get_type(ctx, 3) != DUK_TYPE_NULL) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 3)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	const char *transaction = duk_get_string(ctx, 1);
	const char *event_text = duk_get_string(ctx, 2);
	const char *jsep_text = duk_get_string(ctx, 3);
	/* Parse the event/jsep strings to Jansson objects */
	json_error_t error;
	json_t *event = json_loads(event_text, 0, &error);
	if(!event) {
		duk_push_error_object(ctx, DUK_ERR_ERROR, "JSON error: on line %d: %s", error.line, error.text);
		return duk_throw(ctx);
	}
	json_t *jsep = NULL;
	if(jsep_text != NULL) {
		jsep = json_loads(jsep_text, 0, &error);
		if(!jsep) {
			duk_push_error_object(ctx, DUK_ERR_ERROR, "JSON error: on line %d: %s", error.line, error.text);
			json_decref(event);
			return duk_throw(ctx);
		}
	}
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		json_decref(event);
		if(jsep)
			json_decref(jsep);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* If there's an SDP attached, create a thread to send the event asynchronously:
	 * sending it here would keep the locked Duktape context busy much longer than intended */
	if(jsep != NULL) {
		/* Let's parse the SDP first, though */
		const char *sdp = json_string_value(json_object_get(jsep, "sdp"));
		const char *sdp_type = json_string_value(json_object_get(jsep, "type"));
		char error_str[512];
		janus_sdp *parsed_sdp = janus_sdp_parse(sdp, error_str, sizeof(error_str));
		if(parsed_sdp == NULL) {
			JANUS_LOG(LOG_ERR, "Error parsing answer: %s\n", error_str);
			json_decref(event);
			json_decref(jsep);
			janus_refcount_decrease(&session->ref);
			duk_push_error_object(ctx, DUK_ERR_ERROR, "Error parsing answer: %s", error_str);
			return duk_throw(ctx);
		}
		janus_duktape_async_event *asev = g_malloc0(sizeof(janus_duktape_async_event));
		asev->session = session;
		asev->type = janus_duktape_async_event_type_pushevent;
		asev->transaction = transaction ? g_strdup(transaction) : NULL;
		asev->event = event;
		asev->jsep = jsep;
		if(json_is_true(json_object_get(jsep, "e2ee")))
			session->e2ee = TRUE;
		if(sdp_type && !strcasecmp(sdp_type, "answer")) {
			/* Take note of which video codec were negotiated */
			const char *vcodec = NULL;
			janus_sdp_find_first_codecs(parsed_sdp, NULL, &vcodec);
			if(vcodec)
				session->vcodec = janus_videocodec_from_name(vcodec);
			if(session->vcodec != JANUS_VIDEOCODEC_VP8 && session->vcodec != JANUS_VIDEOCODEC_H264) {
				/* VP8 r H.264 were not negotiated, if simulcasting was enabled then disable it here */
				int i=0;
				for(i=0; i<3; i++) {
					session->ssrc[i] = 0;
					g_free(session->rid[0]);
					session->rid[0] = NULL;
				}
			}
		}
		janus_sdp_destroy(parsed_sdp);
		/* Send asynchronously */
		GError *error = NULL;
		g_thread_try_new("duktape pushevent", janus_duktape_async_event_helper, asev, &error);
		if(error != NULL) {
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Duktape pushevent thread...\n",
				error->code, error->message ? error->message : "??");
			g_error_free(error);
			json_decref(event);
			json_decref(jsep);
			g_free(asev->transaction);
			janus_refcount_decrease(&session->ref);
			g_free(asev);
		}
		/* Return a success/error right away */
		if(error) {
			duk_push_error_object(ctx, DUK_ERR_ERROR, "Error spawning pushevent thread");
			return duk_throw(ctx);
		}
		duk_push_int(ctx, 0);
		return 1;
	}
	/* No SDP, send the event now */
	int res = janus_core->push_event(session->handle, &janus_duktape_plugin, transaction, event, NULL);
	janus_refcount_decrease(&session->ref);
	json_decref(event);
	duk_push_int(ctx, res);
	return 1;
}

static duk_ret_t janus_duktape_method_notifyevent(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	const char *event_text = duk_get_string(ctx, 1);
	if(event_text == NULL)
		return duk_throw(ctx);
	/* Get the arguments from the provided context */
	if(!janus_core->events_is_enabled()) {
		/* Event handlers are disabled in the core, ignoring */
		duk_push_int(ctx, 0);
		return 1;
	}
	/* Parse the event/jsep strings to Jansson objects */
	json_error_t error;
	json_t *event = json_loads(event_text, 0, &error);
	if(!event) {
		duk_push_error_object(ctx, DUK_ERR_ERROR, "JSON error: on line %d: %s", error.line, error.text);
		return duk_throw(ctx);
	}
	/* Find the session (optional) */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session != NULL)
		janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Notify the event */
	janus_core->notify_event(&janus_duktape_plugin, session ? session->handle : NULL, event);
	if(session != NULL)
		janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_eventsisenabled(duk_context *ctx) {
	/* Return info on whether event handlers are enabled in the core or not */
	duk_push_int(ctx, janus_core->events_is_enabled());
	return 1;
}

static duk_ret_t janus_duktape_method_closepc(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Close the PeerConnection */
	janus_core->close_pc(session->handle);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_endsession(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Close the plugin handle */
	janus_core->end_session(session->handle);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_configuremedium(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 3) != DUK_TYPE_BOOLEAN) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_BOOLEAN), janus_duktape_type_string(duk_get_type(ctx, 3)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	const char *medium = duk_get_string(ctx, 1);
	const char *direction = duk_get_string(ctx, 2);
	int enabled = duk_get_boolean(ctx, 3);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Modify the session media property */
	if(medium && direction) {
		if(!strcasecmp(medium, "audio")) {
			if(!strcasecmp(direction, "in")) {
				session->accept_audio = enabled ? TRUE : FALSE;
			} else {
				session->send_audio = enabled ? TRUE : FALSE;
			}
		} else if(!strcasecmp(medium, "video")) {
			if(!strcasecmp(direction, "in")) {
				session->accept_video = enabled ? TRUE : FALSE;
			} else {
				session->send_video = enabled ? TRUE : FALSE;
			}
		} else if(!strcasecmp(medium, "data")) {
			if(!strcasecmp(direction, "in")) {
				session->accept_data = enabled ? TRUE : FALSE;
			} else {
				session->send_data = enabled ? TRUE : FALSE;
			}
		}
	}
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_addrecipient(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint32_t rid = (uint32_t)duk_get_number(ctx, 1);
	/* Find the sessions */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->recipients_mutex);
	janus_duktape_session *recipient = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(rid));
	if(recipient == NULL || g_atomic_int_get(&recipient->destroyed)) {
		janus_mutex_unlock(&session->recipients_mutex);
		janus_refcount_decrease(&session->ref);
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Recipient session %"SCNu32" doesn't exist", rid);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&recipient->ref);
	/* Add to the list of recipients */
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(g_slist_find(session->recipients, recipient) == NULL) {
		janus_refcount_increase(&session->ref);
		janus_refcount_increase(&recipient->ref);
		session->recipients = g_slist_append(session->recipients, recipient);
		recipient->sender = session;
	}
	janus_mutex_unlock(&session->recipients_mutex);
	/* Done */
	janus_refcount_decrease(&session->ref);
	janus_refcount_decrease(&recipient->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_removerecipient(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint32_t rid = (uint32_t)duk_get_number(ctx, 1);
	/* Find the sessions */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->recipients_mutex);
	janus_duktape_session *recipient = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(rid));
	if(recipient == NULL) {
		janus_mutex_unlock(&session->recipients_mutex);
		janus_refcount_decrease(&session->ref);
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Recipient session %"SCNu32" doesn't exist", rid);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&recipient->ref);
	/* Remove from the list of recipients */
	janus_mutex_unlock(&duktape_sessions_mutex);
	gboolean unref = FALSE;
	if(g_slist_find(session->recipients, recipient) != NULL) {
		session->recipients = g_slist_remove(session->recipients, recipient);
		recipient->sender = NULL;
		unref = TRUE;
	}
	janus_mutex_unlock(&session->recipients_mutex);
	if(unref) {
		janus_refcount_decrease(&session->ref);
		janus_refcount_decrease(&recipient->ref);
	}
	/* Done */
	janus_refcount_decrease(&session->ref);
	janus_refcount_decrease(&recipient->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_setbitrate(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint32_t bitrate = (uint32_t)duk_get_number(ctx, 1);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	session->bitrate = bitrate;
	/* Send a REMB right away too, if the PeerConnection is up */
	if(g_atomic_int_get(&session->started)) {
		/* No limit ~= 10000000 */
		janus_core->send_remb(session->handle, session->bitrate ? session->bitrate : 10000000);
	}
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_setplifreq(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint16_t pli_freq = (uint16_t)duk_get_number(ctx, 1);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	session->pli_freq = pli_freq;
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_setsubstream(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint16_t substream = (uint16_t)duk_get_number(ctx, 1);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(substream <= 2)
		session->sim_context.substream_target = substream;
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_settemporallayer(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	uint16_t temporal = (uint16_t)duk_get_number(ctx, 1);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(temporal <= 2)
		session->sim_context.templayer_target = temporal;
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_sendpli(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Send a PLI */
	session->pli_latest = janus_get_monotonic_time();
	JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->id);
	janus_core->send_pli(session->handle);
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_relayrtp(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_BOOLEAN) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_BOOLEAN), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 3) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 3)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	int is_video = duk_get_boolean(ctx, 1);
	const char *payload = duk_get_string(ctx, 2);
	int len = (int)duk_get_number(ctx, 3);
	if(payload == NULL || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid payload\n");
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Invalid payload of declared size %d", len);
		return duk_throw(ctx);
	}
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Send the RTP packet */
	janus_plugin_rtp rtp = { .video = is_video, .buffer = (char *)payload, .length = len };
	janus_plugin_rtp_extensions_reset(&rtp.extensions);
	janus_core->relay_rtp(session->handle, &rtp);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_relayrtcp(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_BOOLEAN) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_BOOLEAN), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 3) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 3)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	int is_video = duk_get_boolean(ctx, 1);
	const char *payload = duk_get_string(ctx, 2);
	int len = (int)duk_get_number(ctx, 3);
	if(payload == NULL || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid payload\n");
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Invalid payload of declared size %d", len);
		return duk_throw(ctx);
	}
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Send the RTCP packet */
	janus_plugin_rtcp rtcp = { .video = is_video, .buffer = (char *)payload, .length = len };
	janus_core->relay_rtcp(session->handle, &rtcp);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_relaytextdata(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	/* FIXME We should add support for labels, here */
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	const char *payload = duk_get_string(ctx, 1);
	int len = (int)duk_get_number(ctx, 2);
	if(payload == NULL || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid data\n");
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Invalid payload of declared size %d", len);
		return duk_throw(ctx);
	}
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(!g_atomic_int_get(&session->dataready)) {
		janus_refcount_decrease(&session->ref);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Datachannel not ready yet for session %"SCNu32, id);
		return duk_throw(ctx);
	}
	/* Send the data */
	janus_plugin_data data = {
		.label = NULL,
		.protocol = NULL,
		.binary = FALSE,
		.buffer = (char *)payload,
		.length = len
	};
	janus_core->relay_data(session->handle, &data);
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_relaybinarydata(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 1) != DUK_TYPE_STRING) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_STRING), janus_duktape_type_string(duk_get_type(ctx, 1)));
		return duk_throw(ctx);
	}
	if(duk_get_type(ctx, 2) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 2)));
		return duk_throw(ctx);
	}
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* FIXME We should add support for labels, here */
	const char *payload = duk_get_string(ctx, 1);
	int len = (int)duk_get_number(ctx, 2);
	if(payload == NULL || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid data\n");
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Invalid payload of declared size %d", len);
		return duk_throw(ctx);
	}
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(!g_atomic_int_get(&session->dataready)) {
		janus_refcount_decrease(&session->ref);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Datachannel not ready yet for session %"SCNu32, id);
		return duk_throw(ctx);
	}
	janus_plugin_data data = {
		.label = NULL,
		.protocol = NULL,
		.binary = TRUE,
		.buffer = (char *)payload,
		.length = len
	};
	janus_core->relay_data(session->handle, &data);
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}

static int janus_duktape_method_relaydata(duk_context *ctx) {
	JANUS_LOG(LOG_WARN, "Deprecated function 'relayData' called, invoking 'relayTextData' instead\n");
	return janus_duktape_method_relaytextdata(ctx);
}

static duk_ret_t janus_duktape_method_startrecording(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	int n = duk_get_top(ctx);
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->rec_mutex);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Iterate on all arguments, to see what we're being asked to record */
	int recordings = 0;
	n--;
	int i = 0;
	janus_recorder *arc = NULL, *vrc = NULL, *drc = NULL;
	while(n > 0) {
		i++; n--;
		const char *type = duk_get_string(ctx, i);
		i++; n--;
		const char *codec = duk_get_string(ctx, i);
		i++; n--;
		const char *folder = duk_get_string(ctx, i);
		i++; n--;
		const char *filename = duk_get_string(ctx, i);
		if(type == NULL || codec == NULL) {
			/* No type or codec provided, skip this */
			continue;
		}
		/* Check if the codec contains some fmtp stuff too */
		const char *c = codec, *f = NULL;
		gchar **parts = NULL;
		if(strstr(codec, "/fmtp=") != NULL) {
			parts = g_strsplit(codec, "/fmtp=", 2);
			c = parts[0];
			f = parts[1];
		}
		/* Create the recorder */
		janus_recorder *rc = janus_recorder_create_full(folder, c, f, filename);
		if(parts != NULL)
			g_strfreev(parts);
		if(rc == NULL) {
			JANUS_LOG(LOG_ERR, "Error creating '%s' recorder...\n", type);
			goto error;
		}
		if(!strcasecmp(type, "audio")) {
			if(arc != NULL || session->arc != NULL) {
				janus_recorder_destroy(rc);
				JANUS_LOG(LOG_WARN, "Duplicate audio recording, skipping\n");
				continue;
			}
			/* If media is encrypted, mark it in the recording */
			if(session->e2ee)
				janus_recorder_encrypted(rc);
			arc = rc;
		} else if(!strcasecmp(type, "video")) {
			if(vrc != NULL || session->vrc != NULL) {
				janus_recorder_destroy(rc);
				JANUS_LOG(LOG_WARN, "Duplicate video recording, skipping\n");
				continue;
			}
			janus_rtp_switching_context_reset(&session->rec_ctx);
			janus_rtp_simulcasting_context_reset(&session->rec_simctx);
			session->rec_simctx.substream_target = 2;
			session->rec_simctx.templayer_target = 2;
			/* If media is encrypted, mark it in the recording */
			if(session->e2ee)
				janus_recorder_encrypted(rc);
			vrc = rc;
		} else if(!strcasecmp(type, "data")) {
			if(drc != NULL || session->drc != NULL) {
				janus_recorder_destroy(rc);
				JANUS_LOG(LOG_WARN, "Duplicate data recording, skipping\n");
				continue;
			}
			drc = rc;
		}
		recordings++;
	}
	if(recordings == 0)
		goto error;
	if(arc) {
		session->arc = arc;
	}
	if(vrc) {
		session->vrc = vrc;
		/* Also send a keyframe request */
		session->pli_latest = janus_get_monotonic_time();
		JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->id);
		janus_core->send_pli(session->handle);
	}
	if(drc) {
		session->drc = drc;
	}
	janus_refcount_decrease(&session->ref);
	goto done;

error:
	janus_recorder_destroy(arc);
	janus_recorder_destroy(vrc);
	janus_recorder_destroy(drc);
	janus_mutex_unlock(&session->rec_mutex);
	/* Something went wrong */
	janus_refcount_decrease(&session->ref);
	duk_push_error_object(ctx, DUK_ERR_ERROR, "Error starting the recording of session %"SCNu32, id);
	return duk_throw(ctx);

done:
	janus_mutex_unlock(&session->rec_mutex);
	/* Done */
	duk_push_int(ctx, 0);
	return 1;
}

static duk_ret_t janus_duktape_method_stoprecording(duk_context *ctx) {
	if(duk_get_type(ctx, 0) != DUK_TYPE_NUMBER) {
		duk_push_error_object(ctx, DUK_RET_TYPE_ERROR, "Invalid argument (expected %s, got %s)\n",
			janus_duktape_type_string(DUK_TYPE_NUMBER), janus_duktape_type_string(duk_get_type(ctx, 0)));
		return duk_throw(ctx);
	}
	int n = duk_get_top(ctx);
	uint32_t id = (uint32_t)duk_get_number(ctx, 0);
	/* Find the session */
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		duk_push_error_object(ctx, DUK_ERR_ERROR, "Session %"SCNu32" doesn't exist", id);
		return duk_throw(ctx);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->rec_mutex);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Iterate on all arguments, to see what which recording we're being asked to stop */
	n--;
	int i = 0;
	while(n > 0) {
		i++; n--;
		const char *type = duk_get_string(ctx, i);
		if(type == NULL)
			continue;
		if(!strcasecmp(type, "audio")) {
			if(session->arc != NULL) {
				janus_recorder *rc = session->arc;
				session->arc = NULL;
				janus_recorder_close(rc);
				janus_recorder_destroy(rc);
			}
		} else if(!strcasecmp(type, "video")) {
			if(session->vrc != NULL) {
				janus_recorder *rc = session->vrc;
				session->vrc = NULL;
				janus_recorder_close(rc);
				janus_recorder_destroy(rc);
			}
		} else if(!strcasecmp(type, "data")) {
			if(session->drc != NULL) {
				janus_recorder *rc = session->drc;
				session->drc = NULL;
				janus_recorder_close(rc);
				janus_recorder_destroy(rc);
			}
		}
	}
	janus_mutex_unlock(&session->rec_mutex);
	/* Done */
	janus_refcount_decrease(&session->ref);
	duk_push_int(ctx, 0);
	return 1;
}


/* Plugin implementation */
int janus_duktape_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&duktape_stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_DUKTAPE_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_DUKTAPE_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_DUKTAPE_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config == NULL) {
		/* No config means no JS script */
		JANUS_LOG(LOG_ERR, "Failed to load configuration file for Duktape plugin...\n");
		return -1;
	}
	janus_config_print(config);
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
	janus_config_item *folder = janus_config_get(config, config_general, janus_config_type_item, "path");
	if(folder && folder->value)
		duktape_folder = g_strdup(folder->value);
	janus_config_item *script = janus_config_get(config, config_general, janus_config_type_item, "script");
	if(script == NULL || script->value == NULL) {
		JANUS_LOG(LOG_ERR, "Missing script path in Duktape plugin configuration...\n");
		janus_config_destroy(config);
		g_free(duktape_folder);
		return -1;
	}
	char *duktape_file = g_strdup(script->value);
	char *duktape_config = NULL;
	janus_config_item *conf = janus_config_get(config, config_general, janus_config_type_item, "config");
	if(conf && conf->value)
		duktape_config = g_strdup(conf->value);
	janus_config_destroy(config);

	/* Initialize Duktape */
	duktape_ctx = duk_create_heap_default();
	if(duktape_ctx == NULL) {
		JANUS_LOG(LOG_ERR, "Error creating Duktape heap...\n");
		g_free(duktape_folder);
		return -1;
	}
	duk_console_init(duktape_ctx, DUK_CONSOLE_PROXY_WRAPPER);
	duk_module_duktape_init(duktape_ctx);

	/* Register our functions */
	duk_push_c_function(duktape_ctx, janus_duktape_method_getmodulesfolder, 0);
	duk_put_global_string(duktape_ctx, "getModulesFolder");
	duk_push_c_function(duktape_ctx, janus_duktape_method_readfile, 1);
	duk_put_global_string(duktape_ctx, "readFile");
	duk_push_c_function(duktape_ctx, janus_duktape_method_pokescheduler, 0);
	duk_put_global_string(duktape_ctx, "pokeScheduler");
	duk_push_c_function(duktape_ctx, janus_duktape_method_timecallback, 3);
	duk_put_global_string(duktape_ctx, "timeCallback");
	duk_push_c_function(duktape_ctx, janus_duktape_method_pushevent, 4);
	duk_put_global_string(duktape_ctx, "pushEvent");
	duk_push_c_function(duktape_ctx, janus_duktape_method_notifyevent, 2);
	duk_put_global_string(duktape_ctx, "notifyEvent");
	duk_push_c_function(duktape_ctx, janus_duktape_method_eventsisenabled, 0);
	duk_put_global_string(duktape_ctx, "eventsIsEnabled");
	duk_push_c_function(duktape_ctx, janus_duktape_method_closepc, 1);
	duk_put_global_string(duktape_ctx, "closePc");
	duk_push_c_function(duktape_ctx, janus_duktape_method_endsession, 1);
	duk_put_global_string(duktape_ctx, "endSession");
	duk_push_c_function(duktape_ctx, janus_duktape_method_configuremedium, 4);
	duk_put_global_string(duktape_ctx, "configureMedium");
	duk_push_c_function(duktape_ctx, janus_duktape_method_addrecipient, 2);
	duk_put_global_string(duktape_ctx, "addRecipient");
	duk_push_c_function(duktape_ctx, janus_duktape_method_removerecipient, 2);
	duk_put_global_string(duktape_ctx, "removeRecipient");
	duk_push_c_function(duktape_ctx, janus_duktape_method_setbitrate, 2);
	duk_put_global_string(duktape_ctx, "setBitrate");
	duk_push_c_function(duktape_ctx, janus_duktape_method_setplifreq, 2);
	duk_put_global_string(duktape_ctx, "setPliFreq");
	duk_push_c_function(duktape_ctx, janus_duktape_method_setsubstream, 2);
	duk_put_global_string(duktape_ctx, "setSubstream");
	duk_push_c_function(duktape_ctx, janus_duktape_method_settemporallayer, 2);
	duk_put_global_string(duktape_ctx, "setTemporalLayer");
	duk_push_c_function(duktape_ctx, janus_duktape_method_sendpli, 1);
	duk_put_global_string(duktape_ctx, "sendPli");
	duk_push_c_function(duktape_ctx, janus_duktape_method_relayrtp, 4);
	duk_put_global_string(duktape_ctx, "relayRtp");
	duk_push_c_function(duktape_ctx, janus_duktape_method_relayrtcp, 4);
	duk_put_global_string(duktape_ctx, "relayRtcp");
	duk_push_c_function(duktape_ctx, janus_duktape_method_relaydata, 3);	/* Legacy function, deprecated */
	duk_put_global_string(duktape_ctx, "relayData");
	duk_push_c_function(duktape_ctx, janus_duktape_method_relaytextdata, 3);
	duk_put_global_string(duktape_ctx, "relayTextData");
	duk_push_c_function(duktape_ctx, janus_duktape_method_relaybinarydata, 3);
	duk_put_global_string(duktape_ctx, "relayBinaryData");
	duk_push_c_function(duktape_ctx, janus_duktape_method_startrecording, 13);
	duk_put_global_string(duktape_ctx, "startRecording");
	duk_push_c_function(duktape_ctx, janus_duktape_method_stoprecording, 4);
	duk_put_global_string(duktape_ctx, "stopRecording");
	duk_push_c_function(duktape_ctx, janus_duktape_method_getversion, 0);
	duk_put_global_string(duktape_ctx, "getDuktapeVersion");
	/* Register all extra functions, if any were added */
	janus_duktape_register_extra_functions(duktape_ctx);

	/* Now load the script (FIXME badly) */
	FILE *f = fopen(duktape_file, "rb");
	if(f == NULL) {
		JANUS_LOG(LOG_ERR, "Error loading JS script %s: no such file\n", duktape_file);
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	if(len < 1) {
		JANUS_LOG(LOG_ERR, "Error loading JS script %s: empty file\n", duktape_file);
		fclose(f);
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		return -1;
	}
	char *buf = (char *)g_malloc0(len);
	fseek(f, 0, SEEK_SET);
	fread((void *)buf, 1, len, f);
	fclose(f);
	duk_push_lstring(duktape_ctx, (const char *)buf, (duk_size_t)len);
	g_free(buf);
	if(duk_peval(duktape_ctx) != 0) {
		JANUS_LOG(LOG_ERR, "Error loading JS script %s: %s\n", duktape_file, duk_safe_to_string(duktape_ctx, -1));
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		return -1;
	}
	duk_pop(duktape_ctx);
	/* Make sure that all the functions we need are there */
	uint i=0;
	for(i=0; i<duktape_funcsize; i++) {
		duk_get_global_string(duktape_ctx, duktape_functions[i]);
		if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) == 0) {
			JANUS_LOG(LOG_ERR, "Function '%s' is missing in %s\n", duktape_functions[i], duktape_file);
			duk_destroy_heap(duktape_ctx);
			g_free(duktape_folder);
			g_free(duktape_file);
			return -1;
		}
	}
	/* Some JS functions are optional (e.g., those to directly handle RTP, RTCP and
	 * data, as those will typically be kept at a C level, with JavaScript only dictating
	 * the logic, or those overriding the plugin namespace and versioning information */
	duk_get_global_string(duktape_ctx, "getVersion");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_version = TRUE;
	duk_get_global_string(duktape_ctx, "getVersionString");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_version_string = TRUE;
	duk_get_global_string(duktape_ctx, "getDescription");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_description = TRUE;
	duk_get_global_string(duktape_ctx, "getName");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_name = TRUE;
	duk_get_global_string(duktape_ctx, "getAuthor");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_author = TRUE;
	duk_get_global_string(duktape_ctx, "getPackage");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_get_package = TRUE;
	duk_get_global_string(duktape_ctx, "handleAdminMessage");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_handle_admin_message = TRUE;
	duk_get_global_string(duktape_ctx, "incomingRtp");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_incoming_rtp = TRUE;
	duk_get_global_string(duktape_ctx, "incomingRtcp");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_incoming_rtcp = TRUE;
	duk_get_global_string(duktape_ctx, "incomingData");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0) {
		has_incoming_data_legacy = TRUE;
		JANUS_LOG(LOG_WARN, "The Duktape script contains the deprecated 'incomingData' callback: update it "
			"to use 'incomingTextData' and/or 'incomingBinaryData' in the future (see PR #1878)\n");
	}
	duk_get_global_string(duktape_ctx, "incomingTextData");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_incoming_text_data = TRUE;
	duk_get_global_string(duktape_ctx, "incomingBinaryData");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_incoming_binary_data = TRUE;
	duk_get_global_string(duktape_ctx, "dataReady");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_data_ready = TRUE;
	duk_get_global_string(duktape_ctx, "slowLink");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_slow_link = TRUE;
	duk_get_global_string(duktape_ctx, "substreamChanged");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_substream_changed = TRUE;
	duk_get_global_string(duktape_ctx, "temporalLayerChanged");
	if(duk_is_function(duktape_ctx, duk_get_top(duktape_ctx)-1) != 0)
		has_temporal_changed = TRUE;

	duktape_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_duktape_session_destroy);
	duktape_ids = g_hash_table_new(NULL, NULL);
	events = g_async_queue_new();
	callbacks = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_duktape_callback_free);

	g_atomic_int_set(&duktape_initialized, 1);

	/* Launch the scheduler thread (which will be responsible for resuming asynchronous coroutines) */
	GError *error = NULL;
	scheduler_thread = g_thread_try_new("duktape scheduler", janus_duktape_scheduler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&duktape_initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Duktape scheduler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		g_free(duktape_config);
		return -1;
	}
	/* Launch the timer loop thread (which will be responsible for scheduling timed callbacks) */
	timer_context = g_main_context_new();
	timer_loop = g_main_loop_new(timer_context, FALSE);
	timer_thread = g_thread_try_new("duktape timer", janus_duktape_timer, timer_loop, &error);
	if(error != NULL) {
		g_atomic_int_set(&duktape_initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Duktape timer loop thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		if(timer_loop != NULL)
			g_main_loop_unref(timer_loop);
		if(timer_context != NULL)
			g_main_context_unref(timer_context);
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		g_free(duktape_config);
		return -1;
	}

	/* This is the callback we'll need to invoke to contact the Janus core */
	janus_core = callback;

	/* Init the JS script, in case it's needed */
	duk_get_global_string(duktape_ctx, "init");
	duk_push_string(duktape_ctx, duktape_config);
	int res = duk_pcall(duktape_ctx, 1);
	if(res != DUK_EXEC_SUCCESS) {
		g_atomic_int_set(&duktape_initialized, 0);
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(duktape_ctx, -1));
		duk_pop(duktape_ctx);
		if(timer_loop != NULL)
			g_main_loop_unref(timer_loop);
		if(timer_context != NULL)
			g_main_context_unref(timer_context);
		duk_destroy_heap(duktape_ctx);
		g_free(duktape_folder);
		g_free(duktape_file);
		g_free(duktape_config);
		return -1;
	}

	g_free(duktape_file);
	g_free(duktape_config);

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_DUKTAPE_NAME);
	return 0;
}

void janus_duktape_destroy(void) {
	if(!g_atomic_int_get(&duktape_initialized))
		return;
	g_atomic_int_set(&duktape_stopping, 1);

	g_async_queue_push(events, GUINT_TO_POINTER(janus_duktape_event_exit));
	if(scheduler_thread != NULL) {
		g_thread_join(scheduler_thread);
		scheduler_thread = NULL;
	}
	if(timer_loop != NULL)
		g_main_loop_quit(timer_loop);
	if(timer_thread != NULL) {
		g_thread_join(timer_thread);
		timer_thread = NULL;
	}
	if(timer_loop != NULL) {
		g_main_loop_unref(timer_loop);
		timer_loop = NULL;
	}
	if(timer_context != NULL) {
		g_main_context_unref(timer_context);
		timer_context = NULL;
	}

	/* Deinit the JS script, in case it's needed */
	janus_mutex_lock(&duktape_mutex);
	duk_get_global_string(duktape_ctx, "destroy");
	int res = duk_pcall(duktape_ctx, 0);
	if(res != DUK_EXEC_SUCCESS) {
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(duktape_ctx, -1));
		duk_pop(duktape_ctx);
	}
	g_hash_table_destroy(callbacks);
	callbacks = NULL;
	janus_mutex_unlock(&duktape_mutex);

	janus_mutex_lock(&duktape_sessions_mutex);
	g_hash_table_destroy(duktape_sessions);
	duktape_sessions = NULL;
	g_hash_table_destroy(duktape_ids);
	duktape_ids = NULL;
	g_async_queue_unref(events);
	events = NULL;
	janus_mutex_unlock(&duktape_sessions_mutex);

	janus_mutex_lock(&duktape_mutex);
	duk_destroy_heap(duktape_ctx);
	duktape_ctx = NULL;
	janus_mutex_unlock(&duktape_mutex);

	g_free(duktape_script_version_string);
	g_free(duktape_script_description);
	g_free(duktape_script_name);
	g_free(duktape_script_author);
	g_free(duktape_script_package);

	g_free(duktape_folder);

	g_atomic_int_set(&duktape_initialized, 0);
	g_atomic_int_set(&duktape_stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_DUKTAPE_NAME);
}

int janus_duktape_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_duktape_get_version(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_version) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_version != -1) {
			/* Unless we asked already */
			return duktape_script_version;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getVersion");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_VERSION;
		}
		duktape_script_version = (int)duk_get_number(t, -1);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_version;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_VERSION;
}

const char *janus_duktape_get_version_string(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_version_string) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_version_string != NULL) {
			/* Unless we asked already */
			return duktape_script_version_string;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getVersionString");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_VERSION_STRING;
		}
		const char *version = duk_get_string(t, -1);
		if(version != NULL)
			duktape_script_version_string = g_strdup(version);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_version_string;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_VERSION_STRING;
}

const char *janus_duktape_get_description(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_description) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_description != NULL) {
			/* Unless we asked already */
			return duktape_script_description;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getDescription");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_DESCRIPTION;
		}
		const char *description = duk_get_string(t, -1);
		if(description != NULL)
			duktape_script_description = g_strdup(description);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_description;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_DESCRIPTION;
}

const char *janus_duktape_get_name(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_name) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_name != NULL) {
			/* Unless we asked already */
			return duktape_script_name;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getName");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_NAME;
		}
		const char *name = duk_get_string(t, -1);
		if(name != NULL)
			duktape_script_name = g_strdup(name);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_name;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_NAME;
}

const char *janus_duktape_get_author(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_author) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_author != NULL) {
			/* Unless we asked already */
			return duktape_script_author;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getAuthor");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_AUTHOR;
		}
		const char *author = duk_get_string(t, -1);
		if(author != NULL)
			duktape_script_author = g_strdup(author);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_author;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_AUTHOR;
}

const char *janus_duktape_get_package(void) {
	/* Check if the JS script wants to override this method and return info itself */
	if(has_get_package) {
		/* Yep, pass the request to the JS script and return the info */
		if(duktape_script_package != NULL) {
			/* Unless we asked already */
			return duktape_script_package;
		}
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "getPackage");
		int res = duk_pcall(t, 0);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... return the Janus Duktape plugin info */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
			duk_pop(t);
			duk_pop(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
			return JANUS_DUKTAPE_PACKAGE;
		}
		const char *package = duk_get_string(t, -1);
		if(package != NULL)
			duktape_script_package = g_strdup(package);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return duktape_script_package;
	}
	/* No override, return the Janus Duktape plugin info */
	return JANUS_DUKTAPE_PACKAGE;
}

janus_duktape_session *janus_duktape_lookup_session(janus_plugin_session *handle) {
	janus_duktape_session *session = NULL;
	if (g_hash_table_contains(duktape_sessions, handle)) {
		session = (janus_duktape_session *)handle->plugin_handle;
	}
	return session;
}

void janus_duktape_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&duktape_sessions_mutex);
	uint32_t id = 0;
	while(id == 0) {
		id = janus_random_uint32();
		if(g_hash_table_lookup(duktape_ids, GUINT_TO_POINTER(id))) {
			id = 0;
			continue;
		}
	}
	JANUS_LOG(LOG_VERB, "Creating new Duktape session %"SCNu32"...\n", id);
	janus_duktape_session *session = (janus_duktape_session *)g_malloc0(sizeof(janus_duktape_session));
	session->handle = handle;
	session->id = id;
	janus_rtp_switching_context_reset(&session->rtpctx);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	session->sim_context.substream_target = 2;
	session->sim_context.templayer_target = 2;
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	session->vcodec = JANUS_VIDEOCODEC_NONE;
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_duktape_session_free);
	handle->plugin_handle = session;
	g_hash_table_insert(duktape_sessions, handle, session);
	g_hash_table_insert(duktape_ids, GUINT_TO_POINTER(session->id), session);
	janus_mutex_unlock(&duktape_sessions_mutex);

	/* Notify the JS script */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "createSession");
	duk_push_number(t, session->id);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... this session will likely be broken */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
	}
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);

	return;
}

void janus_duktape_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	uint32_t id = session->id;
	JANUS_LOG(LOG_VERB, "Removing Duktape session %"SCNu32"...\n", id);
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);

	/* Notify the JS script */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "destroySession");
	duk_push_number(t, id);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
	}
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);

	/* Get any rid references recipients of this sessions may have */
	janus_mutex_lock(&session->recipients_mutex);
	while(session->recipients != NULL) {
		janus_duktape_session *recipient = (janus_duktape_session *)session->recipients->data;
		if(recipient != NULL) {
			recipient->sender = NULL;
			janus_refcount_decrease(&session->ref);
			janus_refcount_decrease(&recipient->ref);
		}
		session->recipients = g_slist_remove(session->recipients, recipient);
	}
	janus_mutex_unlock(&session->recipients_mutex);

	/* Finally, remove from the hashtable */
	janus_mutex_lock(&duktape_sessions_mutex);
	g_hash_table_remove(duktape_sessions, handle);
	janus_mutex_unlock(&duktape_sessions_mutex);
	janus_refcount_decrease(&session->ref);

	return;
}

json_t *janus_duktape_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized)) {
		return NULL;
	}
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	/* Ask the JS script for information on this session */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "querySession");
	duk_push_number(t, session->id);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... return this error */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		json_t *json = json_object();
		json_object_set_new(json, "error", json_string(duk_safe_to_string(t, -1)));
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_refcount_decrease(&session->ref);
		return json;
	}
	janus_refcount_decrease(&session->ref);
	const char *info = duk_get_string(t, -1);
	duk_pop(t);
	duk_pop(duktape_ctx);
	/* We need a Jansson object */
	json_error_t error;
	json_t *json = json_loads(info, 0, &error);
	janus_mutex_unlock(&duktape_mutex);
	if(!json) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s", error.line, error.text);
		return NULL;
	}
	return json;
}

struct janus_plugin_result *janus_duktape_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&duktape_stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);

	/* Processing the message is up to the JS script: serialize the Jansson objects to strings */
	char *message_text = message ? json_dumps(message, JSON_INDENT(0) | JSON_PRESERVE_ORDER) : NULL;
	json_decref(message);
	if(message == NULL || message_text == NULL) {
		janus_refcount_decrease(&session->ref);
		JANUS_LOG(LOG_ERR, "Invalid message..?\n");
		if(jsep != NULL)
			json_decref(jsep);
		g_free(transaction);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}
	char *jsep_text = jsep ? json_dumps(jsep, JSON_INDENT(0) | JSON_PRESERVE_ORDER) : NULL;
	if(jsep != NULL) {
		json_t *simulcast = json_object_get(jsep, "simulcast");
		if(simulcast != NULL) {
			janus_rtp_simulcasting_prepare(simulcast,
				&session->rid_extmap_id, NULL,
				session->ssrc, session->rid);
		}
		const char *sdp_type = json_string_value(json_object_get(jsep, "type"));
		if(sdp_type && !strcasecmp(sdp_type, "answer")) {
			char error_str[512];
			const char *sdp = json_string_value(json_object_get(jsep, "sdp"));
			janus_sdp *parsed_sdp = janus_sdp_parse(sdp, error_str, sizeof(error_str));
			const char *vcodec = NULL;
			janus_sdp_find_first_codecs(parsed_sdp, NULL, &vcodec);
			if(vcodec)
				session->vcodec = janus_videocodec_from_name(vcodec);
			if(session->vcodec != JANUS_VIDEOCODEC_VP8 && session->vcodec != JANUS_VIDEOCODEC_H264) {
				/* VP8 r H.264 were not negotiated, if simulcasting was enabled then disable it here */
				int i=0;
				for(i=0; i<3; i++) {
					session->ssrc[i] = 0;
					g_free(session->rid[0]);
					session->rid[0] = NULL;
				}
			}
			janus_sdp_destroy(parsed_sdp);
		}
		if(json_is_true(json_object_get(jsep, "e2ee")))
			session->e2ee = TRUE;
		json_decref(jsep);
	}
	/* Invoke the script function */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "handleMessage");
	duk_push_number(t, session->id);
	duk_push_string(t, transaction);
	duk_push_string(t, message_text);
	duk_push_string(t, jsep_text);
	int res = duk_pcall(t, 4);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Duktape error", NULL);
	}
	janus_refcount_decrease(&session->ref);
	if(message_text != NULL)
		free(message_text);
	if(jsep_text != NULL)
		free(jsep_text);
	g_free(transaction);
	/* Check if this is a synchronous or asynchronous response */
	if(duk_get_type(t, 0) == DUK_TYPE_NUMBER) {
		/* Either an error or an asynchronous response */
		int res = (int)duk_get_number(t, 0);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		if(res < 0) {
			/* We got an error */
			return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Duktape error", NULL);
		}
		/* If we got here, it's an asynchronous response */
		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else if(duk_get_type(t, 0) == DUK_TYPE_STRING) {
		/* If it's not a number, it's a string, and so a synchronous response */
		const char *response = duk_get_string(t, 0);
		json_error_t error;
		json_t *json = json_loads(response, 0, &error);
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		if(!json) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Duktape error", NULL);
		}
		return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, json);
	}
	/* If we got here, we didn't get what we expect */
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);
	return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Duktape error", NULL);
}

json_t *janus_duktape_handle_admin_message(json_t *message) {
	if(!has_handle_admin_message || message == NULL)
		return NULL;
	char *message_text = json_dumps(message, JSON_INDENT(0) | JSON_PRESERVE_ORDER);
	/* Invoke the script function */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "handleAdminMessage");
	duk_push_string(t, message_text);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return NULL;
	}
	if(message_text != NULL)
		free(message_text);
	/* Get the response */
	const char *response = duk_get_string(t, 0);
	json_error_t error;
	json_t *json = json_loads(response, 0, &error);
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);
	if(!json) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
		return NULL;
	}
	return json;
}

void janus_duktape_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->started, 1);
	session->pli_latest = janus_get_monotonic_time();

	/* Notify the JS script */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "setupMedia");
	duk_push_number(t, session->id);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... this media session will likely be broken */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
	}
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);
	janus_refcount_decrease(&session->ref);
}

void janus_duktape_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *rtp_packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_duktape_session *session = (janus_duktape_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	gboolean video = rtp_packet->video;
	char *buf = rtp_packet->buffer;
	uint16_t len = rtp_packet->length;
	/* Check if the JS script wants to handle/manipulate RTP packets itself */
	if(has_incoming_rtp) {
		/* Yep, pass the data to the JS script and return */
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "incomingRtp");
		duk_push_number(t, session->id);
		duk_push_boolean(t, video);
		duk_push_lstring(t, buf, len);
		duk_push_number(t, len);
		int res = duk_pcall(t, 4);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		}
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return;
	}
	/* Is this session allowed to send media? */
	if((video && !session->send_video) || (!video && !session->send_audio))
		return;
	/* Handle the packet */
	janus_rtp_header *rtp = (janus_rtp_header *)buf;
	/* Check if we're simulcasting, and if so, keep track of the "layer" */
	int sc = video ? 0 : -1;
	if(video && (session->ssrc[0] != 0 || session->rid[0] != NULL)) {
		uint32_t ssrc = ntohl(rtp->ssrc);
		if(ssrc == session->ssrc[0])
			sc = 0;
		else if(ssrc == session->ssrc[1])
			sc = 1;
		else if(ssrc == session->ssrc[2])
			sc = 2;
		else if(session->rid_extmap_id > 0) {
			/* We may not know the SSRC yet, try the rid RTP extension */
			char sdes_item[16];
			if(janus_rtp_header_extension_parse_rid(buf, len, session->rid_extmap_id, sdes_item, sizeof(sdes_item)) == 0) {
				if(session->rid[0] != NULL && !strcmp(session->rid[0], sdes_item)) {
					session->ssrc[0] = ssrc;
					sc = 0;
				} else if(session->rid[1] != NULL && !strcmp(session->rid[1], sdes_item)) {
					session->ssrc[1] = ssrc;
					sc = 1;
				} else if(session->rid[2] != NULL && !strcmp(session->rid[2], sdes_item)) {
					session->ssrc[2] = ssrc;
					sc = 2;
				}
			}
		}
	}
	/* Are we recording? */
	if(!video || (session->ssrc[0] == 0 && session->rid[0] == NULL)) {
		janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
	} else {
		/* We're simulcasting, save the best video quality */
		gboolean save = janus_rtp_simulcasting_context_process_rtp(&session->rec_simctx,
			buf, len, session->ssrc, session->rid, session->vcodec, &session->rec_ctx);
		if(save) {
			uint32_t seq_number = ntohs(rtp->seq_number);
			uint32_t timestamp = ntohl(rtp->timestamp);
			uint32_t ssrc = ntohl(rtp->ssrc);
			janus_rtp_header_update(rtp, &session->rec_ctx, TRUE, 0);
			/* We use a fixed SSRC for the whole recording */
			rtp->ssrc = session->ssrc[0];
			janus_recorder_save_frame(session->vrc, buf, len);
			/* Restore the header, as it will be needed by recipients of this packet */
			rtp->ssrc = htonl(ssrc);
			rtp->timestamp = htonl(timestamp);
			rtp->seq_number = htons(seq_number);
		}
	}
	janus_duktape_rtp_relay_packet packet;
	packet.sender = session;
	packet.data = rtp;
	packet.length = len;
	packet.is_video = video;
	packet.ssrc[0] = (sc != -1 ? session->ssrc[0] : 0);
	packet.ssrc[1] = (sc != -1 ? session->ssrc[1] : 0);
	packet.ssrc[2] = (sc != -1 ? session->ssrc[2] : 0);
	/* Backup the actual timestamp and sequence number set by the publisher, in case switching is involved */
	packet.timestamp = ntohl(packet.data->timestamp);
	packet.seq_number = ntohs(packet.data->seq_number);
	/* Relay to all recipients */
	janus_mutex_lock_nodebug(&session->recipients_mutex);
	g_slist_foreach(session->recipients, janus_duktape_relay_rtp_packet, &packet);
	janus_mutex_unlock_nodebug(&session->recipients_mutex);

	/* Check if we need to send any PLI to this media source */
	if(video && session->pli_freq > 0) {
		/* We send a FIR every tot seconds, depending on what the JS script configured */
		gint64 now = janus_get_monotonic_time();
		if((now-session->pli_latest) >= ((gint64)session->pli_freq*G_USEC_PER_SEC)) {
			session->pli_latest = now;
			janus_core->send_pli(handle);
		}
	}
}

void janus_duktape_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_duktape_session *session = (janus_duktape_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	gboolean video = packet->video;
	char *buf = packet->buffer;
	uint16_t len = packet->length;
	/* Check if the JS script wants to handle/manipulate RTCP packets itself */
	if(has_incoming_rtcp) {
		/* Yep, pass the data to the JS script and return */
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "incomingRtcp");
		duk_push_number(t, session->id);
		duk_push_boolean(t, video);
		duk_push_lstring(t, buf, len);
		duk_push_number(t, len);
		int res = duk_pcall(t, 4);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		}
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return;
	}
	/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
	uint32_t bitrate = janus_rtcp_get_remb(buf, len);
	if(bitrate > 0) {
		/* No limit ~= 10000000 */
		janus_core->send_remb(handle, session->bitrate ? session->bitrate : 10000000);
	}
	/* If there's an incoming PLI, instead, relay it to the source of the media if any */
	if(janus_rtcp_has_pli(buf, len)) {
		if(session->sender != NULL) {
			janus_mutex_lock_nodebug(&session->sender->recipients_mutex);
			/* Send a PLI */
			session->sender->pli_latest = janus_get_monotonic_time();
			JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->sender->id);
			janus_core->send_pli(session->sender->handle);
			janus_mutex_unlock_nodebug(&session->sender->recipients_mutex);
		}
	}
}

void janus_duktape_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_duktape_session *session = (janus_duktape_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	char *buf = packet->buffer;
	uint16_t len = packet->length;
	/* Are we recording? */
	janus_recorder_save_frame(session->drc, buf, len);
	/* Check if the JS script wants to handle/manipulate data channel packets itself */
	if((!packet->binary && (has_incoming_data_legacy || has_incoming_text_data)) || (packet->binary && has_incoming_binary_data)) {
		/* Yep, pass the data to the JS script and return */
		if(packet->binary && !has_incoming_text_data)
			JANUS_LOG(LOG_WARN, "Missing 'incomingTextData', invoking deprecated function 'incomingData' instead\n");
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, packet->binary ? "incomingBinaryData" : (has_incoming_text_data ? "incomingTextData" : "incomingData"));
		duk_push_number(t, session->id);
		/* We use a string for both text and binary data */
		duk_push_lstring(t, buf, len);
		duk_push_number(t, len);
		int res = duk_pcall(t, 3);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		}
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return;
	}
	/* Is this session allowed to send data? */
	if(!session->send_data)
		return;
	JANUS_LOG(LOG_VERB, "Got a %s DataChannel message (%d bytes) to forward\n",
		packet->binary ? "binary" : "text", len);
	/* Relay to all recipients */
	janus_duktape_rtp_relay_packet pkt;
	pkt.sender = session;
	pkt.data = (janus_rtp_header *)buf;
	pkt.length = len;
	pkt.is_rtp = FALSE;
	pkt.textdata = !packet->binary;
	janus_mutex_lock_nodebug(&session->recipients_mutex);
	/* FIXME We should add support for labels, here */
	g_slist_foreach(session->recipients, janus_duktape_relay_data_packet, &pkt);
	janus_mutex_unlock_nodebug(&session->recipients_mutex);
}

void janus_duktape_data_ready(janus_plugin_session *handle) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_duktape_session *session = (janus_duktape_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	if(g_atomic_int_compare_and_exchange(&session->dataready, 0, 1)) {
		JANUS_LOG(LOG_INFO, "[%s-%p] Data channel available\n", JANUS_DUKTAPE_PACKAGE, handle);
	}
	/* Check if the JS script wants to receive this event */
	if(has_data_ready) {
		/* Yep, pass the event to the JS script and return */
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "dataReady");
		duk_push_number(t, session->id);
		int res = duk_pcall(t, 1);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		}
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
		return;
	}
}

void janus_duktape_slow_link(janus_plugin_session *handle, int uplink, int video) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	/* Check if the Duktape script wants to handle such events */
	janus_refcount_increase(&session->ref);
	if(has_slow_link) {
		/* Notify the JS script */
		janus_mutex_lock(&duktape_mutex);
		duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
		duk_context *t = duk_get_context(duktape_ctx, thr_idx);
		duk_get_global_string(t, "slowLink");
		duk_push_number(t, session->id);
		duk_push_boolean(t, uplink);
		duk_push_boolean(t, video);
		int res = duk_pcall(t, 3);
		if(res != DUK_EXEC_SUCCESS) {
			/* Something went wrong... */
			JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
		}
		duk_pop(t);
		duk_pop(duktape_ctx);
		janus_mutex_unlock(&duktape_mutex);
	}
	janus_refcount_decrease(&session->ref);
}

void janus_duktape_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_DUKTAPE_PACKAGE, handle);
	if(g_atomic_int_get(&duktape_stopping) || !g_atomic_int_get(&duktape_initialized))
		return;
	janus_mutex_lock(&duktape_sessions_mutex);
	janus_duktape_session *session = janus_duktape_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&duktape_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&duktape_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	g_atomic_int_set(&session->started, 0);
	g_atomic_int_set(&session->dataready, 0);

	/* Reset the media properties */
	session->accept_audio = FALSE;
	session->accept_video = FALSE;
	session->accept_data = FALSE;
	session->send_audio = FALSE;
	session->send_video = FALSE;
	session->send_data = FALSE;
	session->bitrate = 0;
	session->pli_freq = 0;
	session->pli_latest = 0;
	session->e2ee = FALSE;
	janus_rtp_switching_context_reset(&session->rtpctx);
	janus_rtp_simulcasting_context_reset(&session->sim_context);
	session->sim_context.substream_target = 2;
	session->sim_context.templayer_target = 2;
	janus_vp8_simulcast_context_reset(&session->vp8_context);
	session->vcodec = JANUS_VIDEOCODEC_NONE;
	int i=0;
	for(i=0; i<3; i++) {
		session->ssrc[i] = 0;
		g_free(session->rid[i]);
		session->rid[i] = NULL;
	}

	/* Get rid of the recipients */
	janus_mutex_lock(&session->recipients_mutex);
	while(session->recipients) {
		janus_duktape_session *recipient = (janus_duktape_session *)session->recipients->data;
		session->recipients = g_slist_remove(session->recipients, recipient);
		recipient->sender = NULL;
		janus_refcount_decrease(&session->ref);
		janus_refcount_decrease(&recipient->ref);
	}
	janus_mutex_unlock(&session->recipients_mutex);

	/* Notify the JS script */
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, "hangupMedia");
	duk_push_number(t, session->id);
	int res = duk_pcall(t, 1);
	if(res != DUK_EXEC_SUCCESS) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
	}
	duk_pop(t);
	duk_pop(duktape_ctx);
	janus_mutex_unlock(&duktape_mutex);
	janus_refcount_decrease(&session->ref);
}

/* Helpers to quickly relay RTP and data packets to the intended recipients */
static void janus_duktape_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_duktape_rtp_relay_packet *packet = (janus_duktape_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_duktape_session *sender = (janus_duktape_session *)packet->sender;
	janus_duktape_session *session = (janus_duktape_session *)data;
	if(!session || !session->handle || !g_atomic_int_get(&session->started)) {
		return;
	}

	/* Check if this recipient is willing/allowed to receive this medium */
	if((packet->is_video && !session->accept_video) || (!packet->is_video && !session->accept_audio)) {
		/* Nope, don't relay */
		return;
	}
	if(packet->ssrc[0] != 0) {
		/* Handle simulcast: make sure we have a payload to work with */
		int plen = 0;
		char *payload = janus_rtp_payload((char *)packet->data, packet->length, &plen);
		if(payload == NULL)
			return;
		/* Process this packet: don't relay if it's not the SSRC/layer we wanted to handle */
		gboolean relay = janus_rtp_simulcasting_context_process_rtp(&session->sim_context,
			(char *)packet->data, packet->length, packet->ssrc, NULL, sender->vcodec, &session->rtpctx);
		if(session->sim_context.need_pli && sender->handle) {
			/* Send a PLI */
			JANUS_LOG(LOG_VERB, "We need a PLI for the simulcast context\n");
			janus_core->send_pli(sender->handle);
		}
		/* Do we need to drop this? */
		if(!relay)
			return;
		/* Any event we should notify? */
		if(session->sim_context.changed_substream) {
			/* Notify the script about the substream change */
			if(has_substream_changed) {
				janus_mutex_lock(&duktape_mutex);
				duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
				duk_context *t = duk_get_context(duktape_ctx, thr_idx);
				duk_get_global_string(t, "substreamChanged");
				duk_push_number(t, session->id);
				duk_push_number(t, session->sim_context.substream);
				int res = duk_pcall(t, 2);
				if(res != DUK_EXEC_SUCCESS) {
					/* Something went wrong... */
					JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
				}
				duk_pop(t);
				duk_pop(duktape_ctx);
				janus_mutex_unlock(&duktape_mutex);
			}
		}
		if(session->sim_context.changed_temporal) {
			/* Notify the user about the temporal layer change */
			if(has_substream_changed) {
				janus_mutex_lock(&duktape_mutex);
				duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
				duk_context *t = duk_get_context(duktape_ctx, thr_idx);
				duk_get_global_string(t, "temporalLayerChanged");
				duk_push_number(t, session->id);
				duk_push_number(t, session->sim_context.templayer);
				int res = duk_pcall(t, 2);
				if(res != DUK_EXEC_SUCCESS) {
					/* Something went wrong... */
					JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
				}
				duk_pop(t);
				duk_pop(duktape_ctx);
				janus_mutex_unlock(&duktape_mutex);
			}
		}
		/* If we got here, update the RTP header and send the packet */
		janus_rtp_header_update(packet->data, &session->rtpctx, TRUE, 0);
		char vp8pd[6];
		if(sender->vcodec == JANUS_VIDEOCODEC_VP8) {
			/* For VP8, we save the original payload descriptor, to restore it after */
			memcpy(vp8pd, payload, sizeof(vp8pd));
			janus_vp8_simulcast_descriptor_update(payload, plen, &session->vp8_context,
				session->sim_context.changed_substream);
		}
		/* Send the packet */
		if(janus_core != NULL) {
			janus_plugin_rtp rtp = { .video = packet->is_video, .buffer = (char *)packet->data, .length = packet->length };
			janus_plugin_rtp_extensions_reset(&rtp.extensions);
			janus_core->relay_rtp(session->handle, &rtp);
		}
		/* Restore the timestamp and sequence number to what the publisher set them to */
		packet->data->timestamp = htonl(packet->timestamp);
		packet->data->seq_number = htons(packet->seq_number);
		if(sender->vcodec == JANUS_VIDEOCODEC_VP8) {
			/* Restore the original payload descriptor as well, as it will be needed by the next viewer */
			memcpy(payload, vp8pd, sizeof(vp8pd));
		}
	} else {
		/* Fix sequence number and timestamp (publisher switching may be involved) */
		janus_rtp_header_update(packet->data, &session->rtpctx, packet->is_video, 0);
		/* Send the packet */
		if(janus_core != NULL) {
			janus_plugin_rtp rtp = { .video = packet->is_video, .buffer = (char *)packet->data, .length = packet->length };
			janus_plugin_rtp_extensions_reset(&rtp.extensions);
			janus_core->relay_rtp(session->handle, &rtp);
		}
		/* Restore the timestamp and sequence number to what the publisher set them to */
		packet->data->timestamp = htonl(packet->timestamp);
		packet->data->seq_number = htons(packet->seq_number);
	}

	return;
}

static void janus_duktape_relay_data_packet(gpointer data, gpointer user_data) {
	janus_duktape_rtp_relay_packet *packet = (janus_duktape_rtp_relay_packet *)user_data;
	if(!packet || packet->is_rtp || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_duktape_session *session = (janus_duktape_session *)data;
	if(!session || !session->handle || !g_atomic_int_get(&session->started) ||
			!session->accept_data || !g_atomic_int_get(&session->dataready)) {
		return;
	}
	if(janus_core != NULL) {
		JANUS_LOG(LOG_VERB, "Forwarding %s DataChannel message (%d bytes) to session %"SCNu32"\n",
			packet->textdata ? "text" : "binary", packet->length, session->id);
		janus_plugin_data data = {
			.label = NULL,
			.protocol = NULL,
			.binary = !packet->textdata,
			.buffer = (char *)packet->data,
			.length = packet->length
		};
		janus_core->relay_data(session->handle, &data);
	}
	return;
}

/* This is a scheduler thread: if we know there are coroutines to resume in
 * JavaScript (e.g., for asynchronous requests), we do that ourselves here */
static void *janus_duktape_scheduler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Duktape scheduler thread\n");
	janus_duktape_event *event = NULL;
	/* Wait until there are events to process */
	while(g_atomic_int_get(&duktape_initialized) && !g_atomic_int_get(&duktape_stopping)) {
		event = g_async_queue_pop(events);
		if(event == GUINT_TO_POINTER(janus_duktape_event_exit))
			break;
		if(event == GUINT_TO_POINTER(janus_duktape_event_resume)) {
			/* There are coroutines to resume */
			janus_mutex_lock(&duktape_mutex);
			duk_get_global_string(duktape_ctx, "resumeScheduler");
			int res = duk_pcall(duktape_ctx, 0);
			if(res != DUK_EXEC_SUCCESS) {
				JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(duktape_ctx, -1));
			}
			duk_pop(duktape_ctx);
			/* Print the count of elements into Duktape stack */
			janus_duktape_stackdump(duktape_ctx);
			janus_mutex_unlock(&duktape_mutex);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving Duktape scheduler thread\n");
	return NULL;
}

/* This is a loop that can be used for timing callbacks, e.g., whenever
 * the JS script asks for asynchronously invoking one of its methods
 * after some time, rather than immediately (which is what the scheduler
 * would be for instead). Allows for a string parameter to be passed. */
static void *janus_duktape_timer(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Duktape timer loop\n");
	GMainLoop *loop = (GMainLoop *)data;
	/* Start loop */
	g_main_loop_run(loop);
	/* Done */
	JANUS_LOG(LOG_VERB, "Leaving Duktape timer loop\n");
	return NULL;
}

/* Callback to trigger timed callbacks */
static gboolean janus_duktape_timer_cb(void *data) {
	janus_duktape_callback *cb = (janus_duktape_callback *)data;
	if(cb == NULL)
		return FALSE;
	/* Invoke the callback with the provided argument, if available */
	JANUS_LOG(LOG_VERB, "Invoking scheduled callback (waited %"SCNu32"ms) with ID %u\n", cb->ms, cb->id);
	janus_mutex_lock(&duktape_mutex);
	duk_idx_t thr_idx = duk_push_thread(duktape_ctx);
	duk_context *t = duk_get_context(duktape_ctx, thr_idx);
	duk_get_global_string(t, cb->function);
	if(cb->argument) {
		duk_push_string(t, cb->argument);
	}
	int res = duk_pcall(t, cb->argument ? 1 : 0);
	if(res != DUK_EXEC_SUCCESS) {
		JANUS_LOG(LOG_ERR, "Duktape error: %s\n", duk_safe_to_string(t, -1));
	}
	duk_pop(t);
	duk_pop(duktape_ctx);
	/* Done */
	g_hash_table_remove(callbacks, cb);
	janus_mutex_unlock(&duktape_mutex);
	return FALSE;
}
