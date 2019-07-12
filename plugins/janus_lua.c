/*! \file   janus_lua.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Lua plugin
 * \details Check the \ref lua for more details.
 *
 * \ingroup plugins
 * \ingroup luapapi
 * \ref plugins
 * \ref luapapi
 *
 * \page lua Lua plugin documentation
 * This is a plugin that implements a simple bridge to Lua
 * scripts. While the plugin implements low level stuff like media
 * manipulation, routing, recording, etc., all the logic is demanded
 * to an external Lua script. This means that the C code exposes functions
 * to the Lua script (e.g., to dictate what to do with media, whether
 * recording should be done, sending PLIs, etc.), while Lua exposes
 * functions to be notified by the C code about important events (e.g.,
 * new users, WebRTC state, incoming messages, etc.).
 *
 * Considering the C code and the Lua script will need some sort of
 * "contract" in order to be able to properly interact with each other,
 * the interface (as in method names) must be consistent, but the logic
 * in the Lua script can be completely customized, so that it fits
 * whatever requirement one has (e.g., something like the EchoTest, or
 * something like the VideoRoom).
 *
 * \section luaapi Lua interfaces
 *
 * Every Lua script that wants to implement a Janus plugin must provide
 * the following functions as callbacks:
 *
 * - \c init(): called when janus_lua.c is initialized;
 * - \c destroy(): called when janus_lua.c is deinitialized (Janus shutting down);
 * - \c createSession(): called when a new user attaches to the Janus Lua plugin;
 * - \c destroySession(): called when an attached user detaches from the Janus Lua plugin;
 * - \c querySession(): called when an Admin API query for a specific user gets to the Janus Lua plugin;
 * - \c handleMessage(): called when a user sends a message to the Janus Lua plugin;
 * - \c setupMedia(): called when a users's WebRTC PeerConnection goes up;
 * - \c hangupMedia(): called when a users's WebRTC PeerConnection goes down;
 * - \c resumeScheduler(): called by the C scheduler to resume coroutines.
 *
 * While \c init() expects a path to a config file (which you can ignore if
 * unneeded), and \c destroy() and \c resumeScheduler() don't need any
 * argument, all other functions expect at the very least a numeric session
 * identifier, that will uniquely address a user in the plugin. Such a
 * value is created dynamically by the C code, and so all the Lua script
 * needs to do is track it as a unique session identifier when handling
 * requests and pushing responses/events/actions towards the C code.
 * Refer to the existing examples (e.g., \c echotest.lua) to see the
 * exact signature for all the above callbacks.
 *
 * \note Notice that, along the above mentioned callbacks, Lua scripts
 * can also implement functions like \c incomingRtp() \c incomingRtcp()
 * and \c incomingData() to handle those packets directly, instead of
 * letting the C code worry about relaying/processing them. While it might
 * make sense to handle incoming data channel messages with \c incomingData()
 * though, the performance impact of directly processing and manipulating
 * RTP an RTCP packets is probably too high, and so their usage is currently
 * discouraged. As an additional note, Lua scripts can also decide to
 * implement the functions that return information about the plugin itself,
 * namely \c getVersion() \c getVersionString() \c getDescription()
 * \c getName() \c getAuthor() and \c getPackage(). If not implemented,
 * the Lua plugin will return its own info (i.e., "janus.plugin.lua", etc.).
 * Most of the times, Lua scripts will not need to override this information,
 * unless they really want to register their own name spaces and versioning.
 * Finally, Lua scripts can receive information on slow links via the
 * \c slowLink() callback, in order to react accordingly: e.g., reduce
 * the bitrate of a video sender if they, or their viewers, are experiencing
 * issues.
 *
 * \section capi C interfaces
 *
 * Just as the Lua script needs to expose callbacks that the C code can
 * invoke, the C code exposes methods as Lua functions accessible from
 * the Lua script. This includes means to push events, configure how
 * media should be routed without handling each packet in Lua, sending
 * RTCP feedback, start/stop recording and so on.
 *
 * The following are the functions the C code exposes:
 *
 * - \c pushEvent(): push an event to the user via Janus API;
 * - \c eventsIsEnabled(): check if Event Handlers are enabled in the core;
 * - \c notifyEvent(): send an event to Event Handlers;
 * - \c closePc(): force the closure of a PeerConnection;
 * - \c endSession(): force the detach of a plugin handle;
 * - \c configureMedium(): specify whether audio/video/data can be received/sent;
 * - \c addRecipient(): specify which user should receive a user's media;
 * - \c removeRecipient(): specify which user should not receive a user's media anymore;
 * - \c setBitrate(): specify the bitrate to force on a user via REMB feedback;
 * - \c setPliFreq(): specify how often the plugin should send a PLI to this user;
 * - \c sendPli(): send a PLI (keyframe request);
 * - \c startRecording(): start recording audio, video and or data for a user;
 * - \c stopRecording(): start recording audio, video and or data for a user;
 * - \c pokeScheduler(): notify the C code that there's a coroutine to resume;
 * - \c timeCallback(): trigger the execution of a Lua function after X milliseconds.
 *
 * As anticipated in the previous section, almost all these methods also
 * expect the unique session identifier to address a specific user in the
 * plugin. This is true for all the above methods expect \c eventsIsEnabled
 * and, more importantly, both \c timeCallback() and \c pokeScheduler() which,
 * together with Lua's \c resumeScheduler(), will be clearer in the next section.
 *
 * \section coroutines Lua/C coroutines scheduler
 *
 * Lua is a single threaded environment. While it has a concept similar
 * to threads called coroutines, these are not threads as known in C.
 * In order to allow for an easy to implement asynchronous behaviour in
 * Lua scripts, you can leverage a scheduler implemented in the C code.
 *
 * More specifically, when the plugin starts a dedicated thread is devoted
 * to the only purpose of acting as a scheduler for Lua coroutines. This
 * means that, whenever this C scheduler is awaken, it will call the
 * \c resumeScheduler() function in the Lua script, thus allowing the
 * Lua script to execute one or more pending coroutines. The C scheduler
 * only acts when triggered, which means it's up to the Lua script to
 * tell it when to wake up: this is possible via the \c pokeScheduler()
 * function, which does nothing more than sending a simple signal to the
 * C scheduler to wake it up. As such, it's easy for the Lua script to
 * implement asynchronous behaviour, e.g.:
 *
 * 1. Lua script needs to do something asynchronously;
 * 2. Lua script creates coroutine, and takes note of it somewhere;
 * 3. Lua script calls \c pokeScheduler();
 * 4. C code sends signal to the thread acting as a scheduler;
 * 5. when the scheduling thread wakes up, it calls \c resumeScheduler();
 * 6. Lua script resumes the previously queued coroutine.
 *
 * This simple mechanism is what the sample Lua scripts provided in this
 * repo use, for instance, to handle incoming messages asynchronously,
 * so you can refer to those to have an idea of how it can be used. The
 * next section will address \ref timers instead.
 *
 * \note You can implement asynchronous behaviour any way you want, and
 * you're not required to use this C scheduler. Anyway, you must implement
 * a method called \c resumeScheduler() anyway, as the C code checks for
 * its presence and fails if it's not there. If you don't need it, just
 * create an empty function that does nothing and you'll be fine.
 *
 * \section timers Lua/C time-based scheduler
 *
 * Another helpful way to implement asynchronous behaviour is with the
 * help of the \c timeCallback() function. Specifically, this function
 * implements a mechanism to ask for a specific Lua method to be invoked
 * after a provided amount of time. To specify the function to invoke,
 * an optional argument to pass (which MUST be a string) and the time to
 * wait to do that. This is particularly helpful when you're handling
 * asynchronous behaviour that you want to inspect on a regular basis.
 *
 * The \c timeCallback() function expects three arguments:
 *
 * \verbatim
timeCallback(function, argument, milliseconds)
\endverbatim
 *
 * The only mandatory parameter is \c function: if you set \c argument
 * to \c nil no argument will be passed to \c function when it's executed;
 * it \c milliseconds is 0, \c function will be executed as soon as possible.
 *
 * \verbatim
-- This will cause an error (timeCallback needs three arguments)
timeCallback()
-- Invoke test() in 500 milliseconds
timeCallback("test", nil, 500)
-- Invoke test("ciccio") in 2 seconds
timeCallback("test", "ciccio", 2000)
\endverbatim
 *
 * Notice that \c timeCallback() allows you to formally recreate the
 * mechanism \c pokeScheduler() and \c resumeScheduler() implement, as
 * the following is pretty much an equivalent of that:
 *
 * \verbatim
timeCallback("resumeScheduler", nil, 0)
\endverbatim
 *
 * Anyway, \c pokeScheduler() and \c resumeScheduler() is much more
 * compact and less verbose, and as such is preferred in cases where
 * timing and opaque arguments are not needed.
 *
 * Refer to the \ref luapapi section for more information on how you
 * can register your own C functions.
 */

#include <jansson.h>

/* Session definition and hashtable */
#include "janus_lua_data.h"
/* Extra/custom C hooks and code */
#include "janus_lua_extra.h"


/* Plugin information */
#define JANUS_LUA_VERSION			1
#define JANUS_LUA_VERSION_STRING	"0.0.1"
#define JANUS_LUA_DESCRIPTION		"A custom plugin for the Lua framework."
#define JANUS_LUA_NAME				"Janus Lua plugin"
#define JANUS_LUA_AUTHOR			"Meetecho s.r.l."
#define JANUS_LUA_PACKAGE			"janus.plugin.lua"

/* Plugin methods */
janus_plugin *create(void);
int janus_lua_init(janus_callbacks *callback, const char *config_path);
void janus_lua_destroy(void);
int janus_lua_get_api_compatibility(void);
int janus_lua_get_version(void);
const char *janus_lua_get_version_string(void);
const char *janus_lua_get_description(void);
const char *janus_lua_get_name(void);
const char *janus_lua_get_author(void);
const char *janus_lua_get_package(void);
void janus_lua_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_lua_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_lua_handle_admin_message(json_t *message);
void janus_lua_setup_media(janus_plugin_session *handle);
void janus_lua_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_lua_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_lua_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len);
void janus_lua_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_lua_hangup_media(janus_plugin_session *handle);
void janus_lua_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_lua_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_lua_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_lua_init,
		.destroy = janus_lua_destroy,

		.get_api_compatibility = janus_lua_get_api_compatibility,
		.get_version = janus_lua_get_version,
		.get_version_string = janus_lua_get_version_string,
		.get_description = janus_lua_get_description,
		.get_name = janus_lua_get_name,
		.get_author = janus_lua_get_author,
		.get_package = janus_lua_get_package,

		.create_session = janus_lua_create_session,
		.handle_message = janus_lua_handle_message,
		.handle_admin_message = janus_lua_handle_admin_message,
		.setup_media = janus_lua_setup_media,
		.incoming_rtp = janus_lua_incoming_rtp,
		.incoming_rtcp = janus_lua_incoming_rtcp,
		.incoming_data = janus_lua_incoming_data,
		.slow_link = janus_lua_slow_link,
		.hangup_media = janus_lua_hangup_media,
		.destroy_session = janus_lua_destroy_session,
		.query_session = janus_lua_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_LUA_NAME);
	return &janus_lua_plugin;
}

/* Useful stuff */
volatile gint lua_initialized = 0, lua_stopping = 0;
janus_callbacks *janus_core = NULL;

/* Lua stuff */
lua_State *lua_state = NULL;
janus_mutex lua_mutex = JANUS_MUTEX_INITIALIZER;
static const char *lua_functions[] = {
	"init", "destroy", "resumeScheduler",
	"createSession", "destroySession", "querySession",
	"handleMessage",
	"setupMedia", "hangupMedia"
};
static uint lua_funcsize = sizeof(lua_functions)/sizeof(*lua_functions);
/* Some bindings are optional */
static gboolean has_get_version = FALSE;
static int lua_script_version = -1;
static gboolean has_get_version_string = FALSE;
static char *lua_script_version_string = NULL;
static gboolean has_get_description = FALSE;
static char *lua_script_description = NULL;
static gboolean has_get_name = FALSE;
static char *lua_script_name = NULL;
static gboolean has_get_author = FALSE;
static char *lua_script_author = NULL;
static gboolean has_get_package = FALSE;
static char *lua_script_package = NULL;
static gboolean has_handle_admin_message = FALSE;
static gboolean has_incoming_rtp = FALSE;
static gboolean has_incoming_rtcp = FALSE;
static gboolean has_incoming_data = FALSE;
static gboolean has_slow_link = FALSE;
/* Lua C scheduler (for coroutines) */
static GThread *scheduler_thread = NULL;
static void *janus_lua_scheduler(void *data);
static GAsyncQueue *events = NULL;
typedef enum janus_lua_event {
	janus_lua_event_none = 0,
	janus_lua_event_resume,		/* Resume one or more pending coroutines */
	janus_lua_event_exit		/* Break the scheduler loop */
} janus_lua_event;
/* Lua timer loop (for scheduled callbacks) */
static GMainContext *timer_context = NULL;
static GMainLoop *timer_loop = NULL;
static GThread *timer_thread = NULL;
static void *janus_lua_timer(void *data);
static gboolean janus_lua_timer_cb(void *data);
typedef struct janus_lua_callback {
	guint id;
	uint32_t ms;
	GSource *source;
	char *function;
	char *argument;
} janus_lua_callback;

/* Helper function to sample the number of occupied slots into Lua stack */
static void janus_lua_stackdump(lua_State* l) {
    int top = lua_gettop(l);
    JANUS_LOG(LOG_HUGE, "Total in lua stack %d\n", top);
}

/* janus_lua_session is defined in janus_lua_data.h, but it's managed here */
GHashTable *lua_sessions, *lua_ids;
janus_mutex lua_sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_lua_session_destroy(janus_lua_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1)) {
		janus_refcount_decrease(&session->ref);
	}
}

static void janus_lua_session_free(const janus_refcount *session_ref) {
	janus_lua_session *session = janus_refcount_containerof(session_ref, janus_lua_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_hash_table_remove(lua_ids, GUINT_TO_POINTER(session->id));
	janus_recorder_destroy(session->arc);
	janus_recorder_destroy(session->vrc);
	janus_recorder_destroy(session->drc);
	g_free(session);
}

/* Packet data and routing */
typedef struct janus_lua_rtp_relay_packet {
	rtp_header *data;
	gint length;
	gboolean is_video;
	uint32_t timestamp;
	uint16_t seq_number;
} janus_lua_rtp_relay_packet;
static void janus_lua_relay_rtp_packet(gpointer data, gpointer user_data);
static void janus_lua_relay_data_packet(gpointer data, gpointer user_data);


/* Helper struct to address outgoing notifications, e.g., involving PeerConnections */
typedef enum janus_lua_async_event_type {
	janus_lua_async_event_type_none = 0,
	janus_lua_async_event_type_pushevent
} janus_lua_async_event_type;
typedef struct janus_lua_async_event {
	janus_lua_session *session;			/* Who this event is for */
	janus_lua_async_event_type type;	/* What this event is about */
	char *transaction;					/* Notification transaction, if any */
	json_t *event;						/* Content of the notification, if any */
	json_t *jsep;						/* Content of JSEP SDP, if any */
} janus_lua_async_event;
/* Helper thread to push events that need to be asynchronous, e.g., for those
 * that would keep the Lua state busy longer than usual and cause delays,
 * or those that might actually result in a deadlock if done synchronously */
static void *janus_lua_async_event_helper(void *data) {
	janus_lua_async_event *asev = (janus_lua_async_event *)data;
	if(asev == NULL)
		return NULL;
	if(asev->type == janus_lua_async_event_type_pushevent) {
		/* Send the event */
		janus_core->push_event(asev->session->handle, &janus_lua_plugin, asev->transaction, asev->event, asev->jsep);
	}
	json_decref(asev->event);
	json_decref(asev->jsep);
	g_free(asev->transaction);
	janus_refcount_decrease(&asev->session->ref);
	g_free(asev);
	return NULL;
}


/* Methods that we expose to the Lua script */
static int janus_lua_method_pokescheduler(lua_State *s) {
	/* This method allows the Lua script to poke the scheduler and have it wake up ASAP */
	g_async_queue_push(events, GUINT_TO_POINTER(janus_lua_event_resume));
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_timecallback(lua_State *s) {
	/* This method allows the Lua script to schedule a callback after a specified amount of time */
	int n = lua_gettop(s);
	if(n != 3) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 3)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	const char *function = lua_tostring(s, 1);
	if(function == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid argument (missing function name)\n");
		lua_pushnumber(s, -1);
		return 1;
	}
	const char *argument = lua_tostring(s, 2);
	guint32 ms = lua_tonumber(s, 3);
	/* Create a callback instance */
	janus_lua_callback *cb = g_malloc0(sizeof(janus_lua_callback));
	cb->function = g_strdup(function);
	if(argument != NULL)
		cb->argument = g_strdup(argument);
	cb->ms = ms;
	cb->source = g_timeout_source_new(ms);
	g_source_set_callback(cb->source, janus_lua_timer_cb, cb, NULL);
	cb->id = g_source_attach(cb->source, timer_context);
	JANUS_LOG(LOG_VERB, "Created scheduled callback (%"SCNu32"ms) with ID %u\n", cb->ms, cb->id);
	/* Done */
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_pushevent(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 4) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 4)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	const char *transaction = lua_tostring(s, 2);
	const char *event_text = lua_tostring(s, 3);
	const char *jsep_text = lua_tostring(s, 4);
	/* Parse the event/jsep strings to Jansson objects */
	json_error_t error;
	json_t *event = json_loads(event_text, 0, &error);
	if(!event) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s", error.line, error.text);
		lua_pushnumber(s, -1);
		return 1;
	}
	json_t *jsep = NULL;
	if(jsep_text != NULL) {
		jsep = json_loads(jsep_text, 0, &error);
		if(!jsep) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s", error.line, error.text);
			json_decref(event);
			lua_pushnumber(s, -1);
			return 1;
		}
	}
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		json_decref(event);
		if(jsep)
			json_decref(jsep);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* If there's an SDP attached, create a thread to send the event asynchronously:
	 * sending it here would keep the locked Lua state busy much longer than intended */
	if(jsep != NULL) {
		janus_lua_async_event *asev = g_malloc0(sizeof(janus_lua_async_event));
		asev->session = session;
		asev->type = janus_lua_async_event_type_pushevent;
		asev->transaction = transaction ? g_strdup(transaction) : NULL;
		asev->event = event;
		asev->jsep = jsep;
		GError *error = NULL;
		g_thread_try_new("lua pushevent", janus_lua_async_event_helper, asev, &error);
		if(error != NULL) {
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Lua pushevent thread...\n",
				error->code, error->message ? error->message : "??");
			json_decref(event);
			json_decref(jsep);
			g_free(asev->transaction);
			janus_refcount_decrease(&session->ref);
			g_free(asev);
		}
		/* Return a success/error right away */
		lua_pushnumber(s, error ? 1 : 0);
		return 1;
	}
	/* No SDP, send the event now */
	int res = janus_core->push_event(session->handle, &janus_lua_plugin, transaction, event, NULL);
	janus_refcount_decrease(&session->ref);
	json_decref(event);
	lua_pushnumber(s, res);
	return 1;
}

static int janus_lua_method_notifyevent(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	if(!janus_core->events_is_enabled()) {
		/* Event handlers are disabled in the core, ignoring */
		lua_pushnumber(s, 0);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	const char *event_text = lua_tostring(s, 2);
	/* Parse the event/jsep strings to Jansson objects */
	json_error_t error;
	json_t *event = json_loads(event_text, 0, &error);
	if(!event) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s", error.line, error.text);
		lua_pushnumber(s, -1);
		return 1;
	}
	/* Find the session (optional) */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session != NULL)
		janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Notify the event */
	janus_core->notify_event(&janus_lua_plugin, session ? session->handle : NULL, event);
	if(session != NULL)
		janus_refcount_decrease(&session->ref);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_eventsisenabled(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 0) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 0)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	/* Event handlers are disabled in the core, ignoring */
	lua_pushnumber(s, janus_core->events_is_enabled());
	return 1;
}

static int janus_lua_method_closepc(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 1) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 1)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Close the PeerConnection */
	janus_core->close_pc(session->handle);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_endsession(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 1) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 1)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Close the plugin handle */
	janus_core->end_session(session->handle);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_configuremedium(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 4) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 4)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	const char *medium = lua_tostring(s, 2);
	const char *direction = lua_tostring(s, 3);
	int enabled = lua_toboolean(s, 4);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
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
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_addrecipient(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	guint32 rid = lua_tonumber(s, 2);
	/* Find the sessions */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->recipients_mutex);
	janus_lua_session *recipient = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(rid));
	if(recipient == NULL || g_atomic_int_get(&recipient->destroyed)) {
		janus_mutex_unlock(&session->recipients_mutex);
		janus_refcount_decrease(&session->ref);
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&recipient->ref);
	/* Add to the list of recipients */
	janus_mutex_unlock(&lua_sessions_mutex);
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
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_removerecipient(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	guint32 rid = lua_tonumber(s, 2);
	/* Find the sessions */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->recipients_mutex);
	janus_lua_session *recipient = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(rid));
	if(recipient == NULL) {
		janus_mutex_unlock(&session->recipients_mutex);
		janus_refcount_decrease(&session->ref);
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&recipient->ref);
	/* Remove from the list of recipients */
	janus_mutex_unlock(&lua_sessions_mutex);
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
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_setbitrate(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	guint32 bitrate = lua_tonumber(s, 2);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	session->bitrate = bitrate;
	/* Send a REMB right away too, if the PeerConnection is up */
	if(session->bitrate > 0 && g_atomic_int_get(&session->started)) {
		char rtcpbuf[24];
		janus_rtcp_remb((char *)(&rtcpbuf), 24, session->bitrate);
		janus_core->relay_rtcp(session->handle, 1, rtcpbuf, 24);
	}
	/* Done */
	janus_refcount_decrease(&session->ref);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_setplifreq(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	guint16 pli_freq = lua_tonumber(s, 2);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	session->pli_freq = pli_freq;
	/* Done */
	janus_refcount_decrease(&session->ref);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_sendpli(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 1) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 1)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Send a PLI */
	session->pli_latest = janus_get_monotonic_time();
	char rtcpbuf[12];
	janus_rtcp_pli((char *)&rtcpbuf, 12);
	JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->id);
	janus_core->relay_rtcp(session->handle, 1, rtcpbuf, 12);
	/* Done */
	janus_refcount_decrease(&session->ref);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_relayrtp(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 4) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 4)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	int is_video = lua_toboolean(s, 2);
	const char *payload = lua_tostring(s, 3);
	int len = lua_tonumber(s, 4);
	if(!payload || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid payload\n");
		lua_pushnumber(s, -1);
		return 1;
	}
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Send the RTP packet */
	janus_core->relay_rtp(session->handle, is_video, (char *)payload, len);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_relayrtcp(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 4) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 4)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	int is_video = lua_toboolean(s, 2);
	const char *payload = lua_tostring(s, 3);
	int len = lua_tonumber(s, 4);
	if(!payload || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid payload\n");
		lua_pushnumber(s, -1);
		return 1;
	}
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Send the RTCP packet */
	janus_core->relay_rtcp(session->handle, is_video, (char *)payload, len);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_relaydata(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 3) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	const char *payload = lua_tostring(s, 2);
	int len = lua_tonumber(s, 3);
	if(!payload || len < 1) {
		JANUS_LOG(LOG_ERR, "Invalid data\n");
		lua_pushnumber(s, -1);
		return 1;
	}
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Send the RTP packet */
	janus_core->relay_data(session->handle, NULL, (char *)payload, len);
	janus_refcount_decrease(&session->ref);
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_startrecording(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 5 && n != 9 && n != 13) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 5, 9 or 13)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->rec_mutex);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Iterate on all arguments, to see what we're being asked to record */
	n--;
	int i = 1;
	janus_recorder *arc = NULL, *vrc = NULL, *drc = NULL;
	while(n > 0) {
		i++; n--;
		const char *type = lua_tostring(s, i);
		i++; n--;
		const char *codec = lua_tostring(s, i);
		i++; n--;
		const char *folder = lua_tostring(s, i);
		i++; n--;
		const char *filename = lua_tostring(s, i);
		janus_recorder *rc = janus_recorder_create(folder, codec, filename);
		if(rc == NULL) {
			JANUS_LOG(LOG_ERR, "Error creating '%s' recorder...\n", type);
			goto error;
		}
		if(!strcasecmp(type, "audio")) {
			if(arc != NULL || session->arc != NULL) {
				JANUS_LOG(LOG_ERR, "Duplicate audio recording\n");
				goto error;
			}
			arc = rc;
		} else if(!strcasecmp(type, "video")) {
			if(vrc != NULL || session->vrc != NULL) {
				JANUS_LOG(LOG_ERR, "Duplicate video recording\n");
				goto error;
			}
			vrc = rc;
		} else if(!strcasecmp(type, "data")) {
			if(drc != NULL || session->drc != NULL) {
				JANUS_LOG(LOG_ERR, "Duplicate data recording\n");
				goto error;
			}
			drc = rc;
		}
	}
	if(arc) {
		session->arc = arc;
	}
	if(vrc) {
		session->vrc = vrc;
		/* Also send a keyframe request */
		session->pli_latest = janus_get_monotonic_time();
		char rtcpbuf[12];
		janus_rtcp_pli((char *)&rtcpbuf, 12);
		JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->id);
		janus_core->relay_rtcp(session->handle, 1, rtcpbuf, 12);
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
	lua_pushnumber(s, -1);
	return 1;

done:
	janus_mutex_unlock(&session->rec_mutex);
	/* Done */
	lua_pushnumber(s, 0);
	return 1;
}

static int janus_lua_method_stoprecording(lua_State *s) {
	/* Get the arguments from the provided state */
	int n = lua_gettop(s);
	if(n != 2 && n != 3 && n != 4) {
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2, 3 or 4)\n", n);
		lua_pushnumber(s, -1);
		return 1;
	}
	guint32 id = lua_tonumber(s, 1);
	/* Find the session */
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id));
	if(session == NULL || g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&lua_sessions_mutex);
		lua_pushnumber(s, -1);
		return 1;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_lock(&session->rec_mutex);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Iterate on all arguments, to see what which recording we're being asked to stop */
	n--;
	int i = 1;
	while(n > 0) {
		i++; n--;
		const char *type = lua_tostring(s, i);
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
	lua_pushnumber(s, 0);
	return 1;
}


/* Plugin implementation */
int janus_lua_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&lua_stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_LUA_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_LUA_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_LUA_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config == NULL) {
		/* No config means no Lua script */
		JANUS_LOG(LOG_ERR, "Failed to load configuration file for Lua plugin...\n");
		return -1;
	}
	janus_config_print(config);
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
	char *lua_folder = NULL;
	janus_config_item *folder = janus_config_get(config, config_general, janus_config_type_item, "path");
	if(folder && folder->value)
		lua_folder = g_strdup(folder->value);
	janus_config_item *script = janus_config_get(config, config_general, janus_config_type_item, "script");
	if(script == NULL || script->value == NULL) {
		JANUS_LOG(LOG_ERR, "Missing script path in Lua plugin configuration...\n");
		janus_config_destroy(config);
		g_free(lua_folder);
		return -1;
	}
	char *lua_file = g_strdup(script->value);
	char *lua_config = NULL;
	janus_config_item *conf = janus_config_get(config, config_general, janus_config_type_item, "config");
	if(conf && conf->value)
		lua_config = g_strdup(conf->value);
	janus_config_destroy(config);

	/* Initialize Lua */
	lua_state = luaL_newstate();
	luaL_openlibs(lua_state);

	if(lua_folder != NULL) {
		/* Add the script folder to the path, so that we can load other scripts from there */
		lua_getglobal(lua_state, "package");
		lua_getfield(lua_state, -1, "path");
		const char *cur_path = lua_tostring(lua_state, -1);
		char new_path[1024];
		memset(new_path, 0, sizeof(new_path));
		g_snprintf(new_path, sizeof(new_path), "%s;%s/?.lua", cur_path, lua_folder);
		lua_pop(lua_state, 1);
		lua_pushstring(lua_state, new_path);
		lua_setfield(lua_state, -2, "path");
		lua_pop(lua_state, 1);
	}

	/* Register our functions */
	lua_register(lua_state, "pokeScheduler", janus_lua_method_pokescheduler);
	lua_register(lua_state, "timeCallback", janus_lua_method_timecallback);
	lua_register(lua_state, "pushEvent", janus_lua_method_pushevent);
	lua_register(lua_state, "notifyEvent", janus_lua_method_notifyevent);
	lua_register(lua_state, "eventsIsEnabled", janus_lua_method_eventsisenabled);
	lua_register(lua_state, "closePc", janus_lua_method_closepc);
	lua_register(lua_state, "endSession", janus_lua_method_endsession);
	lua_register(lua_state, "configureMedium", janus_lua_method_configuremedium);
	lua_register(lua_state, "addRecipient", janus_lua_method_addrecipient);
	lua_register(lua_state, "removeRecipient", janus_lua_method_removerecipient);
	lua_register(lua_state, "setBitrate", janus_lua_method_setbitrate);
	lua_register(lua_state, "setPliFreq", janus_lua_method_setplifreq);
	lua_register(lua_state, "sendPli", janus_lua_method_sendpli);
	lua_register(lua_state, "relayRtp", janus_lua_method_relayrtp);
	lua_register(lua_state, "relayRtcp", janus_lua_method_relayrtcp);
	lua_register(lua_state, "relayData", janus_lua_method_relaydata);
	lua_register(lua_state, "startRecording", janus_lua_method_startrecording);
	lua_register(lua_state, "stopRecording", janus_lua_method_stoprecording);
	/* Register all extra functions, if any were added */
	janus_lua_register_extra_functions(lua_state);

	/* Now load the script */
	int err = luaL_dofile(lua_state, lua_file);
	if(err) {
		JANUS_LOG(LOG_ERR, "Error loading Lua script %s: %s\n", lua_file, lua_tostring(lua_state, -1));
		lua_close(lua_state);
		g_free(lua_folder);
		g_free(lua_file);
		return -1;
	}
	/* Make sure that all the functions we need are there */
	uint i=0;
	for(i=0; i<lua_funcsize; i++) {
		lua_getglobal(lua_state, lua_functions[i]);
		if(lua_isfunction(lua_state, lua_gettop(lua_state)) == 0) {
			JANUS_LOG(LOG_ERR, "Function '%s' is missing in %s\n", lua_functions[i], lua_file);
			lua_close(lua_state);
			g_free(lua_folder);
			g_free(lua_file);
			return -1;
		}
	}
	/* Some Lua functions are optional (e.g., those to directly handle RTP, RTCP and
	 * data, as those will typically be kept at a C level, with Lua only dictating
	 * the logic, or those overriding the plugin namespace and versioning information */
	lua_getglobal(lua_state, "getVersion");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_version = TRUE;
	lua_getglobal(lua_state, "getVersionString");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_version_string = TRUE;
	lua_getglobal(lua_state, "getDescription");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_description = TRUE;
	lua_getglobal(lua_state, "getName");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_name = TRUE;
	lua_getglobal(lua_state, "getAuthor");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_author = TRUE;
	lua_getglobal(lua_state, "getPackage");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_get_package = TRUE;
	lua_getglobal(lua_state, "handleAdminMessage");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_handle_admin_message = TRUE;
	lua_getglobal(lua_state, "incomingRtp");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_incoming_rtp = TRUE;
	lua_getglobal(lua_state, "incomingRtcp");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_incoming_rtcp = TRUE;
	lua_getglobal(lua_state, "incomingData");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_incoming_data = TRUE;
	lua_getglobal(lua_state, "slowLink");
	if(lua_isfunction(lua_state, lua_gettop(lua_state)) != 0)
		has_slow_link = TRUE;

	lua_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_lua_session_destroy);
	lua_ids = g_hash_table_new(NULL, NULL);
	events = g_async_queue_new();

	g_atomic_int_set(&lua_initialized, 1);

	/* Launch the scheduler thread (which will be responsible for resuming asynchronous coroutines) */
	GError *error = NULL;
	scheduler_thread = g_thread_try_new("lua scheduler", janus_lua_scheduler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&lua_initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Lua scheduler thread...\n",
			error->code, error->message ? error->message : "??");
		lua_close(lua_state);
		g_free(lua_folder);
		g_free(lua_file);
		g_free(lua_config);
		return -1;
	}
	/* Launch the timer loop thread (which will be responsible for scheduling timed callbacks) */
	timer_context = g_main_context_new();
	timer_loop = g_main_loop_new(timer_context, FALSE);
	timer_thread = g_thread_try_new("lua timer", janus_lua_timer, timer_loop, &error);
	if(error != NULL) {
		g_atomic_int_set(&lua_initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the Lua timer loop thread...\n",
			error->code, error->message ? error->message : "??");
		if(timer_loop != NULL)
			g_main_loop_unref(timer_loop);
		if(timer_context != NULL)
			g_main_context_unref(timer_context);
		lua_close(lua_state);
		g_free(lua_folder);
		g_free(lua_file);
		g_free(lua_config);
		return -1;
	}

	/* This is the callback we'll need to invoke to contact the Janus core */
	janus_core = callback;

	/* Init the Lua script, in case it's needed */
	lua_getglobal(lua_state, "init");
	lua_pushstring(lua_state, lua_config);
	lua_call(lua_state, 1, 0);

	g_free(lua_folder);
	g_free(lua_file);
	g_free(lua_config);

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_LUA_NAME);
	return 0;
}

void janus_lua_destroy(void) {
	if(!g_atomic_int_get(&lua_initialized))
		return;
	g_atomic_int_set(&lua_stopping, 1);

	g_async_queue_push(events, GUINT_TO_POINTER(janus_lua_event_exit));
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

	/* Deinit the Lua script, in case it's needed */
	janus_mutex_lock(&lua_mutex);
	lua_getglobal(lua_state, "destroy");
	lua_call(lua_state, 0, 0);
	janus_mutex_unlock(&lua_mutex);

	janus_mutex_lock(&lua_sessions_mutex);
	g_hash_table_destroy(lua_sessions);
	lua_sessions = NULL;
	g_hash_table_destroy(lua_ids);
	lua_ids = NULL;
	g_async_queue_unref(events);
	events = NULL;
	janus_mutex_unlock(&lua_sessions_mutex);

	janus_mutex_lock(&lua_mutex);
	lua_close(lua_state);
	lua_state = NULL;
	janus_mutex_unlock(&lua_mutex);

	g_free(lua_script_version_string);
	g_free(lua_script_description);
	g_free(lua_script_name);
	g_free(lua_script_author);
	g_free(lua_script_package);

	g_atomic_int_set(&lua_initialized, 0);
	g_atomic_int_set(&lua_stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_LUA_NAME);
}

int janus_lua_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_lua_get_version(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_version) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_version != -1) {
			/* Unless we asked already */
			return lua_script_version;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getVersion");
		lua_call(t, 0, 1);
		lua_script_version = (int)lua_tonumber(t, -1);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_version;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_VERSION;
}

const char *janus_lua_get_version_string(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_version_string) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_version_string != NULL) {
			/* Unless we asked already */
			return lua_script_version_string;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getVersionString");
		lua_call(t, 0, 1);
		const char *version = lua_tostring(t, -1);
		if(version != NULL)
			lua_script_version_string = g_strdup(version);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_version_string;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_VERSION_STRING;
}

const char *janus_lua_get_description(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_description) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_description != NULL) {
			/* Unless we asked already */
			return lua_script_description;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getDescription");
		lua_call(t, 0, 1);
		const char *description = lua_tostring(t, -1);
		if(description != NULL)
			lua_script_description = g_strdup(description);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_description;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_DESCRIPTION;
}

const char *janus_lua_get_name(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_name) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_name != NULL) {
			/* Unless we asked already */
			return lua_script_name;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getName");
		lua_call(t, 0, 1);
		const char *name = lua_tostring(t, -1);
		if(name != NULL)
			lua_script_name = g_strdup(name);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_name;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_NAME;
}

const char *janus_lua_get_author(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_author) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_author != NULL) {
			/* Unless we asked already */
			return lua_script_author;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getAuthor");
		lua_call(t, 0, 1);
		const char *author = lua_tostring(t, -1);
		if(author != NULL)
			lua_script_author = g_strdup(author);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_author;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_AUTHOR;
}

const char *janus_lua_get_package(void) {
	/* Check if the Lua script wants to override this method and return info itself */
	if(has_get_package) {
		/* Yep, pass the request to the Lua script and return the info */
		if(lua_script_package != NULL) {
			/* Unless we asked already */
			return lua_script_package;
		}
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "getPackage");
		lua_call(t, 0, 1);
		const char *package = lua_tostring(t, -1);
		if(package != NULL)
			lua_script_package = g_strdup(package);
		lua_pop(t, 1);
		janus_mutex_unlock(&lua_mutex);
		return lua_script_package;
	}
	/* No override, return the Janus Lua plugin info */
	return JANUS_LUA_PACKAGE;
}

janus_lua_session *janus_lua_lookup_session(janus_plugin_session *handle) {
	janus_lua_session *session = NULL;
	if (g_hash_table_contains(lua_sessions, handle)) {
		session = (janus_lua_session *)handle->plugin_handle;
	}
	return session;
}

void janus_lua_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&lua_sessions_mutex);
	guint32 id = 0;
	while(id == 0) {
		id = janus_random_uint32();
		if(g_hash_table_lookup(lua_ids, GUINT_TO_POINTER(id))) {
			id = 0;
			continue;
		}
	}
	JANUS_LOG(LOG_VERB, "Creating new Lua session %"SCNu32"...\n", id);
	janus_lua_session *session = (janus_lua_session *)g_malloc0(sizeof(janus_lua_session));
	session->handle = handle;
	session->id = id;
	janus_rtp_switching_context_reset(&session->rtpctx);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	janus_refcount_init(&session->ref, janus_lua_session_free);
	handle->plugin_handle = session;
	g_hash_table_insert(lua_sessions, handle, session);
	g_hash_table_insert(lua_ids, GUINT_TO_POINTER(session->id), session);
	janus_mutex_unlock(&lua_sessions_mutex);

	/* Notify the Lua script */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "createSession");
	lua_pushnumber(t, session->id);
	lua_call(t, 1, 0);
	lua_pop(lua_state, 1);
	janus_mutex_unlock(&lua_mutex);

	return;
}

void janus_lua_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	guint32 id = session->id;
	JANUS_LOG(LOG_VERB, "Removing Lua session %"SCNu32"...\n", id);
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);

	/* Notify the Lua script */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "destroySession");
	lua_pushnumber(t, id);
	lua_call(t, 1, 0);
	lua_pop(lua_state, 1);
	janus_mutex_unlock(&lua_mutex);

	/* Get any rid references recipients of this sessions may have */
	janus_mutex_lock(&session->recipients_mutex);
	while(session->recipients != NULL) {
		janus_lua_session *recipient = (janus_lua_session *)session->recipients->data;
		if(recipient != NULL) {
			recipient->sender = NULL;
			janus_refcount_decrease(&session->ref);
			janus_refcount_decrease(&recipient->ref);
		}
		session->recipients = g_slist_remove(session->recipients, recipient);
	}
	janus_mutex_unlock(&session->recipients_mutex);

	/* Finally, remove from the hashtable */
	janus_mutex_lock(&lua_sessions_mutex);
	g_hash_table_remove(lua_sessions, handle);
	janus_mutex_unlock(&lua_sessions_mutex);
	janus_refcount_decrease(&session->ref);

	return;
}

json_t *janus_lua_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized)) {
		return NULL;
	}
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	/* Ask the Lua script for information on this session */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "querySession");
	lua_pushnumber(t, session->id);
	lua_call(t, 1, 1);
	lua_pop(lua_state, 1);
	janus_refcount_decrease(&session->ref);
	const char *info = lua_tostring(t, -1);
	lua_pop(t, 1);
	/* We need a Jansson object */
	json_error_t error;
	json_t *json = json_loads(info, 0, &error);
	janus_mutex_unlock(&lua_mutex);
	if(!json) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s", error.line, error.text);
		return NULL;
	}
	return json;
}

struct janus_plugin_result *janus_lua_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&lua_stopping) ? "Shutting down" : "Plugin not initialized", NULL);
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);

	/* Processing the message is up to the Lua script: serialize the Jansson objects to strings */
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
	json_decref(jsep);
	/* Invoke the script function */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "handleMessage");
	lua_pushnumber(t, session->id);
	lua_pushstring(t, transaction);
	lua_pushstring(t, message_text);
	lua_pushstring(t, jsep_text);
	lua_call(t, 4, 2);
	lua_pop(lua_state, 1);
	janus_refcount_decrease(&session->ref);
	if(message_text != NULL)
		free(message_text);
	if(jsep_text != NULL)
		free(jsep_text);
	g_free(transaction);
	int n = lua_gettop(t);
	if(n != 2) {
		janus_mutex_unlock(&lua_mutex);
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 2)\n", n);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Lua error", NULL);
	}
	/* Check if this is a synchronous or asynchronous response */
	int res = (int)lua_tonumber(t, 1);
	const char *response = lua_tostring(t, 2);
	lua_pop(t, 2);
	if(res < 0) {
		/* We got an error */
		janus_mutex_unlock(&lua_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, response ? response : "Lua error", NULL);
	} else if(res == 0) {
		/* Synchronous response: we need a Jansson object */
		json_error_t error;
		json_t *json = json_loads(response, 0, &error);
		janus_mutex_unlock(&lua_mutex);
		if(!json) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Lua error", NULL);
		}
		return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, json);
	}
	janus_mutex_unlock(&lua_mutex);
	/* If we got here, it's an asynchronous response */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

json_t *janus_lua_handle_admin_message(json_t *message) {
	if(!has_handle_admin_message || message == NULL)
		return NULL;
	char *message_text = json_dumps(message, JSON_INDENT(0) | JSON_PRESERVE_ORDER);
	/* Invoke the script function */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "handleAdminMessage");
	lua_pushstring(t, message_text);
	lua_call(t, 1, 1);
	lua_pop(lua_state, 1);
	if(message_text != NULL)
		free(message_text);
	int n = lua_gettop(t);
	if(n != 1) {
		janus_mutex_unlock(&lua_mutex);
		JANUS_LOG(LOG_ERR, "Wrong number of arguments: %d (expected 1)\n", n);
		return NULL;
	}
	/* Get the response */
	const char *response = lua_tostring(t, 1);
	json_error_t error;
	json_t *json = json_loads(response, 0, &error);
	janus_mutex_unlock(&lua_mutex);
	if(!json) {
		JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
		return NULL;
	}
	return json;
}

void janus_lua_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->started, 1);
	session->pli_latest = janus_get_monotonic_time();

	/* Notify the Lua script */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "setupMedia");
	lua_pushnumber(t, session->id);
	lua_call(t, 1, 0);
	lua_pop(lua_state, 1);
	janus_mutex_unlock(&lua_mutex);
	janus_refcount_decrease(&session->ref);
}

void janus_lua_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_lua_session *session = (janus_lua_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	/* Check if the Lua script wants to handle/manipulate RTP packets itself */
	if(has_incoming_rtp) {
		/* Yep, pass the data to the Lua script and return */
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "incomingRtp");
		lua_pushnumber(t, session->id);
		lua_pushboolean(t, video);
		lua_pushlstring(t, buf, len);
		lua_pushnumber(t, len);
		lua_call(t, 4, 0);
		lua_pop(lua_state, 1);
		janus_mutex_unlock(&lua_mutex);
		return;
	}
	/* Is this session allowed to send media? */
	if((video && !session->send_video) || (!video && !session->send_audio))
		return;
	/* Are we recording? */
	janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
	/* Handle the packet */
	rtp_header *rtp = (rtp_header *)buf;
	janus_lua_rtp_relay_packet packet;
	packet.data = rtp;
	packet.length = len;
	packet.is_video = video;
	/* Backup the actual timestamp and sequence number set by the publisher, in case switching is involved */
	packet.timestamp = ntohl(packet.data->timestamp);
	packet.seq_number = ntohs(packet.data->seq_number);
	/* Relay to all recipients */
	janus_mutex_lock_nodebug(&session->recipients_mutex);
	g_slist_foreach(session->recipients, janus_lua_relay_rtp_packet, &packet);
	janus_mutex_unlock_nodebug(&session->recipients_mutex);

	/* Check if we need to send any PLI to this media source */
	if(video && session->pli_freq > 0) {
		/* We send a FIR every tot seconds, depending on what the Lua script configured */
		gint64 now = janus_get_monotonic_time();
		if((now-session->pli_latest) >= ((gint64)session->pli_freq*G_USEC_PER_SEC)) {
			session->pli_latest = now;
			char rtcpbuf[12];
			janus_rtcp_pli((char *)&rtcpbuf, 12);
			JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->id);
			janus_core->relay_rtcp(handle, 1, rtcpbuf, 12);
		}
	}
}

void janus_lua_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_lua_session *session = (janus_lua_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	/* Check if the Lua script wants to handle/manipulate RTCP packets itself */
	if(has_incoming_rtcp) {
		/* Yep, pass the data to the Lua script and return */
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "incomingRtcp");
		lua_pushnumber(t, session->id);
		lua_pushboolean(t, video);
		lua_pushlstring(t, buf, len);
		lua_pushnumber(t, len);
		lua_call(t, 4, 0);
		lua_pop(lua_state, 1);
		janus_mutex_unlock(&lua_mutex);
		return;
	}
	/* If a REMB arrived, make sure we cap it to our configuration, and send it as a video RTCP */
	guint32 bitrate = janus_rtcp_get_remb(buf, len);
	if(bitrate > 0) {
		if(session->bitrate > 0) {
			char rtcpbuf[24];
			janus_rtcp_remb((char *)(&rtcpbuf), 24, session->bitrate);
			janus_core->relay_rtcp(handle, 1, rtcpbuf, 24);
		} else {
			janus_core->relay_rtcp(handle, 1, buf, len);
		}
	}
	/* If there's an incoming PLI, instead, relay it to the source of the media if any */
	if(janus_rtcp_has_pli(buf, len)) {
		if(session->sender != NULL) {
			janus_mutex_lock_nodebug(&session->sender->recipients_mutex);
			/* Send a PLI */
			session->sender->pli_latest = janus_get_monotonic_time();
			char rtcpbuf[12];
			janus_rtcp_pli((char *)&rtcpbuf, 12);
			JANUS_LOG(LOG_HUGE, "Sending PLI to session %"SCNu32"\n", session->sender->id);
			janus_core->relay_rtcp(session->sender->handle, 1, rtcpbuf, 12);
			janus_mutex_unlock_nodebug(&session->sender->recipients_mutex);
		}
	}
}

void janus_lua_incoming_data(janus_plugin_session *handle, char *label, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_lua_session *session = (janus_lua_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	/* Are we recording? */
	janus_recorder_save_frame(session->drc, buf, len);
	/* Check if the Lua script wants to handle/manipulate data channel packets itself */
	if(has_incoming_data) {
		/* Yep, pass the data to the Lua script and return */
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "incomingData");
		lua_pushnumber(t, session->id);
		lua_pushlstring(t, buf, len);
		lua_pushnumber(t, len);
		lua_call(t, 3, 0);
		lua_pop(lua_state, 1);
		janus_mutex_unlock(&lua_mutex);
		return;
	}
	/* Is this session allowed to send data? */
	if(!session->send_data)
		return;
	/* Get a string out of the data */
	char *text = g_malloc0(len+1);
	if(text == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to forward: %s\n", strlen(text), text);
	/* Relay to all recipients */
	janus_mutex_lock_nodebug(&session->recipients_mutex);
	g_slist_foreach(session->recipients, janus_lua_relay_data_packet, text);
	janus_mutex_unlock_nodebug(&session->recipients_mutex);
	g_free(text);
}

void janus_lua_slow_link(janus_plugin_session *handle, int uplink, int video) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_mutex_unlock(&lua_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	/* Check if the Lua script wants to handle such events */
	janus_refcount_increase(&session->ref);
	if(has_slow_link) {
		/* Notify the Lua script */
		janus_mutex_lock(&lua_mutex);
		lua_State *t = lua_newthread(lua_state);
		lua_getglobal(t, "slowLink");
		lua_pushnumber(t, session->id);
		lua_pushboolean(t, uplink);
		lua_pushboolean(t, video);
		lua_call(t, 3, 0);
		lua_pop(lua_state, 1);
		janus_mutex_unlock(&lua_mutex);
	}
	janus_refcount_decrease(&session->ref);
}

void janus_lua_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_LUA_PACKAGE, handle);
	if(g_atomic_int_get(&lua_stopping) || !g_atomic_int_get(&lua_initialized))
		return;
	janus_mutex_lock(&lua_sessions_mutex);
	janus_lua_session *session = janus_lua_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&lua_sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&lua_sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	if(g_atomic_int_add(&session->hangingup, 1)) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	g_atomic_int_set(&session->started, 0);

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
	janus_rtp_switching_context_reset(&session->rtpctx);

	/* Get rid of the recipients */
	janus_mutex_lock(&session->recipients_mutex);
	while(session->recipients) {
		janus_lua_session *recipient = (janus_lua_session *)session->recipients->data;
		session->recipients = g_slist_remove(session->recipients, recipient);
		recipient->sender = NULL;
		janus_refcount_decrease(&session->ref);
		janus_refcount_decrease(&recipient->ref);
	}
	janus_mutex_unlock(&session->recipients_mutex);

	/* Notify the Lua script */
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, "hangupMedia");
	lua_pushnumber(t, session->id);
	lua_call(t, 1, 0);
	lua_pop(lua_state, 1);
	janus_mutex_unlock(&lua_mutex);
	janus_refcount_decrease(&session->ref);
}

/* Helpers to quickly relay RTP and data packets to the intended recipients */
static void janus_lua_relay_rtp_packet(gpointer data, gpointer user_data) {
	janus_lua_rtp_relay_packet *packet = (janus_lua_rtp_relay_packet *)user_data;
	if(!packet || !packet->data || packet->length < 1) {
		JANUS_LOG(LOG_ERR, "Invalid packet...\n");
		return;
	}
	janus_lua_session *session = (janus_lua_session *)data;
	if(!session || !session->handle || !g_atomic_int_get(&session->started)) {
		return;
	}

	/* Check if this recipient is willing/allowed to receive this medium */
	if((packet->is_video && !session->accept_video) || (!packet->is_video && !session->accept_audio)) {
		/* Nope, don't relay */
		return;
	}
	/* Fix sequence number and timestamp (publisher switching may be involved) */
	janus_rtp_header_update(packet->data, &session->rtpctx, packet->is_video, packet->is_video ? 4500 : 960);
	/* Send the packet */
	if(janus_core != NULL)
		janus_core->relay_rtp(session->handle, packet->is_video, (char *)packet->data, packet->length);
	/* Restore the timestamp and sequence number to what the publisher set them to */
	packet->data->timestamp = htonl(packet->timestamp);
	packet->data->seq_number = htons(packet->seq_number);

	return;
}

static void janus_lua_relay_data_packet(gpointer data, gpointer user_data) {
	janus_lua_session *session = (janus_lua_session *)data;
	if(!session || !session->handle || !g_atomic_int_get(&session->started) || !session->accept_data) {
		return;
	}
	char *text = (char *)user_data;
	if(janus_core != NULL && text != NULL) {
		JANUS_LOG(LOG_VERB, "Forwarding DataChannel message (%zu bytes) to session %"SCNu32": %s\n",
			strlen(text), session->id, text);
		janus_core->relay_data(session->handle, NULL, text, strlen(text));
	}
	return;
}

/* This is a scheduler thread: if we know there are coroutines to resume
 * in Lua (e.g., for asynchronous requests), we do that ourselves here */
static void *janus_lua_scheduler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Lua scheduler thread\n");
	janus_lua_event *event = NULL;
	/* Wait until there are events to process */
	while(g_atomic_int_get(&lua_initialized) && !g_atomic_int_get(&lua_stopping)) {
		event = g_async_queue_pop(events);
		if(event == GUINT_TO_POINTER(janus_lua_event_exit))
			break;
		if(event == GUINT_TO_POINTER(janus_lua_event_resume)) {
			/* There are coroutines to resume */
			janus_mutex_lock(&lua_mutex);
			lua_getglobal(lua_state, "resumeScheduler");
			lua_call(lua_state, 0, 0);
			/* Print the count of elements into Lua stack */
			janus_lua_stackdump(lua_state);
			janus_mutex_unlock(&lua_mutex);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving Lua scheduler thread\n");
	return NULL;
}

/* This is a loop that can be used for timing callbacks, e.g., whenever
 * the Lua script asks for asynchronously invoking one of its methods
 * after some time, rather than immediately (which is what the scheduler
 * would be for instead). Allows for a string parameter to be passed. */
static void *janus_lua_timer(void *data) {
	JANUS_LOG(LOG_VERB, "Joining Lua timer loop\n");
	GMainLoop *loop = (GMainLoop *)data;
	/* Start loop */
	g_main_loop_run(loop);
	/* Done */
	JANUS_LOG(LOG_VERB, "Leaving Lua timer loop\n");
	return NULL;
}

/* Callback to trigger timed callbacks */
static gboolean janus_lua_timer_cb(void *data) {
	janus_lua_callback *cb = (janus_lua_callback *)data;
	if(cb == NULL)
		return FALSE;
	/* Invoke the callback with the provided argument, if available */
	JANUS_LOG(LOG_VERB, "Invoking scheduled callback (waited %"SCNu32"ms) with ID %u\n", cb->ms, cb->id);
	janus_mutex_lock(&lua_mutex);
	lua_State *t = lua_newthread(lua_state);
	lua_getglobal(t, cb->function);
	if(cb->argument == NULL) {
		lua_call(t, 0, 0);
	} else {
		lua_pushstring(t, cb->argument);
		lua_call(t, 1, 0);
	}
	lua_pop(lua_state, 1);
	janus_mutex_unlock(&lua_mutex);
	/* Done */
	g_source_destroy(cb->source);
	g_source_unref(cb->source);
	g_free(cb->function);
	g_free(cb->argument);
	g_free(cb);
	return FALSE;
}
