/*! \file   janus_textroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus TextRoom plugin
 * \details Check the \ref textroom for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page textroom Janus TextRoom documentation
 * This is a plugin implementing a DataChannel only text room.
 * As such, it does NOT support or negotiate audio or video, but only
 * data channels, in order to provide text broadcasting features. The
 * plugin allows users to join multiple text-only rooms via a single
 * PeerConnection. Users can send messages either to a room in general
 * (broadcasting), or to individual users (whispers). This plugin can be
 * used within the context of any application that needs real-time text
 * broadcasting (e.g., chatrooms, but not only).
 *
 * The only message that is typically sent to the plugin through the Janus API is
 * a "setup" message, by which the user initializes the PeerConnection
 * itself. Apart from that, all other messages can be exchanged directly
 * via Data Channels. For room management purposes, though, requests like
 * "create", "edit", "destroy", "list" and "exists" are available through the
 * Janus API as well: notice that in this case you'll have to use "request"
 * and not "textroom" as the name of the request.
 *
 * Each room can also be configured with an HTTP backend to contact for
 * incoming messages. If configured, messages addressed to that room will
 * also be forwarded, by means of an HTTP POST, to the specified address.
 * Notice that this will only work if libcurl was available when
 * configuring and installing Janus.
 *
 * \note This plugin is only meant to showcase what you can do with
 * data channels involving multiple participants at the same time. While
 * functional, it's not inherently better or faster than doing the same
 * thing using the Janus API messaging itself (e.g., as part of the
 * plugin API messaging) or using existing instant messaging protocols
 * (e.g., Jabber). In fact, while data channels are being used, you're
 * still going through a server, so it's not really peer-to-peer. That
 * said, the plugin can be useful if you don't plan to use any other
 * infrastructure than Janus, and yet you also want to have text-based
 * communication (e.g., to add a chatroom to an audio or video conference).
 *
 * Notice that, in general, all users can create rooms. If you want to
 * limit this functionality, you can configure an admin \c admin_key in
 * the plugin settings. When configured, only "create" requests that
 * include the correct \c admin_key value in an "admin_key" property
 * will succeed, and will be rejected otherwise.
 *
 * Rooms to make available at startup are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.textroom.cfg
 * and includes a demo room for testing.
 *
 * To add more static rooms or modify the existing one, you can use the following
 * syntax:
 *
 * \verbatim
[<unique room ID>]
description = This is my awesome room
is_private = true|false (whether this room should be in the public list, default=true)
secret = <optional password needed for manipulating (e.g. destroying) the room>
pin = <optional password needed for joining the room>
post = <optional backend to contact via HTTP post for all incoming messages>
\endverbatim
 *
 * As explained in the next section, you can also create rooms programmatically.
 *
 * \section textroomapi Text Room API
 *
 * All TextRoom API requests are addressed by a \c textroom named property,
 * and must contain a \c transaction string property as well, which will
 * be returned in the response. Notice that, for the sake of brevity, the
 * \c transaction property will not be displayed in the documentation,
 * although, as explained, it MUST be present, and WILL be included in
 * all responses (but not in the unsolicited events, like join/leave
 * or incoming messages).
 *
 * To get a list of the available rooms (excluded those configured or
 * created as private rooms) you can make use of the \c list request,
 * which has to be formatted as follows:
 *
\verbatim
{
	"textroom" : "list",
}
\endverbatim
 *
 * A successful request will produce a list of rooms in a \c success response:
 *
\verbatim
{
	"textroom" : "success",
	"rooms" : [		// Array of room objects
		{	// Room #1
			"room" : <unique numeric ID>,
			"description" : "<Name of the room>",
			"pin_required" : <true|false, depending on whether the room is PIN-protected>,
			"num_participants" : <count of the participants>
		},
		// Other rooms
	]
}
\endverbatim
 *
 * To create new TextRoom rooms you can use the \c create request. The API
 * room creation supports the same fields as creation via configuration files,
 * which means the request must be formatted as follows:
 *
\verbatim
{
	"textroom" : "create",
	"room" : <unique numeric room ID to assign; optional, chosen by plugin if missing>,
	"admin_key" : "<plugin administrator key; mandatory if configured>",
	"description" : "<description of room; optional>",
	"secret" : "<secret to query/edit the room later; optional>",
	"pin" : "<PIN required for participants to join room; optional>",
	"is_private" : <true|false, whether the room should be listable; optional, true by default>,
	"post" : "<backend to contact via HTTP post for all incoming messages; optional>",
	"permanent" : <true|false, whether the mountpoint should be saved to configuration file or not; false by default>
}
\endverbatim
 *
 * A successful creation procedure will result in a \c success response:
 *
\verbatim
{
	"textroom" : "success",
	"room" : <unique numeric ID>,
	"permanent" : <true if saved to config file, false if not>
}
\endverbatim
 *
 * If you requested a permanent room but a \c false value is returned
 * instead, good chances are that there are permission problems.
 *
 * An error instead (and the same applies to all other requests, so this
 * won't be repeated) would provide both an error code and a more verbose
 * description of the cause of the issue:
 *
\verbatim
{
	"textroom" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * Once a room has been created, you can still edit some (but not all)
 * of its properties using the \c edit request. This allows you to modify
 * the room description, secret, pin, whether it's private or not and
 * the backend to forward incoming messages to: you won't be able to modify
 * other more static properties, though, like the room ID for instance.
 * If you're interested in changing the ACL, instead, check the \c allowed
 * message. An \c edit request has to be formatted as follows:
 *
\verbatim
{
	"textroom" : "edit",
	"room" : <unique numeric ID of the room to edit; mandatory>,
	"secret" : "<room secret; mandatory if configured>",
	"new_description" : "<new pretty name of the room; optional>",
	"new_secret" : "<new password required to edit/destroy the room; optional>",
	"new_pin" : "<new password required to join the room; optional>",
	"new_is_private" : <true|false, whether the room should appear in a list request; optional>,
	"permanent" : <true|false, whether the room should be also removed from the config file; default=false>
}
\endverbatim
 *
 * A successful edit procedure will result in a \c success response:
 *
\verbatim
{
	"textroom" : "edited",
	"room" : <unique numeric ID>,
	"permanent" : <true if changes were saved to config file, false if not>
}
\endverbatim
 *
 * On the other hand, \c destroy can be used to destroy an existing text
 * room, whether created dynamically or statically, and has to be
 * formatted as follows:
 *
\verbatim
{
	"textroom" : "destroy",
	"room" : <unique numeric ID of the room to destroy; mandatory>,
	"secret" : "<room secret; mandatory if configured>",
	"permanent" : <true|false, whether the room should be also removed from the config file; default=false>
}
\endverbatim
 *
 * A successful destruction procedure will result in a \c destroyed response:
 *
\verbatim
{
	"textroom" : "destroyed",
	"room" : <unique numeric ID>,
	"permanent" : <true if the room was removed from config file too, false if not>
}
\endverbatim
 *
 * This will also result in a \c destroyed event being sent to all the
 * participants in the room, which will look like this:
 *
\verbatim
{
	"textroom" : "destroyed",
	"room" : <unique numeric ID of the destroyed room>
}
\endverbatim
 *
 * You can check whether a room exists using the \c exists request,
 * which has to be formatted as follows:
 *
\verbatim
{
	"textroom" : "exists",
	"room" : <unique numeric ID of the room to check; mandatory>
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"textroom" : "success",
	"room" : <unique numeric ID>,
	"exists" : <true|false>
}
\endverbatim
 *
 * You can configure whether to check tokens or add/remove people who can join
 * a room using the \c allowed request, which has to be formatted as follows:
 *
\verbatim
{
	"textroom" : "allowed",
	"secret" : "<room secret; mandatory if configured>",
	"action" : "enable|disable|add|remove",
	"room" : <unique numeric ID of the room to update; mandatory>,
	"allowed" : [
		// Array of strings (tokens users might pass in "join", only for add|remove)
	]
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"textroom" : "success",
	"room" : <unique numeric ID>,
	"allowed" : [
		// Updated, complete, list of allowed tokens (only for enable|add|remove)
	]
}
\endverbatim
 *
 * If you're the administrator of a room (that is, you created it and have access
 * to the secret) you can kick participants using the \c kick request. Notice
 * that this only kicks the user out of the room, but does not prevent them from
 * re-joining: to ban them, you need to first remove them from the list of
 * authorized users (see \c allowed request) and then \c kick them. The \c kick
 * request has to be formatted as follows:
 *
\verbatim
{
	"textroom" : "kick",
	"secret" : "<room secret; mandatory if configured>",
	"room" : <unique numeric ID of the room; mandatory>,
	"username" : "<unique username of the participant to kick; mandatory>"
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"textroom" : "success",
}
\endverbatim
 *
 * This will also result in a \c kicked event being sent to all the other
 * participants in the room, which will look like this:
 *
\verbatim
{
	"textroom" : "kicked",
	"room" : <unique numeric ID of the room>,
	"username" : "<unique username of the kicked participant>"
}
\endverbatim
 *
 * For what concerns room participation, you can join a room using the
 * \c join request, send messages (public and private) using the
 * \c message request, and leave a room with \c leave instead.
 *
 * A \c join request must be formatted as follows:
 *
\verbatim
{
	"textroom" : "join",
	"room" : <unique numeric ID of the room to join>,
	"pin" : "<pin to join the room; mandatory if configured>",
	"username" : "<unique username to have in the room; mandatory>",
	"display" : "<display name to use in the room; optional>"
}
\endverbatim
 *
 * A successful join will result in a \c success response, which will
 * include a list of all the other participants currently in the room:
 *
\verbatim
{
	"textroom" : "success",
	"participants" : [
		{
			"username" : "<username of participant #1>",
			"display" : "<display name of participant #1, if any>"
		},
		// Other participants
	]
}
\endverbatim
 *
 * As explained previously, there's no hardcoded limit in how many rooms
 * you can join with the same participant and on the same PeerConnection.
 *
 * Notice that a successful \c join request will also result in a
 * \c join event being sent to all the other participants, so that
 * they're notified about the new participant getting in the room:
 *
\verbatim
{
	"textroom" : "join",
	"room" : <room ID>,
	"username" : "<username of new participant>",
	"display" : "<display name of new participant, if any>"
}
\endverbatim
 *
 * To leave a previously joined room, instead, the \c leave request can
 * be used, which must be formatted like this:
 *
\verbatim
{
	"textroom" : "leave",
	"room" : <unique numeric ID of the room to leave>
}
\endverbatim
 *
 * A successful leave will result in a \c success response:
 *
\verbatim
{
	"textroom" : "success"
}
\endverbatim
 *
 * Notice that a successful \c leave request will also result in a
 * \c leave event being sent to all the other participants, so that
 * they're notified about the participant that just left the room:
 *
\verbatim
{
	"textroom" : "leave",
	"room" : <room ID>,
	"username" : "<username of gone participant>"
}
\endverbatim
 *
 * Finally, the \c message request allows you to send public and private
 * messages within the context of a room. It must be formatted like this:
 *
\verbatim
{
	"textroom" : "message",
	"room" : <unique numeric ID of the room this message will refer to>,
	"to" : "<username to send the message to; optional, only needed in case of private messages>",
	"tos" : "<array of usernames to send the message to; optional, only needed in case of private messages>",
	"text" : "<content of the message to send, as a string>",
	"ack" : <true|false, whether the sender wants an ack for the sent message(s); optional, true by default>
}
\endverbatim
 *
 * A \c message with no \c to and no \c tos is considered a public message,
 * and so will be sent to all the participants in the room. In case either
 * \c to or \c tos is specified, instead, this is considered to be a whisper,
 * that is a private message only meant for the specified recipients. Notice
 * that \c to and \c tos are mutually exclusive, and you cannot specify both.
 *
 * \c text must be a string, but apart from that there's no limit on what
 * you can put in there. It could be, for instance, a serialized JSON string,
 * or a stringified XML document, or whatever makes sense to the application.
 *
 * A successful message delivery will result in a \c success response, but
 * only if \c ack was \c true in the \c message request. This was done by
 * design, to allow users to disable explicit acks for every outgoing message,
 * especially in case of verbose communications. In case an ack is required,
 * the response will look like this:
 *
\verbatim
{
	"textroom" : "success"
}
\endverbatim
 *
 * Incoming messages can come either as \c message or \c whisper events.
 * \c message will notify the user about an incoming public message, that
 * is a message that was sent to the whole room:
 *
\verbatim
{
	"textroom" : "message",
	"room" : <room ID the message was sent to>,
	"from" : "<username of participant who sent the public message>",
	"date" : "<date/time of when the message was sent>",
	"text" : "<content of the message>"
}
\endverbatim
 *
 * \c whisper messages, instead, will notify the user about an incoming
 * \b private message from another participant in the room:
 *
\verbatim
{
	"textroom" : "whisper",
	"room" : <room ID the message was sent to>,
	"from" : "<username of participant who sent the private message>",
	"date" : "<date/time of when the message was sent>",
	"text" : "<content of the message>"
}
\endverbatim
 */

#include "plugin.h"

#include <jansson.h>

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#endif

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_TEXTROOM_VERSION			2
#define JANUS_TEXTROOM_VERSION_STRING	"0.0.2"
#define JANUS_TEXTROOM_DESCRIPTION		"This is a plugin implementing a text-only room for Janus, using DataChannels."
#define JANUS_TEXTROOM_NAME				"JANUS TextRoom plugin"
#define JANUS_TEXTROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_TEXTROOM_PACKAGE			"janus.plugin.textroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_textroom_init(janus_callbacks *callback, const char *config_path);
void janus_textroom_destroy(void);
int janus_textroom_get_api_compatibility(void);
int janus_textroom_get_version(void);
const char *janus_textroom_get_version_string(void);
const char *janus_textroom_get_description(void);
const char *janus_textroom_get_name(void);
const char *janus_textroom_get_author(void);
const char *janus_textroom_get_package(void);
void janus_textroom_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_textroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_textroom_setup_media(janus_plugin_session *handle);
void janus_textroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_textroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_textroom_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_textroom_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_textroom_hangup_media(janus_plugin_session *handle);
void janus_textroom_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_textroom_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_textroom_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_textroom_init,
		.destroy = janus_textroom_destroy,

		.get_api_compatibility = janus_textroom_get_api_compatibility,
		.get_version = janus_textroom_get_version,
		.get_version_string = janus_textroom_get_version_string,
		.get_description = janus_textroom_get_description,
		.get_name = janus_textroom_get_name,
		.get_author = janus_textroom_get_author,
		.get_package = janus_textroom_get_package,

		.create_session = janus_textroom_create_session,
		.handle_message = janus_textroom_handle_message,
		.setup_media = janus_textroom_setup_media,
		.incoming_rtp = janus_textroom_incoming_rtp,
		.incoming_rtcp = janus_textroom_incoming_rtcp,
		.incoming_data = janus_textroom_incoming_data,
		.slow_link = janus_textroom_slow_link,
		.hangup_media = janus_textroom_hangup_media,
		.destroy_session = janus_textroom_destroy_session,
		.query_session = janus_textroom_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_TEXTROOM_NAME);
	return &janus_textroom_plugin;
}


/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter transaction_parameters[] = {
	{"textroom", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"transaction", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter room_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter create_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
	{"description", JSON_STRING, 0},
	{"secret", JSON_STRING, 0},
	{"pin", JSON_STRING, 0},
	{"post", JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0},
	{"allowed", JSON_ARRAY, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter destroy_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter edit_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JSON_STRING, 0},
	{"new_description", JSON_STRING, 0},
	{"new_secret", JSON_STRING, 0},
	{"new_pin", JSON_STRING, 0},
	{"new_post", JSON_STRING, 0},
	{"new_is_private", JANUS_JSON_BOOL, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter allowed_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JSON_STRING, 0},
	{"action", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"allowed", JSON_ARRAY, 0}
};
static struct janus_json_parameter kick_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"secret", JSON_STRING, 0},
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter join_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"pin", JSON_STRING, 0},
	{"display", JSON_STRING, 0}
};
static struct janus_json_parameter message_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"text", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"to", JSON_STRING, 0},
	{"tos", JSON_ARRAY, 0},
	{"ack", JANUS_JSON_BOOL, 0}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex = JANUS_MUTEX_INITIALIZER;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_textroom_handler(void *data);
static void janus_textroom_hangup_media_internal(janus_plugin_session *handle);

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


typedef struct janus_textroom_room {
	guint64 room_id;			/* Unique room ID */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	gchar *http_backend;		/* Server to contact via HTTP POST for incoming messages, if any */
	GHashTable *participants;	/* Map of participants */
	gboolean check_tokens;		/* Whether to check tokens when participants join (see below) */
	GHashTable *allowed;		/* Map of participants (as tokens) allowed to join */
	volatile gint destroyed;	/* Whether this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */
	janus_refcount ref;
} janus_textroom_room;
static GHashTable *rooms;
static janus_mutex rooms_mutex = JANUS_MUTEX_INITIALIZER;
static char *admin_key = NULL;

typedef struct janus_textroom_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	GHashTable *rooms;			/* Map of rooms this user is in, and related participant instance */
	janus_mutex mutex;			/* Mutex to lock this session */
	volatile gint setup;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_textroom_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

typedef struct janus_textroom_participant {
	janus_textroom_session *session;
	janus_textroom_room *room;	/* Room this participant is in */
	gchar *username;			/* Unique username in the room */
	gchar *display;				/* Display name in the room, if any */
	janus_mutex mutex;			/* Mutex to lock this session */
	volatile gint destroyed;	/* Whether this participant has been destroyed */
	janus_refcount ref;
} janus_textroom_participant;

static void janus_textroom_room_destroy(janus_textroom_room *textroom) {
	if(textroom && g_atomic_int_compare_and_exchange(&textroom->destroyed, 0, 1))
		janus_refcount_decrease(&textroom->ref);
}
static void janus_textroom_room_free(const janus_refcount *textroom_ref) {
	janus_textroom_room *textroom = janus_refcount_containerof(textroom_ref, janus_textroom_room, ref);
	/* This room can be destroyed, free all the resources */
	g_free(textroom->room_name);
	g_free(textroom->room_secret);
	g_free(textroom->room_pin);
	g_free(textroom->http_backend);
	g_hash_table_destroy(textroom->participants);
	g_hash_table_destroy(textroom->allowed);
	g_free(textroom);
}

static void janus_textroom_session_destroy(janus_textroom_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}
static void janus_textroom_session_free(const janus_refcount *session_ref) {
	janus_textroom_session *session = janus_refcount_containerof(session_ref, janus_textroom_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_hash_table_destroy(session->rooms);
	g_free(session);
}

static void janus_textroom_participant_dereference(janus_textroom_participant *p) {
	if(p)
		janus_refcount_decrease(&p->ref);
}

static void janus_textroom_participant_destroy(janus_textroom_participant *participant) {
	if(participant && g_atomic_int_compare_and_exchange(&participant->destroyed, 0, 1))
		janus_refcount_decrease(&participant->ref);
}
static void janus_textroom_participant_free(const janus_refcount *participant_ref) {
	janus_textroom_participant *participant = janus_refcount_containerof(participant_ref, janus_textroom_participant, ref);
	/* This participant can be destroyed, free all the resources */
	g_free(participant->username);
	g_free(participant->display);
	g_free(participant);
}


typedef struct janus_textroom_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_textroom_message;
static GAsyncQueue *messages = NULL;
static janus_textroom_message exit_message;

static void janus_textroom_message_free(janus_textroom_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_textroom_session *session = (janus_textroom_session *)msg->handle->plugin_handle;
		janus_refcount_decrease(&session->ref);
	}
	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message)
		json_decref(msg->message);
	msg->message = NULL;
	if(msg->jsep)
		json_decref(msg->jsep);
	msg->jsep = NULL;

	g_free(msg);
}


/* SDP template: we only offer data channels */
#define sdp_template \
		"v=0\r\n" \
		"o=- %"SCNu64" %"SCNu64" IN IP4 127.0.0.1\r\n"	/* We need current time here */ \
		"s=Janus TextRoom plugin\r\n" \
		"t=0 0\r\n" \
		"m=application 1 DTLS/SCTP 5000\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctpmap:5000 webrtc-datachannel 16\r\n"


/* Error codes */
#define JANUS_TEXTROOM_ERROR_NO_MESSAGE			411
#define JANUS_TEXTROOM_ERROR_INVALID_JSON		412
#define JANUS_TEXTROOM_ERROR_MISSING_ELEMENT	413
#define JANUS_TEXTROOM_ERROR_INVALID_ELEMENT	414
#define JANUS_TEXTROOM_ERROR_INVALID_REQUEST	415
#define JANUS_TEXTROOM_ERROR_ALREADY_SETUP		416
#define JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM		417
#define JANUS_TEXTROOM_ERROR_ROOM_EXISTS		418
#define JANUS_TEXTROOM_ERROR_UNAUTHORIZED		419
#define JANUS_TEXTROOM_ERROR_USERNAME_EXISTS	420
#define JANUS_TEXTROOM_ERROR_ALREADY_IN_ROOM	421
#define JANUS_TEXTROOM_ERROR_NOT_IN_ROOM		422
#define JANUS_TEXTROOM_ERROR_NO_SUCH_USER		423
#define JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR		499

#ifdef HAVE_LIBCURL
static size_t janus_textroom_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	return size*nmemb;
}
#endif

/* We use this method to handle incoming requests. Since most of the requests
 * will arrive from data channels, but some may also arrive from the regular
 * plugin messaging (e.g., room management), we have the ability to pass
 * parsed JSON objects instead of strings, which explains why we specify a
 * janus_plugin_result pointer as a return value; messages handles via
 * datachannels would simply return NULL. Besides, some requests are actually
 * originated internally, and don't need any response to be sent to anyone,
 * which is what the additional boolean "internal" value is for */
janus_plugin_result *janus_textroom_handle_incoming_request(janus_plugin_session *handle,
	char *text, json_t *json, gboolean internal);


/* Plugin implementation */
int janus_textroom_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_TEXTROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_TEXTROOM_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_TEXTROOM_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);
	rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_textroom_room_destroy);
	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_textroom_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_textroom_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	/* Parse configuration to populate the rooms list */
	if(config != NULL) {
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "json");
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
		/* Any admin key to limit who can "create"? */
		janus_config_item *key = janus_config_get(config, config_general, janus_config_type_item, "admin_key");
		if(key != NULL && key->value != NULL)
			admin_key = g_strdup(key->value);
		janus_config_item *events = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(events != NULL && events->value != NULL)
			notify_events = janus_is_true(events->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_TEXTROOM_NAME);
		}
		/* Iterate on all rooms */
		GList *clist = janus_config_get_categories(config, NULL), *cl = clist;
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL || !strcasecmp(cat->name, "general")) {
				cl = cl->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding text room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get(config, cat, janus_config_type_item, "description");
			janus_config_item *priv = janus_config_get(config, cat, janus_config_type_item, "is_private");
			janus_config_item *secret = janus_config_get(config, cat, janus_config_type_item, "secret");
			janus_config_item *pin = janus_config_get(config, cat, janus_config_type_item, "pin");
			janus_config_item *post = janus_config_get(config, cat, janus_config_type_item, "post");
			/* Create the text room */
			janus_textroom_room *textroom = g_malloc0(sizeof(janus_textroom_room));
			const char *room_num = cat->name;
			if(strstr(room_num, "room-") == room_num)
				room_num += 5;
			textroom->room_id = g_ascii_strtoull(room_num, NULL, 0);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			textroom->room_name = description;
			textroom->is_private = priv && priv->value && janus_is_true(priv->value);
			if(secret != NULL && secret->value != NULL) {
				textroom->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				textroom->room_pin = g_strdup(pin->value);
			}
			if(post != NULL && post->value != NULL) {
#ifdef HAVE_LIBCURL
				/* FIXME Should we check if this is a valid HTTP address? */
				textroom->http_backend = g_strdup(post->value);
#else
				JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
			}
			textroom->participants = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_textroom_participant_dereference);
			textroom->check_tokens = FALSE;	/* Static rooms can't have an "allowed" list yet, no hooks to the configuration file */
			textroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
			textroom->destroyed = 0;
			janus_mutex_init(&textroom->mutex);
			janus_refcount_init(&textroom->ref, janus_textroom_room_free);
			JANUS_LOG(LOG_VERB, "Created textroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
				textroom->room_id, textroom->room_name,
				textroom->is_private ? "private" : "public",
				textroom->room_secret ? textroom->room_secret : "no secret",
				textroom->room_pin ? textroom->room_pin : "no pin");
			g_hash_table_insert(rooms, janus_uint64_dup(textroom->room_id), textroom);
			cl = cl->next;
		}
		g_list_free(clist);
		/* Done: we keep the configuration file open in case we get a "create" or "destroy" with permanent=true */
	}

	/* Show available rooms */
	janus_mutex_lock(&rooms_mutex);
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, rooms);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		janus_textroom_room *tr = value;
		JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s]\n", tr->room_id, tr->room_name);
	}
	janus_mutex_unlock(&rooms_mutex);

#ifdef HAVE_LIBCURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("textroom handler", janus_textroom_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the TextRoom handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_TEXTROOM_NAME);
	return 0;
}

void janus_textroom_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	sessions = NULL;
	janus_mutex_unlock(&sessions_mutex);
	janus_mutex_lock(&rooms_mutex);
	g_hash_table_destroy(rooms);
	rooms = NULL;
	janus_mutex_unlock(&rooms_mutex);
	g_async_queue_unref(messages);
	messages = NULL;

#ifdef HAVE_LIBCURL
	curl_global_cleanup();
#endif

	janus_config_destroy(config);
	g_free(admin_key);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_TEXTROOM_NAME);
}

int janus_textroom_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_textroom_get_version(void) {
	return JANUS_TEXTROOM_VERSION;
}

const char *janus_textroom_get_version_string(void) {
	return JANUS_TEXTROOM_VERSION_STRING;
}

const char *janus_textroom_get_description(void) {
	return JANUS_TEXTROOM_DESCRIPTION;
}

const char *janus_textroom_get_name(void) {
	return JANUS_TEXTROOM_NAME;
}

const char *janus_textroom_get_author(void) {
	return JANUS_TEXTROOM_AUTHOR;
}

const char *janus_textroom_get_package(void) {
	return JANUS_TEXTROOM_PACKAGE;
}

static janus_textroom_session *janus_textroom_lookup_session(janus_plugin_session *handle) {
	janus_textroom_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_textroom_session *)handle->plugin_handle;
	}
	return session;
}

void janus_textroom_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_textroom_session *session = g_malloc0(sizeof(janus_textroom_session));
	session->handle = handle;
	session->rooms = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_textroom_participant_dereference);
	session->destroyed = 0;
	janus_mutex_init(&session->mutex);
	janus_refcount_init(&session->ref, janus_textroom_session_free);
	g_atomic_int_set(&session->setup, 0);
	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_textroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_textroom_session *session = janus_textroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing TextRoom session...\n");
	janus_textroom_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_textroom_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_textroom_session *session = janus_textroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* TODO Return meaningful info: participant details, rooms they're in, etc. */
	json_t *info = json_object();
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_textroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_textroom_session *session = janus_textroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been destroyed...\n");
		error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_TEXTROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_TEXTROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request = json_object_get(root, "request");
	/* Some requests (e.g., 'create' and 'destroy') can be handled synchronously */
	const char *request_text = json_string_value(request);
	if(!strcasecmp(request_text, "list")
			|| !strcasecmp(request_text, "exists")
			|| !strcasecmp(request_text, "create")
			|| !strcasecmp(request_text, "edit")
			|| !strcasecmp(request_text, "destroy")) {
		/* These requests typically only belong to the datachannel
		 * messaging, but for admin purposes we might use them on
		 * the Janus API as well: add the properties the datachannel
		 * processor would expect and handle everything there */
		json_object_set_new(root, "textroom", json_string(request_text));
		json_object_set_new(root, "transaction", json_string(transaction));
		janus_plugin_result *result = janus_textroom_handle_incoming_request(session->handle, NULL, root, FALSE);
		if(result == NULL) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_TEXTROOM_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto plugin_response;
		}
		if(root != NULL)
			json_decref(root);
		if(jsep != NULL)
			json_decref(jsep);
		g_free(transaction);
		janus_refcount_decrease(&session->ref);
		return result;
	} else if(!strcasecmp(request_text, "setup") || !strcasecmp(request_text, "ack") || !strcasecmp(request_text, "restart")) {
		/* These messages are handled asynchronously */
		janus_textroom_message *msg = g_malloc(sizeof(janus_textroom_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_TEXTROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "textroom", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			if(root != NULL)
				json_decref(root);
			if(jsep != NULL)
				json_decref(jsep);
			g_free(transaction);

			if(session != NULL)
				janus_refcount_decrease(&session->ref);
			return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, response);
		}

}

void janus_textroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_textroom_session *session = janus_textroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_unlock(&sessions_mutex);
}

void janus_textroom_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	/* We don't do audio/video */
}

void janus_textroom_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	/* We don't do audio/video */
}

void janus_textroom_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Incoming request from this user: what should we do? */
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	if(session->destroyed) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	if(buf == NULL || len <= 0) {
		janus_refcount_decrease(&session->ref);
		return;
	}
	char *text = g_malloc(len+1);
	memcpy(text, buf, len);
	*(text+len) = '\0';
	JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes): %s\n", strlen(text), text);
	janus_textroom_handle_incoming_request(handle, text, NULL, FALSE);
	janus_refcount_decrease(&session->ref);
}

/* Helper method to handle incoming messages from the data channel */
janus_plugin_result *janus_textroom_handle_incoming_request(janus_plugin_session *handle, char *text, json_t *json, gboolean internal) {
	janus_textroom_session *session = (janus_textroom_session *)handle->plugin_handle;
	/* Parse JSON, if needed */
	json_error_t error;
	json_t *root = text ? json_loads(text, 0, &error) : json;
	g_free(text);
	if(!root) {
		JANUS_LOG(LOG_ERR, "Error parsing data channel message (JSON error: on line %d: %s)\n", error.line, error.text);
		return NULL;
	}
	/* Handle request */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(root, transaction_parameters,
		error_code, error_cause, TRUE,
		JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
	const char *transaction_text = NULL;
	json_t *reply = NULL;
	if(error_code != 0)
		goto msg_response;
	json_t *request = json_object_get(root, "textroom");
	json_t *transaction = json_object_get(root, "transaction");
	const char *request_text = json_string_value(request);
	transaction_text = json_string_value(transaction);
	if(!strcasecmp(request_text, "message")) {
		JANUS_VALIDATE_JSON_OBJECT(root, message_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_refcount_increase(&textroom->ref);
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_textroom_participant *participant = g_hash_table_lookup(session->rooms, &room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			JANUS_LOG(LOG_ERR, "Not in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %"SCNu64, room_id);
			goto msg_response;
		}
		janus_refcount_increase(&participant->ref);
		json_t *username = json_object_get(root, "to");
		json_t *usernames = json_object_get(root, "tos");
		if(username && usernames) {
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			JANUS_LOG(LOG_ERR, "Both to and tos array provided\n");
			error_code = JANUS_TEXTROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Both to and tos array provided");
			goto msg_response;
		}
		json_t *text = json_object_get(root, "text");
		const char *message = json_string_value(text);
		/* Prepare outgoing message */
		json_t *msg = json_object();
		json_object_set_new(msg, "textroom", json_string("message"));
		json_object_set_new(msg, "room", json_integer(room_id));
		json_object_set_new(msg, "from", json_string(participant->username));
		time_t timer;
		time(&timer);
		struct tm *tm_info = localtime(&timer);
		char msgTime[64];
		strftime(msgTime, sizeof(msgTime), "%FT%T%z", tm_info);
		json_object_set_new(msg, "date", json_string(msgTime));
		json_object_set_new(msg, "text", json_string(message));
		if(username || usernames)
			json_object_set_new(msg, "whisper", json_true());
		char *msg_text = json_dumps(msg, json_format);
		json_decref(msg);
		/* Start preparing the response too */
		reply = json_object();
		json_object_set_new(reply, "textroom", json_string("success"));
		/* Who should we send this message to? */
		if(username) {
			/* A single user */
			json_t *sent = json_object();
			const char *to = json_string_value(username);
			JANUS_LOG(LOG_VERB, "To %s in %"SCNu64": %s\n", to, room_id, message);
			janus_textroom_participant *top = g_hash_table_lookup(textroom->participants, to);
			if(top) {
				janus_refcount_increase(&top->ref);
				gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
				janus_refcount_decrease(&top->ref);
				json_object_set_new(sent, to, json_true());
			} else {
				JANUS_LOG(LOG_WARN, "User %s is not in room %"SCNu64", failed to send message\n", to, room_id);
				json_object_set_new(sent, to, json_false());
			}
			json_object_set_new(reply, "sent", sent);
		} else if(usernames) {
			/* A limited number of users */
			json_t *sent = json_object();
			size_t i = 0;
			for(i=0; i<json_array_size(usernames); i++) {
				json_t *u = json_array_get(usernames, i);
				const char *to = json_string_value(u);
				JANUS_LOG(LOG_VERB, "To %s in %"SCNu64": %s\n", to, room_id, message);
				janus_textroom_participant *top = g_hash_table_lookup(textroom->participants, to);
				if(top) {
					janus_refcount_increase(&top->ref);
					gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
					janus_refcount_decrease(&top->ref);
					json_object_set_new(sent, to, json_true());
				} else {
					JANUS_LOG(LOG_WARN, "User %s is not in room %"SCNu64", failed to send message\n", to, room_id);
					json_object_set_new(sent, to, json_false());
				}
			}
			json_object_set_new(reply, "sent", sent);
		} else {
			/* Everybody in the room */
			JANUS_LOG(LOG_VERB, "To everybody in %"SCNu64": %s\n", room_id, message);
			if(textroom->participants) {
				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, textroom->participants);
				while(g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_textroom_participant *top = value;
					JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64": %s\n", top->username, room_id, message);
					janus_refcount_increase(&top->ref);
					gateway->relay_data(top->session->handle, msg_text, strlen(msg_text));
					janus_refcount_decrease(&top->ref);
				}
			}
#ifdef HAVE_LIBCURL
			/* Is there a backend waiting for this message too? */
			if(textroom->http_backend) {
				/* Prepare the libcurl context */
				CURLcode res;
				CURL *curl = curl_easy_init();
				if(curl == NULL) {
					JANUS_LOG(LOG_ERR, "Error initializing CURL context\n");
				} else {
					curl_easy_setopt(curl, CURLOPT_URL, textroom->http_backend);
					struct curl_slist *headers = NULL;
					headers = curl_slist_append(headers, "Accept: application/json");
					headers = curl_slist_append(headers, "Content-Type: application/json");
					headers = curl_slist_append(headers, "charsets: utf-8");
					curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
					curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg_text);
					curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, janus_textroom_write_data);
					/* Send the request */
					res = curl_easy_perform(curl);
					if(res != CURLE_OK) {
						JANUS_LOG(LOG_ERR, "Couldn't relay event to the backend: %s\n", curl_easy_strerror(res));
					} else {
						JANUS_LOG(LOG_DBG, "Event sent!\n");
					}
					curl_easy_cleanup(curl);
					curl_slist_free_all(headers);
				}
			}
#endif
		}
		janus_refcount_decrease(&participant->ref);
		free(msg_text);
		janus_mutex_unlock(&textroom->mutex);
		janus_refcount_decrease(&textroom->ref);
		/* By default we send a confirmation back to the user that sent this message:
		 * if the user passed an ack=false, though, we don't do that */
		json_t *ack = json_object_get(root, "ack");
		if(!internal && (ack == NULL || json_is_true(ack))) {
			/* Send response back */
		} else {
			internal = TRUE;
			json_decref(reply);
			reply = NULL;
		}
	} else if(!strcasecmp(request_text, "join")) {
		JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_refcount_increase(&textroom->ref);
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		/* A PIN may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_pin, root, "pin", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			goto msg_response;
		}
		janus_mutex_lock(&session->mutex);
		if(g_hash_table_lookup(session->rooms, &room_id) != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			JANUS_LOG(LOG_ERR, "Already in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_ALREADY_IN_ROOM;
			g_snprintf(error_cause, 512, "Already in room %"SCNu64, room_id);
			goto msg_response;
		}
		json_t *username = json_object_get(root, "username");
		const char *username_text = json_string_value(username);
		janus_textroom_participant *participant = g_hash_table_lookup(textroom->participants, username_text);
		if(participant != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			JANUS_LOG(LOG_ERR, "Username already taken\n");
			error_code = JANUS_TEXTROOM_ERROR_USERNAME_EXISTS;
			g_snprintf(error_cause, 512, "Username already taken");
			goto msg_response;
		}
		json_t *display = json_object_get(root, "display");
		const char *display_text = json_string_value(display);
		/* Create a participant instance */
		participant = g_malloc(sizeof(janus_textroom_participant));
		participant->session = session;
		participant->room = textroom;
		participant->username = g_strdup(username_text);
		participant->display = display_text ? g_strdup(display_text) : NULL;
		participant->destroyed = 0;
		janus_mutex_init(&participant->mutex);
		janus_refcount_init(&participant->ref, janus_textroom_participant_free);
		janus_refcount_increase(&participant->ref);
		g_hash_table_insert(session->rooms, janus_uint64_dup(textroom->room_id), participant);
		janus_refcount_increase(&participant->ref);
		g_hash_table_insert(textroom->participants, participant->username, participant);
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new join\n");
		json_t *list = json_array();
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("join"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			json_object_set_new(event, "username", json_string(username_text));
			if(display_text != NULL)
				json_object_set_new(event, "display", json_string(display_text));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
				/* Take note of this user */
				json_t *p = json_object();
				json_object_set_new(p, "username", json_string(top->username));
				if(top->display != NULL)
					json_object_set_new(p, "display", json_string(top->display));
				json_array_append_new(list, p);
				janus_refcount_decrease(&top->ref);
			}
			free(event_text);
		}
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&textroom->mutex);
		janus_refcount_decrease(&textroom->ref);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "participants", list);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("join"));
			json_object_set_new(info, "room", json_integer(room_id));
			json_object_set_new(info, "username", json_string(username_text));
			if(display_text)
				json_object_set_new(info, "display", json_string(display_text));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
	} else if(!strcasecmp(request_text, "leave")) {
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_refcount_increase(&textroom->ref);
		janus_mutex_lock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&session->mutex);
		janus_textroom_participant *participant = g_hash_table_lookup(session->rooms, &room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&textroom->mutex);
			janus_refcount_decrease(&textroom->ref);
			JANUS_LOG(LOG_ERR, "Not in room %"SCNu64"\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %"SCNu64, room_id);
			goto msg_response;
		}
		janus_refcount_increase(&participant->ref);
		g_hash_table_remove(session->rooms, &room_id);
		g_hash_table_remove(textroom->participants, participant->username);
		participant->session = NULL;
		participant->room = NULL;
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new leave\n");
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("leave"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			json_object_set_new(event, "username", json_string(participant->username));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
				janus_refcount_decrease(&top->ref);
			}
			free(event_text);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("leave"));
			json_object_set_new(info, "room", json_integer(room_id));
			json_object_set_new(info, "username", json_string(participant->username));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&textroom->mutex);
		janus_refcount_decrease(&textroom->ref);
		janus_refcount_decrease(&participant->ref);
		janus_textroom_participant_destroy(participant);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
		}
	} else if(!strcasecmp(request_text, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		json_t *list = json_array();
		JANUS_LOG(LOG_VERB, "Request for the list for all text rooms\n");
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_room *room = value;
			if(!room)
				continue;
			janus_refcount_increase(&room->ref);
			janus_mutex_lock(&room->mutex);
			if(room->is_private) {
				/* Skip private room */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				janus_mutex_unlock(&room->mutex);
				janus_refcount_decrease(&room->ref);
				continue;
			}
			json_t *rl = json_object();
			json_object_set_new(rl, "room", json_integer(room->room_id));
			json_object_set_new(rl, "description", json_string(room->room_name));
			json_object_set_new(rl, "pin_required", room->room_pin ? json_true() : json_false());
			/* TODO: Possibly list participant details... or make it a separate API call for a specific room */
			json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
			json_array_append_new(list, rl);
			janus_mutex_unlock(&room->mutex);
			janus_refcount_decrease(&room->ref);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "list", list);
		}
	} else if(!strcasecmp(request_text, "allowed")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit the list of allowed participants in an existing textroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, allowed_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *action = json_object_get(root, "action");
		json_t *room = json_object_get(root, "room");
		json_t *allowed = json_object_get(root, "allowed");
		const char *action_text = json_string_value(action);
		if(strcasecmp(action_text, "enable") && strcasecmp(action_text, "disable") &&
				strcasecmp(action_text, "add") && strcasecmp(action_text, "remove")) {
			JANUS_LOG(LOG_ERR, "Unsupported action '%s' (allowed)\n", action_text);
			error_code = JANUS_TEXTROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Unsupported action '%s' (allowed)", action_text);
			goto msg_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_mutex_lock(&textroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		if(!strcasecmp(action_text, "enable")) {
			JANUS_LOG(LOG_VERB, "Enabling the check on allowed authorization tokens for room %"SCNu64"\n", room_id);
			textroom->check_tokens = TRUE;
		} else if(!strcasecmp(action_text, "disable")) {
			JANUS_LOG(LOG_VERB, "Disabling the check on allowed authorization tokens for room %"SCNu64" (free entry)\n", room_id);
			textroom->check_tokens = FALSE;
		} else {
			gboolean add = !strcasecmp(action_text, "add");
			if(allowed) {
				/* Make sure the "allowed" array only contains strings */
				gboolean ok = TRUE;
				if(json_array_size(allowed) > 0) {
					size_t i = 0;
					for(i=0; i<json_array_size(allowed); i++) {
						json_t *a = json_array_get(allowed, i);
						if(!a || !json_is_string(a)) {
							ok = FALSE;
							break;
						}
					}
				}
				if(!ok) {
					JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
					error_code = JANUS_TEXTROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
					janus_mutex_unlock(&textroom->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto msg_response;
				}
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(add) {
						if(!g_hash_table_lookup(textroom->allowed, token))
							g_hash_table_insert(textroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
					} else {
						g_hash_table_remove(textroom->allowed, token);
					}
				}
			}
		}
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "room", json_integer(textroom->room_id));
			json_t *list = json_array();
			if(strcasecmp(action_text, "disable")) {
				if(g_hash_table_size(textroom->allowed) > 0) {
					GHashTableIter iter;
					gpointer key;
					g_hash_table_iter_init(&iter, textroom->allowed);
					while(g_hash_table_iter_next(&iter, &key, NULL)) {
						char *token = key;
						json_array_append_new(list, json_string(token));
					}
				}
				json_object_set_new(reply, "allowed", list);
			}
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_VERB, "TextRoom room allowed list updated\n");
		}
	} else if(!strcasecmp(request_text, "kick")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick a participant from an existing textroom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, kick_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		json_t *username = json_object_get(root, "username");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_mutex_lock(&textroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		const char *user_id = json_string_value(username);
		janus_textroom_participant *participant = g_hash_table_lookup(textroom->participants, user_id);
		if(participant == NULL) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such participant %s in room %"SCNu64"\n", user_id, room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_USER;
			g_snprintf(error_cause, 512, "No such user %s in room %"SCNu64, user_id, room_id);
			goto msg_response;
		}
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new kick\n");
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("kicked"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			json_object_set_new(event, "username", json_string(participant->username));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
			}
			free(event_text);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "textroom", json_string("kicked"));
			json_object_set_new(info, "room", json_integer(textroom->room_id));
			json_object_set_new(info, "username", json_string(participant->username));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
		/* Remove user from list */
		g_hash_table_remove(participant->session->rooms, &room_id);
		g_hash_table_remove(textroom->participants, participant->username);
		participant->session = NULL;
		participant->room = NULL;
		g_free(participant->username);
		g_free(participant->display);
		g_free(participant);
		/* Done */
		janus_mutex_unlock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textbridge", json_string("success"));
		}
	} else if(!strcasecmp(request_text, "create")) {
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto msg_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
			if(error_code != 0)
				goto msg_response;
		}
		json_t *room = json_object_get(root, "room");
		json_t *desc = json_object_get(root, "description");
		json_t *is_private = json_object_get(root, "is_private");
		json_t *allowed = json_object_get(root, "allowed");
		json_t *secret = json_object_get(root, "secret");
		json_t *pin = json_object_get(root, "pin");
		json_t *post = json_object_get(root, "post");
		json_t *permanent = json_object_get(root, "permanent");
		if(allowed) {
			/* Make sure the "allowed" array only contains strings */
			gboolean ok = TRUE;
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					json_t *a = json_array_get(allowed, i);
					if(!a || !json_is_string(a)) {
						ok = FALSE;
						break;
					}
				}
			}
			if(!ok) {
				JANUS_LOG(LOG_ERR, "Invalid element in the allowed array (not a string)\n");
				error_code = JANUS_TEXTROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
				goto msg_response;
			}
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto msg_response;
		}
		guint64 room_id = 0;
		room_id = json_integer_value(room);
		if(room_id == 0) {
			JANUS_LOG(LOG_WARN, "Desired room ID is 0, which is not allowed... picking random ID instead\n");
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, &room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Room %"SCNu64" already exists!\n", room_id);
				error_code = JANUS_TEXTROOM_ERROR_ROOM_EXISTS;
				g_snprintf(error_cause, 512, "Room %"SCNu64" already exists", room_id);
				goto msg_response;
			}
		}
		/* Create the text room */
		janus_textroom_room *textroom = g_malloc0(sizeof(janus_textroom_room));
		/* Generate a random ID */
		if(room_id == 0) {
			while(room_id == 0) {
				room_id = janus_random_uint64();
				if(g_hash_table_lookup(rooms, &room_id) != NULL) {
					/* Room ID already taken, try another one */
					room_id = 0;
				}
			}
		}
		textroom->room_id = room_id;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %"SCNu64"", textroom->room_id);
			description = g_strdup(roomname);
		}
		textroom->room_name = description;
		textroom->is_private = is_private ? json_is_true(is_private) : FALSE;
		if(secret)
			textroom->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			textroom->room_pin = g_strdup(json_string_value(pin));
		if(post) {
#ifdef HAVE_LIBCURL
			/* FIXME Should we check if this is a valid HTTP address? */
			textroom->http_backend = g_strdup(json_string_value(post));
#else
			JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
		}
		textroom->participants = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_textroom_participant_dereference);
		textroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
		if(allowed != NULL) {
			/* Populate the "allowed" list as an ACL for people trying to join */
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(!g_hash_table_lookup(textroom->allowed, token))
						g_hash_table_insert(textroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
				}
			}
			textroom->check_tokens = TRUE;
		}
		textroom->destroyed = 0;
		janus_mutex_init(&textroom->mutex);
		janus_refcount_init(&textroom->ref, janus_textroom_room_free);
		g_hash_table_insert(rooms, janus_uint64_dup(textroom->room_id), textroom);
		JANUS_LOG(LOG_VERB, "Created textroom: %"SCNu64" (%s, %s, secret: %s, pin: %s)\n",
			textroom->room_id, textroom->room_name,
			textroom->is_private ? "private" : "public",
			textroom->room_secret ? textroom->room_secret : "no secret",
			textroom->room_pin ? textroom->room_pin : "no pin");
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %"SCNu64" permanently in config file\n", textroom->room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, textroom->room_id);
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			/* Now for the values */
			janus_config_add(config, c, janus_config_item_create("description", textroom->room_name));
			if(textroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(textroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", textroom->room_secret));
			if(textroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", textroom->room_pin));
			if(textroom->http_backend)
				janus_config_add(config, c, janus_config_item_create("post", textroom->http_backend));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_TEXTROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_room *tr = value;
			JANUS_LOG(LOG_VERB, "  ::: [%"SCNu64"][%s]\n", tr->room_id, tr->room_name);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "textroom", json_string(json == NULL ? "success" : "created"));
			json_object_set_new(reply, "room", json_integer(textroom->room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "room", json_integer(room_id));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
	} else if(!strcasecmp(request_text, "exists")) {
		JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, &room_id);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "textroom", json_string("success"));
			json_object_set_new(reply, "room", json_integer(room_id));
			json_object_set_new(reply, "exists", room_exists ? json_true() : json_false());
		}
	} else if(!strcasecmp(request_text, "edit")) {
		JANUS_VALIDATE_JSON_OBJECT(root, edit_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		/* We only allow for a limited set of properties to be edited */
		json_t *room = json_object_get(root, "room");
		json_t *desc = json_object_get(root, "new_description");
		json_t *secret = json_object_get(root, "new_secret");
		json_t *is_private = json_object_get(root, "new_is_private");
		json_t *pin = json_object_get(root, "new_pin");
		json_t *post = json_object_get(root, "new_post");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't edit room permanently\n");
			error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't edit room permanently");
			goto msg_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_mutex_lock(&textroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		/* Edit the room properties that were provided */
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			char *old_description = textroom->room_name;
			char *new_description = g_strdup(json_string_value(desc));
			textroom->room_name = new_description;
			g_free(old_description);
		}
		if(is_private)
			textroom->is_private = json_is_true(is_private);
		if(secret && strlen(json_string_value(secret)) > 0) {
			char *old_secret = textroom->room_secret;
			char *new_secret = g_strdup(json_string_value(secret));
			textroom->room_secret = new_secret;
			g_free(old_secret);
		}
		if(post && strlen(json_string_value(post)) > 0) {
			char *old_post = textroom->http_backend;
			char *new_post = g_strdup(json_string_value(post));
			textroom->http_backend = new_post;
			g_free(old_post);
		}
		if(pin && strlen(json_string_value(pin)) > 0) {
			char *old_pin = textroom->room_pin;
			char *new_pin = g_strdup(json_string_value(pin));
			textroom->room_pin = new_pin;
			g_free(old_pin);
		}
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Modifying room %"SCNu64" permanently in config file\n", room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, room_id);
			/* Remove the old category first */
			janus_config_remove(config, NULL, cat);
			/* Now write the room details again */
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			janus_config_add(config, c, janus_config_item_create("description", textroom->room_name));
			if(textroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(textroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", textroom->room_secret));
			if(textroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", textroom->room_pin));
			if(textroom->http_backend)
				janus_config_add(config, c, janus_config_item_create("post", textroom->http_backend));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_TEXTROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room changes are not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		janus_mutex_unlock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "textroom", json_string(json == NULL ? "success" : "edited"));
			json_object_set_new(reply, "room", json_integer(room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("edited"));
			json_object_set_new(info, "room", json_integer(room_id));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
	} else if(!strcasecmp(request_text, "destroy")) {
		JANUS_VALIDATE_JSON_OBJECT(root, destroy_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto msg_response;
		}
		guint64 room_id = json_integer_value(room);
		janus_mutex_lock(&rooms_mutex);
		janus_textroom_room *textroom = g_hash_table_lookup(rooms, &room_id);
		if(textroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%"SCNu64")\n", room_id);
			error_code = JANUS_TEXTROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%"SCNu64")", room_id);
			goto msg_response;
		}
		janus_refcount_increase(&textroom->ref);
		janus_mutex_lock(&textroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(textroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT, JANUS_TEXTROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&textroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			janus_refcount_decrease(&textroom->ref);
			goto msg_response;
		}
		/* Remove room */
		g_hash_table_remove(rooms, &room_id);
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Destroying room %"SCNu64" permanently in config file\n", room_id);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%"SCNu64, room_id);
			janus_config_remove(config, NULL, cat);
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_TEXTROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room destruction is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the destroy\n");
		if(textroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("destroyed"));
			json_object_set_new(event, "room", json_integer(textroom->room_id));
			char *event_text = json_dumps(event, json_format);
			json_decref(event);
			gateway->relay_data(handle, event_text, strlen(event_text));
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, textroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_textroom_participant *top = value;
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %"SCNu64"\n", top->username, room_id);
				gateway->relay_data(top->session->handle, event_text, strlen(event_text));
				janus_mutex_lock(&top->session->mutex);
				g_hash_table_remove(top->session->rooms, &room_id);
				janus_mutex_unlock(&top->session->mutex);
				janus_refcount_decrease(&top->ref);
				janus_textroom_participant_destroy(top);
			}
			free(event_text);
		}
		janus_mutex_unlock(&textroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_refcount_decrease(&textroom->ref);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "textroom", json_string(json == NULL ? "success" : "destroyed"));
			json_object_set_new(reply, "room", json_integer(room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("destroyed"));
			json_object_set_new(info, "room", json_integer(room_id));
			gateway->notify_event(&janus_textroom_plugin, session->handle, info);
		}
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported request %s\n", request_text);
		error_code = JANUS_TEXTROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unsupported request %s", request_text);
		goto msg_response;
	}

msg_response:
		{
			if(!internal) {
				if(error_code == 0 && !reply) {
					error_code = JANUS_TEXTROOM_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Invalid response");
				}
				if(error_code != 0) {
					/* Prepare JSON error event */
					json_t *event = json_object();
					json_object_set_new(event, "textroom", json_string("error"));
					json_object_set_new(event, "error_code", json_integer(error_code));
					json_object_set_new(event, "error", json_string(error_cause));
					reply = event;
				}
				if(transaction_text && json == NULL)
					json_object_set_new(reply, "transaction", json_string(transaction_text));
				if(json == NULL) {
					/* Reply via data channels */
					char *reply_text = json_dumps(reply, json_format);
					json_decref(reply);
					gateway->relay_data(handle, reply_text, strlen(reply_text));
					free(reply_text);
				} else {
					/* Reply via Janus API */
					return janus_plugin_result_new(JANUS_PLUGIN_OK, NULL, reply);
				}
			}
			if(root != NULL)
				json_decref(root);
		}
	return NULL;
}

void janus_textroom_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* We don't do audio/video */
}

void janus_textroom_hangup_media(janus_plugin_session *handle) {
	janus_mutex_lock(&sessions_mutex);
	janus_textroom_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_textroom_hangup_media_internal(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_textroom_session *session = janus_textroom_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Get rid of all participants */
	janus_mutex_lock(&session->mutex);
	GList *list = NULL;
	if(session->rooms) {
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&rooms_mutex);
		g_hash_table_iter_init(&iter, session->rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_textroom_participant *p = value;
			janus_mutex_lock(&p->mutex);
			if(p->room)
				list = g_list_append(list, janus_uint64_dup(p->room->room_id));
			janus_mutex_unlock(&p->mutex);
		}
		janus_mutex_unlock(&rooms_mutex);
	}
	janus_mutex_unlock(&session->mutex);
	JANUS_LOG(LOG_VERB, "Leaving %d rooms\n", g_list_length(list));
	char request[100];
	GList *first = list;
	while(list) {
		guint64 room_id = *((guint64 *)list->data);
		g_snprintf(request, sizeof(request), "{\"textroom\":\"leave\",\"transaction\":\"internal\",\"room\":%"SCNu64"}", room_id);
		janus_textroom_handle_incoming_request(handle, g_strdup(request), NULL, TRUE);
		list = list->next;
	}
	g_list_free_full(first, (GDestroyNotify)g_free);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_textroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining TextRoom handler thread\n");
	janus_textroom_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	gboolean do_offer = FALSE, sdp_update = FALSE;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_textroom_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_textroom_session *session = janus_textroom_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_textroom_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_textroom_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_TEXTROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_TEXTROOM_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_TEXTROOM_ERROR_MISSING_ELEMENT, JANUS_TEXTROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		do_offer = FALSE;
		sdp_update = FALSE;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		do_offer = FALSE;
		if(!strcasecmp(request_text, "setup")) {
			if(!g_atomic_int_compare_and_exchange(&session->setup, 0, 1)) {
				JANUS_LOG(LOG_ERR, "PeerConnection already setup\n");
				error_code = JANUS_TEXTROOM_ERROR_ALREADY_SETUP;
				g_snprintf(error_cause, 512, "PeerConnection already setup");
				goto error;
			}
			do_offer = TRUE;
		} else if(!strcasecmp(request_text, "restart")) {
			if(!g_atomic_int_get(&session->setup)) {
				JANUS_LOG(LOG_ERR, "PeerConnection not setup\n");
				error_code = JANUS_TEXTROOM_ERROR_ALREADY_SETUP;
				g_snprintf(error_cause, 512, "PeerConnection not setup");
				goto error;
			}
			sdp_update = TRUE;
			do_offer = TRUE;
		} else if(!strcasecmp(request_text, "ack")) {
			/* The peer sent their answer back: do nothing */
		} else {
			JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
			error_code = JANUS_TEXTROOM_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "textroom", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		if(!do_offer) {
			int ret = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		} else {
			/* Send an offer (whether it's for an ICE restart or not) */
			if(sdp_update) {
				/* Renegotiation: increase version */
				session->sdp_version++;
			} else {
				/* New session: generate new values */
				session->sdp_version = 1;	/* This needs to be increased when it changes */
				session->sdp_sessid = janus_get_real_time();
			}
			char sdp[500];
			g_snprintf(sdp, sizeof(sdp), sdp_template,
				session->sdp_sessid, session->sdp_version);
			json_t *jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp);
			if(sdp_update)
				json_object_set_new(jsep, "restart", json_true());
			/* How long will the Janus core take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			json_decref(jsep);
		}
		json_decref(event);
		janus_textroom_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "textroom", json_string("error"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_textroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_textroom_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving TextRoom handler thread\n");
	return NULL;
}
