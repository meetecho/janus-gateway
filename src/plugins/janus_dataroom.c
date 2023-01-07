/*! \file   janus_dataroom.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus DataRoom plugin
 * \details Check the \ref dataroom for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page dataroom Janus DataRoom documentation
 * This is a plugin implementing a DataChannel only data room.
 * As such, it does NOT support or negotiate audio or video, but only
 * data channels, in order to provide data broadcasting features. The
 * plugin allows users to join multiple data-only rooms via a single
 * PeerConnection. Users can send data to the room they have joined.
 * This plugin can be
 * used within the condata of any application that needs real-time data
 * broadcasting (e.g., chatrooms, but not only).
 *
 * The only message that is typically sent to the plugin through the Janus API is
 * a "setup" message, by which the user initializes the PeerConnection
 * itself. Apart from that, all other messages can be exchanged directly
 * via Data Channels. For room management purposes, though, requests like
 * "create", "edit", "destroy", "list", "listparticipants" and "exists"
 * are available through the
 * Janus API as well: notice that in this case you'll have to use "request"
 * and not "dataroom" as the name of the request.
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
 * infrastructure than Janus, and yet you also want to have data-based
 * communication (e.g., to add a chatroom to an audio or video conference).
 *
 * Notice that, in general, all users can create rooms. If you want to
 * limit this functionality, you can configure an admin \c admin_key in
 * the plugin settings. When configured, only "create" requests that
 * include the correct \c admin_key value in an "admin_key" property
 * will succeed, and will be rejected otherwise.
 *
 * Rooms to make available at startup are listed in the plugin configuration file.
 * A pre-filled configuration file is provided in \c conf/janus.plugin.dataroom.cfg
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
 * \section dataroomapi Data Room API
 *
 * All DataRoom API requests are addressed by a \c dataroom named property,
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
	"dataroom" : "list",
}
\endverbatim
 *
 * A successful request will produce a list of rooms in a \c success response:
 *
\verbatim
{
	"dataroom" : "success",
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
 * To get a list of the participants in a specific room, instead, you
 * can make use of the \c listparticipants request, which has to be
 * formatted as follows:
 *
\verbatim
{
	"request" : "listparticipants",
	"room" : <unique numeric ID of the room>
}
\endverbatim
 *
 * A successful request will produce a list of participants in a
 * \c participants response:
 *
\verbatim
{
	"room" : <unique numeric ID of the room>,
	"participants" : [		// Array of participant objects
		{	// Participant #1
			"username" : "<username of participant>",
			"display" : "<display name of participant, if any>"
		},
		// Other participants
	]
}
\endverbatim
 *
 * To create new DataRoom rooms you can use the \c create request. The API
 * room creation supports the same fields as creation via configuration files,
 * which means the request must be formatted as follows:
 *
\verbatim
{
	"dataroom" : "create",
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
	"dataroom" : "success",
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
	"dataroom" : "event",
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
	"dataroom" : "edit",
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
	"dataroom" : "edited",
	"room" : <unique numeric ID>,
	"permanent" : <true if changes were saved to config file, false if not>
}
\endverbatim
 *
 * On the other hand, \c destroy can be used to destroy an existing data
 * room, whether created dynamically or statically, and has to be
 * formatted as follows:
 *
\verbatim
{
	"dataroom" : "destroy",
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
	"dataroom" : "destroyed",
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
	"dataroom" : "destroyed",
	"room" : <unique numeric ID of the destroyed room>
}
\endverbatim
 *
 * You can check whether a room exists using the \c exists request,
 * which has to be formatted as follows:
 *
\verbatim
{
	"dataroom" : "exists",
	"room" : <unique numeric ID of the room to check; mandatory>
}
\endverbatim
 *
 * A successful request will result in a \c success response:
 *
\verbatim
{
	"dataroom" : "success",
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
	"dataroom" : "allowed",
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
	"dataroom" : "success",
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
	"dataroom" : "kick",
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
	"dataroom" : "success",
}
\endverbatim
 *
 * This will also result in a \c kicked event being sent to all the other
 * participants in the room, which will look like this:
 *
\verbatim
{
	"dataroom" : "kicked",
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
	"dataroom" : "join",
	"room" : <unique numeric ID of the room to join>,
	"pin" : "<pin to join the room; mandatory if configured>",
	"username" : "<unique username to have in the room; mandatory>",
	"display" : "<display name to use in the room; optional>",
	"token" : "<invitation token, in case the room has an ACL; optional>",
}
\endverbatim
 *
 * A successful join will result in a \c success response, which will
 * include a list of all the other participants currently in the room:
 *
\verbatim
{
	"dataroom" : "success",
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
	"dataroom" : "join",
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
	"dataroom" : "leave",
	"room" : <unique numeric ID of the room to leave>
}
\endverbatim
 *
 * A successful leave will result in a \c success response:
 *
\verbatim
{
	"dataroom" : "success"
}
\endverbatim
 *
 * Notice that a successful \c leave request will also result in a
 * \c leave event being sent to all the other participants, so that
 * they're notified about the participant that just left the room:
 *
\verbatim
{
	"dataroom" : "leave",
	"room" : <room ID>,
	"username" : "<username of gone participant>"
}
\endverbatim
 *
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
#define JANUS_DATAROOM_VERSION			1
#define JANUS_DATAROOM_VERSION_STRING	"0.0.1"
#define JANUS_DATAROOM_DESCRIPTION		"This is a plugin implementing a data-only room for Janus, using DataChannels."
#define JANUS_DATAROOM_NAME				"JANUS DataRoom plugin"
#define JANUS_DATAROOM_AUTHOR			"Meetecho s.r.l."
#define JANUS_DATAROOM_PACKAGE			"janus.plugin.dataroom"

/* Plugin methods */
janus_plugin *create(void);
int janus_dataroom_init(janus_callbacks *callback, const char *config_path);
void janus_dataroom_destroy(void);
int janus_dataroom_get_api_compatibility(void);
int janus_dataroom_get_version(void);
const char *janus_dataroom_get_version_string(void);
const char *janus_dataroom_get_description(void);
const char *janus_dataroom_get_name(void);
const char *janus_dataroom_get_author(void);
const char *janus_dataroom_get_package(void);
void janus_dataroom_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_dataroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
json_t *janus_dataroom_handle_admin_message(json_t *message);
void janus_dataroom_setup_media(janus_plugin_session *handle);
void janus_dataroom_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet);
void janus_dataroom_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet);
void janus_dataroom_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet);
void janus_dataroom_data_ready(janus_plugin_session *handle);
void janus_dataroom_slow_link(janus_plugin_session *handle, int mindex, int uplink, int video);
void janus_dataroom_hangup_media(janus_plugin_session *handle);
void janus_dataroom_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_dataroom_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_dataroom_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_dataroom_init,
		.destroy = janus_dataroom_destroy,

		.get_api_compatibility = janus_dataroom_get_api_compatibility,
		.get_version = janus_dataroom_get_version,
		.get_version_string = janus_dataroom_get_version_string,
		.get_description = janus_dataroom_get_description,
		.get_name = janus_dataroom_get_name,
		.get_author = janus_dataroom_get_author,
		.get_package = janus_dataroom_get_package,

		.create_session = janus_dataroom_create_session,
		.handle_message = janus_dataroom_handle_message,
		.handle_admin_message = janus_dataroom_handle_admin_message,
		.setup_media = janus_dataroom_setup_media,
		.incoming_rtp = janus_dataroom_incoming_rtp,
		.incoming_rtcp = janus_dataroom_incoming_rtcp,
		.incoming_data = janus_dataroom_incoming_data,
		.data_ready = janus_dataroom_data_ready,
		.slow_link = janus_dataroom_slow_link,
		.hangup_media = janus_dataroom_hangup_media,
		.destroy_session = janus_dataroom_destroy_session,
		.query_session = janus_dataroom_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_DATAROOM_NAME);
	return &janus_dataroom_plugin;
}


/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter transaction_parameters[] = {
	{"dataroom", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"transaction", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter room_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter roomopt_parameters[] = {
	{"room", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter roomstr_parameters[] = {
	{"room", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter roomstropt_parameters[] = {
	{"room", JSON_STRING, 0}
};
static struct janus_json_parameter adminkey_parameters[] = {
	{"admin_key", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter create_parameters[] = {
	{"description", JSON_STRING, 0},
	{"secret", JSON_STRING, 0},
	{"pin", JSON_STRING, 0},
	{"post", JSON_STRING, 0},
	{"is_private", JANUS_JSON_BOOL, 0},
	{"allowed", JSON_ARRAY, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter destroy_parameters[] = {
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter edit_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"new_description", JSON_STRING, 0},
	{"new_secret", JSON_STRING, 0},
	{"new_pin", JSON_STRING, 0},
	{"new_post", JSON_STRING, 0},
	{"new_is_private", JANUS_JSON_BOOL, 0},
	{"permanent", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter allowed_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"action", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"allowed", JSON_ARRAY, 0}
};
static struct janus_json_parameter kick_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter delegate_parameters[] = {
	{"secret", JSON_STRING, 0},
	{"room", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"host", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter join_parameters[] = {
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"pin", JSON_STRING, 0},
	{"token", JSON_STRING, 0},
	{"display", JSON_STRING, 0}
};

/* Static configuration instance */
static janus_config *config = NULL;
static const char *config_folder = NULL;
static janus_mutex config_mutex = JANUS_MUTEX_INITIALIZER;

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static gboolean string_ids = FALSE;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static void *janus_dataroom_handler(void *data);
static void janus_dataroom_hangup_media_internal(janus_plugin_session *handle);

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;


typedef struct janus_dataroom_room {
	guint64 room_id;			/* Unique room ID (when using integers) */
	gchar *room_id_str;			/* Unique room ID (when using strings) */
	gchar *room_name;			/* Room description */
	gchar *room_secret;			/* Secret needed to manipulate (e.g., destroy) this room */
	gchar *room_pin;			/* Password needed to join this room, if any */
	gboolean is_private;		/* Whether this room is 'private' (as in hidden) or not */
	gchar *http_backend;		/* Server to contact via HTTP POST for incoming messages, if any */
	GHashTable *participants;	/* Map of participants */
	gchar *host;			/* Room host */
	gboolean check_tokens;		/* Whether to check tokens when participants join (see below) */
	GHashTable *allowed;		/* Map of participants (as tokens) allowed to join */
	volatile gint destroyed;	/* Whether this room has been destroyed */
	janus_mutex mutex;			/* Mutex to lock this room instance */
	janus_refcount ref;
} janus_dataroom_room;
static GHashTable *rooms = NULL;
static janus_mutex rooms_mutex = JANUS_MUTEX_INITIALIZER;
static char *admin_key = NULL;

typedef struct janus_dataroom_session {
	janus_plugin_session *handle;
	gint64 sdp_sessid;
	gint64 sdp_version;
	GHashTable *rooms;			/* Map of rooms this user is in, and related participant instance */
	janus_mutex mutex;			/* Mutex to lock this session */
	volatile gint setup;
	volatile gint dataready;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
} janus_dataroom_session;
static GHashTable *sessions;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

typedef struct janus_dataroom_participant {
	janus_dataroom_session *session;
	janus_dataroom_room *room;	/* Room this participant is in */
	gchar *username;			/* Unique username in the room */
	gchar *display;				/* Display name in the room, if any */
	janus_mutex mutex;			/* Mutex to lock this session */
	volatile gint destroyed;	/* Whether this participant has been destroyed */
	janus_refcount ref;
} janus_dataroom_participant;

static void janus_dataroom_room_destroy(janus_dataroom_room *dataroom) {
	if(dataroom && g_atomic_int_compare_and_exchange(&dataroom->destroyed, 0, 1))
		janus_refcount_decrease(&dataroom->ref);
}
static void janus_dataroom_room_free(const janus_refcount *dataroom_ref) {
	janus_dataroom_room *dataroom = janus_refcount_containerof(dataroom_ref, janus_dataroom_room, ref);
	/* This room can be destroyed, free all the resources */
	g_free(dataroom->room_id_str);
	g_free(dataroom->room_name);
	g_free(dataroom->room_secret);
	g_free(dataroom->room_pin);
	g_free(dataroom->http_backend);
	g_hash_table_destroy(dataroom->participants);
	g_free(dataroom->host);
	g_hash_table_destroy(dataroom->allowed);
	g_free(dataroom);
}

static void janus_dataroom_session_destroy(janus_dataroom_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}
static void janus_dataroom_session_free(const janus_refcount *session_ref) {
	janus_dataroom_session *session = janus_refcount_containerof(session_ref, janus_dataroom_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	g_hash_table_destroy(session->rooms);
	g_free(session);
}

static void janus_dataroom_participant_dereference(janus_dataroom_participant *p) {
	if(p)
		janus_refcount_decrease(&p->ref);
}

static void janus_dataroom_participant_destroy(janus_dataroom_participant *participant) {
	if(participant && g_atomic_int_compare_and_exchange(&participant->destroyed, 0, 1))
		janus_refcount_decrease(&participant->ref);
}
static void janus_dataroom_participant_free(const janus_refcount *participant_ref) {
	janus_dataroom_participant *participant = janus_refcount_containerof(participant_ref, janus_dataroom_participant, ref);
	/* This participant can be destroyed, free all the resources */
	g_free(participant->username);
	g_free(participant->display);
	g_free(participant);
}


typedef struct janus_dataroom_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_dataroom_message;
static GAsyncQueue *messages = NULL;
static janus_dataroom_message exit_message;

static void janus_dataroom_message_free(janus_dataroom_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_dataroom_session *session = (janus_dataroom_session *)msg->handle->plugin_handle;
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
		"s=Janus DataRoom plugin\r\n" \
		"t=0 0\r\n" \
		"m=application 1 UDP/DTLS/SCTP webrtc-datachannel\r\n" \
		"c=IN IP4 1.1.1.1\r\n" \
		"a=sctp-port:5000\r\n"


/* Error codes */
#define JANUS_DATAROOM_ERROR_NO_MESSAGE				411
#define JANUS_DATAROOM_ERROR_INVALID_JSON			412
#define JANUS_DATAROOM_ERROR_MISSING_ELEMENT		413
#define JANUS_DATAROOM_ERROR_INVALID_ELEMENT		414
#define JANUS_DATAROOM_ERROR_INVALID_REQUEST		415
#define JANUS_DATAROOM_ERROR_ALREADY_SETUP			416
#define JANUS_DATAROOM_ERROR_NO_SUCH_ROOM			417
#define JANUS_DATAROOM_ERROR_ROOM_EXISTS			418
#define JANUS_DATAROOM_ERROR_UNAUTHORIZED			419
#define JANUS_DATAROOM_ERROR_USERNAME_EXISTS		420
#define JANUS_DATAROOM_ERROR_ALREADY_IN_ROOM		421
#define JANUS_DATAROOM_ERROR_NOT_IN_ROOM			422
#define JANUS_DATAROOM_ERROR_NO_SUCH_USER			423
#define JANUS_DATAROOM_ERROR_NO_SUCH_USER_IN_ROOM	424
#define JANUS_DATAROOM_ERROR_ALREADY_HOST			425
#define JANUS_DATAROOM_ERROR_NOT_HOST				426

#define JANUS_DATAROOM_ERROR_UNKNOWN_ERROR			499

#ifdef HAVE_LIBCURL
static size_t janus_dataroom_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
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
janus_plugin_result *janus_dataroom_handle_incoming_request(janus_plugin_session *handle,
	char *data, json_t *json, gboolean internal);


/* Plugin implementation */
int janus_dataroom_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

#ifndef HAVE_SCTP
	/* Data channels not supported, no point loading this plugin */
	JANUS_LOG(LOG_WARN, "Data channels support not compiled, disabling DataRoom plugin\n");
	return -1;
#endif

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_DATAROOM_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_DATAROOM_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_DATAROOM_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	config_folder = config_path;
	if(config != NULL)
		janus_config_print(config);
	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_dataroom_session_destroy);
	messages = g_async_queue_new_full((GDestroyNotify) janus_dataroom_message_free);
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
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_DATAROOM_NAME);
		}
		janus_config_item *ids = janus_config_get(config, config_general, janus_config_type_item, "string_ids");
		if(ids != NULL && ids->value != NULL)
			string_ids = janus_is_true(ids->value);
		if(string_ids) {
			JANUS_LOG(LOG_INFO, "DataRoom will use alphanumeric IDs, not numeric\n");
		}
	}
	/* Iterate on all rooms */
	rooms = g_hash_table_new_full(string_ids ? g_str_hash : g_int64_hash, string_ids ? g_str_equal : g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_dataroom_room_destroy);
	if(config != NULL) {
		GList *clist = janus_config_get_categories(config, NULL), *cl = clist;
		while(cl != NULL) {
			janus_config_category *cat = (janus_config_category *)cl->data;
			if(cat->name == NULL || !strcasecmp(cat->name, "general")) {
				cl = cl->next;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Adding DataRoom room '%s'\n", cat->name);
			janus_config_item *desc = janus_config_get(config, cat, janus_config_type_item, "description");
			janus_config_item *priv = janus_config_get(config, cat, janus_config_type_item, "is_private");
			janus_config_item *secret = janus_config_get(config, cat, janus_config_type_item, "secret");
			janus_config_item *pin = janus_config_get(config, cat, janus_config_type_item, "pin");
			janus_config_item *post = janus_config_get(config, cat, janus_config_type_item, "post");
			/* Create the data room */
			janus_dataroom_room *dataroom = g_malloc0(sizeof(janus_dataroom_room));
			const char *room_num = cat->name;
			if(strstr(room_num, "room-") == room_num)
				room_num += 5;
			if(!string_ids) {
				dataroom->room_id = g_ascii_strtoull(room_num, NULL, 0);
				if(dataroom->room_id == 0) {
					JANUS_LOG(LOG_ERR, "Can't add the DataRoom room, invalid ID 0...\n");
					g_free(dataroom);
					cl = cl->next;
					continue;
				}
				/* Make sure the ID is completely numeric */
				char room_id_str[30];
				g_snprintf(room_id_str, sizeof(room_id_str), "%"SCNu64, dataroom->room_id);
				if(strcmp(room_num, room_id_str)) {
					JANUS_LOG(LOG_ERR, "Can't add the DataRoom room, ID '%s' is not numeric...\n", room_num);
					g_free(dataroom);
					cl = cl->next;
					continue;
				}
			}
			/* Let's make sure the room doesn't exist already */
			janus_mutex_lock(&rooms_mutex);
			if(g_hash_table_lookup(rooms, string_ids ? (gpointer)room_num : (gpointer)&dataroom->room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Can't add the DataRoom room, room %s already exists...\n", room_num);
				g_free(dataroom);
				cl = cl->next;
				continue;
			}
			janus_mutex_unlock(&rooms_mutex);
			dataroom->room_id_str = g_strdup(room_num);
			char *description = NULL;
			if(desc != NULL && desc->value != NULL && strlen(desc->value) > 0)
				description = g_strdup(desc->value);
			else
				description = g_strdup(cat->name);
			dataroom->room_name = description;
			dataroom->is_private = priv && priv->value && janus_is_true(priv->value);
			if(secret != NULL && secret->value != NULL) {
				dataroom->room_secret = g_strdup(secret->value);
			}
			if(pin != NULL && pin->value != NULL) {
				dataroom->room_pin = g_strdup(pin->value);
			}
			if(post != NULL && post->value != NULL) {
#ifdef HAVE_LIBCURL
				/* FIXME Should we check if this is a valid HTTP address? */
				dataroom->http_backend = g_strdup(post->value);
#else
				JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
			}
			dataroom->participants = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_dataroom_participant_dereference);
			dataroom->host = g_strdup("");
			dataroom->check_tokens = FALSE;	/* Static rooms can't have an "allowed" list yet, no hooks to the configuration file */
			dataroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
			dataroom->destroyed = 0;
			janus_mutex_init(&dataroom->mutex);
			janus_refcount_init(&dataroom->ref, janus_dataroom_room_free);
			JANUS_LOG(LOG_VERB, "Created DataRoom: %s (%s, %s, secret: %s, pin: %s)\n",
				dataroom->room_id_str, dataroom->room_name,
				dataroom->is_private ? "private" : "public",
				dataroom->room_secret ? dataroom->room_secret : "no secret",
				dataroom->room_pin ? dataroom->room_pin : "no pin");
			g_hash_table_insert(rooms,
				string_ids ? (gpointer)g_strdup(dataroom->room_id_str) : (gpointer)janus_uint64_dup(dataroom->room_id),
				dataroom);
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
		janus_dataroom_room *tr = value;
		JANUS_LOG(LOG_VERB, "  ::: [%s][%s]\n", tr->room_id_str, tr->room_name);
	}
	janus_mutex_unlock(&rooms_mutex);

#ifdef HAVE_LIBCURL
	curl_global_init(CURL_GLOBAL_ALL);
#endif

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("dataroom handler", janus_dataroom_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the DataRoom handler thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_DATAROOM_NAME);
	return 0;
}

void janus_dataroom_destroy(void) {
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
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_DATAROOM_NAME);
}

int janus_dataroom_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_dataroom_get_version(void) {
	return JANUS_DATAROOM_VERSION;
}

const char *janus_dataroom_get_version_string(void) {
	return JANUS_DATAROOM_VERSION_STRING;
}

const char *janus_dataroom_get_description(void) {
	return JANUS_DATAROOM_DESCRIPTION;
}

const char *janus_dataroom_get_name(void) {
	return JANUS_DATAROOM_NAME;
}

const char *janus_dataroom_get_author(void) {
	return JANUS_DATAROOM_AUTHOR;
}

const char *janus_dataroom_get_package(void) {
	return JANUS_DATAROOM_PACKAGE;
}

static janus_dataroom_session *janus_dataroom_lookup_session(janus_plugin_session *handle) {
	janus_dataroom_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_dataroom_session *)handle->plugin_handle;
	}
	return session;
}

void janus_dataroom_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_dataroom_session *session = g_malloc0(sizeof(janus_dataroom_session));
	session->handle = handle;
	session->rooms = g_hash_table_new_full(string_ids ? g_str_hash : g_int64_hash, string_ids ? g_str_equal : g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_dataroom_participant_dereference);
	session->destroyed = 0;
	janus_mutex_init(&session->mutex);
	janus_refcount_init(&session->ref, janus_dataroom_session_free);
	g_atomic_int_set(&session->setup, 0);
	g_atomic_int_set(&session->dataready, 0);
	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_dataroom_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing DataRoom session...\n");
	janus_dataroom_hangup_media_internal(handle);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

json_t *janus_dataroom_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
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

struct janus_plugin_result *janus_dataroom_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	/* Pre-parse the message */
	int error_code = 0;
	char error_cause[512];
	json_t *root = message;
	json_t *response = NULL;

	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "No session associated with this handle...");
		goto plugin_response;
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	if(g_atomic_int_get(&session->destroyed)) {
		JANUS_LOG(LOG_ERR, "Session has already been destroyed...\n");
		error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
		g_snprintf(error_cause, 512, "%s", "Session has already been destroyed...");
		goto plugin_response;
	}

	if(message == NULL) {
		JANUS_LOG(LOG_ERR, "No message??\n");
		error_code = JANUS_DATAROOM_ERROR_NO_MESSAGE;
		g_snprintf(error_cause, 512, "%s", "No message??");
		goto plugin_response;
	}
	if(!json_is_object(root)) {
		JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
		error_code = JANUS_DATAROOM_ERROR_INVALID_JSON;
		g_snprintf(error_cause, 512, "JSON error: not an object");
		goto plugin_response;
	}
	/* Get the request first */
	JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	json_t *request = json_object_get(root, "request");
	/* Some requests (e.g., 'create' and 'destroy') can be handled synchronously */
	const char *request_data = json_string_value(request);
	if(!strcasecmp(request_data, "list")
			|| !strcasecmp(request_data, "listparticipants")
			|| !strcasecmp(request_data, "exists")
			|| !strcasecmp(request_data, "create")
			|| !strcasecmp(request_data, "edit")
			|| !strcasecmp(request_data, "allowed")
			|| !strcasecmp(request_data, "kick")
			|| !strcasecmp(request_data, "delegate")
			|| !strcasecmp(request_data, "destroy")
			|| !strcasecmp(request_data, "join")
			|| !strcasecmp(request_data, "leave")) {
		/* These requests typically only belong to the datachannel
		 * messaging, but for admin purposes we might use them on
		 * the Janus API as well: add the properties the datachannel
		 * processor would expect and handle everything there */
		if(json_object_get(root, "dataroom") == NULL)
			json_object_set_new(root, "dataroom", json_string(request_data));
		json_object_set_new(root, "transaction", json_string(transaction));
		janus_plugin_result *result = janus_dataroom_handle_incoming_request(session->handle, NULL, root, FALSE);
		if(result == NULL) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_DATAROOM_ERROR_INVALID_JSON;
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
	} else if(!strcasecmp(request_data, "setup") || !strcasecmp(request_data, "ack") || !strcasecmp(request_data, "restart")) {
		/* These messages are handled asynchronously */
		janus_dataroom_message *msg = g_malloc(sizeof(janus_dataroom_message));
		msg->handle = handle;
		msg->transaction = transaction;
		msg->message = root;
		msg->jsep = jsep;

		g_async_queue_push(messages, msg);

		return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_data);
		error_code = JANUS_DATAROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_data);
	}

plugin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "dataroom", json_string("event"));
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

json_t *janus_dataroom_handle_admin_message(json_t *message) {
	/* Some requests (e.g., 'create' and 'destroy') can be handled via Admin API */
	int error_code = 0;
	char error_cause[512];
	json_t *response = NULL;

	JANUS_VALIDATE_JSON_OBJECT(message, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto admin_response;
	json_t *request = json_object_get(message, "request");
	const char *request_data = json_string_value(request);
	if(!strcasecmp(request_data, "list")
			|| !strcasecmp(request_data, "listparticipants")
			|| !strcasecmp(request_data, "exists")
			|| !strcasecmp(request_data, "create")
			|| !strcasecmp(request_data, "edit")
			|| !strcasecmp(request_data, "allowed")
			|| !strcasecmp(request_data, "kick")
			|| !strcasecmp(request_data, "delegate")
			|| !strcasecmp(request_data, "destroy")) {
		if(json_object_get(message, "dataroom") == NULL)
			json_object_set_new(message, "dataroom", json_string(request_data));
		janus_plugin_result *result = janus_dataroom_handle_incoming_request(NULL, NULL, message, FALSE);
		if(result == NULL) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_DATAROOM_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto admin_response;
		}
		response = result->content;
		result->content = NULL;
		janus_plugin_result_destroy(result);
		goto admin_response;
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_data);
		error_code = JANUS_DATAROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_data);
	}

admin_response:
		{
			if(!response) {
				/* Prepare JSON error event */
				response = json_object();
				json_object_set_new(response, "dataroom", json_string("event"));
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}

}

void janus_dataroom_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_DATAROOM_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
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

void janus_dataroom_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {
	/* We don't do audio/video */
}

void janus_dataroom_incoming_rtcp(janus_plugin_session *handle, janus_plugin_rtcp *packet) {
	/* We don't do audio/video */
}

/////// Change to just broadcast packet
void janus_dataroom_incoming_data(janus_plugin_session *handle, janus_plugin_data *packet) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;

	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "Session destroyed\n");
		return;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);

	GHashTableIter iter;
	gpointer value;
	gpointer key;
	janus_mutex_lock(&session->mutex);
	janus_mutex_lock(&rooms_mutex);
	g_hash_table_iter_init(&iter, session->rooms);
	while(g_hash_table_iter_next(&iter, &key, &value)) {
		gchar *room_id = (gchar *)key;

		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms, room_id);
		if(dataroom == NULL)
		{
			JANUS_LOG(LOG_ERR, "room_id %s didn't map to a room\n", room_id);
			continue;
		}
		/* Send the announcement to everybody in the room */
		if(dataroom->participants) {
			GHashTableIter iter_participants;
			gpointer value_participants;
			g_hash_table_iter_init(&iter_participants, dataroom->participants);
			while(g_hash_table_iter_next(&iter_participants, NULL, &value_participants)) {
				janus_dataroom_participant *top = value_participants;
				/* Don't send messages to origin */
				if(top->session == session) continue;
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, dataroom->room_id_str);
				janus_refcount_increase(&top->ref);
				janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = packet->binary,
						.buffer = packet->buffer, .length = packet->length };
				gateway->relay_data(top->session->handle, &data);
				janus_refcount_decrease(&top->ref);
			}
		}
	}
	janus_mutex_unlock(&rooms_mutex);
	janus_refcount_decrease(&session->ref);
	janus_mutex_unlock(&session->mutex);

	return;	
}

void janus_dataroom_data_ready(janus_plugin_session *handle) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) ||
			g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || !gateway)
		return;
	/* Data channels are writable: we shouldn't send anything before this happens */
	janus_dataroom_session *session = (janus_dataroom_session *)handle->plugin_handle;
	if(!session || g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->hangingup))
		return;
	if(g_atomic_int_compare_and_exchange(&session->dataready, 0, 1)) {
		JANUS_LOG(LOG_INFO, "[%s-%p] Data channel available\n", JANUS_DATAROOM_PACKAGE, handle);
	}
}

/* Helper method to handle incoming messages from the data channel */
janus_plugin_result *janus_dataroom_handle_incoming_request(janus_plugin_session *handle, char *data, json_t *json, gboolean internal) {
	janus_dataroom_session *session = NULL;
	if(handle)
		session = (janus_dataroom_session *)handle->plugin_handle;
	/* Parse JSON, if needed */
	json_error_t error;
	json_t *root = data ? json_loads(data, 0, &error) : json;
	g_free(data);
	if(!root) {
		JANUS_LOG(LOG_ERR, "Error parsing data channel message (JSON error: on line %d: %s)\n", error.line, error.text);
		return NULL;
	}
	/* Handle request */
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(root, transaction_parameters,
		error_code, error_cause, TRUE,
		JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
	const char *transaction_data = NULL;
	json_t *reply = NULL;
	if(error_code != 0)
		goto msg_response;
	json_t *request = json_object_get(root, "dataroom");
	json_t *transaction = json_object_get(root, "transaction");
	const char *request_data = json_string_value(request);
	transaction_data = json_string_value(transaction);
    if(!strcasecmp(request_data, "join")) {
		JANUS_VALIDATE_JSON_OBJECT(root, join_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_refcount_increase(&dataroom->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&dataroom->mutex);
		/* A PIN may be required for this action */
		JANUS_CHECK_SECRET(dataroom->room_pin, root, "pin", error_code, error_cause,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_refcount_decrease(&dataroom->ref);
			goto msg_response;
		}
		janus_mutex_lock(&session->mutex);
		if(g_hash_table_lookup(session->rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id) != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&dataroom->mutex);
			janus_refcount_decrease(&dataroom->ref);
			JANUS_LOG(LOG_ERR, "Already in room %s\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_ALREADY_IN_ROOM;
			g_snprintf(error_cause, 512, "Already in room %s", room_id_str);
			goto msg_response;
		}
		json_t *username = json_object_get(root, "username");
		const char *username_data = json_string_value(username);
		janus_dataroom_participant *participant = g_hash_table_lookup(dataroom->participants, username_data);
		if(participant != NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&dataroom->mutex);
			janus_refcount_decrease(&dataroom->ref);
			JANUS_LOG(LOG_ERR, "Username already taken\n");
			error_code = JANUS_DATAROOM_ERROR_USERNAME_EXISTS;
			g_snprintf(error_cause, 512, "Username already taken");
			goto msg_response;
		}
		/* A token might be required too */
		if(dataroom->check_tokens) {
			json_t *token = json_object_get(root, "token");
			const char *token_data = token ? json_string_value(token) : NULL;
			if(token_data == NULL || g_hash_table_lookup(dataroom->allowed, token_data) == NULL) {
				janus_mutex_unlock(&session->mutex);
				janus_mutex_unlock(&dataroom->mutex);
				janus_refcount_decrease(&dataroom->ref);
				JANUS_LOG(LOG_ERR, "Unauthorized (not in the allowed list)\n");
				error_code = JANUS_DATAROOM_ERROR_UNAUTHORIZED;
				g_snprintf(error_cause, 512, "Unauthorized (not in the allowed list)");
				goto msg_response;
			}
		}
		json_t *display = json_object_get(root, "display");
		const char *display_data = json_string_value(display);
		/* Create a participant instance */
		participant = g_malloc(sizeof(janus_dataroom_participant));
		participant->session = session;
		participant->room = dataroom;
		participant->username = g_strdup(username_data);
		participant->display = display_data ? g_strdup(display_data) : NULL;
		participant->destroyed = 0;
		/* If there's currently no host, use this user */
		if(!strlen(dataroom->host))
		{
			free(dataroom->host);
			dataroom->host = strdup(username_data);
		}
		janus_mutex_init(&participant->mutex);
		janus_refcount_init(&participant->ref, janus_dataroom_participant_free);
		janus_refcount_increase(&participant->ref);
		g_hash_table_insert(session->rooms,
			string_ids ? (gpointer)g_strdup(dataroom->room_id_str) : (gpointer)janus_uint64_dup(dataroom->room_id),
			participant);
		janus_refcount_increase(&participant->ref);
		g_hash_table_insert(dataroom->participants, participant->username, participant);
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new join\n");
		json_t *list = json_array();
		if(dataroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("join"));
			json_object_set_new(event, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(event, "username", json_string(username_data));
			if(display_data != NULL)
				json_object_set_new(event, "display", json_string(display_data));
			char *event_data = json_dumps(event, json_format);
			json_decref(event);
			if(event_data == NULL) {
				janus_mutex_unlock(&session->mutex);
				janus_mutex_unlock(&dataroom->mutex);
				janus_refcount_decrease(&dataroom->ref);
				JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
				error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Failed to stringify message");
				goto msg_response;
			}
			janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = event_data, .length = strlen(event_data) };
			gateway->relay_data(handle, &data);
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, dataroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_dataroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, room_id_str);
				gateway->relay_data(top->session->handle, &data);
				/* Take note of this user */
				json_t *p = json_object();
				json_object_set_new(p, "username", json_string(top->username));
				if(top->display != NULL)
					json_object_set_new(p, "display", json_string(top->display));
				json_array_append_new(list, p);
				janus_refcount_decrease(&top->ref);
			}
			free(event_data);
		}
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&dataroom->mutex);
		janus_refcount_decrease(&dataroom->ref);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "dataroom", json_string("success"));
			json_object_set_new(reply, "participants", list);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("join"));
			json_object_set_new(info, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(info, "username", json_string(username_data));
			if(display_data)
				json_object_set_new(info, "display", json_string(display_data));
			gateway->notify_event(&janus_dataroom_plugin, session->handle, info);
		}
	} else if(!strcasecmp(request_data, "leave")) {
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_refcount_increase(&dataroom->ref);
		janus_mutex_unlock(&rooms_mutex);
		janus_mutex_lock(&dataroom->mutex);
		janus_mutex_lock(&session->mutex);
		janus_dataroom_participant *participant = g_hash_table_lookup(session->rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&session->mutex);
			janus_mutex_unlock(&dataroom->mutex);
			janus_refcount_decrease(&dataroom->ref);
			JANUS_LOG(LOG_ERR, "Not in room %s\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %s", room_id_str);
			goto msg_response;
		}
		janus_refcount_increase(&participant->ref);
		g_hash_table_remove(session->rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		g_hash_table_remove(dataroom->participants, participant->username);
		/* If was host, clear, and find another one if possible */
		if(!strcmp(dataroom->host, participant->username))
		{
			free(dataroom->host);
			dataroom->host = strdup("");
		}
		participant->session = NULL;
		participant->room = NULL;
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new leave\n");
		if(dataroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("leave"));
			json_object_set_new(event, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(event, "username", json_string(participant->username));
			char *event_data = json_dumps(event, json_format);
			json_decref(event);
			if(event_data == NULL) {
				janus_mutex_unlock(&session->mutex);
				janus_mutex_unlock(&dataroom->mutex);
				janus_refcount_decrease(&dataroom->ref);
				janus_refcount_decrease(&participant->ref);
				janus_dataroom_participant_destroy(participant);
				JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
				error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Failed to stringify message");
				goto msg_response;
			}
			janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = event_data, .length = strlen(event_data) };
			gateway->relay_data(handle, &data);
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, dataroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_dataroom_participant *top = value;
				if(top == participant)
					continue;	/* Skip us */
				if(!strlen(dataroom->host))
				{
					free(dataroom->host);
					dataroom->host = strdup(top->username);
				}
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, room_id_str);
				gateway->relay_data(top->session->handle, &data);
				janus_refcount_decrease(&top->ref);
			}
			free(event_data);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("leave"));
			json_object_set_new(info, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(info, "username", json_string(participant->username));
			gateway->notify_event(&janus_dataroom_plugin, session->handle, info);
		}
		janus_mutex_unlock(&session->mutex);
		janus_mutex_unlock(&dataroom->mutex);
		janus_refcount_decrease(&dataroom->ref);
		janus_refcount_decrease(&participant->ref);
		janus_dataroom_participant_destroy(participant);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "dataroom", json_string("success"));
		}
	} else if(!strcasecmp(request_data, "list")) {
		/* List all rooms (but private ones) and their details (except for the secret, of course...) */
		JANUS_LOG(LOG_VERB, "Request for the list for all data rooms\n");
		gboolean lock_room_list = TRUE;
		if(admin_key != NULL) {
			json_t *admin_key_json = json_object_get(root, "admin_key");
			/* Verify admin_key if it was provided */
			if(admin_key_json != NULL && json_is_string(admin_key_json) && strlen(json_string_value(admin_key_json)) > 0) {
				JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
					JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
				if(error_code != 0) {
					goto msg_response;
				} else {
					lock_room_list = FALSE;
				}
			}
		}
		json_t *list = json_array();
		janus_mutex_lock(&rooms_mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_dataroom_room *room = value;
			if(!room)
				continue;
			janus_refcount_increase(&room->ref);
			janus_mutex_lock(&room->mutex);
			if(room->is_private && lock_room_list) {
				/* Skip private room if no valid admin_key was provided */
				JANUS_LOG(LOG_VERB, "Skipping private room '%s'\n", room->room_name);
				janus_mutex_unlock(&room->mutex);
				janus_refcount_decrease(&room->ref);
				continue;
			}
			json_t *rl = json_object();
			json_object_set_new(rl, "room", string_ids ? json_string(room->room_id_str) : json_integer(room->room_id));
			json_object_set_new(rl, "description", json_string(room->room_name));
			json_object_set_new(rl, "pin_required", room->room_pin ? json_true() : json_false());
			json_object_set_new(rl, "num_participants", json_integer(g_hash_table_size(room->participants)));
			json_array_append_new(list, rl);
			janus_mutex_unlock(&room->mutex);
			janus_refcount_decrease(&room->ref);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "dataroom", json_string("success"));
			json_object_set_new(reply, "list", list);
		}
	} else if(!strcasecmp(request_data, "listparticipants")) {
		/* List all participants in a room */
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL || g_atomic_int_get(&dataroom->destroyed)) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_refcount_increase(&dataroom->ref);
		/* Return a list of all participants */
		json_t *list = json_array();
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, dataroom->participants);
		while (!g_atomic_int_get(&dataroom->destroyed) && g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_dataroom_participant *p = value;
			json_t *pl = json_object();
			json_object_set_new(pl, "username", json_string(p->username));
			if(p->display != NULL)
				json_object_set_new(pl, "display", json_string(p->display));
			json_array_append_new(list, pl);
		}
		janus_refcount_decrease(&dataroom->ref);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(reply, "host", json_string(dataroom->host));
			json_object_set_new(reply, "participants", list);
		}
	} else if(!strcasecmp(request_data, "allowed")) {
		JANUS_LOG(LOG_VERB, "Attempt to edit the list of allowed participants in an existing DataRoom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, allowed_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *action = json_object_get(root, "action");
		json_t *room = json_object_get(root, "room");
		json_t *allowed = json_object_get(root, "allowed");
		const char *action_data = json_string_value(action);
		if(strcasecmp(action_data, "enable") && strcasecmp(action_data, "disable") &&
				strcasecmp(action_data, "add") && strcasecmp(action_data, "remove")) {
			JANUS_LOG(LOG_ERR, "Unsupported action '%s' (allowed)\n", action_data);
			error_code = JANUS_DATAROOM_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Unsupported action '%s' (allowed)", action_data);
			goto msg_response;
		}
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_mutex_lock(&dataroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(dataroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		if(!strcasecmp(action_data, "enable")) {
			JANUS_LOG(LOG_VERB, "Enabling the check on allowed authorization tokens for room %s\n", room_id_str);
			dataroom->check_tokens = TRUE;
		} else if(!strcasecmp(action_data, "disable")) {
			JANUS_LOG(LOG_VERB, "Disabling the check on allowed authorization tokens for room %s (free entry)\n", room_id_str);
			dataroom->check_tokens = FALSE;
		} else {
			gboolean add = !strcasecmp(action_data, "add");
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
					error_code = JANUS_DATAROOM_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
					janus_mutex_unlock(&dataroom->mutex);
					janus_mutex_unlock(&rooms_mutex);
					goto msg_response;
				}
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(add) {
						if(!g_hash_table_lookup(dataroom->allowed, token))
							g_hash_table_insert(dataroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
					} else {
						g_hash_table_remove(dataroom->allowed, token);
					}
				}
			}
		}
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "dataroom", json_string("success"));
			json_object_set_new(reply, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_t *list = json_array();
			if(strcasecmp(action_data, "disable")) {
				if(g_hash_table_size(dataroom->allowed) > 0) {
					GHashTableIter iter;
					gpointer key;
					g_hash_table_iter_init(&iter, dataroom->allowed);
					while(g_hash_table_iter_next(&iter, &key, NULL)) {
						char *token = key;
						json_array_append_new(list, json_string(token));
					}
				}
				json_object_set_new(reply, "allowed", list);
			}
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_VERB, "DataRoom room allowed list updated\n");
		}
	} else if(!strcasecmp(request_data, "kick")) {
		JANUS_LOG(LOG_VERB, "Attempt to kick a participant from an existing DataRoom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, kick_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		json_t *username = json_object_get(root, "username");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_mutex_lock(&dataroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(dataroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		const char *user_id = json_string_value(username);
		janus_dataroom_participant *participant = g_hash_table_lookup(dataroom->participants, user_id);
		if(participant == NULL) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such participant %s in room %s\n", user_id, room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_USER;
			g_snprintf(error_cause, 512, "No such user %s in room %s", user_id, room_id_str);
			goto msg_response;
		}
		/* Was it the host? */
		if(!strcmp(dataroom->host, user_id))
		{
			free(dataroom->host);
			dataroom->host = strdup("");
		}
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new kick\n");
		if(dataroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("kicked"));
			json_object_set_new(event, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(event, "username", json_string(participant->username));
			char *event_data = json_dumps(event, json_format);
			json_decref(event);
			if(event_data == NULL) {
				janus_mutex_unlock(&dataroom->mutex);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
				error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Failed to stringify message");
				goto msg_response;
			}
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, dataroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_dataroom_participant *top = value;
				if(!strlen(dataroom->host) && top != participant)
				{
					free(dataroom->host);
					dataroom->host = strdup(top->username);
				}
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, room_id_str);
				janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = event_data, .length = strlen(event_data) };
				gateway->relay_data(top->session->handle, &data);
			}
			free(event_data);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "dataroom", json_string("kicked"));
			json_object_set_new(info, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(info, "username", json_string(participant->username));
			gateway->notify_event(&janus_dataroom_plugin, session->handle, info);
		}
		/* Remove user from list */
		g_hash_table_remove(participant->session->rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		g_hash_table_remove(dataroom->participants, participant->username);
		participant->session = NULL;
		participant->room = NULL;
		g_free(participant->username);
		g_free(participant->display);
		g_free(participant);
		/* Done */
		janus_mutex_unlock(&dataroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "databridge", json_string("success"));
		}
	} else if(!strcasecmp(request_data, "delegate")) {
		JANUS_LOG(LOG_VERB, "Attempt to delegate host in DataRoom room\n");
		JANUS_VALIDATE_JSON_OBJECT(root, delegate_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		json_t *host = json_object_get(root, "host");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_mutex_lock(&dataroom->mutex);
		const char *user_id = json_string_value(host);
		janus_dataroom_participant *participant = g_hash_table_lookup(dataroom->participants, user_id);
		if(participant == NULL) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such participant %s in room %s\n", user_id, room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_USER_IN_ROOM;
			g_snprintf(error_cause, 512, "No such user %s in room %s", user_id, room_id_str);
			goto msg_response;
		}
		/* Was already the host? */
		if(!strcmp(dataroom->host, user_id))
		{
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "Attempted to delegate to host %s in room %s\n", user_id, room_id_str);
			error_code = JANUS_DATAROOM_ERROR_ALREADY_HOST;
			g_snprintf(error_cause, 512, "Already host %s in room %s", user_id, room_id_str);
			goto msg_response;
		}
		/* Requester is not the host? */

		participant = g_hash_table_lookup(session->rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(participant == NULL) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "Requester not a participant in room %s\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NOT_IN_ROOM;
			g_snprintf(error_cause, 512, "Not in room %s", room_id_str);
			goto msg_response;
		}
		if(strcmp(dataroom->host, participant->username))
		{
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "Requester not host in room %s\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NOT_HOST;
			g_snprintf(error_cause, 512, "Not host in room %s", room_id_str);
			goto msg_response;
		}

		free(dataroom->host);
		dataroom->host = strdup(user_id);
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the new host\n");
		if(dataroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("host"));
			json_object_set_new(event, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(event, "host", json_string(host));
			char *event_data = json_dumps(event, json_format);
			json_decref(event);
			if(event_data == NULL) {
				janus_mutex_unlock(&dataroom->mutex);
				janus_mutex_unlock(&rooms_mutex);
				JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
				error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Failed to stringify message");
				goto msg_response;
			}
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, dataroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_dataroom_participant *top = value;
				if(!strlen(dataroom->host) && top != participant)
				{
					free(dataroom->host);
					dataroom->host = strdup(top->username);
				}
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, room_id_str);
				janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = event_data, .length = strlen(event_data) };
				gateway->relay_data(top->session->handle, &data);
			}
			free(event_data);
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "dataroom", json_string("host"));
			json_object_set_new(info, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(info, "host", json_string(host));
			gateway->notify_event(&janus_dataroom_plugin, session->handle, info);
		}
		/* Done */
		janus_mutex_unlock(&dataroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "databridge", json_string("success"));
		}
	} else if(!strcasecmp(request_data, "create")) {
		JANUS_VALIDATE_JSON_OBJECT(root, create_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, roomopt_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstropt_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		if(admin_key != NULL) {
			/* An admin key was specified: make sure it was provided, and that it's valid */
			JANUS_VALIDATE_JSON_OBJECT(root, adminkey_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto msg_response;
			JANUS_CHECK_SECRET(admin_key, root, "admin_key", error_code, error_cause,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
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
				error_code = JANUS_DATAROOM_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element in the allowed array (not a string)");
				goto msg_response;
			}
		}
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't create permanent room\n");
			error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't create permanent room");
			goto msg_response;
		}
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		if(room_id == 0 && room_id_str == NULL) {
			JANUS_LOG(LOG_WARN, "Desired room ID is empty, which is not allowed... picking random ID instead\n");
		}
		janus_mutex_lock(&rooms_mutex);
		if(room_id > 0 || room_id_str != NULL) {
			/* Let's make sure the room doesn't exist already */
			if(g_hash_table_lookup(rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id) != NULL) {
				/* It does... */
				janus_mutex_unlock(&rooms_mutex);
				error_code = JANUS_DATAROOM_ERROR_ROOM_EXISTS;
				JANUS_LOG(LOG_ERR, "Room %s already exists!\n", room_id_str);
				g_snprintf(error_cause, 512, "Room %s already exists", room_id_str);
				goto msg_response;
			}
		}
		/* Create the data room */
		janus_dataroom_room *dataroom = g_malloc0(sizeof(janus_dataroom_room));
		/* Generate a random ID */
		gboolean room_id_allocated = FALSE;
		if(!string_ids && room_id == 0) {
			while(room_id == 0) {
				room_id = janus_random_uint64();
				if(g_hash_table_lookup(rooms, &room_id) != NULL) {
					/* Room ID already taken, try another one */
					room_id = 0;
				}
			}
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else if(string_ids && room_id_str == NULL) {
			while(room_id_str == NULL) {
				room_id_str = janus_random_uuid();
				if(g_hash_table_lookup(rooms, room_id_str) != NULL) {
					/* Room ID already taken, try another one */
					g_clear_pointer(&room_id_str, g_free);
				}
			}
			room_id_allocated = TRUE;
		}
		dataroom->room_id = room_id;
		dataroom->room_id_str = room_id_str ? g_strdup(room_id_str) : NULL;
		char *description = NULL;
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			description = g_strdup(json_string_value(desc));
		} else {
			char roomname[255];
			g_snprintf(roomname, 255, "Room %s", dataroom->room_id_str);
			description = g_strdup(roomname);
		}
		dataroom->room_name = description;
		dataroom->is_private = is_private ? json_is_true(is_private) : FALSE;
		if(secret)
			dataroom->room_secret = g_strdup(json_string_value(secret));
		if(pin)
			dataroom->room_pin = g_strdup(json_string_value(pin));
		if(post) {
#ifdef HAVE_LIBCURL
			/* FIXME Should we check if this is a valid HTTP address? */
			dataroom->http_backend = g_strdup(json_string_value(post));
#else
			JANUS_LOG(LOG_WARN, "HTTP backend specified, but libcurl support was not built in...\n");
#endif
		}
		dataroom->participants = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)janus_dataroom_participant_dereference);
		dataroom->allowed = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
		if(allowed != NULL) {
			/* Populate the "allowed" list as an ACL for people trying to join */
			if(json_array_size(allowed) > 0) {
				size_t i = 0;
				for(i=0; i<json_array_size(allowed); i++) {
					const char *token = json_string_value(json_array_get(allowed, i));
					if(!g_hash_table_lookup(dataroom->allowed, token))
						g_hash_table_insert(dataroom->allowed, g_strdup(token), GINT_TO_POINTER(TRUE));
				}
			}
			dataroom->check_tokens = TRUE;
		}
		dataroom->host = strdup("");
		dataroom->destroyed = 0;
		janus_mutex_init(&dataroom->mutex);
		janus_refcount_init(&dataroom->ref, janus_dataroom_room_free);
		g_hash_table_insert(rooms,
			string_ids ? (gpointer)g_strdup(dataroom->room_id_str) : (gpointer)janus_uint64_dup(dataroom->room_id),
			dataroom);
		JANUS_LOG(LOG_VERB, "Created DataRoom: %s (%s, %s, secret: %s, pin: %s)\n",
			dataroom->room_id_str, dataroom->room_name,
			dataroom->is_private ? "private" : "public",
			dataroom->room_secret ? dataroom->room_secret : "no secret",
			dataroom->room_pin ? dataroom->room_pin : "no pin");
		if(save) {
			/* This room is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Saving room %s permanently in config file\n", dataroom->room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", dataroom->room_id_str);
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			/* Now for the values */
			janus_config_add(config, c, janus_config_item_create("description", dataroom->room_name));
			if(dataroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(dataroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", dataroom->room_secret));
			if(dataroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", dataroom->room_pin));
			if(dataroom->http_backend)
				janus_config_add(config, c, janus_config_item_create("post", dataroom->http_backend));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_DATAROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Show updated rooms list */
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, rooms);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_dataroom_room *tr = value;
			JANUS_LOG(LOG_VERB, "  ::: [%s][%s]\n", tr->room_id_str, tr->room_name);
		}
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "dataroom", json_string(json == NULL ? "success" : "created"));
			json_object_set_new(reply, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("created"));
			json_object_set_new(info, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			gateway->notify_event(&janus_dataroom_plugin, session ? session->handle : NULL, info);
		}
		if(room_id_allocated)
			g_free(room_id_str);
	} else if(!strcasecmp(request_data, "exists")) {
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		gboolean room_exists = g_hash_table_contains(rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			json_object_set_new(reply, "dataroom", json_string("success"));
			json_object_set_new(reply, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(reply, "exists", room_exists ? json_true() : json_false());
		}
	} else if(!strcasecmp(request_data, "edit")) {
		JANUS_VALIDATE_JSON_OBJECT(root, edit_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
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
			error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't edit room permanently");
			goto msg_response;
		}
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_mutex_lock(&dataroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(dataroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			goto msg_response;
		}
		/* Edit the room properties that were provided */
		if(desc != NULL && strlen(json_string_value(desc)) > 0) {
			char *old_description = dataroom->room_name;
			char *new_description = g_strdup(json_string_value(desc));
			dataroom->room_name = new_description;
			g_free(old_description);
		}
		if(is_private)
			dataroom->is_private = json_is_true(is_private);
		if(secret && strlen(json_string_value(secret)) > 0) {
			char *old_secret = dataroom->room_secret;
			char *new_secret = g_strdup(json_string_value(secret));
			dataroom->room_secret = new_secret;
			g_free(old_secret);
		}
		if(post && strlen(json_string_value(post)) > 0) {
			char *old_post = dataroom->http_backend;
			char *new_post = g_strdup(json_string_value(post));
			dataroom->http_backend = new_post;
			g_free(old_post);
		}
		if(pin && strlen(json_string_value(pin)) > 0) {
			char *old_pin = dataroom->room_pin;
			char *new_pin = g_strdup(json_string_value(pin));
			dataroom->room_pin = new_pin;
			g_free(old_pin);
		}
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Modifying room %s permanently in config file\n", room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ], value[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", room_id_str);
			/* Remove the old category first */
			janus_config_remove(config, NULL, cat);
			/* Now write the room details again */
			janus_config_category *c = janus_config_get_create(config, NULL, janus_config_type_category, cat);
			janus_config_add(config, c, janus_config_item_create("description", dataroom->room_name));
			if(dataroom->is_private)
				janus_config_add(config, c, janus_config_item_create("is_private", "yes"));
			if(dataroom->room_secret)
				janus_config_add(config, c, janus_config_item_create("secret", dataroom->room_secret));
			if(dataroom->room_pin)
				janus_config_add(config, c, janus_config_item_create("pin", dataroom->room_pin));
			if(dataroom->http_backend)
				janus_config_add(config, c, janus_config_item_create("post", dataroom->http_backend));
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_DATAROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room changes are not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		janus_mutex_unlock(&dataroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "dataroom", json_string(json == NULL ? "success" : "edited"));
			json_object_set_new(reply, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("edited"));
			json_object_set_new(info, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			gateway->notify_event(&janus_dataroom_plugin, session ? session->handle : NULL, info);
		}
	} else if(!strcasecmp(request_data, "destroy")) {
		JANUS_VALIDATE_JSON_OBJECT(root, destroy_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto msg_response;
		if(!string_ids) {
			JANUS_VALIDATE_JSON_OBJECT(root, room_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		} else {
			JANUS_VALIDATE_JSON_OBJECT(root, roomstr_parameters,
				error_code, error_cause, TRUE,
				JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		}
		if(error_code != 0)
			goto msg_response;
		json_t *room = json_object_get(root, "room");
		json_t *permanent = json_object_get(root, "permanent");
		gboolean save = permanent ? json_is_true(permanent) : FALSE;
		if(save && config == NULL) {
			JANUS_LOG(LOG_ERR, "No configuration file, can't destroy room permanently\n");
			error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
			g_snprintf(error_cause, 512, "No configuration file, can't destroy room permanently");
			goto msg_response;
		}
		guint64 room_id = 0;
		char room_id_num[30], *room_id_str = NULL;
		if(!string_ids) {
			room_id = json_integer_value(room);
			g_snprintf(room_id_num, sizeof(room_id_num), "%"SCNu64, room_id);
			room_id_str = room_id_num;
		} else {
			room_id_str = (char *)json_string_value(room);
		}
		janus_mutex_lock(&rooms_mutex);
		janus_dataroom_room *dataroom = g_hash_table_lookup(rooms,
			string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(dataroom == NULL) {
			janus_mutex_unlock(&rooms_mutex);
			JANUS_LOG(LOG_ERR, "No such room (%s)\n", room_id_str);
			error_code = JANUS_DATAROOM_ERROR_NO_SUCH_ROOM;
			g_snprintf(error_cause, 512, "No such room (%s)", room_id_str);
			goto msg_response;
		}
		janus_refcount_increase(&dataroom->ref);
		janus_mutex_lock(&dataroom->mutex);
		/* A secret may be required for this action */
		JANUS_CHECK_SECRET(dataroom->room_secret, root, "secret", error_code, error_cause,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT, JANUS_DATAROOM_ERROR_UNAUTHORIZED);
		if(error_code != 0) {
			janus_mutex_unlock(&dataroom->mutex);
			janus_mutex_unlock(&rooms_mutex);
			janus_refcount_decrease(&dataroom->ref);
			goto msg_response;
		}
		/* Remove room */
		g_hash_table_remove(rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
		if(save) {
			/* This change is permanent: save to the configuration file too
			 * FIXME: We should check if anything fails... */
			JANUS_LOG(LOG_VERB, "Destroying room %s permanently in config file\n", room_id_str);
			janus_mutex_lock(&config_mutex);
			char cat[BUFSIZ];
			/* The room ID is the category (prefixed by "room-") */
			g_snprintf(cat, BUFSIZ, "room-%s", room_id_str);
			janus_config_remove(config, NULL, cat);
			/* Save modified configuration */
			if(janus_config_save(config, config_folder, JANUS_DATAROOM_PACKAGE) < 0)
				save = FALSE;	/* This will notify the user the room destruction is not permanent */
			janus_mutex_unlock(&config_mutex);
		}
		/* Notify all participants */
		JANUS_LOG(LOG_VERB, "Notifying all participants about the destroy\n");
		if(dataroom->participants) {
			/* Prepare event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("destroyed"));
			json_object_set_new(event, "room", string_ids ? json_string(dataroom->room_id_str) : json_integer(dataroom->room_id));
			char *event_data = json_dumps(event, json_format);
			json_decref(event);
			if(event_data == NULL) {
				janus_mutex_unlock(&dataroom->mutex);
				janus_mutex_unlock(&rooms_mutex);
				janus_refcount_decrease(&dataroom->ref);
				JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
				error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
				g_snprintf(error_cause, 512, "Failed to stringify message");
				goto msg_response;
			}
			janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = event_data, .length = strlen(event_data) };
			gateway->relay_data(handle, &data);
			/* Broadcast */
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, dataroom->participants);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_dataroom_participant *top = value;
				janus_refcount_increase(&top->ref);
				JANUS_LOG(LOG_VERB, "  >> To %s in %s\n", top->username, room_id_str);
				gateway->relay_data(top->session->handle, &data);
				janus_mutex_lock(&top->session->mutex);
				g_hash_table_remove(top->session->rooms, string_ids ? (gpointer)room_id_str : (gpointer)&room_id);
				janus_mutex_unlock(&top->session->mutex);
				janus_refcount_decrease(&top->ref);
				janus_dataroom_participant_destroy(top);
			}
			free(event_data);
		}
		janus_mutex_unlock(&dataroom->mutex);
		janus_mutex_unlock(&rooms_mutex);
		janus_refcount_decrease(&dataroom->ref);
		if(!internal) {
			/* Send response back */
			reply = json_object();
			/* Notice that we reply differently if the request came via Janus API */
			json_object_set_new(reply, "dataroom", json_string(json == NULL ? "success" : "destroyed"));
			json_object_set_new(reply, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			json_object_set_new(reply, "permanent", save ? json_true() : json_false());
		}
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("destroyed"));
			json_object_set_new(info, "room", string_ids ? json_string(room_id_str) : json_integer(room_id));
			gateway->notify_event(&janus_dataroom_plugin, session ? session->handle : NULL, info);
		}
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported request %s\n", request_data);
		error_code = JANUS_DATAROOM_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unsupported request %s", request_data);
		goto msg_response;
	}

msg_response:
		{
			if(!internal) {
				if(error_code == 0 && !reply) {
					error_code = JANUS_DATAROOM_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Invalid response");
				}
				if(error_code != 0) {
					/* Prepare JSON error event */
					json_t *event = json_object();
					json_object_set_new(event, "dataroom", json_string("error"));
					json_object_set_new(event, "error_code", json_integer(error_code));
					json_object_set_new(event, "error", json_string(error_cause));
					reply = event;
				}
				if(transaction_data && json == NULL)
					json_object_set_new(reply, "transaction", json_string(transaction_data));
				if(json == NULL) {
					/* Reply via data channels */
					char *reply_data = json_dumps(reply, json_format);
					json_decref(reply);
					if(reply_data == NULL) {
						JANUS_LOG(LOG_ERR, "Failed to stringify message...\n");
					} else {
						janus_plugin_data data = { .label = NULL, .protocol = NULL, .binary = FALSE, .buffer = reply_data, .length = strlen(reply_data) };
						gateway->relay_data(handle, &data);
						free(reply_data);
					}
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

void janus_dataroom_slow_link(janus_plugin_session *handle, int mindex, int uplink, int video) {
	/* We don't do audio/video */
}

void janus_dataroom_hangup_media(janus_plugin_session *handle) {
	janus_mutex_lock(&sessions_mutex);
	janus_dataroom_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_dataroom_hangup_media_internal(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_DATAROOM_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_dataroom_session *session = janus_dataroom_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	g_atomic_int_set(&session->dataready, 0);
	/* Get rid of all participants */
	janus_mutex_lock(&session->mutex);
	GList *list = NULL;
	if(session->rooms) {
		GHashTableIter iter;
		gpointer value;
		janus_mutex_lock(&rooms_mutex);
		g_hash_table_iter_init(&iter, session->rooms);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_dataroom_participant *p = value;
			janus_mutex_lock(&p->mutex);
			if(p->room) {
				list = g_list_append(list, string_ids ?
					(gpointer)g_strdup(p->room->room_id_str) : (gpointer)janus_uint64_dup(p->room->room_id));
			}
			janus_mutex_unlock(&p->mutex);
		}
		janus_mutex_unlock(&rooms_mutex);
	}
	janus_mutex_unlock(&session->mutex);
	JANUS_LOG(LOG_VERB, "Leaving %d rooms\n", g_list_length(list));
	char request[100];
	GList *first = list;
	while(list) {
		char *room_id_str = (char *)list->data;
		if(string_ids) {
			g_snprintf(request, sizeof(request), "{\"dataroom\":\"leave\",\"transaction\":\"internal\",\"room\":\"%s\"}", room_id_str);
		} else {
			guint64 room_id = *(guint64 *)room_id_str;
			g_snprintf(request, sizeof(request), "{\"dataroom\":\"leave\",\"transaction\":\"internal\",\"room\":%"SCNu64"}", room_id);
		}
		janus_dataroom_handle_incoming_request(handle, g_strdup(request), NULL, TRUE);
		list = list->next;
	}
	g_list_free_full(first, (GDestroyNotify)g_free);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_dataroom_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining DataRoom handler thread\n");
	janus_dataroom_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	gboolean do_offer = FALSE, sdp_update = FALSE;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_dataroom_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_dataroom_session *session = janus_dataroom_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_dataroom_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_dataroom_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_DATAROOM_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_DATAROOM_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_DATAROOM_ERROR_MISSING_ELEMENT, JANUS_DATAROOM_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		do_offer = FALSE;
		sdp_update = FALSE;
		json_t *request = json_object_get(root, "request");
		const char *request_data = json_string_value(request);
		do_offer = FALSE;
		if(!strcasecmp(request_data, "setup")) {
			if(!g_atomic_int_compare_and_exchange(&session->setup, 0, 1)) {
				JANUS_LOG(LOG_ERR, "PeerConnection already setup\n");
				error_code = JANUS_DATAROOM_ERROR_ALREADY_SETUP;
				g_snprintf(error_cause, 512, "PeerConnection already setup");
				goto error;
			}
			do_offer = TRUE;
		} else if(!strcasecmp(request_data, "restart")) {
			if(!g_atomic_int_get(&session->setup)) {
				JANUS_LOG(LOG_ERR, "PeerConnection not setup\n");
				error_code = JANUS_DATAROOM_ERROR_ALREADY_SETUP;
				g_snprintf(error_cause, 512, "PeerConnection not setup");
				goto error;
			}
			sdp_update = TRUE;
			do_offer = TRUE;
		} else if(!strcasecmp(request_data, "ack")) {
			/* The peer sent their answer back: do nothing */
		} else {
			JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_data);
			error_code = JANUS_DATAROOM_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request '%s'", request_data);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "dataroom", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		if(!do_offer) {
			int ret = gateway->push_event(msg->handle, &janus_dataroom_plugin, msg->transaction, event, NULL);
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
			int res = gateway->push_event(msg->handle, &janus_dataroom_plugin, msg->transaction, event, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			json_decref(jsep);
		}
		json_decref(event);
		janus_dataroom_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "dataroom", json_string("error"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			int ret = gateway->push_event(msg->handle, &janus_dataroom_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_dataroom_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving DataRoom handler thread\n");
	return NULL;
}
