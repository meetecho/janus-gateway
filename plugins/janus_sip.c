/*! \file   janus_sip.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus SIP plugin
 * \details Check the \ref sipsofia for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page sipsofia SIP plugin documentation
 * This is a simple SIP plugin for Janus, allowing WebRTC peers
 * to register at a SIP server (e.g., Asterisk) and call SIP user agents
 * through a Janus instance. Specifically, when attaching to the plugin peers
 * are requested to provide their SIP server credentials, i.e., the address
 * of the SIP server and their username/secret. This results in the plugin
 * registering at the SIP server and acting as a SIP client on behalf of
 * the web peer. Most of the SIP states and lifetime are masked by the plugin,
 * and only the relevant events (e.g., INVITEs and BYEs) and functionality
 * (call, hangup) are made available to the web peer: peers can call
 * extensions at the SIP server or wait for incoming INVITEs, and during
 * a call they can send DTMF tones. Calls can do plain RTP or SDES-SRTP.
 *
 * The concept behind this plugin is to allow different web pages associated
 * to the same peer, and hence the same SIP user, to attach to the plugin
 * at the same time and yet just do a SIP REGISTER once. The same should
 * apply for calls: while an incoming call would be notified to all the
 * web UIs associated to the peer, only one would be able to pick up and
 * answer, in pretty much the same way as SIP forking works but without the
 * need to fork in the same place. This specific functionality, though, has
 * not been implemented as of yet.
 *
 * \section sipapi SIP Plugin API
 *
 * All requests you can send in the SIP Plugin API are asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction.
 *
 * The supported requests are \c register , \c unregister , \c call ,
 * \c accept, \c info , \c message , \c dtmf_info , \c recording ,
 * \c hold , \c unhold , \c update and \c hangup . \c register can be used,
 * as the name suggests, to register a username at a SIP registrar to
 * call and be called, while \c unregister unregisters it; \c call is used
 * to send an INVITE to a different SIP URI through the plugin, while
 * \c accept is used to accept the call in case one is invited instead
 * of inviting; \c hold and \c unhold can be used respectively to put a
 * call on-hold and to resume it; \c info allows you to send a generic
 * SIP INFO request, while \c dtmf_info is focused on using INFO for DTMF
 * instead; \c message is the method you use to send a SIP message
 * to the other peer; \c recording is used, instead, to record the
 * conversation to one or more .mjr files (depending on the direction you
 * want to record); \c update allows you to update an existing session
 * (e.g., to do a renegotiation or force an ICE restart); finally, \c hangup
 * can be used to terminate the communication at any time, either to
 * hangup (BYE) an ongoing call or to cancel/decline (CANCEL/BYE) a call
 * that hasn't started yet.
 *
 * No matter the request, an error response or event is always formatted
 * like this:
 *
\verbatim
{
	"sip" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * Notice that the error syntax above refers to the plugin API messaging,
 * and not SIP error codes obtained in response to SIP requests, which
 * are notified using a different syntax:
 *
\verbatim
{
	"sip" : "event",
	"result" : {
		"event" : "<name of the error event>",
		"code" : <SIP error code>,
		"reason" : "<SIP error reason>"
	}
}
\endverbatim
 *
 * Coming to the available requests, you send a SIP REGISTER using the
 * \c register request, which has to be formatted as follows:
 *
\verbatim
{
	"request" : "register",
	"type" : "<if guest, no SIP REGISTER is actually sent; optional>",
	"send_register" : <true|false; if false, no SIP REGISTER is actually sent; optional>,
	"force_udp" : <true|false; if true, forces UDP for the SIP messaging; optional>,
	"force_tcp" : <true|false; if true, forces TCP for the SIP messaging; optional>,
	"sips" : <true|false; if true, configures a SIPS URI too when registering; optional>,
	"username" : "<SIP URI to register; mandatory>",
	"secret" : "<password to use to register; optional>",
	"ha1_secret" : "<prehashed password to use to register; optional>",
	"authuser" : "<username to use to authenticate (overrides the one in the SIP URI); optional>",
	"display_name" : "<display name to use when sending SIP REGISTER; optional>",
	"user_agent" : "<user agent to use when sending SIP REGISTER; optional>",
	"proxy" : "<server to register at; optional, as won't be needed in case the REGISTER is not goint to be sent (e.g., guests)>",
	"outbound_proxy" : "<outbound proxy to use, if any; optional>",
	"headers" : "<array of key/value objects, to specify custom headers to add to the SIP REGISTER; optional>",
	"refresh" : <true|false; if true, only uses the SIP REGISTER as an update and not a new registration; optional>"
}
\endverbatim
 *
 * A \c registering event will be sent back, as this is an asynchronous request.
 *
 * In case it is required to, this request will originate a SIP REGISTER to the
 * specified server with the right credentials. 401 and 407 responses will be
 * handled automatically, and so errors will not be notified back to the caller
 * unless they're definitive (e.g., wrong credentials). A failure to register
 * will return an error with name \c registration_failed. A successful registration,
 * instead, is notified in a \c registered event formatted like this:
 *
\verbatim
{
	"sip" : "event",
	"result" : {
		"event" : "registered",
		"username" : <SIP URI username>,
		"register_sent" : <true|false, depending on whether a REGISTER was sent or not>
	}
}
\endverbatim
 *
 * To unregister, just send an \c unregister request with no other arguments:
 *
\verbatim
{
	"request" : "unregister"
}
\endverbatim
 *
 * As before, an \c unregistering event will be sent back. Just as before,
 * this will also send a SIP REGISTER in case it had been sent originally.
 * A successful unregistration is notified in an \c unregistered event:
 *
\verbatim
{
	"sip" : "event",
	"result" : {
		"event" : "unregistered",
		"username" : <SIP URI username>,
		"register_sent" : <true|false, depending on whether a REGISTER was sent or not>
	}
}
\endverbatim
 *
 * Once registered, you can call or wait to be called: notice that you won't
 * be able to get incoming calls if you chose never to send a REGISTER at
 * all, though.
 *
 * To send a SIP INVITE, you can use the \c call request, which has to
 * be formatted like this:
 *
\verbatim
{
	"request" : "call",
	"call_id" : "<user-defined value of Call-ID SIP header used in all SIP requests throughout the call; optional>",
	"uri" : "<SIP URI to call; mandatory>",
	"headers" : "<array of key/value objects, to specify custom headers to add to the SIP INVITE; optional>",
	"srtp" : "<whether to mandate (sdes_mandatory) or offer (sdes_optional) SRTP support; optional>",
	"srtp_profile" : "<SRTP profile to negotiate, in case SRTP is offered; optional>",
	"secret" : "<password to use to call, only needed in case authentication is needed and no REGISTER was sent; optional>",
	"ha1_secret" : "<prehashed password to use to call, only needed in case authentication is needed and no REGISTER was sent; optional>",
	"authuser" : "<username to use to authenticate as to call, only needed in case authentication is needed and no REGISTER was sent; optional>"
}
\endverbatim
 *
 * A \c calling event will be sent back, as this is an asynchronous request.
 *
 * Notice that this request MUST be associated to a JSEP offer: there's no
 * way to send an offerless INVITE via the SIP plugin. This will generate
 * a SIP INVITE and send it according to the instructions. While a
 * <code>100 Trying</code> will not be notified back to the user, a
 * <code>180 Ringing</code> will, in a \c ringing event:
 *
\verbatim
{
	"sip" : "event",
	"call_id" : "<value of SIP Call-ID header for related call>",
	"result" : {
		"event" : "ringing",
	}
}
\endverbatim
 *
 * If the call is declined, or any other error occurs, a \c hangup error
 * event will be sent back. If the call is accepted, instead, an \c accepted
 * event will be sent back to the user, along with the JSEP answer originated
 * by the callee:
 *
\verbatim
{
	"sip" : "event",
	"call_id" : "<value of SIP Call-ID header for related call>",
	"result" : {
		"event" : "accepted",
		"username" : "<SIP URI of the callee>"
	}
}
\endverbatim
 *
 * At this point, PeerConnection-related considerations aside, the call
 * can be considered established. A SIP ACK is sent automatically by the
 * SIP plugin, so there's no action required of the application to do
 * that manually.
 *
 * Notice that the SIP plugin supports early-media via \c 183 responses
 * responses. In case a \c 183 response is received, it's sent back to
 * the user, along with the JSEP answer originated by the callee, in
 * a \c progress event:
 *
\verbatim
{
	"sip" : "event",
	"call_id" : "<value of SIP Call-ID header for related call>",
	"result" : {
		"event" : "progress",
		"username" : "<SIP URI of the callee>"
	}
}
\endverbatim
 *
 * In case the caller received a \c progress event, the following
 * \c accepted event will NOT contain a JSEP answer, as the one received
 * in the "Session Progress" event will act as the SDP answer for the session.
 *
 * Notice that you only use \c call to start a conversation, that is for
 * the first INVITE. To update a session via a re-INVITE, e.g., to renegotiate
 * a session to add/remove streams or force an ICE restart, you do NOT
 * use \c call, but another request called \c update instead. This request
 * needs no arguments, as the whole context is derived from the current
 * state of the session. It does need the new JSEP offer to provide, though,
 * as part of the renegotiation.
 *
\verbatim
{
	"request" : "update"
}
\endverbatim
 *
 * An \c updating event will be sent back, as this is an asynchronous request.
 *
 * While the \c call request allows you to send a SIP INVITE (and the
 * \c update request allows you to update an existing session), there is
 * a way to react to SIP INVITEs as well, that is to handle incoming calls.
 * Incoming calls are notified to the application via \c incomingcall
 * events:
 *
\verbatim
{
	"sip" : "event",
	"call_id" : "<value of SIP Call-ID header for related call>",
	"result" : {
		"event" : "incomingcall",
		"username" : "<SIP URI of the caller>",
		"displayname" : "<display name of the caller, if available; optional>",
		"srtp" : "<whether the caller mandates (sdes_mandatory) or offers (sdes_optional) SRTP support; optional>"
	}
}
\endverbatim
 *
 * The \c incomingcall may or may not be accompanied by a JSEP offer, depending
 * on whether the caller sent an offerless INVITE or a regular one. Either
 * way, you can accept the incoming call with the \c accept request:
 *
\verbatim
{
	"request" : "accept",
	"srtp" : "<whether to mandate (sdes_mandatory) or offer (sdes_optional) SRTP support; optional>",
	"headers" : "<array of key/value objects, to specify custom headers to add to the SIP OK; optional>"
}
\endverbatim
 *
 * An \c accepting event will be sent back, as this is an asynchronous request.
 *
 * This will result in a <code>200 OK</code> to be sent back to the caller.
 * An \c accept request must always be accompanied by a JSEP answer (if the
 * \c incomingcall event contained an offer) or offer (in case it was an
 * offerless INVITE). In the former case, an \c accepted event will be
 * sent back just to confirm the call can be considered established;
 * in the latter case, instead, an \c accepting event will be sent back
 * instead, and an \c accepted event will only follow later, as soon as
 * a JSEP answer is available in the SIP ACK the caller sent back.
 *
 * Notice that in case you get an incoming call while you're in another
 * call, you will NOT get an \c incomingcall event, but a \c missed_call
 * event instead, and just as a notification as there's no way to have
 * two calls at the same time on the same handle in the SIP plugin:
 *
\verbatim
{
	"sip" : "event",
	"call_id" : "<value of SIP Call-ID header for related call>",
	"result" : {
		"event" : "missed_call",
		"caller" : "<SIP URI of the caller>",
		"displayname" : "<display name of the caller, if available; optional>"
	}
}
\endverbatim
 *
 * Closing a session depends on the call state. If you have an incoming
 * call that you don't want to accept, use the \c decline request; in all
 * other cases, use the \c hangup request instead. Both requests need no
 * additional arguments, as the whole context can be extracted from the
 * current state of the session in the plugin:
 *
\verbatim
{
	"request" : "decline",
	"code" : <SIP code to be sent, if not set, 486 is used; optional>"
}
\endverbatim
 *
\verbatim
{
	"request" : "hangup"
}
\endverbatim
 *
 * Since these are asynchronous requests, you'll get an event in response:
 * \c declining if you used \c decline and \c hangingup if you used \c hangup.
 *
 * As anticipated before, when a call is declined or being hung up, a
 * \c hangup event is sent instead, which is basically a SIP error event
 * notification as it includes the \c code and \c reason . A regular BYE,
 * for instance, would be notified with \c 200 and <code>SIP BYE</code>,
 * although a more verbose description may be provided as well.
 *
 * When a session has been established, there are different requests that
 * you can use to interact with the session.
 *
 * The \c message request allows you to send a SIP MESSAGE to the peer:
 *
\verbatim
{
	"request" : "message",
	"content" : "<text to send>"
}
\endverbatim
 *
 * A \c messagesent event will be sent back. Incoming SIP MESSAGEs, instead,
 * are notified in \c message events:
 *
\verbatim
{
	"sip" : "event",
	"result" : {
		"event" : "message",
		"sender" : "<SIP URI of the message sender>",
		"displayname" : "<display name of the sender, if available; optional>",
		"content" : "<content of the message>"
	}
}
\endverbatim
 *
 * SIP INFO works pretty much the same way, except that you use an \c info
 * request to one to the peer:
 *
\verbatim
{
	"request" : "info",
	"type" : "<content type>"
	"content" : "<message to send>"
}
\endverbatim
 *
 * A \c infosent event will be sent back. Incoming SIP INFOs, instead,
 * are notified in \c info events:
 *
\verbatim
{
	"sip" : "event",
	"result" : {
		"event" : "info",
		"sender" : "<SIP URI of the message sender>",
		"displayname" : "<display name of the sender, if available; optional>",
		"type" : "<content type of the message>",
		"content" : "<content of the message>"
	}
}
\endverbatim
 *
 * You can also record a SIP call, and it works pretty much the same the
 * VideoCall plugin does. Specifically, you make use of the \c recording
 * request to either start or stop a recording, using the following syntax:
 *
\verbatim
{
	"request" : "recording",
	"action" : "<start|stop, depending on whether you want to start or stop recording something>"
	"audio" : <true|false; whether or not our audio should be recorded>,
	"video" : <true|false; whether or not our video should be recorded>,
	"peer_audio" : <true|false; whether or not our peer's audio should be recorded>,
	"peer_video" : <true|false; whether or not our peer's video should be recorded>,
	"filename" : "<base path/filename to use for all the recordings>"
}
\endverbatim
 *
 * As you can see, this means that the two sides of conversation are recorded
 * separately, and so are the audio and video streams if available. You can
 * choose which ones to record, in case you're interested in just a subset.
 * The \c filename part is just a prefix, and dictates the actual filenames
 * that will be used for the up-to-four recordings that may need to be enabled.
 *
 * A \c recordingupdated event is sent back in case the request is successful.
 */

#include "plugin.h"

#include <arpa/inet.h>
#include <net/if.h>

#include <jansson.h>

#include <sofia-sip/msg_header.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/url.h>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/su_log.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtpsrtp.h"
#include "../rtcp.h"
#include "../sdp-utils.h"
#include "../utils.h"
#include "../ip-utils.h"


/* Plugin information */
#define JANUS_SIP_VERSION			7
#define JANUS_SIP_VERSION_STRING	"0.0.7"
#define JANUS_SIP_DESCRIPTION		"This is a simple SIP plugin for Janus, allowing WebRTC peers to register at a SIP server and call SIP user agents through a Janus instance."
#define JANUS_SIP_NAME				"JANUS SIP plugin"
#define JANUS_SIP_AUTHOR			"Meetecho s.r.l."
#define JANUS_SIP_PACKAGE			"janus.plugin.sip"

/* Plugin methods */
janus_plugin *create(void);
int janus_sip_init(janus_callbacks *callback, const char *config_path);
void janus_sip_destroy(void);
int janus_sip_get_api_compatibility(void);
int janus_sip_get_version(void);
const char *janus_sip_get_version_string(void);
const char *janus_sip_get_description(void);
const char *janus_sip_get_name(void);
const char *janus_sip_get_author(void);
const char *janus_sip_get_package(void);
void janus_sip_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_sip_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_sip_setup_media(janus_plugin_session *handle);
void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_hangup_media(janus_plugin_session *handle);
void janus_sip_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_sip_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_sip_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_sip_init,
		.destroy = janus_sip_destroy,

		.get_api_compatibility = janus_sip_get_api_compatibility,
		.get_version = janus_sip_get_version,
		.get_version_string = janus_sip_get_version_string,
		.get_description = janus_sip_get_description,
		.get_name = janus_sip_get_name,
		.get_author = janus_sip_get_author,
		.get_package = janus_sip_get_package,

		.create_session = janus_sip_create_session,
		.handle_message = janus_sip_handle_message,
		.setup_media = janus_sip_setup_media,
		.incoming_rtp = janus_sip_incoming_rtp,
		.incoming_rtcp = janus_sip_incoming_rtcp,
		.hangup_media = janus_sip_hangup_media,
		.destroy_session = janus_sip_destroy_session,
		.query_session = janus_sip_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SIP_NAME);
	return &janus_sip_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter register_parameters[] = {
	{"type", JSON_STRING, 0},
	{"send_register", JANUS_JSON_BOOL, 0},
	{"force_udp", JANUS_JSON_BOOL, 0},
	{"force_tcp", JANUS_JSON_BOOL, 0},
	{"sips", JANUS_JSON_BOOL, 0},
	{"username", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"secret", JSON_STRING, 0},
	{"ha1_secret", JSON_STRING, 0},
	{"authuser", JSON_STRING, 0},
	{"display_name", JSON_STRING, 0},
	{"user_agent", JSON_STRING, 0},
	{"headers", JSON_OBJECT, 0},
	{"refresh", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter proxy_parameters[] = {
	{"proxy", JSON_STRING, 0},
	{"outbound_proxy", JSON_STRING, 0}
};
static struct janus_json_parameter call_parameters[] = {
	{"uri", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"headers", JSON_OBJECT, 0},
	{"srtp", JSON_STRING, 0},
	{"srtp_profile", JSON_STRING, 0},
	/* The following are only needed in case "guest" registrations
	 * still need an authenticated INVITE for some reason */
	{"secret", JSON_STRING, 0},
	{"ha1_secret", JSON_STRING, 0},
	{"authuser", JSON_STRING, 0}
};
static struct janus_json_parameter accept_parameters[] = {
	{"srtp", JSON_STRING, 0},
	{"headers", JSON_OBJECT, 0}
};
static struct janus_json_parameter recording_parameters[] = {
	{"action", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"peer_audio", JANUS_JSON_BOOL, 0},
	{"peer_video", JANUS_JSON_BOOL, 0},
	{"filename", JSON_STRING, 0}
};
static struct janus_json_parameter dtmf_info_parameters[] = {
	{"digit", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"duration", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter info_parameters[] = {
	{"type", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"content", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter sipmessage_parameters[] = {
	{"content", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};

/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static gboolean notify_events = TRUE;
static janus_callbacks *gateway = NULL;

static char *local_ip = NULL;
static int keepalive_interval = 120;
static gboolean behind_nat = FALSE;
static char *user_agent;
#define JANUS_DEFAULT_REGISTER_TTL	3600
static int register_ttl = JANUS_DEFAULT_REGISTER_TTL;
static uint16_t rtp_range_min = 10000;
static uint16_t rtp_range_max = 60000;

static GThread *handler_thread;
static void *janus_sip_handler(void *data);
static void janus_sip_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_sip_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_sip_message;
static GAsyncQueue *messages = NULL;
static janus_sip_message exit_message;


typedef enum {
	janus_sip_registration_status_disabled = -2,
	janus_sip_registration_status_failed = -1,
	janus_sip_registration_status_unregistered = 0,
	janus_sip_registration_status_registering,
	janus_sip_registration_status_registered,
	janus_sip_registration_status_unregistering,
} janus_sip_registration_status;

static const char *janus_sip_registration_status_string(janus_sip_registration_status status) {
	switch(status) {
		case janus_sip_registration_status_disabled:
			return "disabled";
		case janus_sip_registration_status_failed:
			return "failed";
		case janus_sip_registration_status_unregistered:
			return "unregistered";
		case janus_sip_registration_status_registering:
			return "registering";
		case janus_sip_registration_status_registered:
			return "registered";
		case janus_sip_registration_status_unregistering:
			return "unregistering";
		default:
			return "unknown";
	}
}


typedef enum {
	janus_sip_call_status_idle = 0,
	janus_sip_call_status_inviting,
	janus_sip_call_status_invited,
	janus_sip_call_status_incall,
	janus_sip_call_status_closing,
} janus_sip_call_status;

static const char *janus_sip_call_status_string(janus_sip_call_status status) {
	switch(status) {
		case janus_sip_call_status_idle:
			return "idle";
		case janus_sip_call_status_inviting:
			return "inviting";
		case janus_sip_call_status_invited:
			return "invited";
		case janus_sip_call_status_incall:
			return "incall";
		case janus_sip_call_status_closing:
			return "closing";
		default:
			return "unknown";
	}
}


/* Sofia stuff */
typedef struct ssip_s ssip_t;
typedef struct ssip_oper_s ssip_oper_t;

typedef enum {
	janus_sip_secret_type_plaintext = 1,
	janus_sip_secret_type_hashed = 2,
	janus_sip_secret_type_unknown
} janus_sip_secret_type;

typedef struct janus_sip_account {
	char *identity;
	char *user_agent;		/* Used to override the general UA string */
	gboolean force_udp;
	gboolean force_tcp;
	gboolean sips;
	char *username;
	char *display_name;		/* Used for outgoing calls in the From header */
	char *authuser;			/**< username to use for authentication */
	char *secret;
	janus_sip_secret_type secret_type;
	int sip_port;
	char *proxy;
	char *outbound_proxy;
	janus_sip_registration_status registration_status;
} janus_sip_account;

typedef struct janus_sip_media {
	char *remote_ip;
	gboolean earlymedia;
	gboolean update;
	gboolean ready;
	gboolean require_srtp, has_srtp_local, has_srtp_remote;
	janus_srtp_profile srtp_profile;
	gboolean on_hold;
	gboolean has_audio;
	int audio_rtp_fd, audio_rtcp_fd;
	int local_audio_rtp_port, remote_audio_rtp_port;
	int local_audio_rtcp_port, remote_audio_rtcp_port;
	guint32 audio_ssrc, audio_ssrc_peer;
	int audio_pt;
	const char *audio_pt_name;
	srtp_t audio_srtp_in, audio_srtp_out;
	srtp_policy_t audio_remote_policy, audio_local_policy;
	gboolean audio_send;
	janus_sdp_mdirection pre_hold_audio_dir;
	gboolean has_video;
	int video_rtp_fd, video_rtcp_fd;
	int local_video_rtp_port, remote_video_rtp_port;
	int local_video_rtcp_port, remote_video_rtcp_port;
	guint32 video_ssrc, video_ssrc_peer;
	guint32 simulcast_ssrc;
	int video_pt;
	const char *video_pt_name;
	srtp_t video_srtp_in, video_srtp_out;
	srtp_policy_t video_remote_policy, video_local_policy;
	gboolean video_send;
	janus_sdp_mdirection pre_hold_video_dir;
	janus_rtp_switching_context context;
	int pipefd[2];
	gboolean updated;
} janus_sip_media;

typedef struct janus_sip_session {
	janus_plugin_session *handle;
	ssip_t *stack;
	janus_sip_account account;
	janus_sip_call_status status;
	janus_sip_media media;
	char *transaction;
	char *callee;
	char *callid;
	janus_sdp *sdp;				/* The SDP this user sent */
	janus_recorder *arc;		/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *arc_peer;	/* The Janus recorder instance for the peer's audio, if enabled */
	janus_recorder *vrc;		/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *vrc_peer;	/* The Janus recorder instance for the peer's video, if enabled */
	janus_mutex rec_mutex;		/* Mutex to protect the recorders from race conditions */
	GThread *relayer_thread;
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
	janus_mutex mutex;
} janus_sip_session;
static GHashTable *sessions;
static GHashTable *identities;
static GHashTable *callids;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static void janus_sip_srtp_cleanup(janus_sip_session *session);

static void janus_sip_session_destroy(janus_sip_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		janus_refcount_decrease(&session->ref);
}

static void janus_sip_session_free(const janus_refcount *session_ref) {
	janus_sip_session *session = janus_refcount_containerof(session_ref, janus_sip_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	if(session->account.identity) {
		g_hash_table_remove(identities, session->account.identity);
		g_free(session->account.identity);
		session->account.identity = NULL;
	}
	session->account.force_udp = FALSE;
	session->account.sips = TRUE;
	if(session->account.proxy) {
		g_free(session->account.proxy);
		session->account.proxy = NULL;
	}
	if(session->account.outbound_proxy) {
		g_free(session->account.outbound_proxy);
		session->account.outbound_proxy = NULL;
	}
	if(session->account.secret) {
		g_free(session->account.secret);
		session->account.secret = NULL;
	}
	if(session->account.username) {
		g_free(session->account.username);
		session->account.username = NULL;
	}
	if(session->account.display_name) {
		g_free(session->account.display_name);
		session->account.display_name = NULL;
	}
	if(session->account.user_agent) {
		g_free(session->account.user_agent);
		session->account.user_agent = NULL;
	}
	if(session->account.authuser) {
		g_free(session->account.authuser);
		session->account.authuser = NULL;
	}
	if(session->callee) {
		g_free(session->callee);
		session->callee = NULL;
	}
	if(session->callid) {
		g_hash_table_remove(callids, session->callid);
		g_free(session->callid);
		session->callid = NULL;
	}
	if(session->sdp) {
		janus_sdp_destroy(session->sdp);
		session->sdp = NULL;
	}
	if(session->transaction) {
		g_free(session->transaction);
		session->transaction = NULL;
	}
	if(session->media.remote_ip) {
		g_free(session->media.remote_ip);
		session->media.remote_ip = NULL;
	}
	if(session->stack) {
		g_free(session->stack);
		session->stack = NULL;
	}
	janus_sip_srtp_cleanup(session);
	g_free(session);
}

static void janus_sip_message_free(janus_sip_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_sip_session *session = (janus_sip_session *)msg->handle->plugin_handle;
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


#undef SU_ROOT_MAGIC_T
#define SU_ROOT_MAGIC_T	ssip_t
#undef NUA_MAGIC_T
#define NUA_MAGIC_T		ssip_t
#undef NUA_HMAGIC_T
#define NUA_HMAGIC_T	ssip_oper_t

struct ssip_s {
	su_home_t s_home[1];
	su_root_t *s_root;
	nua_t *s_nua;
	nua_handle_t *s_nh_r, *s_nh_i;
	janus_sip_session *session;
};


/* SRTP stuff (in case we need SDES) */
static int janus_sip_srtp_set_local(janus_sip_session *session, gboolean video, char **profile, char **crypto) {
	if(session == NULL)
		return -1;
	/* Which SRTP profile are we going to negotiate? */
	int key_length = 0, salt_length = 0, master_length = 0;
	if(session->media.srtp_profile == JANUS_SRTP_AES128_CM_SHA1_32) {
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
		*profile = g_strdup("AES_CM_128_HMAC_SHA1_32");
	} else if(session->media.srtp_profile == JANUS_SRTP_AES128_CM_SHA1_80) {
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
		*profile = g_strdup("AES_CM_128_HMAC_SHA1_80");
#ifdef HAVE_SRTP_AESGCM
	} else if(session->media.srtp_profile == JANUS_SRTP_AEAD_AES_128_GCM) {
		key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM128_MASTER_LENGTH;
		*profile = g_strdup("AEAD_AES_128_GCM");
	} else if(session->media.srtp_profile == JANUS_SRTP_AEAD_AES_256_GCM) {
		key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM256_MASTER_LENGTH;
		*profile = g_strdup("AEAD_AES_256_GCM");
#endif
	} else {
		JANUS_LOG(LOG_ERR, "[SIP-%s] Unsupported SRTP profile\n", session->account.username);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[SIP-%s] %s\n", session->account.username, *profile);
	JANUS_LOG(LOG_WARN, "[SIP-%s] Key/Salt/Master: %d/%d/%d\n",
		session->account.username, master_length, key_length, salt_length);
	/* Generate key/salt */
	uint8_t *key = g_malloc0(master_length);
	srtp_crypto_get_random(key, master_length);
	/* Set SRTP policies */
	srtp_policy_t *policy = video ? &session->media.video_local_policy : &session->media.audio_local_policy;
	switch(session->media.srtp_profile) {
		case JANUS_SRTP_AES128_CM_SHA1_32:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
		case JANUS_SRTP_AES128_CM_SHA1_80:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
#ifdef HAVE_SRTP_AESGCM
		case JANUS_SRTP_AEAD_AES_128_GCM:
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtcp));
			break;
		case JANUS_SRTP_AEAD_AES_256_GCM:
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtcp));
			break;
#endif
		default:
			/* Will never happen? */
			JANUS_LOG(LOG_WARN, "[SIP-%s] Unsupported SRTP profile\n", session->account.username);
			break;
	}
	policy->ssrc.type = ssrc_any_inbound;
	policy->key = key;
	policy->next = NULL;
	/* Create SRTP context */
	srtp_err_status_t res = srtp_create(video ? &session->media.video_srtp_out : &session->media.audio_srtp_out, policy);
	if(res != srtp_err_status_ok) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Oops, error creating outbound SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
		g_free(*profile);
		*profile = NULL;
		g_free(key);
		policy->key = NULL;
		return -2;
	}
	/* Base64 encode the salt */
	*crypto = g_base64_encode(key, master_length);
	if((video && session->media.video_srtp_out) || (!video && session->media.audio_srtp_out)) {
		JANUS_LOG(LOG_VERB, "%s outbound SRTP session created\n", video ? "Video" : "Audio");
	}
	return 0;
}
static int janus_sip_srtp_set_remote(janus_sip_session *session, gboolean video, const char *profile, const char *crypto) {
	if(session == NULL || profile == NULL || crypto == NULL)
		return -1;
	/* Which SRTP profile is being negotiated? */
	JANUS_LOG(LOG_WARN, "[SIP-%s] %s\n", session->account.username, profile);
	gsize key_length = 0, salt_length = 0, master_length = 0;
	if(!strcasecmp(profile, "AES_CM_128_HMAC_SHA1_32")) {
		session->media.srtp_profile = JANUS_SRTP_AES128_CM_SHA1_32;
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
	} else if(!strcasecmp(profile, "AES_CM_128_HMAC_SHA1_80")) {
		session->media.srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
		key_length = SRTP_MASTER_KEY_LENGTH;
		salt_length = SRTP_MASTER_SALT_LENGTH;
		master_length = SRTP_MASTER_LENGTH;
#ifdef HAVE_SRTP_AESGCM
	} else if(!strcasecmp(profile, "AEAD_AES_128_GCM")) {
		session->media.srtp_profile = JANUS_SRTP_AEAD_AES_128_GCM;
		key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM128_MASTER_LENGTH;
	} else if(!strcasecmp(profile, "AEAD_AES_256_GCM")) {
		session->media.srtp_profile = JANUS_SRTP_AEAD_AES_256_GCM;
		key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
		salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
		master_length = SRTP_AESGCM256_MASTER_LENGTH;
#endif
	} else {
		JANUS_LOG(LOG_ERR, "[SIP-%s] Unsupported SRTP profile %s\n", session->account.username, profile);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[SIP-%s] Key/Salt/Master: %zu/%zu/%zu\n",
		session->account.username, master_length, key_length, salt_length);
	/* Base64 decode the crypto string and set it as the remote SRTP context */
	gsize len = 0;
	guchar *decoded = g_base64_decode(crypto, &len);
	if(len < master_length) {
		/* FIXME Can this happen? */
		g_free(decoded);
		return -3;
	}
	/* Set SRTP policies */
	srtp_policy_t *policy = video ? &session->media.video_remote_policy : &session->media.audio_remote_policy;
	switch(session->media.srtp_profile) {
		case JANUS_SRTP_AES128_CM_SHA1_32:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
		case JANUS_SRTP_AES128_CM_SHA1_80:
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtcp));
			break;
#ifdef HAVE_SRTP_AESGCM
		case JANUS_SRTP_AEAD_AES_128_GCM:
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_128_16_auth(&(policy->rtcp));
			break;
		case JANUS_SRTP_AEAD_AES_256_GCM:
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtp));
			srtp_crypto_policy_set_aes_gcm_256_16_auth(&(policy->rtcp));
			break;
#endif
		default:
			/* Will never happen? */
			JANUS_LOG(LOG_WARN, "[SIP-%s] Unsupported SRTP profile\n", session->account.username);
			break;
	}
	policy->ssrc.type = ssrc_any_inbound;
	policy->key = decoded;
	policy->next = NULL;
	/* Create SRTP context */
	srtp_err_status_t res = srtp_create(video ? &session->media.video_srtp_in : &session->media.audio_srtp_in, policy);
	if(res != srtp_err_status_ok) {
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Oops, error creating inbound SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
		g_free(decoded);
		policy->key = NULL;
		return -2;
	}
	if((video && session->media.video_srtp_in) || (!video && session->media.audio_srtp_in)) {
		JANUS_LOG(LOG_VERB, "%s inbound SRTP session created\n", video ? "Video" : "Audio");
	}
	return 0;
}
static void janus_sip_srtp_cleanup(janus_sip_session *session) {
	if(session == NULL)
		return;
	session->media.require_srtp = FALSE;
	session->media.has_srtp_local = FALSE;
	session->media.has_srtp_remote = FALSE;
	session->media.srtp_profile = 0;
	/* Audio */
	if(session->media.audio_srtp_out)
		srtp_dealloc(session->media.audio_srtp_out);
	session->media.audio_srtp_out = NULL;
	g_free(session->media.audio_local_policy.key);
	session->media.audio_local_policy.key = NULL;
	if(session->media.audio_srtp_in)
		srtp_dealloc(session->media.audio_srtp_in);
	session->media.audio_srtp_in = NULL;
	g_free(session->media.audio_remote_policy.key);
	session->media.audio_remote_policy.key = NULL;
	/* Video */
	if(session->media.video_srtp_out)
		srtp_dealloc(session->media.video_srtp_out);
	session->media.video_srtp_out = NULL;
	g_free(session->media.video_local_policy.key);
	session->media.video_local_policy.key = NULL;
	if(session->media.video_srtp_in)
		srtp_dealloc(session->media.video_srtp_in);
	session->media.video_srtp_in = NULL;
	g_free(session->media.video_remote_policy.key);
	session->media.video_remote_policy.key = NULL;
}


/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data);
/* Sofia callbacks */
void janus_sip_sofia_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *magic, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]);
/* SDP parsing and manipulation */
void janus_sip_sdp_process(janus_sip_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed);
char *janus_sip_sdp_manipulate(janus_sip_session *session, janus_sdp *sdp, gboolean answer);
/* Media */
static int janus_sip_allocate_local_ports(janus_sip_session *session);
static void *janus_sip_relay_thread(void *data);
static void janus_sip_media_cleanup(janus_sip_session *session);


/* URI parsing utilies */

#define JANUS_SIP_URI_MAXLEN	1024
typedef struct {
	char data[JANUS_SIP_URI_MAXLEN];
	url_t url[1];
} janus_sip_uri_t;

/* Parses a SIP URI (SIPS is not supported), returns 0 on success, -1 otherwise */
static int janus_sip_parse_uri(janus_sip_uri_t *sip_uri, const char *data) {
	g_strlcpy(sip_uri->data, data, JANUS_SIP_URI_MAXLEN);
	if(url_d(sip_uri->url, sip_uri->data) < 0 || sip_uri->url->url_type != url_sip)
		return -1;
	return 0;
}

/* Similar to the above function, but it also accepts SIPS URIs */
static int janus_sip_parse_proxy_uri(janus_sip_uri_t *sip_uri, const char *data) {
	g_strlcpy(sip_uri->data, data, JANUS_SIP_URI_MAXLEN);
	if(url_d(sip_uri->url, sip_uri->data) < 0 || (sip_uri->url->url_type != url_sip && sip_uri->url->url_type != url_sips))
		return -1;
	return 0;
}

/* Error codes */
#define JANUS_SIP_ERROR_UNKNOWN_ERROR		499
#define JANUS_SIP_ERROR_NO_MESSAGE			440
#define JANUS_SIP_ERROR_INVALID_JSON		441
#define JANUS_SIP_ERROR_INVALID_REQUEST		442
#define JANUS_SIP_ERROR_MISSING_ELEMENT		443
#define JANUS_SIP_ERROR_INVALID_ELEMENT		444
#define JANUS_SIP_ERROR_ALREADY_REGISTERED	445
#define JANUS_SIP_ERROR_INVALID_ADDRESS		446
#define JANUS_SIP_ERROR_WRONG_STATE			447
#define JANUS_SIP_ERROR_MISSING_SDP			448
#define JANUS_SIP_ERROR_LIBSOFIA_ERROR		449
#define JANUS_SIP_ERROR_IO_ERROR			450
#define JANUS_SIP_ERROR_RECORDING_ERROR		451
#define JANUS_SIP_ERROR_TOO_STRICT			452


/* Random string helper (for call-ids) */
static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static void janus_sip_random_string(int length, char *buffer) {
	if(length > 0 && buffer) {
		int l = (int)(sizeof(charset)-1);
		int i=0;
		for(i=0; i<length; i++) {
			int key = rand() % l;
			buffer[i] = charset[key];
		}
		buffer[length-1] = '\0';
	}
}

static void janus_sip_parse_custom_headers(json_t *root, char *custom_headers) {
	custom_headers[0] = '\0';
	json_t *headers = json_object_get(root, "headers");
	if(headers) {
		if(json_object_size(headers) > 0) {
			/* Parse custom headers */
			const char *key = NULL;
			json_t *value = NULL;
			void *iter = json_object_iter(headers);
			while(iter != NULL) {
				key = json_object_iter_key(iter);
				value = json_object_get(headers, key);
				if(value == NULL || !json_is_string(value)) {
					JANUS_LOG(LOG_WARN, "Skipping header '%s': value is not a string\n", key);
					iter = json_object_iter_next(headers, iter);
					continue;
				}
				char h[255];
				g_snprintf(h, 255, "%s: %s\r\n", key, json_string_value(value));
				JANUS_LOG(LOG_VERB, "Adding custom header, %s", h);
				g_strlcat(custom_headers, h, 2048);
				iter = json_object_iter_next(headers, iter);
			}
		}
	}
}

/* Sofia SIP logger function: when the Event Handlers mechanism is enabled,
 * we use this to intercept SIP messages sent by the stack (received
 * messages are more easily recoverable in janus_sip_sofia_callback) */
char sofia_log[2048];
char call_id[255];
gboolean skip = FALSE, started = FALSE, append = FALSE;
static void janus_sip_sofia_logger(void *stream, char const *fmt, va_list ap) {
	if(!fmt)
		return;
	char line[255];
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	g_vsnprintf(line, sizeof(line), fmt, ap);
#pragma GCC diagnostic warning "-Wformat-nonliteral"
	if(skip) {
		/* This is a message we're not interested in: just check when it ends */
		if(line[3] == '-') {
			skip = FALSE;
			append = FALSE;
		}
		return;
	}
	if(append) {
		/* We're copying a message in our buffer: check if this is the end */
		if(line[3] == '-') {
			if(!started) {
				/* Ok, start appending from now on */
				started = TRUE;
				sofia_log[0] = '\0';
				call_id[0] = '\0';
			} else {
				/* Message ended, handle it */
				skip = FALSE;
				append = FALSE;
				/* Look for the session this message belongs to */
				janus_sip_session *session = NULL;
				janus_mutex_lock(&sessions_mutex);
				if(strlen(call_id))
					session = g_hash_table_lookup(callids, call_id);
				if(!session) {
					/* Couldn't find any SIP session with that Call-ID, check the request */
					if(strstr(sofia_log, "REGISTER") == sofia_log || strstr(sofia_log, "SIP/2.0 ") == sofia_log) {
						/* FIXME This is a REGISTER or a response code:
						 * check the To header and get the identity from there */
						char *from = strstr(sofia_log, "To: ");
						if(from) {
							from = from+4;
							char *start = strstr(from, "<");
							if(start) {
								start++;
								char *end = strstr(from, ">");
								if(end) {
									*end = '\0';
									g_snprintf(call_id, sizeof(call_id), "%s", start);
									*end = '>';
									session = g_hash_table_lookup(identities, call_id);
								}
							}
						}
					}
				}
				janus_mutex_unlock(&sessions_mutex);
				if(session) {
					/* Notify event handlers about the content of the whole outgoing SIP message */
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("sip-out"));
					json_object_set_new(info, "sip", json_string(sofia_log));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				} else {
					JANUS_LOG(LOG_WARN, "Couldn't find a session associated to this message, dropping it...\n%s", sofia_log);
				}
				/* Done, reset the buffers */
				sofia_log[0] = '\0';
				call_id[0] = '\0';
			}
			return;
		}
		if(strlen(line) == 1) {
			/* Append a carriage and return */
			g_strlcat(sofia_log, "\r\n", sizeof(sofia_log));
		} else {
			/* If this is an OPTIONS, we don't care: drop it */
			char *header = &line[3];
			if(strstr(header, "OPTIONS") == header) {
				skip = TRUE;
				return;
			}
			/* Is this a Call-ID header? Keep note of it */
			if(strstr(header, "Call-ID") == header) {
				g_snprintf(call_id, sizeof(call_id), "%s", header+9);
			}
			/* Append the line to our buffer, skipping the indent */
			g_strlcat(sofia_log, &line[3], sizeof(sofia_log));
		}
		return;
	}
	/* Still waiting to decide if this is a message we need */
	if(line[0] == 's' && line[1] == 'e' && line[2] == 'n' && line[3] == 'd' && line[4] == ' ') {
		/* An outgoing message is going to be logged, prepare for that */
		skip = FALSE;
		started = FALSE;
		append = TRUE;
		int length = atoi(&line[5]);
		JANUS_LOG(LOG_HUGE, "Intercepting message (%d bytes)\n", length);
		if(strstr(line, "-----"))
			started = TRUE;
	}
}


/* Plugin implementation */
int janus_sip_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_SIP_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_SIP_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_SIP_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		janus_config_print(config);

		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "local_ip");
		if(item && item->value) {
			/* Verify that the address is valid */
			struct ifaddrs *ifas = NULL;
			janus_network_address iface;
			janus_network_address_string_buffer ibuf;
			if(getifaddrs(&ifas) == -1) {
				JANUS_LOG(LOG_ERR, "Unable to acquire list of network devices/interfaces; some configurations may not work as expected...\n");
			} else {
				if(janus_network_lookup_interface(ifas, item->value, &iface) != 0) {
					JANUS_LOG(LOG_WARN, "Error setting local IP address to %s, falling back to detecting IP address...\n", item->value);
				} else {
					if(janus_network_address_to_string_buffer(&iface, &ibuf) != 0 || janus_network_address_string_buffer_is_null(&ibuf)) {
						JANUS_LOG(LOG_WARN, "Error getting local IP address from %s, falling back to detecting IP address...\n", item->value);
					} else {
						local_ip = g_strdup(janus_network_address_string_from_buffer(&ibuf));
					}
				}
				freeifaddrs(ifas);
			}
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "keepalive_interval");
		if(item && item->value)
			keepalive_interval = atoi(item->value);
		JANUS_LOG(LOG_VERB, "SIP keep-alive interval set to %d seconds\n", keepalive_interval);

		item = janus_config_get(config, config_general, janus_config_type_item, "register_ttl");
		if(item && item->value)
			register_ttl = atoi(item->value);
		JANUS_LOG(LOG_VERB, "SIP registration TTL set to %d seconds\n", register_ttl);

		item = janus_config_get(config, config_general, janus_config_type_item, "behind_nat");
		if(item && item->value)
			behind_nat = janus_is_true(item->value);

		item = janus_config_get(config, config_general, janus_config_type_item, "user_agent");
		if(item && item->value)
			user_agent = g_strdup(item->value);
		else
			user_agent = g_strdup("Janus WebRTC Server SIP Plugin "JANUS_SIP_VERSION_STRING);
		JANUS_LOG(LOG_VERB, "SIP User-Agent set to %s\n", user_agent);

		item = janus_config_get(config, config_general, janus_config_type_item, "rtp_port_range");
		if(item && item->value) {
			/* Split in min and max port */
			char *maxport = strrchr(item->value, '-');
			if(maxport != NULL) {
				*maxport = '\0';
				maxport++;
				rtp_range_min = atoi(item->value);
				rtp_range_max = atoi(maxport);
				maxport--;
				*maxport = '-';
			}
			if(rtp_range_min > rtp_range_max) {
				uint16_t temp_port = rtp_range_min;
				rtp_range_min = rtp_range_max;
				rtp_range_max = temp_port;
			}
			if(rtp_range_max == 0)
				rtp_range_max = 65535;
			JANUS_LOG(LOG_VERB, "SIP RTP/RTCP port range: %u -- %u\n", rtp_range_min, rtp_range_max);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(item != NULL && item->value != NULL)
			notify_events = janus_is_true(item->value);
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_SIP_NAME);
		}

		janus_config_destroy(config);
	}
	config = NULL;

	if(local_ip == NULL) {
		local_ip = janus_network_detect_local_ip_as_string(janus_network_query_options_any_ip);
		if(local_ip == NULL) {
			JANUS_LOG(LOG_WARN, "Couldn't find any address! using 127.0.0.1 as the local IP... (which is NOT going to work out of your machine)\n");
			local_ip = g_strdup("127.0.0.1");
		}
	}
	JANUS_LOG(LOG_VERB, "Local IP set to %s\n", local_ip);

#ifdef HAVE_SRTP_2
	/* Init randomizer (for randum numbers in SRTP) */
	RAND_poll();
#endif

	/* Setup sofia */
	su_init();
	if(notify_events && callback->events_is_enabled()) {
		/* Enable the transport logging, as we want to have access to the SIP messages */
		setenv("TPORT_LOG", "1", 1);
		su_log_redirect(NULL, janus_sip_sofia_logger, NULL);
	}

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_sip_session_destroy);
	identities = g_hash_table_new(g_str_hash, g_str_equal);
	callids = g_hash_table_new(g_str_hash, g_str_equal);
	messages = g_async_queue_new_full((GDestroyNotify) janus_sip_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("sip handler", janus_sip_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIP handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_SIP_NAME);
	return 0;
}

void janus_sip_destroy(void) {
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
	g_hash_table_destroy(callids);
	g_hash_table_destroy(identities);
	sessions = NULL;
	callids = NULL;
	identities = NULL;
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);

	/* Deinitialize sofia */
	su_deinit();

	g_free(local_ip);

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SIP_NAME);
}

int janus_sip_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_sip_get_version(void) {
	return JANUS_SIP_VERSION;
}

const char *janus_sip_get_version_string(void) {
	return JANUS_SIP_VERSION_STRING;
}

const char *janus_sip_get_description(void) {
	return JANUS_SIP_DESCRIPTION;
}

const char *janus_sip_get_name(void) {
	return JANUS_SIP_NAME;
}

const char *janus_sip_get_author(void) {
	return JANUS_SIP_AUTHOR;
}

const char *janus_sip_get_package(void) {
	return JANUS_SIP_PACKAGE;
}

static janus_sip_session *janus_sip_lookup_session(janus_plugin_session *handle) {
	janus_sip_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_sip_session *)handle->plugin_handle;
	}
	return session;
}

void janus_sip_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_sip_session *session = g_malloc0(sizeof(janus_sip_session));
	session->handle = handle;
	session->account.identity = NULL;
	session->account.force_udp = FALSE;
	session->account.force_tcp = FALSE;
	session->account.sips = TRUE;
	session->account.username = NULL;
	session->account.display_name = NULL;
	session->account.user_agent = NULL;
	session->account.authuser = NULL;
	session->account.secret = NULL;
	session->account.secret_type = janus_sip_secret_type_unknown;
	session->account.sip_port = 0;
	session->account.proxy = NULL;
	session->account.outbound_proxy = NULL;
	session->account.registration_status = janus_sip_registration_status_unregistered;
	session->status = janus_sip_call_status_idle;
	session->stack = NULL;
	session->transaction = NULL;
	session->callee = NULL;
	session->callid = NULL;
	session->sdp = NULL;
	session->media.remote_ip = NULL;
	session->media.earlymedia = FALSE;
	session->media.update = FALSE;
	session->media.ready = FALSE;
	session->media.require_srtp = FALSE;
	session->media.has_srtp_local = FALSE;
	session->media.has_srtp_remote = FALSE;
	session->media.srtp_profile = 0;
	session->media.on_hold = FALSE;
	session->media.has_audio = FALSE;
	session->media.audio_rtp_fd = -1;
	session->media.audio_rtcp_fd= -1;
	session->media.local_audio_rtp_port = 0;
	session->media.remote_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.remote_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	session->media.audio_ssrc_peer = 0;
	session->media.audio_pt = -1;
	session->media.audio_pt_name = NULL;
	session->media.audio_send = TRUE;
	session->media.pre_hold_audio_dir = JANUS_SDP_DEFAULT;
	session->media.has_video = FALSE;
	session->media.video_rtp_fd = -1;
	session->media.video_rtcp_fd= -1;
	session->media.local_video_rtp_port = 0;
	session->media.remote_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.remote_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	session->media.video_ssrc_peer = 0;
	session->media.simulcast_ssrc = 0;
	session->media.video_pt = -1;
	session->media.video_pt_name = NULL;
	session->media.video_send = TRUE;
	session->media.pre_hold_video_dir = JANUS_SDP_DEFAULT;
	/* Initialize the RTP context */
	janus_rtp_switching_context_reset(&session->media.context);
	session->media.pipefd[0] = -1;
	session->media.pipefd[1] = -1;
	session->media.updated = FALSE;
	janus_mutex_init(&session->rec_mutex);
	g_atomic_int_set(&session->hangingup, 0);
	g_atomic_int_set(&session->destroyed, 0);
	su_home_init(session->stack->s_home);
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_sip_session_free);

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_sip_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_sip_session *session = janus_sip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No SIP session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Destroying SIP session (%s)...\n", session->account.username ? session->account.username : "unregistered user");
	janus_sip_hangup_media_internal(handle);
	/* Shutdown the NUA */
	if(session->stack && session->stack->s_nua)
		nua_shutdown(session->stack->s_nua);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_sip_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_sip_session *session = janus_sip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);
	/* Provide some generic info, e.g., if we're in a call and with whom */
	json_t *info = json_object();
	json_object_set_new(info, "username", session->account.username ? json_string(session->account.username) : NULL);
	json_object_set_new(info, "authuser", session->account.authuser ? json_string(session->account.authuser) : NULL);
	json_object_set_new(info, "secret", session->account.secret ? json_string("(hidden)") : NULL);
	json_object_set_new(info, "display_name", session->account.display_name ? json_string(session->account.display_name) : NULL);
	json_object_set_new(info, "user_agent", session->account.user_agent ? json_string(session->account.user_agent) : NULL);
	json_object_set_new(info, "identity", session->account.identity ? json_string(session->account.identity) : NULL);
	json_object_set_new(info, "registration_status", json_string(janus_sip_registration_status_string(session->account.registration_status)));
	json_object_set_new(info, "call_status", json_string(janus_sip_call_status_string(session->status)));
	if(session->callee) {
		json_object_set_new(info, "callee", json_string(session->callee));
		json_object_set_new(info, "srtp-required", json_string(session->media.require_srtp ? "yes" : "no"));
		json_object_set_new(info, "sdes-local", json_string(session->media.has_srtp_local ? "yes" : "no"));
		json_object_set_new(info, "sdes-remote", json_string(session->media.has_srtp_remote ? "yes" : "no"));
	}
	if(session->arc || session->vrc || session->arc_peer || session->vrc_peer) {
		json_t *recording = json_object();
		if(session->arc && session->arc->filename)
			json_object_set_new(recording, "audio", json_string(session->arc->filename));
		if(session->vrc && session->vrc->filename)
			json_object_set_new(recording, "video", json_string(session->vrc->filename));
		if(session->arc_peer && session->arc_peer->filename)
			json_object_set_new(recording, "audio-peer", json_string(session->arc_peer->filename));
		if(session->vrc_peer && session->vrc_peer->filename)
			json_object_set_new(recording, "video-peer", json_string(session->vrc_peer->filename));
		json_object_set_new(info, "recording", recording);
	}
	json_object_set_new(info, "hangingup", json_integer(g_atomic_int_get(&session->hangingup)));
	json_object_set_new(info, "destroyed", json_integer(g_atomic_int_get(&session->destroyed)));
	janus_refcount_decrease(&session->ref);
	return info;
}

struct janus_plugin_result *janus_sip_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	janus_mutex_lock(&sessions_mutex);
	janus_sip_session *session = janus_sip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);

	janus_sip_message *msg = g_malloc(sizeof(janus_sip_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_sip_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] WebRTC media is now available\n", JANUS_SIP_PACKAGE, handle);
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_sip_session *session = janus_sip_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed)) {
		janus_mutex_unlock(&sessions_mutex);
		return;
	}
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_unlock(&sessions_mutex);
	/* TODO Only relay RTP/RTCP when we get this event */
}

void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_call_status_incall)
			return;
		/* Forward to our SIP peer */
		if(video) {
			if(!session->media.video_send) {
				/* Dropping video packet, peer doesn't want to receive it */
				return;
			}
			if(session->media.simulcast_ssrc) {
				/* The user is simulcasting: drop everything except the base layer */
				janus_rtp_header *header = (janus_rtp_header *)buf;
				uint32_t ssrc = ntohl(header->ssrc);
				if(ssrc != session->media.simulcast_ssrc) {
					JANUS_LOG(LOG_DBG, "Dropping packet (not base simulcast substream)\n");
					return;
				}
			}
			if(session->media.video_ssrc == 0) {
				janus_rtp_header *header = (janus_rtp_header *)buf;
				session->media.video_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP video SSRC: %"SCNu32"\n", session->media.video_ssrc);
			}
			if(session->media.has_video && session->media.video_rtp_fd != -1) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(session->vrc, buf, len);
				/* Is SRTP involved? */
				if(session->media.has_srtp_local) {
					char sbuf[2048];
					memcpy(&sbuf, buf, len);
					int protected = len;
					int res = srtp_protect(session->media.video_srtp_out, &sbuf, &protected);
					if(res != srtp_err_status_ok) {
						janus_rtp_header *header = (janus_rtp_header *)&sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_ERR, "[SIP-%s] Video SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session->account.username, janus_srtp_error_str(res), len, protected, timestamp, seq);
					} else {
						/* Forward the frame to the peer */
						if(send(session->media.video_rtp_fd, sbuf, protected, 0) < 0) {
							janus_rtp_header *header = (janus_rtp_header *)&sbuf;
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending SRTP video packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
								session->account.username, strerror(errno), protected, timestamp, seq);
						}
					}
				} else {
					/* Forward the frame to the peer */
					if(send(session->media.video_rtp_fd, buf, len, 0) < 0) {
						janus_rtp_header *header = (janus_rtp_header *)&buf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending RTP video packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session->account.username, strerror(errno), len, timestamp, seq);
					}
				}
			}
		} else {
			if(!session->media.audio_send) {
				/* Dropping audio packet, peer doesn't want to receive it */
				return;
			}
			if(session->media.audio_ssrc == 0) {
				janus_rtp_header *header = (janus_rtp_header *)buf;
				session->media.audio_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP audio SSRC: %"SCNu32"\n", session->media.audio_ssrc);
			}
			if(session->media.has_audio && session->media.audio_rtp_fd != -1) {
				/* Save the frame if we're recording */
				janus_recorder_save_frame(session->arc, buf, len);
				/* Is SRTP involved? */
				if(session->media.has_srtp_local) {
					char sbuf[2048];
					memcpy(&sbuf, buf, len);
					int protected = len;
					int res = srtp_protect(session->media.audio_srtp_out, &sbuf, &protected);
					if(res != srtp_err_status_ok) {
						janus_rtp_header *header = (janus_rtp_header *)&sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_ERR, "[SIP-%s] Audio SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session->account.username, janus_srtp_error_str(res), len, protected, timestamp, seq);
					} else {
						/* Forward the frame to the peer */
						if(send(session->media.audio_rtp_fd, sbuf, protected, 0) < 0) {
							janus_rtp_header *header = (janus_rtp_header *)&sbuf;
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending SRTP audio packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
								session->account.username, strerror(errno), protected, timestamp, seq);
						}
					}
				} else {
					/* Forward the frame to the peer */
					if(send(session->media.audio_rtp_fd, buf, len, 0) < 0) {
						janus_rtp_header *header = (janus_rtp_header *)&buf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending RTP audio packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session->account.username, strerror(errno), len, timestamp, seq);
					}
				}
			}
		}
	}
}

void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || g_atomic_int_get(&handle->stopped) || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_call_status_incall)
			return;
		/* Forward to our SIP peer */
		if(video) {
			if(session->media.has_video && session->media.video_rtcp_fd != -1) {
				/* Fix SSRCs as the Janus core does */
				JANUS_LOG(LOG_HUGE, "[SIP] Fixing SSRCs (local %u, peer %u)\n",
					session->media.video_ssrc, session->media.video_ssrc_peer);
				janus_rtcp_fix_ssrc(NULL, (char *)buf, len, 1, session->media.video_ssrc, session->media.video_ssrc_peer);
				/* Is SRTP involved? */
				if(session->media.has_srtp_local) {
					char sbuf[2048];
					memcpy(&sbuf, buf, len);
					int protected = len;
					int res = srtp_protect_rtcp(session->media.video_srtp_out, &sbuf, &protected);
					if(res != srtp_err_status_ok) {
						JANUS_LOG(LOG_ERR, "[SIP-%s] Video SRTCP protect error... %s (len=%d-->%d)...\n",
							session->account.username, janus_srtp_error_str(res), len, protected);
					} else {
						/* Forward the message to the peer */
						if(send(session->media.video_rtcp_fd, sbuf, protected, 0) < 0) {
							JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending SRTCP video packet... %s (len=%d)...\n",
								session->account.username, strerror(errno), protected);
						}
					}
				} else {
					/* Forward the message to the peer */
					if(send(session->media.video_rtcp_fd, buf, len, 0) < 0) {
						JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending RTCP video packet... %s (len=%d)...\n",
							session->account.username, strerror(errno), len);
					}
				}
			}
		} else {
			if(session->media.has_audio && session->media.audio_rtcp_fd != -1) {
				/* Fix SSRCs as the Janus core does */
				JANUS_LOG(LOG_HUGE, "[SIP] Fixing SSRCs (local %u, peer %u)\n",
					session->media.audio_ssrc, session->media.audio_ssrc_peer);
				janus_rtcp_fix_ssrc(NULL, (char *)buf, len, 1, session->media.audio_ssrc, session->media.audio_ssrc_peer);
				/* Is SRTP involved? */
				if(session->media.has_srtp_local) {
					char sbuf[2048];
					memcpy(&sbuf, buf, len);
					int protected = len;
					int res = srtp_protect_rtcp(session->media.audio_srtp_out, &sbuf, &protected);
					if(res != srtp_err_status_ok) {
						JANUS_LOG(LOG_ERR, "[SIP-%s] Audio SRTCP protect error... %s (len=%d-->%d)...\n",
							session->account.username, janus_srtp_error_str(res), len, protected);
					} else {
						/* Forward the message to the peer */
						if(send(session->media.audio_rtcp_fd, sbuf, protected, 0) < 0) {
							JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending SRTCP audio packet... %s (len=%d)...\n",
								session->account.username, strerror(errno), protected);
						}
					}
				} else {
					/* Forward the message to the peer */
					if(send(session->media.audio_rtcp_fd, buf, len, 0) < 0) {
						JANUS_LOG(LOG_HUGE, "[SIP-%s] Error sending RTCP audio packet... %s (len=%d)...\n",
							session->account.username, strerror(errno), len);
					}
				}
			}
		}
	}
}

static void janus_sip_recorder_close(janus_sip_session *session,
		gboolean stop_audio, gboolean stop_audio_peer, gboolean stop_video, gboolean stop_video_peer) {
	if(session->arc && stop_audio) {
		janus_recorder *rc = session->arc;
		session->arc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed user's audio recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	if(session->arc_peer && stop_audio_peer) {
		janus_recorder *rc = session->arc_peer;
		session->arc_peer = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed peer's audio recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	if(session->vrc && stop_video) {
		janus_recorder *rc = session->vrc;
		session->vrc = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed user's video recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
	if(session->vrc_peer && stop_video_peer) {
		janus_recorder *rc = session->vrc_peer;
		session->vrc_peer = NULL;
		janus_recorder_close(rc);
		JANUS_LOG(LOG_INFO, "Closed peer's video recording %s\n", rc->filename ? rc->filename : "??");
		janus_recorder_destroy(rc);
	}
}

void janus_sip_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "[%s-%p] No WebRTC media anymore\n", JANUS_SIP_PACKAGE, handle);
	janus_mutex_lock(&sessions_mutex);
	janus_sip_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_sip_hangup_media_internal(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_sip_session *session = janus_sip_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	session->media.simulcast_ssrc = 0;
	if(!(session->status == janus_sip_call_status_inviting ||
		 session->status == janus_sip_call_status_invited ||
		 session->status == janus_sip_call_status_incall)) {
		g_atomic_int_set(&session->hangingup, 0);
		return;
	}
	/* Do cleanup if media thread has not been created */
	if(!session->media.ready && !session->relayer_thread) {
		janus_sip_media_cleanup(session);
	}
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	janus_sip_recorder_close(session, TRUE, TRUE, TRUE, TRUE);
	janus_mutex_unlock(&session->rec_mutex);
	/* FIXME Simulate a "hangup" coming from the browser */
	janus_refcount_increase(&session->ref);
	janus_sip_message *msg = g_malloc(sizeof(janus_sip_message));
	msg->handle = handle;
	msg->message = json_pack("{ss}", "request", "hangup");
	msg->transaction = NULL;
	msg->jsep = NULL;
	g_async_queue_push(messages, msg);
	g_atomic_int_set(&session->hangingup, 0);
}

/* Thread to handle incoming messages */
static void *janus_sip_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining SIP handler thread\n");
	janus_sip_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_sip_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_sip_session *session = janus_sip_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_sip_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_sip_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_SIP_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_SIP_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *result = NULL;

		if(!strcasecmp(request_text, "register")) {
			/* Send a REGISTER */
			JANUS_VALIDATE_JSON_OBJECT(root, register_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			gboolean refresh = json_is_true(json_object_get(root, "refresh"));
			if(session->account.registration_status > janus_sip_registration_status_unregistered && !refresh) {
				JANUS_LOG(LOG_ERR, "Already registered (%s)\n", session->account.username);
				error_code = JANUS_SIP_ERROR_ALREADY_REGISTERED;
				g_snprintf(error_cause, 512, "Already registered (%s)", session->account.username);
				goto error;
			}
			/* Parse the request */
			gboolean guest = FALSE;
			json_t *type = json_object_get(root, "type");
			if(type != NULL) {
				const char *type_text = json_string_value(type);
				if(!strcmp(type_text, "guest")) {
					JANUS_LOG(LOG_INFO, "Registering as a guest\n");
					guest = TRUE;
				} else {
					JANUS_LOG(LOG_WARN, "Unknown type '%s', ignoring...\n", type_text);
				}
			}

			gboolean send_register = TRUE;
			json_t *do_register = json_object_get(root, "send_register");
			if(do_register != NULL) {
				if(guest) {
					JANUS_LOG(LOG_ERR, "Conflicting elements: send_register cannot be true if guest is true\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Conflicting elements: send_register cannot be true if guest is true");
					goto error;
				}
				send_register = json_is_true(do_register);
			}

			gboolean sips = TRUE;
			json_t *do_sips = json_object_get(root, "sips");
			if(do_sips != NULL) {
				sips = json_is_true(do_sips);
			}
			gboolean force_udp = FALSE;
			json_t *do_udp = json_object_get(root, "force_udp");
			if(do_udp != NULL) {
				force_udp = json_is_true(do_udp);
			}
			gboolean force_tcp = FALSE;
			json_t *do_tcp = json_object_get(root, "force_tcp");
			if(do_tcp != NULL) {
				force_tcp = json_is_true(do_tcp);
			}
			if(force_udp && force_tcp) {
				JANUS_LOG(LOG_ERR, "Conflicting elements: force_udp and force_tcp cannot both be true\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Conflicting elements: force_udp and force_tcp cannot both be true");
				goto error;
			}

			/* Parse addresses */
			json_t *proxy = json_object_get(root, "proxy");
			const char *proxy_text = NULL;
			if(proxy && !json_is_null(proxy)) {
				/* Has to be validated separately because it could be null */
				JANUS_VALIDATE_JSON_OBJECT(root, proxy_parameters,
					error_code, error_cause, TRUE,
					JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				proxy_text = json_string_value(proxy);
				janus_sip_uri_t proxy_uri;
				if(janus_sip_parse_proxy_uri(&proxy_uri, proxy_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid proxy address %s\n", proxy_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					g_snprintf(error_cause, 512, "Invalid proxy address %s\n", proxy_text);
					goto error;
				}
			}
			json_t *outbound_proxy = json_object_get(root, "outbound_proxy");
			const char *obproxy_text = NULL;
			if (outbound_proxy && !json_is_null(outbound_proxy)) {
				/* Has to be validated separately because it could be null */
				JANUS_VALIDATE_JSON_OBJECT(root, proxy_parameters,
					error_code, error_cause, TRUE,
					JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				obproxy_text = json_string_value(outbound_proxy);
				janus_sip_uri_t outbound_proxy_uri;
				if (janus_sip_parse_proxy_uri(&outbound_proxy_uri, obproxy_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid outbound_proxy address %s\n", obproxy_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					g_snprintf(error_cause, 512, "Invalid outbound_proxy address %s\n", obproxy_text);
					goto error;
				}
			}

			/* Parse register TTL */
			int ttl = register_ttl;
			json_t *reg_ttl = json_object_get(root, "register_ttl");
			if(reg_ttl && json_is_integer(reg_ttl))
				ttl = json_integer_value(reg_ttl);
			if(ttl <= 0)
				ttl = JANUS_DEFAULT_REGISTER_TTL;

			/* Parse display name */
			const char* display_name_text = NULL;
			json_t *display_name = json_object_get(root, "display_name");
			if(display_name && json_is_string(display_name))
				display_name_text = json_string_value(display_name);

			/* Parse user agent */
			const char* user_agent_text = NULL;
			json_t *user_agent = json_object_get(root, "user_agent");
			if(user_agent && json_is_string(user_agent))
				user_agent_text = json_string_value(user_agent);

			/* Now the user part (always needed, even for the guest case) */
			json_t *username = json_object_get(root, "username");
			if(!username) {
				/* The username is mandatory even when registering as guests */
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (username)");
				goto error;
			}
			const char *username_text = NULL;
			const char *secret_text = NULL;
			const char *authuser_text = NULL;
			janus_sip_secret_type secret_type = janus_sip_secret_type_plaintext;
			janus_sip_uri_t username_uri;
			char user_id[256];
			/* Parse address */
			username_text = json_string_value(username);
			if(janus_sip_parse_uri(&username_uri, username_text) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				g_snprintf(error_cause, 512, "Invalid user address %s\n", username_text);
				goto error;
			}
			g_strlcpy(user_id, username_uri.url->url_user, sizeof(user_id));
			if(guest) {
				/* Not needed, we can stop here: just say we're registered */
				JANUS_LOG(LOG_INFO, "Guest will have username %s\n", user_id);
				send_register = FALSE;
			} else {
				json_t *secret = json_object_get(root, "secret");
				json_t *ha1_secret = json_object_get(root, "ha1_secret");
				json_t *authuser = json_object_get(root, "authuser");
				if(!secret && !ha1_secret) {
					JANUS_LOG(LOG_ERR, "Missing element (secret or ha1_secret)\n");
					error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, 512, "Missing element (secret or ha1_secret)");
					goto error;
				}
				if(secret && ha1_secret) {
					JANUS_LOG(LOG_ERR, "Conflicting elements specified (secret and ha1_secret)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Conflicting elements specified (secret and ha1_secret)");
					goto error;
				}
				if(secret) {
					secret_text = json_string_value(secret);
					secret_type = janus_sip_secret_type_plaintext;
				} else {
					secret_text = json_string_value(ha1_secret);
					secret_type = janus_sip_secret_type_hashed;
				}
				if(authuser) {
					authuser_text = json_string_value(authuser);
				}
				/* Got the values, try registering now */
				JANUS_LOG(LOG_VERB, "Registering user %s (auth=%s, secret %s) @ %s through %s (outbound proxy: %s)\n",
					username_text, secret_text, username_uri.url->url_host,
					authuser_text != NULL ? authuser_text : username_text,
					proxy_text != NULL ? proxy_text : "(null)",
					obproxy_text != NULL ? obproxy_text : "none");
			}
			/* If this is a refresh, get rid of the old values */
			if(refresh) {
				/* Cleanup old values */
				if(session->account.identity != NULL) {
					janus_mutex_lock(&sessions_mutex);
					g_hash_table_remove(identities, session->account.identity);
					janus_mutex_unlock(&sessions_mutex);
					g_free(session->account.identity);
				}
				session->account.identity = NULL;
				session->account.force_udp = FALSE;
				session->account.force_tcp = FALSE;
				session->account.sips = TRUE;
				if(session->account.username != NULL)
					g_free(session->account.username);
				session->account.username = NULL;
				if(session->account.display_name != NULL)
					g_free(session->account.display_name);
				session->account.display_name = NULL;
				if(session->account.authuser != NULL)
					g_free(session->account.authuser);
				session->account.authuser = NULL;
				if(session->account.secret != NULL)
					g_free(session->account.secret);
				session->account.secret = NULL;
				session->account.secret_type = janus_sip_secret_type_unknown;
				if(session->account.proxy != NULL)
					g_free(session->account.proxy);
				session->account.proxy = NULL;
				if(session->account.outbound_proxy != NULL)
					g_free(session->account.outbound_proxy);
				session->account.outbound_proxy = NULL;
				if(session->account.user_agent != NULL)
					g_free(session->account.user_agent);
				session->account.user_agent = NULL;
				session->account.registration_status = janus_sip_registration_status_unregistered;
			}
			session->account.identity = g_strdup(username_text);
			janus_mutex_lock(&sessions_mutex);
			g_hash_table_insert(identities, session->account.identity, session);
			janus_mutex_unlock(&sessions_mutex);
			session->account.force_udp = force_udp;
			session->account.force_tcp = force_tcp;
			session->account.sips = sips;
			session->account.username = g_strdup(user_id);
			session->account.authuser = g_strdup(authuser_text ? authuser_text : user_id);
			session->account.secret = secret_text ? g_strdup(secret_text) : NULL;
			session->account.secret_type = secret_type;
			if(display_name_text) {
				session->account.display_name = g_strdup(display_name_text);
			}
			if(user_agent_text) {
				session->account.user_agent = g_strdup(user_agent_text);
			}
			if(proxy_text) {
				session->account.proxy = g_strdup(proxy_text);
			}
			if(obproxy_text) {
				session->account.outbound_proxy = g_strdup(obproxy_text);
			}

			session->account.registration_status = janus_sip_registration_status_registering;
			if(!refresh && session->stack == NULL) {
				/* Start the thread first */
				GError *error = NULL;
				char tname[16];
				g_snprintf(tname, sizeof(tname), "sip %s", session->account.username);
				janus_refcount_increase(&session->ref);
				g_thread_try_new(tname, janus_sip_sofia_thread, session, &error);
				if(error != NULL) {
					janus_refcount_decrease(&session->ref);
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIP Sofia thread...\n", error->code, error->message ? error->message : "??");
					error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Got error %d (%s) trying to launch the SIP Sofia thread", error->code, error->message ? error->message : "??");
					goto error;
				}
				long int timeout = 0;
				while(session->stack == NULL || session->stack->s_nua == NULL) {
					g_usleep(100000);
					timeout += 100000;
					if(timeout >= 2000000) {
						break;
					}
				}
				if(timeout >= 2000000) {
					JANUS_LOG(LOG_ERR, "Two seconds passed and still no NUA, problems with the thread?\n");
					error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Two seconds passed and still no NUA, problems with the thread?");
					goto error;
				}
			}
			if(session->stack->s_nh_r != NULL) {
				nua_handle_destroy(session->stack->s_nh_r);
				session->stack->s_nh_r = NULL;
			}

			if(send_register) {
				/* Check if the REGISTER needs to be enriched with custom headers */
				char custom_headers[2048];
				janus_sip_parse_custom_headers(root, (char *)&custom_headers);
				session->stack->s_nh_r = nua_handle(session->stack->s_nua, session, TAG_END());
				if(session->stack->s_nh_r == NULL) {
					JANUS_LOG(LOG_ERR, "NUA Handle for REGISTER still null??\n");
					error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
					g_snprintf(error_cause, 512, "Invalid NUA Handle");
					goto error;
				}
				char ttl_text[20];
				g_snprintf(ttl_text, sizeof(ttl_text), "%d", ttl);
				/* Send the REGISTER */
				nua_register(session->stack->s_nh_r,
					NUTAG_M_USERNAME(session->account.authuser),
					NUTAG_M_DISPLAY(session->account.display_name),
					SIPTAG_FROM_STR(username_text),
					SIPTAG_TO_STR(username_text),
					TAG_IF(strlen(custom_headers) > 0, SIPTAG_HEADER_STR(custom_headers)),
					SIPTAG_EXPIRES_STR(ttl_text),
					NUTAG_REGISTRAR(proxy_text),
					NUTAG_PROXY(obproxy_text),
					TAG_END());
				result = json_object();
				json_object_set_new(result, "event", json_string("registering"));
			} else {
				JANUS_LOG(LOG_VERB, "Not sending a SIP REGISTER: either send_register was set to false or guest mode was enabled\n");
				session->account.registration_status = janus_sip_registration_status_disabled;
				result = json_object();
				json_object_set_new(result, "event", json_string("registered"));
				json_object_set_new(result, "username", json_string(session->account.username));
				json_object_set_new(result, "register_sent", json_false());
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("registered"));
					json_object_set_new(info, "identity", json_string(session->account.identity));
					json_object_set_new(info, "type", json_string("guest"));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				}
			}
		} else if(!strcasecmp(request_text, "unregister")) {
			if(session->stack == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (register first)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (register first)");
				goto error;
			}
			if(session->account.registration_status < janus_sip_registration_status_registered) {
				JANUS_LOG(LOG_ERR, "Wrong state (not registered)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not registered)");
				goto error;
			}
			if(session->stack->s_nh_r == NULL) {
				JANUS_LOG(LOG_ERR, "NUA Handle for REGISTER still null??\n");
				error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
				g_snprintf(error_cause, 512, "Invalid NUA Handle");
				goto error;
			}
			/* Unregister now */
			session->account.registration_status = janus_sip_registration_status_unregistering;
			nua_unregister(session->stack->s_nh_r, TAG_END());
			result = json_object();
			json_object_set_new(result, "event", json_string("unregistering"));
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->stack == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (register first)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (register first)");
				goto error;
			}
			if(session->account.registration_status != janus_sip_registration_status_registered &&
					session->account.registration_status != janus_sip_registration_status_disabled) {
				JANUS_LOG(LOG_ERR, "Wrong state (not registered)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not registered)");
				goto error;
			}
			if(session->status >= janus_sip_call_status_inviting) {
				JANUS_LOG(LOG_ERR, "Wrong state (already in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (already in a call? status=%s)", janus_sip_call_status_string(session->status));
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, call_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *secret = json_object_get(root, "secret");
			json_t *ha1_secret = json_object_get(root, "ha1_secret");
			json_t *authuser = json_object_get(root, "authuser");
			if(secret && ha1_secret) {
				JANUS_LOG(LOG_ERR, "Conflicting elements specified (secret and ha1_secret)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Conflicting elements specified (secret and ha1_secret)");
				goto error;
			}
			json_t *uri = json_object_get(root, "uri");
			/* Check if the INVITE needs to be enriched with custom headers */
			char custom_headers[2048];
			janus_sip_parse_custom_headers(root, (char *)&custom_headers);
			/* SDES-SRTP is disabled by default, let's see if we need to enable it */
			gboolean offer_srtp = FALSE, require_srtp = FALSE;
			janus_srtp_profile srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
			json_t *srtp = json_object_get(root, "srtp");
			if(srtp) {
				const char *srtp_text = json_string_value(srtp);
				if(!strcasecmp(srtp_text, "sdes_optional")) {
					/* Negotiate SDES, but make it optional */
					offer_srtp = TRUE;
				} else if(!strcasecmp(srtp_text, "sdes_mandatory")) {
					/* Negotiate SDES, and require it */
					offer_srtp = TRUE;
					require_srtp = TRUE;
				} else {
					JANUS_LOG(LOG_ERR, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)");
					goto error;
				}
				if(offer_srtp) {
					/* Any SRTP profile different from the default? */
					srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
					const char *profile = json_string_value(json_object_get(root, "srtp_profile"));
					if(profile) {
						if(!strcmp(profile, "AES_CM_128_HMAC_SHA1_32")) {
							srtp_profile = JANUS_SRTP_AES128_CM_SHA1_32;
						} else if(!strcmp(profile, "AES_CM_128_HMAC_SHA1_80")) {
							srtp_profile = JANUS_SRTP_AES128_CM_SHA1_80;
#ifdef HAVE_SRTP_AESGCM
						} else if(!strcmp(profile, "AEAD_AES_128_GCM")) {
							srtp_profile = JANUS_SRTP_AEAD_AES_128_GCM;
						} else if(!strcmp(profile, "AEAD_AES_256_GCM")) {
							srtp_profile = JANUS_SRTP_AEAD_AES_256_GCM;
#endif
						} else {
							JANUS_LOG(LOG_ERR, "Invalid element (unsupported SRTP profile)\n");
							error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
							g_snprintf(error_cause, 512, "Invalid element (unsupported SRTP profile)");
							goto error;
						}
					}
				}
			}
			/* Parse address */
			const char *uri_text = json_string_value(uri);
			janus_sip_uri_t target_uri;
			if(janus_sip_parse_uri(&target_uri, uri_text) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				g_snprintf(error_cause, 512, "Invalid user address %s\n", uri_text);
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			if(strstr(msg_sdp, "m=application")) {
				JANUS_LOG(LOG_ERR, "The SIP plugin does not support DataChannels\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "The SIP plugin does not support DataChannels");
				goto error;
			}
			JANUS_LOG(LOG_VERB, "%s is calling %s\n", session->account.username, uri_text);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			/* Clean up SRTP stuff from before first, in case it's still needed */
			janus_sip_srtp_cleanup(session);
			session->media.require_srtp = require_srtp;
			session->media.has_srtp_local = offer_srtp;
			session->media.srtp_profile = srtp_profile;
			if(offer_srtp) {
				JANUS_LOG(LOG_VERB, "Going to negotiate SDES-SRTP (%s)...\n", require_srtp ? "mandatory" : "optional");
			}
			/* Parse the SDP we got, manipulate some things, and generate a new one */
			char sdperror[100];
			janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!parsed_sdp) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg_sdp, "m=audio") && !strstr(msg_sdp, "m=audio 0")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate audio...\n");
				session->media.has_audio = TRUE;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg_sdp, "m=video") && !strstr(msg_sdp, "m=video 0")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate video...\n");
				session->media.has_video = TRUE;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = janus_sip_sdp_manipulate(session, parsed_sdp, FALSE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Error manipulating SDP\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Error manipulating SDP");
				goto error;
			}
			/* Take note of the SDP (may be useful for UPDATEs or re-INVITEs) */
			janus_sdp_destroy(session->sdp);
			session->sdp = parsed_sdp;
			JANUS_LOG(LOG_VERB, "Prepared SDP for INVITE:\n%s", sdp);
			/* Prepare the From header */
			char from_hdr[1024];
			if(session->account.display_name) {
				g_snprintf(from_hdr, sizeof(from_hdr), "\"%s\" <%s>", session->account.display_name, session->account.identity);
			} else {
				g_snprintf(from_hdr, sizeof(from_hdr), "%s", session->account.identity);
			}
			/* Prepare the stack */
			if(session->stack->s_nh_i != NULL)
				nua_handle_destroy(session->stack->s_nh_i);
			session->stack->s_nh_i = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for INVITE still null??\n");
				g_free(sdp);
				session->sdp = NULL;
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
				g_snprintf(error_cause, 512, "Invalid NUA Handle");
				goto error;
			}
			g_atomic_int_set(&session->hangingup, 0);
			session->status = janus_sip_call_status_inviting;
			char *callid;
			json_t *request_callid = json_object_get(root, "call_id");
			/* Take call-id from request, if it exists */
			if (request_callid) {
				callid = g_strdup(json_string_value(request_callid));
			} else {
				/* If call-id does not exist in request, create a random one */
				callid = g_malloc0(24);
				janus_sip_random_string(24, callid);
			}
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("calling"));
				json_object_set_new(info, "callee", json_string(uri_text));
				json_object_set_new(info, "call-id", json_string(callid));
				json_object_set_new(info, "sdp", json_string(sdp));
				gateway->notify_event(&janus_sip_plugin, session->handle, info);
			}
			/* If the user negotiated simulcasting, just stick with the base substream */
			json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
			if(msg_simulcast) {
				JANUS_LOG(LOG_WARN, "Client negotiated simulcasting which we don't do here, falling back to base substream...\n");
				session->media.simulcast_ssrc = json_integer_value(json_object_get(msg_simulcast, "ssrc-0"));
			}
			/* Check if there are new credentials to authenticate the INVITE */
			if(authuser) {
				JANUS_LOG(LOG_VERB, "Updating credentials (authuser) for authenticating the INVITE\n");
				g_free(session->account.authuser);
				session->account.authuser = g_strdup(json_string_value(authuser));
			}
			if(secret) {
				JANUS_LOG(LOG_VERB, "Updating credentials (secret) for authenticating the INVITE\n");
				g_free(session->account.secret);
				session->account.secret = g_strdup(json_string_value(secret));
				session->account.secret_type = janus_sip_secret_type_plaintext;
			} else if(ha1_secret) {
				JANUS_LOG(LOG_VERB, "Updating credentials (ha1_secret) for authenticating the INVITE\n");
				g_free(session->account.secret);
				session->account.secret = g_strdup(json_string_value(ha1_secret));
				session->account.secret_type = janus_sip_secret_type_hashed;
			}
			/* Send INVITE */
			g_free(session->callee);
			session->callee = g_strdup(uri_text);
			g_free(session->callid);
			session->callid = callid;
			janus_mutex_lock(&sessions_mutex);
			g_hash_table_insert(callids, session->callid, session);
			janus_mutex_unlock(&sessions_mutex);
			nua_invite(session->stack->s_nh_i,
				SIPTAG_FROM_STR(from_hdr),
				SIPTAG_TO_STR(uri_text),
				SIPTAG_CALL_ID_STR(callid),
				SOATAG_USER_SDP_STR(sdp),
				NUTAG_PROXY(session->account.outbound_proxy),
				TAG_IF(strlen(custom_headers) > 0, SIPTAG_HEADER_STR(custom_headers)),
				NUTAG_AUTOANSWER(0),
				NUTAG_AUTOACK(FALSE),
				TAG_END());
			g_free(sdp);
			session->callee = g_strdup(uri_text);
			g_free(session->transaction);
			session->transaction = msg->transaction ? g_strdup(msg->transaction) : NULL;
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("calling"));
		} else if(!strcasecmp(request_text, "accept")) {
			if(session->status != janus_sip_call_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? status=%s)\n", janus_sip_call_status_string(session->status));
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not invited? status=%s)", janus_sip_call_status_string(session->status));
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no caller?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no caller?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, accept_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *srtp = json_object_get(root, "srtp");
			gboolean answer_srtp = FALSE;
			if(srtp) {
				const char *srtp_text = json_string_value(srtp);
				if(!strcasecmp(srtp_text, "sdes_optional")) {
					/* Negotiate SDES, but make it optional */
					answer_srtp = TRUE;
				} else if(!strcasecmp(srtp_text, "sdes_mandatory")) {
					/* Negotiate SDES, and require it */
					answer_srtp = TRUE;
					session->media.require_srtp = TRUE;
				} else {
					JANUS_LOG(LOG_ERR, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)");
					goto error;
				}
			}
			if(session->media.require_srtp && !session->media.has_srtp_remote) {
				JANUS_LOG(LOG_ERR, "Can't accept the call: SDES-SRTP required, but caller didn't offer it\n");
				error_code = JANUS_SIP_ERROR_TOO_STRICT;
				g_snprintf(error_cause, 512, "Can't accept the call: SDES-SRTP required, but caller didn't offer it");
				goto error;
			}
			answer_srtp = answer_srtp || session->media.has_srtp_remote;
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			/* Accept a call from another peer */
			JANUS_LOG(LOG_VERB, "We're accepting the call from %s\n", session->callee);
			gboolean answer = !strcasecmp(msg_sdp_type, "answer");
			if(!answer) {
				JANUS_LOG(LOG_VERB, "This is a response to an offerless INVITE\n");
			}
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			session->media.has_srtp_local = answer_srtp;
			if(answer_srtp) {
				JANUS_LOG(LOG_VERB, "Going to negotiate SDES-SRTP (%s)...\n", session->media.require_srtp ? "mandatory" : "optional");
			}
			/* Parse the SDP we got, manipulate some things, and generate a new one */
			char sdperror[100];
			janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!parsed_sdp) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg_sdp, "m=audio") && !strstr(msg_sdp, "m=audio 0")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate audio...\n");
				session->media.has_audio = TRUE;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg_sdp, "m=video") && !strstr(msg_sdp, "m=video 0")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate video...\n");
				session->media.has_video = TRUE;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = janus_sip_sdp_manipulate(session, parsed_sdp, TRUE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			if(session->media.audio_pt > -1) {
				session->media.audio_pt_name = janus_get_codec_from_pt(sdp, session->media.audio_pt);
				JANUS_LOG(LOG_VERB, "Detected audio codec: %d (%s)\n", session->media.audio_pt, session->media.audio_pt_name);
			}
			if(session->media.video_pt > -1) {
				session->media.video_pt_name = janus_get_codec_from_pt(sdp, session->media.video_pt);
				JANUS_LOG(LOG_VERB, "Detected video codec: %d (%s)\n", session->media.video_pt, session->media.video_pt_name);
			}
			/* Take note of the SDP (may be useful for UPDATEs or re-INVITEs) */
			janus_sdp_destroy(session->sdp);
			session->sdp = parsed_sdp;
			JANUS_LOG(LOG_VERB, "Prepared SDP for 200 OK:\n%s", sdp);
			/* If the user negotiated simulcasting, just stick with the base substream */
			json_t *msg_simulcast = json_object_get(msg->jsep, "simulcast");
			if(msg_simulcast) {
				JANUS_LOG(LOG_WARN, "Client negotiated simulcasting which we don't do here, falling back to base substream...\n");
				session->media.simulcast_ssrc = json_integer_value(json_object_get(msg_simulcast, "ssrc-0"));
			}
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string(answer ? "accepted" : "accepting"));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				gateway->notify_event(&janus_sip_plugin, session->handle, info);
			}
			/* Check if the OK needs to be enriched with custom headers */
			char custom_headers[2048];
			janus_sip_parse_custom_headers(root, (char *)&custom_headers);
			/* Send 200 OK */
			if(!answer) {
				if(session->transaction)
					g_free(session->transaction);
				session->transaction = msg->transaction ? g_strdup(msg->transaction) : NULL;
			}
			g_atomic_int_set(&session->hangingup, 0);
			session->status = janus_sip_call_status_incall;
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			nua_respond(session->stack->s_nh_i,
				200, sip_status_phrase(200),
				SOATAG_USER_SDP_STR(sdp),
				SOATAG_RTP_SELECT(SOA_RTP_SELECT_COMMON),
				NUTAG_AUTOANSWER(0),
				TAG_IF(strlen(custom_headers) > 0, SIPTAG_HEADER_STR(custom_headers)),
				TAG_END());
			g_free(sdp);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string(answer ? "accepted" : "accepting"));
			if(answer) {
				/* Start the media */
				session->media.ready = TRUE;	/* FIXME Maybe we need a better way to signal this */
				GError *error = NULL;
				char tname[16];
				g_snprintf(tname, sizeof(tname), "siprtp %s", session->account.username);
				janus_refcount_increase(&session->ref);
				session->relayer_thread = g_thread_try_new(tname, janus_sip_relay_thread, session, &error);
				if(error != NULL) {
					session->relayer_thread = NULL;
					session->media.ready = FALSE;
					janus_refcount_decrease(&session->ref);
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
				}
			}
		} else if(!strcasecmp(request_text, "update")) {
			/* Update an existing call */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			if(session->sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no local SDP?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no local SDP?)");
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP update\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP update");
				goto error;
			}
			if(!json_is_true(json_object_get(msg->jsep, "update"))) {
				JANUS_LOG(LOG_ERR, "Missing SDP update\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP update");
				goto error;
			}
			/* Parse the SDP we got, manipulate some things, and generate a new one */
			char sdperror[100];
			janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!parsed_sdp) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			session->sdp->o_version++;
			char *sdp = janus_sip_sdp_manipulate(session, parsed_sdp, FALSE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Error manipulating SDP\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Error manipulating SDP");
				goto error;
			}
			/* Take note of the new SDP */
			janus_sdp_destroy(session->sdp);
			session->sdp = parsed_sdp;
			session->media.update = TRUE;
			JANUS_LOG(LOG_VERB, "Prepared SDP for update:\n%s", sdp);
			nua_invite(session->stack->s_nh_i,
				SOATAG_USER_SDP_STR(sdp),
				TAG_END());
			g_free(sdp);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("updating"));
		} else if(!strcasecmp(request_text, "decline")) {
			/* Reject an incoming call */
			if(session->status != janus_sip_call_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? status=%s)\n", janus_sip_call_status_string(session->status));
				/* Ignore */
				janus_sip_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			session->media.earlymedia = FALSE;
			session->media.update = FALSE;
			session->media.ready = FALSE;
			session->media.on_hold = FALSE;
			session->status = janus_sip_call_status_closing;
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			int response_code = 486;
			json_t *code_json = json_object_get(root, "code");
			if(code_json && json_is_integer(code_json))
				response_code = json_integer_value(code_json);
			if(response_code <= 399) {
				JANUS_LOG(LOG_WARN, "Invalid SIP response code specified, using 486 to decline call\n");
				response_code = 486;
			}
			nua_respond(session->stack->s_nh_i, response_code, sip_status_phrase(response_code), TAG_END());
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("declined"));
				json_object_set_new(info, "callee", json_string(session->callee));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				json_object_set_new(info, "code", json_integer(response_code));
				gateway->notify_event(&janus_sip_plugin, session->handle, info);
			}
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("declining"));
			json_object_set_new(result, "code", json_integer(response_code));
		} else if(!strcasecmp(request_text, "hold") || !strcasecmp(request_text, "unhold")) {
			/* We either need to put the call on-hold, or resume it */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				/* Ignore */
				janus_sip_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			if(session->sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no SDP?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no SDP?)");
				goto error;
			}
			gboolean hold = !strcasecmp(request_text, "hold");
			if(hold != session->media.on_hold) {
				/* To put the call on-hold, we need to set the direction to recvonly:
				 * resuming it means resuming the direction we had before */
				session->media.on_hold = hold;
				janus_sdp_mline *m = janus_sdp_mline_find(session->sdp, JANUS_SDP_AUDIO);
				if(m) {
					if(hold) {
						/* Take note of the original media direction */
						session->media.pre_hold_audio_dir = m->direction;
						/* Update the media direction */
						switch(m->direction) {
							case JANUS_SDP_DEFAULT:
							case JANUS_SDP_SENDRECV:
								m->direction = JANUS_SDP_SENDONLY;
								break;
							default:
								m->direction = JANUS_SDP_INACTIVE;
								break;
						}
					} else {
						m->direction = session->media.pre_hold_audio_dir;
					}
				}
				m = janus_sdp_mline_find(session->sdp, JANUS_SDP_VIDEO);
				if(m) {
					if(hold) {
						/* Take note of the original media direction */
						session->media.pre_hold_video_dir = m->direction;
						/* Update the media direction */
						switch(m->direction) {
							case JANUS_SDP_DEFAULT:
							case JANUS_SDP_SENDRECV:
								m->direction = JANUS_SDP_SENDONLY;
								break;
							default:
								m->direction = JANUS_SDP_INACTIVE;
								break;
						}
					} else {
						m->direction = session->media.pre_hold_video_dir;
					}
				}
				/* Send the re-INVITE */
				char *sdp = janus_sdp_write(session->sdp);
				nua_invite(session->stack->s_nh_i,
					SOATAG_USER_SDP_STR(sdp),
					TAG_END());
				g_free(sdp);
			}
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string(hold ? "holding" : "resuming"));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				/* Ignore */
				janus_sip_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			session->media.earlymedia = FALSE;
			session->media.update = FALSE;
			session->media.ready = FALSE;
			session->media.on_hold = FALSE;
			session->status = janus_sip_call_status_closing;
			nua_bye(session->stack->s_nh_i, TAG_END());
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
		} else if(!strcasecmp(request_text, "recording")) {
			/* Start or stop recording */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, recording_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *action = json_object_get(root, "action");
			const char *action_text = json_string_value(action);
			if(strcasecmp(action_text, "start") && strcasecmp(action_text, "stop")) {
				JANUS_LOG(LOG_ERR, "Invalid action (should be start|stop)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid action (should be start|stop)");
				goto error;
			}
			gboolean record_audio = FALSE, record_video = FALSE,	/* No media is recorded by default */
				record_peer_audio = FALSE, record_peer_video = FALSE;
			json_t *audio = json_object_get(root, "audio");
			record_audio = audio ? json_is_true(audio) : FALSE;
			json_t *video = json_object_get(root, "video");
			record_video = video ? json_is_true(video) : FALSE;
			json_t *peer_audio = json_object_get(root, "peer_audio");
			record_peer_audio = peer_audio ? json_is_true(peer_audio) : FALSE;
			json_t *peer_video = json_object_get(root, "peer_video");
			record_peer_video = peer_video ? json_is_true(peer_video) : FALSE;
			if(!record_audio && !record_video && !record_peer_audio && !record_peer_video) {
				JANUS_LOG(LOG_ERR, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)\n");
				error_code = JANUS_SIP_ERROR_RECORDING_ERROR;
				g_snprintf(error_cause, 512, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)");
				goto error;
			}
			json_t *recfile = json_object_get(root, "filename");
			const char *recording_base = json_string_value(recfile);
			janus_mutex_lock(&session->rec_mutex);
			if(!strcasecmp(action_text, "start")) {
				/* Start recording something */
				char filename[255];
				gint64 now = janus_get_real_time();
				if(record_peer_audio || record_peer_video) {
					JANUS_LOG(LOG_INFO, "Starting recording of peer's %s (user %s, call %s)\n",
						(record_peer_audio && record_peer_video ? "audio and video" : (record_peer_audio ? "audio" : "video")),
						session->account.username, session->transaction);
					/* Start recording this peer's audio and/or video */
					if(record_peer_audio) {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-peer-audio", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->arc_peer = janus_recorder_create(NULL, session->media.audio_pt_name, filename);
							if(session->arc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this peer!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "sip-%s-%s-%"SCNi64"-peer-audio",
								session->account.username ? session->account.username : "unknown",
								session->transaction ? session->transaction : "unknown",
								now);
							/* FIXME This only works if offer/answer happened */
							session->arc_peer = janus_recorder_create(NULL, session->media.audio_pt_name, filename);
							if(session->arc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this peer!\n");
							}
						}
					}
					if(record_peer_video) {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-peer-video", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->vrc_peer = janus_recorder_create(NULL, session->media.video_pt_name, filename);
							if(session->vrc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this peer!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "sip-%s-%s-%"SCNi64"-peer-video",
								session->account.username ? session->account.username : "unknown",
								session->transaction ? session->transaction : "unknown",
								now);
							/* FIXME This only works if offer/answer happened */
							session->vrc_peer = janus_recorder_create(NULL, session->media.video_pt_name, filename);
							if(session->vrc_peer == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this peer!\n");
							}
						}
						/* TODO We should send a FIR/PLI to this peer... */
					}
				}
				if(record_audio || record_video) {
					/* Start recording the user's audio and/or video */
					JANUS_LOG(LOG_INFO, "Starting recording of user's %s (user %s, call %s)\n",
						(record_audio && record_video ? "audio and video" : (record_audio ? "audio" : "video")),
						session->account.username, session->transaction);
					if(record_audio) {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-user-audio", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->arc = janus_recorder_create(NULL, session->media.audio_pt_name, filename);
							if(session->arc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this peer!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "sip-%s-%s-%"SCNi64"-own-audio",
								session->account.username ? session->account.username : "unknown",
								session->transaction ? session->transaction : "unknown",
								now);
							/* FIXME This only works if offer/answer happened */
							session->arc = janus_recorder_create(NULL, session->media.audio_pt_name, filename);
							if(session->arc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an audio recording file for this peer!\n");
							}
						}
					}
					if(record_video) {
						memset(filename, 0, 255);
						if(recording_base) {
							/* Use the filename and path we have been provided */
							g_snprintf(filename, 255, "%s-user-video", recording_base);
							/* FIXME This only works if offer/answer happened */
							session->vrc = janus_recorder_create(NULL, session->media.video_pt_name, filename);
							if(session->vrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this user!\n");
							}
						} else {
							/* Build a filename */
							g_snprintf(filename, 255, "sip-%s-%s-%"SCNi64"-own-video",
								session->account.username ? session->account.username : "unknown",
								session->transaction ? session->transaction : "unknown",
								now);
							/* FIXME This only works if offer/answer happened */
							session->vrc = janus_recorder_create(NULL, session->media.video_pt_name, filename);
							if(session->vrc == NULL) {
								/* FIXME We should notify the fact the recorder could not be created */
								JANUS_LOG(LOG_ERR, "Couldn't open an video recording file for this user!\n");
							}
						}
						/* Send a PLI */
						JANUS_LOG(LOG_VERB, "Recording video, sending a PLI to kickstart it\n");
						char buf[12];
						janus_rtcp_pli((char *)&buf, 12);
						gateway->relay_rtcp(session->handle, 1, buf, 12);
					}
				}
			} else {
				/* Stop recording something: notice that this never returns an error, even when we were not recording anything */
				janus_sip_recorder_close(session, record_audio, record_peer_audio, record_video, record_peer_video);
			}
			janus_mutex_unlock(&session->rec_mutex);
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("recordingupdated"));
		} else if(!strcasecmp(request_text, "info")) {
			/* Send a SIP INFO request: we'll need the payload type and content */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, info_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			const char *info_type = json_string_value(json_object_get(root, "type"));
			const char *info_content = json_string_value(json_object_get(root, "content"));
			nua_info(session->stack->s_nh_i,
				SIPTAG_CONTENT_TYPE_STR(info_type),
				SIPTAG_PAYLOAD_STR(info_content),
				TAG_END());
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("infosent"));
		} else if(!strcasecmp(request_text, "message")) {
			/* Send a SIP MESSAGE request: we'll only need the content */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, sipmessage_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			const char *msg_content = json_string_value(json_object_get(root, "content"));
			nua_message(session->stack->s_nh_i,
				NUTAG_URL(session->callee),
				SIPTAG_CONTENT_TYPE_STR("text/plain"),
				SIPTAG_PAYLOAD_STR(msg_content),
				TAG_END());
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("messagesent"));
		} else if(!strcasecmp(request_text, "dtmf_info")) {
			/* Send DMTF tones using SIP INFO
			 * (https://tools.ietf.org/html/draft-kaplan-dispatch-info-dtmf-package-00)
			 */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, dtmf_info_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIP_ERROR_MISSING_ELEMENT, JANUS_SIP_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *digit = json_object_get(root, "digit");
			const char *digit_text = json_string_value(digit);
			if(strlen(digit_text) != 1) {
				JANUS_LOG(LOG_ERR, "Invalid element (digit should be one character))\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (digit should be one character)");
				goto error;
			}
			int duration_ms = 0;
			json_t *duration = json_object_get(root, "duration");
			duration_ms = duration ? json_integer_value(duration) : 0;
			if(duration_ms <= 0 || duration_ms > 5000) {
				duration_ms = 160; /* default value */
			}
			char payload[64];
			g_snprintf(payload, sizeof(payload), "Signal=%s\r\nDuration=%d", digit_text, duration_ms);
			nua_info(session->stack->s_nh_i,
				SIPTAG_CONTENT_TYPE_STR("application/dtmf-relay"),
				SIPTAG_PAYLOAD_STR(payload),
				TAG_END());
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("dtmfsent"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_SIP_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "sip", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		json_object_set_new(event, "call_id", json_string(session->callid));
		int ret = gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(event);
		janus_sip_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			json_object_set_new(event, "call_id", json_string(session->callid));
			int ret = gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_sip_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving SIP handler thread\n");
	return NULL;
}


/* Sofia callbacks */
void janus_sip_sofia_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *magic, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[])
{
	janus_sip_session *session = (janus_sip_session *)magic;
	ssip_t *ssip = session->stack;

	/* Notify event handlers about the content of the whole incoming SIP message, if any */
	if(notify_events && gateway->events_is_enabled() && ssip) {
		/* Print the incoming message */
		size_t msg_size = 0;
		msg_t *msg = nua_current_request(nua);
		if(msg) {
			char *msg_str = msg_as_string(ssip->s_home, msg, NULL, 0, &msg_size);
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("sip-in"));
			json_object_set_new(info, "sip", json_string(msg_str));
			gateway->notify_event(&janus_sip_plugin, session->handle, info);
		}
	}

	switch (event) {
	/* Status or Error Indications */
		case nua_i_active:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_error:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_fork:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_media_error:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_subscription:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_state:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			tagi_t const *ti = tl_find(tags, nutag_callstate);
			enum nua_callstate callstate = ti ? ti->t_value : -1;
			/* There are several call states, but we care about the terminated state in order to send the 'hangup' event
			 * and the proceeding state in order to send the 'proceeding' event so the client can play a ringback tone for
			 * the user since we don't send early media. (assuming this is the right session, of course).
			 * http://sofia-sip.sourceforge.net/refdocs/nua/nua__tag_8h.html#a516dc237722dc8ca4f4aa3524b2b444b
			 */
			if(callstate == nua_callstate_proceeding &&
					(session->stack->s_nh_i == nh || session->stack->s_nh_i == NULL)) {
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("proceeding"));
				json_object_set_new(calling, "code", json_integer(status));
				json_object_set_new(call, "result", calling);
				json_object_set_new(call, "call_id", json_string(session->callid));
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(call);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("proceeding"));
					if(session->callid)
						json_object_set_new(info, "call-id", json_string(session->callid));
					json_object_set_new(info, "code", json_integer(status));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				}
			} else if(callstate == nua_callstate_terminated &&
					(session->stack->s_nh_i == nh || session->stack->s_nh_i == NULL)) {
				session->media.earlymedia = FALSE;
				session->media.update = FALSE;
				session->media.ready = FALSE;
				session->media.on_hold = FALSE;
				session->status = janus_sip_call_status_idle;
				session->stack->s_nh_i = NULL;
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "code", json_integer(status));
				json_object_set_new(calling, "reason", json_string(phrase ? phrase : ""));
				json_object_set_new(call, "result", calling);
				json_object_set_new(call, "call_id", json_string(session->callid));
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(call);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("hangup"));
					if(session->callid)
						json_object_set_new(info, "call-id", json_string(session->callid));
					json_object_set_new(info, "code", json_integer(status));
					if(phrase)
						json_object_set_new(info, "reason", json_string(phrase));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				}
				/* Get rid of any PeerConnection that may have been set up */
				if(session->callid) {
					janus_mutex_lock(&sessions_mutex);
					g_hash_table_remove(callids, session->callid);
					janus_mutex_unlock(&sessions_mutex);
				}
				g_free(session->callid);
				session->callid = NULL;
				g_free(session->transaction);
				session->transaction = NULL;
				gateway->close_pc(session->handle);
			}
			break;
		case nua_i_terminated:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP requests */
		case nua_i_ack: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* We're only interested in this when there's been an offerless INVITE, as here's where we'd get our answer */
			if(sip->sip_payload && sip->sip_payload->pl_data) {
				JANUS_LOG(LOG_VERB, "This ACK contains a payload, probably as a result of an offerless INVITE: simulating 200 OK...\n");
				janus_sip_sofia_callback(nua_r_invite, 700, "ACK", nua, magic, nh, hmagic, sip, tags);
			}
			break;
		}
		case nua_i_outbound:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_bye: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		}
		case nua_i_cancel: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		}
		case nua_i_invite: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			if(ssip == NULL) {
				JANUS_LOG(LOG_ERR, "\tInvalid SIP stack\n");
				nua_respond(nh, 500, sip_status_phrase(500), TAG_END());
				break;
			}
			gboolean reinvite = FALSE;
			if(session->stack->s_nh_i != NULL) {
				if(session->stack->s_nh_i == nh) {
					/* re-INVITE, we'll check what changed later */
					reinvite = TRUE;
					JANUS_LOG(LOG_VERB, "Got a re-INVITE...\n");
				} else if(session->status >= janus_sip_call_status_inviting) {
					/* Busy with another call */
					JANUS_LOG(LOG_VERB, "\tAlready in a call (busy, status=%s)\n", janus_sip_call_status_string(session->status));
					nua_respond(nh, 486, sip_status_phrase(486), TAG_END());
					/* Notify the web app about the missed invite */
					json_t *missed = json_object();
					json_object_set_new(missed, "sip", json_string("event"));
					json_t *result = json_object();
					json_object_set_new(result, "event", json_string("missed_call"));
					char *caller_text = url_as_string(session->stack->s_home, sip->sip_from->a_url);
					json_object_set_new(result, "caller", json_string(caller_text));
					su_free(session->stack->s_home, caller_text);
					if(sip->sip_from && sip->sip_from->a_display) {
						json_object_set_new(result, "displayname", json_string(sip->sip_from->a_display));
					}
					json_object_set_new(missed, "result", result);
					json_object_set_new(missed, "call_id", json_string(session->callid));
					int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, missed, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
					json_decref(missed);
					/* Also notify event handlers */
					if(notify_events && gateway->events_is_enabled()) {
						json_t *info = json_object();
						json_object_set_new(info, "event", json_string("missed_call"));
						json_object_set_new(info, "caller", json_string(caller_text));
						gateway->notify_event(&janus_sip_plugin, session->handle, info);
					}
					break;
				}
			}
			/* Check if there's an SDP to process */
			janus_sdp *sdp = NULL;
			if(!sip->sip_payload) {
				JANUS_LOG(LOG_VERB,"Received offerless %s\n", reinvite ? "re-INVITE" : "INVITE");
			} else {
				char sdperror[100];
				sdp = janus_sdp_parse(sip->sip_payload->pl_data, sdperror, sizeof(sdperror));
				if(!sdp) {
					JANUS_LOG(LOG_ERR, "\tError parsing SDP! %s\n", sdperror);
					nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
					break;
				}
			}
			if(!reinvite) {
				/* New incoming call */
				g_free(session->callee);
				session->callee = g_strdup(url_as_string(session->stack->s_home, sip->sip_from->a_url));
				g_free(session->callid);
				session->callid = sip && sip->sip_call_id ? g_strdup(sip->sip_call_id->i_id) : NULL;
				if(session->callid) {
					janus_mutex_lock(&sessions_mutex);
					g_hash_table_insert(callids, session->callid, session);
					janus_mutex_unlock(&sessions_mutex);
				}
				session->status = janus_sip_call_status_invited;
				/* Clean up SRTP stuff from before first, in case it's still needed */
				janus_sip_srtp_cleanup(session);
			}
			/* Parse SDP */
			JANUS_LOG(LOG_VERB, "Someone is %s a call:\n%s",
				reinvite ? "updating" : "inviting us in",
				sip->sip_payload ? sip->sip_payload->pl_data : "(no SDP)");
			gboolean changed = FALSE;
			if(sdp) {
				janus_sip_sdp_process(session, sdp, FALSE, reinvite, &changed);
				/* Check if offer has neither audio nor video, fail with 488 */
				if(!session->media.has_audio && !session->media.has_video) {
					nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
					janus_sdp_destroy(sdp);
					break;
				}
				/* Also fail with 488 if there's no remote IP address that can be used for RTP */
				if(!session->media.remote_ip) {
					nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
					janus_sdp_destroy(sdp);
					break;
				}
			}
			if(reinvite) {
				/* No need to involve the browser: we reply ourselves */
				nua_respond(nh, 200, sip_status_phrase(200), TAG_END());
				janus_sdp_destroy(sdp);
				break;
			}
			/* Notify the browser about the call */
			json_t *jsep = NULL;
			if(sdp)
				jsep = json_pack("{ssss}", "type", "offer", "sdp", sip->sip_payload->pl_data);
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("incomingcall"));
			json_object_set_new(calling, "username", json_string(session->callee));
			if(sip->sip_from && sip->sip_from->a_display) {
				json_object_set_new(calling, "displayname", json_string(sip->sip_from->a_display));
			}
			if(sdp && session->media.has_srtp_remote) {
				/* FIXME Maybe a true/false instead? */
				json_object_set_new(calling, "srtp", json_string(session->media.require_srtp ? "sdes_mandatory" : "sdes_optional"));
			}
			json_object_set_new(call, "result", calling);
			json_object_set_new(call, "call_id", json_string(session->callid));
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(call);
			if(jsep)
				json_decref(jsep);
			janus_sdp_destroy(sdp);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("incomingcall"));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				json_object_set_new(info, "username", json_string(session->callee));
				if(sip->sip_from && sip->sip_from->a_display)
					json_object_set_new(info, "displayname", json_string(sip->sip_from->a_display));
				gateway->notify_event(&janus_sip_plugin, session->handle, info);
			}
			/* Send a Ringing back */
			nua_respond(nh, 180, sip_status_phrase(180), TAG_END());
			session->stack->s_nh_i = nh;
			break;
		}
		case nua_i_info: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* We expect a payload */
			if(!sip->sip_content_type || !sip->sip_content_type->c_type || !sip->sip_payload || !sip->sip_payload->pl_data) {
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				return;
			}
			const char *type = sip->sip_content_type->c_type;
			char *payload = sip->sip_payload->pl_data;
			/* Notify the application */
			json_t *info = json_object();
			json_object_set_new(info, "sip", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("info"));
			char *caller_text = url_as_string(session->stack->s_home, sip->sip_from->a_url);
			json_object_set_new(result, "sender", json_string(caller_text));
			su_free(session->stack->s_home, caller_text);
			if(sip->sip_from && sip->sip_from->a_display && strlen(sip->sip_from->a_display) > 0) {
				json_object_set_new(result, "displayname", json_string(sip->sip_from->a_display));
			}
			json_object_set_new(result, "type", json_string(type));
			json_object_set_new(result, "content", json_string(payload));
			json_object_set_new(info, "result", result);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, info, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(info);
			/* Send a 200 back */
			nua_respond(nh, 200, sip_status_phrase(200), TAG_END());
			break;
		}
		case nua_i_message: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* We expect a payload */
			if(!sip->sip_payload || !sip->sip_payload->pl_data) {
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				return;
			}
			char *payload = sip->sip_payload->pl_data;
			/* Notify the application */
			json_t *message = json_object();
			json_object_set_new(message, "sip", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("message"));
			char *caller_text = url_as_string(session->stack->s_home, sip->sip_from->a_url);
			json_object_set_new(result, "sender", json_string(caller_text));
			su_free(session->stack->s_home, caller_text);
			if(sip->sip_from && sip->sip_from->a_display && strlen(sip->sip_from->a_display) > 0) {
				json_object_set_new(result, "displayname", json_string(sip->sip_from->a_display));
			}
			json_object_set_new(result, "content", json_string(payload));
			json_object_set_new(message, "result", result);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, message, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(message);
			/* Send a 200 back */
			nua_respond(nh, 200, sip_status_phrase(200), TAG_END());
			break;
		}
		case nua_i_options:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
	/* Responses */
		case nua_r_get_params:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_set_params:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_notifier:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_shutdown:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			if(status < 200 && !g_atomic_int_get(&stopping)) {
				/* shutdown in progress -> return */
				break;
			}
			if(ssip != NULL) {
				/* end the event loop. su_root_run() will return */
				su_root_break(ssip->s_root);
			}
			break;
		case nua_r_terminate:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP responses */
		case nua_r_bye:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_cancel:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_info:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we notify the user, in case the SIP INFO returned an error? */
			break;
		case nua_r_message:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we notify the user, in case the SIP MESSAGE returned an error? */
			break;
		case nua_r_invite: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");

			gboolean in_progress = FALSE;
			if(status < 200) {
				/* Not ready yet, either notify the user (e.g., "ringing") or handle early media (if it's a 183) */
				if(status == 180) {
					/* Ringing, notify the application */
					json_t *ringing = json_object();
					json_object_set_new(ringing, "sip", json_string("event"));
					json_t *result = json_object();
					json_object_set_new(result, "event", json_string("ringing"));
					json_object_set_new(ringing, "result", result);
					json_object_set_new(ringing, "call_id", json_string(session->callid));
					int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, ringing, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
					json_decref(ringing);
					break;
				} else if(status == 183) {
					/* If's a Session Progress: check if there's an SDP, and if so, treat it like a 200 */
					if(!sip->sip_payload || !sip->sip_payload->pl_data)
						break;
					in_progress = TRUE;
				} else {
					/* Nothing to do, let's wait for a 200 OK */
					break;
				}
			} else if(status == 401 || status == 407) {
				const char* scheme;
				const char* realm;
				if(status == 401) {
 					/* Get scheme/realm from 401 error */
					sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
					scheme = www_auth->au_scheme;
					realm = msg_params_find(www_auth->au_params, "realm=");
				} else {
 					/* Get scheme/realm from 407 error, proxy-auth */
					sip_proxy_authenticate_t const* proxy_auth = sip->sip_proxy_authenticate;
					scheme = proxy_auth->au_scheme;
					realm = msg_params_find(proxy_auth->au_params, "realm=");
				}
				char authuser[100], secret[100];
				memset(authuser, 0, sizeof(authuser));
				memset(secret, 0, sizeof(secret));
				if(session->account.authuser && strchr(session->account.authuser, ':')) {
					/* The authuser contains a colon: wrap it in quotes */
					g_snprintf(authuser, sizeof(authuser), "\"%s\"", session->account.authuser);
				} else {
					g_snprintf(authuser, sizeof(authuser), "%s", session->account.authuser);
				}
				if(session->account.secret && strchr(session->account.secret, ':')) {
					/* The secret contains a colon: wrap it in quotes */
					g_snprintf(secret, sizeof(secret), "\"%s\"", session->account.secret);
				} else {
					g_snprintf(secret, sizeof(secret), "%s", session->account.secret);
				}
				char auth[256];
				memset(auth, 0, sizeof(auth));
				g_snprintf(auth, sizeof(auth), "%s%s:%s:%s:%s%s",
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					scheme,
					realm,
					authuser,
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					secret);
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
				break;
			} else if(status == 700) {
				JANUS_LOG(LOG_VERB, "Handling SDP answer in ACK\n");
			} else if(status >= 400 && status != 700) {
				break;
			}
			if(ssip == NULL) {
				JANUS_LOG(LOG_ERR, "\tInvalid SIP stack\n");
				nua_respond(nh, 500, sip_status_phrase(500), TAG_END());
				break;
			}
			if(sip->sip_payload == NULL) {
				JANUS_LOG(LOG_ERR, "\tMissing SDP\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			char sdperror[100];
			janus_sdp *sdp = janus_sdp_parse(sip->sip_payload->pl_data, sdperror, sizeof(sdperror));
			if(!sdp) {
				JANUS_LOG(LOG_ERR, "\tError parsing SDP! %s\n", sdperror);
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			/* Send an ACK, if needed */
			if(!in_progress) {
				char *route = NULL;
				sip_record_route_t *srr = sip->sip_record_route;
				if(srr != NULL) {
					while(srr->r_next != NULL)
						srr = srr->r_next;
					route = srr ? url_as_string(session->stack->s_home, srr->r_url) : NULL;
				}
				JANUS_LOG(LOG_VERB, "Sending ACK (route=%s)\n", route ? route : "none");
				nua_ack(nh,
					TAG_IF(route, NTATAG_DEFAULT_PROXY(route)),
					TAG_END());
			}
			/* Parse SDP */
			JANUS_LOG(LOG_VERB, "Peer accepted our call:\n%s", sip->sip_payload->pl_data);
			session->status = janus_sip_call_status_incall;
			char *fixed_sdp = sip->sip_payload->pl_data;
			gboolean changed = FALSE;
			gboolean update = session->media.ready;
			janus_sip_sdp_process(session, sdp, TRUE, update, &changed);
			/* If we asked for SRTP and are not getting it, fail */
			if(session->media.require_srtp && !session->media.has_srtp_remote) {
				JANUS_LOG(LOG_ERR, "\tWe asked for mandatory SRTP but didn't get any in the reply!\n");
				janus_sdp_destroy(sdp);
				/* Hangup immediately */
				session->media.earlymedia = FALSE;
				session->media.update = FALSE;
				session->media.ready = FALSE;
				session->media.on_hold = FALSE;
				session->status = janus_sip_call_status_closing;
				nua_bye(nh, TAG_END());
				g_free(session->callee);
				session->callee = NULL;
				break;
			}
			if(!session->media.remote_ip) {
				/* No remote address parsed? Give up */
				JANUS_LOG(LOG_ERR, "\tNo remote IP address found for RTP, something's wrong with the SDP!\n");
				janus_sdp_destroy(sdp);
				/* Hangup immediately */
				session->media.earlymedia = FALSE;
				session->media.update = FALSE;
				session->media.ready = FALSE;
				session->media.on_hold = FALSE;
				session->status = janus_sip_call_status_closing;
				nua_bye(nh, TAG_END());
				g_free(session->callee);
				session->callee = NULL;
				break;
			}
			if(session->media.audio_pt > -1) {
				session->media.audio_pt_name = janus_get_codec_from_pt(fixed_sdp, session->media.audio_pt);
				JANUS_LOG(LOG_VERB, "Detected audio codec: %d (%s)\n", session->media.audio_pt, session->media.audio_pt_name);
			}
			if(session->media.video_pt > -1) {
				session->media.video_pt_name = janus_get_codec_from_pt(fixed_sdp, session->media.video_pt);
				JANUS_LOG(LOG_VERB, "Detected video codec: %d (%s)\n", session->media.video_pt, session->media.video_pt_name);
			}
			session->media.ready = TRUE;	/* FIXME Maybe we need a better way to signal this */
			if(update && !session->media.earlymedia && !session->media.update) {
				/* Don't push to the browser if this is in response to a hold/unhold we sent ourselves */
				JANUS_LOG(LOG_VERB, "This is an update to an existing call (possibly in response to hold/unhold)\n");
				break;
			}
			if(!session->media.earlymedia && !session->media.update) {
				GError *error = NULL;
				char tname[16];
				g_snprintf(tname, sizeof(tname), "siprtp %s", session->account.username);
				janus_refcount_increase(&session->ref);
				session->relayer_thread = g_thread_try_new(tname, janus_sip_relay_thread, session, &error);
				if(error != NULL) {
					session->relayer_thread = NULL;
					session->media.ready = FALSE;
					janus_refcount_decrease(&session->ref);
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
				}
			}
			/* Send event back to the browser */
			json_t *jsep = NULL;
			if(!session->media.earlymedia) {
				jsep = json_pack("{ssss}", "type", "answer", "sdp", fixed_sdp);
			} else {
				/* We've received the 200 OK after the 183, we can remove the flag now */
				session->media.earlymedia = FALSE;
			}
			if(in_progress) {
				/* If we just received the 183, set the flag instead so that we can handle the 200 OK differently */
				session->media.earlymedia = TRUE;
			}
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string(in_progress ? "progress" : "accepted"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(call, "result", calling);
			json_object_set_new(call, "call_id", json_string(session->callid));
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call, jsep);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(call);
			json_decref(jsep);
			janus_sdp_destroy(sdp);
			/* Also notify event handlers */
			if(!session->media.update && notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string(in_progress ? "progress" : "accepted"));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				json_object_set_new(info, "username", json_string(session->callee));
				gateway->notify_event(&janus_sip_plugin, session->handle, info);
			}
			if(session->media.update) {
				/* We just received a 200 OK to an update we sent */
				session->media.update = FALSE;
			}
			break;
		}
		case nua_r_register:
		case nua_r_unregister: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			if(status == 200) {
				if(event == nua_r_register) {
					if(session->account.registration_status < janus_sip_registration_status_registered)
						session->account.registration_status = janus_sip_registration_status_registered;
				} else {
					session->account.registration_status = janus_sip_registration_status_unregistered;
				}
				const char *event_name = (event == nua_r_register ? "registered" : "unregistered");
				JANUS_LOG(LOG_VERB, "Successfully %s\n", event_name);
				/* Notify the browser */
				json_t *reg = json_object();
				json_object_set_new(reg, "sip", json_string("event"));
				json_t *reging = json_object();
				json_object_set_new(reging, "event", json_string(event_name));
				json_object_set_new(reging, "username", json_string(session->account.username));
				if(event == nua_r_register)
					json_object_set_new(reging, "register_sent", json_true());
				json_object_set_new(reg, "result", reging);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, reg, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(reg);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string(event_name));
					json_object_set_new(info, "identity", json_string(session->account.identity));
					if(session->account.proxy)
						json_object_set_new(info, "proxy", json_string(session->account.proxy));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				}
			} else if(status == 401 || status == 407) {
				const char* scheme;
				const char* realm;
				if(status == 401) {
 					/* Get scheme/realm from 401 error */
					sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
					scheme = www_auth->au_scheme;
					realm = msg_params_find(www_auth->au_params, "realm=");
				} else {
 					/* Get scheme/realm from 407 error, proxy-auth */
					sip_proxy_authenticate_t const* proxy_auth = sip->sip_proxy_authenticate;
					scheme = proxy_auth->au_scheme;
					realm = msg_params_find(proxy_auth->au_params, "realm=");
				}
				char authuser[100], secret[100];
				memset(authuser, 0, sizeof(authuser));
				memset(secret, 0, sizeof(secret));
				if(session->account.authuser && strchr(session->account.authuser, ':')) {
					/* The authuser contains a colon: wrap it in quotes */
					g_snprintf(authuser, sizeof(authuser), "\"%s\"", session->account.authuser);
				} else {
					g_snprintf(authuser, sizeof(authuser), "%s", session->account.authuser);
				}
				if(session->account.secret && strchr(session->account.secret, ':')) {
					/* The secret contains a colon: wrap it in quotes */
					g_snprintf(secret, sizeof(secret), "\"%s\"", session->account.secret);
				} else {
					g_snprintf(secret, sizeof(secret), "%s", session->account.secret);
				}
				char auth[256];
				memset(auth, 0, sizeof(auth));
				g_snprintf(auth, sizeof(auth), "%s%s:%s:%s:%s%s",
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					scheme,
					realm,
					authuser,
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					secret);
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
			} else if(status >= 400) {
				/* Authentication failed? */
				session->account.registration_status = janus_sip_registration_status_failed;
				/* Cleanup registration values */
				if(session->account.identity != NULL) {
					janus_mutex_lock(&sessions_mutex);
					g_hash_table_remove(identities, session->account.identity);
					janus_mutex_unlock(&sessions_mutex);
					g_free(session->account.identity);
				}
				session->account.identity = NULL;
				session->account.force_udp = FALSE;
				session->account.force_tcp = FALSE;
				session->account.sips = TRUE;
				if(session->account.username != NULL)
					g_free(session->account.username);
				session->account.username = NULL;
				if(session->account.display_name != NULL)
					g_free(session->account.display_name);
				session->account.display_name = NULL;
				if(session->account.authuser != NULL)
					g_free(session->account.authuser);
				session->account.authuser = NULL;
				if(session->account.secret != NULL)
					g_free(session->account.secret);
				session->account.secret = NULL;
				session->account.secret_type = janus_sip_secret_type_unknown;
				if(session->account.proxy != NULL)
					g_free(session->account.proxy);
				session->account.proxy = NULL;
				if(session->account.outbound_proxy != NULL)
					g_free(session->account.outbound_proxy);
				session->account.outbound_proxy = NULL;
				if(session->account.user_agent != NULL)
					g_free(session->account.user_agent);
				session->account.user_agent = NULL;
				session->account.registration_status = janus_sip_registration_status_unregistered;
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("registration_failed"));
				json_object_set_new(result, "code", json_integer(status));
				json_object_set_new(result, "reason", json_string(phrase ? phrase : ""));
				json_object_set_new(event, "result", result);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				json_decref(event);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("registration_failed"));
					json_object_set_new(info, "code", json_integer(status));
					json_object_set_new(info, "reason", json_string(phrase ? phrase : ""));
					gateway->notify_event(&janus_sip_plugin, session->handle, info);
				}
			}
			break;
		}
		default:
			/* unknown event -> print out error message */
			JANUS_LOG(LOG_ERR, "Unknown event %d (%s)\n", event, nua_event_name(event));
			break;
	}
}

void janus_sip_sdp_process(janus_sip_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed) {
	if(!session || !sdp)
		return;
	/* c= */
	if(sdp->c_addr) {
		if(update && strcmp(sdp->c_addr, session->media.remote_ip)) {
			/* This is an update and an address changed */
			if(changed)
				*changed = TRUE;
		}
		g_free(session->media.remote_ip);
		session->media.remote_ip = g_strdup(sdp->c_addr);
	}
	GList *temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		session->media.require_srtp = session->media.require_srtp || (m->proto && !strcasecmp(m->proto, "RTP/SAVP"));
		if(m->type == JANUS_SDP_AUDIO) {
			if(m->port) {
				if(m->port != session->media.remote_audio_rtp_port) {
					/* This is an update and an address changed */
					if(changed)
						*changed = TRUE;
				}
				session->media.has_audio = TRUE;
				session->media.remote_audio_rtp_port = m->port;
				session->media.remote_audio_rtcp_port = m->port+1;	/* FIXME We're assuming RTCP is on the next port */
				if(m->direction == JANUS_SDP_SENDONLY || m->direction == JANUS_SDP_INACTIVE)
					session->media.audio_send = FALSE;
				else
					session->media.audio_send = TRUE;
			} else {
				session->media.audio_send = FALSE;
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			if(m->port) {
				if(m->port != session->media.remote_video_rtp_port) {
					/* This is an update and an address changed */
					if(changed)
						*changed = TRUE;
				}
				session->media.has_video = TRUE;
				session->media.remote_video_rtp_port = m->port;
				session->media.remote_video_rtcp_port = m->port+1;	/* FIXME We're assuming RTCP is on the next port */
				if(m->direction == JANUS_SDP_SENDONLY || m->direction == JANUS_SDP_INACTIVE)
					session->media.video_send = FALSE;
				else
					session->media.video_send = TRUE;
			} else {
				session->media.video_send = FALSE;
			}
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported media line (not audio/video)\n");
			temp = temp->next;
			continue;
		}
		if(m->c_addr) {
			if(update && strcmp(m->c_addr, session->media.remote_ip)) {
				/* This is an update and an address changed */
				if(changed)
					*changed = TRUE;
			}
			g_free(session->media.remote_ip);
			session->media.remote_ip = g_strdup(m->c_addr);
		}
		if(update) {
			/* FIXME This is a session update, we only accept changes in IP/ports */
			temp = temp->next;
			continue;
		}
		GList *tempA = m->attributes;
		while(tempA) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
			if(a->name) {
				if(!strcasecmp(a->name, "crypto")) {
					if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
						gint32 tag = 0;
						char profile[101], crypto[101];
						/* FIXME inline can be more complex than that, and we're currently only offering SHA1_80 */
						int res = a->value ? (sscanf(a->value, "%"SCNi32" %100s inline:%100s",
							&tag, profile, crypto)) : 0;
						if(res != 3) {
							JANUS_LOG(LOG_WARN, "Failed to parse crypto line, ignoring... %s\n", a->value);
						} else {
							gboolean video = (m->type == JANUS_SDP_VIDEO);
							janus_sip_srtp_set_remote(session, video, profile, crypto);
							session->media.has_srtp_remote = TRUE;
						}
					}
				}
			}
			tempA = tempA->next;
		}
		if(answer && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO)) {
			/* Check which codec was negotiated eventually */
			int pt = -1;
			if(m->ptypes)
				pt = GPOINTER_TO_INT(m->ptypes->data);
			if(pt > -1) {
				if(m->type == JANUS_SDP_AUDIO) {
					session->media.audio_pt = pt;
				} else {
					session->media.video_pt = pt;
				}
			}
		}
		temp = temp->next;
	}
	if(update && changed && *changed) {
		/* Something changed: mark this on the session, so that the thread can update the sockets */
		session->media.updated = TRUE;
		if(session->media.pipefd[1] > 0) {
			int code = 1;
			ssize_t res = 0;
			do {
				res = write(session->media.pipefd[1], &code, sizeof(int));
			} while(res == -1 && errno == EINTR);
		}
	}
}

char *janus_sip_sdp_manipulate(janus_sip_session *session, janus_sdp *sdp, gboolean answer) {
	if(!session || !session->stack || !sdp)
		return NULL;
	/* Start replacing stuff */
	JANUS_LOG(LOG_VERB, "Setting protocol to %s\n", session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
	GList *temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		g_free(m->proto);
		m->proto = g_strdup(session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
		if(m->type == JANUS_SDP_AUDIO) {
			m->port = session->media.local_audio_rtp_port;
			if(session->media.has_srtp_local) {
				char *profile = NULL;
				char *crypto = NULL;
				janus_sip_srtp_set_local(session, FALSE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		} else if(m->type == JANUS_SDP_VIDEO) {
			m->port = session->media.local_video_rtp_port;
			if(session->media.has_srtp_local) {
				char *profile = NULL;
				char *crypto = NULL;
				janus_sip_srtp_set_local(session, TRUE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		}
		g_free(m->c_addr);
		m->c_addr = g_strdup(local_ip);
		if(answer && (m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO)) {
			/* Check which codec was negotiated eventually */
			int pt = -1;
			if(m->ptypes)
				pt = GPOINTER_TO_INT(m->ptypes->data);
			if(pt > -1) {
				if(m->type == JANUS_SDP_AUDIO) {
					session->media.audio_pt = pt;
				} else {
					session->media.video_pt = pt;
				}
			}
		}
		temp = temp->next;
	}
	/* Generate a SDP string out of our changes */
	return janus_sdp_write(sdp);
}

 /* Bind local RTP/RTCP sockets */
static int janus_sip_allocate_local_ports(janus_sip_session *session) {
	if(session == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		return -1;
	}
	/* Reset status */
	if(session->media.audio_rtp_fd != -1) {
		close(session->media.audio_rtp_fd);
		session->media.audio_rtp_fd = -1;
	}
	if(session->media.audio_rtcp_fd != -1) {
		close(session->media.audio_rtcp_fd);
		session->media.audio_rtcp_fd = -1;
	}
	session->media.local_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	if(session->media.video_rtp_fd != -1) {
		close(session->media.video_rtp_fd);
		session->media.video_rtp_fd = -1;
	}
	if(session->media.video_rtcp_fd != -1) {
		close(session->media.video_rtcp_fd);
		session->media.video_rtcp_fd = -1;
	}
	session->media.local_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	if(session->media.pipefd[0] > 0) {
		close(session->media.pipefd[0]);
		session->media.pipefd[0] = -1;
	}
	if(session->media.pipefd[1] > 0) {
		close(session->media.pipefd[1]);
		session->media.pipefd[1] = -1;
	}
	/* Start */
	int attempts = 100;	/* FIXME Don't retry forever */
	if(session->media.has_audio) {
		JANUS_LOG(LOG_VERB, "Allocating audio ports:\n");
		struct sockaddr_in audio_rtp_address, audio_rtcp_address;
		while(session->media.local_audio_rtp_port == 0 || session->media.local_audio_rtcp_port == 0) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.audio_rtp_fd == -1) {
				session->media.audio_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.audio_rtcp_fd == -1) {
				session->media.audio_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.audio_rtp_fd == -1 || session->media.audio_rtcp_fd == -1) {
				JANUS_LOG(LOG_ERR, "Error creating audio sockets...\n");
				return -1;
			}
			int rtp_port = g_random_int_range(rtp_range_min, rtp_range_max);
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			audio_rtp_address.sin_family = AF_INET;
			audio_rtp_address.sin_port = htons(rtp_port);
			inet_pton(AF_INET, local_ip, &audio_rtp_address.sin_addr.s_addr);
			if(bind(session->media.audio_rtp_fd, (struct sockaddr *)(&audio_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for audio RTP (port %d), trying a different one...\n", rtp_port);
				close(session->media.audio_rtp_fd);
				session->media.audio_rtp_fd = -1;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Audio RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			audio_rtcp_address.sin_family = AF_INET;
			audio_rtcp_address.sin_port = htons(rtcp_port);
			inet_pton(AF_INET, local_ip, &audio_rtcp_address.sin_addr.s_addr);
			if(bind(session->media.audio_rtcp_fd, (struct sockaddr *)(&audio_rtcp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for audio RTCP (port %d), trying a different one...\n", rtcp_port);
				/* RTP socket is not valid anymore, reset it */
				close(session->media.audio_rtp_fd);
				session->media.audio_rtp_fd = -1;
				close(session->media.audio_rtcp_fd);
				session->media.audio_rtcp_fd = -1;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Audio RTCP listener bound to port %d\n", rtcp_port);
			session->media.local_audio_rtp_port = rtp_port;
			session->media.local_audio_rtcp_port = rtcp_port;
		}
	}
	if(session->media.has_video) {
		JANUS_LOG(LOG_VERB, "Allocating video ports:\n");
		struct sockaddr_in video_rtp_address, video_rtcp_address;
		while(session->media.local_video_rtp_port == 0 || session->media.local_video_rtcp_port == 0) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.video_rtp_fd == -1) {
				session->media.video_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.video_rtcp_fd == -1) {
				session->media.video_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.video_rtp_fd == -1 || session->media.video_rtcp_fd == -1) {
				JANUS_LOG(LOG_ERR, "Error creating video sockets...\n");
				return -1;
			}
			int rtp_port = g_random_int_range(rtp_range_min, rtp_range_max);
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			video_rtp_address.sin_family = AF_INET;
			video_rtp_address.sin_port = htons(rtp_port);
			inet_pton(AF_INET, local_ip, &video_rtp_address.sin_addr.s_addr);
			if(bind(session->media.video_rtp_fd, (struct sockaddr *)(&video_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTP (port %d), trying a different one...\n", rtp_port);
				close(session->media.video_rtp_fd);
				session->media.video_rtp_fd = -1;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Video RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			video_rtcp_address.sin_family = AF_INET;
			video_rtcp_address.sin_port = htons(rtcp_port);
			inet_pton(AF_INET, local_ip, &video_rtcp_address.sin_addr.s_addr);
			if(bind(session->media.video_rtcp_fd, (struct sockaddr *)(&video_rtcp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTCP (port %d), trying a different one...\n", rtcp_port);
				/* RTP socket is not valid anymore, reset it */
				close(session->media.video_rtp_fd);
				session->media.video_rtp_fd = -1;
				close(session->media.video_rtcp_fd);
				session->media.video_rtcp_fd = -1;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Video RTCP listener bound to port %d\n", rtcp_port);
			session->media.local_video_rtp_port = rtp_port;
			session->media.local_video_rtcp_port = rtcp_port;
		}
	}
	/* We need this to quickly interrupt the poll when it's time to update a session or wrap up */
	pipe(session->media.pipefd);
	return 0;
}

/* Helper method to (re)connect RTP/RTCP sockets */
static void janus_sip_connect_sockets(janus_sip_session *session, struct sockaddr_in *server_addr) {
	if(!session || !server_addr)
		return;

	if(session->media.updated) {
		JANUS_LOG(LOG_VERB, "Updating session sockets\n");
	}

	/* Connect peers (FIXME This pretty much sucks right now) */
	if(session->media.remote_audio_rtp_port) {
		server_addr->sin_port = htons(session->media.remote_audio_rtp_port);
		if(connect(session->media.audio_rtp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect audio RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_audio_rtcp_port) {
		server_addr->sin_port = htons(session->media.remote_audio_rtcp_port);
		if(connect(session->media.audio_rtcp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect audio RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtp_port) {
		server_addr->sin_port = htons(session->media.remote_video_rtp_port);
		if(connect(session->media.video_rtp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect video RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtcp_port) {
		server_addr->sin_port = htons(session->media.remote_video_rtcp_port);
		if(connect(session->media.video_rtcp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect video RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}

}

static void janus_sip_media_cleanup(janus_sip_session *session) {
	if(session->media.audio_rtp_fd != -1) {
		close(session->media.audio_rtp_fd);
		session->media.audio_rtp_fd = -1;
	}
	if(session->media.audio_rtcp_fd != -1) {
		close(session->media.audio_rtcp_fd);
		session->media.audio_rtcp_fd = -1;
	}
	session->media.local_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	if(session->media.video_rtp_fd != -1) {
		close(session->media.video_rtp_fd);
		session->media.video_rtp_fd = -1;
	}
	if(session->media.video_rtcp_fd != -1) {
		close(session->media.video_rtcp_fd);
		session->media.video_rtcp_fd = -1;
	}
	session->media.local_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	session->media.simulcast_ssrc = 0;
	if(session->media.pipefd[0] > 0) {
		close(session->media.pipefd[0]);
		session->media.pipefd[0] = -1;
	}
	if(session->media.pipefd[1] > 0) {
		close(session->media.pipefd[1]);
		session->media.pipefd[1] = -1;
	}
	/* Clean up SRTP stuff, if needed */
	janus_sip_srtp_cleanup(session);
}

/* Thread to relay RTP/RTCP frames coming from the SIP peer */
static void *janus_sip_relay_thread(void *data) {
	janus_sip_session *session = (janus_sip_session *)data;
	if(!session) {
		g_thread_unref(g_thread_self());
		return NULL;
	}
	if(!session->account.username || !session->callee) {
		janus_refcount_decrease(&session->ref);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Starting relay thread (%s <--> %s)\n", session->account.username, session->callee);

	gboolean have_server_ip = TRUE;
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if(inet_aton(session->media.remote_ip, &server_addr.sin_addr) == 0) {	/* Not a numeric IP... */
		struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
		if(!host) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't get host (%s)\n", session->account.username, session->media.remote_ip);
			have_server_ip = FALSE;
		} else {
			server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
		}
	}
	if(have_server_ip)
		janus_sip_connect_sockets(session, &server_addr);

	if(!session->callee) {
		JANUS_LOG(LOG_VERB, "[SIP-%s] Leaving thread, no callee...\n", session->account.username);
		janus_refcount_decrease(&session->ref);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	/* File descriptors */
	socklen_t addrlen;
	struct sockaddr_in remote;
	int resfd = 0, bytes = 0, pollerrs = 0;
	struct pollfd fds[5];
	int pipe_fd = session->media.pipefd[0];
	char buffer[1500];
	memset(buffer, 0, 1500);
	/* Loop */
	int num = 0;
	gboolean goon = TRUE;
	int astep = 0, vstep = 0;
	guint32 ats = 0, vts = 0;
	while(goon && session != NULL && !g_atomic_int_get(&session->destroyed) &&
			session->status > janus_sip_call_status_idle &&
			session->status < janus_sip_call_status_closing) {	/* FIXME We need a per-call watchdog as well */

		if(session->media.updated) {
			/* Apparently there was a session update */
			if(session->media.remote_ip != NULL && (inet_aton(session->media.remote_ip, &server_addr.sin_addr) != 0)) {
				janus_sip_connect_sockets(session, &server_addr);
			} else {
				JANUS_LOG(LOG_ERR, "[SIP-%p] Couldn't update session details: missing or invalid remote IP address? (%s)\n",
					session->account.username, session->media.remote_ip);
			}
			session->media.updated = FALSE;
		}

		/* Prepare poll */
		num = 0;
		if(session->media.audio_rtp_fd != -1) {
			fds[num].fd = session->media.audio_rtp_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(session->media.audio_rtcp_fd != -1) {
			fds[num].fd = session->media.audio_rtcp_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(session->media.video_rtp_fd != -1) {
			fds[num].fd = session->media.video_rtp_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(session->media.video_rtcp_fd != -1) {
			fds[num].fd = session->media.video_rtcp_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(pipe_fd != -1) {
			fds[num].fd = pipe_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		/* Wait for some data */
		resfd = poll(fds, num, 1000);
		if(resfd < 0) {
			if(errno == EINTR) {
				JANUS_LOG(LOG_HUGE, "[SIP-%s] Got an EINTR (%s), ignoring...\n", session->account.username, strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "[SIP-%s] Error polling...\n", session->account.username);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
			break;
		} else if(resfd == 0) {
			/* No data, keep going */
			continue;
		}
		if(session == NULL || g_atomic_int_get(&session->destroyed) ||
				session->status <= janus_sip_call_status_idle ||
				session->status >= janus_sip_call_status_closing)
			break;
		int i = 0;
		for(i=0; i<num; i++) {
			if(fds[i].revents & (POLLERR | POLLHUP)) {
				/* If we just updated the session, let's wait until things have calmed down */
				if(session->media.updated)
					break;
				/* Check the socket error */
				int error = 0;
				socklen_t errlen = sizeof(error);
				getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
				if(error == 0) {
					/* Maybe not a breaking error after all? */
					continue;
				} else if(error == 111) {
					/* ICMP error? If it's related to RTCP, let's just close the RTCP socket and move on */
					if(fds[i].fd == session->media.audio_rtcp_fd) {
						JANUS_LOG(LOG_WARN, "[SIP-%s] Got a '%s' on the audio RTCP socket, closing it\n",
							session->account.username, strerror(error));
						close(session->media.audio_rtcp_fd);
						session->media.audio_rtcp_fd = -1;
						continue;
					} else if(fds[i].fd == session->media.video_rtcp_fd) {
						JANUS_LOG(LOG_WARN, "[SIP-%s] Got a '%s' on the video RTCP socket, closing it\n",
							session->account.username, strerror(error));
						close(session->media.video_rtcp_fd);
						session->media.video_rtcp_fd = -1;
						continue;
					}
				}
				/* FIXME Should we be more tolerant of ICMP errors on RTP sockets as well? */
				pollerrs++;
				if(pollerrs < 100)
					continue;
				JANUS_LOG(LOG_ERR, "[SIP-%s] Too many errors polling %d (socket #%d): %s...\n", session->account.username,
					fds[i].fd, i, fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
				JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, error, strerror(error));
				goon = FALSE;	/* Can we assume it's pretty much over, after a POLLERR? */
				/* FIXME Simulate a "hangup" coming from the browser */
				janus_sip_hangup_media(session->handle);
				break;
			} else if(fds[i].revents & POLLIN) {
				if(pipe_fd != -1 && fds[i].fd == pipe_fd) {
					/* Poll interrupted for a reason, go on */
					int code = 0;
					(void)read(pipe_fd, &code, sizeof(int));
					break;
				}
				/* Got an RTP/RTCP packet */
				if(session->media.audio_rtp_fd != -1 && fds[i].fd == session->media.audio_rtp_fd) {
					/* Got something audio (RTP) */
					addrlen = sizeof(remote);
					bytes = recvfrom(session->media.audio_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
					if(bytes < 0) {
						/* Failed to read? */
						continue;
					}
					pollerrs = 0;
					janus_rtp_header *header = (janus_rtp_header *)buffer;
					if(session->media.audio_ssrc_peer != ntohl(header->ssrc)) {
						session->media.audio_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "Got SIP peer audio SSRC: %"SCNu32"\n", session->media.audio_ssrc_peer);
					}
					/* Is this SRTP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect(session->media.audio_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_ERR, "[SIP-%s] Audio SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n",
								session->account.username, janus_srtp_error_str(res), bytes, buflen, timestamp, seq);
							continue;
						}
						bytes = buflen;
					}
					/* Check if the SSRC changed (e.g., after a re-INVITE or UPDATE) */
					guint32 timestamp = ntohl(header->timestamp);
					janus_rtp_header_update(header, &session->media.context, FALSE, astep ? astep : 960);
					if(ats == 0) {
						ats = timestamp;
					} else if(astep == 0) {
						astep = timestamp-ats;
						if(astep < 0)
							astep = 0;
					}
					/* Save the frame if we're recording */
					janus_recorder_save_frame(session->arc_peer, buffer, bytes);
					/* Relay to browser */
					gateway->relay_rtp(session->handle, 0, buffer, bytes);
					continue;
				} else if(session->media.audio_rtcp_fd != -1 && fds[i].fd == session->media.audio_rtcp_fd) {
					/* Got something audio (RTCP) */
					addrlen = sizeof(remote);
					bytes = recvfrom(session->media.audio_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
					if(bytes < 0) {
						/* Failed to read? */
						continue;
					}
					pollerrs = 0;
					/* Is this SRTCP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect_rtcp(session->media.audio_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							JANUS_LOG(LOG_ERR, "[SIP-%s] Audio SRTCP unprotect error: %s (len=%d-->%d)\n",
								session->account.username, janus_srtp_error_str(res), bytes, buflen);
							continue;
						}
						bytes = buflen;
					}
					/* Relay to browser */
					gateway->relay_rtcp(session->handle, 0, buffer, bytes);
					continue;
				} else if(session->media.video_rtp_fd != -1 && fds[i].fd == session->media.video_rtp_fd) {
					/* Got something video (RTP) */
					addrlen = sizeof(remote);
					bytes = recvfrom(session->media.video_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
					if(bytes < 0) {
						/* Failed to read? */
						continue;
					}
					pollerrs = 0;
					janus_rtp_header *header = (janus_rtp_header *)buffer;
					if(session->media.video_ssrc_peer != ntohl(header->ssrc)) {
						session->media.video_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "Got SIP peer video SSRC: %"SCNu32"\n", session->media.video_ssrc_peer);
					}
					/* Is this SRTP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect(session->media.video_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_ERR, "[SIP-%s] Video SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n",
								session->account.username, janus_srtp_error_str(res), bytes, buflen, timestamp, seq);
							continue;
						}
						bytes = buflen;
					}
					/* Check if the SSRC changed (e.g., after a re-INVITE or UPDATE) */
					janus_rtp_header_update(header, &session->media.context, TRUE, vstep ? vstep : 4500);
					guint32 timestamp = ntohl(header->timestamp);
					if(vts == 0) {
						vts = timestamp;
					} else if(vstep == 0) {
						vstep = timestamp-vts;
						if(vstep < 0)
							vstep = 0;
					}
					/* Save the frame if we're recording */
					janus_recorder_save_frame(session->vrc_peer, buffer, bytes);
					/* Relay to browser */
					gateway->relay_rtp(session->handle, 1, buffer, bytes);
					continue;
				} else if(session->media.video_rtcp_fd != -1 && fds[i].fd == session->media.video_rtcp_fd) {
					/* Got something video (RTCP) */
					addrlen = sizeof(remote);
					bytes = recvfrom(session->media.video_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
					if(bytes < 0) {
						/* Failed to read? */
						continue;
					}
					pollerrs = 0;
					/* Is this SRTCP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect_rtcp(session->media.video_srtp_in, buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							JANUS_LOG(LOG_ERR, "[SIP-%s] Video SRTP unprotect error: %s (len=%d-->%d)\n",
								session->account.username, janus_srtp_error_str(res), bytes, buflen);
							continue;
						}
						bytes = buflen;
					}
					/* Relay to browser */
					gateway->relay_rtcp(session->handle, 1, buffer, bytes);
					continue;
				}
			}
		}
	}
	/* Cleanup the media session */
	janus_sip_media_cleanup(session);
	/* Done */
	JANUS_LOG(LOG_VERB, "Leaving SIP relay thread\n");
	session->relayer_thread = NULL;
	janus_refcount_decrease(&session->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}


/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data) {
	janus_sip_session *session = (janus_sip_session *)user_data;
	if(session == NULL) {
		g_thread_unref(g_thread_self());
		return NULL;
	}
	if(session->account.username == NULL) {
		janus_refcount_decrease(&session->ref);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Joining sofia loop thread (%s)...\n", session->account.username);
	session->stack = g_malloc0(sizeof(ssip_t));
	session->stack->session = session;
	session->stack->s_nua = NULL;
	session->stack->s_nh_r = NULL;
	session->stack->s_nh_i = NULL;
	session->stack->s_root = su_root_create(session->stack);
	su_home_init(session->stack->s_home);
	JANUS_LOG(LOG_VERB, "Setting up sofia stack (sip:%s@%s)\n", session->account.username, local_ip);
	char sip_url[128];
	char sips_url[128];
	char *ipv6;
	ipv6 = strstr(local_ip, ":");
	if(session->account.force_udp)
		g_snprintf(sip_url, sizeof(sip_url), "sip:%s%s%s:*;transport=udp", ipv6 ? "[" : "", local_ip, ipv6 ? "]" : "");
	else if(session->account.force_tcp)
		g_snprintf(sip_url, sizeof(sip_url), "sip:%s%s%s:*;transport=tcp", ipv6 ? "[" : "", local_ip, ipv6 ? "]" : "");
	else
		g_snprintf(sip_url, sizeof(sip_url), "sip:%s%s%s:*", ipv6 ? "[" : "", local_ip, ipv6 ? "]" : "");
	g_snprintf(sips_url, sizeof(sips_url), "sips:%s%s%s:*", ipv6 ? "[" : "", local_ip, ipv6 ? "]" : "");
	char outbound_options[256] = "use-rport no-validate";
	if(keepalive_interval > 0)
		g_strlcat(outbound_options, " options-keepalive", sizeof(outbound_options));
	if(!behind_nat)
		g_strlcat(outbound_options, " no-natify", sizeof(outbound_options));
	session->stack->s_nua = nua_create(session->stack->s_root,
				janus_sip_sofia_callback,
				session,
				SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, MESSAGE, INFO"),
				NUTAG_M_USERNAME(session->account.username),
				NUTAG_URL(sip_url),
				TAG_IF(session->account.sips, NUTAG_SIPS_URL(sips_url)),
				SIPTAG_USER_AGENT_STR(session->account.user_agent ? session->account.user_agent : user_agent),
				NUTAG_KEEPALIVE(keepalive_interval * 1000),	/* Sofia expects it in milliseconds */
				NUTAG_OUTBOUND(outbound_options),
				SIPTAG_SUPPORTED(NULL),
				TAG_NULL());
	su_root_run(session->stack->s_root);
	/* When we get here, we're done */
	nua_destroy(session->stack->s_nua);
	su_root_destroy(session->stack->s_root);
	session->stack->s_root = NULL;
	su_home_deinit(session->stack->s_home);
	su_home_unref(session->stack->s_home);
	g_free(session->stack);
	session->stack = NULL;
	janus_refcount_decrease(&session->ref);
	JANUS_LOG(LOG_VERB, "Leaving sofia loop thread...\n");
	g_thread_unref(g_thread_self());
	return NULL;
}
