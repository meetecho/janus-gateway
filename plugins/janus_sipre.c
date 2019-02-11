/*! \file   janus_sipre.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus SIPre plugin (libre)
 * \details Check the \ref sipre for more details.
 *
 * \ingroup plugins
 * \ref plugins
 *
 * \page sipre SIPre plugin documentation
 * This is basically a clone of the original SIP plugin, with the key
 * difference being that it uses \c libre (http://creytiv.com/re.html)
 * instead of Sofia SIP for its internal stack. As such, it provides an
 * alternative for those who don't want to, or can't, use the Sofia-based
 * SIP plugin. The API it exposes is exactly the same, meaning it should
 * be pretty straightforward to switch from one plugin to another on the
 * client side. The configuration file looks exactly the same as well.
 * As such, you can mostly refer to the \ref sipsofia for both.
 *
 * \section sipreapi SIPre Plugin API
 *
 * All requests you can send in the SIPre Plugin API are asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction.
 *
 * The supported requests are \c register , \c unregister , \c call ,
 * \c accept, \c info , \c message , \c dtmf_info , \c recording ,
 * \c hold , \c unhold and \c hangup . \c register can be used,
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
 * want to record); finally, \c hangup can be used to terminate the
 * communication at any time, either to hangup (BYE) an ongoing call or
 * to cancel/decline (CANCEL/BYE) a call that hasn't started yet.
 *
 * Actual API docs: TBD. For the time being, refer to the Sofia SIP plugin
 * documentation, as while some of the features listed there may not be
 * available in the SIPre plugin as of now, all of the messages are supposed
 * to be formatted exactly the same way.
 */

#include "plugin.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#include <jansson.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_msg.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_main.h>
#include <re_mem.h>
#include <re_mqueue.h>
#include <re_sdp.h>
#include <re_uri.h>
#include <re_sip.h>
#include <re_sipreg.h>
#include <re_sipsess.h>
#include <re_srtp.h>
#include <re_tmr.h>
#include <re_tls.h>
#include <re_dns.h>

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
#define JANUS_SIPRE_VERSION			1
#define JANUS_SIPRE_VERSION_STRING	"0.0.1"
#define JANUS_SIPRE_DESCRIPTION		"This is a simple SIP plugin for Janus (based on libre instead of Sofia), allowing WebRTC peers to register at a SIP server and call SIP user agents through a Janus instance."
#define JANUS_SIPRE_NAME			"JANUS SIPre plugin"
#define JANUS_SIPRE_AUTHOR			"Meetecho s.r.l."
#define JANUS_SIPRE_PACKAGE			"janus.plugin.sipre"

/* Plugin methods */
janus_plugin *create(void);
int janus_sipre_init(janus_callbacks *callback, const char *config_path);
void janus_sipre_destroy(void);
int janus_sipre_get_api_compatibility(void);
int janus_sipre_get_version(void);
const char *janus_sipre_get_version_string(void);
const char *janus_sipre_get_description(void);
const char *janus_sipre_get_name(void);
const char *janus_sipre_get_author(void);
const char *janus_sipre_get_package(void);
void janus_sipre_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_sipre_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_sipre_setup_media(janus_plugin_session *handle);
void janus_sipre_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sipre_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sipre_hangup_media(janus_plugin_session *handle);
void janus_sipre_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_sipre_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_sipre_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_sipre_init,
		.destroy = janus_sipre_destroy,

		.get_api_compatibility = janus_sipre_get_api_compatibility,
		.get_version = janus_sipre_get_version,
		.get_version_string = janus_sipre_get_version_string,
		.get_description = janus_sipre_get_description,
		.get_name = janus_sipre_get_name,
		.get_author = janus_sipre_get_author,
		.get_package = janus_sipre_get_package,

		.create_session = janus_sipre_create_session,
		.handle_message = janus_sipre_handle_message,
		.setup_media = janus_sipre_setup_media,
		.incoming_rtp = janus_sipre_incoming_rtp,
		.incoming_rtcp = janus_sipre_incoming_rtcp,
		.hangup_media = janus_sipre_hangup_media,
		.destroy_session = janus_sipre_destroy_session,
		.query_session = janus_sipre_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SIPRE_NAME);
	return &janus_sipre_plugin;
}

/* Parameter validation */
static struct janus_json_parameter request_parameters[] = {
	{"request", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter register_parameters[] = {
	{"type", JANUS_JSON_STRING, 0},
	{"send_register", JANUS_JSON_BOOL, 0},
	{"sips", JANUS_JSON_BOOL, 0},
	{"username", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"secret", JANUS_JSON_STRING, 0},
	{"authuser", JANUS_JSON_STRING, 0},
	{"display_name", JSON_STRING, 0},
	{"user_agent", JSON_STRING, 0},
	{"headers", JANUS_JSON_OBJECT, 0},
	{"refresh", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter proxy_parameters[] = {
	{"proxy", JSON_STRING, 0},
	{"outbound_proxy", JSON_STRING, 0}
};
static struct janus_json_parameter call_parameters[] = {
	{"uri", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"headers", JANUS_JSON_OBJECT, 0},
	{"srtp", JANUS_JSON_STRING, 0},
	{"srtp_profile", JSON_STRING, 0},
	/* The following are only needed in case "guest" registrations
	 * still need an authenticated INVITE for some reason */
	{"secret", JSON_STRING, 0},
	{"authuser", JSON_STRING, 0}
};
static struct janus_json_parameter accept_parameters[] = {
	{"srtp", JANUS_JSON_STRING, 0},
	{"headers", JSON_OBJECT, 0}
};
static struct janus_json_parameter recording_parameters[] = {
	{"action", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"audio", JANUS_JSON_BOOL, 0},
	{"video", JANUS_JSON_BOOL, 0},
	{"peer_audio", JANUS_JSON_BOOL, 0},
	{"peer_video", JANUS_JSON_BOOL, 0},
	{"filename", JANUS_JSON_STRING, 0}
};
static struct janus_json_parameter dtmf_info_parameters[] = {
	{"digit", JANUS_JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"duration", JANUS_JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
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

static char *local_ip = NULL, *sdp_ip = NULL;
static gboolean behind_nat = FALSE;
static char *user_agent;
#define JANUS_DEFAULT_REGISTER_TTL	3600
static uint32_t register_ttl = JANUS_DEFAULT_REGISTER_TTL;
static uint16_t rtp_range_min = 10000;
static uint16_t rtp_range_max = 60000;

static GThread *handler_thread;
static void *janus_sipre_handler(void *data);
static void janus_sipre_hangup_media_internal(janus_plugin_session *handle);

typedef struct janus_sipre_message {
	janus_plugin_session *handle;
	char *transaction;
	json_t *message;
	json_t *jsep;
} janus_sipre_message;
static GAsyncQueue *messages = NULL;
static janus_sipre_message exit_message;


/* libre SIP stack */
static volatile int libre_inited = 0;
GThread *sipstack_thread = NULL;

/* Message queue */
static struct mqueue *mq = NULL;
void janus_sipre_mqueue_handler(int id, void *data, void *arg);
typedef enum janus_sipre_mqueue_event {
	janus_sipre_mqueue_event_do_init,
	janus_sipre_mqueue_event_do_register,
	janus_sipre_mqueue_event_do_unregister,
	janus_sipre_mqueue_event_do_call,
	janus_sipre_mqueue_event_do_accept,
	janus_sipre_mqueue_event_do_rcode,
	janus_sipre_mqueue_event_do_update,
	janus_sipre_mqueue_event_do_info,
	janus_sipre_mqueue_event_do_message,
	janus_sipre_mqueue_event_do_bye,
	janus_sipre_mqueue_event_do_close,
	janus_sipre_mqueue_event_do_destroy,
	/* TODO Add other events here */
	janus_sipre_mqueue_event_do_exit
} janus_sipre_mqueue_event;
static const char *janus_sipre_mqueue_event_string(janus_sipre_mqueue_event event) {
	switch(event) {
		case janus_sipre_mqueue_event_do_init:
			return "init";
		case janus_sipre_mqueue_event_do_register:
			return "register";
		case janus_sipre_mqueue_event_do_unregister:
			return "unregister";
		case janus_sipre_mqueue_event_do_call:
			return "call";
		case janus_sipre_mqueue_event_do_accept:
			return "accept";
		case janus_sipre_mqueue_event_do_rcode:
			return "rcode";
		case janus_sipre_mqueue_event_do_update:
			return "update";
		case janus_sipre_mqueue_event_do_info:
			return "info";
		case janus_sipre_mqueue_event_do_message:
			return "message";
		case janus_sipre_mqueue_event_do_bye:
			return "bye";
		case janus_sipre_mqueue_event_do_close:
			return "close";
		case janus_sipre_mqueue_event_do_destroy:
			return "destroy";
		case janus_sipre_mqueue_event_do_exit:
			return "exit";
		default:
			return "unknown";
	}
}
typedef struct janus_sipre_session janus_sipre_session;
typedef struct janus_sipre_mqueue_payload {
	janus_sipre_session *session;	/* The session this event refers to */
	const struct sip_msg *msg;		/* The SIP message this refers to, if any */
	int rcode;						/* The error code to send back, if any */
	void *data;						/* Payload specific data */
} janus_sipre_mqueue_payload;

/* Helper to quickly get the reason associated to response codes */
static const char *janus_sipre_error_reason(int rcode) {
	switch(rcode) {
		case 100: return "Trying";
		case 180: return "Ringing";
		case 181: return "Call is Being Forwarded";
		case 182: return "Queued";
		case 183: return "Session in Progress";
		case 199: return "Early Dialog Terminated";
		case 200: return "OK";
		case 202: return "Accepted";
		case 204: return "No Notification";
		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Moved Temporarily";
		case 305: return "Use Proxy";
		case 380: return "Alternative Service";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Conditional Request Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Unsupported URI Scheme";
		case 417: return "Unknown Resource-Priority";
		case 420: return "Bad Extension";
		case 421: return "Extension Required";
		case 422: return "Session Interval Too Small";
		case 423: return "Interval Too Brief";
		case 424: return "Bad Location Information";
		case 428: return "Use Identity Header";
		case 429: return "Provide Referrer Identity";
		case 430: return "Flow Failed";
		case 433: return "Anonymity Disallowed";
		case 436: return "Bad Identity-Info";
		case 437: return "Unsupported Certificate";
		case 438: return "Invalid Identity Header";
		case 439: return "First Hop Lacks Outbound Support";
		case 470: return "Consent Needed";
		case 480: return "Temporarily Unavailable";
		case 481: return "Call/Transaction Does Not Exist";
		case 482: return "Loop Detected.";
		case 483: return "Too Many Hops";
		case 484: return "Address Incomplete";
		case 485: return "Ambiguous";
		case 486: return "Busy Here";
		case 487: return "Request Terminated";
		case 488: return "Not Acceptable Here";
		case 489: return "Bad Event";
		case 491: return "Request Pending";
		case 493: return "Undecipherable";
		case 494: return "Security Agreement Required";
		case 500: return "Server Internal Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Server Time-out";
		case 505: return "Version Not Supported";
		case 513: return "Message Too Large";
		case 580: return "Precondition Failure";
		case 600: return "Busy Everywhere";
		case 603: return "Decline";
		case 604: return "Does Not Exist Anywhere";
		case 606: return "Not Acceptable";
		default: return "Unknown Error";
	}
}

/* Registration info */
typedef enum {
	janus_sipre_registration_status_disabled = -2,
	janus_sipre_registration_status_failed = -1,
	janus_sipre_registration_status_unregistered = 0,
	janus_sipre_registration_status_registering,
	janus_sipre_registration_status_registered,
	janus_sipre_registration_status_unregistering,
} janus_sipre_registration_status;

static const char *janus_sipre_registration_status_string(janus_sipre_registration_status status) {
	switch(status) {
		case janus_sipre_registration_status_disabled:
			return "disabled";
		case janus_sipre_registration_status_failed:
			return "failed";
		case janus_sipre_registration_status_unregistered:
			return "unregistered";
		case janus_sipre_registration_status_registering:
			return "registering";
		case janus_sipre_registration_status_registered:
			return "registered";
		case janus_sipre_registration_status_unregistering:
			return "unregistering";
		default:
			return "unknown";
	}
}


typedef enum {
	janus_sipre_call_status_idle = 0,
	janus_sipre_call_status_inviting,
	janus_sipre_call_status_invited,
	janus_sipre_call_status_incall,
	janus_sipre_call_status_closing,
} janus_sipre_call_status;

static const char *janus_sipre_call_status_string(janus_sipre_call_status status) {
	switch(status) {
		case janus_sipre_call_status_idle:
			return "idle";
		case janus_sipre_call_status_inviting:
			return "inviting";
		case janus_sipre_call_status_invited:
			return "invited";
		case janus_sipre_call_status_incall:
			return "incall";
		case janus_sipre_call_status_closing:
			return "closing";
		default:
			return "unknown";
	}
}


typedef enum {
	janus_sipre_secret_type_plaintext = 1,
	janus_sipre_secret_type_hashed = 2,	/* FIXME Unused */
	janus_sipre_secret_type_unknown
} janus_sipre_secret_type;

typedef struct janus_sipre_account {
	char *identity;
	gboolean sips;
	char *username;
	char *display_name;		/* Used for outgoing calls in the From header */
	char *authuser;			/**< username to use for authentication */
	char *secret;
	janus_sipre_secret_type secret_type;
	int sip_port;
	char *proxy;
	char *outbound_proxy;
	janus_sipre_registration_status registration_status;
} janus_sipre_account;

typedef struct janus_sipre_stack {
	struct sip *sipstack;				/* SIP stack */
	struct tls *tls;					/* TLS transport, if needed */
	struct sipsess *sess;				/* SIP session */
	struct sipsess_sock *sess_sock;		/* SIP session socket */
	struct sipreg *reg;					/* SIP registration */
	struct dnsc *dns_client;			/* DNS client */
	uint32_t expires;					/* Registration interval (seconds) */
	const struct sip_msg *invite;		/* Current INVITE */
	void *session;						/* Opaque pointer to the plugin session */
} janus_sipre_stack;

typedef struct janus_sipre_media {
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
	int video_pt;
	const char *video_pt_name;
	srtp_t video_srtp_in, video_srtp_out;
	srtp_policy_t video_remote_policy, video_local_policy;
	gboolean video_send;
	janus_sdp_mdirection pre_hold_video_dir;
	janus_rtp_switching_context context;
	int pipefd[2];
	gboolean updated;
} janus_sipre_media;

struct janus_sipre_session {
	janus_plugin_session *handle;
	janus_sipre_stack stack;
	janus_sipre_account account;
	janus_sipre_call_status status;
	janus_sipre_media media;
	char *transaction;
	char *callee;
	char *callid;
	char *temp_sdp;
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
};
static GHashTable *sessions;
static GHashTable *identities;
static GHashTable *callids;
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;

static janus_sipre_mqueue_payload *janus_sipre_mqueue_payload_create(janus_sipre_session *session, const struct sip_msg *msg, int rcode, void *data) {
	janus_sipre_mqueue_payload *payload = g_malloc(sizeof(janus_sipre_mqueue_payload));
	if(session)
		janus_refcount_increase(&session->ref);
	payload->session = session;
	payload->msg = msg;
	payload->rcode = rcode;
	payload->data = data;
	return payload;
}
static void janus_sipre_mqueue_payload_free(janus_sipre_mqueue_payload *payload) {
	if(payload == NULL)
		return;
	if(payload->session)
		janus_refcount_decrease(&payload->session->ref);
	g_free(payload);
}

static void janus_sipre_srtp_cleanup(janus_sipre_session *session);

static void janus_sipre_session_destroy(janus_sipre_session *session) {
	if(session && g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1)) {
		/* Unregister */
		mqueue_push(mq, janus_sipre_mqueue_event_do_unregister, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));
		/* Close re-related stuff for this SIP session */
		mqueue_push(mq, janus_sipre_mqueue_event_do_close, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));
		/* Destroy this SIP session in the queue handler */
		mqueue_push(mq, janus_sipre_mqueue_event_do_destroy, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));
	}
}

static void janus_sipre_session_free(const janus_refcount *session_ref) {
	janus_sipre_session *session = janus_refcount_containerof(session_ref, janus_sipre_session, ref);
	/* Remove the reference to the core plugin session */
	janus_refcount_decrease(&session->handle->ref);
	/* This session can be destroyed, free all the resources */
	if(session->account.identity) {
		g_hash_table_remove(identities, session->account.identity);
		g_free(session->account.identity);
		session->account.identity = NULL;
	}
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
	janus_sipre_srtp_cleanup(session);
	session->handle = NULL;
	g_free(session);
	session = NULL;
}

static void janus_sipre_message_free(janus_sipre_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	if(msg->handle && msg->handle->plugin_handle) {
		janus_sipre_session *session = (janus_sipre_session *)msg->handle->plugin_handle;
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


/* SRTP stuff (in case we need SDES) */
static int janus_sipre_srtp_set_local(janus_sipre_session *session, gboolean video, char **profile, char **crypto) {
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
		JANUS_LOG(LOG_ERR, "[SIPre-%s] Unsupported SRTP profile\n", session->account.username);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[SIPre-%s] %s\n", session->account.username, *profile);
	JANUS_LOG(LOG_WARN, "[SIPre-%s] Key/Salt/Master: %d/%d/%d\n",
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
			JANUS_LOG(LOG_WARN, "[SIPre-%s] Unsupported SRTP profile\n", session->account.username);
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
static int janus_sipre_srtp_set_remote(janus_sipre_session *session, gboolean video, const char *profile, const char *crypto) {
	if(session == NULL || profile == NULL || crypto == NULL)
		return -1;
	/* Which SRTP profile is being negotiated? */
	JANUS_LOG(LOG_WARN, "[SIPre-%s] %s\n", session->account.username, profile);
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
		JANUS_LOG(LOG_ERR, "[SIPre-%s] Unsupported SRTP profile %s\n", session->account.username, profile);
		return -2;
	}
	JANUS_LOG(LOG_WARN, "[SIPre-%s] Key/Salt/Master: %zu/%zu/%zu\n",
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
			JANUS_LOG(LOG_WARN, "[SIPre-%s] Unsupported SRTP profile\n", session->account.username);
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
static void janus_sipre_srtp_cleanup(janus_sipre_session *session) {
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


/* libre event thread */
gpointer janus_sipre_stack_thread(gpointer user_data);
/* libre callbacks */
int janus_sipre_cb_auth(char **user, char **pass, const char *realm, void *arg);
void janus_sipre_cb_register(int err, const struct sip_msg *msg, void *arg);
void janus_sipre_cb_progress(const struct sip_msg *msg, void *arg);
void janus_sipre_cb_incoming(const struct sip_msg *msg, void *arg);
int janus_sipre_cb_offer(struct mbuf **mbp, const struct sip_msg *msg, void *arg);
int janus_sipre_cb_answer(const struct sip_msg *msg, void *arg);
void janus_sipre_cb_established(const struct sip_msg *msg, void *arg);
void janus_sipre_cb_info(struct sip *sip, const struct sip_msg *msg, void *arg);
void janus_sipre_cb_closed(int err, const struct sip_msg *msg, void *arg);
void janus_sipre_cb_exit(void *arg);

/* URI parsing utilities */
static int janus_sipre_parse_uri(const char *uri) {
	if(uri == NULL)
		return -1;
	struct sip_addr addr;
	struct pl pluri;
	pl_set_str(&pluri, uri);
	if(sip_addr_decode(&addr, &pluri) != 0)
		return -1;
	return 0;
}
static char *janus_sipre_get_uri_username(const char *uri) {
	if(uri == NULL)
		return NULL;
	struct sip_addr addr;
	struct pl pluri;
	pl_set_str(&pluri, uri);
	if(sip_addr_decode(&addr, &pluri) != 0)
		return NULL;
	char *at = strchr(addr.uri.user.p, '@');
	if(at != NULL)
		*(at) = '\0';
	char *username = g_strdup(addr.uri.user.p);
	if(at != NULL)
		*(at) = '@';
	return username;
}
static char *janus_sipre_get_uri_host(const char *uri) {
	if(uri == NULL)
		return NULL;
	struct sip_addr addr;
	struct pl pluri;
	pl_set_str(&pluri, uri);
	if(sip_addr_decode(&addr, &pluri) != 0)
		return NULL;
	return g_strdup(addr.uri.host.p);
}
static uint16_t janus_sipre_get_uri_port(const char *uri) {
	if(uri == NULL)
		return 0;
	struct sip_addr addr;
	struct pl pluri;
	pl_set_str(&pluri, uri);
	if(sip_addr_decode(&addr, &pluri) != 0)
		return 0;
	return addr.uri.port;
}


/* SDP parsing and manipulation */
void janus_sipre_sdp_process(janus_sipre_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed);
char *janus_sipre_sdp_manipulate(janus_sipre_session *session, janus_sdp *sdp, gboolean answer);
/* Media */
static int janus_sipre_allocate_local_ports(janus_sipre_session *session);
static void *janus_sipre_relay_thread(void *data);
static void janus_sipre_media_cleanup(janus_sipre_session *session);


/* Error codes */
#define JANUS_SIPRE_ERROR_UNKNOWN_ERROR		499
#define JANUS_SIPRE_ERROR_NO_MESSAGE			440
#define JANUS_SIPRE_ERROR_INVALID_JSON		441
#define JANUS_SIPRE_ERROR_INVALID_REQUEST		442
#define JANUS_SIPRE_ERROR_MISSING_ELEMENT		443
#define JANUS_SIPRE_ERROR_INVALID_ELEMENT		444
#define JANUS_SIPRE_ERROR_ALREADY_REGISTERED	445
#define JANUS_SIPRE_ERROR_INVALID_ADDRESS		446
#define JANUS_SIPRE_ERROR_WRONG_STATE			447
#define JANUS_SIPRE_ERROR_MISSING_SDP			448
#define JANUS_SIPRE_ERROR_LIBRE_ERROR		449
#define JANUS_SIPRE_ERROR_IO_ERROR			450
#define JANUS_SIPRE_ERROR_RECORDING_ERROR		451
#define JANUS_SIPRE_ERROR_TOO_STRICT			452


/* Random string helper (for call-ids) */
static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static void janus_sipre_random_string(int length, char *buffer) {
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

static void janus_sipre_parse_custom_headers(json_t *root, char *custom_headers) {
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

#ifdef HAVE_LIBRE_SIPTRACE
/* libre SIP logger function: when the Event Handlers mechanism is enabled,
 * we use this to intercept SIP messages sent and received by the stack */
static void janus_sipre_msg_logger(bool tx, enum sip_transp tp, const struct sa *src, const struct sa *dst,
		const uint8_t *pkt, size_t len, void *arg) {
	/* Access the session this message refers to */
	janus_sipre_session *session = (janus_sipre_session *)arg;
	/* Print the SIP message */
	char sip_msg[2048];
	g_snprintf(sip_msg, sizeof(sip_msg), "%.*s", (int)len, (char *)pkt);
	/* Shoot the event */
	json_t *info = json_object();
	json_object_set_new(info, "event", json_string(tx ? "sip-out" : "sip-in"));
	json_object_set_new(info, "sip", json_string(sip_msg));
	gateway->notify_event(&janus_sipre_plugin, session->handle, info);
}
#endif


/* Plugin implementation */
int janus_sipre_init(janus_callbacks *callback, const char *config_path) {
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
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_SIPRE_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_SIPRE_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_SIPRE_PACKAGE);
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

		item = janus_config_get(config, config_general, janus_config_type_item, "sdp_ip");
		if(item && item->value) {
			sdp_ip = g_strdup(item->value);
			JANUS_LOG(LOG_VERB, "IP to advertise in SDP: %s\n", sdp_ip);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "register_ttl");
		if(item && item->value) {
			register_ttl = atol(item->value);
			if(register_ttl <= 0) {
				JANUS_LOG(LOG_WARN, "Invalid value of register_ttl, using default instead\n");
				register_ttl = JANUS_DEFAULT_REGISTER_TTL;
			}
		}
		JANUS_LOG(LOG_VERB, "SIPre registration TTL set to %d seconds\n", register_ttl);

		item = janus_config_get(config, config_general, janus_config_type_item, "behind_nat");
		if(item && item->value) {
			behind_nat = janus_is_true(item->value);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "user_agent");
		if(item && item->value) {
			user_agent = g_strdup(item->value);
		} else {
			user_agent = g_strdup("Janus WebRTC Server SIPre Plugin "JANUS_SIPRE_VERSION_STRING);
		}
		JANUS_LOG(LOG_VERB, "SIPre User-Agent set to %s\n", user_agent);

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
			JANUS_LOG(LOG_VERB, "SIPre RTP/RTCP port range: %u -- %u\n", rtp_range_min, rtp_range_max);
		}

		item = janus_config_get(config, config_general, janus_config_type_item, "events");
		if(item != NULL && item->value != NULL) {
			notify_events = janus_is_true(item->value);
		}
		if(!notify_events && callback->events_is_enabled()) {
			JANUS_LOG(LOG_WARN, "Notification of events to handlers disabled for %s\n", JANUS_SIPRE_NAME);
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

	sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_sipre_session_destroy);
	callids = g_hash_table_new(g_str_hash, g_str_equal);
	identities = g_hash_table_new(g_str_hash, g_str_equal);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_sipre_message_free);
	/* This is the callback we'll need to invoke to contact the Janus core */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Launch the thread that will handle incoming API messages */
	handler_thread = g_thread_try_new("sipre handler", janus_sipre_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIPre handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle the libre initialization and event loop */
	g_atomic_int_set(&libre_inited, 0);
	sipstack_thread = g_thread_try_new("sipre loop", janus_sipre_stack_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIPre loop thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Let's wait for the libre initialization to complete */
	while(g_atomic_int_get(&libre_inited) == 0)
		g_usleep(100000);
	if(g_atomic_int_get(&libre_inited) == -1) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error trying to initialize libre...\n");
		return -1;
	}

#ifndef HAVE_LIBRE_SIPTRACE
	JANUS_LOG(LOG_WARN, "sip_set_trace() was not found in libre... "
		"The tracing of SIP incoming/outgoing SIP messages when using the SIPre plugin will not be available to Event Handlers. "
		"In case you're interested in that, apply this patch on your libre installation and recompile the plugin: "
		"https://raw.githubusercontent.com/alfredh/patches/master/re-sip-trace.patch\n");
#endif

	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_SIPRE_NAME);
	return 0;
}

void janus_sipre_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}

	/* Break the libre loop */
	mqueue_push(mq, janus_sipre_mqueue_event_do_exit, NULL);
	if(sipstack_thread != NULL) {
		g_thread_join(sipstack_thread);
		sipstack_thread = NULL;
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

	g_free(local_ip);
	g_free(sdp_ip);

	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SIPRE_NAME);
}

int janus_sipre_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_sipre_get_version(void) {
	return JANUS_SIPRE_VERSION;
}

const char *janus_sipre_get_version_string(void) {
	return JANUS_SIPRE_VERSION_STRING;
}

const char *janus_sipre_get_description(void) {
	return JANUS_SIPRE_DESCRIPTION;
}

const char *janus_sipre_get_name(void) {
	return JANUS_SIPRE_NAME;
}

const char *janus_sipre_get_author(void) {
	return JANUS_SIPRE_AUTHOR;
}

const char *janus_sipre_get_package(void) {
	return JANUS_SIPRE_PACKAGE;
}

static janus_sipre_session *janus_sipre_lookup_session(janus_plugin_session *handle) {
	janus_sipre_session *session = NULL;
	if (g_hash_table_contains(sessions, handle)) {
		session = (janus_sipre_session *)handle->plugin_handle;
	}
	return session;
}

void janus_sipre_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_sipre_session *session = g_malloc0(sizeof(janus_sipre_session));
	session->handle = handle;
	session->account.identity = NULL;
	session->account.sips = TRUE;
	session->account.username = NULL;
	session->account.display_name = NULL;
	session->account.authuser = NULL;
	session->account.secret = NULL;
	session->account.secret_type = janus_sipre_secret_type_unknown;
	session->account.sip_port = 0;
	session->account.proxy = NULL;
	session->account.outbound_proxy = NULL;
	session->account.registration_status = janus_sipre_registration_status_unregistered;
	session->status = janus_sipre_call_status_idle;
	memset(&session->stack, 0, sizeof(janus_sipre_stack));
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
	g_atomic_int_set(&session->destroyed, 0);
	g_atomic_int_set(&session->hangingup, 0);
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;
	janus_refcount_init(&session->ref, janus_sipre_session_free);

	mqueue_push(mq, janus_sipre_mqueue_event_do_init, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);


	return;
}

void janus_sipre_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_sipre_session *session = janus_sipre_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		JANUS_LOG(LOG_ERR, "No SIPre session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Destroying SIPre session (%s)...\n", session->account.username ? session->account.username : "unregistered user");
	janus_sipre_hangup_media_internal(handle);
	/* Remove the session from the table: this will trigger a destroy */
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

json_t *janus_sipre_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_mutex_lock(&sessions_mutex);
	janus_sipre_session *session = janus_sipre_lookup_session(handle);
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
	json_object_set_new(info, "identity", session->account.identity ? json_string(session->account.identity) : NULL);
	json_object_set_new(info, "registration_status", json_string(janus_sipre_registration_status_string(session->account.registration_status)));
	json_object_set_new(info, "call_status", json_string(janus_sipre_call_status_string(session->status)));
	if(session->callee) {
		json_object_set_new(info, "callee", json_string(session->callee ? session->callee : "??"));
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

struct janus_plugin_result *janus_sipre_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized", NULL);

	janus_mutex_lock(&sessions_mutex);
	janus_sipre_session *session = janus_sipre_lookup_session(handle);
	if(!session) {
		janus_mutex_unlock(&sessions_mutex);
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "No session associated with this handle", NULL);
	}
	/* Increase the reference counter for this session: we'll decrease it after we handle the message */
	janus_refcount_increase(&session->ref);
	janus_mutex_unlock(&sessions_mutex);

	janus_sipre_message *msg = g_malloc(sizeof(janus_sipre_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->jsep = jsep;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL, NULL);
}

void janus_sipre_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_mutex_lock(&sessions_mutex);
	janus_sipre_session *session = janus_sipre_lookup_session(handle);
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

void janus_sipre_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_sipre_session *session = (janus_sipre_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		/* Forward to our SIPre peer */
		if((video && !session->media.video_send) || (!video && !session->media.audio_send)) {
			/* Dropping packet, peer doesn't want to receive it */
			return;
		}
		if((video && session->media.video_ssrc == 0) || (!video && session->media.audio_ssrc == 0)) {
			rtp_header *header = (rtp_header *)buf;
			if(video) {
				session->media.video_ssrc = ntohl(header->ssrc);
			} else {
				session->media.audio_ssrc = ntohl(header->ssrc);
			}
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Got SIPre %s SSRC: %"SCNu32"\n",
				session->account.username ? session->account.username : "unknown",
				video ? "video" : "audio",
				video ? session->media.video_ssrc : session->media.audio_ssrc);
		}
		if((video && session->media.has_video && session->media.video_rtp_fd != -1) ||
				(!video && session->media.has_audio && session->media.audio_rtp_fd != -1)) {
			/* Save the frame if we're recording */
			janus_recorder_save_frame(video ? session->vrc : session->arc, buf, len);
			/* Is SRTP involved? */
			if(session->media.has_srtp_local) {
				char sbuf[2048];
				memcpy(&sbuf, buf, len);
				int protected = len;
				int res = srtp_protect(
					(video ? session->media.video_srtp_out : session->media.audio_srtp_out),
					&sbuf, &protected);
				if(res != srtp_err_status_ok) {
					rtp_header *header = (rtp_header *)&sbuf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[SIPre-%s] %s SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						session->account.username ? session->account.username : "unknown",
						video ? "Video" : "Audio", janus_srtp_error_str(res), len, protected, timestamp, seq);
				} else {
					/* Forward the frame to the peer */
					if(send((video ? session->media.video_rtp_fd : session->media.audio_rtp_fd), sbuf, protected, 0) < 0) {
						rtp_header *header = (rtp_header *)&sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_HUGE, "[SIPre-%s] Error sending %s SRTP packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
							session->account.username ? session->account.username : "unknown",
							video ? "Video" : "Audio", strerror(errno), protected, timestamp, seq);
					}
				}
			} else {
				/* Forward the frame to the peer */
				if(send((video ? session->media.video_rtp_fd : session->media.audio_rtp_fd), buf, len, 0) < 0) {
					rtp_header *header = (rtp_header *)&buf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_HUGE, "[SIPre-%s] Error sending %s RTP packet... %s (len=%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						session->account.username ? session->account.username : "unknown",
						video ? "Video" : "Audio", strerror(errno), len, timestamp, seq);
				}
			}
		}
	}
}

void janus_sipre_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_sipre_session *session = (janus_sipre_session *)handle->plugin_handle;
		if(!session || g_atomic_int_get(&session->destroyed)) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		/* Forward to our SIPre peer */
		if((video && session->media.has_video && session->media.video_rtcp_fd != -1) ||
				(!video && session->media.has_audio && session->media.audio_rtcp_fd != -1)) {
			/* Fix SSRCs as the Janus core does */
			JANUS_LOG(LOG_HUGE, "[SIPre-%s] Fixing %s SSRCs (local %u, peer %u)\n",
				session->account.username ? session->account.username : "unknown",
				video ? "video" : "audio",
				(video ? session->media.video_ssrc : session->media.audio_ssrc),
				(video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer));
			janus_rtcp_fix_ssrc(NULL, (char *)buf, len, video,
				(video ? session->media.video_ssrc : session->media.audio_ssrc),
				(video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer));
			/* Is SRTP involved? */
			if(session->media.has_srtp_local) {
				char sbuf[2048];
				memcpy(&sbuf, buf, len);
				int protected = len;
				int res = srtp_protect_rtcp(
					(video ? session->media.video_srtp_out : session->media.audio_srtp_out),
					&sbuf, &protected);
				if(res != srtp_err_status_ok) {
					JANUS_LOG(LOG_ERR, "[SIPre-%s] %s SRTCP protect error... %s (len=%d-->%d)...\n",
						session->account.username ? session->account.username : "unknown",
						video ? "Video" : "Audio",
						janus_srtp_error_str(res), len, protected);
				} else {
					/* Forward the message to the peer */
					if(send((video ? session->media.video_rtcp_fd : session->media.audio_rtcp_fd), sbuf, protected, 0) < 0) {
						JANUS_LOG(LOG_HUGE, "[SIPre-%s] Error sending %s SRTCP packet... %s (len=%d)...\n",
							session->account.username ? session->account.username : "unknown",
							video ? "Video" : "Audio", strerror(errno), protected);
					}
				}
			} else {
				/* Forward the message to the peer */
				if(send((video ? session->media.video_rtcp_fd : session->media.audio_rtcp_fd), buf, len, 0) < 0) {
					JANUS_LOG(LOG_HUGE, "[SIPre-%s] Error sending %s RTCP packet... %s (len=%d)...\n",
						session->account.username ? session->account.username : "unknown",
						video ? "Video" : "Audio", strerror(errno), len);
				}
			}
		}
	}
}

static void janus_sipre_recorder_close(janus_sipre_session *session,
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

void janus_sipre_hangup_media(janus_plugin_session *handle) {
	janus_mutex_lock(&sessions_mutex);
	janus_sipre_hangup_media_internal(handle);
	janus_mutex_unlock(&sessions_mutex);
}

static void janus_sipre_hangup_media_internal(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_sipre_session *session = janus_sipre_lookup_session(handle);
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(g_atomic_int_get(&session->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&session->hangingup, 0, 1))
		return;
	/* Do cleanup if media thread has not been created */
	if(!session->media.ready && !session->relayer_thread) {
		janus_sipre_media_cleanup(session);
	}
	session->media.ready = FALSE;
	session->media.on_hold = FALSE;
	session->status = janus_sipre_call_status_closing;
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	janus_sipre_recorder_close(session, TRUE, TRUE, TRUE, TRUE);
	janus_mutex_unlock(&session->rec_mutex);
	g_atomic_int_set(&session->hangingup, 0);
	if(!(session->status == janus_sipre_call_status_inviting ||
		 session->status == janus_sipre_call_status_invited ||
		 session->status == janus_sipre_call_status_incall)) {
		g_atomic_int_set(&session->hangingup, 0);
		return;
	}
	/* Enqueue the BYE */
	mqueue_push(mq, janus_sipre_mqueue_event_do_bye, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));
}

/* Thread to handle incoming messages */
static void *janus_sipre_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining SIPre handler thread\n");
	janus_sipre_message *msg = NULL;
	int error_code = 0;
	char error_cause[512];
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_sipre_message_free(msg);
			continue;
		}
		janus_mutex_lock(&sessions_mutex);
		janus_sipre_session *session = janus_sipre_lookup_session(msg->handle);
		if(!session) {
			janus_mutex_unlock(&sessions_mutex);
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_sipre_message_free(msg);
			continue;
		}
		if(g_atomic_int_get(&session->destroyed)) {
			janus_mutex_unlock(&sessions_mutex);
			janus_sipre_message_free(msg);
			continue;
		}
		janus_mutex_unlock(&sessions_mutex);
		/* Handle request */
		error_code = 0;
		root = msg->message;
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_SIPRE_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_SIPRE_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, request_parameters,
			error_code, error_cause, TRUE,
			JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
		if(error_code != 0)
			goto error;
		json_t *request = json_object_get(root, "request");
		const char *request_text = json_string_value(request);
		json_t *result = NULL;

		if(!strcasecmp(request_text, "register")) {
			JANUS_VALIDATE_JSON_OBJECT(root, register_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			gboolean refresh = json_is_true(json_object_get(root, "refresh"));
			if(session->account.registration_status > janus_sipre_registration_status_unregistered && !refresh) {
				JANUS_LOG(LOG_ERR, "Already registered (%s)\n", session->account.username);
				error_code = JANUS_SIPRE_ERROR_ALREADY_REGISTERED;
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
					error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Conflicting elements: send_register cannot be true if guest is true");
					goto error;
				}
				send_register = json_is_true(do_register);
			}

			gboolean sips = TRUE;
			json_t *do_sipres = json_object_get(root, "sips");
			if(do_sipres != NULL) {
				sips = json_is_true(do_sipres);
			}

			/* Parse address */
			json_t *proxy = json_object_get(root, "proxy");
			const char *proxy_text = NULL;
			if(proxy && !json_is_null(proxy)) {
				/* Has to be validated separately because it could be null */
				JANUS_VALIDATE_JSON_OBJECT(root, proxy_parameters,
					error_code, error_cause, TRUE,
					JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				proxy_text = json_string_value(proxy);
				if(janus_sipre_parse_uri(proxy_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid proxy address %s\n", proxy_text);
					error_code = JANUS_SIPRE_ERROR_INVALID_ADDRESS;
					g_snprintf(error_cause, 512, "Invalid proxy address %s\n", proxy_text);
					goto error;
				}
			}
			json_t *outbound_proxy = json_object_get(root, "outbound_proxy");
			const char *obproxy_text = NULL;
			if(outbound_proxy && !json_is_null(outbound_proxy)) {
				/* Has to be validated separately because it could be null */
				JANUS_VALIDATE_JSON_OBJECT(root, proxy_parameters,
					error_code, error_cause, TRUE,
					JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
				if(error_code != 0)
					goto error;
				obproxy_text = json_string_value(outbound_proxy);
				if(janus_sipre_parse_uri(obproxy_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid outbound_proxy address %s\n", obproxy_text);
					error_code = JANUS_SIPRE_ERROR_INVALID_ADDRESS;
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
				ttl = register_ttl;
			session->stack.expires = ttl;

			/* Parse display name */
			const char* display_name_text = NULL;
			json_t *display_name = json_object_get(root, "display_name");
			if(display_name && json_is_string(display_name))
				display_name_text = json_string_value(display_name);

			/* Now the user part (always needed, even for the guest case) */
			json_t *username = json_object_get(root, "username");
			if(!username) {
				/* The username is mandatory even when registering as guests */
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (username)");
				goto error;
			}
			const char *username_text = NULL;
			const char *secret_text = NULL;
			const char *authuser_text = NULL;
			janus_sipre_secret_type secret_type = janus_sipre_secret_type_plaintext;
			char *user_id = NULL, *user_host = NULL;
			guint16 user_port = 0;
			/* Parse address */
			username_text = json_string_value(username);
			if(janus_sipre_parse_uri(username_text) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
				error_code = JANUS_SIPRE_ERROR_INVALID_ADDRESS;
				g_snprintf(error_cause, 512, "Invalid user address %s\n", username_text);
				goto error;
			}
			user_id = janus_sipre_get_uri_username(username_text);
			user_host = janus_sipre_get_uri_host(username_text);
			user_port = janus_sipre_get_uri_port(username_text);
			if(guest) {
				/* Not needed, we can stop here: just say we're registered */
				JANUS_LOG(LOG_INFO, "Guest will have username %s\n", user_id);
				send_register = FALSE;
			} else {
				json_t *secret = json_object_get(root, "secret");
				json_t *authuser = json_object_get(root, "authuser");
				if(!secret) {
					g_free(user_id);
					g_free(user_host);
					JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
					error_code = JANUS_SIPRE_ERROR_MISSING_ELEMENT;
					g_snprintf(error_cause, 512, "Missing element (secret)");
					goto error;
				}
				secret_text = json_string_value(secret);
				secret_type = janus_sipre_secret_type_plaintext;
				if(authuser) {
					authuser_text = json_string_value(authuser);
				}
				/* Got the values, try registering now */
				JANUS_LOG(LOG_VERB, "Registering user %s (auth=%s, secret %s) @ %s through %s (outbound proxy: %s)\n",
					user_id, secret_text, user_host,
					authuser_text != NULL ? authuser_text : user_id,
					proxy_text != NULL ? proxy_text : "(null)",
					obproxy_text != NULL ? obproxy_text : "none");
			}

			/* If this is a refresh, get rid of the old values */
			if(refresh) {
				/* Cleanup old values */
				if(session->account.identity != NULL) {
					g_hash_table_remove(identities, session->account.identity);
					g_free(session->account.identity);
				}
				session->account.identity = NULL;
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
				session->account.secret_type = janus_sipre_secret_type_unknown;
				if(session->account.proxy != NULL)
					g_free(session->account.proxy);
				session->account.proxy = NULL;
				if(session->account.outbound_proxy != NULL)
					g_free(session->account.outbound_proxy);
				session->account.outbound_proxy = NULL;
				session->account.registration_status = janus_sipre_registration_status_unregistered;
			}
			session->account.identity = g_strdup(username_text);
			g_hash_table_insert(identities, session->account.identity, session);
			session->account.sips = sips;
			session->account.username = g_strdup(user_id);
			session->account.authuser = g_strdup(authuser_text ? authuser_text : user_id);
			session->account.secret = secret_text ? g_strdup(secret_text) : NULL;
			session->account.secret_type = secret_type;
			if(display_name_text) {
				session->account.display_name = g_strdup(display_name_text);
			}
			if(proxy_text) {
				session->account.proxy = g_strdup(proxy_text);
			} else {
				/* Build one from the user's identity */
				char uri[256];
				g_snprintf(uri, sizeof(uri), "sip:%s:%"SCNu16, user_host, (user_port ? user_port : 5060));
				session->account.proxy = g_strdup(uri);
			}
			if(obproxy_text) {
				session->account.outbound_proxy = g_strdup(obproxy_text);
			}
			g_free(user_host);
			g_free(user_id);

			session->account.registration_status = janus_sipre_registration_status_registering;
			if(send_register) {
				/* Check if the INVITE needs to be enriched with custom headers */
				char custom_headers[2048];
				janus_sipre_parse_custom_headers(root, (char *)&custom_headers);
				char *data = NULL;
				if(strlen(custom_headers))
					data = g_strdup(custom_headers);
				/* We enqueue this REGISTER attempt, to be sure it's done in the re_main loop thread
				 * FIXME Maybe passing a key to the session is better than passing the session object
				 * itself? it may be gone when it gets handled... won't be an issue with the
				 * reference counter branch but needs to be taken into account until then */
				mqueue_push(mq, janus_sipre_mqueue_event_do_register,
					janus_sipre_mqueue_payload_create(session, NULL, 0, data));
				result = json_object();
				json_object_set_new(result, "event", json_string("registering"));
			} else {
				JANUS_LOG(LOG_VERB, "Not sending a SIPre REGISTER: either send_register was set to false or guest mode was enabled\n");
				session->account.registration_status = janus_sipre_registration_status_disabled;
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
					gateway->notify_event(&janus_sipre_plugin, session->handle, info);
				}
			}
		} else if(!strcasecmp(request_text, "unregister")) {
			if(session->account.registration_status < janus_sipre_registration_status_registered) {
				JANUS_LOG(LOG_ERR, "Wrong state (not registered)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not registered)");
				goto error;
			}
			/* Unregister now */
			session->account.registration_status = janus_sipre_registration_status_unregistering;
			session->stack.expires = 0;
			mqueue_push(mq, janus_sipre_mqueue_event_do_unregister,
				janus_sipre_mqueue_payload_create(session, NULL, 0, data));
			result = json_object();
			json_object_set_new(result, "event", json_string("unregistering"));
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->account.registration_status != janus_sipre_registration_status_registered &&
					session->account.registration_status != janus_sipre_registration_status_disabled) {
				JANUS_LOG(LOG_ERR, "Wrong state (not registered)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not registered)");
				goto error;
			}
			if(session->status >= janus_sipre_call_status_inviting) {
				JANUS_LOG(LOG_ERR, "Wrong state (already in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (already in a call? status=%s)", janus_sipre_call_status_string(session->status));
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, call_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *uri = json_object_get(root, "uri");
			json_t *secret = json_object_get(root, "secret");
			json_t *authuser = json_object_get(root, "authuser");
			/* Check if the INVITE needs to be enriched with custom headers */
			char custom_headers[2048];
			janus_sipre_parse_custom_headers(root, (char *)&custom_headers);
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
					error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
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
							error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
							g_snprintf(error_cause, 512, "Invalid element (unsupported SRTP profile)");
							goto error;
						}
					}
				}
			}
			/* Parse address */
			const char *uri_text = json_string_value(uri);
			if(janus_sipre_parse_uri(uri_text) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIPRE_ERROR_INVALID_ADDRESS;
				g_snprintf(error_cause, 512, "Invalid user address %s\n", uri_text);
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			if(strstr(msg_sdp, "m=application")) {
				JANUS_LOG(LOG_ERR, "The SIPre plugin does not support DataChannels\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "The SIPre plugin does not support DataChannels");
				goto error;
			}
			JANUS_LOG(LOG_VERB, "%s is calling %s\n", session->account.username, uri_text);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg_sdp_type, msg_sdp);
			/* Clean up SRTP stuff from before first, in case it's still needed */
			janus_sipre_srtp_cleanup(session);
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
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
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
			if(janus_sipre_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIPRE_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = janus_sipre_sdp_manipulate(session, parsed_sdp, FALSE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIPRE_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
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
			g_atomic_int_set(&session->hangingup, 0);
			session->status = janus_sipre_call_status_inviting;
			char *callid;
			json_t *request_callid = json_object_get(root, "call_id");
			/* Take call-id from request, if it exists */
			if (request_callid) {
				callid = g_strdup(json_string_value(request_callid));
			} else {
				/* If call-id does not exist in request, create a random one */
				callid = g_malloc0(24);
				janus_sipre_random_string(24, callid);
			}
			/* Take note of custom headers, if any */
			char *data = NULL;
			if(strlen(custom_headers))
				data = g_strdup(custom_headers);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("calling"));
				json_object_set_new(info, "callee", json_string(uri_text));
				json_object_set_new(info, "call-id", json_string(callid));
				json_object_set_new(info, "sdp", json_string(sdp));
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
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
				session->account.secret_type = janus_sipre_secret_type_plaintext;
			}
			/* Enqueue the INVITE */
			session->callee = g_strdup(uri_text);
			session->callid = callid;
			g_hash_table_insert(callids, session->callid, session);
			session->temp_sdp = sdp;
			mqueue_push(mq, janus_sipre_mqueue_event_do_call, janus_sipre_mqueue_payload_create(session, NULL, 0, data));
			/* Done for now */
			if(session->transaction)
				g_free(session->transaction);
			session->transaction = msg->transaction ? g_strdup(msg->transaction) : NULL;
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("calling"));
		} else if(!strcasecmp(request_text, "accept")) {
			if(session->status != janus_sipre_call_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? status=%s)\n", janus_sipre_call_status_string(session->status));
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (not invited? status=%s)", janus_sipre_call_status_string(session->status));
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no caller?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no caller?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, accept_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
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
					error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (srtp can only be sdes_optional or sdes_mandatory)");
					goto error;
				}
			}
			if(session->media.require_srtp && !session->media.has_srtp_remote) {
				JANUS_LOG(LOG_ERR, "Can't accept the call: SDES-SRTP required, but caller didn't offer it\n");
				error_code = JANUS_SIPRE_ERROR_TOO_STRICT;
				g_snprintf(error_cause, 512, "Can't accept the call: SDES-SRTP required, but caller didn't offer it");
				goto error;
			}
			answer_srtp = answer_srtp || session->media.has_srtp_remote;
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp_type = json_string_value(json_object_get(msg->jsep, "type"));
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
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
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
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
			if(janus_sipre_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIPRE_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = janus_sipre_sdp_manipulate(session, parsed_sdp, TRUE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIPRE_ERROR_IO_ERROR;
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
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string(answer ? "accepted" : "accepting"));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
			}
			/* Enqueue the 200 OK */
			if(!answer) {
				if(session->transaction)
					g_free(session->transaction);
				session->transaction = msg->transaction ? g_strdup(msg->transaction) : NULL;
			}
			g_atomic_int_set(&session->hangingup, 0);
			session->status = janus_sipre_call_status_incall;
			session->temp_sdp = sdp;
			/* Check if the OK needs to be enriched with custom headers */
			char custom_headers[2048];
			janus_sipre_parse_custom_headers(root, (char *)&custom_headers);
			char *data = NULL;
			if(strlen(custom_headers))
				data = g_strdup(custom_headers);

			mqueue_push(mq, janus_sipre_mqueue_event_do_accept, janus_sipre_mqueue_payload_create(session, NULL, 0, data));
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string(answer ? "accepted" : "accepting"));
			if(answer) {
				/* Start the media */
				session->media.ready = TRUE;	/* FIXME Maybe we need a better way to signal this */
				GError *error = NULL;
				char tname[16];
				g_snprintf(tname, sizeof(tname), "siprertp %s", session->account.username);
				janus_refcount_increase(&session->ref);
				session->relayer_thread = g_thread_try_new(tname, janus_sipre_relay_thread, session, &error);
				if(error != NULL) {
					session->relayer_thread = NULL;
					session->media.ready = FALSE;
					janus_refcount_decrease(&session->ref);
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
				}
			}
		} else if(!strcasecmp(request_text, "update")) {
			/* Update an existing call */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			if(session->sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no local SDP?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no local SDP?)");
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			const char *msg_sdp = json_string_value(json_object_get(msg->jsep, "sdp"));
			if(!msg_sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP update\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP update");
				goto error;
			}
			if(!json_is_true(json_object_get(msg->jsep, "update"))) {
				JANUS_LOG(LOG_ERR, "Missing SDP update\n");
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP update");
				goto error;
			}
			/* Parse the SDP we got, manipulate some things, and generate a new one */
			char sdperror[100];
			janus_sdp *parsed_sdp = janus_sdp_parse(msg_sdp, sdperror, sizeof(sdperror));
			if(!parsed_sdp) {
				JANUS_LOG(LOG_ERR, "Error parsing SDP: %s\n", sdperror);
				error_code = JANUS_SIPRE_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Error parsing SDP: %s", sdperror);
				goto error;
			}
			session->sdp->o_version++;
			char *sdp = janus_sipre_sdp_manipulate(session, parsed_sdp, FALSE);
			if(sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Error manipulating SDP\n");
				janus_sdp_destroy(parsed_sdp);
				error_code = JANUS_SIPRE_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Error manipulating SDP");
				goto error;
			}
			/* Take note of the new SDP */
			janus_sdp_destroy(session->sdp);
			session->sdp = parsed_sdp;
			session->media.update = TRUE;
			JANUS_LOG(LOG_VERB, "Prepared SDP for update:\n%s", sdp);
			/* Send the re-INVITE */
			session->temp_sdp = sdp;
			mqueue_push(mq, janus_sipre_mqueue_event_do_update, janus_sipre_mqueue_payload_create(session, NULL, 0, data));
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("updating"));
		} else if(!strcasecmp(request_text, "decline")) {
			/* Reject an incoming call */
			if(session->status != janus_sipre_call_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? status=%s)\n", janus_sipre_call_status_string(session->status));
				/* Ignore */
				janus_sipre_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			session->media.earlymedia = FALSE;
			session->media.update = FALSE;
			session->media.ready = FALSE;
			session->media.on_hold = FALSE;
			session->status = janus_sipre_call_status_closing;
			/* Prepare response */
			int response_code = 486;
			json_t *code_json = json_object_get(root, "code");
			if(code_json && json_is_integer(code_json))
				response_code = json_integer_value(code_json);
			if(response_code <= 399) {
				JANUS_LOG(LOG_WARN, "Invalid SIPre response code specified, using 486 to decline call\n");
				response_code = 486;
			}
			/* Enqueue the response */
			mqueue_push(mq, janus_sipre_mqueue_event_do_rcode,
				janus_sipre_mqueue_payload_create(session, session->stack.invite, response_code, NULL));
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("declined"));
				json_object_set_new(info, "callee", json_string(session->callee));
				if(session->callid)
					json_object_set_new(info, "call-id", json_string(session->callid));
				json_object_set_new(info, "code", json_integer(response_code));
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
			}
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("declining"));
			json_object_set_new(result, "code", json_integer(response_code));
		} else if(!strcasecmp(request_text, "hold") || !strcasecmp(request_text, "unhold")) {
			/* We either need to put the call on-hold, or resume it */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				/* Ignore */
				janus_sipre_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			if(session->sdp == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no SDP?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
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
				session->temp_sdp = sdp;
				mqueue_push(mq, janus_sipre_mqueue_event_do_update, janus_sipre_mqueue_payload_create(session, NULL, 0, data));
			}
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string(hold ? "holding" : "resuming"));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				/* Ignore */
				janus_sipre_message_free(msg);
				continue;
				//~ g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			session->media.earlymedia = FALSE;
			session->media.update = FALSE;
			session->media.ready = FALSE;
			session->media.on_hold = FALSE;
			session->status = janus_sipre_call_status_closing;
			/* Enqueue the BYE */
			mqueue_push(mq, janus_sipre_mqueue_event_do_bye, janus_sipre_mqueue_payload_create(session, NULL, 0, NULL));
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
		} else if(!strcasecmp(request_text, "recording")) {
			/* Start or stop recording */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, recording_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *action = json_object_get(root, "action");
			const char *action_text = json_string_value(action);
			if(strcasecmp(action_text, "start") && strcasecmp(action_text, "stop")) {
				JANUS_LOG(LOG_ERR, "Invalid action (should be start|stop)\n");
				error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
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
				error_code = JANUS_SIPRE_ERROR_RECORDING_ERROR;
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
						memset(buf, 0, 12);
						janus_rtcp_pli((char *)&buf, 12);
						gateway->relay_rtcp(session->handle, 1, buf, 12);
					}
				}
			} else {
				/* Stop recording something: notice that this never returns an error, even when we were not recording anything */
				janus_sipre_recorder_close(session, record_audio, record_peer_audio, record_video, record_peer_video);
			}
			janus_mutex_unlock(&session->rec_mutex);
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("recordingupdated"));
		} else if(!strcasecmp(request_text, "info")) {
			/* Send a SIP INFO request: we'll need the payload type and content */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, info_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			const char *info_type = json_string_value(json_object_get(root, "type"));
			const char *info_content = json_string_value(json_object_get(root, "content"));
			json_t *info = json_object();
			json_object_set_new(info, "type", json_string(info_type));
			json_object_set_new(info, "content", json_string(info_content));
			/* Send SIP INFO */
			mqueue_push(mq, janus_sipre_mqueue_event_do_info,
				janus_sipre_mqueue_payload_create(session, NULL, 0, info));
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("infosent"));
		} else if(!strcasecmp(request_text, "message")) {
			/* Send a SIP MESSAGE request: we'll only need the content */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, sipmessage_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			const char *msg_content = json_string_value(json_object_get(root, "content"));
			/* Send SIP MESSAGE */
			mqueue_push(mq, janus_sipre_mqueue_event_do_message,
				janus_sipre_mqueue_payload_create(session, NULL, 0, g_strdup(msg_content)));
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("messagesent"));
		} else if(!strcasecmp(request_text, "dtmf_info")) {
			/* Send DMTF tones using SIPre INFO
			 * (https://tools.ietf.org/html/draft-kaplan-dispatch-info-dtmf-package-00)
			 */
			if(!(session->status == janus_sipre_call_status_inviting || session->status == janus_sipre_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sipre_call_status_string(session->status));
				g_snprintf(error_cause, 512, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIPRE_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (no callee?)");
				goto error;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, dtmf_info_parameters,
				error_code, error_cause, TRUE,
				JANUS_SIPRE_ERROR_MISSING_ELEMENT, JANUS_SIPRE_ERROR_INVALID_ELEMENT);
			if(error_code != 0)
				goto error;
			json_t *digit = json_object_get(root, "digit");
			const char *digit_text = json_string_value(digit);
			if(strlen(digit_text) != 1) {
				JANUS_LOG(LOG_ERR, "Invalid element (digit should be one character))\n");
				error_code = JANUS_SIPRE_ERROR_INVALID_ELEMENT;
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
			json_t *info = json_object();
			json_object_set_new(info, "type", json_string("application/dtmf-relay"));
			json_object_set_new(info, "content", json_string(payload));
			/* Send "application/dtmf-relay" SIP INFO */
			mqueue_push(mq, janus_sipre_mqueue_event_do_info,
				janus_sipre_mqueue_payload_create(session, NULL, 0, info));
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("dtmfsent"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_SIPRE_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "sip", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		json_object_set_new(event, "call_id", json_string(session->callid));
		int ret = gateway->push_event(msg->handle, &janus_sipre_plugin, msg->transaction, event, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(event);
		janus_sipre_message_free(msg);
		continue;

error:
		{
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			json_object_set_new(event, "call_id", json_string(session->callid));
			int ret = gateway->push_event(msg->handle, &janus_sipre_plugin, msg->transaction, event, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (%s)\n", ret, janus_get_api_error(ret));
			json_decref(event);
			janus_sipre_message_free(msg);
		}
	}
	JANUS_LOG(LOG_VERB, "Leaving SIPre handler thread\n");
	return NULL;
}


/* Process an incoming SDP */
void janus_sipre_sdp_process(janus_sipre_session *session, janus_sdp *sdp, gboolean answer, gboolean update, gboolean *changed) {
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
							janus_sipre_srtp_set_remote(session, video, profile, crypto);
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

char *janus_sipre_sdp_manipulate(janus_sipre_session *session, janus_sdp *sdp, gboolean answer) {
	if(!session || !sdp)
		return NULL;
	/* Start replacing stuff */
	JANUS_LOG(LOG_VERB, "Setting protocol to %s\n", session->media.require_srtp ? "RTP/SAVP" : "RTP/AVP");
	if(sdp->c_addr) {
		g_free(sdp->c_addr);
		sdp->c_addr = g_strdup(sdp_ip ? sdp_ip : local_ip);
	}
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
				janus_sipre_srtp_set_local(session, FALSE, &profile, &crypto);
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
				janus_sipre_srtp_set_local(session, TRUE, &profile, &crypto);
				janus_sdp_attribute *a = janus_sdp_attribute_create("crypto", "1 %s inline:%s", profile, crypto);
				g_free(profile);
				g_free(crypto);
				m->attributes = g_list_append(m->attributes, a);
			}
		}
		g_free(m->c_addr);
		m->c_addr = g_strdup(sdp_ip ? sdp_ip : local_ip);
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
static int janus_sipre_allocate_local_ports(janus_sipre_session *session) {
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
static void janus_sipre_connect_sockets(janus_sipre_session *session, struct sockaddr_in *server_addr) {
	if(!session || !server_addr)
		return;

	if(session->media.updated) {
		JANUS_LOG(LOG_VERB, "Updating session sockets\n");
	}

	/* Connect peers (FIXME This pretty much sucks right now) */
	if(session->media.remote_audio_rtp_port) {
		server_addr->sin_port = htons(session->media.remote_audio_rtp_port);
		if(connect(session->media.audio_rtp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't connect audio RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_audio_rtcp_port) {
		server_addr->sin_port = htons(session->media.remote_audio_rtcp_port);
		if(connect(session->media.audio_rtcp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't connect audio RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtp_port) {
		server_addr->sin_port = htons(session->media.remote_video_rtp_port);
		if(connect(session->media.video_rtp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't connect video RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtcp_port) {
		server_addr->sin_port = htons(session->media.remote_video_rtcp_port);
		if(connect(session->media.video_rtcp_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't connect video RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}

}

static void janus_sipre_media_cleanup(janus_sipre_session *session) {
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
	/* Clean up SRTP stuff, if needed */
	janus_sipre_srtp_cleanup(session);
}

/* Thread to relay RTP/RTCP frames coming from the SIPre peer */
static void *janus_sipre_relay_thread(void *data) {
	janus_sipre_session *session = (janus_sipre_session *)data;
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
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't get host (%s)\n", session->account.username, session->media.remote_ip);
			have_server_ip = FALSE;
		} else {
			server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
		}
	}
	if(have_server_ip)
		janus_sipre_connect_sockets(session, &server_addr);

	if(!session->callee) {
		JANUS_LOG(LOG_VERB, "[SIPre-%s] Leaving thread, no callee...\n", session->account.username);
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
			session->status > janus_sipre_call_status_idle &&
			session->status < janus_sipre_call_status_closing) {	/* FIXME We need a per-call watchdog as well */

		if(session->media.updated) {
			/* Apparently there was a session update */
			if(session->media.remote_ip != NULL && (inet_aton(session->media.remote_ip, &server_addr.sin_addr) != 0)) {
				janus_sipre_connect_sockets(session, &server_addr);
			} else {
				JANUS_LOG(LOG_ERR, "[SIPre-%s] Couldn't update session details (missing or invalid remote IP address)\n", session->account.username);
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
				JANUS_LOG(LOG_HUGE, "[SIPre-%s] Got an EINTR (%s), ignoring...\n", session->account.username, strerror(errno));
				continue;
			}
			JANUS_LOG(LOG_ERR, "[SIPre-%s] Error polling...\n", session->account.username);
			JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
			break;
		} else if(resfd == 0) {
			/* No data, keep going */
			continue;
		}
		if(session == NULL || g_atomic_int_get(&session->destroyed) ||
				session->status <= janus_sipre_call_status_idle ||
				session->status >= janus_sipre_call_status_closing)
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
						JANUS_LOG(LOG_WARN, "[SIPre-%s] Got a '%s' on the audio RTCP socket, closing it\n",
							session->account.username, strerror(error));
						close(session->media.audio_rtcp_fd);
						session->media.audio_rtcp_fd = -1;
						continue;
					} else if(fds[i].fd == session->media.video_rtcp_fd) {
						JANUS_LOG(LOG_WARN, "[SIPre-%s] Got a '%s' on the video RTCP socket, closing it\n",
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
				JANUS_LOG(LOG_ERR, "[SIPre-%s] Too many errors polling %d (socket #%d): %s...\n", session->account.username,
					fds[i].fd, i, fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP");
				JANUS_LOG(LOG_ERR, "[SIPre-%s]   -- %d (%s)\n", session->account.username, error, strerror(error));
				/* Can we assume it's pretty much over, after a POLLERR? */
				goon = FALSE;
				/* FIXME Simulate a "hangup" coming from the browser */
				janus_sipre_hangup_media(session->handle);
				break;
			} else if(fds[i].revents & POLLIN) {
				if(pipe_fd != -1 && fds[i].fd == pipe_fd) {
					/* Poll interrupted for a reason, go on */
					int code = 0;
					(void)read(pipe_fd, &code, sizeof(int));
					break;
				}
				/* Got an RTP/RTCP packet */
				addrlen = sizeof(remote);
				bytes = recvfrom(fds[i].fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
				if(bytes < 0) {
					/* Failed to read? */
					continue;
				}
				/* Let's check what this is */
				gboolean video = fds[i].fd == session->media.video_rtp_fd || fds[i].fd == session->media.video_rtcp_fd;
				gboolean rtcp = fds[i].fd == session->media.audio_rtcp_fd || fds[i].fd == session->media.video_rtcp_fd;
				if(!rtcp) {
					/* Audio or Video RTP */
					if(!janus_is_rtp(buffer, bytes)) {
						/* Not an RTP packet? */
						continue;
					}
					pollerrs = 0;
					rtp_header *header = (rtp_header *)buffer;
					if((video && session->media.video_ssrc_peer != ntohl(header->ssrc)) ||
							(!video && session->media.audio_ssrc_peer != ntohl(header->ssrc))) {
						if(video) {
							session->media.video_ssrc_peer = ntohl(header->ssrc);
						} else {
							session->media.audio_ssrc_peer = ntohl(header->ssrc);
						}
						JANUS_LOG(LOG_VERB, "[SIPre-%s] Got SIP peer %s SSRC: %"SCNu32"\n",
							session->account.username ? session->account.username : "unknown",
							video ? "video" : "audio", session->media.audio_ssrc_peer);
					}
					/* Is this SRTP? */
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect(
							(video ? session->media.video_srtp_in : session->media.audio_srtp_in),
							buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							guint32 timestamp = ntohl(header->timestamp);
							guint16 seq = ntohs(header->seq_number);
							JANUS_LOG(LOG_ERR, "[SIPre-%s] %s SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n",
								session->account.username ? session->account.username : "unknown",
								video ? "Video" : "Audio", janus_srtp_error_str(res), bytes, buflen, timestamp, seq);
							continue;
						}
						bytes = buflen;
					}
					/* Check if the SSRC changed (e.g., after a re-INVITE or UPDATE) */
					guint32 timestamp = ntohl(header->timestamp);
					janus_rtp_header_update(header, &session->media.context, video,
						(video ? (vstep ? vstep : 4500) : (astep ? astep : 960)));
					if(video) {
						if(vts == 0) {
							vts = timestamp;
						} else if(vstep == 0) {
							vstep = timestamp-vts;
							if(vstep < 0) {
								vstep = 0;
							}
						}
					} else {
						if(ats == 0) {
							ats = timestamp;
						} else if(astep == 0) {
							astep = timestamp-ats;
							if(astep < 0) {
								astep = 0;
							}
						}
					}
					/* Save the frame if we're recording */
					janus_recorder_save_frame(video ? session->vrc_peer : session->arc_peer, buffer, bytes);
					/* Relay to browser */
					gateway->relay_rtp(session->handle, video, buffer, bytes);
					continue;
				} else {
					/* Audio or Video RTCP */
					if(!janus_is_rtcp(buffer, bytes)) {
						/* Not an RTCP packet? */
						continue;
					}
					if(session->media.has_srtp_remote) {
						int buflen = bytes;
						srtp_err_status_t res = srtp_unprotect_rtcp(
							(video ? session->media.video_srtp_in : session->media.audio_srtp_in),
							buffer, &buflen);
						if(res != srtp_err_status_ok && res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
							JANUS_LOG(LOG_ERR, "[SIPre-%s] %s SRTCP unprotect error: %s (len=%d-->%d)\n",
								session->account.username ? session->account.username : "unknown",
								video ? "Video" : "Audio", janus_srtp_error_str(res), bytes, buflen);
							continue;
						}
						bytes = buflen;
					}
					/* Relay to browser */
					gateway->relay_rtcp(session->handle, video, buffer, bytes);
					continue;
				}
			}
		}
	}
	/* Cleanup the media session */
	janus_sipre_media_cleanup(session);
	/* Done */
	JANUS_LOG(LOG_VERB, "Leaving SIPre relay thread\n");
	janus_refcount_decrease(&session->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}


/* libre loop thread */
gpointer janus_sipre_stack_thread(gpointer user_data) {
	JANUS_LOG(LOG_INFO, "Joining libre loop thread...\n");

	/* Setup libre */
	int err = libre_init();
	if(err) {
		JANUS_LOG(LOG_ERR, "libre_init() failed: %d (%s)\n", err, strerror(err));
		goto done;
	}
	/* Initialize this thread as a worker */
	err = re_thread_init();
	if(err != 0) {
		printf("re_thread_init failed: %d (%s)\n", err, strerror(err));
		goto done;
	}
	err = mqueue_alloc(&mq, janus_sipre_mqueue_handler, NULL);
	if(err) {
		JANUS_LOG(LOG_ERR, "Failed to initialize message queue: %d (%s)\n", err, strerror(err));
		goto done;
	}
	g_atomic_int_set(&libre_inited, 1);

	/* Enter loop */
	err = re_main(NULL);
	if(err != 0) {
		JANUS_LOG(LOG_ERR, "re_main() failed: %d (%s)\n", err, strerror(err));
	}

	/* Done here */
	JANUS_LOG(LOG_INFO, "Leaving libre loop thread...\n");
	re_thread_close();
	/* Deinitialize libre */
	libre_close();

done:
	g_atomic_int_set(&libre_inited, -1);
	return NULL;
}

/* Called when challenged for credentials */
int janus_sipre_cb_auth(char **user, char **pass, const char *realm, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_auth (realm=%s)\n", session->account.username, realm);
	/* TODO How do we handle hashed secrets? */
	int err = 0;
	err |= str_dup(user, session->account.authuser);
	err |= str_dup(pass, session->account.secret);
	JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- %s / %s\n", session->account.username, *user, *pass);
	return err;
}

/* Called when REGISTER responses are received */
void janus_sipre_cb_register(int err, const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_register\n", session->account.username);
	if(err) {
		JANUS_LOG(LOG_ERR, "[SIPre-%s] REGISTER error: %s\n", session->account.username, strerror(err));
		/* FIXME Should we send an event here? */
	} else {
		const char *event_name = (session->stack.expires > 0 ? "registered" : "unregistered");
		JANUS_LOG(LOG_VERB, "[SIPre-%s] REGISTER reply: %u\n", session->account.username, msg->scode);
		if(msg->scode == 200) {
			if(session->stack.expires > 0) {
				if(session->account.registration_status < janus_sipre_registration_status_registered)
					session->account.registration_status = janus_sipre_registration_status_registered;
			} else {
				session->account.registration_status = janus_sipre_registration_status_unregistered;
			}
			/* Notify the browser */
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string(event_name));
			json_object_set_new(calling, "username", json_string(session->account.username));
			json_object_set_new(calling, "register_sent", json_true());
			json_object_set_new(call, "result", calling);
			if(!g_atomic_int_get(&session->destroyed)) {
				int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, call, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(call);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string(event_name));
				json_object_set_new(info, "identity", json_string(session->account.identity));
				if(session->account.proxy)
					json_object_set_new(info, "proxy", json_string(session->account.proxy));
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
			}
		} else {
			/* Authentication failed? */
			session->account.registration_status = janus_sipre_registration_status_failed;
			mem_deref(session->stack.reg);
			session->stack.reg = NULL;
			/* Tell the browser... */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("registration_failed"));
			json_object_set_new(result, "code", json_integer(msg->scode));
			char reason[256];
			reason[0] = '\0';
			if(msg->reason.l > 0) {
				g_snprintf(reason, (msg->reason.l < 255 ? msg->reason.l+1 : 255), "%s", msg->reason.p);
				json_object_set_new(result, "reason", json_string(reason));
			}
			json_object_set_new(event, "result", result);
			if(!g_atomic_int_get(&session->destroyed)) {
				int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(event);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("registration_failed"));
				json_object_set_new(info, "code", json_integer(msg->scode));
				if(msg->reason.l > 0) {
					json_object_set_new(info, "reason", json_string(reason));
				}
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
			}
		}
	}
}

/* Called when SIP progress (e.g., 180 Ringing or 183 Session Progress) responses are received */
void janus_sipre_cb_progress(const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	char reason[256];
	reason[0] = '\0';
	if(msg->reason.l > 0) {
		g_snprintf(reason, (msg->reason.l < 255 ? msg->reason.l+1 : 255), "%s", msg->reason.p);
	}
	/* Not ready yet, either notify the user (e.g., "ringing") or handle early media (if it's a 183) */
	JANUS_LOG(LOG_WARN, "[SIPre-%s] Session progress: %u %s\n", session->account.username, msg->scode, reason);
	if(msg->scode == 180) {
		/* Ringing, notify the application */
		json_t *ringing = json_object();
		json_object_set_new(ringing, "sip", json_string("event"));
		json_t *result = json_object();
		json_object_set_new(result, "event", json_string("ringing"));
		json_object_set_new(ringing, "result", result);
		json_object_set_new(ringing, "call_id", json_string(session->callid));
		int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, ringing, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
		json_decref(ringing);
	} else if(msg->scode == 183) {
		/* If's a Session Progress: check if there's an SDP, and if so, treat it like a 200 */
		(void)janus_sipre_cb_answer(msg, arg);
	}
}

/* Called upon incoming INVITEs */
void janus_sipre_cb_incoming(const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_incoming (%p)\n", session->account.username, session);
	/* Increase the reference to the msg instance, as we'll need it either
	 * to reply with an error right away, or for a success/error later */
	mem_ref((struct sip_msg *)msg);
	/* Parse a few relevant identifiers */
	char *from = NULL;
	re_sdprintf(&from, "%H", uri_encode, &msg->from.uri);
	JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Caller: %s\n", session->account.username, from);
	char dname[256];
	dname[0] = '\0';
	if(msg->from.dname.l > 0) {
		g_snprintf(dname, sizeof(dname), "%.*s", (int)msg->from.dname.l, msg->from.dname.p);
		JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Display: %s\n", session->account.username, dname);
	}
	char callid[256];
	g_snprintf(callid, sizeof(callid), "%.*s", (int)msg->callid.l, msg->callid.p);
	JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Call-ID: %s\n", session->account.username, callid);
	/* Make sure we're not in a call already */
	if(session->stack.sess != NULL) {
		/* Already in a call */
		JANUS_LOG(LOG_VERB, "Already in a call (busy, status=%s)\n", janus_sipre_call_status_string(session->status));
		mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 486, session));
		/* Notify the web app about the missed invite */
		json_t *missed = json_object();
		json_object_set_new(missed, "sip", json_string("event"));
		json_t *result = json_object();
		json_object_set_new(result, "event", json_string("missed_call"));
		json_object_set_new(result, "caller", json_string(from));
		if(strlen(dname)) {
			json_object_set_new(result, "displayname", json_string(dname));
		}
		json_object_set_new(missed, "result", result);
		json_object_set_new(missed, "call_id", json_string(session->callid));
		if(!g_atomic_int_get(&session->destroyed)) {
			int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, missed, NULL);
			JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
		}
		json_decref(missed);
		/* Also notify event handlers */
		if(notify_events && gateway->events_is_enabled()) {
			json_t *info = json_object();
			json_object_set_new(info, "event", json_string("missed_call"));
			json_object_set_new(info, "caller", json_string(from));
			gateway->notify_event(&janus_sipre_plugin, session->handle, info);
		}
		return;
	}
	/* New incoming call, check if there's an SDP to process */
	char sdp_offer[1024];
	janus_sdp *sdp = NULL;
	const char *offer = (const char *)mbuf_buf(msg->mb);
	if(offer == NULL || mbuf_get_left(msg->mb) == 0) {
		JANUS_LOG(LOG_WARN, "[SIPre-%s] Received offerless INVITE\n", session->account.username);
	} else {
		g_snprintf(sdp_offer, sizeof(sdp_offer), "%.*s", (int)mbuf_get_left(msg->mb), offer);
		JANUS_LOG(LOG_WARN, "[SIPre-%s]   -- Offer: %s\n", session->account.username, sdp_offer);
		/* Parse the remote SDP */
		char sdperror[100];
		sdp = janus_sdp_parse(sdp_offer, sdperror, sizeof(sdperror));
		if(!sdp) {
			JANUS_LOG(LOG_ERR, "Error parsing SDP! %s\n", sdperror);
			mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 488, NULL));
			return;
		}
	}
	session->callee = g_strdup(from);
	session->callid = g_strdup(callid);
	g_hash_table_insert(callids, session->callid, session);
	session->status = janus_sipre_call_status_invited;
	/* Clean up SRTP stuff from before first, in case it's still needed */
	janus_sipre_srtp_cleanup(session);
	/* Parse SDP */
	JANUS_LOG(LOG_VERB, "Someone is inviting us a call\n");
	if(sdp) {
		gboolean changed = FALSE;
		janus_sipre_sdp_process(session, sdp, FALSE, FALSE, &changed);
		/* Check if offer has neither audio nor video, fail with 488 */
		if(!session->media.has_audio && !session->media.has_video) {
			mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 488, NULL));
			janus_sdp_destroy(sdp);
			return;
		}
		/* Also fail with 488 if there's no remote IP address that can be used for RTP */
		if(!session->media.remote_ip) {
			mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 488, NULL));
			janus_sdp_destroy(sdp);
			return;
		}
	}
	session->stack.invite = msg;
	/* Notify the browser about the call */
	json_t *jsep = NULL;
	if(sdp)
		jsep = json_pack("{ssss}", "type", "offer", "sdp", sdp_offer);
	json_t *call = json_object();
	json_object_set_new(call, "sip", json_string("event"));
	json_t *calling = json_object();
	json_object_set_new(calling, "event", json_string("incomingcall"));
	json_object_set_new(calling, "username", json_string(session->callee));
	if(strlen(dname)) {
		json_object_set_new(calling, "displayname", json_string(dname));
	}
	if(sdp && session->media.has_srtp_remote) {
		/* FIXME Maybe a true/false instead? */
		json_object_set_new(calling, "srtp", json_string(session->media.require_srtp ? "sdes_mandatory" : "sdes_optional"));
	}
	json_object_set_new(call, "result", calling);
	json_object_set_new(call, "call_id", json_string(session->callid));
	if(!g_atomic_int_get(&session->destroyed)) {
		int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, call, jsep);
		JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
	}
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
		if(strlen(dname))
			json_object_set_new(info, "displayname", json_string(dname));
		gateway->notify_event(&janus_sipre_plugin, session->handle, info);
	}
	/* Send a Ringing back */
	mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 180, NULL));
}

/* Called when an SDP offer is received (re-INVITE) */
int janus_sipre_cb_offer(struct mbuf **mbp, const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_offer\n", session->account.username);
	/* Get the SDP */
	const char *offer = (const char *)mbuf_buf(msg->mb);
	if(offer == NULL) {
		/* No SDP? */
		JANUS_LOG(LOG_WARN, "[SIPre-%s] No SDP in the re-INVITE?\n", session->account.username);
		return EINVAL;
	}
	char sdp_offer[1024];
	g_snprintf(sdp_offer, sizeof(sdp_offer), "%.*s", (int)mbuf_get_left(msg->mb), offer);
	JANUS_LOG(LOG_VERB, "Someone is updating a call:\n%s", sdp_offer);
	/* Parse the remote SDP */
	char sdperror[100];
	janus_sdp *sdp = janus_sdp_parse(sdp_offer, sdperror, sizeof(sdperror));
	if(!sdp) {
		JANUS_LOG(LOG_ERR, "Error parsing SDP! %s\n", sdperror);
		return EINVAL;
	}
	gboolean changed = FALSE;
	janus_sipre_sdp_process(session, sdp, FALSE, TRUE, &changed);
	janus_sdp_destroy(sdp);
	/* Check if offer has neither audio nor video, fail with 488 */
	if (!session->media.has_audio && !session->media.has_video) {
		mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 488, NULL));
		return EINVAL;
	}
	/* Also fail with 488 if there's no remote IP address that can be used for RTP */
	if (!session->media.remote_ip) {
		mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 488, NULL));
		return EINVAL;
	}
	char *answer = janus_sdp_write(session->sdp);
	JANUS_LOG(LOG_VERB, "Answering re-INVITE:\n%s", answer);
	*mbp = mbuf_alloc(strlen(answer)+1);
	mbuf_printf(*mbp, "%s", answer);
	mbuf_set_pos(*mbp, 0);
	return 0;
}


/* Called when an SDP answer is received */
int janus_sipre_cb_answer(const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_answer\n", session->account.username);
	gboolean in_progress = FALSE;
	if(msg->scode == 183)
		in_progress = TRUE;
	/* Get the SDP */
	const char *answer = (const char *)mbuf_buf(msg->mb);
	if(answer == NULL) {
		/* No SDP? */
		if(in_progress) {
			/* This was a 183, so we don't care */
			return 0;
		}
		JANUS_LOG(LOG_WARN, "[SIPre-%s] No SDP in the answer?\n", session->account.username);
		return EINVAL;
	}
	char sdp_answer[1024];
	g_snprintf(sdp_answer, sizeof(sdp_answer), "%.*s", (int)mbuf_get_left(msg->mb), answer);
	/* Parse the SDP */
	char sdperror[100];
	janus_sdp *sdp = janus_sdp_parse(sdp_answer, sdperror, sizeof(sdperror));
	if(!sdp) {
		JANUS_LOG(LOG_ERR, "Error parsing SDP! %s\n", sdperror);
		return EINVAL;
	}
	/* Parse SDP */
	JANUS_LOG(LOG_VERB, "Peer accepted our call:\n%s", sdp_answer);
	session->status = janus_sipre_call_status_incall;
	gboolean changed = FALSE;
	gboolean update = session->media.ready;
	janus_sipre_sdp_process(session, sdp, TRUE, update, &changed);
	/* If we asked for SRTP and are not getting it, fail */
	if(session->media.require_srtp && !session->media.has_srtp_remote) {
		JANUS_LOG(LOG_ERR, "We asked for mandatory SRTP but didn't get any in the reply!\n");
		janus_sdp_destroy(sdp);
		/* Hangup immediately */
		session->media.earlymedia = FALSE;
		session->media.update = FALSE;
		session->media.ready = FALSE;
		session->media.on_hold = FALSE;
		session->status = janus_sipre_call_status_closing;
		mqueue_push(mq, janus_sipre_mqueue_event_do_bye, janus_sipre_mqueue_payload_create(session, msg, 0, NULL));
		g_free(session->callee);
		session->callee = NULL;
		return EINVAL;
	}
	if(!session->media.remote_ip) {
		/* No remote address parsed? Give up */
		JANUS_LOG(LOG_ERR, "No remote IP address found for RTP, something's wrong with the SDP!\n");
		janus_sdp_destroy(sdp);
		/* Hangup immediately */
		session->media.earlymedia = FALSE;
		session->media.update = FALSE;
		session->media.ready = FALSE;
		session->media.on_hold = FALSE;
		session->status = janus_sipre_call_status_closing;
		mqueue_push(mq, janus_sipre_mqueue_event_do_bye, janus_sipre_mqueue_payload_create(session, msg, 0, NULL));
		g_free(session->callee);
		session->callee = NULL;
		return EINVAL;
	}
	if(session->media.audio_pt > -1) {
		session->media.audio_pt_name = janus_get_codec_from_pt(sdp_answer, session->media.audio_pt);
		JANUS_LOG(LOG_VERB, "Detected audio codec: %d (%s)\n", session->media.audio_pt, session->media.audio_pt_name);
	}
	if(session->media.video_pt > -1) {
		session->media.video_pt_name = janus_get_codec_from_pt(sdp_answer, session->media.video_pt);
		JANUS_LOG(LOG_VERB, "Detected video codec: %d (%s)\n", session->media.video_pt, session->media.video_pt_name);
	}
	session->media.ready = TRUE;	/* FIXME Maybe we need a better way to signal this */
	if(update && !session->media.earlymedia && !session->media.update) {
		/* Don't push to the browser if this is in response to a hold/unhold we sent ourselves */
		JANUS_LOG(LOG_WARN, "This is an update to an existing call (possibly in response to hold/unhold)\n");
		return 0;
	}
	if(!session->media.earlymedia && !session->media.update) {
		GError *error = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "siprertp %s", session->account.username);
		janus_refcount_increase(&session->ref);
		session->relayer_thread = g_thread_try_new(tname, janus_sipre_relay_thread, session, &error);
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
		jsep = json_pack("{ssss}", "type", "answer", "sdp", sdp_answer);
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
	if(!g_atomic_int_get(&session->destroyed)) {
		int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, call, jsep);
		JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
	}
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
		gateway->notify_event(&janus_sipre_plugin, session->handle, info);
	}
	if(session->media.update) {
		/* We just received a 200 OK to an update we sent */
		session->media.update = FALSE;
	}

	return 0;
}

/* Called when the session is established */
void janus_sipre_cb_established(const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	if(session == NULL) {
		JANUS_LOG(LOG_WARN, "[SIPre-??] janus_sipre_cb_established\n");
		return;
	}
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_established\n", session->account.username);
	/* FIXME Anything to do here? */
}

/* Called when an incoming SIP INFO arrives */
void janus_sipre_cb_info(struct sip *sip, const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	if(session == NULL) {
		JANUS_LOG(LOG_WARN, "[SIPre-??] janus_sipre_cb_info\n");
		return;
	}
	JANUS_LOG(LOG_HUGE, "[SIPre-%s] janus_sipre_cb_info\n", session->account.username);
	char *from = NULL;
	re_sdprintf(&from, "%H", uri_encode, &msg->from.uri);
	JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Sender: %s\n", session->account.username, from);
	char dname[256];
	dname[0] = '\0';
	if(msg->from.dname.l > 0) {
		g_snprintf(dname, sizeof(dname), "%.*s", (int)msg->from.dname.l, msg->from.dname.p);
		JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Display: %s\n", session->account.username, dname);
	}
	char type[200];
	type[0] = '\0';
	if(msg->ctyp.type.l > 0) {
		g_snprintf(type, sizeof(type), "%.*s", (int)msg->ctyp.type.l, msg->ctyp.type.p);
		JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Type: %s\n", session->account.username, type);
	}
	const char *payload = (const char *)mbuf_buf(msg->mb);
	char content[1024];
	g_snprintf(content, sizeof(content), "%.*s", (int)mbuf_get_left(msg->mb), payload);
	JANUS_LOG(LOG_HUGE, "[SIPre-%s]   -- Content: %s\n", session->account.username, content);
	/* Notify the application */
	json_t *info = json_object();
	json_object_set_new(info, "sip", json_string("event"));
	json_t *result = json_object();
	json_object_set_new(result, "event", json_string("info"));
	json_object_set_new(result, "sender", json_string(from));
	if(strlen(dname)) {
		json_object_set_new(result, "displayname", json_string(dname));
	}
	json_object_set_new(result, "type", json_string(type));
	json_object_set_new(result, "content", json_string(content));
	json_object_set_new(info, "result", result);
	int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, info, NULL);
	JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
	json_decref(info);
	/* Send a 200 back */
	mqueue_push(mq, janus_sipre_mqueue_event_do_rcode, janus_sipre_mqueue_payload_create(session, msg, 200, session));
}

/* Called when the session fails to connect or is terminated by the peer */
void janus_sipre_cb_closed(int err, const struct sip_msg *msg, void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	if(session == NULL) {
		JANUS_LOG(LOG_HUGE, "[SIPre-??] janus_sipre_cb_closed\n");
		return;
	}
	if(err) {
		JANUS_LOG(LOG_VERB, "[SIPre-%s] Session closed: %d %s\n", session->account.username, err, strerror(err));
	} else {
		JANUS_LOG(LOG_VERB, "[SIPre-%s] Session closed: %u %s\n", session->account.username, msg->scode, (char *)&msg->reason.p);
	}

	/* Tell the browser... */
	json_t *event = json_object();
	json_object_set_new(event, "sip", json_string("event"));
	json_t *result = json_object();
	json_object_set_new(result, "event", json_string("hangup"));
	json_object_set_new(result, "code", json_integer(err ? err : msg->scode));
	char reason[256];
	reason[0] = '\0';
	if(!err && msg->reason.l > 0) {
		g_snprintf(reason, (msg->reason.l < 255 ? msg->reason.l+1 : 255), "%s", msg->reason.p);
	}
	json_object_set_new(result, "reason", json_string(err ? strerror(err) : reason));
	json_object_set_new(event, "result", result);
	json_object_set_new(event, "call_id", json_string(session->callid));
	if(!g_atomic_int_get(&session->destroyed)) {
		int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
		JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
	}
	json_decref(event);
	/* Also notify event handlers */
	if(notify_events && gateway->events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "event", json_string("hangup"));
		json_object_set_new(info, "code", json_integer(err ? err : msg->scode));
		json_object_set_new(info, "reason", json_string(err ? strerror(err) : reason));
		gateway->notify_event(&janus_sipre_plugin, session->handle, info);
	}

	/* Cleanup */
	mem_deref(session->stack.sess);
	session->stack.sess = NULL;
	session->media.earlymedia = FALSE;
	session->media.update = FALSE;
	session->media.ready = FALSE;
	session->media.on_hold = FALSE;
	session->status = janus_sipre_call_status_idle;
}

/* Called when all SIP transactions are completed */
void janus_sipre_cb_exit(void *arg) {
	janus_sipre_session *session = (janus_sipre_session *)arg;
	if(session == NULL) {
		JANUS_LOG(LOG_HUGE, "[SIPre-??] janus_sipre_cb_exit\n");
		return;
	}
	if(!g_atomic_int_get(&session->destroyed))
		return;
	JANUS_LOG(LOG_INFO, "[SIPre-%s] Cleaning SIP stack\n", session->account.username);
	/* TODO use refcount decrease here */
	janus_refcount_decrease(&session->ref);
}

/* Callback to implement SIP requests in the re_main loop thread */
void janus_sipre_mqueue_handler(int id, void *data, void *arg) {
	JANUS_LOG(LOG_HUGE, "janus_sipre_mqueue_handler: %d (%s)\n", id, janus_sipre_mqueue_event_string((janus_sipre_mqueue_event)id));
	switch((janus_sipre_mqueue_event)id) {
		case janus_sipre_mqueue_event_do_init: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			/* We need a DNS client */
			struct sa nsv[8];
			uint32_t nsn = ARRAY_SIZE(nsv);
			int err = dns_srv_get(NULL, 0, nsv, &nsn);
			if(err) {
				JANUS_LOG(LOG_ERR, "Failed to get the DNS servers list for the SIP stack: %d (%s)\n", err, strerror(err));
				janus_sipre_mqueue_payload_free(payload);
				return;
			}
			err = dnsc_alloc(&session->stack.dns_client, NULL, nsv, nsn);
			if(err) {
				JANUS_LOG(LOG_ERR, "Failed to initialize the DNS client for the SIP stack: %d (%s)\n", err, strerror(err));
				janus_sipre_mqueue_payload_free(payload);
				return;
			}
			/* Let's allocate the stack now */
			err = sip_alloc(&session->stack.sipstack, session->stack.dns_client, 32, 32, 32,
				(user_agent ? user_agent : JANUS_SIPRE_NAME), janus_sipre_cb_exit, session);
			if(err) {
				JANUS_LOG(LOG_ERR, "Failed to initialize libre SIP stack: %d (%s)\n", err, strerror(err));
				mem_deref(session->stack.dns_client);
				session->stack.dns_client = NULL;
				janus_sipre_mqueue_payload_free(payload);
				return;
			}
			JANUS_LOG(LOG_INFO, "Initializing SIP transports\n");
			struct sa laddr, laddrs;
			sa_set_str(&laddr, local_ip, 0);
			sa_set_str(&laddrs, local_ip, 0);
			err = 0;
			err |= sip_transp_add(session->stack.sipstack, SIP_TRANSP_UDP, &laddr);
			err |= sip_transp_add(session->stack.sipstack, SIP_TRANSP_TCP, &laddr);
			if(err) {
				JANUS_LOG(LOG_ERR, "Failed to initialize libre SIP transports: %d (%s)\n", err, strerror(err));
				janus_sipre_mqueue_payload_free(payload);
				return;
			}
			err = tls_alloc(&session->stack.tls, TLS_METHOD_SSLV23, NULL, NULL);
			err |= sip_transp_add(session->stack.sipstack, SIP_TRANSP_TLS, &laddrs, session->stack.tls);
			err |= sipsess_listen(&session->stack.sess_sock, session->stack.sipstack, 32, janus_sipre_cb_incoming, session);
			if(err) {
				sip_close(session->stack.sipstack, TRUE);
				session->stack.sipstack = NULL;
				mem_deref(session->stack.tls);
				session->stack.tls = NULL;
				JANUS_LOG(LOG_ERR, "Failed to initialize libre SIPS transports: %d (%s)\n", err, strerror(err));
				janus_sipre_mqueue_payload_free(payload);
				return;
			}
#ifdef HAVE_LIBRE_SIPTRACE
			if(notify_events && gateway->events_is_enabled()) {
				/* Trace incoming/outgoing SIP messages */
				sip_set_trace(session->stack.sipstack, janus_sipre_msg_logger);
			}
#endif
			mem_deref(session->stack.tls);
			session->stack.tls = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_register:
		case janus_sipre_mqueue_event_do_unregister: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			/* Whether it's a REGISTER or an unregister, get rid of the previous instance */
			mem_deref(session->stack.reg);
			session->stack.reg = NULL;
			/* If it's an unregister, we're done */
			if(session->stack.expires == 0) {
				/* Notify the browser */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *unreging = json_object();
				json_object_set_new(unreging, "event", json_string("unregistered"));
				json_object_set_new(unreging, "username", json_string(session->account.username));
				json_object_set_new(unreging, "register_sent", json_true());
				json_object_set_new(event, "result", unreging);
				if(!g_atomic_int_get(&session->destroyed)) {
					int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("unregistered"));
					json_object_set_new(info, "identity", json_string(session->account.identity));
					if(session->account.proxy)
						json_object_set_new(info, "proxy", json_string(session->account.proxy));
					gateway->notify_event(&janus_sipre_plugin, session->handle, info);
				}
				janus_sipre_mqueue_payload_free(payload);
				break;
			}
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending REGISTER\n", session->account.username);
			/* Check if there is an outbound proxy to take into account */
			const char *outbound_proxy[1];
			outbound_proxy[0] = session->account.outbound_proxy;
			/* Check if there are custom headers to add */
			char *headers = (char *)payload->data;
			/* Send the REGISTER */
			int err = sipreg_register(&session->stack.reg, session->stack.sipstack,
				session->account.proxy,
#ifdef HAVE_LIBRE_SIPREGNEWAPI
				session->account.identity, NULL,
#else
				session->account.identity,
#endif
				session->account.identity, session->stack.expires,
				session->account.username,
				outbound_proxy, (outbound_proxy[0] ? 1 : 0), 0,
				janus_sipre_cb_auth, session, FALSE,
				janus_sipre_cb_register, session, NULL, (headers ? headers : ""), NULL);
			g_free(headers);
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to REGISTER: %d (%s)\n", err, strerror(err));
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("registration_failed"));
				json_object_set_new(result, "code", json_integer(err));
				json_object_set_new(result, "reason", json_string(strerror(err)));
				json_object_set_new(event, "result", result);
				if(!g_atomic_int_get(&session->destroyed)) {
					int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("registration_failed"));
					json_object_set_new(info, "code", json_integer(err));
					json_object_set_new(info, "reason", json_string(strerror(err)));
					gateway->notify_event(&janus_sipre_plugin, session->handle, info);
				}
			}
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_call: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending INVITE\n%s", session->account.username, session->temp_sdp);
			/* Check if there is an outbound proxy to take into account */
			const char *outbound_proxy[1];
			outbound_proxy[0] = session->account.outbound_proxy;
			/* Check if there are custom headers to add */
			char *headers = (char *)payload->data;
			/* Convert the SDP into a struct mbuf */
			struct mbuf *mb = mbuf_alloc(strlen(session->temp_sdp)+1);
			mbuf_printf(mb, "%s", session->temp_sdp);
			mbuf_set_pos(mb, 0);
			/* Send the INVITE */
			int err = sipsess_connect(&session->stack.sess, session->stack.sess_sock,
				session->callee,
				session->account.display_name, session->account.identity,
				session->account.username,
				outbound_proxy, (outbound_proxy[0] ? 1 : 0),
				"application/sdp", mb,
				janus_sipre_cb_auth, session, FALSE,
				janus_sipre_cb_offer, janus_sipre_cb_answer,
				janus_sipre_cb_progress, janus_sipre_cb_established,
				NULL, NULL, janus_sipre_cb_closed, session,
				"%s", (headers ? headers : ""));
			g_free(headers);
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to INVITE: %d (%s)\n", err, strerror(err));
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("hangup"));
				json_object_set_new(result, "code", json_integer(err));
				json_object_set_new(result, "reason", json_string(strerror(err)));
				json_object_set_new(event, "result", result);
				json_object_set_new(event, "call_id", json_string(session->callid));
				if(!g_atomic_int_get(&session->destroyed)) {
					int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("hangup"));
					json_object_set_new(info, "code", json_integer(err));
					json_object_set_new(info, "reason", json_string(strerror(err)));
					gateway->notify_event(&janus_sipre_plugin, session->handle, info);
				}
			}
			mem_deref(mb);
			g_free(session->temp_sdp);
			session->temp_sdp = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_accept: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending 200 OK\n%s", session->account.username, session->temp_sdp);
			/* Convert the SDP into a struct mbuf */
			struct mbuf *mb = mbuf_alloc(strlen(session->temp_sdp)+1);
			mbuf_printf(mb, "%s", session->temp_sdp);
			mbuf_set_pos(mb, 0);
			/* Check if there are custom headers to add */
                        char *headers = (char *)payload->data;
			/* Send the 200 OK */
			int err = sipsess_answer(session->stack.sess, 200, "OK", mb, (headers ? headers : ""));
			g_free(headers);
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to send the 200 OK: %d (%s)\n", err, strerror(err));
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("hangup"));
				json_object_set_new(result, "code", json_integer(err));
				json_object_set_new(result, "reason", json_string(strerror(err)));
				json_object_set_new(event, "result", result);
				json_object_set_new(event, "call_id", json_string(session->callid));
				if(!g_atomic_int_get(&session->destroyed)) {
					int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
					JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
				}
				json_decref(event);
				/* Also notify event handlers */
				if(notify_events && gateway->events_is_enabled()) {
					json_t *info = json_object();
					json_object_set_new(info, "event", json_string("hangup"));
					json_object_set_new(info, "code", json_integer(err));
					json_object_set_new(info, "reason", json_string(strerror(err)));
					gateway->notify_event(&janus_sipre_plugin, session->handle, info);
				}
			}
			mem_deref(mb);
			g_free(session->temp_sdp);
			session->temp_sdp = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_rcode: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending response code %d\n", session->account.username, payload->rcode);
			/* Send the response code */
			int err = 0;
			if(session->stack.sess == NULL) {
				/* We still need to accept the connection */
				err = sipsess_accept(&session->stack.sess, session->stack.sess_sock,
					session->stack.invite, payload->rcode, janus_sipre_error_reason(payload->rcode),
					session->account.display_name ? session->account.display_name : session->account.username,
					"application/sdp", NULL,
					janus_sipre_cb_auth, session, FALSE,
					janus_sipre_cb_offer, janus_sipre_cb_answer,
					janus_sipre_cb_established, janus_sipre_cb_info, NULL,
					janus_sipre_cb_closed, session, NULL);
			} else {
				/* Connection already accepted */
				if(payload->rcode < 200) {
					/* 1xx */
					err = sipsess_progress(session->stack.sess, payload->rcode, janus_sipre_error_reason(payload->rcode), NULL, NULL);
				} else if(payload->rcode < 300) {
					/* 2xx */
					err = sipsess_answer(session->stack.sess, payload->rcode, janus_sipre_error_reason(payload->rcode), NULL, NULL);
				} else {
					/* 3xx, 4xx, 5xx, 6xx */
					if(payload->data == NULL) {
						/* Send an error message on the current call */
						err = sipsess_reject(session->stack.sess, payload->rcode, janus_sipre_error_reason(payload->rcode), NULL);
						session->media.earlymedia = FALSE;
						session->media.update = FALSE;
						session->media.ready = FALSE;
						session->media.on_hold = FALSE;
						session->status = janus_sipre_call_status_idle;
					} else {
						/* We're rejecting a new call because we're busy in another one: accept first and then reject */
						struct sipsess *sess = NULL;
						err = sipsess_accept(&sess, session->stack.sess_sock,
							payload->msg, 180, janus_sipre_error_reason(180),
							session->account.display_name ? session->account.display_name : session->account.username,
							"application/sdp", NULL,
							janus_sipre_cb_auth, session, FALSE,
							janus_sipre_cb_offer, janus_sipre_cb_answer,
							janus_sipre_cb_established, NULL, NULL,
							janus_sipre_cb_closed, session, NULL);
						err = sipsess_reject(sess, payload->rcode, janus_sipre_error_reason(payload->rcode), NULL);
					}
				}
			}
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to send the %d error code: %d (%s)\n", payload->rcode, err, strerror(err));
			}
			if(payload->rcode > 399) {
				g_free(session->callee);
				session->callee = NULL;
				g_free(session->callid);
				session->callid = NULL;
				/* FIXME */
				session->stack.sess = NULL;
			}
			mem_deref((void *)payload->msg);
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_update: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending SIP re-INVITE\n", session->account.username);
			/* Convert the SDP into a struct mbuf */
			struct mbuf *mb = mbuf_alloc(strlen(session->temp_sdp)+1);
			mbuf_printf(mb, "%s", session->temp_sdp);
			mbuf_set_pos(mb, 0);
			/* Send the INVITE */
			int err = sipsess_modify(session->stack.sess, mb);
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to re-INVITE: %d (%s)\n", err, strerror(err));
			}
			mem_deref(mb);
			g_free(session->temp_sdp);
			session->temp_sdp = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_info: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			json_t *info = (json_t *)payload->data;
			const char *type = json_string_value(json_object_get(info, "type"));
			const char *content = json_string_value(json_object_get(info, "content"));
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending SIP INFO (%s, %s)\n", session->account.username, type, content);
			/* Convert the SDP into a struct mbuf */
			struct mbuf *mb = mbuf_alloc(strlen(content)+1);
			mbuf_printf(mb, "%s", content);
			mbuf_set_pos(mb, 0);
			/* Send the SIP INFO */
			int err = sipsess_info(session->stack.sess, type, mb, NULL, NULL);
			if(err != 0) {
				JANUS_LOG(LOG_ERR, "Error attempting to send the SIP INFO: %d (%s)\n", err, strerror(err));
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("infoerror"));
				json_object_set_new(result, "code", json_integer(err));
				json_object_set_new(result, "reason", json_string(strerror(err)));
				json_object_set_new(event, "result", result);
			}
			mem_deref(mb);
			json_decref(info);
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_message: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending SIP MESSAGE: %s\n", session->account.username, (char *)payload->data);
			/* Convert the SDP into a struct mbuf */
			struct mbuf *mb = mbuf_alloc(strlen((char *)payload->data)+1);
			mbuf_printf(mb, "%s", (char *)payload->data);
			mbuf_set_pos(mb, 0);
			g_free(payload->data);
			/* FIXME This is only a placeholder... there's no way to send SIP MESSAGE apparently? */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("messageerror"));
			json_object_set_new(result, "code", json_integer(-1));
			json_object_set_new(result, "reason", json_string("SIP MESSAGE currently unsupported"));
			json_object_set_new(event, "result", result);
			mem_deref(mb);
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_bye: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Sending BYE\n", session->account.username);
			/* Send a BYE */
			mem_deref(session->stack.sess);
			session->stack.sess = NULL;
			g_free(session->callee);
			session->callee = NULL;
			/* Tell the browser... */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "event", json_string("hangup"));
			json_object_set_new(result, "code", json_integer(200));
			json_object_set_new(result, "reason", json_string("BYE"));
			json_object_set_new(event, "result", result);
			json_object_set_new(event, "call_id", json_string(session->callid));
			if(!g_atomic_int_get(&session->destroyed)) {
				int ret = gateway->push_event(session->handle, &janus_sipre_plugin, session->transaction, event, NULL);
				JANUS_LOG(LOG_VERB, "  >> Pushing event to peer: %d (%s)\n", ret, janus_get_api_error(ret));
			}
			json_decref(event);
			/* Also notify event handlers */
			if(notify_events && gateway->events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "event", json_string("hangup"));
				json_object_set_new(info, "code", json_integer(200));
				json_object_set_new(info, "reason", json_string("BYE"));
				gateway->notify_event(&janus_sipre_plugin, session->handle, info);
			}
			session->media.earlymedia = FALSE;
			session->media.update = FALSE;
			session->media.ready = FALSE;
			session->media.on_hold = FALSE;
			session->status = janus_sipre_call_status_idle;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_close: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Closing session\n", session->account.username);
			/* FIXME How to correctly clean up? */
			mem_deref(session->stack.reg);
			session->stack.reg = NULL;
			mem_deref(session->stack.sess);
			session->stack.sess = NULL;
			mem_deref(session->stack.dns_client);
			session->stack.dns_client = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_destroy: {
			janus_sipre_mqueue_payload *payload = (janus_sipre_mqueue_payload *)data;
			janus_sipre_session *session = (janus_sipre_session *)payload->session;
			JANUS_LOG(LOG_VERB, "[SIPre-%s] Destroying session\n", session->account.username);
			/* Destroy the session and wrap up */
			sipsess_close_all(session->stack.sess_sock);
			sip_close(session->stack.sipstack, FALSE);
			session->stack.sipstack = NULL;
			janus_sipre_mqueue_payload_free(payload);
			break;
		}
		case janus_sipre_mqueue_event_do_exit:
			/* We're done, here, break the loop */
			re_cancel();
			break;
		default:
			/* Shouldn't happen */
			break;
	}
}
