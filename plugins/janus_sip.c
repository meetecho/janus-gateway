/*! \file   janus_sip.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus SIP plugin
 * \details  This is a simple SIP plugin for Janus, allowing WebRTC peers
 * to register at a SIP server (e.g., Asterisk) and call SIP user agents
 * through the gateway. Specifically, when attaching to the plugin peers
 * are requested to provide their SIP server credentials, i.e., the address
 * of the SIP server and their username/secret. This results in the plugin
 * registering at the SIP server and acting as a SIP client on behalf of
 * the web peer. Most of the SIP states and lifetime are masked by the plugin,
 * and only the relevant events (e.g., INVITEs and BYEs) and functionality
 * (call, hangup) are made available to the web peer: peers can call
 * extensions at the SIP server or wait for incoming INVITEs, and during
 * a call they can send DTMF tones.
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
 * \todo Only Asterisk and Kamailio have been tested as a SIP server, and
 * specifically only with basic audio calls: this plugin needs some work
 * to make it more stable and reliable.
 *
 * \section sipapi SIP Plugin API
 *
 * All requests you can send in the SIP Plugin API are asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction.
 *
 * The supported requests are \c register , \c call , \c accept and
 * \c hangup . \c register can be used, as the name suggests, to register
 * a username at a SIP registrar to call and be called; \c call is used
 * to send an INVITE to a different SIP URI through the plugin, while
 * \c accept is used to accept the call in case one is invited instead
 * of inviting; finally, \c hangup can be used to terminate the
 * communication at any time, either to hangup (BYE) an ongoing call or
 * to cancel/decline (CANCEL/BYE) a call that hasn't started yet.
 *
 * Actual API docs: TBD.
 *
 * \ingroup plugins
 * \ref plugins
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

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_SIP_VERSION			5
#define JANUS_SIP_VERSION_STRING	"0.0.5"
#define JANUS_SIP_DESCRIPTION		"This is a simple SIP plugin for Janus, allowing WebRTC peers to register at a SIP server and call SIP user agents through the gateway."
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
struct janus_plugin_result *janus_sip_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_sip_setup_media(janus_plugin_session *handle);
void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_hangup_media(janus_plugin_session *handle);
void janus_sip_destroy_session(janus_plugin_session *handle, int *error);
char *janus_sip_query_session(janus_plugin_session *handle);

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


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;

static char local_ip[INET6_ADDRSTRLEN];
static int keepalive_interval = 120;
static gboolean behind_nat = FALSE;
static char *user_agent;
#define JANUS_DEFAULT_REGISTER_TTL	3600
static int register_ttl = JANUS_DEFAULT_REGISTER_TTL;

static GThread *handler_thread;
static GThread *watchdog;
static void *janus_sip_handler(void *data);

typedef struct janus_sip_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_sip_message;
static GAsyncQueue *messages = NULL;
static janus_sip_message exit_message;

static void janus_sip_message_free(janus_sip_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	g_free(msg->message);
	msg->message = NULL;
	g_free(msg->sdp_type);
	msg->sdp_type = NULL;
	g_free(msg->sdp);
	msg->sdp = NULL;

	g_free(msg);
}


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
	gboolean sips;
	char *username;
	char *authuser;			/**< username to use for authentication */
	char *secret;
	janus_sip_secret_type secret_type;
	int sip_port;
	char *proxy;
	janus_sip_registration_status registration_status;
} janus_sip_account;

typedef struct janus_sip_media {
	char *remote_ip;
	int ready:1;
	int has_audio:1;
	int audio_rtp_fd, audio_rtcp_fd;
	int local_audio_rtp_port, remote_audio_rtp_port;
	int local_audio_rtcp_port, remote_audio_rtcp_port;
	guint32 audio_ssrc, audio_ssrc_peer;
	int has_video:1;
	int video_rtp_fd, video_rtcp_fd;
	int local_video_rtp_port, remote_video_rtp_port;
	int local_video_rtcp_port, remote_video_rtcp_port;
	guint32 video_ssrc, video_ssrc_peer;
} janus_sip_media;

typedef struct janus_sip_session {
	janus_plugin_session *handle;
	ssip_t *stack;
	janus_sip_account account;
	janus_sip_call_status status;
	janus_sip_media media;
	char *transaction;
	char *callee;
	janus_recorder *arc;		/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *arc_peer;	/* The Janus recorder instance for the peer's audio, if enabled */
	janus_recorder *vrc;		/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *vrc_peer;	/* The Janus recorder instance for the peer's video, if enabled */
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
	janus_mutex mutex;
} janus_sip_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;


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


/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data);
/* Sofia callbacks */
void janus_sip_sofia_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *magic, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[]);
/* SDP parsing */
void janus_sip_sdp_process(janus_sip_session *session, sdp_session_t *sdp);
/* Media */
static int janus_sip_allocate_local_ports(janus_sip_session *session);
static void *janus_sip_relay_thread(void *data);


/* URI parsing utilies */

#define JANUS_SIP_URI_MAXLEN	1024
typedef struct {
	char data[JANUS_SIP_URI_MAXLEN];
	url_t url[1];
} janus_sip_uri_t;

/* Parses a SIP URI (SIPS is not supported), returns 0 on success, -1 otherwise */
static int janus_sip_parse_uri(janus_sip_uri_t *sip_uri, const char *data) {
	g_strlcpy(sip_uri->data, data, JANUS_SIP_URI_MAXLEN);
	if (url_d(sip_uri->url, sip_uri->data) < 0 || sip_uri->url->url_type != url_sip)
		return -1;
	return 0;
}

/* Similar to th above function, but it also accepts SIPS URIs */
static int janus_sip_parse_proxy_uri(janus_sip_uri_t *sip_uri, const char *data) {
	g_strlcpy(sip_uri->data, data, JANUS_SIP_URI_MAXLEN);
	if (url_d(sip_uri->url, sip_uri->data) < 0 || (sip_uri->url->url_type != url_sip && sip_uri->url->url_type != url_sips))
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


/* SIP watchdog/garbage collector (sort of) */
void *janus_sip_watchdog(void *data);
void *janus_sip_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "SIP watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old SIP sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_sip_session *session = (janus_sip_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if (now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old SIP session\n");
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					if (session->account.identity) {
					    g_free(session->account.identity);
					    session->account.identity = NULL;
					}
					session->account.sips = TRUE;
					if (session->account.proxy) {
					    g_free(session->account.proxy);
					    session->account.proxy = NULL;
					}
					if (session->account.secret) {
					    g_free(session->account.secret);
					    session->account.secret = NULL;
					}
					if (session->account.username) {
					    g_free(session->account.username);
					    session->account.username = NULL;
					}
					if (session->account.authuser) {
					    g_free(session->account.authuser);
					    session->account.authuser = NULL;
					}
					if (session->callee) {
					    g_free(session->callee);
					    session->callee = NULL;
					}
					if (session->transaction) {
					    g_free(session->transaction);
					    session->transaction = NULL;
					}
					if (session->media.remote_ip) {
					    g_free(session->media.remote_ip);
					    session->media.remote_ip = NULL;
					}
					if (session->stack) {
					    g_free(session->stack);
					    session->stack = NULL;
					}
					session->handle = NULL;
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "SIP watchdog stopped\n");
	return NULL;
}


static void janus_sip_detect_local_ip(char *buf, size_t buflen) {
	JANUS_LOG(LOG_VERB, "Autodetecting local IP...\n");

	struct sockaddr_in addr;
	socklen_t len;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		goto error;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1);
	inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr.s_addr);
	if (connect(fd, (const struct sockaddr*) &addr, sizeof(addr)) < 0)
		goto error;
	len = sizeof(addr);
	if (getsockname(fd, (struct sockaddr*) &addr, &len) < 0)
		goto error;
	if (getnameinfo((const struct sockaddr*) &addr, sizeof(addr),
			buf, buflen,
			NULL, 0, NI_NUMERICHOST) != 0)
		goto error;
	close(fd);
	return;

error:
	if (fd != -1)
		close(fd);
	JANUS_LOG(LOG_VERB, "Couldn't find any address! using 127.0.0.1 as the local IP... (which is NOT going to work out of your machine)\n");
	g_strlcpy(buf, "127.0.0.1", buflen);
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
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_SIP_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);

	gboolean local_ip_set = FALSE;
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "local_ip");
	if(item && item->value) {
		int family;
		if (!janus_is_ip_valid(item->value, &family)) {
			JANUS_LOG(LOG_WARN, "Invalid local IP specified: %s, guessing the default...\n", item->value);
		} else {
			/* Verify that we can actually bind to that address */
			int fd = socket(family, SOCK_DGRAM, 0);
			if (fd == -1) {
				JANUS_LOG(LOG_WARN, "Error creating test socket, falling back to detecting IP address...\n");
			} else {
				int r;
				struct sockaddr_storage ss;
				socklen_t addrlen;
				memset(&ss, 0, sizeof(ss));
				if (family == AF_INET) {
					struct sockaddr_in *addr4 = (struct sockaddr_in*)&ss;
					addr4->sin_family = AF_INET;
					addr4->sin_port = 0;
					inet_pton(AF_INET, item->value, &(addr4->sin_addr.s_addr));
					addrlen = sizeof(struct sockaddr_in);
				} else {
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)&ss;
					addr6->sin6_family = AF_INET6;
					addr6->sin6_port = 0;
					inet_pton(AF_INET6, item->value, &(addr6->sin6_addr.s6_addr));
					addrlen = sizeof(struct sockaddr_in6);
				}
				r = bind(fd, (const struct sockaddr*)&ss, addrlen);
				close(fd);
				if (r < 0) {
					JANUS_LOG(LOG_WARN, "Error setting local IP address to %s, falling back to detecting IP address...\n", item->value);
				} else {
					g_strlcpy(local_ip, item->value, sizeof(local_ip));
					local_ip_set = TRUE;
				}
			}
		}
	}
	if (!local_ip_set)
		janus_sip_detect_local_ip(local_ip, sizeof(local_ip));
	JANUS_LOG(LOG_VERB, "Local IP set to %s\n", local_ip);

	item = janus_config_get_item_drilldown(config, "general", "keepalive_interval");
	if(item && item->value)
		keepalive_interval = atoi(item->value);
	JANUS_LOG(LOG_VERB, "SIP keep-alive interval set to %d seconds\n", keepalive_interval);

	item = janus_config_get_item_drilldown(config, "general", "register_ttl");
	if(item && item->value)
		register_ttl = atoi(item->value);
	JANUS_LOG(LOG_VERB, "SIP registration TTL set to %d seconds\n", register_ttl);

	item = janus_config_get_item_drilldown(config, "general", "behind_nat");
	if(item && item->value)
		behind_nat = janus_is_true(item->value);

	item = janus_config_get_item_drilldown(config, "general", "user_agent");
	if(item && item->value)
		user_agent = g_strdup(item->value);
	else
		user_agent = g_strdup("Janus WebRTC Gateway SIP Plugin "JANUS_SIP_VERSION_STRING);
	JANUS_LOG(LOG_VERB, "SIP User-Agent set to %s\n", user_agent);

	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;

	/* Setup sofia */
	su_init();

	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_sip_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("etest watchdog", &janus_sip_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIP watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("janus sip handler", janus_sip_handler, NULL, &error);
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
	if(watchdog != NULL) {
		g_thread_join(watchdog);
		watchdog = NULL;
	}
	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;
	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
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

void janus_sip_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}
	janus_sip_session *session = g_malloc0(sizeof(janus_sip_session));
	session->handle = handle;
	session->account.identity = NULL;
	session->account.sips = TRUE;
	session->account.username = NULL;
	session->account.authuser = NULL;
	session->account.secret = NULL;
	session->account.secret_type = janus_sip_secret_type_unknown;
	session->account.sip_port = 0;
	session->account.proxy = NULL;
	session->account.registration_status = janus_sip_registration_status_unregistered;
	session->status = janus_sip_call_status_idle;
	session->stack = g_malloc0(sizeof(ssip_t));
	session->stack->session = session;
	session->stack->s_nua = NULL;
	session->stack->s_nh_r = NULL;
	session->stack->s_nh_i = NULL;
	session->stack->s_root = NULL;
	session->transaction = NULL;
	session->callee = NULL;
	session->media.remote_ip = NULL;
	session->media.ready = 0;
	session->media.has_audio = 0;
	session->media.audio_rtp_fd = 0;
	session->media.audio_rtcp_fd= 0;
	session->media.local_audio_rtp_port = 0;
	session->media.remote_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.remote_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	session->media.audio_ssrc_peer = 0;
	session->media.has_video = 0;
	session->media.video_rtp_fd = 0;
	session->media.video_rtcp_fd= 0;
	session->media.local_video_rtp_port = 0;
	session->media.remote_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.remote_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	session->media.video_ssrc_peer = 0;
	session->destroyed = 0;
	g_atomic_int_set(&session->hangingup, 0);
	su_home_init(session->stack->s_home);
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;

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
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No SIP session associated with this handle...\n");
		*error = -2;
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	if(!session->destroyed) {
		g_hash_table_remove(sessions, handle);
		janus_sip_hangup_media(handle);
		session->destroyed = janus_get_monotonic_time();
		JANUS_LOG(LOG_VERB, "Destroying SIP session (%s)...\n", session->account.username ? session->account.username : "unregistered user");
		/* Shutdown the NUA */
		nua_shutdown(session->stack->s_nua);
		/* Cleaning up and removing the session is done in a lazy way */
		old_sessions = g_list_append(old_sessions, session);
	}
	janus_mutex_unlock(&sessions_mutex);
	return;
}

char *janus_sip_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* Provide some generic info, e.g., if we're in a call and with whom */
	json_t *info = json_object();
	json_object_set_new(info, "username", session->account.username ? json_string(session->account.username) : NULL);
	json_object_set_new(info, "identity", session->account.identity ? json_string(session->account.identity) : NULL);
	json_object_set_new(info, "registration_status", json_string(janus_sip_registration_status_string(session->account.registration_status)));
	json_object_set_new(info, "call_status", json_string(janus_sip_call_status_string(session->status)));
	if(session->callee)
		json_object_set_new(info, "callee", json_string(session->callee ? session->callee : "??"));
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
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	char *info_text = json_dumps(info, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(info);
	return info_text;
}

struct janus_plugin_result *janus_sip_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized");
	JANUS_LOG(LOG_VERB, "%s\n", message);
	janus_sip_message *msg = g_malloc0(sizeof(janus_sip_message));
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, NULL);
}

void janus_sip_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	g_atomic_int_set(&session->hangingup, 0);
	/* TODO Only relay RTP/RTCP when we get this event */
}

void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
		if(!session || session->destroyed) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_call_status_incall)
			return;
		/* Forward to our SIP peer */
		if(video) {
			if(session->media.video_ssrc == 0) {
				rtp_header *header = (rtp_header *)buf;
				session->media.video_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP video SSRC: %"SCNu32"\n", session->media.video_ssrc);
			}
			if(session->media.has_video && session->media.video_rtp_fd) {
				/* Save the frame if we're recording */
				if(session->vrc)
					janus_recorder_save_frame(session->vrc, buf, len);
				/* Forward the frame to the peer */
				send(session->media.video_rtp_fd, buf, len, 0);
			}
		} else {
			if(session->media.audio_ssrc == 0) {
				rtp_header *header = (rtp_header *)buf;
				session->media.audio_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP audio SSRC: %"SCNu32"\n", session->media.audio_ssrc);
			}
			if(session->media.has_audio && session->media.audio_rtp_fd) {
				/* Save the frame if we're recording */
				if(session->arc)
					janus_recorder_save_frame(session->arc, buf, len);
				/* Forward the frame to the peer */
				send(session->media.audio_rtp_fd, buf, len, 0);
			}
		}
	}
}

void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	if(gateway) {
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
		if(!session || session->destroyed) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_call_status_incall)
			return;
		/* Fix SSRCs as the gateway does */
		JANUS_LOG(LOG_HUGE, "[SIP] Fixing SSRCs (local %u, peer %u)\n",
			video ? session->media.video_ssrc : session->media.audio_ssrc,
			video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer);
		janus_rtcp_fix_ssrc((char *)buf, len, 1,
			video ? session->media.video_ssrc : session->media.audio_ssrc,
			video ? session->media.video_ssrc_peer : session->media.audio_ssrc_peer);
		/* Forward to our SIP peer */
		if(video) {
			if(session->media.has_video && session->media.video_rtcp_fd) {
				send(session->media.video_rtcp_fd, buf, len, 0);
			}
		} else {
			if(session->media.has_audio && session->media.audio_rtcp_fd) {
				send(session->media.audio_rtcp_fd, buf, len, 0);
			}
		}
	}
}

void janus_sip_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	if(!(session->status == janus_sip_call_status_inviting ||
		 session->status == janus_sip_call_status_invited ||
		 session->status == janus_sip_call_status_incall))
		return;
	/* Get rid of the recorders, if available */
	if(session->arc) {
		janus_recorder_close(session->arc);
		JANUS_LOG(LOG_INFO, "Closed user's audio recording %s\n", session->arc->filename ? session->arc->filename : "??");
		janus_recorder_free(session->arc);
	}
	session->arc = NULL;
	if(session->arc_peer) {
		janus_recorder_close(session->arc_peer);
		JANUS_LOG(LOG_INFO, "Closed peer's audio recording %s\n", session->arc_peer->filename ? session->arc_peer->filename : "??");
		janus_recorder_free(session->arc_peer);
	}
	session->arc_peer = NULL;
	if(session->vrc) {
		janus_recorder_close(session->vrc);
		JANUS_LOG(LOG_INFO, "Closed user's video recording %s\n", session->vrc->filename ? session->vrc->filename : "??");
		janus_recorder_free(session->vrc);
	}
	session->vrc = NULL;
	if(session->vrc_peer) {
		janus_recorder_close(session->vrc_peer);
		JANUS_LOG(LOG_INFO, "Closed peer's video recording %s\n", session->vrc_peer->filename ? session->vrc_peer->filename : "??");
		janus_recorder_free(session->vrc_peer);
	}
	session->vrc_peer = NULL;
	/* FIXME Simulate a "hangup" coming from the browser */
	janus_sip_message *msg = g_malloc0(sizeof(janus_sip_message));
	msg->handle = handle;
	msg->message = g_strdup("{\"request\":\"hangup\"}");
	msg->transaction = NULL;
	msg->sdp_type = NULL;
	msg->sdp = NULL;
	g_async_queue_push(messages, msg);
}

/* Thread to handle incoming messages */
static void *janus_sip_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining SIP handler thread\n");
	janus_sip_message *msg = NULL;
	int error_code = 0;
	char *error_cause = g_malloc0(512);
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == NULL)
			continue;
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_sip_message_free(msg);
			continue;
		}
		janus_sip_session *session = NULL;
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_lookup(sessions, msg->handle) != NULL ) {
			session = (janus_sip_session *)msg->handle->plugin_handle;
		}
		janus_mutex_unlock(&sessions_mutex);
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_sip_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_sip_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = NULL;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_SIP_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_SIP_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_SIP_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		json_t *request = json_object_get(root, "request");
		if(!request) {
			JANUS_LOG(LOG_ERR, "Missing element (request)\n");
			error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
			g_snprintf(error_cause, 512, "Missing element (request)");
			goto error;
		}
		if(!json_is_string(request)) {
			JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
			error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid element (request should be a string)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *result = NULL;
		char *sdp_type = NULL, *sdp = NULL;
		if(!strcasecmp(request_text, "register")) {
			/* Send a REGISTER */
			if(session->account.registration_status > janus_sip_registration_status_unregistered) {
				JANUS_LOG(LOG_ERR, "Already registered (%s)\n", session->account.username);
				error_code = JANUS_SIP_ERROR_ALREADY_REGISTERED;
				g_snprintf(error_cause, 512, "Already registered (%s)", session->account.username);
				goto error;
			}

			/* Cleanup old values */
			if(session->account.identity != NULL)
				g_free(session->account.identity);
			session->account.identity = NULL;
			session->account.sips = TRUE;
			if(session->account.username != NULL)
				g_free(session->account.username);
			session->account.username = NULL;
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
			session->account.registration_status = janus_sip_registration_status_unregistered;

			gboolean guest = FALSE;
			json_t *type = json_object_get(root, "type");
			if(type != NULL) {
				if(!json_is_string(type)) {
					JANUS_LOG(LOG_ERR, "Invalid element (type should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (type should be a string)");
					goto error;
				}
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
				if(!json_is_boolean(do_register)) {
					JANUS_LOG(LOG_ERR, "Invalid element (send_register should be boolean)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (send_register should be boolean)");
					goto error;
				}
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
				if(!json_is_boolean(do_sips)) {
					JANUS_LOG(LOG_ERR, "Invalid element (sips should be boolean)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (sips should be boolean)");
					goto error;
				}
				sips = json_is_true(do_sips);
			}

			/* Parse address */
			json_t *proxy = json_object_get(root, "proxy");
			const char *proxy_text = NULL;

			if (proxy && !json_is_null(proxy)) {
				if(!json_is_string(proxy)) {
					JANUS_LOG(LOG_ERR, "Invalid element (proxy should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (proxy should be a string)");
					goto error;
				}
				proxy_text = json_string_value(proxy);
				janus_sip_uri_t proxy_uri;
				if (janus_sip_parse_proxy_uri(&proxy_uri, proxy_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid proxy address %s\n", proxy_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					g_snprintf(error_cause, 512, "Invalid proxy address %s\n", proxy_text);
					goto error;
				}
			}

			/* Parse register TTL */
			int ttl = register_ttl;
			json_t *reg_ttl = json_object_get(root, "register_ttl");
			if (reg_ttl && json_is_integer(reg_ttl))
				ttl = json_integer_value(reg_ttl);
			if (ttl <= 0)
				ttl = JANUS_DEFAULT_REGISTER_TTL;

			/* Now the user part, if needed */
			json_t *username = json_object_get(root, "username");
			if(!guest && !username) {
				/* The username is mandatory if we're not registering as guests */
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (username)");
				goto error;
			}
			const char *username_text = NULL;
			janus_sip_uri_t username_uri;
			char user_id[256];
			if(username) {
				if(!json_is_string(username)) {
					JANUS_LOG(LOG_ERR, "Invalid element (username should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					g_snprintf(error_cause, 512, "Invalid element (username should be a string)");
					goto error;
				}
				/* Parse address */
				username_text = json_string_value(username);
				if (janus_sip_parse_uri(&username_uri, username_text) < 0) {
					JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					g_snprintf(error_cause, 512, "Invalid user address %s\n", username_text);
					goto error;
				}
				g_strlcpy(user_id, username_uri.url->url_user, sizeof(user_id));
			}
			if(guest) {
				/* Not needed, we can stop here: just pick a random username if it wasn't provided and say we're registered */
				if(!username)
					g_snprintf(user_id, 255, "janus-sip-%"SCNu32"", g_random_int());
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
				const char *secret_text;
				if(secret) {
					if(!json_is_string(secret)) {
						JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
						error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (secret should be a string)");
						goto error;
					}
					secret_text = json_string_value(secret);
					session->account.secret = g_strdup(secret_text);
					session->account.secret_type = janus_sip_secret_type_plaintext;
				} else {
					if(!json_is_string(ha1_secret)) {
						JANUS_LOG(LOG_ERR, "Invalid element (ha1_secret should be a string)\n");
						error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (ha1_secret should be a string)");
						goto error;
					}
					secret_text = json_string_value(ha1_secret);
					session->account.secret = g_strdup(secret_text);
					session->account.secret_type = janus_sip_secret_type_hashed;
				}
				if (authuser) {
					const char *authuser_text;
					if (!json_is_string(authuser)) {
						JANUS_LOG(LOG_ERR, "Invalid element (authentication username should be a string)\n");
						error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
						g_snprintf(error_cause, 512, "Invalid element (authentication username should be a string)");
						goto error;
					}
					authuser_text = json_string_value(authuser);
					session->account.authuser = g_strdup(authuser_text);
				} else {
					session->account.authuser = g_strdup(user_id);
				}
				/* Got the values, try registering now */
				JANUS_LOG(LOG_VERB, "Registering user %s (secret %s) @ %s through %s\n",
					username_text, secret_text, username_uri.url->url_host, proxy_text != NULL ? proxy_text : "(null)");
			}

			session->account.identity = g_strdup(username_text);
			session->account.sips = sips;
			session->account.username = g_strdup(user_id);
			if (proxy_text) {
				session->account.proxy = g_strdup(proxy_text);
			}

			session->account.registration_status = janus_sip_registration_status_registering;
			if(session->stack->s_nua == NULL) {
				/* Start the thread first */
				GError *error = NULL;
				g_thread_try_new("worker", janus_sip_sofia_thread, session, &error);
				if(error != NULL) {
					JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the SIP Sofia thread...\n", error->code, error->message ? error->message : "??");
					error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
					g_snprintf(error_cause, 512, "Got error %d (%s) trying to launch the SIP Sofia thread", error->code, error->message ? error->message : "??");
					goto error;
				}
				long int timeout = 0;
				while(session->stack->s_nua == NULL) {
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

			if (send_register) {
				session->stack->s_nh_r = nua_handle(session->stack->s_nua, session, TAG_END());
				if(session->stack->s_nh_r == NULL) {
					JANUS_LOG(LOG_ERR, "NUA Handle for REGISTER still null??\n");
					error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
					g_snprintf(error_cause, 512, "Invalid NUA Handle");
					goto error;
				}
				char ttl_text[20];
				g_snprintf(ttl_text, sizeof(ttl_text), "%d", ttl);
				nua_register(session->stack->s_nh_r,
					NUTAG_M_USERNAME(session->account.username),
					SIPTAG_FROM_STR(username_text),
					SIPTAG_TO_STR(username_text),
					SIPTAG_EXPIRES_STR(ttl_text),
					NUTAG_PROXY(proxy_text),
					TAG_END());
				result = json_object();
				json_object_set_new(result, "event", json_string("registering"));
			} else {
				JANUS_LOG(LOG_VERB, "Not sending a SIP REGISTER: either send_register was set to false or guest mode was enabled\n");
				session->account.registration_status = janus_sip_registration_status_disabled;
				result = json_object();
				json_object_set_new(result, "event", json_string("registered"));
				json_object_set_new(result, "username", json_string(session->account.username));
				json_object_set_new(result, "register_sent", json_string("false"));
			}
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->status >= janus_sip_call_status_inviting) {
				JANUS_LOG(LOG_ERR, "Wrong state (already in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				g_snprintf(error_cause, 512, "Wrong state (already in a call? status=%s)", janus_sip_call_status_string(session->status));
				goto error;
			}
			json_t *uri = json_object_get(root, "uri");
			if(!uri) {
				JANUS_LOG(LOG_ERR, "Missing element (uri)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (uri)");
				goto error;
			}
			if(!json_is_string(uri)) {
				JANUS_LOG(LOG_ERR, "Invalid element (uri should be a string)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (uri should be a string)");
				goto error;
			}
			/* Parse address */
			const char *uri_text = json_string_value(uri);
			janus_sip_uri_t target_uri;
			if (janus_sip_parse_uri(&target_uri, uri_text) < 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				g_snprintf(error_cause, 512, "Invalid user address %s\n", uri_text);
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			JANUS_LOG(LOG_VERB, "%s is calling %s\n", session->account.username, uri_text);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg->sdp, "m=audio")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate audio...\n");
				session->media.has_audio = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg->sdp, "m=video")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate video...\n");
				session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			sdp = janus_string_replace(sdp, " UDP/TLS/", " ");
			sdp = janus_string_replace(sdp, "RTP/SAVPF", "RTP/AVP");
			sdp = janus_string_replace(sdp, "1.1.1.1", local_ip);
			if(session->media.has_audio) {
				JANUS_LOG(LOG_VERB, "Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				g_snprintf(mline, 20, "m=audio %d", session->media.local_audio_rtp_port);
				sdp = janus_string_replace(sdp, "m=audio 1", mline);
			}
			if(session->media.has_video) {
				JANUS_LOG(LOG_VERB, "Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				g_snprintf(mline, 20, "m=video %d", session->media.local_video_rtp_port);
				sdp = janus_string_replace(sdp, "m=video 1", mline);
			}
			/* Send INVITE */
			if(session->stack->s_nh_i != NULL)
				nua_handle_destroy(session->stack->s_nh_i);
			session->stack->s_nh_i = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for INVITE still null??\n");
				error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
				g_snprintf(error_cause, 512, "Invalid NUA Handle");
				goto error;
			}
			session->status = janus_sip_call_status_inviting;
			nua_invite(session->stack->s_nh_i,
				SIPTAG_FROM_STR(session->account.identity),
				SIPTAG_TO_STR(uri_text),
				SOATAG_USER_SDP_STR(sdp),
				NUTAG_PROXY(session->account.proxy),
				NUTAG_AUTOANSWER(0),
				TAG_END());
			g_free(sdp);
			session->callee = g_strdup(uri_text);
			if(session->transaction)
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
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				g_snprintf(error_cause, 512, "Missing SDP");
				goto error;
			}
			/* Accept a call from another peer */
			JANUS_LOG(LOG_VERB, "We're accepting the call from %s\n", session->callee);
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg->sdp, "m=audio")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate audio...\n");
				session->media.has_audio = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg->sdp, "m=video")) {
				JANUS_LOG(LOG_VERB, "Going to negotiate video...\n");
				session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_LOG(LOG_ERR, "Could not allocate RTP/RTCP ports\n");
				error_code = JANUS_SIP_ERROR_IO_ERROR;
				g_snprintf(error_cause, 512, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			sdp = janus_string_replace(sdp, " UDP/TLS/", " ");
			sdp = janus_string_replace(sdp, "RTP/SAVPF", "RTP/AVP");
			sdp = janus_string_replace(sdp, "1.1.1.1", local_ip);
			if(session->media.has_audio) {
				JANUS_LOG(LOG_VERB, "Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				g_snprintf(mline, 20, "m=audio %d", session->media.local_audio_rtp_port);
				sdp = janus_string_replace(sdp, "m=audio 1", mline);
			}
			if(session->media.has_video) {
				JANUS_LOG(LOG_VERB, "Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				g_snprintf(mline, 20, "m=video %d", session->media.local_video_rtp_port);
				sdp = janus_string_replace(sdp, "m=video 1", mline);
			}
			/* Send 200 OK */
			session->status = janus_sip_call_status_incall;
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			nua_respond(session->stack->s_nh_i,
				200, sip_status_phrase(200),
				SOATAG_USER_SDP_STR(sdp),
				NUTAG_AUTOANSWER(0),
				TAG_END());
			g_free(sdp);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("accepted"));
			/* Start the media */
			session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
			GError *error = NULL;
			g_thread_try_new("janus rtp handler", janus_sip_relay_thread, session, &error);
			if(error != NULL) {
				JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
			}
		} else if(!strcasecmp(request_text, "decline")) {
			/* Reject an incoming call */
			if(session->status != janus_sip_call_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? status=%s)\n", janus_sip_call_status_string(session->status));
				/* Ignore */
				json_decref(root);
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
			session->status = janus_sip_call_status_closing;
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			int response_code = 486;
			json_t *code_json = json_object_get(root, "code");
			if (code_json && json_is_integer(code_json))
				response_code = json_integer_value(code_json);
			if (response_code <= 399) {
				JANUS_LOG(LOG_WARN, "Invalid SIP response code specified, using 486 to decline call\n");
				response_code = 486;
			}
			nua_respond(session->stack->s_nh_i, response_code, sip_status_phrase(response_code), TAG_END());
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("declining"));
			json_object_set_new(result, "code", json_integer(response_code));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call */
			if(!(session->status == janus_sip_call_status_inviting || session->status == janus_sip_call_status_incall)) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? status=%s)\n", janus_sip_call_status_string(session->status));
				/* Ignore */
				json_decref(root);
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
			json_t *action = json_object_get(root, "action");
			if(!action) {
				JANUS_LOG(LOG_ERR, "Missing element (action)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				g_snprintf(error_cause, 512, "Missing element (action)");
				goto error;
			}
			if(!json_is_string(action)) {
				JANUS_LOG(LOG_ERR, "Invalid element (action should be a string)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid element (action should be a string)");
				goto error;
			}
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
			if(audio && !json_is_boolean(audio)) {
				JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
				goto error;
			}
			record_audio = audio ? json_is_true(audio) : FALSE;
			json_t *video = json_object_get(root, "video");
			if(video && !json_is_boolean(video)) {
				JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
				goto error;
			}
			record_video = video ? json_is_true(video) : FALSE;
			json_t *peer_audio = json_object_get(root, "peer_audio");
			if(peer_audio && !json_is_boolean(peer_audio)) {
				JANUS_LOG(LOG_ERR, "Invalid element (peer_audio should be a boolean)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (peer_audio should be a boolean)");
				goto error;
			}
			record_peer_audio = peer_audio ? json_is_true(peer_audio) : FALSE;
			json_t *peer_video = json_object_get(root, "peer_video");
			if(peer_video && !json_is_boolean(peer_video)) {
				JANUS_LOG(LOG_ERR, "Invalid element (peer_video should be a boolean)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (peer_video should be a boolean)");
				goto error;
			}
			record_peer_video = peer_video ? json_is_true(peer_video) : FALSE;
			if(!record_audio && !record_video && !record_peer_audio && !record_peer_video) {
				JANUS_LOG(LOG_ERR, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)\n");
				error_code = JANUS_SIP_ERROR_RECORDING_ERROR;
				g_snprintf(error_cause, 512, "Invalid request (at least one of audio, video, peer_audio and peer_video should be true)");
				goto error;
			}
			json_t *recfile = json_object_get(root, "filename");
			if(recfile && !json_is_string(recfile)) {
				JANUS_LOG(LOG_ERR, "Invalid element (filename should be a string)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				g_snprintf(error_cause, 512, "Invalid value (filename should be a string)");
				goto error;
			}
			const char *recording_base = json_string_value(recfile);
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
							session->arc_peer = janus_recorder_create(NULL, 0, filename);
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
							session->arc_peer = janus_recorder_create(NULL, 0, filename);
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
							session->vrc_peer = janus_recorder_create(NULL, 1, filename);
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
							session->vrc_peer = janus_recorder_create(NULL, 1, filename);
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
							session->arc = janus_recorder_create(NULL, 0, filename);
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
							session->arc = janus_recorder_create(NULL, 0, filename);
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
							session->vrc = janus_recorder_create(NULL, 1, filename);
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
							session->vrc = janus_recorder_create(NULL, 1, filename);
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
				if(record_audio) {
					if(session->arc) {
						janus_recorder_close(session->arc);
						JANUS_LOG(LOG_INFO, "Closed user's audio recording %s\n", session->arc->filename ? session->arc->filename : "??");
						janus_recorder_free(session->arc);
					}
					session->arc = NULL;
				}
				if(record_video) {
					if(session->vrc) {
						janus_recorder_close(session->vrc);
						JANUS_LOG(LOG_INFO, "Closed user's video recording %s\n", session->vrc->filename ? session->vrc->filename : "??");
						janus_recorder_free(session->vrc);
					}
					session->vrc = NULL;
				}
				if(record_peer_audio) {
					if(session->arc_peer) {
						janus_recorder_close(session->arc_peer);
						JANUS_LOG(LOG_INFO, "Closed peer's audio recording %s\n", session->arc_peer->filename ? session->arc_peer->filename : "??");
						janus_recorder_free(session->arc_peer);
					}
					session->arc_peer = NULL;
				}
				if(record_peer_video) {
					if(session->vrc_peer) {
						janus_recorder_close(session->vrc_peer);
						JANUS_LOG(LOG_INFO, "Closed peer's video recording %s\n", session->vrc_peer->filename ? session->vrc_peer->filename : "??");
						janus_recorder_free(session->vrc_peer);
					}
					session->vrc_peer = NULL;
				}
			}
			/* Notify the result */
			result = json_object();
			json_object_set_new(result, "event", json_string("recordingupdated"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_SIP_ERROR_INVALID_REQUEST;
			g_snprintf(error_cause, 512, "Unknown request (%s)", request_text);
			goto error;
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "sip", json_string("event"));
		if(result != NULL)
			json_object_set_new(event, "result", result);
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
		int ret = gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event_text, sdp_type, sdp);
		JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		g_free(event_text);
		if(sdp)
			g_free(sdp);
		janus_sip_message_free(msg);
		continue;

error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "sip", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
			int ret = gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(event_text);
			janus_sip_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving SIP handler thread\n");
	return NULL;
}


/* Sofia callbacks */
void janus_sip_sofia_callback(nua_event_t event, int status, char const *phrase, nua_t *nua, nua_magic_t *magic, nua_handle_t *nh, nua_hmagic_t *hmagic, sip_t const *sip, tagi_t tags[])
{
	janus_sip_session *session = (janus_sip_session *)magic;
	ssip_t *ssip = session->stack;
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
			/* There are several call states, but we only care about the terminated state
			 * in order to send the 'hangup' event (assuming this is the right session, of course).
			 * http://sofia-sip.sourceforge.net/refdocs/nua/nua__tag_8h.html#a516dc237722dc8ca4f4aa3524b2b444b
			 */
			if(callstate == nua_callstate_terminated &&
					(session->stack->s_nh_i == nh || session->stack->s_nh_i == NULL)) {
				session->status = janus_sip_call_status_idle;
				session->stack->s_nh_i = NULL;
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "code", json_integer(status));
				json_object_set_new(calling, "reason", json_string(phrase ? phrase : "???"));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
				/* Get rid of any PeerConnection that may have been set up */
				if(session->transaction)
					g_free(session->transaction);
				session->transaction = NULL;
				gateway->close_pc(session->handle);
			}
			break;
		case nua_i_terminated:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP requests */
		case nua_i_ack:
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			break;
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
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if(!sdp_session(parser)) {
				JANUS_LOG(LOG_ERR, "\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
                                sdp_parser_free(parser);
				break;
			}
			if(session->stack->s_nh_i != NULL) {
				if(session->stack->s_nh_i == nh) {
					/* re-INVITE, we don't support those. */
					nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
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
					if (sip->sip_from && sip->sip_from->a_display) {
						json_object_set_new(result, "displayname", json_string(sip->sip_from->a_display));
					}
					json_object_set_new(missed, "result", result);
					char *missed_text = json_dumps(missed, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
					json_decref(missed);
					JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", missed_text);
					int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, missed_text, NULL, NULL);
					JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
					g_free(missed_text);
				}
				sdp_parser_free(parser);
				break;
			}
			/* New incoming call */
			session->callee = g_strdup(url_as_string(session->stack->s_home, sip->sip_from->a_url));
			session->status = janus_sip_call_status_invited;
			/* Parse SDP */
			char *fixed_sdp = g_strdup(sip->sip_payload->pl_data);
			JANUS_LOG(LOG_VERB, "Someone is inviting us in a call:\n%s", sip->sip_payload->pl_data);
			sdp_session_t *sdp = sdp_session(parser);
			janus_sip_sdp_process(session, sdp);
			/* Send SDP to the browser */
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("incomingcall"));
			json_object_set_new(calling, "username", json_string(session->callee));
			if (sip->sip_from && sip->sip_from->a_display) {
				json_object_set_new(calling, "displayname", json_string(sip->sip_from->a_display));
			}
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call_text, "offer", fixed_sdp);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Send a Ringing back */
			nua_respond(nh, 180, sip_status_phrase(180), TAG_END());
			session->stack->s_nh_i = nh;
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
			/* end the event loop. su_root_run() will return */
			su_root_break(ssip->s_root);
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
		case nua_r_invite: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			if(status < 200) {
				/* Not ready yet (FIXME May this be pranswer?? we don't handle it yet...) */
				break;
			} else if(status == 401 || status == 407) {
				char auth[256];
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
				memset(auth, 0, sizeof(auth));
				g_snprintf(auth, sizeof(auth), "%s%s:%s:%s:%s%s",
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					scheme,
					realm,
					session->account.authuser ? session->account.authuser : "null",
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					session->account.secret ? session->account.secret : "null");
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
				break;
			} else if(status >= 400) {
				break;
			}
			ssip_t *ssip = session->stack;
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if(!sdp_session(parser)) {
				JANUS_LOG(LOG_ERR, "\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			JANUS_LOG(LOG_VERB, "Peer accepted our call:\n%s", sip->sip_payload->pl_data);
			session->status = janus_sip_call_status_incall;
			char *fixed_sdp = g_strdup(sip->sip_payload->pl_data);
			sdp_session_t *sdp = sdp_session(parser);
			janus_sip_sdp_process(session, sdp);
			session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
			GError *error = NULL;
			g_thread_try_new("janus rtp handler", janus_sip_relay_thread, session, &error);
			if(error != NULL) {
				JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTP/RTCP thread...\n", error->code, error->message ? error->message : "??");
			}
			/* Send SDP to the browser */
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("accepted"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call_text, "answer", fixed_sdp);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			break;
		}
		case nua_r_register: {
			JANUS_LOG(LOG_VERB, "[%s][%s]: %d %s\n", session->account.username, nua_event_name(event), status, phrase ? phrase : "??");
			if(status == 200) {
				if(session->account.registration_status < janus_sip_registration_status_registered)
					session->account.registration_status = janus_sip_registration_status_registered;
				JANUS_LOG(LOG_VERB, "Successfully registered\n");
				/* Notify the browser */
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("registered"));
				json_object_set_new(calling, "username", json_string(session->account.username));
				json_object_set_new(calling, "register_sent", json_string("true"));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, call_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
			} else if(status == 401) {
				/* Get scheme/realm from 401 error */
				sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
				char const* scheme = www_auth->au_scheme;
				const char* realm = msg_params_find(www_auth->au_params, "realm=");
				char auth[256];
				memset(auth, 0, sizeof(auth));
				g_snprintf(auth, sizeof(auth), "%s%s:%s:%s:%s%s",
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					scheme,
					realm,
					session->account.username,
					session->account.secret_type == janus_sip_secret_type_hashed ? "HA1+" : "",
					session->account.secret);
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
			} else if(status >= 400) {
				/* Authentication failed? */
				session->account.registration_status = janus_sip_registration_status_failed;
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				json_t *result = json_object();
				json_object_set_new(result, "event", json_string("registration_failed"));
			        json_object_set_new(result, "code", json_integer(status));
				json_object_set_new(result, "reason", json_string(phrase ? phrase : ""));
			        json_object_set_new(event, "result", result);
				char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(event);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, session->transaction, event_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(event_text);
			}
			break;
		}
		default:
			/* unknown event -> print out error message */
			JANUS_LOG(LOG_ERR, "Unknown event %d (%s)\n", event, nua_event_name(event));
			break;
	}
}

void janus_sip_sdp_process(janus_sip_session *session, sdp_session_t *sdp) {
	if(!session || !sdp)
		return;
	/* c= */
	if(sdp->sdp_connection && sdp->sdp_connection->c_address) {
		if(session->media.remote_ip != NULL)
			g_free(session->media.remote_ip);
		session->media.remote_ip = g_strdup(sdp->sdp_connection->c_address);
		JANUS_LOG(LOG_VERB, "  >> Media connection:\n");
		JANUS_LOG(LOG_VERB, "       %s\n", session->media.remote_ip);
	}
	JANUS_LOG(LOG_VERB, "  >> Media lines:\n");
	sdp_media_t *m = sdp->sdp_media;
	while(m) {
		if(m->m_type == sdp_media_audio) {
			JANUS_LOG(LOG_VERB, "       Audio: %lu\n", m->m_port);
			if(m->m_port) {
				session->media.has_audio = 1;
				session->media.remote_audio_rtp_port = m->m_port;
				session->media.remote_audio_rtcp_port = m->m_port+1;	/* FIXME We're assuming RTCP is on the next port */
			}
		} else if(m->m_type == sdp_media_video) {
			JANUS_LOG(LOG_VERB, "       Video: %lu\n", m->m_port);
			if(m->m_port) {
				session->media.has_video = 1;
				session->media.remote_video_rtp_port = m->m_port;
				session->media.remote_video_rtcp_port = m->m_port+1;	/* FIXME We're assuming RTCP is on the next port */
			}
		} else {
			JANUS_LOG(LOG_WARN, "       Unsupported media line (not audio/video)\n");
			m = m->m_next;
			continue;
		}
		JANUS_LOG(LOG_VERB, "       Media connections:\n");
		if(m->m_connections) {
			sdp_connection_t *c = m->m_connections;
			while(c) {
				if(c->c_address) {
					if(session->media.remote_ip != NULL)
						g_free(session->media.remote_ip);
					session->media.remote_ip = g_strdup(c->c_address);
					JANUS_LOG(LOG_VERB, "         [%s]\n", session->media.remote_ip);
				}
				c = c->c_next;
			}
		}
		JANUS_LOG(LOG_VERB, "       Media RTP maps:\n");
		sdp_rtpmap_t *r = m->m_rtpmaps;
		while(r) {
			JANUS_LOG(LOG_VERB, "         [%u] %s\n", r->rm_pt, r->rm_encoding);
			r = r->rm_next;
		}
		JANUS_LOG(LOG_VERB, "       Media attributes:\n");
		sdp_attribute_t *a = m->m_attributes;
		while(a) {
			if(a->a_name) {
				if(!strcasecmp(a->a_name, "rtpmap")) {
					JANUS_LOG(LOG_VERB, "         RTP Map:     %s\n", a->a_value);
				}
			}
			a = a->a_next;
		}
		m = m->m_next;
	}
}

/* Bind local RTP/RTCP sockets */
static int janus_sip_allocate_local_ports(janus_sip_session *session) {
	if(session == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		return -1;
	}
	/* Reset status */
	if(session->media.audio_rtp_fd > 0) {
		close(session->media.audio_rtp_fd);
		session->media.audio_rtp_fd = 0;
	}
	if(session->media.audio_rtcp_fd > 0) {
		close(session->media.audio_rtcp_fd);
		session->media.audio_rtcp_fd = 0;
	}
	session->media.local_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	if(session->media.video_rtp_fd > 0) {
		close(session->media.video_rtp_fd);
		session->media.video_rtp_fd = 0;
	}
	if(session->media.video_rtcp_fd > 0) {
		close(session->media.video_rtcp_fd);
		session->media.video_rtcp_fd = 0;
	}
	session->media.local_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	/* Start */
	int attempts = 100;	/* FIXME Don't retry forever */
	if(session->media.has_audio) {
		JANUS_LOG(LOG_VERB, "Allocating audio ports:\n");
		struct sockaddr_in audio_rtp_address, audio_rtcp_address;
		while(session->media.local_audio_rtp_port == 0 || session->media.local_audio_rtcp_port == 0) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.audio_rtp_fd == 0) {
				session->media.audio_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.audio_rtcp_fd == 0) {
				session->media.audio_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			int rtp_port = g_random_int_range(10000, 60000);	/* FIXME Should this be configurable? */
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			audio_rtp_address.sin_family = AF_INET;
			audio_rtp_address.sin_port = htons(rtp_port);
			inet_pton(AF_INET, local_ip, &audio_rtp_address.sin_addr.s_addr);
			if(bind(session->media.audio_rtp_fd, (struct sockaddr *)(&audio_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for audio RTP (port %d), trying a different one...\n", rtp_port);
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
				session->media.audio_rtp_fd = 0;
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
			if(session->media.video_rtp_fd == 0) {
				session->media.video_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			if(session->media.video_rtcp_fd == 0) {
				session->media.video_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			}
			int rtp_port = g_random_int_range(10000, 60000);	/* FIXME Should this be configurable? */
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			video_rtp_address.sin_family = AF_INET;
			video_rtp_address.sin_port = htons(rtp_port);
			inet_pton(AF_INET, local_ip, &video_rtp_address.sin_addr.s_addr);
			if(bind(session->media.video_rtp_fd, (struct sockaddr *)(&video_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTP (port %d), trying a different one...\n", rtp_port);
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
				session->media.video_rtp_fd = 0;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Video RTCP listener bound to port %d\n", rtcp_port);
			session->media.local_video_rtp_port = rtp_port;
			session->media.local_video_rtcp_port = rtcp_port;
		}
	}
	return 0;
}

/* Thread to relay RTP/RTCP frames coming from the SIP peer */
static void *janus_sip_relay_thread(void *data) {
	janus_sip_session *session = (janus_sip_session *)data;
	if(!session || !session->account.username || !session->callee) {
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Starting relay thread (%s <--> %s)\n", session->account.username, session->callee);

	gboolean have_server_ip = TRUE;
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
		struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
		if(!host) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't get host (%s)\n", session->account.username, session->media.remote_ip);
			have_server_ip = FALSE;
		} else {
			server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
		}
	}

	/* Connect peers (FIXME This pretty much sucks right now) */
	if(have_server_ip && session->media.remote_audio_rtp_port) {
		server_addr.sin_port = htons(session->media.remote_audio_rtp_port);
		if(connect(session->media.audio_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect audio RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(have_server_ip && session->media.remote_audio_rtcp_port) {
		server_addr.sin_port = htons(session->media.remote_audio_rtcp_port);
		if(connect(session->media.audio_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect audio RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_audio_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(have_server_ip && session->media.remote_video_rtp_port) {
		server_addr.sin_port = htons(session->media.remote_video_rtp_port);
		if(connect(session->media.video_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect video RTP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}
	if(have_server_ip && session->media.remote_video_rtcp_port) {
		server_addr.sin_port = htons(session->media.remote_video_rtcp_port);
		if(connect(session->media.video_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Couldn't connect video RTCP? (%s:%d)\n", session->account.username, session->media.remote_ip, session->media.remote_video_rtcp_port);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
		}
	}

	if(!session->callee) {
		JANUS_LOG(LOG_VERB, "[SIP-%s] Leaving thread, no callee...\n", session->account.username);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	/* Loop */
	socklen_t addrlen;
	struct sockaddr_in remote;
	int resfd = 0, bytes = 0;
	struct pollfd fds[4];
	char buffer[1500];
	memset(buffer, 0, 1500);
	while(session != NULL && !session->destroyed &&
			session->status > janus_sip_call_status_idle &&
			session->status < janus_sip_call_status_closing) {	/* FIXME We need a per-call watchdog as well */
		/* Wait for some data */
		fds[0].fd = 0;
		fds[0].events = 0;
		fds[0].revents = 0;
		if(session->media.audio_rtp_fd > 0) {
			fds[0].fd = session->media.audio_rtp_fd;
			fds[0].events = POLLIN;
		}
		fds[1].fd = 0;
		fds[1].events = 0;
		fds[1].revents = 0;
		if(session->media.audio_rtcp_fd > 0) {
			fds[1].fd = session->media.audio_rtcp_fd;
			fds[1].events = POLLIN;
		}
		fds[2].fd = 0;
		fds[2].events = 0;
		fds[2].revents = 0;
		if(session->media.video_rtp_fd > 0) {
			fds[2].fd = session->media.video_rtp_fd;
			fds[2].events = POLLIN;
		}
		fds[3].fd = 0;
		fds[3].events = 0;
		fds[3].revents = 0;
		if(session->media.video_rtcp_fd > 0) {
			fds[3].fd = session->media.video_rtcp_fd;
			fds[3].events = POLLIN;
		}
		resfd = poll(fds, 4, 1000);
		if(resfd < 0) {
			JANUS_LOG(LOG_ERR, "[SIP-%s] Error polling...\n", session->account.username);
			JANUS_LOG(LOG_ERR, "[SIP-%s]   -- %d (%s)\n", session->account.username, errno, strerror(errno));
			break;
		} else if(resfd == 0) {
			/* No data, keep going */
			continue;
		}
		if(session == NULL || session->destroyed ||
				session->status <= janus_sip_call_status_idle ||
				session->status >= janus_sip_call_status_closing)
			break;
		if(session->media.audio_rtp_fd && (fds[0].revents & POLLIN)) {
			/* Got something audio (RTP) */
			fds[0].revents = 0;
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.audio_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_LOG(LOG_VERB, "************************\nGot %d bytes on the audio RTP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_LOG(LOG_VERB, " ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			if(session->media.audio_ssrc_peer == 0) {
				rtp_header *header = (rtp_header *)buffer;
				session->media.audio_ssrc_peer = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP peer audio SSRC: %"SCNu32"\n", session->media.audio_ssrc_peer);
			}
			/* Save the frame if we're recording */
			if(session->arc_peer)
				janus_recorder_save_frame(session->arc_peer, buffer, bytes);
			/* Relay to browser */
			gateway->relay_rtp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.audio_rtcp_fd && (fds[1].revents & POLLIN)) {
			/* Got something audio (RTCP) */
			fds[1].revents = 0;
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.audio_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_LOG(LOG_VERB, "************************\nGot %d bytes on the audio RTCP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_LOG(LOG_VERB, " ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Save the frame if we're recording */
			if(session->vrc_peer)
				janus_recorder_save_frame(session->vrc_peer, buffer, bytes);
			/* Relay to browser */
			gateway->relay_rtcp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.video_rtp_fd && (fds[2].revents & POLLIN)) {
			/* Got something video (RTP) */
			fds[2].revents = 0;
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.video_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_LOG(LOG_VERB, "************************\nGot %d bytes on the video RTP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_LOG(LOG_VERB, " ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			if(session->media.video_ssrc_peer == 0) {
				rtp_header *header = (rtp_header *)buffer;
				session->media.video_ssrc_peer = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP peer video SSRC: %"SCNu32"\n", session->media.video_ssrc_peer);
			}
			/* Relay to browser */
			gateway->relay_rtp(session->handle, 1, buffer, bytes);
			continue;
		}
		if(session->media.video_rtcp_fd && (fds[3].revents & POLLIN)) {
			/* Got something video (RTCP) */
			fds[3].revents = 0;
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.video_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_LOG(LOG_VERB, "************************\nGot %d bytes on the video RTCP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_LOG(LOG_VERB, " ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtcp(session->handle, 1, buffer, bytes);
			continue;
		}
	}
	if(session->media.audio_rtp_fd > 0) {
		close(session->media.audio_rtp_fd);
		session->media.audio_rtp_fd = 0;
	}
	if(session->media.audio_rtcp_fd > 0) {
		close(session->media.audio_rtcp_fd);
		session->media.audio_rtcp_fd = 0;
	}
	session->media.local_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.audio_ssrc = 0;
	if(session->media.video_rtp_fd > 0) {
		close(session->media.video_rtp_fd);
		session->media.video_rtp_fd = 0;
	}
	if(session->media.video_rtcp_fd > 0) {
		close(session->media.video_rtcp_fd);
		session->media.video_rtcp_fd = 0;
	}
	session->media.local_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.video_ssrc = 0;
	JANUS_LOG(LOG_VERB, "Leaving SIP relay thread\n");
	g_thread_unref(g_thread_self());
	return NULL;
}


/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data) {
	janus_sip_session *session = (janus_sip_session *)user_data;
	if(session == NULL || session->account.username == NULL || session->stack == NULL) {
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "Joining sofia loop thread (%s)...\n", session->account.username);
	session->stack->s_root = su_root_create(session->stack);
	JANUS_LOG(LOG_VERB, "Setting up sofia stack (sip:%s@%s)\n", session->account.username, local_ip);
	char sip_url[128];
	char sips_url[128];
	char *ipv6;
	ipv6 = strstr(local_ip, ":");
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
				SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS"),
				NUTAG_M_USERNAME(session->account.username),
				NUTAG_URL(sip_url),
				TAG_IF(session->account.sips, NUTAG_SIPS_URL(sips_url)),
				SIPTAG_USER_AGENT_STR(user_agent),
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
	su_deinit();
	//~ stop = 1;
	JANUS_LOG(LOG_VERB, "Leaving sofia loop thread...\n");
	g_thread_unref(g_thread_self());
	return NULL;
}
