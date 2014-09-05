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
 * \todo Only Asterisk has been tested as a SIP server (which explains why
 * the plugin talks of extensions and not generic SIP URIs), and specifically
 * only basic audio calls have been tested: this plugin needs a lot of work.
 * 
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <ifaddrs.h>
#include <net/if.h>

#include <jansson.h>

#include <sofia-sip/msg_header.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip_status.h>

#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_SIP_VERSION			2
#define JANUS_SIP_VERSION_STRING	"0.0.2"
#define JANUS_SIP_DESCRIPTION		"This is a simple SIP plugin for Janus, allowing WebRTC peers to register at a SIP server and call SIP user agents through the gateway."
#define JANUS_SIP_NAME				"JANUS SIP plugin"
#define JANUS_SIP_AUTHOR			"Meetecho s.r.l."
#define JANUS_SIP_PACKAGE			"janus.plugin.sip"

/* Plugin methods */
janus_plugin *create(void);
int janus_sip_init(janus_callbacks *callback, const char *config_path);
void janus_sip_destroy(void);
int janus_sip_get_version(void);
const char *janus_sip_get_version_string(void);
const char *janus_sip_get_description(void);
const char *janus_sip_get_name(void);
const char *janus_sip_get_author(void);
const char *janus_sip_get_package(void);
void janus_sip_create_session(janus_plugin_session *handle, int *error);
void janus_sip_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_sip_setup_media(janus_plugin_session *handle);
void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_sip_hangup_media(janus_plugin_session *handle);
void janus_sip_destroy_session(janus_plugin_session *handle, int *error);

/* Plugin setup */
static janus_plugin janus_sip_plugin =
	{
		.init = janus_sip_init,
		.destroy = janus_sip_destroy,

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
	}; 

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SIP_NAME);
	return &janus_sip_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static char *local_ip = NULL;

static GThread *handler_thread;
static void *janus_sip_handler(void *data);

typedef struct janus_sip_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_sip_message;
GQueue *messages;

void janus_sip_message_free(janus_sip_message *msg);
void janus_sip_message_free(janus_sip_message *msg) {
	if(!msg)
		return;
	msg->handle = NULL;
	if(msg->transaction != NULL)
		g_free(msg->transaction);
	msg->transaction = NULL;
	if(msg->message != NULL)
		g_free(msg->message);
	msg->message = NULL;
	if(msg->sdp_type != NULL)
		g_free(msg->sdp_type);
	msg->sdp_type = NULL;
	if(msg->sdp != NULL)
		g_free(msg->sdp);
	msg->sdp = NULL;
	g_free(msg);
	msg = NULL;
}


typedef enum janus_sip_status {
	janus_sip_status_failed = -1,
	janus_sip_status_unregistered = 0,
	janus_sip_status_registering,
	janus_sip_status_registered,
	janus_sip_status_inviting,
	janus_sip_status_invited,
	janus_sip_status_incall,
	janus_sip_status_closing,
	janus_sip_status_unregistering,
} janus_sip_status;


/* Sofia stuff */
typedef struct ssip_s ssip_t;
typedef struct ssip_oper_s ssip_oper_t;

typedef struct janus_sip_account {
	char *identity;
	char *username;
	char *secret;
	int sip_port;
	char *proxy;
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
	janus_sip_status status;
	janus_sip_media media;
	char *callee;
	gboolean destroy;
	janus_mutex mutex;
} janus_sip_session;
GHashTable *sessions;
janus_mutex sessions_mutex;


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


/* Interface/IP ignore list */
GList *janus_sip_ignore_list = NULL;
janus_mutex ignore_list_mutex;
void janus_sip_ignore_interface(const char *ip);
gboolean janus_sip_is_ignored(const char *ip);

void janus_sip_ignore_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ignore_list_mutex);
	janus_sip_ignore_list = g_list_append(janus_sip_ignore_list, (gpointer)ip);
	janus_mutex_unlock(&ignore_list_mutex);
}

gboolean janus_sip_is_ignored(const char *ip) {
	if(ip == NULL || janus_sip_ignore_list == NULL)
		return FALSE;
	janus_mutex_lock(&ignore_list_mutex);
	GList *temp = janus_sip_ignore_list;
	while(temp) {
		const char *ignored = (const char *)temp->data;
		if(ignored != NULL && strstr(ip, ignored)) {
			janus_mutex_unlock(&ignore_list_mutex);
			return TRUE;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ignore_list_mutex);
	return FALSE;
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


/* Plugin implementation */
int janus_sip_init(janus_callbacks *callback, const char *config_path) {
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
	sprintf(filename, "%s/%s.cfg", config_path, JANUS_SIP_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	janus_config_item *item = janus_config_get_item_drilldown(config, "general", "c_address");
	if(item != NULL && item->value != NULL) {
		local_ip = g_strdup(item->value);
		JANUS_LOG(LOG_VERB, "Going to use %s as a c-line in the SDPs\n", local_ip);
	}
	item = janus_config_get_item_drilldown(config, "general", "autodetect_ignore");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_VERB, "Adding '%s' to the c-line ignore list...\n", index);
					janus_sip_ignore_interface(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_strfreev(list);
		list = NULL;
	}

	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	if(local_ip == NULL) {
		/* What is the local public IP? */
		JANUS_LOG(LOG_VERB, "Autodetecting through available interfaces...\n");
		/* Try to autodetect, but ignore those in the ignore list */
		struct ifaddrs *ifaddr, *ifa;
		int family, s, n;
		char host[NI_MAXHOST];
		if(getifaddrs(&ifaddr) == -1) {
			JANUS_LOG(LOG_ERR, "Error getting list of interfaces...");
		} else {
			for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
				if(ifa->ifa_addr == NULL)
					continue;
				family = ifa->ifa_addr->sa_family;
				if(family != AF_INET && family != AF_INET6)
					continue;
				/* FIXME We skip IPv6 addresses for now */
				if(family == AF_INET6)
					continue;
				/* Check the interface name first: we can ignore that as well */
				if(ifa->ifa_name != NULL && janus_sip_is_ignored(ifa->ifa_name))
					continue;
				s = getnameinfo(ifa->ifa_addr,
						(family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
						host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				if(s != 0) {
					JANUS_LOG(LOG_ERR, "getnameinfo() failed: %s\n", gai_strerror(s));
					continue;
				}
				/* Skip localhost */
				if(!strcmp(host, "127.0.0.1") || !strcmp(host, "::1") || !strcmp(host, "0.0.0.0"))
					continue;
				/* Check if this IP address is in the ignore list, now */
				if(janus_sip_is_ignored(host))
					continue;
				/* FIXME Ok, add use this interface (we're sticking with the first we get) */
				local_ip = g_strdup(host);
				break;
			}
			freeifaddrs(ifaddr);
		}
		if(local_ip == NULL) {
			JANUS_LOG(LOG_VERB, "Couldn't find any address! using 127.0.0.1 for c-lines... (which is NOT going to work out of your machine)\n");
			local_ip = g_strdup("127.0.0.1");
		} else {
			JANUS_LOG(LOG_VERB, "Going to use %s as a c-line in the SDPs\n", local_ip);
		}
	}

	/* Setup sofia */
	su_init();

	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	messages = g_queue_new();
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;

	initialized = 1;
	/* Launch the thread that will handle incoming messages */
	GError *error = NULL;
	handler_thread = g_thread_try_new("janus sip handler", janus_sip_handler, NULL, &error);
	if(error != NULL) {
		initialized = 0;
		/* Something went wrong... */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_SIP_NAME);
	return 0;
}

void janus_sip_destroy(void) {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	/* FIXME We should destroy the sessions cleanly */
	g_hash_table_destroy(sessions);
	g_queue_free(messages);
	sessions = NULL;
	initialized = 0;
	stopping = 0;
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_SIP_NAME);
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
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_sip_session *session = (janus_sip_session *)calloc(1, sizeof(janus_sip_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->account.identity = NULL;
	session->account.username = NULL;
	session->account.secret = NULL;
	session->account.sip_port = 0;
	session->account.proxy = NULL;
	session->stack = calloc(1, sizeof(ssip_t));
	if(session->stack == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		g_free(session);
		return;
	}
	session->stack->session = session;
	session->stack->s_nua = NULL;
	session->stack->s_nh_r = NULL;
	session->stack->s_nh_i = NULL;
	session->stack->s_root = NULL;
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
	su_home_init(session->stack->s_home);
	janus_mutex_init(&session->mutex);
	handle->plugin_handle = session;

	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_sip_destroy_session(janus_plugin_session *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroy) {
		JANUS_LOG(LOG_VERB, "Session already destroyed...\n");
		return;
	}
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_remove(sessions, handle);
	janus_mutex_unlock(&sessions_mutex);
	janus_sip_hangup_media(handle);
	JANUS_LOG(LOG_VERB, "Destroying SIP session (%s)...\n", session->account.username ? session->account.username : "unregistered user");
	/* Shutdown the NUA */
	nua_shutdown(session->stack->s_nua);
	/* Cleaning up and removing the session is done in a lazy way */
	session->destroy = TRUE;
	return;
}

void janus_sip_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_LOG(LOG_VERB, "%s\n", message);
	janus_sip_message *msg = calloc(1, sizeof(janus_sip_message));
	if(msg == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_queue_push_tail(messages, msg);
}

void janus_sip_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* TODO Only relay RTP/RTCP when we get this event */
}

void janus_sip_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized)
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
		if(!session || session->destroy) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_status_incall)
			return;
		/* Forward to our SIP peer */
		if(video) {
			if(session->media.video_ssrc == 0) {
				rtp_header *header = (rtp_header *)buf;
				session->media.video_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP video SSRC: %"SCNu32"\n", session->media.video_ssrc);
			}
			if(session->media.has_video && session->media.video_rtp_fd) {
				send(session->media.video_rtp_fd, buf, len, 0);
			}
		} else {
			if(session->media.audio_ssrc == 0) {
				rtp_header *header = (rtp_header *)buf;
				session->media.audio_ssrc = ntohl(header->ssrc);
				JANUS_LOG(LOG_VERB, "Got SIP audio SSRC: %"SCNu32"\n", session->media.audio_ssrc);
			}
			if(session->media.has_audio && session->media.audio_rtp_fd) {
				send(session->media.audio_rtp_fd, buf, len, 0);
			}
		}
	}
}

void janus_sip_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || stopping || !initialized)
		return;
	if(gateway) {
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
		if(!session || session->destroy) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->status != janus_sip_status_incall)
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
	if(stopping || !initialized)
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	if(session->status < janus_sip_status_inviting || session->status > janus_sip_status_incall)
		return;
	/* FIXME Simulate a "hangup" coming from the browser */
	janus_sip_message *msg = calloc(1, sizeof(janus_sip_message));
	if(msg == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->message = g_strdup("{\"request\":\"hangup\"}");
	msg->transaction = NULL;
	msg->sdp_type = NULL;
	msg->sdp = NULL;
	g_queue_push_tail(messages, msg);
}

/* Thread to handle incoming messages */
static void *janus_sip_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining thread\n");
	janus_sip_message *msg = NULL;
	int error_code = 0;
	char *error_cause = calloc(512, sizeof(char));	/* FIXME 512 should be enough, but anyway... */
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	while(initialized && !stopping) {
		if(!messages || (msg = g_queue_pop_head(messages)) == NULL) {
			usleep(50000);
			continue;
		}
		janus_sip_session *session = (janus_sip_session *)msg->handle->plugin_handle;
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_sip_message_free(msg);
			continue;
		}
		if(session->destroy) {
			janus_sip_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_SIP_ERROR_NO_MESSAGE;
			sprintf(error_cause, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		json_t *root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_SIP_ERROR_INVALID_JSON;
			sprintf(error_cause, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_SIP_ERROR_INVALID_JSON;
			sprintf(error_cause, "JSON error: not an object");
			goto error;
		}
		json_t *request = json_object_get(root, "request");
		if(!request) {
			JANUS_LOG(LOG_ERR, "Missing element (request)\n");
			error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
			sprintf(error_cause, "Missing element (request)");
			goto error;
		}
		if(!json_is_string(request)) {
			JANUS_LOG(LOG_ERR, "Invalid element (request should be a string)\n");
			error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
			sprintf(error_cause, "Invalid element (request should be a string)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *result = NULL;
		char *sdp_type = NULL, *sdp = NULL;
		if(!strcasecmp(request_text, "register")) {
			/* Send a REGISTER */
			if(session->status > janus_sip_status_unregistered) {
				JANUS_LOG(LOG_ERR, "Already registered (%s)\n", session->account.username);
				error_code = JANUS_SIP_ERROR_ALREADY_REGISTERED;
				sprintf(error_cause, "Already registered (%s)", session->account.username);
				goto error;
			}
			gboolean guest = FALSE;
			json_t *type = json_object_get(root, "type");
			if(type != NULL) {
				if(!type) {
					JANUS_LOG(LOG_ERR, "Missing element (type)\n");
					error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (type)");
					goto error;
				}
				if(!json_is_string(type)) {
					JANUS_LOG(LOG_ERR, "Invalid element (type should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (type should be a string)");
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
			/* Parse address */
			json_t *proxy = json_object_get(root, "proxy");
			if(!proxy) {
				JANUS_LOG(LOG_ERR, "Missing element (proxy)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				sprintf(error_cause, "Missing element (proxy)");
				goto error;
			}
			if(!json_is_string(proxy)) {
				JANUS_LOG(LOG_ERR, "Invalid element (proxy should be a string)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (proxy should be a string)");
				goto error;
			}
			const char *proxy_text = json_string_value(proxy);
			if(strstr(proxy_text, "sip:") != proxy_text) {
				JANUS_LOG(LOG_ERR, "Invalid proxy address %s\n", proxy_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				sprintf(error_cause, "Invalid proxy address %s\n", proxy_text);
				goto error;
			}
			const char *domain_part = proxy_text+4;	/* Skip sip: part */
			char proxy_ip[256];
			uint16_t proxy_port = 0;
			if(strstr(domain_part, ":") == NULL) {
				strncpy(proxy_ip, domain_part, strlen(domain_part) < 255 ? strlen(domain_part) : 255);
				proxy_ip[strlen(domain_part) < 255 ? strlen(domain_part) : 255] = '\0';
				proxy_port = 5060;
			} else {
				gchar **domain = g_strsplit(domain_part, ":", -1);
				if(domain[0] == NULL || domain[1] == NULL) {
					g_strfreev(domain);
					JANUS_LOG(LOG_ERR, "Invalid proxy address %s\n", domain_part);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					sprintf(error_cause, "Invalid proxy address %s\n", domain_part);
					goto error;
				}
				strncpy(proxy_ip, domain[0], strlen(domain[0]) < 255 ? strlen(domain[0]) : 255);
				proxy_ip[strlen(domain[0]) < 255 ? strlen(domain[0]) : 255] = '\0';
				proxy_port = atoi(domain[1]);
				g_strfreev(domain);
			}
			/* Now the user part, if needed */
			json_t *username = json_object_get(root, "username");
			if(!guest && !username) {
				/* The username is mandatory if we're not registering as guests */
				JANUS_LOG(LOG_ERR, "Missing element (username)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				sprintf(error_cause, "Missing element (username)");
				goto error;
			}
			const char *username_text = NULL;
			char user_id[256];
			char user_ip[256];
			uint16_t user_port = 0;
			if(username) {
				if(!json_is_string(username)) {
					JANUS_LOG(LOG_ERR, "Invalid element (username should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (username should be a string)");
					goto error;
				}
				/* Parse address */
				username_text = username ? json_string_value(username) : NULL;
				if(strstr(username_text, "sip:") != username_text && !strstr(username_text, "@")) {
					JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					sprintf(error_cause, "Invalid user address %s\n", username_text);
					goto error;
				}
				gchar **parts = g_strsplit(username_text+4, "@", -1);
				if(parts[0] == NULL || parts[1] == NULL) {
					g_strfreev(parts);
					JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					sprintf(error_cause, "Invalid user address %s\n", username_text);
					goto error;
				}
				strncpy(user_id, parts[0], strlen(parts[0]) < 255 ? strlen(parts[0]) : 255);
				user_id[strlen(parts[0]) < 255 ? strlen(parts[0]) : 255] = '\0';
				if(strstr(parts[1], ":") == NULL) {
					strncpy(user_ip, parts[1], strlen(parts[1]) < 255 ? strlen(parts[1]) : 255);
					user_ip[strlen(parts[1]) < 255 ? strlen(parts[1]) : 255] = '\0';
					user_port = 5060;
				} else {
					gchar **domain = g_strsplit(parts[1], ":", -1);
					if(domain[0] == NULL || domain[1] == NULL) {
						g_strfreev(domain);
						JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
						error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
						sprintf(error_cause, "Invalid user address %s\n", username_text);
						goto error;
					}
					strncpy(user_ip, domain[0], strlen(domain[0]) < 255 ? strlen(domain[0]) : 255);
					user_ip[strlen(domain[0]) < 255 ? strlen(domain[0]) : 255] = '\0';
					user_port = atoi(domain[1]);
					g_strfreev(domain);
				}
				g_strfreev(parts);
				if(user_port == 0) {
					JANUS_LOG(LOG_ERR, "Invalid user address %s\n", username_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					sprintf(error_cause, "Invalid user address %s\n", username_text);
					goto error;
				}
			}
			if(guest) {
				/* Not needed, we can stop here: just pick a random username if it wasn't provided and say we're registered */
				if(!username) {
					char username[255];
					sprintf(username, "janus-sip-%"SCNu32"", g_random_int());
					session->account.username = g_strdup(username);
				} else {
					session->account.username = g_strdup(user_id);
				}
				JANUS_LOG(LOG_INFO, "Guest will have username %s\n", session->account.username);
				session->status = janus_sip_status_registering;
				if(session->stack->s_nua == NULL) {
					/* Start the thread first */
					GError *error = NULL;
					g_thread_try_new("worker", janus_sip_sofia_thread, session, &error);
					g_assert (!error);
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
						sprintf(error_cause, "Two seconds passed and still no NUA, problems with the thread?");
						goto error;
					}
				}
				if(session->stack->s_nh_r != NULL)
					nua_handle_destroy(session->stack->s_nh_r);
				session->stack->s_nh_r = nua_handle(session->stack->s_nua, session, TAG_END());
				if(session->stack->s_nh_r == NULL) {
					JANUS_LOG(LOG_ERR, "NUA Handle for REGISTER still null??\n");
					error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
					sprintf(error_cause, "Invalid NUA Handle");
					goto error;
				}
				session->status = janus_sip_status_registered;
				result = json_object();
				json_object_set_new(result, "event", json_string("registered"));
				json_object_set_new(result, "username", json_string(session->account.username));
			} else {
				json_t *secret = json_object_get(root, "secret");
				if(!secret) {
					JANUS_LOG(LOG_ERR, "Missing element (secret)\n");
					error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
					sprintf(error_cause, "Missing element (secret)");
					goto error;
				}
				if(!json_is_string(secret)) {
					JANUS_LOG(LOG_ERR, "Invalid element (secret should be a string)\n");
					error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
					sprintf(error_cause, "Invalid element (secret should be a string)");
					goto error;
				}
				const char *secret_text = json_string_value(secret);
				/* Got the values, try registering now */
				char registrar[256];
				sprintf(registrar, "sip:%s:%d", user_ip, user_port); 
				JANUS_LOG(LOG_VERB, "Registering user sip:%s@%s:%d (secret %s) @ %s through sip:%s:%d\n",
					user_id, user_ip, user_port, secret_text, registrar, proxy_ip, proxy_port);
				if(session->account.identity != NULL)
					g_free(session->account.identity);
				if(session->account.username != NULL)
					g_free(session->account.username);
				if(session->account.secret != NULL)
					g_free(session->account.secret);
				if(session->account.proxy != NULL)
					g_free(session->account.proxy);
				session->account.identity = g_strdup(username_text);
				session->account.username = g_strdup(user_id);
				session->account.secret = g_strdup(secret_text);
				session->account.proxy = g_strdup(proxy_text);
				if(session->account.identity == NULL || session->account.username == NULL || session->account.secret == NULL || session->account.proxy == NULL) {
					JANUS_LOG(LOG_FATAL, "Memory error!\n");
					error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
					sprintf(error_cause, "Memory error");
					goto error;
				}
				session->status = janus_sip_status_registering;
				if(session->stack->s_nua == NULL) {
					/* Start the thread first */
					GError *error = NULL;
					g_thread_try_new("worker", janus_sip_sofia_thread, session, &error);
					g_assert (!error);
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
						sprintf(error_cause, "Two seconds passed and still no NUA, problems with the thread?");
						goto error;
					}
				}
				if(session->stack->s_nh_r != NULL)
					nua_handle_destroy(session->stack->s_nh_r);
				session->stack->s_nh_r = nua_handle(session->stack->s_nua, session, TAG_END());
				if(session->stack->s_nh_r == NULL) {
					JANUS_LOG(LOG_ERR, "NUA Handle for REGISTER still null??\n");
					error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
					sprintf(error_cause, "Invalid NUA Handle");
					goto error;
				}
				JANUS_LOG(LOG_VERB, "%s --> %s\n", username_text, proxy_text);
				nua_register(session->stack->s_nh_r,
					NUTAG_M_DISPLAY(g_strdup(session->account.username)),
					NUTAG_M_USERNAME(g_strdup(session->account.username)),
					SIPTAG_FROM_STR(g_strdup(username_text)),
					SIPTAG_TO_STR(g_strdup(username_text)),
					NUTAG_REGISTRAR(g_strdup(registrar)),
					NUTAG_PROXY(g_strdup(proxy_text)),
					TAG_END());
				result = json_object();
				json_object_set_new(result, "event", json_string("registering"));
			}
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->status >= janus_sip_status_inviting) {
				JANUS_LOG(LOG_ERR, "Wrong state (already in a call?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				sprintf(error_cause, "Wrong state (already in a call?)");
				goto error;
			}
			json_t *uri = json_object_get(root, "uri");
			if(!uri) {
				JANUS_LOG(LOG_ERR, "Missing element (uri)\n");
				error_code = JANUS_SIP_ERROR_MISSING_ELEMENT;
				sprintf(error_cause, "Missing element (uri)");
				goto error;
			}
			if(!json_is_string(uri)) {
				JANUS_LOG(LOG_ERR, "Invalid element (uri should be a string)\n");
				error_code = JANUS_SIP_ERROR_INVALID_ELEMENT;
				sprintf(error_cause, "Invalid element (uri should be a string)");
				goto error;
			}
			/* Parse address */
			const char *uri_text = json_string_value(uri);
			if(strstr(uri_text, "sip:") != uri_text && !strstr(uri_text, "@")) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				sprintf(error_cause, "Invalid user address %s\n", uri_text);
				goto error;
			}
			char user_id[256];
			char user_ip[256];
			uint16_t user_port = 0;
			gchar **parts = g_strsplit(uri_text+4, "@", -1);
			if(parts[0] == NULL || parts[1] == NULL) {
				g_strfreev(parts);
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				sprintf(error_cause, "Invalid user address %s\n", uri_text);
				goto error;
			}
			strncpy(user_id, parts[0], strlen(parts[0]) < 255 ? strlen(parts[0]) : 255);
			user_id[strlen(parts[0]) < 255 ? strlen(parts[0]) : 255] = '\0';
			if(strstr(parts[1], ":") == NULL) {
				strncpy(user_ip, parts[1], strlen(parts[1]) < 255 ? strlen(parts[1]) : 255);
				user_ip[strlen(parts[1]) < 255 ? strlen(parts[1]) : 255] = '\0';
				user_port = 5060;
			} else {
				gchar **domain = g_strsplit(parts[1], ":", -1);
				if(domain[0] == NULL || domain[1] == NULL) {
					g_strfreev(domain);
					JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
					error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
					sprintf(error_cause, "Invalid user address %s\n", uri_text);
					goto error;
				}
				strncpy(user_ip, domain[0], strlen(domain[0]) < 255 ? strlen(domain[0]) : 255);
				user_ip[strlen(domain[0]) < 255 ? strlen(domain[0]) : 255] = '\0';
				user_port = atoi(domain[1]);
				g_strfreev(domain);
			}
			g_strfreev(parts);
			if(user_port == 0) {
				JANUS_LOG(LOG_ERR, "Invalid user address %s\n", uri_text);
				error_code = JANUS_SIP_ERROR_INVALID_ADDRESS;
				sprintf(error_cause, "Invalid user address %s\n", uri_text);
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				sprintf(error_cause, "Missing SDP");
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
				sprintf(error_cause, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			if(sdp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Memory error");
				goto error;
			}
			sdp = janus_string_replace(sdp, "RTP/SAVPF", "RTP/AVP");
			sdp = janus_string_replace(sdp, "1.1.1.1", local_ip);
			if(session->media.has_audio) {
				JANUS_LOG(LOG_VERB, "Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				sprintf(mline, "m=audio %d", session->media.local_audio_rtp_port);
				sdp = janus_string_replace(sdp, "m=audio 1", mline);
			}
			if(session->media.has_video) {
				JANUS_LOG(LOG_VERB, "Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				sprintf(mline, "m=video %d", session->media.local_video_rtp_port);
				sdp = janus_string_replace(sdp, "m=video 1", mline);
			}
			/* Send INVITE */
			if(session->stack->s_nh_i != NULL)
				nua_handle_destroy(session->stack->s_nh_i);
			session->stack->s_nh_i = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for INVITE still null??\n");
				error_code = JANUS_SIP_ERROR_LIBSOFIA_ERROR;
				sprintf(error_cause, "Invalid NUA Handle");
				goto error;
			}
			session->status = janus_sip_status_inviting;
			nua_invite(session->stack->s_nh_i,
				SIPTAG_TO_STR(g_strdup(uri_text)),
				SOATAG_USER_SDP_STR(g_strdup(sdp)),
				NUTAG_PROXY(g_strdup(session->account.proxy)),
				TAG_END());
			g_free(sdp);
			session->callee = g_strdup(uri_text);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("calling"));
		} else if(!strcasecmp(request_text, "accept")) {
			if(session->status != janus_sip_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? state=%d)\n", session->status);
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				sprintf(error_cause, "Wrong state (not invited?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no caller?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				sprintf(error_cause, "Wrong state (no caller?)");
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_LOG(LOG_ERR, "Missing SDP\n");
				error_code = JANUS_SIP_ERROR_MISSING_SDP;
				sprintf(error_cause, "Missing SDP");
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
				sprintf(error_cause, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			if(sdp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				error_code = JANUS_SIP_ERROR_UNKNOWN_ERROR;
				sprintf(error_cause, "Memory error");
				goto error;
			}
			sdp = janus_string_replace(sdp, "RTP/SAVPF", "RTP/AVP");
			sdp = janus_string_replace(sdp, "1.1.1.1", local_ip);
			if(session->media.has_audio) {
				JANUS_LOG(LOG_VERB, "Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				sprintf(mline, "m=audio %d", session->media.local_audio_rtp_port);
				sdp = janus_string_replace(sdp, "m=audio 1", mline);
			}
			if(session->media.has_video) {
				JANUS_LOG(LOG_VERB, "Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				sprintf(mline, "m=video %d", session->media.local_video_rtp_port);
				sdp = janus_string_replace(sdp, "m=video 1", mline);
			}
			/* Send 200 OK */
			session->status = janus_sip_status_incall;
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			nua_respond(session->stack->s_nh_i,
				200, sip_status_phrase(200),
				SIPTAG_TO_STR(g_strdup(session->callee)),
				SOATAG_USER_SDP_STR(g_strdup(sdp)),
				TAG_END());
			g_free(sdp);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("accepted"));
			/* Start the media */
			session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
			GError *error = NULL;
			g_thread_try_new("janus rtp handler", janus_sip_relay_thread, session, &error);
			if(error) {
				JANUS_LOG(LOG_ERR, "Error starting RTP/RTCP thread?\n");
			}
		} else if(!strcasecmp(request_text, "decline")) {
			/* Reject an incoming call */
			if(session->status != janus_sip_status_invited) {
				JANUS_LOG(LOG_ERR, "Wrong state (not invited? state=%d)\n", session->status);
				/* Ignore */
				json_decref(root);
				continue;
				//~ sprintf(error_cause, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				sprintf(error_cause, "Wrong state (no callee?)");
				goto error;
			}
			session->status = janus_sip_status_registered;	/* FIXME */
			if(session->stack->s_nh_i == NULL) {
				JANUS_LOG(LOG_WARN, "NUA Handle for 200 OK still null??\n");
			}
			nua_respond(session->stack->s_nh_i, 603, sip_status_phrase(603), TAG_END());
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("ack"));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call */
			if(session->status < janus_sip_status_inviting || session->status > janus_sip_status_incall) {
				JANUS_LOG(LOG_ERR, "Wrong state (not in a call? state=%d)\n", session->status);
				/* Ignore */
				json_decref(root);
				continue;
				//~ sprintf(error_cause, "Wrong state (not in a call?)");
				//~ goto error;
			}
			if(session->callee == NULL) {
				JANUS_LOG(LOG_ERR, "Wrong state (no callee?)\n");
				error_code = JANUS_SIP_ERROR_WRONG_STATE;
				sprintf(error_cause, "Wrong state (no callee?)");
				goto error;
			}
			session->status = janus_sip_status_closing;
			nua_bye(session->stack->s_nh_i,
				SIPTAG_TO_STR(g_strdup(session->callee)),
				TAG_END());
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
		} else {
			JANUS_LOG(LOG_ERR, "Unknown request (%s)\n", request_text);
			error_code = JANUS_SIP_ERROR_INVALID_REQUEST;
			sprintf(error_cause, "Unknown request (%s)", request_text);
			goto error;
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "sip", json_string("event"));
		if(result != NULL)
			json_object_set(event, "result", result);
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		if(result != NULL)
			json_decref(result);
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
	JANUS_LOG(LOG_VERB, "Leaving thread\n");
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
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_error:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_fork:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_media_error:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_subscription:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_state:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_terminated:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP requests */
		case nua_i_ack:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_outbound:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_bye: {
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* Call ended, notify the browser */
			session->status = janus_sip_status_registered;	/* FIXME What about a 'closing' state? */
			char reason[100];
			memset(reason, 0, 100);
			sprintf(reason, "%d %s", status, phrase);
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string(reason));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Get rid of any PeerConnection that may have been set up in the meanwhile */
			gateway->close_pc(session->handle);
			break;
		}
		case nua_i_cancel: {
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Check state? */
			session->status = janus_sip_status_registered;	/* FIXME What about a 'closing' state? */
			/* Notify the browser */
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string("Remote cancel"));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Get rid of any PeerConnection that may have been set up in the meanwhile */
			gateway->close_pc(session->handle);
			break;
		}
		case nua_i_chat:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_info:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_invite: {
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if (!sdp_session(parser)) {
				JANUS_LOG(LOG_ERR, "\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			if(session->status >= janus_sip_status_inviting) {
				/* Busy */
				JANUS_LOG(LOG_VERB, "\tAlready in a call (busy)\n");
				nua_respond(nh, 486, sip_status_phrase(486), TAG_END());
				break;
			}
			const char *caller = sip->sip_from->a_url->url_user;
			session->callee = g_strdup(url_as_string(session->stack->s_home, sip->sip_from->a_url));
			session->status = janus_sip_status_invited;
			/* Parse SDP */
			char *fixed_sdp = g_strdup(sip->sip_payload->pl_data);
			if(fixed_sdp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				nua_respond(nh, 500, sip_status_phrase(500), TAG_END());
				break;
			}
			JANUS_LOG(LOG_VERB, "Someone is inviting us in a call:\n%s", sip->sip_payload->pl_data);
			sdp_session_t *sdp = sdp_session(parser);
			janus_sip_sdp_process(session, sdp);
			/* Send SDP to the browser */
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("incomingcall"));
			json_object_set_new(calling, "username", json_string(caller));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, "offer", sip->sip_payload->pl_data);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Send a Ringing back */
			nua_respond(nh, 180, sip_status_phrase(180), TAG_END());
			session->stack->s_nh_i = nh;
			break;
		}
		case nua_i_message:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_method:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_notify:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_options:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_prack:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_publish:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_refer:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_register:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_subscribe:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_update:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
	/* Responses */
		case nua_r_get_params:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_set_params:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_notifier:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_shutdown:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			if (status < 200 && stopping < 3) {
				/* shutdown in progress -> return */
				break;
			}
			/* end the event loop. su_root_run() will return */
			su_root_break(ssip->s_root);
			break;
		case nua_r_terminate:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP responses */
		case nua_r_bye:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* Call ended, notify the browser */
			session->status = janus_sip_status_registered;
			char reason[100];
			memset(reason, 0, 100);
			sprintf(reason, "%d %s", status, phrase);
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string("Bye"));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			/* Get rid of any PeerConnection that may have been set up in the meanwhile */
			gateway->close_pc(session->handle);
			break;
		case nua_r_cancel:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_info:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_invite: {
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			if(status < 200) {
				/* Not ready yet (FIXME May this be pranswer?? we don't handle it yet...) */
				break;
			} else if(status == 401) {
 				/* Get scheme/realm from 401 error */
				sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
				char const* scheme = www_auth->au_scheme;
				const char* realm = msg_params_find(www_auth->au_params, "realm=");
				char auth[100];
				memset(auth, 0, 100);
				sprintf(auth, "%s:%s:%s:%s", scheme, realm,
					session->account.username ? session->account.username : "null",
					session->account.secret ? session->account.secret : "null");
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
				break;
			} else if(status >= 400) {
				/* Something went wrong, notify the browser */
				session->status = janus_sip_status_registered;
				char reason[100];
				memset(reason, 0, 100);
				sprintf(reason, "%d %s", status, phrase);
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "username", json_string(session->callee));
				json_object_set_new(calling, "reason", json_string(reason));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
				/* Get rid of any PeerConnection that may have been set up in the meanwhile */
				gateway->close_pc(session->handle);
				break;
			}
			ssip_t *ssip = session->stack;
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if (!sdp_session(parser)) {
				JANUS_LOG(LOG_ERR, "\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			JANUS_LOG(LOG_VERB, "Peer accepted our call:\n%s", sip->sip_payload->pl_data);
			session->status = janus_sip_status_incall;
			char *fixed_sdp = g_strdup(sip->sip_payload->pl_data);
			if(fixed_sdp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				nua_respond(nh, 500, sip_status_phrase(500), TAG_END());
				break;
			}
			sdp_session_t *sdp = sdp_session(parser);
			janus_sip_sdp_process(session, sdp);
			session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
			GError *error = NULL;
			g_thread_try_new("janus rtp handler", janus_sip_relay_thread, session, &error);
			if(error) {
				JANUS_LOG(LOG_ERR, "Error starting RTP/RTCP thread?\n");
			}
			/* Send SDP to the browser */
			session->status = janus_sip_status_incall;
			json_t *call = json_object();
			json_object_set_new(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("accepted"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(call);
			JANUS_LOG(LOG_VERB, "Pushing event to peer: %s\n", call_text);
			int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, "answer", fixed_sdp);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(call_text);
			break;
		}
		case nua_r_message:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_notify:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_options:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_prack:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_publish:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_refer:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_register: {
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			if(status == 200) {
				if(session->status < janus_sip_status_registered)
					session->status = janus_sip_status_registered;
				JANUS_LOG(LOG_VERB, "Successfully registered\n");
				/* Notify the browser */
				json_t *call = json_object();
				json_object_set_new(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("registered"));
				json_object_set_new(calling, "username", json_string(session->account.username));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(call);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", call_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(call_text);
			} else if(status == 401) {
				/* Get scheme/realm from 401 error */
				sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
				char const* scheme = www_auth->au_scheme;
				const char* realm = msg_params_find(www_auth->au_params, "realm=");
				char auth[100];
				memset(auth, 0, 100);
				sprintf(auth, "%s:%s:%s:%s", scheme, realm, session->account.username, session->account.secret);
				JANUS_LOG(LOG_VERB, "\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
			} else if(status >= 400) {
				/* Authentication failed? */
				session->status = janus_sip_status_failed;
				/* Tell the browser... */
				json_t *event = json_object();
				json_object_set_new(event, "sip", json_string("event"));
				char error_cause[256];
				sprintf(error_cause, "Registration failed: %d %s", status, phrase ? phrase : "??");
				json_object_set_new(event, "error", json_string(error_cause));
				char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
				json_decref(event);
				JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
				int ret = gateway->push_event(session->handle, &janus_sip_plugin, NULL, event_text, NULL, NULL);
				JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
				g_free(event_text);
			}
			break;
		}
		case nua_r_subscribe:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unpublish:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unregister:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unsubscribe:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_update:
			JANUS_LOG(LOG_VERB, "[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
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
	//~ /* Reset status */
	//~ session->media.ready = 0;
	//~ session->media.has_audio = 0;
	//~ session->media.audio_rtp_fd = 0;
	//~ session->media.audio_rtcp_fd= 0;
	//~ session->media.local_audio_rtp_port = 0;
	//~ session->media.remote_audio_rtp_port = 0;
	//~ session->media.local_audio_rtcp_port = 0;
	//~ session->media.remote_audio_rtcp_port = 0;
	//~ session->media.has_video = 0;
	//~ session->media.video_rtp_fd = 0;
	//~ session->media.video_rtcp_fd= 0;
	//~ session->media.local_video_rtp_port = 0;
	//~ session->media.remote_video_rtp_port = 0;
	//~ session->media.local_video_rtcp_port = 0;
	//~ session->media.remote_video_rtcp_port = 0;
	/* Start */
	int attempts = 100;	/* FIXME Don't retry forever */
	if(session->media.has_audio) {
		JANUS_LOG(LOG_VERB, "Allocating audio ports:\n");
		struct sockaddr_in audio_rtp_address, audio_rtcp_address;
		int yes = 1;	/* For setsockopt() SO_REUSEADDR */
		while(session->media.local_audio_rtp_port == 0 || session->media.local_audio_rtcp_port == 0) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.audio_rtp_fd == 0) {
				yes = 1;
				session->media.audio_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(session->media.audio_rtp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
			}
			if(session->media.audio_rtcp_fd == 0) {
				yes = 1;
				session->media.audio_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(session->media.audio_rtcp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
			}
			int rtp_port = g_random_int_range(10000, 60000);	/* FIXME Should this be configurable? */
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			audio_rtp_address.sin_family = AF_INET;
			audio_rtp_address.sin_port = htons(rtp_port);
			audio_rtp_address.sin_addr.s_addr = INADDR_ANY;
			if(bind(session->media.audio_rtp_fd, (struct sockaddr *)(&audio_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for audio RTP (port %d), trying a different one...\n", rtp_port);
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Audio RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			audio_rtcp_address.sin_family = AF_INET;
			audio_rtcp_address.sin_port = htons(rtcp_port);
			audio_rtcp_address.sin_addr.s_addr = INADDR_ANY;
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
		int yes = 1;	/* For setsockopt() SO_REUSEADDR */
		while(session->media.local_video_rtp_port == 0 || session->media.local_video_rtcp_port == 0) {
			if(attempts == 0)	/* Too many failures */
				return -1;
			if(session->media.video_rtp_fd == 0) {
				yes = 1;
				session->media.video_rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(session->media.video_rtp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
			}
			if(session->media.video_rtcp_fd == 0) {
				yes = 1;
				session->media.video_rtcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(session->media.video_rtcp_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
			}
			int rtp_port = g_random_int_range(10000, 60000);	/* FIXME Should this be configurable? */
			if(rtp_port % 2)
				rtp_port++;	/* Pick an even port for RTP */
			video_rtp_address.sin_family = AF_INET;
			video_rtp_address.sin_port = htons(rtp_port);
			video_rtp_address.sin_addr.s_addr = INADDR_ANY;
			if(bind(session->media.video_rtp_fd, (struct sockaddr *)(&video_rtp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTP (port %d), trying a different one...\n", rtp_port);
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Audio RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			video_rtcp_address.sin_family = AF_INET;
			video_rtcp_address.sin_port = htons(rtcp_port);
			video_rtcp_address.sin_addr.s_addr = INADDR_ANY;
			if(bind(session->media.video_rtcp_fd, (struct sockaddr *)(&video_rtcp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(LOG_ERR, "Bind failed for video RTCP (port %d), trying a different one...\n", rtcp_port);
				/* RTP socket is not valid anymore, reset it */
				close(session->media.video_rtp_fd);
				session->media.video_rtp_fd = 0;
				attempts--;
				continue;
			}
			JANUS_LOG(LOG_VERB, "Audio RTCP listener bound to port %d\n", rtcp_port);
			session->media.local_video_rtp_port = rtp_port;
			session->media.local_video_rtcp_port = rtcp_port;
		}
	}
	return 0;
}

/* Thread to relay RTP/RTCP frames coming from the SIP peer */
static void *janus_sip_relay_thread(void *data) {
	janus_sip_session *session = (janus_sip_session *)data;
	if(!session || !session->account.username || !session->callee)
		return NULL;
	JANUS_LOG(LOG_VERB, "Starting relay thread (%s <--> %s)\n", session->account.username, session->callee);
	/* Socket stuff */
	int maxfd = 0;
	if(session->media.audio_rtp_fd > maxfd)
		maxfd = session->media.audio_rtp_fd;
	if(session->media.audio_rtcp_fd > maxfd)
		maxfd = session->media.audio_rtcp_fd;
	if(session->media.video_rtp_fd > maxfd)
		maxfd = session->media.video_rtp_fd;
	if(session->media.video_rtcp_fd > maxfd)
		maxfd = session->media.video_rtcp_fd;
	//~ /* Wait for the remote information */
	//~ while(!session->media.ready) {
		//~ 
	//~ }
	/* Connect peers (FIXME This pretty much sucks right now) */
	if(session->media.remote_audio_rtp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
			if(!host) {
				JANUS_LOG(LOG_ERR, "Couldn't get host (%s)\n", session->media.remote_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_audio_rtp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.audio_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "Couldn't connect audio RTP? (%s:%d)\n", session->media.remote_ip, session->media.remote_audio_rtp_port);
			JANUS_LOG(LOG_ERR, "  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_audio_rtcp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
			if(!host) {
				JANUS_LOG(LOG_ERR, "Couldn't get host (%s)\n", session->media.remote_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_audio_rtcp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.audio_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "Couldn't connect audio RTCP? (%s:%d)\n", session->media.remote_ip, session->media.remote_audio_rtcp_port);
			JANUS_LOG(LOG_ERR, "  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
			if(!host) {
				JANUS_LOG(LOG_ERR, "Couldn't get host (%s)\n", session->media.remote_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_video_rtp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.video_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "Couldn't connect video RTP? (%s:%d)\n", session->media.remote_ip, session->media.remote_video_rtp_port);
			JANUS_LOG(LOG_ERR, "  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtcp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->media.remote_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->media.remote_ip);	/* ...resolve name */
			if(!host) {
				JANUS_LOG(LOG_ERR, "Couldn't get host (%s)\n", session->media.remote_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_video_rtcp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.video_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_LOG(LOG_ERR, "Couldn't connect video RTCP? (%s:%d)\n", session->media.remote_ip, session->media.remote_video_rtcp_port);
			JANUS_LOG(LOG_ERR, "  -- %d (%s)\n", errno, strerror(errno));
		}
	}

	if(!session->callee) {
		JANUS_LOG(LOG_VERB, "Leaving thread, no callee...\n");
		return NULL; 
	}
	/* Loop */
	socklen_t addrlen;
	struct sockaddr_in remote;
	int resfd = 0, bytes = 0;
	struct timeval timeout;
	fd_set readfds;
	FD_ZERO(&readfds);
	char buffer[1500];
	memset(buffer, 0, 1500);
	while(session != NULL && !session->destroy &&
			session->status > janus_sip_status_registered &&
			session->status < janus_sip_status_closing) {	/* FIXME We need a per-call watchdog as well */
		/* Wait for some data */
		if(session->media.audio_rtp_fd > 0)
			FD_SET(session->media.audio_rtp_fd, &readfds);
		if(session->media.audio_rtcp_fd > 0)
			FD_SET(session->media.audio_rtcp_fd, &readfds);
		if(session->media.video_rtp_fd > 0)
			FD_SET(session->media.video_rtp_fd, &readfds);
		if(session->media.video_rtcp_fd > 0)
			FD_SET(session->media.video_rtcp_fd, &readfds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		resfd = select(maxfd+1, &readfds, NULL, NULL, &timeout);
		if(resfd < 0)
			break;
		if(session == NULL || session->destroy ||
				session->status <= janus_sip_status_registered ||
				session->status >= janus_sip_status_closing)
			break;
		if(session->media.audio_rtp_fd && FD_ISSET(session->media.audio_rtp_fd, &readfds)) {
			/* Got something audio (RTP) */
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
			/* Relay to browser */
			gateway->relay_rtp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.audio_rtcp_fd && FD_ISSET(session->media.audio_rtcp_fd, &readfds)) {
			/* Got something audio (RTCP) */
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.audio_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_LOG(LOG_VERB, "************************\nGot %d bytes on the audio RTCP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_LOG(LOG_VERB, " ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtcp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.video_rtp_fd && FD_ISSET(session->media.video_rtp_fd, &readfds)) {
			/* Got something video (RTP) */
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
		if(session->media.video_rtcp_fd && FD_ISSET(session->media.video_rtcp_fd, &readfds)) {
			/* Got something video (RTCP) */
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
	JANUS_LOG(LOG_VERB, "Leaving relay thread\n");
	return NULL;
}

/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data) {
	janus_sip_session *session = (janus_sip_session *)user_data;
	if(session == NULL || session->account.username == NULL || session->stack == NULL)
		return NULL;
	JANUS_LOG(LOG_VERB, "Joining sofia loop thread (%s)...\n", session->account.username);
	session->stack->s_root = su_root_create(session->stack);
	char tag_url[100];
	memset(tag_url, 0, 100);
	sprintf(tag_url, "sip:%s@0.0.0.0:0", session->account.username);
	JANUS_LOG(LOG_VERB, "Setting up sofia stack (%s)\n", tag_url);
	session->stack->s_nua = nua_create(session->stack->s_root,
				janus_sip_sofia_callback,
				session,
				SIPTAG_FROM_STR(g_strdup(tag_url)),
				NUTAG_URL("sip:0.0.0.0:*;transport=udp"),
				//~ NUTAG_OUTBOUND("outbound natify use-rport"),	/* To use the same port used in Contact */
				TAG_NULL());
	nua_set_params(session->stack->s_nua, TAG_NULL());
	su_root_run(session->stack->s_root);
	/* When we get here, we're done */
	nua_destroy(session->stack->s_nua);
	su_root_destroy(session->stack->s_root);
	session->stack->s_root = NULL;
	su_home_deinit(session->stack->s_home);
	su_deinit();
	//~ stop = 1;
	JANUS_LOG(LOG_VERB, "Leaving sofia loop thread...\n");
	return NULL;
}
