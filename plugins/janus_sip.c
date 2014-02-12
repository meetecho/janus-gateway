/*! \file   janus_sip.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
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

#include "../config.h"


/* Plugin information */
#define JANUS_SIP_VERSION			1
#define JANUS_SIP_VERSION_STRING	"0.0.1"
#define JANUS_SIP_DESCRIPTION		"This is a simple SIP plugin for Janus, allowing WebRTC peers to register at a SIP server and call SIP user agents through the gateway."
#define JANUS_SIP_NAME				"JANUS SIP plugin"
#define JANUS_SIP_PACKAGE			"janus.plugin.sip"

/* Plugin methods */
janus_plugin *create(void);
int janus_sip_init(janus_callbacks *callback, const char *config_path);
void janus_sip_destroy(void);
int janus_sip_get_version(void);
const char *janus_sip_get_version_string(void);
const char *janus_sip_get_description(void);
const char *janus_sip_get_name(void);
const char *janus_sip_get_package(void);
void janus_sip_create_session(janus_pluginession *handle, int *error);
void janus_sip_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_sip_setup_media(janus_pluginession *handle);
void janus_sip_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len);
void janus_sip_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len);
void janus_sip_hangup_media(janus_pluginession *handle);
void janus_sip_destroy_session(janus_pluginession *handle, int *error);

/* Plugin setup */
static janus_plugin janus_sip_plugin =
	{
		.init = janus_sip_init,
		.destroy = janus_sip_destroy,

		.get_version = janus_sip_get_version,
		.get_version_string = janus_sip_get_version_string,
		.get_description = janus_sip_get_description,
		.get_name = janus_sip_get_name,
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
	JANUS_PRINT("%s created!\n", JANUS_SIP_NAME);
	return &janus_sip_plugin;
}


/* Useful stuff */
static int initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static char *local_ip = NULL;

static GThread *handler_thread;
static void *janus_sip_handler(void *data);
char *string_replace(char *message, char *old, char *new, int *modified);

typedef struct janus_sip_message {
	janus_pluginession *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_sip_message;
GQueue *messages;

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
	char *username;
	char *secret;
	int sip_port;
	char *proxy_ip;
	int proxy_port;
} janus_sip_account;

typedef struct janus_sip_media {
	int ready:1;
	int has_audio:1;
	int audio_rtp_fd, audio_rtcp_fd;
	int local_audio_rtp_port, remote_audio_rtp_port;
	int local_audio_rtcp_port, remote_audio_rtcp_port;
	int has_video:1;
	int video_rtp_fd, video_rtcp_fd;
	int local_video_rtp_port, remote_video_rtp_port;
	int local_video_rtcp_port, remote_video_rtcp_port;
} janus_sip_media;

typedef struct janus_sip_session {
	janus_pluginession *handle;
	ssip_t *stack;
	janus_sip_account account;
	janus_sip_status status;
	janus_sip_media media;
	char *callee;
	gboolean destroy;
} janus_sip_session;
GHashTable *sessions;


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
	JANUS_PRINT("Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	/* What is the local public IP? */
	JANUS_PRINT("Available interfaces:\n");
	struct ifaddrs *myaddrs, *ifa;
	int status = getifaddrs(&myaddrs);
	if (status == 0) {
		for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
			if(ifa->ifa_addr == NULL) {
				continue;
			}
			if((ifa->ifa_flags & IFF_UP) == 0) {
				continue;
			}
			if(ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *ip = (struct sockaddr_in *)(ifa->ifa_addr);
				char buf[16];
				if(inet_ntop(ifa->ifa_addr->sa_family, (void *)&(ip->sin_addr), buf, sizeof(buf)) == NULL) {
					JANUS_PRINT("\t%s:\tinet_ntop failed!\n", ifa->ifa_name);
				} else {
					JANUS_PRINT("\t%s:\t%s\n", ifa->ifa_name, buf);
					if(strcasecmp(buf, "127.0.0.1"))	/* FIXME Check private IP addresses as well */
						local_ip = strdup(buf);
				}
			}
			/* TODO IPv6! */
		}
		freeifaddrs(myaddrs);
	}
	if(local_ip == NULL) {
		JANUS_PRINT("Couldn't find any address! using 127.0.0.1 as local IP... (which is NOT going to work out of your machine)\n");
		local_ip = "127.0.0.1";
	} else {
		JANUS_PRINT("Using %s as local IP...\n", local_ip);
	}

	/* Setup sofia */
	su_init();

	sessions = g_hash_table_new(NULL, NULL);
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
		JANUS_DEBUG("Got error %d (%s) trying to launch thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_PRINT("%s initialized!\n", JANUS_SIP_NAME);
	return 0;
}

void janus_sip_destroy() {
	if(!initialized)
		return;
	stopping = 1;
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
	}
	handler_thread = NULL;
	/* TODO Actually clean up and remove ongoing sessions */
	g_hash_table_destroy(sessions);
	g_queue_free(messages);
	sessions = NULL;
	initialized = 0;
	stopping = 0;
	JANUS_PRINT("%s destroyed!\n", JANUS_SIP_NAME);
}

int janus_sip_get_version() {
	return JANUS_SIP_VERSION;
}

const char *janus_sip_get_version_string() {
	return JANUS_SIP_VERSION_STRING;
}

const char *janus_sip_get_description() {
	return JANUS_SIP_DESCRIPTION;
}

const char *janus_sip_get_name() {
	return JANUS_SIP_NAME;
}

const char *janus_sip_get_package() {
	return JANUS_SIP_PACKAGE;
}

void janus_sip_create_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_sip_session *session = (janus_sip_session *)calloc(1, sizeof(janus_sip_session));
	if(session == NULL) {
		JANUS_DEBUG("Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->account.username = NULL;
	session->account.secret = NULL;
	session->account.sip_port = 0;
	session->account.proxy_ip = NULL;
	session->account.proxy_port = 0;
	session->stack = calloc(1, sizeof(ssip_t));
	if(session->stack == NULL) {
		JANUS_DEBUG("Memory error!\n");
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
	session->media.ready = 0;
	session->media.has_audio = 0;
	session->media.audio_rtp_fd = 0;
	session->media.audio_rtcp_fd= 0;
	session->media.local_audio_rtp_port = 0;
	session->media.remote_audio_rtp_port = 0;
	session->media.local_audio_rtcp_port = 0;
	session->media.remote_audio_rtcp_port = 0;
	session->media.has_video = 0;
	session->media.video_rtp_fd = 0;
	session->media.video_rtcp_fd= 0;
	session->media.local_video_rtp_port = 0;
	session->media.remote_video_rtp_port = 0;
	session->media.local_video_rtcp_port = 0;
	session->media.remote_video_rtcp_port = 0;
	su_home_init(session->stack->s_home);
	handle->plugin_handle = session;

	return;
}

void janus_sip_destroy_session(janus_pluginession *handle, int *error) {
	if(stopping || !initialized) {
		*error = -1;
		return;
	}	
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle; 
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		*error = -2;
		return;
	}
	if(session->destroy) {
		JANUS_PRINT("Session already destroyed...\n");
		g_free(session);
		return;
	}
	g_hash_table_remove(sessions, handle);
	janus_sip_hangup_media(handle);
	JANUS_PRINT("Destroying SIP session (%s)...\n", session->account.username ? session->account.username : "unregistered user");
	/* Shutdown the NUA */
	nua_shutdown(session->stack->s_nua);
	session->destroy = TRUE;
	g_free(session);
	return;
}

void janus_sip_handle_message(janus_pluginession *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(stopping || !initialized)
		return;
	JANUS_PRINT("%s\n", message);
	janus_sip_message *msg = calloc(1, sizeof(janus_sip_message));
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

void janus_sip_setup_media(janus_pluginession *handle) {
	JANUS_DEBUG("WebRTC media is now available\n");
	if(stopping || !initialized)
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* TODO Only relay RTP/RTCP when we get this event */
}

void janus_sip_incoming_rtp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			return;
		}
		/* Forward to our SIP peer */
		if(video) {
			if(session->media.has_video && session->media.video_rtp_fd) {
				send(session->media.video_rtp_fd, buf, len, 0);
			}
		} else {
			if(session->media.has_audio && session->media.audio_rtp_fd) {
				send(session->media.audio_rtp_fd, buf, len, 0);
			}
		}
	}
}

void janus_sip_incoming_rtcp(janus_pluginession *handle, int video, char *buf, int len) {
	if(stopping || !initialized)
		return;
	if(gateway) {
		janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_DEBUG("No session associated with this handle...\n");
			return;
		}
		/* Forward to our SIP peer */
		/* TODO Fix SSRCs as the gateway does */
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

void janus_sip_hangup_media(janus_pluginession *handle) {
	JANUS_PRINT("No WebRTC media anymore\n");
	if(stopping || !initialized)
		return;
	janus_sip_session *session = (janus_sip_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_DEBUG("No session associated with this handle...\n");
		return;
	}
	if(session->destroy)
		return;
	/* FIXME Simulate a "hangup" coming from the browser */
	janus_sip_message *msg = calloc(1, sizeof(janus_sip_message));
	if(msg == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return;
	}
	msg->handle = handle;
	msg->message = "{\"request\":\"hangup\"}";
	msg->transaction = NULL;
	msg->sdp_type = NULL;
	msg->sdp = NULL;
	g_queue_push_tail(messages, msg);
}

/* Thread to handle incoming messages */
static void *janus_sip_handler(void *data) {
	JANUS_DEBUG("Joining thread\n");
	janus_sip_message *msg = NULL;
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
		janus_sip_session *session = (janus_sip_session *)msg->handle->plugin_handle;
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
		json_t *request = json_object_get(root, "request");
		if(!request || !json_is_string(request)) {
			JANUS_DEBUG("JSON error: invalid element (request)\n");
			sprintf(error_cause, "JSON error: invalid element (request)");
			goto error;
		}
		const char *request_text = json_string_value(request);
		json_t *result = NULL;
		char *sdp_type = NULL, *sdp = NULL;
		if(!strcasecmp(request_text, "register")) {
			/* Send a REGISTER */
			if(session->status > janus_sip_status_unregistered) {
				JANUS_DEBUG("Already registered (%s)\n", session->account.username);
				sprintf(error_cause, "Already registered (%s)", session->account.username);
				goto error;
			}
			json_t *username = json_object_get(root, "username");
			if(!username || !json_is_string(username)) {
				JANUS_DEBUG("JSON error: missing element (username)\n");
				sprintf(error_cause, "JSON error: missing element (username)");
				goto error;
			}
			const char *username_text = json_string_value(username);
			json_t *secret = json_object_get(root, "secret");
			if(!secret || !json_is_string(secret)) {
				JANUS_DEBUG("JSON error: missing element (secret)\n");
				sprintf(error_cause, "JSON error: missing element (secret)");
				goto error;
			}
			const char *secret_text = json_string_value(secret);
			json_t *proxyip = json_object_get(root, "proxy_ip");
			if(!proxyip || !json_is_string(proxyip)) {
				JANUS_DEBUG("JSON error: missing element (proxy_ip)\n");
				sprintf(error_cause, "JSON error: missing element (proxy_ip)");
				goto error;
			}
			const char *proxyip_text = json_string_value(proxyip);
			json_t *proxyport = json_object_get(root, "proxy_port");
			if(!proxyport || !json_is_integer(proxyport)) {
				JANUS_DEBUG("JSON error: missing element (proxy_port)\n");
				sprintf(error_cause, "JSON error: missing element (proxy_port)");
				goto error;
			}
			int proxyport_value = json_integer_value(proxyport);
			/* Got the values, try registering now */
			JANUS_PRINT("Registering user %s (secret %s) @ %s:%d\n",
				username_text, secret_text, proxyip_text, proxyport_value);
			if(session->account.username != NULL)
				g_free(session->account.username);
			if(session->account.secret != NULL)
				g_free(session->account.secret);
			if(session->account.proxy_ip != NULL)
				g_free(session->account.proxy_ip);
			session->account.username = g_strdup(username_text);
			session->account.secret = g_strdup(secret_text);
			session->account.proxy_ip = g_strdup(proxyip_text);
			if(session->account.username == NULL || session->account.secret == NULL || session->account.proxy_ip == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				goto error;
			}
			session->account.proxy_port = proxyport_value;
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
					JANUS_PRINT("Two seconds passed and still no NUA, problems with the thread?\n");
					sprintf(error_cause, "Two seconds passed and still no NUA, problems with the thread?");
					goto error;
				}
			}
			if(session->stack->s_nh_r == NULL)
				session->stack->s_nh_r = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_r == NULL)
				JANUS_PRINT("NUA Handle for REGISTER still null??\n");
			char regto[100];
			memset(regto, 0, 100);
			sprintf(regto, "sip:%s@%s:%d", session->account.username, session->account.proxy_ip, session->account.proxy_port);
			char proxy[100];
			memset(proxy, 0, 100);
			sprintf(proxy, "sip:%s:%d", session->account.proxy_ip, session->account.proxy_port);
			JANUS_PRINT("%s --> %s\n", regto, proxy);
			nua_register(session->stack->s_nh_r,
				NUTAG_M_DISPLAY(session->account.username),
				NUTAG_M_USERNAME(session->account.username),
				SIPTAG_TO_STR(regto),
				NUTAG_REGISTRAR(proxy),
				TAG_END());
			result = json_object();
			json_object_set_new(result, "event", json_string("registering"));
		} else if(!strcasecmp(request_text, "call")) {
			/* Call another peer */
			if(session->status >= janus_sip_status_inviting) {
				JANUS_DEBUG("Wrong state (already in a call?)\n");
				sprintf(error_cause, "Wrong state (already in a call?)");
				goto error;
			}
			json_t *extension = json_object_get(root, "extension");
			if(!extension || !json_is_string(extension)) {
				JANUS_DEBUG("JSON error: missing element (extension)\n");
				sprintf(error_cause, "JSON error: missing element (extension)");
				goto error;
			}
			const char *extension_text = json_string_value(extension);
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_DEBUG("Missing SDP\n");
				sprintf(error_cause, "Missing SDP");
				goto error;
			}
			JANUS_PRINT("%s is calling %s\n", session->account.username, extension_text);
			JANUS_PRINT("This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg->sdp, "m=audio")) {
				JANUS_PRINT("Going to negotiate audio...\n");
				session->media.has_audio = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg->sdp, "m=video")) {
				JANUS_PRINT("Going to negotiate video...\n");
				session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_PRINT("Could not allocate RTP/RTCP ports\n");
				sprintf(error_cause, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			if(sdp == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				goto error;
			}
			int modified = 0;
			char *temp = string_replace(sdp, "RTP/SAVPF", "RTP/AVP", &modified);
			if(modified)
				g_free(sdp);
			sdp = temp;
			temp = string_replace(sdp, "1.1.1.1", local_ip, &modified);
			if(modified)
				g_free(sdp);
			sdp = temp;
			if(session->media.has_audio) {
				JANUS_PRINT("Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				sprintf(mline, "m=audio %d", session->media.local_audio_rtp_port);
				temp = string_replace(sdp, "m=audio 1", mline, &modified);
				if(modified)
					g_free(sdp);
				sdp = temp;
			}
			if(session->media.has_video) {
				JANUS_PRINT("Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				sprintf(mline, "m=video %d", session->media.local_video_rtp_port);
				temp = string_replace(sdp, "m=video 1", mline, &modified);
				if(modified)
					g_free(sdp);
				sdp = temp;
			}
			/* Send INVITE */
			session->status = janus_sip_status_inviting;
			char callee[100];
			memset(callee, 0, 100);
			sprintf(callee, "sip:%s@%s:%d", extension_text, session->account.proxy_ip, session->account.proxy_port);
			if(session->stack->s_nh_i == NULL)
				session->stack->s_nh_i = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_i == NULL)
				JANUS_PRINT("NUA Handle for INVITE still null??\n");
			nua_invite(session->stack->s_nh_i,
				SIPTAG_TO_STR(callee),
				SOATAG_USER_SDP_STR(sdp),
				TAG_END());
			session->callee = g_strdup(callee);
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("calling"));
		} else if(!strcasecmp(request_text, "accept")) {
			if(session->status != janus_sip_status_invited) {
				JANUS_DEBUG("Wrong state (not invited? state=%d)\n", session->status);
				sprintf(error_cause, "Wrong state (not invited?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_DEBUG("Wrong state (no caller?)\n");
				sprintf(error_cause, "Wrong state (no caller?)");
				goto error;
			}
			/* Any SDP to handle? if not, something's wrong */
			if(!msg->sdp) {
				JANUS_DEBUG("Missing SDP\n");
				sprintf(error_cause, "Missing SDP");
				goto error;
			}
			/* Accept a call from another peer */
			JANUS_PRINT("We're accepting the call from %s\n", session->callee);
			JANUS_PRINT("This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			/* Allocate RTP ports and merge them with the anonymized SDP */
			if(strstr(msg->sdp, "m=audio")) {
				JANUS_PRINT("Going to negotiate audio...\n");
				session->media.has_audio = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(strstr(msg->sdp, "m=video")) {
				JANUS_PRINT("Going to negotiate video...\n");
				session->media.has_video = 1;	/* FIXME Maybe we need a better way to signal this */
			}
			if(janus_sip_allocate_local_ports(session) < 0) {
				JANUS_PRINT("Could not allocate RTP/RTCP ports\n");
				sprintf(error_cause, "Could not allocate RTP/RTCP ports");
				goto error;
			}
			char *sdp = g_strdup(msg->sdp);
			if(sdp == NULL) {
				JANUS_DEBUG("Memory error!\n");
				sprintf(error_cause, "Memory error");
				goto error;
			}
			int modified = 0;
			char *temp = string_replace(sdp, "RTP/SAVPF", "RTP/AVP", &modified);
			if(modified)
				g_free(sdp);
			sdp = temp;
			temp = string_replace(sdp, "1.1.1.1", local_ip, &modified);
			if(modified)
				g_free(sdp);
			sdp = temp;
			if(session->media.has_audio) {
				JANUS_PRINT("Setting local audio port: %d\n", session->media.local_audio_rtp_port);
				char mline[20];
				sprintf(mline, "m=audio %d", session->media.local_audio_rtp_port);
				temp = string_replace(sdp, "m=audio 1", mline, &modified);
				if(modified)
					g_free(sdp);
				sdp = temp;
			}
			if(session->media.has_video) {
				JANUS_PRINT("Setting local video port: %d\n", session->media.local_video_rtp_port);
				char mline[20];
				sprintf(mline, "m=video %d", session->media.local_video_rtp_port);
				temp = string_replace(sdp, "m=video 1", mline, &modified);
				if(modified)
					g_free(sdp);
				sdp = temp;
			}
			/* Send 200 OK */
			session->status = janus_sip_status_incall;
			//~ if(session->stack->s_nh_i == NULL)
				//~ session->stack->s_nh_i = nua_handle(session->stack->s_nua, session, TAG_END());
			if(session->stack->s_nh_i == NULL)
				JANUS_PRINT("NUA Handle for 200 OK still null??\n");
			nua_respond(session->stack->s_nh_i,
				200, sip_status_phrase(200),
				SIPTAG_TO_STR(session->callee),
				SOATAG_USER_SDP_STR(sdp),
				TAG_END());
			/* Send an ack back */
			result = json_object();
			json_object_set_new(result, "event", json_string("accepted"));
		} else if(!strcasecmp(request_text, "hangup")) {
			/* Hangup an ongoing call or reject an incoming one */
			if(session->status < janus_sip_status_inviting || session->status > janus_sip_status_incall) {
				JANUS_DEBUG("Wrong state (not in a call? state=%d)\n", session->status);
				sprintf(error_cause, "Wrong state (not in a call?)");
				goto error;
			}
			if(session->callee == NULL) {
				JANUS_DEBUG("Wrong state (no callee?)\n");
				sprintf(error_cause, "Wrong state (no callee?)");
				goto error;
			}
			session->status = janus_sip_status_closing;
			nua_bye(session->stack->s_nh_i,
				SIPTAG_TO_STR(session->callee),
				TAG_END());
			g_free(session->callee);
			session->callee = NULL;
			/* Notify the operation */
			result = json_object();
			json_object_set_new(result, "event", json_string("hangingup"));
		} else {
			JANUS_DEBUG("Unknown request (%s)\n", request_text);
			sprintf(error_cause, "Unknown request (%s)", request_text);
			goto error;
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set(event, "sip", json_string("event"));
		if(result != NULL)
			json_object_set(event, "result", result);
		char *event_text = json_dumps(event, JSON_INDENT(3));
		json_decref(event);
		if(result != NULL)
			json_decref(result);
		JANUS_PRINT("Pushing event: %s\n", event_text);
		JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event_text, sdp_type, sdp));
		if(sdp)
			g_free(sdp);
		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set(event, "sip", json_string("event"));
			json_object_set(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3));
			json_decref(event);
			JANUS_PRINT("Pushing event: %s\n", event_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(msg->handle, &janus_sip_plugin, msg->transaction, event_text, NULL, NULL));
		}
	}
	JANUS_DEBUG("Leaving thread\n");
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
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_error:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_fork:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_media_error:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_subscription:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_state:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_terminated:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP requests */
		case nua_i_ack:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_outbound:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_i_bye: {
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* Call ended, notify the browser */
			session->status = janus_sip_status_registered;	/* FIXME What about a 'closing' state? */
			char reason[100];
			memset(reason, 0, 100);
			sprintf(reason, "%d %s", status, phrase);
			json_t *call = json_object();
			json_object_set(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string(reason));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3));
			json_decref(call);
			JANUS_PRINT("Pushing event: %s\n", call_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL));
			break;
		}
		case nua_i_cancel: {
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Check state? */
			session->status = janus_sip_status_closing;
			/* Notify the browser */
			json_t *call = json_object();
			json_object_set(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string("Remote cancel"));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3));
			json_decref(call);
			JANUS_PRINT("Pushing event: %s\n", call_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL));
			break;
		}
		case nua_i_chat:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_info:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_invite: {
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if (!sdp_session(parser)) {
				JANUS_PRINT("\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			if(session->status >= janus_sip_status_inviting) {
				/* Busy */
				JANUS_PRINT("\tAlready in a call (busy)\n");
				nua_respond(nh, 486, sip_status_phrase(486), TAG_END());
				break;
			}
			const char *caller = sip->sip_from->a_url->url_user;
			session->callee = g_strdup(url_as_string(session->stack->s_home, sip->sip_from->a_url));
			session->status = janus_sip_status_invited;
			/* Send SDP to the browser */
			json_t *call = json_object();
			json_object_set(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("incomingcall"));
			json_object_set_new(calling, "username", json_string(caller));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3));
			json_decref(call);
			JANUS_PRINT("Pushing event to peer: %s\n", call_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, "offer", sip->sip_payload->pl_data));
			/* Send a Ringing back */
			nua_respond(nh, 180, sip_status_phrase(180), TAG_END());
			session->stack->s_nh_i = nh;
			break;
		}
		case nua_i_message:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_method:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_notify:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_options:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_prack:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_publish:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_refer:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_register:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_subscribe:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
		case nua_i_update:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* FIXME Should we handle this message? for now we reply with a 405 Method Not Implemented */
			nua_respond(nh, 405, sip_status_phrase(405), TAG_END());
			break;
	/* Responses */
		case nua_r_get_params:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_set_params:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_notifier:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_shutdown:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			if (status < 200 && stopping < 3) {
				/* shutdown in progress -> return */
				break;
			}
			/* end the event loop. su_root_run() will return */
			//~ su_root_break(magic->root);
			su_root_break(ssip->s_root);
			break;
		case nua_r_terminate:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
	/* SIP responses */
		case nua_r_bye:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			/* Call ended, notify the browser */
			session->status = janus_sip_status_registered;
			char reason[100];
			memset(reason, 0, 100);
			sprintf(reason, "%d %s", status, phrase);
			json_t *call = json_object();
			json_object_set(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("hangup"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(calling, "reason", json_string(reason));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3));
			json_decref(call);
			JANUS_PRINT("Pushing event: %s\n", call_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL));
			break;
		case nua_r_cancel:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_info:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_invite: {
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
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
				sprintf(auth, "%s:%s:%s:%s", scheme, realm, session->account.username, session->account.secret);
				JANUS_PRINT("\t%s\n", auth);
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
				json_object_set(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("hangup"));
				json_object_set_new(calling, "username", json_string(session->callee));
				json_object_set_new(calling, "reason", json_string(reason));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3));
				json_decref(call);
				JANUS_PRINT("Pushing event: %s\n", call_text);
				JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL));
				break;
			}
			ssip_t *ssip = session->stack;
			sdp_parser_t *parser = sdp_parse(ssip->s_home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
			if (!sdp_session(parser)) {
				JANUS_PRINT("\tError parsing SDP!\n");
				nua_respond(nh, 488, sip_status_phrase(488), TAG_END());
				break;
			}
			JANUS_PRINT("Peer accepted our call:\n%s", sip->sip_payload->pl_data);
			session->status = janus_sip_status_incall;
			char *fixed_sdp = g_strdup(sip->sip_payload->pl_data);
			if(fixed_sdp == NULL) {
				JANUS_DEBUG("Memory error!\n");
				nua_respond(nh, 500, sip_status_phrase(500), TAG_END());
				break;
			}
			sdp_session_t *sdp = sdp_session(parser);
			janus_sip_sdp_process(session, sdp);
			session->media.ready = 1;	/* FIXME Maybe we need a better way to signal this */
			GError *error = NULL;
			g_thread_try_new("janus rtp handler", janus_sip_relay_thread, session, &error);
			if(error) {
				JANUS_PRINT("Error starting RTP/RTCP thread?\n");
			}
			/* Send SDP to the browser */
			session->status = janus_sip_status_incall;
			json_t *call = json_object();
			json_object_set(call, "sip", json_string("event"));
			json_t *calling = json_object();
			json_object_set_new(calling, "event", json_string("accepted"));
			json_object_set_new(calling, "username", json_string(session->callee));
			json_object_set_new(call, "result", calling);
			char *call_text = json_dumps(call, JSON_INDENT(3));
			json_decref(call);
			JANUS_PRINT("Pushing event to peer: %s\n", call_text);
			JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, "answer", fixed_sdp));
			break;
		}
		case nua_r_message:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_notify:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_options:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_prack:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_publish:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_refer:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_register: {
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			if(status == 200) {
				if(session->status < janus_sip_status_registered)
					session->status = janus_sip_status_registered;
				JANUS_PRINT("Successfully registered\n");
				/* Notify the browser */
				json_t *call = json_object();
				json_object_set(call, "sip", json_string("event"));
				json_t *calling = json_object();
				json_object_set_new(calling, "event", json_string("registered"));
				json_object_set_new(calling, "username", json_string(session->account.username));
				json_object_set_new(call, "result", calling);
				char *call_text = json_dumps(call, JSON_INDENT(3));
				json_decref(call);
				JANUS_PRINT("Pushing event: %s\n", call_text);
				JANUS_PRINT("  >> %d\n", gateway->push_event(session->handle, &janus_sip_plugin, NULL, call_text, NULL, NULL));
			} else if(status == 401) {
				/* Get scheme/realm from 401 error */
				sip_www_authenticate_t const* www_auth = sip->sip_www_authenticate;
				char const* scheme = www_auth->au_scheme;
				const char* realm = msg_params_find(www_auth->au_params, "realm=");
				char auth[100];
				memset(auth, 0, 100);
				sprintf(auth, "%s:%s:%s:%s", scheme, realm, session->account.username, session->account.secret);
				JANUS_PRINT("\t%s\n", auth);
				/* Authenticate */
				nua_authenticate(nh,
					NUTAG_AUTH(auth),
					TAG_END());
			} else {
				/* Authentication failed? */
				session->status = janus_sip_status_failed;
				/* TODO Tell the browser... */
			}
			break;
		}
		case nua_r_subscribe:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unpublish:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unregister:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_unsubscribe:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		case nua_r_update:
			JANUS_PRINT("[%s]: %d %s\n", nua_event_name(event), status, phrase ? phrase : "??");
			break;
		default:
			/* unknown event -> print out error message */
			JANUS_PRINT("Unknown event %d (%s)\n", event, nua_event_name(event));
			break;
	}
}

void janus_sip_sdp_process(janus_sip_session *session, sdp_session_t *sdp) {
	if(!session || !sdp)
		return;
	JANUS_PRINT("  >> Media lines:\n");
	sdp_media_t *m = sdp->sdp_media;
	while(m) {
		if(m->m_type == sdp_media_audio) {
			JANUS_PRINT("       Audio: %lu\n", m->m_port);
			if(m->m_port) {
				session->media.has_audio = 1;
				session->media.remote_audio_rtp_port = m->m_port;
				session->media.remote_audio_rtcp_port = m->m_port+1;	/* FIXME We're assuming RTCP is on the next port */
			}
		} else if(m->m_type == sdp_media_video) {
			JANUS_PRINT("       Video: %lu\n", m->m_port);
			if(m->m_port) {
				session->media.has_video = 1;
				session->media.remote_video_rtp_port = m->m_port;
				session->media.remote_video_rtcp_port = m->m_port+1;	/* FIXME We're assuming RTCP is on the next port */
			}
		} else {
			JANUS_PRINT("       Unsupported media line (not audio/video)\n");
			m = m->m_next;
			continue;
		}
		JANUS_PRINT("       Media RTP maps:\n");
		sdp_rtpmap_t *r = m->m_rtpmaps;
		while(r) {
			JANUS_PRINT("         [%u] %s\n", r->rm_pt, r->rm_encoding);
			r = r->rm_next;
		}
		JANUS_PRINT("       Media attributes:\n");
		sdp_attribute_t *a = m->m_attributes;
		while(a) {
			if(a->a_name) {
				if(!strcasecmp(a->a_name, "rtpmap")) {
					JANUS_PRINT("         RTP Map:     %s\n", a->a_value);
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
		JANUS_PRINT("Invalid session\n");
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
		JANUS_PRINT("Allocating audio ports:\n");
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
				JANUS_PRINT("Bind failed for audio RTP (port %d), trying a different one...\n", rtp_port);
				attempts--;
				continue;
			}
			JANUS_PRINT("Audio RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			audio_rtcp_address.sin_family = AF_INET;
			audio_rtcp_address.sin_port = htons(rtcp_port);
			audio_rtcp_address.sin_addr.s_addr = INADDR_ANY;
			if(bind(session->media.audio_rtcp_fd, (struct sockaddr *)(&audio_rtcp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_PRINT("Bind failed for audio RTCP (port %d), trying a different one...\n", rtcp_port);
				/* RTP socket is not valid anymore, reset it */
				close(session->media.audio_rtp_fd);
				session->media.audio_rtp_fd = 0;
				attempts--;
				continue;
			}
			JANUS_PRINT("Audio RTCP listener bound to port %d\n", rtcp_port);
			session->media.local_audio_rtp_port = rtp_port;
			session->media.local_audio_rtcp_port = rtcp_port;
		}
	}
	if(session->media.has_video) {
		JANUS_PRINT("Allocating video ports:\n");
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
				JANUS_PRINT("Bind failed for video RTP (port %d), trying a different one...\n", rtp_port);
				attempts--;
				continue;
			}
			JANUS_PRINT("Audio RTP listener bound to port %d\n", rtp_port);
			int rtcp_port = rtp_port+1;
			video_rtcp_address.sin_family = AF_INET;
			video_rtcp_address.sin_port = htons(rtcp_port);
			video_rtcp_address.sin_addr.s_addr = INADDR_ANY;
			if(bind(session->media.video_rtcp_fd, (struct sockaddr *)(&video_rtcp_address), sizeof(struct sockaddr)) < 0) {
				JANUS_PRINT("Bind failed for video RTCP (port %d), trying a different one...\n", rtcp_port);
				/* RTP socket is not valid anymore, reset it */
				close(session->media.video_rtp_fd);
				session->media.video_rtp_fd = 0;
				attempts--;
				continue;
			}
			JANUS_PRINT("Audio RTCP listener bound to port %d\n", rtcp_port);
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
	JANUS_PRINT("Starting relay thread (%s <--> %s)\n", session->account.username, session->callee);
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
		if((inet_aton(session->account.proxy_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->account.proxy_ip);	/* ...resolve name */
			if(!host) {
				JANUS_PRINT("Couldn't get host (%s)\n", session->account.proxy_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_audio_rtp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.audio_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_PRINT("Couldn't connect audio RTP? (%s:%d)\n", session->account.proxy_ip, session->media.remote_audio_rtp_port);
			JANUS_PRINT("  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_audio_rtcp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->account.proxy_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->account.proxy_ip);	/* ...resolve name */
			if(!host) {
				JANUS_PRINT("Couldn't get host (%s)\n", session->account.proxy_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_audio_rtcp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.audio_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_PRINT("Couldn't connect audio RTCP? (%s:%d)\n", session->account.proxy_ip, session->media.remote_audio_rtcp_port);
			JANUS_PRINT("  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->account.proxy_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->account.proxy_ip);	/* ...resolve name */
			if(!host) {
				JANUS_PRINT("Couldn't get host (%s)\n", session->account.proxy_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_video_rtp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.video_rtp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_PRINT("Couldn't connect video RTP? (%s:%d)\n", session->account.proxy_ip, session->media.remote_video_rtp_port);
			JANUS_PRINT("  -- %d (%s)\n", errno, strerror(errno));
		}
	}
	if(session->media.remote_video_rtcp_port) {
		struct sockaddr_in server_addr;
		server_addr.sin_family = AF_INET;
		if((inet_aton(session->account.proxy_ip, &server_addr.sin_addr)) <= 0) {	/* Not a numeric IP... */
			struct hostent *host = gethostbyname(session->account.proxy_ip);	/* ...resolve name */
			if(!host) {
				JANUS_PRINT("Couldn't get host (%s)\n", session->account.proxy_ip);
			} else {
				server_addr.sin_addr = *(struct in_addr *)host->h_addr_list;
			}
		}
		server_addr.sin_port = htons(session->media.remote_video_rtcp_port);
		memset(&(server_addr.sin_zero), '\0', 8);
		if(connect(session->media.video_rtcp_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			JANUS_PRINT("Couldn't connect video RTCP? (%s:%d)\n", session->account.proxy_ip, session->media.remote_video_rtcp_port);
			JANUS_PRINT("  -- %d (%s)\n", errno, strerror(errno));
		}
	}

	if(!session->callee) {
		JANUS_DEBUG("Leaving thread, no callee...\n");
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
	while(session->callee) {	/* FIXME We need a per-call watchdog as well */
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
		if(session->media.audio_rtp_fd && FD_ISSET(session->media.audio_rtp_fd, &readfds)) {
			/* Got something audio (RTP) */
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.audio_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_PRINT("************************\nGot %d bytes on the audio RTP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_PRINT(" ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.audio_rtcp_fd && FD_ISSET(session->media.audio_rtcp_fd, &readfds)) {
			/* Got something audio (RTCP) */
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.audio_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_PRINT("************************\nGot %d bytes on the audio RTCP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_PRINT(" ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtcp(session->handle, 0, buffer, bytes);
			continue;
		}
		if(session->media.video_rtp_fd && FD_ISSET(session->media.video_rtp_fd, &readfds)) {
			/* Got something video (RTP) */
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.video_rtp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_PRINT("************************\nGot %d bytes on the video RTP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_PRINT(" ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtp(session->handle, 1, buffer, bytes);
			continue;
		}
		if(session->media.video_rtcp_fd && FD_ISSET(session->media.video_rtcp_fd, &readfds)) {
			/* Got something video (RTCP) */
			addrlen = sizeof(remote);
			bytes = recvfrom(session->media.video_rtcp_fd, buffer, 1500, 0, (struct sockaddr*)&remote, &addrlen);
			//~ JANUS_PRINT("************************\nGot %d bytes on the video RTCP channel...\n", bytes);
			//~ rtp_header_t *rtp = (rtp_header_t *)buffer;
			//~ JANUS_PRINT(" ... parsed RTP packet (ssrc=%u, pt=%u, seq=%u, ts=%u)...\n",
				//~ ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
			/* Relay to browser */
			gateway->relay_rtcp(session->handle, 1, buffer, bytes);
			continue;
		}
	}
	JANUS_PRINT("Leaving relay thread\n");
	return NULL;
}

/* Sofia Event thread */
gpointer janus_sip_sofia_thread(gpointer user_data) {
	janus_sip_session *session = (janus_sip_session *)user_data;
	if(session == NULL || session->account.username == NULL || session->stack == NULL)
		return NULL;
	JANUS_PRINT("Joining sofia loop thread (%s)...\n", session->account.username);
	session->stack->s_root = su_root_create(session->stack);
	char tag_url[100];
	memset(tag_url, 0, 100);
	sprintf(tag_url, "sip:%s@0.0.0.0:0", session->account.username);
	JANUS_PRINT("Setting up sofia stack (%s)\n", tag_url);
	session->stack->s_nua = nua_create(session->stack->s_root,
				janus_sip_sofia_callback,
				session,
				SIPTAG_FROM_STR(tag_url),
				NUTAG_URL("sip:0.0.0.0:*;transport=udp"),
				//~ NUTAG_OUTBOUND("outbound natify use-rport"),	/* To use the same port used in Contact */
				//~ NUTAG_URL(tag_url),
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
	JANUS_PRINT("Leaving sofia loop thread...\n");
	return NULL;
}

/* Easy way to replace multiple occurrences of a string with another: ALWAYS creates a NEW string */
char *string_replace(char *message, char *old, char *new, int *modified)
{
	if(!message || !old || !new || !modified)
		return NULL;
	*modified = 0;
	if(!strstr(message, old)) {	/* Nothing to be done (old is not there) */
		return message;
	}
	if(!strcmp(old, new)) {	/* Nothing to be done (old=new) */
		return message;
	}
	if(strlen(old) == strlen(new)) {	/* Just overwrite */
		char *outgoing = message;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		int i = 0;
		while(pos) {
			i++;
			memcpy(pos, new, strlen(new));
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		return outgoing;
	} else {	/* We need to resize */
		*modified = 1;
		char *outgoing = strdup(message);
		if(outgoing == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		int diff = strlen(new) - strlen(old);
		/* Count occurrences */
		int counter = 0;
		char *pos = strstr(outgoing, old), *tmp = NULL;
		while(pos) {
			counter++;
			pos += strlen(old);
			tmp = strstr(pos, old);
			pos = tmp;
		}
		uint16_t oldlen = strlen(outgoing)+1, newlen = oldlen + diff*counter;
		*modified = diff*counter;
		if(diff > 0) {	/* Resize now */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		/* Replace string */
		pos = strstr(outgoing, old);
		while(pos) {
			if(diff > 0) {	/* Move to the right (new is larger than old) */
				uint16_t len = strlen(pos)+1;
				memmove(pos + diff, pos, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(new);
				tmp = strstr(pos, old);
			} else {	/* Move to the left (new is smaller than old) */
				uint16_t len = strlen(pos - diff)+1;
				memmove(pos, pos - diff, len);
				memcpy(pos, new, strlen(new));
				pos += strlen(old);
				tmp = strstr(pos, old);
			}
			pos = tmp;
		}
		if(diff < 0) {	/* We skipped the resize previously (shrinking memory) */
			tmp = realloc(outgoing, newlen);
			if(!tmp)
				return NULL;
			outgoing = tmp;
		}
		outgoing[strlen(outgoing)] = '\0';
		return outgoing;
	}
}
