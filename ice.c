/*! \file    ice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN processing
 * \details  Implementation (based on libnice) of the ICE process. The
 * code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. Incoming RTP and RTCP packets from peers are relayed to the associated
 * plugins by means of the incoming_rtp and incoming_rtcp callbacks. Packets
 * to be sent to peers are relayed by peers invoking the relay_rtp and
 * relay_rtcp gateway callbacks instead. 
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stun/usages/bind.h>
#include <nice/debug.h>

#include "janus.h"
#include "debug.h"
#include "ice.h"
#include "dtls.h"
#include "rtp.h"
#include "rtcp.h"
#include "apierror.h"


/* STUN server/port, if any */
static char *janus_stun_server = NULL;
static uint16_t janus_stun_port = 0;

char *janus_ice_get_stun_server(void) {
	return janus_stun_server;
}
uint16_t janus_ice_get_stun_port(void) {
	return janus_stun_port;
}


/* TURN server/portand credentials, if any */
static char *janus_turn_server = NULL;
static uint16_t janus_turn_port = 0;
static char *janus_turn_user = NULL, *janus_turn_pwd = NULL;
static NiceRelayType janus_turn_type = NICE_RELAY_TYPE_TURN_UDP;

char *janus_ice_get_turn_server(void) {
	return janus_turn_server;
}
uint16_t janus_ice_get_turn_port(void) {
	return janus_turn_port;
}


/* ICE-Lite status */
static gboolean janus_ice_lite_enabled;
gboolean janus_ice_is_ice_lite_enabled(void) {
	return janus_ice_lite_enabled;
}

/* ICE-TCP support (only libnice >= 0.1.8, currently broken) */
static gboolean janus_ice_tcp_enabled;
gboolean janus_ice_is_ice_tcp_enabled(void) {
	return janus_ice_tcp_enabled;
}

/* IPv6 support (still mostly WIP) */
static gboolean janus_ipv6_enabled;
gboolean janus_ice_is_ipv6_enabled(void) {
	return janus_ipv6_enabled;
}


/* libnice debugging */
static gboolean janus_ice_debugging_enabled;
gboolean janus_ice_is_ice_debugging_enabled(void) {
	return janus_ice_debugging_enabled;
}
void janus_ice_debugging_enable(void) {
	JANUS_LOG(LOG_VERB, "Enabling libnice debugging...\n");
	if(g_getenv("NICE_DEBUG") == NULL) {
		JANUS_LOG(LOG_WARN, "No NICE_DEBUG environment variable set, setting maximum debug\n");
		g_setenv("NICE_DEBUG", "all", TRUE);
	}
	if(g_getenv("G_MESSAGES_DEBUG") == NULL) {
		JANUS_LOG(LOG_WARN, "No G_MESSAGES_DEBUG environment variable set, setting maximum debug\n");
		g_setenv("G_MESSAGES_DEBUG", "all", TRUE);
	}
	JANUS_LOG(LOG_VERB, "Debugging NICE_DEBUG=%s G_MESSAGES_DEBUG=%s\n",
		g_getenv("NICE_DEBUG"), g_getenv("G_MESSAGES_DEBUG"));
	janus_ice_debugging_enabled = TRUE;
	nice_debug_enable(strstr(g_getenv("NICE_DEBUG"), "all") || strstr(g_getenv("NICE_DEBUG"), "stun"));
}
void janus_ice_debugging_disable(void) {
	JANUS_LOG(LOG_VERB, "Disabling libnice debugging...\n");
	janus_ice_debugging_enabled = FALSE;
	nice_debug_disable(TRUE);
}


/* Interface/IP ignore list */
GList *janus_ice_ignore_list = NULL;
janus_mutex ignore_list_mutex;
void janus_ice_ignore_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ignore_list_mutex);
	janus_ice_ignore_list = g_list_append(janus_ice_ignore_list, (gpointer)ip);
	janus_mutex_unlock(&ignore_list_mutex);
}

gboolean janus_ice_is_ignored(const char *ip) {
	if(ip == NULL || janus_ice_ignore_list == NULL)
		return false;
	janus_mutex_lock(&ignore_list_mutex);
	GList *temp = janus_ice_ignore_list;
	while(temp) {
		const char *ignored = (const char *)temp->data;
		if(ignored != NULL && strstr(ip, ignored)) {
			janus_mutex_unlock(&ignore_list_mutex);
			return true;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ignore_list_mutex);
	return false;
}


/* RTP/RTCP port range */
uint16_t rtp_range_min = 0;
uint16_t rtp_range_max = 0;


/* Helpers to demultiplex protocols */
gboolean janus_is_dtls(gchar *buf);
gboolean janus_is_dtls(gchar *buf) {
	return ((*buf >= 20) && (*buf <= 64));
}

gboolean janus_is_rtp(gchar *buf);
gboolean janus_is_rtp(gchar *buf) {
	rtp_header *header = (rtp_header *)buf;
	return ((header->type < 64) || (header->type >= 96));
}

gboolean janus_is_rtcp(gchar *buf);
gboolean janus_is_rtcp(gchar *buf) {
	rtp_header *header = (rtp_header *)buf;
	return ((header->type >= 64) && (header->type < 96));
}


/* Maximum values for the NACK queue/retransmissions */
#define DEFAULT_MAX_NACK_QUEUE	300
/* Maximum ignore count after retransmission (100ms) */
#define MAX_NACK_IGNORE			100000

static uint max_nack_queue = DEFAULT_MAX_NACK_QUEUE;
void janus_set_max_nack_queue(uint mnq) {
	max_nack_queue = mnq;
	JANUS_LOG(LOG_VERB, "Setting max NACK queue to %d\n", max_nack_queue);
}
uint janus_get_max_nack_queue(void) {
	return max_nack_queue;
}


/* Watchdog for removing old handles */
static GHashTable *old_handles = NULL;
static GMainContext *handles_watchdog_context = NULL;
GMainLoop *handles_watchdog_loop = NULL;
GThread *handles_watchdog = NULL;
static janus_mutex old_handles_mutex;

static gboolean janus_ice_handles_cleanup(gpointer user_data);
static gboolean janus_ice_handles_check(gpointer user_data);
static gpointer janus_ice_handles_watchdog(gpointer user_data);

static gboolean janus_ice_handles_cleanup(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *) user_data;

	JANUS_LOG(LOG_INFO, "Cleaning up handle %"SCNu64"...\n", handle->handle_id);
	janus_ice_free(handle);

	return G_SOURCE_REMOVE;
}

static gboolean janus_ice_handles_check(gpointer user_data) {
	GMainContext *watchdog_context = (GMainContext *) user_data;
	janus_mutex_lock(&old_handles_mutex);
	if(old_handles && g_hash_table_size(old_handles) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, old_handles);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_ice_handle *handle = (janus_ice_handle *) value;
			if (!handle) {
				continue;
			}
			/* Schedule the ICE handle for deletion */
			g_hash_table_iter_remove(&iter);
			GSource *timeout_source = g_timeout_source_new_seconds(3);
			g_source_set_callback(timeout_source, janus_ice_handles_cleanup, handle, NULL);
			g_source_attach(timeout_source, watchdog_context);
			g_source_unref(timeout_source);
		}
	}
	janus_mutex_unlock(&old_handles_mutex);

	return G_SOURCE_CONTINUE;
}

static gpointer janus_ice_handles_watchdog(gpointer user_data) {
	GMainLoop *loop = (GMainLoop *) user_data;
	GMainContext *watchdog_context = g_main_loop_get_context(loop);
	GSource *timeout_source;

	timeout_source = g_timeout_source_new_seconds(1);
	g_source_set_callback(timeout_source, janus_ice_handles_check, watchdog_context, NULL);
	g_source_attach(timeout_source, watchdog_context);
	g_source_unref(timeout_source);

	JANUS_LOG(LOG_INFO, "ICE handles watchdog started\n");

	g_main_loop_run(loop);

	return NULL;
}


static gint janus_nack_sort(gconstpointer n1, gconstpointer n2);
static gint janus_nack_sort(gconstpointer n1, gconstpointer n2) {
	guint16 nack1, nack2;
	nack1 = GPOINTER_TO_UINT(n1);
	nack2 = GPOINTER_TO_UINT(n2);
	/* TODO Take into account the sequence number rounding when it gets to 2^16 */
	return (nack1 > nack2 ? +1 : nack1 == nack2 ? 0 : -1);
}

void janus_ice_notify_media(janus_ice_handle *handle, gboolean video, gboolean up);
void janus_ice_notify_media(janus_ice_handle *handle, gboolean video, gboolean up) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying that we %s receiving %s\n",
		handle->handle_id, up ? "are" : "are NOT", video ? "video" : "audio");
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL || session->messages == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("media"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	json_object_set_new(event, "type", json_string(video ? "video" : "audio"));
	json_object_set_new(event, "receiving", json_string(up ? "true" : "false"));
	/* Convert to a string */
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", handle->handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	notification->code = 200;
	notification->payload = event_text;
	notification->allocated = 1;

	g_async_queue_push(session->messages, notification);
}

void janus_ice_notify_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying WebRTC hangup\n", handle->handle_id);
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("hangup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(reason != NULL)
		json_object_set_new(event, "reason", json_string(reason));
	/* Convert to a string */
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", handle->handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	notification->code = 200;
	notification->payload = event_text;
	notification->allocated = 1;

	g_async_queue_push(session->messages, notification);
}

/* libnice initialization */
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean ipv6, uint16_t rtp_min_port, uint16_t rtp_max_port) {
	janus_ice_lite_enabled = ice_lite;
	janus_ice_tcp_enabled = ice_tcp;
	janus_ipv6_enabled = ipv6;
	JANUS_LOG(LOG_INFO, "Initializing ICE stuff (%s mode, ICE-TCP candidates %s, IPv6 support %s)\n",
		janus_ice_lite_enabled ? "Lite" : "Full",
		janus_ice_tcp_enabled ? "enabled" : "disabled",
		janus_ipv6_enabled ? "enabled" : "disabled");
	if(janus_ice_tcp_enabled) {
#ifndef HAVE_LIBNICE_TCP
		JANUS_LOG(LOG_WARN, "libnice version < 0.1.8, disabling ICE-TCP support\n");
		janus_ice_tcp_enabled = FALSE;
#else
		if(!janus_ice_lite_enabled) {
			JANUS_LOG(LOG_WARN, "ICE-TCP only works in libnice if you enable ICE Lite too: disabling ICE-TCP support\n");
			janus_ice_tcp_enabled = FALSE;
		}
#endif
	}
	/* Automatically enable libnice debugging based on debug_level */
	if(log_level >= LOG_DBG) {
		janus_ice_debugging_enable();
	} else {
		nice_debug_disable(TRUE);
	}
	/*! \note The RTP/RTCP port range configuration may be just a placeholder: for
	 * instance, libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails
	 * when linking with an undefined reference to \c nice_agent_set_port_range 
	 * so this is checked by the install.sh script in advance. */
	rtp_range_min = rtp_min_port;
	rtp_range_max = rtp_max_port;
	if(rtp_range_max < rtp_range_min) {
		JANUS_LOG(LOG_WARN, "Invalid ICE port range: %"SCNu16" > %"SCNu16"\n", rtp_range_min, rtp_range_max);
	} else if(rtp_range_min > 0 || rtp_range_max > 0) {
#ifndef HAVE_PORTRANGE
		JANUS_LOG(LOG_WARN, "nice_agent_set_port_range unavailable, port range disabled\n");
#else
		JANUS_LOG(LOG_INFO, "ICE port range: %"SCNu16"-%"SCNu16"\n", rtp_range_min, rtp_range_max);
#endif
	}

	/* Start the handles watchdog */
	janus_mutex_init(&old_handles_mutex);
	old_handles = g_hash_table_new(NULL, NULL);
	handles_watchdog_context = g_main_context_new();
	handles_watchdog_loop = g_main_loop_new(handles_watchdog_context, FALSE);
	GError *error = NULL;
	handles_watchdog = g_thread_try_new("handles watchdog", &janus_ice_handles_watchdog, handles_watchdog_loop, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start handles watchdog...\n", error->code, error->message ? error->message : "??");
		exit(1);
	}

}

void janus_ice_deinit(void) {
	JANUS_LOG(LOG_INFO, "Ending ICE handles watchdog mainloop...\n");
	g_main_loop_quit(handles_watchdog_loop);
	g_thread_join(handles_watchdog);
	handles_watchdog = NULL;
	g_main_loop_unref(handles_watchdog_loop);
	g_main_context_unref(handles_watchdog_context);
	janus_mutex_lock(&old_handles_mutex);
	if(old_handles != NULL)
		g_hash_table_destroy(old_handles);
	old_handles = NULL;
	janus_mutex_unlock(&old_handles_mutex);
}

int janus_ice_set_stun_server(gchar *stun_server, uint16_t stun_port) {
	if(stun_server == NULL)
		return 0;	/* No initialization needed */
	if(stun_port == 0)
		stun_port = 3478;
	JANUS_LOG(LOG_INFO, "STUN server to use: %s:%u\n", stun_server, stun_port);
	/* Resolve address to get an IP */
	struct hostent *he = gethostbyname(stun_server);
	if(he == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
		return -1;
	}
	struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
	if(addr_list[0] == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
		return -1;
	}
	janus_stun_server = g_strdup(inet_ntoa(*addr_list[0]));
	if(janus_stun_server == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return -1;
	}
	janus_stun_port = stun_port;
	JANUS_LOG(LOG_VERB, "  >> %s:%u\n", janus_stun_server, janus_stun_port);
	/* Test the STUN server */
	StunAgent stun;
	stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
	StunMessage msg;
	uint8_t buf[1500];
	size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
	JANUS_LOG(LOG_INFO, "Testing STUN server: message is of %zu bytes\n", len);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int yes = 1;	/* For setsockopt() SO_REUSEADDR */
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	struct sockaddr_in address, remote;
	address.sin_family = AF_INET;
	address.sin_port = 0;
	address.sin_addr.s_addr = INADDR_ANY;
	remote.sin_family = AF_INET;
	remote.sin_port = htons(janus_stun_port);
	remote.sin_addr.s_addr = inet_addr(janus_stun_server);
	if(bind(fd, (struct sockaddr *)(&address), sizeof(struct sockaddr)) < 0) {
		JANUS_LOG(LOG_FATAL, "Bind failed for STUN BINDING test\n");
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, (struct sockaddr*)&remote, sizeof(remote));
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Error sending STUN BINDING test\n");
		return -1;
	}
	JANUS_LOG(LOG_VERB, "  >> Sent %d bytes %s:%u, waiting for reply...\n", bytes, janus_stun_server, janus_stun_port);
	struct timeval timeout;
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 5;	/* FIXME Don't wait forever */
	timeout.tv_usec = 0;
	select(fd+1, &readfds, NULL, NULL, &timeout);
	if(!FD_ISSET(fd, &readfds)) {
		JANUS_LOG(LOG_FATAL, "No response to our STUN BINDING test\n");
		return -1;
	}
	socklen_t addrlen = sizeof(remote);
	bytes = recvfrom(fd, buf, 1500, 0, (struct sockaddr*)&remote, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> Got %d bytes...\n", bytes);
	if(stun_agent_validate (&stun, &msg, buf, bytes, NULL, NULL) != STUN_VALIDATION_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Failed to validate STUN BINDING response\n");
		return -1;
	}
	StunClass class = stun_message_get_class(&msg);
	StunMethod method = stun_message_get_method(&msg);
	if(class != STUN_RESPONSE || method != STUN_BINDING) {
		JANUS_LOG(LOG_FATAL, "Unexpected STUN response: %d/%d\n", class, method);
		return -1;
	}
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr *)&address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", inet_ntoa(address.sin_addr));
		return 0;
	}
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr *)&address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", inet_ntoa(address.sin_addr));
		return 0;
	}
	return -1;
}

int janus_ice_set_turn_server(gchar *turn_server, uint16_t turn_port, gchar *turn_type, gchar *turn_user, gchar *turn_pwd) {
	if(turn_server == NULL)
		return 0;	/* No initialization needed */
	if(turn_type == NULL)
		turn_type = (char *)"udp";
	if(turn_port == 0)
		turn_port = 3478;
	JANUS_LOG(LOG_INFO, "TURN server to use: %s:%u (%s)\n", turn_server, turn_port, turn_type);
	/* Resolve address to get an IP */
	struct hostent *he = gethostbyname(turn_server);
	if(he == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		return -1;
	}
	struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
	if(addr_list[0] == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		return -1;
	}
	if(!strcasecmp(turn_type, "udp")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_UDP;
	} else if(!strcasecmp(turn_type, "tcp")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_TCP;
	} else if(!strcasecmp(turn_type, "tls")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_TLS;
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported relay type '%s'...\n", turn_type);
		return -1;
	}
	janus_turn_server = g_strdup(inet_ntoa(*addr_list[0]));
	if(janus_turn_server == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return -1;
	}
	janus_turn_port = turn_port;
	JANUS_LOG(LOG_VERB, "  >> %s:%u\n", janus_turn_server, janus_turn_port);
	if(turn_user)
		janus_turn_user = g_strdup(turn_user);
	if(turn_pwd)
		janus_turn_pwd = g_strdup(turn_pwd);
	return 0;
}

/* ICE stuff */
static const gchar *janus_ice_state_name[] = 
{
	"disconnected",
	"gathering",
	"connecting",
	"connected",
	"ready",
	"failed"
};
const gchar *janus_get_ice_state_name(gint state) {
	if(state < 0 || state > 5)
		return NULL;
	return janus_ice_state_name[state];
}

/* Stats */
void janus_ice_stats_queue_free(gpointer data);
void janus_ice_stats_queue_free(gpointer data) {
	janus_ice_stats_item *s = (janus_ice_stats_item *)data;
	g_free(s);
}

void janus_ice_stats_reset(janus_ice_stats *stats) {
	if(stats == NULL)
		return;
	stats->audio_bytes = 0;
	if(stats->audio_bytes_lastsec)
		g_list_free_full(stats->audio_bytes_lastsec, &janus_ice_stats_queue_free);
	stats->audio_bytes_lastsec = NULL;
	stats->audio_notified_lastsec = FALSE;
	stats->audio_nacks = 0;
	stats->video_bytes = 0;
	if(stats->video_bytes_lastsec)
		g_list_free_full(stats->video_bytes_lastsec, &janus_ice_stats_queue_free);
	stats->video_bytes_lastsec = NULL;
	stats->video_notified_lastsec = FALSE;
	stats->video_nacks = 0;
	stats->data_bytes = 0;
}


/* ICE Handles */
janus_ice_handle *janus_ice_handle_create(void *gateway_session) {
	if(gateway_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)gateway_session;
	guint64 handle_id = 0;
	while(handle_id == 0) {
		handle_id = g_random_int();
		if(janus_ice_handle_find(gateway_session, handle_id) != NULL) {
			/* Handle ID already taken, try another one */
			handle_id = 0;
		}
	}
	JANUS_LOG(LOG_INFO, "Creating new handle in session %"SCNu64": %"SCNu64"\n", session->session_id, handle_id);
	janus_ice_handle *handle = (janus_ice_handle *)calloc(1, sizeof(janus_ice_handle));
	if(handle == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	handle->session = gateway_session;
	handle->handle_id = handle_id;
	handle->app = NULL;
	handle->app_handle = NULL;
	janus_mutex_init(&handle->mutex);

	/* Set up other stuff. */
	janus_mutex_lock(&session->mutex);
	if(session->ice_handles == NULL)
		session->ice_handles = g_hash_table_new(NULL, NULL);
	g_hash_table_insert(session->ice_handles, GUINT_TO_POINTER(handle_id), handle);
	janus_mutex_unlock(&session->mutex);

	return handle;
}

janus_ice_handle *janus_ice_handle_find(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)gateway_session;
	janus_mutex_lock(&session->mutex);
	janus_ice_handle *handle = session->ice_handles ? g_hash_table_lookup(session->ice_handles, GUINT_TO_POINTER(handle_id)) : NULL;
	janus_mutex_unlock(&session->mutex);
	return handle;
}

gint janus_ice_handle_attach_plugin(void *gateway_session, guint64 handle_id, janus_plugin *plugin) {
	if(gateway_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	if(plugin == NULL)
		return JANUS_ERROR_PLUGIN_NOT_FOUND;
	janus_session *session = (janus_session *)gateway_session;
	janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	janus_mutex_lock(&session->mutex);
	if(handle->app != NULL) {
		/* This handle is already attached to a plugin */
		janus_mutex_unlock(&session->mutex);
		return JANUS_ERROR_PLUGIN_ATTACH;
	}
	int error = 0;
	janus_plugin_session *session_handle = calloc(1, sizeof(janus_plugin_session));
	if(session_handle == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		janus_mutex_unlock(&session->mutex);
		return JANUS_ERROR_UNKNOWN;	/* FIXME Do we need something like "Internal Server Error"? */
	}
	session_handle->gateway_handle = handle;
	session_handle->plugin_handle = NULL;
	session_handle->stopped = 0;
	plugin->create_session(session_handle, &error);
	if(error) {
		/* TODO Make error struct to pass verbose information */
		janus_mutex_unlock(&session->mutex);
		return error;
	}
	handle->app = plugin;
	handle->app_handle = session_handle;
	janus_mutex_unlock(&session->mutex);
	return 0;
}

gint janus_ice_handle_destroy(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = (janus_session *)gateway_session;
	janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	janus_mutex_lock(&session->mutex);
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there */
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
		if(handle->iceloop)
			g_main_loop_quit(handle->iceloop);
		janus_mutex_unlock(&session->mutex);
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s\n", plugin_t->get_name());
	/* TODO Actually detach handle... */
	int error = 0;
	handle->app_handle->stopped = 1;	/* This is to tell the plugin to stop using this session: we'll get rid of it later */
	plugin_t->destroy_session(handle->app_handle, &error);
	/* Get rid of the handle now */
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	if(handle->iceloop)
		g_main_loop_quit(handle->iceloop);

	/* Prepare JSON event to notify user/application */
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("detached"));
	json_object_set_new(event, "sender", json_integer(handle_id));
	/* Convert to a string */
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the event before we do anything */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification) {
		notification->code = 200;
		notification->payload = event_text;
		notification->allocated = 1;

		g_async_queue_push(session->messages, notification);
	}
	janus_mutex_unlock(&session->mutex);
	/* We only actually destroy the handle later */
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Handle detached (error=%d), scheduling destruction\n", handle_id, error);
	janus_mutex_lock(&old_handles_mutex);
	g_hash_table_insert(old_handles, GUINT_TO_POINTER(handle_id), handle);
	janus_mutex_unlock(&old_handles_mutex);
	return error;
}

void janus_ice_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	handle->session = NULL;
	handle->app = NULL;
	if(handle->app_handle != NULL) {
		handle->app_handle->stopped = 1;
		handle->app_handle->gateway_handle = NULL;
		handle->app_handle->plugin_handle = NULL;
		g_free(handle->app_handle);
		handle->app_handle = NULL;
	}
	janus_mutex_unlock(&handle->mutex);
	janus_ice_webrtc_free(handle);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Handle and related resources freed\n", handle->handle_id);
	g_free(handle);
	handle = NULL;
}

void janus_ice_webrtc_hangup(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	handle->icethread = NULL;
	if(handle->streams != NULL) {
		if(handle->audio_stream) {
			janus_ice_stream *stream = handle->audio_stream;
			if(stream->rtp_component)
				janus_dtls_srtp_send_alert(stream->rtp_component->dtls);
			if(stream->rtcp_component)
				janus_dtls_srtp_send_alert(stream->rtcp_component->dtls);
		}
		if(handle->video_stream) {
			janus_ice_stream *stream = handle->video_stream;
			if(stream->rtp_component)
				janus_dtls_srtp_send_alert(stream->rtp_component->dtls);
			if(stream->rtcp_component)
				janus_dtls_srtp_send_alert(stream->rtcp_component->dtls);
		}
		if(handle->data_stream) {
			janus_ice_stream *stream = handle->data_stream;
			if(stream->rtp_component)
				janus_dtls_srtp_send_alert(stream->rtp_component->dtls);
			if(stream->rtcp_component)
				janus_dtls_srtp_send_alert(stream->rtcp_component->dtls);
		}
	}
	janus_mutex_unlock(&handle->mutex);
}

void janus_ice_webrtc_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	if(handle->iceloop != NULL) {
		g_main_loop_unref (handle->iceloop);
		handle->iceloop = NULL;
	}
	if(handle->icectx != NULL) {
		g_main_context_unref (handle->icectx);
		handle->icectx = NULL;
	}
	handle->icethread = NULL;
	if(handle->streams != NULL) {
		janus_ice_stream_free(handle->streams, handle->audio_stream);
		handle->audio_stream = NULL;
		janus_ice_stream_free(handle->streams, handle->video_stream);
		handle->video_stream = NULL;
		janus_ice_stream_free(handle->streams, handle->data_stream);
		handle->data_stream = NULL;
		g_hash_table_destroy(handle->streams);
		handle->streams = NULL;
	}
	if(handle->agent != NULL) {
		if(G_IS_OBJECT(handle->agent))
			g_object_unref(handle->agent);
		handle->agent = NULL;
	}
	if(handle->remote_hashing != NULL) {
		g_free(handle->remote_hashing);
		handle->remote_hashing = NULL;
	}
	if(handle->remote_fingerprint != NULL) {
		g_free(handle->remote_fingerprint);
		handle->remote_fingerprint = NULL;
	}
	if(handle->local_sdp != NULL) {
		g_free(handle->local_sdp);
		handle->local_sdp = NULL;
	}
	if(handle->remote_sdp != NULL) {
		g_free(handle->remote_sdp);
		handle->remote_sdp = NULL;
	}
	if(handle->queued_packets != NULL) {
		janus_ice_queued_packet *pkt = NULL;
		while(g_async_queue_length(handle->queued_packets) > 0) {
			pkt = g_async_queue_try_pop(handle->queued_packets);
			if(pkt != NULL) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
			}
		}
		g_async_queue_unref(handle->queued_packets);
		handle->queued_packets = NULL;
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] WebRTC resources freed\n", handle->handle_id);
}

void janus_ice_stream_free(GHashTable *streams, janus_ice_stream *stream) {
	if(stream == NULL)
		return;
	if(streams != NULL)
		g_hash_table_remove(streams, stream);
	if(stream->components != NULL) {
		janus_ice_component_free(stream->components, stream->rtp_component);
		stream->rtp_component = NULL;
		janus_ice_component_free(stream->components, stream->rtcp_component);
		stream->rtcp_component = NULL;
		g_hash_table_destroy(stream->components);
	}
	stream->handle = NULL;
	if(stream->ruser != NULL) {
		g_free(stream->ruser);
		stream->ruser = NULL;
	}
	if(stream->rpass != NULL) {
		g_free(stream->rpass);
		stream->rpass = NULL;
	}
	g_free(stream);
	stream = NULL;
}

void janus_ice_component_free(GHashTable *components, janus_ice_component *component) {
	if(component == NULL)
		return;
	janus_ice_stream *stream = component->stream;
	if(stream == NULL)
		return;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return;
	//~ janus_mutex_lock(&handle->mutex);
	if(components != NULL)
		g_hash_table_remove(components, component);
	component->stream = NULL;
	if(component->source != NULL) {
		g_source_destroy(component->source);
		if(G_IS_OBJECT(component->source))
			g_object_unref(component->source);
		component->source = NULL;
	}
	if(component->dtls != NULL) {
		janus_dtls_srtp_destroy(component->dtls);
		component->dtls = NULL;
	}
	if(component->retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		GList *first = g_list_first(component->retransmit_buffer);
		while(first != NULL) {
			p = (janus_rtp_packet *)first->data;
			first->data = NULL;
			component->retransmit_buffer = g_list_delete_link(component->retransmit_buffer, first);
			g_free(p->data);
			p->data = NULL;
			g_free(p);
			first = g_list_first(component->retransmit_buffer);
		}
	}
	if(component->candidates != NULL) {
		GSList *i = NULL, *candidates = component->candidates;
		for (i = candidates; i; i = i->next) {
			NiceCandidate *c = (NiceCandidate *) i->data;
			if(c != NULL) {
				nice_candidate_free(c);
				c = NULL;
			}
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->candidates = NULL;
	if(component->local_candidates != NULL) {
		GSList *i = NULL, *candidates = component->local_candidates;
		for (i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			if(c != NULL) {
				g_free(c);
				c = NULL;
			}
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->local_candidates = NULL;
	if(component->remote_candidates != NULL) {
		GSList *i = NULL, *candidates = component->remote_candidates;
		for (i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			if(c != NULL) {
				g_free(c);
				c = NULL;
			}
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->remote_candidates = NULL;
	if(component->selected_pair != NULL)
		g_free(component->selected_pair);
	component->selected_pair = NULL;
	if(component->last_seqs)
		g_list_free(component->last_seqs);
	janus_ice_stats_reset(&component->in_stats);
	janus_ice_stats_reset(&component->out_stats);
	g_free(component);
	//~ janus_mutex_unlock(&handle->mutex);
}


/* Callbacks */
void janus_ice_cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	if(!handle)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Gathering done for stream %d\n", handle->handle_id, stream_id);
	handle->cdone++;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]  No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	stream->cdone = 1;
}

void janus_ice_cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice) {
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component state changed for component %d in stream %d: %d (%s)\n",
		handle ? handle->handle_id : 0, component_id, stream_id, state, janus_get_ice_state_name(state));
	if(!handle)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	component->state = state;
	/* FIXME Even in case the state is 'connected', we wait for the 'new-selected-pair' callback to do anything */
	if(state == NICE_COMPONENT_STATE_FAILED) {
		/* Failed doesn't mean necessarily we need to give up: we may be trickling */
		if(handle &&
				(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES))
					&& !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
			/* FIXME Should we really give up for what may be a failure in only one of the media? */
			if(stream->disabled) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but stream is disabled so we don't care...\n", handle->handle_id, component_id, stream_id);
				return;
			}
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
			janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
			janus_plugin *plugin = (janus_plugin *)handle->app;
			if(plugin != NULL) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
				if(plugin && plugin->hangup_media)
					plugin->hangup_media(handle->app_handle);
			}
			janus_ice_notify_hangup(handle, "ICE failed");
		}
	}
}

#ifndef HAVE_LIBNICE_TCP
void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, gchar *local, gchar *remote, gpointer ice) {
#else
void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local, NiceCandidate *remote, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local, remote);
#else
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local->foundation, remote->foundation);
#endif
	if(!handle)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(component->selected_pair)
		g_free(component->selected_pair);
	char sp[200];
#ifndef HAVE_LIBNICE_TCP
	g_snprintf(sp, 200, "%s <-> %s", local, remote);
#else
	gchar laddress[NICE_ADDRESS_STRING_LEN], raddress[NICE_ADDRESS_STRING_LEN];
	gint lport = 0, rport = 0;
	nice_address_to_string(&(local->addr), (gchar *)&laddress);
	nice_address_to_string(&(remote->addr), (gchar *)&raddress);
	lport = nice_address_get_port(&(local->addr));
	rport = nice_address_get_port(&(remote->addr));
	const char *ltype = NULL, *rtype = NULL; 
	switch(local->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			ltype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			ltype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			ltype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			ltype = "relay";
			break;
		default:
			break;
	}
	switch(remote->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			rtype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			rtype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			rtype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			rtype = "relay";
			break;
		default:
			break;
	}
	g_snprintf(sp, 200, "%s:%d [%s,%s] <-> %s:%d [%s,%s]",
		laddress, lport, ltype, local->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp",
		raddress, rport, rtype, remote->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp");
#endif
	component->selected_pair = g_strdup(sp);
	/* Now we can start the DTLS handshake (FIXME This was on the 'connected' state notification, before) */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready enough, starting DTLS handshake...\n", handle->handle_id);
	/* Have we been here before? (might happen, when trickling) */
	if(component->dtls != NULL)
		return;
	/* Create DTLS-SRTP context, at last */
	component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
	if(!component->dtls) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component DTLS-SRTP session??\n", handle->handle_id);
		return;
	}
	janus_dtls_srtp_handshake(component->dtls);
	/* Create retransmission timer */
	component->source = g_timeout_source_new(100);
	g_source_set_callback(component->source, janus_dtls_retry, component->dtls, NULL);
	guint id = g_source_attach(component->source, handle->icectx);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
}

void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
	janus_ice_component *component = (janus_ice_component *)ice;
	if(!component) {
		JANUS_LOG(LOG_ERR, "No component %d in stream %d??\n", component_id, stream_id);
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream %d??\n", stream_id);
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle) {
		JANUS_LOG(LOG_ERR, "No handle for stream %d??\n", stream_id);
		return;
	}
	if(!component->dtls) {	/* Still waiting for the DTLS stack */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Still waiting for the DTLS stack for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
		return;
	}
	/* What is this? */
	if (janus_is_dtls(buf) || (!janus_is_rtp(buf) && !janus_is_rtcp(buf))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Looks like DTLS!\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		component->in_stats.data_bytes += len;
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/rfc5761#section-4) */
	if(len < 12)
		return;	/* Definitely nothing useful */
	if(component_id == 1 && (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) || janus_is_rtp(buf))) {
		/* FIXME If rtcp-mux is not used, a first component is always RTP; otherwise, we need to check */
		//~ JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTP packet (%s stream)!\n", handle->handle_id,
			//~ janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? "bundled" : (stream->stream_id == handle->audio_id ? "audio" : "video"));
		if(!component->dtls || !component->dtls->srtp_valid) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			rtp_header *header = (rtp_header *)buf;
			/* Is this audio or video? */
			int video = 0;
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
				/* Easy enough */
				video = (stream->stream_id == handle->video_id ? 1 : 0);
			} else {
				/* Bundled streams, check SSRC */
				video = (stream->video_ssrc_peer == ntohl(header->ssrc) ? 1 : 0);
				//~ JANUS_LOG(LOG_VERB, "[RTP] Bundling: this is %s (video=%"SCNu64", audio=%"SCNu64", got %ld)\n",
					//~ video ? "video" : "audio", stream->video_ssrc_peer, stream->audio_ssrc_peer, ntohl(header->ssrc));
			}
			if(video) {
				/* Keep track of the video packets, in case we need to NACK them */
				guint16 seq = ntohs(header->seq_number);
				//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got sequence number %"SCNu16"\n", handle->handle_id, seq);
				component->last_seqs = g_list_append(component->last_seqs, GUINT_TO_POINTER(seq));
				if(g_list_length(component->last_seqs) > 100)
					component->last_seqs = g_list_delete_link(component->last_seqs, g_list_first(component->last_seqs));
			}
			int buflen = len;
			err_status_t res = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
			if(res != err_status_ok) {
				if(res != err_status_replay_fail && res != err_status_replay_old) {
					/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
					rtp_header *header = (rtp_header *)buf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n", handle->handle_id, janus_get_srtp_error(res), len, buflen, timestamp, seq);
				}
			} else {
				if(video) {
					if(stream->video_ssrc_peer == 0) {
						stream->video_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer video SSRC: %u\n", handle->handle_id, stream->video_ssrc_peer);
					}
				} else {
					if(stream->audio_ssrc_peer == 0) {
						stream->audio_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer audio SSRC: %u\n", handle->handle_id, stream->audio_ssrc_peer);
					}
				}
				/* Pass the data to the responsible plugin */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp)
					plugin->incoming_rtp(handle->app_handle, video, buf, buflen);
				/* Update stats (TODO Do the same for the last second window as well) */
				if(buflen > 0) {
					/* Update the last sec queue as well */
					janus_ice_stats_item *s = calloc(1, sizeof(janus_ice_stats_item));
					s->bytes = buflen;
					s->when = janus_get_monotonic_time();
					janus_mutex_lock(&component->mutex);
					if(!video) {
						if(component->in_stats.audio_bytes == 0 || component->in_stats.audio_notified_lastsec) {
							/* We either received our first audio packet, or we started receiving it again after missing more than a second */
							component->in_stats.audio_notified_lastsec = FALSE;
							janus_ice_notify_media(handle, FALSE, TRUE);
						}
						component->in_stats.audio_bytes += buflen;
						component->in_stats.audio_bytes_lastsec = g_list_append(component->in_stats.audio_bytes_lastsec, s);
						if(g_list_length(component->in_stats.audio_bytes_lastsec) > 100) {
							GList *first = g_list_first(component->in_stats.audio_bytes_lastsec);
							s = (janus_ice_stats_item *)first->data;
							first->data = NULL;
							component->in_stats.audio_bytes_lastsec = g_list_delete_link(component->in_stats.audio_bytes_lastsec, first);
							g_free(s);
						}
					} else {
						if(component->in_stats.video_bytes == 0 || component->in_stats.video_notified_lastsec) {
							/* We either received our first video packet, or we started receiving it again after missing more than a second */
							component->in_stats.video_notified_lastsec = FALSE;
							janus_ice_notify_media(handle, TRUE, TRUE);
						}
						component->in_stats.video_bytes += buflen;
						component->in_stats.video_bytes_lastsec = g_list_append(component->in_stats.video_bytes_lastsec, s);
						if(g_list_length(component->in_stats.video_bytes_lastsec) > 100) {
							GList *first = g_list_first(component->in_stats.video_bytes_lastsec);
							s = (janus_ice_stats_item *)first->data;
							first->data = NULL;
							component->in_stats.video_bytes_lastsec = g_list_delete_link(component->in_stats.video_bytes_lastsec, first);
							g_free(s);
						}
					}
					janus_mutex_unlock(&component->mutex);
				}
			}
			if(video) {
				/* FIXME Check the sequence number, to see if we missed anything and need to send a NACK... */
				gint64 now = janus_get_monotonic_time();
				if(now-component->last_nack_time > 500000) {
					/* FIXME ... but don't send NACKs too often (max 2 per second) */
					component->last_seqs = g_list_sort(component->last_seqs, janus_nack_sort);
					GSList *nacks = NULL;
					GList *seqs = component->last_seqs, *prev = seqs;
					if(seqs != NULL && g_list_length(seqs) > 1) {
						while(seqs) {
							if(seqs != prev) {
								guint16 n = GPOINTER_TO_UINT(seqs->data);
								guint16 np = GPOINTER_TO_UINT(prev->data);
								if(n-np > 1 && n-np < 5000) {
									int i=0;
									for(i=0; i<n-np; i++) {
										JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16", going to NACK it...\n", handle->handle_id, np+i+1);
										nacks = g_slist_append(nacks, GUINT_TO_POINTER(np+i+1));
									}
								}
							}
							prev = seqs;
							seqs = seqs->next;
						}
					}
					if(nacks != NULL) {
						/* FIXME Generate a NACK and send it */
						if(now-component->last_nack_time > 2*G_USEC_PER_SEC) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Missed some packets, NACKing them now...\n", handle->handle_id);
						}
						char nackbuf[200];
						int res = janus_rtcp_nacks((char *)&nackbuf, 200, nacks);
						if(res > 0)
							janus_ice_relay_rtcp(handle, video, nackbuf, res);
						/* Update stats */
						if(video) {
							component->out_stats.video_nacks++;
						} else {
							component->out_stats.audio_nacks++;
						}
						/* Inform the plugin about the slow downlink in case it's needed */
						if(g_slist_length(nacks) >= 16) {	/* FIXME Find a good threshold */
							/* ... but never more than once per second */
							if(now-component->last_slowlink_time >= G_USEC_PER_SEC) {
								component->last_slowlink_time = now;
								janus_plugin *plugin = (janus_plugin *)handle->app;
								if(plugin && plugin->slow_link)
									plugin->slow_link(handle->app_handle, 0, video);
							}
						}
						g_slist_free(nacks);
						nacks = NULL;
					}
					component->last_nack_time = now;
				}
			}
		}
		return;
	}
	if(component_id == 2 || (component_id == 1 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && janus_is_rtcp(buf))) {
		/* FIXME A second component is always RTCP; in case of rtcp-mux, we need to check */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTCP packet (%s stream)!\n", handle->handle_id,
			janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? "bundled" : (stream->stream_id == handle->audio_id ? "audio" : "video"));
		if(!component->dtls || !component->dtls->srtp_valid) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			err_status_t res = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
			if(res != err_status_ok) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTCP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_get_srtp_error(res), len, buflen);
			} else {
				/* Is this audio or video? */
				int video = 0;
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					/* Easy enough */
					video = (stream->stream_id == handle->video_id ? 1 : 0);
				} else {
					/* TODO Bundled streams, check SSRC */
					guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, len);
					video = (stream->video_ssrc_peer == rtcp_ssrc ? 1 : 0);
					//~ JANUS_LOG(LOG_VERB, "[RTCP] Bundling: this is %s (video=%"SCNu64", audio=%"SCNu64", got %ld)\n",
						//~ video ? "video" : "audio", stream->video_ssrc_peer, stream->audio_ssrc_peer, rtcp_ssrc);
				}
				GSList *nacks = janus_rtcp_get_nacks(buf, buflen);
				int nacks_count = g_slist_length(nacks);
				if(nacks != NULL && nacks_count > 0) {
					/* Handle NACK */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Just got some NACKS (%d) we should handle...\n", handle->handle_id, nacks_count);
					GSList *list = nacks;
					gint64 now = janus_get_monotonic_time();
					janus_mutex_lock(&component->mutex);
					while(list) {
						unsigned int seqnr = GPOINTER_TO_UINT(list->data);
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> %u\n", handle->handle_id, seqnr);
						GList *rp = component->retransmit_buffer;
						while(rp) {
							janus_rtp_packet *p = (janus_rtp_packet *)rp->data;
							if(p) {
								rtp_header *rh = (rtp_header *)p->data;
								if(ntohs(rh->seq_number) == seqnr) {
									/* Should we retransmit this packet? */
									if((p->last_retransmit > 0) && (now-p->last_retransmit < MAX_NACK_IGNORE)) {
										JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"ms ago, skipping\n", handle->handle_id, seqnr, now-p->last_retransmit);
										break;
									}
									JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission!\n", handle->handle_id, seqnr);
									p->last_retransmit = now;
									/* Enqueue it */
									janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)calloc(1, sizeof(janus_ice_queued_packet));
									pkt->data = calloc(p->length, sizeof(char));
									memcpy(pkt->data, p->data, p->length);
									pkt->length = p->length;
									pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
									pkt->control = FALSE;
									pkt->encrypted = TRUE;	/* This was already encrypted before */
									if(handle->queued_packets != NULL)
										g_async_queue_push(handle->queued_packets, pkt);
									break;
								}
							}
							rp = rp->next;
						}
						list = list->next;
					}
					janus_mutex_unlock(&component->mutex);
					g_slist_free(nacks);
					nacks = NULL;
					/* FIXME Remove the NACK compound packet, we've handled it */
					buflen = janus_rtcp_remove_nacks(buf, buflen);
					/* Update stats */
					if(video) {
						component->in_stats.video_nacks++;
					} else {
						component->in_stats.audio_nacks++;
					}
					/* Inform the plugin about the slow uplink in case it's needed */
					if(nacks_count >= 16) {	/* FIXME Find a good threshold */
						/* ... but never more than once per second */
						gint64 now = janus_get_monotonic_time();
						if(now-component->last_slowlink_time >= G_USEC_PER_SEC) {
							component->last_slowlink_time = now;
							janus_plugin *plugin = (janus_plugin *)handle->app;
							if(plugin && plugin->slow_link)
								plugin->slow_link(handle->app_handle, 1, video);
						}
					}
				}
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtcp)
					plugin->incoming_rtcp(handle->app_handle, video, buf, buflen);
			}
		}
		return;
	}
	if(component_id == 3 || (janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)
			&& janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS))) {
		JANUS_LOG(LOG_INFO, "[%"SCNu64"] Not RTP and not RTCP... may these be data channels?\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		if(len > 0) {
			component->in_stats.data_bytes += len;
		}
		return;
	}
}

void janus_ice_incoming_data(janus_ice_handle *handle, char *buffer, int length) {
	if(handle == NULL || buffer == NULL || length <= 0)
		return;
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin && plugin->incoming_data)
		plugin->incoming_data(handle->app_handle, buffer, length);
}


/* Thread to create agent */
void *janus_ice_thread(void *data) {
	janus_ice_handle *handle = data;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE thread started\n", handle->handle_id);
	GMainLoop *loop = handle->iceloop;
	if(loop == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid loop...\n", handle->handle_id);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	g_usleep (100000);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Looping (ICE)...\n", handle->handle_id);
	g_main_loop_run (loop);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	if(handle->cdone == 0)
		handle->cdone = -1;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE thread ended!\n", handle->handle_id);
	/* This handle has been destroyed, wait a bit and then free all the resources */
	g_usleep (1*G_USEC_PER_SEC);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		//~ janus_ice_free(handle);
	} else {
		janus_ice_webrtc_free(handle);
	}
	g_thread_unref(g_thread_self());
	return NULL;
}

/* Helper: candidates */
void janus_ice_candidates_to_sdp(janus_ice_handle *handle, char *sdp, guint stream_id, guint component_id)
{
	if(!handle || !handle->agent || !sdp)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	NiceAgent* agent = handle->agent;
	/* adding a stream should cause host candidates to be generated */
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	gboolean log_candidates = (component->local_candidates == NULL);
	/* Any provided public IP to consider? */
	char *host_ip = NULL;
	if(janus_get_public_ip() != janus_get_local_ip()) {
		host_ip = janus_get_public_ip(); 
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Public IP specified (%s), using that as host address in the candidates\n", handle->handle_id, host_ip);
	} 
	for (i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Stream #%d, Component #%d\n", handle->handle_id, c->stream_id, c->component_id);
		gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
		gint port = 0, base_port = 0;
		nice_address_to_string(&(c->addr), (gchar *)&address);
		port = nice_address_get_port(&(c->addr));
		nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
		base_port = nice_address_get_port(&(c->base_addr));
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
		/* SDP time */
		gchar buffer[100];
		if(c->type == NICE_CANDIDATE_TYPE_HOST) {
			/* 'host' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				g_snprintf(buffer, 100,
					"a=candidate:%s %d %s %d %s %d typ host\r\n", 
						c->foundation,
						c->component_id,
						"udp",
						c->priority,
						host_ip ? host_ip : address,
						port);
			} else {
				if(!janus_ice_tcp_enabled) {
					/* ICE-TCP support disabled */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping host TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping host TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
				nice_candidate_free(c);
				continue;
#else
				const char *type = NULL;
				switch(c->transport) {
					case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
						type = "active";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
						type = "passive";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_SO:
						type = "so";
						break;
					default:
						break;
				}
				if(type == NULL) {
					/* FIXME Unsupported transport */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP host candidate...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				} else {
					g_snprintf(buffer, 100,
						"a=candidate:%s %d %s %d %s %d typ host tcptype %s\r\n", 
							c->foundation,
							c->component_id,
							"tcp",
							c->priority,
							host_ip ? host_ip : address,
							port,
							type);
				}
#endif
			}
		} else if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
			/* 'srflx' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
				gint base_port = nice_address_get_port(&(c->base_addr));
				g_snprintf(buffer, 100,
					"a=candidate:%s %d %s %d %s %d typ srflx raddr %s rport %d\r\n", 
						c->foundation,
						c->component_id,
						"udp",
						c->priority,
						address,
						port,
						base_address,
						base_port);
			} else {
				if(!janus_ice_tcp_enabled) {
					/* ICE-TCP support disabled */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping srflx TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping srflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
				nice_candidate_free(c);
				continue;
#else
				const char *type = NULL;
				switch(c->transport) {
					case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
						type = "active";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
						type = "passive";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_SO:
						type = "so";
						break;
					default:
						break;
				}
				if(type == NULL) {
					/* FIXME Unsupported transport */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP srflx candidate...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				} else {
					g_snprintf(buffer, 100,
						"a=candidate:%s %d %s %d %s %d typ srflx raddr %s rport %d tcptype %s\r\n", 
							c->foundation,
							c->component_id,
							"tcp",
							c->priority,
							address,
							port,
							base_address,
							base_port,
							type);
				}
#endif
			}
		} else if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
			/* 'prflx' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				g_snprintf(buffer, 100,
					"a=candidate:%s %d %s %d %s %d typ prflx raddr %s rport %d\r\n", 
						c->foundation,
						c->component_id,
						"udp",
						c->priority,
						address,
						port,
						base_address,
						base_port);
			} else {
				if(!janus_ice_tcp_enabled) {
					/* ICE-TCP support disabled */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
				nice_candidate_free(c);
				continue;
#else
				const char *type = NULL;
				switch(c->transport) {
					case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
						type = "active";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
						type = "passive";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_SO:
						type = "so";
						break;
					default:
						break;
				}
				if(type == NULL) {
					/* FIXME Unsupported transport */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP prflx candidate...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				} else {
					g_snprintf(buffer, 100,
						"a=candidate:%s %d %s %d %s %d typ prflx raddr %s rport %d tcptype %s\r\n", 
							c->foundation,
							c->component_id,
							"tcp",
							c->priority,
							address,
							port,
							base_address,
							base_port,
							type);
				}
#endif
			}
		} else if(c->type == NICE_CANDIDATE_TYPE_RELAYED) {
			/* 'relay' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				g_snprintf(buffer, 100,
					"a=candidate:%s %d %s %d %s %d typ relay raddr %s rport %d\r\n", 
						c->foundation,
						c->component_id,
						"udp",
						c->priority,
						address,
						port,
						base_address,
						base_port);
			} else {
				if(!janus_ice_tcp_enabled) {
					/* ICE-TCP support disabled */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping relay TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping relay TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
				nice_candidate_free(c);
				continue;
#else
				const char *type = NULL;
				switch(c->transport) {
					case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
						type = "active";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
						type = "passive";
						break;
					case NICE_CANDIDATE_TRANSPORT_TCP_SO:
						type = "so";
						break;
					default:
						break;
				}
				if(type == NULL) {
					/* FIXME Unsupported transport */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP relay candidate...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				} else {
					g_snprintf(buffer, 100,
						"a=candidate:%s %d %s %d %s %d typ relay raddr %s rport %d tcptype %s\r\n", 
							c->foundation,
							c->component_id,
							"tcp",
							c->priority,
							address,
							port,
							base_address,
							base_port,
							type);
				}
#endif
			}
		}
		g_strlcat(sdp, buffer, BUFSIZE);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]     %s\n", handle->handle_id, buffer);
		if(log_candidates) {
			/* Save for the summary, in case we need it */
			component->local_candidates = g_slist_append(component->local_candidates, g_strdup(buffer+strlen("a=candidate:")));
		}
		nice_candidate_free(c);
	}
	g_slist_free(candidates);
}

void janus_ice_setup_remote_candidates(janus_ice_handle *handle, guint stream_id, guint component_id) {
	if(!handle || !handle->agent || !handle->streams)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream || !stream->components) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such stream %d: cannot setup remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	if(stream->disabled) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Stream %d is disabled, skipping remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such component %d in stream %d: cannot setup remote candidates\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(component->process_started) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component %d in stream %d has already been set up\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(!component->candidates || !component->candidates->data) {
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)
				|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) { 
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No remote candidates for component %d in stream %d: was the remote SDP parsed?\n", handle->handle_id, component_id, stream_id);
		}
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ## Setting remote candidates: stream %d, component %d (%u in the list)\n",
		handle->handle_id, stream_id, component_id, g_slist_length(component->candidates));
	/* Add all candidates */
	NiceCandidate *c = NULL;
	GSList *gsc = component->candidates;
	gchar *rufrag = NULL, *rpwd = NULL;
	while(gsc) {
		c = (NiceCandidate *) gsc->data;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] >> Remote Stream #%d, Component #%d\n", handle->handle_id, c->stream_id, c->component_id);
		if(c->username && !rufrag)
			rufrag = c->username;
		if(c->password && !rpwd)
			rpwd = c->password;
		gchar address[NICE_ADDRESS_STRING_LEN];
		nice_address_to_string(&(c->addr), (gchar *)&address);
		gint port = nice_address_get_port(&(c->addr));
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Username:   %s\n", handle->handle_id, c->username);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Password:   %s\n", handle->handle_id, c->password);
		gsc = gsc->next;
	}
	if(rufrag && rpwd) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Setting remote credendials...\n", handle->handle_id);
		if(!nice_agent_set_remote_credentials(handle->agent, stream_id, rufrag, rpwd)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"]  failed to set remote credentials!\n", handle->handle_id);
		}
	}
	guint added = nice_agent_set_remote_candidates(handle->agent, stream_id, component_id, component->candidates);
	if(added < g_slist_length(component->candidates)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to set remote candidates :-( (added %u, expected %u)\n",
			handle->handle_id, added, g_slist_length(component->candidates));
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote candidates set!\n", handle->handle_id);
		component->process_started = TRUE;
	}
}

int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video, int data, int bundle, int rtcpmux, int trickle) {
	if(!handle)
		return -1;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting ICE locally: got %s (%d audios, %d videos)\n", handle->handle_id, offer ? "OFFER" : "ANSWER", audio, video);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);

	/* Note: in case this is not an OFFER, we don't know whether DataChannels are supported on the other side or not yet */
	if(data) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	}
	/* Note: in case this is not an OFFER, we don't know whether BUNDLE is supported on the other side or not yet */
	if(offer && bundle) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
	}
	/* Note: in case this is not an OFFER, we don't know whether rtcp-mux is supported on the other side or not yet */
	if(offer && rtcpmux) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX);
	}
	/* Note: in case this is not an OFFER, we don't know whether ICE trickling is supported on the other side or not yet */
	if(offer && trickle) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED);

	handle->icectx = g_main_context_new();
	handle->iceloop = g_main_loop_new(handle->icectx, FALSE);
	GError *error = NULL;
	handle->icethread = g_thread_try_new("ice thread", &janus_ice_thread, handle, &error);
	if(error != NULL) {
		/* FIXME We should clear some resources... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the ICE thread...\n", handle->handle_id, error->code, error->message ? error->message : "??");
		return -1;
 	}
	handle->queued_packets = g_async_queue_new();
	handle->send_thread = g_thread_try_new("ice send thread", &janus_ice_send_thread, handle, &error);
	if(error != NULL) {
		/* FIXME We should clear some resources... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the ICE send thread...\n", handle->handle_id, error->code, error->message ? error->message : "??");
		return -1;
 	}
	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice */
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Creating ICE agent (ICE %s mode, %s)\n", handle->handle_id,
		janus_ice_lite_enabled ? "Lite" : "Full", offer ? "controlled" : "controlling");
	handle->agent = nice_agent_new(handle->icectx, NICE_COMPATIBILITY_DRAFT19);
	if(janus_ice_lite_enabled) {
		g_object_set(G_OBJECT(handle->agent), "full-mode", FALSE, NULL);
	}
	/* Any STUN server to use? */
	if(janus_stun_server != NULL && janus_stun_port > 0) {
		g_object_set(G_OBJECT(handle->agent),
			"stun-server", janus_stun_server,
			"stun-server-port", janus_stun_port,
			NULL);
	}
	g_object_set(G_OBJECT(handle->agent), "upnp", FALSE, NULL);
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", !offer, NULL);
	g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
	g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
#ifndef HAVE_LIBNICE_TCP
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair",
#else
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair-full",
#endif
		G_CALLBACK (janus_ice_cb_new_selected_pair), handle);

	/* Add all local addresses, except those in the ignore list */
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	char host[NI_MAXHOST];
	if(getifaddrs(&ifaddr) == -1) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error getting list of interfaces...", handle->handle_id);
	} else {
		for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
			if(ifa->ifa_addr == NULL)
				continue;
			/* Skip interfaces which are not up and running */
			if (!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
				continue;
			/* Skip loopback interfaces */
			if (ifa->ifa_flags & IFF_LOOPBACK)
				continue;
			family = ifa->ifa_addr->sa_family;
			if(family != AF_INET && family != AF_INET6)
				continue;
			/* We only add IPv6 addresses if support for them has been explicitly enabled (still WIP, mostly) */
			if(family == AF_INET6 && !janus_ipv6_enabled)
				continue;
			/* Check the interface name first: we can ignore that as well */
			if(ifa->ifa_name != NULL && janus_ice_is_ignored(ifa->ifa_name))
				continue;
			s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if(s != 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] getnameinfo() failed: %s\n", handle->handle_id, gai_strerror(s));
				continue;
			}
			/* Skip 0.0.0.0, :: and local scoped addresses  */
			if(!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strncmp(host, "fe80:", 5))
				continue;
			/* Check if this IP address is in the ignore list, now */
			if(janus_ice_is_ignored(host))
				continue;
			/* Ok, add interface to the ICE agent */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding %s to the addresses to gather candidates for\n", handle->handle_id, host);
			NiceAddress addr_local;
			nice_address_init (&addr_local);
			if(!nice_address_set_from_string (&addr_local, host)) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping invalid address %s\n", handle->handle_id, host);
				continue;
			}
			nice_agent_add_local_address (handle->agent, &addr_local);
		}
		freeifaddrs(ifaddr);
	}

	handle->cdone = 0;
	handle->streams_num = 0;
	handle->streams = g_hash_table_new(NULL, NULL);
	if(audio) {
		/* Add an audio stream */
		handle->streams_num++;
		handle->audio_id = nice_agent_add_stream (handle->agent, janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) ? 1 : 2);
		janus_ice_stream *audio_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(audio_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		audio_stream->stream_id = handle->audio_id;
		audio_stream->handle = handle;
		audio_stream->cdone = 0;
		audio_stream->payload_type = -1;
		audio_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		audio_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		audio_stream->audio_ssrc = g_random_int();	/* FIXME Should we look for conflicts? */
		audio_stream->audio_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		audio_stream->video_ssrc = 0;
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
			/* If we're bundling, this stream is going to be used for video as well */
			audio_stream->video_ssrc = g_random_int();	/* FIXME Should we look for conflicts? */
		}
		audio_stream->video_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		janus_mutex_init(&audio_stream->mutex);
		audio_stream->components = g_hash_table_new(NULL, NULL);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->audio_id), audio_stream);
		if(janus_turn_server != NULL) {
			/* We need relay candidates as well */
			nice_agent_set_relay_info(handle->agent, handle->audio_id, 1,
				janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
		}
		handle->audio_stream = audio_stream;
		janus_ice_component *audio_rtp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(audio_rtp == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		audio_rtp->stream = audio_stream;
		audio_rtp->candidates = NULL;
		audio_rtp->local_candidates = NULL;
		audio_rtp->remote_candidates = NULL;
		audio_rtp->selected_pair = NULL;
		audio_rtp->process_started = FALSE;
		audio_rtp->source = NULL;
		audio_rtp->dtls = NULL;
		audio_rtp->retransmit_buffer = NULL;
		audio_rtp->last_seqs = NULL;
		audio_rtp->last_nack_time = 0;
		audio_rtp->last_slowlink_time = 0;
		janus_ice_stats_reset(&audio_rtp->in_stats);
		janus_ice_stats_reset(&audio_rtp->out_stats);
		janus_mutex_init(&audio_rtp->mutex);
		g_hash_table_insert(audio_stream->components, GUINT_TO_POINTER(1), audio_rtp);
		audio_stream->rtp_component = audio_rtp;
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->audio_id, 1, rtp_range_min, rtp_range_max);
#endif
		janus_ice_component *audio_rtcp = NULL;
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
			audio_rtcp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
			if(audio_rtcp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				return -1;
			}
			if(janus_turn_server != NULL) {
				/* We need relay candidates as well */
				nice_agent_set_relay_info(handle->agent, handle->audio_id, 2,
					janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
			}
			audio_rtcp->stream = audio_stream;
			audio_rtcp->candidates = NULL;
			audio_rtcp->local_candidates = NULL;
			audio_rtcp->remote_candidates = NULL;
			audio_rtcp->selected_pair = NULL;
			audio_rtcp->process_started = FALSE;
			audio_rtcp->source = NULL;
			audio_rtcp->dtls = NULL;
			audio_rtcp->retransmit_buffer = NULL;
			audio_rtcp->last_seqs = NULL;
			audio_rtcp->last_nack_time = 0;
			audio_rtcp->last_slowlink_time = 0;
			janus_ice_stats_reset(&audio_rtcp->in_stats);
			janus_ice_stats_reset(&audio_rtcp->out_stats);
			janus_mutex_init(&audio_rtcp->mutex);
			g_hash_table_insert(audio_stream->components, GUINT_TO_POINTER(2), audio_rtcp);
			audio_stream->rtcp_component = audio_rtcp;
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
			nice_agent_set_port_range(handle->agent, handle->audio_id, 2, rtp_range_min, rtp_range_max);
#endif
		}
		nice_agent_gather_candidates (handle->agent, handle->audio_id);
		nice_agent_attach_recv (handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtp);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && audio_rtcp != NULL)
			nice_agent_attach_recv (handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtcp);
	}
	if(video && (!audio || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))) {
		/* Add a video stream */
		handle->streams_num++;
		handle->video_id = nice_agent_add_stream (handle->agent, janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) ? 1 : 2);
		janus_ice_stream *video_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(video_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		video_stream->handle = handle;
		video_stream->stream_id = handle->video_id;
		video_stream->cdone = 0;
		video_stream->payload_type = -1;
		video_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		video_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		video_stream->video_ssrc = g_random_int();	/* FIXME Should we look for conflicts? */
		video_stream->video_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		video_stream->audio_ssrc = 0;
		video_stream->audio_ssrc_peer = 0;
		video_stream->components = g_hash_table_new(NULL, NULL);
		janus_mutex_init(&video_stream->mutex);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->video_id), video_stream);
		handle->video_stream = video_stream;
		janus_ice_component *video_rtp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(video_rtp == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		if(janus_turn_server != NULL) {
			/* We need relay candidates as well */
			nice_agent_set_relay_info(handle->agent, handle->video_id, 1,
				janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
		}
		video_rtp->stream = video_stream;
		video_rtp->candidates = NULL;
		video_rtp->local_candidates = NULL;
		video_rtp->remote_candidates = NULL;
		video_rtp->selected_pair = NULL;
		video_rtp->process_started = FALSE;
		video_rtp->source = NULL;
		video_rtp->dtls = NULL;
		video_rtp->retransmit_buffer = NULL;
		video_rtp->last_seqs = NULL;
		video_rtp->last_nack_time = 0;
		video_rtp->last_slowlink_time = 0;
		janus_ice_stats_reset(&video_rtp->in_stats);
		janus_ice_stats_reset(&video_rtp->out_stats);
		janus_mutex_init(&video_rtp->mutex);
		g_hash_table_insert(video_stream->components, GUINT_TO_POINTER(1), video_rtp);
		video_stream->rtp_component = video_rtp;
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->video_id, 1, rtp_range_min, rtp_range_max);
#endif
		janus_ice_component *video_rtcp = NULL;
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
			video_rtcp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
			if(video_rtcp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				return -1;
			}
			if(janus_turn_server != NULL) {
				/* We need relay candidates as well */
				nice_agent_set_relay_info(handle->agent, handle->audio_id, 2,
					janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
			}
			video_rtcp->stream = video_stream;
			video_rtcp->candidates = NULL;
			video_rtcp->local_candidates = NULL;
			video_rtcp->remote_candidates = NULL;
			video_rtcp->selected_pair = NULL;
			video_rtcp->process_started = FALSE;
			video_rtcp->source = NULL;
			video_rtcp->dtls = NULL;
			video_rtcp->retransmit_buffer = NULL;
			video_rtcp->last_seqs = NULL;
			video_rtcp->last_nack_time = 0;
			video_rtcp->last_slowlink_time = 0;
			janus_ice_stats_reset(&video_rtcp->in_stats);
			janus_ice_stats_reset(&video_rtcp->out_stats);
			janus_mutex_init(&video_rtcp->mutex);
			g_hash_table_insert(video_stream->components, GUINT_TO_POINTER(2), video_rtcp);
			video_stream->rtcp_component = video_rtcp;
#ifdef HAVE_PORTRANGE
			/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
			nice_agent_set_port_range(handle->agent, handle->video_id, 2, rtp_range_min, rtp_range_max);
#endif
		}
		nice_agent_gather_candidates (handle->agent, handle->video_id);
		nice_agent_attach_recv (handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtp);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && video_rtcp != NULL)
			nice_agent_attach_recv (handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtcp);
	}
#ifndef HAVE_SCTP
	handle->data_id = 0;
	handle->data_stream = NULL;
#else
	if(data && ((!audio && !video) || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))) {
		/* Add a SCTP/DataChannel stream */
		handle->streams_num++;
		handle->data_id = nice_agent_add_stream (handle->agent, 1);
		janus_ice_stream *data_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(data_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		if(janus_turn_server != NULL) {
			/* We need relay candidates as well */
			nice_agent_set_relay_info(handle->agent, handle->data_id, 1,
				janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
		}
		data_stream->handle = handle;
		data_stream->stream_id = handle->data_id;
		data_stream->cdone = 0;
		data_stream->payload_type = -1;
		data_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		data_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		data_stream->components = g_hash_table_new(NULL, NULL);
		janus_mutex_init(&data_stream->mutex);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->data_id), data_stream);
		handle->data_stream = data_stream;
		janus_ice_component *data_component = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(data_component == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		data_component->stream = data_stream;
		data_component->candidates = NULL;
		data_component->local_candidates = NULL;
		data_component->remote_candidates = NULL;
		data_component->selected_pair = NULL;
		data_component->process_started = FALSE;
		data_component->source = NULL;
		data_component->dtls = NULL;
		data_component->retransmit_buffer = NULL;
		data_component->last_seqs = NULL;
		data_component->last_nack_time = 0;
		data_component->last_slowlink_time = 0;
		janus_ice_stats_reset(&data_component->in_stats);
		janus_ice_stats_reset(&data_component->out_stats);
		janus_mutex_init(&data_component->mutex);
		g_hash_table_insert(data_stream->components, GUINT_TO_POINTER(1), data_component);
		data_stream->rtp_component = data_component;	/* We use the component called 'RTP' for data */
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->data_id, 1, rtp_range_min, rtp_range_max);
#endif
		nice_agent_gather_candidates (handle->agent, handle->data_id);
		nice_agent_attach_recv (handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, data_component);
	}
#endif
	return 0;
}

void *janus_ice_send_thread(void *data) {
	janus_ice_handle *handle = (janus_ice_handle *)data;
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] ICE send thread started...\n", handle->handle_id);
	janus_ice_queued_packet *pkt = NULL;
	gint64 now = janus_get_monotonic_time(), before = now;
	while(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
		now = janus_get_monotonic_time();
		if(now-before >= G_USEC_PER_SEC) {
			/* First of all, let's see if everything's fine on the recv side */
			if(handle->audio_stream && handle->audio_stream->rtp_component) {
				janus_ice_component *component = handle->audio_stream->rtp_component;
				GList *lastitem = g_list_last(component->in_stats.audio_bytes_lastsec);
				janus_ice_stats_item *last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
				if(!component->in_stats.audio_notified_lastsec && last && now-last->when >= G_USEC_PER_SEC) {
					/* Notify that we missed more than a second of audio! */
					component->in_stats.audio_notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive audio for more than a second...\n", handle->handle_id);
					janus_ice_notify_media(handle, FALSE, FALSE);
				}
				if(!component->in_stats.video_notified_lastsec && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					lastitem = g_list_last(component->in_stats.video_bytes_lastsec);
					last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
					if(last && now-last->when >= G_USEC_PER_SEC) {
						/* Notify that we missed more than a second of video! */
						component->in_stats.video_notified_lastsec = TRUE;
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video for more than a second...\n", handle->handle_id);
						janus_ice_notify_media(handle, TRUE, FALSE);
					}
				}
			}
			if(handle->video_stream && handle->video_stream->rtp_component) {
				janus_ice_component *component = handle->video_stream->rtp_component;
				GList *lastitem = g_list_last(component->in_stats.video_bytes_lastsec);
				janus_ice_stats_item *last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
				if(!component->in_stats.video_notified_lastsec && last && now-last->when >= G_USEC_PER_SEC) {
					/* Notify that we missed more than a second of video! */
					component->in_stats.video_notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video for more than a second...\n", handle->handle_id);
					janus_ice_notify_media(handle, TRUE, FALSE);
				}
			}
			before = now;
		}
		/* Now let's get on with the packets */
		if(handle->queued_packets != NULL)
			pkt = g_async_queue_try_pop(handle->queued_packets);
		if(pkt == NULL) {
			/* Sleep 10ms */
			g_usleep(10000);
			continue;
		}
		if(pkt->data == NULL) {
			g_free(pkt);
			pkt = NULL;
			continue;
		}
		if(pkt->control) {
			/* RTCP */
			int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
			janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (video ? handle->video_stream : handle->audio_stream);
			if(!stream) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			janus_ice_component *component = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) ? stream->rtp_component : stream->rtcp_component;
			if(!component) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			if(!stream->cdone) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !stream->noerrorlog) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     %s candidates not gathered yet for stream??\n", handle->handle_id, video ? "video" : "audio");
					stream->noerrorlog = 1;	/* Don't flood with the same error all over again */
				}
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			stream->noerrorlog = 0;
			if(!component->dtls || !component->dtls->srtp_valid) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]     %s stream (#%u) component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio", stream->stream_id);
					component->noerrorlog = 1;	/* Don't flood with the same error all over again */
				}
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			component->noerrorlog = 0;
			if(pkt->encrypted) {
				/* Already SRTCP */
				int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
				if(sent < pkt->length) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
				}
			} else {
				/* FIXME Copy in a buffer and fix SSRC */
				char sbuf[BUFSIZE];
				memcpy(&sbuf, pkt->data, pkt->length);
				/* Fix all SSRCs! */
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
						video ? stream->video_ssrc : stream->audio_ssrc,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
					janus_rtcp_fix_ssrc((char *)&sbuf, pkt->length, 1,
						video ? stream->video_ssrc : stream->audio_ssrc,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
				} else {
					/* Plan B involved, we trust the plugin to set the right 'local' SSRC and we don't mess with it */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing peer SSRC (Plan B, peer %u)\n", handle->handle_id,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
					janus_rtcp_fix_ssrc((char *)&sbuf, pkt->length, 1, 0,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
				}
				int protected = pkt->length;
				int res = 0;
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
					res = srtp_protect_rtcp(component->dtls->srtp_out, &sbuf, &protected);
				} else {
					/* We need to make sure different sources don't use the SRTP context at the same time */
					janus_mutex_lock(&component->dtls->srtp_mutex);
					res = srtp_protect_rtcp(component->dtls->srtp_out, &sbuf, &protected);
					janus_mutex_unlock(&component->dtls->srtp_mutex);
				}
				//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] ... SRTCP protect %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), pkt->length, protected);
				if(res != err_status_ok) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), pkt->length, protected);
				} else {
					/* Shoot! */
					//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] ... Sending SRTCP packet (pt=%u, seq=%u, ts=%u)...\n", handle->handle_id,
						//~ header->paytype, ntohs(header->seq_number), ntohl(header->timestamp));
					int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const gchar *)&sbuf);
					if(sent < protected) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
					}
				}
			}
			g_free(pkt->data);
			pkt->data = NULL;
			g_free(pkt);
			pkt = NULL;
			continue;
		} else {
			/* RTP or data */
			if(pkt->type == JANUS_ICE_PACKET_AUDIO || pkt->type == JANUS_ICE_PACKET_VIDEO) {
				/* RTP */
				int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
				janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (video ? handle->video_stream : handle->audio_stream);
				if(!stream) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				janus_ice_component *component = stream->rtp_component;
				if(!component) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				if(!stream->cdone) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !stream->noerrorlog) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"]     %s candidates not gathered yet for stream??\n", handle->handle_id, video ? "video" : "audio");
						stream->noerrorlog = 1;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				stream->noerrorlog = 0;
				if(!component->dtls || !component->dtls->srtp_valid) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]     %s stream component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio");
						component->noerrorlog = 1;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				component->noerrorlog = 0;
				if(pkt->encrypted) {
					/* Already RTP (probably a retransmission?) */
					rtp_header *header = (rtp_header *)pkt->data;
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] ... Retransmitting seq.nr %"SCNu16"\n\n", handle->handle_id, ntohs(header->seq_number));
					int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
					if(sent < pkt->length) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
					}
				} else {
					/* FIXME Copy in a buffer and fix SSRC */
					char sbuf[BUFSIZE];
					memcpy(&sbuf, pkt->data, pkt->length);
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
						/* Overwrite SSRC */
						rtp_header *header = (rtp_header *)&sbuf;
						header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
					}
					int protected = pkt->length;
					int res = srtp_protect(component->dtls->srtp_out, &sbuf, &protected);
					//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] ... SRTP protect %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), pkt->length, protected);
					if(res != err_status_ok) {
						rtp_header *header = (rtp_header *)&sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n", handle->handle_id, janus_get_srtp_error(res), pkt->length, protected, timestamp, seq);
					} else {
						/* Shoot! */
						//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] ... Sending SRTP packet (pt=%u, ssrc=%u, seq=%u, ts=%u)...\n", handle->handle_id,
							//~ header->type, ntohl(header->ssrc), ntohs(header->seq_number), ntohl(header->timestamp));
						int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const gchar *)&sbuf);
						if(sent < protected) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
						}
						/* Update stats */
						if(sent > 0) {
							if(pkt->type == JANUS_ICE_PACKET_AUDIO) {
								component->out_stats.audio_bytes += sent;
							} else if(pkt->type == JANUS_ICE_PACKET_VIDEO) {
								component->out_stats.video_bytes += sent;
							}
						}
						/* Save the packet for retransmissions that may be needed later */
						janus_rtp_packet *p = (janus_rtp_packet *)calloc(1, sizeof(janus_rtp_packet));
						p->data = (char *)calloc(protected, sizeof(char));
						memcpy(p->data, (char *)&sbuf, protected);
						p->length = protected;
						p->last_retransmit = 0;
						janus_mutex_lock(&component->mutex);
						component->retransmit_buffer = g_list_append(component->retransmit_buffer, p);
						if(g_list_length(component->retransmit_buffer) > max_nack_queue) {
							/* We only keep a limited window of packets, get rid of the oldest one */
							GList *first = g_list_first(component->retransmit_buffer);
							p = (janus_rtp_packet *)first->data;
							first->data = NULL;
							component->retransmit_buffer = g_list_delete_link(component->retransmit_buffer, first);
							g_free(p->data);
							p->data = NULL;
							g_free(p);
						}
						janus_mutex_unlock(&component->mutex);
					}
				}
			} else {
				/* Data */
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
#ifdef HAVE_SCTP
				janus_ice_stream *stream = handle->data_stream ? handle->data_stream : (handle->audio_stream ? handle->audio_stream : handle->video_stream);
				if(!stream) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				janus_ice_component *component = stream->rtp_component;
				if(!component) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				if(!stream->cdone) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !stream->noerrorlog) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SCTP candidates not gathered yet for stream??\n", handle->handle_id);
						stream->noerrorlog = 1;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				stream->noerrorlog = 0;
				if(!component->dtls) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]     SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
						component->noerrorlog = 1;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				component->noerrorlog = 0;
				janus_dtls_wrap_sctp_data(component->dtls, pkt->data, pkt->length);
#endif
			}
			g_free(pkt->data);
			pkt->data = NULL;
			g_free(pkt);
			pkt = NULL;
			continue;
		}
	}
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] ICE send thread leaving...\n", handle->handle_id);
	g_thread_unref(g_thread_self());
	return NULL;
}

void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len) {
	/* TODO Should we fix something in RTP header stuff too? */
	if(!handle || buf == NULL || len < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)calloc(1, sizeof(janus_ice_queued_packet));
	pkt->data = calloc(len, sizeof(char));
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, pkt);
}

void janus_ice_relay_rtcp(janus_ice_handle *handle, int video, char *buf, int len) {
	if(!handle || buf == NULL || len < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)calloc(1, sizeof(janus_ice_queued_packet));
	pkt->data = calloc(len, sizeof(char));
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = TRUE;
	pkt->encrypted = FALSE;
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, pkt);
}

#ifdef HAVE_SCTP
void janus_ice_relay_data(janus_ice_handle *handle, char *buf, int len) {
	if(!handle || buf == NULL || len < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)calloc(1, sizeof(janus_ice_queued_packet));
	pkt->data = calloc(len, sizeof(char));
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = JANUS_ICE_PACKET_DATA;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, pkt);
}
#endif

void janus_ice_dtls_handshake_done(janus_ice_handle *handle, janus_ice_component *component) {
	if(!handle || !component)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] The DTLS handshake for the component %d in stream %d has been completed\n",
		handle->handle_id, component->component_id, component->stream_id);
	/* Check if all components are ready */
	janus_mutex_lock(&handle->mutex);
	if(handle->audio_stream && !handle->audio_stream->disabled) {
		if(handle->audio_stream->rtp_component && (!handle->audio_stream->rtp_component->dtls ||
				!handle->audio_stream->rtp_component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
		if(handle->audio_stream->rtcp_component && (!handle->audio_stream->rtcp_component->dtls ||
				!handle->audio_stream->rtcp_component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(handle->video_stream && !handle->video_stream->disabled) {
		if(handle->video_stream->rtp_component && (!handle->video_stream->rtp_component->dtls ||
				!handle->video_stream->rtp_component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
		if(handle->video_stream->rtcp_component && (!handle->video_stream->rtcp_component->dtls ||
				!handle->video_stream->rtcp_component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(handle->data_stream && !handle->data_stream->disabled) {
		if(handle->data_stream->rtp_component && (!handle->data_stream->rtp_component->dtls ||
				!handle->data_stream->rtp_component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		/* Already notified */
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] The DTLS handshake has been completed\n", handle->handle_id);
	/* Notify the plugin that the WebRTC PeerConnection is ready to be used */
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin != NULL) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
		if(plugin && plugin->setup_media)
			plugin->setup_media(handle->app_handle);
	}
	/* Also prepare JSON event to notify user/application */
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("webrtcup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	/* Convert to a string */
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding event to queue of messages...\n", handle->handle_id);
	janus_http_event *notification = (janus_http_event *)calloc(1, sizeof(janus_http_event));
	if(notification == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return;
	}
	notification->code = 200;
	notification->payload = event_text;
	notification->allocated = 1;

	g_async_queue_push(session->messages, notification);
}
