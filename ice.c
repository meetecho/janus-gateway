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
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <stun/usages/bind.h>
#include <nice/debug.h>

#include "janus.h"
#include "debug.h"
#include "ice.h"
#include "turnrest.h"
#include "dtls.h"
#include "sdp.h"
#include "rtpsrtp.h"
#include "rtcp.h"
#include "apierror.h"
#include "ip-utils.h"
#include "events.h"

/* STUN server/port, if any */
static char *janus_stun_server = NULL;
static uint16_t janus_stun_port = 0;

char *janus_ice_get_stun_server(void) {
	return janus_stun_server;
}
uint16_t janus_ice_get_stun_port(void) {
	return janus_stun_port;
}


/* TURN server/port and credentials, if any */
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


/* TURN REST API support, if any */
char *janus_ice_get_turn_rest_api(void) {
#ifndef HAVE_LIBCURL
	return NULL;
#else
	return (char *)janus_turnrest_get_backend();
#endif
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

/* Whether BUNDLE support is mandatory or not (false by default) */
static gboolean janus_force_bundle;
void janus_ice_force_bundle(gboolean forced) {
	janus_force_bundle = forced;
	JANUS_LOG(LOG_INFO, "BUNDLE %s going to be forced\n", janus_force_bundle ? "is" : "is NOT");
}
gboolean janus_ice_is_bundle_forced(void) {
	return janus_force_bundle;
}

/* Whether rtcp-mux support is mandatory or not (false by default) */
static gboolean janus_force_rtcpmux;
static gint janus_force_rtcpmux_blackhole_port = 1234;
static gint janus_force_rtcpmux_blackhole_fd = -1;
void janus_ice_force_rtcpmux(gboolean forced) {
	janus_force_rtcpmux = forced;
	JANUS_LOG(LOG_INFO, "rtcp-mux %s going to be forced\n", janus_force_rtcpmux ? "is" : "is NOT");
	if(!janus_force_rtcpmux) {
		/*
		 * Since rtcp-mux is NOT going to be forced, we need to do some magic to get rid of unneeded
		 * RTCP components when rtcp-mux is indeed negotiated when creating a PeerConnection. In
		 * particular, there's no way to remove a component in libnice (you can only remove streams),
		 * and you can read why this is a problem here:
		 * 		https://github.com/meetecho/janus-gateway/issues/154
		 * 		https://github.com/meetecho/janus-gateway/pull/362
		 * This means that, to effectively do that without just ignoring the component, we need
		 * to set a dummy candidate on it to "trick" libnice into thinking ICE is done for it.
		 * Since libnice will still occasionally send keepalives to the dummy peer, and we don't
		 * want it to send messages to a service that might not like it, we create a "blackhole"
		 * UDP server to receive all those keepalives and then just discard them.
		 */
		int blackhole = socket(AF_INET, SOCK_DGRAM, 0);
		if(blackhole < 0) {
			JANUS_LOG(LOG_WARN, "Error creating RTCP component blackhole socket, using port %d instead\n", janus_force_rtcpmux_blackhole_port);
			return;
		}
		fcntl(blackhole, F_SETFL, O_NONBLOCK);
		struct sockaddr_in serveraddr;
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
		serveraddr.sin_port = htons(0);		/* Choose a random port, that works for us */
		if(bind(blackhole, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
			JANUS_LOG(LOG_WARN, "Error binding RTCP component blackhole socket, using port %d instead\n", janus_force_rtcpmux_blackhole_port);
			close(blackhole);
			return;
		}
		socklen_t len = sizeof(serveraddr);
		if(getsockname(blackhole, (struct sockaddr *)&serveraddr, &len) < 0) {
			JANUS_LOG(LOG_WARN, "Error retrieving port assigned to RTCP component blackhole socket, using port %d instead\n", janus_force_rtcpmux_blackhole_port);
			close(blackhole);
			return;
		}
		janus_force_rtcpmux_blackhole_port = ntohs(serveraddr.sin_port);
		JANUS_LOG(LOG_VERB, "  -- RTCP component blackhole socket bound to port %d\n", janus_force_rtcpmux_blackhole_port);
		janus_force_rtcpmux_blackhole_fd = blackhole;
	}
}
gint janus_ice_get_rtcpmux_blackhole_port(void) {
	return janus_force_rtcpmux_blackhole_port;
}
gboolean janus_ice_is_rtcpmux_forced(void) {
	return janus_force_rtcpmux;
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


/* NAT 1:1 stuff */
static gboolean nat_1_1_enabled = FALSE;
void janus_ice_enable_nat_1_1(void) {
	nat_1_1_enabled = TRUE;
}

/* Interface/IP enforce/ignore lists */
GList *janus_ice_enforce_list = NULL, *janus_ice_ignore_list = NULL;
janus_mutex ice_list_mutex;

void janus_ice_enforce_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ice_list_mutex);
	janus_ice_enforce_list = g_list_append(janus_ice_enforce_list, (gpointer)ip);
	janus_mutex_unlock(&ice_list_mutex);
}
gboolean janus_ice_is_enforced(const char *ip) {
	if(ip == NULL || janus_ice_enforce_list == NULL)
		return false;
	janus_mutex_lock(&ice_list_mutex);
	GList *temp = janus_ice_enforce_list;
	while(temp) {
		const char *enforced = (const char *)temp->data;
		if(enforced != NULL && strstr(ip, enforced)) {
			janus_mutex_unlock(&ice_list_mutex);
			return true;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return false;
}

void janus_ice_ignore_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ice_list_mutex);
	janus_ice_ignore_list = g_list_append(janus_ice_ignore_list, (gpointer)ip);
	if(janus_ice_enforce_list != NULL) {
		JANUS_LOG(LOG_WARN, "Added %s to the ICE ignore list, but the ICE enforce list is not empty: the ICE ignore list will not be used\n", ip);
	}
	janus_mutex_unlock(&ice_list_mutex);
}
gboolean janus_ice_is_ignored(const char *ip) {
	if(ip == NULL || janus_ice_ignore_list == NULL)
		return false;
	janus_mutex_lock(&ice_list_mutex);
	GList *temp = janus_ice_ignore_list;
	while(temp) {
		const char *ignored = (const char *)temp->data;
		if(ignored != NULL && strstr(ip, ignored)) {
			janus_mutex_unlock(&ice_list_mutex);
			return true;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return false;
}


/* Frequency of statistics via event handlers (one second by default) */
static int janus_ice_event_stats_period = 1;
void janus_ice_set_event_stats_period(int period) {
	janus_ice_event_stats_period = period;
}
int janus_ice_get_event_stats_period(void) {
	return janus_ice_event_stats_period;
}


/* RTP/RTCP port range */
uint16_t rtp_range_min = 0;
uint16_t rtp_range_max = 0;


/* Helpers to demultiplex protocols */
static gboolean janus_is_dtls(gchar *buf) {
	return ((*buf >= 20) && (*buf <= 64));
}

static gboolean janus_is_rtp(gchar *buf) {
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type < 64) || (header->type >= 96));
}

static gboolean janus_is_rtcp(gchar *buf) {
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type >= 64) && (header->type < 96));
}


#define JANUS_ICE_PACKET_AUDIO	0
#define JANUS_ICE_PACKET_VIDEO	1
#define JANUS_ICE_PACKET_DATA	2
/* Janus enqueued (S)RTP/(S)RTCP packet to send */
typedef struct janus_ice_queued_packet {
	char *data;
	gint length;
	gint type;
	gboolean control;
	gboolean encrypted;
} janus_ice_queued_packet;
/* This is a static, fake, message we use as a trigger to send a DTLS alert */
static janus_ice_queued_packet janus_ice_dtls_alert;


/* Time, in seconds, that should pass with no media (audio or video) being
 * received before Janus notifies you about this with a receiving=false */
#define DEFAULT_NO_MEDIA_TIMER	1
static uint no_media_timer = DEFAULT_NO_MEDIA_TIMER;
void janus_set_no_media_timer(uint timer) {
	no_media_timer = timer;
	if(no_media_timer == 0)
		JANUS_LOG(LOG_VERB, "Disabling no-media timer\n");
	else
		JANUS_LOG(LOG_VERB, "Setting no-media timer to %ds\n", no_media_timer);
}
uint janus_get_no_media_timer(void) {
	return no_media_timer;
}


/* Maximum value, in milliseconds, for the NACK queue/retransmissions (default=300ms) */
#define DEFAULT_MAX_NACK_QUEUE	300
/* Maximum ignore count after retransmission (100ms) */
#define MAX_NACK_IGNORE			100000

static uint max_nack_queue = DEFAULT_MAX_NACK_QUEUE;
void janus_set_max_nack_queue(uint mnq) {
	max_nack_queue = mnq;
	if(max_nack_queue == 0)
		JANUS_LOG(LOG_VERB, "Disabling NACK queue\n");
	else
		JANUS_LOG(LOG_VERB, "Setting max NACK queue to %ds\n", max_nack_queue);
}
uint janus_get_max_nack_queue(void) {
	return max_nack_queue;
}
/* Helper to clean old NACK packets in the buffer when they exceed the queue time limit */
static void janus_cleanup_nack_buffer(gint64 now, janus_ice_stream *stream) {
	if(stream && stream->rtp_component) {
		janus_ice_component *component = stream->rtp_component;
		janus_mutex_lock(&component->mutex);
		if(component->retransmit_buffer) {
			GList *first = g_list_first(component->retransmit_buffer);
			janus_rtp_packet *p = (janus_rtp_packet *)first->data;
			while(p && (now - p->created >= (gint64)max_nack_queue*1000)) {
				/* Packet is too old, get rid of it */
				first->data = NULL;
				component->retransmit_buffer = g_list_delete_link(component->retransmit_buffer, first);
				g_free(p->data);
				p->data = NULL;
				g_free(p);
				first = g_list_first(component->retransmit_buffer);
				p = (janus_rtp_packet *)(first ? first->data : NULL);
			}
		}
		janus_mutex_unlock(&component->mutex);
	}
}


#define SEQ_MISSING_WAIT 12000 /*  12ms */
#define SEQ_NACKED_WAIT 155000 /* 155ms */
/* janus_seq_info list functions */
static void janus_seq_append(janus_seq_info **head, janus_seq_info *new_seq) {
	if(*head == NULL) {
		new_seq->prev = new_seq;
		new_seq->next = new_seq;
		*head = new_seq;
	} else {
		janus_seq_info *last_seq = (*head)->prev;
		new_seq->prev = last_seq;
		new_seq->next = *head;
		(*head)->prev = new_seq;
		last_seq->next = new_seq;
	}
}
static janus_seq_info *janus_seq_pop_head(janus_seq_info **head) {
	janus_seq_info *pop_seq = *head;
	if(pop_seq) {
		janus_seq_info *new_head = pop_seq->next;
		if(pop_seq == new_head || new_head == NULL) {
			*head = NULL;
		} else {
			*head = new_head;
			new_head->prev = pop_seq->prev;
			new_head->prev->next = new_head;
		}
	}
	return pop_seq;
}
static void janus_seq_list_free(janus_seq_info **head) {
	if(!*head)
		return;
	janus_seq_info *cur = *head;
	do {
		janus_seq_info *next = cur->next;
		g_free(cur);
		cur = next;
	} while(cur != *head);
	*head = NULL;
}
static int janus_seq_in_range(guint16 seqn, guint16 start, guint16 len) {
	/* Supports wrapping sequence (easier with int range) */
	int n = seqn;
	int nh = (1<<16) + n;
	int s = start;
	int e = s + len;
	return (s <= n && n < e) || (s <= nh && nh < e);
}


/* Internal method for relaying RTCP messages, optionally filtering them in case they come from plugins */
void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, int video, char *buf, int len, gboolean filter_rtcp);


/* Map of old plugin sessions that have been closed */
static GHashTable *old_plugin_sessions;
static janus_mutex old_plugin_sessions_mutex;
gboolean janus_plugin_session_is_alive(janus_plugin_session *plugin_session) {
	/* Make sure this plugin session is still alive */
	janus_mutex_lock_nodebug(&old_plugin_sessions_mutex);
	janus_plugin_session *result = g_hash_table_lookup(old_plugin_sessions, plugin_session);
	janus_mutex_unlock_nodebug(&old_plugin_sessions_mutex);
	if(result != NULL) {
		JANUS_LOG(LOG_ERR, "Invalid plugin session (%p)\n", plugin_session);
	}
	return (result == NULL);
}

/* Watchdog for removing old handles */
static GHashTable *old_handles = NULL;
static GMainContext *handles_watchdog_context = NULL;
GMainLoop *handles_watchdog_loop = NULL;
GThread *handles_watchdog = NULL;
static janus_mutex old_handles_mutex;

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

	if(janus_force_rtcpmux_blackhole_fd > -1) {
		/* Also read the blackhole socket (unneeded RTCP components keepalives) and dump the packets */
		char buffer[1500];
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);
		ssize_t res = 0;
		do {
			/* Read and ignore */
			res = recvfrom(janus_force_rtcpmux_blackhole_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &len);
		} while(res > -1);
	}

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


static void janus_ice_notify_media(janus_ice_handle *handle, gboolean video, gboolean up) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying that we %s receiving %s\n",
		handle->handle_id, up ? "are" : "are NOT", video ? "video" : "audio");
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("media"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	json_object_set_new(event, "type", json_string(video ? "video" : "audio"));
	json_object_set_new(event, "receiving", up ? json_true() : json_false());
	if(!up && no_media_timer > 1)
		json_object_set_new(event, "seconds", json_integer(no_media_timer));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "media", json_string(video ? "video" : "audio"));
		json_object_set_new(info, "receiving", up ? json_true() : json_false());
		if(!up && no_media_timer > 1)
			json_object_set_new(info, "seconds", json_integer(no_media_timer));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, info);
	}
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
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("hangup"));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
	}
}


/* Trickle helpers */
janus_ice_trickle *janus_ice_trickle_new(janus_ice_handle *handle, const char *transaction, json_t *candidate) {
	if(transaction == NULL || candidate == NULL)
		return NULL;
	janus_ice_trickle *trickle = g_malloc0(sizeof(janus_ice_trickle));
	trickle->handle = handle;
	trickle->received = janus_get_monotonic_time();
	trickle->transaction = g_strdup(transaction);
	trickle->candidate = json_deep_copy(candidate);
	return trickle;
}

gint janus_ice_trickle_parse(janus_ice_handle *handle, json_t *candidate, const char **error) {
	const char *ignore_error = NULL;
	if (error == NULL) {
		error = &ignore_error;
	}
	if(handle == NULL) {
		*error = "Invalid handle";
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	}
	/* Parse trickle candidate */
	if(!json_is_object(candidate) || json_object_get(candidate, "completed") != NULL) {
		JANUS_LOG(LOG_VERB, "No more remote candidates for handle %"SCNu64"!\n", handle->handle_id);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
	} else {
		/* Handle remote candidate */
		json_t *mid = json_object_get(candidate, "sdpMid");
		if(!mid) {
			*error = "Trickle error: missing mandatory element (sdpMid)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
		}
		if(!json_is_string(mid)) {
			*error = "Trickle error: invalid element type (sdpMid should be a string)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		json_t *mline = json_object_get(candidate, "sdpMLineIndex");
		if(!mline) {
			*error = "Trickle error: missing mandatory element (sdpMLineIndex)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
		}
		if(!json_is_integer(mline) || json_integer_value(mline) < 0) {
			*error = "Trickle error: invalid element type (sdpMLineIndex should be an integer)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		json_t *rc = json_object_get(candidate, "candidate");
		if(!rc) {
			*error = "Trickle error: missing mandatory element (candidate)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
		}
		if(!json_is_string(rc)) {
			*error = "Trickle error: invalid element type (candidate should be a string)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Trickle candidate (%s): %s\n", handle->handle_id, json_string_value(mid), json_string_value(rc));
		/* Parse it */
		int sdpMLineIndex = json_integer_value(mline);
		int video = 0, data = 0;
		/* FIXME badly, we should have an array of m-lines in the handle object */
		switch(sdpMLineIndex) {
			case 0:
				if(handle->audio_stream == NULL) {
					video = handle->video_stream ? 1 : 0;
					data = !video;
				}
				break;
			case 1:
				if(handle->audio_stream == NULL) {
					data = 1;
				} else {
					video = handle->video_stream ? 1 : 0;
					data = !video;
				}
				break;
			case 2:
				data = 1;
				break;
			default:
				/* FIXME We don't support more than 3 m-lines right now */
				*error = "Trickle error: invalid element type (sdpMLineIndex not [0,2])";
				return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
#ifndef HAVE_SCTP
		data = 0;
#endif
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)
				&& sdpMLineIndex != 0) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a %s candidate but we're bundling, ignoring...\n", handle->handle_id, json_string_value(mid));
		} else {
			janus_ice_stream *stream = video ? handle->video_stream : (data ? handle->data_stream : handle->audio_stream);
			if(stream == NULL) {
				*error = "Trickle error: invalid element type (no such stream)";
				return JANUS_ERROR_TRICKE_INVALID_STREAM;
			}
			int res = janus_sdp_parse_candidate(stream, json_string_value(rc), 1);
			if(res != 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
				/* FIXME Should we return an error? */
			}
		}
	}
	return 0;
}

void janus_ice_trickle_destroy(janus_ice_trickle *trickle) {
	if(trickle == NULL)
		return;
	trickle->handle = NULL;
	if(trickle->transaction)
		g_free(trickle->transaction);
	trickle->transaction = NULL;
	if(trickle->candidate)
		json_decref(trickle->candidate);
	trickle->candidate = NULL;
	g_free(trickle);
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
	/* libnice debugging is disabled unless explicitly stated */
	nice_debug_disable(TRUE);

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

	/* We keep track of old plugin sessions to avoid problems */
	old_plugin_sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&old_plugin_sessions_mutex);

	/* Start the handles watchdog */
	janus_mutex_init(&old_handles_mutex);
	old_handles = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	handles_watchdog_context = g_main_context_new();
	handles_watchdog_loop = g_main_loop_new(handles_watchdog_context, FALSE);
	GError *error = NULL;
	handles_watchdog = g_thread_try_new("handles watchdog", &janus_ice_handles_watchdog, handles_watchdog_loop, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start handles watchdog...\n", error->code, error->message ? error->message : "??");
		exit(1);
	}
	
#ifdef HAVE_LIBCURL
	/* Initialize the TURN REST API client stack, whether we're going to use it or not */
	janus_turnrest_init();
#endif

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
	if(janus_force_rtcpmux_blackhole_fd > -1)
		close(janus_force_rtcpmux_blackhole_fd);
	old_handles = NULL;
	janus_mutex_unlock(&old_handles_mutex);
#ifdef HAVE_LIBCURL
	janus_turnrest_deinit();
#endif
}

int janus_ice_set_stun_server(gchar *stun_server, uint16_t stun_port) {
	if(stun_server == NULL)
		return 0;	/* No initialization needed */
	if(stun_port == 0)
		stun_port = 3478;
	JANUS_LOG(LOG_INFO, "STUN server to use: %s:%u\n", stun_server, stun_port);
	/* Resolve address to get an IP */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(stun_server, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	janus_stun_server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	if(janus_stun_server == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
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
	/* TODO Use the janus_network_address info to drive the socket creation */
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		JANUS_LOG(LOG_FATAL, "Error creating socket for STUN BINDING test\n");
		return -1;
	}
	struct sockaddr_in address, remote;
	address.sin_family = AF_INET;
	address.sin_port = 0;
	address.sin_addr.s_addr = INADDR_ANY;
	remote.sin_family = AF_INET;
	remote.sin_port = htons(janus_stun_port);
	remote.sin_addr.s_addr = inet_addr(janus_stun_server);
	if(bind(fd, (struct sockaddr *)(&address), sizeof(struct sockaddr)) < 0) {
		JANUS_LOG(LOG_FATAL, "Bind failed for STUN BINDING test\n");
		close(fd);
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, (struct sockaddr*)&remote, sizeof(remote));
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Error sending STUN BINDING test\n");
		close(fd);
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
		close(fd);
		return -1;
	}
	socklen_t addrlen = sizeof(remote);
	bytes = recvfrom(fd, buf, 1500, 0, (struct sockaddr*)&remote, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> Got %d bytes...\n", bytes);
	if(stun_agent_validate (&stun, &msg, buf, bytes, NULL, NULL) != STUN_VALIDATION_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Failed to validate STUN BINDING response\n");
		close(fd);
		return -1;
	}
	StunClass class = stun_message_get_class(&msg);
	StunMethod method = stun_message_get_method(&msg);
	if(class != STUN_RESPONSE || method != STUN_BINDING) {
		JANUS_LOG(LOG_FATAL, "Unexpected STUN response: %d/%d\n", class, method);
		close(fd);
		return -1;
	}
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)&address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr((struct sockaddr *)&address, &addr) != 0 ||
				janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve XOR-MAPPED-ADDRESS...\n");
		} else {
			const char *public_ip = janus_network_address_string_from_buffer(&addr_buf);
			JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", public_ip);
			janus_set_public_ip(public_ip);
			close(fd);
		}
		return 0;
	}
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)&address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr((struct sockaddr *)&address, &addr) != 0 ||
				janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve MAPPED-ADDRESS...\n");
		} else {
			const char *public_ip = janus_network_address_string_from_buffer(&addr_buf);
			JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", public_ip);
			janus_set_public_ip(public_ip);
			close(fd);
		}
		return 0;
	}
	close(fd);
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
	/* Resolve address to get an IP */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(turn_server, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	janus_turn_server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	if(janus_turn_server == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		return -1;
	}
	janus_turn_port = turn_port;
	JANUS_LOG(LOG_VERB, "  >> %s:%u\n", janus_turn_server, janus_turn_port);
	if(janus_turn_user != NULL)
		g_free(janus_turn_user);
	janus_turn_user = NULL;
	if(turn_user)
		janus_turn_user = g_strdup(turn_user);
	if(janus_turn_pwd != NULL)
		g_free(janus_turn_pwd);
	janus_turn_pwd = NULL;
	if(turn_pwd)
		janus_turn_pwd = g_strdup(turn_pwd);
	return 0;
}

int janus_ice_set_turn_rest_api(gchar *api_server, gchar *api_key, gchar *api_method) {
#ifndef HAVE_LIBCURL
	JANUS_LOG(LOG_ERR, "Janus has been nuilt with no libcurl support, TURN REST API unavailable\n");
	return -1; 
#else
	if(api_server != NULL &&
			(strstr(api_server, "http://") != api_server && strstr(api_server, "https://") != api_server)) {
		JANUS_LOG(LOG_ERR, "Invalid TURN REST API backend: not an HTTP address\n");
		return -1;
	}
	janus_turnrest_set_backend(api_server, api_key, api_method);
	JANUS_LOG(LOG_INFO, "TURN REST API backend: %s\n", api_server ? api_server : "(disabled)");
#endif
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
static void janus_ice_stats_queue_free(gpointer data) {
	janus_ice_stats_item *s = (janus_ice_stats_item *)data;
	g_free(s);
}

void janus_ice_stats_reset(janus_ice_stats *stats) {
	if(stats == NULL)
		return;
	stats->audio_packets = 0;
	stats->audio_bytes = 0;
	if(stats->audio_bytes_lastsec)
		g_list_free_full(stats->audio_bytes_lastsec, &janus_ice_stats_queue_free);
	stats->audio_bytes_lastsec = NULL;
	stats->audio_notified_lastsec = FALSE;
	stats->audio_nacks = 0;
	stats->video_packets = 0;
	stats->video_bytes = 0;
	if(stats->video_bytes_lastsec)
		g_list_free_full(stats->video_bytes_lastsec, &janus_ice_stats_queue_free);
	stats->video_bytes_lastsec = NULL;
	stats->video_notified_lastsec = FALSE;
	stats->video_nacks = 0;
	stats->data_packets = 0;
	stats->data_bytes = 0;
	stats->last_slowlink_time = 0;
	stats->sl_nack_period_ts = 0;
	stats->sl_nack_recent_cnt = 0;
}


/* ICE Handles */
janus_ice_handle *janus_ice_handle_create(void *gateway_session, const char *opaque_id) {
	if(gateway_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)gateway_session;
	guint64 handle_id = 0;
	while(handle_id == 0) {
		handle_id = janus_random_uint64();
		if(janus_ice_handle_find(gateway_session, handle_id) != NULL) {
			/* Handle ID already taken, try another one */
			handle_id = 0;
		}
	}
	JANUS_LOG(LOG_INFO, "Creating new handle in session %"SCNu64": %"SCNu64"\n", session->session_id, handle_id);
	janus_ice_handle *handle = (janus_ice_handle *)g_malloc0(sizeof(janus_ice_handle));
	if(handle == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	handle->session = gateway_session;
	if(opaque_id)
		handle->opaque_id = g_strdup(opaque_id);
	handle->created = janus_get_monotonic_time();
	handle->handle_id = handle_id;
	handle->app = NULL;
	handle->app_handle = NULL;
	handle->queued_packets = g_async_queue_new();
	janus_mutex_init(&handle->mutex);

	/* Set up other stuff. */
	if(session->ice_handles == NULL)
		session->ice_handles = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	g_hash_table_insert(session->ice_handles, janus_uint64_dup(handle->handle_id), handle);

	return handle;
}

janus_ice_handle *janus_ice_handle_find(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)gateway_session;
	janus_ice_handle *handle = session->ice_handles ? g_hash_table_lookup(session->ice_handles, &handle_id) : NULL;
	return handle;
}

gint janus_ice_handle_attach_plugin(void *gateway_session, guint64 handle_id, janus_plugin *plugin) {
	if(gateway_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	if(plugin == NULL)
		return JANUS_ERROR_PLUGIN_NOT_FOUND;
	janus_session *session = (janus_session *)gateway_session;
	if(session->destroy)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	if(handle->app != NULL) {
		/* This handle is already attached to a plugin */
		return JANUS_ERROR_PLUGIN_ATTACH;
	}
	int error = 0;
	janus_plugin_session *session_handle = g_malloc0(sizeof(janus_plugin_session));
	if(session_handle == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return JANUS_ERROR_UNKNOWN;	/* FIXME Do we need something like "Internal Server Error"? */
	}
	session_handle->gateway_handle = handle;
	session_handle->plugin_handle = NULL;
	session_handle->stopped = 0;
	plugin->create_session(session_handle, &error);
	if(error) {
		/* TODO Make error struct to pass verbose information */
		return error;
	}
	handle->app = plugin;
	handle->app_handle = session_handle;
	/* Make sure this plugin session is not in the old sessions list */
	janus_mutex_lock(&old_plugin_sessions_mutex);
	g_hash_table_remove(old_plugin_sessions, session_handle);
	janus_mutex_unlock(&old_plugin_sessions_mutex);
	/* Notify event handlers */
	if(janus_events_is_enabled())
		janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE,
			session->session_id, handle_id, "attached", plugin->get_package(), handle->opaque_id);
	return 0;
}

gint janus_ice_handle_destroy(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = (janus_session *)gateway_session;
	janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there */
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
		if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
			if(handle->audio_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
					nice_agent_attach_recv(handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			if(handle->video_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
					nice_agent_attach_recv(handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			if(handle->data_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			g_main_loop_quit(handle->iceloop);
		}
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s\n", plugin_t->get_name());
	/* Actually detach handle... */
	int error = 0;
	janus_mutex_lock(&old_plugin_sessions_mutex);
	/* This is to tell the plugin to stop using this session: we'll get rid of it later */
	handle->app_handle->stopped = 1;
	/* And this is to put the plugin session in the old sessions list, to avoid it being used */
	g_hash_table_insert(old_plugin_sessions, handle->app_handle, handle->app_handle);
	janus_mutex_unlock(&old_plugin_sessions_mutex);
	/* Notify the plugin that the session's over */
	plugin_t->destroy_session(handle->app_handle, &error);
	/* Get rid of the handle now */
	if(g_atomic_int_compare_and_exchange(&handle->dump_packets, 1, 0)) {
		janus_text2pcap_close(handle->text2pcap);
		g_clear_pointer(&handle->text2pcap, janus_text2pcap_free);
	}
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
		if(handle->audio_id > 0) {
			nice_agent_attach_recv(handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
				nice_agent_attach_recv(handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
		}
		if(handle->video_id > 0) {
			nice_agent_attach_recv(handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
				nice_agent_attach_recv(handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
		}
		if(handle->data_id > 0) {
			nice_agent_attach_recv(handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
		}
		g_main_loop_quit(handle->iceloop);
	}

	/* Prepare JSON event to notify user/application */
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("detached"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle_id));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
	janus_session_notify_event(session, event);
	/* We only actually destroy the handle later */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle detached (error=%d), scheduling destruction\n", handle_id, error);
	janus_mutex_lock(&old_handles_mutex);
	g_hash_table_insert(old_handles, janus_uint64_dup(handle->handle_id), handle);
	janus_mutex_unlock(&old_handles_mutex);
	/* Notify event handlers as well */
	if(janus_events_is_enabled())
		janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE,
			session->session_id, handle_id, "detached", plugin_t->get_package(), NULL);
	return error;
}

void janus_ice_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	janus_ice_queued_packet *pkt = NULL;
	while(g_async_queue_length(handle->queued_packets) > 0) {
		pkt = g_async_queue_try_pop(handle->queued_packets);
		if(pkt != NULL && pkt != &janus_ice_dtls_alert) {
			g_free(pkt->data);
			g_free(pkt);
		}
	}
	g_async_queue_unref(handle->queued_packets);
	handle->queued_packets = NULL;
	handle->session = NULL;
	handle->app = NULL;
	if(handle->app_handle != NULL) {
		janus_mutex_lock(&old_plugin_sessions_mutex);
		handle->app_handle->stopped = 1;
		g_hash_table_insert(old_plugin_sessions, handle->app_handle, handle->app_handle);
		handle->app_handle->gateway_handle = NULL;
		handle->app_handle->plugin_handle = NULL;
		g_free(handle->app_handle);
		handle->app_handle = NULL;
		janus_mutex_unlock(&old_plugin_sessions_mutex);
	}
	janus_mutex_unlock(&handle->mutex);
	janus_ice_webrtc_free(handle);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Handle and related resources freed\n", handle->handle_id);
	g_free(handle->opaque_id);
	g_free(handle);
	handle = NULL;
}

void janus_ice_webrtc_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin != NULL) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the hangup because of a %s (%s)\n",
			handle->handle_id, reason, plugin->get_name());
		if(plugin && plugin->hangup_media)
			plugin->hangup_media(handle->app_handle);
		janus_ice_notify_hangup(handle, reason);
	}
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, &janus_ice_dtls_alert);
	if(handle->send_thread == NULL) {
		/* Get rid of the loop */
		if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
			if(handle->audio_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
					nice_agent_attach_recv(handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			if(handle->video_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX))
					nice_agent_attach_recv(handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			if(handle->data_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			gint64 waited = 0;
			while(handle->iceloop && !g_main_loop_is_running(handle->iceloop)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE loop exists but is not running, waiting for it to run\n", handle->handle_id);
				g_usleep (100000);
				waited += 100000;
				if(waited >= G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited a second, that's enough!\n", handle->handle_id);
					break;
				}
			}
			if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forcing ICE loop to quit (%s)\n", handle->handle_id, g_main_loop_is_running(handle->iceloop) ? "running" : "NOT running");
				g_main_loop_quit(handle->iceloop);
				g_main_context_wakeup(handle->icectx);
			}
		}
	}
	handle->icethread = NULL;
}

void janus_ice_webrtc_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
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
	handle->agent_created = 0;
	if(handle->pending_trickles) {
		while(handle->pending_trickles) {
			GList *temp = g_list_first(handle->pending_trickles);
			handle->pending_trickles = g_list_remove_link(handle->pending_trickles, temp);
			janus_ice_trickle *trickle = (janus_ice_trickle *)temp->data;
			g_list_free(temp);
			janus_ice_trickle_destroy(trickle);
		}
	}
	handle->pending_trickles = NULL;
	g_free(handle->rtp_profile);
	handle->rtp_profile = NULL;
	g_free(handle->local_sdp);
	handle->local_sdp = NULL;
	g_free(handle->remote_sdp);
	handle->remote_sdp = NULL;
	if(handle->audio_mid != NULL) {
		g_free(handle->audio_mid);
		handle->audio_mid = NULL;
	}
	if(handle->video_mid != NULL) {
		g_free(handle->video_mid);
		handle->video_mid = NULL;
	}
	if(handle->data_mid != NULL) {
		g_free(handle->data_mid);
		handle->data_mid = NULL;
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] WebRTC resources freed\n", handle->handle_id);
}

void janus_ice_stream_free(GHashTable *streams, janus_ice_stream *stream) {
	if(stream == NULL)
		return;
	if(streams != NULL)
		g_hash_table_remove(streams, GUINT_TO_POINTER(stream->stream_id));
	if(stream->components != NULL) {
		janus_ice_component_free(stream->components, stream->rtp_component);
		stream->rtp_component = NULL;
		janus_ice_component_free(stream->components, stream->rtcp_component);
		stream->rtcp_component = NULL;
		g_hash_table_destroy(stream->components);
	}
	stream->handle = NULL;
	if(stream->remote_hashing != NULL) {
		g_free(stream->remote_hashing);
		stream->remote_hashing = NULL;
	}
	if(stream->remote_fingerprint != NULL) {
		g_free(stream->remote_fingerprint);
		stream->remote_fingerprint = NULL;
	}
	if(stream->ruser != NULL) {
		g_free(stream->ruser);
		stream->ruser = NULL;
	}
	if(stream->rpass != NULL) {
		g_free(stream->rpass);
		stream->rpass = NULL;
	}
	g_free(stream->rid[0]);
	stream->rid[0] = NULL;
	g_free(stream->rid[1]);
	stream->rid[1] = NULL;
	g_free(stream->rid[2]);
	stream->rid[2] = NULL;
	g_list_free(stream->audio_payload_types);
	stream->audio_payload_types = NULL;
	g_list_free(stream->video_payload_types);
	stream->video_payload_types = NULL;
	g_free(stream->audio_rtcp_ctx);
	stream->audio_rtcp_ctx = NULL;
	g_free(stream->video_rtcp_ctx);
	stream->video_rtcp_ctx = NULL;
	stream->audio_first_ntp_ts = 0;
	stream->audio_first_rtp_ts = 0;
	stream->video_first_ntp_ts = 0;
	stream->video_first_rtp_ts = 0;
	stream->audio_last_ts = 0;
	stream->video_last_ts = 0;
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
		g_hash_table_remove(components, GUINT_TO_POINTER(component->component_id));
	component->stream = NULL;
	if(component->icestate_source != NULL) {
		g_source_destroy(component->icestate_source);
		g_source_unref(component->icestate_source);
		component->icestate_source = NULL;
	}
	if(component->dtlsrt_source != NULL) {
		g_source_destroy(component->dtlsrt_source);
		g_source_unref(component->dtlsrt_source);
		component->dtlsrt_source = NULL;
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
	if(component->last_seqs_audio)
		janus_seq_list_free(&component->last_seqs_audio);
	if(component->last_seqs_video)
		janus_seq_list_free(&component->last_seqs_video);
	janus_ice_stats_reset(&component->in_stats);
	janus_ice_stats_reset(&component->out_stats);
	g_free(component);
	//~ janus_mutex_unlock(&handle->mutex);
}

/* Call plugin slow_link callback if enough NACKs within a second */
#define SLOW_LINK_NACKS_PER_SEC 8
static void
janus_slow_link_update(janus_ice_component *component, janus_ice_handle *handle,
		guint nacks, int video, int uplink, gint64 now) {
	/* We keep the counters in different janus_ice_stats objects, depending on the direction */
	gint64 sl_nack_period_ts = uplink ? component->in_stats.sl_nack_period_ts : component->out_stats.sl_nack_period_ts;
	/* Is the NACK too old? */
	if(now-sl_nack_period_ts > 2*G_USEC_PER_SEC) {
		/* Old nacks too old, don't count them */
		if(uplink) {
			component->in_stats.sl_nack_period_ts = now;
			component->in_stats.sl_nack_recent_cnt = 0;
		} else {
			component->out_stats.sl_nack_period_ts = now;
			component->out_stats.sl_nack_recent_cnt = 0;
		}
	}
	if(uplink) {
		component->in_stats.sl_nack_recent_cnt += nacks;
	} else {
		component->out_stats.sl_nack_recent_cnt += nacks;
	}
	gint64 last_slowlink_time = uplink ? component->in_stats.last_slowlink_time : component->out_stats.last_slowlink_time;
	guint sl_nack_recent_cnt = uplink ? component->in_stats.sl_nack_recent_cnt : component->out_stats.sl_nack_recent_cnt;
	if((sl_nack_recent_cnt >= SLOW_LINK_NACKS_PER_SEC) && (now-last_slowlink_time > 1*G_USEC_PER_SEC)) {
		/* Tell the plugin */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin && plugin->slow_link && janus_plugin_session_is_alive(handle->app_handle))
			plugin->slow_link(handle->app_handle, uplink, video);
		/* Notify the user/application too */
		janus_session *session = (janus_session *)handle->session;
		if(session != NULL) {
			json_t *event = json_object();
			json_object_set_new(event, "janus", json_string("slowlink"));
			json_object_set_new(event, "session_id", json_integer(session->session_id));
			json_object_set_new(event, "sender", json_integer(handle->handle_id));
			json_object_set_new(event, "uplink", uplink ? json_true() : json_false());
			json_object_set_new(event, "nacks", json_integer(sl_nack_recent_cnt));
			/* Send the event */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
			janus_session_notify_event(session, event);
			/* Finally, notify event handlers */
			if(janus_events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "media", json_string(video ? "video" : "audio"));
				json_object_set_new(info, "slow_link", json_string(uplink ? "uplink" : "downlink"));
				json_object_set_new(info, "nacks_lastsec", json_integer(sl_nack_recent_cnt));
				janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, info);
			}
		}
		/* Update the counters */
		if(uplink) {
			component->in_stats.last_slowlink_time = now;
			component->in_stats.sl_nack_period_ts = now;
			component->in_stats.sl_nack_recent_cnt = 0;
		} else {
			component->out_stats.last_slowlink_time = now;
			component->out_stats.sl_nack_period_ts = now;
			component->out_stats.sl_nack_recent_cnt = 0;
		}
	}
}


/* ICE state check timer (needed to check if a failed really is definitive or if things can still improve) */
static gboolean janus_ice_check_failed(gpointer data) {
	janus_ice_component *component = (janus_ice_component *)data;
	if(component == NULL)
		return FALSE;
	janus_ice_stream *stream = component->stream;
	if(!stream)
		goto stoptimer;
	janus_ice_handle *handle = stream->handle;
	if(!handle)
		goto stoptimer;
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) ||
			janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		goto stoptimer;
	if(component->state == NICE_COMPONENT_STATE_CONNECTED || component->state == NICE_COMPONENT_STATE_READY) {
		/* ICE succeeded in the meanwhile, get rid of this timer */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE succeeded, disabling ICE state check timer!\n", handle->handle_id);
		goto stoptimer;
	}
	/* Still in the failed state, how much time passed since we first detected it? */
	if(janus_get_monotonic_time() - component->icefailed_detected < 5*G_USEC_PER_SEC) {
		/* Let's wait a little longer */
		return TRUE;
	}
	/* If we got here it means the timer expired, and we should check if this is a failure */
	gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
	gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	/* We may still be waiting for something... but we don't wait forever */
	gboolean do_wait = TRUE;
	if(janus_get_monotonic_time() - component->icefailed_detected >= 15*G_USEC_PER_SEC) {
		do_wait = FALSE;
	}
	if(!do_wait || (handle && trickle_recv && answer_recv && !alert_set)) {
		/* FIXME Should we really give up for what may be a failure in only one of the media? */
		if(stream->disabled) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but stream is disabled so we don't care...\n",
				handle->handle_id, component->component_id, stream->stream_id);
			goto stoptimer;
		}
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n",
			handle->handle_id, component->component_id, stream->stream_id);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin != NULL) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
			if(plugin && plugin->hangup_media)
				plugin->hangup_media(handle->app_handle);
		}
		janus_ice_notify_hangup(handle, "ICE failed");
		goto stoptimer;
	}
	/* Let's wait a little longer */
	JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but we're still waiting for some info so we don't care... (trickle %s, answer %s, alert %s)\n",
		handle->handle_id, component->component_id, stream->stream_id,
		trickle_recv ? "received" : "pending",
		answer_recv ? "received" : "pending",
		alert_set ? "set" : "not set");
	return TRUE;

stoptimer:
	if(component->icestate_source != NULL) {
		g_source_destroy(component->icestate_source);
		g_source_unref(component->icestate_source);
		component->icestate_source = NULL;
	}
	return FALSE;
}

/* Callbacks */
static void janus_ice_cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
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

static void janus_ice_cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice) {
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
	if(component_id > 1 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
		/* State changed for a component we don't need anymore (rtcp-mux) */
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component state changed for component %d in stream %d: %d (%s)\n",
		handle->handle_id, component_id, stream_id, state, janus_get_ice_state_name(state));
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
	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "ice", json_string(janus_get_ice_state_name(state)));
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
	}
	/* Handle new state */
	if((state == NICE_COMPONENT_STATE_CONNECTED || state == NICE_COMPONENT_STATE_READY)
			&& handle->send_thread == NULL) {
		/* Make sure we're not trying to start the thread more than once */
		if(!g_atomic_int_compare_and_exchange(&handle->send_thread_created, 0, 1)) {
			return;
		}
		/* Start the outgoing data thread */
		GError *error = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "icesend %"SCNu64, handle->handle_id);
		handle->send_thread = g_thread_try_new(tname, &janus_ice_send_thread, handle, &error);
		if(error != NULL) {
			/* FIXME We should clear some resources... */
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the ICE send thread...\n", handle->handle_id, error->code, error->message ? error->message : "??");
			return;
		}
	}
	/* FIXME Even in case the state is 'connected', we wait for the 'new-selected-pair' callback to do anything */
	if(state == NICE_COMPONENT_STATE_FAILED) {
		/* Failed doesn't mean necessarily we need to give up: we may be trickling */
		gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		if(alert_set)
			return;
		gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
		gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but let's give it some time... (trickle %s, answer %s, alert %s)\n",
			handle->handle_id, component_id, stream_id,
			trickle_recv ? "received" : "pending",
			answer_recv ? "received" : "pending",
			alert_set ? "set" : "not set");
		/* In case we haven't started a timer yet, let's do it now */
		if(component->icestate_source == NULL && component->icefailed_detected == 0) {
			component->icefailed_detected = janus_get_monotonic_time();
			component->icestate_source = g_timeout_source_new(500);
			g_source_set_callback(component->icestate_source, janus_ice_check_failed, component, NULL);
			guint id = g_source_attach(component->icestate_source, handle->icectx);
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating ICE state check timer with ID %u\n", handle->handle_id, id);
		}
	}
}

#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, gchar *local, gchar *remote, gpointer ice) {
#else
static void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local, NiceCandidate *remote, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
	if(component_id > 1 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
		/* New selected pair for a component we don't need anymore (rtcp-mux) */
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local, remote);
#else
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local->foundation, remote->foundation);
#endif
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
	gchar *prev_selected_pair = component->selected_pair;
	component->selected_pair = g_strdup(sp);
	g_clear_pointer(&prev_selected_pair, g_free);
	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "selected-pair", json_string(sp));
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
	}
	/* Now we can start the DTLS handshake (FIXME This was on the 'connected' state notification, before) */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready enough, starting DTLS handshake...\n", handle->handle_id);
	/* Have we been here before? (might happen, when trickling) */
	if(component->dtls != NULL)
		return;
	component->component_connected = janus_get_monotonic_time();
	/* Create DTLS-SRTP context, at last */
	component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
	if(!component->dtls) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component DTLS-SRTP session??\n", handle->handle_id);
		return;
	}
	janus_dtls_srtp_handshake(component->dtls);
	/* Create retransmission timer */
	component->dtlsrt_source = g_timeout_source_new(100);
	g_source_set_callback(component->dtlsrt_source, janus_dtls_retry, component->dtls, NULL);
	guint id = g_source_attach(component->dtlsrt_source, handle->icectx);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
}

#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer ice) {
#else
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new remote candidate for component %d in stream %d: foundation=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, foundation);
#else
	const char *ctype = NULL;
	switch(candidate->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			ctype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			ctype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			ctype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			ctype = "relay";
			break;
		default:
			break;
	}
	guint stream_id = candidate->stream_id;
	guint component_id = candidate->component_id;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new remote candidate for component %d in stream %d: type=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, ctype);
#endif
	if(!handle)
		return;
	if(component_id > 1 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX)) {
		/* New remote candidate for a component we don't need anymore (rtcp-mux) */
		return;
	}
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
#ifndef HAVE_LIBNICE_TCP
	/* Get remote candidates and look for the related foundation */
	NiceCandidate *candidate = NULL;
	GSList *candidates = nice_agent_get_remote_candidates(agent, component_id, stream_id), *tmp = candidates;
	while(tmp) {
		NiceCandidate *c = (NiceCandidate *)tmp->data;
		if(candidate == NULL) {
			/* Check if this is what we're looking for */
			if(!strcasecmp(c->foundation, foundation)) {
				/* It is! */
				candidate = c;
				tmp = tmp->next;
				continue;
			}
		}
		nice_candidate_free(c);
		tmp = tmp->next;
	}
	g_slist_free(candidates);
	if(candidate == NULL) {
		JANUS_LOG(LOG_WARN, "Candidate with foundation %s not found?\n", foundation);
		return;
	}
#endif
	/* Render the candidate and add it to the remote_candidates cache for the admin API */
	if(candidate->type != NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
		/* ... but only if it's 'prflx', the others we add ourselves */
		goto candidatedone;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Stream #%d, Component #%d\n", handle->handle_id, candidate->stream_id, candidate->component_id);
	gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
	gint port = 0, base_port = 0;
	nice_address_to_string(&(candidate->addr), (gchar *)&address);
	port = nice_address_get_port(&(candidate->addr));
	nice_address_to_string(&(candidate->base_addr), (gchar *)&base_address);
	base_port = nice_address_get_port(&(candidate->base_addr));
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, candidate->priority);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, candidate->foundation);
	char buffer[100];
	if(candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
		g_snprintf(buffer, 100,
			"%s %d %s %d %s %d typ prflx raddr %s rport %d\r\n", 
				candidate->foundation,
				candidate->component_id,
				"udp",
				candidate->priority,
				address,
				port,
				base_address,
				base_port);
	} else {
		if(!janus_ice_tcp_enabled) {
			/* ICETCP support disabled */
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, ICETCP support disabled...\n", handle->handle_id);
			goto candidatedone;
		}
#ifndef HAVE_LIBNICE_TCP
		/* TCP candidates are only supported since libnice 0.1.8 */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			goto candidatedone;
#else
		const char *type = NULL;
		switch(candidate->transport) {
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
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping nonUDP/TCP prflx candidate...\n", handle->handle_id);
			goto candidatedone;
		} else {
			g_snprintf(buffer, 100,
				"%s %d %s %d %s %d typ prflx raddr %s rport %d tcptype %s\r\n",
					candidate->foundation,
					candidate->component_id,
					"tcp",
					candidate->priority,
					address,
					port,
					base_address,
					base_port,
					type);
		}
#endif
	}

	/* Save for the summary, in case we need it */
	component->remote_candidates = g_slist_append(component->remote_candidates, g_strdup(buffer));

	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "remote-candidate", json_string(buffer));
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
	}

candidatedone:
#ifndef HAVE_LIBNICE_TCP
	nice_candidate_free(candidate);
#endif
	return;
}

static void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
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
	janus_session *session = (janus_session *)handle->session;
	if(!component->dtls) {	/* Still waiting for the DTLS stack */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Still waiting for the DTLS stack for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
		return;
	}
	/* What is this? */
	if (janus_is_dtls(buf) || (!janus_is_rtp(buf) && !janus_is_rtcp(buf))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Looks like DTLS!\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		component->in_stats.data_packets++;
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
		if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			janus_rtp_header *header = (janus_rtp_header *)buf;
			guint32 packet_ssrc = ntohl(header->ssrc);
			/* Is this audio or video? */
			int video = 0;
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
				/* Easy enough */
				video = (stream->stream_id == handle->video_id ? 1 : 0);
			} else {
				/* Bundled streams, check SSRC */
				video = ((stream->video_ssrc_peer == packet_ssrc
					|| stream->video_ssrc_peer_rtx == packet_ssrc
					|| stream->video_ssrc_peer_sim_1 == packet_ssrc
					|| stream->video_ssrc_peer_sim_2 == packet_ssrc) ? 1 : 0);
				if(!video && stream->audio_ssrc_peer != packet_ssrc) {
					/* FIXME In case it happens, we should check what it is */
					if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer == 0) {
						/* Apparently we were not told the peer SSRCs, try to guess from the payload type */
						gboolean found = FALSE;
						guint16 pt = header->type;
						if(stream->audio_ssrc_peer == 0 && stream->audio_payload_types) {
							GList *pts = stream->audio_payload_types;
							while(pts) {
								guint16 audio_pt = GPOINTER_TO_UINT(pts->data);
								if(pt == audio_pt) {
									JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unadvertized SSRC (%"SCNu32") is audio! (payload type %"SCNu16")\n", handle->handle_id, packet_ssrc, pt);
									video = 0;
									stream->audio_ssrc_peer = packet_ssrc;
									found = TRUE;
									break;
								}
								pts = pts->next;
							}
						}
						if(!found && stream->video_ssrc_peer == 0 && stream->video_payload_types) {
							GList *pts = stream->video_payload_types;
							while(pts) {
								guint16 video_pt = GPOINTER_TO_UINT(pts->data);
								if(pt == video_pt) {
									JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unadvertized SSRC (%"SCNu32") is video! (payload type %"SCNu16")\n", handle->handle_id, packet_ssrc, pt);
									video = 1;
									stream->video_ssrc_peer = packet_ssrc;
									found = TRUE;
									break;
								}
								pts = pts->next;
							}
						}
					}
					if(!video && stream->audio_ssrc_peer != packet_ssrc) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Not video and not audio? dropping (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
						return;
					}
				}
				if(stream->video_ssrc_peer_rtx == packet_ssrc) {
					/* FIXME This is a video retransmission: set the regular peer SSRC so
					 * that we avoid outgoing SRTP errors in case we got the packet already */
					header->ssrc = htonl(stream->video_ssrc_peer);
				} else if(stream->video_ssrc_peer_sim_1 == packet_ssrc) {
					/* FIXME Simulcast (1) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #1 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
				} else if(stream->video_ssrc_peer_sim_2 == packet_ssrc) {
					/* FIXME Simulcast (2) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #2 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
				}
				//~ JANUS_LOG(LOG_VERB, "[RTP] Bundling: this is %s (video=%"SCNu64", audio=%"SCNu64", got %ld)\n",
					//~ video ? "video" : "audio", stream->video_ssrc_peer, stream->audio_ssrc_peer, ntohl(header->ssrc));
			}

			int buflen = len;
			srtp_err_status_t res = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
			if(res != srtp_err_status_ok) {
				if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
					/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
					janus_rtp_header *header = (janus_rtp_header *)buf;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n", handle->handle_id, janus_srtp_error_str(res), len, buflen, timestamp, seq);
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
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, TRUE, buf, buflen,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* Pass the data to the responsible plugin */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp)
					plugin->incoming_rtp(handle->app_handle, video, buf, buflen);
				/* Update stats (TODO Do the same for the last second window as well) */
				if(buflen > 0) {
					/* Update the last sec queue as well */
					janus_ice_stats_item *s = g_malloc0(sizeof(janus_ice_stats_item));
					s->bytes = buflen;
					s->when = janus_get_monotonic_time();
					janus_mutex_lock(&component->mutex);
					if(!video) {
						if(component->in_stats.audio_bytes == 0 || component->in_stats.audio_notified_lastsec) {
							/* We either received our first audio packet, or we started receiving it again after missing more than a second */
							component->in_stats.audio_notified_lastsec = FALSE;
							janus_ice_notify_media(handle, FALSE, TRUE);
						}
						component->in_stats.audio_packets++;
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
						component->in_stats.video_packets++;
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

				/* FIXME Don't handle RTCP or stats for the simulcasted SSRCs, for now */
				if(video && packet_ssrc != stream->video_ssrc_peer)
					return;

				/* Update the RTCP context as well */
				rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx : stream->audio_rtcp_ctx;
				janus_rtcp_process_incoming_rtp(rtcp_ctx, buf, buflen);

				/* Keep track of RTP sequence numbers, in case we need to NACK them */
				/* 	Note: unsigned int overflow/underflow wraps (defined behavior) */
				if((!video && !component->do_audio_nacks) || (video && !component->do_video_nacks)) {
					/* ... unless NACKs are disabled for this medium */
					return;
				}
				guint16 new_seqn = ntohs(header->seq_number);
				guint16 cur_seqn;
				int last_seqs_len = 0;
				janus_mutex_lock(&component->mutex);
				janus_seq_info **last_seqs = video ? &component->last_seqs_video : &component->last_seqs_audio;
				janus_seq_info *cur_seq = *last_seqs;
				if(cur_seq) {
					cur_seq = cur_seq->prev;
					cur_seqn = cur_seq->seq;
				} else {
					/* First seq, set up to add one seq */
					cur_seqn = new_seqn - (guint16)1; /* Can wrap */
				}
				if(!janus_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN) &&
						!janus_seq_in_range(cur_seqn, new_seqn, 1000)) {
					/* Jump too big, start fresh */
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Big sequence number jump %hu -> %hu (%s stream)\n",
						handle->handle_id, cur_seqn, new_seqn, video ? "video" : "audio");
					janus_seq_list_free(last_seqs);
					cur_seq = NULL;
					cur_seqn = new_seqn - (guint16)1;
				}

				GSList *nacks = NULL;
				gint64 now = janus_get_monotonic_time();

				if(janus_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN)) {
					/* Add new seq objs forward */
					while(cur_seqn != new_seqn) {
						cur_seqn += (guint16)1; /* can wrap */
						janus_seq_info *seq_obj = g_malloc0(sizeof(janus_seq_info));
						seq_obj->seq = cur_seqn;
						seq_obj->ts = now;
						seq_obj->state = (cur_seqn == new_seqn) ? SEQ_RECVED : SEQ_MISSING;
						janus_seq_append(last_seqs, seq_obj);
						last_seqs_len++;
					}
				}
				if(cur_seq) {
					/* Scan old seq objs backwards */
					while(cur_seq != NULL) {
						last_seqs_len++;
						if(cur_seq->seq == new_seqn) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received missed sequence number %"SCNu16"\n", handle->handle_id, cur_seq->seq);
							cur_seq->state = SEQ_RECVED;
						} else if(cur_seq->state == SEQ_MISSING && now - cur_seq->ts > SEQ_MISSING_WAIT) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16", sending 1st NACK\n", handle->handle_id, cur_seq->seq);
							nacks = g_slist_append(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_NACKED;
						} else if(cur_seq->state == SEQ_NACKED  && now - cur_seq->ts > SEQ_NACKED_WAIT) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16", sending 2nd NACK\n", handle->handle_id, cur_seq->seq);
							nacks = g_slist_append(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_GIVEUP;
						}
						if(cur_seq == *last_seqs) {
							/* Just processed head */
							break;
						}
						cur_seq = cur_seq->prev;
					}
				}
				while(last_seqs_len > LAST_SEQS_MAX_LEN) {
					janus_seq_info *node = janus_seq_pop_head(last_seqs);
					g_free(node);
					last_seqs_len--;
				}

				guint nacks_count = g_slist_length(nacks);
				if(nacks_count) {
					/* Generate a NACK and send it */
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] now sending NACK for %u missed packets\n", handle->handle_id, nacks_count);
					char nackbuf[120];
					int res = janus_rtcp_nacks(nackbuf, sizeof(nackbuf), nacks);
					if(res > 0)
						janus_ice_relay_rtcp_internal(handle, video, nackbuf, res, FALSE);
					/* Update stats */
					component->nack_sent_recent_cnt += nacks_count;
					if(video) {
						component->out_stats.video_nacks += nacks_count;
					} else {
						component->out_stats.audio_nacks += nacks_count;
					}
					/* Inform the plugin about the slow downlink in case it's needed */
					janus_slow_link_update(component, handle, nacks_count, video, 0, now);
				}
				if (component->nack_sent_recent_cnt &&
				    now - component->nack_sent_log_ts > 5 * G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%10"SCNu64"]  sent NACKs for %u missing packets\n",
					                      handle->handle_id, component->nack_sent_recent_cnt);
					component->nack_sent_recent_cnt = 0;
					component->nack_sent_log_ts = now;
				}
				janus_mutex_unlock(&component->mutex);
				g_slist_free(nacks);
				nacks = NULL;
			}
		}
		return;
	}
	if(component_id == 2 || (component_id == 1 && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && janus_is_rtcp(buf))) {
		/* FIXME A second component is always RTCP; in case of rtcp-mux, we need to check */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTCP packet (%s stream)!\n", handle->handle_id,
			janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? "bundled" : (stream->stream_id == handle->audio_id ? "audio" : "video"));
		if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			srtp_err_status_t res = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
			if(res != srtp_err_status_ok) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTCP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_srtp_error_str(res), len, buflen);
			} else {
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, TRUE, buf, buflen,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* Check if there's an RTCP BYE: in case, let's wrap up */
				if(janus_rtcp_has_bye(buf, buflen)) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got RTCP BYE on stream %"SCNu16" (component %"SCNu16"), closing...\n", handle->handle_id, stream->stream_id, component->component_id);
					janus_ice_webrtc_hangup(handle, "RTCP BYE");
					return;
				}
				/* Is this audio or video? */
				int video = 0;
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					/* Easy enough */
					video = (stream->stream_id == handle->video_id ? 1 : 0);
				} else {
					/* Bundled streams, should we check the SSRCs? */
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
						/* No audio has been negotiated, definitely video */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is video (no audio has been negotiated)\n", handle->handle_id);
						video = 1;
					} else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
						/* No video has been negotiated, definitely audio */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is audio (no video has been negotiated)\n", handle->handle_id);
						video = 0;
					} else {
						if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer == 0) {
							/* We don't know the remote SSRC: this can happen for recvonly clients
							 * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
							 * Check the local SSRC, compare it to what we have */
							guint32 rtcp_ssrc = janus_rtcp_get_receiver_ssrc(buf, len);
							if(rtcp_ssrc == stream->audio_ssrc) {
								video = 0;
							} else if(rtcp_ssrc == stream->video_ssrc) {
								video = 1;
							} else {
								/* Mh, no SR or RR? Try checking if there's any FIR, PLI or REMB */
								if(janus_rtcp_has_fir(buf, len) || janus_rtcp_has_pli(buf, len) || janus_rtcp_get_remb(buf, len)) {
									video = 1;
								}
							}
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (local SSRC: video=%"SCNu32", audio=%"SCNu32", got %"SCNu32")\n",
								handle->handle_id, video ? "video" : "audio", stream->video_ssrc, stream->audio_ssrc, rtcp_ssrc);
						} else {
							/* Check the remote SSRC, compare it to what we have */
							guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, len);
							if(rtcp_ssrc == stream->audio_ssrc_peer) {
								video = 0;
							} else if(rtcp_ssrc == stream->video_ssrc_peer) {
								video = 1;
							} else {
								/* If we're simulcasting, let's compare to the other SSRCs too */
								if((stream->video_ssrc_peer_sim_1 && rtcp_ssrc == stream->video_ssrc_peer_sim_1) ||
										(stream->video_ssrc_peer_sim_2 && rtcp_ssrc == stream->video_ssrc_peer_sim_2)) {
									/* FIXME RTCP for simulcasting SSRC, let's drop it for now... */
									JANUS_LOG(LOG_HUGE, "Dropping RTCP packet for SSRC %"SCNu32"\n", rtcp_ssrc);
									return;
								}
							}
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (remote SSRC: video=%"SCNu32", audio=%"SCNu32", got %"SCNu32")\n",
								handle->handle_id, video ? "video" : "audio", stream->video_ssrc_peer, stream->audio_ssrc_peer, rtcp_ssrc);
						}
					}
				}

				/* Let's process this RTCP (compound?) packet, and update the RTCP context for this stream in case */
				rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx : stream->audio_rtcp_ctx;
				janus_rtcp_parse(rtcp_ctx, buf, buflen);

				/* Now let's see if there are any NACKs to handle */
				gint64 now = janus_get_monotonic_time();
				GSList *nacks = janus_rtcp_get_nacks(buf, buflen);
				guint nacks_count = g_slist_length(nacks);
				if(nacks_count && ((!video && component->do_audio_nacks) || (video && component->do_video_nacks))) {
					/* Handle NACK */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"]     Just got some NACKS (%d) we should handle...\n", handle->handle_id, nacks_count);
					GSList *list = nacks;
					int retransmits_cnt = 0;
					janus_mutex_lock(&component->mutex);
					while(list) {
						unsigned int seqnr = GPOINTER_TO_UINT(list->data);
						JANUS_LOG(LOG_DBG, "[%"SCNu64"]   >> %u\n", handle->handle_id, seqnr);
						GList *rp = component->retransmit_buffer;
						while(rp) {
							janus_rtp_packet *p = (janus_rtp_packet *)rp->data;
							if(p) {
								janus_rtp_header *rh = (janus_rtp_header *)p->data;
								if(ntohs(rh->seq_number) == seqnr) {
									/* Should we retransmit this packet? */
									if((p->last_retransmit > 0) && (now-p->last_retransmit < MAX_NACK_IGNORE)) {
										JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"ms ago, skipping\n", handle->handle_id, seqnr, now-p->last_retransmit);
										break;
									}
									JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission due to NACK\n", handle->handle_id, seqnr);
									p->last_retransmit = now;
									retransmits_cnt++;
									/* Enqueue it */
									janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)g_malloc0(sizeof(janus_ice_queued_packet));
									pkt->data = g_malloc0(p->length);
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
					component->retransmit_recent_cnt += retransmits_cnt;
					/* FIXME Remove the NACK compound packet, we've handled it */
					buflen = janus_rtcp_remove_nacks(buf, buflen);
					/* Update stats */
					if(video) {
						component->in_stats.video_nacks += nacks_count;
					} else {
						component->in_stats.audio_nacks += nacks_count;
					}
					/* Inform the plugin about the slow uplink in case it's needed */
					janus_slow_link_update(component, handle, retransmits_cnt, video, 1, now);
					janus_mutex_unlock(&component->mutex);
					g_slist_free(nacks);
					nacks = NULL;
				}
				if (component->retransmit_recent_cnt &&
				    now - component->retransmit_log_ts > 5 * G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%10"SCNu64"]  retransmitted %u packets due to NACK\n",
					                      handle->handle_id,    component->retransmit_recent_cnt);
					component->retransmit_recent_cnt = 0;
					component->retransmit_log_ts = now;
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
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Not RTP and not RTCP... may these be data channels?\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		if(len > 0) {
			component->in_stats.data_packets++;
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
	JANUS_LOG(LOG_DBG, "[%"SCNu64"] Looping (ICE)...\n", handle->handle_id);
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
void janus_ice_candidates_to_sdp(janus_ice_handle *handle, janus_sdp_mline *mline, guint stream_id, guint component_id)
{
	if(!handle || !handle->agent || !mline)
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
	char *host_ip = NULL;
	if(nat_1_1_enabled) {
		/* A 1:1 NAT mapping was specified, overwrite all the host addresses with the public IP */
		host_ip = janus_get_public_ip();
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Public IP specified and 1:1 NAT mapping enabled (%s), using that as host address in the candidates\n", handle->handle_id, host_ip);
	}
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	gboolean log_candidates = (component->local_candidates == NULL);
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
		gchar buffer[200];
		if(c->type == NICE_CANDIDATE_TYPE_HOST) {
			/* 'host' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				g_snprintf(buffer, sizeof(buffer),
					"%s %d %s %d %s %d typ host",
						c->foundation,
						c->component_id,
						"udp",
						c->priority,
						host_ip ? host_ip : address,
						port);
			} else {
				if(!janus_ice_tcp_enabled) {
					/* ICE-TCP support disabled */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
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
					g_snprintf(buffer, sizeof(buffer),
						"%s %d %s %d %s %d typ host tcptype %s",
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
				g_snprintf(buffer, sizeof(buffer),
					"%s %d %s %d %s %d typ srflx raddr %s rport %d",
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
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
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
					g_snprintf(buffer, sizeof(buffer),
						"%s %d %s %d %s %d typ srflx raddr %s rport %d tcptype %s",
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
			/* 'prflx' candidate: skip it, we don't add them to the SDP */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
			nice_candidate_free(c);
			continue;
		} else if(c->type == NICE_CANDIDATE_TYPE_RELAYED) {
			/* 'relay' candidate */
			if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
				g_snprintf(buffer, sizeof(buffer),
					"%s %d %s %d %s %d typ relay raddr %s rport %d",
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
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping relay TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
					nice_candidate_free(c);
					continue;
				}
#ifndef HAVE_LIBNICE_TCP
				/* TCP candidates are only supported since libnice 0.1.8 */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping relay TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
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
					g_snprintf(buffer, sizeof(buffer),
						"%s %d %s %d %s %d typ relay raddr %s rport %d tcptype %s",
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
		janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
		mline->attributes = g_list_append(mline->attributes, a);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]     %s", handle->handle_id, buffer); /* buffer already newline terminated */
		if(log_candidates) {
			/* Save for the summary, in case we need it */
			component->local_candidates = g_slist_append(component->local_candidates, g_strdup(buffer));
			/* Notify event handlers */
			if(janus_events_is_enabled()) {
				janus_session *session = (janus_session *)handle->session;
				json_t *info = json_object();
				json_object_set_new(info, "local-candidate", json_string(buffer));
				json_object_set_new(info, "stream_id", json_integer(stream_id));
				json_object_set_new(info, "component_id", json_integer(component_id));
				janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
			}
		}
		nice_candidate_free(c);
	}
	/* Done */
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
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]  Setting remote credentials...\n", handle->handle_id);
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
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT)) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Agent already exists?\n", handle->handle_id);
		return -2;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting ICE locally: got %s (%d audios, %d videos)\n", handle->handle_id, offer ? "OFFER" : "ANSWER", audio, video);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);

	/* Note: in case this is not an OFFER, we don't know whether any medium are supported on the other side or not yet */
	if(audio) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	}
	if(video) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	}
	if(data) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	}
	/* Note: in case this is not an OFFER, we don't know whether BUNDLE is supported on the other side or not yet,
	 * unless Janus was configured to force BUNDLE in which case we enable it on our side anyway */
	if((offer && bundle) || janus_force_bundle || handle->force_bundle) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE);
	}
	/* Note: in case this is not an OFFER, we don't know whether rtcp-mux is supported on the other side or not yet,
	 * unless Janus was configured to force rtcp-mux in which case we enable it on our side anyway */
	if((offer && rtcpmux) || janus_force_rtcpmux || handle->force_rtcp_mux) {
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
	char tname[16];
	g_snprintf(tname, sizeof(tname), "iceloop %"SCNu64, handle->handle_id);
	handle->icethread = g_thread_try_new(tname, &janus_ice_thread, handle, &error);
	if(error != NULL) {
		/* FIXME We should clear some resources... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the ICE thread...\n", handle->handle_id, error->code, error->message ? error->message : "??");
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		return -1;
	}
	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice */
	handle->controlling = janus_ice_lite_enabled ? FALSE : !offer;
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Creating ICE agent (ICE %s mode, %s)\n", handle->handle_id,
		janus_ice_lite_enabled ? "Lite" : "Full", handle->controlling ? "controlling" : "controlled");
	handle->agent = g_object_new(NICE_TYPE_AGENT,
		"compatibility", NICE_COMPATIBILITY_DRAFT19,
		"main-context", handle->icectx,
		"reliable", FALSE,
		"full-mode", janus_ice_lite_enabled ? FALSE : TRUE,
#ifdef HAVE_LIBNICE_TCP
		"ice-udp", TRUE,
		"ice-tcp", janus_ice_tcp_enabled ? TRUE : FALSE,
#endif
		NULL);
	handle->agent_created = janus_get_monotonic_time();
	handle->srtp_errors_count = 0;
	handle->last_srtp_error = 0;
	/* Any STUN server to use? */
	if(janus_stun_server != NULL && janus_stun_port > 0) {
		g_object_set(G_OBJECT(handle->agent),
			"stun-server", janus_stun_server,
			"stun-server-port", janus_stun_port,
			NULL);
	}
	/* Any dynamic TURN credentials to retrieve via REST API? */
	gboolean have_turnrest_credentials = FALSE;
#ifdef HAVE_LIBCURL
	janus_turnrest_response *turnrest_credentials = janus_turnrest_request();
	if(turnrest_credentials != NULL) {
		have_turnrest_credentials = TRUE;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got credentials from the TURN REST API backend!\n", handle->handle_id);
		JANUS_LOG(LOG_HUGE, "  -- Username: %s\n", turnrest_credentials->username);
		JANUS_LOG(LOG_HUGE, "  -- Password: %s\n", turnrest_credentials->password);
		JANUS_LOG(LOG_HUGE, "  -- TTL:      %"SCNu32"\n", turnrest_credentials->ttl);
		JANUS_LOG(LOG_HUGE, "  -- Servers:  %d\n", g_list_length(turnrest_credentials->servers));
		GList *server = turnrest_credentials->servers;
		while(server != NULL) {
			janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
			JANUS_LOG(LOG_HUGE, "  -- -- URI: %s:%"SCNu16" (%d)\n", instance->server, instance->port, instance->transport);
			server = server->next;
		}
	}
#endif
	g_object_set(G_OBJECT(handle->agent), "upnp", FALSE, NULL);
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", handle->controlling, NULL);
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
#ifndef HAVE_LIBNICE_TCP
	g_signal_connect (G_OBJECT (handle->agent), "new-remote-candidate",
#else
	g_signal_connect (G_OBJECT (handle->agent), "new-remote-candidate-full",
#endif
		G_CALLBACK (janus_ice_cb_new_remote_candidate), handle);

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
			/* Check the interface name first, we can ignore that as well: enforce list would be checked later */
			if(janus_ice_enforce_list == NULL && ifa->ifa_name != NULL && janus_ice_is_ignored(ifa->ifa_name))
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
			/* Check if this IP address is in the ignore/enforce list, now: the enforce list has the precedence */
			if(janus_ice_enforce_list != NULL) {
				if(ifa->ifa_name != NULL && !janus_ice_is_enforced(ifa->ifa_name) && !janus_ice_is_enforced(host))
					continue;
			} else {
				if(janus_ice_is_ignored(host))
					continue;
			}
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
		janus_ice_stream *audio_stream = (janus_ice_stream *)g_malloc0(sizeof(janus_ice_stream));
		if(audio_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		handle->audio_mid = NULL;
		audio_stream->stream_id = handle->audio_id;
		audio_stream->handle = handle;
		audio_stream->cdone = 0;
		audio_stream->payload_type = -1;
		audio_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		audio_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		audio_stream->audio_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		audio_stream->audio_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		audio_stream->video_ssrc = 0;
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
			/* If we're bundling, this stream is going to be used for video as well */
			audio_stream->video_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		}
		audio_stream->video_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		audio_stream->video_ssrc_peer_rtx = 0;		/* FIXME Right now we don't know if and what this will be */
		audio_stream->video_ssrc_peer_sim_1 = 0;	/* FIXME Right now we don't know if and what this will be */
		audio_stream->video_ssrc_peer_sim_2 = 0;	/* FIXME Right now we don't know if and what this will be */
		audio_stream->audio_rtcp_ctx = g_malloc0(sizeof(rtcp_context));
		audio_stream->audio_rtcp_ctx->tb = 48000;	/* May change later */
		audio_stream->video_rtcp_ctx = g_malloc0(sizeof(rtcp_context));
		audio_stream->video_rtcp_ctx->tb = 90000;
		audio_stream->noerrorlog = FALSE;
		janus_mutex_init(&audio_stream->mutex);
		audio_stream->components = g_hash_table_new(NULL, NULL);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->audio_id), audio_stream);
		if(!have_turnrest_credentials) {
			/* No TURN REST API server and credentials, any static ones? */
			if(janus_turn_server != NULL) {
				/* We need relay candidates as well */
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->audio_id, 1,
					janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						janus_turn_server, janus_turn_port);
				}
			}
#ifdef HAVE_LIBCURL
		} else {
			/* We need relay candidates as well: add all those we got */
			GList *server = turnrest_credentials->servers;
			while(server != NULL) {
				janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->audio_id, 1,
					instance->server, instance->port,
					turnrest_credentials->username, turnrest_credentials->password,
					instance->transport);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						instance->server, instance->port);
				}
				server = server->next;
			}
#endif
		}
		handle->audio_stream = audio_stream;
		janus_ice_component *audio_rtp = (janus_ice_component *)g_malloc0(sizeof(janus_ice_component));
		if(audio_rtp == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		audio_rtp->stream = audio_stream;
		audio_rtp->stream_id = audio_stream->stream_id;
		audio_rtp->component_id = 1;
		audio_rtp->candidates = NULL;
		audio_rtp->local_candidates = NULL;
		audio_rtp->remote_candidates = NULL;
		audio_rtp->selected_pair = NULL;
		audio_rtp->process_started = FALSE;
		audio_rtp->icestate_source = NULL;
		audio_rtp->icefailed_detected = 0;
		audio_rtp->dtlsrt_source = NULL;
		audio_rtp->dtls = NULL;
		audio_rtp->do_audio_nacks = FALSE;
		audio_rtp->do_video_nacks = FALSE;
		audio_rtp->retransmit_buffer = NULL;
		audio_rtp->retransmit_log_ts = 0;
		audio_rtp->retransmit_recent_cnt = 0;
		audio_rtp->nack_sent_log_ts = 0;
		audio_rtp->nack_sent_recent_cnt = 0;
		audio_rtp->last_seqs_audio = NULL;
		audio_rtp->last_seqs_video = NULL;
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
			audio_rtcp = (janus_ice_component *)g_malloc0(sizeof(janus_ice_component));
			if(audio_rtcp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				return -1;
			}
			if(!have_turnrest_credentials) {
				/* No TURN REST API server and credentials, any static ones? */
				if(janus_turn_server != NULL) {
					/* We need relay candidates as well */
					gboolean ok = nice_agent_set_relay_info(handle->agent, handle->audio_id, 2,
						janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
					if(!ok) {
						JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
							janus_turn_server, janus_turn_port);
					}
				}
#ifdef HAVE_LIBCURL
			} else {
				/* We need relay candidates as well: add all those we got */
				GList *server = turnrest_credentials->servers;
				while(server != NULL) {
					janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
					gboolean ok = nice_agent_set_relay_info(handle->agent, handle->audio_id, 2,
						instance->server, instance->port,
						turnrest_credentials->username, turnrest_credentials->password,
						instance->transport);
					if(!ok) {
						JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
							instance->server, instance->port);
					}
					server = server->next;
				}
#endif
			}
			audio_rtcp->stream = audio_stream;
			audio_rtcp->stream_id = audio_stream->stream_id;
			audio_rtcp->component_id = 2;
			audio_rtcp->candidates = NULL;
			audio_rtcp->local_candidates = NULL;
			audio_rtcp->remote_candidates = NULL;
			audio_rtcp->selected_pair = NULL;
			audio_rtcp->process_started = FALSE;
			audio_rtcp->icestate_source = NULL;
			audio_rtcp->icefailed_detected = 0;
			audio_rtcp->dtlsrt_source = NULL;
			audio_rtcp->dtls = NULL;
			audio_rtcp->do_audio_nacks = FALSE;
			audio_rtcp->do_video_nacks = FALSE;
			audio_rtcp->retransmit_buffer = NULL;
			audio_rtcp->retransmit_log_ts = 0;
			audio_rtcp->retransmit_recent_cnt = 0;
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
		nice_agent_gather_candidates(handle->agent, handle->audio_id);
		nice_agent_attach_recv(handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtp);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && audio_rtcp != NULL)
			nice_agent_attach_recv(handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtcp);
	}
	if(video && (!audio || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))) {
		/* Add a video stream */
		handle->streams_num++;
		handle->video_id = nice_agent_add_stream (handle->agent, janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) ? 1 : 2);
		janus_ice_stream *video_stream = (janus_ice_stream *)g_malloc0(sizeof(janus_ice_stream));
		if(video_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		handle->video_mid = NULL;
		video_stream->handle = handle;
		video_stream->stream_id = handle->video_id;
		video_stream->cdone = 0;
		video_stream->payload_type = -1;
		video_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		video_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		video_stream->video_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		video_stream->video_ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		video_stream->video_ssrc_peer_rtx = 0;		/* FIXME Right now we don't know if and what this will be */
		video_stream->video_ssrc_peer_sim_1 = 0;	/* FIXME Right now we don't know if and what this will be */
		video_stream->video_ssrc_peer_sim_2 = 0;	/* FIXME Right now we don't know if and what this will be */
		video_stream->audio_ssrc = 0;
		video_stream->audio_ssrc_peer = 0;
		video_stream->video_rtcp_ctx = g_malloc0(sizeof(rtcp_context));
		video_stream->video_rtcp_ctx->tb = 90000;
		video_stream->components = g_hash_table_new(NULL, NULL);
		video_stream->noerrorlog = FALSE;
		janus_mutex_init(&video_stream->mutex);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->video_id), video_stream);
		if(!have_turnrest_credentials) {
			/* No TURN REST API server and credentials, any static ones? */
			if(janus_turn_server != NULL) {
				/* We need relay candidates as well */
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->video_id, 1,
					janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						janus_turn_server, janus_turn_port);
				}
			}
#ifdef HAVE_LIBCURL
		} else {
			/* We need relay candidates as well: add all those we got */
			GList *server = turnrest_credentials->servers;
			while(server != NULL) {
				janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->video_id, 1,
					instance->server, instance->port,
					turnrest_credentials->username, turnrest_credentials->password,
					instance->transport);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						instance->server, instance->port);
				}
				server = server->next;
			}
#endif
		}
		handle->video_stream = video_stream;
		janus_ice_component *video_rtp = (janus_ice_component *)g_malloc0(sizeof(janus_ice_component));
		if(video_rtp == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		video_rtp->stream = video_stream;
		video_rtp->stream_id = video_stream->stream_id;
		video_rtp->component_id = 1;
		video_rtp->candidates = NULL;
		video_rtp->local_candidates = NULL;
		video_rtp->remote_candidates = NULL;
		video_rtp->selected_pair = NULL;
		video_rtp->process_started = FALSE;
		video_rtp->icestate_source = NULL;
		video_rtp->icefailed_detected = 0;
		video_rtp->dtlsrt_source = NULL;
		video_rtp->dtls = NULL;
		video_rtp->do_audio_nacks = FALSE;
		video_rtp->do_video_nacks = FALSE;
		video_rtp->retransmit_buffer = NULL;
		video_rtp->retransmit_log_ts = 0;
		video_rtp->retransmit_recent_cnt = 0;
		video_rtp->nack_sent_log_ts = 0;
		video_rtp->nack_sent_recent_cnt = 0;
		video_rtp->last_seqs_audio = NULL;
		video_rtp->last_seqs_video = NULL;
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
			video_rtcp = (janus_ice_component *)g_malloc0(sizeof(janus_ice_component));
			if(video_rtcp == NULL) {
				JANUS_LOG(LOG_FATAL, "Memory error!\n");
				return -1;
			}
			if(!have_turnrest_credentials) {
				/* No TURN REST API server and credentials, any static ones? */
				if(janus_turn_server != NULL) {
					/* We need relay candidates as well */
					gboolean ok = nice_agent_set_relay_info(handle->agent, handle->video_id, 2,
						janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
					if(!ok) {
						JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
							janus_turn_server, janus_turn_port);
					}
				}
#ifdef HAVE_LIBCURL
			} else {
				/* We need relay candidates as well: add all those we got */
				GList *server = turnrest_credentials->servers;
				while(server != NULL) {
					janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
					gboolean ok = nice_agent_set_relay_info(handle->agent, handle->video_id, 2,
						instance->server, instance->port,
						turnrest_credentials->username, turnrest_credentials->password,
						instance->transport);
					if(!ok) {
						JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
							instance->server, instance->port);
					}
					server = server->next;
				}
#endif
			}
			video_rtcp->stream = video_stream;
			video_rtcp->stream_id = video_stream->stream_id;
			video_rtcp->component_id = 2;
			video_rtcp->candidates = NULL;
			video_rtcp->local_candidates = NULL;
			video_rtcp->remote_candidates = NULL;
			video_rtcp->selected_pair = NULL;
			video_rtcp->process_started = FALSE;
			video_rtcp->icestate_source = NULL;
			video_rtcp->icefailed_detected = 0;
			video_rtcp->dtlsrt_source = NULL;
			video_rtcp->dtls = NULL;
			video_rtcp->do_audio_nacks = FALSE;
			video_rtcp->do_video_nacks = FALSE;
			video_rtcp->retransmit_buffer = NULL;
			video_rtcp->retransmit_log_ts = 0;
			video_rtcp->retransmit_recent_cnt = 0;
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
		nice_agent_gather_candidates(handle->agent, handle->video_id);
		nice_agent_attach_recv(handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtp);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RTCPMUX) && video_rtcp != NULL)
			nice_agent_attach_recv(handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtcp);
	}
#ifndef HAVE_SCTP
	handle->data_id = 0;
	handle->data_stream = NULL;
#else
	if(data && ((!audio && !video) || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE))) {
		/* Add a SCTP/DataChannel stream */
		handle->streams_num++;
		handle->data_id = nice_agent_add_stream (handle->agent, 1);
		janus_ice_stream *data_stream = (janus_ice_stream *)g_malloc0(sizeof(janus_ice_stream));
		if(data_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		handle->data_mid = NULL;
		if(!have_turnrest_credentials) {
			/* No TURN REST API server and credentials, any static ones? */
			if(janus_turn_server != NULL) {
				/* We need relay candidates as well */
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->data_id, 1,
					janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						janus_turn_server, janus_turn_port);
				}
			}
#ifdef HAVE_LIBCURL
		} else {
			/* We need relay candidates as well: add all those we got */
			GList *server = turnrest_credentials->servers;
			while(server != NULL) {
				janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
				gboolean ok = nice_agent_set_relay_info(handle->agent, handle->data_id, 1,
					instance->server, instance->port,
					turnrest_credentials->username, turnrest_credentials->password,
					instance->transport);
				if(!ok) {
					JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
						instance->server, instance->port);
				}
				server = server->next;
			}
#endif
		}
		data_stream->handle = handle;
		data_stream->stream_id = handle->data_id;
		data_stream->cdone = 0;
		data_stream->payload_type = -1;
		data_stream->disabled = FALSE;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		data_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		data_stream->components = g_hash_table_new(NULL, NULL);
		data_stream->noerrorlog = FALSE;
		janus_mutex_init(&data_stream->mutex);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->data_id), data_stream);
		handle->data_stream = data_stream;
		janus_ice_component *data_component = (janus_ice_component *)g_malloc0(sizeof(janus_ice_component));
		if(data_component == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		data_component->stream = data_stream;
		data_component->stream_id = data_stream->stream_id;
		data_component->component_id = 1;
		data_component->candidates = NULL;
		data_component->local_candidates = NULL;
		data_component->remote_candidates = NULL;
		data_component->selected_pair = NULL;
		data_component->process_started = FALSE;
		data_component->icestate_source = NULL;
		data_component->icefailed_detected = 0;
		data_component->dtlsrt_source = NULL;
		data_component->dtls = NULL;
		data_component->do_audio_nacks = FALSE;
		data_component->do_video_nacks = FALSE;
		data_component->retransmit_buffer = NULL;
		data_component->retransmit_log_ts = 0;
		data_component->retransmit_recent_cnt = 0;
		janus_ice_stats_reset(&data_component->in_stats);
		janus_ice_stats_reset(&data_component->out_stats);
		janus_mutex_init(&data_component->mutex);
		g_hash_table_insert(data_stream->components, GUINT_TO_POINTER(1), data_component);
		data_stream->rtp_component = data_component;	/* We use the component called 'RTP' for data */
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->data_id, 1, rtp_range_min, rtp_range_max);
#endif
		nice_agent_gather_candidates(handle->agent, handle->data_id);
		nice_agent_attach_recv(handle->agent, handle->data_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, data_component);
	}
#endif
#ifdef HAVE_LIBCURL
	if(turnrest_credentials != NULL) {
		janus_turnrest_response_destroy(turnrest_credentials);
		turnrest_credentials = NULL;
	}
#endif
	return 0;
}

void *janus_ice_send_thread(void *data) {
	janus_ice_handle *handle = (janus_ice_handle *)data;
	janus_session *session = (janus_session *)handle->session;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE send thread started...\n", handle->handle_id);
	janus_ice_queued_packet *pkt = NULL;
	gint64 before = janus_get_monotonic_time(),
		audio_rtcp_last_rr = before, audio_rtcp_last_sr = before, audio_last_event = before,
		video_rtcp_last_rr = before, video_rtcp_last_sr = before, video_last_event = before,
		last_srtp_summary = before, last_nack_cleanup = before;
	while(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		if(handle->queued_packets != NULL) {
			pkt = g_async_queue_timeout_pop(handle->queued_packets, 500000);
		} else {
			g_usleep(100000);
		}
		if(pkt == &janus_ice_dtls_alert) {
			/* The session is over, send an alert on all streams and components */
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
			while(g_async_queue_length(handle->queued_packets) > 0) {
				pkt = g_async_queue_try_pop(handle->queued_packets);
				if(pkt != NULL && pkt != &janus_ice_dtls_alert) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
				}
			}
			if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
				g_main_loop_quit(handle->iceloop);
				g_main_context_wakeup(handle->icectx);
			}
			continue;
		}
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
			if(pkt)
				g_free(pkt->data);
			g_free(pkt);
			pkt = NULL;
			continue;
		}
		/* First of all, let's see if everything's fine on the recv side */
		gint64 now = janus_get_monotonic_time();
		if(no_media_timer > 0 && now-before >= G_USEC_PER_SEC) {
			if(handle->audio_stream && handle->audio_stream->rtp_component) {
				janus_ice_component *component = handle->audio_stream->rtp_component;
				GList *lastitem = g_list_last(component->in_stats.audio_bytes_lastsec);
				janus_ice_stats_item *last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
				if(!component->in_stats.audio_notified_lastsec && last && now-last->when >= (gint64)no_media_timer*G_USEC_PER_SEC) {
					/* We missed more than no_second_timer seconds of audio! */
					component->in_stats.audio_notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive audio for more than %d seconds...\n", handle->handle_id, no_media_timer);
					janus_ice_notify_media(handle, FALSE, FALSE);
				}
				if(!component->in_stats.video_notified_lastsec && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					lastitem = g_list_last(component->in_stats.video_bytes_lastsec);
					last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
					if(last && now-last->when >= (gint64)no_media_timer*G_USEC_PER_SEC) {
						/* We missed more than no_second_timer seconds of video! */
						component->in_stats.video_notified_lastsec = TRUE;
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video for more than %d seconds...\n", handle->handle_id, no_media_timer);
						janus_ice_notify_media(handle, TRUE, FALSE);
					}
				}
			}
			if(handle->video_stream && handle->video_stream->rtp_component) {
				janus_ice_component *component = handle->video_stream->rtp_component;
				GList *lastitem = g_list_last(component->in_stats.video_bytes_lastsec);
				janus_ice_stats_item *last = lastitem ? ((janus_ice_stats_item *)lastitem->data) : NULL;
				if(!component->in_stats.video_notified_lastsec && last && now-last->when >= (gint64)no_media_timer*G_USEC_PER_SEC) {
					/* We missed more than no_second_timer seconds of video! */
					component->in_stats.video_notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video for more than a second...\n", handle->handle_id);
					janus_ice_notify_media(handle, TRUE, FALSE);
				}
			}
			before = now;
		}
		/* Let's check if it's time to send a RTCP RR as well */
		if(now-audio_rtcp_last_rr >= 5*G_USEC_PER_SEC) {
			janus_ice_stream *stream = handle->audio_stream;
			if(handle->audio_stream && stream->audio_rtcp_ctx && stream->audio_rtcp_ctx->rtp_recvd) {
				/* Create a RR */
				int rrlen = 32;
				char rtcpbuf[32];
				memset(rtcpbuf, 0, sizeof(rtcpbuf));
				rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 1;
				rr->header.length = htons((rrlen/4)-1);
				janus_rtcp_report_block(stream->audio_rtcp_ctx, &rr->rb[0]);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 0, rtcpbuf, 32, FALSE);
			}
			audio_rtcp_last_rr = now;
		}
		if(now-video_rtcp_last_rr >= 5*G_USEC_PER_SEC) {
			janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (handle->video_stream);
			if(stream) {
				if(stream->video_rtcp_ctx && stream->video_rtcp_ctx->rtp_recvd) {
					/* Create a RR */
					int rrlen = 32;
					char rtcpbuf[32];
					memset(rtcpbuf, 0, sizeof(rtcpbuf));
					rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
					rr->header.version = 2;
					rr->header.type = RTCP_RR;
					rr->header.rc = 1;
					rr->header.length = htons((rrlen/4)-1);
					janus_rtcp_report_block(stream->video_rtcp_ctx, &rr->rb[0]);
					/* Enqueue it, we'll send it later */
					janus_ice_relay_rtcp_internal(handle, 1, rtcpbuf, 32, FALSE);
				}
			}
			video_rtcp_last_rr = now;
		}
		/* Do the same with SR/SDES */
		if(now-audio_rtcp_last_sr >= 5*G_USEC_PER_SEC) {
			janus_ice_stream *stream = handle->audio_stream;
			if(stream && stream->rtp_component && stream->rtp_component->out_stats.audio_packets > 0) {
				/* Create a SR/SDES compound */
				int srlen = 28;
				int sdeslen = 20;
				char rtcpbuf[srlen+sdeslen];
				memset(rtcpbuf, 0, sizeof(rtcpbuf));
				rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
				sr->header.version = 2;
				sr->header.type = RTCP_SR;
				sr->header.rc = 0;
				sr->header.length = htons((srlen/4)-1);
				struct timeval tv;
				gettimeofday(&tv, NULL);
				uint32_t s = tv.tv_sec + 2208988800u;
				uint32_t u = tv.tv_usec;
				uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
				sr->si.ntp_ts_msw = htonl(s);
				sr->si.ntp_ts_lsw = htonl(f);
				/* Compute an RTP timestamp coherent with the NTP one */
				rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
				if(rtcp_ctx == NULL) {
					sr->si.rtp_ts = htonl(stream->audio_last_ts);	/* FIXME */
				} else {
					int64_t ntp = tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
					uint32_t rtp_ts = ((ntp-stream->audio_first_ntp_ts)/1000)*(rtcp_ctx->tb/1000) + stream->audio_first_rtp_ts;
					sr->si.rtp_ts = htonl(rtp_ts);
				}
				sr->si.s_packets = htonl(stream->rtp_component->out_stats.audio_packets);
				sr->si.s_octets = htonl(stream->rtp_component->out_stats.audio_bytes);
				rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
				janus_rtcp_sdes((char *)sdes, sdeslen, "janusaudio", 10);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 0, rtcpbuf, srlen+sdeslen, FALSE);
			}
			audio_rtcp_last_sr = now;
		}
		if(now-video_rtcp_last_sr >= 5*G_USEC_PER_SEC) {
			janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (handle->video_stream);
			if(stream && stream->rtp_component && stream->rtp_component->out_stats.video_packets > 0) {
				/* Create a SR/SDES compound */
				int srlen = 28;
				int sdeslen = 20;
				char rtcpbuf[srlen+sdeslen];
				memset(rtcpbuf, 0, sizeof(rtcpbuf));
				rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
				sr->header.version = 2;
				sr->header.type = RTCP_SR;
				sr->header.rc = 0;
				sr->header.length = htons((srlen/4)-1);
				struct timeval tv;
				gettimeofday(&tv, NULL);
				uint32_t s = tv.tv_sec + 2208988800u;
				uint32_t u = tv.tv_usec;
				uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
				sr->si.ntp_ts_msw = htonl(s);
				sr->si.ntp_ts_lsw = htonl(f);
				/* Compute an RTP timestamp coherent with the NTP one */
				rtcp_context *rtcp_ctx = stream->video_rtcp_ctx;
				if(rtcp_ctx == NULL) {
					sr->si.rtp_ts = htonl(stream->video_last_ts);	/* FIXME */
				} else {
					int64_t ntp = tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
					uint32_t rtp_ts = ((ntp-stream->video_first_ntp_ts)/1000)*(rtcp_ctx->tb/1000) + stream->video_first_rtp_ts;
					sr->si.rtp_ts = htonl(rtp_ts);
				}
				sr->si.s_packets = htonl(stream->rtp_component->out_stats.video_packets);
				sr->si.s_octets = htonl(stream->rtp_component->out_stats.video_bytes);
				rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
				janus_rtcp_sdes((char *)sdes, sdeslen, "janusvideo", 10);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 1, rtcpbuf, srlen+sdeslen, FALSE);
			}
			video_rtcp_last_sr = now;
		}
		/* We tell event handlers once per second about RTCP-related stuff
		 * FIXME Should we really do this here? Would this slow down this thread and add delay? */
		if(janus_ice_event_stats_period > 0 && now-audio_last_event >= (gint64)janus_ice_event_stats_period*G_USEC_PER_SEC) {
			if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
				janus_ice_stream *stream = handle->audio_stream;
				if(stream && stream->audio_rtcp_ctx) {
					json_t *info = json_object();
					json_object_set_new(info, "media", json_string("audio"));
					json_object_set_new(info, "base", json_integer(stream->audio_rtcp_ctx->tb));
					json_object_set_new(info, "lsr", json_integer(janus_rtcp_context_get_lsr(stream->audio_rtcp_ctx)));
					json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, FALSE)));
					json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, TRUE)));
					json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, FALSE)));
					json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, TRUE)));
					if(stream->rtp_component) {
						json_object_set_new(info, "packets-received", json_integer(stream->rtp_component->in_stats.audio_packets));
						json_object_set_new(info, "packets-sent", json_integer(stream->rtp_component->out_stats.audio_packets));
						json_object_set_new(info, "bytes-received", json_integer(stream->rtp_component->in_stats.audio_bytes));
						json_object_set_new(info, "bytes-sent", json_integer(stream->rtp_component->out_stats.audio_bytes));
						json_object_set_new(info, "nacks-received", json_integer(stream->rtp_component->in_stats.audio_nacks));
						json_object_set_new(info, "nacks-sent", json_integer(stream->rtp_component->out_stats.audio_nacks));
					}
					janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, info);
				}
			}
			audio_last_event = now;
		}
		if(janus_ice_event_stats_period > 0 && now-video_last_event >= (gint64)janus_ice_event_stats_period*G_USEC_PER_SEC) {
			if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
				janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (handle->video_stream);
				if(stream && stream->video_rtcp_ctx) {
					json_t *info = json_object();
					json_object_set_new(info, "media", json_string("video"));
					json_object_set_new(info, "base", json_integer(stream->video_rtcp_ctx->tb));
					json_object_set_new(info, "lsr", json_integer(janus_rtcp_context_get_lsr(stream->video_rtcp_ctx)));
					json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx, FALSE)));
					json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx, TRUE)));
					json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx, FALSE)));
					json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx, TRUE)));
					if(stream->rtp_component) {
						json_object_set_new(info, "packets-received", json_integer(stream->rtp_component->in_stats.video_packets));
						json_object_set_new(info, "packets-sent", json_integer(stream->rtp_component->out_stats.video_packets));
						json_object_set_new(info, "bytes-received", json_integer(stream->rtp_component->in_stats.video_bytes));
						json_object_set_new(info, "bytes-sent", json_integer(stream->rtp_component->out_stats.video_bytes));
						json_object_set_new(info, "nacks-received", json_integer(stream->rtp_component->in_stats.video_nacks));
						json_object_set_new(info, "nacks-sent", json_integer(stream->rtp_component->out_stats.video_nacks));
					}
					janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, info);
				}
			}
			video_last_event = now;
		}
		/* Should we clean up old NACK buffers? (we check each 1/4 of the max_nack_queue time) */
		if(max_nack_queue > 0 && (now-last_nack_cleanup >= (max_nack_queue*250))) {
			/* Check if we do for both streams */
			janus_cleanup_nack_buffer(now, handle->audio_stream);
			janus_cleanup_nack_buffer(now, handle->video_stream);
			last_nack_cleanup = now;
		}
		/* Check if we should also print a summary of SRTP-related errors */
		if(now-last_srtp_summary >= (2*G_USEC_PER_SEC)) {
			if(handle->srtp_errors_count > 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got %d SRTP/SRTCP errors in the last few seconds (last error: %s)\n",
					handle->handle_id, handle->srtp_errors_count, janus_srtp_error_str(handle->last_srtp_error));
				handle->srtp_errors_count = 0;
				handle->last_srtp_error = 0;
			}
			last_srtp_summary = now;
		}

		/* Now let's get on with the packets */
		if(pkt == NULL) {
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
					stream->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			stream->noerrorlog = FALSE;
			if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"]     %s stream (#%u) component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio", stream->stream_id);
					component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			component->noerrorlog = FALSE;
			if(pkt->encrypted) {
				/* Already SRTCP */
				int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
				if(sent < pkt->length) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
				}
			} else {
				/* Check if there's anything we need to do before sending */
				uint32_t bitrate = janus_rtcp_get_remb(pkt->data, pkt->length);
				if(bitrate > 0) {
					/* There's a REMB, prepend a RR as it won't work otherwise */
					int rrlen = 32;
					char *rtcpbuf = g_malloc0(rrlen+pkt->length);
					memset(rtcpbuf, 0, rrlen+pkt->length);
					rtcp_rr *rr = (rtcp_rr *)rtcpbuf;
					rr->header.version = 2;
					rr->header.type = RTCP_RR;
					rr->header.rc = 0;
					rr->header.length = htons((rrlen/4)-1);
					janus_ice_stream *stream = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE) ? (handle->audio_stream ? handle->audio_stream : handle->video_stream) : (handle->video_stream);
					if(stream && stream->video_rtcp_ctx && stream->video_rtcp_ctx->rtp_recvd) {
						rr->header.rc = 1;
						janus_rtcp_report_block(stream->video_rtcp_ctx, &rr->rb[0]);
					}
					/* Append REMB */
					memcpy(rtcpbuf+rrlen, pkt->data, pkt->length);
					/* If we're simulcasting, set the extra SSRCs (the first one will be set by janus_rtcp_fix_ssrc) */
					if(stream->video_ssrc_peer_sim_1 && pkt->length >= 28) {
						rtcp_fb *rtcpfb = (rtcp_fb *)(rtcpbuf+rrlen);
						rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
						remb->ssrc[1] = htonl(stream->video_ssrc_peer_sim_1);
						if(stream->video_ssrc_peer_sim_2 && pkt->length >= 32) {
							remb->ssrc[2] = htonl(stream->video_ssrc_peer_sim_2);
						}
					}
					/* Free old packet and update */
					char *prev_data = pkt->data;
					pkt->data = rtcpbuf;
					pkt->length = rrlen+pkt->length;
					g_clear_pointer(&prev_data, g_free);
				}
				/* FIXME Copy in a buffer and fix SSRC */
				char sbuf[JANUS_BUFSIZE];
				memcpy(sbuf, pkt->data, pkt->length);
				/* Fix all SSRCs! */
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
						video ? stream->video_ssrc : stream->audio_ssrc,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
					janus_rtcp_fix_ssrc(NULL, sbuf, pkt->length, 1,
						video ? stream->video_ssrc : stream->audio_ssrc,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
				} else {
					/* Plan B involved, we trust the plugin to set the right 'local' SSRC and we don't mess with it */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing peer SSRC (Plan B, peer %u)\n", handle->handle_id,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
					janus_rtcp_fix_ssrc(NULL, sbuf, pkt->length, 1, 0,
						video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);
				}
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, FALSE, sbuf, pkt->length,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* Encrypt SRTCP */
				int protected = pkt->length;
				int res = 0;
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
					res = srtp_protect_rtcp(component->dtls->srtp_out, sbuf, &protected);
				} else {
					/* We need to make sure different sources don't use the SRTP context at the same time */
					janus_mutex_lock(&component->dtls->srtp_mutex);
					res = srtp_protect_rtcp(component->dtls->srtp_out, sbuf, &protected);
					janus_mutex_unlock(&component->dtls->srtp_mutex);
				}
				if(res != srtp_err_status_ok) {
					/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
					handle->srtp_errors_count++;
					handle->last_srtp_error = res;
					/* If we're debugging, though, print every occurrence */
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected);
				} else {
					/* Shoot! */
					int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, sbuf);
					if(sent < protected) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
					}
				}
			}
			g_free(pkt->data);
			g_free(pkt);
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
						stream->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				stream->noerrorlog = FALSE;
				if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]     %s stream component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio");
						component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				component->noerrorlog = FALSE;
				if(pkt->encrypted) {
					/* Already RTP (probably a retransmission?) */
					janus_rtp_header *header = (janus_rtp_header *)pkt->data;
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] ... Retransmitting seq.nr %"SCNu16"\n\n", handle->handle_id, ntohs(header->seq_number));
					int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
					if(sent < pkt->length) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
					}
				} else {
					/* FIXME Copy in a buffer and fix SSRC */
					char sbuf[JANUS_BUFSIZE];
					memcpy(sbuf, pkt->data, pkt->length);
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PLAN_B)) {
						/* Overwrite SSRC */
						janus_rtp_header *header = (janus_rtp_header *)sbuf;
						header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
					}
					/* Do we need to dump this packet for debugging? */
					if(g_atomic_int_get(&handle->dump_packets))
						janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, FALSE, sbuf, pkt->length,
							"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
					/* Encrypt SRTP */
					int protected = pkt->length;
					int res = srtp_protect(component->dtls->srtp_out, sbuf, &protected);
					if(res != srtp_err_status_ok) {
						/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
						handle->srtp_errors_count++;
						handle->last_srtp_error = res;
						/* If we're debugging, though, print every occurrence */
						janus_rtp_header *header = (janus_rtp_header *)sbuf;
						guint32 timestamp = ntohl(header->timestamp);
						guint16 seq = ntohs(header->seq_number);
						JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected, timestamp, seq);
					} else {
						/* Shoot! */
						int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, sbuf);
						if(sent < protected) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
						}
						/* Update stats */
						if(sent > 0) {
							/* Update the RTCP context as well */
							janus_rtp_header *header = (janus_rtp_header *)sbuf;
							guint32 timestamp = ntohl(header->timestamp);
							if(pkt->type == JANUS_ICE_PACKET_AUDIO) {
								component->out_stats.audio_packets++;
								component->out_stats.audio_bytes += sent;
								stream->audio_last_ts = timestamp;
								if(stream->audio_first_ntp_ts == 0) {
									struct timeval tv;
									gettimeofday(&tv, NULL);
									stream->audio_first_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
									stream->audio_first_rtp_ts = timestamp;
								}
								/* Let's check if this was G.711: in case we may need to change the timestamp base */
								rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx : stream->audio_rtcp_ctx;
								int pt = header->type;
								if((pt == 0 || pt == 8) && (rtcp_ctx->tb == 48000))
									rtcp_ctx->tb = 8000;
							} else if(pkt->type == JANUS_ICE_PACKET_VIDEO) {
								component->out_stats.video_packets++;
								component->out_stats.video_bytes += sent;
								stream->video_last_ts = timestamp;
								if(stream->video_first_ntp_ts == 0) {
									struct timeval tv;
									gettimeofday(&tv, NULL);
									stream->video_first_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
									stream->video_first_rtp_ts = timestamp;
								}
							}
						}
						if(max_nack_queue > 0) {
							/* Save the packet for retransmissions that may be needed later */
							if((pkt->type == JANUS_ICE_PACKET_AUDIO && !component->do_audio_nacks) ||
									(pkt->type == JANUS_ICE_PACKET_VIDEO && !component->do_video_nacks)) {
								/* ... unless NACKs are disabled for this medium */
								g_free(pkt->data);
								pkt->data = NULL;
								g_free(pkt);
								pkt = NULL;
								continue;
							}
							janus_rtp_packet *p = (janus_rtp_packet *)g_malloc0(sizeof(janus_rtp_packet));
							p->data = (char *)g_malloc0(protected);
							memcpy(p->data, sbuf, protected);
							p->length = protected;
							p->created = janus_get_monotonic_time();
							p->last_retransmit = 0;
							janus_mutex_lock(&component->mutex);
							component->retransmit_buffer = g_list_append(component->retransmit_buffer, p);
							janus_mutex_unlock(&component->mutex);
						}
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
						stream->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				stream->noerrorlog = FALSE;
				if(!component->dtls) {
					if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"]     SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
						component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
					}
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				component->noerrorlog = FALSE;
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
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE send thread leaving...\n", handle->handle_id);
	g_thread_unref(g_thread_self());
	return NULL;
}

void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len) {
	if(!handle || buf == NULL || len < 1)
		return;
	if((!video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO))
			|| (video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)))
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)g_malloc0(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc0(len);
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, pkt);
}

void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, int video, char *buf, int len, gboolean filter_rtcp) {
	if(!handle || buf == NULL || len < 1)
		return;
	/* We use this internal method to check whether we need to filter RTCP (e.g., to make
	 * sure we don't just forward any SR/RR from peers/plugins, but use our own) or it has
	 * already been done, and so this is actually a packet added by the ICE send thread */
	char *rtcp_buf = buf;
	int rtcp_len = len;
	if(filter_rtcp) {
		/* FIXME Strip RR/SR/SDES/NACKs/etc. */
		rtcp_buf = janus_rtcp_filter(buf, len, &rtcp_len);
		if(rtcp_buf == NULL)
			return;
	}
	if(rtcp_len < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)g_malloc0(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc0(len);
	memcpy(pkt->data, rtcp_buf, rtcp_len);
	pkt->length = rtcp_len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = TRUE;
	pkt->encrypted = FALSE;
	if(handle->queued_packets != NULL)
		g_async_queue_push(handle->queued_packets, pkt);
	if(rtcp_buf != buf) {
		/* We filtered the original packet, deallocate it */
		g_free(rtcp_buf);
	}
}

void janus_ice_relay_rtcp(janus_ice_handle *handle, int video, char *buf, int len) {
	janus_ice_relay_rtcp_internal(handle, video, buf, len, TRUE);
}

#ifdef HAVE_SCTP
void janus_ice_relay_data(janus_ice_handle *handle, char *buf, int len) {
	if(!handle || buf == NULL || len < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)g_malloc0(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc0(len);
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
	/* Clear the queue before we wake the send thread */
	janus_ice_queued_packet *pkt = NULL;
	while(g_async_queue_length(handle->queued_packets) > 0) {
		pkt = g_async_queue_try_pop(handle->queued_packets);
		if(pkt != NULL && pkt != &janus_ice_dtls_alert) {
			g_free(pkt->data);
			g_free(pkt);
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
		if(plugin && plugin->setup_media && janus_plugin_session_is_alive(handle->app_handle))
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
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("webrtcup"));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, info);
	}
}
