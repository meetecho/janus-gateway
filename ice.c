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

/* Full-trickle support */
static gboolean janus_full_trickle_enabled;
gboolean janus_ice_is_full_trickle_enabled(void) {
	return janus_full_trickle_enabled;
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
	gboolean retransmission;
	gboolean encrypted;
} janus_ice_queued_packet;
/* This is a static, fake, message we use as a trigger to send a DTLS alert */
static janus_ice_queued_packet janus_ice_dtls_alert;

/* Janus NACKed packet we're tracking (to avoid duplicates) */
typedef struct janus_ice_nacked_packet {
	janus_ice_handle *handle;
	int vindex;
	guint16 seq_number;
} janus_ice_nacked_packet;
static gboolean janus_ice_nacked_packet_cleanup(gpointer user_data) {
	janus_ice_nacked_packet *pkt = (janus_ice_nacked_packet *)user_data;

	JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Cleaning up NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
		pkt->handle->handle_id, pkt->seq_number, pkt->handle->stream->video_ssrc_peer[pkt->vindex], pkt->vindex);
	g_hash_table_remove(pkt->handle->stream->rtx_nacked[pkt->vindex], GUINT_TO_POINTER(pkt->seq_number));

	return G_SOURCE_REMOVE;
}

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


/* RFC4588 support */
static gboolean rfc4588_enabled = FALSE;
void janus_set_rfc4588_enabled(gboolean enabled) {
	rfc4588_enabled = enabled;
	JANUS_LOG(LOG_VERB, "RFC4588 support is %s\n", rfc4588_enabled ? "enabled" : "disabled");
}
gboolean janus_is_rfc4588_enabled(void) {
	return rfc4588_enabled;
}


/* Maximum value, in milliseconds, for the NACK queue/retransmissions (default=500ms) */
#define DEFAULT_MAX_NACK_QUEUE	500
/* Maximum ignore count after retransmission (200ms) */
#define MAX_NACK_IGNORE			200000

static uint max_nack_queue = DEFAULT_MAX_NACK_QUEUE;
void janus_set_max_nack_queue(uint mnq) {
	max_nack_queue = mnq;
	if(max_nack_queue == 0)
		JANUS_LOG(LOG_VERB, "Disabling NACK queue\n");
	else
		JANUS_LOG(LOG_VERB, "Setting max NACK queue to %dms\n", max_nack_queue);
}
uint janus_get_max_nack_queue(void) {
	return max_nack_queue;
}
/* Helper to clean old NACK packets in the buffer when they exceed the queue time limit */
static void janus_cleanup_nack_buffer(gint64 now, janus_ice_stream *stream, gboolean audio, gboolean video) {
	if(stream && stream->component) {
		janus_ice_component *component = stream->component;
		janus_mutex_lock(&component->mutex);
		if(audio && component->audio_retransmit_buffer) {
			janus_rtp_packet *p = (janus_rtp_packet *)g_queue_peek_head(component->audio_retransmit_buffer);
			while(p && (!now || (now - p->created >= (gint64)max_nack_queue*1000))) {
				/* Packet is too old, get rid of it */
				g_queue_pop_head(component->audio_retransmit_buffer);
				/* Remove from hashtable too */
				janus_rtp_header *header = (janus_rtp_header *)p->data;
				guint16 seq = ntohs(header->seq_number);
				g_hash_table_remove(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq));
				/* Free the packet */
				g_free(p->data);
				p->data = NULL;
				g_free(p);
				p = (janus_rtp_packet *)g_queue_peek_head(component->audio_retransmit_buffer);
			}
		}
		if(video && component->video_retransmit_buffer) {
			janus_rtp_packet *p = (janus_rtp_packet *)g_queue_peek_head(component->video_retransmit_buffer);
			while(p && (!now || (now - p->created >= (gint64)max_nack_queue*1000))) {
				/* Packet is too old, get rid of it */
				g_queue_pop_head(component->video_retransmit_buffer);
				/* Remove from hashtable too */
				janus_rtp_header *header = (janus_rtp_header *)p->data;
				guint16 seq = ntohs(header->seq_number);
				g_hash_table_remove(component->video_retransmit_seqs, GUINT_TO_POINTER(seq));
				/* Free the packet */
				g_free(p->data);
				p->data = NULL;
				g_free(p);
				p = (janus_rtp_packet *)g_queue_peek_head(component->video_retransmit_buffer);
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
void janus_seq_list_free(janus_seq_info **head) {
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


/* Map of active plugin sessions */
static GHashTable *plugin_sessions;
static janus_mutex plugin_sessions_mutex;
gboolean janus_plugin_session_is_alive(janus_plugin_session *plugin_session) {
	/* Make sure this plugin session is still alive */
	janus_mutex_lock_nodebug(&plugin_sessions_mutex);
	janus_plugin_session *result = g_hash_table_lookup(plugin_sessions, plugin_session);
	janus_mutex_unlock_nodebug(&plugin_sessions_mutex);
	if(result == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid plugin session (%p)\n", plugin_session);
	}
	return (result != NULL);
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
			/* Be sure that iceloop is not running, before freeing */
			if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
				JANUS_LOG(LOG_WARN, "Handle %"SCNu64" cleanup skipped because iceloop is still running...\n", handle->handle_id);
				g_main_loop_quit(handle->iceloop);
				continue;
			}
			/* Be sure that icethread has finished, before freeing*/
			if(handle->icethread != NULL) {
				JANUS_LOG(LOG_WARN, "Handle %"SCNu64" cleanup skipped because icethread is still running...\n", handle->handle_id);
				continue;
			}
			/* Be sure that ice send thread has finished, before freeing*/
			if (g_atomic_int_get(&handle->send_thread_created) && handle->send_thread != NULL) {
				JANUS_LOG(LOG_WARN, "Handle %"SCNu64" cleanup skipped because icesendthread is still running...\n", handle->handle_id);
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


static void janus_ice_notify_trickle(janus_ice_handle *handle, char *buffer) {
	if(handle == NULL)
		return;
	char cbuffer[200];
	if(buffer != NULL)
		g_snprintf(cbuffer, sizeof(cbuffer), "candidate:%s", buffer);
	/* Send a "trickle" event to the browser */
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("trickle"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	json_t *candidate = json_object();
	if(buffer != NULL) {
		json_object_set_new(candidate, "sdpMid", json_string(handle->stream_mid));
		json_object_set_new(candidate, "sdpMLineIndex", json_integer(0));
		json_object_set_new(candidate, "candidate", json_string(cbuffer));
	} else {
		json_object_set_new(candidate, "completed", json_true());
	}
	json_object_set_new(event, "candidate", candidate);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending trickle event (%s) to transport...\n",
		handle->handle_id, buffer ? "candidate" : "end-of-candidates");
	janus_session_notify_event(session, event);
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, handle->opaque_id, info);
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}


/* Trickle helpers */
janus_ice_trickle *janus_ice_trickle_new(janus_ice_handle *handle, const char *transaction, json_t *candidate) {
	if(transaction == NULL || candidate == NULL)
		return NULL;
	janus_ice_trickle *trickle = g_malloc(sizeof(janus_ice_trickle));
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
		if(sdpMLineIndex > 0) {
			/* FIXME We bundle everything, so we ignore candidates for anything beyond the first m-line */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a %s candidate (index %d) but we're bundling, ignoring...\n",
				handle->handle_id, json_string_value(mid), sdpMLineIndex);
			return 0;
		}
		janus_ice_stream *stream = handle->stream;
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
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean full_trickle, gboolean ipv6, uint16_t rtp_min_port, uint16_t rtp_max_port) {
	janus_ice_lite_enabled = ice_lite;
	janus_ice_tcp_enabled = ice_tcp;
	janus_full_trickle_enabled = full_trickle;
	janus_ipv6_enabled = ipv6;
	JANUS_LOG(LOG_INFO, "Initializing ICE stuff (%s mode, ICE-TCP candidates %s, %s-trickle, IPv6 support %s)\n",
		janus_ice_lite_enabled ? "Lite" : "Full",
		janus_ice_tcp_enabled ? "enabled" : "disabled",
		janus_full_trickle_enabled ? "full" : "half",
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

	/* We keep track of plugin sessions to avoid problems */
	plugin_sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&plugin_sessions_mutex);

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
	JANUS_LOG(LOG_INFO, "  >> %s:%u (%s)\n", janus_stun_server, janus_stun_port, addr.family == AF_INET ? "IPv4" : "IPv6");
	/* Test the STUN server */
	StunAgent stun;
	stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
	StunMessage msg;
	uint8_t buf[1500];
	size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
	JANUS_LOG(LOG_INFO, "Testing STUN server: message is of %zu bytes\n", len);
	/* Use the janus_network_address info to drive the socket creation */
	int fd = socket(addr.family, SOCK_DGRAM, 0);
	if(fd < 0) {
		JANUS_LOG(LOG_FATAL, "Error creating socket for STUN BINDING test\n");
		return -1;
	}
	struct sockaddr *address = NULL, *remote = NULL;
	struct sockaddr_in address4, remote4;
	struct sockaddr_in6 address6, remote6;
	socklen_t addrlen = 0;
	if(addr.family == AF_INET) {
		memset(&address4, 0, sizeof(address4));
		address4.sin_family = AF_INET;
		address4.sin_port = 0;
		address4.sin_addr.s_addr = INADDR_ANY;
		memset(&remote4, 0, sizeof(remote4));
		remote4.sin_family = AF_INET;
		remote4.sin_port = htons(janus_stun_port);
		memcpy(&remote4.sin_addr, &addr.ipv4, sizeof(addr.ipv4));
		address = (struct sockaddr *)(&address4);
		remote = (struct sockaddr *)(&remote4);
		addrlen = sizeof(remote4);
	} else if(addr.family == AF_INET6) {
		memset(&address6, 0, sizeof(address6));
		address6.sin6_family = AF_INET6;
		address6.sin6_port = 0;
		address6.sin6_addr = in6addr_any;
		memset(&remote6, 0, sizeof(remote6));
		remote6.sin6_family = AF_INET6;
		remote6.sin6_port = htons(janus_stun_port);
		memcpy(&remote6.sin6_addr, &addr.ipv6, sizeof(addr.ipv6));
		remote6.sin6_addr = addr.ipv6;
		address = (struct sockaddr *)(&address6);
		remote = (struct sockaddr *)(&remote6);
		addrlen = sizeof(remote6);
	}
	if(bind(fd, address, addrlen) < 0) {
		JANUS_LOG(LOG_FATAL, "Bind failed for STUN BINDING test: %d (%s)\n", errno, strerror(errno));
		close(fd);
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, remote, addrlen);
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
	int err = select(fd+1, &readfds, NULL, NULL, &timeout);
	if(err < 0) {
		JANUS_LOG(LOG_FATAL, "Error waiting for a response to our STUN BINDING test: %d (%s)\n", errno, strerror(errno));
		close(fd);
		return -1;
	}
	if(!FD_ISSET(fd, &readfds)) {
		JANUS_LOG(LOG_FATAL, "No response to our STUN BINDING test\n");
		close(fd);
		return -1;
	}
	bytes = recvfrom(fd, buf, 1500, 0, remote, &addrlen);
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
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr((struct sockaddr *)address, &addr) != 0 ||
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
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr((struct sockaddr *)address, &addr) != 0 ||
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
	janus_ice_handle *handle = g_malloc0(sizeof(janus_ice_handle));
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
	janus_plugin_session *session_handle = g_malloc(sizeof(janus_plugin_session));
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
	/* Add this plugin session to active sessions map */
	janus_mutex_lock(&plugin_sessions_mutex);
	g_hash_table_insert(plugin_sessions, session_handle, session_handle);
	janus_mutex_unlock(&plugin_sessions_mutex);
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
	/* Remove the session from active sessions map */
	janus_mutex_lock(&plugin_sessions_mutex);
	gboolean found = g_hash_table_remove(plugin_sessions, handle->app_handle);
	if (!found) {
		janus_mutex_unlock(&plugin_sessions_mutex);
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	}
	/* This is to tell the plugin to stop using this session: we'll get rid of it later */
	handle->app_handle->stopped = 1;
	janus_mutex_unlock(&plugin_sessions_mutex);
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there */
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
		if(handle->iceloop != NULL) {
			if(handle->stream_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
			}
			if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
				g_main_loop_quit(handle->iceloop);
			}
		}
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s\n", plugin_t->get_name());
	/* Actually detach handle... */
	int error = 0;
	/* Notify the plugin that the session's over */
	plugin_t->destroy_session(handle->app_handle, &error);
	/* Get rid of the handle now */
	if(g_atomic_int_compare_and_exchange(&handle->dump_packets, 1, 0)) {
		janus_text2pcap_close(handle->text2pcap);
		g_clear_pointer(&handle->text2pcap, janus_text2pcap_free);
	}
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	if(handle->iceloop != NULL) {
		if(handle->stream_id > 0) {
			nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
		}
		if(handle->iceloop != NULL && g_main_loop_is_running(handle->iceloop)) {
			g_main_loop_quit(handle->iceloop);
		}
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
			session->session_id, handle_id, "detached", plugin_t->get_package(), handle->opaque_id);
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
		janus_mutex_lock(&plugin_sessions_mutex);
		handle->app_handle->stopped = 1;
		handle->app_handle->gateway_handle = NULL;
		handle->app_handle->plugin_handle = NULL;
		g_free(handle->app_handle);
		handle->app_handle = NULL;
		janus_mutex_unlock(&plugin_sessions_mutex);
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
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin != NULL) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the hangup because of a %s (%s)\n",
			handle->handle_id, reason, plugin->get_name());
		if(plugin && plugin->hangup_media && janus_plugin_session_is_alive(handle->app_handle))
			plugin->hangup_media(handle->app_handle);
		/* User will be notified only after the actual hangup */
		handle->hangup_reason = reason;
	}
	if(handle->queued_packets != NULL && handle->send_thread_created)
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_dtls_alert);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_dtls_alert);
#endif
	/* Get rid of the loop */
	if(handle->send_thread == NULL) {
		if(handle->iceloop != NULL) {
			if(handle->stream_id > 0) {
				nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context (handle->iceloop), NULL, NULL);
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
				if (handle->icectx != NULL) {
					g_main_context_wakeup(handle->icectx);
				}
			}
		}
	}
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
	if(handle->stream != NULL) {
		janus_ice_stream_free(handle->stream);
		handle->stream = NULL;
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
	handle->stream_mid = NULL;
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
	if (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) && handle->hangup_reason) {
		janus_ice_notify_hangup(handle, handle->hangup_reason);
	}
	handle->hangup_reason = NULL;
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] WebRTC resources freed\n", handle->handle_id);
}

void janus_ice_stream_free(janus_ice_stream *stream) {
	if(stream == NULL)
		return;
	if(stream->component != NULL) {
		janus_ice_component_free(stream->component);
		stream->component = NULL;
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
	if(stream->rtx_payload_types != NULL)
		g_hash_table_destroy(stream->rtx_payload_types);
	stream->rtx_payload_types = NULL;
	g_free(stream->audio_codec);
	stream->audio_codec = NULL;
	g_free(stream->video_codec);
	stream->video_codec = NULL;
	g_free(stream->audio_rtcp_ctx);
	stream->audio_rtcp_ctx = NULL;
	g_free(stream->video_rtcp_ctx[0]);
	stream->video_rtcp_ctx[0] = NULL;
	g_free(stream->video_rtcp_ctx[1]);
	stream->video_rtcp_ctx[1] = NULL;
	g_free(stream->video_rtcp_ctx[2]);
	stream->video_rtcp_ctx[2] = NULL;
	if(stream->rtx_nacked[0])
		g_hash_table_destroy(stream->rtx_nacked[0]);
	stream->rtx_nacked[0] = NULL;
	if(stream->rtx_nacked[1])
		g_hash_table_destroy(stream->rtx_nacked[1]);
	stream->rtx_nacked[1] = NULL;
	if(stream->rtx_nacked[2])
		g_hash_table_destroy(stream->rtx_nacked[2]);
	stream->rtx_nacked[2] = NULL;
	g_slist_free_full(stream->transport_wide_received_seq_nums, (GDestroyNotify)g_free);
	stream->transport_wide_received_seq_nums = NULL;
	stream->audio_first_ntp_ts = 0;
	stream->audio_first_rtp_ts = 0;
	stream->video_first_ntp_ts[0] = 0;
	stream->video_first_ntp_ts[1] = 0;
	stream->video_first_ntp_ts[2] = 0;
	stream->video_first_rtp_ts[0] = 0;
	stream->video_first_rtp_ts[1] = 0;
	stream->video_first_rtp_ts[2] = 0;
	stream->audio_last_ts = 0;
	stream->video_last_ts = 0;
	g_free(stream);
	stream = NULL;
}

void janus_ice_component_free(janus_ice_component *component) {
	if(component == NULL)
		return;
	janus_ice_stream *stream = component->stream;
	if(stream == NULL)
		return;
	janus_ice_handle *handle = stream->handle;
	if(handle == NULL)
		return;
	//~ janus_mutex_lock(&handle->mutex);
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
	if(component->audio_retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		while((p = (janus_rtp_packet *)g_queue_pop_head(component->audio_retransmit_buffer)) != NULL) {
			/* Remove from hashtable too */
			janus_rtp_header *header = (janus_rtp_header *)p->data;
			guint16 seq = ntohs(header->seq_number);
			g_hash_table_remove(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq));
			/* Free the packet */
			g_free(p->data);
			p->data = NULL;
			g_free(p);
		}
		g_queue_free(component->audio_retransmit_buffer);
		g_hash_table_destroy(component->audio_retransmit_seqs);
	}
	if(component->video_retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		while((p = (janus_rtp_packet *)g_queue_pop_head(component->video_retransmit_buffer)) != NULL) {
			/* Remove from hashtable too */
			janus_rtp_header *header = (janus_rtp_header *)p->data;
			guint16 seq = ntohs(header->seq_number);
			g_hash_table_remove(component->video_retransmit_seqs, GUINT_TO_POINTER(seq));
			/* Free the packet */
			g_free(p->data);
			p->data = NULL;
			g_free(p);
		}
		g_queue_free(component->video_retransmit_buffer);
		g_hash_table_destroy(component->video_retransmit_seqs);
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
	if(component->last_seqs_video[0])
		janus_seq_list_free(&component->last_seqs_video[0]);
	if(component->last_seqs_video[1])
		janus_seq_list_free(&component->last_seqs_video[1]);
	if(component->last_seqs_video[2])
		janus_seq_list_free(&component->last_seqs_video[2]);
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
				janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, handle->opaque_id, info);
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
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n",
			handle->handle_id, component->component_id, stream->stream_id);
		janus_ice_webrtc_hangup(handle, "ICE failed");
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
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]  No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	stream->cdone = 1;
	/* If we're doing full-trickle, send an event to the user too */
	if(janus_full_trickle_enabled) {
		/* Send a "trickle" event with completed:true to the browser */
		janus_ice_notify_trickle(handle, NULL);
	}
}

static void janus_ice_cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice) {
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
	if(component_id > 1) {
		/* State changed for a component we don't need anymore (rtcp-mux) */
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component state changed for component %d in stream %d: %d (%s)\n",
		handle->handle_id, component_id, stream_id, state, janus_get_ice_state_name(state));
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
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
	if(component_id > 1) {
		/* New selected pair for a component we don't need anymore (rtcp-mux) */
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local, remote);
#else
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local->foundation, remote->foundation);
#endif
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	/* Have we been here before? (might happen, when trickling) */
	if(component->component_connected > 0)
		return;
	/* Now we can start the DTLS handshake (FIXME This was on the 'connected' state notification, before) */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready enough, starting DTLS handshake...\n", handle->handle_id);
	component->component_connected = janus_get_monotonic_time();
	/* Start the DTLS handshake, at last */
	janus_dtls_srtp_handshake(component->dtls);
	/* Create retransmission timer */
	component->dtlsrt_source = g_timeout_source_new(50);
	g_source_set_callback(component->dtlsrt_source, janus_dtls_retry, component->dtls, NULL);
	guint id = g_source_attach(component->dtlsrt_source, handle->icectx);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
}

/* Candidates management */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate);
#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_local_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer ice) {
#else
static void janus_ice_cb_new_local_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice) {
#endif
	if(!janus_full_trickle_enabled) {
		/* Ignore if we're not full-trickling: for half-trickle
		 * janus_ice_candidates_to_sdp() is used instead */
		return;
	}
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new local candidate for component %d in stream %d: foundation=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, foundation);
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
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new local candidate for component %d in stream %d: type=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, ctype);
#endif
	if(component_id > 1) {
		/* New remote candidate for a component we don't need anymore (rtcp-mux) */
		return;
	}
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	/* Get local candidates and look for the related foundation */
	NiceCandidate *candidate = NULL;
	GSList *candidates = nice_agent_get_local_candidates(agent, component_id, stream_id), *tmp = candidates;
	while(tmp) {
		NiceCandidate *c = (NiceCandidate *)tmp->data;
		/* Check if this is what we're looking for */
		if(!strcasecmp(c->foundation, foundation)) {
			/* It is! */
			candidate = c;
			break;
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
	char buffer[200];
	if(janus_ice_candidate_to_string(handle, candidate, buffer, sizeof(buffer), TRUE) == 0) {
		/* Candidate encoded, send a "trickle" event to the browser (but only if it's not a 'prflx') */
		if(candidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
		} else {
			janus_ice_notify_trickle(handle, buffer);
		}
	}

#ifndef HAVE_LIBNICE_TCP
	nice_candidate_free(candidate);
#endif
}

#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer ice) {
#else
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
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
	if(component_id > 1) {
		/* New remote candidate for a component we don't need anymore (rtcp-mux) */
		return;
	}
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
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
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still waiting for the DTLS stack for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
		return;
	}
	/* What is this? */
	if (janus_is_dtls(buf) || (!janus_is_rtp(buf) && !janus_is_rtcp(buf))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Looks like DTLS!\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		component->in_stats.data.packets++;
		component->in_stats.data.bytes += len;
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/rfc5761#section-4) */
	if(len < 12)
		return;	/* Definitely nothing useful */
	if(janus_is_rtp(buf)) {
		/* This is RTP */
		if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			janus_rtp_header *header = (janus_rtp_header *)buf;
			guint32 packet_ssrc = ntohl(header->ssrc);
			/* Is this audio or video? */
			int video = 0, vindex = 0, rtx = 0;
			/* Bundled streams, check SSRC */
			video = ((stream->video_ssrc_peer[0] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[0] == packet_ssrc
				|| stream->video_ssrc_peer[1] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[1] == packet_ssrc
				|| stream->video_ssrc_peer[2] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[2] == packet_ssrc) ? 1 : 0);
			if(!video && stream->audio_ssrc_peer != packet_ssrc) {
				/* FIXME In case it happens, we should check what it is */
				if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer[0] == 0) {
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
					if(!found && stream->video_ssrc_peer[0] == 0 && stream->video_payload_types) {
						GList *pts = stream->video_payload_types;
						while(pts) {
							guint16 video_pt = GPOINTER_TO_UINT(pts->data);
							if(pt == video_pt) {
								JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unadvertized SSRC (%"SCNu32") is video! (payload type %"SCNu16")\n", handle->handle_id, packet_ssrc, pt);
								video = 1;
								stream->video_ssrc_peer[0] = packet_ssrc;
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
			/* Make sure we're prepared to receive this media packet */
			if((!video && !stream->audio_recv) || (video && !stream->video_recv))
				return;
			/* If this is video, check if this is simulcast and/or a retransmission using RFC4588 */
			if(video) {
				if(stream->video_ssrc_peer[1] == packet_ssrc) {
					/* FIXME Simulcast (1) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #1 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 1;
				} else if(stream->video_ssrc_peer[2] == packet_ssrc) {
					/* FIXME Simulcast (2) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #2 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 2;
				} else {
					/* Maybe a video retransmission using RFC4588? */
					if(stream->video_ssrc_peer_rtx[0] == packet_ssrc) {
						rtx = 1;
						vindex = 0;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video (SSRC %"SCNu32")...\n",
							handle->handle_id, packet_ssrc);
					} else if(stream->video_ssrc_peer_rtx[1] == packet_ssrc) {
						rtx = 1;
						vindex = 1;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					} else if(stream->video_ssrc_peer_rtx[2] == packet_ssrc) {
						rtx = 1;
						vindex = 2;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					}
				}
			}

			int buflen = len;
			srtp_err_status_t res = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
			if(res != srtp_err_status_ok) {
				if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
					/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n", handle->handle_id, janus_srtp_error_str(res), len, buflen, timestamp, seq);
				}
			} else {
				if(video) {
					if(stream->video_ssrc_peer[0] == 0) {
						stream->video_ssrc_peer[0] = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer video SSRC: %u\n", handle->handle_id, stream->video_ssrc_peer[0]);
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
				/* If this is a retransmission using RFC4588, we have to do something first to get the original packet */
				janus_rtp_header *header = (janus_rtp_header *)buf;
				if(rtx) {
					/* The original sequence number is in the first two bytes of the payload */
					int plen = 0;
					char *payload = janus_rtp_payload(buf, buflen, &plen);
					guint16 original_seq = 0;
					memcpy(&original_seq, payload, 2);
					original_seq = htons(original_seq);
					/* Rewrite the header with the info from the original packet (payload type, SSRC, sequence number) */
					header->type = stream->video_payload_type;
					packet_ssrc = stream->video_ssrc_peer[vindex];
					header->ssrc = htonl(packet_ssrc);
					header->seq_number = htons(original_seq);
					/* Finally, remove the original sequence number from the payload: rather than moving
					 * the whole payload back two bytes, we shift the header forward (less bytes to move) */
					buflen -= 2;
					size_t hsize = payload-buf;
					memmove(buf+2, buf, hsize);
					buf += 2;
					header = (janus_rtp_header *)buf;
				}
				if(video && stream->rtx_nacked[vindex] != NULL) {
					/* Check if this packet is a duplicate: can happen with RFC4588 */
					guint16 seqno = ntohs(header->seq_number);
					int nstate = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_nacked[vindex], GUINT_TO_POINTER(seqno)));
					if(nstate == 1) {
						/* Packet was NACKed and this is the first time we receive it: change state to received */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						g_hash_table_insert(stream->rtx_nacked[vindex], GUINT_TO_POINTER(seqno), GUINT_TO_POINTER(2));
					} else if(nstate == 2) {
						/* We already received this packet: drop it */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Detected duplicate packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						return;
					}
				}
				/* Backup the RTP header before passing it to the proper RTP switching context */
				janus_rtp_header backup = *header;
				if(!video) {
					if(stream->audio_ssrc_peer_orig == 0)
						stream->audio_ssrc_peer_orig = packet_ssrc;
					janus_rtp_header_update(header, &stream->rtp_ctx[0], FALSE, 0);
					header->ssrc = htonl(stream->audio_ssrc_peer_orig);
				} else {
					if(stream->video_ssrc_peer_orig[vindex] == 0)
						stream->video_ssrc_peer_orig[vindex] = packet_ssrc;
					janus_rtp_header_update(header, &stream->rtp_ctx[vindex], TRUE, 0);
					header->ssrc = htonl(stream->video_ssrc_peer_orig[vindex]);
				}
				/* Keep track of payload types too */
				if(!video && stream->audio_payload_type < 0) {
					stream->audio_payload_type = header->type;
					if(stream->audio_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->audio_payload_type);
						if(codec != NULL)
							stream->audio_codec = g_strdup(codec);
					}
				} else if(video && stream->video_payload_type < 0) {
					stream->video_payload_type = header->type;
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
							stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
						stream->video_rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(stream->video_payload_type)));
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
							handle->handle_id, stream->video_rtx_payload_type);
					}
					if(stream->video_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->video_payload_type);
						if(codec != NULL)
							stream->video_codec = g_strdup(codec);
					}
					if(stream->video_is_keyframe == NULL && stream->video_codec != NULL) {
						if(!strcasecmp(stream->video_codec, "vp8"))
							stream->video_is_keyframe = &janus_vp8_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "vp9"))
							stream->video_is_keyframe = &janus_vp9_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "h264"))
							stream->video_is_keyframe = &janus_h264_is_keyframe;
					}
				}
				/* Check if we need to handle transport wide cc */
				if(stream->do_transport_wide_cc) {
					guint16 transport_seq_num;
					/* Get transport wide seq num */
					if(janus_rtp_header_extension_parse_transport_wide_cc(buf, buflen, stream->transport_wide_cc_ext_id, &transport_seq_num)==0) {
						/* Get current timestamp */
						struct timeval now;
						gettimeofday(&now,0);
						/* Create <seq num, time> pair */
						janus_rtcp_transport_wide_cc_stats *stats = g_malloc0(sizeof(janus_rtcp_transport_wide_cc_stats));
						/* Check if we have a sequence wrap */
						if(transport_seq_num<0x0FFF && (stream->transport_wide_cc_last_seq_num&0xFFFF)>0xF000) {
							/* Increase cycles */
							stream->transport_wide_cc_cycles++;
						}
						/* Get extended value */
						guint32 transport_ext_seq_num = stream->transport_wide_cc_cycles<<16 | transport_seq_num;
						/* Store last received transport seq num */
						stream->transport_wide_cc_last_seq_num = transport_seq_num;
						/* Set stats values */
						stats->transport_seq_num = transport_ext_seq_num;
						stats->timestamp = (((guint64)now.tv_sec)*1E6+now.tv_usec);
						/* Lock & append to received list*/
						janus_mutex_lock(&stream->mutex);
						stream->transport_wide_received_seq_nums = g_slist_prepend(stream->transport_wide_received_seq_nums, stats);
						janus_mutex_unlock(&stream->mutex);
					}
				}
				/* Pass the data to the responsible plugin */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp)
					plugin->incoming_rtp(handle->app_handle, video, buf, buflen);
				/* Restore the header for the stats (plugins may have messed with it) */
				*header = backup;
				/* Update stats (overall data received, and data received in the last second) */
				if(buflen > 0) {
					gint64 now = janus_get_monotonic_time();
					if(!video) {
						if(component->in_stats.audio.bytes == 0 || component->in_stats.audio.notified_lastsec) {
							/* We either received our first audio packet, or we started receiving it again after missing more than a second */
							component->in_stats.audio.notified_lastsec = FALSE;
							janus_ice_notify_media(handle, FALSE, TRUE);
						}
						/* Overall audio data */
						component->in_stats.audio.packets++;
						component->in_stats.audio.bytes += buflen;
						/* Last second audio data */
						if(component->in_stats.audio.updated == 0)
							component->in_stats.audio.updated = now;
						if(now > component->in_stats.audio.updated &&
								now - component->in_stats.audio.updated >= G_USEC_PER_SEC) {
							component->in_stats.audio.bytes_lastsec = component->in_stats.audio.bytes_lastsec_temp;
							component->in_stats.audio.bytes_lastsec_temp = 0;
							component->in_stats.audio.updated = now;
						}
						component->in_stats.audio.bytes_lastsec_temp += buflen;
					} else {
						if(component->in_stats.video[vindex].bytes == 0 || component->in_stats.video[vindex].notified_lastsec) {
							/* We either received our first video packet, or we started receiving it again after missing more than a second */
							component->in_stats.video[vindex].notified_lastsec = FALSE;
							janus_ice_notify_media(handle, TRUE, TRUE);
						}
						/* Overall video data for this SSRC */
						component->in_stats.video[vindex].packets++;
						component->in_stats.video[vindex].bytes += buflen;
						/* Last second video data for this SSRC */
						if(component->in_stats.video[vindex].updated == 0)
							component->in_stats.video[vindex].updated = now;
						if(now > component->in_stats.video[vindex].updated &&
								now - component->in_stats.video[vindex].updated >= G_USEC_PER_SEC) {
							component->in_stats.video[vindex].bytes_lastsec = component->in_stats.video[vindex].bytes_lastsec_temp;
							component->in_stats.video[vindex].bytes_lastsec_temp = 0;
							component->in_stats.video[vindex].updated = now;
						}
						component->in_stats.video[vindex].bytes_lastsec_temp += buflen;
					}
				}

				/* Update the RTCP context as well (but not if it's a retransmission) */
				if(!rtx) {
					rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[vindex] : stream->audio_rtcp_ctx;
					janus_rtcp_process_incoming_rtp(rtcp_ctx, buf, buflen);
				}

				/* Keep track of RTP sequence numbers, in case we need to NACK them */
				/* 	Note: unsigned int overflow/underflow wraps (defined behavior) */
				if((!video && !component->do_audio_nacks) || (video && !component->do_video_nacks)) {
					/* ... unless NACKs are disabled for this medium */
					return;
				}
				/* If this is video, check if this is a keyframe: if so, we empty our NACK queue */
				if(video && stream->video_is_keyframe) {
					int plen = 0;
					char *payload = janus_rtp_payload(buf, buflen, &plen);
					if(stream->video_is_keyframe(payload, plen)) {
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe received, resetting NACK queue\n", handle->handle_id);
						if(component->last_seqs_video[vindex])
							janus_seq_list_free(&component->last_seqs_video[vindex]);
					}
				}
				guint16 new_seqn = ntohs(header->seq_number);
				guint16 cur_seqn;
				int last_seqs_len = 0;
				janus_mutex_lock(&component->mutex);
				janus_seq_info **last_seqs = video ? &component->last_seqs_video[vindex] : &component->last_seqs_audio;
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
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Big sequence number jump %hu -> %hu (%s stream #%d)\n",
						handle->handle_id, cur_seqn, new_seqn, video ? "video" : "audio", vindex);
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
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received missed sequence number %"SCNu16" (%s stream #%d)\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							cur_seq->state = SEQ_RECVED;
						} else if(cur_seq->state == SEQ_MISSING && now - cur_seq->ts > SEQ_MISSING_WAIT) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16" (%s stream #%d), sending 1st NACK\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							nacks = g_slist_append(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_NACKED;
							if(video && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* Keep track of this sequence number, we need to avoid duplicates */
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Tracking NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
									handle->handle_id, cur_seq->seq, packet_ssrc, vindex);
								if(stream->rtx_nacked[vindex] == NULL)
									stream->rtx_nacked[vindex] = g_hash_table_new(NULL, NULL);
								g_hash_table_insert(stream->rtx_nacked[vindex], GUINT_TO_POINTER(cur_seq->seq), GINT_TO_POINTER(1));
								/* We don't track it forever, though: add a timed source to remove it in a few seconds */
								janus_ice_nacked_packet *np = g_malloc(sizeof(janus_ice_nacked_packet));
								np->handle = handle;
								np->seq_number = new_seqn;
								np->vindex = vindex;
								GSource *timeout_source = g_timeout_source_new_seconds(5);
								g_source_set_callback(timeout_source, janus_ice_nacked_packet_cleanup, np, (GDestroyNotify)g_free);
								g_source_attach(timeout_source, handle->icectx);
								g_source_unref(timeout_source);
							}
						} else if(cur_seq->state == SEQ_NACKED  && now - cur_seq->ts > SEQ_NACKED_WAIT) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16" (%s stream #%d), sending 2nd NACK\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
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
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] Now sending NACK for %u missed packets (%s stream #%d)\n",
						handle->handle_id, nacks_count, video ? "video" : "audio", vindex);
					char nackbuf[120];
					int res = janus_rtcp_nacks(nackbuf, sizeof(nackbuf), nacks);
					if(res > 0) {
						/* Set the right local and remote SSRC in the RTCP packet */
						janus_rtcp_fix_ssrc(NULL, nackbuf, res, 1,
							video ? stream->video_ssrc : stream->audio_ssrc,
							video ? stream->video_ssrc_peer[vindex] : stream->audio_ssrc_peer);
						janus_ice_relay_rtcp_internal(handle, video, nackbuf, res, FALSE);
					}
					/* Update stats */
					component->nack_sent_recent_cnt += nacks_count;
					if(video) {
						component->out_stats.video[vindex].nacks += nacks_count;
					} else {
						component->out_stats.audio.nacks += nacks_count;
					}
					/* Inform the plugin about the slow downlink in case it's needed */
					janus_slow_link_update(component, handle, nacks_count, video, 0, now);
				}
				if (component->nack_sent_recent_cnt &&
						(now - component->nack_sent_log_ts) > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sent NACKs for %u missing packets (%s stream #%d)\n",
						handle->handle_id, component->nack_sent_recent_cnt, video ? "video" : "audio", vindex);
					component->nack_sent_recent_cnt = 0;
					component->nack_sent_log_ts = now;
				}
				janus_mutex_unlock(&component->mutex);
				g_slist_free(nacks);
				nacks = NULL;
			}
		}
		return;
	} else if(janus_is_rtcp(buf)) {
		/* This is RTCP */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTCP packet\n", handle->handle_id);
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
				/* Check if there's an RTCP BYE: in case, let's log it */
				if(janus_rtcp_has_bye(buf, buflen)) {
					/* Note: we used to use this as a trigger to close the PeerConnection, but not anymore
					 * Discussion here, https://groups.google.com/forum/#!topic/meetecho-janus/4XtfbYB7Jvc */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got RTCP BYE on stream %"SCNu16" (component %"SCNu16")\n", handle->handle_id, stream->stream_id, component->component_id);
				}
				/* Is this audio or video? */
				int video = 0, vindex = 0;
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
					if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer[0] == 0) {
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
						/* Check the remote SSRC, compare it to what we have: in case
						 * we're simulcasting, let's compare to the other SSRCs too */
						guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, len);
						if(rtcp_ssrc == stream->audio_ssrc_peer) {
							video = 0;
						} else if(rtcp_ssrc == stream->video_ssrc_peer[0]) {
							video = 1;
						} else if(stream->video_ssrc_peer[1] && rtcp_ssrc == stream->video_ssrc_peer[1]) {
							video = 1;
							vindex = 1;
						} else if(stream->video_ssrc_peer[2] && rtcp_ssrc == stream->video_ssrc_peer[2]) {
							video = 1;
							vindex = 2;
						}
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (remote SSRC: video=%"SCNu32" #%d, audio=%"SCNu32", got %"SCNu32")\n",
							handle->handle_id, video ? "video" : "audio", stream->video_ssrc_peer[vindex], vindex, stream->audio_ssrc_peer, rtcp_ssrc);
					}
				}

				/* Let's process this RTCP (compound?) packet, and update the RTCP context for this stream in case */
				rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[vindex] : stream->audio_rtcp_ctx;
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
						int in_rb = 0;
						/* Check if we have the packet */
						janus_rtp_packet *p = g_hash_table_lookup(video ?
							component->video_retransmit_seqs : component->audio_retransmit_seqs, GUINT_TO_POINTER(seqnr));
						if(p == NULL) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Can't retransmit packet %u, we don't have it...\n", handle->handle_id, seqnr);
						} else {
							/* Should we retransmit this packet? */
							if((p->last_retransmit > 0) && (now-p->last_retransmit < MAX_NACK_IGNORE)) {
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"ms ago, skipping\n", handle->handle_id, seqnr, now-p->last_retransmit);
								list = list->next;
								continue;
							}
							in_rb = 1;
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission due to NACK\n", handle->handle_id, seqnr);
							p->last_retransmit = now;
							retransmits_cnt++;
							/* Enqueue it */
							janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
							pkt->data = g_malloc(p->length);
							memcpy(pkt->data, p->data, p->length);
							pkt->length = p->length;
							pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
							pkt->control = FALSE;
							pkt->retransmission = TRUE;
							/* What to send and how depends on whether we're doing RFC4588 or not */
							if(!video || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* We're not: just clarify the packet was already encrypted before */
								pkt->encrypted = TRUE;
							} else {
								/* We are: overwrite the RTP header (which means we'll need a new SRTP encrypt) */
								janus_rtp_header *header = (janus_rtp_header *)pkt->data;
								header->type = stream->video_rtx_payload_type;
								header->ssrc = htonl(stream->video_ssrc_rtx);
								component->rtx_seq_number++;
								header->seq_number = htons(component->rtx_seq_number);
							}
							if(handle->queued_packets != NULL)
#if GLIB_CHECK_VERSION(2, 46, 0)
								g_async_queue_push_front(handle->queued_packets, pkt);
#else
								g_async_queue_push(handle->queued_packets, pkt);
#endif
						}
						if (rtcp_ctx != NULL && in_rb) {
							g_atomic_int_inc(&rtcp_ctx->nack_count);
						}
						list = list->next;
					}
					component->retransmit_recent_cnt += retransmits_cnt;
					/* FIXME Remove the NACK compound packet, we've handled it */
					buflen = janus_rtcp_remove_nacks(buf, buflen);
					/* Update stats */
					if(video) {
						component->in_stats.video[vindex].nacks += nacks_count;
					} else {
						component->in_stats.audio.nacks += nacks_count;
					}
					/* Inform the plugin about the slow uplink in case it's needed */
					janus_slow_link_update(component, handle, retransmits_cnt, video, 1, now);
					janus_mutex_unlock(&component->mutex);
					g_slist_free(nacks);
					nacks = NULL;
				}
				if(component->retransmit_recent_cnt &&
						now - component->retransmit_log_ts > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Retransmitted %u packets due to NACK (%s stream #%d)\n",
						handle->handle_id, component->retransmit_recent_cnt, video ? "video" : "audio", vindex);
					component->retransmit_recent_cnt = 0;
					component->retransmit_log_ts = now;
				}

				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtcp)
					plugin->incoming_rtcp(handle->app_handle, video, buf, buflen);
			}
		}
		return;
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Not RTP and not RTCP... may these be data channels?\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (only overall data received) */
		if(len > 0) {
			component->in_stats.data.packets++;
			component->in_stats.data.bytes += len;
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
	JANUS_LOG(LOG_DBG, "[%"SCNu64"] Looping (ICE)...\n", handle->handle_id);
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
		g_main_loop_run (loop);
	} else {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping ICE loop because alert has been set\n", handle->handle_id);
	}
	if(handle->cdone == 0)
		handle->cdone = -1;
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
		janus_ice_webrtc_free(handle);
	}
	g_thread_unref(g_thread_self());
	handle->icethread = NULL;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE thread ended!\n", handle->handle_id);
	return NULL;
}

/* Helper: encoding local candidates to string/SDP */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate) {
	if(!handle || !handle->agent || !c || !buffer || buflen < 1)
		return -1;
	janus_ice_stream *stream = handle->stream;
	if(!stream)
		return -2;
	janus_ice_component *component = stream->component;
	if(!component)
		return -3;
	char *host_ip = NULL;
	if(nat_1_1_enabled) {
		/* A 1:1 NAT mapping was specified, overwrite all the host addresses with the public IP */
		host_ip = janus_get_public_ip();
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Public IP specified and 1:1 NAT mapping enabled (%s), using that as host address in the candidates\n", handle->handle_id, host_ip);
	}
	/* Encode the candidate to a string */
	gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
	gint port = 0, base_port = 0;
	nice_address_to_string(&(c->addr), (gchar *)&address);
	port = nice_address_get_port(&(c->addr));
	nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
	base_port = nice_address_get_port(&(c->base_addr));
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
	/* Start */
	if(c->type == NICE_CANDIDATE_TYPE_HOST) {
		/* 'host' candidate */
		if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ host",
					c->foundation, c->component_id,
					"udp", c->priority,
					host_ip ? host_ip : address, port);
		} else {
			if(!janus_ice_tcp_enabled) {
				/* ICE-TCP support disabled */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
				return -4;
			}
#ifndef HAVE_LIBNICE_TCP
			/* TCP candidates are only supported since libnice 0.1.8 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			return -4;
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
				return -5;
			}
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ host tcptype %s",
					c->foundation, c->component_id,
					"tcp", c->priority,
					host_ip ? host_ip : address, port, type);
#endif
		}
	} else if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
			c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE ||
			c->type == NICE_CANDIDATE_TYPE_RELAYED) {
		/* 'srflx', 'prflx', or 'relay' candidate: what is this, exactly? */
		const char *ltype = NULL;
		switch(c->type) {
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
		if(ltype == NULL)
			return -5;
		if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
			nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
			gint base_port = nice_address_get_port(&(c->base_addr));
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ %s raddr %s rport %d",
					c->foundation, c->component_id,
					"udp", c->priority,
					address, port, ltype,
					base_address, base_port);
		} else {
			if(!janus_ice_tcp_enabled) {
				/* ICE-TCP support disabled */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
				return -4;
			}
#ifndef HAVE_LIBNICE_TCP
			/* TCP candidates are only supported since libnice 0.1.8 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			return -4;
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
				return -5;
			} else {
				g_snprintf(buffer, buflen,
					"%s %d %s %d %s %d typ %s raddr %s rport %d tcptype %s",
						c->foundation, c->component_id,
						"tcp", c->priority,
						address, port, ltype,
						base_address, base_port, type);
			}
#endif
		}
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]     %s\n", handle->handle_id, buffer);
	if(log_candidate) {
		/* Save for the summary, in case we need it */
		component->local_candidates = g_slist_append(component->local_candidates, g_strdup(buffer));
		/* Notify event handlers */
		if(janus_events_is_enabled()) {
			janus_session *session = (janus_session *)handle->session;
			json_t *info = json_object();
			json_object_set_new(info, "local-candidate", json_string(buffer));
			json_object_set_new(info, "stream_id", json_integer(stream->stream_id));
			json_object_set_new(info, "component_id", json_integer(component->component_id));
			janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
		}
	}
	return 0;
}

void janus_ice_candidates_to_sdp(janus_ice_handle *handle, janus_sdp_mline *mline, guint stream_id, guint component_id) {
	if(!handle || !handle->agent || !mline)
		return;
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	NiceAgent *agent = handle->agent;
	/* Iterate on all */
	gchar buffer[200];
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	gboolean log_candidates = (component->local_candidates == NULL);
	for (i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), log_candidates) == 0) {
			/* Candidate encoded, add to the SDP (but only if it's not a 'prflx') */
			if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
			} else {
				janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
				mline->attributes = g_list_append(mline->attributes, a);
			}
		}
		nice_candidate_free(c);
	}
	/* Done */
	g_slist_free(candidates);
}

void janus_ice_setup_remote_candidates(janus_ice_handle *handle, guint stream_id, guint component_id) {
	if(!handle || !handle->agent)
		return;
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such stream %d: cannot setup remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
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

int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video, int data, int trickle) {
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
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);

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
	if(janus_full_trickle_enabled) {
#ifndef HAVE_LIBNICE_TCP
		g_signal_connect (G_OBJECT (handle->agent), "new-candidate",
#else
		g_signal_connect (G_OBJECT (handle->agent), "new-candidate-full",
#endif
			G_CALLBACK (janus_ice_cb_new_local_candidate), handle);
	}
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
	handle->stream_id = 0;
	/* If this is our first offer, let's generate some mids */
	if(!offer) {
		if(audio) {
			if(handle->audio_mid == NULL)
				handle->audio_mid = g_strdup("audio");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->audio_mid;
		}
		if(video) {
			if(handle->video_mid == NULL)
				handle->video_mid = g_strdup("video");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->video_mid;
		}
#ifdef HAVE_SCTP
		if(data) {
			if(handle->data_mid == NULL)
				handle->data_mid = g_strdup("data");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->data_mid;
		}
#endif
	}
	/* Now create an ICE stream for all the media we'll handle */
	handle->stream_id = nice_agent_add_stream(handle->agent, 1);
	janus_ice_stream *stream = g_malloc0(sizeof(janus_ice_stream));
	stream->stream_id = handle->stream_id;
	stream->handle = handle;
	stream->audio_payload_type = -1;
	stream->video_payload_type = -1;
	stream->video_rtx_payload_type = -1;
	/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
	stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
	if(audio) {
		stream->audio_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		stream->audio_rtcp_ctx = g_malloc0(sizeof(janus_rtcp_context));
		stream->audio_rtcp_ctx->tb = 48000;	/* May change later */
	}
	if(video) {
		stream->video_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
			/* Create an SSRC for RFC4588 as well */
			stream->video_ssrc_rtx = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		}
		stream->video_rtcp_ctx[0] = g_malloc0(sizeof(janus_rtcp_context));
		stream->video_rtcp_ctx[0]->tb = 90000;
	}
	janus_mutex_init(&stream->mutex);
	if(!have_turnrest_credentials) {
		/* No TURN REST API server and credentials, any static ones? */
		if(janus_turn_server != NULL) {
			/* We need relay candidates as well */
			gboolean ok = nice_agent_set_relay_info(handle->agent, handle->stream_id, 1,
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
			gboolean ok = nice_agent_set_relay_info(handle->agent, handle->stream_id, 1,
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
	handle->stream = stream;
	janus_ice_component *component = g_malloc0(sizeof(janus_ice_component));
	component->stream = stream;
	component->stream_id = stream->stream_id;
	component->component_id = 1;
	janus_mutex_init(&component->mutex);
	stream->component = component;
#ifdef HAVE_PORTRANGE
	/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
	nice_agent_set_port_range(handle->agent, handle->stream_id, 1, rtp_range_min, rtp_range_max);
#endif
	nice_agent_gather_candidates(handle->agent, handle->stream_id);
	nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->iceloop), janus_ice_cb_nice_recv, component);
#ifdef HAVE_LIBCURL
	if(turnrest_credentials != NULL) {
		janus_turnrest_response_destroy(turnrest_credentials);
		turnrest_credentials = NULL;
	}
#endif
	/* Create DTLS-SRTP context, at last */
	component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
	if(!component->dtls) {
		/* FIXME We should clear some resources... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error creating DTLS-SRTP stack...\n", handle->handle_id);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		return -1;
	}
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
	return 0;
}

void janus_ice_restart(janus_ice_handle *handle) {
	if(!handle || !handle->agent || !handle->stream)
		return;
	/* Restart ICE */
	if(nice_agent_restart(handle->agent) == FALSE) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE restart failed...\n", handle->handle_id);
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
}

void janus_ice_resend_trickles(janus_ice_handle *handle) {
	if(!handle || !handle->agent)
		return;
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);
	janus_ice_stream *stream = handle->stream;
	if(!stream)
		return;
	janus_ice_component *component = stream->component;
	if(!component)
		return;
	NiceAgent *agent = handle->agent;
	/* Iterate on all existing local candidates */
	gchar buffer[200];
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream->stream_id, component->component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n",
		handle->handle_id, g_slist_length(candidates), stream->stream_id, component->component_id);
	for (i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE)
			continue;
		if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), FALSE) == 0) {
			/* Candidate encoded, send a "trickle" event to the browser */
			janus_ice_notify_trickle(handle, buffer);
		}
		nice_candidate_free(c);
	}
	/* Send a "completed" trickle at the end */
	janus_ice_notify_trickle(handle, NULL);
}

static gint rtcp_transport_wide_cc_stats_comparator(gconstpointer item1, gconstpointer item2) {
	return ((rtcp_transport_wide_cc_stats*)item1)->transport_seq_num - ((rtcp_transport_wide_cc_stats*)item2)->transport_seq_num;
}

void *janus_ice_send_thread(void *data) {
	janus_ice_handle *handle = (janus_ice_handle *)data;
	janus_session *session = (janus_session *)handle->session;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE send thread started...\n", handle->handle_id);
	janus_ice_queued_packet *pkt = NULL;
	gint64 before = janus_get_monotonic_time(),
		rtcp_last_sr_rr = before, last_event = before,
		last_srtp_summary = before, last_nack_cleanup = before;
	gboolean alert_sent = FALSE;
	while(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		if(handle->queued_packets != NULL) {
			pkt = g_async_queue_timeout_pop(handle->queued_packets, 500000);
		} else {
			g_usleep(100000);
		}
		if(pkt == &janus_ice_dtls_alert) {
			/* The session is over, send an alert on all streams and components */
			if(!alert_sent && handle->stream && handle->stream->component && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
				janus_dtls_srtp_send_alert(handle->stream->component->dtls);
				alert_sent = TRUE;
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
				if (handle->icectx != NULL) {
					g_main_context_wakeup(handle->icectx);
				}
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
		if(alert_sent)
			alert_sent = FALSE;
		/* Reset the last second counters if too much time passed with no data in or out */
		gint64 now = janus_get_monotonic_time();
		janus_ice_stream *stream = handle->stream;
		if(stream && stream->component) {
			janus_ice_component *component = stream->component;
			/* Audio */
			gint64 last = component->in_stats.audio.updated;
			if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->in_stats.audio.bytes_lastsec_temp > 0) {
				component->in_stats.audio.bytes_lastsec = 0;
				component->in_stats.audio.bytes_lastsec_temp = 0;
			}
			last = component->out_stats.audio.updated;
			if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->out_stats.audio.bytes_lastsec_temp > 0) {
				component->out_stats.audio.bytes_lastsec = 0;
				component->out_stats.audio.bytes_lastsec_temp = 0;
			}
			/* Video */
			int vindex = 0;
			for(vindex=0; vindex < 3; vindex++) {
				gint64 last = component->in_stats.video[vindex].updated;
				if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->in_stats.video[vindex].bytes_lastsec_temp > 0) {
					component->in_stats.video[vindex].bytes_lastsec = 0;
					component->in_stats.video[vindex].bytes_lastsec_temp = 0;
				}
				last = component->out_stats.video[vindex].updated;
				if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->out_stats.video[vindex].bytes_lastsec_temp > 0) {
					component->out_stats.video[vindex].bytes_lastsec = 0;
					component->out_stats.video[vindex].bytes_lastsec_temp = 0;
				}
			}
		}
		/* Let's see if we need to notify the user about no incoming audio or video */
		if(no_media_timer > 0 && now-before >= G_USEC_PER_SEC) {
			stream = handle->stream;
			if(stream && stream->component) {
				janus_ice_component *component = stream->component;
				/* Audio */
				gint64 last = component->in_stats.audio.updated;
				if(!component->in_stats.audio.notified_lastsec && last &&
						!component->in_stats.audio.bytes_lastsec && !component->in_stats.audio.bytes_lastsec_temp &&
							now-last >= (gint64)no_media_timer*G_USEC_PER_SEC) {
					/* We missed more than no_second_timer seconds of audio! */
					component->in_stats.audio.notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive audio for more than %d seconds...\n", handle->handle_id, no_media_timer);
					janus_ice_notify_media(handle, FALSE, FALSE);
				}
				/* Video */
				last = component->in_stats.video[0].updated;
				if(!component->in_stats.video[0].notified_lastsec && last &&
						!component->in_stats.video[0].bytes_lastsec && !component->in_stats.video[0].bytes_lastsec_temp &&
							now-last >= (gint64)no_media_timer*G_USEC_PER_SEC) {
					/* We missed more than no_second_timer seconds of video! */
					component->in_stats.video[0].notified_lastsec = TRUE;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video for more than a second...\n", handle->handle_id);
					janus_ice_notify_media(handle, TRUE, FALSE);
				}
			}
			before = now;
		}
		/* Let's check if it's time to send a RTCP SR/SDES/RR as well */
		if(now-rtcp_last_sr_rr >= 1*G_USEC_PER_SEC) {
			rtcp_last_sr_rr = now;
			janus_ice_stream *stream = handle->stream;
			/* Audio */
			if(stream && stream->component && stream->component->out_stats.audio.packets > 0) {
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
				sr->ssrc = htonl(stream->audio_ssrc);
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
					uint32_t rtp_ts = ((ntp-stream->audio_first_ntp_ts)*(rtcp_ctx->tb))/1000000 + stream->audio_first_rtp_ts;
					sr->si.rtp_ts = htonl(rtp_ts);
				}
				sr->si.s_packets = htonl(stream->component->out_stats.audio.packets);
				sr->si.s_octets = htonl(stream->component->out_stats.audio.bytes);
				rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
				janus_rtcp_sdes_cname((char *)sdes, sdeslen, "janusaudio", 10);
				sdes->chunk.ssrc = htonl(stream->audio_ssrc);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 0, rtcpbuf, srlen+sdeslen, FALSE);
			}
			if(stream) {
				/* Create a RR too */
				int rrlen = 32;
				char rtcpbuf[32];
				memset(rtcpbuf, 0, sizeof(rtcpbuf));
				rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 1;
				rr->header.length = htons((rrlen/4)-1);
				rr->ssrc = htonl(stream->audio_ssrc);
				janus_rtcp_report_block(stream->audio_rtcp_ctx, &rr->rb[0]);
				rr->rb[0].ssrc = htonl(stream->audio_ssrc_peer);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 0, rtcpbuf, 32, FALSE);
			}
			/* Now do the same for video */
			if(stream && stream->component && stream->component->out_stats.video[0].packets > 0) {
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
				sr->ssrc = htonl(stream->video_ssrc);
				struct timeval tv;
				gettimeofday(&tv, NULL);
				uint32_t s = tv.tv_sec + 2208988800u;
				uint32_t u = tv.tv_usec;
				uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
				sr->si.ntp_ts_msw = htonl(s);
				sr->si.ntp_ts_lsw = htonl(f);
				/* Compute an RTP timestamp coherent with the NTP one */
				rtcp_context *rtcp_ctx = stream->video_rtcp_ctx[0];
				if(rtcp_ctx == NULL) {
					sr->si.rtp_ts = htonl(stream->video_last_ts);	/* FIXME */
				} else {
					int64_t ntp = tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
					uint32_t rtp_ts = ((ntp-stream->video_first_ntp_ts[0])*(rtcp_ctx->tb))/1000000 + stream->video_first_rtp_ts[0];
					sr->si.rtp_ts = htonl(rtp_ts);
				}
				sr->si.s_packets = htonl(stream->component->out_stats.video[0].packets);
				sr->si.s_octets = htonl(stream->component->out_stats.video[0].bytes);
				rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
				janus_rtcp_sdes_cname((char *)sdes, sdeslen, "janusvideo", 10);
				sdes->chunk.ssrc = htonl(stream->video_ssrc);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 1, rtcpbuf, srlen+sdeslen, FALSE);
			}
			if(stream) {
				/* Create a RR too (for each SSRC, if we're simulcasting) */
				int vindex=0;
				for(vindex=0; vindex<3; vindex++) {
					if(stream->video_rtcp_ctx[vindex] && stream->video_rtcp_ctx[vindex]->rtp_recvd) {
						/* Create a RR */
						int rrlen = 32;
						char rtcpbuf[32];
						memset(rtcpbuf, 0, sizeof(rtcpbuf));
						rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
						rr->header.version = 2;
						rr->header.type = RTCP_RR;
						rr->header.rc = 1;
						rr->header.length = htons((rrlen/4)-1);
						rr->ssrc = htonl(stream->video_ssrc);
						janus_rtcp_report_block(stream->video_rtcp_ctx[vindex], &rr->rb[0]);
						rr->rb[0].ssrc = htonl(stream->video_ssrc_peer[vindex]);
						/* Enqueue it, we'll send it later */
						janus_ice_relay_rtcp_internal(handle, 1, rtcpbuf, 32, FALSE);
					}
				}
			}
			if (stream && stream->do_transport_wide_cc) {
				/* Create a transport wide feedback message */
				size_t size = 1300;
				char rtcpbuf[1300];
				/* Lock session */
				janus_mutex_lock(&handle->stream->mutex);
				/* Order packet list */
				GSList *sorted = g_slist_sort(handle->stream->transport_wide_received_seq_nums, rtcp_transport_wide_cc_stats_comparator);
				/* Create full stats queue */
				GQueue *packets = g_queue_new();
				/* For all packets */
				GSList *it = NULL;
				for (it = sorted; it; it = it->next) {
					/* Get stat */
					janus_rtcp_transport_wide_cc_stats *stats = (janus_rtcp_transport_wide_cc_stats *)it->data;
					/* Get transport seq */
					guint32 transport_seq_num = stats->transport_seq_num;
					/* Check if it is an out of order  */
					if (transport_seq_num < handle->stream->transport_wide_cc_last_feedback_seq_num)
						/* Skip, it was already reported as lost */
						continue;
					/* If not first */
					if (handle->stream->transport_wide_cc_last_feedback_seq_num) {
						/* For each lost */
						guint32 i = 0;
						for (i = handle->stream->transport_wide_cc_last_feedback_seq_num+1; i<transport_seq_num; ++i) {
							/* Create new stat */
							janus_rtcp_transport_wide_cc_stats *missing = g_malloc(sizeof(janus_rtcp_transport_wide_cc_stats));
							/* Add missing packet */
							missing->transport_seq_num = i;
							missing->timestamp = 0;
							/* Add it */
							g_queue_push_tail(packets, missing);
						}
					}
					/* Store last */
					handle->stream->transport_wide_cc_last_feedback_seq_num = transport_seq_num;
					/* Add this one */
					g_queue_push_tail(packets, stats);
				}
				/* Clear stats */
				g_slist_free(handle->stream->transport_wide_received_seq_nums);
				/* Reset list */
				handle->stream->transport_wide_received_seq_nums = NULL;
				/* Get feedback pacakte count and increase it for next one */
				guint8 feedback_packet_count = handle->stream->transport_wide_cc_feedback_count++;
				/* Unlock session */
				janus_mutex_unlock(&handle->stream->mutex);
				/* Create rtcp packet */
				int len = janus_rtcp_transport_wide_cc_feedback(rtcpbuf, size, handle->stream->video_ssrc, stream->video_ssrc_peer[0] , feedback_packet_count, packets);
				/* Enqueue it, we'll send it later */
				janus_ice_relay_rtcp_internal(handle, 1, rtcpbuf, len, FALSE);
				/* Free mem */
				g_queue_free(packets);
			}
		}
		/* We tell event handlers once per second about RTCP-related stuff
		 * FIXME Should we really do this here? Would this slow down this thread and add delay? */
		if(janus_ice_event_stats_period > 0 && now-last_event >= (gint64)janus_ice_event_stats_period*G_USEC_PER_SEC) {
			last_event = now;
			janus_ice_stream *stream = handle->stream;
			/* Audio */
			if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
				if(stream && stream->audio_rtcp_ctx) {
					json_t *info = json_object();
					json_object_set_new(info, "media", json_string("audio"));
					json_object_set_new(info, "base", json_integer(stream->audio_rtcp_ctx->tb));
					json_object_set_new(info, "rtt", json_integer(janus_rtcp_context_get_rtt(stream->audio_rtcp_ctx)));
					json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, FALSE)));
					json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, TRUE)));
					json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, FALSE)));
					json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, TRUE)));
					json_object_set_new(info, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(stream->audio_rtcp_ctx)));
					json_object_set_new(info, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(stream->audio_rtcp_ctx)));
					json_object_set_new(info, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(stream->audio_rtcp_ctx)));
					json_object_set_new(info, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(stream->audio_rtcp_ctx)));
					if(stream->component) {
						json_object_set_new(info, "packets-received", json_integer(stream->component->in_stats.audio.packets));
						json_object_set_new(info, "packets-sent", json_integer(stream->component->out_stats.audio.packets));
						json_object_set_new(info, "bytes-received", json_integer(stream->component->in_stats.audio.bytes));
						json_object_set_new(info, "bytes-sent", json_integer(stream->component->out_stats.audio.bytes));
						json_object_set_new(info, "bytes-received-lastsec", json_integer(stream->component->in_stats.audio.bytes_lastsec));
						json_object_set_new(info, "bytes-sent-lastsec", json_integer(stream->component->out_stats.audio.bytes_lastsec));
						json_object_set_new(info, "nacks-received", json_integer(stream->component->in_stats.audio.nacks));
						json_object_set_new(info, "nacks-sent", json_integer(stream->component->out_stats.audio.nacks));
					}
					janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, handle->opaque_id, info);
				}
			}
			/* Do the same for video */
			if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
				int vindex=0;
				for(vindex=0; vindex<3; vindex++) {
					if(stream && stream->video_rtcp_ctx[vindex]) {
						json_t *info = json_object();
						if(vindex == 0)
							json_object_set_new(info, "media", json_string("video"));
						else if(vindex == 1)
							json_object_set_new(info, "media", json_string("video-sim1"));
						else
							json_object_set_new(info, "media", json_string("video-sim2"));
						json_object_set_new(info, "base", json_integer(stream->video_rtcp_ctx[vindex]->tb));
						if(vindex == 0)
							json_object_set_new(info, "rtt", json_integer(janus_rtcp_context_get_rtt(stream->video_rtcp_ctx[vindex])));
						json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx[vindex], FALSE)));
						json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx[vindex], TRUE)));
						json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx[vindex], FALSE)));
						json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx[vindex], TRUE)));
						json_object_set_new(info, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(stream->video_rtcp_ctx[vindex])));
						json_object_set_new(info, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(stream->video_rtcp_ctx[vindex])));
						json_object_set_new(info, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(stream->video_rtcp_ctx[vindex])));
						json_object_set_new(info, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(stream->video_rtcp_ctx[vindex])));
						if(stream->component) {
							json_object_set_new(info, "packets-received", json_integer(stream->component->in_stats.video[vindex].packets));
							json_object_set_new(info, "packets-sent", json_integer(stream->component->out_stats.video[vindex].packets));
							json_object_set_new(info, "bytes-received", json_integer(stream->component->in_stats.video[vindex].bytes));
							json_object_set_new(info, "bytes-sent", json_integer(stream->component->out_stats.video[vindex].bytes));
							json_object_set_new(info, "bytes-received-lastsec", json_integer(stream->component->in_stats.video[vindex].bytes_lastsec));
							json_object_set_new(info, "bytes-sent-lastsec", json_integer(stream->component->out_stats.video[vindex].bytes_lastsec));
							json_object_set_new(info, "nacks-received", json_integer(stream->component->in_stats.video[vindex].nacks));
							json_object_set_new(info, "nacks-sent", json_integer(stream->component->out_stats.video[vindex].nacks));
						}
						janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, session->session_id, handle->handle_id, handle->opaque_id, info);
					}
				}
			}
		}
		/* Should we clean up old NACK buffers? (we check each 1/4 of the max_nack_queue time) */
		if(max_nack_queue > 0 && (now-last_nack_cleanup >= (max_nack_queue*250))) {
			/* Check if we do for all streams */
			janus_cleanup_nack_buffer(now, handle->stream, TRUE, TRUE);
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
			janus_ice_stream *stream = handle->stream;
			if(!stream) {
				g_free(pkt->data);
				pkt->data = NULL;
				g_free(pkt);
				pkt = NULL;
				continue;
			}
			janus_ice_component *component = stream->component;
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
					rtcp_rr *rr = (rtcp_rr *)rtcpbuf;
					rr->header.version = 2;
					rr->header.type = RTCP_RR;
					rr->header.rc = 0;
					rr->header.length = htons((rrlen/4)-1);
					janus_ice_stream *stream = handle->stream;
					if(stream && stream->video_rtcp_ctx[0] && stream->video_rtcp_ctx[0]->rtp_recvd) {
						rr->header.rc = 1;
						janus_rtcp_report_block(stream->video_rtcp_ctx[0], &rr->rb[0]);
					}
					/* Append REMB */
					memcpy(rtcpbuf+rrlen, pkt->data, pkt->length);
					/* If we're simulcasting, set the extra SSRCs (the first one will be set by janus_rtcp_fix_ssrc) */
					if(stream->video_ssrc_peer[1] && pkt->length >= 28) {
						rtcp_fb *rtcpfb = (rtcp_fb *)(rtcpbuf+rrlen);
						rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
						remb->ssrc[1] = htonl(stream->video_ssrc_peer[1]);
						if(stream->video_ssrc_peer[2] && pkt->length >= 32) {
							remb->ssrc[2] = htonl(stream->video_ssrc_peer[2]);
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
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, FALSE, sbuf, pkt->length,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* Encrypt SRTCP */
				int protected = pkt->length;
				int res = srtp_protect_rtcp(component->dtls->srtp_out, sbuf, &protected);
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
				janus_ice_stream *stream = handle->stream;
				if(!stream) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				if((!video && !stream->audio_send) || (video && !stream->video_send)) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				janus_ice_component *component = stream->component;
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
					/* Overwrite SSRC */
					janus_rtp_header *header = (janus_rtp_header *)sbuf;
					if(!pkt->retransmission) {
						/* ... but only if this isn't a retransmission (for those we already set it before) */
						header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
					}
					/* Keep track of payload types too */
					if(!video && stream->audio_payload_type < 0) {
						stream->audio_payload_type = header->type;
						if(stream->audio_codec == NULL) {
							const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->audio_payload_type);
							if(codec != NULL)
								stream->audio_codec = g_strdup(codec);
						}
					} else if(video && stream->video_payload_type < 0) {
						stream->video_payload_type = header->type;
						if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
								stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
							stream->video_rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(stream->video_payload_type)));
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
								handle->handle_id, stream->video_rtx_payload_type);
						}
						if(stream->video_codec == NULL) {
							const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->video_payload_type);
							if(codec != NULL)
								stream->video_codec = g_strdup(codec);
						}
						if(stream->video_is_keyframe == NULL && stream->video_codec != NULL) {
							if(!strcasecmp(stream->video_codec, "vp8"))
								stream->video_is_keyframe = &janus_vp8_is_keyframe;
							else if(!strcasecmp(stream->video_codec, "vp9"))
								stream->video_is_keyframe = &janus_vp9_is_keyframe;
							else if(!strcasecmp(stream->video_codec, "h264"))
								stream->video_is_keyframe = &janus_h264_is_keyframe;
						}
					}
					/* Do we need to dump this packet for debugging? */
					if(g_atomic_int_get(&handle->dump_packets))
						janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, FALSE, sbuf, pkt->length,
							"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
					/* If this is video, check if this is a keyframe: if so, we empty our retransmit buffer for incoming NACKs */
					if(video && stream->video_is_keyframe) {
						int plen = 0;
						char *payload = janus_rtp_payload(sbuf, pkt->length, &plen);
						if(stream->video_is_keyframe(payload, plen)) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe sent, cleaning retransmit buffer\n", handle->handle_id);
							janus_cleanup_nack_buffer(0, stream, FALSE, TRUE);
						}
					}
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
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected, timestamp, seq);
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
								component->out_stats.audio.packets++;
								component->out_stats.audio.bytes += pkt->length;
								/* Last second outgoing audio */
								gint64 now = janus_get_monotonic_time();
								if(component->out_stats.audio.updated == 0)
									component->out_stats.audio.updated = now;
								if(now > component->out_stats.audio.updated &&
										now - component->out_stats.audio.updated >= G_USEC_PER_SEC) {
									component->out_stats.audio.bytes_lastsec = component->out_stats.audio.bytes_lastsec_temp;
									component->out_stats.audio.bytes_lastsec_temp = 0;
									component->out_stats.audio.updated = now;
								}
								component->out_stats.audio.bytes_lastsec_temp += pkt->length;
								stream->audio_last_ts = timestamp;
								if(stream->audio_first_ntp_ts == 0) {
									struct timeval tv;
									gettimeofday(&tv, NULL);
									stream->audio_first_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
									stream->audio_first_rtp_ts = timestamp;
								}
								/* Let's check if this was G.711: in case we may need to change the timestamp base */
								rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
								int pt = header->type;
								if((pt == 0 || pt == 8) && (rtcp_ctx->tb == 48000))
									rtcp_ctx->tb = 8000;
							} else if(pkt->type == JANUS_ICE_PACKET_VIDEO) {
								component->out_stats.video[0].packets++;
								component->out_stats.video[0].bytes += pkt->length;
								/* Last second outgoing video */
								gint64 now = janus_get_monotonic_time();
								if(component->out_stats.video[0].updated == 0)
									component->out_stats.video[0].updated = now;
								if(now > component->out_stats.video[0].updated &&
										now - component->out_stats.video[0].updated >= G_USEC_PER_SEC) {
									component->out_stats.video[0].bytes_lastsec = component->out_stats.video[0].bytes_lastsec_temp;
									component->out_stats.video[0].bytes_lastsec_temp = 0;
									component->out_stats.video[0].updated = now;
								}
								component->out_stats.video[0].bytes_lastsec_temp += pkt->length;
								stream->video_last_ts = timestamp;
								if(stream->video_first_ntp_ts[0] == 0) {
									struct timeval tv;
									gettimeofday(&tv, NULL);
									stream->video_first_ntp_ts[0] = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
									stream->video_first_rtp_ts[0] = timestamp;
								}
							}
							/* Update sent packets counter */
							rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[0] : stream->audio_rtcp_ctx;
							g_atomic_int_inc(&rtcp_ctx->sent_packets_since_last_rr);
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
							janus_rtp_packet *p = g_malloc(sizeof(janus_rtp_packet));
							/* What to store and how depends on whether we're doing RFC4588 or not */
							if(pkt->type == JANUS_ICE_PACKET_AUDIO || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* We're not: just store the SRTP packet we just encrypted */
								p->data = g_malloc(protected);
								memcpy(p->data, sbuf, protected);
								p->length = protected;
							} else {
								/* We are: make room for two more bytes to store the original sequence number */
								janus_rtp_header *header = (janus_rtp_header *)pkt->data;
								guint16 original_seq = header->seq_number;
								p->data = g_malloc(pkt->length+2);
								p->length = pkt->length+2;
								/* Check where the payload starts */
								int plen = 0;
								char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
								size_t hsize = payload - pkt->data;
								/* Copy the header first */
								memcpy(p->data, pkt->data, hsize);
								/* Copy the original sequence number */
								memcpy(p->data+hsize, &original_seq, 2);
								/* Copy the payload */
								memcpy(p->data+hsize+2, payload, pkt->length - hsize);
							}
							p->created = janus_get_monotonic_time();
							p->last_retransmit = 0;
							janus_mutex_lock(&component->mutex);
							janus_rtp_header *header = (janus_rtp_header *)sbuf;
							guint16 seq = ntohs(header->seq_number);
							if(!video) {
								if(component->audio_retransmit_buffer == NULL) {
									component->audio_retransmit_buffer = g_queue_new();
									component->audio_retransmit_seqs = g_hash_table_new(NULL, NULL);
								}
								g_queue_push_tail(component->audio_retransmit_buffer, p);
								/* Insert in the table too, for quick lookup */
								g_hash_table_insert(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq), p);
							} else {
								if(component->video_retransmit_buffer == NULL) {
									component->video_retransmit_buffer = g_queue_new();
									component->video_retransmit_seqs = g_hash_table_new(NULL, NULL);
								}
								g_queue_push_tail(component->video_retransmit_buffer, p);
								/* Insert in the table too, for quick lookup */
								g_hash_table_insert(component->video_retransmit_seqs, GUINT_TO_POINTER(seq), p);
							}
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
				janus_ice_stream *stream = handle->stream;
				if(!stream) {
					g_free(pkt->data);
					pkt->data = NULL;
					g_free(pkt);
					pkt = NULL;
					continue;
				}
				janus_ice_component *component = stream->component;
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
	handle->send_thread = NULL;
	return NULL;
}

void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len) {
	if(!handle || buf == NULL || len < 1)
		return;
	if((!video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO))
			|| (video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)))
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(len);
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
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
		janus_ice_stream *stream = handle->stream;
		if(stream == NULL)
			return;
		rtcp_buf = janus_rtcp_filter(buf, len, &rtcp_len);
		if(rtcp_buf == NULL || rtcp_len < 1)
			return;
		/* Fix all SSRCs before enqueueing, as we need to use the ones for this media
		 * leg. Note that this is only needed for RTCP packets coming from plugins: the
		 * ones created by the core already have the right SSRCs in the right place */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
			video ? stream->video_ssrc : stream->audio_ssrc,
			video ? stream->video_ssrc_peer[0] : stream->audio_ssrc_peer);
		janus_rtcp_fix_ssrc(NULL, rtcp_buf, rtcp_len, 1,
			video ? stream->video_ssrc : stream->audio_ssrc,
			video ? stream->video_ssrc_peer[0] : stream->audio_ssrc_peer);
	}
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(len);
	memcpy(pkt->data, rtcp_buf, rtcp_len);
	pkt->length = rtcp_len;
	pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = TRUE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
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
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(len);
	memcpy(pkt->data, buf, len);
	pkt->length = len;
	pkt->type = JANUS_ICE_PACKET_DATA;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
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
	if(handle->stream) {
		if(handle->stream->component && (!handle->stream->component->dtls ||
				!handle->stream->component->dtls->srtp_valid)) {
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
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}
