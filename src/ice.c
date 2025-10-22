/*! \file    ice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Janus handles and ICE/STUN/TURN processing
 * \details  A Janus handle represents an abstraction of the communication
 * between a user and a specific plugin, within a Janus session. This is
 * particularly important in terms of media connectivity, as each handle
 * can be associated with a single WebRTC PeerConnection. This code also
 * contains the implementation (based on libnice) of a WebRTC PeerConnection.
 * The code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. Incoming RTP and RTCP packets from peers are relayed to the associated
 * plugins by means of the incoming_rtp and incoming_rtcp callbacks. Packets
 * to be sent to peers are relayed by peers invoking the relay_rtp and
 * relay_rtcp core callbacks instead.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <ifaddrs.h>
#include <poll.h>
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
#ifndef HAVE_TURNRESTAPI
	return NULL;
#else
	return (char *)janus_turnrest_get_backend();
#endif
}

/* Force relay settings */
static gboolean force_relay_allowed = FALSE;
void janus_ice_allow_force_relay(void) {
	force_relay_allowed = TRUE;
}
gboolean janus_ice_is_force_relay_allowed(void) {
	return force_relay_allowed;
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

/* mDNS resolution support */
static gboolean janus_mdns_enabled;
gboolean janus_ice_is_mdns_enabled(void) {
	return janus_mdns_enabled;
}

/* IPv6 support */
static gboolean janus_ipv6_enabled;
static gboolean janus_ipv6_linklocal_enabled;
gboolean janus_ice_is_ipv6_enabled(void) {
	return janus_ipv6_enabled;
}
static gboolean janus_ipv6_linklocal_enabled;
gboolean janus_ice_is_ipv6_linklocal_enabled(void) {
	return janus_ipv6_linklocal_enabled;
}

#ifdef HAVE_ICE_NOMINATION
/* Since libnice 0.1.15, we can configure the ICE nomination mode: it was
 * always "aggressive" before, so we set it to "aggressive" by default as well */
static NiceNominationMode janus_ice_nomination = NICE_NOMINATION_MODE_AGGRESSIVE;
void janus_ice_set_nomination_mode(const char *nomination) {
	if(nomination == NULL) {
		JANUS_LOG(LOG_WARN, "Invalid ICE nomination mode, falling back to 'aggressive'\n");
	} else if(!strcasecmp(nomination, "regular")) {
		JANUS_LOG(LOG_INFO, "Configuring Janus to use ICE regular nomination\n");
		janus_ice_nomination = NICE_NOMINATION_MODE_REGULAR;
	} else if(!strcasecmp(nomination, "aggressive")) {
		JANUS_LOG(LOG_INFO, "Configuring Janus to use ICE aggressive nomination\n");
		janus_ice_nomination = NICE_NOMINATION_MODE_AGGRESSIVE;
	} else {
		JANUS_LOG(LOG_WARN, "Unsupported ICE nomination mode '%s', falling back to 'aggressive'\n", nomination);
	}
}
const char *janus_ice_get_nomination_mode(void) {
	return (janus_ice_nomination == NICE_NOMINATION_MODE_REGULAR ? "regular" : "aggressive");
}
#endif

/* ICE consent freshness */
static gboolean janus_ice_consent_freshness = FALSE;
void janus_ice_set_consent_freshness_enabled(gboolean enabled) {
#ifndef HAVE_CONSENT_FRESHNESS
	if(enabled) {
		JANUS_LOG(LOG_WARN, "libnice version doesn't support consent freshness\n");
		return;
	}
#endif
	janus_ice_consent_freshness = enabled;
	if(janus_ice_consent_freshness) {
		JANUS_LOG(LOG_INFO, "Using content freshness checks in PeerConnection\n");
		janus_ice_set_keepalive_conncheck_enabled(TRUE);
	}
}
gboolean janus_ice_is_consent_freshness_enabled(void) {
	return janus_ice_consent_freshness;
}

/* Keepalive via connectivity checks */
static gboolean janus_ice_keepalive_connchecks = FALSE;
void janus_ice_set_keepalive_conncheck_enabled(gboolean enabled) {
	if(janus_ice_consent_freshness && !enabled) {
		JANUS_LOG(LOG_WARN, "Can't disable connectivity checks as PeerConnection keep-alive, consent freshness is enabled\n");
		return;
	}
	janus_ice_keepalive_connchecks = enabled;
	if(janus_ice_keepalive_connchecks) {
		JANUS_LOG(LOG_INFO, "Using connectivity checks as PeerConnection keep-alive\n");
	}
}
gboolean janus_ice_is_keepalive_conncheck_enabled(void) {
	return janus_ice_keepalive_connchecks;
}

/* How to react to ICE failures */
static gboolean janus_ice_hangup_on_failed = FALSE;
void janus_ice_set_hangup_on_failed_enabled(gboolean enabled) {
	janus_ice_hangup_on_failed = enabled;
	if(janus_ice_hangup_on_failed) {
		JANUS_LOG(LOG_INFO, "Will hangup PeerConnections immediately on ICE failures\n");
	}
}
gboolean janus_ice_is_hangup_on_failed_enabled(void) {
	return janus_ice_hangup_on_failed;
}

/* Opaque IDs set by applications are by default only passed to event handlers
 * for correlation purposes, but not sent back to the user or application in
 * the related Janus API responses or events, unless configured otherwise */
static gboolean opaqueid_in_api = FALSE;
void janus_enable_opaqueid_in_api(void) {
	opaqueid_in_api = TRUE;
}
gboolean janus_is_opaqueid_in_api_enabled(void) {
	return opaqueid_in_api;
}

/* Only needed in case we're using static event loops spawned at startup (disabled by default) */
typedef struct janus_ice_static_event_loop {
	int id;
	GMainContext *mainctx;
	GMainLoop *mainloop;
	GThread *thread;
	uint16_t handles;
	volatile gint destroyed;
	janus_refcount ref;
} janus_ice_static_event_loop;
static void janus_ice_static_event_loop_destroy(janus_ice_static_event_loop *loop) {
	if(!g_atomic_int_compare_and_exchange(&loop->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&loop->ref);
}
static void janus_ice_static_event_loop_free(const janus_refcount *loop_ref) {
	janus_ice_static_event_loop *loop = janus_refcount_containerof(loop_ref, janus_ice_static_event_loop, ref);
	g_free(loop);
}
static int static_event_loops = 0;
static gboolean allow_loop_indication = FALSE;
static GSList *event_loops = NULL;
static janus_mutex event_loops_mutex = JANUS_MUTEX_INITIALIZER;
static void *janus_ice_static_event_loop_thread(void *data) {
	janus_ice_static_event_loop *loop = data;
	JANUS_LOG(LOG_VERB, "[loop#%d] Event loop thread started\n", loop->id);
	if(loop->mainloop == NULL) {
		JANUS_LOG(LOG_ERR, "[loop#%d] Invalid loop...\n", loop->id);
		g_thread_unref(g_thread_self());
		janus_refcount_decrease(&loop->ref);
		return NULL;
	}
	JANUS_LOG(LOG_DBG, "[loop#%d] Looping...\n", loop->id);
	g_main_loop_run(loop->mainloop);
	/* When the loop quits, we can unref it */
	g_main_loop_unref(loop->mainloop);
	g_main_context_unref(loop->mainctx);
	JANUS_LOG(LOG_VERB, "[loop#%d] Event loop thread ended!\n", loop->id);
	janus_refcount_decrease(&loop->ref);
	return NULL;
}
int janus_ice_get_static_event_loops(void) {
	return static_event_loops;
}
gboolean janus_ice_is_loop_indication_allowed(void) {
	return allow_loop_indication;
}
void janus_ice_set_static_event_loops(int loops, gboolean allow_api) {
	if(loops == 0)
		return;
	else if(loops < 1) {
		JANUS_LOG(LOG_WARN, "Invalid number of static event loops (%d), disabling\n", loops);
		return;
	}
	/* Create a pool of new event loops */
	int i = 0;
	for(i=0; i<loops; i++) {
		janus_ice_static_event_loop *loop = g_malloc0(sizeof(janus_ice_static_event_loop));
		loop->id = static_event_loops;
		loop->mainctx = g_main_context_new();
		loop->mainloop = g_main_loop_new(loop->mainctx, FALSE);
		janus_refcount_init(&loop->ref, janus_ice_static_event_loop_free);
		/* Now spawn a thread for this loop */
		GError *error = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "hloop %d", loop->id);
		janus_refcount_increase(&loop->ref);
		loop->thread = g_thread_try_new(tname, &janus_ice_static_event_loop_thread, loop, &error);
		if(error != NULL) {
			g_main_loop_unref(loop->mainloop);
			g_main_context_unref(loop->mainctx);
			janus_refcount_decrease(&loop->ref);
			janus_ice_static_event_loop_destroy(loop);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch a new event loop thread...\n",
				error->code, error->message ? error->message : "??");
			g_error_free(error);
		} else {
			event_loops = g_slist_append(event_loops, loop);
			static_event_loops++;
		}
	}
	JANUS_LOG(LOG_INFO, "Spawned %d static event loops (handles won't have a dedicated loop)\n", static_event_loops);
	allow_loop_indication = allow_api;
	JANUS_LOG(LOG_INFO, "  -- Janus API %s be able to drive the loop choice for new handles\n",
		allow_loop_indication ? "will" : "will NOT");
	return;
}
json_t *janus_ice_static_event_loops_info(void) {
	json_t *list = json_array();
	if(static_event_loops < 1)
		return list;
	janus_mutex_lock(&event_loops_mutex);
	GSList *l = event_loops;
	while(l) {
		janus_ice_static_event_loop *loop = (janus_ice_static_event_loop *)l->data;
		json_t *info = json_object();
		json_object_set_new(info, "id", json_integer(loop->id));
		json_object_set_new(info, "handles", json_integer(loop->handles));
		json_array_append_new(list, info);
		l = l->next;
	}
	janus_mutex_unlock(&event_loops_mutex);
	return list;
}
void janus_ice_stop_static_event_loops(void) {
	if(static_event_loops < 1)
		return;
	/* Quit all the static loops and wait for the threads to leave */
	janus_mutex_lock(&event_loops_mutex);
	GSList *l = event_loops;
	while(l) {
		janus_ice_static_event_loop *loop = (janus_ice_static_event_loop *)l->data;
		if(loop->mainloop != NULL && g_main_loop_is_running(loop->mainloop))
			g_main_loop_quit(loop->mainloop);
		g_thread_join(loop->thread);
		l = l->next;
	}
	g_slist_free_full(event_loops, (GDestroyNotify)janus_ice_static_event_loop_destroy);
	janus_mutex_unlock(&event_loops_mutex);
}

/* NAT 1:1 stuff */
static gboolean nat_1_1_enabled = FALSE;
static gboolean keep_private_host = FALSE;
void janus_ice_enable_nat_1_1(gboolean kph) {
	nat_1_1_enabled = TRUE;
	keep_private_host = kph;
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
	janus_mutex_lock(&ice_list_mutex);
	if(ip == NULL || janus_ice_enforce_list == NULL) {
		janus_mutex_unlock(&ice_list_mutex);
		return FALSE;
	}
	GList *temp = janus_ice_enforce_list;
	while(temp) {
		const char *enforced = (const char *)temp->data;
		if(enforced != NULL && strstr(ip, enforced) == ip) {
			janus_mutex_unlock(&ice_list_mutex);
			return TRUE;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return FALSE;
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
	janus_mutex_lock(&ice_list_mutex);
	if(ip == NULL || janus_ice_ignore_list == NULL) {
		janus_mutex_unlock(&ice_list_mutex);
		return FALSE;
	}
	GList *temp = janus_ice_ignore_list;
	while(temp) {
		const char *ignored = (const char *)temp->data;
		if(ignored != NULL && strstr(ip, ignored) == ip) {
			janus_mutex_unlock(&ice_list_mutex);
			return TRUE;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return FALSE;
}


/* Frequency of statistics via event handlers (one second by default) */
static int janus_ice_event_stats_period = 1;
void janus_ice_set_event_stats_period(int period) {
	janus_ice_event_stats_period = period;
}
int janus_ice_get_event_stats_period(void) {
	return janus_ice_event_stats_period;
}

/* How to handle media statistic events (one per media or one per peerConnection) */
static gboolean janus_ice_event_combine_media_stats = FALSE;
void janus_ice_event_set_combine_media_stats(gboolean combine_media_stats_to_one_event) {
	janus_ice_event_combine_media_stats = combine_media_stats_to_one_event;
}
gboolean janus_ice_event_get_combine_media_stats(void) {
	return janus_ice_event_combine_media_stats;
}

/* Number of active PeerConnection (for stats) */
static volatile gint pc_num = 0;
int janus_ice_get_peerconnection_num(void) {
	return g_atomic_int_get(&pc_num);
}

/* RTP/RTCP port range */
static uint16_t rtp_range_min = 0;
static uint16_t rtp_range_max = 0;


#define JANUS_ICE_PACKET_AUDIO	0
#define JANUS_ICE_PACKET_VIDEO	1
#define JANUS_ICE_PACKET_TEXT	2
#define JANUS_ICE_PACKET_BINARY	3
#define JANUS_ICE_PACKET_SCTP	4
/* Helper to convert packet types to core types */
static janus_media_type janus_media_type_from_packet(int type) {
	switch(type) {
		case JANUS_ICE_PACKET_AUDIO:
			return JANUS_MEDIA_AUDIO;
		case JANUS_ICE_PACKET_VIDEO:
			return JANUS_MEDIA_VIDEO;
		case JANUS_ICE_PACKET_TEXT:
		case JANUS_ICE_PACKET_BINARY:
		case JANUS_ICE_PACKET_SCTP:
			return JANUS_MEDIA_DATA;
		default:
			break;
	}
	return JANUS_MEDIA_UNKNOWN;
}
/* Janus enqueued (S)RTP/(S)RTCP packet to send */
typedef struct janus_ice_queued_packet {
	gint mindex;
	char *data;
	char *label;
	char *protocol;
	janus_plugin_rtp_extensions extensions;
	gint length;
	gint type;
	gboolean control, control_ext;
	gboolean retransmission;
	gboolean encrypted;
	gint64 added;
} janus_ice_queued_packet;
/* A few static, fake, messages we use as a trigger: e.g., to start a
 * new DTLS handshake, hangup a PeerConnection or close a handle */
static janus_ice_queued_packet
	janus_ice_start_gathering,
	janus_ice_add_candidates,
	janus_ice_dtls_handshake,
	janus_ice_media_stopped,
	janus_ice_hangup_peerconnection,
	janus_ice_detach_handle,
	janus_ice_data_ready;

/* Janus NACKed packet we're tracking (to avoid duplicates) */
typedef struct janus_ice_nacked_packet {
	janus_ice_peerconnection_medium *medium;
	int vindex;
	guint16 seq_number;
	guint source_id;
} janus_ice_nacked_packet;
static gboolean janus_ice_nacked_packet_cleanup(gpointer user_data) {
	janus_ice_nacked_packet *pkt = (janus_ice_nacked_packet *)user_data;

	if(pkt->medium && pkt->medium->pc && pkt->medium->pc->handle) {
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Cleaning up NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
			pkt->medium->pc->handle->handle_id, pkt->seq_number, pkt->medium->ssrc_peer[pkt->vindex], pkt->vindex);
		g_hash_table_remove(pkt->medium->rtx_nacked[pkt->vindex], GUINT_TO_POINTER(pkt->seq_number));
		g_hash_table_remove(pkt->medium->pending_nacked_cleanup, GUINT_TO_POINTER(pkt->source_id));
	}

	return G_SOURCE_REMOVE;
}

const char *janus_media_type_str(janus_media_type type) {
	switch(type) {
		case JANUS_MEDIA_AUDIO:
			return "audio";
		case JANUS_MEDIA_VIDEO:
			return "video";
		case JANUS_MEDIA_DATA:
			return "data";
		case JANUS_MEDIA_UNKNOWN:
			return "unknown";
		default:
			break;
	}
	return NULL;
}

/* Deallocation helpers for handles and related structs */
static void janus_ice_handle_free(const janus_refcount *handle_ref);
static void janus_ice_webrtc_free(janus_ice_handle *handle);
static void janus_ice_plugin_session_free(const janus_refcount *app_handle_ref);
static void janus_ice_peerconnection_free(const janus_refcount *pc_ref);
static void janus_ice_peerconnection_medium_free(const janus_refcount *medium_ref);

/* Custom GSource for outgoing traffic */
typedef struct janus_ice_outgoing_traffic {
	GSource parent;
	janus_ice_handle *handle;
	GDestroyNotify destroy;
} janus_ice_outgoing_traffic;
static gboolean janus_ice_outgoing_rtcp_handle(gpointer user_data);
static gboolean janus_ice_outgoing_stats_handle(gpointer user_data);
static gboolean janus_ice_outgoing_traffic_handle(janus_ice_handle *handle, janus_ice_queued_packet *pkt);
static gboolean janus_ice_outgoing_traffic_prepare(GSource *source, gint *timeout) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	return (g_async_queue_length(t->handle->queued_packets) > 0);
}
static gboolean janus_ice_outgoing_traffic_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	int ret = G_SOURCE_CONTINUE;
	janus_ice_queued_packet *pkt = NULL;
	while((pkt = g_async_queue_try_pop(t->handle->queued_packets)) != NULL) {
		if(janus_ice_outgoing_traffic_handle(t->handle, pkt) == G_SOURCE_REMOVE)
			ret = G_SOURCE_REMOVE;
	}
	return ret;
}
static void janus_ice_outgoing_traffic_finalize(GSource *source) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Finalizing loop source\n", t->handle->handle_id);
	if(static_event_loops > 0) {
		/* This handle was sharing an event loop with others */
		janus_ice_webrtc_free(t->handle);
		janus_refcount_decrease(&t->handle->ref);
	} else if(t->handle->mainloop != NULL && g_main_loop_is_running(t->handle->mainloop)) {
		/* This handle had a dedicated event loop, quit it */
		g_main_loop_quit(t->handle->mainloop);
	}
	janus_refcount_decrease(&t->handle->ref);
}
static GSourceFuncs janus_ice_outgoing_traffic_funcs = {
	janus_ice_outgoing_traffic_prepare,
	NULL,	/* We don't need check */
	janus_ice_outgoing_traffic_dispatch,
	janus_ice_outgoing_traffic_finalize,
	NULL, NULL
};
static GSource *janus_ice_outgoing_traffic_create(janus_ice_handle *handle, GDestroyNotify destroy) {
	GSource *source = g_source_new(&janus_ice_outgoing_traffic_funcs, sizeof(janus_ice_outgoing_traffic));
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	char name[255];
	g_snprintf(name, sizeof(name), "source-%"SCNu64, handle->handle_id);
	g_source_set_name(source, name);
	janus_refcount_increase(&handle->ref);
	t->handle = handle;
	t->destroy = destroy;
	return source;
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
		JANUS_LOG(LOG_VERB, "Setting no-media timer to %us\n", no_media_timer);
}
uint janus_get_no_media_timer(void) {
	return no_media_timer;
}

/* Number of lost packets per seconds on a media stream (uplink or downlink,
 * audio or video), that should result in a slow-link event to the user.
 * By default the feature is disabled (threshold=0), as it can be quite
 * verbose and is often redundant information, since the same info on lost
 * packets (in and out) can already be retrieved via client-side stats */
#define DEFAULT_SLOWLINK_THRESHOLD	0
static uint slowlink_threshold = DEFAULT_SLOWLINK_THRESHOLD;
void janus_set_slowlink_threshold(uint packets) {
	slowlink_threshold = packets;
	if(slowlink_threshold == 0)
		JANUS_LOG(LOG_VERB, "Disabling slow-link events\n");
	else
		JANUS_LOG(LOG_VERB, "Setting slowlink-threshold to %u packets\n", slowlink_threshold);
}
uint janus_get_slowlink_threshold(void) {
	return slowlink_threshold;
}

/* Period, in milliseconds, to refer to for sending TWCC feedback */
#define DEFAULT_TWCC_PERIOD		200
static uint twcc_period = DEFAULT_TWCC_PERIOD;
void janus_set_twcc_period(uint period) {
	twcc_period = period;
	if(twcc_period == 0) {
		JANUS_LOG(LOG_WARN, "Invalid TWCC period, falling back to default\n");
		twcc_period = DEFAULT_TWCC_PERIOD;
	} else {
		JANUS_LOG(LOG_VERB, "Setting TWCC period to %ds\n", twcc_period);
	}
}
uint janus_get_twcc_period(void) {
	return twcc_period;
}

/* DSCP value, which we can set via libnice: it's disabled by default */
static int dscp_ef = 0;
void janus_set_dscp(int dscp) {
	dscp_ef = dscp;
	if(dscp_ef > 0) {
		JANUS_LOG(LOG_VERB, "Setting DSCP EF to %d\n", dscp_ef);
	}
}
int janus_get_dscp(void) {
	return dscp_ef;
}


static inline void janus_ice_free_rtp_packet(janus_rtp_packet *pkt) {
	if(pkt == NULL) {
		return;
	}

	g_free(pkt->data);
	g_free(pkt);
}

static void janus_ice_free_queued_packet(janus_ice_queued_packet *pkt) {
	if(pkt == NULL || pkt == &janus_ice_start_gathering ||
			pkt == &janus_ice_add_candidates ||
			pkt == &janus_ice_dtls_handshake ||
			pkt == &janus_ice_media_stopped ||
			pkt == &janus_ice_hangup_peerconnection ||
			pkt == &janus_ice_detach_handle ||
			pkt == &janus_ice_data_ready) {
		return;
	}
	g_free(pkt->data);
	g_free(pkt->label);
	g_free(pkt->protocol);
	g_free(pkt);
}

/* Minimum and maximum value, in milliseconds, for the NACK queue/retransmissions (default=200ms/1000ms) */
#define DEFAULT_MIN_NACK_QUEUE	200
#define DEFAULT_MAX_NACK_QUEUE	1000
/* Min/Max time to rate limit retransmissions of the same packet */
#define MAX_NACK_IGNORE			DEFAULT_MAX_NACK_QUEUE*1000
#define MIN_NACK_IGNORE			40000

static gboolean nack_optimizations = FALSE;
void janus_set_nack_optimizations_enabled(gboolean optimize) {
	nack_optimizations = optimize;
}
gboolean janus_is_nack_optimizations_enabled(void) {
	return nack_optimizations;
}

static uint16_t min_nack_queue = DEFAULT_MIN_NACK_QUEUE;
void janus_set_min_nack_queue(uint16_t mnq) {
	min_nack_queue = mnq < DEFAULT_MAX_NACK_QUEUE ? mnq : DEFAULT_MAX_NACK_QUEUE;
	if(min_nack_queue == 0)
		JANUS_LOG(LOG_VERB, "Disabling NACK queue\n");
	else
		JANUS_LOG(LOG_VERB, "Setting min NACK queue to %dms\n", min_nack_queue);
}
uint16_t janus_get_min_nack_queue(void) {
	return min_nack_queue;
}
/* Helper to clean old NACK packets in the buffer when they exceed the queue time limit */
static void janus_cleanup_nack_buffer(gint64 now, janus_ice_peerconnection *pc, gboolean audio, gboolean video) {
	/* Iterate on all media */
	janus_ice_peerconnection_medium *medium = NULL;
	uint mi=0;
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		if(!medium)
			continue;
		if((medium->type == JANUS_MEDIA_AUDIO && !audio) || (medium->type == JANUS_MEDIA_VIDEO && !video))
			continue;
		if(medium->retransmit_buffer) {
			janus_rtp_packet *p = (janus_rtp_packet *)g_queue_peek_head(medium->retransmit_buffer);
			while(p && (!now || (now - p->created >= (gint64)medium->nack_queue_ms*1000))) {
				/* Packet is too old, get rid of it */
				g_queue_pop_head(medium->retransmit_buffer);
				/* Remove from hashtable too */
				janus_rtp_header *header = (janus_rtp_header *)p->data;
				guint16 seq = ntohs(header->seq_number);
				g_hash_table_remove(medium->retransmit_seqs, GUINT_TO_POINTER(seq));
				/* Free the packet */
				janus_ice_free_rtp_packet(p);
				p = (janus_rtp_packet *)g_queue_peek_head(medium->retransmit_buffer);
			}
		}
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
void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, janus_ice_peerconnection_medium *medium,
	janus_plugin_rtcp *packet, gboolean filter_rtcp);


/* Map of active plugin sessions */
static GHashTable *plugin_sessions;
static janus_mutex plugin_sessions_mutex = JANUS_MUTEX_INITIALIZER;
gboolean janus_plugin_session_is_alive(janus_plugin_session *plugin_session) {
	if(plugin_session == NULL || plugin_session < (janus_plugin_session *)0x1000 ||
			g_atomic_int_get(&plugin_session->stopped))
		return FALSE;
	/* Make sure this plugin session is still alive */
	janus_mutex_lock_nodebug(&plugin_sessions_mutex);
	janus_plugin_session *result = g_hash_table_lookup(plugin_sessions, plugin_session);
	janus_mutex_unlock_nodebug(&plugin_sessions_mutex);
	if(result == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid plugin session (%p)\n", plugin_session);
	}
	return (result != NULL);
}
static void janus_plugin_session_dereference(janus_plugin_session *plugin_session) {
	if(plugin_session)
		janus_refcount_decrease(&plugin_session->ref);
}


static void janus_ice_clear_queued_candidates(janus_ice_handle *handle) {
	if(handle == NULL || handle->queued_candidates == NULL) {
		return;
	}
	while(g_async_queue_length(handle->queued_candidates) > 0) {
		(void)g_async_queue_try_pop(handle->queued_candidates);
	}
}

static void janus_ice_clear_queued_packets(janus_ice_handle *handle) {
	if(handle == NULL || handle->queued_packets == NULL) {
		return;
	}
	janus_ice_queued_packet *pkt = NULL;
	while(g_async_queue_length(handle->queued_packets) > 0) {
		pkt = g_async_queue_try_pop(handle->queued_packets);
		janus_ice_free_queued_packet(pkt);
	}
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
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	json_t *candidate = json_object();
	if(buffer != NULL) {
		json_object_set_new(candidate, "sdpMid", json_string(handle->pc_mid));
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

static void janus_ice_notify_media(janus_ice_handle *handle, char *mid, gboolean video, gboolean simulcast, int substream, gboolean up) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying that we %s receiving %s on mid %s\n",
		handle->handle_id, up ? "are" : "are NOT", video ? "video" : "audio", mid);
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("media"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	json_object_set_new(event, "mid", json_string(mid));
	json_object_set_new(event, "type", json_string(video ? "video" : "audio"));
	if(simulcast)
		json_object_set_new(event, "substream", json_integer(substream));
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
		json_object_set_new(info, "mid", json_string(mid));
		if(simulcast)
			json_object_set_new(info, "substream", json_integer(substream));
		json_object_set_new(info, "receiving", up ? json_true() : json_false());
		if(!up && no_media_timer > 1)
			json_object_set_new(info, "seconds", json_integer(no_media_timer));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}

static void janus_ice_notify_ice_failed(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying WebRTC ICE failure; %p\n", handle->handle_id, handle);
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("ice-failed"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
	janus_session_notify_event(session, event);
}

void janus_ice_notify_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying WebRTC hangup; %p\n", handle->handle_id, handle);
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("hangup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	if(reason != NULL)
		json_object_set_new(event, "reason", json_string(reason));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("hangup"));
		if(reason != NULL)
			json_object_set_new(info, "reason", json_string(reason));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}


/* Trickle helpers */
janus_ice_trickle *janus_ice_trickle_new(const char *transaction, json_t *candidate) {
	if(transaction == NULL || candidate == NULL)
		return NULL;
	janus_ice_trickle *trickle = g_malloc(sizeof(janus_ice_trickle));
	trickle->handle = NULL;
	trickle->received = janus_get_monotonic_time();
	trickle->transaction = g_strdup(transaction);
	trickle->candidate = json_deep_copy(candidate);
	return trickle;
}

gint janus_ice_trickle_parse(janus_ice_handle *handle, json_t *candidate, const char **error) {
	const char *ignore_error = NULL;
	if(error == NULL) {
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
		if(mid && !json_is_string(mid)) {
			*error = "Trickle error: invalid element type (sdpMid should be a string)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		json_t *mline = json_object_get(candidate, "sdpMLineIndex");
		if(mline && (!json_is_integer(mline) || json_integer_value(mline) < 0)) {
			*error = "Trickle error: invalid element type (sdpMLineIndex should be a positive integer)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		if(!mid && !mline) {
			*error = "Trickle error: missing mandatory element (sdpMid or sdpMLineIndex)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
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
		int sdpMLineIndex = mline ? json_integer_value(mline) : -1;
		const char *sdpMid = json_string_value(mid);
		if(sdpMLineIndex > 0 || (handle->pc_mid && sdpMid && strcmp(handle->pc_mid, sdpMid))) {
			/* FIXME We bundle everything, so we ignore candidates for anything beyond the first m-line */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a mid='%s' candidate (index %d) but we're bundling, ignoring...\n",
				handle->handle_id, json_string_value(mid), sdpMLineIndex);
			return 0;
		}
		janus_ice_peerconnection *pc = handle->pc;
		if(pc == NULL) {
			*error = "Trickle error: invalid element type (no such PeerConnection)";
			return JANUS_ERROR_TRICKE_INVALID_STREAM;
		}
		int res = janus_sdp_parse_candidate(pc, json_string_value(rc), 1);
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
	g_free(trickle->transaction);
	trickle->transaction = NULL;
	if(trickle->candidate)
		json_decref(trickle->candidate);
	trickle->candidate = NULL;
	g_free(trickle);
}


/* libnice initialization */
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean full_trickle, gboolean ignore_mdns,
		gboolean ipv6, gboolean ipv6_linklocal, uint16_t rtp_min_port, uint16_t rtp_max_port) {
	janus_ice_lite_enabled = ice_lite;
	janus_ice_tcp_enabled = ice_tcp;
	janus_full_trickle_enabled = full_trickle;
	janus_mdns_enabled = !ignore_mdns;
	janus_ipv6_enabled = ipv6;
	if(ipv6)
		janus_ipv6_linklocal_enabled = ipv6_linklocal;
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
			JANUS_LOG(LOG_WARN, "You may experience problems when having ICE-TCP enabled without having ICE Lite enabled too in libnice\n");
		}
#endif
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
	if(!janus_mdns_enabled)
		JANUS_LOG(LOG_WARN, "mDNS resolution disabled, .local candidates will be ignored\n");

	/* We keep track of plugin sessions to avoid problems */
	plugin_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_plugin_session_dereference);

#ifdef HAVE_TURNRESTAPI
	/* Initialize the TURN REST API client stack, whether we're going to use it or not */
	janus_turnrest_init();
#endif

}

void janus_ice_deinit(void) {
#ifdef HAVE_TURNRESTAPI
	janus_turnrest_deinit();
#endif
}

int janus_ice_test_stun_server(janus_network_address *addr, uint16_t port,
		uint16_t local_port, janus_network_address *public_addr, uint16_t *public_port) {
	if(!addr || !public_addr)
		return -1;
	/* Test the STUN server */
	StunAgent stun;
	stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
	StunMessage msg;
	uint8_t buf[1500];
	size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
	JANUS_LOG(LOG_INFO, "Testing STUN server: message is of %zu bytes\n", len);
	/* Use the janus_network_address info to drive the socket creation */
	int fd = socket(addr->family, SOCK_DGRAM, 0);
	if(fd < 0) {
		JANUS_LOG(LOG_FATAL, "Error creating socket for STUN BINDING test\n");
		return -1;
	}
	struct sockaddr *address = NULL, *remote = NULL;
	struct sockaddr_in address4 = { 0 }, remote4 = { 0 };
	struct sockaddr_in6 address6 = { 0 }, remote6 = { 0 };
	socklen_t addrlen = 0;
	if(addr->family == AF_INET) {
		memset(&address4, 0, sizeof(address4));
		address4.sin_family = AF_INET;
		address4.sin_port = htons(local_port);
		address4.sin_addr.s_addr = INADDR_ANY;
		memset(&remote4, 0, sizeof(remote4));
		remote4.sin_family = AF_INET;
		remote4.sin_port = htons(port);
		memcpy(&remote4.sin_addr, &addr->ipv4, sizeof(addr->ipv4));
		address = (struct sockaddr *)(&address4);
		remote = (struct sockaddr *)(&remote4);
		addrlen = sizeof(remote4);
	} else if(addr->family == AF_INET6) {
		memset(&address6, 0, sizeof(address6));
		address6.sin6_family = AF_INET6;
		address6.sin6_port = htons(local_port);
		address6.sin6_addr = in6addr_any;
		memset(&remote6, 0, sizeof(remote6));
		remote6.sin6_family = AF_INET6;
		remote6.sin6_port = htons(port);
		memcpy(&remote6.sin6_addr, &addr->ipv6, sizeof(addr->ipv6));
		remote6.sin6_addr = addr->ipv6;
		address = (struct sockaddr *)(&address6);
		remote = (struct sockaddr *)(&remote6);
		addrlen = sizeof(remote6);
	}
	if(bind(fd, address, addrlen) < 0) {
		JANUS_LOG(LOG_FATAL, "Bind failed for STUN BINDING test: %d (%s)\n", errno, g_strerror(errno));
		close(fd);
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, remote, addrlen);
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Error sending STUN BINDING test\n");
		close(fd);
		return -1;
	}
	JANUS_LOG(LOG_VERB, "  >> Sent %d bytes, waiting for reply...\n", bytes);
	struct timeval timeout;
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 5;	/* FIXME Don't wait forever */
	timeout.tv_usec = 0;
	int err = select(fd+1, &readfds, NULL, NULL, &timeout);
	if(err < 0) {
		JANUS_LOG(LOG_FATAL, "Error waiting for a response to our STUN BINDING test: %d (%s)\n", errno, g_strerror(errno));
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
	close(fd);
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Failed to receive STUN\n");
		return -1;
	}
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
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve XOR-MAPPED-ADDRESS...\n");
			return -1;
		}
		if(public_port != NULL) {
			if(address->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)address;
				*public_port = ntohs(addr->sin_port);
			} else if(address->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
				*public_port = ntohs(addr->sin6_port);
			}
		}
		return 0;
	}
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve MAPPED-ADDRESS...\n");
			return -1;
		}
		if(public_port != NULL) {
			if(address->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)address;
				*public_port = ntohs(addr->sin_port);
			} else if(address->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
				*public_port = ntohs(addr->sin6_port);
			}
		}
		return 0;
	}
	/* No usable attribute? */
	JANUS_LOG(LOG_ERR, "No XOR-MAPPED-ADDRESS or MAPPED-ADDRESS...\n");
	return -1;
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
	janus_network_address public_addr = { 0 };
	if(janus_ice_test_stun_server(&addr, janus_stun_port, 0, &public_addr, NULL) < 0) {
		g_free(janus_stun_server);
		janus_stun_server = NULL;
		return -1;
	}
	if(janus_network_address_to_string_buffer(&public_addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve public address...\n");
		g_free(janus_stun_server);
		janus_stun_server = NULL;
		return -1;
	}
	const char *public_ip = janus_network_address_string_from_buffer(&addr_buf);
	JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", public_ip);
	janus_add_public_ip(public_ip);
	return 0;
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
	g_free(janus_turn_server);
	janus_turn_server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	if(janus_turn_server == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		return -1;
	}
	janus_turn_port = turn_port;
	JANUS_LOG(LOG_VERB, "  >> %s:%u\n", janus_turn_server, janus_turn_port);
	g_free(janus_turn_user);
	janus_turn_user = NULL;
	if(turn_user)
		janus_turn_user = g_strdup(turn_user);
	g_free(janus_turn_pwd);
	janus_turn_pwd = NULL;
	if(turn_pwd)
		janus_turn_pwd = g_strdup(turn_pwd);
	return 0;
}

int janus_ice_set_turn_rest_api(gchar *api_server, gchar *api_key, gchar *api_method, uint api_timeout) {
#ifndef HAVE_TURNRESTAPI
	JANUS_LOG(LOG_ERR, "Janus has been built with no libcurl support, TURN REST API unavailable\n");
	return -1;
#else
	if(api_server != NULL &&
			(strstr(api_server, "http://") != api_server && strstr(api_server, "https://") != api_server)) {
		JANUS_LOG(LOG_ERR, "Invalid TURN REST API backend: not an HTTP address\n");
		return -1;
	}
	janus_turnrest_set_backend(api_server, api_key, api_method, api_timeout);
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


/* Thread to take care of the handle loop */
static void *janus_ice_handle_thread(void *data) {
	janus_ice_handle *handle = data;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle thread started; %p\n", handle->handle_id, handle);
	if(handle->mainloop == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid loop...\n", handle->handle_id);
		janus_refcount_decrease(&handle->ref);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_DBG, "[%"SCNu64"] Looping...\n", handle->handle_id);
	g_main_loop_run(handle->mainloop);
	janus_ice_webrtc_free(handle);
	handle->thread = NULL;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle thread ended! %p\n", handle->handle_id, handle);
	/* Unref the handle */
	janus_refcount_decrease(&handle->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}

janus_ice_handle *janus_ice_handle_create(void *core_session, const char *opaque_id, const char *token) {
	if(core_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)core_session;
	janus_ice_handle *handle = NULL;
	guint64 handle_id = 0;
	while(handle_id == 0) {
		handle_id = janus_random_uint64();
		handle = janus_session_handles_find(session, handle_id);
		if(handle != NULL) {
			/* Handle ID already taken, try another one */
			janus_refcount_decrease(&handle->ref);	/* janus_session_handles_find increases it */
			handle_id = 0;
		}
	}
	handle = (janus_ice_handle *)g_malloc0(sizeof(janus_ice_handle));
	JANUS_LOG(LOG_INFO, "Creating new handle in session %"SCNu64": %"SCNu64"; %p %p\n", session->session_id, handle_id, core_session, handle);
	janus_refcount_init(&handle->ref, janus_ice_handle_free);
	janus_refcount_increase(&session->ref);
	handle->session = core_session;
	if(opaque_id)
		handle->opaque_id = g_strdup(opaque_id);
	if(token)
		handle->token = g_strdup(token);
	handle->created = janus_get_monotonic_time();
	handle->handle_id = handle_id;
	handle->app = NULL;
	handle->app_handle = NULL;
	handle->queued_candidates = g_async_queue_new();
	handle->queued_packets = g_async_queue_new();
	janus_mutex_init(&handle->mutex);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_session_handles_insert(session, handle);
	return handle;
}

gint janus_ice_handle_attach_plugin(void *core_session, janus_ice_handle *handle, janus_plugin *plugin, int loop_index) {
	if(core_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = (janus_session *)core_session;
	if(plugin == NULL)
		return JANUS_ERROR_PLUGIN_NOT_FOUND;
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
	g_atomic_int_set(&session_handle->stopped, 0);
	plugin->create_session(session_handle, &error);
	if(error) {
		/* TODO Make error struct to pass verbose information */
		g_free(session_handle);
		return error;
	}
	janus_refcount_init(&session_handle->ref, janus_ice_plugin_session_free);
	/* Handle and plugin session reference each other */
	janus_refcount_increase(&session_handle->ref);
	janus_refcount_increase(&handle->ref);
	handle->app = plugin;
	handle->app_handle = session_handle;
	/* Add this plugin session to active sessions map */
	janus_mutex_lock(&plugin_sessions_mutex);
	g_hash_table_insert(plugin_sessions, session_handle, session_handle);
	janus_mutex_unlock(&plugin_sessions_mutex);
	/* Create a new context, loop, and source */
	if(static_event_loops == 0) {
		handle->mainctx = g_main_context_new();
		handle->mainloop = g_main_loop_new(handle->mainctx, FALSE);
	} else {
		/* We're actually using static event loops, pick one from the list */
		if(!allow_loop_indication && loop_index > -1) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Manual allocation of event loops forbidden, ignoring provided loop index %d\n", handle->handle_id, loop_index);
		}
		janus_refcount_increase(&handle->ref);
		janus_mutex_lock(&event_loops_mutex);
		gboolean automatic_selection = TRUE;
		if(allow_loop_indication && loop_index != -1) {
			/* The API can drive the selection and an index was provided, check if it exists */
			janus_ice_static_event_loop *loop = g_slist_nth_data(event_loops, loop_index);
			if(loop == NULL) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Invalid loop index %d, picking event loop automatically\n", handle->handle_id, loop_index);
			} else {
				janus_refcount_increase(&loop->ref);
				automatic_selection = FALSE;
				handle->mainctx = loop->mainctx;
				handle->mainloop = loop->mainloop;
				loop->handles++;
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Manually added handle to loop #%d\n", handle->handle_id, loop->id);
			}
		}
		if(automatic_selection) {
			/* Pick an available loop automatically (least loaded) */
			int handles = -1;
			janus_ice_static_event_loop *loop = NULL;
			GSList *l = event_loops;
			while(l) {
				janus_ice_static_event_loop *el = (janus_ice_static_event_loop *)l->data;
				if(el->handles == 0) {
					/* Best option, stop here */
					loop = el;
					break;
				}
				if(handles == -1 || el->handles < handles) {
					handles = el->handles;
					loop = el;
				}
				l = l->next;
			}
			janus_refcount_increase(&loop->ref);
			loop->handles++;
			handle->mainctx = loop->mainctx;
			handle->mainloop = loop->mainloop;
			handle->static_event_loop = loop;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Automatically added handle to loop #%d\n", handle->handle_id, loop->id);
		}
		janus_mutex_unlock(&event_loops_mutex);
	}
	handle->rtp_source = janus_ice_outgoing_traffic_create(handle, (GDestroyNotify)g_free);
	g_source_set_priority(handle->rtp_source, G_PRIORITY_DEFAULT);
	g_source_attach(handle->rtp_source, handle->mainctx);
	if(static_event_loops == 0) {
		/* Now spawn a thread for this loop */
		GError *terror = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "hloop %"SCNu64, handle->handle_id);
		janus_refcount_increase(&handle->ref);
		handle->thread = g_thread_try_new(tname, &janus_ice_handle_thread, handle, &terror);
		if(terror != NULL) {
			/* FIXME We should clear some resources... */
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the handle thread...\n",
				handle->handle_id, terror->code, terror->message ? terror->message : "??");
			g_error_free(terror);
			janus_refcount_decrease(&handle->ref);	/* This is for the thread reference we just added */
			janus_ice_handle_destroy(session, handle);
			return -1;
		}
	}
	/* Notify event handlers */
	if(janus_events_is_enabled())
		janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE, JANUS_EVENT_SUBTYPE_NONE,
			session->session_id, handle->handle_id, "attached", plugin->get_package(), handle->opaque_id, handle->token);
	return 0;
}

gint janus_ice_handle_destroy(void *core_session, janus_ice_handle *handle) {
	/* session->mutex has to be locked when calling this function */
	janus_session *session = (janus_session *)core_session;
	if(session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	if(!g_atomic_int_compare_and_exchange(&handle->destroyed, 0, 1))
		return 0;
	/* First of all, hangup the PeerConnection, if any */
	janus_ice_webrtc_hangup(handle, "Detach");
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	/* Remove the session from active sessions map */
	janus_mutex_lock(&plugin_sessions_mutex);
	gboolean found = g_hash_table_remove(plugin_sessions, handle->app_handle);
	if(!found) {
		janus_mutex_unlock(&plugin_sessions_mutex);
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	}
	janus_mutex_unlock(&plugin_sessions_mutex);
	janus_mutex_lock(&event_loops_mutex);
	if(handle->static_event_loop != NULL) {
		janus_ice_static_event_loop *loop = (janus_ice_static_event_loop *)handle->static_event_loop;
		loop->handles--;
		janus_refcount_decrease(&loop->ref);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Manually removed handle from loop #%d\n", handle->handle_id, loop->id);
	}
	janus_mutex_unlock(&event_loops_mutex);
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there */
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
		if(handle->mainloop != NULL) {
			if(static_event_loops == 0 && handle->mainloop != NULL && g_main_loop_is_running(handle->mainloop)) {
				g_main_loop_quit(handle->mainloop);
			}
		}
		janus_refcount_decrease(&handle->ref);
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s; %p %p %p %p\n", plugin_t->get_name(),
		handle, handle ? handle->app_handle : NULL,
		(handle && handle->app_handle) ? handle->app_handle->gateway_handle : NULL,
		(handle && handle->app_handle) ? handle->app_handle->plugin_handle : NULL);
	/* Actually detach handle... */
	if(g_atomic_int_compare_and_exchange(&handle->app_handle->stopped, 0, 1)) {
		/* Notify the plugin that the session's over (the plugin will
		 * remove the other reference to the plugin session handle) */
		g_async_queue_push(handle->queued_packets, &janus_ice_detach_handle);
		g_main_context_wakeup(handle->mainctx);
	}
	/* Get rid of the handle now */
	if(g_atomic_int_compare_and_exchange(&handle->dump_packets, 1, 0)) {
		janus_text2pcap_close(handle->text2pcap);
		g_clear_pointer(&handle->text2pcap, janus_text2pcap_free);
	}
	/* We only actually destroy the handle later */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle detached, scheduling destruction\n", handle->handle_id);
	/* Unref the handle: we only unref the session too when actually freeing the handle, so that it is freed before that */
	janus_refcount_decrease(&handle->ref);
	return 0;
}

static void janus_ice_handle_free(const janus_refcount *handle_ref) {
	janus_ice_handle *handle = janus_refcount_containerof(handle_ref, janus_ice_handle, ref);
	/* This stack can be destroyed, free all the resources */
	janus_mutex_lock(&handle->mutex);
	if(handle->queued_candidates != NULL) {
		janus_ice_clear_queued_candidates(handle);
		g_async_queue_unref(handle->queued_candidates);
	}
	if(handle->queued_packets != NULL) {
		janus_ice_clear_queued_packets(handle);
		g_async_queue_unref(handle->queued_packets);
	}
	if(static_event_loops == 0 && handle->mainloop != NULL) {
		g_main_loop_unref(handle->mainloop);
		handle->mainloop = NULL;
	}
	if(static_event_loops == 0 && handle->mainctx != NULL) {
		g_main_context_unref(handle->mainctx);
		handle->mainctx = NULL;
	}
	janus_mutex_unlock(&handle->mutex);
	janus_ice_webrtc_free(handle);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Handle and related resources freed; %p %p\n", handle->handle_id, handle, handle->session);
	/* Finally, unref the session and free the handle */
	if(handle->session != NULL) {
		janus_session *session = (janus_session *)handle->session;
		janus_refcount_decrease(&session->ref);
	}
	g_free(handle->opaque_id);
	g_free(handle->token);
	janus_mutex_destroy(&handle->mutex);
	g_free(handle);
}

#ifdef HAVE_CLOSE_ASYNC
static void janus_ice_cb_agent_closed(GObject *src, GAsyncResult *result, gpointer data) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)data;
	janus_ice_handle *handle = t->handle;

	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Disposing nice agent %p\n", handle->handle_id, handle->agent);
	g_object_unref(handle->agent);
	handle->agent = NULL;
	g_source_unref((GSource *)t);
	janus_refcount_decrease(&handle->ref);
}
#endif

static void janus_ice_plugin_session_free(const janus_refcount *app_handle_ref) {
	janus_plugin_session *app_handle = janus_refcount_containerof(app_handle_ref, janus_plugin_session, ref);
	/* This app handle can be destroyed, free all the resources */
	if(app_handle->gateway_handle != NULL) {
		janus_ice_handle *handle = (janus_ice_handle *)app_handle->gateway_handle;
		app_handle->gateway_handle = NULL;
		handle->app_handle = NULL;
		janus_refcount_decrease(&handle->ref);
	}
	g_free(app_handle);
}

void janus_ice_webrtc_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	g_atomic_int_set(&handle->closepc, 0);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	/* User will be notified only after the actual hangup */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Hanging up PeerConnection because of a %s\n",
		handle->handle_id, reason);
	handle->hangup_reason = reason;
	/* Let's message the loop, we'll notify the plugin from there */
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_hangup_peerconnection);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_hangup_peerconnection);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
	if(g_atomic_int_dec_and_test(&handle->has_pc))
		g_atomic_int_dec_and_test(&pc_num);
}

static void janus_ice_webrtc_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	if(!handle->agent_created) {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	handle->agent_created = 0;
	handle->agent_started = 0;
	if(handle->pc != NULL) {
		janus_ice_peerconnection_destroy(handle->pc);
		handle->pc = NULL;
	}
	if(handle->agent != NULL) {
#ifdef HAVE_CLOSE_ASYNC
		if(G_IS_OBJECT(handle->agent)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Removing stream %d from agent %p\n",
				handle->handle_id, handle->stream_id, handle->agent);
			nice_agent_remove_stream(handle->agent, handle->stream_id);
			handle->stream_id = 0;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Closing nice agent %p\n", handle->handle_id, handle->agent);
			janus_refcount_increase(&handle->ref);
			if(handle->rtp_source != NULL) {
				/* Destroy the agent asynchronously */
				g_source_ref(handle->rtp_source);
				nice_agent_close_async(handle->agent, janus_ice_cb_agent_closed, handle->rtp_source);
			} else {
				/* No traffic source, destroy it right away */
				if(G_IS_OBJECT(handle->agent))
					g_object_unref(handle->agent);
				handle->agent = NULL;
				janus_refcount_decrease(&handle->ref);
			}
		}
#else
		if(G_IS_OBJECT(handle->agent))
			g_object_unref(handle->agent);
		handle->agent = NULL;
#endif
	}
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
	janus_ice_clear_queued_candidates(handle);
	g_free(handle->rtp_profile);
	handle->rtp_profile = NULL;
	g_free(handle->local_sdp);
	handle->local_sdp = NULL;
	g_free(handle->remote_sdp);
	handle->remote_sdp = NULL;
	g_free(handle->pc_mid);
	handle->pc_mid = NULL;
	handle->thread = NULL;
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) && handle->hangup_reason) {
		janus_ice_notify_hangup(handle, handle->hangup_reason);
	}
	handle->hangup_reason = NULL;
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] WebRTC resources freed; %p %p\n", handle->handle_id, handle, handle->session);
}

void janus_ice_peerconnection_destroy(janus_ice_peerconnection *pc) {
	if(pc == NULL)
		return;
	/* Remove all media instances */
	g_hash_table_remove_all(pc->media);
	g_hash_table_remove_all(pc->media_byssrc);
	g_hash_table_remove_all(pc->media_bymid);
	g_hash_table_remove_all(pc->media_bytype);
	/* Get rid of the DTLS stack */
	if(pc->dtlsrt_source != NULL) {
		g_source_destroy(pc->dtlsrt_source);
		g_source_unref(pc->dtlsrt_source);
		pc->dtlsrt_source = NULL;
	}
	if(pc->dtls != NULL) {
		janus_dtls_srtp_destroy(pc->dtls);
		janus_refcount_decrease(&pc->dtls->ref);
		pc->dtls = NULL;
	}
	janus_ice_handle *handle = pc->handle;
	if(handle != NULL) {
		janus_refcount_decrease(&handle->ref);
		pc->handle = NULL;
	}
	janus_refcount_decrease(&pc->ref);
}

static void janus_ice_peerconnection_free(const janus_refcount *pc_ref) {
	janus_ice_peerconnection *pc = janus_refcount_containerof(pc_ref, janus_ice_peerconnection, ref);
	/* This PeerConnection can be destroyed, free all the resources */
	pc->handle = NULL;
	g_hash_table_destroy(pc->media);
	g_hash_table_destroy(pc->media_byssrc);
	g_hash_table_destroy(pc->media_bymid);
	g_hash_table_destroy(pc->media_bytype);
	if(pc->icestate_source != NULL) {
		g_source_destroy(pc->icestate_source);
		g_source_unref(pc->icestate_source);
		pc->icestate_source = NULL;
	}
	g_free(pc->remote_hashing);
	pc->remote_hashing = NULL;
	g_free(pc->remote_fingerprint);
	pc->remote_fingerprint = NULL;
	g_free(pc->ruser);
	pc->ruser = NULL;
	g_free(pc->rpass);
	pc->rpass = NULL;
	g_slist_free_full(pc->transport_wide_received_seq_nums, (GDestroyNotify)g_free);
	pc->transport_wide_received_seq_nums = NULL;
	if(pc->candidates != NULL) {
		GSList *i = NULL, *candidates = pc->candidates;
		for(i = candidates; i; i = i->next) {
			NiceCandidate *c = (NiceCandidate *) i->data;
			if(c != NULL) {
				nice_candidate_free(c);
				c = NULL;
			}
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	pc->candidates = NULL;
	if(pc->local_candidates != NULL) {
		GSList *i = NULL, *candidates = pc->local_candidates;
		for(i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			g_free(c);
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	pc->local_candidates = NULL;
	if(pc->remote_candidates != NULL) {
		GSList *i = NULL, *candidates = pc->remote_candidates;
		for(i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			g_free(c);
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	pc->remote_candidates = NULL;
	g_free(pc->selected_pair);
	pc->selected_pair = NULL;
	if(pc->payload_types != NULL)
		g_hash_table_destroy(pc->payload_types);
	pc->payload_types = NULL;
	if(pc->clock_rates != NULL)
		g_hash_table_destroy(pc->clock_rates);
	pc->clock_rates = NULL;
	if(pc->rtx_payload_types != NULL)
		g_hash_table_destroy(pc->rtx_payload_types);
	pc->rtx_payload_types = NULL;
	if(pc->rtx_payload_types_rev != NULL)
		g_hash_table_destroy(pc->rtx_payload_types_rev);
	pc->rtx_payload_types_rev = NULL;
	if(pc->nacks_queue != NULL)
		g_queue_free(pc->nacks_queue);
	janus_mutex_destroy(&pc->mutex);
	g_free(pc);
}

janus_ice_peerconnection_medium *janus_ice_peerconnection_medium_create(janus_ice_handle *handle, janus_media_type type) {
	if(handle == NULL || handle->pc == NULL)
		return NULL;
	janus_ice_peerconnection *pc = handle->pc;
	janus_ice_peerconnection_medium *medium = g_malloc0(sizeof(janus_ice_peerconnection_medium));
	medium->pc = pc;
	medium->type = type;
	medium->mindex = g_hash_table_size(pc->media);
	janus_mutex_init(&medium->mutex);
	janus_refcount_init(&medium->ref, janus_ice_peerconnection_medium_free);
	janus_refcount_increase(&pc->ref);
	g_hash_table_insert(pc->media, GINT_TO_POINTER(medium->mindex), medium);
	/* If this is audio or video, fill in some other fields too */
	if(type == JANUS_MEDIA_AUDIO || type == JANUS_MEDIA_VIDEO) {
		medium->payload_type = -1;
		medium->rtx_payload_type = -1;
		medium->ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
			/* Create an SSRC for RFC4588 as well */
			medium->ssrc_rtx = janus_random_uint32();	/* FIXME Should we look for conflicts? */
		}
		medium->rtcp_ctx[0] = g_malloc0(sizeof(janus_rtcp_context));
		medium->rtcp_ctx[0]->tb = (type == JANUS_MEDIA_VIDEO ? 90000 : 48000);	/* May change later */
		medium->rtcp_ctx[0]->in_link_quality = 100;
		medium->rtcp_ctx[0]->in_media_link_quality = 100;
		medium->rtcp_ctx[0]->out_link_quality = 100;
		medium->rtcp_ctx[0]->out_media_link_quality = 100;
		/* We can address media by SSRC */
		g_hash_table_insert(pc->media_byssrc, GINT_TO_POINTER(medium->ssrc), medium);
		janus_refcount_increase(&medium->ref);
		if(medium->ssrc_rtx > 0) {
			g_hash_table_insert(pc->media_byssrc, GINT_TO_POINTER(medium->ssrc_rtx), medium);
			janus_refcount_increase(&medium->ref);
		}
		g_hash_table_insert(pc->media_bytype, GINT_TO_POINTER(type), medium);
		janus_refcount_increase(&medium->ref);
	}
	/* For backwards compatibility, we address media by type too (e.g., first video stream) */
	g_hash_table_insert(pc->media_bytype, GINT_TO_POINTER(type), medium);
	janus_refcount_increase(&medium->ref);
	return medium;
}

static void janus_ice_peerconnection_medium_destroy(janus_ice_peerconnection_medium *medium) {
	if(medium == NULL)
		return;
	janus_ice_peerconnection *pc = medium->pc;
	if(pc != NULL) {
		janus_refcount_decrease(&pc->ref);
		medium->pc = NULL;
	}
	janus_refcount_decrease(&medium->ref);
}

static void janus_ice_peerconnection_medium_dereference(janus_ice_peerconnection_medium *medium) {
	if(medium == NULL)
		return;
	janus_refcount_decrease(&medium->ref);
}

static void janus_ice_peerconnection_medium_free(const janus_refcount *medium_ref) {
	janus_ice_peerconnection_medium *medium = janus_refcount_containerof(medium_ref, janus_ice_peerconnection_medium, ref);
	g_free(medium->mid);
	g_free(medium->msid);
	g_free(medium->mstid);
	g_free(medium->remote_msid);
	g_free(medium->remote_mstid);
	g_free(medium->rid[0]);
	medium->rid[0] = NULL;
	g_free(medium->rid[1]);
	medium->rid[1] = NULL;
	g_free(medium->rid[2]);
	medium->rid[2] = NULL;
	g_list_free(medium->payload_types);
	medium->payload_types = NULL;
	if(medium->rtx_payload_types != NULL)
		g_hash_table_destroy(medium->rtx_payload_types);
	medium->rtx_payload_types = NULL;
	if(medium->clock_rates != NULL)
		g_hash_table_destroy(medium->clock_rates);
	medium->clock_rates = NULL;
	g_free(medium->codec);
	medium->codec = NULL;
	g_free(medium->rtcp_ctx[0]);
	medium->rtcp_ctx[0] = NULL;
	g_free(medium->rtcp_ctx[1]);
	medium->rtcp_ctx[1] = NULL;
	g_free(medium->rtcp_ctx[2]);
	medium->rtcp_ctx[2] = NULL;
	if(medium->rtx_nacked[0])
		g_hash_table_destroy(medium->rtx_nacked[0]);
	medium->rtx_nacked[0] = NULL;
	if(medium->rtx_nacked[1])
		g_hash_table_destroy(medium->rtx_nacked[1]);
	medium->rtx_nacked[1] = NULL;
	if(medium->rtx_nacked[2])
		g_hash_table_destroy(medium->rtx_nacked[2]);
	medium->rtx_nacked[2] = NULL;
	if(medium->pending_nacked_cleanup != NULL) {
		if(g_hash_table_size(medium->pending_nacked_cleanup) > 0) {
			GHashTableIter iter;
			gpointer val;
			g_hash_table_iter_init(&iter, medium->pending_nacked_cleanup);
			while(g_hash_table_iter_next(&iter, NULL, &val)) {
				GSource *source = val;
				g_source_destroy(source);
			}
		}
		g_hash_table_destroy(medium->pending_nacked_cleanup);
	}
	medium->pending_nacked_cleanup = NULL;
	if(medium->retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		while((p = (janus_rtp_packet *)g_queue_pop_head(medium->retransmit_buffer)) != NULL) {
			/* Remove from hashtable too */
			janus_rtp_header *header = (janus_rtp_header *)p->data;
			guint16 seq = ntohs(header->seq_number);
			g_hash_table_remove(medium->retransmit_seqs, GUINT_TO_POINTER(seq));
			/* Free the packet */
			janus_ice_free_rtp_packet(p);
		}
		g_queue_free(medium->retransmit_buffer);
		g_hash_table_destroy(medium->retransmit_seqs);
	}
	if(medium->last_seqs[0])
		janus_seq_list_free(&medium->last_seqs[0]);
	if(medium->last_seqs[1])
		janus_seq_list_free(&medium->last_seqs[1]);
	if(medium->last_seqs[2])
		janus_seq_list_free(&medium->last_seqs[2]);
	janus_mutex_destroy(&medium->mutex);
	g_free(medium);
}

/* Call plugin slow_link callback if a minimum of lost packets are detected within a second */
static void
janus_slow_link_update(janus_ice_peerconnection_medium *medium, janus_ice_handle *handle,
		gboolean uplink, guint lost) {
	/* We keep the counters in different janus_ice_stats objects, depending on the direction */
	gboolean video = (medium->type == JANUS_MEDIA_VIDEO);
	guint sl_lost_last_count = uplink ? medium->in_stats.sl_lost_count : medium->out_stats.sl_lost_count;
	guint sl_lost_recently = (lost >= sl_lost_last_count) ? (lost - sl_lost_last_count) : 0;
	if(slowlink_threshold > 0 && sl_lost_recently >= slowlink_threshold) {
		/* Tell the plugin */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin && plugin->slow_link && janus_plugin_session_is_alive(handle->app_handle) &&
				!g_atomic_int_get(&handle->destroyed))
			plugin->slow_link(handle->app_handle, medium->mindex, video, uplink);
		/* Notify the user/application too */
		janus_session *session = (janus_session *)handle->session;
		if(session != NULL) {
			json_t *event = json_object();
			json_object_set_new(event, "janus", json_string("slowlink"));
			json_object_set_new(event, "session_id", json_integer(session->session_id));
			json_object_set_new(event, "sender", json_integer(handle->handle_id));
			if(opaqueid_in_api && handle->opaque_id != NULL)
				json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
			json_object_set_new(event, "mid", json_string(medium->mid));
			json_object_set_new(event, "media", json_string(video ? "video" : "audio"));
			json_object_set_new(event, "uplink", uplink ? json_true() : json_false());
			json_object_set_new(event, "lost", json_integer(sl_lost_recently));
			/* Send the event */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
			janus_session_notify_event(session, event);
			/* Finally, notify event handlers */
			if(janus_events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "mid", json_string(medium->mid));
				json_object_set_new(info, "media", json_string(video ? "video" : "audio"));
				json_object_set_new(info, "slow_link", json_string(uplink ? "uplink" : "downlink"));
				json_object_set_new(info, "lost_lastsec", json_integer(sl_lost_recently));
				janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_SLOWLINK,
					session->session_id, handle->handle_id, handle->opaque_id, info);
			}
		}
	}
	/* Update the counter */
	if(uplink) {
		medium->in_stats.sl_lost_count = lost;
	} else {
		medium->out_stats.sl_lost_count = lost;
	}
}


/* ICE state check timer (needed to check if a failed really is definitive or if things can still improve) */
static gboolean janus_ice_check_failed(gpointer data) {
	janus_ice_peerconnection *pc = (janus_ice_peerconnection *)data;
	if(!pc)
		goto stoptimer;
	janus_ice_handle *handle = pc->handle;
	if(!handle)
		goto stoptimer;
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) ||
			janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		goto stoptimer;
	if(pc->state == NICE_COMPONENT_STATE_CONNECTED || pc->state == NICE_COMPONENT_STATE_READY) {
		/* ICE succeeded in the meanwhile, get rid of this timer */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE succeeded, disabling ICE state check timer!\n", handle->handle_id);
		pc->icefailed_detected = 0;
		goto stoptimer;
	}
	/* Still in the failed state, how much time passed since we first detected it? */
	if(janus_get_monotonic_time() - pc->icefailed_detected < 5*G_USEC_PER_SEC) {
		/* Let's wait a little longer */
		return TRUE;
	}
	/* If we got here it means the timer expired, and we should check if this is a failure */
	gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
	gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	/* We may still be waiting for something... but we don't wait forever */
	gboolean do_wait = TRUE;
	if(janus_get_monotonic_time() - pc->icefailed_detected >= 15*G_USEC_PER_SEC) {
		do_wait = FALSE;
	}
	if(!do_wait || (handle && trickle_recv && answer_recv && !alert_set)) {
		/* FIXME Should we really give up for what may be a failure in only one of the media? */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n",
			handle->handle_id, pc->component_id, pc->stream_id);
		janus_ice_webrtc_hangup(handle, "ICE failed");
		goto stoptimer;
	}
	/* Let's wait a little longer */
	JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but we're still waiting for some info so we don't care... (trickle %s, answer %s, alert %s)\n",
		handle->handle_id, pc->component_id, pc->stream_id,
		trickle_recv ? "received" : "pending",
		answer_recv ? "received" : "pending",
		alert_set ? "set" : "not set");
	return TRUE;

stoptimer:
	if(pc && pc->icestate_source != NULL) {
		g_source_destroy(pc->icestate_source);
		g_source_unref(pc->icestate_source);
		pc->icestate_source = NULL;
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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]  No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	pc->gathered = janus_get_monotonic_time();
	pc->cdone = TRUE;
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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	guint prev_state = pc->state;
	pc->state = state;
	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "ice", json_string(janus_get_ice_state_name(state)));
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_ICE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	/* FIXME Even in case the state is 'connected', we wait for the 'new-selected-pair' callback to do anything */
	if(state == NICE_COMPONENT_STATE_FAILED) {
		/* Failed doesn't mean necessarily we need to give up: we may be trickling */
		gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		if(alert_set)
			return;
		if(prev_state == NICE_COMPONENT_STATE_CONNECTED || prev_state == NICE_COMPONENT_STATE_READY) {
			/* Failed after connected/ready means consent freshness detected something broken:
			 * notify the user via a Janus API event and then fire the 'failed' timer as sual */
			janus_ice_notify_ice_failed(handle);
			/* Check if we need to hangup right away, rather than start the grace period */
			if(janus_ice_hangup_on_failed && pc->icefailed_detected == 0) {
				/* We do, hangup the PeerConnection */
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n",
					handle->handle_id, component_id, stream_id);
				janus_ice_webrtc_hangup(handle, "ICE failed");
				return;
			}
		}
		gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
		gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but let's give it some time... (trickle %s, answer %s, alert %s)\n",
			handle->handle_id, component_id, stream_id,
			trickle_recv ? "received" : "pending",
			answer_recv ? "received" : "pending",
			alert_set ? "set" : "not set");
		/* In case we haven't started a timer yet, let's do it now */
		if(pc->icestate_source == NULL && pc->icefailed_detected == 0) {
			pc->icefailed_detected = janus_get_monotonic_time();
			pc->icestate_source = g_timeout_source_new(500);
			g_source_set_callback(pc->icestate_source, janus_ice_check_failed, pc, NULL);
			guint id = g_source_attach(pc->icestate_source, handle->mainctx);
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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
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
	g_snprintf(sp, sizeof(sp), "%s:%d [%s,%s] <-> %s:%d [%s,%s]",
		laddress, lport, ltype, local->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp",
		raddress, rport, rtype, remote->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp");
#endif
	gboolean newpair = FALSE;
	if(pc->selected_pair == NULL || strcmp(sp, pc->selected_pair)) {
		newpair = TRUE;
		gchar *prev_selected_pair = pc->selected_pair;
		pc->selected_pair = g_strdup(sp);
		g_clear_pointer(&prev_selected_pair, g_free);
	}
	/* Notify event handlers */
	if(newpair && janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "selected-pair", json_string(sp));
#ifdef HAVE_LIBNICE_TCP
		json_t *candidates = json_object();
		json_t *lcand = json_object();
		json_object_set_new(lcand, "address", json_string(laddress));
		json_object_set_new(lcand, "port", json_integer(lport));
		json_object_set_new(lcand, "type", json_string(ltype));
		json_object_set_new(lcand, "transport", json_string(local->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp"));
		json_object_set_new(lcand, "family", json_integer(nice_address_ip_version(&local->addr)));
		json_object_set_new(candidates, "local", lcand);
		json_t *rcand = json_object();
		json_object_set_new(rcand, "address", json_string(raddress));
		json_object_set_new(rcand, "port", json_integer(rport));
		json_object_set_new(rcand, "type", json_string(rtype));
		json_object_set_new(rcand, "transport", json_string(remote->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp"));
		json_object_set_new(rcand, "family", json_integer(nice_address_ip_version(&remote->addr)));
		json_object_set_new(candidates, "remote", rcand);
		json_object_set_new(info, "candidates", candidates);
#endif
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_PAIR,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	/* Have we been here before? (might happen, when trickling) */
	if(pc->connected > 0)
		return;
	/* FIXME Clear the queue */
	janus_ice_clear_queued_packets(handle);
	/* Now we can start the DTLS handshake (FIXME This was on the 'connected' state notification, before) */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready enough, starting DTLS handshake...\n", handle->handle_id);
	pc->connected = janus_get_monotonic_time();
	/* Start the DTLS handshake, at last */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_dtls_handshake);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_dtls_handshake);
#endif
	g_main_context_wakeup(handle->mainctx);
}

/* Candidates management */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate, gboolean force_private, guint public_ip_index);
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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	/* Get local candidates and look for the related foundation */
	NiceCandidate *candidate = NULL;
	GSList *candidates = nice_agent_get_local_candidates(agent, component_id, stream_id), *tmp = candidates;
	while(tmp) {
		NiceCandidate *c = (NiceCandidate *)tmp->data;
		/* Check if this is what we're looking for */
		if(!candidate && !strcasecmp(c->foundation, foundation)) {
			/* It is! */
			candidate = c;
		} else {
			nice_candidate_free(c);
		}
		tmp = tmp->next;
	}
	g_slist_free(candidates);
	if(candidate == NULL) {
		JANUS_LOG(LOG_WARN, "Candidate with foundation %s not found?\n", foundation);
		return;
	}
#endif
	char buffer[200];
	guint public_ip_index = 0;
	gboolean ipv6 = (nice_address_ip_version(&candidate->addr) == 6);
	gboolean same_family = (!ipv6 && janus_has_public_ipv4_ip()) || (ipv6 && janus_has_public_ipv6_ip());
	do {
		if(janus_ice_candidate_to_string(handle, candidate, buffer, sizeof(buffer), TRUE, FALSE, public_ip_index) == 0) {
			/* Candidate encoded, send a "trickle" event to the browser (but only if it's not a 'prflx') */
			if(candidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
			} else {
				if(strlen(buffer) > 0)
					janus_ice_notify_trickle(handle, buffer);
				/* If nat-1-1 is enabled but we want to keep the private host, add another candidate */
				if(nat_1_1_enabled && public_ip_index == 0 && (keep_private_host || !same_family) &&
						janus_ice_candidate_to_string(handle, candidate, buffer, sizeof(buffer), TRUE, TRUE, public_ip_index) == 0) {
					if(candidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
					} else if(strlen(buffer) > 0) {
						janus_ice_notify_trickle(handle, buffer);
					}
				}
			}
		}
		public_ip_index++;
		if(!same_family) {
			/* We don't have any nat-1-1 address of the same family as this candidate, we're done */
			break;
		}
	} while (public_ip_index < janus_get_public_ip_count());

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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
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
	char buffer[200];
	if(candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
		g_snprintf(buffer, sizeof(buffer),
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
			g_snprintf(buffer, sizeof(buffer),
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

	/* Now parse the candidate as if we received it from the Janus API */
	int res = janus_sdp_parse_candidate(pc, buffer, 1);
	if(res != 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse prflx candidate... (%d)\n", handle->handle_id, res);
	}

candidatedone:
#ifndef HAVE_LIBNICE_TCP
	nice_candidate_free(candidate);
#endif
	return;
}

static void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
	janus_ice_peerconnection *pc = (janus_ice_peerconnection *)ice;
	if(!pc) {
		JANUS_LOG(LOG_ERR, "No component %d in stream %d??\n", component_id, stream_id);
		return;
	}
	janus_ice_handle *handle = pc->handle;
	if(!handle) {
		JANUS_LOG(LOG_ERR, "No handle for stream %d??\n", stream_id);
		return;
	}
	janus_session *session = (janus_session *)handle->session;
	if(!pc->dtls) {	/* Still waiting for the DTLS stack */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still waiting for the DTLS stack for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) || janus_is_stopping()) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forced to stop it here...\n", handle->handle_id);
		return;
	}
	/* What is this? */
	if(janus_is_dtls(buf) || (!janus_is_rtp(buf, len) && !janus_is_rtcp(buf, len))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Looks like DTLS!\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(pc->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) */
		pc->dtls_in_stats.info[0].packets++;
		pc->dtls_in_stats.info[0].bytes += len;
		/* If there's a datachannel medium, update the stats there too */
		janus_ice_peerconnection_medium *medium = g_hash_table_lookup(pc->media_bytype, GINT_TO_POINTER(JANUS_MEDIA_DATA));
		if(medium) {
			medium->in_stats.info[0].packets++;
			medium->in_stats.info[0].bytes += len;
		}
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/rfc5761#section-4) */
	if(janus_is_rtp(buf, len)) {
		/* This is RTP */
		if(janus_is_webrtc_encryption_enabled() && (!pc->dtls || !pc->dtls->srtp_valid || !pc->dtls->srtp_in)) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			janus_rtp_header *header = (janus_rtp_header *)buf;
			guint32 packet_ssrc = ntohl(header->ssrc);
			/* Which medium does this refer to? Is this audio or video? */
			int video = 0, vindex = 0, rtx = 0;
			janus_ice_peerconnection_medium *medium = g_hash_table_lookup(pc->media_byssrc, GINT_TO_POINTER(packet_ssrc));
			if(medium == NULL) {
				/* SSRC not found, try the mid/rid RTP extensions if in use */
				if(pc->mid_ext_id > 0) {
					char sdes_item[16];
					if(janus_rtp_header_extension_parse_mid(buf, len, pc->mid_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
						medium = g_hash_table_lookup(pc->media_bymid, sdes_item);
						if(medium != NULL) {
							/* Found! Associate this SSRC to this stream */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] SSRC %"SCNu32" is associated to mid %s\n",
								handle->handle_id, packet_ssrc, medium->mid);
							gboolean found = FALSE;
							/* Check if simulcasting is involved */
							janus_mutex_lock(&handle->mutex);
							if(medium->rid[0] == NULL || pc->rid_ext_id < 1) {
								medium->ssrc_peer[0] = packet_ssrc;
								found = TRUE;
							} else {
								if(janus_rtp_header_extension_parse_rid(buf, len, pc->rid_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
									/* Try the RTP stream ID */
									if(medium->rid[0] != NULL && !strcmp(medium->rid[0], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting: rid=%s\n", handle->handle_id, sdes_item);
										medium->ssrc_peer[0] = packet_ssrc;
										found = TRUE;
									} else if(medium->rid[1] != NULL && !strcmp(medium->rid[1], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #1: rid=%s\n", handle->handle_id, sdes_item);
										medium->ssrc_peer[1] = packet_ssrc;
										found = TRUE;
									} else if(medium->rid[2] != NULL && !strcmp(medium->rid[2], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #2: rid=%s\n", handle->handle_id, sdes_item);
										medium->ssrc_peer[2] = packet_ssrc;
										found = TRUE;
									} else {
										JANUS_LOG(LOG_WARN, "[%"SCNu64"]  -- Simulcasting: unknown rid %s..?\n", handle->handle_id, sdes_item);
									}
								} else if(pc->ridrtx_ext_id > 0 &&
										janus_rtp_header_extension_parse_rid(buf, len, pc->ridrtx_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
									/* Try the repaired RTP stream ID */
									if(medium->rid[0] != NULL && !strcmp(medium->rid[0], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										medium->ssrc_peer_rtx[0] = packet_ssrc;
										found = TRUE;
									} else if(medium->rid[1] != NULL && !strcmp(medium->rid[1], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #1: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										medium->ssrc_peer_rtx[1] = packet_ssrc;
										found = TRUE;
									} else if(medium->rid[2] != NULL && !strcmp(medium->rid[2], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #2: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										medium->ssrc_peer_rtx[2] = packet_ssrc;
										found = TRUE;
									} else {
										JANUS_LOG(LOG_WARN, "[%"SCNu64"]  -- Simulcasting: unknown rid %s..?\n", handle->handle_id, sdes_item);
									}
								}
							}
							janus_mutex_unlock(&handle->mutex);
							if(found) {
								g_hash_table_insert(pc->media_byssrc, GINT_TO_POINTER(packet_ssrc), medium);
								janus_refcount_increase(&medium->ref);
							} else {
								medium = NULL;
							}
						}
					}
				}
			}
			if(medium == NULL) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unknown SSRC, dropping packet (SSRC %"SCNu32")...\n",
					handle->handle_id, packet_ssrc);
				return;
			}
			video = (medium->type == JANUS_MEDIA_VIDEO);
			/* Make sure we're prepared to receive this media packet */
			if(!medium->recv)
				return;
			/* If this is video, check if this is simulcast and/or a retransmission using RFC4588 */
			vindex = 0;
			if(video && medium->ssrc_peer[0] != packet_ssrc) {
				if(medium->ssrc_peer[1] == packet_ssrc) {
					/* FIXME Simulcast (1) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #1 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 1;
				} else if(medium->ssrc_peer[2] == packet_ssrc) {
					/* FIXME Simulcast (2) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #2 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 2;
				} else {
					/* Maybe a video retransmission using RFC4588? */
					if(medium->ssrc_peer_rtx[0] == packet_ssrc) {
						rtx = 1;
						vindex = 0;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video (SSRC %"SCNu32")...\n",
							handle->handle_id, packet_ssrc);
					} else if(medium->ssrc_peer_rtx[1] == packet_ssrc) {
						rtx = 1;
						vindex = 1;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					} else if(medium->ssrc_peer_rtx[2] == packet_ssrc) {
						rtx = 1;
						vindex = 2;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					}
				}
			}

			int buflen = len;
			srtp_err_status_t res = janus_is_webrtc_encryption_enabled() ?
				srtp_unprotect(pc->dtls->srtp_in, buf, &buflen) : srtp_err_status_ok;
			if(res != srtp_err_status_ok) {
				if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
					/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n", handle->handle_id, janus_srtp_error_str(res), len, buflen, timestamp, seq);
				}
			} else {
				if((!video && medium->ssrc_peer[0] == 0) || (vindex == 0 && medium->ssrc_peer[0] == 0)) {
					medium->ssrc_peer[0] = ntohl(header->ssrc);
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer #%d (%s) SSRC: %u\n",
						handle->handle_id, medium->mindex,
						medium->type == JANUS_MEDIA_VIDEO ? "video" : "audio",
						medium->ssrc_peer[0]);
				}
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, TRUE, buf, buflen,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* If this is a retransmission using RFC4588, we have to do something first to get the original packet */
				janus_rtp_header *header = (janus_rtp_header *)buf;
				int plen = 0;
				char *payload = janus_rtp_payload(buf, buflen, &plen);
				if (!payload) {
					  JANUS_LOG(LOG_ERR, "[%"SCNu64"]     Error accessing the RTP payload len=%d\n", handle->handle_id, buflen);
				}
				if(rtx) {
					/* The original sequence number is in the first two bytes of the payload */
					/* Rewrite the header with the info from the original packet (payload type, SSRC, sequence number) */
					header->type = medium->payload_type;
					packet_ssrc = medium->ssrc_peer[vindex];
					header->ssrc = htonl(packet_ssrc);
					if(plen > 0) {
						memcpy(&header->seq_number, payload, 2);
						/* Finally, remove the original sequence number from the payload: move the whole
						 * payload back two bytes rather than shifting the header forward (avoid misaligned access) */
						buflen -= 2;
						plen -= 2;
						memmove(payload, payload+2, plen);
						header = (janus_rtp_header *)buf;
						if(pc->rid_ext_id > 1 && pc->ridrtx_ext_id > 1) {
							/* Replace the 'repaired' extension ID as well with the 'regular' one */
							janus_rtp_header_extension_replace_id(buf, buflen, pc->ridrtx_ext_id, pc->rid_ext_id);
						}
					}
				}
				/* Check if we need to handle transport wide cc */
				if(pc->do_transport_wide_cc) {
					guint16 transport_seq_num;
					/* Get transport wide seq num */
					if(janus_rtp_header_extension_parse_transport_wide_cc(buf, buflen, pc->transport_wide_cc_ext_id, &transport_seq_num) == 0) {
						/* Get current timestamp */
						struct timeval now;
						gettimeofday(&now,0);
						/* Create <seq num, time> pair */
						janus_rtcp_transport_wide_cc_stats *stats = g_malloc0(sizeof(janus_rtcp_transport_wide_cc_stats));
						/* Check if we have a sequence wrap */
						if(transport_seq_num<0x0FFF && (pc->transport_wide_cc_last_seq_num&0xFFFF)>0xF000) {
							/* Increase cycles */
							pc->transport_wide_cc_cycles++;
						}
						/* Get extended value */
						guint32 transport_ext_seq_num = pc->transport_wide_cc_cycles<<16 | transport_seq_num;
						/* Store last received transport seq num */
						pc->transport_wide_cc_last_seq_num = transport_seq_num;
						/* Set stats values */
						stats->transport_seq_num = transport_ext_seq_num;
						stats->timestamp = (((guint64)now.tv_sec)*1E6+now.tv_usec);
						/* Lock and append to received list */
						janus_mutex_lock(&pc->mutex);
						pc->transport_wide_received_seq_nums = g_slist_prepend(pc->transport_wide_received_seq_nums, stats);
						janus_mutex_unlock(&pc->mutex);
					}
				}
				if(medium->do_nacks) {
					/* Check if this packet is a duplicate: can happen with RFC4588 */
					guint16 seqno = ntohs(header->seq_number);
					int nstate = medium->rtx_nacked[vindex] ?
						GPOINTER_TO_INT(g_hash_table_lookup(medium->rtx_nacked[vindex], GUINT_TO_POINTER(seqno))) : 0;
					if(nstate == 1) {
						/* Packet was NACKed and this is the first time we receive it: change state to received */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						g_hash_table_insert(medium->rtx_nacked[vindex], GUINT_TO_POINTER(seqno), GUINT_TO_POINTER(2));
					} else if(nstate == 2) {
						/* We already received this packet: drop it */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Detected duplicate packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						return;
					} else if(rtx && nstate == 0) {
						/* We received a retransmission for a packet we didn't NACK: drop it
						 * FIXME This seems to happen with Chrome when RFC4588 is enabled: in that case,
						 * Chrome sends the first packet ~8 times as a retransmission, probably to ensure
						 * we receive it, since the first packet cannot be NACKed (NACKs are triggered
						 * when there's a gap in between two packets, and the first doesn't have a reference)
						 * Rather than dropping, we should add a better check in the future */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Got a retransmission for non-NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						return;
					}
				}
				/* Backup the RTP header before passing it to the proper RTP switching context */
				janus_rtp_header backup = *header;
				if(medium->ssrc_peer_orig[vindex] == 0)
					medium->ssrc_peer_orig[vindex] = packet_ssrc;
				janus_rtp_header_update(header, &medium->rtp_ctx[vindex], medium->type == JANUS_MEDIA_VIDEO, 0);
				header->ssrc = htonl(medium->ssrc_peer_orig[vindex]);
				/* Keep track of payload types too */
				if(medium->payload_type < 0) {
					medium->payload_type = header->type;
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
							medium->rtx_payload_types && g_hash_table_size(medium->rtx_payload_types) > 0) {
						medium->rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(medium->rtx_payload_types, GINT_TO_POINTER(medium->payload_type)));
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
							handle->handle_id, medium->rtx_payload_type);
					}
					if(medium->codec == NULL) {
						janus_mutex_lock(&handle->mutex);
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, medium->payload_type);
						janus_mutex_unlock(&handle->mutex);
						if(codec != NULL)
							medium->codec = g_strdup(codec);
					}
					if(medium->type == JANUS_MEDIA_VIDEO && medium->video_is_keyframe == NULL && medium->codec != NULL) {
						if(!strcasecmp(medium->codec, "vp8"))
							medium->video_is_keyframe = &janus_vp8_is_keyframe;
						else if(!strcasecmp(medium->codec, "vp9"))
							medium->video_is_keyframe = &janus_vp9_is_keyframe;
						else if(!strcasecmp(medium->codec, "h264"))
							medium->video_is_keyframe = &janus_h264_is_keyframe;
						else if(!strcasecmp(medium->codec, "av1"))
							medium->video_is_keyframe = &janus_av1_is_keyframe;
						else if(!strcasecmp(medium->codec, "h265"))
							medium->video_is_keyframe = &janus_h265_is_keyframe;
					}
				}
				/* Prepare the data to pass to the responsible plugin */
				janus_plugin_rtp rtp = { .mindex = medium->mindex, .video = video, .buffer = buf, .length = buflen };
				janus_plugin_rtp_extensions_reset(&rtp.extensions);
				/* Parse RTP extensions before involving the plugin */
				if(!video && pc->audiolevel_ext_id != -1) {
					gboolean vad = FALSE;
					int level = -1;
					if(janus_rtp_header_extension_parse_audio_level(buf, buflen,
							pc->audiolevel_ext_id, &vad, &level) == 0) {
						rtp.extensions.audio_level = level;
						rtp.extensions.audio_level_vad = vad;
					}
				}
				if(video && pc->videoorientation_ext_id != -1) {
					gboolean c = FALSE, f = FALSE, r1 = FALSE, r0 = FALSE;
					if(janus_rtp_header_extension_parse_video_orientation(buf, buflen,
							pc->videoorientation_ext_id, &c, &f, &r1, &r0) == 0) {
						rtp.extensions.video_rotation = 0;
						if(r1 && r0)
							rtp.extensions.video_rotation = 270;
						else if(r1)
							rtp.extensions.video_rotation = 180;
						else if(r0)
							rtp.extensions.video_rotation = 90;
						rtp.extensions.video_back_camera = c;
						rtp.extensions.video_flipped = f;
					}
				}
				if(video && pc->playoutdelay_ext_id != -1) {
					uint16_t min = 0, max = 0;
					if(janus_rtp_header_extension_parse_playout_delay(buf, buflen,
							pc->playoutdelay_ext_id, &min, &max) == 0) {
						rtp.extensions.min_delay = min;
						rtp.extensions.max_delay = max;
					}
				}
				if(video && pc->dependencydesc_ext_id != -1) {
					uint8_t dd[256];
					int len = sizeof(dd);
					if(janus_rtp_header_extension_parse_dependency_desc(buf, buflen,
							pc->dependencydesc_ext_id, dd, &len) == 0 && len > 0) {
						/* We copy the DD bytes as they are: it's up to plugins to parse it, if needed */
						rtp.extensions.dd_len = len;
						memcpy(rtp.extensions.dd_content, dd, len);
					}
				}
				if(pc->abs_capture_time_ext_id != -1) {
					uint64_t abs_ts = 0;
					if(janus_rtp_header_extension_parse_abs_capture_time(buf, buflen,
							pc->abs_capture_time_ext_id, &abs_ts) == 0) {
						rtp.extensions.abs_capture_ts = abs_ts;
					}
				}
				if(pc->videolayers_ext_id != -1) {
					int8_t spatial_layers = -1, temporal_layers = -1;
					if(janus_rtp_header_extension_parse_video_layers_allocation(buf, buflen,
							pc->videolayers_ext_id, &spatial_layers, &temporal_layers) == 0) {
						/* We copy the VLA bytes as they are: it's up to plugins to parse it, if needed */
						rtp.extensions.spatial_layers = spatial_layers;
						rtp.extensions.temporal_layers = temporal_layers;
					}
				}
				/* Pass the packet to the plugin */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp && handle->app_handle &&
						!g_atomic_int_get(&handle->app_handle->stopped) &&
						!g_atomic_int_get(&handle->destroyed))
					plugin->incoming_rtp(handle->app_handle, &rtp);
				/* Restore the header for the stats (plugins may have messed with it) */
				*header = backup;
				/* Update stats (overall data received, and data received in the last second) */
				if(buflen > 0) {
					gint64 now = janus_get_monotonic_time();
					if(medium->in_stats.info[vindex].bytes == 0 || medium->in_stats.info[vindex].notified_lastsec) {
						/* We either received our first packet, or we started receiving it again after missing more than a second */
						medium->in_stats.info[vindex].notified_lastsec = FALSE;
						janus_ice_notify_media(handle, medium->mid, medium->type == JANUS_MEDIA_VIDEO, medium->rtcp_ctx[1] != NULL, vindex, TRUE);
					}
					/* Overall video data for this SSRC */
					medium->in_stats.info[vindex].packets++;
					medium->in_stats.info[vindex].bytes += buflen;
					/* Last second video data for this SSRC */
					if(medium->in_stats.info[vindex].updated == 0)
						medium->in_stats.info[vindex].updated = now;
					if(now > medium->in_stats.info[vindex].updated &&
							now - medium->in_stats.info[vindex].updated >= G_USEC_PER_SEC) {
						medium->in_stats.info[vindex].bytes_lastsec = medium->in_stats.info[vindex].bytes_lastsec_temp;
						medium->in_stats.info[vindex].bytes_lastsec_temp = 0;
						medium->in_stats.info[vindex].updated = now;
					}
					medium->in_stats.info[vindex].bytes_lastsec_temp += buflen;
				}

				/* Update the RTCP context as well */
				rtcp_context *rtcp_ctx = medium->rtcp_ctx[vindex];
				gboolean retransmissions_disabled = !medium->do_nacks;
				janus_rtcp_process_incoming_rtp(rtcp_ctx, buf, buflen,
						(video && rtx) ? TRUE : FALSE,
						(video && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)),
						retransmissions_disabled, medium->clock_rates
				);

				/* Keep track of RTP sequence numbers, in case we need to NACK them */
				/* 	Note: unsigned int overflow/underflow wraps (defined behavior) */
				if(retransmissions_disabled) {
					/* ... unless NACKs are disabled for this medium */
					return;
				}
				guint16 new_seqn = ntohs(header->seq_number);
				/* If this is video, check if this is a keyframe: if so, we empty our NACK queue */
				if(video && medium->video_is_keyframe) {
					if(medium->video_is_keyframe(payload, plen)) {
						if(rtcp_ctx && (int16_t)(new_seqn - rtcp_ctx->max_seq_nr) > 0) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe received with a highest sequence number, resetting NACK queue\n", handle->handle_id);
							janus_seq_list_free(&medium->last_seqs[vindex]);
						}
					}
				}
				guint16 cur_seqn;
				int last_seqs_len = 0;
				janus_mutex_lock(&medium->mutex);
				janus_seq_info **last_seqs = &medium->last_seqs[vindex];
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
							nacks = g_slist_prepend(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_NACKED;
							if(video && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* Keep track of this sequence number, we need to avoid duplicates */
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Tracking NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
									handle->handle_id, cur_seq->seq, packet_ssrc, vindex);
								if(medium->rtx_nacked[vindex] == NULL)
									medium->rtx_nacked[vindex] = g_hash_table_new(NULL, NULL);
								g_hash_table_insert(medium->rtx_nacked[vindex], GUINT_TO_POINTER(cur_seq->seq), GINT_TO_POINTER(1));
								/* We don't track it forever, though: add a timed source to remove it in a few seconds */
								janus_ice_nacked_packet *np = g_malloc(sizeof(janus_ice_nacked_packet));
								np->medium = medium;
								np->seq_number = cur_seq->seq;
								np->vindex = vindex;
								if(medium->pending_nacked_cleanup == NULL)
									medium->pending_nacked_cleanup = g_hash_table_new(NULL, NULL);
								GSource *timeout_source = g_timeout_source_new_seconds(5);
								g_source_set_callback(timeout_source, janus_ice_nacked_packet_cleanup, np, (GDestroyNotify)g_free);
								np->source_id = g_source_attach(timeout_source, handle->mainctx);
								g_source_unref(timeout_source);
								g_hash_table_insert(medium->pending_nacked_cleanup, GUINT_TO_POINTER(np->source_id), timeout_source);
							}
						} else if(cur_seq->state == SEQ_NACKED  && now - cur_seq->ts > SEQ_NACKED_WAIT) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16" (%s stream #%d), sending 2nd NACK\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							nacks = g_slist_prepend(nacks, GUINT_TO_POINTER(cur_seq->seq));
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
							medium->ssrc, medium->ssrc_peer[vindex]);
						janus_plugin_rtcp rtcp = { .mindex = medium->mindex, .video = video, .buffer = nackbuf, .length = res };
						janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
					}
					/* Update stats */
					medium->nack_sent_recent_cnt += nacks_count;
					medium->out_stats.info[vindex].nacks += nacks_count;
				}
				if(medium->nack_sent_recent_cnt &&
						(now - medium->nack_sent_log_ts) > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sent NACKs for %u missing packets (%s stream #%d)\n",
						handle->handle_id, medium->nack_sent_recent_cnt, video ? "video" : "audio", vindex);
					medium->nack_sent_recent_cnt = 0;
					medium->nack_sent_log_ts = now;
				}
				janus_mutex_unlock(&medium->mutex);
				g_slist_free(nacks);
				nacks = NULL;
			}
		}
		return;
	} else if(janus_is_rtcp(buf, len)) {
		/* This is RTCP */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTCP packet\n", handle->handle_id);
		if(janus_is_webrtc_encryption_enabled() && (!pc->dtls || !pc->dtls->srtp_valid || !pc->dtls->srtp_in)) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			srtp_err_status_t res = janus_is_webrtc_encryption_enabled() ?
				srtp_unprotect_rtcp(pc->dtls->srtp_in, buf, &buflen) : srtp_err_status_ok;
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
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got RTCP BYE on stream %u (component %u)\n", handle->handle_id, stream_id, component_id);
				}
				/* Is this audio or video? */
				int video = 0, vindex = 0;
				/* Bundled streams, should we check the SSRCs? */
				guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, buflen);
				janus_ice_peerconnection_medium *medium = g_hash_table_lookup(pc->media_byssrc, GINT_TO_POINTER(rtcp_ssrc));
				if(medium == NULL) {
					/* We don't know the remote SSRC: this can happen for recvonly clients
					 * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
					 * Check the local SSRC, compare it to what we have */
					rtcp_ssrc = janus_rtcp_get_receiver_ssrc(buf, buflen);
					medium = g_hash_table_lookup(pc->media_byssrc, GINT_TO_POINTER(rtcp_ssrc));
					if(medium == NULL) {
						if(rtcp_ssrc > 0) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unknown SSRC, dropping RTCP packet (SSRC %"SCNu32")...\n",
								handle->handle_id, rtcp_ssrc);
						}
						return;
					}
				}
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
					janus_rtcp_swap_report_blocks(buf, buflen, medium->ssrc_rtx);
				}
				video = (medium->type == JANUS_MEDIA_VIDEO);
				/* If this is video, check if this is simulcast */
				if(video) {
					if(medium->ssrc_peer[1] == rtcp_ssrc) {
						vindex = 1;
					} else if(medium->ssrc_peer[2] == rtcp_ssrc) {
						vindex = 2;
					}
				}

				/* Let's process this RTCP (compound?) packet, and update the RTCP context for this stream in case */
				rtcp_context *rtcp_ctx = medium->rtcp_ctx[vindex];
				uint32_t rtt = rtcp_ctx ? rtcp_ctx->rtt : 0;
				if(janus_rtcp_parse(rtcp_ctx, buf, buflen) < 0) {
					/* Drop the packet if the parsing function returns with an error */
					return;
				}
				if(rtcp_ctx && rtcp_ctx->rtt != rtt) {
					/* Check the current RTT, to see if we need to update the size of the queue: we take
					 * the RTT (should we include all media?) and add 100ms just to be conservative */
					uint32_t medium_rtt = janus_rtcp_context_get_rtt(medium->rtcp_ctx[0]);
					uint16_t nack_queue_ms = medium_rtt + 100;
					if(nack_queue_ms > DEFAULT_MAX_NACK_QUEUE)
						nack_queue_ms = DEFAULT_MAX_NACK_QUEUE;
					else if(nack_queue_ms < min_nack_queue)
						nack_queue_ms = min_nack_queue;
					uint16_t mavg = rtt ? ((7*medium->nack_queue_ms + nack_queue_ms)/8) : nack_queue_ms;
					if(mavg > DEFAULT_MAX_NACK_QUEUE)
						mavg = DEFAULT_MAX_NACK_QUEUE;
					else if(mavg < min_nack_queue)
						mavg = min_nack_queue;
					medium->nack_queue_ms = mavg;
				}
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Got %s RTCP (%d bytes)\n", handle->handle_id, video ? "video" : "audio", buflen);
				/* See if there's any REMB bitrate to track */
				uint32_t bitrate = janus_rtcp_get_remb(buf, buflen);
				if(bitrate > 0)
					pc->remb_bitrate = bitrate;

				/* Now let's see if there are any NACKs to handle */
				gint64 now = janus_get_monotonic_time();
				if(pc->nacks_queue == NULL)
					pc->nacks_queue = g_queue_new();
				GQueue *nacks = pc->nacks_queue;
				janus_rtcp_get_nacks(buf, buflen, nacks);
				guint nacks_count = g_queue_get_length(nacks);
				if(nacks_count && medium->do_nacks) {
					/* Handle NACK */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"]     Just got some NACKS (%d) we should handle...\n", handle->handle_id, nacks_count);
					GHashTable *retransmit_seqs = medium->retransmit_seqs;
					GQueue *queue = (retransmit_seqs != NULL ? nacks : NULL);
					int retransmits_cnt = 0;
					janus_mutex_lock(&medium->mutex);
					while(queue != NULL && g_queue_get_length(queue) > 0) {
						unsigned int seqnr = GPOINTER_TO_UINT(g_queue_pop_tail(queue));
						JANUS_LOG(LOG_DBG, "[%"SCNu64"]   >> %u\n", handle->handle_id, seqnr);
						int in_rb = 0;
						/* Check if we have the packet */
						janus_rtp_packet *p = g_hash_table_lookup(retransmit_seqs, GUINT_TO_POINTER(seqnr));
						if(p == NULL) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Can't retransmit packet %u, we don't have it...\n", handle->handle_id, seqnr);
						} else {
							/* Should we retransmit this packet? */
							if((p->last_retransmit > 0) && (now-p->last_retransmit < p->current_backoff)) {
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"us ago, skipping\n", handle->handle_id, seqnr, now-p->last_retransmit);
								g_queue_pop_tail(queue);
								continue;
							}
							in_rb = 1;
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission due to NACK\n", handle->handle_id, seqnr);
							p->last_retransmit = now;
							if(p->current_backoff == 0) {
								p->current_backoff = MIN_NACK_IGNORE;
							} else {
								p->current_backoff *= 2;
								if(p->current_backoff > MAX_NACK_IGNORE)
									p->current_backoff = MAX_NACK_IGNORE;
							}
							retransmits_cnt++;
							/* Enqueue it */
							janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
							pkt->mindex = medium->mindex;
							pkt->data = g_malloc(p->length+SRTP_MAX_TAG_LEN);
							memcpy(pkt->data, p->data, p->length);
							pkt->length = p->length;
							pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
							pkt->extensions = p->extensions;
							pkt->control = FALSE;
							pkt->control_ext = FALSE;
							pkt->retransmission = TRUE;
							pkt->label = NULL;
							pkt->protocol = NULL;
							pkt->added = janus_get_monotonic_time();
							/* What to send and how depends on whether we're doing RFC4588 or not */
							if(!video || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* We're not: just clarify the packet was already encrypted before */
								pkt->encrypted = TRUE;
							} else {
								/* We are: overwrite the RTP header (which means we'll need a new SRTP encrypt) */
								pkt->encrypted = FALSE;
								janus_rtp_header *header = (janus_rtp_header *)pkt->data;
								header->type = medium->rtx_payload_type;
								header->ssrc = htonl(medium->ssrc_rtx);
								medium->rtx_seq_number++;
								header->seq_number = htons(medium->rtx_seq_number);
							}
							if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
								g_async_queue_push_front(handle->queued_packets, pkt);
#else
								g_async_queue_push(handle->queued_packets, pkt);
#endif
								g_main_context_wakeup(handle->mainctx);
							} else {
								janus_ice_free_queued_packet(pkt);
							}
						}
						if(rtcp_ctx != NULL && in_rb) {
							g_atomic_int_inc(&rtcp_ctx->nack_count);
						}
						g_queue_pop_tail(queue);
					}
					medium->retransmit_recent_cnt += retransmits_cnt;
					/* FIXME Remove the NACK compound packet, we've handled it */
					buflen = janus_rtcp_remove_nacks(buf, buflen);
					/* Update stats */
					medium->in_stats.info[vindex].nacks += nacks_count;
					janus_mutex_unlock(&medium->mutex);
				}
				if(medium->retransmit_recent_cnt &&
						now - medium->retransmit_log_ts > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Retransmitted %u packets due to NACK (%s stream #%d)\n",
						handle->handle_id, medium->retransmit_recent_cnt, video ? "video" : "audio", vindex);
					medium->retransmit_recent_cnt = 0;
					medium->retransmit_log_ts = now;
				}

				/* Fix packet data for RTCP SR and RTCP RR */
				janus_rtp_switching_context *rtp_ctx = &medium->rtp_ctx[vindex];
				uint32_t base_ts = rtp_ctx->base_ts;
				uint32_t base_ts_prev = rtp_ctx->base_ts_prev;
				uint32_t ssrc_peer = medium->ssrc_peer_orig[vindex];
				uint32_t ssrc_local = medium->ssrc;
				uint32_t ssrc_expected = rtp_ctx->last_ssrc;
				if (janus_rtcp_fix_report_data(buf, buflen, base_ts, base_ts_prev, ssrc_peer, ssrc_local, ssrc_expected, video) < 0) {
					/* Drop packet in case of parsing error or SSRC different from the one expected. */
					/* This might happen at the very beginning of the communication or early after */
					/* a re-negotiation has been concluded. */
					return;
				}

				janus_plugin_rtcp rtcp = { .mindex = medium->mindex, .video = video, .buffer = buf, .length = buflen };
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtcp && handle->app_handle &&
						!g_atomic_int_get(&handle->app_handle->stopped) &&
						!g_atomic_int_get(&handle->destroyed))
					plugin->incoming_rtcp(handle->app_handle, &rtcp);
			}
		}
		return;
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Not RTP and not RTCP... may these be data channels?\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(pc->dtls, buf, len);
		/* Update stats (only overall data received) */
		if(len > 0) {
			pc->dtls_in_stats.info[0].packets++;
			pc->dtls_in_stats.info[0].bytes += len;
		}
		return;
	}
}

void janus_ice_incoming_data(janus_ice_handle *handle, char *label, char *protocol, gboolean textdata, char *buffer, int length) {
	if(handle == NULL || buffer == NULL || length <= 0)
		return;
	janus_plugin_data data = { .label = label, .protocol = protocol, .binary = !textdata, .buffer = buffer, .length = length };
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin && plugin->incoming_data && handle->app_handle &&
			!g_atomic_int_get(&handle->app_handle->stopped) &&
			!g_atomic_int_get(&handle->destroyed))
		plugin->incoming_data(handle->app_handle, &data);
}


/* Helper: encoding local candidates to string/SDP */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate, gboolean force_private, guint public_ip_index) {
	if(!handle || !handle->agent || !c || !buffer || buflen < 1)
		return -1;
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc)
		return -2;
	char *host_ip = NULL;
	gboolean ipv6 = (nice_address_ip_version(&c->addr) == 6);
	if(nat_1_1_enabled && !force_private) {
		/* A 1:1 NAT mapping was specified, either overwrite all the host addresses with the public IP, or add new candidates */
		host_ip = janus_get_public_ip(public_ip_index);
		gboolean host_ip_v6 = (strchr(host_ip, ':') != NULL);
		if(host_ip_v6 != ipv6) {
			/* nat-1-1 address and candidate are not the same address family, don't do anything */
			buffer[0] = '\0';
			return 0;
		}
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
		pc->local_candidates = g_slist_append(pc->local_candidates, g_strdup(buffer));
		/* Notify event handlers */
		if(janus_events_is_enabled()) {
			janus_session *session = (janus_session *)handle->session;
			json_t *info = json_object();
			json_object_set_new(info, "local-candidate", json_string(buffer));
			json_object_set_new(info, "stream_id", json_integer(pc->stream_id));
			json_object_set_new(info, "component_id", json_integer(pc->component_id));
			janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_LCAND,
				session->session_id, handle->handle_id, handle->opaque_id, info);
		}
	}
	return 0;
}

void janus_ice_candidates_to_sdp(janus_ice_handle *handle, janus_sdp_mline *mline, guint stream_id, guint component_id) {
	if(!handle || !handle->agent || !mline)
		return;
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	NiceAgent *agent = handle->agent;
	/* Iterate on all */
	gchar buffer[200];
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	gboolean log_candidates = (pc->local_candidates == NULL);
	for(i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		gboolean ipv6 = (nice_address_ip_version(&c->addr) == 6);
		gboolean same_family = (!ipv6 && janus_has_public_ipv4_ip()) || (ipv6 && janus_has_public_ipv6_ip());
		guint public_ip_index = 0;
		do {
			if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), log_candidates, FALSE, public_ip_index) == 0) {
				/* Candidate encoded, add to the SDP (but only if it's not a 'prflx') */
				if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
				} else {
					if(strlen(buffer) > 0) {
						janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
						mline->attributes = g_list_append(mline->attributes, a);
					}
					if(nat_1_1_enabled && public_ip_index == 0 && (keep_private_host || !same_family) &&
							janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), log_candidates, TRUE, public_ip_index) == 0) {
						/* Candidate with private host encoded, add to the SDP (but only if it's not a 'prflx') */
						if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
						} else if(strlen(buffer) > 0) {
							janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
							mline->attributes = g_list_append(mline->attributes, a);
						}
					}
				}
			}
			public_ip_index++;
			if(!same_family) {
				/* We don't have any nat-1-1 address of the same family as this candidate, we're done */
				break;
			}
		} while (public_ip_index < janus_get_public_ip_count());
		nice_candidate_free(c);
	}
	/* Done */
	g_slist_free(candidates);
}

void janus_ice_add_remote_candidate(janus_ice_handle *handle, NiceCandidate *c) {
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Queueing candidate %p\n", handle->handle_id, c);
	if(handle->queued_candidates != NULL)
		g_async_queue_push(handle->queued_candidates, c);
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_add_candidates);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_add_candidates);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
}

void janus_ice_setup_remote_candidates(janus_ice_handle *handle, guint stream_id, guint component_id) {
	if(!handle || !handle->agent)
		return;
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc || pc->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such stream %d: cannot setup remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	if(pc->process_started) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component %d in stream %d has already been set up\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(!pc->candidates || !pc->candidates->data) {
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)
				|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No remote candidates for component %d in stream %d: was the remote SDP parsed?\n", handle->handle_id, component_id, stream_id);
		}
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ## Setting remote candidates: stream %d, component %d (%u in the list)\n",
		handle->handle_id, stream_id, component_id, g_slist_length(pc->candidates));
	/* Add all candidates */
	NiceCandidate *c = NULL;
	GSList *gsc = pc->candidates;
	while(gsc) {
		c = (NiceCandidate *) gsc->data;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Queueing candidate %p (startup)\n", handle->handle_id, c);
		if(handle->queued_candidates != NULL)
			g_async_queue_push(handle->queued_candidates, c);
		gsc = gsc->next;
	}
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_add_candidates);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_add_candidates);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
	pc->process_started = TRUE;
}

int janus_ice_setup_local(janus_ice_handle *handle, gboolean offer, gboolean trickle, janus_dtls_role dtls_role) {
	if(!handle || g_atomic_int_get(&handle->destroyed))
		return -1;
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT)) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Agent already exists?\n", handle->handle_id);
		return -2;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting ICE locally: got %s\n", handle->handle_id, offer ? "OFFER" : "ANSWER");
	g_atomic_int_set(&handle->closepc, 0);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);

	/* Note: in case this is not an OFFER, we don't know whether ICE trickling is supported on the other side or not yet */
	if(offer && trickle) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED);

	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice */
	handle->controlling = janus_ice_lite_enabled ? FALSE : !offer;
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Creating ICE agent (ICE %s mode, %s)\n", handle->handle_id,
		janus_ice_lite_enabled ? "Lite" : "Full", handle->controlling ? "controlling" : "controlled");
	handle->agent = g_object_new(NICE_TYPE_AGENT,
		"compatibility", NICE_COMPATIBILITY_RFC5245,
		"main-context", handle->mainctx,
		"reliable", FALSE,
		"full-mode", janus_ice_lite_enabled ? FALSE : TRUE,
#ifdef HAVE_ICE_NOMINATION
		"nomination-mode", janus_ice_nomination,
#endif
#ifdef HAVE_CONSENT_FRESHNESS
		"consent-freshness", janus_ice_consent_freshness ? TRUE : FALSE,
#endif
		"keepalive-conncheck", janus_ice_keepalive_connchecks ? TRUE : FALSE,
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
#ifdef HAVE_TURNRESTAPI
	/* When using the TURN REST API, we use the handle's opaque_id as a username
	 * by default, and fall back to the session_id when it's missing. Refer to this
	 * issue for more context: https://github.com/meetecho/janus-gateway/issues/2199 */
	char turnrest_username[20];
	if(handle->opaque_id == NULL) {
		janus_session *session = (janus_session *)handle->session;
		g_snprintf(turnrest_username, sizeof(turnrest_username), "%"SCNu64, session->session_id);
	}
	janus_turnrest_response *turnrest_credentials = janus_turnrest_request((const char *)(handle->opaque_id ?
		handle->opaque_id : turnrest_username));
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
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error getting list of interfaces... %d (%s)\n",
			handle->handle_id, errno, g_strerror(errno));
	} else {
		for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
			if(ifa->ifa_addr == NULL)
				continue;
			/* Skip interfaces which are not up and running */
			if(!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
				continue;
			/* Skip loopback interfaces */
			if(ifa->ifa_flags & IFF_LOOPBACK)
				continue;
			family = ifa->ifa_addr->sa_family;
			if(family != AF_INET && family != AF_INET6)
				continue;
			/* We only add IPv6 addresses if support for them has been explicitly enabled */
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
			/* Skip 0.0.0.0, :: and, unless otherwise configured, local scoped addresses  */
			if(!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || (!janus_ipv6_linklocal_enabled && !strncmp(host, "fe80:", 5)))
				continue;
			/* Check if this IP address is in the ignore/enforce list: the enforce list has the precedence but the ignore list can then discard candidates */
			if(janus_ice_enforce_list != NULL) {
				if(ifa->ifa_name != NULL && !janus_ice_is_enforced(ifa->ifa_name) && !janus_ice_is_enforced(host))
					continue;
			}
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
	handle->stream_id = 0;
	/* Now create a ICE stream for all the media we'll handle */
	handle->stream_id = nice_agent_add_stream(handle->agent, 1);
	if(dscp_ef > 0) {
		/* A DSCP value was configured, shift it and pass it to libnice as a TOS */
		nice_agent_set_stream_tos(handle->agent, handle->stream_id, dscp_ef << 2);
	}
	/* Create the PeerConnection object */
	janus_ice_peerconnection *pc = g_malloc0(sizeof(janus_ice_peerconnection));
	janus_refcount_init(&pc->ref, janus_ice_peerconnection_free);
	janus_refcount_increase(&handle->ref);
	pc->stream_id = handle->stream_id;
	pc->handle = handle;
	pc->dtls_role = dtls_role;
	janus_mutex_init(&pc->mutex);
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
#ifdef HAVE_TURNRESTAPI
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
	handle->pc = pc;
	/* Create the media instances we need */
	pc->media = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_ice_peerconnection_medium_destroy);
	pc->media_byssrc = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_ice_peerconnection_medium_dereference);
	pc->media_bymid = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_ice_peerconnection_medium_dereference);
	pc->media_bytype = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_ice_peerconnection_medium_dereference);
#ifdef HAVE_PORTRANGE
	/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
	nice_agent_set_port_range(handle->agent, handle->stream_id, 1, rtp_range_min, rtp_range_max);
#endif
	/* Gather now only if we're doing hanf-trickle */
	if(!janus_full_trickle_enabled && !nice_agent_gather_candidates(handle->agent, handle->stream_id)) {
#ifdef HAVE_TURNRESTAPI
		if(turnrest_credentials != NULL) {
			janus_turnrest_response_destroy(turnrest_credentials);
			turnrest_credentials = NULL;
		}
#endif
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates...\n", handle->handle_id);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_ice_webrtc_hangup(handle, "Gathering error");
		return -1;
	}
	nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->mainloop),
		janus_ice_cb_nice_recv, pc);
#ifdef HAVE_TURNRESTAPI
	if(turnrest_credentials != NULL) {
		janus_turnrest_response_destroy(turnrest_credentials);
		turnrest_credentials = NULL;
	}
#endif
	/* Create DTLS-SRTP context, at last */
	pc->dtls = janus_dtls_srtp_create(pc, pc->dtls_role);
	if(!pc->dtls) {
		/* FIXME We should clear some resources... */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error creating DTLS-SRTP stack...\n", handle->handle_id);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_ice_webrtc_hangup(handle, "DTLS-SRTP stack error");
		return -1;
	}
	janus_refcount_increase(&pc->dtls->ref);
	/* If we're doing full-tricke, start gathering asynchronously */
	if(janus_full_trickle_enabled) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_start_gathering);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_start_gathering);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
	return 0;
}

void janus_ice_restart(janus_ice_handle *handle) {
	if(!handle || !handle->agent || !handle->pc)
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
	janus_ice_peerconnection *pc = handle->pc;
	if(!pc)
		return;
	NiceAgent *agent = handle->agent;
	/* Iterate on all existing local candidates */
	gchar buffer[200];
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, pc->stream_id, pc->component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n",
		handle->handle_id, g_slist_length(candidates), pc->stream_id, pc->component_id);
	for(i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
			nice_candidate_free(c);
			continue;
		}

		guint public_ip_index = 0;
		do {
			if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), FALSE, FALSE, public_ip_index) == 0) {
				/* Candidate encoded, send a "trickle" event to the browser */
				janus_ice_notify_trickle(handle, buffer);
				/* If nat-1-1 is enabled but we want to keep the private host, add another candidate */
				if(nat_1_1_enabled && keep_private_host && public_ip_index == 0 &&
						janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), FALSE, TRUE, public_ip_index) == 0) {
					/* Candidate encoded, send a "trickle" event to the browser */
					janus_ice_notify_trickle(handle, buffer);
				}
			}
			public_ip_index++;
		} while (public_ip_index < janus_get_public_ip_count());
		nice_candidate_free(c);
	}
	/* Send a "completed" trickle at the end */
	janus_ice_notify_trickle(handle, NULL);
}

static void janus_ice_rtp_extension_update(janus_ice_handle *handle, janus_ice_peerconnection_medium *medium, janus_ice_queued_packet *packet) {
	if(handle == NULL || handle->pc == NULL || medium == NULL || packet == NULL || packet->data == NULL)
		return;
	uint16_t totlen = RTP_HEADER_SIZE;
	/* Check how large the payload is */
	int plen = 0;
	char *payload = janus_rtp_payload(packet->data, packet->length, &plen);
	if(payload != NULL)
		totlen += plen;
	/* We need to strip extensions, here, and add those that need to be there manually */
	uint16_t extlen = 0;
	char extensions[320];
	uint16_t extbufsize = sizeof(extensions);
	janus_rtp_header *header = (janus_rtp_header *)packet->data;
	header->extension = 0;
	/* Add core and plugin extensions, if any */
	gboolean video = (packet->type == JANUS_ICE_PACKET_VIDEO);
	if(handle->pc->mid_ext_id > 0 || (video && handle->pc->abs_send_time_ext_id > 0) ||
			(video && handle->pc->transport_wide_cc_ext_id > 0) ||
			(!video && packet->extensions.audio_level > -1 && handle->pc->audiolevel_ext_id > 0) ||
			(video && packet->extensions.video_rotation > -1 && handle->pc->videoorientation_ext_id > 0) ||
			(video && packet->extensions.min_delay > -1 && packet->extensions.max_delay > -1 && handle->pc->playoutdelay_ext_id > 0) ||
			(video && packet->extensions.dd_len > 0 && handle->pc->dependencydesc_ext_id > 0) ||
			(packet->extensions.abs_capture_ts > 0 && handle->pc->abs_capture_time_ext_id > 0)) {
		/* Do we need 2-byte extemsions, or are 1-byte extensions fine? */
		gboolean use_2byte = (video && packet->extensions.dd_len > 16 && handle->pc->dependencydesc_ext_id > 0);
		/* Write the extension(s) */
		header->extension = 1;
		memset(extensions, 0, sizeof(extensions));
		janus_rtp_header_extension *extheader = (janus_rtp_header_extension *)extensions;
		extheader->type = htons(use_2byte ? 0x1000 : 0xBEDE);
		extheader->length = 0;
		/* Iterate on all extensions we need */
		char *index = extensions + 4;
		extbufsize -= 4;
		/* Check if we need to add the abs-send-time extension */
		if(video && handle->pc->abs_send_time_ext_id > 0) {
			int64_t now = (((janus_get_monotonic_time()/1000) << 18) + 500) / 1000;
			uint32_t abs_ts = (uint32_t)now & 0x00FFFFFF;
			uint32_t abs24 = htonl(abs_ts) >> 8;
			if(!use_2byte) {
				*index = (handle->pc->abs_send_time_ext_id << 4) + 2;
				memcpy(index+1, &abs24, 3);
				index += 4;
				extlen += 4;
				extbufsize -= 4;
			} else {
				*index = handle->pc->abs_send_time_ext_id;
				*(index+1) = 3;
				memcpy(index+2, &abs24, 3);
				index += 5;
				extlen += 5;
				extbufsize -= 5;
			}
		}
		/* Check if we need to add the transport-wide CC extension */
		if(video && handle->pc->transport_wide_cc_ext_id > 0) {
			handle->pc->transport_wide_cc_out_seq_num++;
			uint16_t transSeqNum = htons(handle->pc->transport_wide_cc_out_seq_num);
			if(!use_2byte) {
				*index = (handle->pc->transport_wide_cc_ext_id << 4) + 1;
				memcpy(index+1, &transSeqNum, 2);
				index += 3;
				extlen += 3;
				extbufsize -= 3;
			} else {
				*index = handle->pc->transport_wide_cc_ext_id;
				*(index+1) = 2;
				memcpy(index+2, &transSeqNum, 2);
				index += 4;
				extlen += 4;
				extbufsize -= 4;
			}
		}
		/* Check if the plugin (or source) included other extensions */
		if(!video && packet->extensions.audio_level > -1 && handle->pc->audiolevel_ext_id > 0) {
			/* Add audio-level extension */
			if(!use_2byte) {
				*index = (handle->pc->audiolevel_ext_id << 4);
				*(index+1) = (packet->extensions.audio_level_vad << 7) + (packet->extensions.audio_level & 0x7F);
				index += 2;
				extlen += 2;
				extbufsize -= 2;
			} else {
				*index = handle->pc->audiolevel_ext_id;
				*(index+1) = 1;
				*(index+2) = (packet->extensions.audio_level_vad << 7) + (packet->extensions.audio_level & 0x7F);
				index += 3;
				extlen += 3;
				extbufsize -= 3;
			}
		}
		if(video && packet->extensions.video_rotation > -1 && handle->pc->videoorientation_ext_id > 0) {
			/* Add video-orientation extension */
			gboolean c = (packet->extensions.video_back_camera == TRUE),
				f = (packet->extensions.video_flipped == TRUE), r1 = FALSE, r0 = FALSE;
			switch(packet->extensions.video_rotation) {
				case 270:
					r1 = TRUE;
					r0 = TRUE;
					break;
				case 180:
					r1 = TRUE;
					r0 = FALSE;
					break;
				case 90:
					r1 = FALSE;
					r0 = TRUE;
					break;
				case 0:
				default:
					r1 = FALSE;
					r0 = FALSE;
					break;
			}
			if(!use_2byte) {
				*index = (handle->pc->videoorientation_ext_id << 4);
				*(index+1) = (c<<3) + (f<<2) + (r1<<1) + r0;
				index += 2;
				extlen += 2;
				extbufsize -= 2;
			} else {
				*index = handle->pc->videoorientation_ext_id;
				*(index+1) = 1;
				*(index+2) = (c<<3) + (f<<2) + (r1<<1) + r0;
				index += 3;
				extlen += 3;
				extbufsize -= 3;
			}
		}
		if(video && packet->extensions.min_delay > -1 && packet->extensions.max_delay > -1 && handle->pc->playoutdelay_ext_id > 0) {
			/* Add playout-delay extension */
			uint32_t min_delay = (uint32_t)packet->extensions.min_delay;
			uint32_t max_delay = (uint32_t)packet->extensions.max_delay;
			uint32_t pd = ((min_delay << 12) & 0x00FFF000) + (max_delay & 0x00000FFF);
			uint32_t pd24 = htonl(pd) >> 8;
			if(!use_2byte) {
				*index = (handle->pc->playoutdelay_ext_id << 4) + 2;
				memcpy(index+1, &pd24, 3);
				index += 4;
				extlen += 4;
				extbufsize -= 4;
			} else {
				*index = handle->pc->playoutdelay_ext_id;
				*(index+1) = 3;
				memcpy(index+2, &pd24, 3);
				index += 5;
				extlen += 5;
				extbufsize -= 5;
			}
		}
		/* Check if we need to add the mid extension */
		if(handle->pc->mid_ext_id > 0) {
			char *mid = medium->mid;
			if(mid != NULL) {
				if(!use_2byte) {
					size_t midlen = strlen(mid) & 0x0F;
					if(extbufsize < (midlen + 1)) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Not enough room for mid extension, skipping it...\n", handle->handle_id);
					} else {
						*index = (handle->pc->mid_ext_id << 4) + (midlen ? midlen-1 : 0);
						memcpy(index+1, mid, midlen);
						index += (midlen + 1);
						extlen += (midlen + 1);
						extbufsize -= (midlen + 1);
					}
				} else {
					size_t midlen = strlen(mid);
					if(midlen > 16) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] mid too large, capping to first 16 characters...\n", handle->handle_id);
						midlen = 16;
					} else if(extbufsize < (midlen + 2)) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Not enough room for mid extension, skipping it...\n", handle->handle_id);
					} else {
						*index = handle->pc->mid_ext_id;
						*(index+1) = midlen;
						memcpy(index+2, mid, midlen);
						index += (midlen + 2);
						extlen += (midlen + 2);
						extbufsize -= (midlen + 2);
					}
				}
			}
		}
		if(video && packet->extensions.dd_len > 0 && handle->pc->dependencydesc_ext_id > 0) {
			/* Add dependency descriptor extension */
			if(extbufsize < (packet->extensions.dd_len + (use_2byte ? 2 : 1))) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Not enough room for dependency-descriptor extension, skipping it...\n", handle->handle_id);
			} else {
				if(!use_2byte) {
					*index = (handle->pc->dependencydesc_ext_id << 4) + (packet->extensions.dd_len-1);
					index++;
					memcpy(index, packet->extensions.dd_content, packet->extensions.dd_len);
					index += packet->extensions.dd_len;
					extlen += packet->extensions.dd_len + 1;
					extbufsize -= packet->extensions.dd_len + 1;
				} else {
					*index = handle->pc->dependencydesc_ext_id;
					*(index+1) = packet->extensions.dd_len;
					memcpy(index+2, packet->extensions.dd_content, packet->extensions.dd_len);
					index += packet->extensions.dd_len + 2;
					extlen += packet->extensions.dd_len + 2;
					extbufsize -= packet->extensions.dd_len + 2;
				}
			}
		}
		/* Check if we need to add the abs-capture-time extension */
		if(packet->extensions.abs_capture_ts > 0 && handle->pc->abs_capture_time_ext_id > 0) {
			uint64_t abs64 = htonll(packet->extensions.abs_capture_ts);
			if(!use_2byte) {
				*index = (handle->pc->abs_capture_time_ext_id << 4) + 7;
				memcpy(index+1, &abs64, 8);
				index += 9;
				extlen += 9;
				extbufsize -= 9;
			} else {
				*index = handle->pc->abs_capture_time_ext_id;
				*(index+1) = 8;
				memcpy(index+2, &abs64, 8);
				index += 10;
				extlen += 10;
				extbufsize -= 10;
			}
		}
		/* Calculate the whole length */
		uint16_t words = extlen/4;
		if(extlen%4 != 0)
			words++;
		extheader->length = htons(words);
		/* Update lengths (taking into account the RFC5285 header) */
		extlen = 4 + (words*4);
		totlen += extlen;
	}
	/* Check if we need to resize this packet buffer first */
	uint16_t payload_start = payload ? (payload - packet->data) : 0;
	if(packet->length < totlen)
		packet->data = g_realloc(packet->data, totlen + SRTP_MAX_TAG_LEN);
	/* Now check if we need to move the payload */
	payload = payload_start ? (packet->data + payload_start) : NULL;
	if(payload != NULL && plen > 0 && packet->length != totlen)
		memmove(packet->data + RTP_HEADER_SIZE + extlen, payload, plen);
	/* Finally, copy RTP extensions, if any */
	if(extlen > 0) {
		/* Copy the extensions after the RTP header */
		memcpy(packet->data + RTP_HEADER_SIZE, extensions, extlen);
	}
	packet->length = totlen;
}

static gint rtcp_transport_wide_cc_stats_comparator(gconstpointer item1, gconstpointer item2) {
	return ((rtcp_transport_wide_cc_stats*)item1)->transport_seq_num - ((rtcp_transport_wide_cc_stats*)item2)->transport_seq_num;
}
static gboolean janus_ice_outgoing_transport_wide_cc_feedback(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	janus_ice_peerconnection *pc = handle->pc;

	guint32 ssrc_peer = 0;
	janus_ice_peerconnection_medium *medium = NULL;
	if(pc) {
		/* Find inbound video medium */
		janus_mutex_lock(&handle->mutex);
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, pc->media_bymid);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_ice_peerconnection_medium *m = value;
			if(m && m->type == JANUS_MEDIA_VIDEO && m->recv) {
				/* If a medium (or simulcast layer, if applicable) has not received data, its SSRC may be unknown. */
				/* Pick the first valid SSRC we find across all considered mediums */
				int i = 0;
				for(i = 0; i < 3; i++) {
					if(m->ssrc_peer[i] != 0) {
						ssrc_peer = m->ssrc_peer[i];
						medium = m;
						break;
					}
				}

				/* Stop if we found a valid SSRC/medium to use */
				if(medium && ssrc_peer)
					break;
			}
		}
		janus_mutex_unlock(&handle->mutex);
	}

	if(medium == NULL) {
		JANUS_LOG(LOG_HUGE, "No medium with a valid peer SSRC found for transport-wide CC feedback\n");
		return G_SOURCE_CONTINUE;
	}

	if(pc && pc->do_transport_wide_cc) {
		/* Create a transport wide feedback message */
		size_t size = 1300;
		char rtcpbuf[1300];
		/* Order packet list */
		pc->transport_wide_received_seq_nums = g_slist_sort(pc->transport_wide_received_seq_nums,
			rtcp_transport_wide_cc_stats_comparator);
		/* Create full stats queue */
		GQueue *packets = g_queue_new();
		/* For all packets */
		GSList *it = NULL;
		for(it = pc->transport_wide_received_seq_nums; it; it = it->next) {
			/* Get stat */
			janus_rtcp_transport_wide_cc_stats *stats = (janus_rtcp_transport_wide_cc_stats *)it->data;
			/* Get transport seq */
			guint32 transport_seq_num = stats->transport_seq_num;
			/* Check if it is an out of order  */
			if(transport_seq_num < pc->transport_wide_cc_last_feedback_seq_num) {
				/* Skip, it was already reported as lost */
				g_free(stats);
				continue;
			}
			/* If not first */
			if(pc->transport_wide_cc_last_feedback_seq_num) {
				/* For each lost */
				guint32 i = 0;
				for(i = pc->transport_wide_cc_last_feedback_seq_num+1; i<transport_seq_num; ++i) {
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
			pc->transport_wide_cc_last_feedback_seq_num = transport_seq_num;
			/* Add this one */
			g_queue_push_tail(packets, stats);
		}
		/* Free and reset stats list */
		g_slist_free(pc->transport_wide_received_seq_nums);
		pc->transport_wide_received_seq_nums = NULL;
		/* Create and enqueue RTCP packets */
		guint packets_len = 0;
		while((packets_len = g_queue_get_length(packets)) > 0) {
			GQueue *packets_to_process;
			/* If we have more than 400 packets to acknowledge, let's send more than one message */
			if(packets_len > 400) {
				/* Split the queue into two */
				GList *new_head = g_queue_peek_nth_link(packets, 400);
				GList *new_tail = new_head->prev;
				new_head->prev = NULL;
				new_tail->next = NULL;
				packets_to_process = g_queue_new();
				packets_to_process->head = packets->head;
				packets_to_process->tail = new_tail;
				packets_to_process->length = 400;
				packets->head = new_head;
				/* packets->tail is unchanged */
				packets->length = packets_len - 400;
			} else {
				packets_to_process = packets;
			}
			/* Get feedback packet count and increase it for next one */
			guint8 feedback_packet_count = pc->transport_wide_cc_feedback_count++;
			/* Create RTCP packet */
			int len = janus_rtcp_transport_wide_cc_feedback(rtcpbuf, size,
				medium->ssrc, ssrc_peer, feedback_packet_count, packets_to_process);
			/* Enqueue it, we'll send it later */
			if(len > 0) {
				janus_plugin_rtcp rtcp = { .mindex = medium->mindex, .video = TRUE, .buffer = rtcpbuf, .length = len };
				janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
			}
			if(packets_to_process != packets) {
				g_queue_free(packets_to_process);
			}
		}
		/* Free mem */
		g_queue_free(packets);
	}
	return G_SOURCE_CONTINUE;
}

static gboolean janus_ice_outgoing_rtcp_handle(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	janus_ice_peerconnection *pc = handle->pc;
	/* Iterate on all media */
	janus_ice_peerconnection_medium *medium = NULL;
	uint mi=0;
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		if(!medium || (medium->type != JANUS_MEDIA_AUDIO && medium->type != JANUS_MEDIA_VIDEO))
			continue;
		if(medium->out_stats.info[0].packets > 0) {
			/* Create a SR/SDES compound */
			int srlen = 28;
			int sdeslen = 16;
			char rtcpbuf[sizeof(janus_rtcp_sr)+sdeslen];
			memset(rtcpbuf, 0, sizeof(rtcpbuf));
			rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
			sr->header.version = 2;
			sr->header.type = RTCP_SR;
			sr->header.rc = 0;
			sr->header.length = htons((srlen/4)-1);
			sr->ssrc = htonl(medium->ssrc);
			struct timeval tv;
			gettimeofday(&tv, NULL);
			uint32_t s = tv.tv_sec + 2208988800u;
			uint32_t u = tv.tv_usec;
			uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
			sr->si.ntp_ts_msw = htonl(s);
			sr->si.ntp_ts_lsw = htonl(f);
			/* Compute an RTP timestamp coherent with the NTP one */
			rtcp_context *rtcp_ctx = medium->rtcp_ctx[0];
			if(rtcp_ctx == NULL) {
				sr->si.rtp_ts = htonl(medium->last_rtp_ts);	/* FIXME */
			} else {
				int64_t ntp = ((int64_t)tv.tv_sec)*G_USEC_PER_SEC + tv.tv_usec;
				uint32_t rtp_ts = ((ntp-medium->last_ntp_ts)*(rtcp_ctx->tb))/1000000 + medium->last_rtp_ts;
				sr->si.rtp_ts = htonl(rtp_ts);
			}
			sr->si.s_packets = htonl(medium->out_stats.info[0].packets);
			sr->si.s_octets = htonl(medium->out_stats.info[0].bytes);
			rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[srlen];
			janus_rtcp_sdes_cname((char *)sdes, sdeslen, "janus", 5);
			sdes->chunk.ssrc = htonl(medium->ssrc);
			/* Enqueue it, we'll send it later */
			janus_plugin_rtcp rtcp = { .mindex = medium->mindex,
				.video = (medium->type == JANUS_MEDIA_VIDEO), .buffer = rtcpbuf, .length = srlen+sdeslen };
			janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
			/* Check if we detected too many losses, and send a slowlink event in case */
			gint lost = janus_rtcp_context_get_lost_all(rtcp_ctx, TRUE);
			lost = lost > 0 ? lost : 0;
			janus_slow_link_update(medium, handle, TRUE, lost);
		}
		if(medium->recv) {
			/* Create a RR too (for each SSRC, if we're simulcasting) */
			int vindex=0;
			for(vindex=0; vindex<3; vindex++) {
				if(medium->rtcp_ctx[vindex] && medium->rtcp_ctx[vindex]->rtp_recvd) {
					/* Create a RR */
					int rrlen = 32;
					char rtcpbuf[32];
					memset(rtcpbuf, 0, sizeof(rtcpbuf));
					rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
					rr->header.version = 2;
					rr->header.type = RTCP_RR;
					rr->header.rc = 1;
					rr->header.length = htons((rrlen/4)-1);
					rr->ssrc = htonl(medium->ssrc);
					janus_rtcp_report_block(medium->rtcp_ctx[vindex], &rr->rb[0]);
					rr->rb[0].ssrc = htonl(medium->ssrc_peer[vindex]);
					/* Enqueue it, we'll send it later */
					janus_plugin_rtcp rtcp = { .mindex = medium->mindex,
						.video = (medium->type == JANUS_MEDIA_VIDEO), .buffer = rtcpbuf, .length = 32 };
					janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
					if(vindex == 0) {
						/* Check if we detected too many losses, and send a slowlink event in case */
						gint lost = janus_rtcp_context_get_lost_all(medium->rtcp_ctx[vindex], FALSE);
						lost = lost > 0 ? lost : 0;
						janus_slow_link_update(medium, handle, FALSE, lost);
					}
				}
			}
		}
	}
	if(twcc_period == 1000) {
		/* The Transport Wide CC feedback period is 1s as well, send it here */
		janus_ice_outgoing_transport_wide_cc_feedback(handle);
	}
	return G_SOURCE_CONTINUE;
}

static gboolean janus_ice_outgoing_stats_handle(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	/* This callback is for stats and other things we need to do on a regular basis (typically called once per second) */
	janus_session *session = (janus_session *)handle->session;
	gint64 now = janus_get_monotonic_time();
	/* Reset the last second counters if too much time passed with no data in or out */
	janus_ice_peerconnection *pc = handle->pc;
	if(pc == NULL)
		return G_SOURCE_CONTINUE;
	/* Iterate on all media */
	handle->last_event_stats++;
	janus_ice_peerconnection_medium *medium = NULL;
	json_t *combined_event = NULL;
	uint mi=0;
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		if(!medium)
			continue;
		int vindex = 0;
		for(vindex=0; vindex < 3; vindex++) {
			if(vindex > 0 && (medium->type != JANUS_MEDIA_VIDEO || medium->rtcp_ctx[1] == NULL))
				continue;	/* We won't need simulcast checks */
			gint64 last = medium->in_stats.info[vindex].updated;
			if(last && now > last && now-last >= 2*G_USEC_PER_SEC && medium->in_stats.info[vindex].bytes_lastsec_temp > 0) {
				medium->in_stats.info[vindex].bytes_lastsec = 0;
				medium->in_stats.info[vindex].bytes_lastsec_temp = 0;
			}
			last = medium->out_stats.info[vindex].updated;
			if(last && now > last && now-last >= 2*G_USEC_PER_SEC && medium->out_stats.info[vindex].bytes_lastsec_temp > 0) {
				medium->out_stats.info[vindex].bytes_lastsec = 0;
				medium->out_stats.info[vindex].bytes_lastsec_temp = 0;
			}
			if(medium->type != JANUS_MEDIA_AUDIO && medium->type != JANUS_MEDIA_VIDEO)
				continue;
			/* Now let's see if we need to notify the user about no incoming audio or video */
			if(no_media_timer > 0 && pc->dtls && pc->dtls->dtls_connected > 0 && (now - pc->dtls->dtls_connected >= G_USEC_PER_SEC)) {
				gint64 last = medium->in_stats.info[vindex].updated;
				if(!medium->in_stats.info[vindex].notified_lastsec && last &&
						!medium->in_stats.info[vindex].bytes_lastsec && !medium->in_stats.info[vindex].bytes_lastsec_temp &&
							now - last >= (gint64)no_media_timer*G_USEC_PER_SEC) {
					/* We missed more than no_second_timer seconds of video! */
					medium->in_stats.info[vindex].notified_lastsec = TRUE;
					if(vindex == 0) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive %s for more than %u second(s)...\n",
							handle->handle_id, medium->type == JANUS_MEDIA_VIDEO ? "video" : "audio", no_media_timer);
					} else {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive %s (substream #%d) for more than %u second(s)...\n",
							handle->handle_id, medium->type == JANUS_MEDIA_VIDEO ? "video" : "audio", vindex, no_media_timer);
					}
					janus_ice_notify_media(handle, medium->mid, medium->type == JANUS_MEDIA_VIDEO, medium->rtcp_ctx[1] != NULL, vindex, FALSE);
				}
			}
		}
		/* We also send live stats to event handlers every tot-seconds (configurable) */
		if(janus_ice_event_stats_period > 0 && handle->last_event_stats >= janus_ice_event_stats_period) {
			if(janus_events_is_enabled()) {
				/* Check if we should send dedicated events per media, or one per peerConnection */
				if(janus_events_is_enabled() && janus_ice_event_get_combine_media_stats() && combined_event == NULL)
					combined_event = json_array();
				int vindex=0;
				for(vindex=0; vindex<3; vindex++) {
					if(medium && ((medium->type == JANUS_MEDIA_DATA && vindex == 0) || medium->rtcp_ctx[vindex])) {
						json_t *info = json_object();
						json_object_set_new(info, "mid", json_string(medium->mid));
						json_object_set_new(info, "mindex", json_integer(medium->mindex));
						if(vindex == 0)
							json_object_set_new(info, "media", json_string(janus_media_type_str(medium->type)));
						else if(vindex == 1)
							json_object_set_new(info, "media", json_string("video-sim1"));
						else
							json_object_set_new(info, "media", json_string("video-sim2"));
						if(medium->type == JANUS_MEDIA_AUDIO || medium->type == JANUS_MEDIA_VIDEO) {
							if(medium->codec)
								json_object_set_new(info, "codec", json_string(medium->codec));
							json_object_set_new(info, "base", json_integer(medium->rtcp_ctx[vindex]->tb));
							if(vindex == 0) {
								uint32_t rtt = janus_rtcp_context_get_rtt(medium->rtcp_ctx[vindex]);
								json_object_set_new(info, "rtt", json_integer(rtt));
								if(rtt > 0 && medium->rtcp_ctx[vindex]) {
									json_t *rtt_vals = json_object();
									json_object_set_new(rtt_vals, "ntp", json_integer(medium->rtcp_ctx[vindex]->rtt_ntp));
									json_object_set_new(rtt_vals, "lsr", json_integer(medium->rtcp_ctx[vindex]->rtt_lsr));
									json_object_set_new(rtt_vals, "dlsr", json_integer(medium->rtcp_ctx[vindex]->rtt_dlsr));
									json_object_set_new(info, "rtt-values", rtt_vals);
								}
							}
							json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(medium->rtcp_ctx[vindex], FALSE)));
							json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(medium->rtcp_ctx[vindex], TRUE)));
							json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(medium->rtcp_ctx[vindex], FALSE)));
							json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(medium->rtcp_ctx[vindex], TRUE)));
							json_object_set_new(info, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(medium->rtcp_ctx[vindex])));
							json_object_set_new(info, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(medium->rtcp_ctx[vindex])));
							json_object_set_new(info, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(medium->rtcp_ctx[vindex])));
							json_object_set_new(info, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(medium->rtcp_ctx[vindex])));
						}
						json_object_set_new(info, "packets-received", json_integer(medium->in_stats.info[vindex].packets));
						json_object_set_new(info, "packets-sent", json_integer(medium->out_stats.info[vindex].packets));
						json_object_set_new(info, "bytes-received", json_integer(medium->in_stats.info[vindex].bytes));
						json_object_set_new(info, "bytes-sent", json_integer(medium->out_stats.info[vindex].bytes));
						if(medium->type == JANUS_MEDIA_AUDIO || medium->type == JANUS_MEDIA_VIDEO) {
							json_object_set_new(info, "bytes-received-lastsec", json_integer(medium->in_stats.info[vindex].bytes_lastsec));
							json_object_set_new(info, "bytes-sent-lastsec", json_integer(medium->out_stats.info[vindex].bytes_lastsec));
							json_object_set_new(info, "nacks-received", json_integer(medium->in_stats.info[vindex].nacks));
							json_object_set_new(info, "nacks-sent", json_integer(medium->out_stats.info[vindex].nacks));
							json_object_set_new(info, "retransmissions-received", json_integer(medium->rtcp_ctx[vindex]->retransmitted));
						}
						if(medium->mindex == 0 && pc->remb_bitrate > 0)
							json_object_set_new(info, "remb-bitrate", json_integer(pc->remb_bitrate));
						if(combined_event != NULL) {
							json_array_append_new(combined_event, info);
						} else {
							janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATS,
								session->session_id, handle->handle_id, handle->opaque_id, info);
						}
					}
				}
			}
		}
	}
	if(combined_event != NULL) {
		janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATS,
			session->session_id, handle->handle_id, handle->opaque_id, combined_event);
	}
	/* Reset stats event counter */
	if(handle->last_event_stats >= janus_ice_event_stats_period)
		handle->last_event_stats = 0;
	/* Should we clean up old NACK buffers for any of the streams? */
	janus_cleanup_nack_buffer(now, handle->pc, TRUE, TRUE);
	/* Check if we should also print a summary of SRTP-related errors */
	handle->last_srtp_summary++;
	if(handle->last_srtp_summary == 0 || handle->last_srtp_summary == 2) {
		if(handle->srtp_errors_count > 0) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got %d SRTP/SRTCP errors in the last few seconds (last error: %s)\n",
				handle->handle_id, handle->srtp_errors_count, janus_srtp_error_str(handle->last_srtp_error));
			handle->srtp_errors_count = 0;
			handle->last_srtp_error = 0;
		}
		handle->last_srtp_summary = 0;
	}
	return G_SOURCE_CONTINUE;
}

static gboolean janus_ice_outgoing_traffic_handle(janus_ice_handle *handle, janus_ice_queued_packet *pkt) {
	janus_session *session = (janus_session *)handle->session;
	janus_ice_peerconnection *pc = handle->pc;
	janus_ice_peerconnection_medium *medium = NULL;
	if(pkt == &janus_ice_start_gathering) {
		/* Start gathering candidates */
		if(handle->agent == NULL) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] No ICE agent, not going to gather candidates...\n", handle->handle_id);
		} else if(!nice_agent_gather_candidates(handle->agent, handle->stream_id)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates...\n", handle->handle_id);
			janus_ice_webrtc_hangup(handle, "ICE gathering error");
		}
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_add_candidates) {
		/* There are remote candidates pending, add them now */
		GSList *candidates = NULL;
		NiceCandidate *c = NULL;
		while((c = g_async_queue_try_pop(handle->queued_candidates)) != NULL) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Processing candidate %p\n", handle->handle_id, c);
			if(c->priority > 0) {
				candidates = g_slist_append(candidates, c);
			} else {
				/* Workaround for https://gitlab.freedesktop.org/libnice/libnice/-/issues/181 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Candidate %p has priority 0, ignoring it\n", handle->handle_id, c);
			}
		}
		guint count = g_slist_length(candidates);
		if(pc != NULL && count > 0) {
			if(handle->agent_started == 0)
				handle->agent_started = janus_get_monotonic_time();
			int added = nice_agent_set_remote_candidates(handle->agent, pc->stream_id, pc->component_id, candidates);
			if(added < 0 || (guint)added != count) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Failed to add some remote candidates (added %u, expected %u)\n",
					handle->handle_id, added, count);
			} else {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] %d remote %s added\n", handle->handle_id,
					count, (count > 1 ? "candidates" : "candidate"));
			}
		}
		g_slist_free(candidates);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_dtls_handshake) {
		if(!janus_is_webrtc_encryption_enabled()) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] WebRTC encryption disabled, skipping DTLS handshake\n", handle->handle_id);
			janus_ice_dtls_handshake_done(handle);
			return G_SOURCE_CONTINUE;
		} else if(!pc) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] PeerConnection not initialized, aborting DTLS handshake\n", handle->handle_id);
			return G_SOURCE_CONTINUE;
		}
		/* Start the DTLS handshake */
		janus_dtls_srtp_handshake(pc->dtls);
		/* Create retransmission timer */
		pc->dtlsrt_source = g_timeout_source_new(50);
		g_source_set_callback(pc->dtlsrt_source, janus_dtls_retry, pc->dtls, NULL);
		guint id = g_source_attach(pc->dtlsrt_source, handle->mainctx);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_media_stopped) {
		/* Some media has been disabled on the way in, so use the callback to notify the peer */
		if(pc == NULL)
			return G_SOURCE_CONTINUE;
		uint mi=0;
		for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
			medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
			if(!medium || (medium->type != JANUS_MEDIA_AUDIO && medium->type != JANUS_MEDIA_VIDEO))
				continue;	/* We don't process data channels here */
			int vindex = 0;
			for(vindex=0; vindex < 3; vindex++) {
				if(vindex > 0 && (medium->type != JANUS_MEDIA_VIDEO || medium->rtcp_ctx[1] == NULL))
					continue;	/* We won't need simulcast checks */
				if(!medium->in_stats.info[vindex].notified_lastsec && medium->in_stats.info[vindex].bytes && !medium->recv) {
					/* This medium won't be received for a while, notify */
					medium->in_stats.info[vindex].notified_lastsec = TRUE;
					janus_ice_notify_media(handle, medium->mid, medium->type == JANUS_MEDIA_VIDEO, medium->rtcp_ctx[1] != NULL, vindex, FALSE);
				}
			}
		}
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_hangup_peerconnection) {
		/* The media session is over, send an alert on all streams and components */
		if(handle->pc && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
			janus_dtls_srtp_send_alert(handle->pc->dtls);
		}
		/* Notify the plugin about the fact this PeerConnection has just gone */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the hangup (%s)\n",
			handle->handle_id, plugin ? plugin->get_name() : "??");
		if(plugin != NULL && handle->app_handle != NULL) {
			plugin->hangup_media(handle->app_handle);
		}
		/* Get rid of the attached sources */
		if(handle->rtcp_source) {
			g_source_destroy(handle->rtcp_source);
			g_source_unref(handle->rtcp_source);
			handle->rtcp_source = NULL;
		}
		if(handle->twcc_source) {
			g_source_destroy(handle->twcc_source);
			g_source_unref(handle->twcc_source);
			handle->twcc_source = NULL;
		}
		if(handle->stats_source) {
			g_source_destroy(handle->stats_source);
			g_source_unref(handle->stats_source);
			handle->stats_source = NULL;
		}
		/* If event handlers are active, send stats one last time */
		if(janus_events_is_enabled()) {
			handle->last_event_stats = janus_ice_event_stats_period;
			(void)janus_ice_outgoing_stats_handle(handle);
		}
		janus_ice_webrtc_free(handle);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_detach_handle) {
		/* This handle has just been detached, notify the plugin */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the handle detach (%s)\n",
			handle->handle_id, plugin ? plugin->get_name() : "??");
		if(plugin != NULL && handle->app_handle != NULL) {
			int error = 0;
			plugin->destroy_session(handle->app_handle, &error);
		}
		handle->app_handle = NULL;
		/* TODO Get rid of the loop by removing the source */
		if(handle->rtp_source) {
			g_source_destroy(handle->rtp_source);
			g_source_unref(handle->rtp_source);
			handle->rtp_source = NULL;
		}
		/* Prepare JSON event to notify user/application */
		json_t *event = json_object();
		json_object_set_new(event, "janus", json_string("detached"));
		json_object_set_new(event, "session_id", json_integer(session->session_id));
		json_object_set_new(event, "sender", json_integer(handle->handle_id));
		if(opaqueid_in_api && handle->opaque_id != NULL)
			json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
		/* Send the event */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
		janus_session_notify_event(session, event);
		/* Notify event handlers as well */
		if(janus_events_is_enabled())
			janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE, JANUS_EVENT_SUBTYPE_NONE,
				session->session_id, handle->handle_id, "detached",
				plugin ? plugin->get_package() : NULL, handle->opaque_id, handle->token);
		return G_SOURCE_REMOVE;
	} else if(pkt == &janus_ice_data_ready) {
		/* Data is writable on this PeerConnection, notify the plugin */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin != NULL && plugin->data_ready != NULL && handle->app_handle != NULL) {
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Telling the plugin about the data channel being ready (%s)\n",
				handle->handle_id, plugin ? plugin->get_name() : "??");
			plugin->data_ready(handle->app_handle);
		}
	}
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	/* Now let's get on with the packet */
	if(pkt == NULL)
		return G_SOURCE_CONTINUE;
	if(pkt->data == NULL || pc == NULL) {
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	gint64 age = (janus_get_monotonic_time() - pkt->added);
	if(age > G_USEC_PER_SEC) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Discarding too old outgoing packet (age=%"SCNi64"us)\n", handle->handle_id, age);
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	if(!pc->cdone) {
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !pc->noerrorlog) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No candidates not gathered yet for stream??\n", handle->handle_id);
			pc->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
		}
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	/* Find the right medium instance */
	if(pkt->mindex != -1) {
		medium = g_hash_table_lookup(pc->media, GINT_TO_POINTER(pkt->mindex));
	} else {
		janus_media_type mtype = janus_media_type_from_packet(pkt->type);
		medium = g_hash_table_lookup(pc->media_bytype, GINT_TO_POINTER(mtype));
	}
	if(medium == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No medium #%d associated to this packet??\n", handle->handle_id, pkt->mindex);
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	if(pkt->control) {
		/* RTCP */
		int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
		pc->noerrorlog = FALSE;
		if(janus_is_webrtc_encryption_enabled() && (!pc->dtls || !pc->dtls->srtp_valid || !pc->dtls->srtp_out)) {
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !pc->noerrorlog) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] %s stream (#%u) component has no valid SRTP session (yet?)\n",
					handle->handle_id, video ? "video" : "audio", pc->stream_id);
				medium->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
			}
			janus_ice_free_queued_packet(pkt);
			return G_SOURCE_CONTINUE;
		}
		medium->noerrorlog = FALSE;
		if(pkt->encrypted) {
			/* Already SRTCP */
			int sent = nice_agent_send(handle->agent, pc->stream_id, pc->component_id, pkt->length, (const gchar *)pkt->data);
			if(sent < pkt->length) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
			}
		} else {
			/* Check if there's anything we need to do before sending */
			if(pkt->control_ext) {
				/* Fix all SSRCs before enqueueing, as we need to use the ones for this media
				 * leg. Note that this is only needed for RTCP packets coming from plugins: the
				 * ones created by the core already have the right SSRCs in the right place */
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
					medium->ssrc, medium->ssrc_peer[0]);
				janus_rtcp_fix_ssrc(NULL, pkt->data, pkt->length, 1,
					medium->ssrc, medium->ssrc_peer[0]);
				/* If this is a PLI and we're simulcasting, send a PLI on other layers as well */
				if(video && janus_rtcp_has_pli(pkt->data, pkt->length)) {
					if(medium->ssrc_peer[1]) {
						char plibuf[12];
						memset(plibuf, 0, 12);
						janus_rtcp_pli((char *)&plibuf, 12);
						janus_rtcp_fix_ssrc(NULL, plibuf, sizeof(plibuf), 1,
							medium->ssrc, medium->ssrc_peer[1]);
						janus_plugin_rtcp rtcp = { .mindex = medium->mindex, .video = TRUE, .buffer = plibuf, .length = sizeof(plibuf) };
						janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
					}
					if(medium->ssrc_peer[2]) {
						char plibuf[12];
						memset(plibuf, 0, 12);
						janus_rtcp_pli((char *)&plibuf, 12);
						janus_rtcp_fix_ssrc(NULL, plibuf, sizeof(plibuf), 1,
							medium->ssrc, medium->ssrc_peer[2]);
						janus_plugin_rtcp rtcp = { .mindex = medium->mindex, .video = TRUE, .buffer = plibuf, .length = sizeof(plibuf) };
						janus_ice_relay_rtcp_internal(handle, medium, &rtcp, FALSE);
					}
				}
			}
			uint32_t bitrate = janus_rtcp_get_remb(pkt->data, pkt->length);
			if(bitrate > 0) {
				/* There's a REMB, prepend a RR as it won't work otherwise */
				int rrlen = 8;
				char *rtcpbuf = g_malloc0(rrlen+pkt->length+SRTP_MAX_TAG_LEN+4);
				rtcp_rr *rr = (rtcp_rr *)rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 0;
				rr->header.length = htons((rrlen/4)-1);
				/* Append REMB */
				memcpy(rtcpbuf+rrlen, pkt->data, pkt->length);
				/* If we're simulcasting, set the extra SSRCs (the first one will be set by janus_rtcp_fix_ssrc) */
				if(medium->ssrc_peer[1] && pkt->length >= 28) {
					rtcp_fb *rtcpfb = (rtcp_fb *)(rtcpbuf+rrlen);
					rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
					remb->ssrc[1] = htonl(medium->ssrc_peer[1]);
					if(medium->ssrc_peer[2] && pkt->length >= 32) {
						remb->ssrc[2] = htonl(medium->ssrc_peer[2]);
					}
				}
				/* Free old packet and update */
				char *prev_data = pkt->data;
				pkt->data = rtcpbuf;
				pkt->length = rrlen+pkt->length;
				g_clear_pointer(&prev_data, g_free);
			}
			/* Do we need to dump this packet for debugging? */
			if(g_atomic_int_get(&handle->dump_packets))
				janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, FALSE, pkt->data, pkt->length,
					"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
			/* Encrypt SRTCP */
			int protected = pkt->length;
			int res = janus_is_webrtc_encryption_enabled() ?
				srtp_protect_rtcp(pc->dtls->srtp_out, pkt->data, &protected) : srtp_err_status_ok;
			if(res != srtp_err_status_ok) {
				/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
				handle->srtp_errors_count++;
				handle->last_srtp_error = res;
				/* If we're debugging, though, print every occurrence */
				JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected);
			} else {
				/* Shoot! */
				int sent = nice_agent_send(handle->agent, pc->stream_id, pc->component_id, protected, pkt->data);
				if(sent < protected) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
				}
			}
		}
		janus_ice_free_queued_packet(pkt);
	} else {
		/* RTP or data */
		if(pkt->type == JANUS_ICE_PACKET_AUDIO || pkt->type == JANUS_ICE_PACKET_VIDEO) {
			/* RTP */
			int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
			if(!medium->send) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			if(janus_is_webrtc_encryption_enabled() && (!pc->dtls || !pc->dtls->srtp_valid || !pc->dtls->srtp_out)) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !medium->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] %s stream component has no valid SRTP session (yet?)\n",
						handle->handle_id, video ? "video" : "audio");
					medium->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			medium->noerrorlog = FALSE;
			if(pkt->encrypted) {
				/* Already RTP (probably a retransmission?) */
				janus_rtp_header *header = (janus_rtp_header *)pkt->data;
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] ... Retransmitting seq.nr %"SCNu16"\n\n", handle->handle_id, ntohs(header->seq_number));
				int sent = nice_agent_send(handle->agent, pc->stream_id, pc->component_id, pkt->length, (const gchar *)pkt->data);
				if(sent < pkt->length) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
				}
			} else {
				/* Prune/update/set RTP extensions */
				janus_ice_rtp_extension_update(handle, medium, pkt);
				/* Overwrite SSRC */
				janus_rtp_header *header = (janus_rtp_header *)pkt->data;
				if(!pkt->retransmission) {
					/* ... but only if this isn't a retransmission (for those we already set it before) */
					header->ssrc = htonl(medium->ssrc);
				}
				/* Keep track of payload types too */
				if(medium->payload_type < 0) {
					medium->payload_type = header->type;
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
							medium->rtx_payload_types && g_hash_table_size(medium->rtx_payload_types) > 0) {
						medium->rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(medium->rtx_payload_types, GINT_TO_POINTER(medium->payload_type)));
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
							handle->handle_id, medium->rtx_payload_type);
					}
					if(medium->codec == NULL) {
						janus_mutex_lock(&handle->mutex);
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, medium->payload_type);
						janus_mutex_unlock(&handle->mutex);
						if(codec != NULL)
							medium->codec = g_strdup(codec);
					}
					if(video && medium->video_is_keyframe == NULL && medium->codec != NULL) {
						if(!strcasecmp(medium->codec, "vp8"))
							medium->video_is_keyframe = &janus_vp8_is_keyframe;
						else if(!strcasecmp(medium->codec, "vp9"))
							medium->video_is_keyframe = &janus_vp9_is_keyframe;
						else if(!strcasecmp(medium->codec, "h264"))
							medium->video_is_keyframe = &janus_h264_is_keyframe;
						else if(!strcasecmp(medium->codec, "av1"))
							medium->video_is_keyframe = &janus_av1_is_keyframe;
						else if(!strcasecmp(medium->codec, "h265"))
							medium->video_is_keyframe = &janus_h265_is_keyframe;
					}
				}
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, FALSE, pkt->data, pkt->length,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* If this is video and NACK optimizations are enabled, check if this is
				 * a keyframe: if so, we empty our retransmit buffer for incoming NACKs */
				if(video && nack_optimizations && medium->video_is_keyframe) {
					int plen = 0;
					char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
					if(medium->video_is_keyframe(payload, plen)) {
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe sent, cleaning retransmit buffer\n", handle->handle_id);
						janus_cleanup_nack_buffer(0, pc, FALSE, TRUE);
					}
				}
				/* Before encrypting, check if we need to copy the unencrypted payload (e.g., for rtx/90000) */
				janus_rtp_packet *p = NULL;
				if(medium->nack_queue_ms > 0 && !pkt->retransmission && pkt->type == JANUS_ICE_PACKET_VIDEO && medium->do_nacks &&
						janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
					/* Save the packet for retransmissions that may be needed later: start by
					 * making room for two more bytes to store the original sequence number */
					p = g_malloc(sizeof(janus_rtp_packet));
					janus_rtp_header *header = (janus_rtp_header *)pkt->data;
					guint16 original_seq = header->seq_number;
					p->data = g_malloc(pkt->length+2);
					p->length = pkt->length+2;
					/* Check where the payload starts */
					int plen = 0;
					char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
					if(plen == 0) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Discarding outgoing empty RTP packet\n", handle->handle_id);
						janus_ice_free_rtp_packet(p);
						janus_ice_free_queued_packet(pkt);
						return G_SOURCE_CONTINUE;
					}
					size_t hsize = payload - pkt->data;
					/* Copy the header first */
					memcpy(p->data, pkt->data, hsize);
					/* Copy the original sequence number */
					memcpy(p->data+hsize, &original_seq, 2);
					/* Copy the extensions struct */
					p->extensions = pkt->extensions;
					/* Copy the payload */
					memcpy(p->data+hsize+2, payload, pkt->length - hsize);
				}
				/* Encrypt SRTP */
				int protected = pkt->length;
				int res = janus_is_webrtc_encryption_enabled() ?
					srtp_protect(pc->dtls->srtp_out, pkt->data, &protected) : srtp_err_status_ok;
				if(res != srtp_err_status_ok) {
					/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
					handle->srtp_errors_count++;
					handle->last_srtp_error = res;
					/* If we're debugging, though, print every occurrence */
					janus_rtp_header *header = (janus_rtp_header *)pkt->data;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						handle->handle_id, janus_srtp_error_str(res), pkt->length, protected, timestamp, seq);
					janus_ice_free_rtp_packet(p);
				} else {
					/* Shoot! */
					int sent = nice_agent_send(handle->agent, pc->stream_id, pc->component_id, protected, pkt->data);
					if(sent < protected) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
					}
					/* Update stats */
					if(sent > 0) {
						/* Update the RTCP context as well */
						janus_rtp_header *header = (janus_rtp_header *)pkt->data;
						guint32 timestamp = ntohl(header->timestamp);
						medium->out_stats.info[0].packets++;
						medium->out_stats.info[0].bytes += pkt->length;
						/* Last second outgoing media */
						gint64 now = janus_get_monotonic_time();
						if(medium->out_stats.info[0].updated == 0)
							medium->out_stats.info[0].updated = now;
						if(now > medium->out_stats.info[0].updated &&
								now - medium->out_stats.info[0].updated >= G_USEC_PER_SEC) {
							medium->out_stats.info[0].bytes_lastsec = medium->out_stats.info[0].bytes_lastsec_temp;
							medium->out_stats.info[0].bytes_lastsec_temp = 0;
							medium->out_stats.info[0].updated = now;
						}
						medium->out_stats.info[0].bytes_lastsec_temp += pkt->length;
						struct timeval tv;
						gettimeofday(&tv, NULL);
						if(medium->last_ntp_ts == 0 || (gint32)(timestamp - medium->last_rtp_ts) > 0) {
							medium->last_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
							medium->last_rtp_ts = timestamp;
						}
						if(medium->first_ntp_ts[0] == 0) {
							medium->first_ntp_ts[0] = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
							medium->first_rtp_ts[0] = timestamp;
						}
						/* Update sent packets counter */
						rtcp_context *rtcp_ctx = medium->rtcp_ctx[0];
						if(rtcp_ctx) {
							g_atomic_int_inc(&rtcp_ctx->sent_packets_since_last_rr);
							if(pkt->type == JANUS_ICE_PACKET_AUDIO) {
								/* Let's check if this is not Opus: in case we may need to change the timestamp base */
								int pt = header->type;
								uint32_t clock_rate = medium->clock_rates ?
									GPOINTER_TO_UINT(g_hash_table_lookup(medium->clock_rates, GINT_TO_POINTER(pt))) : 48000;
								if(rtcp_ctx->tb != clock_rate)
									rtcp_ctx->tb = clock_rate;
							}
						}
					}
					if(medium->nack_queue_ms > 0 && !pkt->retransmission) {
						/* Save the packet for retransmissions that may be needed later */
						if(!medium->do_nacks) {
							/* ... unless NACKs are disabled for this medium */
							janus_ice_free_queued_packet(pkt);
							return G_SOURCE_CONTINUE;
						}
						if(p == NULL) {
							/* If we're not doing RFC4588, we're saving the SRTP packet as it is */
							p = g_malloc(sizeof(janus_rtp_packet));
							p->data = g_malloc(protected);
							memcpy(p->data, pkt->data, protected);
							p->length = protected;
							janus_plugin_rtp_extensions_reset(&p->extensions);
						}
						p->created = janus_get_monotonic_time();
						p->last_retransmit = 0;
						p->current_backoff = 0;
						janus_rtp_header *header = (janus_rtp_header *)pkt->data;
						guint16 seq = ntohs(header->seq_number);
						if(medium->retransmit_buffer == NULL) {
							medium->retransmit_buffer = g_queue_new();
							medium->retransmit_seqs = g_hash_table_new(NULL, NULL);
						}
						g_queue_push_tail(medium->retransmit_buffer, p);
						/* Insert in the table too, for quick lookup */
						g_hash_table_insert(medium->retransmit_seqs, GUINT_TO_POINTER(seq), p);
					} else {
						janus_ice_free_rtp_packet(p);
					}
				}
			}
		} else if(pkt->type == JANUS_ICE_PACKET_TEXT || pkt->type == JANUS_ICE_PACKET_BINARY) {
			/* Data */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
#ifdef HAVE_SCTP
			if(!pc->dtls) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !medium->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
					medium->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			medium->noerrorlog = FALSE;
			/* TODO Support binary data */
			janus_dtls_wrap_sctp_data(pc->dtls, pkt->label, pkt->protocol,
				pkt->type == JANUS_ICE_PACKET_TEXT, pkt->data, pkt->length);
#endif
		} else if(pkt->type == JANUS_ICE_PACKET_SCTP) {
			/* SCTP data to push */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
#ifdef HAVE_SCTP
			/* Encapsulate this data in DTLS and send it */
			if(!pc->dtls) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !medium->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
					medium->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			medium->noerrorlog = FALSE;
			janus_dtls_send_sctp_data(pc->dtls, pkt->data, pkt->length);
#endif
		} else {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported packet type %d\n", handle->handle_id, pkt->type);
		}
		janus_ice_free_queued_packet(pkt);
	}
	return G_SOURCE_CONTINUE;
}

static void janus_ice_queue_packet(janus_ice_handle *handle, janus_ice_queued_packet *pkt) {
	/* TODO: There is a potential race condition where the "queued_packets"
	 * could get released between the condition and pushing the packet. */
	if(handle->queued_packets != NULL) {
		g_async_queue_push(handle->queued_packets, pkt);
		g_main_context_wakeup(handle->mainctx);
	} else {
		janus_ice_free_queued_packet(pkt);
	}
}

void janus_ice_relay_rtp(janus_ice_handle *handle, janus_plugin_rtp *packet) {
	if(!handle || !handle->pc || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL ||
			!janus_is_rtp(packet->buffer, packet->length))
		return;
	/* Queue this packet as it is (we'll prune/update/set extensions later) */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->mindex = packet->mindex;
	pkt->data = g_malloc(packet->length + SRTP_MAX_TAG_LEN);
	memcpy(pkt->data, packet->buffer, packet->length);
	pkt->length = packet->length;
	pkt->type = packet->video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->extensions = packet->extensions;
	pkt->control = FALSE;
	pkt->control_ext = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
}

void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, janus_ice_peerconnection_medium *medium,
		janus_plugin_rtcp *packet, gboolean filter_rtcp) {
	if(!handle || !handle->pc || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL ||
			!janus_is_rtcp(packet->buffer, packet->length))
		return;
	/* We use this internal method to check whether we need to filter RTCP (e.g., to make
	 * sure we don't just forward any SR/RR from peers/plugins, but use our own) or it has
	 * already been done, and so this is actually a packet added by the ICE send thread */
	char *rtcp_buf = packet->buffer;
	int rtcp_len = packet->length;
	gboolean has_medium = (medium != NULL);
	if(filter_rtcp) {
		/* Strip RR/SR/SDES/NACKs/etc. */
		rtcp_buf = janus_rtcp_filter(packet->buffer, packet->length, &rtcp_len);
		if(rtcp_buf == NULL || rtcp_len < 1) {
			g_free(rtcp_buf);
			return;
		}
		if(has_medium) {
			/* Fix all SSRCs before enqueueing, as we need to use the ones for this media
			* leg. Note that this is only needed for RTCP packets coming from plugins: the
			* ones created by the core already have the right SSRCs in the right place */
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
				medium->ssrc, medium->ssrc_peer[0]);
			janus_rtcp_fix_ssrc(NULL, rtcp_buf, rtcp_len, 1,
				medium->ssrc, medium->ssrc_peer[0]);
		}
	}
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->mindex = (has_medium) ? medium->mindex : packet->mindex;
	pkt->data = g_malloc(rtcp_len+SRTP_MAX_TAG_LEN+4);
	memcpy(pkt->data, rtcp_buf, rtcp_len);
	pkt->length = rtcp_len;
	pkt->type = packet->video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	memset(&pkt->extensions, 0, sizeof(pkt->extensions));
	pkt->control = TRUE;
	pkt->control_ext = !has_medium;	/* We could do further processing for this packet in the loop */
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
	if(rtcp_buf != packet->buffer) {
		/* We filtered the original packet, deallocate it */
		g_free(rtcp_buf);
	}
}

void janus_ice_relay_rtcp(janus_ice_handle *handle, janus_plugin_rtcp *packet) {
	janus_ice_relay_rtcp_internal(handle, NULL, packet, TRUE);
}

void janus_ice_send_pli(janus_ice_handle *handle) {
	if(handle == NULL || handle->pc == NULL)
		return;
	/* Iterate on all video streams, and send the PLI there */
	janus_ice_peerconnection_medium *medium = NULL;
	uint mi=0;
	for(mi=0; mi<g_hash_table_size(handle->pc->media); mi++) {
		medium = g_hash_table_lookup(handle->pc->media, GUINT_TO_POINTER(mi));
		if(!medium || medium->type != JANUS_MEDIA_VIDEO)
			continue;
		janus_ice_send_pli_stream(handle, medium->mindex);
	}
}

void janus_ice_send_pli_stream(janus_ice_handle *handle, int mindex) {
	char rtcpbuf[12];
	memset(rtcpbuf, 0, 12);
	janus_rtcp_pli((char *)&rtcpbuf, 12);
	/* FIXME We send the PLI on the first video m-line we have */
	janus_plugin_rtcp rtcp = { .mindex = mindex, .video = TRUE, .buffer = rtcpbuf, .length = 12 };
	janus_ice_relay_rtcp(handle, &rtcp);
}

void janus_ice_send_remb(janus_ice_handle *handle, uint32_t bitrate) {
	char rtcpbuf[24];
	janus_rtcp_remb((char *)&rtcpbuf, 24, bitrate);
	/* FIXME We send the PLI on the first video m-line we have */
	janus_plugin_rtcp rtcp = { .mindex = -1, .video = TRUE, .buffer = rtcpbuf, .length = 24 };
	janus_ice_relay_rtcp(handle, &rtcp);
}

#ifdef HAVE_SCTP
void janus_ice_relay_data(janus_ice_handle *handle, janus_plugin_data *packet) {
	if(!handle || !handle->pc || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(packet->length);
	pkt->mindex = -1;
	memcpy(pkt->data, packet->buffer, packet->length);
	pkt->length = packet->length;
	pkt->type = packet->binary ? JANUS_ICE_PACKET_BINARY : JANUS_ICE_PACKET_TEXT;
	memset(&pkt->extensions, 0, sizeof(pkt->extensions));
	pkt->control = FALSE;
	pkt->control_ext = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = packet->label ? g_strdup(packet->label) : NULL;
	pkt->protocol = packet->protocol ? g_strdup(packet->protocol) : NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
}
#endif

void janus_ice_relay_sctp(janus_ice_handle *handle, char *buffer, int length) {
#ifdef HAVE_SCTP
	if(!handle || !handle->pc || handle->queued_packets == NULL || buffer == NULL || length < 1)
		return;
	/* Find the right medium instance */
	janus_ice_peerconnection_medium *medium = g_hash_table_lookup(handle->pc->media_bytype,
		GINT_TO_POINTER(JANUS_MEDIA_DATA));
	if(!medium)	/* Queue this packet */
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(length);
	pkt->mindex = medium->mindex;
	memcpy(pkt->data, buffer, length);
	pkt->length = length;
	pkt->type = JANUS_ICE_PACKET_SCTP;
	memset(&pkt->extensions, 0, sizeof(pkt->extensions));
	pkt->control = FALSE;
	pkt->control_ext = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
#endif
}

void janus_ice_notify_data_ready(janus_ice_handle *handle) {
#ifdef HAVE_SCTP
	if(!handle || handle->queued_packets == NULL)
		return;
	/* Queue this event */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_data_ready);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_data_ready);
#endif
	g_main_context_wakeup(handle->mainctx);
#endif
}

void janus_ice_notify_media_stopped(janus_ice_handle *handle) {
	if(!handle || handle->queued_packets == NULL)
		return;
	/* Queue this event */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_media_stopped);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_media_stopped);
#endif
	g_main_context_wakeup(handle->mainctx);
}

void janus_ice_dtls_handshake_done(janus_ice_handle *handle) {
	if(!handle || !handle->pc)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] The DTLS handshake for the component %d in stream %d has been completed\n",
		handle->handle_id, handle->pc->component_id, handle->pc->stream_id);
	/* Check if all components are ready */
	janus_mutex_lock(&handle->mutex);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		/* Already notified */
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	/* Create a source for RTCP and one for stats */
	handle->rtcp_source = g_timeout_source_new_seconds(1);
	g_source_set_priority(handle->rtcp_source, G_PRIORITY_DEFAULT);
	g_source_set_callback(handle->rtcp_source, janus_ice_outgoing_rtcp_handle, handle, NULL);
	g_source_attach(handle->rtcp_source, handle->mainctx);
	if(twcc_period != 1000) {
		/* The Transport Wide CC feedback period is different, create another source */
		handle->twcc_source = g_timeout_source_new(twcc_period);
		g_source_set_priority(handle->twcc_source, G_PRIORITY_DEFAULT);
		g_source_set_callback(handle->twcc_source, janus_ice_outgoing_transport_wide_cc_feedback, handle, NULL);
		g_source_attach(handle->twcc_source, handle->mainctx);
	}
	handle->last_event_stats = 0;
	handle->last_srtp_summary = -1;
	handle->stats_source = g_timeout_source_new_seconds(1);
	g_source_set_callback(handle->stats_source, janus_ice_outgoing_stats_handle, handle, NULL);
	g_source_set_priority(handle->stats_source, G_PRIORITY_DEFAULT);
	g_source_attach(handle->stats_source, handle->mainctx);
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
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("webrtcup"));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	g_atomic_int_set(&handle->has_pc, 1);
	g_atomic_int_inc(&pc_num);
}
