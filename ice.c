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
#include <sys/socket.h>
#include <netdb.h>
#include <stun/usages/bind.h>

#include "janus.h"
#include "debug.h"
#include "ice.h"
#include "dtls.h"
#include "rtp.h"
#include "rtcp.h"
#include "apierror.h"


/* STUN server/port, if any */
static char *janus_stun_server;
static uint16_t janus_stun_port;

char *janus_ice_get_stun_server(void) {
	return janus_stun_server;
}
uint16_t janus_ice_get_stun_port(void) {
	return janus_stun_port;
}


/* IPv6 support (still mostly WIP) */
static gboolean janus_ipv6_enabled;
gboolean janus_ice_is_ipv6_enabled(void) {
	return janus_ipv6_enabled;
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


/* Maximum value for the NACK queue */
#define DEFAULT_MAX_NACK_QUEUE	300
static uint max_nack_queue = DEFAULT_MAX_NACK_QUEUE;
void janus_set_max_nack_queue(uint mnq) {
	max_nack_queue = mnq;
	JANUS_LOG(LOG_VERB, "Setting max NACK queue to %d\n", max_nack_queue);
}
uint janus_get_max_nack_queue(void) {
	return max_nack_queue;
}


/* libnice initialization */
gint janus_ice_init(gchar *stun_server, uint16_t stun_port, uint16_t rtp_min_port, uint16_t rtp_max_port, gboolean ipv6) {
	janus_ipv6_enabled = ipv6;
	JANUS_LOG(LOG_INFO, "Initializing ICE stuff (IPv6 candidates %s)\n", janus_ipv6_enabled ? "enabled" : "disabled");
	if(stun_server == NULL)
		return 0;	/* No initialization needed */
	if(stun_port == 0)
		stun_port = 3478;
	/*! \note The RTP/RTCP port range configuration may be just a placeholder: for
	 * instance, libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails
	 * when linking with an undefined reference to \c nice_agent_set_port_range 
	 * so this is checked by the install.sh script in advance. */
	rtp_range_min = rtp_min_port;
	rtp_range_max = rtp_max_port;
#ifndef HAVE_PORTRANGE
	JANUS_LOG(LOG_WARN, "nice_agent_set_port_range unavailable, port range disabled\n");
#else
	JANUS_LOG(LOG_INFO, "ICE port range: %"SCNu16"-%"SCNu16"\n", rtp_range_min, rtp_range_max);
#endif
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
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	if(handle->iceloop)
		g_main_loop_quit(handle->iceloop);
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there */
		janus_mutex_unlock(&session->mutex);
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s\n", plugin_t->get_name());
	/* TODO Actually detach handle... */
	int error = 0;
	handle->app_handle->stopped = 1;	/* This is to tell the plugin to stop using this session: we'll get rid of it later */
	plugin_t->destroy_session(handle->app_handle, &error);

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
	JANUS_LOG(LOG_INFO, "Handle detached (%d), scheduling destruction\n", error);
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
	if(state == NICE_COMPONENT_STATE_CONNECTED) {	/* FIXME Was NICE_COMPONENT_STATE_READY, but this gives us a working pair anyway */
		/* Now we can start the DTLS handshake */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready, starting DTLS handshake...\n", handle->handle_id);
		/* Have we been here before? (might happen, when trickling) */
		if(component->dtls != NULL)
			return;
		/* Create DTLS-SRTP context, at last */
		component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
		if(!component->dtls) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component DTLS-SRTP session??\n", handle->handle_id);
			return;
		}
		/* Create retransmission timer */
		component->source = g_timeout_source_new(500);
		g_source_set_callback(component->source, janus_dtls_retry, component->dtls, NULL);
		guint id = g_source_attach(component->source, handle->icectx);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
		/* Do DTLS handshake */
		janus_dtls_srtp_handshake(component->dtls);
	} else if(state == NICE_COMPONENT_STATE_FAILED) {
		/* Failed doesn't mean necessarily we need to give up: we may be trickling */
		if(handle &&
				(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES))
					&& !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
			/* FIXME Should we really give up for what may be a failure in only one of the media? */
			JANUS_LOG(LOG_ERR, "ICE failed for handle %"SCNu64"...\n", handle->handle_id);
			janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
			janus_plugin *plugin = (janus_plugin *)handle->app;
			if(plugin != NULL) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
				if(plugin && plugin->hangup_media)
					plugin->hangup_media(handle->app_handle);
			}
			/* Also prepare JSON event to notify user/application */
			janus_session *session = (janus_session *)handle->session;
			if(session == NULL)
				return;
			json_t *event = json_object();
			json_object_set_new(event, "janus", json_string("hangup"));
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
	}
}

void janus_ice_cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, gchar *lfoundation, gchar *rfoundation, gpointer ice) {
	JANUS_LOG(LOG_VERB, "New selected pair for component %d in stream %d: %s <-> %s\n", component_id, stream_id, lfoundation, rfoundation);
}

void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
	janus_ice_component *component = (janus_ice_component *)ice;
	if(!component) {
		JANUS_LOG(LOG_ERR, "No component %d in stream %d??\n", component_id, stream_id);
		return;
	}
	if(!component->dtls) {	/* Still waiting for the DTLS stack */
		JANUS_LOG(LOG_ERR, "Still waiting for the DTLS stack for component %d in stream %d...\n", component_id, stream_id);
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
	/* What is this? */
	if (janus_is_dtls(buf) || (!janus_is_rtp(buf) && !janus_is_rtcp(buf))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels */
		JANUS_LOG(LOG_HUGE, "Looks like DTLS!\n");
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
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
			int buflen = len;
			err_status_t res = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
			if(res != err_status_ok) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_get_srtp_error(res), len, buflen);
			} else {
				/* Is this audio or video? */
				int video = 0;
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_BUNDLE)) {
					/* Easy enough */
					video = (stream->stream_id == handle->video_id ? 1 : 0);
				} else {
					/* Bundled streams, check SSRC */
					rtp_header *header = (rtp_header *)buf;
					video = (stream->video_ssrc_peer == ntohl(header->ssrc) ? 1 : 0);
					//~ JANUS_LOG(LOG_VERB, "[RTP] Bundling: this is %s (video=%"SCNu64", audio=%"SCNu64", got %ld)\n",
						//~ video ? "video" : "audio", stream->video_ssrc_peer, stream->audio_ssrc_peer, ntohl(header->ssrc));
				}
				if(video) {
					if(stream->video_ssrc_peer == 0) {
						rtp_header *header = (rtp_header *)buf;
						stream->video_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer video SSRC: %u\n", handle->handle_id, stream->video_ssrc_peer);
					}
				} else {
					if(stream->audio_ssrc_peer == 0) {
						rtp_header *header = (rtp_header *)buf;
						stream->audio_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer audio SSRC: %u\n", handle->handle_id, stream->audio_ssrc_peer);
					}
				}
				/* TODO Should we store the packet in a circular buffer, in case we get a NACK we can handle ourselves without relaying? */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp)
					plugin->incoming_rtp(handle->app_handle, video, buf, buflen);
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
				if(nacks != NULL) {
					/* Handle NACK */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Just got some NACKS we should handle...\n", handle->handle_id);
					GSList *list = nacks;
					janus_mutex_lock(&component->mutex);
					while(list) {
						unsigned int seqnr = GPOINTER_TO_UINT(list->data);
						JANUS_LOG(LOG_HUGE, "  >> %u\n", seqnr);
						GList *rp = component->retransmit_buffer;
						while(rp) {
							janus_rtp_packet *p = (janus_rtp_packet *)rp->data;
							if(p) {
								rtp_header *rh = (rtp_header *)p->data;
								if(ntohs(rh->seq_number) == seqnr) {
									/* Retransmit this packet */
									JANUS_LOG(LOG_HUGE, "  >> >> Scheduling %u for retransmission!\n", seqnr);
									/* Enqueue it */
									janus_ice_queued_packet *pkt = (janus_ice_queued_packet *)calloc(1, sizeof(janus_ice_queued_packet));
									pkt->data = calloc(p->length, sizeof(char));
									memcpy(pkt->data, p->data, p->length);
									pkt->length = p->length;
									pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
									pkt->control = FALSE;
									pkt->encrypted = TRUE;	/* This was already encrypted before */
									g_async_queue_push(handle->queued_packets, pkt);
									break;
								}
							}
							rp = rp->next;
						}
						list = list->next;
					}
					janus_mutex_unlock(&component->mutex);
					JANUS_LOG(LOG_HUGE, "\n");
					g_slist_free(nacks);
					nacks = NULL;
					/* FIXME Remove the NACK compound packet, we've handled it */
					buflen = janus_rtcp_remove_nacks(buf, buflen);
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
		JANUS_LOG(LOG_INFO, "Not RTP and not RTCP... may these be data channels?\n");
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
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
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE thread started, looping...\n", handle->handle_id);
	GMainLoop *loop = handle->iceloop;
	if(loop == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid loop...\n", handle->handle_id);
		return NULL;
	}
	g_usleep (100000);
	g_main_loop_run (loop);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	if(handle->cdone == 0)
		handle->cdone = -1;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE thread ended!\n", handle->handle_id);
	/* This handle has been destroyed, wait a bit and then free all the resources */
	g_usleep (1*G_USEC_PER_SEC);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		janus_ice_free(handle);
	} else {
		janus_ice_webrtc_free(handle);
	}
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
		JANUS_LOG(LOG_VERB, "Public IP specified (%s), using that as host address in the candidates\n", host_ip);
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
			g_snprintf(buffer, 100,
				"a=candidate:%s %d %s %d %s %d typ host\r\n", 
					c->foundation,
					c->component_id,
					"udp",
					c->priority,
					host_ip ? host_ip : address,
					port);
		} else if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
			/* 'srflx' candidate */
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
		} else if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
			/* 'prflx' candidate */
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
		} else if(c->type == NICE_CANDIDATE_TYPE_RELAYED) {
			/* 'relay' candidate */
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
		}
		g_strlcat(sdp, buffer, BUFSIZE);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]     %s\n", handle->handle_id, buffer);
		if(log_candidates) {
			/* Save for the summary, in case we need it */
			component->local_candidates = g_slist_append(component->local_candidates, g_strdup(buffer));
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
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such component %d in stream %d: cannot setup remote candidates\n", handle->handle_id, component_id, stream_id);
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
	if (nice_agent_set_remote_candidates(handle->agent, stream_id, component_id, component->candidates) < 1) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to set remote candidates :-(\n", handle->handle_id);
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote candidates set!\n", handle->handle_id);
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
	handle->icethread = g_thread_new("ice thread", &janus_ice_thread, handle);
	/* We have a dedicated thread for sending packets/messages */
	handle->queued_packets = g_async_queue_new();
	handle->send_thread = g_thread_new("ice send thread", &janus_ice_send_thread, handle);
	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice */
	handle->agent = nice_agent_new(handle->icectx, NICE_COMPATIBILITY_DRAFT19);
	/* Any STUN server to use? */
	if(janus_stun_server != NULL && janus_stun_port > 0) {
		g_object_set(G_OBJECT(handle->agent),
			"stun-server", janus_stun_server,
			"stun-server-port", janus_stun_port,
			NULL);
	}
	g_object_set(G_OBJECT(handle->agent), "upnp", FALSE, NULL);
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", !offer, NULL);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Creating ICE agent (%s mode)\n", handle->handle_id, offer ? "controlled" : "controlling");
	g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
	g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair",
		G_CALLBACK (janus_ice_cb_new_selected_pair), handle);

	/* Add all local addresses, except those in the ignore list */
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
				JANUS_LOG(LOG_ERR, "getnameinfo() failed: %s\n", gai_strerror(s));
				continue;
			}
			/* Skip localhost and 0.0.0.0 */
			if(!strcmp(host, "127.0.0.1") || !strcmp(host, "0.0.0.0")
					|| !strcmp(host, "::1") || !strcmp(host, "::") || strchr(host, '%'))
				continue;
			/* Check if this IP address is in the ignore list, now */
			if(janus_ice_is_ignored(host))
				continue;
			/* Ok, add interface to the ICE agent */
			JANUS_LOG(LOG_VERB, "Adding %s to the addresses to gather candidates for\n", host);
			NiceAddress addr_local;
			nice_address_init (&addr_local);
			if(!nice_address_set_from_string (&addr_local, host)) {
				JANUS_LOG(LOG_WARN, "Skipping invalid address %s\n", host);
				continue;
			}
			nice_agent_add_local_address (handle->agent, &addr_local);
		}
		freeifaddrs(ifaddr);
	}

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
		audio_rtp->source = NULL;
		audio_rtp->dtls = NULL;
		audio_rtp->retransmit_buffer = NULL;
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
			audio_rtcp->stream = audio_stream;
			audio_rtcp->candidates = NULL;
			audio_rtcp->local_candidates = NULL;
			audio_rtcp->remote_candidates = NULL;
			audio_rtcp->source = NULL;
			audio_rtcp->dtls = NULL;
			audio_rtcp->retransmit_buffer = NULL;
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
		video_rtp->stream = video_stream;
		video_rtp->candidates = NULL;
		video_rtp->local_candidates = NULL;
		video_rtp->remote_candidates = NULL;
		video_rtp->source = NULL;
		video_rtp->dtls = NULL;
		video_rtp->retransmit_buffer = NULL;
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
			video_rtcp->stream = video_stream;
			video_rtcp->candidates = NULL;
			video_rtcp->local_candidates = NULL;
			video_rtcp->remote_candidates = NULL;
			video_rtcp->source = NULL;
			video_rtcp->dtls = NULL;
			video_rtcp->retransmit_buffer = NULL;
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
		handle->data_id = nice_agent_add_stream (handle->agent, 3);
		janus_ice_stream *data_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(data_stream == NULL) {
			JANUS_LOG(LOG_FATAL, "Memory error!\n");
			return -1;
		}
		data_stream->handle = handle;
		data_stream->stream_id = handle->data_id;
		data_stream->cdone = 0;
		data_stream->payload_type = -1;
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
		data_component->source = NULL;
		data_component->dtls = NULL;
		data_component->retransmit_buffer = NULL;
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
	while(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
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
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     %s stream (#%u) component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio", stream->stream_id);
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
						JANUS_LOG(LOG_ERR, "[%"SCNu64"]     %s stream component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio");
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
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), pkt->length, protected);
					} else {
						/* Shoot! */
						//~ JANUS_LOG(LOG_VERB, "[%"SCNu64"] ... Sending SRTP packet (pt=%u, ssrc=%u, seq=%u, ts=%u)...\n", handle->handle_id,
							//~ header->type, ntohl(header->ssrc), ntohs(header->seq_number), ntohl(header->timestamp));
						int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const gchar *)&sbuf);
						if(sent < protected) {
							JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
						}
						/* Save the packet for retransmissions that may be needed later */
						janus_rtp_packet *p = (janus_rtp_packet *)calloc(1, sizeof(janus_rtp_packet));
						p->data = (char *)calloc(protected, sizeof(char));
						memcpy(p->data, (char *)&sbuf, protected);
						p->length = protected;
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
						JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
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
	if(handle->audio_stream) {
		if(handle->audio_stream->rtp_component && handle->audio_stream->rtp_component->dtls &&
				!handle->audio_stream->rtp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
		if(handle->audio_stream->rtcp_component && handle->audio_stream->rtcp_component->dtls &&
				!handle->audio_stream->rtcp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(handle->video_stream) {
		if(handle->video_stream->rtp_component && handle->video_stream->rtp_component->dtls &&
				!handle->video_stream->rtp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
		if(handle->video_stream->rtcp_component && handle->video_stream->rtcp_component->dtls &&
				!handle->video_stream->rtcp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(handle->data_stream) {
		if(handle->data_stream->rtp_component && handle->data_stream->rtp_component->dtls &&
				!handle->data_stream->rtp_component->dtls->srtp_valid) {
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
