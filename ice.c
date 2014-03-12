/*! \file    ice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
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

char *janus_ice_get_stun_server() {
	return janus_stun_server;
}
uint16_t janus_ice_get_stun_port() {
	return janus_stun_port;
}


/* RTP/RTCP port range */
uint16_t rtp_range_min = 0;
uint16_t rtp_range_max = 0;


/* libnice initialization */
gint janus_ice_init(gchar *stun_server, uint16_t stun_port, uint16_t rtp_min_port, uint16_t rtp_max_port) {
	if(stun_server == NULL)
		return 0;	/* No initialization needed */
	if(stun_port == 0)
		stun_port = 3478;
	/*! \todo The RTP/RTCP port range configuration may be just a placeholder: for
	 * instance, libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails
	 * when linking with an undefined reference to \c nice_agent_set_port_range 
	 * so this is checked by the install.sh script in advance. */
	rtp_range_min = rtp_min_port;
	rtp_range_max = rtp_max_port;
#ifndef HAVE_PORTRANGE
	JANUS_DEBUG("nice_agent_set_port_range unavailable, port range disabled\n");
#endif
	JANUS_PRINT("STUN server to use: %s:%u\n", stun_server, stun_port);
	/* Resolve address to get an IP */
	struct hostent *he = gethostbyname(stun_server);
	if(he == NULL) {
		JANUS_DEBUG("Could not resolve %s...\n", stun_server);
		return -1;
	}
	struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
	if(addr_list[0] == NULL) {
		JANUS_DEBUG("Could not resolve %s...\n", stun_server);
		return -1;
	}
	janus_stun_server = g_strdup(inet_ntoa(*addr_list[0]));
	if(janus_stun_server == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return -1;
	}
	janus_stun_port = stun_port;
	JANUS_PRINT("  >> %s:%u\n", janus_stun_server, janus_stun_port);
	/* Test the STUN server */
	StunAgent stun;
	stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
	StunMessage msg;
	uint8_t buf[1500];
	size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
	JANUS_PRINT("Testing STUN server: message is of %zu bytes\n", len);
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
		JANUS_PRINT("Bind failed for STUN BINDING test\n");
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, (struct sockaddr*)&remote, sizeof(remote));
	if(bytes < 0) {
		JANUS_PRINT("Error sending STUN BINDING test\n");
		return -1;
	}
	JANUS_PRINT("  >> Sent %d bytes %s:%u, waiting for reply...\n", bytes, janus_stun_server, janus_stun_port);
	struct timeval timeout;
	fd_set readfds;
	FD_SET(fd, &readfds);
	timeout.tv_sec = 5;	/* FIXME Don't wait forever */
	timeout.tv_usec = 0;
	select(fd+1, &readfds, NULL, NULL, &timeout);
	if(!FD_ISSET(fd, &readfds)) {
		JANUS_PRINT("No response to our STUN BINDING test\n");
		return -1;
	}
	socklen_t addrlen = sizeof(remote);
	bytes = recvfrom(fd, buf, 1500, 0, (struct sockaddr*)&remote, &addrlen);
	JANUS_PRINT("  >> Got %d bytes...\n", bytes);
	if(stun_agent_validate (&stun, &msg, buf, bytes, NULL, NULL) < 0) {
		JANUS_PRINT("Failed to validate STUN BINDING response\n");
		return -1;
	}
	StunClass class = stun_message_get_class(&msg);
	StunMethod method = stun_message_get_method(&msg);
	if(class != STUN_RESPONSE || method != STUN_BINDING) {
		JANUS_PRINT("Unexpected STUN response: %d/%d\n", class, method);
		return -1;
	}
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr *)&address, &addrlen);
	JANUS_PRINT("  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		janus_set_public_ip(inet_ntoa(address.sin_addr));
		JANUS_PRINT("  >> Our public address is %s\n", janus_get_public_ip());
		return 0;
	}
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr *)&address, &addrlen);
	JANUS_PRINT("  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		janus_set_public_ip(inet_ntoa(address.sin_addr));
		JANUS_PRINT("  >> Our public address is %s\n", janus_get_public_ip());
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

/* ICE Handless */
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
	JANUS_PRINT("Creating new handle in session %"SCNu64": %"SCNu64"\n", session->session_id, handle_id);
	janus_ice_handle *handle = (janus_ice_handle *)calloc(1, sizeof(janus_ice_handle));
	if(handle == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	handle->session = gateway_session;
	handle->handle_id = handle_id;
	handle->app = NULL;
	handle->app_handle = NULL;
	janus_mutex_init(&handle->mutex);
		/* Setup other stuff */
	if(session->ice_handles == NULL)
		session->ice_handles = g_hash_table_new(NULL, NULL);
	g_hash_table_insert(session->ice_handles, GUINT_TO_POINTER(handle_id), handle);
	return handle;
}

janus_ice_handle *janus_ice_handle_find(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)gateway_session;
	return session->ice_handles ? g_hash_table_lookup(session->ice_handles, GUINT_TO_POINTER(handle_id)) : NULL;
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
	int error = 0;
	janus_pluginession *session_handle = calloc(1, sizeof(janus_pluginession));
	if(session_handle == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return JANUS_ERROR_UNKNOWN;	/* FIXME Do we need something like "Internal Server Error"? */
	}
	session_handle->gateway_handle = handle;
	session_handle->plugin_handle = NULL;
	plugin->create_session(session_handle, &error);
	if(error) {
		/* TODO Make error struct to pass verbose information */
		return error;
	}
	handle->app = plugin;
	handle->app_handle = session_handle;
	return 0;
}

gint janus_ice_handle_destroy(void *gateway_session, guint64 handle_id) {
	if(gateway_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = (janus_session *)gateway_session;
	janus_ice_handle *handle = janus_ice_handle_find(session, handle_id);
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	handle->stop = 1;
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	JANUS_PRINT("Detaching handle from %s\n", plugin_t->get_name());
	/* TODO Actually detach handle... */
	int error = 0;
	handle->app_handle->gateway_handle = NULL;
	plugin_t->destroy_session(handle->app_handle, &error);
	g_hash_table_remove(session->ice_handles, GUINT_TO_POINTER(handle_id));
	/* TODO Actually destroy handle */
	return error;
}


/* Callbacks */
void janus_ice_cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	if(!handle)
		return;
	JANUS_PRINT("[%"SCNu64"] Gathering done for stream %d\n", handle->handle_id, stream_id);
	handle->cdone++;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_DEBUG("[%"SCNu64"]  No stream %d??\n", handle->handle_id, stream_id);
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	stream->cdone = 1;
}
void janus_ice_cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice) {
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	JANUS_PRINT("[%"SCNu64"] Component state changed for component %d in stream %d: %d (%s)\n",
		handle ? handle->handle_id : -1, component_id, stream_id, state, janus_get_ice_state_name(state));
	if(!handle)
		return;
	if(state == NICE_COMPONENT_STATE_READY) {
		/* Now we can start the DTLS handshake */
		JANUS_PRINT("[%"SCNu64"]   Component is ready, starting DTLS handshake...\n", handle->handle_id);
		janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
		if(!stream) {
			JANUS_DEBUG("[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
			return;
		}
		janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
		if(!component) {
			JANUS_DEBUG("[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
			return;
		}
		/* Create DTLS-SRTP context, at last */
		component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
		if(!component->dtls) {
			JANUS_DEBUG("[%"SCNu64"]     No component DTLS-SRTP session??\n", handle->handle_id);
			return;
		}
		/* Create retransmission timer */
		//~ SSL_set_mode(component->ssl, SSL_MODE_AUTO_RETRY);
		//~ SSL_set_read_ahead(component->ssl, 1);
		//~ guint id = g_timeout_add_seconds(1, janus_dtls_retry, component);
		GSource *source = g_timeout_source_new_seconds(1);
		g_source_set_callback(source, janus_dtls_retry, component->dtls, NULL);
		guint id = g_source_attach(source, handle->icectx);
		JANUS_PRINT("[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
		/* Do DTLS handshake */
		janus_dtls_srtp_handshake(component->dtls);
	} else if(state == NICE_COMPONENT_STATE_FAILED) {
		if(handle && !handle->stop) {
			/* FIXME Should we really give up for what may be a failure in only one of the media? */
			handle->stop = 1;
			janus_plugin *plugin = (janus_plugin *)handle->app;
			if(plugin != NULL) {
				JANUS_PRINT("[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
				if(plugin && plugin->hangup_media)
					plugin->hangup_media(handle->app_handle);
			}
		}
	}
}

void janus_ice_cb_new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, gchar *lfoundation, gchar *rfoundation, gpointer ice) {
	JANUS_PRINT("New selected pair for component %d in stream %d: %s <-> %s\n", component_id, stream_id, lfoundation, rfoundation);
}

void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
	//~ JANUS_PRINT("Got data (%d bytes) for component %d in stream %d\n", len, component_id, stream_id);
	janus_ice_component *component = (janus_ice_component *)ice;
	if(!component) {
		JANUS_DEBUG("janus_ice_cb_nice_recv:     No component %d in stream %d??\n", component_id, stream_id);
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_DEBUG("janus_ice_cb_nice_recv:     No stream %d??\n", stream_id);
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle)
		return;
	/* What is this? */
	if ((*buf >= 20) && (*buf <= 64)) {
		//~ JANUS_PRINT("  Looks like DTLS!\n");
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/draft-ietf-avt-rtp-and-rtcp-mux-07#page-11) */
	if(len < 12)
		return;	/* Definitely nothing useful */
	if(component_id == 1) {
		/* TODO Actually check if this is RTP or RTCP: right now we assume the first component is RTP */
		if(!component->dtls || !component->dtls->srtp_valid) {
			JANUS_DEBUG("[%"SCNu64"]     Missing valid SRTP session, skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			err_status_t res = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
			if(res != err_status_ok) {
				JANUS_DEBUG("[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_get_srtp_error(res), len, buflen);
			} else {
				if(stream->ssrc_peer == 0) {
					rtp_header *header = (rtp_header *)buf;
					stream->ssrc_peer = ntohl(header->ssrc);
					JANUS_PRINT("[%"SCNu64"]     Peer %s SSRC: %u\n", handle->handle_id, stream->stream_id == handle->audio_id ? "audio" : "video", stream->ssrc_peer);
				}
				/* TODO Should we store the packet in a circular buffer, in case we get a NACK we can handle ourselves without relaying? */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp)
					plugin->incoming_rtp(handle->app_handle, stream->stream_id == handle->video_id ? 1 : 0, buf, buflen);
			}
		}
		return;
	}
	if(component_id == 2) {
		/* TODO Actually check if this is RTP or RTCP: right now we assume the second component is RTCP */
		JANUS_PRINT("[%"SCNu64"]  Got an RTCP packet (%s stream)!\n", handle->handle_id, stream->stream_id == handle->audio_id ? "audio" : "video");
		if(!component->dtls || !component->dtls->srtp_valid) {
			JANUS_DEBUG("[%"SCNu64"]     Missing valid SRTP session, skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			err_status_t res = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
			if(res != err_status_ok) {
				JANUS_DEBUG("[%"SCNu64"]     SRTCP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_get_srtp_error(res), len, buflen);
			} else {
				GSList *nacks = janus_rtcp_get_nacks(buf, buflen);
				if(nacks != NULL) {
					/* TODO Actually handle NACK */
					JANUS_PRINT("[%"SCNu64"]     Just got some NACKS we should probably handle...\n", handle->handle_id);
					JANUS_PRINT("           >>");
					GSList *list = nacks;
					while(list->next) {
						JANUS_PRINT(" %u", GPOINTER_TO_UINT(list->data));
						list = list->next;
					}
					JANUS_PRINT("\n");
				}
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtcp)
					plugin->incoming_rtcp(handle->app_handle, stream->stream_id == handle->video_id ? 1 : 0, buf, buflen);
			}
		}
	}
}

/* Thread to create agent */
void *janus_ice_thread(void *data) {
	janus_ice_handle *handle = data;
	JANUS_PRINT("[%"SCNu64"] ICE thread started, looping...\n", handle->handle_id);
	GMainLoop *loop = handle->iceloop;
	g_usleep (100000);
	g_main_loop_run (loop);
	if(handle->cdone == 0)
		handle->cdone = -1;
	JANUS_PRINT("[%"SCNu64"] ICE thread ended!\n", handle->handle_id);
	return NULL;
}

/* Helper: candidates */
void janus_ice_setup_candidate(janus_ice_handle *handle, char *sdp, guint stream_id, guint component_id)
{
	if(!handle || !handle->agent || !sdp)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream) {
		JANUS_DEBUG("[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component) {
		JANUS_DEBUG("[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	NiceAgent* agent = handle->agent;
	/* adding a stream should cause host candidates to be generated */
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_PRINT("[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	for (i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		JANUS_PRINT("[%"SCNu64"] Stream #%d, Component #%d\n", handle->handle_id, c->stream_id, c->component_id);
		gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
		gint port = 0, base_port = 0;
		nice_address_to_string(&(c->addr), (gchar *)&address);
		port = nice_address_get_port(&(c->addr));
		nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
		base_port = nice_address_get_port(&(c->base_addr));
		JANUS_PRINT("[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
		JANUS_PRINT("[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
		JANUS_PRINT("[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
		/* SDP time */
		gchar buffer[100];
		if(c->type == NICE_CANDIDATE_TYPE_HOST) {
			/* 'host' candidate */
			g_sprintf(buffer,
				"a=candidate:%s %d %s %d %s %d typ host\r\n", 
					c->foundation,
					c->component_id,
					"udp",
					c->priority,
					address,
					port);
		} else if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
			/* 'srflx' candidate */
			nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
			gint base_port = nice_address_get_port(&(c->base_addr));
			g_sprintf(buffer,
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
			g_sprintf(buffer,
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
			g_sprintf(buffer,
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
		JANUS_PRINT("[%"SCNu64"]     %s\n", handle->handle_id, buffer);
		/* RTP or RTCP? */
		gchar *search = NULL, replace[6];
		g_sprintf(replace, "%d", port);
		if(stream_id == handle->audio_id) {
			if(component_id == 1) {
				/* Audio RTP */
				search = "ARTPP";
			} else {
				/* Audio RTCP */
				search = "ARTCP";
			}
		} else {	/* FIXME We assume this is video: there's nothing else right now */
			if(component_id == 1) {
				/* Video RTP */
				search = "VRTPP";
			} else {
				/* Video RTCP */
				search = "VRTCP";
			}
		}
		/* FIXME This is a VERY ugly way to set ports in m-lines! */
		gchar *index = g_strstr_len(sdp, BUFSIZE, search);
		if(index) {
			int j=0;
			for(j=0; j<5; j++)
				index[j] = replace[j];
		}
	}
}

void janus_ice_setup_remote_candidate(janus_ice_handle *handle, guint stream_id, guint component_id) {
	if(!handle || !handle->agent || !handle->streams)
		return;
	janus_ice_stream *stream = g_hash_table_lookup(handle->streams, GUINT_TO_POINTER(stream_id));
	if(!stream || !stream->components) {
		JANUS_DEBUG("[%"SCNu64"] No such stream %d: cannot setup remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	janus_ice_component *component = g_hash_table_lookup(stream->components, GUINT_TO_POINTER(component_id));
	if(!component || !component->candidates) {
		JANUS_DEBUG("[%"SCNu64"] No such component %d in stream %d: cannot setup remote candidates\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(!component || !component->candidates || !component->candidates->data) {
		JANUS_DEBUG("[%"SCNu64"] No remote data for component %d in stream %d: was the remote SDP parsed?\n", handle->handle_id, component_id, stream_id);
		return;
	}
	JANUS_PRINT("[%"SCNu64"] ## Setting remote candidates: stream %d, component %d (%u in the list)\n",
		handle->handle_id, stream_id, component_id, g_slist_length(component->candidates));
	/* Add all candidates */
	NiceCandidate *c = NULL;
	GSList *gsc = component->candidates;
	gchar *rufrag = NULL, *rpwd = NULL;
	while(gsc) {
		c = (NiceCandidate *) gsc->data;
		JANUS_PRINT("[%"SCNu64"] >> Remote Stream #%d, Component #%d\n", handle->handle_id, c->stream_id, c->component_id);
		if(c->username && !rufrag)
			rufrag = c->username;
		if(c->password && !rpwd)
			rpwd = c->password;
		gchar address[NICE_ADDRESS_STRING_LEN];
		nice_address_to_string(&(c->addr), (gchar *)&address);
		gint port = nice_address_get_port(&(c->addr));
		JANUS_PRINT("[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
		JANUS_PRINT("[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
		JANUS_PRINT("[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
		JANUS_PRINT("[%"SCNu64"]   Username:   %s\n", handle->handle_id, c->username);
		JANUS_PRINT("[%"SCNu64"]   Password:   %s\n", handle->handle_id, c->password);
		gsc = gsc->next;
	}
	if(rufrag && rpwd) {
		JANUS_PRINT("[%"SCNu64"]  Setting remote credendials...\n", handle->handle_id);
		if(!nice_agent_set_remote_credentials(handle->agent, stream_id, rufrag, rpwd)) {
			JANUS_DEBUG("[%"SCNu64"]  failed to set remote credentials!\n", handle->handle_id);
		}
	}
	if (nice_agent_set_remote_candidates(handle->agent, stream_id, component_id, component->candidates) < 1) {
		JANUS_DEBUG("[%"SCNu64"] Failed to set remote candidates :-(\n", handle->handle_id);
	} else {
		JANUS_PRINT("[%"SCNu64"] Remote candidates set!\n", handle->handle_id);
	}
}

int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video) {
	if(!handle)
		return -1;
	JANUS_PRINT("[%"SCNu64"] Setting ICE locally: got %s (%d audios, %d videos)\n", handle->handle_id, offer ? "OFFER" : "ANSWER", audio, video);
	handle->stop = 0;	/* FIXME Reset handle */
	handle->icectx = g_main_context_new();
	handle->iceloop = g_main_loop_new(handle->icectx, FALSE);
	handle->icethread = g_thread_new("ice thread", &janus_ice_thread, handle);
	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice */
	handle->agent = nice_agent_new(handle->icectx, NICE_COMPATIBILITY_DRAFT19);
	/* Any STUN server to use? */
	if(janus_stun_server != NULL && janus_stun_port > 0) {
		g_object_set (G_OBJECT(handle->agent),
			"stun-server", janus_stun_server,
			"stun-server-port", janus_stun_port,
			NULL);
	}
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", !offer, NULL);
	JANUS_PRINT("[%"SCNu64"] Creating ICE agent (%s mode)\n", handle->handle_id, offer ? "controlled" : "controlling");
	g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
	g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair",
		G_CALLBACK (janus_ice_cb_new_selected_pair), handle);
	/* Add one local address */
	NiceAddress addr_local;
	nice_address_init (&addr_local);
	nice_address_set_from_string (&addr_local, janus_get_local_ip());
	nice_agent_add_local_address (handle->agent, &addr_local);
	handle->streams_num = 0;
	handle->streams = g_hash_table_new(NULL, NULL);
	if(audio) {
		/* Add an audio stream */
		handle->streams_num++;
		handle->audio_id = nice_agent_add_stream (handle->agent, 2);
		janus_ice_stream *audio_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(audio_stream == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		audio_stream->stream_id = handle->audio_id;
		audio_stream->handle = handle;
		audio_stream->cdone = 0;
		audio_stream->payload_type = -1;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		audio_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		audio_stream->ssrc = 12345;	/* FIXME Should we make this dynamic? */
		audio_stream->ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		janus_mutex_init(&audio_stream->mutex);
		audio_stream->components = g_hash_table_new(NULL, NULL);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->audio_id), audio_stream);
		handle->audio_stream = audio_stream;
		janus_ice_component *audio_rtp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(audio_rtp == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		audio_rtp->stream = audio_stream;
		audio_rtp->candidates = NULL;
		janus_mutex_init(&audio_rtp->mutex);
		janus_ice_component *audio_rtcp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(audio_rtcp == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		audio_rtcp->stream = audio_stream;
		audio_rtcp->candidates = NULL;
		janus_mutex_init(&audio_rtcp->mutex);
		g_hash_table_insert(audio_stream->components, GUINT_TO_POINTER(1), audio_rtp);
		audio_stream->rtp_component = audio_rtp;
		g_hash_table_insert(audio_stream->components, GUINT_TO_POINTER(2), audio_rtcp);
		audio_stream->rtcp_component = audio_rtcp;
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->audio_id, 1, rtp_range_min, rtp_range_max);
		nice_agent_set_port_range(handle->agent, handle->audio_id, 2, rtp_range_min, rtp_range_max);
#endif
		nice_agent_gather_candidates (handle->agent, handle->audio_id);
		nice_agent_attach_recv (handle->agent, handle->audio_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtp);
		nice_agent_attach_recv (handle->agent, handle->audio_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, audio_rtcp);
	}
	if(video) {
		/* Add a video stream */
		handle->streams_num++;
		handle->video_id = nice_agent_add_stream (handle->agent, 2);
		janus_ice_stream *video_stream = (janus_ice_stream *)calloc(1, sizeof(janus_ice_stream));
		if(video_stream == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		video_stream->handle = handle;
		video_stream->stream_id = handle->video_id;
		video_stream->cdone = 0;
		video_stream->payload_type = -1;
		/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE... */
		video_stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
		video_stream->ssrc = 54321;	/* FIXME Should we make this dynamic? */
		video_stream->ssrc_peer = 0;	/* FIXME Right now we don't know what this will be */
		video_stream->components = g_hash_table_new(NULL, NULL);
		janus_mutex_init(&video_stream->mutex);
		g_hash_table_insert(handle->streams, GUINT_TO_POINTER(handle->video_id), video_stream);
		handle->video_stream = video_stream;
		janus_ice_component *video_rtp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(video_rtp == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		video_rtp->stream = video_stream;
		video_rtp->candidates = NULL;
		janus_mutex_init(&video_rtp->mutex);
		janus_ice_component *video_rtcp = (janus_ice_component *)calloc(1, sizeof(janus_ice_component));
		if(video_rtcp == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return -1;
		}
		video_rtcp->stream = video_stream;
		video_rtcp->candidates = NULL;
		janus_mutex_init(&video_rtcp->mutex);
		g_hash_table_insert(video_stream->components, GUINT_TO_POINTER(1), video_rtp);
		video_stream->rtp_component = video_rtp;
		g_hash_table_insert(video_stream->components, GUINT_TO_POINTER(2), video_rtcp);
		video_stream->rtcp_component = video_rtcp;
#ifdef HAVE_PORTRANGE
		/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! */
		nice_agent_set_port_range(handle->agent, handle->video_id, 1, rtp_range_min, rtp_range_max);
		nice_agent_set_port_range(handle->agent, handle->video_id, 2, rtp_range_min, rtp_range_max);
#endif
		nice_agent_gather_candidates (handle->agent, handle->video_id);
		nice_agent_attach_recv (handle->agent, handle->video_id, 1, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtp);
		nice_agent_attach_recv (handle->agent, handle->video_id, 2, g_main_loop_get_context (handle->iceloop), janus_ice_cb_nice_recv, video_rtcp);
	}
	return 0;
}

void janus_ice_relay_rtp(janus_ice_handle *handle, int video, char *buf, int len) {
	/* TODO Should we fix something in RTP header stuff too? */
	if(!handle)
		return;
	janus_ice_stream *stream = video ? handle->video_stream : handle->audio_stream;
	if(!stream)
		return;
	janus_ice_component *component = stream->rtp_component;
	if(!component)
		return;
	if(!stream->cdone) {
		if(!stream->noerrorlog) {
			JANUS_DEBUG("[%"SCNu64"]     %s candidates not gathered yet for stream??\n", handle->handle_id, video ? "video" : "audio");
			stream->noerrorlog = 1;	/* Don't flood with thre same error all over again */
		}
		return;
	}
	stream->noerrorlog = 0;
	if(!component->dtls || !component->dtls->srtp_valid) {
		if(!component->noerrorlog) {
			JANUS_DEBUG("[%"SCNu64"]     %s stream component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio");
			component->noerrorlog = 1;	/* Don't flood with thre same error all over again */
		}
		return;
	}
	component->noerrorlog = 0;
	/* FIXME Copy in a buffer and fix SSRC */
	char sbuf[BUFSIZE];
	memcpy(&sbuf, buf, len);
	rtp_header *header = (rtp_header *)&sbuf;
	header->ssrc = htonl(stream->ssrc);
	int protected = len;
	int res = srtp_protect(component->dtls->srtp_out, &sbuf, &protected);
	//~ JANUS_PRINT("[%"SCNu64"] ... SRTP protect %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), len, protected);
	if(res != err_status_ok) {
		JANUS_DEBUG("[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), len, protected);
	} else {
		/* Shoot! */
		//~ JANUS_PRINT("[%"SCNu64"] ... Sending SRTP packet (pt=%u, ssrc=%u, seq=%u, ts=%u)...\n", handle->handle_id,
			//~ header->type, ntohl(header->ssrc), ntohs(header->seq_number), ntohl(header->timestamp));
		int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const gchar *)&sbuf);
		if(sent < protected)
			JANUS_DEBUG("[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
	}
}

void janus_ice_relay_rtcp(janus_ice_handle *handle, int video, char *buf, int len) {
	if(!handle)
		return;
	janus_ice_stream *stream = video ? handle->video_stream : handle->audio_stream;
	if(!stream)
		return;
	janus_ice_component *component = stream->rtcp_component;
	if(!component)
		return;
	if(!stream->cdone) {
		if(!stream->noerrorlog) {
			JANUS_DEBUG("[%"SCNu64"]     %s candidates not gathered yet for stream??\n", handle->handle_id, video ? "video" : "audio");
			stream->noerrorlog = 1;	/* Don't flood with thre same error all over again */
		}
		return;
	}
	stream->noerrorlog = 0;
	if(!component->dtls || !component->dtls->srtp_valid) {
		if(!component->noerrorlog) {
			JANUS_DEBUG("[%"SCNu64"]     %s stream component has no valid SRTP session (yet?)\n", handle->handle_id, video ? "video" : "audio");
			component->noerrorlog = 1;	/* Don't flood with thre same error all over again */
		}
		return;
	}
	component->noerrorlog = 0;
	/* FIXME Copy in a buffer and fix SSRC */
	char sbuf[BUFSIZE];
	memcpy(&sbuf, buf, len);
	/* Fix all SSRCs! */
	JANUS_PRINT("[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id, stream->ssrc, stream->ssrc_peer);
	janus_rtcp_fix_ssrc((char *)&sbuf, len, 1, stream->ssrc, stream->ssrc_peer);
	int protected = len;
	int res = srtp_protect_rtcp(component->dtls->srtp_out, &sbuf, &protected);
	//~ JANUS_PRINT("[%"SCNu64"] ... SRTCP protect %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), len, protected);
	if(res != err_status_ok) {
		JANUS_DEBUG("[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_get_srtp_error(res), len, protected);
	} else {
		/* Shoot! */
		//~ JANUS_PRINT("[%"SCNu64"] ... Sending SRTCP packet (pt=%u, seq=%u, ts=%u)...\n", handle->handle_id,
			//~ header->paytype, ntohs(header->seq_number), ntohl(header->timestamp));
		int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, (const gchar *)&sbuf);
		if(sent < protected)
			JANUS_DEBUG("[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
	}
}

void janus_ice_dtls_handshake_done(janus_ice_handle *handle, janus_ice_component *component) {
	if(!handle || !component)
		return;
	JANUS_PRINT("[%"SCNu64"] The DTLS handshake for the component %d in stream %d has been completed\n",
		handle->handle_id, component->component_id, component->stream_id);
	/* Check if all components are ready */
	if(handle->audio_stream) {
		if(handle->audio_stream->rtp_component &&  handle->audio_stream->rtp_component->dtls &&
				!handle->audio_stream->rtp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			return;
		}
		if(handle->audio_stream->rtcp_component &&  handle->audio_stream->rtcp_component->dtls &&
				!handle->audio_stream->rtcp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			return;
		}
	}
	if(handle->video_stream) {
		if(handle->video_stream->rtp_component &&  handle->video_stream->rtp_component->dtls &&
				!handle->video_stream->rtp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			return;
		}
		if(handle->video_stream->rtcp_component &&  handle->video_stream->rtcp_component->dtls &&
				!handle->video_stream->rtcp_component->dtls->srtp_valid) {
			/* Still waiting for this component to become ready */
			return;
		}
	}
	/* Notify the plugin that the WebRTC PeerConnection is ready to be used */
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin != NULL) {
		JANUS_PRINT("[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
		if(plugin && plugin->setup_media)
			plugin->setup_media(handle->app_handle);
	}
}
