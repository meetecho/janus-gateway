/*! \file    rtpfwd.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP forwarders
 * \details  Implementation of the so called RTP forwarders, that is an
 * helper mechanism that core and/or plugins can make use of to quickly
 * and simply forward RTP streams to a separate UDP address out of the
 * context of any signalling. Such a mechanism can be used, for instance,
 * for scalabiloty purposes, monitoring, or feeding external applications
 * with media traffic handled by Janus..
 *
 * \ingroup protocols
 * \ref protocols
 */

#include "rtpfwd.h"
#include "rtcp.h"
#include "utils.h"

/* Local resources */
static janus_mutex rtpfwds_mutex = JANUS_MUTEX_INITIALIZER;
static GHashTable *rtpfwds = NULL;
static gboolean ipv6_disabled = FALSE;
/* RTCP stuff */
static GMainContext *rtcpfwd_ctx = NULL;
static GMainLoop *rtcpfwd_loop = NULL;
static GThread *rtcpfwd_thread = NULL;
static void *janus_rtp_forwarder_rtcp_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining RTCP thread for RTP forwarders...\n");
	/* Run the main loop */
	g_main_loop_run(rtcpfwd_loop);
	/* When the loop ends, we're done */
	JANUS_LOG(LOG_VERB, "Leaving RTCP thread for RTP forwarders...\n");
	return NULL;
}

/* Static helper to quickly unref an RTP forwarder instance */
static void janus_rtp_forwarder_unref(janus_rtp_forwarder *rf);
/* Static helper to free an RTP forwarder instance when the reference goes to 0 */
static void janus_rtp_forwarder_free(const janus_refcount *f_ref);

/* \brief RTP forwarders code initialization
 * @returns 0 in case of success, a negative integer on errors */
int janus_rtp_forwarders_init(void) {
	/* Initialize the forwarders table and muted */
	rtpfwds = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_rtp_forwarder_unref);
	/* Let's check if IPv6 is disabled, as we may need to know for forwarders */
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if(fd < 0) {
		ipv6_disabled = TRUE;
	} else {
		int v6only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0)
			ipv6_disabled = TRUE;
	}
	if(fd >= 0)
		close(fd);
	if(ipv6_disabled) {
		JANUS_LOG(LOG_WARN, "IPv6 disabled, will only create RTP forwarders to IPv4 addresses\n");
	}
	/* Spawn the thread for handling incoming RTCP packets from RTP forwarders, if any */
	rtcpfwd_ctx = g_main_context_new();
	rtcpfwd_loop = g_main_loop_new(rtcpfwd_ctx, FALSE);
	GError *error = NULL;
	rtcpfwd_thread = g_thread_try_new("rtcpfwd", janus_rtp_forwarder_rtcp_thread, NULL, &error);
	if(error != NULL) {
		/* We show the error but it's not fatal */
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the RTCP thread for RTP forwarders...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	/* Donw */
	return 0;
}

/* \brief RTP forwarders code de-initialization */
void janus_rtp_forwarders_deinit(void) {
	/* Stop the RTCP receiver thread */
	if(rtcpfwd_thread != NULL) {
		if(g_main_loop_is_running(rtcpfwd_loop)) {
			g_main_loop_quit(rtcpfwd_loop);
			g_main_context_wakeup(rtcpfwd_ctx);
		}
		g_thread_join(rtcpfwd_thread);
		rtcpfwd_thread = NULL;
	}
	/* Get rid of the table */
	janus_mutex_lock(&rtpfwds_mutex);
	g_hash_table_destroy(rtpfwds);
	rtpfwds = NULL;
	janus_mutex_unlock(&rtpfwds_mutex);
}

/* RTCP support in RTP forwarders */
typedef struct janus_rtcp_receiver {
	GSource parent;
	janus_rtp_forwarder *rf;
	GDestroyNotify destroy;
} janus_rtcp_receiver;
static void janus_rtp_forwarder_rtcp_receive(janus_rtp_forwarder *rf) {
	char buffer[1500];
	struct sockaddr_storage remote_addr;
	socklen_t addrlen = sizeof(remote_addr);
	int len = recvfrom(rf->rtcp_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote_addr, &addrlen);
	if(len > 0 && janus_is_rtcp(buffer, len)) {
		JANUS_LOG(LOG_HUGE, "Got %s RTCP packet: %d bytes\n", rf->is_video ? "video" : "audio", len);
		/* Invoke the callback function for RTCP feedback, if any */
		if(rf->rtcp_callback)
			rf->rtcp_callback(rf, buffer, len);
	}
}
static gboolean janus_rtp_forwarder_rtcp_prepare(GSource *source, gint *timeout) {
	*timeout = -1;
	return FALSE;
}
static gboolean janus_rtp_forwarder_rtcp_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	janus_rtcp_receiver *rr = (janus_rtcp_receiver *)source;
	/* Receive the packet */
	if(rr)
		janus_rtp_forwarder_rtcp_receive(rr->rf);
	return G_SOURCE_CONTINUE;
}
static void janus_rtp_forwarder_rtcp_finalize(GSource *source) {
	janus_rtcp_receiver *rr = (janus_rtcp_receiver *)source;
	/* Remove the reference to the forwarder */
	if(rr && rr->rf) {
		if(rr->rf->source) {
			//~ janus_publisher_stream_dereference_void(r->forward->source);
			rr->rf->source = NULL;
		}
		janus_rtp_forwarder_unref(rr->rf);
	}
}
static GSourceFuncs janus_rtp_forwarder_rtcp_funcs = {
	janus_rtp_forwarder_rtcp_prepare,
	NULL,
	janus_rtp_forwarder_rtcp_dispatch,
	janus_rtp_forwarder_rtcp_finalize,
	NULL, NULL
};

/* Create a new forwarder */
janus_rtp_forwarder *janus_rtp_forwarder_create(const char *ctx,
		uint32_t stream_id, int udp_fd, const char *host, int port,
		uint32_t ssrc, int pt, int srtp_suite, const char *srtp_crypto,
		gboolean simulcast, int substream, gboolean is_video, gboolean is_data) {
	janus_mutex_lock(&rtpfwds_mutex);
	if(ctx == NULL)
		ctx = "default";
	char id[1024];
	if(stream_id > 0) {
		/* Make sure the provided ID isn't already in use */
		g_snprintf(id, sizeof(id), "%s-%"SCNu32, ctx, stream_id);
		if(g_hash_table_lookup(rtpfwds, id) != NULL) {
			janus_mutex_unlock(&rtpfwds_mutex);
			JANUS_LOG(LOG_ERR, "RTP forwarder with ID %"SCNu32" already exists in context '%s'\n",
				stream_id, ctx);
			return NULL;
		}
	} else {
		/* Autogenerate an ID within the provided context */
		stream_id = janus_random_uint32();
		g_snprintf(id, sizeof(id), "%s-%"SCNu32, ctx, stream_id);
		while(g_hash_table_lookup(rtpfwds, id)) {
			stream_id = janus_random_uint32();
			g_snprintf(id, sizeof(id), "%s-%"SCNu32, ctx, stream_id);
		}
	}
	janus_rtp_forwarder *rf = g_malloc0(sizeof(janus_rtp_forwarder));
	rf->udp_fd = udp_fd;	/* FIXME Should we create one ourselves, if not provided? */
	/* RTCP may be added later */
	rf->rtcp_fd = -1;
	rf->local_rtcp_port = 0;
	rf->remote_rtcp_port = 0;
	/* First of all, let's check if we need to setup an SRTP forwarder */
	if(!is_data && srtp_suite > 0 && srtp_crypto != NULL) {
		/* Base64 decode the crypto string and set it as the SRTP context */
		gsize len = 0;
		guchar *decoded = g_base64_decode(srtp_crypto, &len);
		if(len < SRTP_MASTER_LENGTH) {
			janus_mutex_unlock(&rtpfwds_mutex);
			JANUS_LOG(LOG_ERR, "Invalid SRTP crypto (%s)\n", srtp_crypto);
			g_free(decoded);
			g_free(rf);
			return NULL;
		}
		/* Set SRTP policy */
		srtp_policy_t *policy = &rf->srtp_policy;
		srtp_crypto_policy_set_rtp_default(&(policy->rtp));
		if(srtp_suite == 32) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(policy->rtp));
		} else if(srtp_suite == 80) {
			srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(policy->rtp));
		}
		policy->ssrc.type = ssrc_any_outbound;
		policy->key = decoded;
		policy->next = NULL;
		/* Create SRTP context */
		srtp_err_status_t res = srtp_create(&rf->srtp_ctx, policy);
		if(res != srtp_err_status_ok) {
			/* Something went wrong... */
			janus_mutex_unlock(&rtpfwds_mutex);
			JANUS_LOG(LOG_ERR, "Error creating forwarder SRTP session: %d (%s)\n", res, janus_srtp_error_str(res));
			g_free(decoded);
			policy->key = NULL;
			g_free(rf);
			return NULL;
		}
		rf->is_srtp = TRUE;
	}
	rf->is_video = is_video;
	rf->payload_type = pt;
	rf->ssrc = ssrc;
	rf->substream = substream;
	rf->is_data = is_data;
	/* Check if the host address is IPv4 or IPv6 */
	if(strstr(host, ":") != NULL) {
		rf->serv_addr6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host, &(rf->serv_addr6.sin6_addr));
		rf->serv_addr6.sin6_port = htons(port);
	} else {
		rf->serv_addr.sin_family = AF_INET;
		inet_pton(AF_INET, host, &(rf->serv_addr.sin_addr));
		rf->serv_addr.sin_port = htons(port);
	}
	if(is_video && simulcast) {
		rf->simulcast = TRUE;
		janus_rtp_switching_context_reset(&rf->rtp_context);
		janus_rtp_simulcasting_context_reset(&rf->sim_context);
		rf->sim_context.substream_target = 2;
		rf->sim_context.templayer_target = 2;
	}
	janus_refcount_init(&rf->ref, janus_rtp_forwarder_free);
	rf->context = g_strdup(ctx);
	rf->stream_id = stream_id;
	janus_refcount_increase(&rf->ref);
	g_hash_table_insert(rtpfwds, g_strdup(id), rf);
	janus_mutex_unlock(&rtpfwds_mutex);
	/* Done */
	return rf;
}

/* Add RTCP support to an existing RTP forwarder */
int janus_rtp_forwarder_add_rtcp(janus_rtp_forwarder *rf, int rtcp_port,
		void (*rtcp_callback)(janus_rtp_forwarder *rf, char *buffer, int len)) {
	if(rf == NULL || g_atomic_int_get(&rf->destroyed) || rf->rtcp_fd > 0 || rtcp_port < 1 || rf->is_data)
		return -1;
	/* Bind to a port for RTCP */
	uint16_t local_rtcp_port = 0;
	int fd = socket(!ipv6_disabled ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(fd < 0) {
		JANUS_LOG(LOG_ERR, "Error creating RTCP socket for new RTP forwarder... %d (%s)\n",
			errno, g_strerror(errno));
		return -4;
	}
	struct sockaddr *address = NULL;
	struct sockaddr_in addr4 = { 0 };
	struct sockaddr_in6 addr6 = { 0 };
	socklen_t len = 0;
	if(!ipv6_disabled) {
		/* Configure the socket so that it can be used both on IPv4 and IPv6 */
		int v6only = 0;
		if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
			JANUS_LOG(LOG_ERR, "Error configuring RTCP socket for new RTP forwarder... %d (%s)\n",
				errno, g_strerror(errno));
			close(fd);
			return -5;
		}
		len = sizeof(addr6);
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(0);		/* The RTCP port we received is the remote one */
		addr6.sin6_addr = in6addr_any;
		address = (struct sockaddr *)&addr6;
	} else {
		/* IPv6 is disabled, only do IPv4 */
		len = sizeof(addr4);
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(0);		/* The RTCP port we received is the remote one */
		addr4.sin_addr.s_addr = INADDR_ANY;
		address = (struct sockaddr *)&addr4;
	}
	if(bind(fd, (struct sockaddr *)address, len) < 0 ||
			getsockname(fd, (struct sockaddr *)address, &len) < 0) {
		JANUS_LOG(LOG_ERR, "Error binding RTCP socket for new RTP forwarder... %d (%s)\n",
			errno, g_strerror(errno));
		close(fd);
		return -6;
	}
	local_rtcp_port = ntohs(!ipv6_disabled ? addr6.sin6_port : addr4.sin_port);
	JANUS_LOG(LOG_HUGE, "Bound RTP forwarder's local %s RTCP port: %"SCNu16"\n",
		rf->is_video ? "video" : "audio", local_rtcp_port);
	/* Update the forwarder, and create a source for the loop */
	rf->rtcp_fd = fd;
	rf->remote_rtcp_port = rtcp_port;
	rf->local_rtcp_port = local_rtcp_port;
	rf->rtcp_callback = rtcp_callback;
	rf->rtcp_recv = g_source_new(&janus_rtp_forwarder_rtcp_funcs, sizeof(janus_rtcp_receiver));
	janus_rtcp_receiver *rr = (janus_rtcp_receiver *)rf->rtcp_recv;
	janus_refcount_increase(&rf->ref);
	rr->rf = rf;
	g_source_set_priority(rf->rtcp_recv, G_PRIORITY_DEFAULT);
	g_source_add_unix_fd(rf->rtcp_recv, fd, G_IO_IN | G_IO_ERR);
	g_source_attach((GSource *)rf->rtcp_recv, rtcpfwd_ctx);
	/* Send a couple of empty RTP packets to the remote port to do latching */
	JANUS_LOG(LOG_HUGE, "Latching to remote %s RTCP port: %"SCNu16"\n",
		rf->is_video ? "video" : "audio", local_rtcp_port);
	socklen_t addrlen = 0;
	if(rf->serv_addr.sin_family == AF_INET) {
		addr4.sin_family = AF_INET;
		addr4.sin_addr.s_addr = rf->serv_addr.sin_addr.s_addr;
		addr4.sin_port = htons(rf->remote_rtcp_port);
		address = (struct sockaddr *)&addr4;
		addrlen = sizeof(addr4);
	} else {
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr, &rf->serv_addr6.sin6_addr, sizeof(struct in6_addr));
		addr6.sin6_port = htons(rf->remote_rtcp_port);
		address = (struct sockaddr *)&addr6;
		addrlen = sizeof(addr6);
	}
	janus_rtp_header rtp = { 0 };
	rtp.version = 2;
	(void)sendto(fd, &rtp, 12, 0, address, addrlen);
	(void)sendto(fd, &rtp, 12, 0, address, addrlen);
	/* Done */
	return 0;
}

/* Simplified frontend to the forwarder function */
void janus_rtp_forwarder_send_rtp(janus_rtp_forwarder *rf, char *buffer, int len, int substream) {
	janus_rtp_forwarder_send_rtp_full(rf, buffer, len, substream, NULL, NULL, JANUS_VIDEOCODEC_NONE, NULL);
}

/* Helper function to forward an RTP packet within the context of a forwarder */
void janus_rtp_forwarder_send_rtp_full(janus_rtp_forwarder *rf, char *buffer, int len, int substream,
		uint32_t *ssrcs, char **rids, janus_videocodec vcodec, janus_mutex *rid_mutex) {
	if(!rf || g_atomic_int_get(&rf->destroyed) || !buffer || !janus_is_rtp(buffer, len))
		return;
	/* Access the RTP header */
	janus_rtp_header *rtp = (janus_rtp_header *)buffer;
	/* Backup the RTP header info, as we may rewrite part of it */
	uint32_t seq_number = ntohs(rtp->seq_number);
	uint32_t timestamp = ntohl(rtp->timestamp);
	int pt = rtp->type;
	uint32_t ssrc = ntohl(rtp->ssrc);
	/* First of all, check if we're simulcasting and if we need to forward or ignore this frame */
	if(rf->is_video && !rf->simulcast && rf->substream != substream) {
		/* We're being asked to forward a specific substream, and it's not it */
		return;
	}
	if(rf->is_video && rf->simulcast) {
		/* This is video and we're simulcasting, check if we need to forward this frame */
		if(!janus_rtp_simulcasting_context_process_rtp(&rf->sim_context,
				buffer, len, NULL, 0, ssrcs, rids, vcodec, &rf->rtp_context, rid_mutex)) {
			/* There was an error processing simulcasting for this packet */
			return;
		}
		janus_rtp_header_update(rtp, &rf->rtp_context, TRUE, 0);
		/* By default we use a fixed SSRC (it may be overwritten later) */
		rtp->ssrc = htonl(rf->stream_id);
	}
	/* Check if payload type and/or SSRC need to be overwritten for this forwarder */
	if(rf->payload_type > 0)
		rtp->type = rf->payload_type;
	if(rf->ssrc > 0)
		rtp->ssrc = htonl(rf->ssrc);
	/* Check if this is an RTP or SRTP forwarder */
	if(!rf->is_srtp) {
		/* Plain RTP */
		struct sockaddr *address = (rf->serv_addr.sin_family == AF_INET ?
			(struct sockaddr *)&rf->serv_addr : (struct sockaddr *)&rf->serv_addr6);
		size_t addrlen = (rf->serv_addr.sin_family == AF_INET ? sizeof(rf->serv_addr) : sizeof(rf->serv_addr6));
		if(sendto(rf->udp_fd, buffer, len, 0, address, addrlen) < 0) {
			JANUS_LOG(LOG_HUGE, "Error forwarding RTP %s packet... %s (len=%d)...\n",
				(rf->is_video ? "video" : "audio"), g_strerror(errno), len);
		}
	} else {
		/* SRTP: encrypt the packet before sending it */
		char sbuf[1500];
		memcpy(sbuf, buffer, len);
		int protected = len;
		int res = srtp_protect(rf->srtp_ctx, sbuf, &protected);
		if(res != srtp_err_status_ok) {
			janus_rtp_header *header = (janus_rtp_header *)sbuf;
			guint32 timestamp = ntohl(header->timestamp);
			guint16 seq = ntohs(header->seq_number);
			JANUS_LOG(LOG_ERR, "Error encrypting %s packet... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
				(rf->is_video ? "Video" : "Audio"), janus_srtp_error_str(res), len, protected, timestamp, seq);
		} else {
			struct sockaddr *address = (rf->serv_addr.sin_family == AF_INET ?
				(struct sockaddr *)&rf->serv_addr : (struct sockaddr *)&rf->serv_addr6);
			size_t addrlen = (rf->serv_addr.sin_family == AF_INET ? sizeof(rf->serv_addr) : sizeof(rf->serv_addr6));
			if(sendto(rf->udp_fd, sbuf, protected, 0, address, addrlen) < 0) {
				JANUS_LOG(LOG_HUGE, "Error forwarding SRTP %s packet... %s (len=%d)...\n",
					(rf->is_video ? "video" : "audio"), g_strerror(errno), protected);
			}
		}
	}
	/* Restore original values of the RTP payload before returning */
	rtp->type = pt;
	rtp->ssrc = htonl(ssrc);
	rtp->timestamp = htonl(timestamp);
	rtp->seq_number = htons(seq_number);
}

/* Mark an RTP forwarder instance as destroyed */
void janus_rtp_forwarder_destroy(janus_rtp_forwarder *rf) {
	if(rf && g_atomic_int_compare_and_exchange(&rf->destroyed, 0, 1)) {
		if(rf->rtcp_fd > -1 && rf->rtcp_recv != NULL) {
			g_source_destroy(rf->rtcp_recv);
			g_source_unref(rf->rtcp_recv);
		}
		char id[1024];
		g_snprintf(id, sizeof(id), "%s-%"SCNu32, rf->context, rf->stream_id);
		janus_mutex_lock(&rtpfwds_mutex);
		if(rtpfwds != NULL)
			g_hash_table_remove(rtpfwds, id);
		janus_mutex_unlock(&rtpfwds_mutex);
		janus_refcount_decrease(&rf->ref);
	}
}

/* Static helper to quickly unref an RTP forwarder instance */
static void janus_rtp_forwarder_unref(janus_rtp_forwarder *rf) {
	if(rf)
		janus_refcount_decrease(&rf->ref);
}

/* Static helper to free an RTP forwarder instance when the reference goes to 0 */
static void janus_rtp_forwarder_free(const janus_refcount *f_ref) {
	janus_rtp_forwarder *rf = janus_refcount_containerof(f_ref, janus_rtp_forwarder, ref);
	if(rf->rtcp_fd > -1)
		close(rf->rtcp_fd);
	if(rf->is_srtp) {
		srtp_dealloc(rf->srtp_ctx);
		g_free(rf->srtp_policy.key);
	}
	g_free(rf->context);
	g_free(rf->metadata);
	g_free(rf);
}
