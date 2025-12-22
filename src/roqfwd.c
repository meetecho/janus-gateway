/*! \file    roqfwd.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP over QUIC (RoQ) forwarders
 * \details  Implementation of the same principle of RoQ forwarders,
 * but based on RTP over QUIC (RoQ), with ability to multiplex multiple
 * streams on top of the same connection. Only available if Janus was built
 * with <a href="https://imquic.conf.meetecho.com/">imquic</a> support.
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifdef HAVE_IMQUIC

#include "roqfwd.h"
#include "rtcp.h"
#include "utils.h"

/* Local resources */
static janus_mutex roqfwds_mutex = JANUS_MUTEX_INITIALIZER;
static GHashTable *roqfwds = NULL;

/* Static helper to quickly unref an RoQ forwarder instance */
static void janus_roq_forwarder_unref(janus_roq_forwarder *rf);
/* Static helper to free an RoQ forwarder instance when the reference goes to 0 */
static void janus_roq_forwarder_free(const janus_refcount *f_ref);

/* \brief RoQ forwarders code initialization
 * @returns 0 in case of success, a negative integer on errors */
int janus_roq_forwarders_init(void) {
	/* FIXME Initialize imquic */
	imquic_set_log_level(IMQUIC_LOG_INFO);
	if(imquic_init(NULL) < 0)
		return -1;
	/* Initialize the forwarders table */
	roqfwds = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)janus_roq_forwarder_unref);
	/* Donw */
	return 0;
}

/* \brief RoQ forwarders code de-initialization */
void janus_roq_forwarders_deinit(void) {
	/* Get rid of the table */
	janus_mutex_lock(&roqfwds_mutex);
	g_hash_table_destroy(roqfwds);
	roqfwds = NULL;
	janus_mutex_unlock(&roqfwds_mutex);
}

/* RoQ callbacks */
static void janus_roq_forwarders_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	JANUS_LOG(LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
	janus_roq_forwarder *rf = (janus_roq_forwarder *)user_data;
	janus_mutex_lock(&rf->mutex);
	rf->roq_conn = conn;
	janus_mutex_unlock(&rf->mutex);
}

static void janus_roq_forwarders_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	JANUS_LOG(LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	/* TODO */
	//~ if(conn == roq_conn)
		//~ imquic_connection_unref(conn);
}

/* Create a new forwarder */
janus_roq_forwarder *janus_roq_forwarder_create(const char *ctx, uint32_t id, const char *host, int port,
		void (*rtcp_callback)(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len)) {
	janus_mutex_lock(&roqfwds_mutex);
	if(ctx == NULL)
		ctx = "default";
	char uid[1024];
	if(id > 0) {
		/* Make sure the provided ID isn't already in use */
		g_snprintf(uid, sizeof(uid), "%s-%"SCNu32, ctx, id);
		if(g_hash_table_lookup(roqfwds, uid) != NULL) {
			janus_mutex_unlock(&roqfwds_mutex);
			JANUS_LOG(LOG_ERR, "RoQ forwarder with ID %"SCNu32" already exists in context '%s'\n",
				id, ctx);
			return NULL;
		}
	} else {
		/* Autogenerate an ID within the provided context */
		id = janus_random_uint32();
		g_snprintf(uid, sizeof(uid), "%s-%"SCNu32, ctx, id);
		while(g_hash_table_lookup(roqfwds, uid)) {
			id = janus_random_uint32();
			g_snprintf(uid, sizeof(uid), "%s-%"SCNu32, ctx, id);
		}
	}
	/* Create the forwarder */
	janus_roq_forwarder *rf = g_malloc0(sizeof(janus_roq_forwarder));
	rf->roq_client = imquic_create_roq_client(uid,
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_REMOTE_HOST, host,
		IMQUIC_CONFIG_REMOTE_PORT, port,
		IMQUIC_CONFIG_RAW_QUIC, TRUE,		/* FIXME */
		IMQUIC_CONFIG_WEBTRANSPORT, FALSE,	/* FIXME */
		IMQUIC_CONFIG_USER_DATA, rf,
		IMQUIC_CONFIG_DONE, NULL);
	if(rf->roq_client == NULL) {
		janus_mutex_unlock(&roqfwds_mutex);
		g_free(rf);
		return NULL;
	}
	imquic_set_new_roq_connection_cb(rf->roq_client, janus_roq_forwarders_new_connection);
	imquic_set_roq_connection_gone_cb(rf->roq_client, janus_roq_forwarders_connection_gone);
	/* Configure the forwarder */
	rf->context = g_strdup(ctx);
	rf->id = id;
	rf->flows = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)g_free);
	janus_mutex_init(&rf->mutex);
	janus_refcount_init(&rf->ref, janus_roq_forwarder_free);
	janus_refcount_increase(&rf->ref);
	g_hash_table_insert(roqfwds, g_strdup(uid), rf);
	janus_mutex_unlock(&roqfwds_mutex);
	imquic_start_endpoint(rf->roq_client);
	/* Done */
	return rf;
}

/* Add a flow */
int janus_roq_forwarder_add_flow(janus_roq_forwarder *rf, uint64_t flow_id,
		uint32_t ssrc, int pt, gboolean simulcast, int substream, gboolean is_video) {
	if(!rf || g_atomic_int_get(&rf->destroyed))
		return -1;
	janus_mutex_lock(&rf->mutex);
	if(g_hash_table_lookup(rf->flows, &flow_id) != NULL) {
		janus_mutex_unlock(&rf->mutex);
		JANUS_LOG(LOG_WARN, "[RoQ][%s-%"SCNu32"][%"SCNu64"] Flow already exists...\n",
			rf->context, rf->id, flow_id);
		return -1;
	}
	janus_roq_forwarder_flow *flow = g_malloc0(sizeof(janus_roq_forwarder_flow));
	flow->flow_id = flow_id;
	flow->is_video = is_video;
	flow->ssrc = ssrc;
	flow->payload_type = pt;
	flow->substream = substream;
	if(is_video && simulcast) {
		flow->simulcast = TRUE;
		janus_rtp_switching_context_reset(&flow->rtp_context);
		janus_rtp_simulcasting_context_reset(&flow->sim_context);
		flow->sim_context.substream_target = 2;
		flow->sim_context.templayer_target = 2;
	}
	g_hash_table_insert(rf->flows, janus_uint64_dup(flow_id), flow);
	janus_mutex_unlock(&rf->mutex);
	return 0;
}

/* Remove a flow */
int janus_roq_forwarder_remove_flow(janus_roq_forwarder *rf, uint64_t flow_id) {
	if(!rf || g_atomic_int_get(&rf->destroyed))
		return -1;
	janus_mutex_lock(&rf->mutex);
	gboolean removed = g_hash_table_remove(rf->flows, &flow_id);
	janus_mutex_unlock(&rf->mutex);
	return removed ? 0 : -1;
}

/* Simplified frontend to the forwarder function */
void janus_roq_forwarder_send_rtp(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len, int substream) {
	janus_roq_forwarder_send_rtp_full(rf, flow_id, buffer, len, substream, NULL, NULL, JANUS_VIDEOCODEC_NONE, NULL);
}

/* Helper function to forward an RTP packet within the context of a forwarder */
void janus_roq_forwarder_send_rtp_full(janus_roq_forwarder *rf, uint64_t flow_id, char *buffer, int len,
		int substream, uint32_t *ssrcs, char **rids, janus_videocodec vcodec, janus_mutex *rid_mutex) {
	if(!rf || g_atomic_int_get(&rf->destroyed) || !buffer || !janus_is_rtp(buffer, len))
		return;
	janus_mutex_lock(&rf->mutex);
	janus_roq_forwarder_flow *flow = g_hash_table_lookup(rf->flows, &flow_id);
	if(flow == NULL || !rf->roq_conn) {
		janus_mutex_unlock(&rf->mutex);
		return;
	}
	/* Access the RTP header */
	janus_rtp_header *rtp = (janus_rtp_header *)buffer;
	/* Backup the RTP header info, as we may rewrite part of it */
	uint32_t seq_number = ntohs(rtp->seq_number);
	uint32_t timestamp = ntohl(rtp->timestamp);
	int pt = rtp->type;
	uint32_t ssrc = ntohl(rtp->ssrc);
	/* First of all, check if we're simulcasting and if we need to forward or ignore this frame */
	if(flow->is_video && !flow->simulcast && flow->substream != substream) {
		/* We're being asked to forward a specific substream, and it's not it */
		return;
	}
	if(flow->is_video && flow->simulcast) {
		/* This is video and we're simulcasting, check if we need to forward this frame */
		if(!janus_rtp_simulcasting_context_process_rtp(&flow->sim_context,
				buffer, len, NULL, 0, ssrcs, rids, vcodec, &flow->rtp_context, rid_mutex)) {
			/* There was an error processing simulcasting for this packet */
			return;
		}
		janus_rtp_header_update(rtp, &flow->rtp_context, TRUE, 0);
	}
	/* Check if payload type and/or SSRC need to be overwritten for this forwarder */
	if(flow->payload_type > 0)
		rtp->type = flow->payload_type;
	if(flow->ssrc > 0)
		rtp->ssrc = htonl(flow->ssrc);
	/* FIXME Send the packet */
	if(imquic_roq_send_rtp(rf->roq_conn, IMQUIC_ROQ_DATAGRAM, flow->flow_id, (uint8_t *)buffer, len, FALSE) == 0) {
		JANUS_LOG(LOG_WARN, "[RoQ][%s-%"SCNu32"][%"SCNu64"] Couldn't send RTP packet...\n",
			rf->context, rf->id, flow->flow_id);
	}
	/* Restore original values of the RTP payload before returning */
	rtp->type = pt;
	rtp->ssrc = htonl(ssrc);
	rtp->timestamp = htonl(timestamp);
	rtp->seq_number = htons(seq_number);
	janus_mutex_unlock(&rf->mutex);
}

/* Mark an RoQ forwarder instance as destroyed */
void janus_roq_forwarder_destroy(janus_roq_forwarder *rf) {
	if(rf && g_atomic_int_compare_and_exchange(&rf->destroyed, 0, 1)) {
		char id[1024];
		g_snprintf(id, sizeof(id), "%s-%"SCNu32, rf->context, rf->id);
		janus_mutex_lock(&roqfwds_mutex);
		if(roqfwds != NULL)
			g_hash_table_remove(roqfwds, id);
		janus_mutex_unlock(&roqfwds_mutex);
		imquic_shutdown_endpoint(rf->roq_client);
		rf->roq_client = NULL;
		janus_refcount_decrease(&rf->ref);
	}
}

/* Static helper to quickly unref an RoQ forwarder instance */
static void janus_roq_forwarder_unref(janus_roq_forwarder *rf) {
	if(rf)
		janus_refcount_decrease(&rf->ref);
}

/* Static helper to free an RoQ forwarder instance when the reference goes to 0 */
static void janus_roq_forwarder_free(const janus_refcount *f_ref) {
	janus_roq_forwarder *rf = janus_refcount_containerof(f_ref, janus_roq_forwarder, ref);
	/* TODO RoQ stuff */
	g_hash_table_destroy(rf->flows);
	janus_mutex_destroy(&rf->mutex);
	g_free(rf->context);
	g_free(rf->metadata);
	g_free(rf);
}

#endif
