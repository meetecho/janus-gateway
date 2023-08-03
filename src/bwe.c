/*! \file    bwe.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Bandwidth estimation tools
 * \details  Implementation of a basic bandwidth estimator for outgoing
 * RTP flows, based on Transport Wide CC and a few other utilities.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <inttypes.h>
#include <string.h>

#include "bwe.h"
#include "debug.h"
#include "utils.h"

const char *janus_bwe_twcc_status_description(janus_bwe_twcc_status status) {
	switch(status) {
		case janus_bwe_twcc_status_notreceived:
			return "notreceived";
		case janus_bwe_twcc_status_smalldelta:
			return "smalldelta";
		case janus_bwe_twcc_status_largeornegativedelta:
			return "largeornegativedelta";
		case janus_bwe_twcc_status_reserved:
			return "reserved";
		default: break;
	}
	return NULL;
}

static void janus_bwe_twcc_inflight_destroy(janus_bwe_twcc_inflight *stat) {
	g_free(stat);
}

janus_bwe_context *janus_bwe_context_create(void) {
	janus_bwe_context *bwe = g_malloc0(sizeof(janus_bwe_context));
	/* TODO */
	bwe->packets = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_bwe_twcc_inflight_destroy);
	return bwe;
}

void janus_bwe_context_destroy(janus_bwe_context *bwe) {
	if(bwe) {
		/* TODO clean everything up */
		g_hash_table_destroy(bwe->packets);
		g_free(bwe);
	}
}

gboolean janus_bwe_context_add_inflight(janus_bwe_context *bwe,
		uint16_t seq, int64_t sent, janus_bwe_packet_type type, int size) {
	if(bwe == NULL)
		return FALSE;
	janus_bwe_twcc_inflight *stat = g_malloc(sizeof(janus_bwe_twcc_inflight));
	stat->seq = seq;
	stat->sent_ts = sent;
	stat->delta_us = bwe->last_sent_ts ? (sent - bwe->last_sent_ts) : 0;
	bwe->last_sent_ts = sent;
	stat->type = type;
	stat->size = size;
	bwe->sent_bytes += size;
	g_hash_table_insert(bwe->packets, GUINT_TO_POINTER(seq), stat);
	return TRUE;
}

void janus_bwe_context_handle_feedback(janus_bwe_context *bwe,
		uint16_t seq, janus_bwe_twcc_status status, int64_t delta_us, gboolean first) {
	if(bwe == NULL)
		return;
	/* Find the inflight information we stored when sending this packet */
	janus_bwe_twcc_inflight *p = g_hash_table_lookup(bwe->packets, GUINT_TO_POINTER(seq));
	if(p == NULL) {
		JANUS_LOG(LOG_WARN, "[BWE] [%"SCNu16"] not found in inflight packets table\n", seq);
		return;
	}
	/* The first recv delta is relative to the reference time, not to the previous packet */
	if(!first) {
		int64_t send_delta_us = 0;
		if(seq == bwe->last_recv_seq + 1) {
			send_delta_us = p->delta_us;
		} else {
			janus_bwe_twcc_inflight *prev_p = g_hash_table_lookup(bwe->packets, GUINT_TO_POINTER(bwe->last_recv_seq));
			if(prev_p != NULL) {
				send_delta_us = p->sent_ts - prev_p->sent_ts;
			} else {
				JANUS_LOG(LOG_WARN, "[BWE] [%"SCNu16"] not found in inflight packets table\n", bwe->last_recv_seq);
			}
		}
		int64_t rounded_delta_us = (send_delta_us / 250) * 250;
		int64_t diff_us = delta_us - rounded_delta_us;
		bwe->delay += diff_us;
		JANUS_LOG(LOG_HUGE, "[BWE] [%"SCNu16"] %s (%"SCNi64"us) (send: %"SCNi64"us) diff_us=%"SCNi64"\n", seq,
			janus_bwe_twcc_status_description(status), delta_us, rounded_delta_us, diff_us);
	}
	if(status != janus_bwe_twcc_status_notreceived) {
		bwe->received_bytes += p->size;
		bwe->received_pkts++;
		bwe->last_recv_seq = seq;
	}
}

void janus_bwe_context_update(janus_bwe_context *bwe) {
	if(bwe == NULL)
		return;
	int64_t now = janus_get_monotonic_time();
	if(bwe->bitrate_ts == 0)
		bwe->bitrate_ts = now;
	/* Reset the outgoing and (acked) incoming bitrate, and estimate the bitrate */
	if(now > bwe->bitrate_ts) {
		/* TODO Actually estimate the bitrate: now we're just checking how
		 * much the peer received out of what we sent, which is not enough */
		int64_t diff = now - bwe->bitrate_ts;
		double ratio = (double)G_USEC_PER_SEC / (double)diff;
		double estimate_bytes = ratio * bwe->received_bytes;
		bwe->estimate = 8 * estimate_bytes;
		bwe->bitrate_ts = now;
	}
	JANUS_LOG(LOG_WARN, "[BWE] sent=%"SCNu32"kbps, received=%"SCNu32"kbps, avg_delay=%.2fms\n",
		(bwe->sent_bytes / 1000) * 8, (bwe->received_bytes / 1000) * 8, ((double)bwe->delay / (double)bwe->received_pkts) / 1000);
	bwe->sent_bytes = 0;
	bwe->received_bytes = 0;
	bwe->delay = 0;
	bwe->received_pkts = 0;
}

janus_bwe_stream_bitrate *janus_bwe_stream_bitrate_create(void) {
	janus_bwe_stream_bitrate *bwe_sb = g_malloc0(sizeof(janus_bwe_stream_bitrate));
	janus_mutex_init(&bwe_sb->mutex);
	return bwe_sb;
}

void janus_bwe_stream_bitrate_update(janus_bwe_stream_bitrate *bwe_sb, int64_t when, int sl, int tl, int size) {
	if(bwe_sb == NULL || sl < 0 || sl > 2 || tl > 2)
		return;
	if(tl < 0)
		tl = 0;
	int i = 0;
	int64_t cleanup_ts = when - G_USEC_PER_SEC;
	janus_mutex_lock(&bwe_sb->mutex);
	for(i=tl; i<3; i++) {
		if(i <= tl && bwe_sb->packets[sl*3 + i] == NULL)
			bwe_sb->packets[sl*3 + i] = g_queue_new();
		if(bwe_sb->packets[sl*3 + i] == NULL)
			continue;
		/* Check if we need to get rid of some old packets */
		janus_bwe_stream_packet *sp = g_queue_peek_head(bwe_sb->packets[sl*3 + i]);
		while(sp && sp->sent_ts < cleanup_ts) {
			sp = g_queue_pop_head(bwe_sb->packets[sl*3 + i]);
			if(bwe_sb->bitrate[sl*3 + i] >= sp->size)
				bwe_sb->bitrate[sl*3 + i] -= sp->size;
			g_free(sp);
			sp = g_queue_peek_head(bwe_sb->packets[sl*3 + i]);
		}
		/* Check if there's anything new we need to add now */
		if(size > 0) {
			sp = g_malloc(sizeof(janus_bwe_stream_packet));
			sp->sent_ts = when;
			sp->size = size*8;
			bwe_sb->bitrate[sl*3 + i] += sp->size;
			g_queue_push_tail(bwe_sb->packets[sl*3 + i], sp);
		}
	}
	janus_mutex_unlock(&bwe_sb->mutex);
}

void janus_bwe_stream_bitrate_destroy(janus_bwe_stream_bitrate *bwe_sb) {
	if(bwe_sb == NULL)
		return;
	janus_mutex_lock(&bwe_sb->mutex);
	for(int i=0; i<9; i++) {
		if(bwe_sb->packets[i] != NULL) {
			g_queue_free_full(bwe_sb->packets[i], (GDestroyNotify)g_free);
			bwe_sb->packets[i] = NULL;
		}
	}
	janus_mutex_unlock(&bwe_sb->mutex);
	janus_mutex_destroy(&bwe_sb->mutex);
	g_free(bwe_sb);
}
