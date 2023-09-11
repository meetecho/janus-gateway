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

const char *janus_bwe_status_description(janus_bwe_status status) {
	switch(status) {
		case janus_bwe_status_start:
			return "start";
		case janus_bwe_status_regular:
			return "regular";
		case janus_bwe_status_lossy:
			return "lossy";
		case janus_bwe_status_congested:
			return "congested";
		case janus_bwe_status_recovering:
			return "recovering";
		default: break;
	}
	return NULL;
}

static void janus_bwe_twcc_inflight_destroy(janus_bwe_twcc_inflight *stat) {
	g_free(stat);
}

janus_bwe_context *janus_bwe_context_create(void) {
	janus_bwe_context *bwe = g_malloc0(sizeof(janus_bwe_context));
	/* FIXME */
	bwe->packets = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_bwe_twcc_inflight_destroy);
	bwe->probing_mindex = -1;
	return bwe;
}

void janus_bwe_context_destroy(janus_bwe_context *bwe) {
	if(bwe) {
		/* FIXME clean everything up */
		g_hash_table_destroy(bwe->packets);
		g_free(bwe);
	}
}

gboolean janus_bwe_context_add_inflight(janus_bwe_context *bwe,
		uint16_t seq, int64_t sent, janus_bwe_packet_type type, int size) {
	if(bwe == NULL)
		return FALSE;
	int64_t now = janus_get_monotonic_time();
	if(bwe->started == 0)
		bwe->started = now;
	if(bwe->status == janus_bwe_status_start && now - bwe->started >= G_USEC_PER_SEC) {
		/* Let's move from the starting phase to the regular stage */
		bwe->status = janus_bwe_status_regular;
		bwe->status_changed = now;
	}
	janus_bwe_twcc_inflight *stat = g_malloc(sizeof(janus_bwe_twcc_inflight));
	stat->seq = seq;
	stat->sent_ts = sent;
	stat->delta_us = bwe->last_sent_ts ? (sent - bwe->last_sent_ts) : 0;
	bwe->last_sent_ts = sent;
	stat->type = type;
	stat->size = size;
	bwe->sent_bytes += size;
	if(type == janus_bwe_packet_type_probing)
		bwe->sent_bytes_probing += size;
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
		if(p->type == janus_bwe_packet_type_probing)
			bwe->received_bytes_probing += p->size;
		bwe->received_pkts++;
		bwe->last_recv_seq = seq;
	} else {
		bwe->lost_pkts++;
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
		uint32_t estimate = 8 * estimate_bytes;
		uint16_t tot = bwe->received_pkts + bwe->lost_pkts;
		if(tot > 0)
			bwe->loss_ratio = (double)bwe->lost_pkts / (double)tot;
		double avg_delay = ((double)bwe->delay / (double)bwe->received_pkts) / 1000;
		/* Check if there's packet loss or congestion */
		if(bwe->loss_ratio > 0.05) {
			/* FIXME Lossy network? Set the estimate to the acknowledged bitrate */
			bwe->status = janus_bwe_status_lossy;
			bwe->status_changed = now;
			bwe->estimate = estimate;
		} else if(bwe->avg_delay > 0 && avg_delay - bwe->avg_delay > 0.5) {
			/* FIXME Delay is increasing, converge to acknowledged bitrate */
			bwe->status = janus_bwe_status_congested;
			bwe->status_changed = now;
			//~ if(estimate > bwe->estimate)
				bwe->estimate = estimate;
			//~ else
				//~ bwe->estimate = ((double)bwe->estimate * 0.8) + ((double)estimate * 0.2);
		} else {
			/* FIXME All is fine? Check what state we're in */
			if(bwe->status == janus_bwe_status_lossy || bwe->status == janus_bwe_status_congested) {
				bwe->status = janus_bwe_status_recovering;
				bwe->status_changed = now;
			}
			if(bwe->status == janus_bwe_status_recovering) {
				/* FIXME Still recovering */
				if(now - bwe->status_changed >= 5*G_USEC_PER_SEC) {
					bwe->status = janus_bwe_status_regular;
					bwe->status_changed = now;
				} else {
					/* FIXME Keep converging to the estimate */
					if(estimate > bwe->estimate)
						bwe->estimate = estimate;
					//~ else
						//~ bwe->estimate = ((double)bwe->estimate * 0.8) + ((double)estimate * 0.2);
				}
			}
			if(bwe->status == janus_bwe_status_regular) {
				/* FIXME Slowly increase */
				if(estimate > bwe->estimate)
					bwe->estimate = estimate;
				else if(now - bwe->status_changed < 10*G_USEC_PER_SEC)
					bwe->estimate = ((double)bwe->estimate * 1.02);
			}
		}
		bwe->avg_delay = avg_delay;
		bwe->bitrate_ts = now;
	}
	JANUS_LOG(LOG_WARN, "[BWE][%s] sent=%"SCNu32"kbps (probing=%"SCNu32"kbps), received=%"SCNu32"kbps (probing=%"SCNu32"kbps), loss=%.2f%%, avg_delay=%.2fms\n",
		janus_bwe_status_description(bwe->status),
		(bwe->sent_bytes / 1000) * 8, (bwe->sent_bytes_probing / 1000) * 8,
		(bwe->received_bytes / 1000) * 8, (bwe->received_bytes_probing / 1000) * 8,
		bwe->loss_ratio, bwe->avg_delay);
	bwe->sent_bytes = 0;
	bwe->received_bytes = 0;
	bwe->sent_bytes_probing = 0;
	bwe->received_bytes_probing = 0;
	bwe->delay = 0;
	bwe->received_pkts = 0;
	bwe->lost_pkts = 0;
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
