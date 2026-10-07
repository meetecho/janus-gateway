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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include "bwe.h"
#include "debug.h"
#include "utils.h"
#include "ip-utils.h"


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
	bwe->sent = janus_bwe_stream_bitrate_create();
	bwe->acked = janus_bwe_stream_bitrate_create();
	bwe->delays = janus_bwe_delay_tracker_create(0);
	bwe->probing_mindex = -1;
	bwe->fd = -1;
	return bwe;
}

void janus_bwe_context_destroy(janus_bwe_context *bwe) {
	if(bwe) {
		/* FIXME clean everything up */
		g_hash_table_destroy(bwe->packets);
		janus_bwe_stream_bitrate_destroy(bwe->sent);
		janus_bwe_stream_bitrate_destroy(bwe->acked);
		janus_bwe_delay_tracker_destroy(bwe->delays);
		if(bwe->csv != NULL)
			fclose(bwe->csv);
		if(bwe->fd > -1)
			close(bwe->fd);
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
		bwe->last_notified = janus_get_monotonic_time();
	}
	janus_bwe_twcc_inflight *stat = g_malloc(sizeof(janus_bwe_twcc_inflight));
	stat->seq = seq;
	stat->sent_ts = sent;
	stat->delta_us = bwe->last_sent_ts ? (sent - bwe->last_sent_ts) : 0;
	bwe->last_sent_ts = sent;
	stat->type = type;
	stat->size = size;
	janus_bwe_stream_bitrate_update(bwe->sent, now, type, 0, size);
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
		janus_bwe_stream_bitrate_update(bwe->acked, janus_get_monotonic_time(), p->type, 0, p->size);
		bwe->received_pkts++;
		bwe->last_recv_seq = seq;
	} else {
		bwe->lost_pkts++;
	}
}

void janus_bwe_context_update(janus_bwe_context *bwe) {
	if(bwe == NULL)
		return;
	/* Reset the outgoing and (acked) incoming bitrate, and estimate the bitrate */
	int64_t now = janus_get_monotonic_time();
	if(bwe->bitrate_ts == 0)
		bwe->bitrate_ts = now;
	gboolean notify_plugin = FALSE;
	/* Clean up old bitrate values, and get the current bitrates */
	janus_bwe_stream_bitrate_update(bwe->sent, now, janus_bwe_packet_type_regular, 0, 0);
	janus_bwe_stream_bitrate_update(bwe->sent, now, janus_bwe_packet_type_rtx, 0, 0);
	janus_bwe_stream_bitrate_update(bwe->sent, now, janus_bwe_packet_type_probing, 0, 0);
	janus_bwe_stream_bitrate_update(bwe->acked, now, janus_bwe_packet_type_regular, 0, 0);
	janus_bwe_stream_bitrate_update(bwe->acked, now, janus_bwe_packet_type_rtx, 0, 0);
	janus_bwe_stream_bitrate_update(bwe->acked, now, janus_bwe_packet_type_probing, 0, 0);
	uint32_t rtx_out = bwe->sent->packets[janus_bwe_packet_type_rtx*3] ? bwe->sent->bitrate[janus_bwe_packet_type_rtx*3] : 0;
	uint32_t probing_out = bwe->sent->packets[janus_bwe_packet_type_probing*3] ? bwe->sent->bitrate[janus_bwe_packet_type_probing*3] : 0;
	uint32_t bitrate_out = rtx_out + probing_out + (bwe->sent->packets[0] ? bwe->sent->bitrate[0] : 0);
	uint32_t rtx_in = bwe->acked->packets[janus_bwe_packet_type_rtx*3] ? bwe->acked->bitrate[janus_bwe_packet_type_rtx*3] : 0;
	uint32_t probing_in = bwe->acked->packets[janus_bwe_packet_type_probing*3] ? bwe->acked->bitrate[janus_bwe_packet_type_probing*3] : 0;
	uint32_t bitrate_in = rtx_in + probing_in + (bwe->acked->packets[0] ? bwe->acked->bitrate[0] : 0);
	/* Get the average delay */
	double avg_delay_latest = ((double)bwe->delay / (double)bwe->received_pkts) / 1000;
	janus_bwe_delay_tracker_update(bwe->delays, now, avg_delay_latest);
	int dts = bwe->delays->queue ? g_queue_get_length(bwe->delays->queue) : 0;
	if(dts == 0)
		dts = 1;
	double avg_delay = bwe->delays->sum / (double)dts;
	double avg_delay_weighted = (bwe->bitrate_ts == now ? avg_delay : ((bwe->avg_delay * 0.9) + (avg_delay * 0.1)));
	/* FIXME Estimate the bandwidth */
	uint32_t estimate = bitrate_in;
	uint16_t tot = bwe->received_pkts + bwe->lost_pkts;
	if(tot > 0)
		bwe->loss_ratio = (double)bwe->lost_pkts / (double)tot;
	/* Check if there's packet loss or congestion */
	if(bwe->loss_ratio > 0.05) {
		/* FIXME Lossy network? Set the estimate to the acknowledged bitrate */
		if(bwe->status != janus_bwe_status_lossy && bwe->status != janus_bwe_status_congested)
			notify_plugin = TRUE;
		bwe->status = janus_bwe_status_lossy;
		bwe->status_changed = now;
		bwe->estimate = estimate;
	} else if(avg_delay_weighted >= 1.0 && (avg_delay_weighted - bwe->avg_delay) >= 0.05) {
		JANUS_LOG(LOG_WARN, "[BWE][%"SCNi64"] Congested (delay=%.2f, increase=%.2f)\n",
			now, avg_delay_weighted, avg_delay_weighted - bwe->avg_delay);
		/* FIXME Delay is increasing */
		if(bwe->status != janus_bwe_status_lossy && bwe->status != janus_bwe_status_congested)
			notify_plugin = TRUE;
		bwe->status = janus_bwe_status_congested;
		bwe->status_changed = now;
		bwe->estimate = estimate;
		//~ else
			//~ bwe->estimate = ((double)bwe->estimate * 0.8) + ((double)estimate * 0.2);
	//~ } else if(bitrate_out > bitrate_in && (bitrate_out - bitrate_in > 50000)) {
		//~ /* FIXME We sent much more than what was acked, another indicator of possible congestion? */
		//~ JANUS_LOG(LOG_WARN, "[BWE][%"SCNi64"] Congested (too much diff with acked rate, %"SCNu32")\n",
			//~ now, bitrate_out - bitrate_in);
		//~ if(bwe->status != janus_bwe_status_lossy && bwe->status != janus_bwe_status_congested)
			//~ notify_plugin = TRUE;
		//~ bwe->status = janus_bwe_status_congested;
		//~ bwe->status_changed = now;
		//~ bwe->estimate = estimate;
	} else {
		/* FIXME All is fine? Check what state we're in */
		if(bwe->status == janus_bwe_status_lossy || bwe->status == janus_bwe_status_congested) {
			bwe->status = janus_bwe_status_recovering;
			bwe->status_changed = now;
		}
		if(bwe->status == janus_bwe_status_recovering) {
			/* FIXME Still recovering */
			if(now - bwe->status_changed >= 5*G_USEC_PER_SEC) {
				/* FIXME Recovery ended, let's assume everything is fine now */
				bwe->status = janus_bwe_status_regular;
				bwe->status_changed = now;
				/* Restore probing but incrementally */
				bwe->probing_sent = 0;
				bwe->probing_portion = 0.0;
				bwe->probing_buildup = 0;
				bwe->probing_buildup_step = 1000;
				bwe->probing_buildup_timer = now;
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
			//~ else if(now - bwe->status_changed < 10*G_USEC_PER_SEC)
				//~ bwe->estimate = ((double)bwe->estimate * 1.02);
		}
	}
	bwe->avg_delay = avg_delay_weighted;
	bwe->bitrate_ts = now;
	JANUS_LOG(LOG_DBG, "[BWE][%"SCNi64"][%s] sent=%"SCNu32"kbps (probing=%"SCNu32"kbps), acked=%"SCNu32"kbps (probing=%"SCNu32"kbps), loss=%.2f%%, avg_delay=%.2fms, estimate=%"SCNu32"\n",
		now, janus_bwe_status_description(bwe->status),
		bitrate_out / 1024, probing_out / 1024, bitrate_in / 1024, probing_in / 1024,
		bwe->loss_ratio, bwe->avg_delay, bwe->estimate);

	/* Save the details to CSV and/or send them externally via UDP, if enabled */
	if(bwe->csv != NULL || bwe->fd > -1) {
		char line[2048];
		g_snprintf(line, sizeof(line), "%"SCNi64",%d,%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu32",%"SCNu16",%"SCNu16",%.2f,%.2f,%.2f,%.2f\n",
			now - bwe->started, bwe->status,
			bwe->estimate, bwe->probing_target, bitrate_out, rtx_out, probing_out, bitrate_in, rtx_in, probing_in,
			bwe->received_pkts, bwe->lost_pkts, bwe->loss_ratio, avg_delay, avg_delay_weighted, avg_delay_latest);
		if(bwe->csv != NULL)
			fwrite(line, sizeof(char), strlen(line), bwe->csv);
		if(bwe->fd > -1)
			send(bwe->fd, line, strlen(line), 0);
	}

	/* Reset values */
	bwe->delay = 0;
	bwe->received_pkts = 0;
	bwe->lost_pkts = 0;
	/* Check if we should notify the plugin about the estimate */
	if(bwe->status != janus_bwe_status_start && (notify_plugin || (now - bwe->last_notified) >= 250000)) {
		bwe->notify_plugin = TRUE;
		bwe->last_notified = now;
	}
}

gboolean janus_bwe_save_csv(janus_bwe_context *bwe, const char *path) {
	if(bwe == NULL || path == NULL || bwe->csv != NULL)
		return FALSE;
	/* Open the CSV file */
	bwe->csv = fopen(path, "wt");
	if(bwe->csv == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open CSV file for BWE stats: %s\n", g_strerror(errno));
		return FALSE;
	}
	/* Write a header line with the names of the fields we'll save */
	char line[2048];
	g_snprintf(line, sizeof(line), "time,status,estimate,probing_target,bitrate_out,rtx_out,probing_out,bitrate_in,rtx_in,probing_in,acked,lost,loss_ratio,avg_delay,avg_delay_weighted,avg_delay_fb\n");
	fwrite(line, sizeof(char), strlen(line), bwe->csv);
	fflush(bwe->csv);
	/* Done */
	return TRUE;
}

void janus_bwe_close_csv(janus_bwe_context *bwe) {
	if(bwe == NULL || bwe->csv == NULL)
		return;
	fclose(bwe->csv);
	bwe->csv = NULL;
}

gboolean janus_bwe_save_live(janus_bwe_context *bwe, const char *host, uint16_t port) {
	if(bwe == NULL || host == NULL || port == 0 || bwe->fd > -1)
		return FALSE;
	/* Check if we need to resolve this host address */
	struct addrinfo *res = NULL, *start = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	const char *resolved_host = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	if(getaddrinfo(host, NULL, NULL, &res) == 0) {
		start = res;
		while(res != NULL) {
			if(janus_network_address_from_sockaddr(res->ai_addr, &addr) == 0 &&
					janus_network_address_to_string_buffer(&addr, &addr_buf) == 0) {
				/* Resolved */
				resolved_host = janus_network_address_string_from_buffer(&addr_buf);
				freeaddrinfo(start);
				start = NULL;
				break;
			}
			res = res->ai_next;
		}
	}
	if(resolved_host == NULL) {
		if(start)
			freeaddrinfo(start);
		JANUS_LOG(LOG_ERR, "Could not resolve address (%s) for BWE stats...\n", host);
		return FALSE;
	}
	host = resolved_host;
	/* Create the socket */
	bwe->fd = socket(addr.family, SOCK_DGRAM, IPPROTO_UDP);
	if(bwe->fd == -1) {
		JANUS_LOG(LOG_ERR, "Error creating socket for BWE stats: %s\n", g_strerror(errno));
		return FALSE;
	}
	struct sockaddr_in serv_addr = { 0 };
	struct sockaddr_in6 serv_addr6 = { 0 };
	if(addr.family == AF_INET6) {
		serv_addr6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host, &serv_addr6.sin6_addr);
		serv_addr6.sin6_port = htons(port);
	} else {
		serv_addr.sin_family = AF_INET;
		inet_pton(AF_INET, host, &serv_addr.sin_addr);
		serv_addr.sin_port = htons(port);
	}
	/* Connect the socket to the provided address */
	struct sockaddr *address = (addr.family == AF_INET ? (struct sockaddr *)&serv_addr : (struct sockaddr *)&serv_addr6);
	size_t addrlen = (addr.family == AF_INET ? sizeof(serv_addr) : sizeof(serv_addr6));
	if(connect(bwe->fd, (struct sockaddr *)address, addrlen) < 0) {
		JANUS_LOG(LOG_ERR, "Error connecting socket for BWE stats: %s\n", g_strerror(errno));
		close(bwe->fd);
		bwe->fd = -1;
	}
	/* Done */
	return TRUE;
}

void janus_bwe_close_live(janus_bwe_context *bwe) {
	if(bwe == NULL || bwe->fd == -1)
		return;
	close(bwe->fd);
	bwe->fd = -1;
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

janus_bwe_delay_tracker *janus_bwe_delay_tracker_create(int64_t keep_ts) {
	janus_bwe_delay_tracker *dt = g_malloc0(sizeof(janus_bwe_delay_tracker));
	dt->keep_ts = (keep_ts > 0 ? keep_ts : G_USEC_PER_SEC);
	return dt;
}

void janus_bwe_delay_tracker_update(janus_bwe_delay_tracker *dt, int64_t when, double avg_delay) {
	if(dt == NULL)
		return;
	if(dt->queue == NULL)
		dt->queue = g_queue_new();
	/* Check if we need to get rid of some old feedback */
	int64_t cleanup_ts = when - dt->keep_ts;
	janus_bwe_delay_fb *fb = g_queue_peek_head(dt->queue);
	while(fb && fb->sent_ts < cleanup_ts) {
		fb = g_queue_pop_head(dt->queue);
		dt->sum -= fb->avg_delay;
		g_free(fb);
		fb = g_queue_peek_head(dt->queue);
	}
	/* Check if there's anything new we need to add now */
	fb = g_malloc(sizeof(janus_bwe_delay_fb));
	fb->sent_ts = when;
	fb->avg_delay = avg_delay;
	dt->sum += avg_delay;
	g_queue_push_tail(dt->queue, fb);
}

void janus_bwe_delay_tracker_destroy(janus_bwe_delay_tracker *dt) {
	if(dt && dt->queue)
		g_queue_free_full(dt->queue, (GDestroyNotify)g_free);
	g_free(dt);
}
