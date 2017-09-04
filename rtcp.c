/*! \file    rtcp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTCP processing
 * \details  Implementation (based on the oRTP structures) of the RTCP
 * messages. RTCP messages coming through the gateway are parsed and,
 * if needed (according to http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00),
 * fixed before they are sent to the peers (e.g., to fix SSRCs that may
 * have been changed by the gateway). Methods to generate FIR messages
 * and generate/cap REMB messages are provided as well.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#include <math.h>
#include <stdlib.h>

#include "debug.h"
#include "rtp.h"
#include "rtcp.h"
#include "utils.h"

int janus_rtcp_parse(rtcp_context *ctx, char *packet, int len) {
	return janus_rtcp_fix_ssrc(ctx, packet, len, 0, 0, 0);
}

guint32 janus_rtcp_get_sender_ssrc(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return 0;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				rtcp_sr *sr = (rtcp_sr*)rtcp;
				return ntohl(sr->ssrc);
			}
			case RTCP_RR: {
				/* RR, receiver report */
				rtcp_rr *rr = (rtcp_rr*)rtcp;
				return ntohl(rr->ssrc);
			}
			case RTCP_RTPFB: {
				/* RTPFB, Transport layer FB message (rfc4585) */
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				return ntohl(rtcpfb->ssrc);
			}
			case RTCP_PSFB: {
				/* PSFB, Payload-specific FB message (rfc4585) */
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				return ntohl(rtcpfb->ssrc);
			}
			case RTCP_XR: {
				/* XR, extended reports (rfc3611) */
				rtcp_xr *xr = (rtcp_xr *)rtcp;
				return ntohl(xr->ssrc);
			}
			default:
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0) {
			break;
		}
		total -= length*4+4;
		if(total <= 0) {
			break;
		}
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

guint32 janus_rtcp_get_receiver_ssrc(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return 0;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				rtcp_sr *sr = (rtcp_sr*)rtcp;
				if(sr->header.rc > 0) {
					return ntohl(sr->rb[0].ssrc);
				}
				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				rtcp_rr *rr = (rtcp_rr*)rtcp;
				if(rr->header.rc > 0) {
					return ntohl(rr->rb[0].ssrc);
				}
				break;
			}
			default:
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0) {
			break;
		}
		total -= length*4+4;
		if(total <= 0) {
			break;
		}
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Helper to handle an incoming SR: triggered by a call to janus_rtcp_fix_ssrc with fixssrc=0 */
static void janus_rtcp_incoming_sr(rtcp_context *ctx, rtcp_sr *sr) {
	if(ctx == NULL)
		return;
	/* Update the context with info on the monotonic time of last SR received */
	ctx->lsr_ts = janus_get_monotonic_time();
	/* Compute the last SR received as well */
	uint64_t ntp = ntohl(sr->si.ntp_ts_msw);
	ntp = (ntp << 32) | ntohl(sr->si.ntp_ts_lsw);
	ctx->lsr = (ntp >> 16);
}

/* Helper to handle an incoming RR: triggered by a call to janus_rtcp_fix_ssrc with fixssrc=0 */
static void janus_rtcp_incoming_rr(rtcp_context *ctx, rtcp_rr *rr) {
	if(ctx == NULL)
		return;
	/* FIXME Check the Record Blocks */
	if(rr->header.rc > 0) {
		double jitter = (double)ntohl(rr->rb[0].jitter);
		uint32_t fraction = ntohl(rr->rb[0].flcnpl) >> 24;
		uint32_t total = ntohl(rr->rb[0].flcnpl) & 0x00FFFFFF;
		JANUS_LOG(LOG_HUGE, "jitter=%f, fraction=%"SCNu32", loss=%"SCNu32"\n", jitter, fraction, total);
		ctx->lost_remote = total;
		ctx->jitter_remote = jitter;
	}
}

int janus_rtcp_fix_ssrc(rtcp_context *ctx, char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr) {
	if(packet == NULL || len <= 0)
		return -1;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return -2;
	int pno = 0, total = len;
	JANUS_LOG(LOG_HUGE, "   Parsing compound packet (total of %d bytes)\n", total);
	while(rtcp) {
		pno++;
		/* TODO Should we handle any of these packets ourselves, or just relay them? */
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				JANUS_LOG(LOG_HUGE, "     #%d SR (200)\n", pno);
				rtcp_sr *sr = (rtcp_sr*)rtcp;
				/* RTCP context provided, update it with info on this SR */
				janus_rtcp_incoming_sr(ctx, sr);
				if(fixssrc && newssrcl) {
					sr->ssrc = htonl(newssrcl);
				}
				if(fixssrc && newssrcr && sr->header.rc > 0) {
					sr->rb[0].ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				JANUS_LOG(LOG_HUGE, "     #%d RR (201)\n", pno);
				rtcp_rr *rr = (rtcp_rr*)rtcp;
				if(ctx != NULL) {
					/* RTCP context provided, update it with info on this SR */
					janus_rtcp_incoming_rr(ctx, rr);
				}
				if(fixssrc && newssrcl) {
					rr->ssrc = htonl(newssrcl);
				}
				if(fixssrc && newssrcr && rr->header.rc > 0) {
					rr->rb[0].ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_SDES: {
				/* SDES, source description */
				JANUS_LOG(LOG_HUGE, "     #%d SDES (202)\n", pno);
				rtcp_sdes *sdes = (rtcp_sdes*)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(sdes->chunk.ssrc));
				if(fixssrc && newssrcl) {
					sdes->chunk.ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_BYE: {
				/* BYE, goodbye */
				JANUS_LOG(LOG_HUGE, "     #%d BYE (203)\n", pno);
				rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(bye->ssrc[0]));
				if(fixssrc && newssrcl) {
					bye->ssrc[0] = htonl(newssrcl);
				}
				break;
			}
			case RTCP_APP: {
				/* APP, application-defined */
				JANUS_LOG(LOG_HUGE, "     #%d APP (204)\n", pno);
				rtcp_app_t *app = (rtcp_app_t*)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(app->ssrc));
				if(fixssrc && newssrcl) {
					app->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_FIR: {
				/* FIR, rfc2032 */
				JANUS_LOG(LOG_HUGE, "     #%d FIR (192)\n", pno);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				if(fixssrc && newssrcr && (ntohs(rtcp->length) >= 20)) {
					rtcpfb->media = htonl(newssrcr);
				}
				if(fixssrc && newssrcr) {
					uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
					*ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_RTPFB: {
				/* RTPFB, Transport layer FB message (rfc4585) */
				//~ JANUS_LOG(LOG_HUGE, "     #%d RTPFB (205)\n", pno);
				gint fmt = rtcp->rc;
				//~ JANUS_LOG(LOG_HUGE, "       -- FMT: %u\n", fmt);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					JANUS_LOG(LOG_HUGE, "     #%d NACK -- RTPFB (205)\n", pno);
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
					int nacks = ntohs(rtcp->length)-2;	/* Skip SSRCs */
					if(nacks > 0) {
						JANUS_LOG(LOG_DBG, "        Got %d nacks\n", nacks);
						rtcp_nack *nack = NULL;
						uint16_t pid = 0;
						uint16_t blp = 0;
						int i=0, j=0;
						char bitmask[20];
						for(i=0; i< nacks; i++) {
							nack = (rtcp_nack *)rtcpfb->fci + i;
							pid = ntohs(nack->pid);
							blp = ntohs(nack->blp);
							memset(bitmask, 0, 20);
							for(j=0; j<16; j++) {
								bitmask[j] = (blp & ( 1 << j )) >> j ? '1' : '0';
							}
							bitmask[16] = '\n';
							JANUS_LOG(LOG_DBG, "[%d] %"SCNu16" / %s\n", i, pid, bitmask);
						}
					}
				} else if(fmt == 3) {	/* rfc5104 */
					/* TMMBR: http://tools.ietf.org/html/rfc5104#section-4.2.1.1 */
					JANUS_LOG(LOG_HUGE, "     #%d TMMBR -- RTPFB (205)\n", pno);
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else {
					JANUS_LOG(LOG_HUGE, "     #%d ??? -- RTPFB (205, fmt=%d)\n", pno, fmt);
				}
				if(fixssrc && newssrcl) {
					rtcpfb->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_PSFB: {
				/* PSFB, Payload-specific FB message (rfc4585) */
				//~ JANUS_LOG(LOG_HUGE, "     #%d PSFB (206)\n", pno);
				gint fmt = rtcp->rc;
				//~ JANUS_LOG(LOG_HUGE, "       -- FMT: %u\n", fmt);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					JANUS_LOG(LOG_HUGE, "     #%d PLI -- PSFB (206)\n", pno);
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
				} else if(fmt == 2) {
					JANUS_LOG(LOG_HUGE, "     #%d SLI -- PSFB (206)\n", pno);
				} else if(fmt == 3) {
					JANUS_LOG(LOG_HUGE, "     #%d RPSI -- PSFB (206)\n", pno);
				} else if(fmt == 4) {	/* rfc5104 */
					/* FIR: http://tools.ietf.org/html/rfc5104#section-4.3.1.1 */
					JANUS_LOG(LOG_HUGE, "     #%d FIR -- PSFB (206)\n", pno);
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else if(fmt == 5) {	/* rfc5104 */
					/* FIR: http://tools.ietf.org/html/rfc5104#section-4.3.2.1 */
					JANUS_LOG(LOG_HUGE, "     #%d PLI -- TSTR (206)\n", pno);
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else if(fmt == 15) {
					//~ JANUS_LOG(LOG_HUGE, "       -- This is a AFB!\n");
					rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
					if(fixssrc && newssrcr) {
						rtcpfb->ssrc = htonl(newssrcr);
						rtcpfb->media = 0;
					}
					rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
					if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
						JANUS_LOG(LOG_HUGE, "     #%d REMB -- PSFB (206)\n", pno);
						if(fixssrc && newssrcr) {
							remb->ssrc[0] = htonl(newssrcr);
						}
						/* FIXME From rtcp_utility.cc */
						unsigned char *_ptrRTCPData = (unsigned char *)remb;
						_ptrRTCPData += 4;	// Skip unique identifier and num ssrc
						//~ JANUS_LOG(LOG_HUGE, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
						uint8_t numssrc = (_ptrRTCPData[0]);
						uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
						uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
						brMantissa += (_ptrRTCPData[2] << 8);
						brMantissa += (_ptrRTCPData[3]);
						uint32_t bitRate = brMantissa << brExp;
						JANUS_LOG(LOG_HUGE, "       -- -- -- REMB: %u * 2^%u = %"SCNu32" (%d SSRCs, %u)\n",
							brMantissa, brExp, bitRate, numssrc, ntohl(remb->ssrc[0]));
					} else {
						JANUS_LOG(LOG_HUGE, "     #%d AFB ?? -- PSFB (206)\n", pno);
					}
				} else {
					JANUS_LOG(LOG_HUGE, "     #%d ?? -- PSFB (206, fmt=%d)\n", pno, fmt);
				}
				if(fixssrc && newssrcl) {
					rtcpfb->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_XR: {
				/* XR, extended reports (rfc3611) */
				rtcp_xr *xr = (rtcp_xr *)rtcp;
				if(fixssrc && newssrcl) {
					xr->ssrc = htonl(newssrcl);
				}
				/* TODO Fix report blocks too, once we support them */
				break;
			}
			default:
				JANUS_LOG(LOG_ERR, "     Unknown RTCP PT %d\n", rtcp->type);
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		JANUS_LOG(LOG_HUGE, "       RTCP PT %d, length: %d bytes\n", rtcp->type, length*4+4);
		if(length == 0) {
			//~ JANUS_LOG(LOG_HUGE, "  0-length, end of compound packet\n");
			break;
		}
		total -= length*4+4;
		//~ JANUS_LOG(LOG_HUGE, "     Packet has length %d (%d bytes, %d remaining), moving to next one...\n", length, length*4+4, total);
		if(total <= 0) {
			JANUS_LOG(LOG_HUGE, "  End of compound packet\n");
			break;
		}
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

char *janus_rtcp_filter(char *packet, int len, int *newlen) {
	if(packet == NULL || len <= 0 || newlen == NULL)
		return NULL;
	*newlen = 0;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return NULL;
	char *filtered = NULL;
	int total = len, length = 0, bytes = 0;
	/* Iterate on the compound packets */
	gboolean keep = TRUE;
	while(rtcp) {
		keep = TRUE;
		length = ntohs(rtcp->length);
		if(length == 0)
			break;
		bytes = length*4+4;
		switch(rtcp->type) {
			case RTCP_SR:
			case RTCP_RR:
			case RTCP_SDES:
				/* These are packets we generate ourselves, so remove them */
				keep = FALSE;
				break;
			case RTCP_BYE:
			case RTCP_APP:
			case RTCP_FIR:
			case RTCP_PSFB:
				break;
			case RTCP_RTPFB:
				if(rtcp->rc == 1) {
					/* We handle NACKs ourselves as well, remove this too */
					keep = FALSE;
					break;
				}
				break;
			case RTCP_XR:
				/* FIXME We generate RR/SR ourselves, so remove XR */
				keep = FALSE;
				break;
			default:
				JANUS_LOG(LOG_ERR, "Unknown RTCP PT %d\n", rtcp->type);
				/* FIXME Should we allow this to go through instead? */
				keep = FALSE;
				break;
		}
		if(keep) {
			/* Keep this packet */
			if(filtered == NULL)
				filtered = g_malloc0(total);
			memcpy(filtered+*newlen, (char *)rtcp, bytes);
			*newlen += bytes;
		}
		total -= bytes;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return filtered;
}


int janus_rtcp_process_incoming_rtp(rtcp_context *ctx, char *packet, int len) {
	if(ctx == NULL || packet == NULL || len < 1)
		return -1;

	/* First of all, let's check if this is G.711: in case we may need to change the timestamp base */
	rtp_header *rtp = (rtp_header *)packet;
	int pt = rtp->type;
	if((pt == 0 || pt == 8) && (ctx->tb == 48000))
		ctx->tb = 8000;
	/* Now parse this RTP packet header and update the rtcp_context instance */
	uint16_t seq_number = ntohs(rtp->seq_number);
	if(ctx->base_seq == 0 && ctx->seq_cycle == 0)
		ctx->base_seq = seq_number;

	if(seq_number < ctx->last_seq_nr) {
		if(ctx->last_seq_nr - seq_number < 1000) {
			/* FIXME Just a retransmission, not a reset, ignore */
			return 0;
		}
		ctx->seq_cycle++;
	}
	ctx->last_seq_nr = seq_number;
	ctx->received++;
	uint32_t rtp_expected = 0x0;
	if(ctx->seq_cycle > 0) {
		rtp_expected = ctx->seq_cycle;
		rtp_expected = rtp_expected << 16;
	}
	rtp_expected = rtp_expected + 1 + seq_number - ctx->base_seq;
	ctx->lost = rtp_expected - ctx->received;
	ctx->expected = rtp_expected;

	uint64_t arrival = (janus_get_monotonic_time() * ctx->tb) / 1000000;
	uint64_t transit = arrival - ntohl(rtp->timestamp);
	uint64_t d = abs(transit - ctx->transit);
	ctx->transit = transit;
	ctx->jitter += (1./16.) * ((double)d  - ctx->jitter);

	/* RTP packet received: it means we can start sending RR */
	ctx->rtp_recvd = 1;

	return 0;
}


uint32_t janus_rtcp_context_get_lsr(rtcp_context *ctx) {
	return ctx ? ctx->lsr : 0;
}

uint32_t janus_rtcp_context_get_lost_all(rtcp_context *ctx, gboolean remote) {
	if(ctx == NULL)
		return 0;
	return remote ? ctx->lost_remote : ctx->lost;
}

static uint32_t janus_rtcp_context_get_lost(rtcp_context *ctx) {
	if(ctx == NULL)
		return 0;
	uint32_t lost;
	if(ctx->lost > 0x7FFFFF) {
		lost = 0x7FFFFF;
	} else {
		lost = ctx->lost;
	}
	return lost;
}

static uint32_t janus_rtcp_context_get_lost_fraction(rtcp_context *ctx) {
	if(ctx == NULL)
		return 0;
	uint32_t expected_interval = ctx->expected - ctx->expected_prior;
	uint32_t received_interval = ctx->received - ctx->received_prior;
	int32_t lost_interval = expected_interval - received_interval;
	uint32_t fraction;
	if(expected_interval == 0 || lost_interval <=0)
		fraction = 0;
	else
		fraction = (lost_interval << 8) / expected_interval;
	return fraction << 24;
}

uint32_t janus_rtcp_context_get_jitter(rtcp_context *ctx, gboolean remote) {
	if(ctx == NULL || ctx->tb == 0)
		return 0;
	return (uint32_t) floor((remote ? ctx->jitter_remote : ctx->jitter) * 1000.0 / ctx->tb);
}

int janus_rtcp_report_block(rtcp_context *ctx, report_block *rb) {
	if(ctx == NULL || rb == NULL)
		return -1;
	gint64 now = janus_get_monotonic_time();
	rb->jitter = htonl((uint32_t) ctx->jitter);
	rb->ehsnr = htonl((((uint32_t) 0x0 + ctx->seq_cycle) << 16) + ctx->last_seq_nr);
	uint32_t lost = janus_rtcp_context_get_lost(ctx);
	uint32_t fraction = janus_rtcp_context_get_lost_fraction(ctx);
	ctx->expected_prior = ctx->expected;
	ctx->received_prior = ctx->received;
	rb->flcnpl = htonl(lost | fraction);
	if(ctx->lsr > 0) {
		rb->lsr = htonl(ctx->lsr);
		rb->delay = htonl(((now - ctx->lsr_ts) << 16) / 1000000);
	} else {
		rb->lsr = 0;
		rb->delay = 0;
	}
	ctx->last_sent = now;
	return 0;
}


int janus_rtcp_has_bye(char *packet, int len) {
	gboolean got_bye = FALSE;
	/* Parse RTCP compound packet */
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return FALSE;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_BYE:
				got_bye = TRUE;
				break;
			default:
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return got_bye ? TRUE : FALSE;
}

int janus_rtcp_has_fir(char *packet, int len) {
	gboolean got_fir = FALSE;
	/* Parse RTCP compound packet */
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return FALSE;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_FIR:
				got_fir = TRUE;
				break;
			default:
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return got_fir ? TRUE : FALSE;
}

int janus_rtcp_has_pli(char *packet, int len) {
	gboolean got_pli = FALSE;
	/* Parse RTCP compound packet */
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return FALSE;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_PSFB: {
				gint fmt = rtcp->rc;
				if(fmt == 1)
					got_pli = TRUE;
				break;
			}
			default:
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return got_pli ? TRUE : FALSE;
}

GSList *janus_rtcp_get_nacks(char *packet, int len) {
	if(packet == NULL || len == 0)
		return NULL;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return NULL;
	/* FIXME Get list of sequence numbers we should send again */
	GSList *list = NULL;
	int total = len;
	while(rtcp) {
		if(rtcp->type == RTCP_RTPFB) {
			gint fmt = rtcp->rc;
			if(fmt == 1) {
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				int nacks = ntohs(rtcp->length)-2;	/* Skip SSRCs */
				if(nacks > 0) {
					JANUS_LOG(LOG_DBG, "        Got %d nacks\n", nacks);
					rtcp_nack *nack = NULL;
					uint16_t pid = 0;
					uint16_t blp = 0;
					int i=0, j=0;
					char bitmask[20];
					for(i=0; i< nacks; i++) {
						nack = (rtcp_nack *)rtcpfb->fci + i;
						pid = ntohs(nack->pid);
						list = g_slist_append(list, GUINT_TO_POINTER(pid));
						blp = ntohs(nack->blp);
						memset(bitmask, 0, 20);
						for(j=0; j<16; j++) {
							bitmask[j] = (blp & ( 1 << j )) >> j ? '1' : '0';
							if((blp & ( 1 << j )) >> j)
								list = g_slist_append(list, GUINT_TO_POINTER(pid+j+1));
						}
						bitmask[16] = '\n';
						JANUS_LOG(LOG_DBG, "[%d] %"SCNu16" / %s\n", i, pid, bitmask);
					}
				}
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return list;
}

int janus_rtcp_remove_nacks(char *packet, int len) {
	if(packet == NULL || len == 0)
		return len;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return len;
	/* Find the NACK message */
	char *nacks = NULL;
	int total = len, nacks_len = 0;
	while(rtcp) {
		if(rtcp->type == RTCP_RTPFB) {
			gint fmt = rtcp->rc;
			if(fmt == 1) {
				nacks = (char *)rtcp;
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		if(nacks != NULL) {
			nacks_len = length*4+4;
			break;
		}
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	if(nacks != NULL) {
		total = len - ((nacks-packet)+nacks_len);
		if(total < 0) {
			/* FIXME Should never happen, but you never know: do nothing */
			return len;
		} else if(total == 0) {
			/* NACK was the last compound packet, easy enough */
			return len-nacks_len;
		} else {
			/* NACK is between two compound packets, move them around */
			int i=0;
			for(i=0; i<total; i++)
				*(nacks+i) = *(nacks+nacks_len+i);
			return len-nacks_len;
		}
	}
	return len;
}

/* Query an existing REMB message */
uint32_t janus_rtcp_get_remb(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return 0;
	/* Get REMB bitrate, if any */
	int total = len;
	while(rtcp) {
		if(rtcp->type == RTCP_PSFB) {
			gint fmt = rtcp->rc;
			if(fmt == 15) {
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
				if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
					/* FIXME From rtcp_utility.cc */
					unsigned char *_ptrRTCPData = (unsigned char *)remb;
					_ptrRTCPData += 4;	/* Skip unique identifier and num ssrc */
					//~ JANUS_LOG(LOG_VERB, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
					uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
					uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
					brMantissa += (_ptrRTCPData[2] << 8);
					brMantissa += (_ptrRTCPData[3]);
					uint32_t bitrate = brMantissa << brExp;
					JANUS_LOG(LOG_HUGE, "Got REMB bitrate %"SCNu32"\n", bitrate);
					return bitrate;
				}
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Change an existing REMB message */
int janus_rtcp_cap_remb(char *packet, int len, uint32_t bitrate) {
	if(packet == NULL || len == 0)
		return -1;
	rtcp_header *rtcp = (rtcp_header *)packet;
	if(rtcp->version != 2)
		return -2;
	if(bitrate == 0)
		return 0;	/* No need to cap */
	/* Cap REMB bitrate */
	int total = len;
	while(rtcp) {
		if(rtcp->type == RTCP_PSFB) {
			gint fmt = rtcp->rc;
			if(fmt == 15) {
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
				if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
					/* FIXME From rtcp_utility.cc */
					unsigned char *_ptrRTCPData = (unsigned char *)remb;
					_ptrRTCPData += 4;	/* Skip unique identifier and num ssrc */
					//~ JANUS_LOG(LOG_VERB, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
					uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
					uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
					brMantissa += (_ptrRTCPData[2] << 8);
					brMantissa += (_ptrRTCPData[3]);
					uint32_t origbitrate = brMantissa << brExp;
					if(origbitrate > bitrate) {
						JANUS_LOG(LOG_HUGE, "Got REMB bitrate %"SCNu32", need to cap it to %"SCNu32"\n", origbitrate, bitrate);
						JANUS_LOG(LOG_HUGE, "  >> %u * 2^%u = %"SCNu32"\n", brMantissa, brExp, origbitrate);
						/* bitrate --> brexp/brmantissa */
						uint8_t b = 0;
						uint8_t newbrexp = 0;
						uint32_t newbrmantissa = 0;
						for(b=0; b<32; b++) {
							if(bitrate <= ((uint32_t) 0x3FFFF << b)) {
								newbrexp = b;
								break;
							}
						}
						if(b > 31)
							b = 31;
						newbrmantissa = bitrate >> b;
						JANUS_LOG(LOG_HUGE, "new brexp:      %"SCNu8"\n", newbrexp);
						JANUS_LOG(LOG_HUGE, "new brmantissa: %"SCNu32"\n", newbrmantissa);
						/* FIXME From rtcp_sender.cc */
						_ptrRTCPData[1] = (uint8_t)((newbrexp << 2) + ((newbrmantissa >> 16) & 0x03));
						_ptrRTCPData[2] = (uint8_t)(newbrmantissa >> 8);
						_ptrRTCPData[3] = (uint8_t)(newbrmantissa);
					}
				}
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Generate a new SDES message */
int janus_rtcp_sdes(char *packet, int len, const char *cname, int cnamelen) {
	if(packet == NULL || len <= 0 || cname == NULL || cnamelen <= 0)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_SDES;
	rtcp->rc = 1;
	int plen = 8;	/* Header + chunk + item header */
	plen += cnamelen+2;
	if((cnamelen+2)%4)	/* Account for padding */
		plen += 4;
	if(len < plen) {
		JANUS_LOG(LOG_ERR, "Buffer too small for SDES message: %d < %d\n", len, plen);
		return -1;
	}
	rtcp->length = htons((plen/4)-1);
	/* Now set SDES stuff */
	rtcp_sdes *rtcpsdes = (rtcp_sdes *)rtcp;
	rtcpsdes->item.type = 1;
	rtcpsdes->item.len = cnamelen;
	memcpy(rtcpsdes->item.content, cname, cnamelen);
	return plen;
}

/* Generate a new REMB message */
int janus_rtcp_remb(char *packet, int len, uint32_t bitrate) {
	/* By default we assume a single SSRC will be set */
	return janus_rtcp_remb_ssrcs(packet, len, bitrate, 1);
}

int janus_rtcp_remb_ssrcs(char *packet, int len, uint32_t bitrate, uint8_t numssrc) {
	if(packet == NULL || numssrc == 0)
		return -1;
	int min_len = 20 + numssrc*4;
	if(len < min_len)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 15;
	rtcp->length = htons((min_len/4)-1);
	/* Now set REMB stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
	remb->id[0] = 'R';
	remb->id[1] = 'E';
	remb->id[2] = 'M';
	remb->id[3] = 'B';
	/* bitrate --> brexp/brmantissa */
	uint8_t b = 0;
	uint8_t newbrexp = 0;
	uint32_t newbrmantissa = 0;
	for(b=0; b<32; b++) {
		if(bitrate <= ((uint32_t) 0x3FFFF << b)) {
			newbrexp = b;
			break;
		}
	}
	if(b > 31)
		b = 31;
	newbrmantissa = bitrate >> b;
	/* FIXME From rtcp_sender.cc */
	unsigned char *_ptrRTCPData = (unsigned char *)remb;
	_ptrRTCPData += 4;	/* Skip unique identifier */
	_ptrRTCPData[0] = numssrc;
	_ptrRTCPData[1] = (uint8_t)((newbrexp << 2) + ((newbrmantissa >> 16) & 0x03));
	_ptrRTCPData[2] = (uint8_t)(newbrmantissa >> 8);
	_ptrRTCPData[3] = (uint8_t)(newbrmantissa);
	JANUS_LOG(LOG_HUGE, "[REMB] bitrate=%"SCNu32" (%d bytes)\n", bitrate, 4*(ntohs(rtcp->length)+1));
	return min_len;
}

/* Generate a new FIR message */
int janus_rtcp_fir(char *packet, int len, int *seqnr) {
	if(packet == NULL || len != 20 || seqnr == NULL)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	*seqnr = *seqnr + 1;
	if(*seqnr < 0 || *seqnr >= 256)
		*seqnr = 0;	/* Reset sequence number */
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 4;	/* FMT=4 */
	rtcp->length = htons((len/4)-1);
	/* Now set FIR stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_fir *fir = (rtcp_fir *)rtcpfb->fci;
	fir->seqnr = htonl(*seqnr << 24);	/* FCI: Sequence number */
	JANUS_LOG(LOG_HUGE, "[FIR] seqnr=%d (%d bytes)\n", *seqnr, 4*(ntohs(rtcp->length)+1));
	return 20;
}

/* Generate a new legacy FIR message */
int janus_rtcp_fir_legacy(char *packet, int len, int *seqnr) {
	/* FIXME Right now, this is identical to the new FIR, with the difference that we use 192 as PT */
	if(packet == NULL || len != 20 || seqnr == NULL)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	*seqnr = *seqnr + 1;
	if(*seqnr < 0 || *seqnr >= 256)
		*seqnr = 0;	/* Reset sequence number */
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_FIR;
	rtcp->rc = 4;	/* FMT=4 */
	rtcp->length = htons((len/4)-1);
	/* Now set FIR stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_fir *fir = (rtcp_fir *)rtcpfb->fci;
	fir->seqnr = htonl(*seqnr << 24);	/* FCI: Sequence number */
	JANUS_LOG(LOG_HUGE, "[FIR] seqnr=%d (%d bytes)\n", *seqnr, 4*(ntohs(rtcp->length)+1));
	return 20;
}

/* Generate a new PLI message */
int janus_rtcp_pli(char *packet, int len) {
	if(packet == NULL || len != 12)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 1;	/* FMT=1 */
	rtcp->length = htons((len/4)-1);
	return 12;
}

/* Generate a new NACK message */
int janus_rtcp_nacks(char *packet, int len, GSList *nacks) {
	if(packet == NULL || len < 16 || nacks == NULL)
		return -1;
	memset(packet, 0, len);
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_RTPFB;
	rtcp->rc = 1;	/* FMT=1 */
	/* Now set NACK stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_nack *nack = (rtcp_nack *)rtcpfb->fci;
	/* FIXME We assume the GSList list is already ordered... */
	guint16 pid = GPOINTER_TO_UINT(nacks->data);
	nack->pid = htons(pid);
	nacks = nacks->next;
	int words = 3;
	while(nacks) {
		guint16 npid = GPOINTER_TO_UINT(nacks->data);
		if(npid-pid < 1) {
			JANUS_LOG(LOG_HUGE, "Skipping PID to NACK (%"SCNu16" already added)...\n", npid);
		} else if(npid-pid > 16) {
			/* We need a new block: this sequence number will be its root PID */
			JANUS_LOG(LOG_HUGE, "Adding another block of NACKs (%"SCNu16"-%"SCNu16" > %"SCNu16")...\n", npid, pid, npid-pid);
			words++;
			if(len < (words*4+4)) {
				JANUS_LOG(LOG_ERR, "Buffer too small: %d < %d (at least %d NACK blocks needed)\n", len, words*4+4, words);
				return -1;
			}
			char *new_block = packet + words*4;
			nack = (rtcp_nack *)new_block;
			pid = GPOINTER_TO_UINT(nacks->data);
			nack->pid = htons(pid);
		} else {
			uint16_t blp = ntohs(nack->blp);
			blp |= 1 << (npid-pid-1);
			nack->blp = htons(blp);
		}
		nacks = nacks->next;
	}
	rtcp->length = htons(words);
	return words*4+4;
}
