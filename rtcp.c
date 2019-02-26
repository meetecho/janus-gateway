/*! \file    rtcp.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTCP processing
 * \details  Implementation (based on the oRTP structures) of the RTCP
 * messages. RTCP messages coming through the server are parsed and,
 * if needed (according to http://tools.ietf.org/html/draft-ietf-straw-b2bua-rtcp-00),
 * fixed before they are sent to the peers (e.g., to fix SSRCs that may
 * have been changed by the server). Methods to generate FIR messages
 * and generate/cap REMB messages are provided as well.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <math.h>
#include <stdlib.h>
#include <sys/time.h>

#include "debug.h"
#include "rtp.h"
#include "rtcp.h"
#include "utils.h"

gboolean janus_is_rtcp(char *buf, guint len) {
	if (len < 8)
		return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type >= 64) && (header->type < 96));
}

int janus_rtcp_parse(janus_rtcp_context *ctx, char *packet, int len) {
	return janus_rtcp_fix_ssrc(ctx, packet, len, 0, 0, 0);
}

guint32 janus_rtcp_get_sender_ssrc(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		pno++;
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				janus_rtcp_sr *sr = (janus_rtcp_sr *)rtcp;
				return ntohl(sr->ssrc);
			}
			case RTCP_RR: {
				/* RR, receiver report */
				janus_rtcp_rr *rr = (janus_rtcp_rr *)rtcp;
				return ntohl(rr->ssrc);
			}
			case RTCP_RTPFB: {
				/* RTPFB, Transport layer FB message (rfc4585) */
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				return ntohl(rtcpfb->ssrc);
			}
			case RTCP_PSFB: {
				/* PSFB, Payload-specific FB message (rfc4585) */
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				return ntohl(rtcpfb->ssrc);
			}
			case RTCP_XR: {
				/* XR, extended reports (rfc3611) */
				janus_rtcp_xr *xr = (janus_rtcp_xr *)rtcp;
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
		if(total <= 0)
			break;
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

guint32 janus_rtcp_get_receiver_ssrc(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		pno++;
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				if (!janus_rtcp_check_sr(rtcp, total))
					break;
				janus_rtcp_sr *sr = (janus_rtcp_sr *)rtcp;
				if(sr->header.rc > 0) {
					return ntohl(sr->rb[0].ssrc);
				}
				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				if (!janus_rtcp_check_rr(rtcp, total))
					break;
				janus_rtcp_rr *rr = (janus_rtcp_rr *)rtcp;
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
		if(total <= 0)
			break;
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Helper to handle an incoming SR: triggered by a call to janus_rtcp_fix_ssrc with fixssrc=0 */
static void janus_rtcp_incoming_sr(janus_rtcp_context *ctx, janus_rtcp_sr *sr) {
	if(ctx == NULL)
		return;
	/* Update the context with info on the monotonic time of last SR received */
	ctx->lsr_ts = janus_get_monotonic_time();
	/* Compute the last SR received as well */
	uint64_t ntp = ntohl(sr->si.ntp_ts_msw);
	ntp = (ntp << 32) | ntohl(sr->si.ntp_ts_lsw);
	ctx->lsr = (ntp >> 16);
}

/* Link quality estimate filter coefficient */
#define LINK_QUALITY_FILTER_K 3.0

static double janus_rtcp_link_quality_filter(double last, double in) {
	/* Note: the last!=last is there to check for NaN */
	if(last == 0 || last == in || last != last) {
		return in;
	} else {
		return (1.0 - 1.0/LINK_QUALITY_FILTER_K) * last + (1.0/LINK_QUALITY_FILTER_K) * in;
	}
}

/* Update link quality stats based on RR */
static void janus_rtcp_rr_update_stats(rtcp_context *ctx, janus_report_block rb) {
	int64_t ts = janus_get_monotonic_time();
	int64_t delta_t = ts - ctx->rr_last_ts;
	if(delta_t < 2*G_USEC_PER_SEC) {
		return;
	}
	ctx->rr_last_ts = ts;
	uint32_t total_lost = ntohl(rb.flcnpl) & 0x00FFFFFF;
	if (ctx->rr_last_ehsnr != 0) {
		uint32_t sent = g_atomic_int_get(&ctx->sent_packets_since_last_rr);
		uint32_t expect = ntohl(rb.ehsnr) - ctx->rr_last_ehsnr;
		int32_t nacks = g_atomic_int_get(&ctx->nack_count) - ctx->rr_last_nack_count;
		double link_q = !sent ? 0 : 100.0 - (100.0 * nacks / (double)sent);
		ctx->out_link_quality = janus_rtcp_link_quality_filter(ctx->out_link_quality, link_q);
		int32_t lost = total_lost - ctx->rr_last_lost;
		if(lost < 0) {
			lost = 0;
		}
		double media_link_q = !expect ? 0 : 100.0 - (100.0 * lost / (double)expect);
		ctx->out_media_link_quality = janus_rtcp_link_quality_filter(ctx->out_media_link_quality, media_link_q);
		JANUS_LOG(LOG_HUGE, "Out link quality=%"SCNu32", media link quality=%"SCNu32"\n", janus_rtcp_context_get_out_link_quality(ctx), janus_rtcp_context_get_out_media_link_quality(ctx));
	}
	ctx->rr_last_ehsnr = ntohl(rb.ehsnr);
	ctx->rr_last_lost = total_lost;
	ctx->rr_last_nack_count = g_atomic_int_get(&ctx->nack_count);
	g_atomic_int_set(&ctx->sent_packets_since_last_rr, 0);
}

/* Helper to handle an incoming RR: triggered by a call to janus_rtcp_fix_ssrc with fixssrc=0 */
static void janus_rtcp_incoming_rr(janus_rtcp_context *ctx, janus_rtcp_rr *rr) {
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
		janus_rtcp_rr_update_stats(ctx, rr->rb[0]);
		/* FIXME Compute round trip time */
		uint32_t lsr = ntohl(rr->rb[0].lsr);
		uint32_t dlsr = ntohl(rr->rb[0].delay);
		if(lsr == 0)	/* Not enough info yet */
			return;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint32_t s = tv.tv_sec + 2208988800u;
		uint32_t u = tv.tv_usec;
		uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
		uint32_t ntp_ts_msw = s;
		uint32_t ntp_ts_lsw = f;
		uint64_t temp = ((uint64_t)ntp_ts_msw << 32 ) | ntp_ts_lsw;
		uint32_t a = (uint32_t)(temp >> 16);
		uint32_t rtt = a - lsr - dlsr;
		uint32_t rtt_msw = (rtt & 0xFFFF0000) >> 16;
		uint32_t rtt_lsw = rtt & 0x0000FFFF;
		tv.tv_sec = rtt_msw;
		tv.tv_usec = (rtt_lsw * 15625) >> 10;
		ctx->rtt = tv.tv_sec*1000 + tv.tv_usec/1000;	/* We need milliseconds */
		JANUS_LOG(LOG_HUGE, "rtt=%"SCNu32"\n", ctx->rtt);
	}
}

gboolean janus_rtcp_check_len(janus_rtcp_header *rtcp, int len) {
	if (len < (int)sizeof(janus_rtcp_header) + (int)sizeof(uint32_t)) {
		JANUS_LOG(LOG_VERB, "Packet size is too small (%d bytes) to contain RTCP\n", len);
		return FALSE;
	}
	int header_def_len = 4*(int)ntohs(rtcp->length) + 4;
	if (len < header_def_len) {
		JANUS_LOG(LOG_VERB, "Invalid RTCP packet defined length, expected %d bytes > actual %d bytes\n", header_def_len, len);
		return FALSE;
	}
	return TRUE;
}

gboolean janus_rtcp_check_sr(janus_rtcp_header *rtcp, int len) {
	if (len < (int)sizeof(janus_rtcp_header) + (int)sizeof(uint32_t) + (int)sizeof(sender_info)) {
		JANUS_LOG(LOG_VERB, "RTCP Packet is too small (%d bytes) to contain SR\n", len);
		return FALSE;
	}
	int header_rb_len = (int)(rtcp->rc)*(int)sizeof(report_block);
	int actual_rb_len = len - (int)sizeof(janus_rtcp_header) - (int)sizeof(uint32_t) - (int)sizeof(sender_info);
	if (actual_rb_len < header_rb_len) {
		JANUS_LOG(LOG_VERB, "SR got %d RB count, expected %d bytes > actual %d bytes\n", rtcp->rc, header_rb_len, actual_rb_len);
		return FALSE;
	}
	return TRUE;
}

gboolean janus_rtcp_check_rr(janus_rtcp_header *rtcp, int len) {
	int header_rb_len = (int)(rtcp->rc)*(int)sizeof(report_block);
	int actual_rb_len = len - (int)sizeof(janus_rtcp_header) - (int)sizeof(uint32_t);
	if (actual_rb_len < header_rb_len) {
		JANUS_LOG(LOG_VERB, "RR got %d RB count, expected %d bytes > actual %d bytes\n", rtcp->rc, header_rb_len, actual_rb_len);
		return FALSE;
	}
	return TRUE;
}

gboolean janus_rtcp_check_fci(janus_rtcp_header *rtcp, int len, int sizeof_fci) {
	/* At least one sizeof_fci bytes FCI */
	if (len < (int)sizeof(janus_rtcp_header) + 2*(int)sizeof(uint32_t) + sizeof_fci) {
		JANUS_LOG(LOG_VERB, "RTCP Packet is too small (%d bytes) to contain at least one %d bytes FCI\n", len, sizeof_fci);
		return FALSE;
	}
	/* Evaluate fci total size */
	int fci_size = len - (int)sizeof(janus_rtcp_header) - 2*(int)sizeof(uint32_t);
	/*  The length of the feedback message is set to 2+(sizeof_fci/4)*N where
		N is the number of FCI entries */
	int fcis;
	switch(sizeof_fci) {
		case 0:
			fcis = 0;
			break;
		case 4:
			fcis = (int)ntohs(rtcp->length) - 2;
			break;
		case 8:
			fcis = ((int)ntohs(rtcp->length) - 2) >> 1;
			break;
		default:
			fcis = ((int)ntohs(rtcp->length)- 2) / (sizeof_fci >> 2);
			break;
	}
	/* Every FCI is sizeof_fci bytes */
	if (fci_size < sizeof_fci*fcis) {
		JANUS_LOG(LOG_VERB, "Got %d FCI count, expected %d bytes > actual %d bytes\n", fcis, sizeof_fci*fcis, fci_size);
		return FALSE;
	}
	return TRUE;
}

gboolean janus_rtcp_check_remb(janus_rtcp_header *rtcp, int len) {
	/* At least 1 SSRC feedback */
	if (len < (int)sizeof(janus_rtcp_header) + 2*(int)sizeof(uint32_t) + 3*(int)sizeof(uint32_t)) {
		JANUS_LOG(LOG_VERB, "Packet is too small (%d bytes) to contain REMB\n", len);
		return FALSE;
	}
	janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
	uint8_t numssrc = *(rtcpfb->fci+4);
	/* Evaluate ssrcs total size */
	int ssrc_size = len - (int)sizeof(janus_rtcp_header) - 2*(int)sizeof(uint32_t);
	/* Every SSRC is 4 bytes */
	if (ssrc_size < 4*numssrc) {
		JANUS_LOG(LOG_VERB, "REMB got %d SSRC count, expected %d bytes > actual %d bytes\n", numssrc, 4*numssrc, ssrc_size);
		return FALSE;
	}
	return TRUE;
}

int janus_rtcp_fix_ssrc(janus_rtcp_context *ctx, char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr) {
	if(packet == NULL || len <= 0)
		return -1;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	JANUS_LOG(LOG_HUGE, "   Parsing compound packet (total of %d bytes)\n", total);
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			return -2;
		if(rtcp->version != 2)
			return -2;
		pno++;
		/* TODO Should we handle any of these packets ourselves, or just relay them? */
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				JANUS_LOG(LOG_HUGE, "     #%d SR (200)\n", pno);
				if (!janus_rtcp_check_sr(rtcp, total))
					return -2;
				janus_rtcp_sr *sr = (janus_rtcp_sr *)rtcp;
				/* If an RTCP context was provided, update it with info on this SR */
				janus_rtcp_incoming_sr(ctx, sr);
				if(fixssrc && newssrcl) {
					sr->ssrc = htonl(newssrcl);
					if (sr->header.rc > 0) {
						sr->rb[0].ssrc = htonl(newssrcr);
					}
				}
				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				JANUS_LOG(LOG_HUGE, "     #%d RR (201)\n", pno);
				if (!janus_rtcp_check_rr(rtcp, total))
					return -2;
				janus_rtcp_rr *rr = (janus_rtcp_rr *)rtcp;
				/* If an RTCP context was provided, update it with info on this RR */
				janus_rtcp_incoming_rr(ctx, rr);
				if(fixssrc && newssrcl) {
					rr->ssrc = htonl(newssrcl);
					if (rr->header.rc > 0) {
						rr->rb[0].ssrc = htonl(newssrcr);
					}
				}
				break;
			}
			case RTCP_SDES: {
				/* SDES, source description */
				JANUS_LOG(LOG_HUGE, "     #%d SDES (202)\n", pno);
				janus_rtcp_sdes *sdes = (janus_rtcp_sdes *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(sdes->chunk.ssrc));
				if(fixssrc && newssrcl) {
					sdes->chunk.ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_BYE: {
				/* BYE, goodbye */
				JANUS_LOG(LOG_HUGE, "     #%d BYE (203)\n", pno);
				janus_rtcp_bye *bye = (janus_rtcp_bye *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(bye->ssrc[0]));
				if(fixssrc && newssrcl) {
					bye->ssrc[0] = htonl(newssrcl);
				}
				break;
			}
			case RTCP_APP: {
				/* APP, application-defined */
				JANUS_LOG(LOG_HUGE, "     #%d APP (204)\n", pno);
				janus_rtcp_app *app = (janus_rtcp_app *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(app->ssrc));
				if(fixssrc && newssrcl) {
					app->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_FIR: {
				/* FIR, rfc2032 */
				JANUS_LOG(LOG_HUGE, "     #%d FIR (192)\n", pno);
				break;
			}
			case RTCP_RTPFB: {
				/* RTPFB, Transport layer FB message (rfc4585) */
				//~ JANUS_LOG(LOG_HUGE, "     #%d RTPFB (205)\n", pno);
				gint fmt = rtcp->rc;
				//~ JANUS_LOG(LOG_HUGE, "       -- FMT: %u\n", fmt);
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					JANUS_LOG(LOG_HUGE, "     #%d NACK -- RTPFB (205)\n", pno);
					/* NACK FCI size is 4 bytes */
					if (!janus_rtcp_check_fci(rtcp, total, 4))
						return -2;
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
					int nacks = ntohs(rtcp->length)-2;	/* Skip SSRCs */
					if(nacks > 0) {
						JANUS_LOG(LOG_DBG, "        Got %d nacks\n", nacks);
						janus_rtcp_nack *nack = NULL;
						uint16_t pid = 0;
						uint16_t blp = 0;
						int i=0, j=0;
						char bitmask[20];
						for(i=0; i< nacks; i++) {
							nack = (janus_rtcp_nack *)rtcpfb->fci + i;
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
						/* TMMBR FCI size is 8 bytes */
						if (!janus_rtcp_check_fci(rtcp, total, 8))
							return -2;
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
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					JANUS_LOG(LOG_HUGE, "     #%d PLI -- PSFB (206)\n", pno);
					/* PLI does not require parameters.  Therefore, the length field MUST be
						2, and there MUST NOT be any Feedback Control Information. */
					if(fixssrc && newssrcr) {
						if (!janus_rtcp_check_fci(rtcp, total, 0))
							return -2;
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
						/* FIR FCI size is 8 bytes */
						if (!janus_rtcp_check_fci(rtcp, total, 8))
							return -2;
						rtcpfb->media = htonl(newssrcr);
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else if(fmt == 5) {	/* rfc5104 */
					/* TSTR: http://tools.ietf.org/html/rfc5104#section-4.3.2.1 */
					JANUS_LOG(LOG_HUGE, "     #%d PLI -- TSTR (206)\n", pno);
				} else if(fmt == 15) {
					//~ JANUS_LOG(LOG_HUGE, "       -- This is a AFB!\n");
					janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
					if(fixssrc && newssrcr) {
						/* AFB FCI size is variable, check just media SSRC */
						if (!janus_rtcp_check_fci(rtcp, total, 0))
							return -2;
						rtcpfb->ssrc = htonl(newssrcr);
						rtcpfb->media = 0;
					}
					janus_rtcp_fb_remb *remb = (janus_rtcp_fb_remb *)rtcpfb->fci;
					if(janus_rtcp_check_remb(rtcp, total) && remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
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
						uint32_t bitRate = (uint64_t)brMantissa << brExp;
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
				janus_rtcp_xr *xr = (janus_rtcp_xr *)rtcp;
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
		if(total <= 0)
			break;
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

char *janus_rtcp_filter(char *packet, int len, int *newlen) {
	if(packet == NULL || len <= 0 || newlen == NULL)
		return NULL;
	*newlen = 0;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	char *filtered = NULL;
	int total = len, length = 0, bytes = 0;
	/* Iterate on the compound packets */
	gboolean keep = TRUE;
	gboolean error = FALSE;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total)) {
			error = TRUE;
			break;
		}
		if(rtcp->version != 2) {
			error = TRUE;
			break;
		}
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	if (error) {
		g_free(filtered);
		filtered = NULL;
		*newlen = 0;
	}
	return filtered;
}


int janus_rtcp_process_incoming_rtp(janus_rtcp_context *ctx, char *packet, int len, gboolean count_lost) {
	if(ctx == NULL || packet == NULL || len < 1)
		return -1;

	/* First of all, let's check if this is G.711: in case we may need to change the timestamp base */
	janus_rtp_header *rtp = (janus_rtp_header *)packet;
	int pt = rtp->type;
	if((pt == 0 || pt == 8) && (ctx->tb == 48000))
		ctx->tb = 8000;
	/* Now parse this RTP packet header and update the rtcp_context instance */
	uint16_t seq_number = ntohs(rtp->seq_number);
	if(ctx->base_seq == 0 && ctx->seq_cycle == 0)
		ctx->base_seq = seq_number;

	if((int16_t)(seq_number - ctx->max_seq_nr) < 0) {
		/* Late packet or retransmission */
		ctx->retransmitted++;
	} else {
		if(seq_number < ctx->max_seq_nr)
			ctx->seq_cycle++;
		ctx->max_seq_nr = seq_number;
		ctx->received++;
	}
	uint32_t rtp_expected = 0x0;
	if(ctx->seq_cycle > 0) {
		rtp_expected = ctx->seq_cycle;
		rtp_expected = rtp_expected << 16;
	}
	rtp_expected = rtp_expected + 1 + ctx->max_seq_nr - ctx->base_seq;
	if(count_lost && rtp_expected >= ctx->received)
		ctx->lost = rtp_expected - ctx->received;
	ctx->expected = rtp_expected;

	int64_t arrival = (janus_get_monotonic_time() * ctx->tb) / 1000000;
	int64_t transit = arrival - ntohl(rtp->timestamp);
	int64_t d = transit - ctx->transit;
	if (d < 0) d = -d;
	ctx->transit = transit;
	ctx->jitter += (1./16.) * ((double)d  - ctx->jitter);

	/* RTP packet received: it means we can start sending RR */
	ctx->rtp_recvd = 1;

	return 0;
}


uint32_t janus_rtcp_context_get_rtt(janus_rtcp_context *ctx) {
	return ctx ? ctx->rtt : 0;
}

uint32_t janus_rtcp_context_get_in_link_quality(janus_rtcp_context *ctx) {
	return ctx ? (uint32_t)(ctx->in_link_quality + 0.5) : 0;
}

uint32_t janus_rtcp_context_get_in_media_link_quality(janus_rtcp_context *ctx) {
	return ctx ? (uint32_t)(ctx->in_media_link_quality + 0.5) : 0;
}

uint32_t janus_rtcp_context_get_out_link_quality(janus_rtcp_context *ctx) {
	return ctx ? (uint32_t)(ctx->out_link_quality + 0.5) : 0;
}

uint32_t janus_rtcp_context_get_out_media_link_quality(janus_rtcp_context *ctx) {
	return ctx ? (uint32_t)(ctx->out_media_link_quality + 0.5) : 0;
}

uint32_t janus_rtcp_context_get_lost_all(janus_rtcp_context *ctx, gboolean remote) {
	if(ctx == NULL)
		return 0;
	return remote ? ctx->lost_remote : ctx->lost;
}

static uint32_t janus_rtcp_context_get_lost(janus_rtcp_context *ctx) {
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

static uint32_t janus_rtcp_context_get_lost_fraction(janus_rtcp_context *ctx) {
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

uint32_t janus_rtcp_context_get_jitter(janus_rtcp_context *ctx, gboolean remote) {
	if(ctx == NULL || ctx->tb == 0)
		return 0;
	return (uint32_t) floor((remote ? ctx->jitter_remote : ctx->jitter) * 1000.0 / ctx->tb);
}

static void janus_rtcp_estimate_in_link_quality(janus_rtcp_context *ctx) {
	int64_t ts = janus_get_monotonic_time();
	int64_t delta_t = ts - ctx->out_rr_last_ts;
	if(delta_t < 3*G_USEC_PER_SEC) {
		return;
	}
	ctx->out_rr_last_ts = ts;

	uint32_t expected_interval = ctx->expected - ctx->expected_prior;
	uint32_t received_interval = ctx->received - ctx->received_prior;
	uint32_t retransmitted_interval = ctx->retransmitted - ctx->retransmitted_prior;

	int32_t link_lost = expected_interval - (received_interval - retransmitted_interval);
	double link_q = !expected_interval ? 0 : 100.0 - (100.0 * (double)link_lost / (double)expected_interval);
	ctx->in_link_quality = janus_rtcp_link_quality_filter(ctx->in_link_quality, link_q);

	int32_t lost = expected_interval - received_interval;
	if (lost < 0) {
		lost = 0;
	}
	double media_link_q = !expected_interval ? 0 : 100.0 - (100.0 * (double)lost / (double)expected_interval);
	ctx->in_media_link_quality = janus_rtcp_link_quality_filter(ctx->in_media_link_quality, media_link_q);

	JANUS_LOG(LOG_HUGE, "In link quality=%"SCNu32", media link quality=%"SCNu32"\n", janus_rtcp_context_get_in_link_quality(ctx), janus_rtcp_context_get_in_media_link_quality(ctx));
}

int janus_rtcp_report_block(janus_rtcp_context *ctx, janus_report_block *rb) {
	if(ctx == NULL || rb == NULL)
		return -1;
	gint64 now = janus_get_monotonic_time();
	rb->jitter = htonl((uint32_t) ctx->jitter);
	rb->ehsnr = htonl((((uint32_t) 0x0 + ctx->seq_cycle) << 16) + ctx->max_seq_nr);
	uint32_t lost = janus_rtcp_context_get_lost(ctx);
	uint32_t fraction = janus_rtcp_context_get_lost_fraction(ctx);
	janus_rtcp_estimate_in_link_quality(ctx);
	ctx->expected_prior = ctx->expected;
	ctx->received_prior = ctx->received;
	ctx->retransmitted_prior = ctx->retransmitted;
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

int janus_rtcp_fix_report_data(char *packet, int len, uint32_t base_ts, uint32_t base_ts_prev, uint32_t ssrc_peer, uint32_t ssrc_local, uint32_t ssrc_expected, gboolean video) {
	if(packet == NULL || len <= 0)
		return -1;
	/* Parse RTCP compound packet */
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len, status = 0;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			return -2;
		if(rtcp->version != 2)
			return -2;
		pno++;
		switch(rtcp->type) {
			case RTCP_RR: {
				if (!janus_rtcp_check_rr(rtcp, total))
					return -2;
				janus_rtcp_rr *rr = (janus_rtcp_rr *)rtcp;
				rr->ssrc = htonl(ssrc_peer);
				status++;
				if (rr->header.rc > 0) {
					rr->rb[0].ssrc = htonl(ssrc_local);
					status++;
					/* FIXME we need to fix the extended highest sequence number received */
					/* FIXME we need to fix the cumulative number of packets lost */
					break;
				}
				break;
			}
			case RTCP_SR: {
				if (!janus_rtcp_check_sr(rtcp, total))
					return -2;
				janus_rtcp_sr *sr = (janus_rtcp_sr *)rtcp;
				uint32_t recv_ssrc = ntohl(sr->ssrc);
				if (recv_ssrc != ssrc_expected) {
					if(ssrc_expected != 0) {
						JANUS_LOG(LOG_WARN,"Incoming RTCP SR SSRC (%"SCNu32") does not match the expected one (%"SCNu32") video=%d\n", recv_ssrc, ssrc_expected, video);
					}
					return -3;
				}
				sr->ssrc = htonl(ssrc_peer);
				/* FIXME we need to fix the sender's packet count */
				/* FIXME we need to fix the sender's octet count */
				uint32_t sr_ts = ntohl(sr->si.rtp_ts);
				uint32_t fix_ts = (sr_ts - base_ts) + base_ts_prev;
				sr->si.rtp_ts = htonl(fix_ts);
				status++;
				if (sr->header.rc > 0) {
					sr->rb[0].ssrc = htonl(ssrc_local);
					status++;
					/* FIXME we need to fix the extended highest sequence number received */
					/* FIXME we need to fix the cumulative number of packets lost */
					break;
				}
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return status;
}

gboolean janus_rtcp_has_bye(char *packet, int len) {
	/* Parse RTCP compound packet */
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		pno++;
		switch(rtcp->type) {
			case RTCP_BYE:
				return TRUE;
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return FALSE;
}

gboolean janus_rtcp_has_fir(char *packet, int len) {
	/* Parse RTCP compound packet */
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		pno++;
		switch(rtcp->type) {
			case RTCP_FIR:
				return TRUE;
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return FALSE;
}

gboolean janus_rtcp_has_pli(char *packet, int len) {
	/* Parse RTCP compound packet */
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	int pno = 0, total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		pno++;
		switch(rtcp->type) {
			case RTCP_PSFB: {
				gint fmt = rtcp->rc;
				if(fmt == 1)
					return TRUE;
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return FALSE;
}

GSList *janus_rtcp_get_nacks(char *packet, int len) {
	if(packet == NULL || len == 0)
		return NULL;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* FIXME Get list of sequence numbers we should send again */
	GSList *list = NULL;
	int total = len;
	gboolean error = FALSE;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total)) {
			error = TRUE;
			break;
		}
		if (rtcp->version != 2) {
			error = TRUE;
			break;
		}
		if(rtcp->type == RTCP_RTPFB) {
			gint fmt = rtcp->rc;
			if(fmt == 1) {
				/* NACK FCI size is 4 bytes */
				if (!janus_rtcp_check_fci(rtcp, total, 4)) {
					error = TRUE;
					break;
				}
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				int nacks = ntohs(rtcp->length)-2;	/* Skip SSRCs */
				if(nacks > 0) {
					JANUS_LOG(LOG_DBG, "        Got %d nacks\n", nacks);
					janus_rtcp_nack *nack = NULL;
					uint16_t pid = 0;
					uint16_t blp = 0;
					int i=0, j=0;
					char bitmask[20];
					for(i=0; i< nacks; i++) {
						nack = (janus_rtcp_nack *)rtcpfb->fci + i;
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
				break;
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	if (error && list) {
		g_slist_free(list);
		list = NULL;
	}
	return list;
}

int janus_rtcp_remove_nacks(char *packet, int len) {
	if(packet == NULL || len == 0)
		return len;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Find the NACK message */
	char *nacks = NULL;
	int total = len, nacks_len = 0;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total)) {
			break;
		}
		if(rtcp->version != 2)
			break;
		if(rtcp->type == RTCP_RTPFB) {
			gint fmt = rtcp->rc;
			if(fmt == 1) {
				nacks = (char *)rtcp;
				if (!janus_rtcp_check_fci(rtcp, total, 4)) {
					break;
				}
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
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
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Get REMB bitrate, if any */
	int total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			break;
		if(rtcp->version != 2)
			break;
		if(rtcp->type == RTCP_PSFB) {
			gint fmt = rtcp->rc;
			if(fmt == 15) {
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				janus_rtcp_fb_remb *remb = (janus_rtcp_fb_remb *)rtcpfb->fci;
				if(janus_rtcp_check_remb(rtcp, total) && remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
					/* FIXME From rtcp_utility.cc */
					unsigned char *_ptrRTCPData = (unsigned char *)remb;
					_ptrRTCPData += 4;	/* Skip unique identifier and num ssrc */
					//~ JANUS_LOG(LOG_VERB, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
					uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
					uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
					brMantissa += (_ptrRTCPData[2] << 8);
					brMantissa += (_ptrRTCPData[3]);
					uint32_t bitrate = (uint64_t)brMantissa << brExp;
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Change an existing REMB message */
int janus_rtcp_cap_remb(char *packet, int len, uint32_t bitrate) {
	if(packet == NULL || len == 0)
		return -1;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	if(bitrate == 0)
		return 0;	/* No need to cap */
	/* Cap REMB bitrate */
	int total = len;
	while(rtcp) {
		if (!janus_rtcp_check_len(rtcp, total))
			return -2;
		if(rtcp->version != 2)
			return -2;
		if(rtcp->type == RTCP_PSFB) {
			gint fmt = rtcp->rc;
			if(fmt == 15) {
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				janus_rtcp_fb_remb *remb = (janus_rtcp_fb_remb *)rtcpfb->fci;
				if(janus_rtcp_check_remb(rtcp, total) && remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
					/* FIXME From rtcp_utility.cc */
					unsigned char *_ptrRTCPData = (unsigned char *)remb;
					_ptrRTCPData += 4;	/* Skip unique identifier and num ssrc */
					//~ JANUS_LOG(LOG_VERB, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
					uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
					uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
					brMantissa += (_ptrRTCPData[2] << 8);
					brMantissa += (_ptrRTCPData[3]);
					uint32_t origbitrate = (uint64_t)brMantissa << brExp;
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
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

/* Generate a new SDES message */
int janus_rtcp_sdes_cname(char *packet, int len, const char *cname, int cnamelen) {
	if(packet == NULL || len <= 0 || cname == NULL || cnamelen <= 0)
		return -1;
	memset(packet, 0, len);
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_SDES;
	rtcp->rc = 1;
	int plen = 8;	/* Header + chunk + item header */
	plen += cnamelen+3; /* cname item header(2) + cnamelen + terminator(1) */
	/* calculate padding length. assume that plen is shorter than 65535 */
	plen = (plen + 3) & 0xFFFC;
	if(len < plen) {
		JANUS_LOG(LOG_ERR, "Buffer too small for SDES message: %d < %d\n", len, plen);
		return -1;
	}
	rtcp->length = htons((plen/4)-1);
	/* Now set SDES stuff */
	janus_rtcp_sdes *rtcpsdes = (janus_rtcp_sdes *)rtcp;
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
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 15;
	rtcp->length = htons((min_len/4)-1);
	/* Now set REMB stuff */
	janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
	janus_rtcp_fb_remb *remb = (janus_rtcp_fb_remb *)rtcpfb->fci;
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
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	*seqnr = *seqnr + 1;
	if(*seqnr < 0 || *seqnr >= 256)
		*seqnr = 0;	/* Reset sequence number */
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 4;	/* FMT=4 */
	rtcp->length = htons((len/4)-1);
	/* Now set FIR stuff */
	janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
	janus_rtcp_fb_fir *fir = (janus_rtcp_fb_fir *)rtcpfb->fci;
	fir->seqnr = htonl(*seqnr << 24);	/* FCI: Sequence number */
	JANUS_LOG(LOG_HUGE, "[FIR] seqnr=%d (%d bytes)\n", *seqnr, 4*(ntohs(rtcp->length)+1));
	return 20;
}

/* Generate a new PLI message */
int janus_rtcp_pli(char *packet, int len) {
	if(packet == NULL || len != 12)
		return -1;
	memset(packet, 0, len);
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
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
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_RTPFB;
	rtcp->rc = 1;	/* FMT=1 */
	/* Now set NACK stuff */
	janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
	janus_rtcp_nack *nack = (janus_rtcp_nack *)rtcpfb->fci;
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
			JANUS_LOG(LOG_HUGE, "Adding another block of NACKs (%"SCNu16"-%"SCNu16" > 16)...\n", npid, pid);
			words++;
			if(len < (words*4+4)) {
				JANUS_LOG(LOG_ERR, "Buffer too small: %d < %d (at least %d NACK blocks needed)\n", len, words*4+4, words);
				return -1;
			}
			char *new_block = packet + words*4;
			nack = (janus_rtcp_nack *)new_block;
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

typedef enum janus_rtp_packet_status {
	janus_rtp_packet_status_notreceived = 0,
	janus_rtp_packet_status_smalldelta = 1,
	janus_rtp_packet_status_largeornegativedelta = 2,
	janus_rtp_packet_status_reserved = 3
} janus_rtp_packet_status;

int janus_rtcp_transport_wide_cc_feedback(char *packet, size_t size, guint32 ssrc, guint32 media, guint8 feedback_packet_count, GQueue *transport_wide_cc_stats) {
	if(packet == NULL || size < sizeof(janus_rtcp_header) || transport_wide_cc_stats == NULL || g_queue_is_empty(transport_wide_cc_stats))
		return -1;

	memset(packet, 0, size);
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_RTPFB;
	rtcp->rc = 15;
	/* Now set FB stuff */
	janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
	rtcpfb->ssrc = htonl(ssrc);
	rtcpfb->media = htonl(media);

	/* Get first packet */
	janus_rtcp_transport_wide_cc_stats *stat = (janus_rtcp_transport_wide_cc_stats *) g_queue_pop_head (transport_wide_cc_stats);
	/* Calculate temporal info */
	guint16 base_seq_num = stat->transport_seq_num;
	gboolean first_received	= FALSE;
	guint64 reference_time = 0;
	guint packet_status_count = g_queue_get_length(transport_wide_cc_stats) + 1;

	/*
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	       |      base sequence number     |      packet status count      |
	       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	       |                 reference time                | fb pkt. count |
	       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	/* The packet as unsigned */
	guint8 *data = (guint8 *)packet;
	/* The start of the feedback data */
	size_t len = sizeof(janus_rtcp_header) + 8;

	/* Set header data */
	janus_set2(data, len, base_seq_num);
	janus_set2(data, len+2, packet_status_count);
	/* Set3 referenceTime when first received */
	size_t reference_time_pos = len + 4;
	janus_set1(data, len+7, feedback_packet_count);

	/* Next byte */
	len += 8;

	/* Initial time in us */
	guint64 timestamp = 0;

	/* Store delta array */
	GQueue *deltas = g_queue_new();
	GQueue *statuses = g_queue_new();
	janus_rtp_packet_status last_status = janus_rtp_packet_status_reserved;
	janus_rtp_packet_status max_status = janus_rtp_packet_status_notreceived;
	gboolean all_same = TRUE;

	/* For each packet  */
	while (stat != NULL) {
		janus_rtp_packet_status status = janus_rtp_packet_status_notreceived;

		/* If got packet */
		if (stat->timestamp) {
			int delta = 0;
			/* If first received */
			if (!first_received) {
				/* Got it  */
				first_received = TRUE;
				/* Set it */
				reference_time = (stat->timestamp/64000);
				/* Get initial time */
				timestamp = reference_time * 64000;
				/* also in bufffer */
				janus_set3(data, reference_time_pos, reference_time);
			}

			/* Get delta */
			if (stat->timestamp>timestamp)
				delta = (stat->timestamp-timestamp)/250;
			else
				delta = -(int)((timestamp-stat->timestamp)/250);
			/* If it is negative or too big */
			if (delta<0 || delta> 127) {
				/* Big one */
				status = janus_rtp_packet_status_largeornegativedelta;
			} else {
				/* Small */
				status = janus_rtp_packet_status_smalldelta;
			}
			/* Store delta */
			g_queue_push_tail(deltas, GINT_TO_POINTER(delta));
			/* Set last time */
			timestamp = stat->timestamp;
		}

		/* Check if all previoues ones were equal and this one the firt different */
		if (all_same && last_status!=janus_rtp_packet_status_reserved && status!=last_status) {
			/* How big was the same run */
			if (g_queue_get_length(statuses)>7) {
				guint32 word = 0;
				/* Write run! */
				/*
					0                   1
					0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				       |T| S |       Run Length        |
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					T = 0
				 */
				word = janus_push_bits(word, 1, 0);
				word = janus_push_bits(word, 2, last_status);
				word = janus_push_bits(word, 13, g_queue_get_length(statuses));
				/* Write word */
				janus_set2(data, len, word);
				len += 2;
				/* Remove all statuses */
				g_queue_clear(statuses);
				/* Reset status */
				last_status = janus_rtp_packet_status_reserved;
				max_status = janus_rtp_packet_status_notreceived;
				all_same = TRUE;
			} else {
				/* Not same */
				all_same = FALSE;
			}
		}

		/* Push back statuses, it will be handled later */
		g_queue_push_tail(statuses, GUINT_TO_POINTER(status));

		/* If it is bigger */
		if (status>max_status) {
			/* Store it */
			max_status = status;
		}
		/* Store las status */
		last_status = status;

		/* Check if we can still be enquing for a run */
		if (!all_same) {
			/* Check  */
			if (!all_same && max_status==janus_rtp_packet_status_largeornegativedelta && g_queue_get_length(statuses)>6) {
				guint32 word = 0;
				/*
					0                   1
					0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				       |T|S|        Symbols            |
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					T = 1
					S = 1
				 */
				word = janus_push_bits(word, 1, 1);
				word = janus_push_bits(word, 1, 1);
				/* Set next 7 */
				size_t i = 0;
				for (i=0;i<7;++i) {
					/* Get status */
					janus_rtp_packet_status status = (janus_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
					/* Write */
					word = janus_push_bits(word, 2, (guint8)status);
				}
				/* Write word */
				janus_set2(data, len, word);
				len += 2;
				/* Reset */
				last_status = janus_rtp_packet_status_reserved;
				max_status = janus_rtp_packet_status_notreceived;
				all_same = TRUE;

				/* We need to restore the values, as there may be more elements on the buffer */
				for (i=0; i<g_queue_get_length(statuses); ++i) {
					/* Get status */
					status = (janus_rtp_packet_status) GPOINTER_TO_UINT(g_queue_peek_nth(statuses, i));
					/* If it is bigger */
					if (status>max_status) {
						/* Store it */
						max_status = status;
					}
					//Check if it is the same */
					if (all_same && last_status!=janus_rtp_packet_status_reserved && status!=last_status) {
						/* Not the same */
						all_same = FALSE;
					}
					/* Store las status */
					last_status = status;
				}
			} else if (!all_same && g_queue_get_length(statuses)>13) {
				guint32 word = 0;
				/*
					0                   1
					0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				       |T|S|       symbol list         |
				       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					 T = 1
					 S = 0
				 */
				word = janus_push_bits(word, 1, 1);
				word = janus_push_bits(word, 1, 0);
				/* Set next 7 */
				guint32 i = 0;
				for (i=0;i<14;++i) {
					/* Get status */
					janus_rtp_packet_status status = (janus_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
					/* Write */
					word = janus_push_bits(word, 1, (guint8)status);
				}
				/* Write word */
				janus_set2(data, len, word);
				len += 2;
				/* Reset */
				last_status = janus_rtp_packet_status_reserved;
				max_status = janus_rtp_packet_status_notreceived;
				all_same = TRUE;
			}
		}
		/* Free mem */
		g_free(stat);

		/* Get next packet stat */
		stat = (janus_rtcp_transport_wide_cc_stats *) g_queue_pop_head (transport_wide_cc_stats);
	}

	/* Get status len */
	size_t statuses_len = g_queue_get_length(statuses);

	/* If not finished yet */
	if (statuses_len>0) {
		/* How big was the same run */
		if (all_same) {
			guint32 word = 0;
			/* Write run! */
			word = janus_push_bits(word, 1, 0);
			word = janus_push_bits(word, 2, last_status);
			word = janus_push_bits(word, 13, statuses_len);
			/* Write word */
			janus_set2(data, len, word);
			len += 2;
		} else if (max_status == janus_rtp_packet_status_largeornegativedelta) {
			guint32 word = 0;
			/* Write chunk */
			word = janus_push_bits(word, 1, 1);
			word = janus_push_bits(word, 1, 1);
			/* Write all the statuses */
			unsigned int i = 0;
			for (i=0;i<statuses_len;i++) {
				/* Get each status */
				janus_rtp_packet_status status = (janus_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
				/* Write */
				word = janus_push_bits(word, 2, (guint8)status);
			}
			/* Write pending */
			word = janus_push_bits(word, 14-statuses_len*2, 0);
			/* Write word */
			janus_set2(data , len, word);
			len += 2;
		} else {
			guint32 word = 0;
			/* Write chunck */
			word = janus_push_bits(word, 1, 1);
			word = janus_push_bits(word, 1, 0);
			/* Write all the statuses */
			unsigned int i = 0;
			for (i=0;i<statuses_len;i++) {
				/* Get each status */
				janus_rtp_packet_status status = (janus_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
				/* Write */
				word = janus_push_bits(word, 1, (guint8)status);
			}
			/* Write pending */
			word = janus_push_bits(word, 14-statuses_len, 0);
			/* Write word */
			janus_set2(data, len, word);
			len += 2;
		}
	}

	/* Write now the deltas */
	while (!g_queue_is_empty(deltas)) {
		/* Get next delta */
		gint delta = GPOINTER_TO_INT(g_queue_pop_head (deltas));
		/* Check size */
		if (delta<0 || delta>127) {
			/* 2 bytes */
			janus_set2(data, len, (short)delta);
			/* Inc */
			len += 2;
		} else {
			/* 1 byte */
			janus_set1(data, len, (guint8)delta);
			/* Inc */
			len ++;
		}
	}

	/* Clean mem */
	g_queue_free(statuses);
	g_queue_free(deltas);

	/* Add zero padding */
	while (len%4) {
		/* Add padding */
		janus_set1(data, len++, 0);
	}

	/* Set RTCP Len */
	rtcp->length = htons((len/4)-1);

	/* Done */
	return len;
}
