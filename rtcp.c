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
 
#include "debug.h"
#include "rtcp.h"

int janus_rtcp_parse(char *packet, int len) {
	return janus_rtcp_fix_ssrc(packet, len, 0, 0, 0);
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

int janus_rtcp_fix_ssrc(char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr) {
	if(packet == NULL || len == 0)
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
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u (%u in RB)\n", ntohl(sr->ssrc), report_block_get_ssrc(&sr->rb[0]));
				//~ JANUS_LOG(LOG_HUGE, "       -- Lost: %u/%u\n", report_block_get_fraction_lost(&sr->rb[0]), report_block_get_cum_packet_loss(&sr->rb[0]));
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
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u (%u in RB)\n", ntohl(rr->ssrc), report_block_get_ssrc(&rr->rb[0]));
				//~ JANUS_LOG(LOG_HUGE, "       -- Lost: %u/%u\n", report_block_get_fraction_lost(&rr->rb[0]), report_block_get_cum_packet_loss(&rr->rb[0]));
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
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(sr->ssrc));
				if(fixssrc && newssrcl) {
					sdes->ssrc = htonl(newssrcl);
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
					//~ int nacks = ntohs(rtcp->length)-2;	/* Skip SSRCs */
					//~ if(nacks > 0) {
						//~ JANUS_LOG(LOG_HUGE, "        Got %d nacks\n", nacks);
						//~ rtcp_nack *nack = NULL;
						//~ uint16_t pid = 0;
						//~ uint16_t blp = 0;
						//~ int i=0, j=0;
						//~ char bitmask[20];
						//~ for(i=0; i< nacks; i++) {
							//~ nack = (rtcp_nack *)rtcpfb->fci + i;
							//~ pid = ntohs(nack->pid);
							//~ blp = ntohs(nack->blp);
							//~ memset(bitmask, 0, 20);
							//~ for(j=0; j<16; j++) {
								//~ bitmask[j] = (blp & ( 1 << j )) >> j ? '1' : '0';
							//~ }
							//~ bitmask[16] = '\n';
							//~ JANUS_LOG(LOG_HUGE, "[%d] %"SCNu16" / %s\n", i, pid, bitmask);
						//~ }
					//~ }
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
					rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
					if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
						JANUS_LOG(LOG_HUGE, "     #%d REMB -- PSFB (206)\n", pno);
						/* FIXME From rtcp_utility.cc */
						unsigned char *_ptrRTCPData = (unsigned char *)remb;
						_ptrRTCPData += 4;	// Skip unique identifier and num ssrc
						//~ JANUS_LOG(LOG_HUGE, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
						uint8_t numssrc = (_ptrRTCPData[0]);
						uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
						uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
						brMantissa += (_ptrRTCPData[2] << 8);
						brMantissa += (_ptrRTCPData[3]);
						uint64_t bitRate = brMantissa << brExp;
						JANUS_LOG(LOG_HUGE, "       -- -- -- REMB: %u * 2^%u = %"SCNu64" (%d SSRCs, %u)\n",
							brMantissa, brExp, bitRate, numssrc, ntohl(remb->ssrc[0]));

						if(fixssrc && newssrcr) {
							remb->ssrc[0] = htonl(newssrcr);
						}
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
			default:
				JANUS_LOG(LOG_ERR, "     Unknown RTCP PT %d\n", rtcp->type);
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
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
					JANUS_LOG(LOG_VERB, "        Got %d nacks\n", nacks);
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
						JANUS_LOG(LOG_VERB, "[%d] %"SCNu16" / %s\n", i, pid, bitmask);
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

/* Change an existing REMB message */
int janus_rtcp_cap_remb(char *packet, int len, uint64_t bitrate) {
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
					uint64_t origbitrate = brMantissa << brExp;
					if(origbitrate > bitrate) {
						JANUS_LOG(LOG_VERB, "Got REMB bitrate %"SCNu64", need to cap it to %"SCNu64"\n", origbitrate, bitrate);
						JANUS_LOG(LOG_HUGE, "  >> %u * 2^%u = %"SCNu64"\n", brMantissa, brExp, origbitrate);
						/* bitrate --> brexp/brmantissa */
						uint8_t b = 0;
						uint8_t newbrexp = 0;
						uint32_t newbrmantissa = 0;
						for(b=0; b<64; b++) {
							if(bitrate <= ((uint64_t) 0x3FFFF << b)) {
								newbrexp = b;
								break;
							}
						}
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

/* Generate a new REMB message */
int janus_rtcp_remb(char *packet, int len, uint64_t bitrate) {
	if(packet == NULL || len != 24)
		return -1;
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 15;
	rtcp->length = htons((len/4)-1);
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
	for(b=0; b<64; b++) {
		if(bitrate <= ((uint64_t) 0x3FFFF << b)) {
			newbrexp = b;
			break;
		}
	}
	newbrmantissa = bitrate >> b;
	/* FIXME From rtcp_sender.cc */
	unsigned char *_ptrRTCPData = (unsigned char *)remb;
	_ptrRTCPData += 4;	/* Skip unique identifier */
	_ptrRTCPData[0] = (uint8_t)(1);	/* Just one SSRC */
	_ptrRTCPData[1] = (uint8_t)((newbrexp << 2) + ((newbrmantissa >> 16) & 0x03));
	_ptrRTCPData[2] = (uint8_t)(newbrmantissa >> 8);
	_ptrRTCPData[3] = (uint8_t)(newbrmantissa);
	JANUS_LOG(LOG_HUGE, "[REMB] bitrate=%"SCNu64" (%d bytes)\n", bitrate, 4*(ntohs(rtcp->length)+1));
	return 0;
}

/* Generate a new FIR message */
int janus_rtcp_fir(char *packet, int len, int *seqnr) {
	if(packet == NULL || len != 20 || seqnr == NULL)
		return -1;
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
	return 0;
}

/* Generate a new legacy FIR message */
int janus_rtcp_fir_legacy(char *packet, int len, int *seqnr) {
	/* FIXME Right now, this is identical to the new FIR, with the difference that we use 192 as PT */
	if(packet == NULL || len != 20 || seqnr == NULL)
		return -1;
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
	return 0;
}

/* Generate a new PLI message */
int janus_rtcp_pli(char *packet, int len) {
	if(packet == NULL || len != 12)
		return -1;
	rtcp_header *rtcp = (rtcp_header *)packet;
	/* Set header */
	rtcp->version = 2;
	rtcp->type = RTCP_PSFB;
	rtcp->rc = 1;	/* FMT=1 */
	rtcp->length = htons((len/4)-1);
	return 0;
}
