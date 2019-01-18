#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <glib.h>
#include "../debug.h"
#include "../utils.h"
#include "../rtp.h"

static size_t NUM_COPY = 2;
int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;

static gboolean janus_is_rtp(const uint8_t *buf, size_t len) {
	if (len < 2) return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type < 64) || (header->type >= 96));
}

/* Clone libsrtp srtp_validate_rtp_header */
#define octets_in_rtp_header 12
#define uint32s_in_rtp_header 3
#define octets_in_rtp_extn_hdr 4

static int srtp_validate_rtp_header(char *data, int pkt_octet_len) {
    if (pkt_octet_len < octets_in_rtp_header)
        return -1;

    janus_rtp_header *hdr = (janus_rtp_header *)data;

    /* Check RTP header length */
    int rtp_header_len = octets_in_rtp_header + 4 * hdr->csrccount;
    if (hdr->extension == 1)
        rtp_header_len += octets_in_rtp_extn_hdr;

    if (pkt_octet_len < rtp_header_len)
        return -1;

    /* Verifing profile length. */
    if (hdr->extension == 1) {
    	janus_rtp_header_extension *xtn_hdr =
            (janus_rtp_header_extension *)((uint32_t *)hdr + uint32s_in_rtp_header +
                                hdr->csrccount);
        int profile_len = ntohs(xtn_hdr->length);
        rtp_header_len += profile_len * 4;
        /* profile length counts the number of 32-bit words */
        if (pkt_octet_len < rtp_header_len)
            return -1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* Sanity Checks */
	/* Max UDP payload with MTU=1500 */
	if (size > 1472) return 0;
	/* libnice checks that a packet length is positive */
	if (size <= 0) return 0;
	/* Janus checks that an entire packet length must be >= 2 bytes
	 * and RTP header type must be in range [64-95] */
	if (!janus_is_rtp(data, size)) return 0;
	/* Do same checks that libsrtp does */
	if (srtp_validate_rtp_header((char *)data, size) < 0) return 0;

	/* RTP extensions parsers */
	char sdes_item[16];
	guint16 transport_seq_num;
	janus_rtp_header_extension_parse_audio_level((char *)data, size, 0, NULL);
	janus_rtp_header_extension_parse_playout_delay((char *)data, size, 0, NULL, NULL);
	janus_rtp_header_extension_parse_rtp_stream_id((char *)data, size, 0, sdes_item, sizeof(sdes_item));
	janus_rtp_header_extension_parse_transport_wide_cc((char *)data, size, 0, &transport_seq_num);

	/* Extract codec payload */
	int plen = 0;
	char *payload = janus_rtp_payload((char *)data, size, &plen);
	/* Make a copy of payload */
	char *copy_payload = g_malloc0(plen);
	memcpy(copy_payload, payload, plen);

	/* H.264 targets */
	janus_h264_is_keyframe(payload, plen);

	/* VP8 targets */
	uint16_t picid = 0;
	uint8_t tlzi = 0, tid = 0, ybit = 0, keyidx = 0;
	janus_vp8_simulcast_context *vp8_context = g_malloc0(sizeof(janus_vp8_simulcast_context));
	janus_vp8_is_keyframe((char *)data, size);
	janus_vp8_parse_descriptor(payload, plen, &picid, &tlzi, &tid, &ybit, &keyidx);
	janus_vp8_simulcast_descriptor_update(copy_payload, plen, vp8_context, TRUE);

	/* VP9 targets */
	uint8_t pbit = 0, dbit = 0, ubit = 0, bbit = 0, ebit = 0;
	int found = 0, spatial_layer = 0, temporal_layer = 0;
	janus_vp9_is_keyframe((char *)data, size);
	//janus_vp9_parse_svc(payload, plen, &found, &spatial_layer, &temporal_layer, &pbit, &dbit, &ubit, &bbit, &ebit);

	/* Free resources */
	g_free(copy_payload);
	g_free(vp8_context);

	return 0;
}
