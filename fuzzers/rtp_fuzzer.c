#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <glib.h>
#include "../src/debug.h"
#include "../src/utils.h"
#include "../src/rtp.h"

int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

/* This is to avoid linking with openSSL */
int RAND_bytes(uint8_t *key, int len) {
	return 0;
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
	/* Janus checks for a minimum packet length
	 * and the RTP header type value */
	if (!janus_is_rtp((char *)data, size)) return 0;

	/* Do same checks that libsrtp does: plain RTP (e.g., relayed by
	 * plugins) doesn't go through libsrtp, so the RTP helpers must
	 * reject on their own the headers that libsrtp would reject (we
	 * work on a copy, as replacing an extension ID writes to the packet) */
	if (srtp_validate_rtp_header((char *)data, size) < 0) {
		char copy_packet[size];
		memcpy(copy_packet, data, size);
		if (janus_rtp_payload(copy_packet, size, NULL) != NULL)
			abort();
		if (janus_rtp_header_extension_replace_id(copy_packet, size, 1, 2) == 0)
			abort();
		return 0;
	}

	/* RTP extensions parsers */
	char sdes_item[16];
	janus_rtp_header_extension_parse_rid((char *)data, size, 1, sdes_item, sizeof(sdes_item));
	janus_rtp_header_extension_parse_mid((char *)data, size, 1, sdes_item, sizeof(sdes_item));
	guint16 transport_seq_num;
	gboolean c, f, r1, r0;
	uint8_t dd[256];
	int sizedd = sizeof(dd);
	janus_rtp_header_extension_parse_audio_level((char *)data, size, 1, NULL, NULL);
	janus_rtp_header_extension_parse_playout_delay((char *)data, size, 1, NULL, NULL);
	janus_rtp_header_extension_parse_transport_wide_cc((char *)data, size, 1, &transport_seq_num);
	janus_rtp_header_extension_parse_abs_send_time((char *)data, size, 1, NULL);
	janus_rtp_header_extension_parse_abs_capture_time((char *)data, size, 1, NULL);
	janus_rtp_header_extension_parse_video_orientation((char * )data, size, 1, &c, &f, &r1, &r0);
	janus_rtp_header_extension_parse_dependency_desc((char *)data, size, 1, (uint8_t *)&dd, &sizedd);
	janus_rtp_header_extension_parse_video_layers_allocation((char *)data, size, 1, NULL, NULL);

	/* AV1 SVC targets */
	if (sizedd > 0) {
		uint8_t template = 0, ebit = 0;
		janus_av1_svc_context av1_context = { 0 };
		janus_av1_svc_context_process_dd(&av1_context, dd, sizedd, &template, &ebit);
		janus_av1_svc_context_reset(&av1_context);
	}

	/* Extract codec payload */
	int plen = 0;
	char *payload = janus_rtp_payload((char *)data, size, &plen);
	if (!payload) return 0;
	/* Make a copy of payload */
	char copy_payload[plen];
	memcpy(copy_payload, payload, plen);

	/* H.264 targets */
	janus_h264_is_keyframe(payload, plen);

	/* VP8 targets */
	gboolean m = FALSE;
	uint16_t picid = 0;
	uint8_t tlzi = 0, tid = 0, ybit = 0, keyidx = 0;
	janus_vp8_simulcast_context vp8_context;
	memset(&vp8_context, 0, sizeof(janus_vp8_simulcast_context));
	janus_vp8_is_keyframe(payload, plen);
	janus_vp8_parse_descriptor(payload, plen, &m, &picid, &tlzi, &tid, &ybit, &keyidx);
	janus_vp8_simulcast_descriptor_update(copy_payload, plen, &vp8_context, TRUE);

	/* VP9 targets */
	int found = 0;
	janus_vp9_svc_info info;
	janus_vp9_is_keyframe(payload, plen);
	janus_vp9_parse_svc(payload, plen, &found, &info);

	/* VP9 SVC context: plugins take the targets from the API, which only
	 * checks they're not negative, so the spatial layer must stay in range */
	janus_rtp_svc_context svc_context;
	janus_rtp_svc_context_reset(&svc_context);
	svc_context.spatial_target = 1000;
	char copy_packet[size];
	memcpy(copy_packet, data, size);
	janus_rtp_svc_context_process_rtp(&svc_context, copy_packet, size, NULL, 0,
		JANUS_VIDEOCODEC_VP9, NULL, NULL);
	if(svc_context.spatial > 2)
		abort();
	janus_rtp_svc_context_reset(&svc_context);

	/* Free resources */

	return 0;
}
