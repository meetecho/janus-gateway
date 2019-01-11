#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <glib.h>
#include "../rtcp.h"
#include "../rtp.h"
#include "../debug.h"

static size_t NUM_COPY = 5;
int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;

static gboolean janus_is_rtcp(const uint8_t *buf, size_t len) {
	if (len < 2) return FALSE;
	janus_rtp_header *header = (janus_rtp_header *)buf;
	return ((header->type >= 64) && (header->type < 96));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* Sanity Checks */
	/* Max UDP payload with MTU=1500 */
	if (size > 1472) return 0;
	/* libnice checks that a packet length is positive */
	if (size <= 0) return 0;
	/* Janus checks that an entire COMPOUND packet length must be >= 2 bytes
	 * and RTP header type must be in range [64-95] */
	if (!janus_is_rtcp(data, size)) return 0;
	/* libsrtp checks that an entire COMPOUND packet must
	 * contain at least a full RTCP header */
	if (size < 8) return 0;

	/* Test context setup */
	/* Do some copies of input data */
	char *copy_data[NUM_COPY];
	for (int i=0; i < NUM_COPY; i++) {
		copy_data[i] = g_malloc0(size);
		memcpy(copy_data[i], data, size);
	}
	/* Create void RTCP context */
	janus_rtcp_context *ctx = g_malloc0(sizeof(janus_rtcp_context));
	int newlen = 0;

	/* Targets */
	/* Functions that just read data */
	janus_rtcp_has_bye((char *)data, size);
	janus_rtcp_has_fir((char *)data, size);
	janus_rtcp_has_pli((char *)data, size);
	janus_rtcp_get_receiver_ssrc((char *)data, size);
	janus_rtcp_get_remb((char *)data, size);
	janus_rtcp_get_sender_ssrc((char *)data, size);
	/* Functions that alter input data */
	size_t copy_idx = 0;
	janus_rtcp_cap_remb(copy_data[copy_idx++], size, 256000);
	janus_rtcp_fix_report_data(copy_data[copy_idx++], size, 2000, 1000, 1234, 1234, 1234, TRUE);
	janus_rtcp_fix_ssrc(ctx, copy_data[copy_idx++], size, 1, 2, 3);
	janus_rtcp_parse(ctx, copy_data[copy_idx++], size);
	janus_rtcp_remove_nacks(copy_data[copy_idx++], size);
	/* Functions that allocate new memory */
	char *output_data = janus_rtcp_filter((char *)data, size, &newlen);
	GSList *list = janus_rtcp_get_nacks((char *)data, size);

	/* Free resources */
	for (int i=0; i < NUM_COPY; i++) {
		g_free(copy_data[i]);
	}
	g_free(ctx);
	g_free(output_data);
	if (list) {
		g_slist_free(list);
	}
	return 0;
}
