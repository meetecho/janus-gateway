#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <glib.h>
#include "../debug.h"
#include "../rtcp.h"
#include "../rtp.h"

int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* Sanity Checks */
	/* Max UDP payload with MTU=1500 */
	if (size > 1472) return 0;
	/* libnice checks that a packet length is positive */
	if (size <= 0) return 0;
	/* Janus checks for a minimum COMPOUND packet length
	 * and the RTP header type value */
	if (!janus_is_rtcp((char *)data, size)) return 0;
	/* libsrtp checks that an entire COMPOUND packet must
	 * contain at least a full RTCP header */
	if (size < 8) return 0;

	/* Test context setup */
	/* Do some copies of input data */
	uint8_t copy_data0[size], copy_data1[size],
		copy_data2[size], copy_data3[size],
			copy_data4[size];
	uint8_t *copy_data[5] = { copy_data0, copy_data1,
			copy_data2, copy_data3, copy_data4};
	int idx, newlen;
	for (idx=0; idx < 5; idx++) {
		memcpy(copy_data[idx], data, size);
	}
	idx = 0;
	/* Create some void RTCP contexts */
	janus_rtcp_context ctx0, ctx1;
	memset(&ctx0, 0, sizeof(janus_rtcp_context));
	memset(&ctx1, 0, sizeof(janus_rtcp_context));

	/* Targets */
	/* Functions that just read data */
	janus_rtcp_has_bye((char *)data, size);
	janus_rtcp_has_fir((char *)data, size);
	janus_rtcp_has_pli((char *)data, size);
	janus_rtcp_get_receiver_ssrc((char *)data, size);
	janus_rtcp_get_remb((char *)data, size);
	janus_rtcp_get_sender_ssrc((char *)data, size);
	/* Functions that alter input data */
	janus_rtcp_cap_remb((char *)copy_data[idx++], size, 256000);
	janus_rtcp_fix_report_data((char *)copy_data[idx++], size, 2000, 1000, 1234, 1234, 1234, TRUE);
	janus_rtcp_fix_ssrc(&ctx0, (char *)copy_data[idx++], size, 1, 2, 3);
	janus_rtcp_parse(&ctx1, (char *)copy_data[idx++], size);
	janus_rtcp_remove_nacks((char *)copy_data[idx++], size);
	/* Functions that allocate new memory */
	char *output_data = janus_rtcp_filter((char *)data, size, &newlen);
	GSList *list = janus_rtcp_get_nacks((char *)data, size);

	/* Free resources */
	g_free(output_data);
	if (list) g_slist_free(list);
	return 0;
}
