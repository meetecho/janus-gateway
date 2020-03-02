#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "../debug.h"
#include "../sdp-utils.h"

int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;
int refcount_debug = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* Since we're fuzzing SDP, and that in our case SDP always comes
	 * from a Jansson call, this will need to be a valid string */
	if(size <= 0)
		return 0;
	char sdp_string[size];
	memcpy(sdp_string, data, size);
	sdp_string[size-1] = '\0';
	/* Parse the SDP using the utils */
	char error_str[512];
	janus_sdp *parsed_sdp = janus_sdp_parse((const char *)sdp_string, error_str, sizeof(error_str));
	if(parsed_sdp == NULL)
		return 0;
	/* Regenerate the SDP blog */
	char *generated_sdp = janus_sdp_write(parsed_sdp);

	/* Free resources */
	janus_sdp_destroy(parsed_sdp);
	g_free(generated_sdp);

	return 0;
}
