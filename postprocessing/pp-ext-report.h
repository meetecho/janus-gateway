#ifndef JANUS_GATEWAY_PP_EXT_REPORT_H
#define JANUS_GATEWAY_PP_EXT_REPORT_H

#include <inttypes.h>

#include "pp-rtp.h"

#include <glib.h>

typedef struct janus_pp_extension_report_rotation {
	int rotation;
	double timestamp;
} janus_pp_extension_report_rotation;

void janus_pp_print_ext_report(GSList *rotations);

GSList *janus_pp_add_ext_rotation(GSList *rotations, double timestamp, int rotation);
GSList *janus_pp_detect_rotation_changes(janus_pp_frame_packet *list);

#endif //JANUS_GATEWAY_PP_EXT_REPORT_H
