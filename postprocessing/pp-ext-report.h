#ifndef JANUS_GATEWAY_PP_EXT_REPORT_H
#define JANUS_GATEWAY_PP_EXT_REPORT_H

#include <inttypes.h>

#include "pp-rtp.h"

typedef struct janus_pp_extension_report_rotation {
	int rotation;
	double timestamp;
	struct janus_pp_extension_report_rotation* next;
} janus_pp_extension_report_rotation;

typedef struct janus_pp_extension_report {
	struct janus_pp_extension_report_rotation* rotations;
} janus_pp_extension_report;

void janus_pp_print_ext_report(janus_pp_extension_report* report);

void janus_pp_free_ext_report(janus_pp_extension_report* report);
janus_pp_extension_report* janus_pp_create_ext_report(void);

void janus_pp_add_ext_rotation(janus_pp_extension_report* report, double timestamp, int rotation);
void janus_pp_detect_rotation_changes(janus_pp_extension_report *report, janus_pp_frame_packet *list);

#endif //JANUS_GATEWAY_PP_EXT_REPORT_H
