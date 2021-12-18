#ifndef JANUS_GATEWAY_PP_EXT_REPORT_H
#define JANUS_GATEWAY_PP_EXT_REPORT_H

typedef struct janus_pp_extension_report_rotation {
	int rotation;
	double timestamp;
	struct janus_pp_extension_report_rotation* next;
} janus_pp_extension_report_rotation;

typedef struct janus_pp_extension_report {
	struct janus_pp_extension_report_rotation* rotations;
} janus_pp_extension_report;

void print_ext_report(janus_pp_extension_report* report);

void free_ext_report(janus_pp_extension_report* report);
janus_pp_extension_report* create_ext_report(void);

void add_ext_rotation(janus_pp_extension_report* report, double timestamp, int rotation);


#endif //JANUS_GATEWAY_PP_EXT_REPORT_H
