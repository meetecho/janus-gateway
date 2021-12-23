#include "pp-ext-report.h"

#include <jansson.h>

#include "stdlib.h"
#include "glib.h"

#include "../debug.h"

void janus_pp_print_ext_report(GList *rotations) {
	json_t *obj = json_object();


	/* add rotations to json */
	json_t *json_rotations = json_array();
	GSList* iterator = rotations;
	for (iterator = rotations; iterator; iterator = iterator->next) {
		json_t *elem = json_object();

		janus_pp_extension_report_rotation *rot = (janus_pp_extension_report_rotation *)iterator->data;

		json_object_set_new(elem, "ts", json_real(rot->timestamp));
		json_object_set_new(elem, "rotation", json_integer(rot->rotation));

		json_array_append_new(json_rotations, elem);
	}

	json_object_set_new(obj, "rotations", json_arr);

	char *str = json_dumps(obj, JSON_INDENT(0) | JSON_PRESERVE_ORDER);
	JANUS_PRINT("%s\n", str);
	free(str);

	json_decref(obj);
}

GList* janus_pp_add_ext_rotation(GList *rotations, double timestamp, int rotation) {
	janus_pp_extension_report_rotation *entry = g_malloc(sizeof(janus_pp_extension_report_rotation));
	entry->rotation = rotation;
	entry->timestamp = timestamp;

	return g_slist_append(report->rotations, entry);
}

GList* janus_pp_detect_rotation_changes(GList *rotations, janus_pp_frame_packet *list) {
	janus_pp_frame_packet *tmp = list;
	int rotation = -1;
	while (tmp) {
		if(tmp->rotation != -1 && tmp->rotation != rotation) {
			rotation = tmp->rotation;
			double ts = (double)(tmp->ts-list->ts)/(double)90000;
			rotations = janus_pp_add_ext_rotation(rotations, ts, rotation);
		}

		tmp = tmp->next;
	}
	return rotations;
}
