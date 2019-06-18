/*! \file   plugin.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Plugin-Core communication (implementation)
 * \details  Implementation of the janus_plugin_result stuff: all the
 * important things related to the actual plugin API is in plugin.h.
 *
 * \ingroup pluginapi
 * \ref pluginapi
 */

#include "plugin.h"

#include <jansson.h>

#include "../apierror.h"
#include "../debug.h"

janus_plugin_result *janus_plugin_result_new(janus_plugin_result_type type, const char *text, json_t *content) {
	JANUS_LOG(LOG_HUGE, "Creating plugin result...\n");
	janus_plugin_result *result = g_malloc(sizeof(janus_plugin_result));
	result->type = type;
	result->text = text;
	result->content = content;
	return result;
}

/*! \brief Helper to quickly destroy a janus_plugin_result instance
 * @param[in] result The janus_plugin_result instance to destroy
 * @note Will decrease the reference counter of the JSON content, if available
 */
void janus_plugin_result_destroy(janus_plugin_result *result) {
	JANUS_LOG(LOG_HUGE, "Destroying plugin result...\n");
	result->text = NULL;
	if(result->content)
		json_decref(result->content);
	result->content = NULL;
	g_free(result);
}

