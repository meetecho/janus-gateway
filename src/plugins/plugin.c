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

/* Plugin results */
janus_plugin_result *janus_plugin_result_new(janus_plugin_result_type type, const char *text, json_t *content) {
	JANUS_LOG(LOG_HUGE, "Creating plugin result...\n");
	janus_plugin_result *result = g_malloc(sizeof(janus_plugin_result));
	result->type = type;
	result->text = text;
	result->content = content;
	return result;
}

void janus_plugin_result_destroy(janus_plugin_result *result) {
	JANUS_LOG(LOG_HUGE, "Destroying plugin result...\n");
	result->text = NULL;
	if(result->content)
		json_decref(result->content);
	result->content = NULL;
	g_free(result);
}

/* RTP, RTCP and data packets initialization */
void janus_plugin_rtp_extensions_reset(janus_plugin_rtp_extensions *extensions) {
	if(extensions) {
		/* By extensions are not added to packets */
		extensions->audio_level = -1;
		extensions->audio_level_vad = FALSE;
		extensions->video_rotation = -1;
		extensions->video_back_camera = FALSE;
		extensions->video_flipped = FALSE;
		extensions->min_delay = -1;
		extensions->max_delay = -1;
		extensions->dd_len = 0;
		memset(extensions->dd_content, 0, sizeof(extensions->dd_content));
		extensions->spatial_layers = -1;
		extensions->temporal_layers = -1;
	}
}
void janus_plugin_rtp_reset(janus_plugin_rtp *packet) {
	if(packet) {
		memset(packet, 0, sizeof(janus_plugin_rtp));
		packet->mindex = -1;
		janus_plugin_rtp_extensions_reset(&packet->extensions);
	}
}
janus_plugin_rtp *janus_plugin_rtp_duplicate(janus_plugin_rtp *packet) {
	janus_plugin_rtp *p = NULL;
	if(packet) {
		p = g_malloc(sizeof(janus_plugin_rtp));
		p->mindex = packet->mindex;
		p->video = packet->video;
		if(packet->buffer == NULL || packet->length == 0) {
			p->buffer = NULL;
			p->length = 0;
		} else {
			p->buffer = g_malloc(packet->length);
			memcpy(p->buffer, packet->buffer, packet->length);
			p->length = packet->length;
		}
		p->extensions = packet->extensions;
	}
	return p;
}
void janus_plugin_rtcp_reset(janus_plugin_rtcp *packet) {
	if(packet) {
		memset(packet, 0, sizeof(janus_plugin_rtcp));
		packet->mindex = -1;
	}
}
void janus_plugin_data_reset(janus_plugin_data *packet) {
	if(packet)
		memset(packet, 0, sizeof(janus_plugin_data));
}
