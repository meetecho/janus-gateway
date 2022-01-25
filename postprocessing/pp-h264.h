/*! \file    pp-h264.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files out of H.264 frames (headers)
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of H.264 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_H264
#define JANUS_PP_H264

#include <stdio.h>
#include <jansson.h>

#include "pp-rtp.h"

/* H.264 stuff */
const char **janus_pp_h264_get_extensions(void);
int janus_pp_h264_create(char *destination, char *metadata, gboolean faststart, const char *extension);
int janus_pp_h264_preprocess(FILE *file, janus_pp_frame_packet *list, json_t *info);
int janus_pp_h264_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_h264_close(void);


#endif
