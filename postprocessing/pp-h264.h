/*! \file    pp-h264.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files (headers)
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of H.264 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_H264
#define JANUS_PP_H264

#include <stdio.h>

#include "pp-rtp.h"

/* H.264 stuff */
int janus_pp_h264_create(char *destination, char *metadata, gboolean faststart);
int janus_pp_h264_preprocess(FILE *file, janus_pp_frame_packet *list);
int janus_pp_h264_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_h264_close(void);


#endif
