/*! \file    pp-av1.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files out of AV1 frames (headers)
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of AV1 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_AV1
#define JANUS_PP_AV1

#include <stdio.h>

#include "pp-rtp.h"

/* AV1 stuff */
int janus_pp_av1_create(char *destination, char *metadata, gboolean faststart);
int janus_pp_av1_preprocess(FILE *file, janus_pp_frame_packet *list);
int janus_pp_av1_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_av1_close(void);


#endif
