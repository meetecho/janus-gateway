/*! \file    pp-h265.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .mp4 files out of H.265 frames (headers)
 * \details  Implementation of the post-processing code (based on FFmpeg)
 * needed to generate .mp4 files out of H.265 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_H265
#define JANUS_PP_H265

#include <stdio.h>

#include "pp-rtp.h"

/* H.265 stuff */
int janus_pp_h265_create(char *destination, char *metadata, gboolean faststart);
int janus_pp_h265_preprocess(FILE *file, janus_pp_frame_packet *list);
int janus_pp_h265_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_h265_close(void);


#endif
