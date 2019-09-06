/*! \file    pp-srt.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .srt files (headers)
 * \details  Implementation of the post-processing code needed to
 * generate .srt files out of text data recordings.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_SRT
#define JANUS_PP_SRT

#include <stdio.h>

#include "pp-rtp.h"

int janus_pp_srt_create(char *destination, char *metadata);
int janus_pp_srt_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_srt_close(void);

#endif
