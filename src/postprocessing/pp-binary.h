/*! \file    pp-binary.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate binary files out of binary data recordings (headers)
 * \details  Implementation of the post-processing code needed to
 * generate .srt files out of text data recordings.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_BINARY
#define JANUS_PP_BINARY

#include <stdio.h>

#include "pp-rtp.h"

int janus_pp_binary_create(char *destination, char *metadata);
int janus_pp_binary_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_binary_close(void);

#endif
