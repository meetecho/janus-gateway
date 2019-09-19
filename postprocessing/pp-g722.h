/*! \file    pp-g722.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files from G.722 (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of G.722 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_G722
#define JANUS_PP_G722

#include <stdio.h>

#include "pp-rtp.h"

int janus_pp_g722_create(char *destination, char *metadata);
int janus_pp_g722_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_g722_close(void);

#endif
