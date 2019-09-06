/*! \file    pp-g711.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of G.711 (mu-law or a-law) RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_G711
#define JANUS_PP_G711

#include <stdio.h>

#include "pp-rtp.h"

int janus_pp_g711_create(char *destination, char *metadata);
int janus_pp_g711_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_g711_close(void);

#endif
