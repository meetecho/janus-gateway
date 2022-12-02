/*! \file    pp-l16.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files out of L16 frames (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of L16 RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_L16
#define JANUS_PP_L16

#include <stdio.h>

#include "pp-rtp.h"

/* L16 stuff */
const char **janus_pp_l16_get_extensions(void);
int janus_pp_l16_create(char *destination, int samplerate, char *metadata);
int janus_pp_l16_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_l16_close(void);

#endif
