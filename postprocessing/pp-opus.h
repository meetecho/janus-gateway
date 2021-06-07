/*! \file    pp-opus.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .opus files (headers)
 * \details  Implementation of the post-processing code (based on libogg)
 * needed to generate .opus files out of Opus RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_OPUS
#define JANUS_PP_OPUS

#include <stdio.h>

#include "pp-rtp.h"

/* Opus stuff */
const char **janus_pp_opus_get_extensions(void);
int janus_pp_opus_create(char *destination, char *metadata, const char *extension);
int janus_pp_opus_process(FILE *file, janus_pp_frame_packet *list, int *working);
void janus_pp_opus_close(void);

#endif
