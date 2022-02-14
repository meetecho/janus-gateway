/*! \file    pp-avformat.h
 * \copyright GNU General Public License v3
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_AVFORMAT
#define JANUS_PP_AVFORMAT

#include "../debug.h"

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))

#if LIBAVCODEC_VER_AT_LEAST(51, 42)
#define PIX_FMT_YUV420P AV_PIX_FMT_YUV420P
#endif

#if LIBAVCODEC_VER_AT_LEAST(56, 56)
#ifndef CODEC_FLAG_GLOBAL_HEADER
#define CODEC_FLAG_GLOBAL_HEADER AV_CODEC_FLAG_GLOBAL_HEADER
#endif
#ifndef FF_INPUT_BUFFER_PADDING_SIZE
#define FF_INPUT_BUFFER_PADDING_SIZE AV_INPUT_BUFFER_PADDING_SIZE
#endif
#endif

#if LIBAVCODEC_VER_AT_LEAST(57, 14)
#define USE_CODECPAR
#endif

void janus_pp_setup_avformat(void);

AVFormatContext *janus_pp_create_avformatcontext(const char *format, const char *metadata, const char *destination);

AVStream *janus_pp_new_video_avstream(AVFormatContext *fctx, int codec_id, int width, int height);
AVStream *janus_pp_new_audio_avstream(AVFormatContext *fctx, int codec_id, int samplerate, int channels, const uint8_t *extradata, int size);


#endif
