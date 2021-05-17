/*! \file    pp-webm.h
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

static inline void janus_pp_setup_avformat(void) {
	/* Setup FFmpeg */
#if ( LIBAVFORMAT_VERSION_INT < AV_VERSION_INT(58,9,100) )
	av_register_all();
#endif
	/* Adjust logging to match the postprocessor's */
	av_log_set_level(janus_log_level <= LOG_NONE ? AV_LOG_QUIET :
		(janus_log_level == LOG_FATAL ? AV_LOG_FATAL :
			(janus_log_level == LOG_ERR ? AV_LOG_ERROR :
				(janus_log_level == LOG_WARN ? AV_LOG_WARNING :
					(janus_log_level == LOG_INFO ? AV_LOG_INFO :
						(janus_log_level == LOG_VERB ? AV_LOG_VERBOSE : AV_LOG_DEBUG))))));

}

static inline AVStream *janus_pp_new_video_avstream(AVFormatContext *fctx, int codec_id, int width, int height) {
	AVStream *st = avformat_new_stream(fctx, NULL);
	if(!st)
		return NULL;

#ifdef USE_CODECPAR
	AVCodecParameters *c = st->codecpar;
#else
	AVCodecContext *c = st->codec;
#endif
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_VIDEO;
	c->width = width;
	c->height = height;

	return st;
}

#endif
