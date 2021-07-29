/*! \file    pp-avformat.c
 * \copyright GNU General Public License v3
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include "pp-avformat.h"

void janus_pp_setup_avformat(void) {
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

AVFormatContext *janus_pp_create_avformatcontext(const char *format, const char *metadata, const char *destination) {
	janus_pp_setup_avformat();

	AVFormatContext *ctx = avformat_alloc_context();
	if(!ctx)
		return NULL;

	/* We save the metadata part as a comment (see #1189) */
	if(metadata)
		av_dict_set(&ctx->metadata, "comment", metadata, 0);

	ctx->oformat = av_guess_format(format, NULL, NULL);
        if(ctx->oformat == NULL) {
		JANUS_LOG(LOG_ERR, "Error guessing format\n");
		avformat_free_context(ctx);
		return NULL;
	}

	int res = avio_open(&ctx->pb, destination, AVIO_FLAG_WRITE);
	if(res < 0) {
		JANUS_LOG(LOG_ERR, "Error opening file for output (%d)\n", res);
		avformat_free_context(ctx);
		return NULL;
	}

	return ctx;
}

AVStream *janus_pp_new_audio_avstream(AVFormatContext *fctx, int codec_id, int samplerate, int channels, const uint8_t *extradata, int size) {
	AVStream *st = avformat_new_stream(fctx, NULL);
	if(!st)
		return NULL;

#ifdef USE_CODECPAR
	AVCodecParameters *c = st->codecpar;
#else
	AVCodecContext *c = st->codec;
#endif
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_AUDIO;
	c->sample_rate = samplerate;
	c->channels = channels;
	if(extradata) {
		c->extradata_size = size;
		c->extradata = av_memdup(extradata, size);
	}

	return st;
}

AVStream *janus_pp_new_video_avstream(AVFormatContext *fctx, int codec_id, int width, int height) {
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

