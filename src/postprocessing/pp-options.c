/*! \file    pp-options.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Command line options parser for janus-pp-rec
 * \details  Helper code to parse the janus-pp-rec command line options
 * using GOptionEntry.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include "../debug.h"
#include "pp-options.h"

static GOptionContext *opts = NULL;

gboolean janus_pprec_options_parse(janus_pprec_options *options, int argc, char *argv[]) {
	/* Supported command-line arguments */
	GOptionEntry opt_entries[] = {
		{ "file-extensions", 'F', 0, G_OPTION_ARG_NONE, &options->fileexts_only, "Only print the supported target file extensions per codec", NULL },
		{ "json", 'j', 0, G_OPTION_ARG_NONE, &options->jsonheader_only, "Only print JSON header", NULL },
		{ "header", 'H', 0, G_OPTION_ARG_NONE, &options->header_only, "Only parse .mjr header", NULL },
		{ "parse", 'p', 0, G_OPTION_ARG_NONE, &options->parse_only, "Only parse and re-order packets", NULL },
		{ "extended-json", 'e', 0, G_OPTION_ARG_NONE, &options->extjson_only, "Only print extended JSON report (automatically enables --json)", NULL },
		{ "metadata", 'm', 0, G_OPTION_ARG_STRING, &options->metadata, "Save this metadata string in the target file", NULL },
		{ "ignore-first", 'i', 0, G_OPTION_ARG_INT, &options->ignore_first_packets, "Number of first packets to ignore when processing, e.g., in case they're cause of issues (default=0)", NULL },
		{ "payload-type", 'P', 0, G_OPTION_ARG_INT, &options->match_pt, "Ignore all RTP packets that don't match the specified payload type (default=none)", NULL },
		{ "audiolevel-ext", 'a', 0, G_OPTION_ARG_INT, &options->audio_level_extmap_id, "ID of the audio-levels RTP extension (default=none)", NULL },
		{ "videoorient-ext", 'v', 0, G_OPTION_ARG_INT, &options->video_orient_extmap_id, "ID of the video-orientation RTP extension (default=none)", NULL },
		{ "debug-level", 'd', 0, G_OPTION_ARG_INT, &options->debug_level, "Debug/logging level (0=disable debugging, 7=maximum debug level; default=4)", NULL },
		{ "debug-timestamps", 'D', 0, G_OPTION_ARG_NONE, &options->debug_timestamps, "Enable debug/logging timestamps", NULL },
		{ "disable-colors", 'o', 0, G_OPTION_ARG_NONE, &options->disable_colors, "Disable color in the logging", NULL },
		{ "format", 'f', 0, G_OPTION_ARG_STRING, &options->extension, "Specifies the output format (overrides the format from the destination)", NULL },
		{ "faststart", 't', 0, G_OPTION_ARG_NONE, &options->faststart, "For mp4 files write the MOOV atom at the head of the file", NULL },
		{ "audioskew", 'S', 0, G_OPTION_ARG_INT, &options->audioskew_th, "Time threshold to trigger an audio skew compensation, disabled if 0 (default=0)", NULL },
		{ "silence-distance", 'C', 0, G_OPTION_ARG_INT, &options->silence_distance, "RTP packets distance used to detect RTP silence suppression, disabled if 0 (default=0)", NULL },
		{ "restamp", 'r', 0, G_OPTION_ARG_INT, &options->restamp_multiplier, "If the latency of a packet is bigger than the `moving_average_latency * (<restamp>/1000)` the timestamps will be corrected, disabled if 0 (default=0)", NULL },
		{ "restamp-packets", 'c', 0, G_OPTION_ARG_INT, &options->restamp_packets, "Number of packets used for calculating moving average latency for timestamp correction (default=10)", NULL },
		{ "restamp-min-th", 'n', 0, G_OPTION_ARG_INT, &options->restamp_min_th, "Minimum latency of moving average to reach before starting to correct timestamps. (default=500)", NULL },
		{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &options->paths, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL, NULL },
	};

	/* Parse the command-line arguments */
	GError *error = NULL;
	opts = g_option_context_new("source.mjr [destination.[opus|ogg|mka|wav|webm|mkv|h264|srt]]");
	g_option_context_set_help_enabled(opts, TRUE);
	g_option_context_add_main_entries(opts, opt_entries, NULL);
	if(!g_option_context_parse(opts, &argc, &argv, &error)) {
		JANUS_LOG(LOG_INFO, "Janus version: %d (%s)\n", janus_version, janus_version_string);
		JANUS_LOG(LOG_INFO, "Janus commit: %s\n", janus_build_git_sha);
		JANUS_LOG(LOG_INFO, "Compiled on:  %s\n\n", janus_build_git_time);
		g_print("%s\n", error->message);
		g_error_free(error);
		janus_pprec_options_destroy();
		return FALSE;
	}

	/* Done */
	return TRUE;
}

void janus_pprec_options_help(void) {
	JANUS_LOG(LOG_INFO, "Janus version: %d (%s)\n", janus_version, janus_version_string);
	JANUS_LOG(LOG_INFO, "Janus commit: %s\n", janus_build_git_sha);
	JANUS_LOG(LOG_INFO, "Compiled on:  %s\n\n", janus_build_git_time);
	char *help = g_option_context_get_help(opts, TRUE, NULL);
	g_print("%s", help);
	g_free(help);
}

void janus_pprec_options_destroy(void) {
	g_option_context_free(opts);
	opts = NULL;
}
