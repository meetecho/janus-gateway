/*! \file    pp-options.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Command line options parser for janus-pp-rec (headers)
 * \details  Helper code to parse the janus-pp-rec command line options
 * using GOptionEntry.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#ifndef JANUS_PP_OPTIONS
#define JANUS_PP_OPTIONS

#include <glib.h>
#include "../version.h"

/*! \brief Struct containing the parsed command line options for janus-pp-rec */
typedef struct janus_pprec_options {
	gboolean fileexts_only;
	gboolean jsonheader_only;
	gboolean header_only;
	gboolean parse_only;
	gboolean extjson_only;
	const char *metadata;
	gboolean ignore_first_packets;
	int match_pt;
	int audio_level_extmap_id;
	int video_orient_extmap_id;
	int debug_level;
	int debug_timestamps;
	gboolean disable_colors;
	const char *extension;
	gboolean faststart;
	int audioskew_th;
	int silence_distance;
	int restamp_multiplier;
	int restamp_min_th;
	int restamp_packets;
	char **paths;
} janus_pprec_options;

/*! \brief Helper method to parse the command line options
 * @param opts A pointer to the janus_pprec_options instance to save the options to
 * @param argc The number of arguments
 * @param argv The command line arguments
 * @returns TRUE if successful, FALSE otherwise */
gboolean janus_pprec_options_parse(janus_pprec_options *opts, int argc, char *argv[]);

/*! \brief Helper method to print the command line options help summary */
void janus_pprec_options_help(void);

/*! \brief Helper method to get rid of the options parser resources */
void janus_pprec_options_destroy(void);

#endif
