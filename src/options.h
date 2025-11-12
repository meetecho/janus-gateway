/*! \file    options.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Command line options parser for Janus (headers)
 * \details  Helper code to parse the Janus command line options using GOptionEntry.
 *
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_OPTIONS
#define JANUS_OPTIONS

#include <glib.h>

/*! \brief Struct containing the parsed command line options for Janus */
typedef struct janus_options {
	gboolean daemon;
	const char *pid_file;
	gboolean disable_stdout;
	gboolean log_stdout;
	const char *log_file;
	const char *log_rotate_sig;
	const char *cwd_path;
	const char *interface;
	const char *plugins_folder;
	const char *config_file;
	const char *configs_folder;
	const char *cert_pem;
	const char *cert_key;
	const char *cert_pwd;
	const char *stun_server;
	const char *nat_1_1;
	gboolean keep_private_host;
	const char *ice_enforce_list;
	const char *ice_ignore_list;
	gboolean ipv6_candidates;
	gboolean ipv6_link_local;
	gboolean full_trickle;
	gboolean ice_lite;
	gboolean ice_tcp;
	int min_nack_queue;
	int no_media_timer;
	int slowlink_threshold;
	const char *rtp_port_range;
	int twcc_period;
	const char *server_name;
	int session_timeout;
	int reclaim_session_timeout;
	int debug_level;
	gboolean debug_timestamps;
	gboolean disable_colors;
	gboolean debug_locks;
	const char *apisecret;
	gboolean token_auth;
	const char *token_auth_secret;
	gboolean event_handlers;
	gboolean no_webrtc_encryption;
	gboolean print_version;
} janus_options;

/*! \brief Helper method to parse the command line options
 * @param opts A pointer to the janus_options instance to save the options to
 * @param argc The number of arguments
 * @param argv The command line arguments
 * @returns TRUE if successful, FALSE otherwise */
gboolean janus_options_parse(janus_options *opts, int argc, char *argv[]);

/*! \brief Helper method to get rid of the options parser resources */
void janus_options_destroy(void);

#endif
