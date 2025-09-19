/*! \file    options.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Command line options parser for Janus
 * \details  Helper code to parse the Janus command line options using GOptionEntry.
 *
 * \ingroup core
 * \ref core
 */

#include "options.h"
#include "debug.h"

static GOptionContext *opts = NULL;

gboolean janus_options_parse(janus_options *options, int argc, char *argv[]) {
	/* Supported command-line arguments */
	GOptionEntry opt_entries[] = {
		{ "daemon", 'b', 0, G_OPTION_ARG_NONE, &options->daemon, "Launch Janus in background as a daemon", NULL },
		{ "pid-file", 'p', 0, G_OPTION_ARG_STRING, &options->pid_file, "Open the specified PID file when starting Janus (default=none)", "path" },
		{ "disable-stdout", 'N', 0, G_OPTION_ARG_NONE, &options->disable_stdout, "Disable stdout based logging", NULL },
		{ "log-stdout", 0, 0, G_OPTION_ARG_NONE, &options->log_stdout, "Log to stdout, even when the process is daemonized", NULL },
		{ "log-file", 'L', 0, G_OPTION_ARG_STRING, &options->log_file, "Log to the specified file (default=stdout only)", "path" },
		{ "log-rotate-sig", 'R', 0, G_OPTION_ARG_STRING, &options->log_rotate_sig, "Signal to trigger log reloading (e.g. SIGUSR1) (default=none)", "signal" },
		{ "cwd-path", 'H', 0, G_OPTION_ARG_STRING, &options->cwd_path, "Working directory for Janus daemon process (default=/)", "path" },
		{ "interface", 'i', 0, G_OPTION_ARG_STRING, &options->interface, "Interface to use (will be the public IP)", "ipaddress" },
		{ "plugins-folder", 'P', 0, G_OPTION_ARG_STRING, &options->plugins_folder, "Plugins folder (default=./plugins)", "path" },
		{ "config", 'C', 0, G_OPTION_ARG_STRING, &options->config_file, "Configuration file to use", "filename" },
		{ "configs-folder", 'F', 0, G_OPTION_ARG_STRING, &options->configs_folder, "Configuration files folder (default=./conf)", "path" },
		{ "cert-pem", 'c', 0, G_OPTION_ARG_STRING, &options->cert_pem, "DTLS certificate", "filename" },
		{ "cert-key", 'k', 0, G_OPTION_ARG_STRING, &options->cert_key, "DTLS certificate key", "filename" },
		{ "cert-pwd", 'K', 0, G_OPTION_ARG_STRING, &options->cert_pwd, "DTLS certificate key passphrase (if needed)", "text" },
		{ "stun-server", 'S', 0, G_OPTION_ARG_STRING, &options->stun_server, "STUN server(:port) to use, if needed (e.g., Janus behind NAT, default=none)", "address:port" },
		{ "nat-1-1", '1', 0, G_OPTION_ARG_STRING, &options->nat_1_1, "Comma-separated list of public IPs to put in all host candidates, assuming a 1:1 NAT is in place (e.g., Amazon EC2 instances, default=none)", "ips" },
		{ "keep-private-host", '2', 0, G_OPTION_ARG_NONE, &options->keep_private_host, "When nat-1-1 is used (e.g., Amazon EC2 instances), don't remove the private host, but keep both to simulate STUN", NULL },
		{ "ice-enforce-list", 'E', 0, G_OPTION_ARG_STRING, &options->ice_enforce_list, "Comma-separated list of the only interfaces to use for ICE gathering; partial strings are supported (e.g., eth0 or eno1,wlan0, default=none)", "list" },
		{ "ice-ignore-list", 'X', 0, G_OPTION_ARG_STRING, &options->ice_ignore_list, "Comma-separated list of interfaces or IP addresses to ignore for ICE gathering; partial strings are supported (e.g., vmnet8,192.168.0.1,10.0.0.1 or vmnet,192.168., default=vmnet)", "list" },
		{ "ipv6-candidates", '6', 0, G_OPTION_ARG_NONE, &options->ipv6_candidates, "Whether to enable IPv6 candidates or not", NULL },
		{ "ipv6-link-local", 'O', 0, G_OPTION_ARG_NONE, &options->ipv6_link_local, "Whether IPv6 link-local candidates should be gathered as well", NULL },
		{ "full-trickle", 'f', 0, G_OPTION_ARG_NONE, &options->full_trickle, "Do full-trickle instead of half-trickle", NULL },
		{ "ice-lite", 'I', 0, G_OPTION_ARG_NONE, &options->ice_lite, "Whether to enable the ICE Lite mode or not", NULL },
		{ "ice-tcp", 'T', 0, G_OPTION_ARG_NONE, &options->ice_tcp, "Whether to enable ICE-TCP or not (warning: only works with ICE Lite)", NULL },
		{ "min-nack-queue", 'Q', 0, G_OPTION_ARG_INT, &options->min_nack_queue, "Minimum size of the NACK queue (in ms) per user for retransmissions, no matter the RTT", "number" },
		{ "no-media-timer", 't', 0, G_OPTION_ARG_INT, &options->no_media_timer, "Time (in s) that should pass with no media (audio or video) being received before Janus notifies you about this", "number" },
		{ "slowlink-threshold", 'W', 0, G_OPTION_ARG_INT, &options->slowlink_threshold, "Number of lost packets (per s) that should trigger a 'slowlink' Janus API event to users (default=0, feature disabled)", "number" },
		{ "rtp-port-range", 'r', 0, G_OPTION_ARG_STRING, &options->rtp_port_range, "Port range to use for RTP/RTCP", "min-max" },
		{ "twcc-period", 'B', 0, G_OPTION_ARG_INT, &options->twcc_period, "How often (in ms) to send TWCC feedback back to senders, if negotiated (default=200ms)", "number" },
		{ "server-name", 'n', 0, G_OPTION_ARG_STRING, &options->server_name, "Public name of this Janus instance (default=MyJanusInstance)", "name" },
		{ "session-timeout", 's', 0, G_OPTION_ARG_INT, &options->session_timeout, "Session timeout value, in seconds (default=60)", "number" },
		{ "reclaim-session-timeout", 'm', 0, G_OPTION_ARG_INT, &options->reclaim_session_timeout, "Reclaim session timeout value, in seconds (default=0)", "number" },
		{ "debug-level", 'd', 0, G_OPTION_ARG_INT, &options->debug_level, "Debug/logging level (0=disable debugging, 7=maximum debug level; default=4)", "1-7" },
		{ "debug-timestamps", 'D', 0, G_OPTION_ARG_NONE, &options->debug_timestamps, "Enable debug/logging timestamps", NULL },
		{ "disable-colors", 'o', 0, G_OPTION_ARG_NONE, &options->disable_colors, "Disable color in the logging", NULL },
		{ "debug-locks", 'M', 0, G_OPTION_ARG_NONE, &options->debug_locks, "Enable debugging of locks/mutexes (very verbose!)", NULL },
		{ "apisecret", 'a', 0, G_OPTION_ARG_STRING, &options->apisecret, "API secret all requests need to pass in order to be accepted by Janus (useful when wrapping Janus API requests in a server, none by default)", "randomstring" },
		{ "token-auth", 'A', 0, G_OPTION_ARG_NONE, &options->token_auth, "Enable token-based authentication for all requests", NULL },
		{ "token-auth-secret", 0, 0, G_OPTION_ARG_STRING, &options->token_auth_secret, "Secret to verify HMAC-signed tokens with, to be used with -A", "randomstring" },
		{ "event-handlers", 'e', 0, G_OPTION_ARG_NONE, &options->event_handlers, "Enable event handlers", NULL },
		{ "no-webrtc-encryption", 'w', 0, G_OPTION_ARG_NONE, &options->no_webrtc_encryption, "Disable WebRTC encryption, so no DTLS or SRTP (only for debugging!)", NULL },
		{ "version", 'V', 0, G_OPTION_ARG_NONE, &options->print_version, "Print version and exit", NULL },
		{ NULL, 0, 0, 0, NULL, NULL, NULL },
	};

	/* Parse the command-line arguments */
	GError *error = NULL;
	opts = g_option_context_new("");
	g_option_context_set_help_enabled(opts, TRUE);
	g_option_context_add_main_entries(opts, opt_entries, NULL);
	if(!g_option_context_parse(opts, &argc, &argv, &error)) {
		JANUS_PRINT("%s\n", error->message);
		g_error_free(error);
		janus_options_destroy();
		return FALSE;
	}

	/* Done */
	return TRUE;
}

void janus_options_destroy(void) {
	g_option_context_free(opts);
	opts = NULL;
}
