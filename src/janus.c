/*! \file   janus.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus core
 * \details Implementation of the Janus core. This code takes care of
 * the server initialization (command line/configuration) and setup,
 * and makes use of the available transport plugins (by default HTTP,
 * WebSockets, RabbitMQ, if compiled) and Janus protocol (a JSON-based
 * protocol) to interact with the applications, whether they're web based
 * or not. The core also takes care of bridging peers and plugins
 * accordingly, in terms of both messaging and real-time media transfer
 * via WebRTC.
 *
 * \ingroup core
 * \ref core
 */

#include <dlfcn.h>
#include <dirent.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

#include <openssl/rand.h>
#ifdef HAVE_TURNRESTAPI
#include <curl/curl.h>
#endif

#include "janus.h"
#include "version.h"
#include "options.h"
#include "config.h"
#include "apierror.h"
#include "debug.h"
#include "ip-utils.h"
#include "rtcp.h"
#include "rtpfwd.h"
#include "auth.h"
#include "record.h"
#include "events.h"


#define JANUS_NAME				"Janus WebRTC Server"
#define JANUS_AUTHOR			"Meetecho s.r.l."
#define JANUS_SERVER_NAME		"MyJanusInstance"

#ifdef __MACH__
#define SHLIB_EXT "2.dylib"
#else
#define SHLIB_EXT ".so"
#endif


/* Command line options */
static janus_options options = { 0 };

/* Configuration file */
static janus_config *config = NULL;
static char *config_file = NULL;
static char *configs_folder = NULL;

static GHashTable *transports = NULL;
static GHashTable *transports_so = NULL;

static GHashTable *eventhandlers = NULL;
static GHashTable *eventhandlers_so = NULL;

static GHashTable *loggers = NULL;
static GHashTable *loggers_so = NULL;

static GHashTable *plugins = NULL;
static GHashTable *plugins_so = NULL;


/* Daemonization */
static gboolean daemonize = FALSE;
static int pipefd[2];


#ifdef REFCOUNT_DEBUG
/* Reference counters debugging */
GHashTable *counters = NULL;
janus_mutex counters_mutex;
#endif


/* API secrets */
static char *api_secret = NULL, *admin_api_secret = NULL;

/* JSON parameters */
static int janus_process_error_string(janus_request *request, uint64_t session_id, const char *transaction, gint error, gchar *error_string);

static struct janus_json_parameter incoming_request_parameters[] = {
	{"transaction", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"janus", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"id", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter attach_parameters[] = {
	{"plugin", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"opaque_id", JSON_STRING, 0},
	{"loop_index", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE},
};
static struct janus_json_parameter body_parameters[] = {
	{"body", JSON_OBJECT, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter jsep_parameters[] = {
	{"type", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"sdp", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"trickle", JANUS_JSON_BOOL, 0},
	{"rid_order", JSON_STRING, 0},
	{"force_relay", JANUS_JSON_BOOL, 0},
	{"e2ee", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter add_token_parameters[] = {
	{"token", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"plugins", JSON_ARRAY, 0}
};
static struct janus_json_parameter token_parameters[] = {
	{"token", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter admin_parameters[] = {
	{"transaction", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"janus", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter debug_parameters[] = {
	{"debug", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter timeout_parameters[] = {
	{"timeout", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter session_timeout_parameters[] = {
	{"timeout", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter level_parameters[] = {
	{"level", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter timestamps_parameters[] = {
	{"timestamps", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter colors_parameters[] = {
	{"colors", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter mnq_parameters[] = {
	{"min_nack_queue", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter nopt_parameters[] = {
	{"nack_optimizations", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter nmt_parameters[] = {
	{"no_media_timer", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter st_parameters[] = {
	{"slowlink_threshold", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter ans_parameters[] = {
	{"accept", JANUS_JSON_BOOL, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter querytransport_parameters[] = {
	{"transport", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"request", JSON_OBJECT, 0}
};
static struct janus_json_parameter queryhandler_parameters[] = {
	{"handler", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"request", JSON_OBJECT, 0}
};
static struct janus_json_parameter querylogger_parameters[] = {
	{"logger", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"request", JSON_OBJECT, 0}
};
static struct janus_json_parameter messageplugin_parameters[] = {
	{"plugin", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"request", JSON_OBJECT, 0}
};
static struct janus_json_parameter customevent_parameters[] = {
	{"schema", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"data", JSON_OBJECT, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter customlogline_parameters[] = {
	{"line", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"level", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter text2pcap_parameters[] = {
	{"folder", JSON_STRING, 0},
	{"filename", JSON_STRING, 0},
	{"truncate", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};
static struct janus_json_parameter handleinfo_parameters[] = {
	{"plugin_only", JANUS_JSON_BOOL, 0}
};
static struct janus_json_parameter resaddr_parameters[] = {
	{"address", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
static struct janus_json_parameter teststun_parameters[] = {
	{"address", JSON_STRING, JANUS_JSON_PARAM_REQUIRED},
	{"port", JSON_INTEGER, JANUS_JSON_PARAM_REQUIRED | JANUS_JSON_PARAM_POSITIVE},
	{"localport", JSON_INTEGER, JANUS_JSON_PARAM_POSITIVE}
};

/* Admin/Monitor helpers */
json_t *janus_admin_peerconnection_summary(janus_ice_peerconnection *pc);
json_t *janus_admin_peerconnection_medium_summary(janus_ice_peerconnection_medium *medium);


/* IP addresses */
static gchar *local_ip = NULL;
gchar *janus_get_local_ip(void) {
	return local_ip;
}
static GHashTable *public_ips_table = NULL;
static GList *public_ips = NULL;
gboolean public_ips_ipv4 = FALSE, public_ips_ipv6 = FALSE;
guint janus_get_public_ip_count(void) {
	return public_ips_table ? g_hash_table_size(public_ips_table) : 0;
}
gchar *janus_get_public_ip(guint index) {
	if (!janus_get_public_ip_count()) {
		/* Fallback to the local IP, if we have no public one */
		return local_ip;
	}
	if (index >= g_hash_table_size(public_ips_table)) {
		index = g_hash_table_size(public_ips_table) - 1;
	}
	return (char *)g_list_nth(public_ips, index)->data;
}
void janus_add_public_ip(const gchar *ip) {
	if(ip == NULL) {
		return;
	}

	if(!public_ips_table) {
		public_ips_table = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
	}
	if (g_hash_table_insert(public_ips_table, g_strdup(ip), NULL)) {
		g_list_free(public_ips);
		public_ips = g_hash_table_get_keys(public_ips_table);
	}
	/* Take note of whether we received at least one IPv4 and/or IPv6 address */
	if(strchr(ip, ':')) {
		public_ips_ipv6 = TRUE;
	} else {
		public_ips_ipv4 = TRUE;
	}
}
gboolean janus_has_public_ipv4_ip(void) {
	return public_ips_ipv4;
}
gboolean janus_has_public_ipv6_ip(void) {
	return public_ips_ipv6;
}

static volatile gint stop = 0;
static gint stop_signal = 0;
gint janus_is_stopping(void) {
	return g_atomic_int_get(&stop);
}
static GMainLoop *mainloop = NULL;


/* Public instance name */
static gchar *server_name = NULL;

static json_t *janus_create_message(const char *status, uint64_t session_id, const char *transaction) {
	json_t *msg = json_object();
	json_object_set_new(msg, "janus", json_string(status));
	if(session_id > 0)
		json_object_set_new(msg, "session_id", json_integer(session_id));
	if(transaction != NULL)
		json_object_set_new(msg, "transaction", json_string(transaction));
	return msg;
}

/* The default timeout for sessions is 60 seconds: this means that, if
 * we don't get any activity (i.e., no request) on this session for more
 * than 60 seconds, then it's considered expired and we destroy it. That's
 * why we have a keep-alive method in the API. This can be overridden in
 * either janus.cfg/.jcfg or from the command line. Setting this to 0 will
 * disable the timeout mechanism, which is NOT suggested as it may risk
 * having orphaned sessions (sessions not controlled by any transport
 * and never freed). Besides, notice that if you make this shorter than
 * 30s, you'll have to update the timers in janus.js when the long
 * polling mechanism is used and shorten them as well, or you'll risk
 * incurring in unexpected timeouts (when HTTP is used in janus.js, the
 * long poll is used as a keepalive mechanism). */
#define DEFAULT_SESSION_TIMEOUT		60
static uint global_session_timeout = DEFAULT_SESSION_TIMEOUT;

#define DEFAULT_RECLAIM_SESSION_TIMEOUT		0
static uint reclaim_session_timeout = DEFAULT_RECLAIM_SESSION_TIMEOUT;

/* We can programmatically change whether we want to accept new sessions
 * or not: the default is of course TRUE, but we may want to temporarily
 * change that in some cases, e.g., if we don't want the load on this
 * server to grow too much, or because we're draining the server. */
static gboolean accept_new_sessions = TRUE;

/* We don't hold (trickle) candidates indefinitely either: by default, we
 * only store them for 45 seconds. After that, they're discarded, in order
 * to avoid leaks or orphaned media details. This means that, if for instance
 * you're trying to set up a call with someone, and that someone only answers
 * a minute later, the candidates you sent initially will be discarded and
 * the call will fail. You can modify the default value in janus.jcfg */
#define DEFAULT_CANDIDATES_TIMEOUT		45
static uint candidates_timeout = DEFAULT_CANDIDATES_TIMEOUT;

/* By default we list dependencies details, but some may prefer not to */
static gboolean hide_dependencies = FALSE;

/* By default we do not exit if a shared library cannot be loaded or is missing an expected symbol */
static gboolean exit_on_dl_error = FALSE;

/* WebRTC encryption is obviously enabled by default. In the rare cases
 * you want to disable it for debugging purposes, though, you can do
 * that either via command line (-w) or in the main configuration file */
static gboolean webrtc_encryption = TRUE;
gboolean janus_is_webrtc_encryption_enabled(void) {
	return webrtc_encryption;
}

/* Information */
static json_t *janus_info(const char *transaction) {
	/* Prepare a summary on the Janus instance */
	json_t *info = janus_create_message("server_info", 0, transaction);
	json_object_set_new(info, "name", json_string(JANUS_NAME));
	json_object_set_new(info, "version", json_integer(janus_version));
	json_object_set_new(info, "version_string", json_string(janus_version_string));
	json_object_set_new(info, "author", json_string(JANUS_AUTHOR));
	json_object_set_new(info, "commit-hash", json_string(janus_build_git_sha));
	json_object_set_new(info, "compile-time", json_string(janus_build_git_time));
	json_object_set_new(info, "log-to-stdout", janus_log_is_stdout_enabled() ? json_true() : json_false());
	json_object_set_new(info, "log-to-file", janus_log_is_logfile_enabled() ? json_true() : json_false());
	if(janus_log_is_logfile_enabled())
		json_object_set_new(info, "log-path", json_string(janus_log_get_logfile_path()));
#ifdef HAVE_SCTP
	json_object_set_new(info, "data_channels", json_true());
#else
	json_object_set_new(info, "data_channels", json_false());
#endif
	json_object_set_new(info, "accepting-new-sessions", accept_new_sessions ? json_true() : json_false());
	json_object_set_new(info, "session-timeout", json_integer(global_session_timeout));
	json_object_set_new(info, "reclaim-session-timeout", json_integer(reclaim_session_timeout));
	json_object_set_new(info, "candidates-timeout", json_integer(candidates_timeout));
	json_object_set_new(info, "server-name", json_string(server_name ? server_name : JANUS_SERVER_NAME));
	json_object_set_new(info, "local-ip", json_string(local_ip));
	guint public_ip_count = janus_get_public_ip_count();
	if(public_ip_count > 0) {
		json_object_set_new(info, "public-ip", json_string(janus_get_public_ip(0)));
	}
	if(public_ip_count > 1) {
		guint i;
		json_t *ips = json_array();
		for (i = 0; i < public_ip_count; i++) {
			json_array_append_new(ips, json_string(janus_get_public_ip(i)));
		}
		json_object_set_new(info, "public-ips", ips);
	}
	json_object_set_new(info, "ipv6", janus_ice_is_ipv6_enabled() ? json_true() : json_false());
	if(janus_ice_is_ipv6_enabled())
		json_object_set_new(info, "ipv6-link-local", janus_ice_is_ipv6_linklocal_enabled() ? json_true() : json_false());
	json_object_set_new(info, "ice-lite", janus_ice_is_ice_lite_enabled() ? json_true() : json_false());
	json_object_set_new(info, "ice-tcp", janus_ice_is_ice_tcp_enabled() ? json_true() : json_false());
#ifdef HAVE_ICE_NOMINATION
	json_object_set_new(info, "ice-nomination", json_string(janus_ice_get_nomination_mode()));
#endif
	json_object_set_new(info, "ice-consent-freshness", janus_ice_is_consent_freshness_enabled() ? json_true() : json_false());
	json_object_set_new(info, "ice-keepalive-conncheck", janus_ice_is_keepalive_conncheck_enabled() ? json_true() : json_false());
	json_object_set_new(info, "hangup-on-failed", janus_ice_is_hangup_on_failed_enabled() ? json_true() : json_false());
	json_object_set_new(info, "full-trickle", janus_ice_is_full_trickle_enabled() ? json_true() : json_false());
	json_object_set_new(info, "mdns-enabled", janus_ice_is_mdns_enabled() ? json_true() : json_false());
	json_object_set_new(info, "min-nack-queue", json_integer(janus_get_min_nack_queue()));
	json_object_set_new(info, "nack-optimizations", janus_is_nack_optimizations_enabled() ? json_true() : json_false());
	json_object_set_new(info, "twcc-period", json_integer(janus_get_twcc_period()));
	if(janus_get_dscp() > 0)
		json_object_set_new(info, "dscp", json_integer(janus_get_dscp()));
	json_object_set_new(info, "dtls-mtu", json_integer(janus_dtls_bio_agent_get_mtu()));
	if(janus_ice_get_stun_server() != NULL) {
		char server[255];
		g_snprintf(server, 255, "%s:%"SCNu16, janus_ice_get_stun_server(), janus_ice_get_stun_port());
		json_object_set_new(info, "stun-server", json_string(server));
	}
	if(janus_ice_get_turn_server() != NULL) {
		char server[255];
		g_snprintf(server, 255, "%s:%"SCNu16, janus_ice_get_turn_server(), janus_ice_get_turn_port());
		json_object_set_new(info, "turn-server", json_string(server));
	}
	if(janus_ice_is_force_relay_allowed())
		json_object_set_new(info, "allow-force-relay", json_true());
	json_object_set_new(info, "static-event-loops", json_integer(janus_ice_get_static_event_loops()));
	if(janus_ice_get_static_event_loops())
		json_object_set_new(info, "loop-indication", janus_ice_is_loop_indication_allowed() ? json_true() : json_false());
	json_object_set_new(info, "api_secret", api_secret ? json_true() : json_false());
	json_object_set_new(info, "auth_token", janus_auth_is_enabled() ? json_true() : json_false());
	json_object_set_new(info, "event_handlers", janus_events_is_enabled() ? json_true() : json_false());
	json_object_set_new(info, "opaqueid_in_api", janus_is_opaqueid_in_api_enabled() ? json_true() : json_false());
	if(!webrtc_encryption)
		json_object_set_new(info, "webrtc_encryption", json_false());
	/* Dependencies */
	if(!hide_dependencies) {
		json_t *deps = json_object();
		char glib2_version[20];
		g_snprintf(glib2_version, sizeof(glib2_version), "%d.%d.%d", glib_major_version, glib_minor_version, glib_micro_version);
		json_object_set_new(deps, "glib2", json_string(glib2_version));
		json_object_set_new(deps, "jansson", json_string(JANSSON_VERSION));
		json_object_set_new(deps, "libnice", json_string(libnice_version_string));
		json_object_set_new(deps, "libsrtp", json_string(srtp_get_version_string()));
	#ifdef HAVE_TURNRESTAPI
		curl_version_info_data *curl_version = curl_version_info(CURLVERSION_NOW);
		if(curl_version && curl_version->version)
			json_object_set_new(deps, "libcurl", json_string(curl_version->version));
	#endif
		json_object_set_new(deps, "crypto", json_string(janus_get_ssl_version()));
		json_object_set_new(info, "dependencies", deps);
	}
	/* Available transports */
	json_t *t_data = json_object();
	if(transports && g_hash_table_size(transports) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, transports);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_transport *t = value;
			if(t == NULL) {
				continue;
			}
			json_t *transport = json_object();
			json_object_set_new(transport, "name", json_string(t->get_name()));
			json_object_set_new(transport, "author", json_string(t->get_author()));
			json_object_set_new(transport, "description", json_string(t->get_description()));
			json_object_set_new(transport, "version_string", json_string(t->get_version_string()));
			json_object_set_new(transport, "version", json_integer(t->get_version()));
			json_object_set_new(t_data, t->get_package(), transport);
		}
	}
	json_object_set_new(info, "transports", t_data);
	/* Available event handlers */
	json_t *e_data = json_object();
	if(eventhandlers && g_hash_table_size(eventhandlers) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, eventhandlers);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_eventhandler *e = value;
			if(e == NULL) {
				continue;
			}
			json_t *eventhandler = json_object();
			json_object_set_new(eventhandler, "name", json_string(e->get_name()));
			json_object_set_new(eventhandler, "author", json_string(e->get_author()));
			json_object_set_new(eventhandler, "description", json_string(e->get_description()));
			json_object_set_new(eventhandler, "version_string", json_string(e->get_version_string()));
			json_object_set_new(eventhandler, "version", json_integer(e->get_version()));
			json_object_set_new(e_data, e->get_package(), eventhandler);
		}
	}
	json_object_set_new(info, "events", e_data);
	/* Available external loggers */
	json_t *l_data = json_object();
	if(loggers && g_hash_table_size(loggers) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, loggers);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_logger *l = value;
			if(l == NULL) {
				continue;
			}
			json_t *logger = json_object();
			json_object_set_new(logger, "name", json_string(l->get_name()));
			json_object_set_new(logger, "author", json_string(l->get_author()));
			json_object_set_new(logger, "description", json_string(l->get_description()));
			json_object_set_new(logger, "version_string", json_string(l->get_version_string()));
			json_object_set_new(logger, "version", json_integer(l->get_version()));
			json_object_set_new(l_data, l->get_package(), logger);
		}
	}
	json_object_set_new(info, "loggers", l_data);
	/* Available plugins */
	json_t *p_data = json_object();
	if(plugins && g_hash_table_size(plugins) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, plugins);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_plugin *p = value;
			if(p == NULL) {
				continue;
			}
			json_t *plugin = json_object();
			json_object_set_new(plugin, "name", json_string(p->get_name()));
			json_object_set_new(plugin, "author", json_string(p->get_author()));
			json_object_set_new(plugin, "description", json_string(p->get_description()));
			json_object_set_new(plugin, "version_string", json_string(p->get_version_string()));
			json_object_set_new(plugin, "version", json_integer(p->get_version()));
			json_object_set_new(p_data, p->get_package(), plugin);
		}
	}
	json_object_set_new(info, "plugins", p_data);

	return info;
}


/* Logging */
int janus_log_level = LOG_INFO;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
static int janus_log_rotate_sig = 0;
int lock_debug = 0;
#ifdef REFCOUNT_DEBUG
int refcount_debug = 1;
#else
int refcount_debug = 0;
#endif


/*! \brief Signal handler (just used to intercept CTRL+C, SIGTERM and SIGUSR1) */
static void janus_handle_signal(int signum) {
	if(signum == janus_log_rotate_sig && janus_log_rotate_sig > 0) {
		if(stop_signal > 0)
			/* Skip log rotation while stopping */
			return;
		janus_log_reload();
		return;
	}
	/* If we got here it's either a SIGINT or a SIGTERM */
	stop_signal = signum;
	switch(g_atomic_int_get(&stop)) {
		case 0:
			JANUS_PRINT("Stopping server, please wait...\n");
			break;
		case 1:
			JANUS_PRINT("In a hurry? I'm trying to free resources cleanly, here!\n");
			break;
		default:
			JANUS_PRINT("Ok, leaving immediately...\n");
			break;
	}
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
	if(mainloop && g_main_loop_is_running(mainloop))
		g_main_loop_quit(mainloop);
}

/*! \brief Termination handler (atexit) */
static void janus_termination_handler(void) {
	/* Free the instance name, if provided */
	g_free(server_name);
	/* Remove the PID file if we created it */
	janus_pidfile_remove();
	/* Close the logger */
	janus_log_destroy();
	/* Get rid of external loggers too, if any */
	if(loggers != NULL && g_hash_table_size(loggers) > 0) {
		g_hash_table_foreach(loggers, janus_logger_close, NULL);
		g_hash_table_destroy(loggers);
	}
	if(loggers_so != NULL && g_hash_table_size(loggers_so) > 0) {
		g_hash_table_foreach(loggers_so, janus_loggerso_close, NULL);
		g_hash_table_destroy(loggers_so);
	}
	/* If we're daemonizing, we send an error code to the parent */
	if(daemonize) {
		int code = 1;
		ssize_t res = 0;
		do {
			res = write(pipefd[1], &code, sizeof(int));
		} while(res == -1 && errno == EINTR);
	}
}


/** @name Transport plugin callback interface
 * These are the callbacks implemented by the Janus core, as part of
 * the janus_transport_callbacks interface. Everything the transport
 * plugins send the core is handled here.
 */
///@{
void janus_transport_incoming_request(janus_transport *plugin, janus_transport_session *transport, void *request_id, gboolean admin, json_t *message, json_error_t *error);
void janus_transport_gone(janus_transport *plugin, janus_transport_session *transport);
gboolean janus_transport_is_api_secret_needed(janus_transport *plugin);
gboolean janus_transport_is_api_secret_valid(janus_transport *plugin, const char *apisecret);
gboolean janus_transport_is_auth_token_needed(janus_transport *plugin);
gboolean janus_transport_is_auth_token_valid(janus_transport *plugin, const char *token);
void janus_transport_notify_event(janus_transport *plugin, void *transport, json_t *event);

static janus_transport_callbacks janus_handler_transport =
	{
		.incoming_request = janus_transport_incoming_request,
		.transport_gone = janus_transport_gone,
		.is_api_secret_needed = janus_transport_is_api_secret_needed,
		.is_api_secret_valid = janus_transport_is_api_secret_valid,
		.is_auth_token_needed = janus_transport_is_auth_token_needed,
		.is_auth_token_valid = janus_transport_is_auth_token_valid,
		.events_is_enabled = janus_events_is_enabled,
		.notify_event = janus_transport_notify_event,
	};
static GAsyncQueue *requests = NULL;
static janus_request exit_message;
static GThreadPool *tasks = NULL;
void janus_transport_task(gpointer data, gpointer user_data);
///@}


/** @name Plugin callback interface
 * These are the callbacks implemented by the Janus core, as part of
 * the janus_callbacks interface. Everything the plugins send the
 * core is handled here.
 */
///@{
int janus_plugin_push_event(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *transaction, json_t *message, json_t *jsep);
json_t *janus_plugin_handle_sdp(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *sdp_type, const char *sdp, gboolean restart);
void janus_plugin_relay_rtp(janus_plugin_session *plugin_session, janus_plugin_rtp *packet);
void janus_plugin_relay_rtcp(janus_plugin_session *plugin_session, janus_plugin_rtcp *packet);
void janus_plugin_relay_data(janus_plugin_session *plugin_session, janus_plugin_data *message);
void janus_plugin_send_pli(janus_plugin_session *plugin_session);
void janus_plugin_send_pli_stream(janus_plugin_session *plugin_session, int mindex);
void janus_plugin_send_remb(janus_plugin_session *plugin_session, uint32_t bitrate);
void janus_plugin_close_pc(janus_plugin_session *plugin_session);
void janus_plugin_end_session(janus_plugin_session *plugin_session);
void janus_plugin_notify_event(janus_plugin *plugin, janus_plugin_session *plugin_session, json_t *event);
gboolean janus_plugin_auth_is_signed(void);
gboolean janus_plugin_auth_is_signature_valid(janus_plugin *plugin, const char *token);
gboolean janus_plugin_auth_signature_contains(janus_plugin *plugin, const char *token, const char *desc);
static janus_callbacks janus_handler_plugin =
	{
		.push_event = janus_plugin_push_event,
		.relay_rtp = janus_plugin_relay_rtp,
		.relay_rtcp = janus_plugin_relay_rtcp,
		.relay_data = janus_plugin_relay_data,
		.send_pli = janus_plugin_send_pli,
		.send_pli_stream = janus_plugin_send_pli_stream,
		.send_remb = janus_plugin_send_remb,
		.close_pc = janus_plugin_close_pc,
		.end_session = janus_plugin_end_session,
		.events_is_enabled = janus_events_is_enabled,
		.notify_event = janus_plugin_notify_event,
		.auth_is_signed = janus_plugin_auth_is_signed,
		.auth_is_signature_valid = janus_plugin_auth_is_signature_valid,
		.auth_signature_contains = janus_plugin_auth_signature_contains,
	};
///@}


/* Core Sessions */
static janus_mutex sessions_mutex = JANUS_MUTEX_INITIALIZER;
static GHashTable *sessions = NULL;
static GMainContext *sessions_watchdog_context = NULL;

/* Counters */
static volatile gint sessions_num = 0;
static volatile gint handles_num = 0;

static void janus_ice_handle_dereference(janus_ice_handle *handle) {
	if(handle)
		janus_refcount_decrease(&handle->ref);
}

static void janus_session_free(const janus_refcount *session_ref) {
	janus_session *session = janus_refcount_containerof(session_ref, janus_session, ref);
	/* This session can be destroyed, free all the resources */
	if(session->ice_handles != NULL) {
		g_hash_table_destroy(session->ice_handles);
		session->ice_handles = NULL;
	}
	if(session->source != NULL) {
		janus_request_destroy(session->source);
		session->source = NULL;
	}
	janus_mutex_destroy(&session->mutex);
	g_free(session);
}

static janus_request *janus_session_get_request(janus_session *session) {
	if(session == NULL)
		return NULL;
	janus_mutex_lock(&session->mutex);
	janus_request *source = session->source;
	if(source != NULL && !g_atomic_int_get(&source->destroyed)) {
		janus_refcount_increase(&source->ref);
	} else {
		source = NULL;
	}
	janus_mutex_unlock(&session->mutex);
	return source;
}
static void janus_request_unref(janus_request *request) {
	if(request)
		janus_refcount_decrease(&request->ref);
}

static gboolean janus_check_sessions(gpointer user_data) {
	janus_mutex_lock(&sessions_mutex);
	if(sessions && g_hash_table_size(sessions) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, sessions);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_session *session = (janus_session *) value;
			if(!session || g_atomic_int_get(&session->destroyed))
				continue;
			gint64 now = janus_get_monotonic_time();
			/* Use either session-specific timeout or global. */
			gint64 timeout = (gint64)session->timeout;
			if(timeout == -1)
				timeout = (gint64)global_session_timeout;
			if((timeout > 0 && (now - session->last_activity >= timeout * G_USEC_PER_SEC)) ||
					((g_atomic_int_get(&session->transport_gone) && now - session->last_activity >= (gint64)reclaim_session_timeout * G_USEC_PER_SEC))) {
				if(g_atomic_int_compare_and_exchange(&session->timedout, 0, 1)) {
					JANUS_LOG(LOG_INFO, "Timeout expired for session %"SCNu64"...\n", session->session_id);
					/* Mark the session as over, we'll deal with it later */
					janus_session_handles_clear(session);
					/* Notify the transport */
					janus_request *source = janus_session_get_request(session);
					if(source) {
						json_t *event = janus_create_message("timeout", session->session_id, NULL);
						/* Send this to the transport client and notify the session's over */
						source->transport->send_message(source->instance, NULL, FALSE, event);
						source->transport->session_over(source->instance, session->session_id, TRUE, FALSE);
					}
					janus_request_unref(source);
					/* Notify event handlers as well */
					if(janus_events_is_enabled())
						janus_events_notify_handlers(JANUS_EVENT_TYPE_SESSION, JANUS_EVENT_SUBTYPE_NONE,
							session->session_id, "timeout", NULL);
					g_hash_table_iter_remove(&iter);
					g_atomic_int_dec_and_test(&sessions_num);
					janus_session_destroy(session);
				}
			}
		}
	}
	janus_mutex_unlock(&sessions_mutex);

	return G_SOURCE_CONTINUE;
}

static gpointer janus_sessions_watchdog(gpointer user_data) {
	GMainLoop *loop = (GMainLoop *) user_data;
	GMainContext *watchdog_context = g_main_loop_get_context(loop);
	GSource *timeout_source;

	timeout_source = g_timeout_source_new_seconds(2);
	g_source_set_callback(timeout_source, janus_check_sessions, watchdog_context, NULL);
	g_source_attach(timeout_source, watchdog_context);
	g_source_unref(timeout_source);

	JANUS_LOG(LOG_INFO, "Sessions watchdog started\n");

	g_main_loop_run(loop);

	JANUS_LOG(LOG_INFO, "Sessions watchdog stopped\n");

	return NULL;
}

static gboolean janus_status_sessions(gpointer user_data) {
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "status", json_string("update"));
		json_t *details = json_object();
		json_object_set_new(details, "sessions", json_integer(g_atomic_int_get(&sessions_num)));
		json_object_set_new(details, "handles", json_integer(g_atomic_int_get(&handles_num)));
		json_object_set_new(details, "peerconnections", json_integer(janus_ice_get_peerconnection_num()));
		json_object_set_new(details, "stats-period", json_integer(janus_ice_get_event_stats_period()));
		json_object_set_new(info, "info", details);
		janus_events_notify_handlers(JANUS_EVENT_TYPE_CORE, JANUS_EVENT_SUBTYPE_CORE_STARTUP, 0, info);
	}
	return TRUE;
}

janus_session *janus_session_create(guint64 session_id) {
	janus_session *session = NULL;
	if(session_id == 0) {
		while(session_id == 0) {
			session_id = janus_random_uint64();
			session = janus_session_find(session_id);
			if(session != NULL) {
				/* Session ID already taken, try another one */
				janus_refcount_decrease(&session->ref);
				session_id = 0;
			}
		}
	}
	session = (janus_session *)g_malloc(sizeof(janus_session));
	JANUS_LOG(LOG_INFO, "Creating new session: %"SCNu64"; %p\n", session_id, session);
	session->session_id = session_id;
	janus_refcount_init(&session->ref, janus_session_free);
	session->source = NULL;
	session->timeout = -1; /* Negative means rely on global timeout */
	g_atomic_int_set(&session->destroyed, 0);
	g_atomic_int_set(&session->timedout, 0);
	g_atomic_int_set(&session->transport_gone, 0);
	session->last_activity = janus_get_monotonic_time();
	session->ice_handles = NULL;
	janus_mutex_init(&session->mutex);
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, janus_uint64_dup(session->session_id), session);
	g_atomic_int_inc(&sessions_num);
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

janus_session *janus_session_find(guint64 session_id) {
	janus_mutex_lock(&sessions_mutex);
	janus_session *session = g_hash_table_lookup(sessions, &session_id);
	if(session != NULL) {
		/* A successful find automatically increases the reference counter:
		 * it's up to the caller to decrease it again when done */
		janus_refcount_increase(&session->ref);
	}
	janus_mutex_unlock(&sessions_mutex);
	return session;
}

void janus_session_notify_event(janus_session *session, json_t *event) {
	if(session != NULL && !g_atomic_int_get(&session->destroyed)) {
		janus_request *source = janus_session_get_request(session);
		if(source != NULL && source->transport != NULL) {
			/* Send this to the transport client */
			JANUS_LOG(LOG_HUGE, "Sending event to %s (%p)\n", source->transport->get_package(), source->instance);
			source->transport->send_message(source->instance, NULL, FALSE, event);
		} else {
			/* No transport, free the event */
			json_decref(event);
		}
		janus_request_unref(source);
	} else {
		/* No session, free the event */
		json_decref(event);
	}
}


/* Destroys a session but does not remove it from the sessions hash table. */
gint janus_session_destroy(janus_session *session) {
	guint64 session_id = session->session_id;
	JANUS_LOG(LOG_INFO, "Destroying session %"SCNu64"; %p\n", session_id, session);
	if(!g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		return 0;
	janus_session_handles_clear(session);
	/* The session will actually be destroyed when the counter gets to 0 */
	janus_refcount_decrease(&session->ref);

	return 0;
}

janus_ice_handle *janus_session_handles_find(janus_session *session, guint64 handle_id) {
	if(session == NULL)
		return NULL;
	janus_mutex_lock(&session->mutex);
	janus_ice_handle *handle = session->ice_handles ? g_hash_table_lookup(session->ice_handles, &handle_id) : NULL;
	if(handle != NULL) {
		/* A successful find automatically increases the reference counter:
		 * it's up to the caller to decrease it again when done */
		janus_refcount_increase(&handle->ref);
	}
	janus_mutex_unlock(&session->mutex);
	return handle;
}

void janus_session_handles_insert(janus_session *session, janus_ice_handle *handle) {
	janus_mutex_lock(&session->mutex);
	if(session->ice_handles == NULL)
		session->ice_handles = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, (GDestroyNotify)janus_ice_handle_dereference);
	janus_refcount_increase(&handle->ref);
	g_hash_table_insert(session->ice_handles, janus_uint64_dup(handle->handle_id), handle);
	g_atomic_int_inc(&handles_num);
	janus_mutex_unlock(&session->mutex);
}

gint janus_session_handles_remove(janus_session *session, janus_ice_handle *handle) {
	janus_mutex_lock(&session->mutex);
	gint error = janus_ice_handle_destroy(session, handle);
	if(g_hash_table_remove(session->ice_handles, &handle->handle_id))
		g_atomic_int_dec_and_test(&handles_num);
	janus_mutex_unlock(&session->mutex);
	return error;
}

void janus_session_handles_clear(janus_session *session) {
	janus_mutex_lock(&session->mutex);
	if(session->ice_handles != NULL && g_hash_table_size(session->ice_handles) > 0) {
		GHashTableIter iter;
		gpointer value;
		/* Remove all handles */
		g_hash_table_iter_init(&iter, session->ice_handles);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_ice_handle *handle = value;
			if(!handle)
				continue;
			janus_ice_handle_destroy(session, handle);
			g_hash_table_iter_remove(&iter);
			g_atomic_int_dec_and_test(&handles_num);
		}
	}
	janus_mutex_unlock(&session->mutex);
}

json_t *janus_session_handles_list_json(janus_session *session) {
	json_t *list = json_array();
	janus_mutex_lock(&session->mutex);
	if(session->ice_handles != NULL && g_hash_table_size(session->ice_handles) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, session->ice_handles);
		while (g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_ice_handle *handle = value;
			if(!handle)
				continue;
			json_array_append_new(list, json_integer(handle->handle_id));
		}
	}
	janus_mutex_unlock(&session->mutex);
	return list;
}

/* Requests management */
static void janus_request_free(const janus_refcount *request_ref) {
	janus_request *request = janus_refcount_containerof(request_ref, janus_request, ref);
	/* This request can be destroyed, free all the resources */
	request->transport = NULL;
	if(request->instance)
		janus_refcount_decrease(&request->instance->ref);
	request->instance = NULL;
	request->request_id = NULL;
	if(request->message) {
		json_decref(request->message);
		request->message = NULL;
	}
	if(request->error) {
		g_free(request->error);
		request->error = NULL;
	}
	g_free(request);
}

janus_request *janus_request_new(janus_transport *transport, janus_transport_session *instance, void *request_id, gboolean admin, json_t *message, json_error_t *error) {
	janus_request *request = g_malloc(sizeof(janus_request));
	request->transport = transport;
	request->instance = instance;
	janus_refcount_increase(&instance->ref);
	request->request_id = request_id;
	request->admin = admin;
	request->message = message;
	if(error) {
		request->error = (json_error_t*)g_malloc(sizeof(json_error_t));
		*request->error = *error;
	} else {
		request->error = NULL;
	}
	g_atomic_int_set(&request->destroyed, 0);
	janus_refcount_init(&request->ref, janus_request_free);
	return request;
}

void janus_request_destroy(janus_request *request) {
	if(request == NULL || request == &exit_message || !g_atomic_int_compare_and_exchange(&request->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&request->ref);
}

static int janus_request_check_secret(janus_request *request, guint64 session_id, const gchar *transaction_text) {
	gboolean secret_authorized = FALSE, token_authorized = FALSE;
	if(api_secret == NULL && !janus_auth_is_enabled()) {
		/* Nothing to check */
		secret_authorized = TRUE;
		token_authorized = TRUE;
	} else {
		json_t *root = request->message;
		if(api_secret != NULL) {
			/* There's an API secret, check that the client provided it */
			json_t *secret = json_object_get(root, "apisecret");
			if(secret && json_is_string(secret) && janus_strcmp_const_time(json_string_value(secret), api_secret)) {
				secret_authorized = TRUE;
			}
		}
		if(janus_auth_is_enabled()) {
			/* The token based authentication mechanism is enabled, check that the client provided it */
			json_t *token = json_object_get(root, "token");
			if(token && json_is_string(token) && janus_auth_check_token(json_string_value(token))) {
				token_authorized = TRUE;
			}
		}
		/* We consider a request authorized if either the proper API secret or a valid token has been provided */
		if(!(api_secret != NULL && secret_authorized) && !(janus_auth_is_enabled() && token_authorized))
			return JANUS_ERROR_UNAUTHORIZED;
	}
	return 0;
}

static void janus_request_ice_handle_answer(janus_ice_handle *handle, char *jsep_sdp) {
	/* We got our answer */
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
	/* Any pending trickles? */
	if(handle->pending_trickles) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Processing %d pending trickle candidates\n", handle->handle_id, g_list_length(handle->pending_trickles));
		GList *temp = NULL;
		while(handle->pending_trickles) {
			temp = g_list_first(handle->pending_trickles);
			handle->pending_trickles = g_list_remove_link(handle->pending_trickles, temp);
			janus_ice_trickle *trickle = (janus_ice_trickle *)temp->data;
			g_list_free(temp);
			if(trickle == NULL)
				continue;
			if((janus_get_monotonic_time() - trickle->received) > candidates_timeout*G_USEC_PER_SEC) {
				/* FIXME Candidate is too old, discard it */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Discarding candidate (too old)\n", handle->handle_id);
				janus_ice_trickle_destroy(trickle);
				/* FIXME We should report that */
				continue;
			}
			json_t *candidate = trickle->candidate;
			if(candidate == NULL) {
				janus_ice_trickle_destroy(trickle);
				continue;
			}
			if(json_is_object(candidate)) {
				/* We got a single candidate */
				int error = 0;
				const char *error_string = NULL;
				if((error = janus_ice_trickle_parse(handle, candidate, &error_string)) != 0) {
					/* FIXME We should report the error parsing the trickle candidate */
				}
			} else if(json_is_array(candidate)) {
				/* We got multiple candidates in an array */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got multiple candidates (%zu)\n", handle->handle_id, json_array_size(candidate));
				if(json_array_size(candidate) > 0) {
					/* Handle remote candidates */
					size_t i = 0;
					for(i=0; i<json_array_size(candidate); i++) {
						json_t *c = json_array_get(candidate, i);
						/* FIXME We don't care if any trickle fails to parse */
						janus_ice_trickle_parse(handle, c, NULL);
					}
				}
			}
			/* Done, free candidate */
			janus_ice_trickle_destroy(trickle);
		}
	}

	gboolean candidates_found = (handle->pc && g_slist_length(handle->pc->candidates) > 0);
	/* This was an answer, check if it's time to start ICE */
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) && !candidates_found) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- ICE Trickling is supported by the browser, waiting for remote candidates...\n", handle->handle_id);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
	} else {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Done! Sending connectivity checks...\n", handle->handle_id);
		janus_ice_setup_remote_candidates(handle, handle->stream_id, 1);
	}
}

int janus_process_incoming_request(janus_request *request) {
	int ret = -1;
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or payload to process, giving up...\n");
		return ret;
	}
	json_t *root = request->message;
	if(root == NULL) {
		json_error_t *error = request->error;
		if(error != NULL) {
			ret = janus_process_error(request, 0, NULL, JANUS_ERROR_INVALID_JSON,
				"Invalid Janus API request - %s(%d,%d): %s", error->source, error->line, error->column, error->text);
		} else {
			ret = janus_process_error_string(request, 0, NULL, JANUS_ERROR_INVALID_JSON, (char *)"Invalid Janus API request");
		}
		return ret;
	}
	/* Ok, let's start with the ids */
	guint64 session_id = 0, handle_id = 0;
	json_t *s = json_object_get(root, "session_id");
	if(json_is_null(s))
		s = NULL;
	if(s && json_is_integer(s))
		session_id = json_integer_value(s);
	json_t *h = json_object_get(root, "handle_id");
	if(json_is_null(h))
		h = NULL;
	if(h && json_is_integer(h))
		handle_id = json_integer_value(h);

	janus_session *session = NULL;
	janus_ice_handle *handle = NULL;

	int error_code = 0;
	char error_cause[100];
	/* Get transaction and message request */
	JANUS_VALIDATE_JSON_OBJECT(root, incoming_request_parameters,
		error_code, error_cause, FALSE,
		JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
	if(error_code != 0) {
		ret = janus_process_error_string(request, session_id, NULL, error_code, error_cause);
		goto jsondone;
	}
	json_t *transaction = json_object_get(root, "transaction");
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	const gchar *message_text = json_string_value(message);

	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Create new session', a 'Get info' or a 'Ping/Pong' request */
		if(!strcasecmp(message_text, "info")) {
			ret = janus_process_success(request, janus_info(transaction_text));
			goto jsondone;
		}
		if(!strcasecmp(message_text, "ping")) {
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("pong", 0, transaction_text);
			ret = janus_process_success(request, reply);
			goto jsondone;
		}
		if(strcasecmp(message_text, "create")) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		/* Make sure we're accepting new sessions */
		if(!accept_new_sessions) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_NOT_ACCEPTING_SESSIONS, NULL);
			goto jsondone;
		}
		/* Any secret/token to check? */
		ret = janus_request_check_secret(request, session_id, transaction_text);
		if(ret != 0) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
		session_id = 0;
		json_t *id = json_object_get(root, "id");
		if(id != NULL) {
			/* The application provided the session ID to use */
			session_id = json_integer_value(id);
			if(session_id > 0 && (session = janus_session_find(session_id)) != NULL) {
				/* Session ID already taken */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_CONFLICT, "Session ID already in use");
				goto jsondone;
			}
		}

		/* Handle it */
		session = janus_session_create(session_id);
		if(session == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
			goto jsondone;
		}
		session_id = session->session_id;
		/* We increase the counter as this request is using the session */
		janus_refcount_increase(&session->ref);
		/* Take note of the request source that originated this session (HTTP, WebSockets, RabbitMQ?) */
		session->source = janus_request_new(request->transport, request->instance, NULL, FALSE, NULL, NULL);
		/* Notify the source that a new session has been created */
		request->transport->session_created(request->instance, session->session_id);
		/* Notify event handlers */
		if(janus_events_is_enabled()) {
			/* Session created, add info on the transport that originated it */
			json_t *transport = json_object();
			json_object_set_new(transport, "transport", json_string(session->source->transport->get_package()));
			char id[32];
			memset(id, 0, sizeof(id));
			/* To avoid sending a stringified version of the transport pointer
			 * around, we convert it to a number and hash it instead */
			uint64_t p = janus_uint64_hash(GPOINTER_TO_UINT(session->source->instance));
			g_snprintf(id, sizeof(id), "%"SCNu64, p);
			json_object_set_new(transport, "id", json_string(id));
			janus_events_notify_handlers(JANUS_EVENT_TYPE_SESSION, JANUS_EVENT_SUBTYPE_NONE,
				session_id, "created", transport);
		}
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", 0, transaction_text);
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(session_id));
		json_object_set_new(reply, "data", data);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	ret = janus_request_check_secret(request, session_id, transaction_text);
	if(ret != 0) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
		goto jsondone;
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	/* Update the last activity timer */
	session->last_activity = janus_get_monotonic_time();
	handle = NULL;
	if(handle_id > 0) {
		handle = janus_session_handles_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}

	/* What is this? */
	if(!strcasecmp(message_text, "keepalive")) {
		/* Just a keep-alive message, reply with an ack */
		JANUS_LOG(LOG_VERB, "Got a keep-alive on session %"SCNu64"\n", session_id);
		json_t *reply = janus_create_message("ack", session_id, transaction_text);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "attach")) {
		if(handle != NULL) {
			/* Attach is a session-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, attach_parameters,
			error_code, error_cause, FALSE,
			JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
		if(error_code != 0) {
			ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
			goto jsondone;
		}
		json_t *plugin = json_object_get(root, "plugin");
		const gchar *plugin_text = json_string_value(plugin);
		janus_plugin *plugin_t = janus_plugin_find(plugin_text);
		if(plugin_t == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, "No such plugin '%s'", plugin_text);
			goto jsondone;
		}
		/* If the auth token mechanism is enabled, we should check if this token can access this plugin */
		const char *token_value = NULL;
		if(janus_auth_is_enabled()) {
			json_t *token = json_object_get(root, "token");
			if(token != NULL) {
				token_value = json_string_value(token);
				if(token_value && !janus_auth_check_plugin(token_value, plugin_t)) {
					JANUS_LOG(LOG_ERR, "Token '%s' can't access plugin '%s'\n", token_value, plugin_text);
					ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED_PLUGIN, "Provided token can't access plugin '%s'", plugin_text);
					goto jsondone;
				}
			}
		}
		json_t *opaque = json_object_get(root, "opaque_id");
		const char *opaque_id = opaque ? json_string_value(opaque) : NULL;
		json_t *loop = json_object_get(root, "loop_index");
		int loop_index = loop ? json_integer_value(loop) : -1;
		/* Create handle */
		handle = janus_ice_handle_create(session, opaque_id, token_value);
		if(handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Memory error");
			goto jsondone;
		}
		handle_id = handle->handle_id;
		/* We increase the counter as this request is using the handle */
		janus_refcount_increase(&handle->ref);
		/* Attach to the plugin */
		int error = 0;
		if((error = janus_ice_handle_attach_plugin(session, handle, plugin_t, loop_index)) != 0) {
			/* TODO Make error struct to pass verbose information */
			janus_session_handles_remove(session, handle);
			JANUS_LOG(LOG_ERR, "Couldn't attach to plugin '%s', error '%d'\n", plugin_text, error);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_ATTACH, "Couldn't attach to plugin: error '%d'", error);
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		json_t *data = json_object();
		json_object_set_new(data, "id", json_integer(handle_id));
		json_object_set_new(reply, "data", data);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "destroy")) {
		if(handle != NULL) {
			/* Query is a session-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_remove(sessions, &session->session_id))
			g_atomic_int_dec_and_test(&sessions_num);
		janus_mutex_unlock(&sessions_mutex);
		/* Notify the source that the session has been destroyed */
		janus_request *source = janus_session_get_request(session);
		if(source && source->transport)
			source->transport->session_over(source->instance, session->session_id, FALSE, FALSE);
		janus_request_unref(source);

		/* Schedule the session for deletion */
		janus_session_destroy(session);

		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		/* Notify event handlers as well */
		if(janus_events_is_enabled())
			janus_events_notify_handlers(JANUS_EVENT_TYPE_SESSION, JANUS_EVENT_SUBTYPE_NONE,
				session_id, "destroyed", NULL);
	} else if(!strcasecmp(message_text, "detach")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin to detach from");
			goto jsondone;
		}
		int error = janus_session_handles_remove(session, handle);
		if(error != 0) {
			/* TODO Make error struct to pass verbose information */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "Couldn't detach from plugin: error '%d'", error);
			/* TODO Delete handle instance */
			goto jsondone;
		}
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "hangup")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin attached");
			goto jsondone;
		}
		janus_ice_webrtc_hangup(handle, "Janus API");
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "claim")) {
		janus_mutex_lock(&session->mutex);
		if(session->source != NULL) {
			/* If we're claiming from the same transport, ignore */
			if(session->source->instance == request->instance) {
				janus_mutex_unlock(&session->mutex);
				/* Prepare JSON reply */
				json_t *reply = json_object();
				json_object_set_new(reply, "janus", json_string("success"));
				json_object_set_new(reply, "session_id", json_integer(session_id));
				json_object_set_new(reply, "transaction", json_string(transaction_text));
				/* Send the success reply */
				ret = janus_process_success(request, reply);
				goto jsondone;
			}
			/* Notify the old transport that this session is over for them, but has been reclaimed */
			session->source->transport->session_over(session->source->instance, session->session_id, FALSE, TRUE);
			janus_request_destroy(session->source);
			session->source = NULL;
		}
		session->source = janus_request_new(request->transport, request->instance, NULL, FALSE, NULL, NULL);
		/* Notify the new transport that it has claimed a session */
		session->source->transport->session_claimed(session->source->instance, session->session_id);
		/* Previous transport may be gone, clear flag */
		g_atomic_int_set(&session->transport_gone, 0);
		janus_mutex_unlock(&session->mutex);
		/* Prepare JSON reply */
		json_t *reply = json_object();
		json_object_set_new(reply, "janus", json_string("success"));
		json_object_set_new(reply, "session_id", json_integer(session_id));
		json_object_set_new(reply, "transaction", json_string(transaction_text));
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else if(!strcasecmp(message_text, "message")) {
		if(handle == NULL) {
			/* Query is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || handle->app_handle == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this message");
			goto jsondone;
		}
		janus_plugin *plugin_t = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] There's a message for %s\n", handle->handle_id, plugin_t->get_name());
		JANUS_VALIDATE_JSON_OBJECT(root, body_parameters,
			error_code, error_cause, FALSE,
			JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
		if(error_code != 0) {
			ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
			goto jsondone;
		}
		json_t *body = json_object_get(root, "body");
		/* Is there an SDP attached? */
		json_t *jsep = json_object_get(root, "jsep");
		char *jsep_type = NULL;
		char *jsep_sdp = NULL, *jsep_sdp_stripped = NULL;
		gboolean renegotiation = FALSE;
		if(jsep != NULL) {
			if(!json_is_object(jsep)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_JSON_OBJECT, "Invalid jsep object");
				goto jsondone;
			}
			JANUS_VALIDATE_JSON_OBJECT_FORMAT("JSEP error: missing mandatory element (%s)",
				"JSEP error: invalid element type (%s should be %s)",
				jsep, jsep_parameters, error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *type = json_object_get(jsep, "type");
			jsep_type = g_strdup(json_string_value(type));
			type = NULL;
			json_t *jsep_trickle = json_object_get(jsep, "trickle");
			gboolean do_trickle = jsep_trickle ? json_is_true(jsep_trickle) : TRUE;
			json_t *jsep_rids = json_object_get(jsep, "rid_order");
			gboolean rids_hml = TRUE;
			if(jsep_rids != NULL) {
				const char *jsep_rids_value = json_string_value(jsep_rids);
				if(jsep_rids_value != NULL) {
					if(!strcasecmp(jsep_rids_value, "hml")) {
						rids_hml = TRUE;
					} else if(!strcasecmp(jsep_rids_value, "lmh")) {
						rids_hml = FALSE;
					} else {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Invalid 'rid_order' value, falling back to 'hml'\n", handle->handle_id);
					}
				}
				json_object_del(jsep, "rid_order");
			}
			json_t *jsep_e2ee = json_object_get(jsep, "e2ee");
			gboolean e2ee = jsep_e2ee ? json_is_true(jsep_e2ee) : FALSE;
			json_t *svc = json_object_get(jsep, "svc");
			if(svc) {
				/* SVC properties were passed as well, make sure the format is correct */
				gboolean svc_valid = TRUE;
				if(!json_is_array(svc) || json_array_size(svc) < 1) {
					svc_valid = FALSE;
				} else {
					size_t i = 0;
					for(i=0; i<json_array_size(svc); i++) {
						json_t *s = json_array_get(svc, i);
						if(!json_is_object(s)) {
							svc_valid = FALSE;
							break;
						}
						json_t *s_mindex = json_object_get(s, "mindex");
						json_t *s_mid = json_object_get(s, "mid");
						json_t *s_svc = json_object_get(s, "svc");
						if(!s_mindex && !s_mid) {
							svc_valid = FALSE;
							break;
						}
						if((s_mindex && !json_is_integer(s_mindex)) ||
								(s_mid && !json_is_string(s_mid)) ||
								!s_svc || !json_is_string(s_svc)) {
							svc_valid = FALSE;
							break;
						}
					}
				}
				if(!svc_valid) {
					svc = NULL;
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Invalid 'svc' value, ignoring\n", handle->handle_id);
					json_object_del(jsep, "svc");
				}
			}
			/* Are we still cleaning up from a previous media session? */
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", handle->handle_id);
				gint64 waited = 0;
				while(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
					g_usleep(100000);
					waited += 100000;
					if(waited >= 3*G_USEC_PER_SEC) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", handle->handle_id);
						ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_WEBRTC_STATE, "Still cleaning a previous session");
						goto jsondone;
					}
				}
			}
			/* Check if we're renegotiating (if we have an answer, we did an offer/answer round already) */
			renegotiation = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
			/* Check the JSEP type */
			janus_mutex_lock(&handle->mutex);
			gboolean offer = FALSE;
			if(!strcasecmp(jsep_type, "offer")) {
				offer = TRUE;
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
			} else if(!strcasecmp(jsep_type, "answer")) {
				offer = FALSE;
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER))
					janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
			} else {
				/* TODO Handle other message types as well */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_UNKNOWN_TYPE, "JSEP error: unknown message type '%s'", jsep_type);
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			json_t *sdp = json_object_get(jsep, "sdp");
			jsep_sdp = (char *)json_string_value(sdp);
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Remote SDP:\n%s", handle->handle_id, jsep_sdp);
			/* Is this valid SDP? */
			char error_str[512];
			error_str[0] = '\0';
			janus_dtls_role peer_dtls_role = JANUS_DTLS_ROLE_ACTPASS;
			int audio = 0, video = 0, data = 0;
			janus_sdp *parsed_sdp = janus_sdp_preparse(handle, jsep_sdp, error_str, sizeof(error_str),
				(offer && !renegotiation ? &peer_dtls_role : NULL), &audio, &video, &data);
			if(parsed_sdp == NULL) {
				/* Invalid SDP */
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, error_str);
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			/* Notify event handlers */
			if(janus_events_is_enabled()) {
				janus_events_notify_handlers(JANUS_EVENT_TYPE_JSEP, JANUS_EVENT_SUBTYPE_NONE,
					session_id, handle_id, handle->opaque_id, "remote", jsep_type, jsep_sdp);
			}
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] There are %d audio, %d video and %d data m-lines\n",
				handle->handle_id, audio, video, data);
			/* We behave differently if it's a new session or an update... */
			if(!renegotiation) {
				/* New session */
				if(offer) {
					/* Check which DTLS role we should take */
					janus_dtls_role dtls_role = JANUS_DTLS_ROLE_CLIENT;
					if(peer_dtls_role == JANUS_DTLS_ROLE_CLIENT)
						dtls_role = JANUS_DTLS_ROLE_SERVER;
					/* Setup ICE locally (we received an offer) */
					if(janus_ice_setup_local(handle, offer, do_trickle, dtls_role) < 0) {
						JANUS_LOG(LOG_ERR, "Error setting ICE locally\n");
						janus_sdp_destroy(parsed_sdp);
						g_free(jsep_type);
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
						ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error setting ICE locally");
						janus_mutex_unlock(&handle->mutex);
						goto jsondone;
					}
				} else {
					/* Make sure we're waiting for an ANSWER in the first place */
					if(!handle->agent) {
						JANUS_LOG(LOG_ERR, "Unexpected ANSWER (did we offer?)\n");
						janus_sdp_destroy(parsed_sdp);
						g_free(jsep_type);
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
						ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNEXPECTED_ANSWER, "Unexpected ANSWER (did we offer?)");
						janus_mutex_unlock(&handle->mutex);
						goto jsondone;
					}
				}
				/* If for some reason the user is asking us to force using a relay, do that. Notice
				 * that this only works with libnice >= 0.1.14, and will cause the PeerConnection
				 * to fail if Janus itself is not configured to use a TURN server. Don't use this
				 * feature if you don't know what you're doing! You will almost always NOT want
				 * Janus itself to use TURN: https://janus.conf.meetecho.com/docs/FAQ.html#turn */
				if(json_is_true(json_object_get(jsep, "force_relay"))) {
					if(!janus_ice_is_force_relay_allowed()) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Forcing Janus to use a TURN server is not allowed\n", handle->handle_id);
					} else {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forcing Janus to use a TURN server\n", handle->handle_id);
						g_object_set(G_OBJECT(handle->agent), "force-relay", TRUE, NULL);
					}
				}
				/* Process the remote SDP */
				if(janus_sdp_process_remote(handle, parsed_sdp, rids_hml, FALSE) < 0) {
					JANUS_LOG(LOG_ERR, "Error processing SDP\n");
					janus_sdp_destroy(parsed_sdp);
					g_free(jsep_type);
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
					ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "Error processing SDP");
					janus_mutex_unlock(&handle->mutex);
					goto jsondone;
				}
				if(!offer) {
					/* Set remote candidates now (we received an answer) */
					if(do_trickle) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
					}
					janus_request_ice_handle_answer(handle, jsep_sdp);
					/* Check if the answer does contain the mid/abs-send-time/twcc extmaps */
					gboolean do_mid = FALSE, do_twcc = FALSE, do_dd = FALSE, do_abs_send_time = FALSE,
						do_abs_capture_time = FALSE, do_video_layers_alloc = FALSE;
					GList *temp = parsed_sdp->m_lines;
					while(temp) {
						janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
						gboolean have_mid = FALSE, have_twcc = FALSE, have_dd = FALSE,
							have_abs_send_time = FALSE, have_abs_capture_time = FALSE,
							have_video_layers_alloc = FALSE;
						GList *tempA = m->attributes;
						while(tempA) {
							janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
							if(a->name && a->value && !strcasecmp(a->name, "extmap")) {
								if(strstr(a->value, JANUS_RTP_EXTMAP_MID))
									have_mid = TRUE;
								else if(strstr(a->value, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
									have_twcc = TRUE;
								else if(strstr(a->value, JANUS_RTP_EXTMAP_DEPENDENCY_DESC))
									have_dd = TRUE;
								else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_SEND_TIME))
									have_abs_send_time = TRUE;
								else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME))
									have_abs_capture_time = TRUE;
								else if(strstr(a->value, JANUS_RTP_EXTMAP_VIDEO_LAYERS))
									have_video_layers_alloc = TRUE;
							}
							tempA = tempA->next;
						}
						do_mid = do_mid || have_mid;
						do_twcc = do_twcc || have_twcc;
						do_dd = do_dd || have_dd;
						do_abs_send_time = do_abs_send_time || have_abs_send_time;
						do_abs_capture_time = do_abs_capture_time || have_abs_capture_time;
						do_video_layers_alloc = do_video_layers_alloc || have_video_layers_alloc;
						temp = temp->next;
					}
					if(!do_mid && handle->pc)
						handle->pc->mid_ext_id = 0;
					if(!do_twcc && handle->pc) {
						handle->pc->do_transport_wide_cc = FALSE;
						handle->pc->transport_wide_cc_ext_id = 0;
					}
					if(!do_dd && handle->pc)
						handle->pc->dependencydesc_ext_id = 0;
					if(!do_abs_send_time && handle->pc)
						handle->pc->abs_send_time_ext_id = 0;
					if(!do_abs_capture_time && handle->pc)
						handle->pc->abs_capture_time_ext_id = 0;
					if(!do_video_layers_alloc && handle->pc)
						handle->pc->videolayers_ext_id = 0;
				} else {
					/* Check if the mid RTP extension is being negotiated */
					handle->pc->mid_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_MID);
					/* Check if the RTP Stream ID extension is being negotiated */
					handle->pc->rid_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_RID);
					handle->pc->ridrtx_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_REPAIRED_RID);
					/* Check if the audio level ID extension is being negotiated */
					handle->pc->audiolevel_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
					/* Check if the video orientation ID extension is being negotiated */
					handle->pc->videoorientation_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION);
					/* Check if the playout delay ID extension is being negotiated */
					handle->pc->playoutdelay_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_PLAYOUT_DELAY);
					/* Check if the abs-send-time ID extension is being negotiated */
					handle->pc->abs_send_time_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_ABS_SEND_TIME);
					/* Check if the abs-capture-time ID extension is being negotiated */
					handle->pc->abs_capture_time_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME);
					/* Check if the video-layers-allocation ID extension is being negotiated */
					handle->pc->videolayers_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_VIDEO_LAYERS);
					/* Check if transport wide CC is supported */
					int transport_wide_cc_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC);
					handle->pc->do_transport_wide_cc = transport_wide_cc_ext_id > 0 ? TRUE : FALSE;
					handle->pc->transport_wide_cc_ext_id = transport_wide_cc_ext_id;
					/* Check if the dependency descriptor ID extension is being negotiated */
					handle->pc->dependencydesc_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_DEPENDENCY_DESC);
				}
			} else {
				/* FIXME This is a renegotiation: we can currently only handle simple changes in media
				 * direction and ICE restarts: anything more complex than that will result in an error */
				JANUS_LOG(LOG_INFO, "[%"SCNu64"] Negotiation update, checking what changed...\n", handle->handle_id);
				if(janus_sdp_process_remote(handle, parsed_sdp, rids_hml, TRUE) < 0) {
					JANUS_LOG(LOG_ERR, "Error processing SDP\n");
					janus_sdp_destroy(parsed_sdp);
					g_free(jsep_type);
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
					ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNEXPECTED_ANSWER, "Error processing SDP");
					janus_mutex_unlock(&handle->mutex);
					goto jsondone;
				}
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART)) {
					JANUS_LOG(LOG_INFO, "[%"SCNu64"] Restarting ICE...\n", handle->handle_id);
					/* FIXME We only need to do that for offers: if it's an answer, we did that already */
					if(offer) {
						janus_ice_restart(handle);
					} else {
						janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
					}
					/* Update remote credentials for ICE */
					if(handle->pc) {
						nice_agent_set_remote_credentials(handle->agent, handle->pc->stream_id,
							handle->pc->ruser, handle->pc->rpass);
					}
					/* If we're full-trickling, we'll need to resend the candidates later */
					if(janus_ice_is_full_trickle_enabled()) {
						janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);
					}
				}
#ifdef HAVE_SCTP
				if(!offer) {
					/* Were datachannels just added? */
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
						janus_ice_peerconnection *pc = handle->pc;
						if(pc != NULL && pc->dtls != NULL && pc->dtls->sctp == NULL) {
							/* Create SCTP association as well */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating datachannels...\n", handle->handle_id);
							janus_dtls_srtp_create_sctp(pc->dtls);
						}
					}
				}
#endif
				/* Check if renegotiating has added new RTP extensions */
				if(offer) {
					/* Check if the mid RTP extension is being negotiated */
					handle->pc->mid_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_MID);
					/* Check if the RTP Stream ID extension is being negotiated */
					handle->pc->rid_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_RID);
					handle->pc->ridrtx_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_REPAIRED_RID);
					/* Check if the audio level ID extension is being negotiated */
					handle->pc->audiolevel_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_AUDIO_LEVEL);
					/* Check if the video orientation ID extension is being negotiated */
					handle->pc->videoorientation_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION);
					/* Check if the playout delay ID extension is being negotiated */
					handle->pc->playoutdelay_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_PLAYOUT_DELAY);
					/* Check if the abs-send-time ID extension is being negotiated */
					handle->pc->abs_send_time_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_ABS_SEND_TIME);
					/* Check if the abs-capture-time ID extension is being negotiated */
					handle->pc->abs_capture_time_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME);
					/* Check if the video-layers-alloc ID extension is being negotiated */
					handle->pc->videolayers_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_VIDEO_LAYERS);
					/* Check if transport wide CC is supported */
					int transport_wide_cc_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC);
					handle->pc->do_transport_wide_cc = transport_wide_cc_ext_id > 0 ? TRUE : FALSE;
					handle->pc->transport_wide_cc_ext_id = transport_wide_cc_ext_id;
					/* Check if the dependency descriptor ID extension is being negotiated */
					handle->pc->dependencydesc_ext_id = janus_rtp_header_extension_get_id(jsep_sdp, JANUS_RTP_EXTMAP_DEPENDENCY_DESC);
				}
			}
			char *tmp = handle->remote_sdp;
			handle->remote_sdp = g_strdup(jsep_sdp);
			g_free(tmp);
			janus_mutex_unlock(&handle->mutex);
			/* Anonymize SDP */
			if(janus_sdp_anonymize(parsed_sdp) < 0) {
				/* Invalid SDP */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_JSEP_INVALID_SDP, "JSEP error: invalid SDP");
				janus_sdp_destroy(parsed_sdp);
				g_free(jsep_type);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			jsep_sdp_stripped = janus_sdp_write(parsed_sdp);
			janus_sdp_destroy(parsed_sdp);
			sdp = NULL;
			if(e2ee)
				janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
			janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
		}

		/* Make sure the app handle is still valid */
		if(handle->app == NULL || !janus_plugin_session_is_alive(handle->app_handle)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this message");
			if(jsep_sdp_stripped != NULL)
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
			g_free(jsep_type);
			g_free(jsep_sdp_stripped);
			goto jsondone;
		}

		/* Send the message to the plugin (which must eventually free transaction_text and unref the two objects, body and jsep) */
		json_incref(body);
		json_t *body_jsep = NULL;
		if(jsep_sdp_stripped) {
			body_jsep = json_pack("{ssss}", "type", jsep_type, "sdp", jsep_sdp_stripped);
			/* Check if simulcasting is enabled in one of the media streams */
			janus_mutex_lock(&handle->mutex);
			if(handle->pc == NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_WEBRTC_STATE, "Invalid PeerConnection");
				json_decref(body);
				json_decref(body_jsep);
				g_free(jsep_type);
				g_free(jsep_sdp_stripped);
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			json_t *simulcast = NULL;
			janus_ice_peerconnection_medium *medium = NULL;
			uint mi=0;
			for(mi=0; mi<g_hash_table_size(handle->pc->media); mi++) {
				medium = g_hash_table_lookup(handle->pc->media, GUINT_TO_POINTER(mi));
				if(medium && (medium->ssrc_peer[1] || medium->rid[0])) {
					if(simulcast == NULL)
						simulcast = json_array();
					json_t *msc = json_object();
					json_object_set_new(msc, "mindex", json_integer(medium->mindex));
					if(medium->mid != NULL)
						json_object_set_new(msc, "mid", json_string(medium->mid));
					/* If we have rids, pass those, otherwise pass the SSRCs */
					if(medium->rid[0]) {
						json_t *rids = json_array();
						if(medium->rid[2])
							json_array_append_new(rids, json_string(medium->rid[2]));
						if(medium->rid[1])
							json_array_append_new(rids, json_string(medium->rid[1]));
						json_array_append_new(rids, json_string(medium->rid[0]));
						json_object_set_new(msc, "rids", rids);
						if(medium->pc && medium->pc->rid_ext_id > 0)
							json_object_set_new(msc, "rid-ext", json_integer(medium->pc->rid_ext_id));
					} else {
						json_t *ssrcs = json_array();
						json_array_append_new(ssrcs, json_integer(medium->ssrc_peer[0]));
						if(medium->ssrc_peer[1])
							json_array_append_new(ssrcs, json_integer(medium->ssrc_peer[1]));
						if(medium->ssrc_peer[2])
							json_array_append_new(ssrcs, json_integer(medium->ssrc_peer[2]));
						json_object_set_new(msc, "ssrcs", ssrcs);
					}
					json_array_append_new(simulcast, msc);
				}
			}
			janus_mutex_unlock(&handle->mutex);
			if(simulcast)
				json_object_set_new(body_jsep, "simulcast", simulcast);
			json_t *svc = json_object_get(jsep, "svc");
			if(svc) {
				json_incref(svc);
				json_object_set_new(body_jsep, "svc", svc);
			}
			/* Check if this is a renegotiation or update */
			if(renegotiation)
				json_object_set_new(body_jsep, "update", json_true());
			/* If media is encrypted end-to-end, the plugin may need to know */
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE))
				json_object_set_new(body_jsep, "e2ee", json_true());
		}
		janus_plugin_result *result = plugin_t->handle_message(handle->app_handle,
			g_strdup((char *)transaction_text), body, body_jsep);
		g_free(jsep_type);
		g_free(jsep_sdp_stripped);
		if(result == NULL) {
			/* Something went horribly wrong! */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "Plugin didn't give a result");
			if(body_jsep != NULL)
				janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
			goto jsondone;
		}
		if(result->type == JANUS_PLUGIN_OK) {
			/* The plugin gave a result already (synchronous request/response) */
			if(result->content == NULL || !json_is_object(result->content)) {
				/* Missing content, or not a JSON object */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE,
					result->content == NULL ?
						"Plugin didn't provide any content for this synchronous response" :
						"Plugin returned an invalid JSON response");
				janus_plugin_result_destroy(result);
				if(body_jsep != NULL)
					janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
				goto jsondone;
			}
			/* Reference the content, as destroying the result instance will decref it */
			json_incref(result->content);
			/* Prepare JSON response */
			json_t *reply = janus_create_message("success", session->session_id, transaction_text);
			json_object_set_new(reply, "sender", json_integer(handle->handle_id));
			if(janus_is_opaqueid_in_api_enabled() && handle->opaque_id != NULL)
				json_object_set_new(reply, "opaque_id", json_string(handle->opaque_id));
			json_t *plugin_data = json_object();
			json_object_set_new(plugin_data, "plugin", json_string(plugin_t->get_package()));
			json_object_set_new(plugin_data, "data", result->content);
			json_object_set_new(reply, "plugindata", plugin_data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
		} else if(result->type == JANUS_PLUGIN_OK_WAIT) {
			/* The plugin received the request but didn't process it yet, send an ack (asynchronous notifications may follow) */
			json_t *reply = janus_create_message("ack", session_id, transaction_text);
			if(result->text)
				json_object_set_new(reply, "hint", json_string(result->text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
		} else {
			/* Something went horribly wrong! */
			ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE,
				(char *)(result->text ? result->text : "Plugin returned a severe (unknown) error"));
			janus_plugin_result_destroy(result);
			goto jsondone;
		}
		janus_plugin_result_destroy(result);
	} else if(!strcasecmp(message_text, "trickle")) {
		if(handle == NULL) {
			/* Trickle is an handle-level command */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		if(handle->app == NULL || !janus_plugin_session_is_alive(handle->app_handle)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_MESSAGE, "No plugin to handle this trickle candidate");
			goto jsondone;
		}
		json_t *candidate = json_object_get(root, "candidate");
		json_t *candidates = json_object_get(root, "candidates");
		if(candidate == NULL && candidates == NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_MISSING_MANDATORY_ELEMENT, "Missing mandatory element (candidate|candidates)");
			goto jsondone;
		}
		if(candidate != NULL && candidates != NULL) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_JSON, "Can't have both candidate and candidates");
			goto jsondone;
		}
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Received a trickle, but still cleaning a previous session\n", handle->handle_id);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_WEBRTC_STATE, "Still cleaning a previous session");
			goto jsondone;
		}
		janus_mutex_lock(&handle->mutex);
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)) {
			/* It looks like this peer supports Trickle, after all */
			JANUS_LOG(LOG_VERB, "Handle %"SCNu64" supports trickle even if it didn't negotiate it...\n", handle->handle_id);
			janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
		}
		/* Is there any stream ready? this trickle may get here before the SDP it relates to */
		if(handle->pc == NULL) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] No stream, queueing this trickle as it got here before the SDP...\n", handle->handle_id);
			/* Enqueue this trickle candidate(s), we'll process this later */
			janus_ice_trickle *early_trickle = janus_ice_trickle_new(transaction_text, candidate ? candidate : candidates);
			handle->pending_trickles = g_list_append(handle->pending_trickles, early_trickle);
			/* Send the ack right away, an event will tell the application if the candidate(s) failed */
			goto trickledone;
		}
		/* Is the ICE stack ready already? */
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER) ||
				!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER) ||
				!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER)) {
			const char *cause = NULL;
			if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER))
				cause = "processing the offer";
			else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER))
				cause = "waiting for the answer";
			else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER))
				cause = "waiting for the offer";
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still %s, queueing this trickle to wait until we're done there...\n",
				handle->handle_id, cause);
			/* Enqueue this trickle candidate(s), we'll process this later */
			janus_ice_trickle *early_trickle = janus_ice_trickle_new(transaction_text, candidate ? candidate : candidates);
			handle->pending_trickles = g_list_append(handle->pending_trickles, early_trickle);
			/* Send the ack right away, an event will tell the application if the candidate(s) failed */
			goto trickledone;
		}
		if(candidate != NULL) {
			/* We got a single candidate */
			int error = 0;
			const char *error_string = NULL;
			if((error = janus_ice_trickle_parse(handle, candidate, &error_string)) != 0) {
				ret = janus_process_error(request, session_id, transaction_text, error, "%s", error_string);
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
		} else {
			/* We got multiple candidates in an array */
			if(!json_is_array(candidates)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "candidates is not an array");
				janus_mutex_unlock(&handle->mutex);
				goto jsondone;
			}
			JANUS_LOG(LOG_VERB, "Got multiple candidates (%zu)\n", json_array_size(candidates));
			if(json_array_size(candidates) > 0) {
				/* Handle remote candidates */
				size_t i = 0;
				for(i=0; i<json_array_size(candidates); i++) {
					json_t *c = json_array_get(candidates, i);
					/* FIXME We don't care if any trickle fails to parse */
					janus_ice_trickle_parse(handle, c, NULL);
				}
			}
		}

trickledone:
		janus_mutex_unlock(&handle->mutex);
		/* We reply right away, not to block the web server... */
		json_t *reply = janus_create_message("ack", session_id, transaction_text);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
	} else {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN_REQUEST, "Unknown request '%s'", message_text);
	}

jsondone:
	/* Done processing */
	if(handle != NULL)
		janus_refcount_decrease(&handle->ref);
	if(session != NULL)
		janus_refcount_decrease(&session->ref);
	return ret;
}

static json_t *janus_json_token_plugin_array(const char *token_value) {
	json_t *plugins_list = json_array();
	GList *plugins = janus_auth_list_plugins(token_value);
	if(plugins != NULL) {
		GList *tmp = plugins;
		while(tmp) {
			janus_plugin *p = (janus_plugin *)tmp->data;
			if(p != NULL)
				json_array_append_new(plugins_list, json_string(p->get_package()));
			tmp = tmp->next;
		}
		g_list_free(plugins);
		plugins = NULL;
	}
	return plugins_list;
}

static json_t *janus_json_list_token_plugins(const char *token_value, const gchar *transaction_text) {
	json_t *plugins_list = janus_json_token_plugin_array(token_value);
	/* Prepare JSON reply */
	json_t *reply = janus_create_message("success", 0, transaction_text);
	json_t *data = json_object();
	json_object_set_new(data, "plugins", plugins_list);
	json_object_set_new(reply, "data", data);
	return reply;
}

static int janus_request_allow_token(janus_request *request, guint64 session_id, const gchar *transaction_text, gboolean allow, gboolean add) {
	/* Allow/disallow a valid token valid to access a plugin */
	int ret = -1;
	int error_code = 0;
	char error_cause[100];
	json_t *root = request->message;
	if(!janus_auth_is_stored_mode()) {
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Stored-Token based authentication disabled");
		goto jsondone;
	}
	JANUS_VALIDATE_JSON_OBJECT(root, add_token_parameters,
		error_code, error_cause, FALSE,
		JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
	/* Any plugin this token should be limited to? */
	json_t *allowed = json_object_get(root, "plugins");
	if(error_code == 0 && !add && (!allowed || json_array_size(allowed) == 0)) {
		error_code = JANUS_ERROR_INVALID_ELEMENT_TYPE;
		g_strlcpy(error_cause, "Invalid element type (plugins should be a non-empty array)", sizeof(error_cause));
	}
	if(error_code != 0) {
		ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
		goto jsondone;
	}
	json_t *token = json_object_get(root, "token");
	const char *token_value = json_string_value(token);
	if(add) {
		/* First of all, add the new token */
		if(!janus_auth_add_token(token_value)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error adding token");
			goto jsondone;
		}
	} else {
		/* Check if the token is valid, first */
		if(!janus_auth_check_token(token_value)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_TOKEN_NOT_FOUND, "Token %s not found", token_value);
			goto jsondone;
		}
	}
	if(allowed && json_array_size(allowed) > 0) {
		/* Specify which plugins this token has access to */
		size_t i = 0;
		gboolean ok = TRUE;
		for(i=0; i<json_array_size(allowed); i++) {
			json_t *p = json_array_get(allowed, i);
			if(!p || !json_is_string(p)) {
				/* FIXME Should we fail here? */
				if(add){
					JANUS_LOG(LOG_WARN, "Invalid plugin passed to the new token request, skipping...\n");
					continue;
				} else {
					JANUS_LOG(LOG_ERR, "Invalid plugin passed to the new token request...\n");
					ok = FALSE;
					break;
				}
			}
			const gchar *plugin_text = json_string_value(p);
			janus_plugin *plugin_t = janus_plugin_find(plugin_text);
			if(plugin_t == NULL) {
				/* FIXME Should we fail here? */
				if(add) {
					JANUS_LOG(LOG_WARN, "No such plugin '%s' passed to the new token request, skipping...\n", plugin_text);
					continue;
				} else {
					JANUS_LOG(LOG_ERR, "No such plugin '%s' passed to the new token request...\n", plugin_text);
					ok = FALSE;
				}
				break;
			}
		}
		if(!ok) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (some of the provided plugins are invalid)");
			goto jsondone;
		}
		/* Take care of the plugins access limitations */
		i = 0;
		for(i=0; i<json_array_size(allowed); i++) {
			json_t *p = json_array_get(allowed, i);
			const gchar *plugin_text = json_string_value(p);
			janus_plugin *plugin_t = janus_plugin_find(plugin_text);
			if(!(allow ? janus_auth_allow_plugin(token_value, plugin_t) : janus_auth_disallow_plugin(token_value, plugin_t))) {
				/* FIXME Should we notify individual failures? */
				JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_text);
			}
		}
	} else {
		/* No plugin limitation specified, allow all plugins */
		if(plugins && g_hash_table_size(plugins) > 0) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, plugins);
			while (g_hash_table_iter_next(&iter, NULL, &value)) {
				janus_plugin *plugin_t = value;
				if(plugin_t == NULL)
					continue;
				if(!janus_auth_allow_plugin(token_value, plugin_t)) {
					JANUS_LOG(LOG_WARN, "Error allowing access to '%s' to the new token, bad things may happen...\n", plugin_t->get_package());
				}
			}
		}
	}
	/* Get the list of plugins this new token can now access */
	json_t *reply = janus_json_list_token_plugins(token_value, transaction_text);
	/* Send the success reply */
	ret = janus_process_success(request, reply);
jsondone:
	return ret;
}

/* Admin/monitor WebServer requests handler */
int janus_process_incoming_admin_request(janus_request *request) {
	int ret = -1;
	int error_code = 0;
	char error_cause[100];
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request or payload to process, giving up...\n");
		return ret;
	}
	json_t *root = request->message;
	/* Ok, let's start with the ids */
	guint64 session_id = 0, handle_id = 0;
	json_t *s = json_object_get(root, "session_id");
	if(s && json_is_integer(s))
		session_id = json_integer_value(s);
	json_t *h = json_object_get(root, "handle_id");
	if(h && json_is_integer(h))
		handle_id = json_integer_value(h);

	janus_session *session = NULL;
	janus_ice_handle *handle = NULL;

	/* Get transaction and message request */
	JANUS_VALIDATE_JSON_OBJECT(root, admin_parameters,
		error_code, error_cause, FALSE,
		JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
	if(error_code != 0) {
		ret = janus_process_error_string(request, session_id, NULL, error_code, error_cause);
		goto jsondone;
	}
	json_t *transaction = json_object_get(root, "transaction");
	const gchar *transaction_text = json_string_value(transaction);
	json_t *message = json_object_get(root, "janus");
	const gchar *message_text = json_string_value(message);

	if(session_id == 0 && handle_id == 0) {
		/* Can only be a 'Get all sessions' or some general setting manipulation request */
		if(!strcasecmp(message_text, "info")) {
			/* The generic info request */
			ret = janus_process_success(request, janus_info(transaction_text));
			goto jsondone;
		}
		if(!strcasecmp(message_text, "ping")) {
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("pong", 0, transaction_text);
			ret = janus_process_success(request, reply);
			goto jsondone;
		}
		if(admin_api_secret != NULL) {
			/* There's an admin/monitor secret, check that the client provided it */
			json_t *secret = json_object_get(root, "admin_secret");
			if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_api_secret)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
				goto jsondone;
			}
		}
		if(!strcasecmp(message_text, "get_status")) {
			/* Return some info on the settings (mostly debug-related, at the moment) */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_t *status = json_object();
			json_object_set_new(status, "token_auth", janus_auth_is_enabled() ? json_true() : json_false());
			json_object_set_new(status, "session_timeout", json_integer(global_session_timeout));
			json_object_set_new(status, "reclaim_session_timeout", json_integer(reclaim_session_timeout));
			json_object_set_new(status, "candidates_timeout", json_integer(candidates_timeout));
			json_object_set_new(status, "log_level", json_integer(janus_log_level));
			json_object_set_new(status, "log_timestamps", janus_log_timestamps ? json_true() : json_false());
			json_object_set_new(status, "log_colors", janus_log_colors ? json_true() : json_false());
			json_object_set_new(status, "log_rotate_sig", json_integer(janus_log_rotate_sig));
			json_object_set_new(status, "locking_debug", lock_debug ? json_true() : json_false());
			json_object_set_new(status, "refcount_debug", refcount_debug ? json_true() : json_false());
			json_object_set_new(status, "min_nack_queue", json_integer(janus_get_min_nack_queue()));
			json_object_set_new(status, "nack-optimizations", janus_is_nack_optimizations_enabled() ? json_true() : json_false());
			json_object_set_new(status, "no_media_timer", json_integer(janus_get_no_media_timer()));
			json_object_set_new(status, "slowlink_threshold", json_integer(janus_get_slowlink_threshold()));
			json_object_set_new(reply, "status", status);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_session_timeout")) {
			JANUS_VALIDATE_JSON_OBJECT(root, timeout_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *timeout = json_object_get(root, "timeout");
			int timeout_num = json_integer_value(timeout);
			if(timeout_num < 0) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (timeout should be a positive integer)");
				goto jsondone;
			}

			/* Set global session timeout */
			global_session_timeout = timeout_num;

			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "timeout", json_integer(timeout_num));

			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_level")) {
			/* Change the debug logging level */
			JANUS_VALIDATE_JSON_OBJECT(root, level_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *level = json_object_get(root, "level");
			int level_num = json_integer_value(level);
			if(level_num < LOG_NONE || level_num > LOG_MAX) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (level should be between %d and %d)", LOG_NONE, LOG_MAX);
				goto jsondone;
			}
			janus_log_level = level_num;
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "level", json_integer(janus_log_level));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_locking_debug")) {
			/* Enable/disable the locking debug (would show a message on the console for every lock attempt) */
			JANUS_VALIDATE_JSON_OBJECT(root, debug_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *debug = json_object_get(root, "debug");
			lock_debug = json_is_true(debug);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "locking_debug", lock_debug ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_refcount_debug")) {
			/* Enable/disable the reference counter debug (would show a message on the console for every increase/decrease) */
			JANUS_VALIDATE_JSON_OBJECT(root, debug_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *debug = json_object_get(root, "debug");
			if(json_is_true(debug)) {
				refcount_debug = TRUE;
			} else {
				refcount_debug = FALSE;
			}
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "refcount_debug", refcount_debug ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_timestamps")) {
			/* Enable/disable the log timestamps */
			JANUS_VALIDATE_JSON_OBJECT(root, timestamps_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *timestamps = json_object_get(root, "timestamps");
			janus_log_timestamps = json_is_true(timestamps);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "log_timestamps", janus_log_timestamps ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_log_colors")) {
			/* Enable/disable the log colors */
			JANUS_VALIDATE_JSON_OBJECT(root, colors_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *colors = json_object_get(root, "colors");
			janus_log_colors = json_is_true(colors);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "log_colors", janus_log_colors ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_min_nack_queue")) {
			/* Change the current value for the min NACK queue */
			JANUS_VALIDATE_JSON_OBJECT(root, mnq_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *mnq = json_object_get(root, "min_nack_queue");
			int mnq_num = json_integer_value(mnq);
			janus_set_min_nack_queue(mnq_num);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "min_nack_queue", json_integer(janus_get_min_nack_queue()));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_nack_optimizations")) {
			/* Enable/disable NACK optimizations */
			JANUS_VALIDATE_JSON_OBJECT(root, nopt_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			gboolean optimize = json_is_true(json_object_get(root, "nack_optimizations"));
			janus_set_nack_optimizations_enabled(optimize);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "nack-optimizations", janus_is_nack_optimizations_enabled() ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_no_media_timer")) {
			/* Change the current value for the no-media timer */
			JANUS_VALIDATE_JSON_OBJECT(root, nmt_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *nmt = json_object_get(root, "no_media_timer");
			int nmt_num = json_integer_value(nmt);
			janus_set_no_media_timer(nmt_num);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "no_media_timer", json_integer(janus_get_no_media_timer()));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "set_slowlink_threshold")) {
			/* Change the current value for the slowlink-threshold value */
			JANUS_VALIDATE_JSON_OBJECT(root, st_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *nmt = json_object_get(root, "slowlink_threshold");
			int nmt_num = json_integer_value(nmt);
			janus_set_slowlink_threshold(nmt_num);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "slowlink_threshold", json_integer(janus_get_slowlink_threshold()));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "accept_new_sessions")) {
			/* Configure whether we should accept new incoming sessions or not:
			 * this can be particularly useful whenever, e.g., we want to stop
			 * accepting new sessions because we're draining this server */
			JANUS_VALIDATE_JSON_OBJECT(root, ans_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *accept = json_object_get(root, "accept");
			accept_new_sessions = json_is_true(accept);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "accept", accept_new_sessions ? json_true() : json_false());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "message_plugin")) {
			/* Contact a plugin and expect a response */
			JANUS_VALIDATE_JSON_OBJECT(root, messageplugin_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *plugin = json_object_get(root, "plugin");
			const char *plugin_value = json_string_value(plugin);
			janus_plugin *p = janus_plugin_find(plugin_value);
			if(p == NULL) {
				/* No such handler... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Invalid plugin");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, error_cause);
				goto jsondone;
			}
			if(p->handle_admin_message == NULL) {
				/* Handler doesn't implement the hook... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Plugin doesn't support Admin API messages");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, error_cause);
				goto jsondone;
			}
			json_t *query = json_object_get(root, "request");
			json_t *response = p->handle_admin_message(query);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "response", response ? response : json_object());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "query_transport")) {
			/* Contact a transport and expect a response */
			JANUS_VALIDATE_JSON_OBJECT(root, querytransport_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *transport = json_object_get(root, "transport");
			const char *transport_value = json_string_value(transport);
			janus_transport *t = g_hash_table_lookup(transports, transport_value);
			if(t == NULL) {
				/* No such transport... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Invalid transport");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, error_cause);
				goto jsondone;
			}
			if(t->query_transport == NULL) {
				/* Transport doesn't implement the hook... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Transport plugin doesn't support queries");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, error_cause);
				goto jsondone;
			}
			json_t *query = json_object_get(root, "request");
			json_t *response = t->query_transport(query);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "response", response ? response : json_object());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "query_eventhandler")) {
			/* Contact an event handler and expect a response */
			JANUS_VALIDATE_JSON_OBJECT(root, queryhandler_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *handler = json_object_get(root, "handler");
			const char *handler_value = json_string_value(handler);
			janus_eventhandler *evh = g_hash_table_lookup(eventhandlers, handler_value);
			if(evh == NULL) {
				/* No such handler... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Invalid event handler");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, error_cause);
				goto jsondone;
			}
			if(evh->handle_request == NULL) {
				/* Handler doesn't implement the hook... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Event handler doesn't support queries");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, error_cause);
				goto jsondone;
			}
			json_t *query = json_object_get(root, "request");
			json_t *response = evh->handle_request(query);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "response", response ? response : json_object());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "query_logger")) {
			/* Contact a logger and expect a response */
			JANUS_VALIDATE_JSON_OBJECT(root, querylogger_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *logger = json_object_get(root, "logger");
			const char *logger_value = json_string_value(logger);
			janus_logger *l = g_hash_table_lookup(loggers, logger_value);
			if(l == NULL) {
				/* No such handler... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Invalid logger");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_NOT_FOUND, error_cause);
				goto jsondone;
			}
			if(l->handle_request == NULL) {
				/* Handler doesn't implement the hook... */
				g_snprintf(error_cause, sizeof(error_cause), "%s", "Logger doesn't support queries");
				ret = janus_process_error_string(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, error_cause);
				goto jsondone;
			}
			json_t *query = json_object_get(root, "request");
			json_t *response = l->handle_request(query);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "response", response ? response : json_object());
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "custom_event")) {
			/* Enqueue a custom "external" event to notify via event handlers */
			JANUS_VALIDATE_JSON_OBJECT(root, customevent_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *schema = json_object_get(root, "schema");
			const char *schema_value = json_string_value(schema);
			json_t *data = json_object_get(root, "data");
			if(janus_events_is_enabled()) {
				json_incref(data);
				janus_events_notify_handlers(JANUS_EVENT_TYPE_EXTERNAL, JANUS_EVENT_SUBTYPE_NONE,
					0, schema_value, data);
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "custom_logline")) {
			/* Print something custom on the logs, using the specified debug level */
			JANUS_VALIDATE_JSON_OBJECT(root, customlogline_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *line = json_object_get(root, "line");
			const char *log_line = json_string_value(line);
			json_t *level = json_object_get(root, "level");
			int log_level = LOG_INFO;
			if(level) {
				log_level = json_integer_value(level);
				if(log_level < LOG_NONE || log_level > LOG_MAX)
					log_level = LOG_INFO;
			}
			/* Print the log line on the log */
			JANUS_LOG(log_level, "%s\n", log_line);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "list_sessions")) {
			/* List sessions */
			session_id = 0;
			json_t *list = json_array();
			if(sessions != NULL && g_hash_table_size(sessions) > 0) {
				janus_mutex_lock(&sessions_mutex);
				GHashTableIter iter;
				gpointer value;
				g_hash_table_iter_init(&iter, sessions);
				while (g_hash_table_iter_next(&iter, NULL, &value)) {
					janus_session *session = value;
					if(session == NULL) {
						continue;
					}
					json_array_append_new(list, json_integer(session->session_id));
				}
				janus_mutex_unlock(&sessions_mutex);
			}
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "sessions", list);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "add_token")) {
			/* Add a token valid for authentication */
			ret = janus_request_allow_token(request, session_id, transaction_text, TRUE, TRUE);
			goto jsondone;
		} else if(!strcasecmp(message_text, "list_tokens")) {
			/* List all the valid tokens */
			if(!janus_auth_is_stored_mode()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Stored-Token based authentication disabled");
				goto jsondone;
			}
			json_t *tokens_list = json_array();
			GList *list = janus_auth_list_tokens();
			if(list != NULL) {
				GList *tmp = list;
				while(tmp) {
					char *token = (char *)tmp->data;
					if(token != NULL) {
						json_t *plugins_list = janus_json_token_plugin_array(token);
						if(json_array_size(plugins_list) > 0) {
							json_t *t = json_object();
							json_object_set_new(t, "token", json_string(token));
							json_object_set_new(t, "allowed_plugins", plugins_list);
							json_array_append_new(tokens_list, t);
						}
						else
							json_decref(plugins_list);
						tmp->data = NULL;
						g_free(token);
					}
					tmp = tmp->next;
				}
				g_list_free(list);
			}
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_t *data = json_object();
			json_object_set_new(data, "tokens", tokens_list);
			json_object_set_new(reply, "data", data);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "allow_token")) {
			/* Allow a valid token valid to access a plugin */
			ret = janus_request_allow_token(request, session_id, transaction_text, TRUE, FALSE);
			goto jsondone;
		} else if(!strcasecmp(message_text, "disallow_token")) {
			/* Disallow a valid token valid from accessing a plugin */
			ret = janus_request_allow_token(request, session_id, transaction_text, FALSE, FALSE);
			goto jsondone;
		} else if(!strcasecmp(message_text, "remove_token")) {
			/* Invalidate a token for authentication purposes */
			if(!janus_auth_is_stored_mode()) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Stored-Token based authentication disabled");
				goto jsondone;
			}
			JANUS_VALIDATE_JSON_OBJECT(root, token_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			json_t *token = json_object_get(root, "token");
			const char *token_value = json_string_value(token);
			if(!janus_auth_remove_token(token_value)) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN, "Error removing token");
				goto jsondone;
			}
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "resolve_address")) {
			/* Helper method to evaluate whether this instance can resolve an address, and how soon */
			JANUS_VALIDATE_JSON_OBJECT(root, resaddr_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			const char *address = json_string_value(json_object_get(root, "address"));
			/* Resolve the address */
			gint64 start = janus_get_monotonic_time();
			struct addrinfo *res = NULL;
			janus_network_address addr;
			janus_network_address_string_buffer addr_buf;
			if(getaddrinfo(address, NULL, NULL, &res) != 0 ||
					janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
					janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
				JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", address);
				if(res)
					freeaddrinfo(res);
				ret = janus_process_error_string(request, session_id, transaction_text,
					JANUS_ERROR_UNKNOWN, (char *)"Could not resolve address");
				goto jsondone;
			}
			gint64 end = janus_get_monotonic_time();
			freeaddrinfo(res);
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "ip", json_string(janus_network_address_string_from_buffer(&addr_buf)));
			json_object_set_new(reply, "elapsed", json_integer(end-start));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "test_stun")) {
			/* Helper method to evaluate whether this instance can use STUN with a specific server */
			JANUS_VALIDATE_JSON_OBJECT(root, teststun_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			const char *address = json_string_value(json_object_get(root, "address"));
			uint16_t port = json_integer_value(json_object_get(root, "port"));
			uint16_t local_port = json_integer_value(json_object_get(root, "localport"));
			/* Resolve the address */
			gint64 start = janus_get_monotonic_time();
			struct addrinfo *res = NULL;
			janus_network_address addr;
			janus_network_address_string_buffer addr_buf;
			if(getaddrinfo(address, NULL, NULL, &res) != 0 ||
					janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
					janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
				JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", address);
				if(res)
					freeaddrinfo(res);
				ret = janus_process_error_string(request, session_id, transaction_text,
					JANUS_ERROR_UNKNOWN, (char *)"Could not resolve address");
				goto jsondone;
			}
			freeaddrinfo(res);
			/* Test the STUN server */
			janus_network_address public_addr = { 0 };
			uint16_t public_port = 0;
			if(janus_ice_test_stun_server(&addr, port, local_port, &public_addr, &public_port) < 0) {
				ret = janus_process_error_string(request, session_id, transaction_text,
					JANUS_ERROR_UNKNOWN, (char *)"STUN request failed");
				goto jsondone;
			}
			if(janus_network_address_to_string_buffer(&public_addr, &addr_buf) != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text,
					JANUS_ERROR_UNKNOWN, (char *)"Could not resolve public address");
				goto jsondone;
			}
			const char *public_ip_addr = janus_network_address_string_from_buffer(&addr_buf);
			gint64 end = janus_get_monotonic_time();
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "public_ip", json_string(public_ip_addr));
			json_object_set_new(reply, "public_port", json_integer(public_port));
			json_object_set_new(reply, "elapsed", json_integer(end-start));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "loops_info")) {
			/* Query the Janus core to see how many handles each static loop is
			 * handling: will return an empty list if static loops are disabled */
			json_t *list = janus_ice_static_event_loops_info();
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", 0, transaction_text);
			json_object_set_new(reply, "loops", list);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else {
			/* No message we know of */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
	}
	if(session_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid session\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}
	if(h && handle_id < 1) {
		JANUS_LOG(LOG_ERR, "Invalid handle\n");
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, NULL);
		goto jsondone;
	}

	/* Go on with the processing */
	if(admin_api_secret != NULL) {
		/* There's an API secret, check that the client provided it */
		json_t *secret = json_object_get(root, "admin_secret");
		if(!secret || !json_is_string(secret) || !janus_strcmp_const_time(json_string_value(secret), admin_api_secret)) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNAUTHORIZED, NULL);
			goto jsondone;
		}
	}

	/* If we got here, make sure we have a session (and/or a handle) */
	session = janus_session_find(session_id);
	if(!session) {
		JANUS_LOG(LOG_ERR, "Couldn't find any session %"SCNu64"...\n", session_id);
		ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_SESSION_NOT_FOUND, "No such session %"SCNu64"", session_id);
		goto jsondone;
	}
	handle = NULL;
	if(handle_id > 0) {
		handle = janus_session_handles_find(session, handle_id);
		if(!handle) {
			JANUS_LOG(LOG_ERR, "Couldn't find any handle %"SCNu64" in session %"SCNu64"...\n", handle_id, session_id);
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_HANDLE_NOT_FOUND, "No such handle %"SCNu64" in session %"SCNu64"", handle_id, session_id);
			goto jsondone;
		}
	}

	/* What is this? */
	if(handle == NULL) {
		/* Session-related */
		if(!strcasecmp(message_text, "destroy_session")) {
			janus_mutex_lock(&sessions_mutex);
			if(g_hash_table_remove(sessions, &session->session_id))
				g_atomic_int_dec_and_test(&sessions_num);
			janus_mutex_unlock(&sessions_mutex);
			/* Notify the source that the session has been destroyed */
			janus_request *source = janus_session_get_request(session);
			if(source && source->transport)
				source->transport->session_over(source->instance, session->session_id, FALSE, FALSE);
			janus_request_unref(source);
			/* Schedule the session for deletion */
			janus_session_destroy(session);

			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", session_id, transaction_text);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			/* Notify event handlers as well */
			if(janus_events_is_enabled())
				janus_events_notify_handlers(JANUS_EVENT_TYPE_SESSION, JANUS_EVENT_SUBTYPE_NONE,
					session_id, "destroyed", NULL);
			goto jsondone;
		} else if (!strcasecmp(message_text, "set_session_timeout")) {
			/* Specific session timeout setting. */
			JANUS_VALIDATE_JSON_OBJECT(root, session_timeout_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}

			/* Positive timeout is seconds, 0 is unlimited, -1 is global session timeout */
			json_t *timeout = json_object_get(root, "timeout");
			int timeout_num = json_integer_value(timeout);
			if(timeout_num < -1) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_ELEMENT_TYPE, "Invalid element type (timeout should be a non-negative integer or -1)");
				goto jsondone;
			}

			/* Set specific session timeout */
			janus_mutex_lock(&session->mutex);
			session->timeout = timeout_num;
			janus_mutex_unlock(&session->mutex);

			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			json_object_set_new(reply, "timeout", json_integer(timeout_num));
			json_object_set_new(reply, "session_id", json_integer(session_id));

			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(strcasecmp(message_text, "list_handles")) {
			/* If this is not a request to destroy a session, it must be a request to list the handles */
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}

		/* List handles */
		json_t *list = janus_session_handles_list_json(session);
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		json_object_set_new(reply, "handles", list);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	} else {
		/* Handle-related */
		if(!strcasecmp(message_text, "detach_handle")) {
			if(handle->app == NULL || handle->app_handle == NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin to detach from");
				goto jsondone;
			}
			int error = janus_session_handles_remove(session, handle);
			if(error != 0) {
				/* TODO Make error struct to pass verbose information */
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "Couldn't detach from plugin: error '%d'", error);
				/* TODO Delete handle instance */
				goto jsondone;
			}
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", session_id, transaction_text);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "hangup_webrtc")) {
			if(handle->app == NULL || handle->app_handle == NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_PLUGIN_DETACH, "No plugin attached");
				goto jsondone;
			}
			janus_ice_webrtc_hangup(handle, "Admin API");
			/* Prepare JSON reply */
			json_t *reply = janus_create_message("success", session_id, transaction_text);
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "start_pcap") || !strcasecmp(message_text, "start_text2pcap")) {
			/* Start dumping RTP and RTCP packets to a pcap or text2pcap file */
			JANUS_VALIDATE_JSON_OBJECT(root, text2pcap_parameters,
				error_code, error_cause, FALSE,
				JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
			if(error_code != 0) {
				ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
				goto jsondone;
			}
			gboolean text = !strcasecmp(message_text, "start_text2pcap");
			const char *folder = json_string_value(json_object_get(root, "folder"));
			const char *filename = json_string_value(json_object_get(root, "filename"));
			int truncate = json_integer_value(json_object_get(root, "truncate"));
			if(handle->text2pcap != NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN,
					text ? "text2pcap already started" : "pcap already started");
				goto jsondone;
			}
			handle->text2pcap = janus_text2pcap_create(folder, filename, truncate, text);
			if(handle->text2pcap == NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN,
					text ? "Error starting text2pcap dump" : "Error starting pcap dump");
				goto jsondone;
			}
			g_atomic_int_set(&handle->dump_packets, 1);
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		} else if(!strcasecmp(message_text, "stop_pcap") || !strcasecmp(message_text, "stop_text2pcap")) {
			/* Stop dumping RTP and RTCP packets to a pcap or text2pcap file */
			if(handle->text2pcap == NULL) {
				ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_UNKNOWN,
					"Capture not started");
				goto jsondone;
			}
			if(g_atomic_int_compare_and_exchange(&handle->dump_packets, 1, 0)) {
				janus_text2pcap_close(handle->text2pcap);
				g_clear_pointer(&handle->text2pcap, janus_text2pcap_free);
			}
			/* Prepare JSON reply */
			json_t *reply = json_object();
			json_object_set_new(reply, "janus", json_string("success"));
			json_object_set_new(reply, "transaction", json_string(transaction_text));
			/* Send the success reply */
			ret = janus_process_success(request, reply);
			goto jsondone;
		}
		/* If this is not a request to start/stop debugging to text2pcap, it must be a handle_info */
		if(strcasecmp(message_text, "handle_info")) {
			ret = janus_process_error(request, session_id, transaction_text, JANUS_ERROR_INVALID_REQUEST_PATH, "Unhandled request '%s' at this path", message_text);
			goto jsondone;
		}
		JANUS_VALIDATE_JSON_OBJECT(root, handleinfo_parameters,
			error_code, error_cause, FALSE,
			JANUS_ERROR_MISSING_MANDATORY_ELEMENT, JANUS_ERROR_INVALID_ELEMENT_TYPE);
		if(error_code != 0) {
			ret = janus_process_error_string(request, session_id, transaction_text, error_code, error_cause);
			goto jsondone;
		}
		/* Check if we should limit the response to the plugin-specific info */
		gboolean plugin_only = json_is_true(json_object_get(root, "plugin_only"));
		/* Prepare info */
		json_t *info = json_object();
		json_object_set_new(info, "session_id", json_integer(session_id));
		json_object_set_new(info, "session_last_activity", json_integer(session->last_activity));
		json_object_set_new(info, "session_timeout", json_integer(session->timeout == -1 ? global_session_timeout : (guint)session->timeout));
		janus_mutex_lock(&session->mutex);
		if(session->source && session->source->transport)
			json_object_set_new(info, "session_transport", json_string(session->source->transport->get_package()));
		janus_mutex_unlock(&session->mutex);
		janus_mutex_lock(&handle->mutex);
		json_object_set_new(info, "handle_id", json_integer(handle_id));
		if(handle->opaque_id)
			json_object_set_new(info, "opaque_id", json_string(handle->opaque_id));
		if(handle->token)
			json_object_set_new(info, "token", json_string(handle->token));
		json_object_set_new(info, "loop-running", (handle->mainloop != NULL &&
			g_main_loop_is_running(handle->mainloop)) ? json_true() : json_false());
		json_object_set_new(info, "created", json_integer(handle->created));
		json_object_set_new(info, "current_time", json_integer(janus_get_monotonic_time()));
		if(handle->app && janus_plugin_session_is_alive(handle->app_handle)) {
			janus_plugin *plugin = (janus_plugin *)handle->app;
			json_object_set_new(info, "plugin", json_string(plugin->get_package()));
			if(plugin->query_session) {
				/* FIXME This check will NOT work with legacy plugins that were compiled BEFORE the method was specified in plugin.h */
				json_t *query = plugin->query_session(handle->app_handle);
				if(query != NULL) {
					/* Make sure this is a JSON object */
					if(!json_is_object(query)) {
						JANUS_LOG(LOG_WARN, "Ignoring invalid query response from the plugin (not an object)\n");
						json_decref(query);
					} else {
						json_object_set_new(info, "plugin_specific", query);
					}
					query = NULL;
				}
			}
		}
		if(plugin_only)
			goto info_done;
		json_t *flags = json_object();
		json_object_set_new(flags, "got-offer", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER) ? json_true() : json_false());
		json_object_set_new(flags, "got-answer", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER) ? json_true() : json_false());
		json_object_set_new(flags, "negotiated", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED) ? json_true() : json_false());
		json_object_set_new(flags, "processing-offer", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER) ? json_true() : json_false());
		json_object_set_new(flags, "starting", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START) ? json_true() : json_false());
		json_object_set_new(flags, "ice-restart", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART) ? json_true() : json_false());
		json_object_set_new(flags, "ready", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY) ? json_true() : json_false());
		json_object_set_new(flags, "stopped", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) ? json_true() : json_false());
		json_object_set_new(flags, "alert", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) ? json_true() : json_false());
		json_object_set_new(flags, "trickle", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) ? json_true() : json_false());
		json_object_set_new(flags, "all-trickles", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES) ? json_true() : json_false());
		json_object_set_new(flags, "resend-trickles", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES) ? json_true() : json_false());
		json_object_set_new(flags, "trickle-synced", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED) ? json_true() : json_false());
		json_object_set_new(flags, "data-channels", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS) ? json_true() : json_false());
		json_object_set_new(flags, "has-audio", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO) ? json_true() : json_false());
		json_object_set_new(flags, "has-video", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO) ? json_true() : json_false());
		json_object_set_new(flags, "new-datachan-sdp", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP) ? json_true() : json_false());
		json_object_set_new(flags, "rfc4588-rtx", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) ? json_true() : json_false());
		json_object_set_new(flags, "cleaning", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING) ? json_true() : json_false());
		json_object_set_new(flags, "e2ee", janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE) ? json_true() : json_false());
		json_object_set_new(info, "flags", flags);
		if(handle->agent) {
			json_object_set_new(info, "agent-created", json_integer(handle->agent_created));
			if(handle->agent_started > 0)
				json_object_set_new(info, "agent-started", json_integer(handle->agent_started));
			json_object_set_new(info, "ice-mode", json_string(janus_ice_is_ice_lite_enabled() ? "lite" : "full"));
			json_object_set_new(info, "ice-role", json_string(handle->controlling ? "controlling" : "controlled"));
		}
		json_t *sdps = json_object();
		if(handle->rtp_profile)
			json_object_set_new(sdps, "profile", json_string(handle->rtp_profile));
		if(handle->local_sdp)
			json_object_set_new(sdps, "local", json_string(handle->local_sdp));
		if(handle->remote_sdp)
			json_object_set_new(sdps, "remote", json_string(handle->remote_sdp));
		json_object_set_new(info, "sdps", sdps);
		if(handle->pending_trickles)
			json_object_set_new(info, "pending-trickles", json_integer(g_list_length(handle->pending_trickles)));
		if(handle->queued_packets)
			json_object_set_new(info, "queued-packets", json_integer(g_async_queue_length(handle->queued_packets)));
		if(g_atomic_int_get(&handle->dump_packets) && handle->text2pcap) {
			if(handle->text2pcap->text) {
				json_object_set_new(info, "dump-to-text2pcap", json_true());
				json_object_set_new(info, "text2pcap-file", json_string(handle->text2pcap->filename));
			} else {
				json_object_set_new(info, "dump-to-pcap", json_true());
				json_object_set_new(info, "pcap-file", json_string(handle->text2pcap->filename));
			}
		}
		if(handle->pc) {
			json_t *p = janus_admin_peerconnection_summary(handle->pc);
			if(p)
				json_object_set_new(info, "webrtc", p);
		}
info_done:
		janus_mutex_unlock(&handle->mutex);
		/* Prepare JSON reply */
		json_t *reply = janus_create_message("success", session_id, transaction_text);
		json_object_set_new(reply, "handle_id", json_integer(handle_id));
		json_object_set_new(reply, "info", info);
		/* Send the success reply */
		ret = janus_process_success(request, reply);
		goto jsondone;
	}

jsondone:
	/* Done processing */
	if(handle != NULL)
		janus_refcount_decrease(&handle->ref);
	if(session != NULL)
		janus_refcount_decrease(&session->ref);
	return ret;
}

int janus_process_success(janus_request *request, json_t *payload)
{
	if(!request || !payload)
		return -1;
	/* Pass to the right transport plugin */
	JANUS_LOG(LOG_HUGE, "Sending %s API response to %s (%p)\n", request->admin ? "admin" : "Janus", request->transport->get_package(), request->instance);
	return request->transport->send_message(request->instance, request->request_id, request->admin, payload);
}

static int janus_process_error_string(janus_request *request, uint64_t session_id, const char *transaction, gint error, gchar *error_string)
{
	if(!request)
		return -1;
	/* Done preparing error */
	JANUS_LOG(LOG_VERB, "[%s] Returning %s API error %d (%s)\n", transaction, request->admin ? "admin" : "Janus", error, error_string);
	/* Prepare JSON error */
	json_t *reply = janus_create_message("error", session_id, transaction);
	json_t *error_data = json_object();
	json_object_set_new(error_data, "code", json_integer(error));
	json_object_set_new(error_data, "reason", json_string(error_string));
	json_object_set_new(reply, "error", error_data);
	/* Pass to the right transport plugin */
	return request->transport->send_message(request->instance, request->request_id, request->admin, reply);
}

int janus_process_error(janus_request *request, uint64_t session_id, const char *transaction, gint error, const char *format, ...)
{
	if(!request)
		return -1;
	gchar *error_string = NULL;
	gchar error_buf[512];
	if(format == NULL) {
		/* No error string provided, use the default one */
		error_string = (gchar *)janus_get_api_error(error);
	} else {
		/* This callback has variable arguments (error string) */
		va_list ap;
		va_start(ap, format);
		g_vsnprintf(error_buf, sizeof(error_buf), format, ap);
		va_end(ap);
		error_string = error_buf;
	}
	return janus_process_error_string(request, session_id, transaction, error, error_string);
}

/* Admin/monitor helpers */
json_t *janus_admin_peerconnection_summary(janus_ice_peerconnection *pc) {
	if(pc == NULL)
		return NULL;
	json_t *w = json_object();
	json_t *i = json_object();
	json_object_set_new(i, "stream_id", json_integer(pc->stream_id));
	json_object_set_new(i, "component_id", json_integer(pc->component_id));
	json_object_set_new(i, "state", json_string(janus_get_ice_state_name(pc->state)));
	if(pc->icefailed_detected) {
		json_object_set_new(i, "failed-detected", json_integer(pc->icefailed_detected));
		json_object_set_new(i, "icetimer-started", pc->icestate_source ? json_true() : json_false());
	}
	if(pc->gathered > 0)
		json_object_set_new(i, "gathered", json_integer(pc->gathered));
	if(pc->connected > 0)
		json_object_set_new(i, "connected", json_integer(pc->connected));
	if(pc->local_candidates) {
		json_t *cs = json_array();
		GSList *candidates = pc->local_candidates, *c = NULL;
		for (c = candidates; c; c = c->next) {
			gchar *lc = (gchar *) c->data;
			if(lc)
				json_array_append_new(cs, json_string(lc));
		}
		json_object_set_new(i, "local-candidates", cs);
	}
	if(pc->remote_candidates) {
		json_t *cs = json_array();
		GSList *candidates = pc->remote_candidates, *c = NULL;
		for (c = candidates; c; c = c->next) {
			gchar *rc = (gchar *) c->data;
			if(rc)
				json_array_append_new(cs, json_string(rc));
		}
		json_object_set_new(i, "remote-candidates", cs);
	}
	if(pc->selected_pair) {
		json_object_set_new(i, "selected-pair", json_string(pc->selected_pair));
	}
	json_object_set_new(i, "ready", json_integer(pc->cdone));
	json_object_set_new(w, "ice", i);
	json_t *d = json_object();
	if(pc->dtls) {
		janus_dtls_srtp *dtls = pc->dtls;
		json_object_set_new(d, "fingerprint", json_string(janus_dtls_get_local_fingerprint()));
		if(pc->remote_fingerprint)
			json_object_set_new(d, "remote-fingerprint", json_string(pc->remote_fingerprint));
		if(pc->remote_hashing)
			json_object_set_new(d, "remote-fingerprint-hash", json_string(pc->remote_hashing));
		json_object_set_new(d, "dtls-role", json_string(janus_get_dtls_srtp_role(pc->dtls_role)));
		json_object_set_new(d, "dtls-state", json_string(janus_get_dtls_srtp_state(dtls->dtls_state)));
		json_object_set_new(d, "retransmissions", json_integer(dtls->retransmissions));
		json_object_set_new(d, "valid", dtls->srtp_valid ? json_true() : json_false());
		const char *srtp_profile = janus_get_dtls_srtp_profile(dtls->srtp_profile);
		json_object_set_new(d, "srtp-profile", json_string(srtp_profile ? srtp_profile : "none"));
		json_object_set_new(d, "ready", dtls->ready ? json_true() : json_false());
		if(dtls->dtls_started > 0)
			json_object_set_new(d, "handshake-started", json_integer(dtls->dtls_started));
		if(dtls->dtls_connected > 0)
			json_object_set_new(d, "connected", json_integer(dtls->dtls_connected));
#ifdef HAVE_SCTP
		/* FIXME Actually check if this succeeded? */
		json_object_set_new(d, "sctp-association", dtls->sctp ? json_true() : json_false());
#endif
		json_t *stats = json_object();
		json_t *in_stats = json_object();
		json_object_set_new(in_stats, "packets", json_integer(pc->dtls_in_stats.info[0].packets));
		json_object_set_new(in_stats, "bytes", json_integer(pc->dtls_in_stats.info[0].bytes));
		json_t *out_stats = json_object();
		json_object_set_new(out_stats, "packets", json_integer(pc->dtls_out_stats.info[0].packets));
		json_object_set_new(out_stats, "bytes", json_integer(pc->dtls_out_stats.info[0].bytes));
		json_object_set_new(stats, "in", in_stats);
		json_object_set_new(stats, "out", out_stats);
		json_object_set_new(d, "stats", stats);
	}
	json_object_set_new(w, "dtls", d);
	json_t *se = json_object();
	if(pc->mid_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_MID, json_integer(pc->mid_ext_id));
	if(pc->rid_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_RID, json_integer(pc->rid_ext_id));
	if(pc->ridrtx_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_REPAIRED_RID, json_integer(pc->ridrtx_ext_id));
	if(pc->abs_send_time_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_ABS_SEND_TIME, json_integer(pc->abs_send_time_ext_id));
	if(pc->abs_capture_time_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_ABS_SEND_TIME, json_integer(pc->abs_capture_time_ext_id));
	if(pc->transport_wide_cc_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC, json_integer(pc->transport_wide_cc_ext_id));
	if(pc->audiolevel_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_AUDIO_LEVEL, json_integer(pc->audiolevel_ext_id));
	if(pc->videoorientation_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION, json_integer(pc->videoorientation_ext_id));
	if(pc->playoutdelay_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_PLAYOUT_DELAY, json_integer(pc->playoutdelay_ext_id));
	if(pc->dependencydesc_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_DEPENDENCY_DESC, json_integer(pc->dependencydesc_ext_id));
	if(pc->videolayers_ext_id > 0)
		json_object_set_new(se, JANUS_RTP_EXTMAP_VIDEO_LAYERS, json_integer(pc->videolayers_ext_id));
	json_object_set_new(w, "extensions", se);
	json_t *bwe = json_object();
	json_object_set_new(bwe, "twcc", pc->do_transport_wide_cc ? json_true() : json_false());
	if(pc->transport_wide_cc_ext_id >= 0)
		json_object_set_new(bwe, "twcc-ext-id", json_integer(pc->transport_wide_cc_ext_id));
	json_object_set_new(w, "bwe", bwe);
	json_t *media = json_object();
	/* Iterate on all media */
	janus_ice_peerconnection_medium *medium = NULL;
	uint mi=0;
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		json_t *m = janus_admin_peerconnection_medium_summary(medium);
		if(m)
			json_object_set_new(media, medium->mid, m);
	}
	json_object_set_new(w, "media", media);
	return w;
}

json_t *janus_admin_peerconnection_medium_summary(janus_ice_peerconnection_medium *medium) {
	if(medium == NULL)
		return NULL;
	/* SSRCs */
	json_t *m = json_object();
	if(medium->type == JANUS_MEDIA_AUDIO)
		json_object_set_new(m, "type", json_string("audio"));
	else if(medium->type == JANUS_MEDIA_VIDEO)
		json_object_set_new(m, "type", json_string("video"));
	else if(medium->type == JANUS_MEDIA_DATA)
		json_object_set_new(m, "type", json_string("data"));
	json_object_set_new(m, "mindex", json_integer(medium->mindex));
	json_object_set_new(m, "mid", json_string(medium->mid));
	if(medium->msid || medium->remote_msid) {
		json_t *mm = json_object();
		if(medium->msid) {
			json_object_set_new(mm, "local-stream", json_string(medium->msid));
			if(medium->mstid)
				json_object_set_new(mm, "local-track", json_string(medium->mstid));
		}
		if(medium->remote_msid) {
			json_object_set_new(mm, "remote-stream", json_string(medium->remote_msid));
			if(medium->remote_mstid)
				json_object_set_new(mm, "remote-track", json_string(medium->remote_mstid));
		}
		json_object_set_new(m, "msid", mm);
	}
	if(medium->type != JANUS_MEDIA_DATA) {
		json_object_set_new(m, "do_nacks", medium->do_nacks ? json_true() : json_false());
		json_object_set_new(m, "nack-queue-ms", json_integer(medium->nack_queue_ms));
	}
	if(medium->type != JANUS_MEDIA_DATA) {
		json_t *ms = json_object();
		if(medium->ssrc)
			json_object_set_new(ms, "ssrc", json_integer(medium->ssrc));
		if(medium->ssrc_rtx)
			json_object_set_new(ms, "ssrc-rtx", json_integer(medium->ssrc_rtx));
		if(medium->ssrc_peer[0])
			json_object_set_new(ms, "ssrc-peer", json_integer(medium->ssrc_peer[0]));
		if(medium->ssrc_peer[1])
			json_object_set_new(ms, "ssrc-peer-sim-1", json_integer(medium->ssrc_peer[1]));
		if(medium->ssrc_peer[2])
			json_object_set_new(ms, "ssrc-peer-sim-2", json_integer(medium->ssrc_peer[2]));
		if(medium->ssrc_peer_rtx[0])
			json_object_set_new(ms, "ssrc-peer-rtx", json_integer(medium->ssrc_peer_rtx[0]));
		if(medium->ssrc_peer_rtx[1])
			json_object_set_new(ms, "ssrc-peer-sim-1-rtx", json_integer(medium->ssrc_peer_rtx[1]));
		if(medium->ssrc_peer_rtx[2])
			json_object_set_new(ms, "ssrc-peer-sim-2-rtx", json_integer(medium->ssrc_peer_rtx[2]));
		json_object_set_new(m, "ssrc", ms);
		if(medium->rid[0] && medium->pc->rid_ext_id > 0) {
			json_t *mr = json_object();
			json_t *rid = json_array();
			if(medium->rid[2])
				json_array_append_new(rid, json_string(medium->rid[2]));
			if(medium->rid[1])
				json_array_append_new(rid, json_string(medium->rid[1]));
			json_array_append_new(rid, json_string(medium->rid[0]));
			json_object_set_new(mr, "rid", rid);
			json_object_set_new(mr, "rid-ext-id", json_integer(medium->pc->rid_ext_id));
			if(medium->pc->ridrtx_ext_id > 0)
				json_object_set_new(mr, "ridrtx-ext-id", json_integer(medium->pc->ridrtx_ext_id));
			json_object_set_new(mr, "rid-order", json_string(medium->rids_hml ? "hml" : "lmh"));
			if(medium->legacy_rid)
				json_object_set_new(mr, "rid-syntax", json_string("legacy"));
			json_object_set_new(m, "rid-simulcast", mr);
		}
	}
	/* Media direction */
	if(medium->type != JANUS_MEDIA_DATA) {
		json_t *md = json_object();
		json_object_set_new(md, "send", medium->send ? json_true() : json_false());
		json_object_set_new(md, "recv", medium->recv ? json_true() : json_false());
		json_object_set_new(m, "direction", md);
	}
	/* Payload type and codec */
	if(medium->type != JANUS_MEDIA_DATA && (medium->payload_type > -1 || medium->rtx_payload_type > -1)) {
		json_t *sc = json_object();
		if(medium->payload_type > -1)
			json_object_set_new(sc, "pt", json_integer(medium->payload_type));
		if(medium->opusred_pt > 0)
			json_object_set_new(sc, "opus-red-pt", json_integer(medium->opusred_pt));
		if(medium->rtx_payload_type > -1)
			json_object_set_new(sc, "rtx-pt", json_integer(medium->rtx_payload_type));
		if(medium->codec != NULL)
			json_object_set_new(sc, "codec", json_string(medium->codec));
		json_object_set_new(m, "codecs", sc);
	}
	/* RTCP stats */
	int vindex=0;
	if(medium->type != JANUS_MEDIA_DATA) {
		json_t *rtcp_stats = NULL;
		for(vindex=0; vindex<3; vindex++) {
			if(medium->rtcp_ctx[vindex] != NULL) {
				if(rtcp_stats == NULL)
					rtcp_stats = json_object();
				json_t *medium_rtcp_stats = json_object();
				json_object_set_new(medium_rtcp_stats, "base", json_integer(medium->rtcp_ctx[vindex]->tb));
				if(vindex == 0)
					json_object_set_new(medium_rtcp_stats, "rtt", json_integer(janus_rtcp_context_get_rtt(medium->rtcp_ctx[vindex])));
				json_object_set_new(medium_rtcp_stats, "lost", json_integer(janus_rtcp_context_get_lost_all(medium->rtcp_ctx[vindex], FALSE)));
				json_object_set_new(medium_rtcp_stats, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(medium->rtcp_ctx[vindex], TRUE)));
				json_object_set_new(medium_rtcp_stats, "jitter-local", json_integer(janus_rtcp_context_get_jitter(medium->rtcp_ctx[vindex], FALSE)));
				json_object_set_new(medium_rtcp_stats, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(medium->rtcp_ctx[vindex], TRUE)));
				json_object_set_new(medium_rtcp_stats, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(medium->rtcp_ctx[vindex])));
				json_object_set_new(medium_rtcp_stats, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(medium->rtcp_ctx[vindex])));
				json_object_set_new(medium_rtcp_stats, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(medium->rtcp_ctx[vindex])));
				json_object_set_new(medium_rtcp_stats, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(medium->rtcp_ctx[vindex])));
				if(vindex == 0)
					json_object_set_new(rtcp_stats, "main", medium_rtcp_stats);
				else if(vindex == 1)
					json_object_set_new(rtcp_stats, "sim1", medium_rtcp_stats);
				else
					json_object_set_new(rtcp_stats, "sim2", medium_rtcp_stats);
			}
		}
		if(rtcp_stats != NULL)
			json_object_set_new(m, "rtcp", rtcp_stats);
	}
	/* Media stats */
	json_t *stats = json_object();
	json_t *in_stats = json_object();
	json_t *out_stats = json_object();
	for(vindex=0; vindex<3; vindex++) {
		if(vindex > 0 && medium->ssrc_peer[vindex] == 0)
			continue;
		json_t *container = (vindex == 0 ? in_stats : json_object());
		json_object_set_new(container, "packets", json_integer(medium->in_stats.info[vindex].packets));
		json_object_set_new(container, "bytes", json_integer(medium->in_stats.info[vindex].bytes));
		if(medium->type != JANUS_MEDIA_DATA) {
			json_object_set_new(container, "bytes_lastsec", json_integer(medium->in_stats.info[vindex].bytes_lastsec));
			if(medium->do_nacks) {
				json_object_set_new(container, "nacks", json_integer(medium->in_stats.info[vindex].nacks));
				if(medium->rtcp_ctx[vindex])
					json_object_set_new(in_stats, "retransmissions", json_integer(medium->rtcp_ctx[vindex]->retransmitted));
			}
			if(vindex == 1)
				json_object_set_new(in_stats, "video-simulcast-1", container);
			else if(vindex == 2)
				json_object_set_new(in_stats, "video-simulcast-2", container);
		}
	}
	json_object_set_new(out_stats, "packets", json_integer(medium->out_stats.info[0].packets));
	json_object_set_new(out_stats, "bytes", json_integer(medium->out_stats.info[0].bytes));
	if(medium->type != JANUS_MEDIA_DATA) {
		json_object_set_new(out_stats, "bytes_lastsec", json_integer(medium->out_stats.info[0].bytes_lastsec));
		json_object_set_new(out_stats, "nacks", json_integer(medium->out_stats.info[0].nacks));
	}
	json_object_set_new(stats, "in", in_stats);
	json_object_set_new(stats, "out", out_stats);
	json_object_set_new(m, "stats", stats);
	return m;
}


/* Transports */
void janus_transport_close(gpointer key, gpointer value, gpointer user_data) {
	janus_transport *transport = (janus_transport *)value;
	if(!transport)
		return;
	transport->destroy();
}

void janus_transportso_close(gpointer key, gpointer value, gpointer user_data) {
	void *transport = value;
	if(!transport)
		return;
	/* FIXME We don't dlclose transports to be sure we can detect leaks */
	//~ dlclose(transport);
}

/* Transport callback interface */
void janus_transport_incoming_request(janus_transport *plugin, janus_transport_session *transport, void *request_id, gboolean admin, json_t *message, json_error_t *error) {
	JANUS_LOG(LOG_VERB, "Got %s API request from %s (%p)\n", admin ? "an admin" : "a Janus", plugin->get_package(), transport);
	/* Create a janus_request instance to handle the request */
	janus_request *request = janus_request_new(plugin, transport, request_id, admin, message, message ? NULL : error);
	/* Enqueue the request, the thread will pick it up */
	g_async_queue_push(requests, request);
}

void janus_transport_gone(janus_transport *plugin, janus_transport_session *transport) {
	/* Get rid of sessions this transport was handling */
	JANUS_LOG(LOG_VERB, "A %s transport instance has gone away (%p)\n", plugin->get_package(), transport);
	janus_mutex_lock(&sessions_mutex);
	if(sessions && g_hash_table_size(sessions) > 0) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, sessions);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_session *session = (janus_session *) value;
			if(!session || g_atomic_int_get(&session->destroyed) || g_atomic_int_get(&session->timedout) || session->last_activity == 0)
				continue;
			if(session->source && session->source->instance == transport) {
				JANUS_LOG(LOG_VERB, "  -- Session %"SCNu64" will be over if not reclaimed\n", session->session_id);
				JANUS_LOG(LOG_VERB, "  -- Marking Session %"SCNu64" as over\n", session->session_id);
				if(reclaim_session_timeout < 1) { /* Reclaim session timeouts are disabled */
					/* Notify event handlers, if needed */
					if(janus_events_is_enabled())
						janus_events_notify_handlers(JANUS_EVENT_TYPE_SESSION, JANUS_EVENT_SUBTYPE_NONE,
							session->session_id, "destroyed", NULL);
					/* Mark the session as destroyed */
					janus_session_destroy(session);
					g_atomic_int_dec_and_test(&sessions_num);
					g_hash_table_iter_remove(&iter);
				} else {
					/* Set flag for transport_gone. The Janus sessions watchdog will clean this up if not reclaimed */
					g_atomic_int_set(&session->transport_gone, 1);
				}
			}
		}
	}
	janus_mutex_unlock(&sessions_mutex);
}

gboolean janus_transport_is_api_secret_needed(janus_transport *plugin) {
	return api_secret != NULL;
}

gboolean janus_transport_is_api_secret_valid(janus_transport *plugin, const char *apisecret) {
	if(api_secret == NULL)
		return TRUE;
	return apisecret && janus_strcmp_const_time(apisecret, api_secret);
}

gboolean janus_transport_is_auth_token_needed(janus_transport *plugin) {
	return janus_auth_is_enabled();
}

gboolean janus_transport_is_auth_token_valid(janus_transport *plugin, const char *token) {
	if(!janus_auth_is_enabled())
		return TRUE;
	return token && janus_auth_check_token(token);
}

void janus_transport_notify_event(janus_transport *plugin, void *transport, json_t *event) {
	/* A plugin asked to notify an event to the handlers */
	if(!plugin || !event || !json_is_object(event))
		return;
	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_events_notify_handlers(JANUS_EVENT_TYPE_TRANSPORT, JANUS_EVENT_SUBTYPE_NONE,
			0, plugin->get_package(), transport, event);
	} else {
		json_decref(event);
	}
}

void janus_transport_task(gpointer data, gpointer user_data) {
	JANUS_LOG(LOG_VERB, "Transport task pool, serving request\n");
	janus_request *request = (janus_request *)data;
	if(request == NULL) {
		JANUS_LOG(LOG_ERR, "Missing request\n");
		return;
	}
	if(!request->admin)
		janus_process_incoming_request(request);
	else
		janus_process_incoming_admin_request(request);
	/* Done */
	janus_request_destroy(request);
}


/* Thread to handle incoming requests: may involve an asynchronous task for plugin messaging */
static void *janus_transport_requests(void *data) {
	JANUS_LOG(LOG_INFO, "Joining Janus requests handler thread\n");
	janus_request *request = NULL;
	gboolean destroy = FALSE;
	while(!g_atomic_int_get(&stop)) {
		request = g_async_queue_pop(requests);
		if(request == &exit_message)
			break;
		/* Should we process the request synchronously or with a task from the thread pool? */
		destroy = TRUE;
		/* Process the request synchronously only it's not a message for a plugin */
		json_t *message = json_object_get(request->message, "janus");
		const gchar *message_text = json_string_value(message);
		if(message_text && !strcasecmp(message_text, request->admin ? "message_plugin" : "message")) {
			/* Spawn a task thread */
			GError *tperror = NULL;
			g_thread_pool_push(tasks, request, &tperror);
			if(tperror != NULL) {
				/* Something went wrong... */
				JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to push task in thread pool...\n",
					tperror->code, tperror->message ? tperror->message : "??");
				g_error_free(tperror);
				json_t *transaction = json_object_get(message, "transaction");
				const char *transaction_text = json_is_string(transaction) ? json_string_value(transaction) : NULL;
				janus_process_error(request, 0, transaction_text, JANUS_ERROR_UNKNOWN, "Thread pool error");
			} else {
				/* Don't destroy the request now, the task will take care of that */
				destroy = FALSE;
			}
		} else {
			if(!request->admin)
				janus_process_incoming_request(request);
			else
				janus_process_incoming_admin_request(request);
		}
		/* Done */
		if(destroy)
			janus_request_destroy(request);
	}
	JANUS_LOG(LOG_INFO, "Leaving Janus requests handler thread\n");
	return NULL;
}


/* Event handlers */
void janus_eventhandler_close(gpointer key, gpointer value, gpointer user_data) {
	janus_eventhandler *eventhandler = (janus_eventhandler *)value;
	if(!eventhandler)
		return;
	eventhandler->destroy();
}

void janus_eventhandlerso_close(gpointer key, gpointer value, gpointer user_data) {
	void *eventhandler = (janus_eventhandler *)value;
	if(!eventhandler)
		return;
	//~ dlclose(eventhandler);
}


/* Loggers */
void janus_logger_close(gpointer key, gpointer value, gpointer user_data) {
	janus_logger *logger = (janus_logger *)value;
	if(!logger)
		return;
	logger->destroy();
}

void janus_loggerso_close(gpointer key, gpointer value, gpointer user_data) {
	void *logger = (janus_logger *)value;
	if(!logger)
		return;
	//~ dlclose(logger);
}


/* Plugins */
void janus_plugin_close(gpointer key, gpointer value, gpointer user_data) {
	janus_plugin *plugin = (janus_plugin *)value;
	if(!plugin)
		return;
	plugin->destroy();
}

void janus_pluginso_close(gpointer key, gpointer value, gpointer user_data) {
	void *plugin = value;
	if(!plugin)
		return;
	/* FIXME We don't dlclose plugins to be sure we can detect leaks */
	//~ dlclose(plugin);
}

janus_plugin *janus_plugin_find(const gchar *package) {
	if(package != NULL && plugins != NULL)	/* FIXME Do we need to fix the key pointer? */
		return g_hash_table_lookup(plugins, package);
	return NULL;
}


/* Plugin callback interface */
int janus_plugin_push_event(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *transaction, json_t *message, json_t *jsep) {
	if(!plugin || !message)
		return -1;
	if(!janus_plugin_session_is_alive(plugin_session))
		return -2;
	janus_refcount_increase(&plugin_session->ref);
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		janus_refcount_decrease(&plugin_session->ref);
		return JANUS_ERROR_SESSION_NOT_FOUND;
	}
	janus_refcount_increase(&ice_handle->ref);
	janus_session *session = ice_handle->session;
	if(!session || g_atomic_int_get(&session->destroyed)) {
		janus_refcount_decrease(&plugin_session->ref);
		janus_refcount_decrease(&ice_handle->ref);
		return JANUS_ERROR_SESSION_NOT_FOUND;
	}
	/* Make sure this is a JSON object */
	if(!json_is_object(message)) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: not an object)\n", ice_handle->handle_id);
		janus_refcount_decrease(&plugin_session->ref);
		janus_refcount_decrease(&ice_handle->ref);
		return JANUS_ERROR_INVALID_JSON_OBJECT;
	}
	/* Attach JSEP if possible? */
	const char *sdp_type = json_string_value(json_object_get(jsep, "type"));
	const char *sdp = json_string_value(json_object_get(jsep, "sdp"));
	gboolean restart = json_object_get(jsep, "sdp") ? json_is_true(json_object_get(jsep, "restart")) : FALSE;
	gboolean e2ee = json_object_get(jsep, "sdp") ? json_is_true(json_object_get(jsep, "e2ee")) : FALSE;
	json_t *merged_jsep = NULL;
	if(sdp_type != NULL && sdp != NULL) {
		merged_jsep = janus_plugin_handle_sdp(plugin_session, plugin, sdp_type, sdp, restart);
		if(merged_jsep == NULL) {
			if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
					|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (handle not available anymore or negotiation stopped)\n", ice_handle->handle_id);
				janus_refcount_decrease(&plugin_session->ref);
				janus_refcount_decrease(&ice_handle->ref);
				return JANUS_ERROR_HANDLE_NOT_FOUND;
			} else {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Cannot push event (JSON error: problem with the SDP)\n", ice_handle->handle_id);
				janus_refcount_decrease(&plugin_session->ref);
				janus_refcount_decrease(&ice_handle->ref);
				return JANUS_ERROR_JSEP_INVALID_SDP;
			}
		}
	}
	/* Reference the payload, as the plugin may still need it and will do a decref itself */
	json_incref(message);
	/* Prepare JSON event */
	json_t *event = janus_create_message("event", session->session_id, transaction);
	json_object_set_new(event, "sender", json_integer(ice_handle->handle_id));
	if(janus_is_opaqueid_in_api_enabled() && ice_handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(ice_handle->opaque_id));
	json_t *plugin_data = json_object();
	json_object_set_new(plugin_data, "plugin", json_string(plugin->get_package()));
	json_object_set_new(plugin_data, "data", message);
	json_object_set_new(event, "plugindata", plugin_data);
	if(merged_jsep != NULL) {
		if(e2ee)
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
		if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE))
			json_object_set_new(merged_jsep, "e2ee", json_true());
		json_object_set_new(event, "jsep", merged_jsep);
		/* In case event handlers are enabled, push the local SDP to all handlers */
		if(janus_events_is_enabled()) {
			const char *merged_sdp_type = json_string_value(json_object_get(merged_jsep, "type"));
			const char *merged_sdp = json_string_value(json_object_get(merged_jsep, "sdp"));
			/* Notify event handlers as well */
			janus_events_notify_handlers(JANUS_EVENT_TYPE_JSEP, JANUS_EVENT_SUBTYPE_NONE,
				session->session_id, ice_handle->handle_id, ice_handle->opaque_id, "local", merged_sdp_type, merged_sdp);
		}
	}
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", ice_handle->handle_id);
	janus_session_notify_event(session, event);

	if((restart || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES))
			&& janus_ice_is_full_trickle_enabled()) {
		/* We're restarting ICE, send our trickle candidates again */
		janus_ice_resend_trickles(ice_handle);
	}

	janus_refcount_decrease(&plugin_session->ref);
	janus_refcount_decrease(&ice_handle->ref);
	return JANUS_OK;
}

json_t *janus_plugin_handle_sdp(janus_plugin_session *plugin_session, janus_plugin *plugin, const char *sdp_type, const char *sdp, gboolean restart) {
	if(!janus_plugin_session_is_alive(plugin_session) ||
			plugin == NULL || sdp_type == NULL || sdp == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid arguments\n");
		return NULL;
	}
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	//~ if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
	if(ice_handle == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid ICE handle\n");
		return NULL;
	}
	int offer = 0;
	if(!strcasecmp(sdp_type, "offer")) {
		/* This is an offer from a plugin */
		offer = 1;
		janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
		janus_flags_clear(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	} else if(!strcasecmp(sdp_type, "answer")) {
		/* This is an answer from a plugin */
		janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
		if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER))
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
	} else {
		/* TODO Handle other messages */
		JANUS_LOG(LOG_ERR, "Unknown type '%s'\n", sdp_type);
		return NULL;
	}
	/* Is this valid SDP? */
	char error_str[512];
	error_str[0] = '\0';
	int audio = 0, video = 0, data = 0;
	janus_sdp *parsed_sdp = janus_sdp_preparse(ice_handle, sdp, error_str, sizeof(error_str), NULL, &audio, &video, &data);
	if(parsed_sdp == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Couldn't parse SDP... %s\n", ice_handle->handle_id, error_str);
		return NULL;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] There are %d audio, %d video and %d data m-lines\n",
		ice_handle->handle_id, audio, video, data);
	gboolean updating = FALSE;
	if(offer) {
		/* Are we still cleaning up from a previous media session? */
		if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", ice_handle->handle_id);
			gint64 waited = 0;
			while(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING)) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still cleaning up from a previous media session, let's wait a bit...\n", ice_handle->handle_id);
				g_usleep(100000);
				waited += 100000;
				if(waited >= 3*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"]   -- Waited 3 seconds, that's enough!\n", ice_handle->handle_id);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Still cleaning a previous session\n", ice_handle->handle_id);
					janus_sdp_destroy(parsed_sdp);
					return NULL;
				}
			}
		}
		janus_mutex_lock(&ice_handle->mutex);
		if(ice_handle->agent == NULL) {
			/* We still need to configure the WebRTC stuff: negotiate RFC4588 by default */
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX);
			/* Process SDP in order to setup ICE locally (this is going to result in an answer from the browser) */
			if(janus_ice_setup_local(ice_handle, FALSE, TRUE, JANUS_DTLS_ROLE_ACTPASS) < 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error setting ICE locally\n", ice_handle->handle_id);
				janus_sdp_destroy(parsed_sdp);
				janus_mutex_unlock(&ice_handle->mutex);
				return NULL;
			}
			/* Create medium instances */
			if(janus_sdp_process_local(ice_handle, parsed_sdp, FALSE) < 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error processing SDP\n", ice_handle->handle_id);
				janus_sdp_destroy(parsed_sdp);
				janus_mutex_unlock(&ice_handle->mutex);
				return NULL;
			}
		} else {
			updating = TRUE;
			JANUS_LOG(LOG_INFO, "[%"SCNu64"] Updating existing session\n", ice_handle->handle_id);
			if(offer && ice_handle->pc) {
				/* Check what changed */
				if(janus_sdp_process_local(ice_handle, parsed_sdp, TRUE) < 0) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error processing SDP\n", ice_handle->handle_id);
					janus_sdp_destroy(parsed_sdp);
					janus_mutex_unlock(&ice_handle->mutex);
					return NULL;
				}
			}
		}
		/* Make sure we don't send the rid/repaired-rid attributes when offering ourselves */
		int mindex = 0;
		int mid_ext_id = 0, transport_wide_cc_ext_id = 0, abs_send_time_ext_id = 0,
			abs_capture_time_ext_id = 0, audiolevel_ext_id = 0, videoorientation_ext_id = 0,
			playoutdelay_ext_id = 0, dependencydesc_ext_id = 0, videolayers_ext_id = 0;
		GList *temp = parsed_sdp->m_lines;
		while(temp) {
			janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
			janus_ice_peerconnection_medium *medium = ice_handle->pc ?
				g_hash_table_lookup(ice_handle->pc->media, GUINT_TO_POINTER(mindex)) : NULL;
			GList *tempA = m->attributes;
			while(tempA) {
				janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
				if(a->name && a->value) {
					if(!strcasecmp(a->name, "extmap")) {
						if(strstr(a->value, JANUS_RTP_EXTMAP_MID))
							mid_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
							transport_wide_cc_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_SEND_TIME))
							abs_send_time_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME))
							abs_capture_time_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_AUDIO_LEVEL))
							audiolevel_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_VIDEO_ORIENTATION))
							videoorientation_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_PLAYOUT_DELAY))
							playoutdelay_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_DEPENDENCY_DESC))
							dependencydesc_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_VIDEO_LAYERS))
							videolayers_ext_id = atoi(a->value);
						else if(strstr(a->value, JANUS_RTP_EXTMAP_RID) ||
								strstr(a->value, JANUS_RTP_EXTMAP_REPAIRED_RID)) {
							m->attributes = g_list_remove(m->attributes, a);
							tempA = m->attributes;
							janus_sdp_attribute_destroy(a);
							continue;
						}
					} else if(m->type == JANUS_SDP_AUDIO && !strcasecmp(a->name, "rtpmap") &&
							strstr(a->value, "red/48000/2")) {
						/* If the plugin offered RED, take note of it */
						int opusred_pt = atoi(a->value);
						if(medium != NULL)
							medium->opusred_pt = opusred_pt;
					}
				}
				tempA = tempA->next;
			}
			mindex++;
			temp = temp->next;
		}
		if(ice_handle->pc && ice_handle->pc->mid_ext_id != mid_ext_id)
			ice_handle->pc->mid_ext_id = mid_ext_id;
		if(ice_handle->pc && ice_handle->pc->transport_wide_cc_ext_id != transport_wide_cc_ext_id) {
			ice_handle->pc->do_transport_wide_cc = transport_wide_cc_ext_id > 0 ? TRUE : FALSE;
			ice_handle->pc->transport_wide_cc_ext_id = transport_wide_cc_ext_id;
		}
		if(ice_handle->pc && ice_handle->pc->abs_send_time_ext_id != abs_send_time_ext_id)
			ice_handle->pc->abs_send_time_ext_id = abs_send_time_ext_id;
		if(ice_handle->pc && ice_handle->pc->abs_capture_time_ext_id != abs_capture_time_ext_id)
			ice_handle->pc->abs_capture_time_ext_id = abs_capture_time_ext_id;
		if(ice_handle->pc && ice_handle->pc->audiolevel_ext_id != audiolevel_ext_id)
			ice_handle->pc->audiolevel_ext_id = audiolevel_ext_id;
		if(ice_handle->pc && ice_handle->pc->videoorientation_ext_id != videoorientation_ext_id)
			ice_handle->pc->videoorientation_ext_id = videoorientation_ext_id;
		if(ice_handle->pc && ice_handle->pc->playoutdelay_ext_id != playoutdelay_ext_id)
			ice_handle->pc->playoutdelay_ext_id = playoutdelay_ext_id;
		if(ice_handle->pc && ice_handle->pc->dependencydesc_ext_id != dependencydesc_ext_id)
			ice_handle->pc->dependencydesc_ext_id = dependencydesc_ext_id;
		if(ice_handle->pc && ice_handle->pc->videolayers_ext_id != videolayers_ext_id)
			ice_handle->pc->videolayers_ext_id = videolayers_ext_id;
		janus_mutex_unlock(&ice_handle->mutex);
	} else {
		/* Check if the answer does contain the mid/rid/repaired-rid/abs-send-time/twcc extmaps */
		int mindex = 0;
		gboolean do_mid = FALSE, do_rid = FALSE, do_repaired_rid = FALSE,
			do_dd = FALSE, do_twcc = FALSE, do_abs_send_time = FALSE,
			do_abs_capture_time = FALSE, do_video_layers_alloc = FALSE;
		GList *temp = parsed_sdp->m_lines;
		janus_mutex_lock(&ice_handle->mutex);
		while(temp) {
			janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
			janus_ice_peerconnection_medium *medium = ice_handle->pc ?
				g_hash_table_lookup(ice_handle->pc->media, GUINT_TO_POINTER(mindex)) : NULL;
			gboolean have_mid = FALSE, have_rid = FALSE, have_repaired_rid = FALSE,
				have_twcc = FALSE, have_dd = FALSE, have_abs_send_time = FALSE,
				have_abs_capture_time = FALSE, have_video_layers_alloc = FALSE, have_msid = FALSE;
			int opusred_pt = -1;
			GList *tempA = m->attributes;
			while(tempA) {
				janus_sdp_attribute *a = (janus_sdp_attribute *)tempA->data;
				if(a->name && a->value && !strcasecmp(a->name, "msid")) {
					/* Found msid attribute */
					have_msid = TRUE;
					char msid[65], mstid[65];
					msid[0] = '\0';
					mstid[0] = '\0';
					if(sscanf(a->value, "%64s %64s", msid, mstid) != 2) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid msid on m-line #%d\n",
							ice_handle->handle_id, m->index);
						janus_sdp_destroy(parsed_sdp);
						janus_mutex_unlock(&ice_handle->mutex);
						return NULL;
					}
					if(medium != NULL && (medium->msid == NULL || strcasecmp(medium->msid, msid))) {
						char *old_msid = medium->msid;
						medium->msid = g_strdup(msid);
						g_free(old_msid);
					}
					if(medium != NULL && (medium->mstid == NULL || strcasecmp(medium->mstid, mstid))) {
						char *old_mstid = medium->mstid;
						medium->mstid = g_strdup(mstid);
						g_free(old_mstid);
					}
					/* Remove this msid attribute, the core will add it again later */
					GList *msid_attr = tempA;
					tempA = tempA->next;
					m->attributes = g_list_remove_link(m->attributes, msid_attr);
					g_list_free_full(msid_attr, (GDestroyNotify)janus_sdp_attribute_destroy);
					continue;
				} else if(a->name && a->value && !strcasecmp(a->name, "extmap")) {
					if(strstr(a->value, JANUS_RTP_EXTMAP_MID))
						have_mid = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_RID))
						have_rid = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_REPAIRED_RID))
						have_repaired_rid = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_TRANSPORT_WIDE_CC))
						have_twcc = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_DEPENDENCY_DESC))
						do_dd = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_SEND_TIME))
						have_abs_send_time = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_ABS_CAPTURE_TIME))
						have_abs_capture_time = TRUE;
					else if(strstr(a->value, JANUS_RTP_EXTMAP_VIDEO_LAYERS))
						have_video_layers_alloc = TRUE;
				} else if(m->type == JANUS_SDP_AUDIO && medium != NULL && medium->opusred_pt > 0 &&
						a->name && a->value && !strcasecmp(a->name, "rtpmap") && strstr(a->value, "red/48000/2")) {
					opusred_pt = atoi(a->value);
				}
				tempA = tempA->next;
			}
			/* If the user offered RED but the plugin rejected it, disable it */
			if(opusred_pt < 0 && medium != NULL && medium->opusred_pt > 0)
				medium->opusred_pt = 0;
			if(!have_msid && medium != NULL) {
				g_free(medium->msid);
				medium->msid = NULL;
				g_free(medium->mstid);
				medium->mstid = NULL;
			}
			/* Check if rid-based simulcasting is available */
			if(!have_rid && medium != NULL) {
				g_free(medium->rid[0]);
				medium->rid[0] = NULL;
				g_free(medium->rid[1]);
				medium->rid[1] = NULL;
				g_free(medium->rid[2]);
				medium->rid[2] = NULL;
				if(medium->ssrc_peer_temp > 0) {
					medium->ssrc_peer[0] = medium->ssrc_peer_temp;
					medium->ssrc_peer_temp = 0;
				}
			}
			do_mid = do_mid || have_mid;
			do_rid = do_rid || have_rid;
			do_repaired_rid = do_repaired_rid || have_repaired_rid;
			do_twcc = do_twcc || have_twcc;
			do_dd = do_dd || have_dd;
			do_abs_send_time = do_abs_send_time || have_abs_send_time;
			do_abs_capture_time = do_abs_capture_time || have_abs_capture_time;
			do_video_layers_alloc = do_video_layers_alloc || have_video_layers_alloc;
			mindex++;
			temp = temp->next;
		}
		if(!do_mid && ice_handle->pc)
			ice_handle->pc->mid_ext_id = 0;
		if(!do_rid && ice_handle->pc) {
			ice_handle->pc->rid_ext_id = 0;
			ice_handle->pc->ridrtx_ext_id = 0;
		}
		if(!do_repaired_rid && ice_handle->pc)
			ice_handle->pc->ridrtx_ext_id = 0;
		if(!do_twcc && ice_handle->pc) {
			ice_handle->pc->do_transport_wide_cc = FALSE;
			ice_handle->pc->transport_wide_cc_ext_id = 0;
		}
		if(!do_dd && ice_handle->pc)
			ice_handle->pc->dependencydesc_ext_id = 0;
		if(!do_abs_send_time && ice_handle->pc)
			ice_handle->pc->abs_send_time_ext_id = 0;
		if(!do_abs_capture_time && ice_handle->pc)
			ice_handle->pc->abs_capture_time_ext_id = 0;
		if(!do_video_layers_alloc && ice_handle->pc)
			ice_handle->pc->videolayers_ext_id = 0;
		janus_mutex_unlock(&ice_handle->mutex);
	}
	if(!updating && !janus_ice_is_full_trickle_enabled()) {
		/* Wait for candidates-done callback */
		int waiting = 0;
		while(ice_handle->cdone < 1) {
			if(ice_handle == NULL || janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
					|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Handle detached or PC closed, giving up...!\n", ice_handle ? ice_handle->handle_id : 0);
				janus_sdp_destroy(parsed_sdp);
				return NULL;
			}
			if(ice_handle->cdone < 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates!\n", ice_handle->handle_id);
				janus_sdp_destroy(parsed_sdp);
				return NULL;
			}
			if(waiting && (waiting % 5000) == 0) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Waited 5s for candidates, that's way too much... going on with what we have (WebRTC setup might fail)\n", ice_handle->handle_id);
				break;
			}
			if(waiting && (waiting % 1000) == 0) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] %s for candidates-done callback... (slow gathering, are you using STUN or TURN for Janus too, instead of just for users? Consider enabling full-trickle instead)\n",
					ice_handle->handle_id, (waiting == 1000 ? "Waiting" : "Still waiting"));
			}
			waiting++;
			g_usleep(1000);
		}
	}
	/* Anonymize SDP */
	if(janus_sdp_anonymize(parsed_sdp) < 0) {
		/* Invalid SDP */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid SDP\n", ice_handle->handle_id);
		janus_sdp_destroy(parsed_sdp);
		return NULL;
	}

	/* Check if this is a renegotiation and we need an ICE restart */
	if(offer && restart)
		janus_ice_restart(ice_handle);
	/* Add our details */
	janus_mutex_lock(&ice_handle->mutex);
	janus_ice_peerconnection *pc = ice_handle->pc;
	if(pc == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No WebRTC PeerConnection\n", ice_handle->handle_id);
		janus_sdp_destroy(parsed_sdp);
		janus_mutex_unlock(&ice_handle->mutex);
		return NULL;
	}
	/* Iterate on all media */
	janus_ice_peerconnection_medium *medium = NULL;
	uint mi=0;
	/* Let's build a list of payload types first */
	if(pc->payload_types == NULL)
		pc->payload_types = g_hash_table_new(NULL, NULL);
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		if(medium && medium->type != JANUS_MEDIA_DATA) {
			janus_sdp_mline *m = janus_sdp_mline_find_by_index(parsed_sdp, medium->mindex);
			if(m && m->ptypes) {
				GList *tpt = m->ptypes;
				while(tpt) {
					g_hash_table_insert(pc->payload_types, tpt->data, tpt->data);
					tpt = tpt->next;
				}
			}
		}
	}
	/* Now let's iterate on media */
	for(mi=0; mi<g_hash_table_size(pc->media); mi++) {
		medium = g_hash_table_lookup(pc->media, GUINT_TO_POINTER(mi));
		if(medium && medium->type == JANUS_MEDIA_VIDEO &&
				janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
				medium->rtx_payload_types == NULL) {
			/* Make sure we have a list of rtx payload types to generate, if needed */
			janus_sdp_mline *m = janus_sdp_mline_find_by_index(parsed_sdp, medium->mindex);
			if(m && m->ptypes) {
				medium->rtx_payload_types = g_hash_table_new(NULL, NULL);
				if(pc->rtx_payload_types == NULL)
					pc->rtx_payload_types = g_hash_table_new(NULL, NULL);
				if(pc->rtx_payload_types_rev == NULL)
					pc->rtx_payload_types_rev = g_hash_table_new(NULL, NULL);
				GList *ptypes = m->ptypes;
				while(ptypes) {
					int ptype = GPOINTER_TO_INT(ptypes->data);
					if(g_hash_table_lookup(pc->rtx_payload_types_rev, GINT_TO_POINTER(ptype))) {
						/* This is an RTX for an existing payload type, skip */
						ptypes = ptypes->next;
						continue;
					}
					/* Let's check if a mapping exists already */
					int rtx_ptype = GPOINTER_TO_INT(g_hash_table_lookup(pc->rtx_payload_types, GINT_TO_POINTER(ptype)));
					if(rtx_ptype == 0) {
						/* No mapping yet, find one now */
						rtx_ptype = ptype+1;
						if(rtx_ptype > 127)
							rtx_ptype = 96;
						while(g_hash_table_lookup(pc->payload_types, GINT_TO_POINTER(rtx_ptype)) ||
								g_hash_table_lookup(pc->rtx_payload_types_rev, GINT_TO_POINTER(rtx_ptype))) {
							rtx_ptype++;
							if(rtx_ptype > 127)
								rtx_ptype = 96;
							if(rtx_ptype == ptype) {
								/* We did a whole round? should never happen... */
								rtx_ptype = -1;
								break;
							}
						}
					}
					if(rtx_ptype > 0) {
						g_hash_table_insert(pc->payload_types, GINT_TO_POINTER(rtx_ptype), GINT_TO_POINTER(rtx_ptype));
						g_hash_table_insert(pc->rtx_payload_types, GINT_TO_POINTER(ptype), GINT_TO_POINTER(rtx_ptype));
						g_hash_table_insert(pc->rtx_payload_types_rev, GINT_TO_POINTER(rtx_ptype), GINT_TO_POINTER(ptype));
						g_hash_table_insert(medium->rtx_payload_types, GINT_TO_POINTER(ptype), GINT_TO_POINTER(rtx_ptype));
					}
					medium->do_nacks = TRUE;
					ptypes = ptypes->next;
				}
			}
		} else if(medium && medium->type == JANUS_MEDIA_VIDEO &&
				janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
				medium->rtx_payload_types != NULL) {
			/* Check if there are new payload types that conflict with our rtx additions */
			janus_sdp_mline *m = janus_sdp_mline_find_by_index(parsed_sdp, medium->mindex);
			if(m && m->ptypes) {
				GList *ptypes = g_list_copy(m->ptypes), *tempP = ptypes;
				GList *rtx_ptypes = g_hash_table_get_values(medium->rtx_payload_types);
				while(tempP) {
					int ptype = GPOINTER_TO_INT(tempP->data);
					if(g_hash_table_lookup(medium->clock_rates, GINT_TO_POINTER(ptype)) &&
							g_list_find(rtx_ptypes, GINT_TO_POINTER(ptype))) {
						/* We have a payload type that is both a codec and rtx, get rid of it */
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Removing duplicate payload type %d\n", ice_handle->handle_id, ptype);
						janus_sdp_remove_payload_type(parsed_sdp, medium->mindex, ptype);
						g_hash_table_remove(medium->clock_rates, GINT_TO_POINTER(ptype));
					}
					tempP = tempP->next;
				}
				g_list_free(ptypes);
				g_list_free(rtx_ptypes);
			}
		}
	}
	/* Enrich the SDP the plugin gave us with all the WebRTC related stuff */
	char *sdp_merged = janus_sdp_merge(ice_handle, parsed_sdp, offer ? TRUE : FALSE);
	if(sdp_merged == NULL) {
		/* Couldn't merge SDP */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error merging SDP\n", ice_handle->handle_id);
		janus_sdp_destroy(parsed_sdp);
		janus_mutex_unlock(&ice_handle->mutex);
		return NULL;
	}
	janus_sdp_destroy(parsed_sdp);

	if(!updating) {
		if(offer) {
			/* We set the flag to wait for an answer before handling trickle candidates */
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_PROCESSING_OFFER);
		} else {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending answer, ready to setup remote candidates and send connectivity checks...\n", ice_handle->handle_id);
			janus_request_ice_handle_answer(ice_handle, NULL);
		}
	}
#ifdef HAVE_SCTP
	if(!offer && janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		/* Renegotiation: check if datachannels were just added on an existing PeerConnection */
		if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
			janus_ice_peerconnection *pc = ice_handle->pc;
			if(pc != NULL && pc->dtls != NULL && pc->dtls->sctp == NULL) {
				/* Create SCTP association as well */
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating datachannels...\n", ice_handle->handle_id);
				janus_dtls_srtp_create_sctp(pc->dtls);
			}
		}
	}
#endif

	/* Prepare JSON event */
	json_t *jsep = json_object();
	json_object_set_new(jsep, "type", json_string(sdp_type));
	json_object_set_new(jsep, "sdp", json_string(sdp_merged));
	char *tmp = ice_handle->local_sdp;
	ice_handle->local_sdp = sdp_merged;
	janus_mutex_unlock(&ice_handle->mutex);
	g_free(tmp);
	return jsep;
}

void janus_plugin_relay_rtp(janus_plugin_session *plugin_session, janus_plugin_rtp *packet) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped) ||
			packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtp(handle, packet);
}

void janus_plugin_relay_rtcp(janus_plugin_session *plugin_session, janus_plugin_rtcp *packet) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped) ||
			packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtcp(handle, packet);
}

void janus_plugin_relay_data(janus_plugin_session *plugin_session, janus_plugin_data *packet) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped) ||
			packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
#ifdef HAVE_SCTP
	janus_ice_relay_data(handle, packet);
#else
	JANUS_LOG(LOG_WARN, "Asked to relay data, but Data Channels support has not been compiled...\n");
#endif
}

void janus_plugin_send_pli(janus_plugin_session *plugin_session) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped))
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_send_pli(handle);
}

void janus_plugin_send_pli_stream(janus_plugin_session *plugin_session, int mindex) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped))
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_send_pli_stream(handle, mindex);
}

void janus_plugin_send_remb(janus_plugin_session *plugin_session, uint32_t bitrate) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped))
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_send_remb(handle, bitrate);
}

static gboolean janus_plugin_close_pc_internal(gpointer user_data) {
	/* We actually enforce the close_pc here */
	janus_plugin_session *plugin_session = (janus_plugin_session *) user_data;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle || !g_atomic_int_compare_and_exchange(&ice_handle->closepc, 1, 0)) {
		janus_refcount_decrease(&plugin_session->ref);
		return G_SOURCE_REMOVE;
	}
	janus_refcount_increase(&ice_handle->ref);
	if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT)) {
		janus_refcount_decrease(&plugin_session->ref);
		janus_refcount_decrease(&ice_handle->ref);
		return G_SOURCE_REMOVE;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Plugin asked to hangup PeerConnection: sending alert\n", ice_handle->handle_id);
	/* Send an alert on all the DTLS connections */
	janus_ice_webrtc_hangup(ice_handle, "Close PC");
	janus_refcount_decrease(&plugin_session->ref);
	janus_refcount_decrease(&ice_handle->ref);

	return G_SOURCE_REMOVE;
}

void janus_plugin_close_pc(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a PeerConnection: enqueue it as a timed source */
	if(!janus_plugin_session_is_alive(plugin_session))
		return;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle || !g_atomic_int_compare_and_exchange(&ice_handle->closepc, 0, 1))
		return;
	janus_refcount_increase(&plugin_session->ref);
	GSource *timeout_source = g_timeout_source_new_seconds(0);
	g_source_set_callback(timeout_source, janus_plugin_close_pc_internal, plugin_session, NULL);
	g_source_attach(timeout_source, sessions_watchdog_context);
	g_source_unref(timeout_source);
}

static gboolean janus_plugin_end_session_internal(gpointer user_data) {
	/* We actually enforce the end_session here */
	janus_plugin_session *plugin_session = (janus_plugin_session *) user_data;
	janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!ice_handle) {
		janus_refcount_decrease(&plugin_session->ref);
		return G_SOURCE_REMOVE;
	}
	janus_refcount_increase(&ice_handle->ref);
	if(janus_flags_is_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)) {
		janus_refcount_decrease(&plugin_session->ref);
		janus_refcount_decrease(&ice_handle->ref);
		return G_SOURCE_REMOVE;
	}
	janus_session *session = (janus_session *)ice_handle->session;
	if(!session) {
		janus_refcount_decrease(&plugin_session->ref);
		janus_refcount_decrease(&ice_handle->ref);
		return G_SOURCE_REMOVE;
	}
	/* Destroy the handle */
	janus_session_handles_remove(session, ice_handle);

	janus_refcount_decrease(&plugin_session->ref);
	janus_refcount_decrease(&ice_handle->ref);
	return G_SOURCE_REMOVE;
}

void janus_plugin_end_session(janus_plugin_session *plugin_session) {
	/* A plugin asked to get rid of a handle: enqueue it as a timed source */
	if(!janus_plugin_session_is_alive(plugin_session))
		return;
	janus_refcount_increase(&plugin_session->ref);
	GSource *timeout_source = g_timeout_source_new_seconds(0);
	g_source_set_callback(timeout_source, janus_plugin_end_session_internal, plugin_session, NULL);
	g_source_attach(timeout_source, sessions_watchdog_context);
	g_source_unref(timeout_source);
}

void janus_plugin_notify_event(janus_plugin *plugin, janus_plugin_session *plugin_session, json_t *event) {
	/* A plugin asked to notify an event to the handlers */
	if(!plugin || !event || !json_is_object(event))
		return;
	guint64 session_id = 0, handle_id = 0;
	char *opaque_id = NULL;
	if(plugin_session != NULL) {
		if(!janus_plugin_session_is_alive(plugin_session)) {
			json_decref(event);
			return;
		}
		janus_ice_handle *ice_handle = (janus_ice_handle *)plugin_session->gateway_handle;
		if(!ice_handle) {
			json_decref(event);
			return;
		}
		handle_id = ice_handle->handle_id;
		opaque_id = ice_handle->opaque_id;
		janus_session *session = (janus_session *)ice_handle->session;
		if(!session) {
			json_decref(event);
			return;
		}
		session_id = session->session_id;
	}
	/* Notify event handlers */
	if(janus_events_is_enabled()) {
		janus_events_notify_handlers(JANUS_EVENT_TYPE_PLUGIN, JANUS_EVENT_SUBTYPE_NONE,
			session_id, handle_id, opaque_id, plugin->get_package(), event);
	} else {
		json_decref(event);
	}
}

gboolean janus_plugin_auth_is_signed(void) {
	return janus_auth_is_signed_mode();
}

gboolean janus_plugin_auth_is_signature_valid(janus_plugin *plugin, const char *token) {
	return janus_auth_check_signature(token, plugin->get_package());
}

gboolean janus_plugin_auth_signature_contains(janus_plugin *plugin, const char *token, const char *descriptor) {
	return janus_auth_check_signature_contains(token, plugin->get_package(), descriptor);
}


/* Main */
gint main(int argc, char *argv[]) {
	/* Core dumps may be disallowed by parent of this process; change that */
	struct rlimit core_limits;
	core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &core_limits);

	janus_mark_started();

	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, janus_handle_signal);
	signal(SIGTERM, janus_handle_signal);
	atexit(janus_termination_handler);

	JANUS_PRINT("Janus version: %d (%s)\n", janus_version, janus_version_string);
	JANUS_PRINT("Janus commit: %s\n", janus_build_git_sha);
	JANUS_PRINT("Compiled on:  %s\n\n", janus_build_git_time);

	/* Initialize some command line options defaults */
	options.debug_level = -1;
	options.session_timeout = -1;
	options.reclaim_session_timeout = -1;
	options.min_nack_queue = -1;
	options.no_media_timer = -1;
	options.slowlink_threshold = -1;
	options.twcc_period = -1;
	/* Let's call our cmdline parser */
	if(!janus_options_parse(&options, argc, argv))
		exit(1);

	if(options.print_version) {
		janus_options_destroy();
		exit(0);
	}

	/* Any configuration to open? */
	if(options.config_file) {
		config_file = g_strdup(options.config_file);
	}
	if(options.configs_folder) {
		configs_folder = g_strdup(options.configs_folder);
	} else {
		configs_folder = g_strdup(CONFDIR);
	}
	if(config_file == NULL) {
		char file[255];
		g_snprintf(file, 255, "%s/janus.jcfg", configs_folder);
		config_file = g_strdup(file);
	}
	if((config = janus_config_parse(config_file)) == NULL) {
		/* We failed to load the libconfig configuration file, let's try the INI */
		JANUS_PRINT("Failed to load %s, trying the INI instead...\n", config_file);
		g_free(config_file);
		char file[255];
		g_snprintf(file, 255, "%s/janus.cfg", configs_folder);
		config_file = g_strdup(file);
		if((config = janus_config_parse(config_file)) == NULL) {
			if(options.config_file) {
				/* We only give up if the configuration file was explicitly provided */
				JANUS_PRINT("Error reading configuration from %s\n", config_file);
				janus_options_destroy();
				exit(1);
			}
			JANUS_PRINT("Error reading/parsing the configuration file in %s, going on with the defaults and the command line arguments\n",
				configs_folder);
			config = janus_config_create("janus.cfg");
			if(config == NULL) {
				/* If we can't even create an empty configuration, something's definitely wrong */
				janus_options_destroy();
				exit(1);
			}
		}
	}
	/* Pre-fetch some categories (creates them if they don't exist) */
	janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");
	janus_config_category *config_certs = janus_config_get_create(config, NULL, janus_config_type_category, "certificates");
	janus_config_category *config_nat = janus_config_get_create(config, NULL, janus_config_type_category, "nat");
	janus_config_category *config_media = janus_config_get_create(config, NULL, janus_config_type_category, "media");
	janus_config_category *config_transports = janus_config_get_create(config, NULL, janus_config_type_category, "transports");
	janus_config_category *config_plugins = janus_config_get_create(config, NULL, janus_config_type_category, "plugins");
	janus_config_category *config_events = janus_config_get_create(config, NULL, janus_config_type_category, "events");
	janus_config_category *config_loggers = janus_config_get_create(config, NULL, janus_config_type_category, "loggers");

	/* Any log prefix? */
	janus_config_array *lp = janus_config_get(config, config_general, janus_config_type_item, "log_prefix");
	if(lp && lp->value)
		janus_log_global_prefix = g_strdup(lp->value);

	/* Check if there are folders to protect */
	janus_config_array *pfs = janus_config_get(config, config_general, janus_config_type_array, "protected_folders");
	if(pfs && pfs->list) {
		GList *item = pfs->list;
		while(item) {
			janus_config_item *pf = (janus_config_item *)item->data;
			if(pf && pf->type == janus_config_type_item && pf->name == NULL && pf->value != NULL)
				janus_protected_folder_add(pf->value);
			item = item->next;
		}
	}

	/* Check if we need to log to console and/or file */
	gboolean use_stdout = TRUE;
	if(options.disable_stdout) {
		use_stdout = FALSE;
		janus_config_add(config, config_general, janus_config_item_create("log_to_stdout", "no"));
	} else if(!options.log_stdout) {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "log_to_stdout");
		if(item && item->value && !janus_is_true(item->value))
			use_stdout = FALSE;
	}
	const char *logfile = NULL;
	if(options.log_file) {
		logfile = options.log_file;
		janus_config_add(config, config_general, janus_config_item_create("log_to_file", "no"));
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "log_to_file");
		if(item && item->value)
			logfile = item->value;
	}

	/* Set an optional signal handler for log rotation */
	const char *log_rotate_sig = NULL;
	if(options.log_rotate_sig) {
		log_rotate_sig = options.log_rotate_sig;
		janus_config_add(config, config_general, janus_config_item_create("log_rotate_sig", log_rotate_sig));
	} else {
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "log_rotate_sig");
		if(item && item->value)
			log_rotate_sig = item->value;
	}
	if(log_rotate_sig != NULL) {
		if(!strcasecmp(log_rotate_sig, "SIGUSR1")) {
			janus_log_rotate_sig = SIGUSR1;
		} else if(!strcasecmp(log_rotate_sig, "SIGHUP")) {
			janus_log_rotate_sig = SIGHUP;
		} else {
			JANUS_LOG(LOG_WARN, "Unsupported signal for log rotation: %s\n", log_rotate_sig);
		}
		if(janus_log_rotate_sig > 0) {
			JANUS_LOG(LOG_INFO, "Setting signal for log rotation: %s (%d)\n", log_rotate_sig, janus_log_rotate_sig);
			signal(janus_log_rotate_sig, janus_handle_signal);
		}
	}

	/* Check if we're going to daemonize Janus */
	if(options.daemon) {
		daemonize = TRUE;
		janus_config_add(config, config_general, janus_config_item_create("daemonize", "yes"));
	} else {
		/* Check if the configuration file is saying anything about this */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "daemonize");
		if(item && item->value && janus_is_true(item->value))
			daemonize = TRUE;
	}
	/* If we're going to daemonize, make sure logging to stdout is disabled and a log file has been specified */
	if(daemonize && use_stdout && !options.log_stdout) {
		use_stdout = FALSE;
	}
	/* Daemonize now, if we need to */
	if(daemonize) {
		JANUS_PRINT("Running Janus as a daemon\n");

		/* Create a pipe for parent<->child communication during the startup phase */
		if(pipe(pipefd) == -1) {
			JANUS_PRINT("pipe error!\n");
			exit(1);
		}

		/* Fork off the parent process */
		pid_t pid = fork();
		if(pid < 0) {
			JANUS_PRINT("Fork error!\n");
			exit(1);
		}
		if(pid > 0) {
			/* Ok, we're the parent: let's wait for the child to tell us everything started fine */
			close(pipefd[1]);
			int code = -1;
			struct pollfd pollfds;

			while(code < 0) {
				pollfds.fd = pipefd[0];
				pollfds.events = POLLIN;
				int res = poll(&pollfds, 1, -1);
				if(res < 0)
					break;
				if(res == 0)
					continue;
				if(pollfds.revents & POLLERR || pollfds.revents & POLLHUP)
					break;
				if(pollfds.revents & POLLIN) {
					res = read(pipefd[0], &code, sizeof(int));
					break;
				}
			}
			if(code < 0)
				code = 1;

			/* Leave the parent and return the exit code we received from the child */
			if(code)
				JANUS_PRINT("Error launching Janus (error code %d), check the logs for more details\n", code);
			exit(code);
		}
		/* Child here */
		close(pipefd[0]);

		/* Change the file mode mask */
		umask(0);

		/* Create a new SID for the child process */
		pid_t sid = setsid();
		if(sid < 0) {
			JANUS_PRINT("Error setting SID!\n");
			exit(1);
		}
		/* Change the current working directory */
		const char *cwd = options.cwd_path ? options.cwd_path : "/";
		if((chdir(cwd)) < 0) {
			JANUS_PRINT("Error changing the current working directory!\n");
			exit(1);
		}
		/* We close stdin/stdout/stderr when initializing the logger */
	}

	/* Was a custom instance name provided? */
	if(options.server_name)
		janus_config_add(config, config_general, janus_config_item_create("server_name", options.server_name));
	janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "server_name");
	if(item && item->value)
		server_name = g_strdup(item->value);

	/* Check if we should exit immediately on dlopen or dlsym errors */
	item = janus_config_get(config, config_general, janus_config_type_item, "exit_on_dl_error");
	if(item && item->value && janus_is_true(item->value))
		exit_on_dl_error = TRUE;

	/* Check if there are external loggers we need to load */
	const char *path = NULL;
	DIR *dir = NULL;
	/* External loggers are usually disabled by default: they need to be enabled in the configuration */
	gchar **disabled_loggers = NULL;
	path = LOGGERDIR;
	item = janus_config_get(config, config_general, janus_config_type_item, "loggers_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Logger plugins folder: %s\n", path);
	dir = opendir(path);
	if(!dir) {
		/* Not really fatal, we don't care and go on anyway: loggers are not fundamental */
		JANUS_LOG(LOG_WARN, "\tCouldn't access logger plugins folder...\n");
	} else {
		/* Any loggers to ignore? */
		item = janus_config_get(config, config_loggers, janus_config_type_item, "disable");
		if(item && item->value)
			disabled_loggers = g_strsplit(item->value, ",", -1);
		/* Open the shared objects */
		struct dirent *eventent = NULL;
		char eventpath[1024];
		while((eventent = readdir(dir))) {
			int len = strlen(eventent->d_name);
			if (len < 4) {
				continue;
			}
			if (strcasecmp(eventent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
				continue;
			}
			/* Check if this logger has been disabled in the configuration file */
			if(disabled_loggers != NULL) {
				gchar *index = disabled_loggers[0];
				if(index != NULL) {
					int i=0;
					gboolean skip = FALSE;
					while(index != NULL) {
						while(isspace(*index))
							index++;
						if(strlen(index) && !strcmp(index, eventent->d_name)) {
							JANUS_LOG(LOG_WARN, "Logger plugin '%s' has been disabled, skipping...\n", eventent->d_name);
							skip = TRUE;
							break;
						}
						i++;
						index = disabled_loggers[i];
					}
					if(skip)
						continue;
				}
			}
			JANUS_LOG(LOG_INFO, "Loading logger plugin '%s'...\n", eventent->d_name);
			memset(eventpath, 0, 1024);
			g_snprintf(eventpath, 1024, "%s/%s", path, eventent->d_name);
			void *event = dlopen(eventpath, RTLD_NOW | RTLD_GLOBAL);
			if(!event) {
				JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load logger plugin '%s': %s\n", eventent->d_name, dlerror());
				if(exit_on_dl_error)
					exit(1);
			} else {
				create_l *create = (create_l*) dlsym(event, "create");
				const char *dlsym_error = dlerror();
				if(dlsym_error) {
					JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
					if(exit_on_dl_error)
						exit(1);
					continue;
				}
				janus_logger *janus_logger = create();
				if(!janus_logger) {
					JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
					continue;
				}
				/* Are all the mandatory methods and callbacks implemented? */
				if(!janus_logger->init || !janus_logger->destroy ||
						!janus_logger->get_api_compatibility ||
						!janus_logger->get_version ||
						!janus_logger->get_version_string ||
						!janus_logger->get_description ||
						!janus_logger->get_package ||
						!janus_logger->get_name ||
						!janus_logger->incoming_logline) {
					JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this logger plugin...\n");
					continue;
				}
				if(janus_logger->get_api_compatibility() < JANUS_LOGGER_API_VERSION) {
					JANUS_LOG(LOG_ERR, "The '%s' logger plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
						janus_logger->get_package(), janus_logger->get_api_compatibility(), JANUS_LOGGER_API_VERSION);
					continue;
				}
				janus_logger->init(server_name ? server_name : JANUS_SERVER_NAME, configs_folder);
				JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_logger->get_version(), janus_logger->get_version_string());
				JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_logger->get_package(), janus_logger->get_name());
				JANUS_LOG(LOG_VERB, "\t   %s\n", janus_logger->get_description());
				JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_logger->get_api_compatibility());
				if(loggers == NULL)
					loggers = g_hash_table_new(g_str_hash, g_str_equal);
				g_hash_table_insert(loggers, (gpointer)janus_logger->get_package(), janus_logger);
				if(loggers_so == NULL)
					loggers_so = g_hash_table_new(g_str_hash, g_str_equal);
				g_hash_table_insert(loggers_so, (gpointer)janus_logger->get_package(), event);
			}
		}
		closedir(dir);
	}
	if(disabled_loggers != NULL)
		g_strfreev(disabled_loggers);
	disabled_loggers = NULL;

	/* Initialize logger */
	if(janus_log_init(daemonize, use_stdout, logfile, loggers) < 0)
		exit(1);

	JANUS_PRINT("---------------------------------------------------\n");
	JANUS_PRINT("  Starting Meetecho Janus (WebRTC Server) v%s\n", janus_version_string);
	JANUS_PRINT("---------------------------------------------------\n\n");

	/* Setup Glib */
#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif

	/* Logging level: default is info and no timestamps */
	janus_log_level = LOG_INFO;
	janus_log_timestamps = FALSE;
	janus_log_colors = TRUE;
	if(options.debug_level > -1) {
		if(options.debug_level < LOG_NONE)
			options.debug_level = 0;
		else if(options.debug_level > LOG_MAX)
			options.debug_level = LOG_MAX;
		janus_log_level = options.debug_level;
	}

	/* Any PID we need to create? */
	const char *pidfile = NULL;
	if(options.pid_file) {
		pidfile = options.pid_file;
		janus_config_add(config, config_general, janus_config_item_create("pid_file", pidfile));
	} else {
		/* Check if the configuration file is saying anything about this */
		item = janus_config_get(config, config_general, janus_config_type_item, "pid_file");
		if(item && item->value)
			pidfile = item->value;
	}
	if(janus_pidfile_create(pidfile) < 0)
		exit(1);

	/* Proceed with the rest of the configuration */
	janus_config_print(config);
	if(options.debug_level > -1) {
		char debug[5];
		g_snprintf(debug, 5, "%d", options.debug_level);
		janus_config_add(config, config_general, janus_config_item_create("debug_level", debug));
	} else {
		/* No command line directive on logging, try the configuration file */
		item = janus_config_get(config, config_general, janus_config_type_item, "debug_level");
		if(item && item->value) {
			int temp_level = atoi(item->value);
			if(temp_level == 0 && strcmp(item->value, "0")) {
				JANUS_PRINT("Invalid debug level %s (configuration), using default (info=4)\n", item->value);
			} else {
				janus_log_level = temp_level;
				if(janus_log_level < LOG_NONE)
					janus_log_level = 0;
				else if(janus_log_level > LOG_MAX)
					janus_log_level = LOG_MAX;
			}
		}
	}
	/* Any command line argument that should overwrite the configuration? */
	JANUS_PRINT("Checking command line arguments...\n");
	if(options.debug_timestamps)
		janus_config_add(config, config_general, janus_config_item_create("debug_timestamps", "yes"));
	if(options.disable_colors)
		janus_config_add(config, config_general, janus_config_item_create("debug_colors", "no"));
	if(options.debug_locks)
		janus_config_add(config, config_general, janus_config_item_create("debug_locks", "yes"));
	if(options.session_timeout > -1) {
		char st[20];
		g_snprintf(st, 20, "%d", options.session_timeout);
		janus_config_add(config, config_general, janus_config_item_create("session_timeout", st));
	}
	if(options.reclaim_session_timeout > -1) {
		char st[20];
		g_snprintf(st, 20, "%d", options.reclaim_session_timeout);
		janus_config_add(config, config_general, janus_config_item_create("reclaim_session_timeout", st));
	}
 	if(options.interface)
		janus_config_add(config, config_general, janus_config_item_create("interface", options.interface));
	if(options.configs_folder)
		janus_config_add(config, config_general, janus_config_item_create("configs_folder", options.configs_folder));
	if(options.plugins_folder)
		janus_config_add(config, config_general, janus_config_item_create("plugins_folder", options.plugins_folder));
	if(options.apisecret)
		janus_config_add(config, config_general, janus_config_item_create("api_secret", options.apisecret));
	if(options.token_auth)
		janus_config_add(config, config_general, janus_config_item_create("token_auth", "true"));
	if(options.token_auth_secret)
		janus_config_add(config, config_general, janus_config_item_create("token_auth_secret", options.token_auth_secret));
	if(options.no_webrtc_encryption)
		janus_config_add(config, config_general, janus_config_item_create("no_webrtc_encryption", "true"));
	if(options.cert_pem)
		janus_config_add(config, config_certs, janus_config_item_create("cert_pem", options.cert_pem));
	if(options.cert_key)
		janus_config_add(config, config_certs, janus_config_item_create("cert_key", options.cert_key));
	if(options.cert_pwd)
		janus_config_add(config, config_certs, janus_config_item_create("cert_pwd", options.cert_pwd));
	if(options.stun_server) {
		/* Split in server and port (if port missing, use 3478 as default) */
		char *stunport = strrchr(options.stun_server, ':');
		if(stunport != NULL) {
			*stunport = '\0';
			stunport++;
			janus_config_add(config, config_nat, janus_config_item_create("stun_server", options.stun_server));
			janus_config_add(config, config_nat, janus_config_item_create("stun_port", stunport));
		} else {
			janus_config_add(config, config_nat, janus_config_item_create("stun_server", options.stun_server));
			janus_config_add(config, config_nat, janus_config_item_create("stun_port", "3478"));
		}
	}
	if(options.nat_1_1)
		janus_config_add(config, config_nat, janus_config_item_create("nat_1_1_mapping", options.nat_1_1));
	if(options.keep_private_host)
		janus_config_add(config, config_nat, janus_config_item_create("keep_private_host", "true"));
	if(options.ice_enforce_list)
		janus_config_add(config, config_nat, janus_config_item_create("ice_enforce_list", options.ice_enforce_list));
	if(options.ice_ignore_list)
		janus_config_add(config, config_nat, janus_config_item_create("ice_ignore_list", options.ice_ignore_list));
	if(options.full_trickle)
		janus_config_add(config, config_nat, janus_config_item_create("full_trickle", "true"));
	if(options.ice_lite)
		janus_config_add(config, config_nat, janus_config_item_create("ice_lite", "true"));
	if(options.ice_tcp)
		janus_config_add(config, config_nat, janus_config_item_create("ice_tcp", "true"));
	if(options.ipv6_candidates)
		janus_config_add(config, config_media, janus_config_item_create("ipv6", "true"));
	if(options.ipv6_link_local)
		janus_config_add(config, config_media, janus_config_item_create("ipv6_linklocal", "true"));
	if(options.min_nack_queue > -1) {
		char mnq[20];
		g_snprintf(mnq, 20, "%d", options.min_nack_queue);
		janus_config_add(config, config_media, janus_config_item_create("min_nack_queue", mnq));
	}
	if(options.no_media_timer > -1) {
		char nmt[20];
		g_snprintf(nmt, 20, "%d", options.no_media_timer);
		janus_config_add(config, config_media, janus_config_item_create("no_media_timer", nmt));
	}
	if(options.slowlink_threshold > -1) {
		char st[20];
		g_snprintf(st, 20, "%d", options.slowlink_threshold);
		janus_config_add(config, config_media, janus_config_item_create("slowlink_threshold", st));
	}
	if(options.twcc_period > -1) {
		char tp[20];
		g_snprintf(tp, 20, "%d", options.twcc_period);
		janus_config_add(config, config_media, janus_config_item_create("twcc_period", tp));
	}
	if(options.rtp_port_range) {
		janus_config_add(config, config_media, janus_config_item_create("rtp_port_range", options.rtp_port_range));
	}
	if(options.event_handlers)
		janus_config_add(config, config_events, janus_config_item_create("broadcast", "yes"));
	janus_config_print(config);

	/* Logging/debugging */
	JANUS_PRINT("Debug/log level is %d\n", janus_log_level);
	item = janus_config_get(config, config_general, janus_config_type_item, "debug_timestamps");
	if(item && item->value)
		janus_log_timestamps = janus_is_true(item->value);
	JANUS_PRINT("Debug/log timestamps are %s\n", janus_log_timestamps ? "enabled" : "disabled");
	item = janus_config_get(config, config_general, janus_config_type_item, "debug_colors");
	if(item && item->value)
		janus_log_colors = janus_is_true(item->value);
	JANUS_PRINT("Debug/log colors are %s\n", janus_log_colors ? "enabled" : "disabled");
	item = janus_config_get(config, config_general, janus_config_type_item, "debug_locks");
	if(item && item->value)
		lock_debug = janus_is_true(item->value);
	if(lock_debug) {
		JANUS_PRINT("Lock/mutex debugging is enabled\n");
	}

	/* First of all, let's check if we're disabling WebRTC encryption for debugging purposes */
	item = janus_config_get(config, config_general, janus_config_type_item, "no_webrtc_encryption");
	if(item && item->value && janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Disabling WebRTC encryption: *THIS IS ONLY ACCEPTABLE WHEN DEBUGGING!*\n");
		webrtc_encryption = FALSE;
	}

	/* Any IP/interface to enforce/ignore? */
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_enforce_list");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_INFO, "Adding '%s' to the ICE enforce list...\n", index);
					janus_ice_enforce_interface(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_clear_pointer(&list, g_strfreev);
	}
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_ignore_list");
	if(item && item->value) {
		gchar **list = g_strsplit(item->value, ",", -1);
		gchar *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					JANUS_LOG(LOG_INFO, "Adding '%s' to the ICE ignore list...\n", index);
					janus_ice_ignore_interface(g_strdup(index));
				}
				i++;
				index = list[i];
			}
		}
		g_clear_pointer(&list, g_strfreev);
	}
	/* What is the local IP? */
	JANUS_LOG(LOG_VERB, "Selecting local IP address...\n");
	item = janus_config_get(config, config_general, janus_config_type_item, "interface");
	if(item && item->value) {
		JANUS_LOG(LOG_VERB, "  -- Will try to use %s\n", item->value);
		/* Verify that the address is valid */
		struct ifaddrs *ifas = NULL;
		janus_network_address iface;
		janus_network_address_string_buffer ibuf;
		if(getifaddrs(&ifas) == -1) {
			JANUS_LOG(LOG_ERR, "Unable to acquire list of network devices/interfaces; some configurations may not work as expected... %d (%s)\n",
				errno, g_strerror(errno));
		} else {
			if(janus_network_lookup_interface(ifas, item->value, &iface) != 0) {
				JANUS_LOG(LOG_WARN, "Error setting local IP address to %s, falling back to detecting IP address...\n", item->value);
			} else {
				if(janus_network_address_to_string_buffer(&iface, &ibuf) != 0 || janus_network_address_string_buffer_is_null(&ibuf)) {
					JANUS_LOG(LOG_WARN, "Error getting local IP address from %s, falling back to detecting IP address...\n", item->value);
				} else {
					local_ip = g_strdup(janus_network_address_string_from_buffer(&ibuf));
				}
			}
			freeifaddrs(ifas);
		}
	}
	if(local_ip == NULL) {
		local_ip = janus_network_detect_local_ip_as_string(janus_network_query_options_any_ip);
		if(local_ip == NULL) {
			JANUS_LOG(LOG_WARN, "Couldn't find any address! using 127.0.0.1 as the local IP... (which is NOT going to work out of your machine)\n");
			local_ip = g_strdup("127.0.0.1");
		}
	}
	JANUS_LOG(LOG_INFO, "Using %s as local IP...\n", local_ip);

	/* Check if a custom session timeout value was specified */
	item = janus_config_get(config, config_general, janus_config_type_item, "session_timeout");
	if(item && item->value) {
		int st = atoi(item->value);
		if(st < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring session_timeout value as it's not a positive integer\n");
		} else {
			if(st == 0) {
				JANUS_LOG(LOG_WARN, "Session timeouts have been disabled (note, may result in orphaned sessions)\n");
			}
			global_session_timeout = st;
		}
	}

	/* Check if a custom reclaim session timeout value was specified */
	item = janus_config_get(config, config_general, janus_config_type_item, "reclaim_session_timeout");
	if(item && item->value) {
		int rst = atoi(item->value);
		if(rst < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring reclaim_session_timeout value as it's not a positive integer\n");
		} else {
			if(rst == 0) {
				JANUS_LOG(LOG_WARN, "Reclaim session timeouts have been disabled, will cleanup immediately\n");
			}
			reclaim_session_timeout = rst;
		}
	}

	/* Check if a custom candidates timeout value was specified */
	item = janus_config_get(config, config_general, janus_config_type_item, "candidates_timeout");
	if(item && item->value) {
		int ct = atoi(item->value);
		if(ct <= 0) {
			JANUS_LOG(LOG_WARN, "Ignoring candidates_timeout value as it's not a positive integer\n");
		} else {
			candidates_timeout = ct;
		}
	}

	/* Is there any API secret to consider? */
	api_secret = NULL;
	item = janus_config_get(config, config_general, janus_config_type_item, "api_secret");
	if(item && item->value) {
		api_secret = g_strdup(item->value);
	}
	/* Is there any API secret to consider? */
	admin_api_secret = NULL;
	item = janus_config_get(config, config_general, janus_config_type_item, "admin_secret");
	if(item && item->value) {
		admin_api_secret = g_strdup(item->value);
	}
	/* Also check if the token based authentication mechanism needs to be enabled */
	item = janus_config_get(config, config_general, janus_config_type_item, "token_auth");
	gboolean auth_enabled = item && item->value && janus_is_true(item->value);
	item = janus_config_get(config, config_general, janus_config_type_item, "token_auth_secret");
	const char *auth_secret = NULL;
	if (item && item->value)
		auth_secret = item->value;
	janus_auth_init(auth_enabled, auth_secret);

	/* Check if opaque IDs should be sent back in the Janus API too */
	item = janus_config_get(config, config_general, janus_config_type_item, "opaqueid_in_api");
	if(item && item->value && janus_is_true(item->value))
		janus_enable_opaqueid_in_api();

	/* Initialize the recorder code */
	item = janus_config_get(config, config_general, janus_config_type_item, "recordings_tmp_ext");
	if(item && item->value) {
		janus_recorder_init(TRUE, item->value);
	} else {
		janus_recorder_init(FALSE, NULL);
	}

	/* Check if we should hide dependencies in "info" requests */
	item = janus_config_get(config, config_general, janus_config_type_item, "hide_dependencies");
	if(item && item->value && janus_is_true(item->value))
		hide_dependencies = TRUE;

	/* Setup ICE stuff (e.g., checking if the provided STUN server is correct) */
	char *stun_server = NULL, *turn_server = NULL;
	uint16_t stun_port = 0, turn_port = 0;
	char *turn_type = NULL, *turn_user = NULL, *turn_pwd = NULL;
	char *turn_rest_api = NULL, *turn_rest_api_key = NULL;
#ifdef HAVE_TURNRESTAPI
	char *turn_rest_api_method = NULL;
	uint turn_rest_api_timeout = 10;
#endif
	uint16_t rtp_min_port = 0, rtp_max_port = 0;
	gboolean ice_lite = FALSE, ice_tcp = FALSE, full_trickle = FALSE, ipv6 = FALSE,
		ipv6_linklocal = FALSE, ignore_mdns = FALSE, ignore_unreachable_ice_server = FALSE;
	item = janus_config_get(config, config_media, janus_config_type_item, "ipv6");
	ipv6 = (item && item->value) ? janus_is_true(item->value) : FALSE;
	if(ipv6) {
		item = janus_config_get(config, config_media, janus_config_type_item, "ipv6_linklocal");
		ipv6_linklocal = (item && item->value) ? janus_is_true(item->value) : FALSE;
	}
	item = janus_config_get(config, config_media, janus_config_type_item, "rtp_port_range");
	if(item && item->value) {
		/* Split in min and max port */
		char *maxport = strrchr(item->value, '-');
		if(maxport != NULL) {
			*maxport = '\0';
			maxport++;
			if(janus_string_to_uint16(item->value, &rtp_min_port) < 0)
				JANUS_LOG(LOG_WARN, "Invalid RTP min port value: %s (assuming 0)\n", item->value);
			if(janus_string_to_uint16(maxport, &rtp_max_port) < 0)
				JANUS_LOG(LOG_WARN, "Invalid RTP max port value: %s (assuming 0)\n", maxport);
			maxport--;
			*maxport = '-';
		}
		if(rtp_min_port > rtp_max_port) {
			uint16_t temp_port = rtp_min_port;
			rtp_min_port = rtp_max_port;
			rtp_max_port = temp_port;
		}
		if(rtp_max_port == 0)
			rtp_max_port = 65535;
		JANUS_LOG(LOG_INFO, "RTP port range: %u -- %u\n", rtp_min_port, rtp_max_port);
	}
	/* Check if we need to enable the ICE Lite mode */
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_lite");
	ice_lite = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Check if we need to enable ICE-TCP support (warning: still broken, for debugging only) */
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_tcp");
	ice_tcp = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Check if we need to do full-trickle instead of half-trickle */
	item = janus_config_get(config, config_nat, janus_config_type_item, "full_trickle");
	full_trickle = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Check if we should exit if a STUN or TURN server is unreachable */
	item = janus_config_get(config, config_nat, janus_config_type_item, "ignore_unreachable_ice_server");
	ignore_unreachable_ice_server = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Any STUN server to use in Janus? */
	item = janus_config_get(config, config_nat, janus_config_type_item, "stun_server");
	if(item && item->value)
		stun_server = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "stun_port");
	if(item && item->value && janus_string_to_uint16(item->value, &stun_port) < 0) {
		JANUS_LOG(LOG_WARN, "Invalid STUN port: %s (disabling STUN)\n", item->value);
		stun_server = NULL;
	}
	/* Check if we should drop mDNS candidates */
	item = janus_config_get(config, config_nat, janus_config_type_item, "ignore_mdns");
	ignore_mdns = (item && item->value) ? janus_is_true(item->value) : FALSE;
	/* Any 1:1 NAT mapping to take into account? */
	item = janus_config_get(config, config_nat, janus_config_type_item, "nat_1_1_mapping");
	if(item && item->value) {
		JANUS_LOG(LOG_INFO, "Using nat_1_1_mapping for public IP: %s\n", item->value);
		char **list = g_strsplit(item->value, ",", -1);
		char *index = list[0];
		if(index != NULL) {
			int i=0;
			while(index != NULL) {
				if(strlen(index) > 0) {
					if(!janus_network_string_is_valid_address(janus_network_query_options_any_ip, index)) {
						JANUS_LOG(LOG_WARN, "Invalid nat_1_1_mapping address %s, skipping...\n", index);
					} else {
						janus_add_public_ip(index);
					}
				}
				i++;
				index = list[i];
			}
		}
		g_strfreev(list);
		if(janus_get_public_ip_count() > 0) {
			/* Check if we should replace the private host, or advertise both candidates */
			gboolean keep_private_host = FALSE;
			item = janus_config_get(config, config_nat, janus_config_type_item, "keep_private_host");
			if(item && item->value && janus_is_true(item->value)) {
				JANUS_LOG(LOG_INFO, "  -- Going to keep the private host too (separate candidates)\n");
				keep_private_host = TRUE;
			}
			janus_ice_enable_nat_1_1(keep_private_host);
		}
	}
	/* Any TURN server to use in Janus? */
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_server");
	if(item && item->value)
		turn_server = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_port");
	if(item && item->value && janus_string_to_uint16(item->value, &turn_port) < 0) {
		JANUS_LOG(LOG_WARN, "Invalid TURN port: %s (disabling TURN)\n", item->value);
		turn_server = NULL;
	}
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_type");
	if(item && item->value)
		turn_type = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_user");
	if(item && item->value)
		turn_user = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_pwd");
	if(item && item->value)
		turn_pwd = (char *)item->value;
	/* Check if there's any TURN REST API backend to use */
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_rest_api");
	if(item && item->value)
		turn_rest_api = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_rest_api_key");
	if(item && item->value)
		turn_rest_api_key = (char *)item->value;
#ifdef HAVE_TURNRESTAPI
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_rest_api_method");
	if(item && item->value)
		turn_rest_api_method = (char *)item->value;
	item = janus_config_get(config, config_nat, janus_config_type_item, "turn_rest_api_timeout");
	if(item && item->value) {
		int rst = atoi(item->value);
		if(rst <= 0) { /* Don't allow user to set 0 seconds i.e., infinite wait */
			JANUS_LOG(LOG_WARN, "Ignoring turn_rest_api_timeout as it's not a positive integer, leaving at default (10 seconds)\n");
		} else {
			turn_rest_api_timeout = rst;
		}
	}
#endif
	item = janus_config_get(config, config_nat, janus_config_type_item, "allow_force_relay");
	if(item && item->value && janus_is_true(item->value)) {
		JANUS_LOG(LOG_WARN, "Note: applications/users will be allowed to force Janus to use TURN. Make sure you know what you're doing!\n");
		janus_ice_allow_force_relay();
	}
	/* Do we need a limited number of static event loops, or is it ok to have one per handle (the default)? */
	item = janus_config_get(config, config_general, janus_config_type_item, "event_loops");
	if(item && item->value) {
		int loops = atoi(item->value);
		/* Check if we should allow API calls to specify which loops to use for new handles */
		gboolean loops_api = FALSE;
		item = janus_config_get(config, config_general, janus_config_type_item, "allow_loop_indication");
		if(item && item->value)
			loops_api = janus_is_true(item->value);
		janus_ice_set_static_event_loops(loops, loops_api);
	}
	/* Also check if we need a cap on the size of the task pool (default is no limit) */
	int task_pool_size = -1;
	item = janus_config_get(config, config_general, janus_config_type_item, "task_pool_size");
	if(item && item->value) {
		task_pool_size = atoi(item->value);
		if(task_pool_size <= 0)
			task_pool_size = -1;
	}
	/* Initialize the ICE stack now */
	janus_ice_init(ice_lite, ice_tcp, full_trickle, ignore_mdns, ipv6, ipv6_linklocal, rtp_min_port, rtp_max_port);
	if(janus_ice_set_stun_server(stun_server, stun_port) < 0) {
		if(!ignore_unreachable_ice_server) {
			JANUS_LOG(LOG_FATAL, "Invalid STUN address %s:%u\n", stun_server, stun_port);
			janus_options_destroy();
			exit(1);
		} else {
			JANUS_LOG(LOG_ERR, "Invalid STUN address %s:%u. STUN will be disabled\n", stun_server, stun_port);
		}
	}
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_nomination");
	if(item && item->value) {
#ifndef HAVE_ICE_NOMINATION
		JANUS_LOG(LOG_WARN, "This version of libnice doesn't support setting the ICE nomination mode, ignoring '%s'\n", item->value);
#else
		janus_ice_set_nomination_mode(item->value);
#endif
	}
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_consent_freshness");
	if(item && item->value)
		janus_ice_set_consent_freshness_enabled(janus_is_true(item->value));
	item = janus_config_get(config, config_nat, janus_config_type_item, "ice_keepalive_conncheck");
	if(item && item->value)
		janus_ice_set_keepalive_conncheck_enabled(janus_is_true(item->value));
	item = janus_config_get(config, config_nat, janus_config_type_item, "hangup_on_failed");
	if(item && item->value)
		janus_ice_set_hangup_on_failed_enabled(janus_is_true(item->value));
	if(janus_ice_set_turn_server(turn_server, turn_port, turn_type, turn_user, turn_pwd) < 0) {
		if(!ignore_unreachable_ice_server) {
			JANUS_LOG(LOG_FATAL, "Invalid TURN address %s:%u\n", turn_server, turn_port);
			janus_options_destroy();
			exit(1);
		} else {
			JANUS_LOG(LOG_ERR, "Invalid TURN address %s:%u. TURN will be disabled\n", turn_server, turn_port);
		}
	}
#ifndef HAVE_TURNRESTAPI
	if(turn_rest_api != NULL || turn_rest_api_key != NULL) {
		JANUS_LOG(LOG_WARN, "A TURN REST API backend specified in the settings, but libcurl support has not been built\n");
	}
#else
	if(janus_ice_set_turn_rest_api(turn_rest_api, turn_rest_api_key, turn_rest_api_method, turn_rest_api_timeout) < 0) {
		JANUS_LOG(LOG_FATAL, "Invalid TURN REST API configuration: %s (%s, %s)\n", turn_rest_api, turn_rest_api_key, turn_rest_api_method);
		janus_options_destroy();
		exit(1);
	}
#endif
	item = janus_config_get(config, config_nat, janus_config_type_item, "nice_debug");
	if(item && item->value && janus_is_true(item->value)) {
		/* Enable libnice debugging */
		JANUS_LOG(LOG_WARN,"nice_debug option is NOT SUPPORTED ANYMORE! Please set NICE_DEBUG and G_MESSAGES_DEBUG env vars when starting Janus\n");
	}

	if(stun_server == NULL && turn_server == NULL) {
		/* No STUN and TURN server provided for Janus: make sure it isn't on a private address */
		int num_ips = janus_get_public_ip_count();
		if(num_ips == 0) {
			/* If nat_1_1_mapping is off, the first (and only) public IP is the local_ip */
			num_ips++;
		}
		/* Check each public IP */
		int i = 0;
		for(i = 0; i < num_ips; i++) {
			gboolean private_address = FALSE;
			const gchar *test_ip = janus_get_public_ip(i);
			janus_network_address addr;
			if(janus_network_string_to_address(janus_network_query_options_any_ip, test_ip, &addr) != 0) {
				JANUS_LOG(LOG_ERR, "Invalid address %s..?\n", test_ip);
			} else {
				if(addr.family == AF_INET) {
					unsigned short int ip[4];
					sscanf(test_ip, "%hu.%hu.%hu.%hu", &ip[0], &ip[1], &ip[2], &ip[3]);
					if(ip[0] == 10) {
						/* Class A private address */
						private_address = TRUE;
					} else if(ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) {
						/* Class B private address */
						private_address = TRUE;
					} else if(ip[0] == 192 && ip[1] == 168) {
						/* Class C private address */
						private_address = TRUE;
					}
				} else {
					/* TODO Similar check for IPv6... */
				}
			}
			if(private_address) {
				JANUS_LOG(LOG_WARN, "Janus is deployed on a private address (%s) but you didn't specify any STUN server!"
			                    " Expect trouble if this is supposed to work over the internet and not just in a LAN...\n", test_ip);
			}
		}
	}

	/* Is there any DSCP TOS to apply? */
	item = janus_config_get(config, config_media, janus_config_type_item, "dscp");
	if(!item || !item->value)	/* Just for backwards compatibility */
		item = janus_config_get(config, config_media, janus_config_type_item, "dscp_tos");
	if(item && item->value) {
		int dscp = atoi(item->value);
		if(dscp < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring dscp value as it's not a positive integer\n");
		} else {
			janus_set_dscp(dscp);
		}
	}

	/* NACK related stuff */
	item = janus_config_get(config, config_media, janus_config_type_item, "min_nack_queue");
	if(item && item->value) {
		int mnq = atoi(item->value);
		if(mnq < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring min_nack_queue value as it's not a positive integer\n");
		} else {
			janus_set_min_nack_queue(mnq);
		}
	}
	item = janus_config_get(config, config_media, janus_config_type_item, "nack_optimizations");
	if(item && item->value) {
		gboolean optimize = janus_is_true(item->value);
		janus_set_nack_optimizations_enabled(optimize);
	}
	/* no-media timer */
	item = janus_config_get(config, config_media, janus_config_type_item, "no_media_timer");
	if(item && item->value) {
		int nmt = atoi(item->value);
		if(nmt < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring no_media_timer value as it's not a positive integer\n");
		} else {
			janus_set_no_media_timer(nmt);
		}
	}
	/* slowlink-threshold value */
	item = janus_config_get(config, config_media, janus_config_type_item, "slowlink_threshold");
	if(item && item->value) {
		int st = atoi(item->value);
		if(st < 0) {
			JANUS_LOG(LOG_WARN, "Ignoring slowlink_threshold value as it's not a positive integer\n");
		} else {
			janus_set_slowlink_threshold(st);
		}
	}
	/* TWCC period */
	item = janus_config_get(config, config_media, janus_config_type_item, "twcc_period");
	if(item && item->value) {
		int tp = atoi(item->value);
		if(tp <= 0) {
			JANUS_LOG(LOG_WARN, "Ignoring twcc_period value as it's not a positive integer\n");
		} else {
			janus_set_twcc_period(tp);
		}
	}

	/* Setup OpenSSL stuff */
	const char *server_pem;
	item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pem");
	if(!item || !item->value) {
		server_pem = NULL;
	} else {
		server_pem = item->value;
	}
	const char *server_key;
	item = janus_config_get(config, config_certs, janus_config_type_item, "cert_key");
	if(!item || !item->value) {
		server_key = NULL;
	} else {
		server_key = item->value;
	}
	const char *password;
	item = janus_config_get(config, config_certs, janus_config_type_item, "cert_pwd");
	if(!item || !item->value) {
		password = NULL;
	} else {
		password = item->value;
	}
	JANUS_LOG(LOG_VERB, "Using certificates:\n\t%s\n\t%s\n", server_pem, server_key);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	/* Check if random pool looks ok (this does not give any guarantees for later, though) */
	if(RAND_status() != 1) {
		JANUS_LOG(LOG_FATAL, "Random pool is not properly seeded, cannot generate random numbers\n");
		janus_options_destroy();
		exit(1);
	}
	/* ... and DTLS-SRTP in particular */
	const char *dtls_ciphers = NULL;
	item = janus_config_get(config, config_certs, janus_config_type_item, "dtls_ciphers");
	if(item && item->value)
		dtls_ciphers = item->value;
	guint16 dtls_timeout = 1000;
	item = janus_config_get(config, config_media, janus_config_type_item, "dtls_timeout");
	if(item && item->value && janus_string_to_uint16(item->value, &dtls_timeout) < 0) {
		JANUS_LOG(LOG_WARN, "Invalid DTLS timeout: %s (falling back to default)\n", item->value);
		dtls_timeout = 1000;
	}
	gboolean rsa_private_key = FALSE;
	item = janus_config_get(config, config_certs, janus_config_type_item, "rsa_private_key");
	if(item && item->value)
		rsa_private_key = janus_is_true(item->value);
	gboolean dtls_accept_selfsigned = TRUE;
	item = janus_config_get(config, config_certs, janus_config_type_item, "dtls_accept_selfsigned");
	if(item && item->value)
		dtls_accept_selfsigned = janus_is_true(item->value);
	if(janus_dtls_srtp_init(server_pem, server_key, password, dtls_ciphers, dtls_timeout, rsa_private_key, dtls_accept_selfsigned) < 0) {
		janus_options_destroy();
		exit(1);
	}
	/* Check if there's any custom value for the starting MTU to use in the BIO filter */
	item = janus_config_get(config, config_media, janus_config_type_item, "dtls_mtu");
	if(item && item->value)
		janus_dtls_bio_agent_set_mtu(atoi(item->value));

#ifdef HAVE_SCTP
	/* Initialize SCTP for DataChannels */
	if(janus_sctp_init() < 0) {
		janus_options_destroy();
		exit(1);
	}
#else
	JANUS_LOG(LOG_WARN, "Data Channels support not compiled\n");
#endif

	/* Initialize the RTP forwarders functionality */
	if(janus_rtp_forwarders_init() < 0) {
		janus_options_destroy();
		exit(1);
	}

	/* Sessions */
	sessions = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	/* Start the sessions timeout watchdog */
	sessions_watchdog_context = g_main_context_new();
	GMainLoop *watchdog_loop = g_main_loop_new(sessions_watchdog_context, FALSE);
	GError *error = NULL;
	GThread *watchdog = g_thread_try_new("timeout watchdog", &janus_sessions_watchdog, watchdog_loop, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start sessions timeout watchdog...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		janus_options_destroy();
		exit(1);
	}
	/* Start the thread that will dispatch incoming requests */
	requests = g_async_queue_new_full((GDestroyNotify)janus_request_destroy);
	GThread *requests_thread = g_thread_try_new("sessions requests", &janus_transport_requests, NULL, &error);
	if(error != NULL) {
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to start requests thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		janus_options_destroy();
		exit(1);
	}
	/* Create a thread pool to handle asynchronous requests, no matter what the transport */
	error = NULL;
	tasks = g_thread_pool_new(janus_transport_task, NULL, task_pool_size, FALSE, &error);
	if(error != NULL) {
		/* Something went wrong... */
		JANUS_LOG(LOG_FATAL, "Got error %d (%s) trying to launch the request pool task thread...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		janus_options_destroy();
		exit(1);
	}
	/* Wait 120 seconds before stopping idle threads to avoid the creation of too many threads for AddressSanitizer. */
	g_thread_pool_set_max_idle_time(120 * 1000);

	/* Load event handlers */
	path = NULL;
	dir = NULL;
	/* Event handlers are disabled by default, though: they need to be enabled in the configuration */
	item = janus_config_get(config, config_events, janus_config_type_item, "broadcast");
	gboolean enable_events = FALSE;
	if(item && item->value)
		enable_events = janus_is_true(item->value);
	if(!enable_events) {
		JANUS_LOG(LOG_INFO, "Event handlers support disabled\n");
	} else {
		gchar **disabled_eventhandlers = NULL;
		path = EVENTDIR;
		item = janus_config_get(config, config_general, janus_config_type_item, "events_folder");
		if(item && item->value)
			path = (char *)item->value;
		JANUS_LOG(LOG_INFO, "Event handler plugins folder: %s\n", path);
		dir = opendir(path);
		if(!dir) {
			/* Not really fatal, we don't care and go on anyway: event handlers are not fundamental */
			JANUS_LOG(LOG_WARN, "\tCouldn't access event handler plugins folder...\n");
		} else {
			item = janus_config_get(config, config_events, janus_config_type_item, "stats_period");
			if(item && item->value) {
				/* Check if we need to use a larger period for pushing statistics to event handlers */
				int period = atoi(item->value);
				if(period < 0) {
					JANUS_LOG(LOG_WARN, "Invalid event handlers statistics period, using default value (1 second)\n");
				} else if(period == 0) {
					janus_ice_set_event_stats_period(0);
					JANUS_LOG(LOG_WARN, "Disabling event handlers statistics period, no media statistics will be pushed to event handlers\n");
				} else {
					janus_ice_set_event_stats_period(period);
					JANUS_LOG(LOG_INFO, "Setting event handlers statistics period to %d seconds\n", period);
				}
			}
			item = janus_config_get(config, config_events, janus_config_type_item, "combine_media_stats");
			if(item && item->value) {
				gboolean combine = janus_is_true(item->value);
				janus_ice_event_set_combine_media_stats(combine);
				if(combine)
					JANUS_LOG(LOG_INFO, "Event handler configured to send media stats combined in a single event\n");
			}
			/* Any event handlers to ignore? */
			item = janus_config_get(config, config_events, janus_config_type_item, "disable");
			if(item && item->value)
				disabled_eventhandlers = g_strsplit(item->value, ",", -1);
			/* Open the shared objects */
			struct dirent *eventent = NULL;
			char eventpath[1024];
			while((eventent = readdir(dir))) {
				int len = strlen(eventent->d_name);
				if (len < 4) {
					continue;
				}
				if (strcasecmp(eventent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
					continue;
				}
				/* Check if this event handler has been disabled in the configuration file */
				if(disabled_eventhandlers != NULL) {
					gchar *index = disabled_eventhandlers[0];
					if(index != NULL) {
						int i=0;
						gboolean skip = FALSE;
						while(index != NULL) {
							while(isspace(*index))
								index++;
							if(strlen(index) && !strcmp(index, eventent->d_name)) {
								JANUS_LOG(LOG_WARN, "Event handler plugin '%s' has been disabled, skipping...\n", eventent->d_name);
								skip = TRUE;
								break;
							}
							i++;
							index = disabled_eventhandlers[i];
						}
						if(skip)
							continue;
					}
				}
				JANUS_LOG(LOG_INFO, "Loading event handler plugin '%s'...\n", eventent->d_name);
				memset(eventpath, 0, 1024);
				g_snprintf(eventpath, 1024, "%s/%s", path, eventent->d_name);
				void *event = dlopen(eventpath, RTLD_NOW | RTLD_GLOBAL);
				if(!event) {
					JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load event handler plugin '%s': %s\n", eventent->d_name, dlerror());
					if(exit_on_dl_error) {
						janus_options_destroy();
						exit(1);
					}
				} else {
					create_e *create = (create_e*) dlsym(event, "create");
					const char *dlsym_error = dlerror();
					if(dlsym_error) {
						JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
						if(exit_on_dl_error) {
							janus_options_destroy();
							exit(1);
						}
						continue;
					}
					janus_eventhandler *janus_eventhandler = create();
					if(!janus_eventhandler) {
						JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
						continue;
					}
					/* Are all the mandatory methods and callbacks implemented? */
					if(!janus_eventhandler->init || !janus_eventhandler->destroy ||
							!janus_eventhandler->get_api_compatibility ||
							!janus_eventhandler->get_version ||
							!janus_eventhandler->get_version_string ||
							!janus_eventhandler->get_description ||
							!janus_eventhandler->get_package ||
							!janus_eventhandler->get_name ||
							!janus_eventhandler->incoming_event) {
						JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this event handler plugin...\n");
						continue;
					}
					if(janus_eventhandler->get_api_compatibility() < JANUS_EVENTHANDLER_API_VERSION) {
						JANUS_LOG(LOG_ERR, "The '%s' event handler plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
							janus_eventhandler->get_package(), janus_eventhandler->get_api_compatibility(), JANUS_EVENTHANDLER_API_VERSION);
						continue;
					}
					janus_eventhandler->init(configs_folder);
					JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_eventhandler->get_version(), janus_eventhandler->get_version_string());
					JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_eventhandler->get_package(), janus_eventhandler->get_name());
					JANUS_LOG(LOG_VERB, "\t   %s\n", janus_eventhandler->get_description());
					JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_eventhandler->get_api_compatibility());
					JANUS_LOG(LOG_VERB, "\t   Subscriptions:");
					if(janus_eventhandler->events_mask == 0) {
						JANUS_LOG(LOG_VERB, " none");
					} else {
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_SESSION))
							JANUS_LOG(LOG_VERB, " sessions");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_HANDLE))
							JANUS_LOG(LOG_VERB, " handles");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_JSEP))
							JANUS_LOG(LOG_VERB, " jsep");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_WEBRTC))
							JANUS_LOG(LOG_VERB, " webrtc");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_MEDIA))
							JANUS_LOG(LOG_VERB, " media");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_PLUGIN))
							JANUS_LOG(LOG_VERB, " plugins");
						if(janus_flags_is_set(&janus_eventhandler->events_mask, JANUS_EVENT_TYPE_TRANSPORT))
							JANUS_LOG(LOG_VERB, " transports");
					}
					JANUS_LOG(LOG_VERB, "\n");
					if(eventhandlers == NULL)
						eventhandlers = g_hash_table_new(g_str_hash, g_str_equal);
					g_hash_table_insert(eventhandlers, (gpointer)janus_eventhandler->get_package(), janus_eventhandler);
					if(eventhandlers_so == NULL)
						eventhandlers_so = g_hash_table_new(g_str_hash, g_str_equal);
					g_hash_table_insert(eventhandlers_so, (gpointer)janus_eventhandler->get_package(), event);
				}
			}
			closedir(dir);
		}
		if(disabled_eventhandlers != NULL)
			g_strfreev(disabled_eventhandlers);
		disabled_eventhandlers = NULL;
		/* Initialize the event broadcaster */
		if(janus_events_init(enable_events, (server_name ? server_name : (char *)JANUS_SERVER_NAME), eventhandlers) < 0) {
			JANUS_LOG(LOG_FATAL, "Error initializing the Event handlers mechanism...\n");
			janus_options_destroy();
			exit(1);
		}
		/* Send a status event every once in a while */
		GSource *timeout_source = g_timeout_source_new_seconds(15);
		g_source_set_callback(timeout_source, janus_status_sessions, sessions_watchdog_context, NULL);
		g_source_attach(timeout_source, sessions_watchdog_context);
		g_source_unref(timeout_source);
	}

	/* Load plugins */
	path = PLUGINDIR;
	item = janus_config_get(config, config_general, janus_config_type_item, "plugins_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Plugins folder: %s\n", path);
	dir = opendir(path);
	if(!dir) {
		JANUS_LOG(LOG_FATAL, "\tCouldn't access plugins folder...\n");
		janus_options_destroy();
		exit(1);
	}
	/* Any plugin to ignore? */
	gchar **disabled_plugins = NULL;
	item = janus_config_get(config, config_plugins, janus_config_type_item, "disable");
	if(item && item->value)
		disabled_plugins = g_strsplit(item->value, ",", -1);
	/* Open the shared objects */
	struct dirent *pluginent = NULL;
	char pluginpath[1024];
	while((pluginent = readdir(dir))) {
		int len = strlen(pluginent->d_name);
		if (len < 4) {
			continue;
		}
		if (strcasecmp(pluginent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
			continue;
		}
		/* Check if this plugins has been disabled in the configuration file */
		if(disabled_plugins != NULL) {
			gchar *index = disabled_plugins[0];
			if(index != NULL) {
				int i=0;
				gboolean skip = FALSE;
				while(index != NULL) {
					while(isspace(*index))
						index++;
					if(strlen(index) && !strcmp(index, pluginent->d_name)) {
						JANUS_LOG(LOG_WARN, "Plugin '%s' has been disabled, skipping...\n", pluginent->d_name);
						skip = TRUE;
						break;
					}
					i++;
					index = disabled_plugins[i];
				}
				if(skip)
					continue;
			}
		}
		JANUS_LOG(LOG_INFO, "Loading plugin '%s'...\n", pluginent->d_name);
		memset(pluginpath, 0, 1024);
		g_snprintf(pluginpath, 1024, "%s/%s", path, pluginent->d_name);
		void *plugin = dlopen(pluginpath, RTLD_NOW | RTLD_GLOBAL);
		if(!plugin) {
			JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load plugin '%s': %s\n", pluginent->d_name, dlerror());
			if(exit_on_dl_error) {
				janus_options_destroy();
				exit(1);
			}
		} else {
			create_p *create = (create_p*) dlsym(plugin, "create");
			const char *dlsym_error = dlerror();
			if(dlsym_error) {
				JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
				if(exit_on_dl_error) {
					janus_options_destroy();
					exit(1);
				}
				continue;
			}
			janus_plugin *janus_plugin = create();
			if(!janus_plugin) {
				JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
				continue;
			}
			/* Are all the mandatory methods and callbacks implemented? */
			if(!janus_plugin->init || !janus_plugin->destroy ||
					!janus_plugin->get_api_compatibility ||
					!janus_plugin->get_version ||
					!janus_plugin->get_version_string ||
					!janus_plugin->get_description ||
					!janus_plugin->get_package ||
					!janus_plugin->get_name ||
					!janus_plugin->create_session ||
					!janus_plugin->query_session ||
					!janus_plugin->destroy_session ||
					!janus_plugin->handle_message ||
					!janus_plugin->setup_media ||
					!janus_plugin->hangup_media) {
				JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this plugin...\n");
				continue;
			}
			if(janus_plugin->get_api_compatibility() < JANUS_PLUGIN_API_VERSION) {
				JANUS_LOG(LOG_ERR, "The '%s' plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
					janus_plugin->get_package(), janus_plugin->get_api_compatibility(), JANUS_PLUGIN_API_VERSION);
				continue;
			}
			if(janus_plugin->init(&janus_handler_plugin, configs_folder) < 0) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin could not be initialized\n", janus_plugin->get_package());
				dlclose(plugin);
				continue;
			}
			JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_plugin->get_version(), janus_plugin->get_version_string());
			JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_plugin->get_package(), janus_plugin->get_name());
			JANUS_LOG(LOG_VERB, "\t   %s\n", janus_plugin->get_description());
			JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_plugin->get_api_compatibility());
			if(!janus_plugin->incoming_rtp && !janus_plugin->incoming_rtcp && !janus_plugin->incoming_data) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin doesn't implement any callback for RTP/RTCP/data... is this on purpose?\n",
					janus_plugin->get_package());
			}
			if(!janus_plugin->incoming_rtp && !janus_plugin->incoming_rtcp && janus_plugin->incoming_data) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin will only handle data channels (no RTP/RTCP)... is this on purpose?\n",
					janus_plugin->get_package());
			}
			if(plugins == NULL)
				plugins = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins, (gpointer)janus_plugin->get_package(), janus_plugin);
			if(plugins_so == NULL)
				plugins_so = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(plugins_so, (gpointer)janus_plugin->get_package(), plugin);
		}
	}
	closedir(dir);
	if(disabled_plugins != NULL)
		g_strfreev(disabled_plugins);
	disabled_plugins = NULL;

	/* Load transports */
	gboolean janus_api_enabled = FALSE, admin_api_enabled = FALSE;
	path = TRANSPORTDIR;
	item = janus_config_get(config, config_general, janus_config_type_item, "transports_folder");
	if(item && item->value)
		path = (char *)item->value;
	JANUS_LOG(LOG_INFO, "Transport plugins folder: %s\n", path);
	dir = opendir(path);
	if(!dir) {
		JANUS_LOG(LOG_FATAL, "\tCouldn't access transport plugins folder...\n");
		janus_options_destroy();
		exit(1);
	}
	/* Any transport to ignore? */
	gchar **disabled_transports = NULL;
	item = janus_config_get(config, config_transports, janus_config_type_item, "disable");
	if(item && item->value)
		disabled_transports = g_strsplit(item->value, ",", -1);
	/* Open the shared objects */
	struct dirent *transportent = NULL;
	char transportpath[1024];
	while((transportent = readdir(dir))) {
		int len = strlen(transportent->d_name);
		if (len < 4) {
			continue;
		}
		if (strcasecmp(transportent->d_name+len-strlen(SHLIB_EXT), SHLIB_EXT)) {
			continue;
		}
		/* Check if this transports has been disabled in the configuration file */
		if(disabled_transports != NULL) {
			gchar *index = disabled_transports[0];
			if(index != NULL) {
				int i=0;
				gboolean skip = FALSE;
				while(index != NULL) {
					while(isspace(*index))
						index++;
					if(strlen(index) && !strcmp(index, transportent->d_name)) {
						JANUS_LOG(LOG_WARN, "Transport plugin '%s' has been disabled, skipping...\n", transportent->d_name);
						skip = TRUE;
						break;
					}
					i++;
					index = disabled_transports[i];
				}
				if(skip)
					continue;
			}
		}
		JANUS_LOG(LOG_INFO, "Loading transport plugin '%s'...\n", transportent->d_name);
		memset(transportpath, 0, 1024);
		g_snprintf(transportpath, 1024, "%s/%s", path, transportent->d_name);
		void *transport = dlopen(transportpath, RTLD_NOW | RTLD_GLOBAL);
		if(!transport) {
			JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load transport plugin '%s': %s\n", transportent->d_name, dlerror());
			if(exit_on_dl_error) {
				janus_options_destroy();
				exit(1);
			}
		} else {
			create_t *create = (create_t*) dlsym(transport, "create");
			const char *dlsym_error = dlerror();
			if(dlsym_error) {
				JANUS_LOG(exit_on_dl_error ? LOG_FATAL : LOG_ERR, "\tCouldn't load symbol 'create': %s\n", dlsym_error);
				if(exit_on_dl_error) {
					janus_options_destroy();
					exit(1);
				}
				continue;
			}
			janus_transport *janus_transport = create();
			if(!janus_transport) {
				JANUS_LOG(LOG_ERR, "\tCouldn't use function 'create'...\n");
				continue;
			}
			/* Are all the mandatory methods and callbacks implemented? */
			if(!janus_transport->init || !janus_transport->destroy ||
					!janus_transport->get_api_compatibility ||
					!janus_transport->get_version ||
					!janus_transport->get_version_string ||
					!janus_transport->get_description ||
					!janus_transport->get_package ||
					!janus_transport->get_name ||
					!janus_transport->send_message ||
					!janus_transport->is_janus_api_enabled ||
					!janus_transport->is_admin_api_enabled ||
					!janus_transport->session_created ||
					!janus_transport->session_over ||
					!janus_transport->session_claimed) {
				JANUS_LOG(LOG_ERR, "\tMissing some mandatory methods/callbacks, skipping this transport plugin...\n");
				continue;
			}
			if(janus_transport->get_api_compatibility() < JANUS_TRANSPORT_API_VERSION) {
				JANUS_LOG(LOG_ERR, "The '%s' transport plugin was compiled against an older version of the API (%d < %d), skipping it: update it to enable it again\n",
					janus_transport->get_package(), janus_transport->get_api_compatibility(), JANUS_TRANSPORT_API_VERSION);
				continue;
			}
			if(janus_transport->init(&janus_handler_transport, configs_folder) < 0) {
				JANUS_LOG(LOG_WARN, "The '%s' plugin could not be initialized\n", janus_transport->get_package());
				dlclose(transport);
				continue;
			}
			JANUS_LOG(LOG_VERB, "\tVersion: %d (%s)\n", janus_transport->get_version(), janus_transport->get_version_string());
			JANUS_LOG(LOG_VERB, "\t   [%s] %s\n", janus_transport->get_package(), janus_transport->get_name());
			JANUS_LOG(LOG_VERB, "\t   %s\n", janus_transport->get_description());
			JANUS_LOG(LOG_VERB, "\t   Plugin API version: %d\n", janus_transport->get_api_compatibility());
			JANUS_LOG(LOG_VERB, "\t   Janus API: %s\n", janus_transport->is_janus_api_enabled() ? "enabled" : "disabled");
			JANUS_LOG(LOG_VERB, "\t   Admin API: %s\n", janus_transport->is_admin_api_enabled() ? "enabled" : "disabled");
			janus_api_enabled = janus_api_enabled || janus_transport->is_janus_api_enabled();
			admin_api_enabled = admin_api_enabled || janus_transport->is_admin_api_enabled();
			if(transports == NULL)
				transports = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(transports, (gpointer)janus_transport->get_package(), janus_transport);
			if(transports_so == NULL)
				transports_so = g_hash_table_new(g_str_hash, g_str_equal);
			g_hash_table_insert(transports_so, (gpointer)janus_transport->get_package(), transport);
		}
	}
	closedir(dir);
	if(disabled_transports != NULL)
		g_strfreev(disabled_transports);
	disabled_transports = NULL;
	/* Make sure at least a Janus API transport is available */
	if(!janus_api_enabled) {
		JANUS_LOG(LOG_FATAL, "No Janus API transport is available... enable at least one and restart Janus\n");
		janus_options_destroy();
		exit(1);	/* FIXME Should we really give up? */
	}
	/* Make sure at least an admin API transport is available, if the auth mechanism is enabled */
	if(!admin_api_enabled && janus_auth_is_stored_mode()) {
		JANUS_LOG(LOG_FATAL, "No Admin/monitor transport is available, but the stored token based authentication mechanism is enabled... this will cause all requests to fail, giving up! If you want to use tokens, enable the Admin/monitor API or set the token auth secret.\n");
		janus_options_destroy();
		exit(1);	/* FIXME Should we really give up? */
	}

	/* Make sure libnice is recent enough, otherwise print a warning */
	int libnice_version = 0;
	if(libnice_version_string != NULL && sscanf(libnice_version_string, "%*d.%*d.%d", &libnice_version) == 1) {
		if(libnice_version < 16) {
			JANUS_LOG(LOG_WARN, "libnice version outdated: %s installed, at least 0.1.16 recommended. Notice the installed version was checked at build time: if you updated libnice in the meanwhile, re-configure and recompile to get rid of this warning\n",
				libnice_version_string);
		}
	}

	/* Ok, Janus has started! Let the parent now about this if we're daemonizing */
	if(daemonize) {
		int code = 0;
		ssize_t res = 0;
		do {
			res = write(pipefd[1], &code, sizeof(int));
		} while(res == -1 && errno == EINTR);
	}

	/* If the Event Handlers mechanism is enabled, notify handlers that Janus just started */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "status", json_string("started"));
		json_object_set_new(info, "info", janus_info(NULL));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_CORE, JANUS_EVENT_SUBTYPE_CORE_STARTUP, 0, info);
	}

	/* Loop until we have to stop */
	mainloop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run(mainloop);

	/* If the Event Handlers mechanism is enabled, notify handlers that Janus is hanging up */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "status", json_string("shutdown"));
		json_object_set_new(info, "signum", json_integer(stop_signal));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_CORE, JANUS_EVENT_SUBTYPE_CORE_SHUTDOWN, 0, info);
	}

	/* Done */
	JANUS_LOG(LOG_INFO, "Ending sessions timeout watchdog...\n");
	g_main_loop_quit(watchdog_loop);
	g_thread_join(watchdog);
	watchdog = NULL;
	g_main_loop_unref(watchdog_loop);
	g_main_context_unref(sessions_watchdog_context);
	sessions_watchdog_context = NULL;

	if(config)
		janus_config_destroy(config);

	JANUS_LOG(LOG_INFO, "Closing transport plugins:\n");
	if(transports != NULL && g_hash_table_size(transports) > 0) {
		g_hash_table_foreach(transports, janus_transport_close, NULL);
		g_clear_pointer(&transports, g_hash_table_destroy);
	}
	if(transports_so != NULL && g_hash_table_size(transports_so) > 0) {
		g_hash_table_foreach(transports_so, janus_transportso_close, NULL);
		g_clear_pointer(&transports_so, g_hash_table_destroy);
	}
	/* Get rid of requests tasks and thread too */
	g_thread_pool_free(tasks, FALSE, FALSE);
	JANUS_LOG(LOG_INFO, "Ending requests thread...\n");
	g_async_queue_push(requests, &exit_message);
	g_thread_join(requests_thread);
	requests_thread = NULL;
	g_async_queue_unref(requests);

	JANUS_LOG(LOG_INFO, "Destroying sessions...\n");
	g_clear_pointer(&sessions, g_hash_table_destroy);
	janus_ice_deinit();
	JANUS_LOG(LOG_INFO, "Freeing crypto resources...\n");
	janus_dtls_srtp_cleanup();
	EVP_cleanup();
	ERR_free_strings();
#ifdef HAVE_SCTP
	JANUS_LOG(LOG_INFO, "De-initializing SCTP...\n");
	janus_sctp_deinit();
#endif
	janus_rtp_forwarders_deinit();
	janus_auth_deinit();

	JANUS_LOG(LOG_INFO, "Closing plugins:\n");
	if(plugins != NULL && g_hash_table_size(plugins) > 0) {
		g_hash_table_foreach(plugins, janus_plugin_close, NULL);
		g_clear_pointer(&plugins, g_hash_table_destroy);
	}
	if(plugins_so != NULL && g_hash_table_size(plugins_so) > 0) {
		g_hash_table_foreach(plugins_so, janus_pluginso_close, NULL);
		g_clear_pointer(&plugins_so, g_hash_table_destroy);
	}

	JANUS_LOG(LOG_INFO, "Closing event handlers:\n");
	janus_events_deinit();
	if(eventhandlers != NULL && g_hash_table_size(eventhandlers) > 0) {
		g_hash_table_foreach(eventhandlers, janus_eventhandler_close, NULL);
		g_clear_pointer(&eventhandlers, g_hash_table_destroy);
	}
	if(eventhandlers_so != NULL && g_hash_table_size(eventhandlers_so) > 0) {
		g_hash_table_foreach(eventhandlers_so, janus_eventhandlerso_close, NULL);
		g_clear_pointer(&eventhandlers_so, g_hash_table_destroy);
	}

	janus_recorder_deinit();
	g_free(local_ip);
	if (public_ips) {
		g_list_free(public_ips);
	}
	if (public_ips_table) {
		g_clear_pointer(&public_ips_table, g_hash_table_destroy);
	}

	if(janus_ice_get_static_event_loops() > 0)
		janus_ice_stop_static_event_loops();

	janus_protected_folders_clear();

#ifdef REFCOUNT_DEBUG
	/* Any reference counters that are still up while we're leaving? (debug-mode only) */
	janus_mutex_lock(&counters_mutex);
	if(counters && g_hash_table_size(counters) > 0) {
		JANUS_PRINT("Debugging reference counters: %d still allocated\n", g_hash_table_size(counters));
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, counters);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			JANUS_PRINT("  -- %p\n", value);
		}
	} else {
		JANUS_PRINT("Debugging reference counters: 0 still allocated\n");
	}
	janus_mutex_unlock(&counters_mutex);
#endif
	g_clear_pointer(&janus_log_global_prefix, g_free);

	janus_options_destroy();
	JANUS_PRINT("Bye!\n");

	exit(0);
}
