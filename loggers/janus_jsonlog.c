/*! \file   janus_jsonlog.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus JSON logger plugin
 * \details  This is a trivial logger plugin for Janus, which is only
 * there to showcase how you can implement your own external logger for
 * log lines coming from the Janus core or one of the plugins. This
 * specific logger plugin serializes log lines to a JSON object and
 * saves them all to a configured local file.
 *
 * \ingroup loggers
 * \ref loggers
 */

#include "logger.h"

#include "../debug.h"
#include "../config.h"
#include "../mutex.h"
#include "../utils.h"


/* Plugin information */
#define JANUS_JSONLOG_VERSION			1
#define JANUS_JSONLOG_VERSION_STRING	"0.0.1"
#define JANUS_JSONLOG_DESCRIPTION		"This is a trivial sample logger plugin for Janus, which saves log lines to a local JSON file."
#define JANUS_JSONLOG_NAME				"JANUS JSON logger plugin"
#define JANUS_JSONLOG_AUTHOR			"Meetecho s.r.l."
#define JANUS_JSONLOG_PACKAGE			"janus.logger.jsonlog"

/* Plugin methods */
janus_logger *create(void);
int janus_jsonlog_init(const char *server_name, const char *config_path);
void janus_jsonlog_destroy(void);
int janus_jsonlog_get_api_compatibility(void);
int janus_jsonlog_get_version(void);
const char *janus_jsonlog_get_version_string(void);
const char *janus_jsonlog_get_description(void);
const char *janus_jsonlog_get_name(void);
const char *janus_jsonlog_get_author(void);
const char *janus_jsonlog_get_package(void);
void janus_jsonlog_incoming_logline(int64_t timestamp, const char *line);
json_t *janus_jsonlog_handle_request(json_t *request);

/* Logger setup */
static janus_logger janus_jsonlog =
	JANUS_LOGGER_INIT (
		.init = janus_jsonlog_init,
		.destroy = janus_jsonlog_destroy,

		.get_api_compatibility = janus_jsonlog_get_api_compatibility,
		.get_version = janus_jsonlog_get_version,
		.get_version_string = janus_jsonlog_get_version_string,
		.get_description = janus_jsonlog_get_description,
		.get_name = janus_jsonlog_get_name,
		.get_author = janus_jsonlog_get_author,
		.get_package = janus_jsonlog_get_package,

		.incoming_logline = janus_jsonlog_incoming_logline,
		.handle_request = janus_jsonlog_handle_request,
	);

/* Plugin creator */
janus_logger *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_JSONLOG_NAME);
	return &janus_jsonlog;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static GThread *logger_thread;
static void *janus_jsonlog_thread(void *data);
static janus_mutex logger_mutex;

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* Queue of log lines to handle */
static GAsyncQueue *loglines = NULL;

/* Structure we use for queueing log lines */
typedef struct janus_jsonlog_line {
	int64_t timestamp;		/* When the log line was printed */
	char *line;				/* Content of the log line */
} janus_jsonlog_line;
static janus_jsonlog_line exit_line;
static void janus_jsonlog_line_free(janus_jsonlog_line *jline) {
	if(!jline || jline == &exit_line)
		return;
	g_free(jline->line);
	g_free(jline);
}

/* File to save the log to */
static FILE *logfile = NULL;
static char *logfilename = NULL;


/* Parameter validation (for querying or tweaking via Admin API) */
static struct janus_json_parameter request_parameters[] = {
	{"request", JSON_STRING, JANUS_JSON_PARAM_REQUIRED}
};
/* Error codes for the Admin API interaction */
#define JANUS_JSONLOG_ERROR_INVALID_REQUEST		411
#define JANUS_JSONLOG_ERROR_MISSING_ELEMENT		412
#define JANUS_JSONLOG_ERROR_INVALID_ELEMENT		413
#define JANUS_JSONLOG_ERROR_UNKNOWN_ERROR		499


/* Plugin implementation */
int janus_jsonlog_init(const char *server_name, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	gboolean enabled = FALSE;
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.jcfg", config_path, JANUS_JSONLOG_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config == NULL) {
		JANUS_LOG(LOG_WARN, "Couldn't find .jcfg configuration file (%s), trying .cfg\n", JANUS_JSONLOG_PACKAGE);
		g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_JSONLOG_PACKAGE);
		JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
		config = janus_config_parse(filename);
	}
	if(config != NULL) {
		/* Handle configuration */
		janus_config_print(config);
		janus_config_category *config_general = janus_config_get_create(config, NULL, janus_config_type_category, "general");

		/* Setup the logger, if required */
		janus_config_item *item = janus_config_get(config, config_general, janus_config_type_item, "enabled");
		if(!item || !item->value || !janus_is_true(item->value)) {
			JANUS_LOG(LOG_WARN, "JSON logger disabled\n");
		} else {
			/* File to save log to */
			item = janus_config_get(config, config_general, janus_config_type_item, "filename");
			if(!item || !item->value) {
				JANUS_LOG(LOG_WARN, "No filename for the JSON logger specified\n");
			} else {
				logfilename = g_strdup(item->value);
				logfile = fopen(logfilename, "a");
				if(logfile == NULL) {
					JANUS_LOG(LOG_FATAL, "Error opening file '%s' (%d, %s)\n",
						logfilename, errno, strerror(errno));
				}
			}

			/* Check the JSON indentation */
			item = janus_config_get(config, config_general, janus_config_type_item, "json");
			if(item && item->value) {
				/* Check how we need to format/serialize the JSON output */
				if(!strcasecmp(item->value, "indented")) {
					/* Default: indented, we use three spaces for that */
					json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
				} else if(!strcasecmp(item->value, "plain")) {
					/* Not indented and no new lines, but still readable */
					json_format = JSON_INDENT(0) | JSON_PRESERVE_ORDER;
				} else if(!strcasecmp(item->value, "compact")) {
					/* Compact, so no spaces between separators */
					json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;
				} else {
					JANUS_LOG(LOG_WARN, "Unsupported JSON format option '%s', using default (indented)\n", item->value);
					json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;
				}
			}
			/* Done */
			enabled = (logfile != NULL);
		}
	}

	janus_config_destroy(config);
	config = NULL;
	if(!enabled) {
		return -1;	/* No point in keeping the plugin loaded */
	}
	JANUS_LOG(LOG_VERB, "JSON logger configured: %s\n", logfilename);

	/* Initialize the log queue */
	loglines = g_async_queue_new_full((GDestroyNotify) janus_jsonlog_line_free);
	janus_mutex_init(&logger_mutex);

	g_atomic_int_set(&initialized, 1);

	/* Launch the thread that will handle incoming log lines */
	GError *error = NULL;
	logger_thread = g_thread_try_new("janus jsonlog thread", janus_jsonlog_thread, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the JSON logger thread...\n",
			error->code, error->message ? error->message : "??");
		return -1;
	}
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_JSONLOG_NAME);
	return 0;
}

void janus_jsonlog_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(loglines, &exit_line);
	if(logger_thread != NULL) {
		g_thread_join(logger_thread);
		logger_thread = NULL;
	}

	g_async_queue_unref(loglines);
	loglines = NULL;

	if(logfile != NULL) {
		fflush(logfile);
		fclose(logfile);
	}
	g_free(logfilename);

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_JSONLOG_NAME);
}

int janus_jsonlog_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_LOGGER_API_VERSION;
}

int janus_jsonlog_get_version(void) {
	return JANUS_JSONLOG_VERSION;
}

const char *janus_jsonlog_get_version_string(void) {
	return JANUS_JSONLOG_VERSION_STRING;
}

const char *janus_jsonlog_get_description(void) {
	return JANUS_JSONLOG_DESCRIPTION;
}

const char *janus_jsonlog_get_name(void) {
	return JANUS_JSONLOG_NAME;
}

const char *janus_jsonlog_get_author(void) {
	return JANUS_JSONLOG_AUTHOR;
}

const char *janus_jsonlog_get_package(void) {
	return JANUS_JSONLOG_PACKAGE;
}

void janus_jsonlog_incoming_logline(int64_t timestamp, const char *line) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized) || line == NULL) {
		/* Janus is closing or the plugin is */
		return;
	}

	/* Do NOT handle the log line here in this callback! Since Janus sends
	 * log lines from its internal logger thread, performing I/O or network
	 * operations in here could dangerously slow Janus down. Let's just
	 * duplicate and enqueue the string containing the log line, and handle
	 * it in our own thread: we have a monotonic time indicator of when the
	 * log line was actually added on this machine, so that, if relevant, we can
	 * compute any delay in the actual log line processing ourselves. */
	janus_jsonlog_line *l = g_malloc(sizeof(janus_jsonlog_line));
	l->timestamp = timestamp;
	l->line = g_strdup(line);
	g_async_queue_push(loglines, l);

}

json_t *janus_jsonlog_handle_request(json_t *request) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}
	/* We can use this requests to query the plugin or apply tweaks to the logic */
	json_t *response = json_object();
	int error_code = 0;
	char error_cause[512];
	JANUS_VALIDATE_JSON_OBJECT(request, request_parameters,
		error_code, error_cause, TRUE,
		JANUS_JSONLOG_ERROR_MISSING_ELEMENT, JANUS_JSONLOG_ERROR_INVALID_ELEMENT);
	if(error_code != 0)
		goto plugin_response;
	/* Get the request */
	const char *request_text = json_string_value(json_object_get(request, "request"));
	if(!strcasecmp(request_text, "info")) {
		/* We only support a request to get some info from the plugin */
		json_object_set_new(response, "result", json_integer(200));
	} else {
		JANUS_LOG(LOG_VERB, "Unknown request '%s'\n", request_text);
		error_code = JANUS_JSONLOG_ERROR_INVALID_REQUEST;
		g_snprintf(error_cause, 512, "Unknown request '%s'", request_text);
	}

plugin_response:
		{
			if(error_code != 0) {
				/* Prepare JSON error event */
				json_object_set_new(response, "error_code", json_integer(error_code));
				json_object_set_new(response, "error", json_string(error_cause));
			}
			return response;
		}
}

/* Thread to handle incoming log lines */
static void *janus_jsonlog_thread(void *data) {
	JANUS_LOG(LOG_VERB, "Joining JSON logger thread\n");

	janus_jsonlog_line *jline = NULL;
	json_t *json = NULL;
	char *json_text = NULL;
	size_t json_len = 0, offset = 0, written = 0;

	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		/* Get a log line from the queue */
		jline = g_async_queue_pop(loglines);
		if(jline == NULL)
			continue;
		if(jline == &exit_line)
			break;

		/* Create a new JSON object with its contents */
		json = json_object();
		json_object_set_new(json, "timestamp", json_integer(jline->timestamp));
		if(jline->line != NULL)
			json_object_set_new(json, "line", json_string(jline->line));
		janus_jsonlog_line_free(jline);

		/* Convert the JSON object to string */
		json_text = json_dumps(json, json_format);
		json_decref(json);

		/* Save it to file */
		json_len = strlen(json_text);
		offset = 0;
		while(json_len > 0) {
			written = fwrite(json_text + offset, sizeof(char), json_len, logfile);
			json_len -= written;
			offset += written;
		}
		fwrite("\n", sizeof(char), sizeof("\n"), logfile);
		fflush(logfile);
		free(json_text);
	}
	JANUS_LOG(LOG_VERB, "Leaving JSON logger thread\n");
	return NULL;
}
