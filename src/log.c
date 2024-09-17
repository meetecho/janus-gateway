/*! \file     log.c
 * \author    Jay Ridgeway <jayridge@gmail.com>
 * \copyright GNU General Public License v3
 * \brief     Buffered logging
 * \details   Implementation of a simple buffered logger designed to remove
 * I/O wait from threads that may be sensitive to such delays. Each time
 * there's stuff to be written (to stdout, log files, or external loggers),
 * it's added to an async queue, which is consumed from a dedicated thread
 * that then actually takes care of I/O.
 *
 * \ingroup core
 * \ref core
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "debug.h"
#include "utils.h"
#include "loggers/logger.h"

#define THREAD_NAME "log"

typedef struct janus_log_buffer {
	int64_t timestamp;
	size_t allocated;
	char *str;
} janus_log_buffer;
static janus_log_buffer exit_message;
static void janus_log_buffer_free(janus_log_buffer *b) {
	if(b == NULL || b == &exit_message)
		return;
	g_free(b->str);
	g_free(b);
}

static GAsyncQueue *janus_log_queue = NULL;
static GThread *log_thread = NULL;

static gboolean janus_log_console = TRUE;
static char *janus_log_filepath = NULL;
static FILE *janus_log_file = NULL;

static GHashTable *external_loggers = NULL;

static volatile gint initialized = 0;
static gint stopping = 0;

gboolean janus_log_is_stdout_enabled(void) {
	return janus_log_console;
}

gboolean janus_log_is_logfile_enabled(void) {
	return janus_log_file != NULL;
}

char *janus_log_get_logfile_path(void) {
	return janus_log_filepath;
}

static void janus_log_print_buffer(janus_log_buffer *b) {
	if(janus_log_console)
		fputs(b->str, stdout);
	if(janus_log_file)
		fputs(b->str, janus_log_file);
	if(external_loggers != NULL) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, external_loggers);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			janus_logger *l = value;
			if(l == NULL)
				continue;
			l->incoming_logline(b->timestamp, b->str);
		}
	}
	/* Flush the buffers */
	if(janus_log_console)
		fflush(stdout);
	if(janus_log_file)
		fflush(janus_log_file);
}

static void *janus_log_thread(void *ctx) {
	janus_log_buffer *b = NULL;

	while(!g_atomic_int_get(&stopping)) {
		b = g_async_queue_pop(janus_log_queue);
		if(b == NULL || b == &exit_message)
			break;
		if(b->str == NULL) {
			janus_log_buffer_free(b);
			continue;
		}
		/* We have something to log */
		janus_log_print_buffer(b);
		/* Done, get rid of this log line */
		janus_log_buffer_free(b);
	}
	if(janus_log_console)
		fflush(stdout);
	if(janus_log_file)
		fflush(janus_log_file);

	if(janus_log_file)
		fclose(janus_log_file);
	janus_log_file = NULL;
	g_free(janus_log_filepath);
	janus_log_filepath = NULL;

	return NULL;
}

void janus_vprintf(const char *format, ...) {
	if(g_atomic_int_get(&stopping))
		return;
	if(janus_log_queue == NULL)
		janus_log_queue = g_async_queue_new_full((GDestroyNotify)janus_log_buffer_free);
	int len;
	va_list ap, ap2;
	va_start(ap, format);
	va_copy(ap2, ap);

	janus_log_buffer *b = g_malloc(sizeof(janus_log_buffer));
	b->timestamp = janus_get_real_time();
	b->allocated = 256;	/* FIXME */
	b->str = g_malloc(b->allocated);

	/* First attempt (we don't know how long the string will actually be) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	len = g_vsnprintf(b->str, b->allocated, format, ap);
#pragma GCC diagnostic pop
	va_end(ap);
	if(len >= (int)b->allocated) {
		/* The allocated buffer wasn't big enough */
		b->allocated = len + 1;
		b->str = g_realloc(b->str, b->allocated);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		g_vsnprintf(b->str, b->allocated, format, ap2);
#pragma GCC diagnostic pop
	}
	va_end(ap2);
	/* Queue the output */
	g_async_queue_push(janus_log_queue, b);
}

int janus_log_init(gboolean daemon, gboolean console, const char *logfile, GHashTable *loggers) {
	/* Make sure we only initialize once */
	if(!g_atomic_int_compare_and_exchange(&initialized, 0, 1))
		return 0;
	if(console) {
		/* Set stdout to block buffering, see BUFSIZ in stdio.h */
		setvbuf(stdout, NULL, _IOFBF, 0);
	}
	janus_log_console = console;
	external_loggers = loggers;
	if(logfile != NULL) {
		/* Open a log file for writing (and append) */
		janus_log_file = fopen(logfile, "awt");
		if(janus_log_file == NULL) {
			JANUS_PRINT("Error opening log file %s: %s\n", logfile, g_strerror(errno));
			goto error;
		}
		janus_log_filepath = g_strdup(logfile);
	}
	if(external_loggers != NULL)
		JANUS_PRINT("Adding %d external loggers\n", g_hash_table_size(external_loggers));
	if(!janus_log_console && logfile == NULL && external_loggers == NULL) {
		JANUS_PRINT("WARNING: logging completely disabled!\n");
		JANUS_PRINT("         (no stdout, no logfile and no external loggers, this may not be what you want...)\n");
	}
	if(daemon && !console) {
		/* Replace the standard file descriptors */
		if(freopen("/dev/null", "r", stdin) == NULL) {
			JANUS_PRINT("Error replacing stdin with /dev/null\n");
			goto error;
		}
		if(freopen("/dev/null", "w", stdout) == NULL) {
			JANUS_PRINT("Error replacing stdout with /dev/null\n");
			goto error;
		}
		if(freopen("/dev/null", "w", stderr) == NULL) {
			JANUS_PRINT("Error replacing stderr with /dev/null\n");
			goto error;
		}
	}
	if(janus_log_queue == NULL)
		janus_log_queue = g_async_queue_new_full((GDestroyNotify)janus_log_buffer_free);
	log_thread = g_thread_new(THREAD_NAME, &janus_log_thread, NULL);
	return 0;

error:
	g_atomic_int_set(&initialized, 0);
	janus_log_destroy();
	return -1;
}

void janus_log_destroy(void) {
	g_atomic_int_set(&stopping, 1);
	if(log_thread != NULL) {
		g_async_queue_push(janus_log_queue, &exit_message);
		g_thread_join(log_thread);
	} else if(!g_atomic_int_get(&initialized)) {
		/* Never initialized Print what was in the buffer to stdout */
		janus_log_buffer *b = NULL;
		while((b = g_async_queue_try_pop(janus_log_queue)) != NULL) {
			if(b->str != NULL)
				janus_log_print_buffer(b);
			janus_log_buffer_free(b);
		}
	}
	g_async_queue_unref(janus_log_queue);
	janus_log_queue = NULL;
}
