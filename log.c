/*! \file     log.c
 * \author    Jay Ridgeway <jayridge@gmail.com>
 * \copyright GNU General Public License v3
 * \brief     Buffered logging
 * \details   Implementation of a simple buffered logger designed to remove
 * I/O wait from threads that may be sensitive to such delays. Buffers are
 * saved and reused to reduce allocation calls. The logger output can then
 * be printed to stdout and/or a log file.
 *
 * \ingroup core
 * \ref core
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#define THREAD_NAME "log"

typedef struct janus_log_buffer janus_log_buffer;
struct janus_log_buffer {
	size_t allocated;
	janus_log_buffer *next;
	/* str is grown by allocating beyond the struct */
	char str[1];
};

#define INITIAL_BUFSZ		2000

static gboolean janus_log_console = TRUE;
static char *janus_log_filepath = NULL;
static FILE *janus_log_file = NULL;

static volatile gint initialized = 0;
static gint stopping = 0;
static gint poolsz = 0;
static gint maxpoolsz = 32;
/* Buffers over this size will be freed */
static size_t maxbuffersz = 8000;
static GMutex lock;
static GCond cond;
static GThread *printthread = NULL;
static janus_log_buffer *printhead = NULL;
static janus_log_buffer *printtail = NULL;
static janus_log_buffer *bufferpool = NULL;


gboolean janus_log_is_stdout_enabled(void) {
	return janus_log_console;
}

gboolean janus_log_is_logfile_enabled(void) {
	return janus_log_file != NULL;
}

char *janus_log_get_logfile_path(void) {
	return janus_log_filepath;
}


static void janus_log_freebuffers(janus_log_buffer **list) {
	janus_log_buffer *b, *head = *list;

	while (head) {
		b = head;
		head = b->next;
		g_free(b);
	}
	*list = NULL;
}

static janus_log_buffer *janus_log_getbuf(void) {
	janus_log_buffer *b;

	g_mutex_lock(&lock);
	b = bufferpool;
	if (b) {
		bufferpool = b->next;
		b->next = NULL;
	} else {
		poolsz++;
	}
	g_mutex_unlock(&lock);
	if (b == NULL) {
		b = g_malloc(INITIAL_BUFSZ + sizeof(*b));
		b->allocated = INITIAL_BUFSZ;
		b->next = NULL;
	}
	return b;
}

static void *janus_log_thread(void *ctx) {
	janus_log_buffer *head, *b, *tofree = NULL;

	while (!g_atomic_int_get(&stopping)) {
		g_mutex_lock(&lock);
		if (!printhead) {
			g_cond_wait(&cond, &lock);
		}
		head = printhead;
		printhead = printtail = NULL;
		g_mutex_unlock(&lock);

		if (head) {
			for (b = head; b; b = b->next) {
				if(janus_log_console)
					fputs(b->str, stdout);
				if(janus_log_file)
					fputs(b->str, janus_log_file);
			}
			g_mutex_lock(&lock);
			while (head) {
				b = head;
				head = b->next;
				if (poolsz >= maxpoolsz || b->allocated > maxbuffersz) {
					b->next = tofree;
					tofree = b;
					poolsz--;
				} else {
					b->next = bufferpool;
					bufferpool = b;
				}
			}
			g_mutex_unlock(&lock);
			if(janus_log_console)
				fflush(stdout);
			if(janus_log_file)
				fflush(janus_log_file);
			janus_log_freebuffers(&tofree);
		}
	}
	/* print any remaining messages, stdout flushed on exit */
	for (b = printhead; b; b = b->next) {
		if(janus_log_console)
			fputs(b->str, stdout);
		if(janus_log_file)
			fputs(b->str, janus_log_file);
	}
	if(janus_log_console)
		fflush(stdout);
	if(janus_log_file)
		fflush(janus_log_file);
	janus_log_freebuffers(&printhead);
	janus_log_freebuffers(&bufferpool);
	g_mutex_clear(&lock);
	g_cond_clear(&cond);

	if(janus_log_file)
		fclose(janus_log_file);
	janus_log_file = NULL;
	g_free(janus_log_filepath);
	janus_log_filepath = NULL;

	return NULL;
}

void janus_vprintf(const char *format, ...) {
	int len;
	va_list ap, ap2;
	janus_log_buffer *b = janus_log_getbuf();

	va_start(ap, format);
	va_copy(ap2, ap);
	/* first try */
	len = vsnprintf(b->str, b->allocated, format, ap);
	va_end(ap);
	if (len >= (int) b->allocated) {
		/* buffer wasn't big enough */
		b = g_realloc(b, len + 1 + sizeof(*b));
		b->allocated = len + 1;
		vsnprintf(b->str, b->allocated, format, ap2);
	}
	va_end(ap2);

	g_mutex_lock(&lock);
	if (!printhead) {
		printhead = printtail = b;
	} else {
		printtail->next = b;
		printtail = b;
	}
	g_cond_signal(&cond);
	g_mutex_unlock(&lock);
}

int janus_log_init(gboolean daemon, gboolean console, const char *logfile) {
	if (!g_atomic_int_compare_and_exchange(&initialized, 0, 1)) {
		return 0;
	}
	g_mutex_init(&lock);
	g_cond_init(&cond);
	if(console) {
		/* Set stdout to block buffering, see BUFSIZ in stdio.h */
		setvbuf(stdout, NULL, _IOFBF, 0);
	}
	janus_log_console = console;
	if(logfile != NULL) {
		/* Open a log file for writing (and append) */
		janus_log_file = fopen(logfile, "awt");
		if(janus_log_file == NULL) {
			g_print("Error opening log file %s: %s\n", logfile, strerror(errno));
			return -1;
		}
		janus_log_filepath = g_strdup(logfile);
	}
	if(!janus_log_console && logfile == NULL) {
		g_print("WARNING: logging completely disabled!\n");
		g_print("         (no stdout and no logfile, this may not be what you want...)\n");
	}
	if(daemon) {
		/* Replace the standard file descriptors */
		if (freopen("/dev/null", "r", stdin) == NULL) {
			g_print("Error replacing stdin with /dev/null\n");
			return -1;
		}
		if (freopen("/dev/null", "w", stdout) == NULL) {
			g_print("Error replacing stdout with /dev/null\n");
			return -1;
		}
		if (freopen("/dev/null", "w", stderr) == NULL) {
			g_print("Error replacing stderr with /dev/null\n");
			return -1;
		}
	}
	printthread = g_thread_new(THREAD_NAME, &janus_log_thread, NULL);
	return 0;
}

void janus_log_destroy(void) {
	g_atomic_int_set(&stopping, 1);
	g_mutex_lock(&lock);
	/* Signal print thread to print any remaining message */
	g_cond_signal(&cond);
	g_mutex_unlock(&lock);
	g_thread_join(printthread);
}
