/*! \file     log.c
 * \author    Jay Ridgeway <jayridge@gmail.com>
 * \copyright GNU General Public License v3
 * \brief     Buffered logging
 * \details   Implementation of a simple buffered logger designed to remove
 * I/O wait from threads that may be sensitive to such delays. Buffers are
 * saved and reused to reduce allocation calls.
 *
 * \ingroup core
 * \ref core
 */

#include "log.h"

#define INITIAL_BUFSZ 2048
#define THREAD_NAME   "log"


static gint	 initialized = 0;
static gint	 stopping = 0;
/* Maximum sleep in ms for the print thread */
static gint	 maxdelay = 3000;
/* Buffers over this size will be freed */
static gsize	maxbuffer = 1024*16;
static GMutex   lock;
static GCond	cond;
static GSList   *printqueue = NULL;
static GQueue   *freebufs = NULL;
static GThread  *printthread = NULL;


static void stringfree(void *s)
{
	if (s) {
		g_string_free((GString *)s, TRUE);
	}
}

static GString * getbuf(void)
{
	GString *s;

	g_mutex_lock(&lock);
	s = (GString *)g_queue_pop_head(freebufs);
	g_mutex_unlock(&lock);
	if (s == NULL) {
		s = g_string_sized_new(INITIAL_BUFSZ);
	}
	return s;
}

static void * janus_log_thread(void *ctx)
{
	GSList  *head, *p;
	GString *s;
	gint64  abstime;

	while (!g_atomic_int_get(&stopping)) {
		abstime = g_get_monotonic_time() + maxdelay * G_TIME_SPAN_MILLISECOND;
		g_mutex_lock(&lock);
		g_cond_wait_until(&cond, &lock, abstime);
		head = printqueue;
		printqueue = NULL;
		g_mutex_unlock(&lock);

		if (head) {
			for (p = head; p; p = g_slist_next(p)) {
				s = (GString *)p->data;
				fputs(s->str, stdout);
				if (s->allocated_len > maxbuffer) {
					g_string_free(s, TRUE);
				} else {
					g_mutex_lock(&lock);
					g_queue_push_head(freebufs, s);
					g_mutex_unlock(&lock);
				}
			}
			fflush(stdout);
			g_slist_free(head);
		}
	}
	g_mutex_lock(&lock);
	/* free buffers, printqueue should be NULL */
	g_queue_free_full(freebufs, stringfree);
	g_mutex_unlock(&lock);

	g_mutex_clear(&lock);
	g_cond_clear(&cond);
	return NULL;
}

void janus_vprintf(const gchar *format, ...)
{
	va_list args;
	GString *s = getbuf();

	va_start(args, format);
	g_string_vprintf(s, format, args);
	va_end(args);

	g_mutex_lock(&lock);
	printqueue = g_slist_append(printqueue, s);
	g_cond_signal(&cond);
	g_mutex_unlock(&lock);
}

void janus_log_init(void)
{
	if (g_atomic_int_get(&initialized)) {
		return;
	}
	g_atomic_int_set(&initialized, 1);
	g_mutex_init(&lock);
	g_cond_init(&cond);
	/* Set stdout to block buffering, see BUFSIZ in stdio.h */
	setvbuf(stdout, NULL, _IOFBF, 0);
	freebufs = g_queue_new();
	printthread = g_thread_new(THREAD_NAME, &janus_log_thread, NULL);
}

void janus_log_destroy(void)
{
	g_atomic_int_set(&stopping, 1);
	g_mutex_lock(&lock);
	/* signal print thread to print any remaining message */
	g_cond_signal(&cond);
	g_mutex_unlock(&lock);
	g_thread_join(printthread);
}
