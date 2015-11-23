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

#define INITIAL_BUFSZ 1024*2
#define THREAD_NAME   "log"

struct Buffer {
	GString *s;
	struct Buffer *next;
};

static gint     initialized = 0;
static gint     stopping = 0;
static gint     poolsz = 0;
static gint     maxpoolsz = 8;
/* Buffers over this size will be freed */
static gsize    maxbuffersz = 1024*8;
static GMutex   lock;
static GCond    cond;
static GThread  *printthread = NULL;
static struct Buffer *printhead = NULL;
static struct Buffer *printtail = NULL;
static struct Buffer *bufferpool = NULL;


static void freebuffers(struct Buffer **list)
{
	struct Buffer *b, *head = *list;

	while (head) {
		b = head;
		head = b->next;
		g_string_free(b->s, TRUE);
		g_free(b);
	}
	*list = NULL;
}


static struct Buffer * getbuf(void)
{
	struct Buffer *b;

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
		b = g_malloc0(sizeof(*b));
		b->s = g_string_sized_new(INITIAL_BUFSZ);
	}
	return b;
}

static void * janus_log_thread(void *ctx)
{
	struct Buffer *head, *b, *tofree = NULL;

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
				fputs(b->s->str, stdout);
			}
			g_mutex_lock(&lock);
			while (head) {
				b = head;
				head = b->next;
				if (poolsz >= maxpoolsz || b->s->allocated_len > maxbuffersz) {
					b->next = tofree;
					tofree = b;
					poolsz--;
				} else {
					b->next = bufferpool;
					bufferpool = b;
				}
			}
			g_mutex_unlock(&lock);
			fflush(stdout);
			freebuffers(&tofree);
		}
	}
	/* print any remaining messages, stdout flushed on exit */
	for (b = printhead; b; b = b->next) {
		fputs(b->s->str, stdout);
	}
	freebuffers(&printhead);
	freebuffers(&bufferpool);
	g_mutex_clear(&lock);
	g_cond_clear(&cond);
	return NULL;
}

void janus_vprintf(const gchar *format, ...)
{
	va_list args;
	struct Buffer *b = getbuf();

	va_start(args, format);
	g_string_vprintf(b->s, format, args);
	va_end(args);

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

void janus_log_init(void)
{
	if (g_atomic_int_get(&initialized)) {
		return;
	}
	g_atomic_int_set(&initialized, 1);
	g_mutex_init(&lock);
	g_cond_init(&cond);
	/* set stdout to block buffering, see BUFSIZ in stdio.h */
	setvbuf(stdout, NULL, _IOFBF, 0);
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
