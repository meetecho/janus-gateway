/*! \file    refcount.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Reference counter mechanism
 * \details  Implementation of a simple reference counter that can be
 * used to keep track of memory management in Janus, in order to avoid
 * the need for timed garbage collectord and the like which have proven
 * ineffective in the past (e.g., crashes whenever race conditions
 * occurred). This implementation is heavily based on an excellent
 * <a href="http://nullprogram.com/blog/2015/02/17/">blog post</a>
 * written by Chris Wellons.
 *
 * Objects interested in leveraging this reference counter mechanism
 * must add a janus_refcount instance as one of the members of the object
 * itself, and then call janus_refcall_init() to set it up. Initializing
 * the reference counter just needs a pointer to the function to invoke
 * when the object needs to be destroyed (counter reaches 0), while it
 * will automatically set the counter to 1. To increase and decrease the
 * counter just call janus_refcount_increase() and janus_refcount_decrease().
 * When the counter reaches 0, the function passed when initializing it will
 * be invoked: this means it's up to you to then free all the resources
 * the object may have allocated. Notice that if this involves other
 * objects that are reference counted, freeing the resource will just
 * mean decreasing the related counter, and not destroying it right away.
 *
 * The free function must be defined like this:
 *
\verbatim
void my_free_function(janus_refcount *counter);
\endverbatim
 *
 * Since the reference counter cannot know the size of the object to be
 * freed, or where in the list of members the counter has been placed,
 * retrieving the pointer to the object to free is up to you, using the
 * janus_refcount_containerof macro. This is an example of how the
 * free function we have defined above may be implemented:
 * 
\verbatim
typedef my_struct {
	int number;
	char *string;
	janus_refcount myref;
}

void my_free_function(janus_refcount *counter) {
	struct my_struct *my_object = janus_refcount_containerof(counter, struct my_struct, myref);
	if(my_object->string)
		free(my_object->string);
	free(my_object);
}
\endverbatim
 *
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_REFCOUNT_H
#define _JANUS_REFCOUNT_H

#include <glib.h>
#include "mutex.h"

//~ #define REFCOUNT_DEBUG

extern int refcount_debug;

/*! \brief Macro to programmatically address the object itself from its counter
 * \details \c refptr is the pointer to the janus_refcount instance, \c type
 * is the type of the object itself (e.g., <code>struct mystruct</code>),
 * while \c member is how the janus_refcount instance is called in the
 * object that contains it. */
#define janus_refcount_containerof(refptr, type, member) \
	((type *)((char *)(refptr) - offsetof(type, member)))


/*! \brief Janus reference counter structure */
typedef struct janus_refcount janus_refcount; 
struct janus_refcount {
	/*! \brief The reference counter itself */
	gint count;
	/*! \brief Pointer to the function that will be used to free the object */
	void (*free)(const janus_refcount *);
};


#ifdef REFCOUNT_DEBUG
/* Reference counters debugging */
extern GHashTable *counters;
extern janus_mutex counters_mutex;
#define janus_refcount_track(refp) { \
	janus_mutex_lock(&counters_mutex); \
	if(counters == NULL) \
		counters = g_hash_table_new(NULL, NULL); \
	g_hash_table_insert(counters, refp, refp); \
	janus_mutex_unlock(&counters_mutex); \
}
#define janus_refcount_untrack(refp) { \
	janus_mutex_lock(&counters_mutex); \
	g_hash_table_remove(counters, refp); \
	janus_mutex_unlock(&counters_mutex); \
}
#endif


/*! \brief Janus reference counter initialization (debug according to settings)
 * \note Also sets the counter to 1 automatically, so no need to increase
 * it again manually via janus_refcount_increase() after the initialization
 * @param refp Pointer to the Janus reference counter instance
 * @param free_fn Pointer to the function to invoke when the object the counter
 * refers to needs to be destroyed */
#define janus_refcount_init(refp, free_fn) { \
	if(!refcount_debug) { \
		janus_refcount_init_nodebug(refp, free_fn); \
	} else { \
		janus_refcount_init_debug(refp, free_fn); \
	} \
}
/*! \brief Janus reference counter initialization (no debug)
 * \note Also sets the counter to 1 automatically, so no need to increase
 * it again manually via janus_refcount_increase() after the initialization
 * @param refp Pointer to the Janus reference counter instance
 * @param free_fn Pointer to the function to invoke when the object the counter
 * refers to needs to be destroyed */
#ifdef REFCOUNT_DEBUG
#define janus_refcount_init_nodebug(refp, free_fn) { \
	(refp)->count = 1; \
	(refp)->free = free_fn; \
	janus_refcount_track((refp)); \
}
#else
#define janus_refcount_init_nodebug(refp, free_fn) { \
	(refp)->count = 1; \
	(refp)->free = free_fn; \
}
#endif
/*! \brief Janus reference counter initialization (debug)
 * \note Also sets the counter to 1 automatically, so no need to increase
 * it again manually via janus_refcount_increase() after the initialization
 * @param refp Pointer to the Janus reference counter instance
 * @param free_fn Pointer to the function to invoke when the object the counter
 * refers to needs to be destroyed */
#ifdef REFCOUNT_DEBUG
#define janus_refcount_init_debug(refp, free_fn) { \
	(refp)->count = 1; \
	JANUS_PRINT("[%s:%s:%d:init] %p (%d)\n", __FILE__, __FUNCTION__, __LINE__, refp, (refp)->count); \
	(refp)->free = free_fn; \
	janus_refcount_track((refp)); \
}
#else
#define janus_refcount_init_debug(refp, free_fn) { \
	(refp)->count = 1; \
	JANUS_PRINT("[%s:%s:%d:init] %p (%d)\n", __FILE__, __FUNCTION__, __LINE__, refp, (refp)->count); \
	(refp)->free = free_fn; \
}
#endif

/*! \brief Increase the Janus reference counter (debug according to settings)
 * @param refp Pointer to the Janus reference counter instance */
#define janus_refcount_increase(refp) { \
	if(!refcount_debug) { \
		janus_refcount_increase_nodebug(refp); \
	} else { \
		janus_refcount_increase_debug(refp); \
	} \
}
/*! \brief Increase the Janus reference counter (no debug)
 * @param refp Pointer to the Janus reference counter instance */
#define janus_refcount_increase_nodebug(refp)  { \
	g_atomic_int_inc((gint *)&(refp)->count); \
}
/*! \brief Increase the Janus reference counter (debug)
 * @param refp Pointer to the Janus reference counter instance */
#define janus_refcount_increase_debug(refp)  { \
	JANUS_PRINT("[%s:%s:%d:increase] %p (%d)\n", __FILE__, __FUNCTION__, __LINE__, refp, (refp)->count+1); \
	g_atomic_int_inc((gint *)&(refp)->count); \
}

/*! \brief Decrease the Janus reference counter (debug according to settings)
 * \note Will invoke the \c free function if the counter reaches 0
 * @param refp Pointer to the Janus reference counter instance */
#define janus_refcount_decrease(refp) { \
	if(!refcount_debug) { \
		janus_refcount_decrease_nodebug(refp); \
	} else { \
		janus_refcount_decrease_debug(refp); \
	} \
}
/*! \brief Decrease the Janus reference counter (debug)
 * \note Will invoke the \c free function if the counter reaches 0
 * @param refp Pointer to the Janus reference counter instance */
#ifdef REFCOUNT_DEBUG
#define janus_refcount_decrease_debug(refp)  { \
	JANUS_PRINT("[%s:%s:%d:decrease] %p (%d)\n", __FILE__, __FUNCTION__, __LINE__, refp, (refp)->count-1); \
	if(g_atomic_int_dec_and_test((gint *)&(refp)->count)) { \
		(refp)->free(refp); \
		janus_refcount_untrack((refp)); \
	} \
}
#else
#define janus_refcount_decrease_debug(refp)  { \
	JANUS_PRINT("[%s:%s:%d:decrease] %p (%d)\n", __FILE__, __FUNCTION__, __LINE__, refp, (refp)->count-1); \
	if(g_atomic_int_dec_and_test((gint *)&(refp)->count)) { \
		(refp)->free(refp); \
	} \
}
#endif
/*! \brief Decrease the Janus reference counter (no debug)
 * \note Will invoke the \c free function if the counter reaches 0
 * @param refp Pointer to the Janus reference counter instance */
#ifdef REFCOUNT_DEBUG
#define janus_refcount_decrease_nodebug(refp)  { \
	if(g_atomic_int_dec_and_test((gint *)&(refp)->count)) { \
		(refp)->free(refp); \
		janus_refcount_untrack((refp)); \
	} \
}
#else
#define janus_refcount_decrease_nodebug(refp)  { \
	if(g_atomic_int_dec_and_test((gint *)&(refp)->count)) { \
		(refp)->free(refp); \
	} \
}
#endif

#endif
