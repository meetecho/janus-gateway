/*! \file    mutex.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \brief    Semaphors, Mutexes and Conditions
 * \details  Implementation (based on GMutex) of a locking mechanism based on mutexes and conditions.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_MUTEX_H
#define _JANUS_MUTEX_H

#include <pthread.h>
#include <errno.h>

#include "debug.h"

extern int lock_debug;

/*! \brief Janus mutex implementation */
typedef GMutex janus_mutex;
/*! \brief Janus mutex initialization */
#define janus_mutex_init(a) g_mutex_init(a)
/*! \brief Janus static mutex initializer */
#define JANUS_MUTEX_INITIALIZER {0}
/*! \brief Janus mutex destruction */
#define janus_mutex_destroy(a) g_mutex_clear(a)
/*! \brief Janus mutex lock without debug */
#define janus_mutex_lock_nodebug(a) g_mutex_lock(a);
/*! \brief Janus mutex lock with debug (prints the line that locked a mutex) */
#define janus_mutex_lock_debug(a) { JANUS_PRINT("[%s:%s:%d:lock] %p\n", __FILE__, __FUNCTION__, __LINE__, a); g_mutex_lock(a); };
/*! \brief Janus mutex lock wrapper (selective locking debug) */
#define janus_mutex_lock(a) { if(!lock_debug) { janus_mutex_lock_nodebug(a); } else { janus_mutex_lock_debug(a); } };
/*! \brief Janus mutex unlock without debug */
#define janus_mutex_unlock_nodebug(a) g_mutex_unlock(a);
/*! \brief Janus mutex unlock with debug (prints the line that unlocked a mutex) */
#define janus_mutex_unlock_debug(a) { JANUS_PRINT("[%s:%s:%d:unlock] %p\n", __FILE__, __FUNCTION__, __LINE__, a); g_mutex_unlock(a); };
/*! \brief Janus mutex unlock wrapper (selective locking debug) */
#define janus_mutex_unlock(a) { if(!lock_debug) { janus_mutex_unlock_nodebug(a); } else { janus_mutex_unlock_debug(a); } };

/*! \brief Janus condition implementation */
typedef GCond janus_condition;
/*! \brief Janus condition initialization */
#define janus_condition_init(a) g_cond_init(a)
/*! \brief Janus condition destruction */
#define janus_condition_destroy(a) g_cond_clear(a)
/*! \brief Janus condition wait */
#define janus_condition_wait(a, b) g_cond_wait(a, b);
/*! \brief Janus condition wait until */
#define janus_condition_wait_until(a, b, c) g_cond_wait_until(a, b, c);
/*! \brief Janus condition signal */
#define janus_condition_signal(a) g_cond_signal(a);
/*! \brief Janus condition broadcast */
#define janus_condition_broadcast(a) g_cond_broadcast(a);

#endif
