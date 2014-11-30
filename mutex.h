/*! \file    mutex.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \brief    Semaphors and Mutexes
 * \details  Implementation (based on pthread) of a locking mechanism based on mutexes.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_MUTEX_H
#define _JANUS_MUTEX_H

#include <pthread.h>

extern int lock_debug;

/*! \brief Janus mutex implementation */
typedef pthread_mutex_t janus_mutex;
/*! \brief Janus mutex initialization */
#define janus_mutex_init(a) pthread_mutex_init(a,NULL)
/*! \brief Janus mutex destruction */
#define janus_mutex_destroy(a) pthread_mutex_destroy(a)
/*! \brief Janus mutex lock without debug */
#define janus_mutex_lock_nodebug(a) pthread_mutex_lock(a);
/*! \brief Janus mutex lock with debug (prints the line that locked a mutex) */
#define janus_mutex_lock_debug(a) { printf("[%s:%s:%d:] ", __FILE__, __FUNCTION__, __LINE__); printf("LOCK %p\n", a); pthread_mutex_lock(a); };
/*! \brief Janus mutex lock wrapper (selective locking debug) */
#define janus_mutex_lock(a) { if(!lock_debug) { janus_mutex_lock_nodebug(a); } else { janus_mutex_lock_debug(a); } };
/*! \brief Janus mutex unlock without debug */
#define janus_mutex_unlock_nodebug(a) pthread_mutex_unlock(a);
/*! \brief Janus mutex unlock with debug (prints the line that unlocked a mutex) */
#define janus_mutex_unlock_debug(a) { printf("[%s:%s:%d:] ", __FILE__, __FUNCTION__, __LINE__); printf("UNLOCK %p\n", a); pthread_mutex_unlock(a); };
/*! \brief Janus mutex unlock wrapper (selective locking debug) */
#define janus_mutex_unlock(a) { if(!lock_debug) { janus_mutex_unlock_nodebug(a); } else { janus_mutex_unlock_debug(a); } };

#endif
