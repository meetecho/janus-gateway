/*! \file    mutex.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \brief    Semaphors and Mutexes
 * \details  Implementation (based on pthread) of a locking mechanism based on mutexes.
 * \todo     This is mostly unused right now, involve mutexes more in later versions.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_MUTEX_H
#define _JANUS_MUTEX_H

#include <pthread.h>

/*! \brief Janus mutex implementation */
typedef pthread_mutex_t janus_mutex;
/*! \brief Janus mutex initialization */
#define janus_mutex_init(a) pthread_mutex_init(a,NULL)
/*! \brief Janus mutex destruction */
#define janus_mutex_destroy(a) pthread_mutex_destroy(a)
/*! \brief Janus mutex lock */
#define janus_mutex_lock(a) pthread_mutex_lock(a);
//~ #define janus_mutex_lock(a) { printf("[%s:%s:%d:] ", __FILE__, __FUNCTION__, __LINE__); printf("LOCK\n"); pthread_mutex_lock(a); };
/*! \brief Janus mutex unlock */
#define janus_mutex_unlock(a) pthread_mutex_unlock(a);
//~ #define janus_mutex_unlock(a) { printf("[%s:%s:%d:] ", __FILE__, __FUNCTION__, __LINE__); printf("UNLOCK\n"); pthread_mutex_unlock(a); };

#endif
