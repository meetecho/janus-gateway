/*! \file    debug.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \brief    Logging and Debugging
 * \details  Implementation of a wrapper on printf (or g_print) to either log or debug.
 * \todo     Improve this wrappers to add levels of debugging and optionally saving logs on file
 * 
 * \ingroup core
 * \ref core
 */

#include <glib.h>
#include <glib/gprintf.h>
 
#ifndef _JANUS_DEBUG_H
#define _JANUS_DEBUG_H

/* FIXME */
#define JANUS_PRINT g_print
#define JANUS_DEBUG(...) \
	do { \
		g_print("[%s:%s:%d:] ", __FILE__, __FUNCTION__, __LINE__); \
		g_print(__VA_ARGS__); \
	} while(0);
	
#endif
