/*! \file    debug.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Logging and Debugging
 * \details  Implementation of a wrapper on printf (or g_print) to either log or debug.
 * \todo     Improve this wrappers to optionally save logs on file
 * 
 * \ingroup core
 * \ref core
 */

#include <glib.h>
#include <glib/gprintf.h>
 
#ifndef _JANUS_DEBUG_H
#define _JANUS_DEBUG_H

extern int log_level;

/** @name Janus log colors
 */
///@{
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
///@}

/** @name Janus log levels
 */
///@{
/*! \brief No debugging */
#define LOG_NONE     (0)
/*! \brief Fatal error */
#define LOG_FATAL    (1)
/*! \brief Non-fatal error */
#define LOG_ERR      (2)
/*! \brief Warning */
#define LOG_WARN     (3)
/*! \brief Informational message */
#define LOG_INFO     (4)
/*! \brief Verbose message */
#define LOG_VERB     (5)
/*! \brief Overly verbose message */
#define LOG_HUGE     (6)
/*! \brief Debug message (includes .c filename, function and line number) */
#define LOG_DBG      (7)
/*! \brief Maximum level of debugging */
#define LOG_MAX LOG_DBG

/*! \brief Coloured prefixes for errors and warnings logging. */
static char *log_prefix[] = {
	"",
	ANSI_COLOR_MAGENTA"[FATAL]"ANSI_COLOR_RESET" ",
	ANSI_COLOR_RED"[ERR]"ANSI_COLOR_RESET" ",
	ANSI_COLOR_YELLOW"[WARN]"ANSI_COLOR_RESET" ",
	"",
	"",
	"",
	""
};
///@}

/** @name Janus log wrappers
 */
///@{
/*! \brief Simple wrapper to g_print/printf */
#define JANUS_PRINT g_print
/*! \brief Logger based on different levels, which can either be displayed
 * or not according to the configuration of the gateway.
 * The format must be a string literal. */
#define JANUS_LOG(level, format, ...) \
	if (level > LOG_NONE && level <= LOG_MAX && level <= log_level) { \
		if (level == LOG_FATAL || level == LOG_ERR || level == LOG_DBG) { \
			g_print("%s[%s:%s:%d:] " format, log_prefix[level], \
			        __FILE__, __FUNCTION__, __LINE__, \
			        ##__VA_ARGS__); \
		} else { \
			g_print("%s" format, log_prefix[level], \
			        ##__VA_ARGS__); \
		} \
	}
///@}

#endif
