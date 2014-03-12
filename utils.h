/*! \file    utils.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU Affero General Public License v3
 * \brief    Utilities and helpers (headers)
 * \details  Implementations of a few methods that may be of use here
 * and there in the code.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_UTILS_H
#define _JANUS_UTILS_H

#include <glib.h>

/*! \brief Helper to retrieve the system monotonic time, as Glib's
 * g_get_monotonic_time may not be available (only since 2.28)
 * @returns The system monotonic time */
gint64 janus_get_monotonic_time(void);

#endif
