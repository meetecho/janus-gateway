/*! \file    utils.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Utilities and helpers (headers)
 * \details  Implementations of a few methods that may be of use here
 * and there in the code.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_UTILS_H
#define _JANUS_UTILS_H

#include <stdint.h>
#include <glib.h>

/*! \brief Helper to retrieve the system monotonic time, as Glib's
 * g_get_monotonic_time may not be available (only since 2.28)
 * @returns The system monotonic time */
gint64 janus_get_monotonic_time(void);


/** @name Flags helper methods
 */
///@{
/*! \brief Janus flags container */
typedef uint32_t janus_flags;

/*! \brief Janus flags reset method
 * \param[in] flags The janus_flags instance to reset */
void janus_flags_reset(janus_flags *flags);

/*! \brief Janus flags set method
 * \param[in] flags The janus_flags instance to update
 * \param[in] flag The flag to set */
void janus_flags_set(janus_flags *flags, uint32_t flag);

/*! \brief Janus flags clear method
 * \param[in] flags The janus_flags instance to update
 * \param[in] flag The flag to clear */
void janus_flags_clear(janus_flags *flags, uint32_t flag);

/*! \brief Janus flags check method
 * \param[in] flags The janus_flags instance to check
 * \param[in] flag The flag to check
 * \returns true if the flag is set, false otherwise */
gboolean janus_flags_is_set(janus_flags *flags, uint32_t flag);

///@}

#endif
