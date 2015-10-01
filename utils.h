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
#include <netinet/in.h>

/*! \brief Helper to retrieve the system monotonic time, as Glib's
 * g_get_monotonic_time may not be available (only since 2.28)
 * @returns The system monotonic time */
gint64 janus_get_monotonic_time(void);

/*! \brief Helper to retrieve the system real time, as Glib's
 * g_get_real_time may not be available (only since 2.28)
 * @returns The system real time */
gint64 janus_get_real_time(void);

/*! \brief Helper to replace strings
 * @param message The string that contains the text to replace, which may be
 * freed if it is too short
 * @param old_string The old text to replace
 * @param new_string The new text
 * @returns A pointer to the updated text string (re-allocated or just updated) */
char *janus_string_replace(char *message, const char *old_string, const char *new_string) G_GNUC_WARN_UNUSED_RESULT;

/*! \brief Helper to parse yes/no|true/false configuration values
 * @param value The configuration value to parse
 * @returns true if the value contains a "yes", "YES", "true", TRUE", "1", false otherwise */
gboolean janus_is_true(const char *value);

/*! \brief Helper to compare strings in constant time
 * @param str1 The first string to compare
 * @param str2 The second string to compare
 * @returns true if the strings are the same, false otherwise */
gboolean janus_strcmp_const_time(const void *str1, const void *str2);

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

/*! \brief Helper to create a new directory, and recursively create parent directories if needed
 * @param dir Path to the new folder to create
 * @param mode File permissions for the new directory file
 * @returns An integer like the regular mkdir does
 * @note A failure may indicate that creating any of the subdirectories failed: some may still have been created */
int janus_mkdir(const char *dir, mode_t mode);

/*! \brief Ugly and dirty helper to quickly get the Opus payload type in an SDP
 * @param sdp The SDP to parse
 * @returns The Opus payload type, if found, -1 otherwise */
int janus_get_opus_pt(const char *sdp);

/*! \brief Ugly and dirty helper to quickly get the VP8 payload type in an SDP
 * @param sdp The SDP to parse
 * @returns The VP8 payload type, if found, -1 otherwise */
int janus_get_vp8_pt(const char *sdp);

/*! \brief Check if the given IP address is valid: family is set to the address family if the IP is valid
 * @param ip The IP address to check
 * @param[in,out] family The address family of the address, set by the method if valid
 * @returns true if the address is valid, false otherwise */
gboolean janus_is_ip_valid(const char *ip, int *family);

/*! \brief Convert a sockaddr address to an IP string
 * \note The resulting string is allocated, which means the caller must free it itself when done
 * @param address The sockaddr address to convert
 * @returns A string containing the IP address, if successful, NULL otherwise */
char *janus_address_to_ip(struct sockaddr *address);
#endif
