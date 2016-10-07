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
#ifdef _WIN32
#include <sys/types.h>
#else
#include <netinet/in.h>
#endif
#include <jansson.h>

#include "os.h"

/* Use JANUS_JSON_BOOL instead of the non-existing JSON_BOOLEAN */
#define JANUS_JSON_BOOL JSON_TRUE
#define JANUS_JSON_PARAM_REQUIRED 1
#define JANUS_JSON_PARAM_POSITIVE 2
#define JANUS_JSON_PARAM_NONEMPTY 4

struct janus_json_parameter {
	const gchar *name;
	json_type jtype;
	unsigned int flags;
};

/*! \brief Helper to retrieve the system monotonic time, as Glib's
 * g_get_monotonic_time may not be available (only since 2.28)
 * @returns The system monotonic time */
JANUS_API gint64 janus_get_monotonic_time(void);

/*! \brief Helper to retrieve the system real time, as Glib's
 * g_get_real_time may not be available (only since 2.28)
 * @returns The system real time */
JANUS_API gint64 janus_get_real_time(void);

/*! \brief Helper to replace strings
 * @param message The string that contains the text to replace, which may be
 * freed if it is too short
 * @param old_string The old text to replace
 * @param new_string The new text
 * @returns A pointer to the updated text string (re-allocated or just updated) */
JANUS_API char *janus_string_replace(char *message, const char *old_string, const char *new_string) G_GNUC_WARN_UNUSED_RESULT;

/*! \brief Helper to parse yes/no|true/false configuration values
 * @param value The configuration value to parse
 * @returns true if the value contains a "yes", "YES", "true", TRUE", "1", false otherwise */
JANUS_API gboolean janus_is_true(const char *value);

/*! \brief Helper to compare strings in constant time
 * @param str1 The first string to compare
 * @param str2 The second string to compare
 * @returns true if the strings are the same, false otherwise */
JANUS_API gboolean janus_strcmp_const_time(const void *str1, const void *str2);

/*! \brief Helper to generate random 32-bit unsigned integers (useful for SSRCs, etc.)
 * @note Currently just wraps g_random_int()
 * @returns A random 32-bit unsigned integer */
JANUS_API guint32 janus_random_uint32(void);

/*! \brief Helper to generate random 64-bit unsigned integers (useful for Janus IDs)
 * @returns A random 64-bit unsigned integer */
JANUS_API guint64 janus_random_uint64(void);

/*! \brief Helper to generate an allocated copy of a guint64 number
 * @note While apparently silly, this is needed in order to make sure guint64 values
 * used as keys in GHashTable operations are not lost: using temporary guint64 numbers
 * in a g_hash_table_insert, for instance, will cause the key to contain garbage as
 * soon as the temporary variable is lost, and all opererations on the key to fail
 * @param num The guint64 number to duplicate
 * @returns A pointer to a guint64 number, if successful, NULL otherwise */
JANUS_API guint64 *janus_uint64_dup(guint64 num);

/** @name Flags helper methods
 */
///@{
/*! \brief Janus flags container */
typedef uint32_t janus_flags;

/*! \brief Janus flags reset method
 * \param[in] flags The janus_flags instance to reset */
JANUS_API void janus_flags_reset(janus_flags *flags);

/*! \brief Janus flags set method
 * \param[in] flags The janus_flags instance to update
 * \param[in] flag The flag to set */
JANUS_API void janus_flags_set(janus_flags *flags, uint32_t flag);

/*! \brief Janus flags clear method
 * \param[in] flags The janus_flags instance to update
 * \param[in] flag The flag to clear */
JANUS_API void janus_flags_clear(janus_flags *flags, uint32_t flag);

/*! \brief Janus flags check method
 * \param[in] flags The janus_flags instance to check
 * \param[in] flag The flag to check
 * \returns true if the flag is set, false otherwise */
JANUS_API gboolean janus_flags_is_set(janus_flags *flags, uint32_t flag);
///@}

/*! \brief Helper to create a new directory, and recursively create parent directories if needed
 * @param dir Path to the new folder to create
 * @param mode File permissions for the new directory file
 * @returns An integer like the regular mkdir does
 * @note A failure may indicate that creating any of the subdirectories failed: some may still have been created */
JANUS_API int janus_mkdir(const char *dir, mode_t mode);

/*! \brief Ugly and dirty helper to quickly get the payload type associated with a codec in an SDP
 * @param sdp The SDP to parse
 * @param codec The codec to look for
 * @returns The payload type, if found, -1 otherwise */
JANUS_API int janus_get_codec_pt(const char *sdp, const char *codec);

/*! \brief Ugly and dirty helper to quickly get the codec associated with a payload type in an SDP
 * @param sdp The SDP to parse
 * @param pt The payload type to look for
 * @returns The codec name, if found, NULL otherwise */
JANUS_API const char *janus_get_codec_from_pt(const char *sdp, int pt);

/*! \brief Check if the given IP address is valid: family is set to the address family if the IP is valid
 * @param ip The IP address to check
 * @param[in,out] family The address family of the address, set by the method if valid
 * @returns true if the address is valid, false otherwise */
JANUS_API gboolean janus_is_ip_valid(const char *ip, int *family);

/*! \brief Convert a sockaddr address to an IP string
 * \note The resulting string is allocated, which means the caller must free it itself when done
 * @param address The sockaddr address to convert
 * @returns A string containing the IP address, if successful, NULL otherwise */
JANUS_API char *janus_address_to_ip(struct sockaddr *address);

/*! \brief Create and lock a PID file
 * @param file Path to the PID file to use
 * @returns 0 if successful, a negative integer otherwise */
JANUS_API int janus_pidfile_create(const char *file);

/*! \brief Unlock and remove a previously created PID file
 * @returns 0 if successful, a negative integer otherwise */
JANUS_API int janus_pidfile_remove(void);

/*! \brief Creates a string describing the JSON type and constraint
 * @param jtype The JSON type, e.g., JSON_STRING
 * @param flags Indicates constraints for the described type
 * @param[out] The type description, e.g., "a positive integer"; required size is 19 characters */
JANUS_API void janus_get_json_type_name(int jtype, unsigned int flags, char *type_name);

/*! \brief Checks whether the JSON value matches the type and constraint
 * @param val The JSON value to be checked
 * @param jtype The JSON type, e.g., JSON_STRING
 * @param flags Indicates constraints for the described type
 * @returns TRUE if the value is valid */
JANUS_API gboolean janus_json_is_valid(json_t *val, json_type jtype, unsigned int flags);

/*! \brief Sets non blocking mode for given file descriptor
 * @param fd file descriptor */
JANUS_API void janus_set_non_blocking_mode(int fd);

/*! \brief Validates the JSON object against the description of its parameters
 * @param missing_format printf format to indicate a missing required parameter; needs one %s for the parameter name
 * @param invalid_format printf format to indicate an invalid parameter; needs two %s for parameter name and type description from janus_get_json_type_name
 * @param obj The JSON object to be validated
 * @param params Array of struct janus_json_parameter to describe the parameters; the array has to be a global or stack variable to make sizeof work
 * @param[out] error_code int to return error code
 * @param[out] error_cause Array of char or NULL to return the error descriptions; the array has to be a global or stack variable to make sizeof work; the required size is the length of the format string plus the length of the longest parameter name plus 19 for the type description
 * @param log_error If TRUE, log any error with JANUS_LOG(LOG_ERR)
 * @param missing_code The code to be returned in error_code if a parameter is missing
 * @param invalid_code The code to be returned in error_code if a parameter is invalid */
#define JANUS_VALIDATE_JSON_OBJECT_FORMAT(missing_format, invalid_format, obj, params, error_code, error_cause, log_error, missing_code, invalid_code) \
	do { \
		error_code = 0; \
		unsigned int i; \
		for(i = 0; i < sizeof(params) / sizeof(struct janus_json_parameter); i++) { \
			json_t *val = json_object_get(obj, params[i].name); \
			if(!val) { \
				if((params[i].flags & JANUS_JSON_PARAM_REQUIRED) != 0) {	\
					error_code = (missing_code); \
					if(log_error) \
						JANUS_LOG(LOG_ERR, missing_format "\n", params[i].name); \
					if(error_cause != NULL) \
						g_snprintf(error_cause, sizeof(error_cause), missing_format, params[i].name); \
					break; \
				} \
				continue; \
			} \
			if(!janus_json_is_valid(val, params[i].jtype, params[i].flags)) { \
				error_code = (invalid_code); \
				char type_name[20]; \
				janus_get_json_type_name(params[i].jtype, params[i].flags, type_name); \
				if(log_error) \
					JANUS_LOG(LOG_ERR, invalid_format "\n", params[i].name, type_name); \
				if(error_cause != NULL) \
					g_snprintf(error_cause, sizeof(error_cause), invalid_format, params[i].name, type_name); \
				break; \
			} \
		} \
	} while(0)

/*! \brief Validates the JSON object against the description of its parameters
 * @param obj The JSON object to be validated
 * @param params Array of struct janus_json_parameter to describe the parameters; the array has to be a global or stack variable to make sizeof work
 * @param[out] error_code int to return error code
 * @param[out] error_cause Array of char or NULL to return the error descriptions; the array has to be a global or stack variable to make sizeof work; the required size is the length of the longest parameter name plus 54 for the format string and type description
 * @param log_error If TRUE, log any error with JANUS_LOG(LOG_ERR)
 * @param missing_code The code to be returned in error_code if a parameter is missing
 * @param invalid_code The code to be returned in error_code if a parameter is invalid */
#define JANUS_VALIDATE_JSON_OBJECT(obj, params, error_code, error_cause, log_error, missing_code, invalid_code) \
	JANUS_VALIDATE_JSON_OBJECT_FORMAT("Missing mandatory element (%s)", "Invalid element type (%s should be %s)", obj, params, error_code, error_cause, log_error, missing_code, invalid_code)

/*! \brief If the secret isn't NULL, check the secret after validating the specified member of the JSON object
 * @param secret The secret to be checked; no check if the secret is NULL
 * @param obj The JSON object to be validated
 * @param member The JSON member with the secret, usually "secret" or "pin"
 * @param[out] error_code int to return error code
 * @param[out] error_cause Array of char or NULL to return the error descriptions; the array has to be a global or stack variable to make sizeof work; the required size is 60
 * @param log_error If TRUE, log any error with JANUS_LOG(LOG_ERR)
 * @param missing_code The code to be returned in error_code if a parameter is missing
 * @param invalid_code The code to be returned in error_code if a parameter is invalid
 * @param unauthorized_code The code to be returned in error_code if the secret doesn't match */
#define JANUS_CHECK_SECRET(secret, obj, member, error_code, error_cause, missing_code, invalid_code, unauthorized_code) \
	do { \
		if (secret) { \
			static struct janus_json_parameter secret_parameters[] = { \
				{member, JSON_STRING, JANUS_JSON_PARAM_REQUIRED} \
			}; \
			JANUS_VALIDATE_JSON_OBJECT(obj, secret_parameters, error_code, error_cause, TRUE, missing_code, invalid_code); \
			if(error_code == 0 && !janus_strcmp_const_time((secret), json_string_value(json_object_get(obj, member)))) { \
				error_code = (unauthorized_code); \
				JANUS_LOG(LOG_ERR, "Unauthorized (wrong %s)\n", member); \
				if(error_cause != NULL) \
					g_snprintf(error_cause, sizeof(error_cause), "Unauthorized (wrong %s)", member); \
			} \
		} \
	} while(0)

#endif
