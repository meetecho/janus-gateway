/*! \file    auth.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Requests authentication (headers)
 * \details  Implementation of a simple mechanism for authenticating
 * requests. If enabled (it's disabled by default), the Janus admin API
 * can be used to specify valid tokens; each request must then contain
 * a valid token string, or otherwise the request is rejected with an
 * error. Whether tokens should be shared across users or not is
 * completely up to the controlling application: these tokens are
 * completely opaque to Janus, and treated as strings, which means
 * Janus will only check if the token exists or not when asked.
 *
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_AUTH_H
#define JANUS_AUTH_H

#include <glib.h>

#include "plugins/plugin.h"

/*! \brief Method to initializing the token based authentication
 * @param[in] enabled Whether the authentication mechanism should be enabled or not
 * @param[in] secret the secret to validate signed tokens against, or NULL to use stored tokens */
void janus_auth_init(gboolean enabled, const char *secret);
/*! \brief Method to check whether the mechanism is enabled or not */
gboolean janus_auth_is_enabled(void);
/*! \brief Method to check whether the mechanism is in stored-token mode or not */
gboolean janus_auth_is_stored_mode(void);
/*! \brief Method to de-initialize the mechanism */
void janus_auth_deinit(void);

/*! \brief Method to check whether a signed token is valid
 * @param[in] token The token to validate
 * @param[in] realm The token realm
 * @returns TRUE if the signature is valid and not expired, FALSE otherwise */
gboolean janus_auth_check_signature(const char *token, const char *realm);
/*! \brief Method to verify a signed token contains a descriptor
 * @param[in] token The token to validate
 * @param[in] realm The token realm
 * @param[in] desc The descriptor to search for
 * @returns TRUE if the token is valid, not expired and contains the descriptor, FALSE otherwise */
gboolean janus_auth_check_signature_contains(const char *token, const char *realm, const char *desc);

/*! \brief Method to add a new valid token for authenticating
 * @param[in] token The new valid token
 * @returns TRUE if the operation was successful, FALSE otherwise */
gboolean janus_auth_add_token(const char *token);
/*! \brief Method to check whether a provided token is valid or not
 * \note verifies both token signatures and against stored tokens
 * @param[in] token The token to validate
 * @returns TRUE if the token is valid, FALSE otherwise */
gboolean janus_auth_check_token(const char *token);
/*! \brief Method to return a list of the tokens
 * \note It's the caller responsibility to free the list and its values
 * @returns A pointer to a GList instance containing the tokens */
GList *janus_auth_list_tokens(void);
/*! \brief Method to invalidate an existing token
 * @param[in] token The valid to invalidate
 * @returns TRUE if the operation was successful, FALSE otherwise */
gboolean janus_auth_remove_token(const char *token);

/*! \brief Method to allow a token to use a plugin
 * @param[in] token The token that can now access this plugin
 * @param[in] plugin Opaque pointer to the janus_plugin instance this token can access
 * @returns TRUE if the operation was successful, FALSE otherwise */
gboolean janus_auth_allow_plugin(const char *token, janus_plugin *plugin);
/*! \brief Method to check whether a provided token can access a specified plugin
 * \note verifies both token signatures and against stored tokens
 * @param[in] token The token to check
 * @param[in] plugin The plugin to check as an opaque pointer to a janus_plugin instance
 * @returns TRUE if the token is allowed to access the plugin, FALSE otherwise */
gboolean janus_auth_check_plugin(const char *token, janus_plugin *plugin);
/*! \brief Method to return a list of the plugins a specific token has access to
 * \note It's the caller responsibility to free the list (but NOT the values)
 * @param[in] token The token to get the list for
 * @returns A pointer to a GList instance containing the liist */
GList *janus_auth_list_plugins(const char *token);
/*! \brief Method to disallow a token to use a plugin
 * @param[in] token The token this operation refers to
 * @param[in] plugin Opaque pointer to the janus_plugin instance this token can not access anymore
 * @returns TRUE if the operation was successful, FALSE otherwise */
gboolean janus_auth_disallow_plugin(const char *token, janus_plugin *plugin);

#endif
