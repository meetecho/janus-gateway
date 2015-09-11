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
 
#ifndef _JANUS_AUTH_H
#define _JANUS_AUTH_H

#include <glib.h>


/*! \brief Method to initializing the token based authentication
 * @param[in] enabled Whether the authentication mechanism should be enabled or not */
void janus_auth_init(gboolean enabled);
/*! \brief Method to check whether the mechanism is enabled or not */
gboolean janus_auth_is_enabled(void);
/*! \brief Method to de-initialize the mechanism */
void janus_auth_deinit(void);

/*! \brief Method to add a new valid token for authenticating
 * @param[in] token The new valid token
 * @returns true if the operation was successful, false otherwise */
gboolean janus_auth_add_token(const char *token);
/*! \brief Method to check whether a provided token is valid or not
 * @param[in] token The token to validate
 * @returns true if the token is valid, false otherwise */
gboolean janus_auth_check_token(const char *token);
/*! \brief Method to invalidate an existing token
 * @param[in] token The valid to invalidate
 * @returns true if the operation was successful, false otherwise */
gboolean janus_auth_remove_token(const char *token);

#endif
