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
#include <jansson.h>


/*! \brief Method to initializing the token based authentication
 * @param[in] type Type of authentication: 'I'=internal, 'E'=external, '-'=none */
void janus_auth_init(char type);
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
 * @param[in/out] root The JSON root of the incoming message being processed
 * @returns true if the token is valid, false otherwise */
gboolean janus_auth_check_token(const char *token, json_t *root);
/*! \brief Method to return a list of the tokens
 * \note It's the caller responsibility to free the list and its values
 * @returns A pointer to a GList instance containing the tokens */
GList *janus_auth_list_tokens(void);
/*! \brief Method to invalidate an existing token
 * @param[in] token The valid to invalidate
 * @returns true if the operation was successful, false otherwise */
gboolean janus_auth_remove_token(const char *token);

/*! \brief Method to allow a token to use a plugin
 * @param[in] token The token that can now access this plugin
 * @param[in] plugin Opaque pointer to the janus_plugin instance this token can access
 * @returns true if the operation was successful, false otherwise */
gboolean janus_auth_allow_plugin(const char *token, void *plugin);
/*! \brief Method to check whether a provided token can access a specified plugin
 * @param[in] token The token to check
 * @param[in] plugin The plugin to check as an opaque pointer to a janus_plugin instance
 * @returns true if the token is allowed to access the plugin, false otherwise */
gboolean janus_auth_check_plugin(const char *token, void *plugin);
/*! \brief Method to return a list of the plugins a specific token has access to
 * \note It's the caller responsibility to free the list (but NOT the values)
 * @param[in] token The token to get the list for
 * @returns A pointer to a GList instance containing the liist */
GList *janus_auth_list_plugins(const char *token);
/*! \brief Method to disallow a token to use a plugin
 * @param[in] token The token this operation refers to
 * @param[in] plugin Opaque pointer to the janus_plugin instance this token can not access anymore
 * @returns true if the operation was successful, false otherwise */
gboolean janus_auth_disallow_plugin(const char *token, void *plugin);


/*! \brief The external token authenticator function to be used.
 * @param[in] token The token to validate
 * @param[in] root The JSON root of the incoming message being processed
 * @returns true if the token is valid, false otherwise */
gboolean (*janus_auth_check_token_external)(const char *token, json_t *root);


#ifdef HAVE_LIBCURL

/*! \brief External token authenticator that issues http requests for authentication
 * @param[in] token The token to validate
 * @param[in] root The JSON root of the incoming message being processed
 * @returns true if the token is valid, false otherwise */
gboolean janus_auth_check_token_http(const char *token, json_t *root);

#else

/*! \brief External token authenticator that always returns FALSE
 * @param[in] token The token to validate
 * @param[in] root The JSON root of the incoming message being processed
 * @returns false, always */
gboolean janus_auth_check_token_false(const char *token, json_t *root);

#endif

/*! \brief Set the private data of the external token authenticator
 * @param[in] data Data which is meaningful to the external token authenticator
 */
void janus_auth_set_external_private_data(void * data);

/*! \brief Get the private data of the external token authenticator
 * @return the private data previously set
 */
const char * janus_auth_get_external_private_data(void);
#endif
