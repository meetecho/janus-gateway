/*! \file    utils.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    TURN REST API client (headers)
 * \details  Implementation of the \c draft-uberti-rtcweb-turn-rest-00
 * draft, that is a REST API that can be used to access TURN services,
 * more specifically credentials to use. Currently implemented in both
 * rfc5766-turn-server and coturn, and so should be generic enough to
 * be usable here.
 * \note This implementation depends on \c libcurl and is optional.
 *
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_TURNREST_H
#define JANUS_TURNREST_H

#ifdef HAVE_TURNRESTAPI

#include <glib.h>

/*! \brief Initialize the TURN REST API client stack */
void janus_turnrest_init(void);
/*! \brief De-initialize the TURN REST API client stack */
void janus_turnrest_deinit(void);


/*! \brief Set (or reset, in case the server is NULL) the backend that
 * needs to be contacted, and optionally the API key, if required
 * @param server The REST API server address (pass NULL to disable the
 * TURN REST API entirely)
 * @param key The API key, if any (pass NULL if it's not required)
 * @param method The HTTP method to use, POST or GET (NULL means POST) */
void janus_turnrest_set_backend(const char *server, const char *key, const char *method);
/*! \brief Get the currently set TURN REST API backend
 * @returns The currently set TURN REST API backend */
const char *janus_turnrest_get_backend(void);


/*! \brief Complete response from the TURN REST API service */
typedef struct janus_turnrest_response {
	/*! \brief TURN username */
	char *username;
	/*! \brief TURN password */
	char *password;
	/*! \brief Time-to-live of the credentials, in seconds */
	guint32 ttl;
	/*! \brief List of TURN servers */
	GList *servers;
} janus_turnrest_response;

/*! \brief Instance of TURN server as returned by TURN REST API service */
typedef struct janus_turnrest_instance {
	/*! \brief TURN server address */
	char *server;
	/*! \brief TURN server port */
	guint16 port;
	/*! \brief TURN server transport type */
	int transport;
} janus_turnrest_instance;
/*! \brief De-allocate a janus_turnrest_response instance
 * @param response The janus_turnrest_response instance to destroy */
void janus_turnrest_response_destroy(janus_turnrest_response *response);


/*! \brief Retrieve address and credentials for one or more TURN servers
 * @note Use janus_turnrest_response_destroy to get rid of the response, once done
 * @returns A valid janus_turnrest_response instance, if successful, NULL otherwise */
janus_turnrest_response *janus_turnrest_request(void);

#endif

#endif
