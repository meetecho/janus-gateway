/*! \file    apierror.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Janus API errors definition
 * \details  Definition of all the API errors that may occur when invoking
 * the Janus web-based JSON API.
 * \todo     This code still needs proper hooks in the JavaScript libraries that use the interface.
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_API_ERROR_H
#define _JANUS_API_ERROR_H

/*! \brief Success (no error) */
#define JANUS_OK								0

/*! \brief Unauthorized (can only happen when using apisecret/auth token) */
#define JANUS_ERROR_UNAUTHORIZED				403
/*! \brief Unauthorized access to a plugin (can only happen when using auth token) */
#define JANUS_ERROR_UNAUTHORIZED_PLUGIN			405
/*! \brief Unknown/undocumented error */
#define JANUS_ERROR_UNKNOWN						490
/*! \brief The client needs to use HTTP POST for this request */
#define JANUS_ERROR_USE_GET						450
/*! \brief The client needs to use HTTP POST for this request */
#define JANUS_ERROR_USE_POST					451
/*! \brief The request is missing in the message */
#define JANUS_ERROR_MISSING_REQUEST				452
/*! \brief The gateway does not suppurt this request */
#define JANUS_ERROR_UNKNOWN_REQUEST				453
/*! \brief The payload is not a valid JSON message */
#define JANUS_ERROR_INVALID_JSON				454
/*! \brief The object is not a valid JSON object as expected */
#define JANUS_ERROR_INVALID_JSON_OBJECT			455
/*! \brief A mandatory element is missing in the message */
#define JANUS_ERROR_MISSING_MANDATORY_ELEMENT	456
/*! \brief The request cannot be handled for this webserver path  */
#define JANUS_ERROR_INVALID_REQUEST_PATH		457
/*! \brief The session the request refers to doesn't exist */
#define JANUS_ERROR_SESSION_NOT_FOUND			458
/*! \brief The handle the request refers to doesn't exist */
#define JANUS_ERROR_HANDLE_NOT_FOUND			459
/*! \brief The plugin the request wants to talk to doesn't exist */
#define JANUS_ERROR_PLUGIN_NOT_FOUND			460
/*! \brief An error occurring when trying to attach to a plugin and create a handle  */
#define JANUS_ERROR_PLUGIN_ATTACH				461
/*! \brief An error occurring when trying to send a message/request to the plugin */
#define JANUS_ERROR_PLUGIN_MESSAGE				462
/*! \brief An error occurring when trying to detach from a plugin and destroy the related handle  */
#define JANUS_ERROR_PLUGIN_DETACH				463
/*! \brief The gateway doesn't support this SDP type
 * \todo The gateway currently only supports OFFER and ANSWER. */
#define JANUS_ERROR_JSEP_UNKNOWN_TYPE			464
/*! \brief The Session Description provided by the peer is invalid */
#define JANUS_ERROR_JSEP_INVALID_SDP			465
/*! \brief The stream a trickle candidate for does not exist or is invalid */
#define JANUS_ERROR_TRICKE_INVALID_STREAM		466
/*! \brief A JSON element is of the wrong type (e.g., an integer instead of a string) */
#define JANUS_ERROR_INVALID_ELEMENT_TYPE		467
/*! \brief The ID provided to create a new session is already in use */
#define JANUS_ERROR_SESSION_CONFLICT			468
/*! \brief We got an ANSWER to an OFFER we never made */
#define JANUS_ERROR_UNEXPECTED_ANSWER			469
/*! \brief The auth token the request refers to doesn't exist */
#define JANUS_ERROR_TOKEN_NOT_FOUND				470


/*! \brief Helper method to get a string representation of an API error code
 * @param[in] error The API error code
 * @returns A string representation of the error code */
const char *janus_get_api_error(int error);

#endif
