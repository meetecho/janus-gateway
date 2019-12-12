/*! \file   transport.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Modular Janus API transports (headers)
 * \details  This header contains the definition of the callbacks both
 * the Janus core and all the transports need to implement to interact with
 * each other. The structures to make the communication possible are
 * defined here as well.
 *
 * In particular, the Janus core implements the \c janus_transport_callbacks
 * interface. This means that, as a transport plugin, you can use the
 * methods it exposes to contact the core, e.g., in order to notify
 * an incoming message. In particular, the methods the core exposes
 * to transport plugins are:
 *
 * - \c incoming_request(): to notify an incoming JSON message/event
 * from one of the transport clients.
 *
 * On the other hand, a transport plugin that wants to register at the
 * Janus core needs to implement the \c janus_transport interface. Besides,
 * as a transport plugin is a shared object, and as such external to the
 * core itself, in order to be dynamically loaded at startup it needs
 * to implement the \c create_t() hook as well, that should return a
 * pointer to the plugin instance. This is an example of such a step:
 *
\verbatim
static janus_transport mytransport = {
	[..]
};

janus_transport *create(void) {
	JANUS_LOG(LOG_VERB, , "%s created!\n", MY_TRANSPORT_NAME);
	return &mytransport;
}
\endverbatim
 *
 * This will make sure that your transport plugin is loaded at startup
 * by the Janus core, if it is deployed in the proper folder.
 *
 * As anticipated and described in the above example, a transport plugin
 * must basically be an instance of the \c janus_transport type. As such,
 * it must implement the following methods and callbacks for the core:
 *
 * - \c init(): this is called by the Janus core as soon as your transport
 * plugin is started; this is where you should setup your transport plugin
 * (e.g., static stuff and reading the configuration file);
 * - \c destroy(): on the other hand, this is called by the core when it
 * is shutting down, and your transport plugin should too;
 * - \c get_api_compatibility(): this method MUST return JANUS_TRANSPORT_API_VERSION;
 * - \c get_version(): this method should return a numeric version identifier (e.g., 3);
 * - \c get_version_string(): this method should return a verbose version identifier (e.g., "v1.0.1");
 * - \c get_description(): this method should return a verbose description of your transport plugin (e.g., "This is my avian carrier transport plugin for the Janus API");
 * - \c get_name(): this method should return a short display name for your transport plugin (e.g., "My Amazing Transport");
 * - \c get_package(): this method should return a unique package identifier for your transport plugin (e.g., "janus.transport.mytransport");
 * - \c is_janus_api_enabled(): this method should return TRUE if Janus API can be used with this transport, and support has been enabled by the user;
 * - \c is_admin_api_enabled(): this method should return TRUE if Admin API can be used with this transport, and support has been enabled by the user;
 * - \c send_message(): this method asks the transport to send a message (be it a response or an event) to a client on the specified transport;
 * - \c session_created(): this method notifies the transport that a Janus session has been created by one of its requests;
 * - \c session_over(): this method notifies the transport that one of its Janus sessionss is now over, whether because of a timeout or not.
 * - \c session_claimed(): this method notifies the transport that it has claimed a session.
 *
 * All the above methods and callbacks are mandatory: the Janus core will
 * reject a transport plugin that doesn't implement any of the
 * mandatory callbacks.
 *
 * The Janus core \c janus_transport_callbacks interface is provided to a
 * transport plugin, together with the path to the configurations files
 * folder, in the \c init() method. This path can be used to read and
 * parse a configuration file for the transport plugin: the transport
 * plugins we made available out of the box use the package name as a
 * name for the file (e.g., \c janus.transport.http.cfg for the HTTP/HTTPS
 * transport plugin), but you're free to use a different one, as long
 * as it doesn't collide with existing ones. Besides, the existing transport
 * plugins use the same INI format for configuration files the core
 * uses (relying on the \c janus_config helpers for the purpose) but
 * again, if you prefer a different format (XML, JSON, etc.) that's up to you.
 *
 * \ingroup transportapi
 * \ref transportapi
 */

#ifndef JANUS_TRANSPORT_H
#define JANUS_TRANSPORT_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <inttypes.h>

#include <glib.h>
#include <jansson.h>

#include "refcount.h"


/*! \brief Version of the API, to match the one transport plugins were compiled against */
#define JANUS_TRANSPORT_API_VERSION		7

/*! \brief Initialization of all transport plugin properties to NULL
 *
 * \note All transport plugins MUST add this as the FIRST line when initializing
 * their transport plugin structure, e.g.:
 *
\verbatim
static janus_transport janus_http_transport_plugin =
	{
		JANUS_TRANSPORT_INIT,

		.init = janus_http_init,
		[..]
\endverbatim
 * */
#define JANUS_TRANSPORT_INIT(...) {		\
		.init = NULL,					\
		.destroy = NULL,				\
		.get_api_compatibility = NULL,	\
		.get_version = NULL,			\
		.get_version_string = NULL,		\
		.get_description = NULL,		\
		.get_name = NULL,				\
		.get_author = NULL,				\
		.get_package = NULL,			\
		.is_janus_api_enabled = NULL,	\
		.is_admin_api_enabled = NULL,	\
		.send_message = NULL,			\
		.session_created = NULL,		\
		.session_over = NULL,			\
		.session_claimed = NULL,			\
		## __VA_ARGS__ }


/*! \brief Callbacks to contact the Janus core */
typedef struct janus_transport_callbacks janus_transport_callbacks;
/*! \brief The transport plugin session and callbacks interface */
typedef struct janus_transport janus_transport;
/*! \brief Transport-Gateway session mapping */
typedef struct janus_transport_session janus_transport_session;


/*! \brief Transport-Gateway session mapping */
struct janus_transport_session {
	/*! \brief Opaque pointer to the transport session */
	void *transport_p;
	/*! \brief Pointer to the transport-provided function, if needed, that will be used to free the opaque transport session instance */
	void (*p_free)(void *);
	/*! \brief Whether this mapping has been destroyed definitely or not: if so,
	 * the transport shouldn't make use of it anymore */
	volatile gint destroyed;
	/*! \brief Mutex to protect changes to transport_p */
	janus_mutex mutex;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
};
/*! \brief Helper to create a janus_transport_session instance
 * @note This helper automatically initializes the reference counter
 * @param transport_p Pointer to the transport-side session instance (won't be touched by the core)
 * @param p_free Pointer to the transport-provided function, if needed, that will be used to free the opaque transport-side session instance (won't be touched by the core)
 * @returns Pointer to a valid janus_transport_session, if successful, NULL otherwise */
janus_transport_session *janus_transport_session_create(void *transport_p, void (*p_free)(void *));
/*! \brief Helper to mark a janus_transport_session instance as destroyed
 * @note Only use this helper when that specific transport session must not be
 * used by the core anymore: e.g., a WebSocket connection was closed, an
 * HTTP connection associated with a pending request was lost, etc. Remember
 * to decrease the counter in case you increased it in other methods (this
 * method does this automatically as far as the create was concerned).
 * @param session Pointer to the janus_transport_session instance */
void janus_transport_session_destroy(janus_transport_session *session);


/*! \brief The transport plugin session and callbacks interface */
struct janus_transport {
	/*! \brief Transport plugin initialization/constructor
	 * @param[in] callback The callback instance the transport plugin can use to contact the Janus core
	 * @param[in] config_path Path of the folder where the configuration for this transport plugin can be found
	 * @returns 0 in case of success, a negative integer in case of error */
	int (* const init)(janus_transport_callbacks *callback, const char *config_path);
	/*! \brief Transport plugin deinitialization/destructor */
	void (* const destroy)(void);

	/*! \brief Informative method to request the API version this transport plugin was compiled against
	 *  \note All transport plugins MUST implement this method and return JANUS_TRANSPORT_API_VERSION
	 * to make this work, or they will be rejected by the core. */
	int (* const get_api_compatibility)(void);
	/*! \brief Informative method to request the numeric version of the transport plugin */
	int (* const get_version)(void);
	/*! \brief Informative method to request the string version of the transport plugin */
	const char *(* const get_version_string)(void);
	/*! \brief Informative method to request a description of the transport plugin */
	const char *(* const get_description)(void);
	/*! \brief Informative method to request the name of the transport plugin */
	const char *(* const get_name)(void);
	/*! \brief Informative method to request the author of the transport plugin */
	const char *(* const get_author)(void);
	/*! \brief Informative method to request the package name of the transport plugin (what will be used in web applications to refer to it) */
	const char *(* const get_package)(void);

	/*! \brief Informative method to check whether any Janus API support is currently enabled in this transport */
	gboolean (* const is_janus_api_enabled)(void);
	/*! \brief Informative method to check whether any Admin API support is currently enabled in this transport */
	gboolean (* const is_admin_api_enabled)(void);

	/*! \brief Method to send a message to a client over a transport session
	 * \note It's the transport plugin's responsibility to free the message.
	 * Besides, a successful return does not necessarily mean the message has been
	 * actually sent, but only that it has been accepted by the transport plugim
	 * @param[in] transport Pointer to the transport session instance
	 * @param[in] request_id Will be not-NULL in case this is a response to a previous request
	 * @param[in] admin Whether this is an admin API or a Janus API message
	 * @param[in] message The message data as a Jansson json_t object
	 * @returns 0 on success, a negative integer otherwise */
	int (* const send_message)(janus_transport_session *transport, void *request_id, gboolean admin, json_t *message);
	/*! \brief Method to notify the transport plugin that a new session has been created from this transport
	 * \note A transport plugin may decide to close the connection as a result of such an event
	 * @param[in] transport Pointer to the transport session instance
	 * @param[in] session_id The session ID that was created (if the transport cares) */
	void (* const session_created)(janus_transport_session *transport, guint64 session_id);
	/*! \brief Method to notify the transport plugin that a session it originated timed out
	 * \note A transport plugin may decide to close the connection as a result of such an event
	 * @param[in] transport Pointer to the transport session instance
	 * @param[in] session_id The session ID that was closed (if the transport cares)
	 * @param[in] timeout Whether the cause for the session closure is a timeout (this may interest transport plugins more)
	 * @param[in] claimed Whether the cause for the session closure is due to someone claiming the session */
	void (* const session_over)(janus_transport_session *transport, guint64 session_id, gboolean timeout, gboolean claimed);
	/*! \brief Method to notify the transport plugin that a session it owned was claimed by another transport
	 * \note A transport plugin should close the connection as a result of such an event
	 * @param[in] transport Pointer to the new transport session instance that has claimed the session
	 * @param[in] session_id The session ID that was claimed (if the transport cares) */
	void (* const session_claimed)(janus_transport_session *transport, guint64 session_id);

};

/*! \brief Callbacks to contact the Janus core */
struct janus_transport_callbacks {
	/*! \brief Callback to notify a new incoming request
	 * @param[in] handle The transport session that should be associated to this client
	 * @param[in] transport Pointer to the transport session instance that received the event
	 * @param[in] request_id Opaque pointer to a transport plugin specific value that identifies this request, so that an incoming response coming later can be matched
	 * @param[in] admin Whether this is an admin API or a Janus API request
	 * @param[in] message The message data as a Jansson json_t object */
	void (* const incoming_request)(janus_transport *plugin, janus_transport_session *transport, void *request_id, gboolean admin, json_t *message, json_error_t *error);
	/*! \brief Callback to notify an existing transport instance went away
	 * \note Be careful in calling this method, as the core will assume this
	 * client is gone for good, and will tear down all sessions it originated.
	 * So, it makes sense to call it, for instance, when a WebSocket connection
	 * was lost (the user went away). Not as much if you're handling connections
	 * and their matching with clients your own way (e.g., HTTP/HTTPS connections
	 * will come and go).
	 * @param[in] handle The transport session that went away
	 * @param[in] transport Pointer to the transport session instance that went away */
	void (* const transport_gone)(janus_transport *plugin, janus_transport_session *transport);
	/*! \brief Callback to check with the core if an API secret must be provided
	 * @param[in] apisecret The API secret to validate
	 * @returns TRUE if an API secret is needed, FALSE otherwise */
	gboolean (* const is_api_secret_needed)(janus_transport *plugin);
	/*! \brief Callback to check with the core if a provided API secret is valid
	 * \note This callback should only be needed when, for any reason, the transport needs to
	 * validate requests directly, as in general requests will be validated by the core itself.
	 * It is the case, for instance, of HTTP long polls to get session events, as those never
	 * pass through the core and so need to be validated by the transport plugin on its behalf.
	 * @param[in] apisecret The API secret to validate
	 * @returns TRUE if the API secret is correct, FALSE otherwise */
	gboolean (* const is_api_secret_valid)(janus_transport *plugin, const char *apisecret);
	/*! \brief Callback to check with the core if an authentication token is needed
	 * @returns TRUE if an auth token is needed, FALSE otherwise */
	gboolean (* const is_auth_token_needed)(janus_transport *plugin);
	/*! \brief Callback to check with the core if a provided authentication token is valid
	 * \note This callback should only be needed when, for any reason, the transport needs to
	 * validate requests directly, as in general requests will be validated by the core itself.
	 * It is the case, for instance, of HTTP long polls to get session events, as those never
	 * pass through the core and so need to be validated by the transport plugin on its behalf.
	 * @param[in] token The auth token to validate
	 * @returns TRUE if the auth token is valid, FALSE otherwise */
	gboolean (* const is_auth_token_valid)(janus_transport *plugin, const char *token);

	/*! \brief Callback to check whether the event handlers mechanism is enabled
	 * @returns TRUE if it is, FALSE if it isn't (which means notify_event should NOT be called) */
	gboolean (* const events_is_enabled)(void);
	/*! \brief Callback to notify an event to the registered and subscribed event handlers
	 * \note Don't unref the event object, the core will do that for you
	 * @param[in] plugin The transport originating the event
	 * @param[in] event The event to notify as a Jansson json_t object */
	void (* const notify_event)(janus_transport *plugin, void *transport, json_t *event);
};

/*! \brief The hook that transport plugins need to implement to be created from the Janus core */
typedef janus_transport* create_t(void);

#endif
