/*! \file   janus.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus core (headers)
 * \details Implementation of the gateway core. This code takes care of
 * the gateway initialization (command line/configuration) and setup,
 * and makes use of the available transport plugins (by default HTTP,
 * WebSockets, RabbitMQ, if compiled) and Janus protocol (a JSON-based
 * protocol) to interact with the applications, whether they're web based
 * or not. The core also takes care of bridging peers and plugins
 * accordingly, in terms of both messaging and real-time media transfer
 * via WebRTC. 
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_GATEWAY_H
#define _JANUS_GATEWAY_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <jansson.h>

#include "mutex.h"
#include "dtls.h"
#include "ice.h"
#include "sctp.h"
#include "transports/transport.h"
#include "events/eventhandler.h"
#include "plugins/plugin.h"


#define JANUS_BUFSIZE	8192

/*! \brief Helper to address requests and their sources (e.g., a specific HTTP connection, websocket, RabbitMQ or others) */
typedef struct janus_request janus_request;
 
/*! \brief Gateway-Client session */
typedef struct janus_session {
	/*! \brief Janus Gateway-Client session ID */
	guint64 session_id;
	/*! \brief Map of handles this session is managing */
	GHashTable *ice_handles;
	/*! \brief Time of the last activity on the session */
	gint64 last_activity;
	/*! \brief Pointer to the request instance (and the transport that originated the session) */
	janus_request *source;
	/*! \brief Flag to trigger a lazy session destruction */
	gint destroy:1;
	/*! \brief Flag to notify there's been a session timeout */
	gint timeout:1;
	/*! \brief Mutex to lock/unlock this session */
	janus_mutex mutex;
} janus_session;


/** @name Janus Gateway-Client session methods
 */
///@{
/*! \brief Method to create a new Janus Gateway-Client session
 * @param[in] session_id The desired Janus Gateway-Client session ID, or 0 if it needs to be generated randomly
 * @returns The created Janus Gateway-Client session if successful, NULL otherwise */
janus_session *janus_session_create(guint64 session_id);
/*! \brief Method to find an existing Janus Gateway-Client session from its ID
 * @param[in] session_id The Janus Gateway-Client session ID
 * @returns The created Janus Gateway-Client session if successful, NULL otherwise */
janus_session *janus_session_find(guint64 session_id);
/*! \brief Method to add an event to notify to the queue of notifications for this session
 * @param[in] session The Janus Gateway-Client session instance to notify
 * @param[in] event The event to notify as a Jansson JSON object */
void janus_session_notify_event(janus_session *session, json_t *event);
/*! \brief Method to find an existing Janus Gateway-Client session scheduled to be destroyed from its ID
 * @param[in] session_id The Janus Gateway-Client session ID
 * @returns The created Janus Gateway-Client session if successful, NULL otherwise */
janus_session *janus_session_find_destroyed(guint64 session_id);
/*! \brief Method to destroy a Janus Gateway-Client session
 * @param[in] session_id The Janus Gateway-Client session ID to destroy
 * @returns 0 in case of success, a negative integer otherwise */
gint janus_session_destroy(guint64 session_id);
/*! \brief Method to actually free the resources allocated by a Janus Gateway-Client session
 * @param[in] session The Janus Gateway-Client session instance to free */
void janus_session_free(janus_session *session);
///@}


/** @name Janus request processing
 * \details Since messages may come from different sources (plain HTTP,
 * WebSockets, RabbitMQ and potentially even more in the future), we
 * have a shared way to process messages: a method to process a request,
 * and helper methods to return a success or an error message.
 */
///@{
/*! \brief Helper to address requests and their sources (e.g., a specific HTTP connection, websocket, RabbitMQ or others) */
struct janus_request {
	/*! \brief Pointer to the transport plugin */
	janus_transport *transport;
	/*! \brief Opaque pointer to the transport-provided instance */
	void *instance;
	/*! \brief Opaque pointer to the request ID, if available */
	void *request_id;
	/*! \brief Whether this is a Janus API or admin API request */
	gboolean admin;
	/*! \brief Pointer to the original request, if available */
	json_t *message;
};
/*! \brief Helper to allocate a janus_request instance
 * @param[in] transport Pointer to the transport
 * @param[in] instance Opaque pointer to the transport-provided instance
 * @param[in] request_id Opaque pointer to the request ID, if available
 * @param[in] admin Whether this is a Janus API or Admin API request
 * @param[in] message Opaque pointer to the original request, if available
 * @returns A pointer to a janus_request instance if successful, NULL otherwise */
janus_request *janus_request_new(janus_transport *transport, void *instance, void *request_id, gboolean admin, json_t *message);
/*! \brief Helper to destroy a janus_request instance
 * @param[in] request The janus_request instance to destroy
 * @note The opaque pointers in the instance are not destroyed, that's up to you */
void janus_request_destroy(janus_request *request);
/*! \brief Helper to process an incoming request, no matter where it comes from
 * @param[in] request The JSON request
 * @returns 0 on success, a negative integer otherwise
 */
int janus_process_incoming_request(janus_request *request);
/*! \brief Helper to process an incoming admin/monitor request, no matter where it comes from
 * @param[in] request The request instance and its source
 * @returns 0 on success, a negative integer otherwise
 */
int janus_process_incoming_admin_request(janus_request *request);
/*! \brief Method to return a successful Janus response message (JSON) to the browser
 * @param[in] request The request instance and its source
 * @param[in] payload The payload to return as a JSON object
 * @returns 0 on success, a negative integer otherwise
 */
int janus_process_success(janus_request *request, json_t *payload);
/*! \brief Method to return an error Janus response message (JSON) to the browser
 * @param[in] request The request instance and its source
 * @param[in] session_id Janus session identifier this error refers to
 * @param[in] transaction The Janus transaction identifier
 * @param[in] error The error code as defined in apierror.h
 * @param[in] format The printf format of the reason string, followed by a variable
 * number of arguments, if needed; if format is NULL, a pre-configured string
 * associated with the error code is used
 * @returns 0 on success, a negative integer otherwise
 */
int janus_process_error(janus_request *request, uint64_t session_id, const char *transaction, gint error, const char *format, ...) G_GNUC_PRINTF(5, 6);
///@}


/** @name Janus transport plugin management
 * The core doesn't support any transport for the Janus API by default.
 * In order to be able to with external clients, transport plugins are
 * needed, e.g., to provide support for REST HTTP/HTTPS, WebSockets,
 * RabbitMQ or others. These transport plugins are shared objects that
 * need to implement the interfaces defined in transport.h and as such
 * are dynamically loaded by the gateway at startup, and unloaded when
 * the gateway closes.
 */
///@{
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to destroy a transport instance
 * @param[in] key Key of the transports hash table (package name)
 * @param[in] value The janus_transport instance to destroy
 * @param[in] user_data User provided data (unused) */
void janus_transport_close(void *key, void *value, void *user_data);
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to close a transport plugin
 * @param[in] key Key of the transports hash table (package name)
 * @param[in] value The janus_transport instance to close
 * @param[in] user_data User provided data (unused) */
void janus_transportso_close(void *key, void *value, void *user_data);
///@}

/** @name Janus event handler plugin management
 * The core doesn't notify anyone, except session originators, and only
 * then only about stuff relevant to them. In order to allow for a more
 * apt management of core and plugin related events on a broader sense,
 * event handler plugins are needed. These event handler plugins are
 * shared objects that need to implement the interfaces defined in
 * eventhandler.h and as such are dynamically loaded by the gateway at
 * startup, and unloaded when the gateway closes.
 */
///@{
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to destroy an eventhandler instance
 * @param[in] key Key of the events hash table (package name)
 * @param[in] value The janus_eventhandler instance to destroy
 * @param[in] user_data User provided data (unused) */
void janus_eventhandler_close(void *key, void *value, void *user_data);
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to close an eventhandler plugin
 * @param[in] key Key of the events hash table (package name)
 * @param[in] value The janus_eventhandler instance to close
 * @param[in] user_data User provided data (unused) */
void janus_eventhandlerso_close(void *key, void *value, void *user_data);
///@}

/** @name Janus plugin management
 * As anticipated, the gateway doesn't provide any specific feature: it takes
 * care of WebRTC-related stuff, and of sending and receiving JSON-based
 * messages. To implement applications based on these foundations, plugins
 * can be used. These plugins are shared objects that need to implement
 * the interfaces defined in plugin.h and as such are dynamically loaded
 * by the gateway at startup, and unloaded when the gateway closes.
 */
///@{
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to destroy a plugin instance
 * @param[in] key Key of the plugins hash table (package name)
 * @param[in] value The janus_plugin plugin instance to destroy
 * @param[in] user_data User provided data (unused) */
void janus_plugin_close(void *key, void *value, void *user_data);
/*! \brief Callback (g_hash_table_foreach) invoked when it's time to close a plugin
 * @param[in] key Key of the plugins hash table (package name)
 * @param[in] value The janus_plugin plugin instance to close
 * @param[in] user_data User provided data (unused) */
void janus_pluginso_close(void *key, void *value, void *user_data);
/*! \brief Method to return a registered plugin instance out of its package name
 * @param[in] package The unique package name of the plugin
 * @returns The plugin instance */
janus_plugin *janus_plugin_find(const gchar *package);
///@}

/*! \brief Helper method to return the path to the provided server certificate */
gchar *janus_get_server_pem(void);
/*! \brief Helper method to return the path to the provided server certificate key */
gchar *janus_get_server_key(void);


/*! \brief Helper method to return the local IP address (autodetected by default) */
gchar *janus_get_local_ip(void);
/*! \brief Helper method to return the IP address to use in the SDP (autodetected by default) */
gchar *janus_get_public_ip(void);
/*! \brief Helper method to overwrite the IP address to use in the SDP */
void janus_set_public_ip(const char *ip);
/*! \brief Helper method to check whether the gateway is being shut down */
gint janus_is_stopping(void);


#endif
