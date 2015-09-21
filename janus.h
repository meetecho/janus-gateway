/*! \file   janus.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus core (headers)
 * \details Implementation of the gateway core. This code takes care of
 * the gateway initialization (command line/configuration) and setup,
 * and implements the web server (based on libmicrohttpd) and Janus protocol
 * (a JSON protocol implemented with Jansson) to interact with the web
 * applications. The core also takes care of bridging peers and plugins
 * accordingly. 
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
#include <microhttpd.h>
#ifdef HAVE_WEBSOCKETS
#include <libwebsockets.h>
#endif
#ifdef HAVE_RABBITMQ
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#endif

#include "mutex.h"
#include "dtls.h"
#include "ice.h"
#include "sctp.h"
#include "plugins/plugin.h"


#define JANUS_BUFSIZE	8192


/*! \brief Incoming HTTP message */
typedef struct janus_http_msg {
	/*! \brief Value of the Access-Control-Request-Headers HTTP header, if any (needed for CORS) */
	gchar *acrh;
	/*! \brief Value of the Access-Control-Request-Method HTTP header, if any (needed for CORS) */
	gchar *acrm;
	/*! \brief Content-Type of the payload */
	gchar *contenttype;
	/*! \brief Payload of the message */
	gchar *payload;
	/*! \brief Length of the message in octets */
	size_t len;
	/*! \brief Gateway-Client session identifier this message belongs to */
	gint64 session_id;
} janus_http_msg;

/*! \brief HTTP event to push */
typedef struct janus_http_event {
	/*! \brief HTTP response code */
	gint code;
	/*! \brief Payload to send to the client, if any */
	gchar *payload;
	/*! \brief Whether the payload has been allocated (and thus needs to be freed) or not */
	gint allocated:1;
} janus_http_event;
void janus_http_event_free(janus_http_event *event);


/*! \brief Gateway-Client session */
typedef struct janus_session {
	/*! \brief Janus Gateway-Client session ID */
	guint64 session_id;
	/*! \brief Map of handles this session is managing */
	GHashTable *ice_handles;
	/*! \brief Queue of outgoing messages to push */
	GAsyncQueue *messages;
	/*! \brief Time of the last activity on the session */
	gint64 last_activity;
	/*! \brief Opaque pointer to a janus_request_source instance (where the session came from) */
	void *source;
	/*! \brief Flag to trigger a lazy session destruction */
	gint destroy:1;
	/*! \brief Flag to notify there's been a session timeout */
	gint timeout:1;
	/*! \brief Mutex to lock/unlock this session */
	janus_mutex mutex;
} janus_session;

#ifdef HAVE_WEBSOCKETS
/*! \brief WebSocket client session */
typedef struct janus_websocket_client {
	/*! \brief The libwebsock client context */
	struct libwebsocket_context *context;
	/*! \brief The libwebsock client instance */
	struct libwebsocket *wsi;
	/*! \brief List of gateway sessions this client has created and is managing */
	GHashTable *sessions;
	/*! \brief Queue of outgoing responses to push */
	GAsyncQueue *responses;
	/*! \brief Thread pool to serve requests */
	GThreadPool *thread_pool;
	/*! \brief Mutex to lock/unlock this session */
	janus_mutex mutex;
	/*! \brief Flag to trigger a lazy session destruction */
	gint destroy:1;
} janus_websocket_client;

/*! \brief WebSocket request */
typedef struct janus_websocket_request {
	/*! \brief Opaque pointer to a janus_request_source instance (where the request came from) */
	void *source;
	/*! \brief Opaque pointer to the payload of the request (json_t *) */
	void *request;
} janus_websocket_request;
#endif

#ifdef HAVE_RABBITMQ
/*! \brief RabbitMQ client session */
typedef struct janus_rabbitmq_client {
	/*! \brief List of gateway sessions this client has created and is managing */
	GHashTable *sessions;
	/*! \brief Queue of outgoing responses to push */
	GAsyncQueue *responses;
	/*! \brief Threads to handle messaging */
	GThread *in_thread, *out_thread;
	/*! \brief Thread pool to serve requests */
	GThreadPool *thread_pool;
	/*! \brief Mutex to lock/unlock this session */
	janus_mutex mutex;
	/*! \brief Flag to trigger a lazy session destruction */
	gint destroy:1;
} janus_rabbitmq_client;

/*! \brief RabbitMQ request */
typedef struct janus_rabbitmq_request {
	/*! \brief Opaque pointer to a janus_request_source instance (where the request came from) */
	void *source;
	/*! \brief Opaque pointer to the payload of the request (json_t *) */
	void *request;
} janus_rabbitmq_request;

/*! \brief RabbitMQ response */
typedef struct janus_rabbitmq_response {
	/*! \brief Correlation ID, if any */
	gchar *correlation_id;
	/*! \brief Payload to send to the client */
	gchar *payload;
} janus_rabbitmq_response;
#endif


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
 * @param[in] session_id The Janus Gateway-Client session ID
 * @param[in] event The janus_http_event instance to add to the queue */
void janus_session_notify_event(guint64 session_id, janus_http_event *event);
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
 * \details Since messages may come from different sources (plain HTTP or
 * WebSockets, and potentially even more in the future), we have a shared
 * way to process messages: a method to process a request, and helper methods
 * to return a success or an error message.
 */
///@{
/*! \brief Plain HTTP REST source */
#define JANUS_SOURCE_PLAIN_HTTP		1
/*! \brief WebSocket source */
#define JANUS_SOURCE_WEBSOCKETS		2
/*! \brief RabbitMQ source */
#define JANUS_SOURCE_RABBITMQ		3
/*! \brief Helper to address request sources (e.g., a specific HTTP connection, websocket or RabbitMQ queue) */
typedef struct janus_request_source {
	/*! \brief The source type */
	int type;
	/*! \brief Opaque pointer to the source */
	void *source;
	/*! \brief Opaque pointer to the original request, if available */
	void *msg;
} janus_request_source;
/*! \brief Helper to allocate a janus_request_source instance
 * @param[in] type The source type
 * @param[in] source Opaque pointer to the source
 * @param[in] msg Opaque pointer to the original request, if available
 * @returns A pointer to a janus_request_source instance if successful, NULL otherwise */
janus_request_source *janus_request_source_new(int type, void *source, void *msg);
/*! \brief Helper to destroy a janus_request_source instance
 * @param[in] req_source The janus_request_source instance to destroy
 * @note The opaque pointers in the instance are not destroyed, that's up to you */
void janus_request_source_destroy(janus_request_source *req_source);
/*! \brief Helper to process an incoming request, no matter where it comes from
 * @param[in] source The source that originated the request
 * @param[in] request The JSON request
 * @returns MHD_YES on success, MHD_NO otherwise
 */
int janus_process_incoming_request(janus_request_source *source, json_t *request);
/*! \brief Helper to process an incoming admin/monitor request, no matter where it comes from
 * @param[in] source The source that originated the request
 * @param[in] request The JSON request
 * @returns MHD_YES on success, MHD_NO otherwise
 */
int janus_process_incoming_admin_request(janus_request_source *source, json_t *request);
/*! \brief Method to return a successful Janus response message (JSON) to the browser
 * @param[in] source The source that originated the request
 * @param[in] payload The stringified version of the Janus response (JSON) 
 * @returns MHD_YES on success, MHD_NO otherwise */
int janus_process_success(janus_request_source *source, char *payload);
/*! \brief Method to return an error Janus response message (JSON) to the browser
 * @param[in] source The source that originated the request
 * @param[in] session_id Janus session identifier this error refers to
 * @param[in] transaction The Janus transaction identifier
 * @param[in] error The error code as defined in apierror.h
 * @param[in] format The printf format of the reason string, followed by a variable
 * number of arguments, if needed; if format is NULL, a pre-configured string
 * associated with the error code is used
 * @returns MHD_YES on success, MHD_NO otherwise */
int janus_process_error(janus_request_source *source, uint64_t session_id, const char *transaction, gint error, const char *format, ...) G_GNUC_PRINTF(5, 6);
///@}


/** @name Janus web server
 * \details Browsers make use of HTTP to make requests to the gateway.
 * Since the gateway may be deployed on a different domain than the web
 * server hosting the web applications using it, the gateway automatically
 * handles OPTIONS request to comply with the CORS specification.
 * POST requests can be used to ask for the management of a session with
 * the gateway, to attach to a plugin, to send messages to the plugin
 * itself and so on. GET requests instead are used for getting events
 * associated to a gateway session (and as such to all its plugin handles
 * and the events plugins push in the session itself), using a long poll
 * approach. A JavaScript library (janus.js) implements all of this on
 * the client side automatically.
 */
///@{
/*! \brief Callback (libmicrohttpd) invoked when a new connection is attempted on the REST API */
int janus_ws_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen);
/*! \brief Callback (libmicrohttpd) invoked when a new connection is attempted on the admin/monitor webserver */
int janus_admin_ws_client_connect(void *cls, const struct sockaddr *addr, socklen_t addrlen);
/*! \brief Callback (libmicrohttpd) invoked when an HTTP message (GET, POST, OPTIONS, etc.) is available */
int janus_ws_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
/*! \brief Callback (libmicrohttpd) invoked when an admin/monitor HTTP message (GET, POST, OPTIONS, etc.) is available */
int janus_admin_ws_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
/*! \brief Callback (libmicrohttpd) invoked when headers of an incoming HTTP message have been parsed */
int janus_ws_headers(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
/*! \brief Callback (libmicrohttpd) invoked when a request has been processed and can be freed */
void janus_ws_request_completed (void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);
/*! \brief Worker to handle requests that are actually long polls
 * \details As this method handles a long poll, it doesn't return until an
 * event (e.g., pushed by a plugin) is available, or a timeout (30 seconds)
 * has been fired. In case of a timeout, a keep-alive Janus response (JSON)
 * is sent to tell the browser that the session is still valid.
 * @param[in] source The janus_request_source instance that is handling the request
 * @param[in] max_events The maximum number of events that can be returned in a single response (by default just one; if more, an array is returned)
 * @returns MHD_YES on success, MHD_NO otherwise */
int janus_ws_notifier(janus_request_source *source, int max_events);
///@}

#ifdef HAVE_WEBSOCKETS
/** @name Janus WebSockets server
 * \details Browsers can also make use of WebSockets to make requests to the
 * gateway (as long as, of course, support for them has been built, since
 * they're optional in Janus). In that case, the same WebSocket can be used
 * for both sending requests and receiving notifications, without the need
 * for long polls. At the same time, without the concept of a REST path,
 * requests sent through the WebSockets interface will need to include,
 * when needed, additional pieces of information like \c session_id and
 * \c handle_id. That is, where you'd send a Janus request related to a
 * specific session to the \c /janus/<session> path, with WebSockets
 * you'd have to send the same request with an additional \c session_id
 * field in the JSON payload. The same applies for the handle. Our
 * JavaScript library (janus.js) implements all of this on the client
 * side automatically.
 * \note When you create a session using WebSockets, a subscription to
 * the events related to it is done automatically, so no need for an
 * explicit request as the GET in the plain HTTP API. Closing a WebSocket
 * will also destroy all the sessions it created.
 */
///@{
/*! \brief Worker to handle push notifications from the core or the plugins
 * \details Unlike the long poll mechanism needed for the plain HTTP approach,
 * with WebSockets we can send notifications on the same channel we receive
 * requests from: this thread takes care of notifying all the events related
 * to all the events created by a specific WebSocket client.
 * @param[in] data Opaque pointer to the janus_websocket_client this thread refers to
 * @returns Nothing important */
void *janus_wss_thread(void *data);
/*! \brief Worker to have a new request server by the thread pool
 * @param[in] data Opaque pointer to the content of the response
 * @param[in] user_data Opaque pointer to a janus_websocket_client instance
 * @returns Nothing important */
void janus_wss_task(gpointer data, gpointer user_data);
///@}
#endif


#ifdef HAVE_RABBITMQ
/** @name Janus RabbitMQ support
 * \details Recent versions of Janus now also support RabbitMQ based messaging as
 * an alternative "transport" for API requests, responses and notifications.
 * This is only useful when you're wrapping Janus requests in your server
 * application, and handling the communication with clients your own way.
 * At the moment, only a single "application" can be handled at the same
 * time, meaning that Janus won't implement multiple queues to handle
 * multiple concurrent "application servers" taking advantage of its
 * features. Support for this is planned, though (e.g., through some kind
 * of negotiation to create queues on the fly). Right now, you can only
 * configure the address of the RabbitMQ server to use, and the queues to
 * make use of to receive (to-janus) and send (from-janus) messages
 * from/to an external application. As with WebSockets, considering that
 * requests wouldn't include a path to address some mandatory information,
 * these requests addressed to Janus should include as part of their payload,
 * when needed, additional pieces of information like \c session_id and
 * \c handle_id. That is, where you'd send a Janus request related to a
 * specific session to the \c /janus/<session> path, with RabbitMQ
 * you'd have to send the same request with an additional \c session_id
 * field in the JSON payload.
 * \note When you create a session using RabbitMQ, a subscription to the
 * events related to it is done automatically through the outgoing queue,
 * so no need for an explicit request as the GET in the plain HTTP API.
 */
///@{
/*! \brief Worker to handle incoming messages coming from the external
 * application.
 * @param[in] data Currently unused
 * @returns Nothing important */
void *janus_rmq_in_thread(void *data);
/*! \brief Worker to handle responses and push notifications from the
 * core or the plugins
 * \details Unlike the long poll mechanism needed for the plain HTTP approach,
 * with RabbitMQ both responses and notifications travel on the same outgoing
 * queue. A simple way to discriminate them is to place a correlation_id
 * property in the requests: responses will include it (as part of the RPC
 * pattern), notifications won't. You'll still be able to associate notifications
 * to requests by looking at the transaction identifier in the messages.
 * @param[in] data Currently unused
 * @returns Nothing important */
void *janus_rmq_out_thread(void *data);
/*! \brief Worker to have a new request server by the thread pool
 * @param[in] data Opaque pointer to a janus_rmq_request instance
 * @param[in] user_data Opaque pointer to a janus_rabbitmq_client instance
 * @returns Nothing important */
void janus_rmq_task(gpointer data, gpointer user_data);
///@}
#endif


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
