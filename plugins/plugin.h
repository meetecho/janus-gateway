/*! \file   plugin.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Plugin-Core communication
 * \details  This header contains the definition of the callbacks both
 * the Janus core and all the plugins need to implement to interact with
 * each other. The structures to make the communication possible are
 * defined here as well.
 *
 * In particular, the Janus core implements the \c janus_callbacks interface.
 * This means that, as a plugin, you can use the methods it exposes to
 * contact the core, e.g., in order to have it relay a message, event
 * or RTP/RTCP packet to the peer you're handling. In particular, the
 * methods the core exposes to plugins are:
 *
 * - \c push_event(): to send a JSON message/event to the peer (with or without
 * an attached JSEP formatted SDP to negotiate a WebRTC PeerConnection);
 * the syntax of the message/event is completely up to you, the only
 * important thing is that it MUST be a JSON object, as it will be included
 * as such within the Janus session/handle protocol;
 * - \c relay_rtp(): to send/relay the peer an RTP packet;
 * - \c relay_rtcp(): to send/relay the peer an RTCP message.
 * - \c relay_data(): to send/relay the peer a SCTP DataChannel message.
 *
 * On the other hand, a plugin that wants to register at the Janus core
 * needs to implement the \c janus_plugin interface. Besides, as a
 * plugin is a shared object, and as such external to the core itself,
 * in order to be dynamically loaded at startup it needs to implement
 * the \c create_p() hook as well, that should return a pointer to the
 * plugin instance. This is an example of such a step:
 *
\verbatim
static janus_plugin myplugin = {
	[..]
};

janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, , "%s created!\n", MY_PLUGIN_NAME);
	return &myplugin;
}
\endverbatim
 *
 * This will make sure that your plugin is loaded at startup by the Janus core,
 * if it is deployed in the proper folder.
 *
 * As anticipated and described in the above example, a plugin must basically
 * be an instance of the \c janus_plugin type. As such, it must implement
 * the following methods and callbacks for the core:
 *
 * - \c init(): this is called by the Janus core as soon as your plugin is started;
 * this is where you should setup your plugin (e.g., static stuff and reading
 * the configuration file);
 * - \c destroy(): on the other hand, this is called by the core when it
 * is shutting down, and your plugin should too;
 * - \c get_api_compatibility(): this method MUST return JANUS_PLUGIN_API_VERSION;
 * - \c get_version(): this method should return a numeric version identifier (e.g., 3);
 * - \c get_version_string(): this method should return a verbose version identifier (e.g., "v1.0.1");
 * - \c get_description(): this method should return a verbose description of your plugin (e.g., "This is my awesome plugin that does this and that");
 * - \c get_name(): this method should return a short display name for your plugin (e.g., "My Awesome Plugin");
 * - \c get_package(): this method should return a unique package identifier for your plugin (e.g., "janus.plugin.myplugin");
 * - \c create_session(): this method is called by the core to create a session between you and a peer;
 * - \c handle_message(): a callback to notify you the peer sent you a message/request;
 * - \c handle_admin_message(): a callback to notify you a message/request came from the Admin API;
 * - \c setup_media(): a callback to notify you the peer PeerConnection is now ready to be used;
 * - \c incoming_rtp(): a callback to notify you a peer has sent you a RTP packet;
 * - \c incoming_rtcp(): a callback to notify you a peer has sent you a RTCP message;
 * - \c incoming_data(): a callback to notify you a peer has sent you a message on a SCTP DataChannel;
 * - \c data_ready(): a callback to notify you data can be sent on the SCTP DataChannel;
 * - \c slow_link(): a callback to notify you a peer has sent a lot of NACKs recently, and the media path may be slow;
 * - \c hangup_media(): a callback to notify you the peer PeerConnection has been closed (e.g., after a DTLS alert);
 * - \c query_session(): this method is called by the core to get plugin-specific info on a session between you and a peer;
 * - \c destroy_session(): this method is called by the core to destroy a session between you and a peer.
 *
 * All the above methods and callbacks, except for \c incoming_rtp ,
 * \c incoming_rtcp , \c incoming_data and \c slow_link , are mandatory:
 * the Janus core will reject a plugin that doesn't implement any of the
 * mandatory callbacks. The previously mentioned ones, instead, are
 * optional, so you're free to implement only those you care about. If
 * your plugin will not handle any data channel, for instance, it makes
 * sense to not implement the \c incoming_data callback at all. At the
 * same time, if your plugin is ONLY going to use data channels and
 * can't care less about RTP or RTCP, \c incoming_rtp and \c incoming_rtcp
 * can be left out. Finally, \c slow_link is just there as a helper, some
 * additional information you may be interested about, but you're not
 * forced to receive it if you don't care.
 *
 * The Janus core \c janus_callbacks interface is provided to a plugin, together
 * with the path to the configurations files folder, in the \c init() method.
 * This path can be used to read and parse a configuration file for the
 * plugin: the plugins we made available out of the box use the package
 * name as a name for the file (e.g., \c janus.plugin.echotest.cfg for
 * the Echo Test plugin), but you're free to use a different one, as long
 * as it doesn't collide with existing ones. Besides, the existing plugins
 * use the same INI format for configuration files the core uses (relying
 * on the \c janus_config helpers for the purpose) but again, if you prefer
 * a different format (XML, JSON, etc.) that's up to you.
 *
 * Both the the Janus core and a plugin can have several different sessions
 * with the same and/or different peers: to match a specific session,
 * a plugin can rely on a mapping called janus_plugin_session that
 * is what all the communication between the plugins and the core
 * (that is, both methods invoked by the core and callbacks invoked by
 * the plugins) will make use of. See the janus_videoroom.c plugin for
 * an example of multiple handles associated to the same peer.
 *
 * All messages/requests/events sent to and received from a plugin are
 * asynchronous, meaning there's no way to immediately reply to a message
 * sent by a browser, for instance. Messages/requests coming from browsers
 * in a \c handle_message() callback, though, have a transaction
 * identifier, which you can use in a \c push_event() reply to allow the
 * browser to match it to the original request, if needed.
 *
 * As anticipated, both \c handle_message() and \c push_event() can attach
 * a JSEP/SDP payload. This means that a browser, for instance, can attach
 * a JSEP/SDP offer to negotiate a WebRTC PeerConnection with a plugin: the plugin
 * would then need to provide, immediately or not, a JSEP/SDP answer to
 * do so. At the same time, a plugin may want to originate the call instead:
 * in that case, the plugin would attach a JSEP/SDP offer in a \c push_event()
 * call, to which the browser would then need to reply with a JSEP/SDP answer,
 * as described in \ref JS. Renegotiating a session can be done using the
 * same mechanism above: in case plugins want to force an ICE restart,
 * though, they must add a boolean property called \c restart to the JSEP
 * object before passing it to the core. Notice that the core adds a property
 * called \c update whenever the remote user is requesting a renegotiation,
 * whether it's for ICE restarts or just for some media related change.
 * \note It's important to notice that, while the Janus core would indeed
 * take care of the WebRTC PeerConnection setup itself in terms of
 * ICE/DTLS/RT(C)P on your behalf, plugins are what will actually manipulate
 * the media flowing around, and as such it's them who are responsible for
 * what concerns the codec negotiation in a JSEP/SDP offer/answer. This
 * normally is not something you need to worry about, especially if you're
 * just moving SDP around (e.g., janus_echotest.c or janus_videocall.c).
 * If your plugin is going to generate media frames (e.g., as janus_audiobridge.c),
 * you only support some codecs (e.g., Opus in janus_audiobridge.c) or you
 * want to use the same SDP offer for several different sessions (e.g., a webinar),
 * you need to make sure that your offer/answer does not contain anything
 * you don't support. Besides, you also need to make sure that you use
 * SDP-provided information (e.g., payload types, increasing versions in
 * case of renegotiations) coherently.
 *
 * \todo Right now plugins can only interact with peers through the Janus core.
 * Besides, a single PeerConnection can at the moment be used by only one
 * plugin, as that plugin is actually the "owner" of the PeerConnection itself.
 *
 * \ingroup pluginapi
 * \ref pluginapi
 */

#ifndef JANUS_PLUGIN_H
#define JANUS_PLUGIN_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <inttypes.h>

#include <glib.h>

#include "refcount.h"


/*! \brief Version of the API, to match the one plugins were compiled against
 *
 * \note This was added in version 0.0.7 of Janus, to address changes
 * to the API that might break existing plugin or the core itself. All
 * plugins MUST implement the get_api_compatibility() method to make
 * this work. Do NOT try to launch a pre 0.0.7 plugin on a >= 0.0.7
 * Janus instance or it will crash.
 *
 */
#define JANUS_PLUGIN_API_VERSION	15

/*! \brief Initialization of all plugin properties to NULL
 *
 * \note This was added in version 0.0.8 of Janus, to address changes
 * to the API that might break existing plugin or the core itself. All
 * plugins MUST add this as the FIRST line when initializing their
 * plugin structure, e.g.:
 *
\verbatim
static janus_plugin janus_echotest_plugin =
	{
		JANUS_PLUGIN_INIT,

		.init = janus_echotest_init,
		[..]
\endverbatim
 * */
#define JANUS_PLUGIN_INIT(...) {		\
		.init = NULL,					\
		.destroy = NULL,				\
		.get_api_compatibility = NULL,	\
		.get_version = NULL,			\
		.get_version_string = NULL,		\
		.get_description = NULL,		\
		.get_name = NULL,				\
		.get_author = NULL,				\
		.get_package = NULL,			\
		.create_session = NULL,			\
		.handle_message = NULL,			\
		.handle_admin_message = NULL,	\
		.setup_media = NULL,			\
		.incoming_rtp = NULL,			\
		.incoming_rtcp = NULL,			\
		.incoming_data = NULL,			\
		.data_ready = NULL,				\
		.slow_link = NULL,				\
		.hangup_media = NULL,			\
		.destroy_session = NULL,		\
		.query_session = NULL, 			\
		## __VA_ARGS__ }


/*! \brief Callbacks to contact the Janus core */
typedef struct janus_callbacks janus_callbacks;
/*! \brief The plugin session and callbacks interface */
typedef struct janus_plugin janus_plugin;
/*! \brief Plugin-Gateway session mapping */
typedef struct janus_plugin_session janus_plugin_session;
/*! \brief Result of individual requests passed to plugins */
typedef struct janus_plugin_result janus_plugin_result;

/*! \brief RTP packet exchanged with the core */
typedef struct janus_plugin_rtp janus_plugin_rtp;
/*! \brief RTP extensions parsed in an RTP packet */
typedef struct janus_plugin_rtp_extensions janus_plugin_rtp_extensions;
/*! \brief RTCP message exchanged with the core */
typedef struct janus_plugin_rtcp janus_plugin_rtcp;
/*! \brief Data message exchanged with the core */
typedef struct janus_plugin_data janus_plugin_data;

/* Use forward declaration to avoid including jansson.h */
typedef struct json_t json_t;

/*! \brief Plugin-Gateway session mapping */
struct janus_plugin_session {
	/*! \brief Opaque pointer to the Janus core-level handle */
	void *gateway_handle;
	/*! \brief Opaque pointer to the plugin session */
	void *plugin_handle;
	/*! \brief Whether this mapping has been stopped definitely or not: if so,
	 * the plugin shouldn't make use of it anymore */
	volatile gint stopped;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
};

/*! \brief The plugin session and callbacks interface */
struct janus_plugin {
	/*! \brief Plugin initialization/constructor
	 * @param[in] callback The callback instance the plugin can use to contact the Janus core
	 * @param[in] config_path Path of the folder where the configuration for this plugin can be found
	 * @returns 0 in case of success, a negative integer in case of error */
	int (* const init)(janus_callbacks *callback, const char *config_path);
	/*! \brief Plugin deinitialization/destructor */
	void (* const destroy)(void);

	/*! \brief Informative method to request the API version this plugin was compiled against
	 *  \note This was added in version 0.0.7 of Janus, to address changes
	 * to the API that might break existing plugin or the core itself. All
	 * plugins MUST implement this method and return JANUS_PLUGIN_API_VERSION
	 * to make this work, or they will be rejected by the core. Do NOT try
	 * to launch a <= 0.0.7 plugin on a >= 0.0.7 Janus or it will crash. */
	int (* const get_api_compatibility)(void);
	/*! \brief Informative method to request the numeric version of the plugin */
	int (* const get_version)(void);
	/*! \brief Informative method to request the string version of the plugin */
	const char *(* const get_version_string)(void);
	/*! \brief Informative method to request a description of the plugin */
	const char *(* const get_description)(void);
	/*! \brief Informative method to request the name of the plugin */
	const char *(* const get_name)(void);
	/*! \brief Informative method to request the author of the plugin */
	const char *(* const get_author)(void);
	/*! \brief Informative method to request the package name of the plugin (what will be used in web applications to refer to it) */
	const char *(* const get_package)(void);

	/*! \brief Method to create a new session/handle for a peer
	 * @param[in] handle The plugin/gateway session that will be used for this peer
	 * @param[out] error An integer that may contain information about any error */
	void (* const create_session)(janus_plugin_session *handle, int *error);
	/*! \brief Method to handle an incoming message/request from a peer
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] transaction The transaction identifier for this message/request
	 * @param[in] message The json_t object containing the message/request JSON
	 * @param[in] jsep The json_t object containing the JSEP type/SDP, if available
	 * @returns A janus_plugin_result instance that may contain a response (for immediate/synchronous replies), an ack
	 * (for asynchronously managed requests) or an error */
	struct janus_plugin_result * (* const handle_message)(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
	/*! \brief Method to handle an incoming Admin API message/request
	 * @param[in] message The json_t object containing the message/request JSON
	 * @returns A json_t instance containing the response */
	struct json_t * (* const handle_admin_message)(json_t *message);
	/*! \brief Callback to be notified when the associated PeerConnection is up and ready to be used
	 * @param[in] handle The plugin/gateway session used for this peer */
	void (* const setup_media)(janus_plugin_session *handle);
	/*! \brief Method to handle an incoming RTP packet from a peer
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] packet The RTP packet and related data */
	void (* const incoming_rtp)(janus_plugin_session *handle, janus_plugin_rtp *packet);
	/*! \brief Method to handle an incoming RTCP packet from a peer
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] packet The RTP packet and related data */
	void (* const incoming_rtcp)(janus_plugin_session *handle, janus_plugin_rtcp *packet);
	/*! \brief Method to handle incoming SCTP/DataChannel data from a peer (text only, for the moment)
	 * \note We currently only support text data, binary data will follow... please also notice that
	 * DataChannels send unterminated strings, so you'll have to terminate them with a \0 yourself to
	 * use them.
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] packet The message data and related info */
	void (* const incoming_data)(janus_plugin_session *handle, janus_plugin_data *packet);
	/*! \brief Method to be notified about the fact that the datachannel is ready to be written
	 * \note This is not only called when the PeerConnection first becomes available, but also
	 * when the SCTP socket becomes writable again, e.g., because the internal buffer is empty.
	 * @param[in] handle The plugin/gateway session used for this peer */
	void (* const data_ready)(janus_plugin_session *handle);
	/*! \brief Method to be notified by the core when too many NACKs have
	 * been received or sent by Janus, and so a slow or potentially
	 * unreliable network is to be expected for this peer
	 * \note Beware that this callback may be called more than once in a row,
	 * (even though never more than once per second), until things go better for that
	 * PeerConnection. You may or may not want to handle this callback and
	 * act on it, considering you can get bandwidth information from REMB
	 * feedback sent by the peer if the browser supports it. Besides, your
	 * plugin may not have access to encoder related settings to slow down
	 * or decreae the bitrate if required after the callback is called.
	 * Nevertheless, it can be useful for debugging, or for informing your
	 * users about potential issues that may be happening media-wise.
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] uplink Whether this is related to the uplink (Janus to peer)
	 * or downlink (peer to Janus)
	 * @param[in] video Whether this is related to an audio or a video stream */
	void (* const slow_link)(janus_plugin_session *handle, gboolean uplink, gboolean video);
	/*! \brief Callback to be notified about DTLS alerts from a peer (i.e., the PeerConnection is not valid any more)
	 * @param[in] handle The plugin/gateway session used for this peer */
	void (* const hangup_media)(janus_plugin_session *handle);
	/*! \brief Method to destroy a session/handle for a peer
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[out] error An integer that may contain information about any error */
	void (* const destroy_session)(janus_plugin_session *handle, int *error);
	/*! \brief Method to get plugin-specific info of a session/handle
	 *  \note This was added in version 0.0.7 of Janus. Janus assumes
	 * the string is always allocated, so don't return constants here
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @returns A json_t object with the requested info */
	json_t *(* const query_session)(janus_plugin_session *handle);

};

/*! \brief Callbacks to contact the Janus core */
struct janus_callbacks {
	/*! \brief Callback to push events/messages to a peer
	 * @note The Janus core increases the references to both the message and jsep
	 * json_t objects. This means that you'll have to decrease your own
	 * reference yourself with a \c json_decref after calling push_event.
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] plugin The plugin instance that is sending the message/event
	 * @param[in] transaction The transaction identifier this message refers to
	 * @param[in] message The json_t object containing the JSON message
	 * @param[in] jsep The json_t object containing the JSEP type, the SDP attached to the message/event, if any (offer/answer), and whether this is an update */
	int (* const push_event)(janus_plugin_session *handle, janus_plugin *plugin, const char *transaction, json_t *message, json_t *jsep);

	/*! \brief Callback to relay RTP packets to a peer
	 * @param[in] handle The plugin/gateway session used for this peer
	 * @param[in] packet The RTP packet and related data */
	void (* const relay_rtp)(janus_plugin_session *handle, janus_plugin_rtp *packet);
	/*! \brief Callback to relay RTCP messages to a peer
	 * @param[in] handle The plugin/gateway session that will be used for this peer
	 * @param[in] packet The RTCP packet and related data */
	void (* const relay_rtcp)(janus_plugin_session *handle, janus_plugin_rtcp *packet);
	/*! \brief Callback to relay SCTP/DataChannel messages to a peer
	 * @note The protocol is only used for the first message sent on a new data
	 * channel, as it will be used to create it; it will be ignored for following
	 * messages on the same label, so you can set NULL after that
	 * @param[in] handle The plugin/gateway session that will be used for this peer
	 * @param[in] packet The message data and related info */
	void (* const relay_data)(janus_plugin_session *handle, janus_plugin_data *packet);

	/*! \brief Helper to ask for a keyframe via a RTCP PLI
	 * @note This is a shortcut, as it is also possible to do the same by crafting
	 * an RTCP PLI message manually, and passing it to the core via relay_rtcp
	 * @param[in] handle The plugin/gateway session that will be used for this peer */
	void (* const send_pli)(janus_plugin_session *handle);
	/*! \brief Helper to ask for a keyframe via a RTCP PLI
	 * @note This is a shortcut, as it is also possible to do the same by crafting
	 * an RTCP REMB message manually, and passing it to the core via relay_rtcp
	 * @param[in] handle The plugin/gateway session that will be used for this peer
	 * @param[in] bitrate The bitrate value to send in the REMB message */
	void (* const send_remb)(janus_plugin_session *handle, guint32 bitrate);

	/*! \brief Callback to ask the core to close a WebRTC PeerConnection
	 * \note A call to this method will result in the core invoking the hangup_media
	 * callback on this plugin when done
	 * @param[in] handle The plugin/gateway session that the PeerConnection is related to */
	void (* const close_pc)(janus_plugin_session *handle);
	/*! \brief Callback to ask the core to get rid of a plugin/gateway session
	 * \note A call to this method will result in the core invoking the destroy_session
	 * callback on this plugin when done
	 * @param[in] handle The plugin/gateway session to get rid of */
	void (* const end_session)(janus_plugin_session *handle);

	/*! \brief Callback to check whether the event handlers mechanism is enabled
	 * @returns TRUE if it is, FALSE if it isn't (which means notify_event should NOT be called) */
	gboolean (* const events_is_enabled)(void);
	/*! \brief Callback to notify an event to the registered and subscribed event handlers
	 * \note Don't unref the event object, the core will do that for you
	 * @param[in] plugin The plugin originating the event
	 * @param[in] handle The plugin/gateway session originating the event, if any
	 * @param[in] event The event to notify as a Jansson json_t object */
	void (* const notify_event)(janus_plugin *plugin, janus_plugin_session *handle, json_t *event);

	/*! \brief Method to check whether a signed token is valid
	 * \note accepts only tokens with the plugin identifier as realm
	 * @param[in] token The token to validate
	 * @returns TRUE if the signature is valid and not expired, FALSE otherwise */
	gboolean (* const auth_is_signature_valid)(janus_plugin *plugin, const char *token);
	/*! \brief Method to verify a signed token grants access to a descriptor
	 * \note accepts only tokens with the plugin identifier as realm
	 * @param[in] token The token to validate
	 * @param[in] desc The descriptor to search for
	 * @returns TRUE if the token is valid, not expired and contains the descriptor, FALSE otherwise */
	gboolean (* const auth_signature_contains)(janus_plugin *plugin, const char *token, const char *descriptor);
};

/*! \brief The hook that plugins need to implement to be created from the Janus core */
typedef janus_plugin* create_p(void);


/** @name Janus plugin results
 * @brief When a client sends a message to a plugin (e.g., a request or a
 * command) this is notified to the plugin through a handle_message()
 * callback. The plugin can then either handle the request immediately
 * and provide a response (synchronous approach) or decide to queue it
 * and process it later (asynchronous approach). In both cases the plugin
 * must return a janus_plugin_result instance to the core, that will allow
 * the client to: 1. know whether a response is immediately available or
 * it will be later on through notifications, and 2. what the actual content
 * of the result might be. Of course, notifications related to the
 * transaction may occur later on even for synchronous requests, if the
 * plugin was implemented with use cases that envisage this approach.
 * @note An error may be returned as well, but this would cause a core-level
 * error to be returned to the client. If you want to provide indications
 * about a failed operation for application-level reason, the correct
 * approach is to return a success with a plugin-specific payload describing
 * the error.
 */
///@{
/*! \brief Result types */
typedef enum janus_plugin_result_type {
	/*! \brief A severe error happened (not an application level error) */
	JANUS_PLUGIN_ERROR = -1,
	/*! \brief The request was correctly handled and a response is provided (synchronous) */
	JANUS_PLUGIN_OK,
	/*! \brief The request was correctly handled and notifications will follow with more info (asynchronous) */
	JANUS_PLUGIN_OK_WAIT,
} janus_plugin_result_type;

/*! \brief Janus plugin result */
struct janus_plugin_result {
	/*! \brief Result type */
	janus_plugin_result_type type;
	/*! \brief Text associated with this plugin result.
	 * @note This is ONLY used for JANUS_PLUGIN_OK_WAIT (to provide hints on
	 * why a request is being handled asynchronously) and JANUS_PLUGIN_ERROR
	 * (to provide a reason for the error). It is ignored for JANUS_PLUGIN_OK.
	 * Besides, it is NOT freed when destroying the janus_plugin_result instance,
	 * so if you allocated a string for that, you'll have to free it yourself. */
	const char *text;
	/*! \brief Result content
	 * @note This is ONLY used for JANUS_PLUGIN_OK, and is ignored otherwise.
	 * It MUST be a valid JSON payload (even when returning application
	 * level errors). Its reference is decremented automatically when destroying
	 * the janus_plugin_result instance, so if your plugin wants to re-use the
	 * same object for multiple responses, you jave to \c json_incref the object before
	 * passing it to the core, and \c json_decref it when you're done with it. */
	json_t *content;
};

/*! \brief Helper to quickly create a janus_plugin_result instance
 * @param[in] type The type of result
 * @param[in] text String to add to the result (for JANUS_PLUGIN_OK_WAIT or JANUS_PLUGIN_ERROR), if any
 * @param[in] content The json_t object with the content of the result, if any
 * @returns A valid janus_plugin_result instance, if successful, or NULL otherwise */
janus_plugin_result *janus_plugin_result_new(janus_plugin_result_type type, const char *text, json_t *content);

/*! \brief Helper to quickly destroy a janus_plugin_result instance
 * @param[in] result The janus_plugin_result instance to destroy
 * @returns A valid janus_plugin_result instance, if successful, or NULL otherwise */
void janus_plugin_result_destroy(janus_plugin_result *result);
///@}


/** @name Janus plugin media packets
 * @brief The Janus core and plugins exchange different kind of media
 * packets, specifically RTP packets, RTCP messages and datachannel data.
 * While previously these were exchanged between core and plugins using
 * generic pointers and their length, Janus now uses a dedicated structure
 * for each of them: this allows metadata and other info to be carried
 * along the media data itself, making the exchange process extensible
 * as a result (the signature remains the same, the data contained in
 * the struct can change).
 *
 * The janus_plugin_rtp structure represents an RTP packet. When creating
 * a new packet, it should be initialized with janus_plugin_rtp_init. Besides
 * the data and its length, it also contains info on whether the packet is
 * audio or video, and a list of the parsed RTP extensions provided in
 * an instance of the janus_plugin_rtp_extensions structure. Notice that,
 * while this list of extensions is mostly a commodity when receiving a
 * packet, making it easier to access their values (the RTP extensions
 * will still be part of the incoming RTP packet, so plugins are still free
 * to parse them manually), they're very important when it comes to
 * outgoing packets instead: in fact, since the Janus core may needs to
 * terminate its own extensions with the peer, all RTP extensions that
 * are in an RTP packet sent by a plugin are stripped when relay_rtp is
 * called. This means that any attempt to inject an RTP extension in an
 * outgoing packet will fail if the RTP extension is added to the payload
 * manually, and will need to be set in the janus_plugin_rtp_extensions
 * structure instead. It's also important to initialize the extensions
 * structure before passing the packet to the core, as for each extension
 * there may be a different way of telling the core whether the extension
 * needs to be added or not (e.f., \c -1 instead of \c 0 or \c NULL ) .
 * If the RTP extension management you need is not supported, it must be
 * added to the core to get it working.
 *
 * The janus_plugin_rtcp, instead, represents an RTCP packet, which may
 * contain one or more RTCP compound messages. The only info it contains
 * are whether it's related to the audio or video stream, and a pointer
 * to the data itself and its length. When creating a new packet, it should
 * be initialized with janus_plugin_rtcp_init. To make the generation of
 * some of the most common RTCP messages easier, a few helper core
 * callbacks are provided: this means that, while you can craft RTCP
 * messages yourself using the methods available in rtcp.h, it might be
 * easier to send, e.g., a keyframe request using the dedicated method,
 * which will leave the RTCP crafting process up tp the core.
 *
 * Finally, the janus_plugin_data represents a datachannel message. The
 * only info it contains are the label the message came from, a pointer
 * to the data itself and its length. When creating a new packet, it MUST
 * be initialized with janus_plugin_data_init.
 *
 */
///@{
/*! \brief Janus plugin RTP extensions */
struct janus_plugin_rtp_extensions {
	/*! \brief Audio level, in DB (0-127, 127=silence); -1 means no extension */
	int8_t audio_level;
	/*! \brief Whether the encoder detected voice activity (part of audio-level extension)
	 * @note Browsers apparently always set this to 1, so it's unreliable and should be ignored */
	gboolean audio_level_vad;
	/*! \brief Video orientation rotation (0, 90, 180, 270); -1 means no extension */
	int16_t video_rotation;
	/*! \brief Whether the video orientation extension says this is the back camera
	 * @note Will be ignored if no rotation value is set */
	gboolean video_back_camera;
	/*! \brief Whether the video orientation extension says it's flipped horizontally
	 * @note Will be ignored if no rotation value is set */
	gboolean video_flipped;
};
/*! \brief Helper method to initialise/reset the RTP extensions field
 * @note This is important because each of the supported extensions may
 * use a different value to specify an "extension missing" state, which
 * may be different from a 0 or a NULL (e.g., a -1 instead)
 * @param[in] extensions Pointer to the janus_plugin_rtp_extensions instance to reset
*/
void janus_plugin_rtp_extensions_reset(janus_plugin_rtp_extensions *extensions);

/*! \brief Janus plugin RTP packet */
struct janus_plugin_rtp {
	/*! \brief Whether this is an audio or video RTP packet */
	gboolean video;
	/*! \brief The packet data */
	char *buffer;
	/*! \brief The packet length */
	uint16_t length;
	/*! \brief RTP extensions */
	janus_plugin_rtp_extensions extensions;
};
/*! \brief Helper method to initialise/reset the RTP packet
 * @note The main motivation for this method comes from the presence of the
 * extensions as a janus_plugin_rtp_extensions instance.
 * @param[in] packet Pointer to the janus_plugin_rtp packet to reset
*/
void janus_plugin_rtp_reset(janus_plugin_rtp *packet);

/*! \brief Janus plugin RTCP packet */
struct janus_plugin_rtcp {
	/*! \brief Whether this is an audio or video RTCP packet */
	gboolean video;
	/*! \brief The packet data */
	char *buffer;
	/*! \brief The packet length */
	uint16_t length;
};
/*! \brief Helper method to initialise/reset the RTCP packet
 * @param[in] packet Pointer to the janus_plugin_rtcp packet to reset
*/
void janus_plugin_rtcp_reset(janus_plugin_rtcp *packet);

/*! \brief Janus plugin data message
 * @note At the moment, we only support text based datachannels. In the
 * future, once we add support for binary data, this structure may be
 * extended to include info on the nature of the data itself */
struct janus_plugin_data {
	/*! \brief The label this message belongs to */
	char *label;
	/*! \brief The subprotocol this message refers to */
	char *protocol;
	/*! \brief Whether the message data is text (default=FALSE) or binary */
	gboolean binary;
	/*! \brief The message data */
	char *buffer;
	/*! \brief The message length */
	uint16_t length;
};
/*! \brief Helper method to initialise/reset the data message
 * @param[in] packet Pointer to the janus_plugin_data message to reset
*/
void janus_plugin_data_reset(janus_plugin_data *packet);
///@}


#endif
