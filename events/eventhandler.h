/*! \file   eventhandler.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Modular Janus event handlers (headers)
 * \details  This header contains the definition of the callbacks all
 * the event handlers need to implement to interact with the Janus core.
 * In fact, an event handler is basically a module that receives
 * notifications from the Janus core and plugins about things happening,
 * together with more or less detailed information that may be relevant.
 * This may include WebRTC related events (e.g., a PeerConnection going
 * up or down, media stopping or resuming, etc.), events related to media,
 * or custom events plugins may originate on their own (e.g., a participant
 * publishing their media in a conference, or a SIP call starting). What
 * to do with these events is then up to the handler: it may choose to store
 * them somewhere (e.g., a database), analyse and process them, or simply
 * send them to an external tool for statistics purposes or troubleshooting.
 * Whatever the aim, the structures to make the interaction between core
 * and event handlers possible are defined here.
 *
 * An event handler plugin that wants to register at the Janus core needs to
 * implement the \c janus_eventhandler interface. This includes callbacks
 * the Janus core can use to pass and request information, and a mask of
 * the events the plugin is interested in subscribing to. Besides, as an
 * event handler plugin is a shared object, and as such external to the
 * core itself, in order to be dynamically loaded at startup it needs
 * to implement the \c create_e() hook as well, that should return a
 * pointer to the plugin instance. This is an example of such a step:
 *
\verbatim
static janus_eventhandler myhandler = {
	[..]
};

janus_eventhandler *create(void) {
	JANUS_LOG(LOG_VERB, , "%s created!\n", MY_HANDLER_NAME);
	return &myhandler;
}
\endverbatim
 *
 * This will make sure that your event handler plugin is loaded at startup
 * by the Janus core, if it is deployed in the proper folder.
 *
 * As anticipated and described in the above example, an event handler plugin
 * must basically be an instance of the \c janus_eventhandler type. As such,
 * it must implement the following methods and callbacks for the core:
 *
 * - \c init(): this is called by the Janus core as soon as your event handler
 * plugin is started; this is where you should setup your event handler plugin
 * (e.g., static stuff and reading the configuration file);
 * - \c destroy(): on the other hand, this is called by the core when it
 * is shutting down, and your event handler plugin should too;
 * - \c get_api_compatibility(): this method MUST return JANUS_EVENTHANDLER_API_VERSION;
 * - \c get_version(): this method should return a numeric version identifier (e.g., 3);
 * - \c get_version_string(): this method should return a verbose version identifier (e.g., "v1.0.1");
 * - \c get_description(): this method should return a verbose description of your event handler plugin (e.g., "This is an event handler that saves some events on a database");
 * - \c get_name(): this method should return a short display name for your event handler plugin (e.g., "My Amazing Event Handler");
 * - \c get_package(): this method should return a unique package identifier for your event handler plugin (e.g., "janus.eventhandler.myeventhandler");
 * - \c incoming_event(): this callack informs the event handler that an event is available for consumption.
 *
 * All the above methods and callbacks are mandatory: the Janus core will
 * reject an event handler plugin that doesn't implement any of the
 * mandatory callbacks.
 *
 * Additionally, a \c janus_eventhandler instance must also include a
 * mask of the events it is interested in, a \c events_mask janus_flag
 * object that must refer to the available types defined in this header.
 * The core, in fact, will refer to that mask to check whether your event
 * handler is interested in a specific event or not.
 *
 * Unlike other kind of modules (transports, plugins), the \c init() method
 * here only passes the path to the configurations files folder, as event
 * handlers never need to contact the Janus core themselves. This path can be used to read and
 * parse a configuration file for the event handler plugin: the event handler
 * plugins we made available out of the box use the package name as a
 * name for the file (e.g., \c janus.eventhandler.fake.jcfg for the sample
 * event handler plugin), but you're free to use a different one, as long
 * as it doesn't collide with existing ones. Besides, the existing eventhandler
 * plugins use the same libconfig format for configuration files the core
 * uses (relying on the \c janus_config helpers for the purpose) but
 * again, if you prefer a different format (XML, JSON, etc.) that's up to you.
 *
 * \ingroup eventhandlerapi
 * \ref eventhandlerapi
 */

#ifndef JANUS_EVENTHANDLER_H
#define JANUS_EVENTHANDLER_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <inttypes.h>

#include <glib.h>
#include <jansson.h>

#include "../utils.h"


/*! \brief Version of the API, to match the one event handler plugins were compiled against */
#define JANUS_EVENTHANDLER_API_VERSION	3

/*! \brief Initialization of all event handler plugin properties to NULL
 *
 * \note All event handler plugins MUST add this as the FIRST line when initializing
 * their event handler plugin structure, e.g.:
 *
\verbatim
static janus_eventhandler janus_fake_eventhandler_plugin =
	{
		JANUS_EVENTHANDLER_INIT,

		.init = janus_fake_init,
		[..]
\endverbatim
 */

/** @name Type of events Janus could notify, and the handler subscribe to
 * @details This mask makes it easy to subscribe to, and unsubscribe from,
 * specific events, as all you need to do is to use janus_flags_set and
 * janus_flags_clear on the \c events_mask property of the handler instance,
 * and the core will know whether you care about something or not.
 */
///@{
/*! \brief No event */
#define JANUS_EVENT_TYPE_NONE			(0)
/*! \brief Session related events (e.g., session created/destroyed, etc.) */
#define JANUS_EVENT_TYPE_SESSION		(1 << 0)
/*! \brief Handle related events (e.g., handle attached/detached, etc.) */
#define JANUS_EVENT_TYPE_HANDLE			(1 << 1)
/*! \brief External events originated via Admin API (e.g., custom events coming from external scripts) */
#define JANUS_EVENT_TYPE_EXTERNAL		(1 << 2)
/*! \brief JSEP related events (e.g., got/sent offer/answer) */
#define JANUS_EVENT_TYPE_JSEP			(1 << 3)
/*! \brief WebRTC related events (e.g., PeerConnection up/down, ICE updates, DTLS updates, etc.) */
#define JANUS_EVENT_TYPE_WEBRTC			(1 << 4)
/*! \brief Media related events (e.g., media started/stopped flowing, stats on packets/bytes, etc.) */
#define JANUS_EVENT_TYPE_MEDIA			(1 << 5)
/*! \brief Events originated by plugins (at the moment, all of them, no way to pick) */
#define JANUS_EVENT_TYPE_PLUGIN			(1 << 6)
/*! \brief Events originated by transports (at the moment, all of them, no way to pick) */
#define JANUS_EVENT_TYPE_TRANSPORT		(1 << 7)
/*! \brief Events originated by the core for its own events (e.g., Janus starting/shutting down) */
#define JANUS_EVENT_TYPE_CORE			(1 << 8)
	/* TODO Others? */
/*! \brief Mask with all events enabled (shortcut when you want to subscribe to everything) */
#define JANUS_EVENT_TYPE_ALL		(0xffffffff)
///@}

#define JANUS_EVENTHANDLER_INIT(...) {			\
		.init = NULL,							\
		.destroy = NULL,						\
		.get_api_compatibility = NULL,			\
		.get_version = NULL,					\
		.get_version_string = NULL,				\
		.get_description = NULL,				\
		.get_name = NULL,						\
		.get_author = NULL,						\
		.get_package = NULL,					\
		.incoming_event = NULL,					\
		.events_mask = JANUS_EVENT_TYPE_NONE,	\
		## __VA_ARGS__ }


/*! \brief The event handler plugin session and callbacks interface */
typedef struct janus_eventhandler janus_eventhandler;


/*! \brief The event handler plugin session and callbacks interface */
struct janus_eventhandler {
	/*! \brief Event handler plugin initialization/constructor
	 * @param[in] config_path Path of the folder where the configuration for this event handler plugin can be found
	 * @returns 0 in case of success, a negative integer in case of error */
	int (* const init)(const char *config_path);
	/*! \brief Event handler plugin deinitialization/destructor */
	void (* const destroy)(void);

	/*! \brief Informative method to request the API version this event handler plugin was compiled against
	 *  \note All event handler plugins MUST implement this method and return JANUS_EVENTHANDLER_API_VERSION
	 * to make this work, or they will be rejected by the core. */
	int (* const get_api_compatibility)(void);
	/*! \brief Informative method to request the numeric version of the event handler plugin */
	int (* const get_version)(void);
	/*! \brief Informative method to request the string version of the event handler plugin */
	const char *(* const get_version_string)(void);
	/*! \brief Informative method to request a description of the event handler plugin */
	const char *(* const get_description)(void);
	/*! \brief Informative method to request the name of the event handler plugin */
	const char *(* const get_name)(void);
	/*! \brief Informative method to request the author of the event handler plugin */
	const char *(* const get_author)(void);
	/*! \brief Informative method to request the package name of the event handler plugin (what will be used in web applications to refer to it) */
	const char *(* const get_package)(void);

	/*! \brief Method to notify the event handler plugin that a new event is available
	 * \details All events are notified as a Jansson json_t object, and the syntax of
	 * the associated JSON document is as follows:
	 * \verbatim
	{
		"type" : <numeric event type identifier>,
		"timestamp" : <monotonic time of when the event was generated>,
		"session_id" : <unique session identifier>,
		"handle_id" : <unique handle identifier, if provided/available>,
		"event" : {
			<event body, custom depending on event type>
		}
	}
	 * \endverbatim
	 * \note Do NOT handle the event directly in this method. Janus sends events from its
	 * working threads, and so you'd most likely end up slowing it down. Just take note of it
	 * and handle it somewhere else. It's your responsibility to \c json_decref the event
	 * object once you're done with it: a failure to do so will result in memory leaks.
	 * @param[in] event Jansson object containing the event details */
	void (* const incoming_event)(json_t *event);

	/*! \brief Method to send a request to this specific event handler plugin
	 * \details The method takes a Jansson json_t, that contains all the info related
	 * to the request. This object will come from an Admin API request, and is
	 * meant to represent a synchronous request. Since each handler can have
	 * its own bells and whistles, there's no constraint on what this object should
	 * contain, which is entirely handler specific. A json_t object needs to be
	 * returned as a response, which will be sent in response to the Admin API call.
	 * This can be useful to tweak settings in real-time, or to probe the internals
	 * of the handler plugin for monitoring purposes.
	 * @param[in] request Jansson object containing the request
	 * @returns A Jansson object containing the response for the client */
	json_t *(* const handle_request)(json_t *request);

	/*! \brief Mask of events this handler is interested in, as a janus_flags object */
	janus_flags events_mask;
};

/*! \brief The hook that event handler plugins need to implement to be created from the Janus core */
typedef janus_eventhandler* create_e(void);

#endif
