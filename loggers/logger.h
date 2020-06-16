/*! \file   logger.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Modular Janus loggers (headers)
 * \details  This header contains the definition of the callbacks all
 * the custom loggers need to implement to interact with the Janus core.
 * In fact, a custom logger is basically a module that receives log lines
 * from the Janus core and plugins, so that they can be handled somehow
 * (e.g., aggregated or forwarded elsewhere).
 *
 * An logger plugin that wants to register at the Janus core needs to
 * implement the \c janus_logger interface. This includes callbacks
 * the Janus core can use to receive log lines to process. Besides, as a
 * logger plugin is a shared object, and as such external to the
 * core itself, in order to be dynamically loaded at startup it needs
 * to implement the \c create_l() hook as well, that should return a
 * pointer to the plugin instance. This is an example of such a step:
 *
\verbatim
static janus_logger mylogger = {
	[..]
};

janus_logger *create(void) {
	JANUS_LOG(LOG_VERB, , "%s created!\n", MY_LOGGER_NAME);
	return &mylogger;
}
\endverbatim
 *
 * This will make sure that your logger plugin is loaded at startup
 * by the Janus core, if it is deployed in the proper folder.
 *
 * As anticipated and described in the above example, a logger plugin
 * must basically be an instance of the \c janus_logger type. As such,
 * it must implement the following methods and callbacks for the core:
 *
 * - \c init(): this is called by the Janus core as soon as your logger
 * plugin is started; this is where you should setup your logger plugin
 * (e.g., static stuff and reading the configuration file);
 * - \c destroy(): on the other hand, this is called by the core when it
 * is shutting down, and your logger plugin should too;
 * - \c get_api_compatibility(): this method MUST return JANUS_LOGGER_API_VERSION;
 * - \c get_version(): this method should return a numeric version identifier (e.g., 3);
 * - \c get_version_string(): this method should return a verbose version identifier (e.g., "v1.0.1");
 * - \c get_description(): this method should return a verbose description of your logger plugin (e.g., "This is a logger that saves log lines on a database");
 * - \c get_name(): this method should return a short display name for your logger plugin (e.g., "My Amazing Logger");
 * - \c get_package(): this method should return a unique package identifier for your logger plugin (e.g., "janus.logger.mylogger");
 * - \c incoming_logline(): this callack informs the logger that a log line is available for consumption.
 *
 * All the above methods and callbacks are mandatory: the Janus core will
 * reject al logger plugin that doesn't implement any of the mandatory callbacks.
 *
 * Unlike other kind of modules (transports, plugins), the \c init() method
 * here only passes the path to the configurations files folder, as loggers
 * never need to contact the Janus core themselves. This path can be used to
 * read and parse a configuration file for the logger plugin: the logger
 * plugins we made available out of the box use the package name as a
 * name for the file (e.g., \c janus.logger.json.jcfg for the sample
 * logger plugin), but you're free to use a different one, as long
 * as it doesn't collide with existing ones. Besides, the existing logger
 * plugins use the same libconfig format for configuration files the core
 * uses (relying on the \c janus_config helpers for the purpose) but
 * again, if you prefer a different format (XML, JSON, etc.) that's up to you.
 *
 * \ingroup loggerapi
 * \ref loggerapi
 */

#ifndef JANUS_LOGGER_H
#define JANUS_LOGGER_H

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


/*! \brief Version of the API, to match the one logger plugins were compiled against */
#define JANUS_LOGGER_API_VERSION	3

/*! \brief Initialization of all logger plugin properties to NULL
 *
 * \note All logger plugins MUST add this as the FIRST line when initializing
 * their logger plugin structure, e.g.:
 *
\verbatim
static janus_logger janus_fake_logger_plugin =
	{
		JANUS_LOGGER_INIT,

		.init = janus_fake_init,
		[..]
\endverbatim
 */

#define JANUS_LOGGER_INIT(...) {			\
		.init = NULL,							\
		.destroy = NULL,						\
		.get_api_compatibility = NULL,			\
		.get_version = NULL,					\
		.get_version_string = NULL,				\
		.get_description = NULL,				\
		.get_name = NULL,						\
		.get_author = NULL,						\
		.get_package = NULL,					\
		.incoming_logline = NULL,				\
		## __VA_ARGS__ }


/*! \brief The logger plugin session and callbacks interface */
typedef struct janus_logger janus_logger;


/*! \brief The logger plugin session and callbacks interface */
struct janus_logger {
	/*! \brief Logger plugin initialization/constructor
	 * @param[in] server_name Name of the Janus instance generating the logs
	 * @param[in] config_path Path of the folder where the configuration for this logger plugin can be found
	 * @returns 0 in case of success, a negative integer in case of error */
	int (* const init)(const char *server_name, const char *config_path);
	/*! \brief Logger plugin deinitialization/destructor */
	void (* const destroy)(void);

	/*! \brief Informative method to request the API version this logger plugin was compiled against
	 *  \note All logger plugins MUST implement this method and return JANUS_LOGGER_API_VERSION
	 * to make this work, or they will be rejected by the core. */
	int (* const get_api_compatibility)(void);
	/*! \brief Informative method to request the numeric version of the logger plugin */
	int (* const get_version)(void);
	/*! \brief Informative method to request the string version of the logger plugin */
	const char *(* const get_version_string)(void);
	/*! \brief Informative method to request a description of the logger plugin */
	const char *(* const get_description)(void);
	/*! \brief Informative method to request the name of the logger plugin */
	const char *(* const get_name)(void);
	/*! \brief Informative method to request the author of the logger plugin */
	const char *(* const get_author)(void);
	/*! \brief Informative method to request the package name of the logger plugin (what will be used in web applications to refer to it) */
	const char *(* const get_package)(void);

	/*! \brief Method to notify the logger plugin that a new log line is available
	 * \details All log lines are notified as a string
	 * \note Do NOT handle the log line directly in this method. Janus sends
	 * log lines from its internal logger thread, so any I/O or blocking thing
	 * you may be doing here would most likely end up slowing it down. Just take
	 * note of it and handle it somewhere else. It's your responsibility to
	 * duplicate the string to use it later: the string you get in the callback
	 * is NOT a copy, and MUST NOT be modified.
	 * @param[in] timestamp Monotonic timestamp of when the log line was printed
	 * @param[in] line String containing the log line */
	void (* const incoming_logline)(int64_t timestamp, const char *line);

	/*! \brief Method to send a request to this specific logger plugin
	 * \details The method takes a Jansson json_t, that contains all the info related
	 * to the request. This object will come from an Admin API request, and is
	 * meant to represent a synchronous request. Since each logger can have
	 * its own bells and whistles, there's no constraint on what this object should
	 * contain, which is entirely logger-specific. A json_t object needs to be
	 * returned as a response, which will be sent in response to the Admin API call.
	 * This can be useful to tweak settings in real-time, or to probe the internals
	 * of the logger plugin for monitoring purposes.
	 * @param[in] request Jansson object containing the request
	 * @returns A Jansson object containing the response for the client */
	json_t *(* const handle_request)(json_t *request);
};

/*! \brief The hook that logger plugins need to implement to be created from the Janus core */
typedef janus_logger* create_l(void);

#endif
