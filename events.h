/*! \file    events.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Event handler notifications (headers)
 * \details  Event handler plugins can receive events from the Janus core
 * and other plugins, in order to handle them somehow. This methods
 * provide helpers to notify events to such handlers. 
 * 
 * \ingroup core
 * \ref core
 */
 
#ifndef _JANUS_EVENTS_H
#define _JANUS_EVENTS_H

#include "debug.h"
#include "events/eventhandler.h"

/*! \brief Initialize the event handlers broadcaster
 * @param[in] enabled Whether broadcasting events should be supported at all
 * @param[in] server_name The name of this server, to be added to all events
 * @param[in] handlers Map of all registered event handlers
 * @returns 0 on success, a negative integer otherwise */
int janus_events_init(gboolean enabled, char *server_name, GHashTable *handlers);

/*! \brief De-initialize the event handlers broadcaster */
void janus_events_deinit(void);

/*! \brief Quick method to check whether event handlers are enabled at all or not
 * @returns TRUE if they're enabled, FALSE if not */
gboolean janus_events_is_enabled(void);

/*! \brief Notify an event to all interested handlers
 * @note According to the type of event to notify, different arguments may
 * be required and used in order to prepare the actual object to pass to handlers.
 * @param[in] type Type of the event to notify
 * @param[in] session_id Janus session identifier this event refers to */
void janus_events_notify_handlers(int type, guint64 session_id, ...);

/*! \brief Convert event type to text label.
	Labels are lower case and useful for protocol handling.
	For pretty printing, use the names.
	 * @param[in] type Type of the event to notify
 */
const char *event_type_to_label(int event_type);

/*! \brief Convert event type to text name.
	Names may contain spaces, emojis and other stuff
	not suitable for protocol data.
	 * @param[in] type Type of the event to notify
 */
const char *event_type_to_name(int event_type);

#endif
