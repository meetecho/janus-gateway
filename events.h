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

#ifndef JANUS_EVENTS_H
#define JANUS_EVENTS_H

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

/*! \brief Helper method to change the mask of events a handler is interested in
 * @note Every time this is called, the mask is resetted, which means that to
 * unsubscribe from a single event you have to pass an updated list
 * @param[in] list A comma separated string of event types to subscribe to
 * @param[out] target The mask to update */
void janus_events_edit_events_mask(const char *list, janus_flags *target);

/*! \brief Helper method to stringify an event type to its label
 * @param[in] type The event type
 * @returns The event type label, if found, or NULL otherwise */
const char *janus_events_type_to_label(int type);

/*! \brief Helper method to stringify an event type to its prettified name
 * @param[in] type The event type
 * @returns The prettified name of the event type, if found, or NULL otherwise */
const char *janus_events_type_to_name(int type);

#endif
