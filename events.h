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
 * @param[in] eventhandlers Map of all registered event handlers */
void janus_events_init(GHashTable *eventhandlers);

/*! \brief Notify an event to all interested handlers
 * @note According to the type of event to notify, different arguments may
 * be required and used in order to prepare the actual object to pass to handlers.
 * @param[in] type Type of the event to notify
 * @param[in] session_id Janus session identifier this event refers to */
void janus_events_notify_handlers(int type, guint64 session_id, ...);

#endif
