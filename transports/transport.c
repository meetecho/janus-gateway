/*! \file   transport.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Modular Janus API transports
 * \details  This header contains the definition of the callbacks both
 * the gateway and all the transports need too implement to interact with
 * each other. The structures to make the communication possible are
 * defined here as well.
 * 
 * \ingroup transportapi
 * \ref transportapi
 */

#include "transport.h"
#include "debug.h"

static void janus_transport_session_free(const janus_refcount *transport_ref) {
	janus_transport_session *session = janus_refcount_containerof(transport_ref, janus_transport_session, ref);
	JANUS_LOG(LOG_WARN, "Freeing transport session: %p\n", session);
	/* This session can be destroyed, free all the resources */
	if(session->p_free)
		session->p_free(session->transport_p);
	g_free(session);
}

janus_transport_session *janus_transport_session_create(void *transport_p, void (*p_free)(void *)) {
	janus_transport_session *tp = g_malloc0(sizeof(janus_transport_session));
	tp->transport_p = transport_p;
	tp->p_free = p_free;
	g_atomic_int_set(&tp->destroyed, 0);
	janus_refcount_init(&tp->ref, janus_transport_session_free);
	return tp;
}

void janus_transport_session_destroy(janus_transport_session *session) {
	if(!session)
		return;
	if(!g_atomic_int_compare_and_exchange(&session->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&session->ref);
}
