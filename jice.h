/*! \file    jice.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN implementation (headers)
 * \details  Implementation of the ICE protocols and mechanisms. The
 * code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. The code exposes methods to manage an ICE agent, register callbacks
 * to be notified about different events, and send media. Each ICE agent
 * is associated with a single thread, which is responsible for both
 * sending and receiving packets. ICE related traffic is handled
 * automatically, with no intervention from the application, while media
 * and data packets delivery is up to the application itself.
 *
 * \b STUN: https://tools.ietf.org/html/rfc5389
 * \b TURN: https://tools.ietf.org/html/rfc5766
 * \b ICE: https://tools.ietf.org/html/rfc5245
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef _JANUS_JICE_H
#define _JANUS_JICE_H

#include <glib.h>

#include "ice.h"
#include "refcount.h"


/*! \brief ICE states */
typedef enum janus_jice_state {
	JANUS_JICE_DISCONNECTED = 0,
	JANUS_JICE_GATHERING,
	JANUS_JICE_CONNECTING,
	JANUS_JICE_CONNECTED,
	JANUS_JICE_READY,
	JANUS_JICE_FAILED
} janus_jice_state;
const char *janus_jice_state_as_string(janus_jice_state state);

/*! \brief Candidate type */
typedef enum janus_jice_type {
	JANUS_JICE_HOST = 0,
	JANUS_JICE_SRFLX,
	JANUS_JICE_PRFLX,
	JANUS_JICE_RELAY
} janus_jice_type;
const char *janus_jice_type_as_string(janus_jice_type type);

/*! \brief Candidate protocol */
typedef enum janus_jice_protocol {
	JANUS_JICE_UDP = 0,
	JANUS_JICE_TCP,
	JANUS_JICE_TURN_UDP,
	JANUS_JICE_TURN_TCP,
	JANUS_JICE_TURN_TLS
} janus_jice_protocol;
const char *janus_jice_protocol_as_string(janus_jice_protocol protocol);


typedef struct janus_jice_agent janus_jice_agent;

/*! \brief ICE candidate */
typedef struct janus_jice_candidate {
	/*! \brief ICE agent this candidate belongs to */
	janus_jice_agent *agent;
	/*! \brief Whether we notified the application about this candidate */
	gboolean notified;
	/*! \brief Type */
	janus_jice_type type;
	/*! \brief Protocol */
	janus_jice_protocol protocol;
	/*! \brief Address */
	struct sockaddr address;
	/*! \brief Base address (only needed for remote candidates, for local we use the base property) */
	struct sockaddr base_address;
	/*! \brief Parent candidate, if any */
	struct janus_jice_candidate *base;
	/*! \brief Gathering check packet, if any */
	void *pkt;
	/*! \brief How many times we have sent this packet */
	guint pkt_trans;
	/*! \brief Priority */
	guint32 priority;
	/*! \brief Foundation */
	char foundation[33];
	/*! \brief Local preference */
	int lp;
	/*! \brief Socket, if any */
	gint fd;
	/*! \brief GLib source for incoming data, if any */
	GSource *source;
} janus_jice_candidate;
janus_jice_candidate *janus_jice_candidate_new(janus_jice_type type, janus_jice_protocol protocol);
janus_jice_candidate *janus_jice_candidate_new_full(janus_jice_type type, janus_jice_protocol protocol,
	guint32 priority, char *foundation, char *ip, guint16 port, char *base_ip, guint16 base_port);
int janus_jice_candidate_render(janus_jice_candidate *candidate, char *buffer, int buflen, char *public_ip);
int janus_jice_parse_address(char *ip, guint16 port, struct sockaddr *address);
int janus_jice_resolve_address(struct sockaddr *address, char *ip, int len, guint16 *port);

/*! \brief Jice stack initialization */
void janus_jice_init(void);
/*! \brief Jice stack de-initialization */
void janus_jice_deinit(void);

/*! \brief Helper method to enable/disable the debugging of the jice stack */
void janus_jice_debugging(gboolean enable);

/* Agent management */
janus_jice_agent *janus_jice_agent_new(void *handle,
	gboolean full, gboolean controlling, gboolean ipv6, gboolean tcp);
int janus_jice_agent_add_interface(janus_jice_agent *agent, char *iface);
int janus_jice_agent_set_port_range(janus_jice_agent *agent, guint16 min_port, guint16 max_port);
int janus_jice_agent_add_stun_server(janus_jice_agent *agent, char *address, guint16 port);
int janus_jice_agent_add_turn_server(janus_jice_agent *agent, char *address, guint16 port,
	janus_jice_protocol protocol, char *user, char *pwd);
int janus_jice_agent_set_localcand_cb(janus_jice_agent *agent,
	void(*localcand_cb)(void *, janus_jice_candidate *));
int janus_jice_agent_set_remotecand_cb(janus_jice_agent *agent,
	void(*remotecand_cb)(void *, janus_jice_candidate *));
int janus_jice_agent_set_state_cb(janus_jice_agent *agent,
	void(*state_cb)(void *, janus_jice_state));
int janus_jice_agent_set_selectedpair_cb(janus_jice_agent *agent,
	void(*selectedpair_cb)(void *, janus_jice_candidate *, janus_jice_candidate *));
int janus_jice_agent_set_recv_cb(janus_jice_agent *agent,
	void(*recv_cb)(void *, char *, guint));
void janus_jice_agent_start_gathering(janus_jice_agent *agent);
char *janus_jice_agent_get_local_ufrag(janus_jice_agent *agent);
char *janus_jice_agent_get_local_pwd(janus_jice_agent *agent);
int janus_jice_agent_set_remote_credentials(janus_jice_agent *agent, char *ufrag, char *pwd);
char *janus_jice_agent_get_remote_ufrag(janus_jice_agent *agent);
char *janus_jice_agent_get_remote_pwd(janus_jice_agent *agent);
int janus_jice_agent_add_remote_candidate(janus_jice_agent *agent, janus_jice_candidate *candidate);
void janus_jice_agent_start_checks(janus_jice_agent *agent);
GSList *janus_jice_agent_get_local_candidates(janus_jice_agent *agent);
GSList *janus_jice_agent_get_remote_candidates(janus_jice_agent *agent);
int janus_jice_agent_send(janus_jice_agent *agent, char *buf, int len);
void janus_jice_agent_restart(janus_jice_agent *agent);
void janus_jice_agent_destroy(janus_jice_agent *agent);

/* Quick method to test a STUN server (and get an address back) */
int janus_jice_test_stun(char *server, guint16 port, struct sockaddr *mapped_address);
/* Quick method to detect the NAT type: needs two different STUN servers to test against */
int janus_jice_detect_nat_type(char *local_ip, char *serverA, guint16 portA, char *serverB, guint16 portB);

#endif
