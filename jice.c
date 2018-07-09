/*! \file    jice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN implementation
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

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>       
#include <netinet/in.h>
#include <sys/poll.h>

#include <zlib.h>
#include <openssl/hmac.h>

#include "jice.h"
#include "ice.h"
#include "ip-utils.h"
#include "debug.h"
#include "utils.h"


/* Debugging: we define our own values, so that we can tweak them at runtime */
static int JICE_LOG_FATAL = LOG_DBG;
static int JICE_LOG_ERR = LOG_DBG;
static int JICE_LOG_WARN = LOG_DBG;
static int JICE_LOG_INFO = LOG_DBG;
static int JICE_LOG_VERB = LOG_DBG;
static int JICE_LOG_HUGE = LOG_DBG;


/*! \brief Fatal error */
#define LOG_FATAL    (1)
/*! \brief Non-fatal error */
#define LOG_ERR      (2)
/*! \brief Warning */
#define LOG_WARN     (3)
/*! \brief Informational message */
#define LOG_INFO     (4)
/*! \brief Verbose message */
#define LOG_VERB     (5)
/*! \brief Overly verbose message */
#define LOG_HUGE     (6)
/*! \brief Debug message (includes .c filename, function and line number) */
#define LOG_DBG      (7)


/* Classes */
#define	JANUS_STUN_REQUEST					0
#define	JANUS_STUN_INDICATION				1
#define	JANUS_STUN_SUCCESS_RESPONSE			2
#define	JANUS_STUN_ERROR_RESPONSE			3
/* Methods */
#define JANUS_STUN_BINDING					0x0001
#define JANUS_STUN_TURN_ALLOCATE			0x0003
#define JANUS_STUN_TURN_REFRESH				0x0004
#define JANUS_STUN_TURN_SEND				0x0006
#define JANUS_STUN_TURN_DATA				0x0007
#define JANUS_STUN_TURN_CREATE_PERMISSION	0x0008
#define JANUS_STUN_TURN_CHANNEL_BIND		0x0009
/* Magic Cookie and Fingerprint XOR */
#define JANUS_STUN_MAGIC_COOKIE				0x2112a442
#define JANUS_STUN_FINGERPRINT_XOR			0x5354554e
/* Attributes (STUN) */
#define JANUS_STUN_ATTR_MAPPED_ADDRESS		0x0001
#define JANUS_STUN_ATTR_USERNAME			0x0006
#define JANUS_STUN_ATTR_MESSAGE_INTEGRITY	0x0008
#define JANUS_STUN_ATTR_ERROR_CODE			0x0009
#define JANUS_STUN_ATTR_UNKNOWN_ATTRIBUTES	0x000A
#define JANUS_STUN_ATTR_REALM				0x0014
#define JANUS_STUN_ATTR_NONCE				0x0015
#define JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS	0x0020
#define JANUS_STUN_ATTR_SOFTWARE			0x8022
#define JANUS_STUN_ATTR_ALTERNATE_SERVER	0x8023
#define JANUS_STUN_ATTR_FINGERPRINT			0x8028
/* Attributes (ICE) */
#define JANUS_STUN_ATTR_PRIORITY			0x0024
#define JANUS_STUN_ATTR_USE_CANDIDATE		0x0025
#define JANUS_STUN_ATTR_ICE_CONTROLLED		0x8029
#define JANUS_STUN_ATTR_ICE_CONTROLLING		0x802A
/* Experimental */
#define JANUS_STUN_ATTR_NETWORK_COST		0xC057
/* Attributes (TURN) */
#define JANUS_STUN_ATTR_CHANNEL_NUMBER		0x000C
#define JANUS_STUN_ATTR_LIFETIME			0x000D
#define JANUS_STUN_ATTR_XOR_PEER_ADDRESS	0x0012
#define JANUS_STUN_ATTR_DATA				0x0013
#define JANUS_STUN_ATTR_XOR_RELAYED_ADDRESS	0x0016
#define JANUS_STUN_ATTR_EVEN_PORT			0x0018
#define JANUS_STUN_ATTR_REQUESTED_TRANSPORT	0x0019
#define JANUS_STUN_ATTR_DONT_FRAGMENT		0x001A
#define JANUS_STUN_ATTR_RESERVATION_TOKEN	0x0022
/* Errors */
#define JANUS_STUN_ERROR_TRY_ALTERNATE		300
#define JANUS_STUN_ERROR_BAD_REQUEST		400
#define JANUS_STUN_ERROR_UNAUTHORIZED		401
#define JANUS_STUN_ERROR_UNKNOWN_ATTRIBUTE	420
#define JANUS_STUN_ERROR_STALE_NONCE		438
#define JANUS_STUN_ERROR_ROLE_CONFLICT		487
#define JANUS_STUN_ERROR_SERVER_ERROR		500

/* Type preferences for SDP encoding */
#define JANUS_JICE_TYPE_PREFERENCE_HOST		126
#define JANUS_JICE_TYPE_PREFERENCE_SRFLX	100
#define JANUS_JICE_TYPE_PREFERENCE_PRFLX	110
#define JANUS_JICE_TYPE_PREFERENCE_RELAY	2
#define JANUS_JICE_TYPE_PREFERENCE_VPN		0

/* Helpers to manipulate bits and bit masks */
#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) (((a) & (1<<(b))) && (1))
#define BITMASK_SET(x,y) ((x) |= (y))
#define BITMASK_CLEAR(x,y) ((x) &= (~(y)))
#define BITMASK_FLIP(x,y) ((x) ^= (y))
#define BITMASK_CHECK(x,y) (((x) & (y)) == (y))


/* Structures */
typedef struct janus_stun_msg {
	uint16_t type;		/* Class and method */
	uint16_t length;
	uint32_t cookie;	/* 0x2112A442 */
	uint8_t transaction[12];
	char attributes[0];
} janus_stun_msg;

typedef struct janus_stun_attr {
	uint16_t type;
	uint16_t length;
	char value[0];
} janus_stun_attr;

typedef struct janus_stun_attr_mapped_address {
	uint16_t family;
	uint16_t port;
	uint8_t address[16];
} janus_stun_attr_mapped_address;

typedef struct janus_stun_attr_mapped_address janus_stun_attr_xor_mapped_address;

typedef struct janus_stun_attr_username {
	char username[0];
} janus_stun_attr_username;

typedef struct janus_stun_attr_message_integrity {
	uint8_t hash[20];
} janus_stun_attr_message_integrity;

typedef struct janus_stun_attr_fingerprint {
	uint32_t crc;
} janus_stun_attr_fingerprint;

typedef struct janus_stun_attr_error_code {
	uint16_t ignore;
	uint8_t class;
	uint8_t code;
	char reason[0];
} janus_stun_attr_error_code;

typedef struct janus_stun_attr_realm {
	char realm[0];
} janus_stun_attr_realm;

typedef struct janus_stun_attr_nonce {
	char nonce[0];
} janus_stun_attr_nonce;

typedef struct janus_stun_attr_unknown_attrs {
	uint16_t attribute[0];
} janus_stun_attr_unknown_attrs;

typedef struct janus_stun_attr_software {
	char software[0];
} janus_stun_attr_software;

typedef struct janus_stun_attr_mapped_address janus_stun_attr_alternate_server;

typedef struct janus_stun_attr_priority {
	uint32_t priority;
} janus_stun_attr_priority;

typedef struct janus_stun_attr_ice_controlled {
	uint64_t tie;
} janus_stun_attr_ice_controlled;

typedef struct janus_stun_attr_ice_controlled janus_stun_attr_ice_controlling;

typedef struct janus_stun_attr_network_cost {
	uint16_t id;
	uint16_t cost;
} janus_stun_attr_network_cost;

typedef struct janus_stun_attr_channel_number {
	uint16_t channel;
	uint16_t rffu;
} janus_stun_attr_channel_number;

typedef struct janus_stun_attr_lifetime {
	uint32_t seconds;
} janus_stun_attr_lifetime;

typedef struct janus_stun_attr_mapped_address janus_stun_attr_xor_peer_address;

typedef struct janus_stun_attr_data {
	char data[0];
} janus_stun_attr_data;

typedef struct janus_stun_attr_mapped_address janus_stun_attr_xor_relayed_address;

typedef struct janus_stun_attr_even_port {
	uint8_t evenport;
	uint8_t rffu[3];
} janus_stun_attr_even_port;

typedef struct janus_stun_attr_requested_transport {
	uint8_t protocol;
	uint8_t rffu[3];
} janus_stun_attr_requested_transport;

typedef struct janus_stun_attr_reservation_token {
	uint64_t token;
} janus_stun_attr_reservation_token;

typedef struct janus_stun_attr_channel_data {
	uint16_t channel;
	uint16_t length;
	char data[0];
} janus_stun_attr_channel_data;

/* STUN/TURN server details */
typedef struct janus_jice_stunturn_server {
	janus_jice_protocol type;
	char *server;
	guint16 port;
	struct sockaddr_in address;
	struct sockaddr_in6 address6;
	char *user;
	char *pwd;
} janus_jice_stunturn_server;

/* ICE agent */
struct janus_jice_agent {
	janus_ice_handle *handle;
	gboolean full;
	gboolean controlling;
	gboolean ipv6;
	gboolean tcp;
	guint min_port, max_port;
	GSList *stunturn_servers;
	GSList *interfaces;
	guint64 tie;
	char buffer[1500];
	volatile int gathering;
	guint stream_id;
	guint component_id;
	GSList *local_candidates;
	char *local_ufrag, *local_pwd;
	char *old_local_ufrag, *old_local_pwd;
	GSList *remote_candidates;
	char *remote_ufrag, *remote_pwd;
	char *old_remote_ufrag, *old_remote_pwd;
	GSList *pairs;
	janus_jice_candidate_pair *selected_pair;
	GHashTable *gathering_tr;
	GHashTable *checks_tr;
	void(*localcand_cb)(void *, janus_jice_candidate *);
	void(*remotecand_cb)(void *, janus_jice_candidate *);
	void(*state_cb)(void *, janus_jice_state);
	void(*selectedpair_cb)(void *, janus_jice_candidate *, janus_jice_candidate *);
	void(*recv_cb)(void *, char *, guint);
	volatile int destroyed;
	janus_refcount ref;
};

/* Packet */
typedef struct janus_jice_packet {
	janus_jice_agent *agent;
	gboolean is_stun;
	char *data;
	guint length;
	int fd;
	struct sockaddr address;
} janus_jice_packet;
static janus_jice_packet *janus_jice_packet_new(gboolean stun, char *buf, guint length, gboolean allocate);
static void janus_jice_packet_destroy(janus_jice_packet *packet);


/* Utilities */
gboolean janus_stun_sockaddr_is_equal(struct sockaddr *addr1, struct sockaddr *addr2);

/* Methods */
static int janus_stun_msg_set_type(janus_stun_msg *msg, int class, int method);
static int janus_stun_msg_set_length(janus_stun_msg *msg, uint16_t length);
static int janus_stun_msg_set_cookie(janus_stun_msg *msg, uint32_t cookie);
static int janus_stun_msg_set_transaction(janus_stun_msg *msg, uint8_t *transaction);
static int janus_stun_msg_get_class(janus_stun_msg *msg);
static int janus_stun_msg_get_method(janus_stun_msg *msg);
static uint16_t janus_stun_msg_get_length(janus_stun_msg *msg);
static uint32_t janus_stun_msg_get_cookie(janus_stun_msg *msg);
static int janus_stun_msg_get_transaction_as_string(janus_stun_msg *msg, char *buffer);
static int janus_stun_attr_set_type(janus_stun_attr *attr, uint16_t type);
static int janus_stun_attr_set_length(janus_stun_attr *attr, uint16_t length);
static uint16_t janus_stun_attr_get_type(janus_stun_attr *attr);
static uint16_t janus_stun_attr_get_length(janus_stun_attr *attr);
static janus_stun_msg *janus_stun_msg_create(guint size);
static void janus_stun_msg_destroy(janus_stun_msg *msg);
static janus_stun_attr *janus_stun_attr_create(void);
static const char *janus_stun_class_string(int class);
static const char *janus_stun_method_string(int method);
static const char *janus_stun_attribute_string(int attribute);
static void janus_stun_typemask_print(janus_stun_msg *msg);
static gboolean janus_jice_is_stun(char *data);
static janus_stun_msg *janus_jice_create_binding_request(guint *len);
static janus_stun_msg *janus_jice_create_connectivity_check(janus_jice_candidate *candidate, gboolean aggressive, guint *len);
static janus_stun_msg *janus_jice_create_connectivity_check_response(janus_jice_agent *agent, janus_stun_msg *request, guint *len, struct sockaddr *address);
static janus_stun_msg *janus_jice_create_connectivity_check_error(janus_jice_agent *agent, janus_stun_msg *request, int code, guint *len);
static int janus_jice_handle_gathering_response(janus_stun_msg *msg, guint len, struct sockaddr *address);
static int janus_jice_handle_connectivity_check(janus_jice_agent *agent, janus_stun_msg *msg, guint len);
static int janus_jice_handle_connectivity_check_response(janus_jice_agent *agent, janus_stun_msg *msg, guint len, struct sockaddr *address);
static char *janus_jice_random_string(guint len);
static janus_jice_candidate_pair *janus_jice_candidate_pair_new(janus_jice_candidate *local, janus_jice_candidate *remote);
/* Callbacks */
static gboolean janus_jice_checking_internal(gpointer user_data);
static void janus_jice_read_internal(janus_jice_agent *agent, janus_jice_candidate *from);
static int janus_jice_send_internal(janus_jice_agent *agent, janus_jice_packet *pkt);
static gboolean janus_jice_retransmit_internal(gpointer user_data);
static gboolean janus_jice_gathering_internal(gpointer user_data);
static gboolean janus_jice_new_candidate_internal(gpointer user_data);
static gboolean janus_jice_restart_internal(gpointer user_data);


/* Custom GSource for monitoring incoming traffic */
typedef struct janus_jice_fd_source {
	GSource base;
	guint64 handle_id;
	janus_jice_candidate *candidate;
} janus_jice_fd_source;
static gboolean janus_jice_fd_source_prepare(GSource *source, gint *timeout) {
	*timeout = -1;
	return FALSE;
}
static gboolean janus_jice_fd_source_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	janus_jice_fd_source *t = (janus_jice_fd_source *)source;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Dispatching source\n", t->handle_id);
	/* Receive the packet */
	janus_jice_read_internal(t->candidate->agent, t->candidate);
	return G_SOURCE_CONTINUE;
}
static void janus_jice_fd_source_finalize(GSource *source) {
	janus_jice_fd_source *t = (janus_jice_fd_source *)source;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Finalizing source\n", t->handle_id);
	/* TODO Any cleanup we should do here? */
}
static GSourceFuncs janus_jice_fd_source_funcs = {
	janus_jice_fd_source_prepare,
	NULL,
	janus_jice_fd_source_dispatch,
	janus_jice_fd_source_finalize,
	NULL, NULL
};
static GSource *janus_jice_fd_source_create(guint64 handle_id, janus_jice_candidate *candidate) {
	GSource *source = g_source_new(&janus_jice_fd_source_funcs, sizeof(janus_jice_fd_source));
	g_source_set_priority(source, G_PRIORITY_DEFAULT);
	g_source_add_unix_fd(source, candidate->fd, G_IO_IN | G_IO_ERR);
	janus_jice_fd_source *t = (janus_jice_fd_source *)source;
	t->handle_id = handle_id;
	t->candidate = candidate;
	return source;
}


/* Helper to compare sockaddr structures and see if they're the same */
gboolean janus_stun_sockaddr_is_equal(struct sockaddr *addr1, struct sockaddr *addr2) {
	gchar address1[INET6_ADDRSTRLEN], address2[INET6_ADDRSTRLEN];
	guint16 port1 = 0, port2 = 0;
	int res = 0;
	if((res = janus_jice_resolve_address(addr1, address1, INET6_ADDRSTRLEN, &port1)) < 0 ||
			(res = janus_jice_resolve_address(addr2, address2, INET6_ADDRSTRLEN, &port2)) < 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Error resolving address... (error %d)\n", res);
		return FALSE;
	}
	JANUS_LOG(JICE_LOG_INFO, "[jice] Comparing %s:%"SCNu16" with %s:%"SCNu16"\n", address1, port1, address2, port2);
	if(addr1->sa_family != addr2->sa_family)
		return FALSE;
	if(addr1->sa_family == AF_INET) {
		struct sockaddr_in *addr1_v4 = (struct sockaddr_in *)addr1;
		struct sockaddr_in *addr2_v4 = (struct sockaddr_in *)addr2;
		if(addr1_v4->sin_port != addr2_v4->sin_port)
			return FALSE;
		if(addr1_v4->sin_addr.s_addr != addr2_v4->sin_addr.s_addr)
			return FALSE;
		return TRUE;
	} else if(addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr1_v6 = (struct sockaddr_in6 *)addr1;
		struct sockaddr_in6 *addr2_v6 = (struct sockaddr_in6 *)addr2;
		if(addr1_v6->sin6_port != addr2_v6->sin6_port)
			return FALSE;
		if(memcmp(addr1_v6->sin6_addr.s6_addr, addr2_v6->sin6_addr.s6_addr, sizeof(struct sockaddr_in6)))
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

/* Private methods */
static int janus_stun_msg_set_type(janus_stun_msg *msg, int class, int method) {
	/*
		0                 1
		2  3  4 5 6 7 8 9 0 1 2 3 4 5
	   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	   |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
	   |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
	   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if(!msg)
		return -1;
	uint16_t type = 0;
	/* Class first */
	if(class < JANUS_STUN_REQUEST || class > JANUS_STUN_ERROR_RESPONSE)
		return -1;
	switch(class) {
		case JANUS_STUN_REQUEST:
			break;
		case JANUS_STUN_INDICATION:
			BIT_SET(type, 4);
			break;
		case JANUS_STUN_SUCCESS_RESPONSE:
			BIT_SET(type, 8);
			break;
		case JANUS_STUN_ERROR_RESPONSE:
			BIT_SET(type, 4);
			BIT_SET(type, 8);
			break;
		default:
			break;
	}
	/* Then method */
	int i = 0, skip = 0;
	for(i=0; i<12; i++) {
		if(i < 4)
			skip = 0;
		else if(i < 7)
			skip = 1;
		else
			skip = 2;
		if(BIT_CHECK(method, i))
			BIT_SET(type, i+skip);
	}
	msg->type = htons(type);

	return 0;
}

static int janus_stun_msg_set_length(janus_stun_msg *msg, uint16_t length) {
	if(!msg)
		return -1;
	msg->length = htons(length);
	return 0;
}

static int janus_stun_msg_set_cookie(janus_stun_msg *msg, uint32_t cookie) {
	if(!msg)
		return -1;
	msg->cookie = htonl(cookie);
	return 0;
}

static int janus_stun_msg_set_transaction(janus_stun_msg *msg, uint8_t *transaction) {
	if(!msg)
		return -1;
	int i = 0;
	for(i=0; i<12; i++)
		msg->transaction[i] = *(transaction+i);
	return 0;
}

static int janus_stun_msg_get_class(janus_stun_msg *msg) {
	if(!msg)
		return -1;
	int class = 0;
	uint16_t type = ntohs(msg->type);
	if(BIT_CHECK(type, 4))
		BIT_SET(class, 0);
	if(BIT_CHECK(type, 8))
		BIT_SET(class, 1);
	return class;
}

static int janus_stun_msg_get_method(janus_stun_msg *msg) {
	if(!msg)
		return -1;
	int method = 0;
	int i = 0, skip = 0;
	uint16_t type = ntohs(msg->type);
	for(i=0; i<12; i++) {
		if(i < 4)
			skip = 0;
		else if(i < 7)
			skip = 1;
		else
			skip = 2;
		if(BIT_CHECK(type, i+skip))
			BIT_SET(method, i);
	}
	return method;
}

static uint16_t janus_stun_msg_get_length(janus_stun_msg *msg) {
	if(!msg)
		return -1;
	return ntohs(msg->length);
}

static uint32_t janus_stun_msg_get_cookie(janus_stun_msg *msg) {
	if(!msg)
		return -1;
	return ntohl(msg->cookie);
}

static int janus_stun_msg_get_transaction_as_string(janus_stun_msg *msg, char *buffer) {
	if(!msg || !buffer)
		return -1;
	int i = 0;
	for(i=0; i<12; i++)
		sprintf(buffer+(i*2), "%02x", msg->transaction[i]);
	return 0;
}

static int janus_stun_attr_set_type(janus_stun_attr *attr, uint16_t type) {
	if(!attr)
		return -1;
	attr->type = htons(type);
	return 0;
}

static int janus_stun_attr_set_length(janus_stun_attr *attr, uint16_t length) {
	if(!attr)
		return -1;
	attr->length = htons(length);
	return 0;
}

static uint16_t janus_stun_attr_get_type(janus_stun_attr *attr) {
	if(!attr)
		return -1;
	return ntohs(attr->type);
}

static uint16_t janus_stun_attr_get_length(janus_stun_attr *attr) {
	if(!attr)
		return -1;
	return ntohs(attr->length);
}

static janus_stun_msg *janus_stun_msg_create(guint size) {
	if(size < sizeof(janus_stun_msg))
		return NULL;
	janus_stun_msg *msg = g_malloc0(size);
	janus_stun_msg_set_cookie(msg, JANUS_STUN_MAGIC_COOKIE);
	return msg;
}

static void janus_stun_msg_destroy(janus_stun_msg *msg) {
	g_free(msg);
}

static janus_stun_attr *janus_stun_attr_create(void) {
	janus_stun_attr *attr = g_malloc0(sizeof(janus_stun_attr));
	return attr;
}


/* Helpers for debugging reasons */
static const char *janus_stun_class_string(int class) {
	switch(class) {
		case JANUS_STUN_REQUEST:
			return "REQUEST";
		case JANUS_STUN_INDICATION:
			return "INDICATION";
		case JANUS_STUN_SUCCESS_RESPONSE:
			return "SUCCESS-RESPONSE";
		case JANUS_STUN_ERROR_RESPONSE:
			return "ERROR-RESPONSE";
		default:
			return NULL;
	}
}

static const char *janus_stun_method_string(int method) {
	switch(method) {
		case JANUS_STUN_BINDING:
			return "BINDING";
		case JANUS_STUN_TURN_ALLOCATE:
			return "TURN-ALLOCATE";
		case JANUS_STUN_TURN_REFRESH:
			return "TURN-REFRESH";
		case JANUS_STUN_TURN_SEND:
			return "TURN-SEND";
		case JANUS_STUN_TURN_DATA:
			return "TURN-DATA";
		case JANUS_STUN_TURN_CREATE_PERMISSION:
			return "TURN-CREATE-PERMISSION";
		case JANUS_STUN_TURN_CHANNEL_BIND:
			return "TURN-CHANNEL-BIND";
		default:
			return NULL;
	}
}

static const char *janus_stun_attribute_string(int attribute) {
	switch(attribute) {
		case JANUS_STUN_ATTR_MAPPED_ADDRESS:
			return "MAPPED-ADDRESS";
		case JANUS_STUN_ATTR_USERNAME:
			return "USERNAME";
		case JANUS_STUN_ATTR_MESSAGE_INTEGRITY:
			return "MESSAGE-INTEGRITY";
		case JANUS_STUN_ATTR_ERROR_CODE:
			return "ERROR-CODE";
		case JANUS_STUN_ATTR_UNKNOWN_ATTRIBUTES:
			return "UNKNOWN-ATTRIBUTES";
		case JANUS_STUN_ATTR_REALM:
			return "REALM";
		case JANUS_STUN_ATTR_NONCE:
			return "NONCE";
		case JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS:
			return "XOR-MAPPED-ADDRESS";
		case JANUS_STUN_ATTR_SOFTWARE:
			return "SOFTWARE";
		case JANUS_STUN_ATTR_ALTERNATE_SERVER:
			return "ALTERNATE-SERVER";
		case JANUS_STUN_ATTR_FINGERPRINT:
			return "FINGERPRINT";
		case JANUS_STUN_ATTR_PRIORITY:
			return "PRIORITY";
		case JANUS_STUN_ATTR_USE_CANDIDATE:
			return "USE-CANDIDATE";
		case JANUS_STUN_ATTR_ICE_CONTROLLED:
			return "ICE-CONTROLLED";
		case JANUS_STUN_ATTR_ICE_CONTROLLING:
			return "ICE-CONTROLLING";
		case JANUS_STUN_ATTR_NETWORK_COST:
			return "NETWORK-COST";
		case JANUS_STUN_ATTR_CHANNEL_NUMBER:
			return "CHANNEL-NUMBER";
		case JANUS_STUN_ATTR_LIFETIME:
			return "LIFETIME";
		case JANUS_STUN_ATTR_XOR_PEER_ADDRESS:
			return "XOR-PEER-ADDRESS";
		case JANUS_STUN_ATTR_DATA:
			return "DATA";
		case JANUS_STUN_ATTR_XOR_RELAYED_ADDRESS:
			return "XOR-RELAYED-ADDRESS";
		case JANUS_STUN_ATTR_EVEN_PORT:
			return "EVEN-PORT";
		case JANUS_STUN_ATTR_REQUESTED_TRANSPORT:
			return "REQUESTED-TRANSPORT";
		case JANUS_STUN_ATTR_DONT_FRAGMENT:
			return "DONT-FRAGMENT";
		case JANUS_STUN_ATTR_RESERVATION_TOKEN:
			return "RESERVATION-TOKEN";
		default:
			return NULL;
	}
}

static void janus_stun_typemask_print(janus_stun_msg *msg) {
	if(!msg)
		return;
	uint16_t type = ntohs(msg->type);
	JANUS_LOG(JICE_LOG_INFO, "[jice]\n"
	   "+--+--+-+-+-+-+-+-+-+-+-+-+-+-+\n"
	   "|M |M |M|M|M|C|M|M|M|C|M|M|M|M|\n"
	   "|11|10|9|8|7|1|6|5|4|0|3|2|1|0|\n"
	   "| %d| %d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|\n"
	   "+--+--+-+-+-+-+-+-+-+-+-+-+-+-+\n",
			BIT_CHECK(type, 13),
			BIT_CHECK(type, 12),
			BIT_CHECK(type, 11),
			BIT_CHECK(type, 10),
			BIT_CHECK(type, 9),
			BIT_CHECK(type, 8),
			BIT_CHECK(type, 7),
			BIT_CHECK(type, 6),
			BIT_CHECK(type, 5),
			BIT_CHECK(type, 4),
			BIT_CHECK(type, 3),
			BIT_CHECK(type, 2),
			BIT_CHECK(type, 1),
			BIT_CHECK(type, 0)
	);
}

static gboolean janus_jice_is_stun(char *data) {
	if(BIT_CHECK(*data, 7) || BIT_CHECK(*data, 6))
		return FALSE;
	janus_stun_msg *msg = (janus_stun_msg *)data;
	if(janus_stun_msg_get_cookie(msg) != JANUS_STUN_MAGIC_COOKIE)
		return FALSE;
	/* FIXME Add more checks */
	return TRUE;
}

static janus_stun_msg *janus_jice_create_binding_request(guint *len) {
	/* Send a binding request to a STUN server: the only thing we need is a fingerprint attribute */
	janus_stun_msg *request = janus_stun_msg_create(28);
	janus_stun_msg_set_type(request, JANUS_STUN_REQUEST, JANUS_STUN_BINDING);
	janus_stun_msg_set_cookie(request, JANUS_STUN_MAGIC_COOKIE);
	uint8_t transaction[12];
	uint32_t t = g_random_int();
	memcpy(&transaction[0], &t, sizeof(uint32_t));
	t = g_random_int();
	memcpy(&transaction[4], &t, sizeof(uint32_t));
	t = g_random_int();
	memcpy(&transaction[8], &t, sizeof(uint32_t));
	janus_stun_msg_set_transaction(request, transaction);
	/* We don't know how large the packet will be yet, apart from the common header */
	int msglen = 20;
	/* Compute CRC-32 on packet */
	janus_stun_attr *attribute = (janus_stun_attr *)request->attributes;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_FINGERPRINT);
	janus_stun_attr_set_length(attribute, 4);
	janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attribute->value;
	msglen += 8;
	/* Let's first set the correct length in the header */
	janus_stun_msg_set_length(request, msglen-20);
	/* Now we can get a fingerprint */
	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (unsigned char *)request, msglen-8);
	f->crc = ntohl(crc ^ JANUS_STUN_FINGERPRINT_XOR);
	/* Send the length of the packet back to the caller */
	if(len)
		*len = msglen;
	return request;
}

static janus_stun_msg *janus_jice_create_connectivity_check(janus_jice_candidate *candidate, gboolean aggressive, guint *len) {
	if(!candidate)
		return NULL;
	janus_jice_agent *agent = candidate->agent;
	if(!agent || !agent->local_ufrag || !agent->local_pwd)
		return NULL;
	/* Send a connectivity check */
	janus_stun_msg *request = janus_stun_msg_create(200);	/* FIXME */
	janus_stun_msg_set_type(request, JANUS_STUN_REQUEST, JANUS_STUN_BINDING);
	janus_stun_msg_set_cookie(request, JANUS_STUN_MAGIC_COOKIE);
	uint8_t transaction[12];
	uint32_t t = g_random_int();
	memcpy(&transaction[0], &t, sizeof(uint32_t));
	t = g_random_int();
	memcpy(&transaction[4], &t, sizeof(uint32_t));
	t = g_random_int();
	memcpy(&transaction[8], &t, sizeof(uint32_t));
	janus_stun_msg_set_transaction(request, transaction);
	/* We don't know how large the packet will be yet, apart from the common header */
	int msglen = 20;
	char *current_attr = request->attributes;
	/* Add the username attribute (peer:us) */
	janus_stun_attr *attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_USERNAME);
	janus_stun_attr_username *u = (janus_stun_attr_username *)attribute->value;
	g_snprintf(u->username, 100, "%s:%s", agent->remote_ufrag, agent->local_ufrag);
	int ulen = strlen(u->username);
	janus_stun_attr_set_length(attribute, ulen);
	if(ulen % 4)
		ulen += (4-(ulen % 4));
	msglen += ulen+4;
	current_attr += ulen+4;
	/* Add controlling/controlled */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, (agent->controlling ? JANUS_STUN_ATTR_ICE_CONTROLLING : JANUS_STUN_ATTR_ICE_CONTROLLED));
	janus_stun_attr_ice_controlled *c = (janus_stun_attr_ice_controlled *)attribute->value;
	c->tie = agent->tie;	/* FIXME */
	janus_stun_attr_set_length(attribute, 8);
	msglen += 12;
	current_attr += 12;
	if(agent->controlling && aggressive) {
		/* Add use-candidate (but only if we're controlling) */
		attribute = (janus_stun_attr *)current_attr;
		janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_USE_CANDIDATE);
		janus_stun_attr_set_length(attribute, 0);
		msglen += 4;
		current_attr += 4;
	}
	/* Add priority */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_PRIORITY);
	janus_stun_attr_priority *p = (janus_stun_attr_priority *)attribute->value;
	p->priority = htonl(candidate->priority);
	janus_stun_attr_set_length(attribute, 4);
	msglen += 8;
	current_attr += 8;
	/* Add message integrity (use ??'s password) */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_MESSAGE_INTEGRITY);
	janus_stun_attr_set_length(attribute, 20);
	msglen += 24;
	current_attr += 24;
	/* Let's set the current length in the header before computing the hash */
	janus_stun_msg_set_length(request, msglen-20);
	unsigned char *digest = HMAC(EVP_sha1(), agent->remote_pwd, strlen(agent->remote_pwd),
		(unsigned char*)request, (char *)attribute-(char *)request, NULL, NULL);
	janus_stun_attr_message_integrity *mi = (janus_stun_attr_message_integrity *)attribute->value;
	memcpy(mi->hash, digest, 20);
	/* Compute CRC-32 on packet */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_FINGERPRINT);
	janus_stun_attr_set_length(attribute, 4);
	janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attribute->value;
	msglen += 8;
	/* Let's first set the correct length in the header */
	janus_stun_msg_set_length(request, msglen-20);
	/* Now we can get a fingerprint */
	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (unsigned char *)request, msglen-8);
	f->crc = ntohl(crc ^ JANUS_STUN_FINGERPRINT_XOR);
	/* Send the length of the packet back to the caller */
	if(len)
		*len = msglen;
	return request;
}

static janus_stun_msg *janus_jice_create_connectivity_check_response(janus_jice_agent *agent, janus_stun_msg *request, guint *len, struct sockaddr *address) {
	if(!address || !agent || !agent->remote_ufrag || !agent->remote_pwd || !agent->local_ufrag || !agent->local_pwd)
		return NULL;
	/* Send a connectivity check response (success) */
	janus_stun_msg *response = janus_stun_msg_create(200);	/* FIXME */
	janus_stun_msg_set_type(response, JANUS_STUN_SUCCESS_RESPONSE, JANUS_STUN_BINDING);
	janus_stun_msg_set_cookie(response, janus_stun_msg_get_cookie(request));
	janus_stun_msg_set_transaction(response, request->transaction);
	/* We don't know how large the packet will be yet, apart from the common header */
	int msglen = 20;
	char *current_attr = response->attributes;
	/* Add XOR mapped address */
	janus_stun_attr *attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS);
	janus_stun_attr_mapped_address *ma = (janus_stun_attr_mapped_address *)attribute->value;
	if(address->sa_family == AF_INET) {
		/* IPv4 */
		struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
		ma->family = htons(1);
		ma->port = htons(ntohs(addr4->sin_port) ^ 0x2112);
		uint32_t addr;
		memcpy(&addr, &addr4->sin_addr.s_addr, sizeof(uint32_t));
		addr = htonl(ntohl(addr) ^ JANUS_STUN_MAGIC_COOKIE);
		memcpy(&ma->address, &addr, sizeof(addr4->sin_addr.s_addr));
		janus_stun_attr_set_length(attribute, 8);
		msglen += 12;
		current_attr += 12;
	} else {
		/* IPv6 */
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
		ma->family = htons(2);
		ma->port = htons(ntohs(addr6->sin6_port) ^ 0x2112);
		/* TODO Compute XOR-ed IPv6 address */
		janus_stun_attr_set_length(attribute, 20);
		msglen += 24;
		current_attr += 24;
	}
	/* Add the username attribute (us:peer, that is what the original check was) */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_USERNAME);
	janus_stun_attr_username *u = (janus_stun_attr_username *)attribute->value;
	g_snprintf(u->username, 100, "%s:%s", agent->local_ufrag, agent->remote_ufrag);
	int ulen = strlen(u->username);
	janus_stun_attr_set_length(attribute, ulen);
	if(ulen % 4)
		ulen += (4-(ulen % 4));
	msglen += ulen+4;
	current_attr += ulen+4;
	/* Add message integrity (use ??'s password) */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_MESSAGE_INTEGRITY);
	janus_stun_attr_set_length(attribute, 20);
	msglen += 24;
	current_attr += 24;
	/* Let's set the current length in the header before computing the hash */
	janus_stun_msg_set_length(response, msglen-20);
	unsigned char *digest = HMAC(EVP_sha1(), agent->local_pwd, strlen(agent->local_pwd),
		(unsigned char*)response, (char *)attribute-(char *)response, NULL, NULL);
	janus_stun_attr_message_integrity *mi = (janus_stun_attr_message_integrity *)attribute->value;
	memcpy(mi->hash, digest, 20);
	/* Compute CRC-32 on packet */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_FINGERPRINT);
	janus_stun_attr_set_length(attribute, 4);
	janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attribute->value;
	msglen += 8;
	/* Let's first set the correct length in the header */
	janus_stun_msg_set_length(response, msglen-20);
	/* Now we can get a fingerprint */
	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (unsigned char *)response, msglen-8);
	f->crc = ntohl(crc ^ JANUS_STUN_FINGERPRINT_XOR);
	/* Send the length of the packet back to the caller */
	if(len)
		*len = msglen;
	return response;
}

static janus_stun_msg *janus_jice_create_connectivity_check_error(janus_jice_agent *agent, janus_stun_msg *request, int code, guint *len) {
	if(!agent || !agent->local_pwd)
		return NULL;
	/* Send a connectivity check response (error) */
	janus_stun_msg *response = janus_stun_msg_create(60);	/* FIXME */
	janus_stun_msg_set_type(response, JANUS_STUN_ERROR_RESPONSE, JANUS_STUN_BINDING);
	janus_stun_msg_set_cookie(response, janus_stun_msg_get_cookie(request));
	janus_stun_msg_set_transaction(response, request->transaction);
	/* We don't know how large the packet will be yet, apart from the common header */
	int msglen = 20;
	char *current_attr = response->attributes;
	/* Add error attribute */
	janus_stun_attr *attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_ERROR_CODE);
	janus_stun_attr_error_code *e = (janus_stun_attr_error_code *)attribute->value;
	e->class = code/100;
	e->code = code - e->class*100;
	janus_stun_attr_set_length(attribute, 4);
	msglen += 8;
	current_attr += 8;
	if(code != JANUS_STUN_ERROR_BAD_REQUEST) {
		/* Add message-integrity attribute */
		attribute = (janus_stun_attr *)current_attr;
		janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_MESSAGE_INTEGRITY);
		janus_stun_attr_set_length(attribute, 20);
		msglen += 24;
		current_attr += 24;
		/* Let's set the current length in the header before computing the hash */
		janus_stun_msg_set_length(response, msglen-20);
		unsigned char *digest = HMAC(EVP_sha1(), agent->local_pwd, strlen(agent->local_pwd),
			(unsigned char*)response, (char *)attribute-(char *)response, NULL, NULL);
		janus_stun_attr_message_integrity *mi = (janus_stun_attr_message_integrity *)attribute->value;
		memcpy(mi->hash, digest, 20);
	}
	/* Compute CRC-32 on packet */
	attribute = (janus_stun_attr *)current_attr;
	janus_stun_attr_set_type(attribute, JANUS_STUN_ATTR_FINGERPRINT);
	janus_stun_attr_set_length(attribute, 4);
	janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attribute->value;
	msglen += 8;
	/* Let's first set the correct length in the header */
	janus_stun_msg_set_length(response, msglen-20);
	/* Now we can get a fingerprint */
	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (unsigned char *)response, msglen-8);
	f->crc = ntohl(crc ^ JANUS_STUN_FINGERPRINT_XOR);
	/* Send the length of the packet back to the caller */
	if(len)
		*len = msglen;
	return response;
}

static int janus_jice_handle_gathering_response(janus_stun_msg *msg, guint len, struct sockaddr *address) {
	if(!msg || !janus_stun_msg_get_length(msg) || !len || !address)
		return -1;
	uint16_t index = janus_stun_msg_get_length(msg), total = len-20;
	char *start = msg->attributes;
	while(total > 0) {
		/* Parse attributes, looking for mapped addresses, xor-ed or otherwise */
		janus_stun_attr *attr = (janus_stun_attr *)start;
		if((janus_stun_attr_get_length(attr)+4) > total) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Attribute length exceeds size of the packet, broken message...\n");
			return -2;
		}
		switch(janus_stun_attr_get_type(attr)) {
			case JANUS_STUN_ATTR_MAPPED_ADDRESS:
			case JANUS_STUN_ATTR_ALTERNATE_SERVER: {
				janus_stun_attr_mapped_address *ma = (janus_stun_attr_mapped_address *)attr->value;
				int family = ntohs(ma->family);
				uint16_t port = ntohs(ma->port);
				/* Update the address */
				if(family == 1) {
					/* IPv4 */
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					addr4->sin_family = AF_INET;
					addr4->sin_port = htons(port);
					memcpy(&addr4->sin_addr.s_addr, ma->address, sizeof(struct in_addr));
					return 0;
				} else {
					/* FIXME IPv6 */
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
					addr6->sin6_family = AF_INET6;
					addr6->sin6_port = htons(port);
					memcpy(&addr6->sin6_addr.s6_addr, ma->address, sizeof(struct in6_addr));
					return 0;
				}
			}
			case JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS:
			case JANUS_STUN_ATTR_XOR_PEER_ADDRESS:
			case JANUS_STUN_ATTR_XOR_RELAYED_ADDRESS: {
				janus_stun_attr_xor_mapped_address *xma = (janus_stun_attr_xor_mapped_address *)attr->value;
				int family = ntohs(xma->family);
				uint16_t port = ntohs(htons(ntohs(xma->port) ^ 0x2112));
				/* Update the candidate address */
				if(family == 1) {
					/* IPv4 */
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					addr4->sin_family = AF_INET;
					addr4->sin_port = htons(port);
					uint32_t addr;
					memcpy(&addr, xma->address, sizeof(uint32_t));
					addr = htonl(ntohl(addr) ^ JANUS_STUN_MAGIC_COOKIE);
					memcpy(&addr4->sin_addr.s_addr, &addr, sizeof(struct in_addr));
					return 0;
				} else {
					/* TODO IPv6 (we need to XOR with magic cookie + transaction) */
					return 0;
				}
				break;
			}
			case JANUS_STUN_ATTR_ERROR_CODE: {
				janus_stun_attr_error_code *error = (janus_stun_attr_error_code *)attr->value;
				int code = error->class*100 + error->code;
				if(janus_stun_attr_get_length(attr) > 4) {
					char *reason = g_malloc0(janus_stun_attr_get_length(attr)-4+1);
					memcpy(reason, error->reason, janus_stun_attr_get_length(attr)-4);
					*(reason+janus_stun_attr_get_length(attr)-4) = '\0';
					JANUS_LOG(JICE_LOG_ERR, "[jice] Got an error code: %d (%s)\n", code, reason);
					g_free(reason);
				} else {
					JANUS_LOG(JICE_LOG_ERR, "[jice] Got an error code: %d\n", code);
				}
				return code;
			}
			default: {
				break;
			}
		}
		/* Go to next attribute, if any */
		int padding = 0;
		if(janus_stun_attr_get_length(attr)%4)
			padding = 4-janus_stun_attr_get_length(attr)%4;
		start += 4+padding+janus_stun_attr_get_length(attr);
		index += 4+padding+janus_stun_attr_get_length(attr);
		total -= 4+padding+janus_stun_attr_get_length(attr);
	}
	/* If we got here, we didn't get what we wanted */
	return -3;
}

static int janus_jice_handle_connectivity_check(janus_jice_agent *agent, janus_stun_msg *msg, guint len) {
	if(!agent || !msg || !janus_stun_msg_get_length(msg) || !len || !agent || !agent->local_ufrag || !agent->local_pwd)
		return -1;
	uint16_t index = janus_stun_msg_get_length(msg), total = len-20;
	char *start = msg->attributes;
	/* Stuff we'll need */
	char username[256];
	username[0] = '\0';
	char integrity[41], computed[41];
	integrity[0] = '\0';
	computed[0] = '\0';
	guint32 crc = 0, computed_crc = 0;
	gboolean controlling = FALSE;
	gboolean use_candidate = FALSE;
	guint64 tie = 0;
	guint32 priority = 0;
	/* Let's parse */
	while(total > 0) {
		/* Parse attributes, looking for mapped addresses, xor-ed or otherwise */
		janus_stun_attr *attr = (janus_stun_attr *)start;
		if((janus_stun_attr_get_length(attr)+4) > total) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Attribute length exceeds size of the packet, broken message...\n");
			return -2;
		}
		switch(janus_stun_attr_get_type(attr)) {
			case JANUS_STUN_ATTR_USERNAME: {
				janus_stun_attr_username *u = (janus_stun_attr_username *)attr->value;
				int len = janus_stun_attr_get_length(attr);
				if(len > 255)
					len = 255;
				memcpy(username, u->username, len);
				username[len] = '\0';
				break;
			}
			case JANUS_STUN_ATTR_ICE_CONTROLLING: {
				janus_stun_attr_ice_controlling *ic = (janus_stun_attr_ice_controlling *)attr->value;
				tie = ic->tie;	/* FIXME */
				controlling = TRUE;
				break;
			}
			case JANUS_STUN_ATTR_ICE_CONTROLLED: {
				janus_stun_attr_ice_controlling *ic = (janus_stun_attr_ice_controlling *)attr->value;
				tie = ic->tie;	/* FIXME */
				controlling = FALSE;
				break;
			}
			case JANUS_STUN_ATTR_PRIORITY: {
				janus_stun_attr_priority *p = (janus_stun_attr_priority *)attr->value;
				priority = ntohl(p->priority);
				break;
			}
			case JANUS_STUN_ATTR_USE_CANDIDATE: {
				use_candidate = TRUE;
				break;
			}
			case JANUS_STUN_ATTR_MESSAGE_INTEGRITY: {
				janus_stun_attr_message_integrity *mi = (janus_stun_attr_message_integrity *)attr->value;
				int i = 0;
				for(i=0; i<20; i++)
					sprintf(&integrity[i*2], "%02x", mi->hash[i]);
				/* Compute the HMAC-SHA1 hash */
				uint16_t length = janus_stun_msg_get_length(msg);
				janus_stun_msg_set_length(msg, length-8);
				unsigned char *digest = HMAC(EVP_sha1(), agent->local_pwd, strlen(agent->local_pwd),
					(unsigned char*)msg, (char *)attr-(char *)msg, NULL, NULL);
				janus_stun_msg_set_length(msg, length);
				for(i=0; i<20; i++)
					sprintf(&computed[i*2], "%02x", (uint8_t)digest[i]);
				break;
			}
			case JANUS_STUN_ATTR_FINGERPRINT: {
				janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attr->value;
				crc = f->crc;
				/* Compute CRC-32 on packet */
				computed_crc = crc32(0L, Z_NULL, 0);
				computed_crc = crc32(computed_crc, (unsigned char *)msg, (unsigned char *)attr-(unsigned char *)msg);
				computed_crc = ntohl(computed_crc ^ JANUS_STUN_FINGERPRINT_XOR);
				break;
			}
			default: {
				break;
			}
		}
		/* Go to next attribute, if any */
		int padding = 0;
		if(janus_stun_attr_get_length(attr)%4)
			padding = 4-janus_stun_attr_get_length(attr)%4;
		start += 4+padding+janus_stun_attr_get_length(attr);
		index += 4+padding+janus_stun_attr_get_length(attr);
		total -= 4+padding+janus_stun_attr_get_length(attr);
	}
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Got a connectivity check: %u/%u\n",
		agent->handle->handle_id, agent->stream_id, agent->component_id);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Username: %s\n", agent->handle->handle_id, username);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Hash:     %s/%s\n", agent->handle->handle_id, integrity, computed);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- CRC:      %"SCNu32"/%"SCNu32"\n", agent->handle->handle_id, crc, computed_crc);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Role:     %s\n", agent->handle->handle_id, (controlling ? "controlling" : "controlled"));
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Tie:      %"SCNu64"\n", agent->handle->handle_id, tie);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Priority: %"SCNu32"\n", agent->handle->handle_id, priority);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Use cand: %s\n", agent->handle->handle_id, (use_candidate ? "true" : "false"));
	/* Validate this request */
	if(strlen(integrity) == 0 || strlen(username) == 0 || crc == 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Missing username, message integryty, and/or fingerprint\n", agent->handle->handle_id);
		return JANUS_STUN_ERROR_BAD_REQUEST;
	}
	if(crc != computed_crc) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Fingerprint is wrong... %"SCNu32" != %"SCNu32"\n", agent->handle->handle_id, crc, computed_crc);
		return JANUS_STUN_ERROR_BAD_REQUEST;
	}
	char expected_username[256];
	g_snprintf(expected_username, sizeof(expected_username), "%s:%s", agent->local_ufrag, agent->remote_ufrag);
	if(strcmp(username, expected_username)) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Wrong username... %s != %s\n", agent->handle->handle_id, username, expected_username);
		return JANUS_STUN_ERROR_UNAUTHORIZED;
	}
	if(strcmp(integrity, computed)) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Wrong hash... %s != %s\n", agent->handle->handle_id, integrity, computed);
		return JANUS_STUN_ERROR_UNAUTHORIZED;
	}
	if(controlling == agent->controlling) {
		/* TODO Actually handle role conflict */
		JANUS_LOG(JICE_LOG_WARN, "[jice][%"SCNu64"] Role conflict...\n", agent->handle->handle_id);
		return JANUS_STUN_ERROR_ROLE_CONFLICT;
	}
	/* TODO Handle connectivity check info to update the right candidate pair */
	return 0;
}

static int janus_jice_handle_connectivity_check_response(janus_jice_agent *agent, janus_stun_msg *msg, guint len, struct sockaddr *address) {
	if(!agent || !msg || !janus_stun_msg_get_length(msg) || !len ||
			!agent->remote_ufrag || !agent->remote_pwd || !agent->local_ufrag || !agent->local_pwd)
		return -1;
	uint16_t index = janus_stun_msg_get_length(msg), total = len-20;
	char *start = msg->attributes;
	/* Stuff we'll need */
	gboolean got_address = FALSE;
	char username[256];
	username[0] = '\0';
	char integrity[41], computed[41];
	integrity[0] = '\0';
	computed[0] = '\0';
	guint32 crc = 0, computed_crc = 0;
	/* Let's parse */
	while(total > 0) {
		/* Parse attributes, looking for mapped addresses, xor-ed or otherwise */
		janus_stun_attr *attr = (janus_stun_attr *)start;
		if((janus_stun_attr_get_length(attr)+4) > total) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Attribute length exceeds size of the packet, broken message...\n");
			return -2;
		}
		switch(janus_stun_attr_get_type(attr)) {
			case JANUS_STUN_ATTR_MAPPED_ADDRESS:
			case JANUS_STUN_ATTR_ALTERNATE_SERVER: {
				janus_stun_attr_mapped_address *ma = (janus_stun_attr_mapped_address *)attr->value;
				int family = ntohs(ma->family);
				uint16_t port = ntohs(ma->port);
				/* Update the address */
				if(family == 1) {
					/* IPv4 */
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					addr4->sin_family = AF_INET;
					addr4->sin_port = htons(port);
					memcpy(&addr4->sin_addr.s_addr, ma->address, sizeof(struct in_addr));
				} else {
					/* FIXME IPv6 */
					struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
					addr6->sin6_family = AF_INET6;
					addr6->sin6_port = htons(port);
					memcpy(&addr6->sin6_addr.s6_addr, ma->address, sizeof(struct in6_addr));
				}
				got_address = TRUE;
				break;
			}
			case JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS:
			case JANUS_STUN_ATTR_XOR_PEER_ADDRESS:
			case JANUS_STUN_ATTR_XOR_RELAYED_ADDRESS: {
				janus_stun_attr_xor_mapped_address *xma = (janus_stun_attr_xor_mapped_address *)attr->value;
				int family = ntohs(xma->family);
				uint16_t port = ntohs(htons(ntohs(xma->port) ^ 0x2112));
				/* Update the candidate address */
				if(family == 1) {
					/* IPv4 */
					struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
					addr4->sin_family = AF_INET;
					addr4->sin_port = htons(port);
					uint32_t addr;
					memcpy(&addr, xma->address, sizeof(uint32_t));
					addr = htonl(ntohl(addr) ^ JANUS_STUN_MAGIC_COOKIE);
					memcpy(&addr4->sin_addr.s_addr, &addr, sizeof(struct in_addr));
				} else {
					/* TODO IPv6 (we need to XOR with magic cookie + transaction) */
				}
				got_address = TRUE;
				break;
			}
			case JANUS_STUN_ATTR_ERROR_CODE: {
				janus_stun_attr_error_code *error = (janus_stun_attr_error_code *)attr->value;
				int code = error->class*100 + error->code;
				if(janus_stun_attr_get_length(attr) > 4) {
					char *reason = g_malloc0(janus_stun_attr_get_length(attr)-4+1);
					memcpy(reason, error->reason, janus_stun_attr_get_length(attr)-4);
					*(reason+janus_stun_attr_get_length(attr)-4) = '\0';
					JANUS_LOG(JICE_LOG_ERR, "[jice] Got an error code: %d (%s)\n", code, reason);
					g_free(reason);
				} else {
					JANUS_LOG(JICE_LOG_ERR, "[jice] Got an error code: %d\n", code);
				}
				return code;
			}
			case JANUS_STUN_ATTR_USERNAME: {
				janus_stun_attr_username *u = (janus_stun_attr_username *)attr->value;
				int len = janus_stun_attr_get_length(attr);
				if(len > 255)
					len = 255;
				memcpy(username, u->username, len);
				username[len] = '\0';
				break;
			}
			case JANUS_STUN_ATTR_MESSAGE_INTEGRITY: {
				janus_stun_attr_message_integrity *mi = (janus_stun_attr_message_integrity *)attr->value;
				int i = 0;
				for(i=0; i<20; i++)
					sprintf(&integrity[i*2], "%02x", mi->hash[i]);
				/* Compute the HMAC-SHA1 hash */
				uint16_t length = janus_stun_msg_get_length(msg);
				janus_stun_msg_set_length(msg, length-8);
				unsigned char *digest = HMAC(EVP_sha1(), agent->remote_pwd, strlen(agent->remote_pwd),
					(unsigned char*)msg, (char *)attr-(char *)msg, NULL, NULL);
				janus_stun_msg_set_length(msg, length);
				for(i=0; i<20; i++)
					sprintf(&computed[i*2], "%02x", (uint8_t)digest[i]);
				break;
			}
			case JANUS_STUN_ATTR_FINGERPRINT: {
				janus_stun_attr_fingerprint *f = (janus_stun_attr_fingerprint *)attr->value;
				crc = f->crc;
				/* Compute CRC-32 on packet */
				computed_crc = crc32(0L, Z_NULL, 0);
				computed_crc = crc32(computed_crc, (unsigned char *)msg, (unsigned char *)attr-(unsigned char *)msg);
				computed_crc = ntohl(computed_crc ^ JANUS_STUN_FINGERPRINT_XOR);
				break;
			}
			default: {
				break;
			}
		}
		/* Go to next attribute, if any */
		int padding = 0;
		if(janus_stun_attr_get_length(attr)%4)
			padding = 4-janus_stun_attr_get_length(attr)%4;
		start += 4+padding+janus_stun_attr_get_length(attr);
		index += 4+padding+janus_stun_attr_get_length(attr);
		total -= 4+padding+janus_stun_attr_get_length(attr);
	}
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Got a connectivity check response: %u/%u\n",
		agent->handle->handle_id, agent->stream_id, agent->component_id);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Username: %s\n", agent->handle->handle_id, username);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Hash:     %s/%s\n", agent->handle->handle_id, integrity, computed);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- CRC:      %"SCNu32"/%"SCNu32"\n", agent->handle->handle_id, crc, computed_crc);
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- Address:  %s\n", agent->handle->handle_id, (got_address ? "true" : "false"));
	/* Validate this request */
	if(!got_address) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Not an error but no mapped address?\n", agent->handle->handle_id);
		return -4;
	}
	if(strlen(integrity) == 0 || strlen(username) == 0 || crc == 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Missing username, message integryty, and/or fingerprint\n", agent->handle->handle_id);
		return -5;
	}
	if(crc != computed_crc) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Fingerprint is wrong... %"SCNu32" != %"SCNu32"\n", agent->handle->handle_id, crc, computed_crc);
		return -6;
	}
	char expected_username[256];
	g_snprintf(expected_username, sizeof(expected_username), "%s:%s", agent->remote_ufrag, agent->local_ufrag);
	if(strcmp(username, expected_username)) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Wrong username... %s != %s\n", agent->handle->handle_id, username, expected_username);
		return -7;
	}
	if(strcmp(integrity, computed)) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Wrong hash... %s != %s\n", agent->handle->handle_id, integrity, computed);
		return -8;
	}
	/* If we got here, it means we got a valid mapped address */
	return 0;
}

/* Helper to generate random strings (ufrag/pwd) */
static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static char *janus_jice_random_string(guint len) {
	if(!len)
		return NULL;
	char *s = g_malloc0(len+1);
	guint i=0;
	for(i = 0; i < len; ++i) {
		*(s+i) = charset[rand() % (sizeof(charset)-1)];
	}
	*(s+len) = 0;
	return s;
}

/* Stringify helpers */
const char *janus_jice_state_as_string(janus_jice_state state) {
	switch(state) {
		case JANUS_JICE_DISCONNECTED:
			return "disconnected";
		case JANUS_JICE_GATHERING:
			return "gathering";
		case JANUS_JICE_CONNECTING:
			return "connecting";
		case JANUS_JICE_CONNECTED:
			return "connected";
		case JANUS_JICE_READY:
			return "ready";
		case JANUS_JICE_FAILED:
			return "failed";
		default:
			return "unknown";
	}
}

const char *janus_jice_pair_state_as_string(janus_jice_pair_state state) {
	switch(state) {
		case JANUS_JICE_PAIR_FROZEN:
			return "frozen";
		case JANUS_JICE_PAIR_WAITING:
			return "waiting";
		case JANUS_JICE_PAIR_INPROGRESS:
			return "in-progress";
		case JANUS_JICE_PAIR_SUCCEEDED:
			return "succeeded";
		case JANUS_JICE_PAIR_FAILED:
			return "failed";
		default:
			return "unknown";
	}
}

const char *janus_jice_type_as_string(janus_jice_type type) {
	switch(type) {
		case JANUS_JICE_HOST:
			return "host";
		case JANUS_JICE_SRFLX:
			return "srflx";
		case JANUS_JICE_PRFLX:
			return "prflx";
		case JANUS_JICE_RELAY:
			return "relay";
		default:
			return "unknown";
	}
}

const char *janus_jice_protocol_as_string(janus_jice_protocol protocol) {
	switch(protocol) {
		case JANUS_JICE_UDP:
			return "udp";
		case JANUS_JICE_TCP:
			return "tcp";
		case JANUS_JICE_TURN_UDP:
			return "turn-udp";
		case JANUS_JICE_TURN_TCP:
			return "turn-tcp";
		case JANUS_JICE_TURN_TLS:
			return "turn-tls";
		default:
			return "unknown";
	}
}


/* Packet management */
static janus_jice_packet *janus_jice_packet_new(gboolean stun, char *buf, guint length, gboolean allocate) {
	if(!buf || !length)
		return NULL;
	janus_jice_packet *packet = (janus_jice_packet *)g_malloc0(sizeof(janus_jice_packet));
	packet->is_stun = stun;
	if(!allocate) {
		packet->data = buf;
	} else {
		packet->data = g_malloc0(length);
		memcpy(packet->data, buf, length);
	}
	packet->length = length;
	return packet;
}

static void janus_jice_packet_destroy(janus_jice_packet *packet) {
	if(!packet)
		return;
	g_free(packet->data);
	g_free(packet);
}

/* Candidate management */
janus_jice_candidate *janus_jice_candidate_new(janus_jice_type type, janus_jice_protocol protocol) {
	janus_jice_candidate *candidate = (janus_jice_candidate *)g_malloc0(sizeof(janus_jice_candidate));
	candidate->type = type;
	candidate->protocol = type;
	return candidate;
}

janus_jice_candidate *janus_jice_candidate_new_full(janus_jice_type type, janus_jice_protocol protocol,
		guint32 priority, char *foundation, char *ip, guint16 port, char *base_ip, guint16 base_port) {
	if(!ip || !port || !foundation)
		return NULL;
	/* Let's parse the addresses, first */
	janus_network_address addr, base_addr;
	if(janus_network_string_to_address(janus_network_query_options_any_ip, ip, &addr) != 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Error resolving candidate address %s...\n", ip);
		return NULL;
	}
	if(base_ip) {
		janus_network_address_nullify(&base_addr);
		if(janus_network_string_to_address(janus_network_query_options_any_ip, base_ip, &base_addr) != 0) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Error resolving candidate base address %s...\n", base_ip);
			return NULL;
		}
	}
	/* Now let's create the candidate instance */
	janus_jice_candidate *candidate = (janus_jice_candidate *)g_malloc0(sizeof(janus_jice_candidate));
	candidate->type = type;
	candidate->protocol = type;
	candidate->notified = TRUE;
	candidate->priority = priority;
	g_snprintf(candidate->foundation, 32, "%s", foundation);
	if(addr.family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&candidate->address;
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		memcpy(&addr4->sin_addr.s_addr, &addr.ipv4, sizeof(struct in_addr));
	} else {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&candidate->address;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		memcpy(&addr6->sin6_addr.s6_addr, &addr.ipv6, sizeof(struct in6_addr));
	}
	if(base_ip) {
		if(base_addr.family == AF_INET) {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&candidate->base_address;
			addr4->sin_family = AF_INET;
			addr4->sin_port = htons(port);
			memcpy(&addr4->sin_addr.s_addr, &base_addr.ipv4, sizeof(struct in_addr));
		} else {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&candidate->base_address;
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = htons(port);
			memcpy(&addr6->sin6_addr.s6_addr, &base_addr.ipv6, sizeof(struct in6_addr));
		}
	}
	return candidate;
}

static janus_jice_candidate_pair *janus_jice_candidate_pair_new(janus_jice_candidate *local, janus_jice_candidate *remote) {
	if(!local || !remote)
		return NULL;
	/* Make sure these candidates refer to the same component, and are of the same address family */
	if(local->agent != remote->agent)
		return NULL;
	if(local->address.sa_family != remote->address.sa_family)
		return NULL;
	/* Create the pair */
	janus_jice_candidate_pair *pair = (janus_jice_candidate_pair *)g_malloc0(sizeof(janus_jice_candidate_pair));
	pair->local = local;
	pair->remote = remote;
	return pair;
}

/* Helper method to convert a sockaddr to ip/port */
int janus_jice_resolve_address(struct sockaddr *address, char *ip, int len, guint16 *port) {
	if(!address || !ip || !port)
		return -1;
	janus_network_address naddr;
	janus_network_address_string_buffer naddr_buf;
	if(janus_network_address_from_sockaddr(address, &naddr) != 0 ||
			janus_network_address_to_string_buffer(&naddr, &naddr_buf) != 0) {
		return -2;
	}
	g_snprintf(ip, len, "%s", janus_network_address_string_from_buffer(&naddr_buf));
	*port = 0;
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;
	switch(address->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)address;
			*port = ntohs(sin->sin_port);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)address;
			*port = ntohs(sin6->sin6_port);
			break;
		default:
			/* Unknown family */
			return -3;
	}
	return 0;
}

/* Helper method to serialize a jice candidate to string */
int janus_jice_candidate_render(janus_jice_candidate *c, char *buffer, int buflen, char *public_ip) {
	if(!c || !buffer || buflen < 1)
		return -1;
	int component_id = c->agent->component_id;
	char *host_ip = NULL;
	if(public_ip) {
		/* A 1:1 NAT mapping was specified, overwrite all the host addresses with the public IP */
		host_ip = public_ip;
	}
	/* Encode the candidate to a string */
	gchar address[INET6_ADDRSTRLEN], base_address[INET6_ADDRSTRLEN];
	guint16 port = 0, base_port = 0;
	janus_jice_resolve_address((struct sockaddr *)&c->address, address, INET6_ADDRSTRLEN, &port);
	janus_jice_resolve_address((struct sockaddr *)&c->base_address, base_address, INET6_ADDRSTRLEN, &base_port);
	/* Start */
	if(c->type == JANUS_JICE_HOST) {
		/* 'host' candidate */
		if(c->protocol == JANUS_JICE_UDP) {
			g_snprintf(buffer, buflen,
				"%s %d %s %"SCNu32" %s %"SCNu16" typ host",
					c->foundation, component_id,
					"udp", c->priority,
					host_ip ? host_ip : address, port);
		} else {
			if(!c->agent->tcp) {
				/* ICE-TCP support disabled */
				return -4;
			}
			/* TODO We don't support TCP candidates yet */
			return -4;
		}
	} else if(c->type == JANUS_JICE_SRFLX || c->type == JANUS_JICE_PRFLX ||
			c->type == JANUS_JICE_RELAY) {
		/* 'srflx', 'prflx', or 'relay' candidate: what is this, exactly? */
		const char *ltype = janus_jice_type_as_string(c->type);
		if(c->protocol == JANUS_JICE_UDP) {
			g_snprintf(buffer, buflen,
				"%s %d %s %"SCNu32" %s %"SCNu16" typ %s raddr %s rport %"SCNu16,
					c->foundation, component_id,
					"udp", c->priority,
					address, port, ltype,
					base_address, base_port);
		} else {
			if(!c->agent->tcp) {
				/* ICE-TCP support disabled */
			}
			/* TODO We don't support TCP candidates yet */
			return -4;
		}
	}
	return 0;
}

/* Helper method to convert a ip/port to sockaddr */
int janus_jice_parse_address(char *ip, guint16 port, struct sockaddr *address) {
	if(!ip || !port || !address)
		return -1;
	/* Let's parse the addresses, first */
	janus_network_address addr;
	if(janus_network_string_to_address(janus_network_query_options_any_ip, ip, &addr) != 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Error resolving address %s...\n", ip);
		return -2;
	}
	if(addr.family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		memcpy(&addr4->sin_addr.s_addr, &addr.ipv4, sizeof(struct in_addr));
	} else {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		memcpy(&addr6->sin6_addr.s6_addr, &addr.ipv6, sizeof(struct in6_addr));
	}
	return 0;
}

void janus_jice_init(void) {
	/* Nothing to do, here; maybe in the future? */
}

void janus_jice_deinit(void) {
	/* Nothing to do, here; maybe in the future? */
}

void janus_jice_debugging(gboolean enable) {
	if(enable) {
		/* Make all log lines more verbose */
		JICE_LOG_FATAL = LOG_FATAL;
		JICE_LOG_ERR = LOG_ERR;
		JICE_LOG_WARN = LOG_WARN;
		JICE_LOG_INFO = LOG_INFO;
		JICE_LOG_VERB = LOG_VERB;
		JICE_LOG_HUGE = LOG_HUGE;
	} else {
		/* Put all log levels back to debug mode only */
		JICE_LOG_FATAL = LOG_DBG;
		JICE_LOG_ERR = LOG_DBG;
		JICE_LOG_WARN = LOG_DBG;
		JICE_LOG_INFO = LOG_DBG;
		JICE_LOG_VERB = LOG_DBG;
		JICE_LOG_HUGE = LOG_DBG;
	}
}


static gboolean janus_jice_checking_internal(gpointer user_data) {
	/* When this callback is called, we need to (re)start the connectivity checks */
	janus_jice_agent *agent = (janus_jice_agent *)user_data;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Starting connectivity checks...\n", agent->handle->handle_id);
	/* TODO Prepare the pairs (if they don't exist yet), and start sending checks: we
	 * currently support ICE Lite only, which means ATM we never send checks of our own */
	if(agent->state_cb)
		agent->state_cb(agent->handle, JANUS_JICE_CONNECTING);
	return G_SOURCE_REMOVE;
}

static void janus_jice_read_internal(janus_jice_agent *agent, janus_jice_candidate *from) {
	/* There's incoming data */
	int fd = from->fd;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] read_internal (%d)\n", agent->handle->handle_id, fd);

	struct sockaddr remote_addr;
	socklen_t addrlen = sizeof(remote_addr);
	/* FIXME This currently assumes UDP */
	int len = recvfrom(fd, agent->buffer, sizeof(agent->buffer), 0, &remote_addr, &addrlen);
	JANUS_LOG(JICE_LOG_INFO, "[jice] Got %d bytes\n", len);
	if(janus_jice_is_stun(agent->buffer)) {
		/* This is a STUN or TURN packet, let's handle it */
		JANUS_LOG(JICE_LOG_INFO, "[jice] This is STUN!\n");
		char *payload = (char *)agent->buffer;
		if(!BIT_CHECK(*payload, 7) && !BIT_CHECK(*payload, 6)) {
			JANUS_LOG(JICE_LOG_INFO, "[jice]   -- STUN\n");
		} else if(!BIT_CHECK(*payload, 7) && BIT_CHECK(*payload, 6)) {
			JANUS_LOG(JICE_LOG_INFO, "[jice]   -- ChannelData\n");
			janus_stun_attr_channel_data *cd = (janus_stun_attr_channel_data *)agent->buffer;
			JANUS_LOG(JICE_LOG_INFO, "[jice]  << ch=%d, l=%d/%d\n",
				ntohs(cd->channel), ntohs(cd->length), len);
			if(ntohs(cd->channel) < 0x4000 || ntohs(cd->channel) > 0x7FFF)
				JANUS_LOG(JICE_LOG_INFO, "[jice]\t\tInvalid channel (not 0x4000 through 0x7FFF)...\n");
			return;
		} else {
			JANUS_LOG(JICE_LOG_WARN, "[jice]   -- Not a STUN/TURN message?\n");
		}
		/* Parse the message */
		janus_stun_msg *msg = (janus_stun_msg *)payload;
		char transaction[40];
		janus_stun_msg_get_transaction_as_string(msg, transaction);
		janus_stun_typemask_print(msg);
		JANUS_LOG(JICE_LOG_INFO, "[jice]   << c=%d (%s), m=%d (%s), l=%d/%d, t=%"SCNx32"/%s\n",
			janus_stun_msg_get_class(msg),
			janus_stun_class_string(janus_stun_msg_get_class(msg)),
			janus_stun_msg_get_method(msg),
			janus_stun_method_string(janus_stun_msg_get_method(msg)),
			janus_stun_msg_get_length(msg), len,
			janus_stun_msg_get_cookie(msg), transaction);
		if((janus_stun_msg_get_length(msg)+20) > len) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Length plus header is larger than the packet size, broken message...\n");
			return;
		}
		if((janus_stun_msg_get_length(msg)+20) != len) {
			JANUS_LOG(JICE_LOG_WARN, "[jice] Length plus header is different than the packet size, possibly broken message?\n");
		}
		/* Let's ckeck if this is a response and we know the transaction */
		if(janus_stun_msg_get_class(msg) == JANUS_STUN_SUCCESS_RESPONSE ||
				janus_stun_msg_get_class(msg) == JANUS_STUN_ERROR_RESPONSE) {
			janus_jice_candidate *candidate = g_hash_table_lookup(agent->gathering_tr, transaction);
			if(candidate != NULL) {
				/* This is a response to a gathering STUN request */
				g_hash_table_remove(agent->gathering_tr, transaction);
				JANUS_LOG(JICE_LOG_INFO, "[jice] Got response to gathering request (%s)\n", transaction);
				/* Get rid of the original packet, so that we don't retransmit later */
				janus_jice_packet_destroy(candidate->pkt);
				candidate->pkt = NULL;
				/* Parse this response and update the candidate address */
				int res = janus_jice_handle_gathering_response(msg, len, &candidate->address);
				if(res == 0) {
					agent->local_candidates = g_slist_append(agent->local_candidates, candidate);
					/* Notify application, if needed */
					if(!candidate->notified) {
						candidate->notified = TRUE;
						if(agent->localcand_cb)
							agent->localcand_cb(agent->handle, candidate);
					}
					/* Prepare new pairs, if we already have some remote candidates */
					GSList *rc = agent->remote_candidates;
					while(rc) {
						janus_jice_candidate *rcand = (janus_jice_candidate *)rc->data;
						janus_jice_candidate_pair *pair = janus_jice_candidate_pair_new(candidate, rcand);
						if(pair) {
							agent->pairs = g_slist_append(agent->pairs, pair);
						}
						rc = rc->next;
					}
				} else {
					JANUS_LOG(JICE_LOG_ERR, "[jice] Error parsing response to gathering request (%s --> %d)\n", transaction, res);
				}
				return;
			}
			janus_jice_candidate_pair *pair = g_hash_table_lookup(agent->checks_tr, transaction);
			if(pair != NULL) {
				/* This is a response to a connectivity check */
				/* TODO To what should we set "candidate"? */
				g_hash_table_remove(agent->checks_tr, transaction);
				JANUS_LOG(JICE_LOG_HUGE, "[jice] Got response to connectivity check (%s)\n", transaction);
				/* Get rid of the original packet, so that we don't retransmit later */
				janus_jice_packet_destroy(pair->pkt);
				pair->pkt = NULL;
				/* Parse this response and update the pair status */
				int res = janus_jice_handle_connectivity_check_response(agent, msg, len, &candidate->address);
				if(res == 0) {
					/* TODO Handle somehow */
					JANUS_LOG(JICE_LOG_INFO, "[jice] Handling response to connectivity check (%s)\n", transaction);
				} else {
					JANUS_LOG(JICE_LOG_ERR, "[jice] Error parsing response to connectivity check (%s --> %d)\n", transaction, res);
					/* TODO Handle somehow */
				}
				return;
			} else {
				/* Not a response we know about? */
				JANUS_LOG(JICE_LOG_WARN, "[jice] Ignoring response to unknown transaction\n");
				return;
			}
		}
		/* Incoming request, handle */
		janus_jice_candidate *local = NULL, *remote = NULL;
		GSList *c = agent->local_candidates;
		while(c) {
			janus_jice_candidate *cand = (janus_jice_candidate *)c->data;
			if(cand->fd == fd) {
				local = cand;
				break;
			}
			c = c->next;
		}
		c = agent->remote_candidates;
		while(c) {
			janus_jice_candidate *cand = (janus_jice_candidate *)c->data;
			if(janus_stun_sockaddr_is_equal(&remote_addr, &cand->address)) {
				remote = cand;
				break;
			}
			c = c->next;
		}
		if(remote == NULL) {
			JANUS_LOG(JICE_LOG_WARN, "[jice] Not a candidate we know about? Maybe it's a prflx then...\n");
			/* FIXME Create prflx candidate */
			janus_jice_candidate *prflx = g_malloc0(sizeof(janus_jice_candidate));
			prflx->agent = agent;
			prflx->type = JANUS_JICE_PRFLX;
			prflx->protocol = JANUS_JICE_UDP;
			prflx->base = local;
			memcpy(&prflx->address, &remote_addr, sizeof(remote_addr));
			prflx->priority =
				(2^24) * JANUS_JICE_TYPE_PREFERENCE_PRFLX +
				(2^8)  * local->lp +
				(2^0)  * (256 - agent->component_id);
			prflx->lp = local->lp;
			prflx->fd = -1;	/* FIXME We'll refer to the host candidate for the file descriptor */
			g_snprintf(prflx->foundation, sizeof(prflx->foundation)-1, "%s", local->foundation);
			agent->remote_candidates = g_slist_append(agent->remote_candidates, prflx);
			remote = prflx;
		}
		janus_jice_candidate_pair *pair = NULL;
		c = agent->pairs;
		while(c) {
			janus_jice_candidate_pair *p = (janus_jice_candidate_pair *)c->data;
			if(p && p->local == local && p->remote == remote) {
				pair = p;
				break;
			}
			c = c->next;
		}
		if(pair == NULL) {
			JANUS_LOG(JICE_LOG_WARN, "[jice] Not a pair we know about? Create one now...\n");
			pair = janus_jice_candidate_pair_new(local, remote);
			agent->pairs = g_slist_append(agent->pairs, pair);
		}
		JANUS_LOG(JICE_LOG_INFO, "[jice] Got connectivity check (%s), sent to local candidate %p from remote candidate %p\n",
			transaction, local, remote);
		int res = janus_jice_handle_connectivity_check(agent, msg, len);
		if(res == 0) {
			/* TODO A valid connectivity check, handle and respond */
			guint msglen = 0;
			janus_stun_msg *response = janus_jice_create_connectivity_check_response(agent, msg, &msglen, &remote_addr);
			/* Prepare response and send it */
			char ip[INET6_ADDRSTRLEN];
			guint16 port = 0;
			janus_jice_resolve_address((struct sockaddr *)&remote_addr, ip, INET6_ADDRSTRLEN, &port);
			JANUS_LOG(JICE_LOG_INFO, "[jice]   -- Sending response back to %s:%"SCNu16" (%d bytes)\n", ip, port, msglen);
			janus_jice_packet *pkt = janus_jice_packet_new(TRUE, (char *)response, msglen, FALSE);
			pkt->agent = agent;
			pkt->address = remote_addr;
			pkt->fd = fd;
			janus_jice_send_internal(agent, pkt);
			/* Let's send a connectivity check back as well */
			janus_stun_msg *check = janus_jice_create_connectivity_check(local, FALSE, &msglen);
			pkt = janus_jice_packet_new(TRUE, (char *)check, msglen, FALSE);
			pkt->agent = agent;
			pkt->address = remote_addr;
			pkt->fd = fd;
			JANUS_LOG(JICE_LOG_INFO, "[jice]   -- Sending a connectivity check to %s:%"SCNu16" as well (%d bytes)\n", ip, port, msglen);
			janus_jice_send_internal(agent, pkt);
			/* TODO Just for testing, we assume the state is connected now */
			agent->selected_pair = pair;
			if(agent->state_cb)
				agent->state_cb(agent->handle, JANUS_JICE_CONNECTED);
			if(agent->selectedpair_cb)
				agent->selectedpair_cb(agent->handle, local, remote);
		} else {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Error parsing connectivity check (%s --> %d)\n", transaction, res);
			/* TODO Handle somehow */
			guint msglen = 0;
			janus_stun_msg *response = NULL;
			if(res < 0) {
				/* Let's reply with an authorized */
				response = janus_jice_create_connectivity_check_error(agent, msg, JANUS_STUN_ERROR_UNAUTHORIZED, &msglen);
			} else {
				/* Let's reply with whatever the parser gave us back */
				response = janus_jice_create_connectivity_check_error(agent, msg, res, &msglen);
			}
			/* Prepare response and send it */
			char ip[INET6_ADDRSTRLEN];
			guint16 port = 0;
			janus_jice_resolve_address((struct sockaddr *)&remote_addr, ip, INET6_ADDRSTRLEN, &port);
			JANUS_LOG(JICE_LOG_INFO, "[jice]   -- Sending error back to %s:%"SCNu16" (%d bytes)\n", ip, port, msglen);
			janus_jice_packet *pkt = janus_jice_packet_new(TRUE, (char *)response, msglen, FALSE);
			pkt->agent = agent;
			pkt->address = remote_addr;
			pkt->fd = fd;
			janus_jice_send_internal(agent, pkt);
		}
		return;
	}
	JANUS_LOG(JICE_LOG_INFO, "[jice] Apparently not STUN, notifying application (%d bytes)\n", len);
	/* Pass the buffer to the application */
	if(agent->recv_cb)
		agent->recv_cb(agent->handle, agent->buffer, len);
}

static int janus_jice_send_internal(janus_jice_agent *agent, janus_jice_packet *pkt) {
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] send_internal: sending %d bytes (%d)\n",
		agent->handle->handle_id, pkt->length, pkt->fd);
	int addrlen = sizeof(pkt->address);
	int fd = pkt->fd, sent = 0;
	while(TRUE) {
		sent = sendto(fd, pkt->data, pkt->length, 0, &pkt->address, addrlen);
		if(sent < 0) {
			if(errno == EAGAIN) {
				/* Let's try again */
				continue;
			}
			JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Error sending packet: %d (%s)\n",
				agent->handle->handle_id, errno, strerror(errno));
			return sent;
		}
		break;
	}
	/* Only free the packet if it's not STUN/TURN (unless there's no retransmission in place for those) */
	gboolean destroy_packet = TRUE;
	if(pkt->is_stun) {
		char transaction[40];
		janus_stun_msg_get_transaction_as_string((janus_stun_msg *)pkt->data, transaction);
		if(g_hash_table_lookup(agent->gathering_tr, transaction) ||
				g_hash_table_lookup(agent->checks_tr, transaction))
			destroy_packet = FALSE;
	}
	if(destroy_packet)
		janus_jice_packet_destroy(pkt);
	return sent;
}

static gboolean janus_jice_retransmit_internal(gpointer user_data) {
	/* We only get here for STUN packets: that's where we schedule retransmits */
	janus_jice_candidate *candidate = (janus_jice_candidate *)user_data;
	janus_jice_packet *pkt = candidate->pkt;
	if(pkt == NULL) {
		JANUS_LOG(JICE_LOG_INFO, "[jice] No need to retransmit\n");
		return G_SOURCE_REMOVE;
	}
	if(candidate->pkt_trans == 6) {
		JANUS_LOG(JICE_LOG_WARN, "[jice] Too many retransmissions, giving up...\n");
		janus_jice_packet_destroy(pkt);
		candidate->pkt = NULL;
		/* Get rid of candidate */
		return G_SOURCE_REMOVE;
	}
	janus_jice_agent *agent = pkt->agent;
	/* Send the packet */
	janus_jice_send_internal(agent, pkt);
	/* Let's schedule a retransmit */
	guint ms = (1 << candidate->pkt_trans)*100;
	candidate->pkt_trans++;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] retransmit_internal: next one scheduled in %u ms (#%d)\n",
		agent->handle->handle_id, ms, candidate->pkt_trans);
	GSource *retrans = g_timeout_source_new(ms);
	g_source_set_callback(retrans, janus_jice_retransmit_internal, candidate, NULL);
	g_source_attach(retrans, agent->handle->icectx);
	g_source_unref(retrans);
	return G_SOURCE_REMOVE;
}

static gboolean janus_jice_gathering_internal(gpointer user_data) {
	/* When this callback is called, we need to start gathering: we only do this once */
	janus_jice_agent *agent = (janus_jice_agent *)user_data;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Gathering candidates...\n", agent->handle->handle_id);
	/* List all interfaces */
	struct ifaddrs *ifaddr;
	if(getifaddrs(&ifaddr) == -1) {
		JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Error getting list of interfaces...", agent->handle->handle_id);
		return G_SOURCE_REMOVE;
	}
	int family, s, n;
	char host[NI_MAXHOST];
	/* We only have one stream and one component */
	int foundation = 1;
	if(agent->state_cb)
		agent->state_cb(agent->handle, JANUS_JICE_GATHERING);
	/* Let's pick a port to bind to (random by default, unless a range is provided) */
	guint16 port = 0;
	if(agent->min_port && agent->max_port) {
		port = g_random_int_range(agent->min_port, agent->max_port);
	}
	/* Iterate on all interfaces */
	struct ifaddrs *ifa = NULL;
	int lp = 65535;	/* FIXME */
	for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if(ifa->ifa_addr == NULL)
			continue;
		/* Skip interfaces which are not up and running */
		if (!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
			continue;
		/* Skip loopback interfaces */
		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;
		family = ifa->ifa_addr->sa_family;
		if(family != AF_INET && family != AF_INET6)
			continue;
		/* We only add IPv6 addresses if support for them has been explicitly enabled */
		if(family == AF_INET6 && !agent->ipv6)
			continue;
		s = getnameinfo(ifa->ifa_addr,
				(family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
				host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if(s != 0) {
			JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] getnameinfo() failed: %s\n", agent->handle->handle_id, gai_strerror(s));
			continue;
		}
		/* Skip 0.0.0.0, :: and local scoped addresses  */
		if(!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strncmp(host, "fe80:", 5))
			continue;
		/* Check if this interface has been disabled */
		if(agent->interfaces && !g_slist_find_custom(agent->interfaces, host, (GCompareFunc)strcasecmp))
			continue;
		/* Ok, let's bind to this interface now */
		JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Binding to address %s (s=%d, c=%d)\n",
			agent->handle->handle_id, host, agent->stream_id, agent->component_id);
		int fd = -1;
		guint16 start_port = port;
		while(fd < 0) {
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if(fd < 0) {
				break;
			}
			if(family == AF_INET6) {
				((struct sockaddr_in *)ifa->ifa_addr)->sin_port = htons(port);
			} else {
				((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_port = htons(port);
			}
			if(bind(fd, ifa->ifa_addr, sizeof(struct sockaddr)) < 0) {
				JANUS_LOG(JICE_LOG_WARN, "[jice][%"SCNu64"] Bind failed (port %d)...\n", agent->handle->handle_id, port);
				close(fd);
				fd = -1;
				if(port == 0) {
					/* Port was random and it failed? Give up... */
					break;
				}
				port++;
				if(port > agent->max_port)
					port = agent->min_port;
				if(port == start_port) {
					/* We tried them all and it failed, give up... */
					break;
				}
			}
		}
		if(fd < 0) {
			JANUS_LOG(JICE_LOG_ERR, "[jice][%"SCNu64"] Cannot create %s UDP socket...\n",
				agent->handle->handle_id, (family == AF_INET6 ? "IPv6" : "IPv4"));
		} else {
			int bport = 0;
			struct sockaddr address;
			socklen_t len = sizeof(address);
			getsockname(fd, &address, &len);
			if(family == AF_INET6) {
				bport = ntohs(((struct sockaddr_in *)&address)->sin_port);
			} else {
				bport = ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
			}
			if(port == 0)
				port = bport;
			JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- %s:%"SCNu16" (s=%d, c=%d)\n",
				agent->handle->handle_id, host, bport, agent->stream_id, agent->component_id);
			/* Create a candidate instance */
			janus_jice_candidate *candidate = (janus_jice_candidate *)g_malloc0(sizeof(janus_jice_candidate));
			candidate->agent = agent;
			candidate->type = JANUS_JICE_HOST;
			candidate->protocol = JANUS_JICE_UDP;
			candidate->address = address;
			candidate->priority =
				(2^24) * JANUS_JICE_TYPE_PREFERENCE_HOST +
				(2^8)  * lp +
				(2^0)  * (256 - agent->component_id);
			candidate->lp = lp;
			candidate->fd = fd;
			g_snprintf(candidate->foundation, sizeof(candidate->foundation)-1, "%d", foundation);
			agent->local_candidates = g_slist_append(agent->local_candidates, candidate);
			/* Create a source to track incoming traffic on this file descriptor */
			candidate->source = janus_jice_fd_source_create(agent->handle->handle_id, candidate);
			g_source_attach(candidate->source, agent->handle->icectx);
			/* Notify application, if needed */
			candidate->notified = TRUE;
			if(agent->localcand_cb)
				agent->localcand_cb(agent->handle, candidate);
		}
		lp--;	/* FIXME */
	}
	freeifaddrs(ifaddr);
	if(!agent->stunturn_servers) {
		/* No STUN/TURN servers, let's notify that we're done gathering */
		if(agent->localcand_cb)
			agent->localcand_cb(agent->handle, NULL);
		/* TODO We'll need to do the same for when we're gathering srflx/relay candidates as well */
	} else {
		/* Now that we gathered all the host candidates, let's see if there's any STUN/TURN gathering to do */
		JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Host candidates collected, gathering srflx/relay candidates now\n", agent->handle->handle_id);
		GSList *s = agent->stunturn_servers;
		/* Iterate on all STUN servers */
		while(s) {
			janus_jice_stunturn_server *st = (janus_jice_stunturn_server *)s->data;
			/* Iterate on host candidates for this agent */
			GSList *cd = agent->local_candidates;
			while(cd) {
				janus_jice_candidate *candidate = (janus_jice_candidate *)cd->data;
				/* Resolve candidate address */
				janus_network_address naddr;
				janus_network_address_string_buffer naddr_buf;
				if(janus_network_address_from_sockaddr((struct sockaddr *)&candidate->address, &naddr) != 0 ||
						janus_network_address_to_string_buffer(&naddr, &naddr_buf) != 0) {
					JANUS_LOG(JICE_LOG_WARN, "[jice] Error trying to resolve candidate address...\n");
				} else {
					const char *ip = janus_network_address_string_from_buffer(&naddr_buf);
					guint16 port = 0;
					struct sockaddr_in *sin = NULL;
					struct sockaddr_in6 *sin6 = NULL;
					switch(candidate->address.sa_family) {
						case AF_INET:
							sin = (struct sockaddr_in *)&candidate->address;
							port = ntohs(sin->sin_port);
							break;
						case AF_INET6:
							sin6 = (struct sockaddr_in6 *)&candidate->address;
							port = ntohs(sin6->sin6_port);
							break;
						default:
							/* Unknown family */
							break;
					}
					if(st->type == JANUS_JICE_UDP) {
						/* Create a temporary srfx candidate */
						janus_jice_candidate *srflx = g_malloc0(sizeof(janus_jice_candidate));
						srflx->agent = agent;
						srflx->type = JANUS_JICE_SRFLX;
						srflx->protocol = JANUS_JICE_UDP;
						srflx->base = candidate;
						srflx->priority =
							(2^24) * JANUS_JICE_TYPE_PREFERENCE_SRFLX +
							(2^8)  * candidate->lp +
							(2^0)  * (256 - agent->component_id);
						srflx->lp = candidate->lp;
						srflx->fd = -1;	/* FIXME We'll refer to the host candidate for the file descriptor */
						g_snprintf(srflx->foundation, sizeof(srflx->foundation)-1, "%d", foundation);
						/* Send STUN request */
						guint stunlen = 0;
						janus_stun_msg *stun = janus_jice_create_binding_request(&stunlen);
						/* Keep track of transaction */
						char transaction[40];
						janus_stun_msg_get_transaction_as_string(stun, transaction);
						gboolean ipv6 = candidate->address.sa_family == AF_INET6;
						JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Sending %s STUN request (%s) to %s:%"SCNu16" from %s:%"SCNu16" (s=%d, c=%d)\n",
							agent->handle->handle_id, (ipv6 ? "IPv6" : "IPv4"), transaction,
							st->server, st->port, ip, port,
							agent->stream_id, agent->component_id);
						g_hash_table_insert(agent->gathering_tr, g_strdup(transaction), srflx);
						/* Prepare packet and send it */
						janus_jice_packet *pkt = janus_jice_packet_new(TRUE, (char *)stun, stunlen, FALSE);
						pkt->agent = agent;
						memcpy(&pkt->address, (ipv6 ? (struct sockaddr *)&(st->address6) : (struct sockaddr *)&(st->address)), sizeof(struct sockaddr));
						pkt->fd = candidate->fd;
						srflx->pkt = pkt;
						janus_jice_retransmit_internal(srflx);
					} else {
						/* Create a temporary relay candidate */
						janus_jice_candidate *relay = g_malloc0(sizeof(janus_jice_candidate));
						relay->agent = agent;
						relay->type = JANUS_JICE_RELAY;
						relay->protocol = st->type;
						relay->base = candidate;
						relay->priority =
							(2^24) * JANUS_JICE_TYPE_PREFERENCE_RELAY +
							(2^8)  * candidate->lp +
							(2^0)  * (256 - agent->component_id);
						relay->lp = candidate->lp;
						relay->fd = -1;	/* FIXME We'll refer to the host candidate for the file descriptor */
						g_snprintf(relay->foundation, sizeof(relay->foundation)-1, "%d", foundation);
						//~ JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] Sending TURN request to %s:%"SCNu16" from %s:%"SCNu16" (s=%d, c=%d)\n",
							//~ agent->handle->handle_id, st->address, st->port, ip, port,
							//~ agent->stream_id, agent->component_id);
						/* TODO Send TURN request */
					}
				}
				cd = cd->next;
			}
		}
	}
	return G_SOURCE_REMOVE;
}

static gboolean janus_jice_new_candidate_internal(gpointer user_data) {
	/* When this callback is called, it means we have a new remote candidate:
	 * let's check if we need to pair it with our own for connectivity checks */
	janus_jice_candidate *candidate = (janus_jice_candidate *)user_data;
	janus_jice_agent *agent = candidate->agent;
	/* Show the candidate for debugging purposes */
	char buffer[200];
	buffer[0] = '\0';
	if(janus_jice_candidate_render(candidate, buffer, sizeof(buffer), NULL) < 0) {
		JANUS_LOG(JICE_LOG_WARN, "Error rendering %s remote candidate..?\n", janus_jice_type_as_string(candidate->type));
	}
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] candidate_cb: new remote candidate: %s\n",
		agent->handle->handle_id, buffer);
	agent->remote_candidates = g_slist_append(agent->remote_candidates, candidate);
	/* Prepare new pairs */
	GSList *lc = agent->local_candidates;
	while(lc) {
		janus_jice_candidate *lcand = (janus_jice_candidate *)lc->data;
		janus_jice_candidate_pair *pair = janus_jice_candidate_pair_new(lcand, candidate);
		if(pair) {
			JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"]   -- paired with a local candidate\n", agent->handle->handle_id);
			agent->pairs = g_slist_append(agent->pairs, pair);
		}
		lc = lc->next;
	}
	return G_SOURCE_REMOVE;
}

static gboolean janus_jice_restart_internal(gpointer user_data) {
	/* When this callback is called, it means have to do an ICE restart */
	janus_jice_agent *agent = (janus_jice_agent *)user_data;
	JANUS_LOG(JICE_LOG_INFO, "[jice][%"SCNu64"] restart_internal\n", agent->handle->handle_id);
	/* FIXME */
	g_free(agent->old_local_ufrag);
	agent->old_local_ufrag = agent->local_ufrag;
	g_free(agent->old_local_pwd);
	agent->old_local_pwd = agent->local_pwd;
	agent->local_ufrag = janus_jice_random_string(4);
	agent->local_pwd = janus_jice_random_string(22);
	/* Start new checks */
	return janus_jice_checking_internal(agent);
}

static void janus_jice_agent_free(const janus_refcount *agent_ref) {
	janus_jice_agent *agent = janus_refcount_containerof(agent_ref, janus_jice_agent, ref);
	/* TODO Make sure we free everything here */
	while(agent->stunturn_servers) {
		GSList *s = agent->stunturn_servers;
		janus_jice_stunturn_server *st = (janus_jice_stunturn_server *)s->data;
		agent->stunturn_servers = g_slist_remove(agent->stunturn_servers, st);
		g_free(st->server);
		g_free(st->user);
		g_free(st->pwd);
		g_free(st);
	}
	g_slist_free_full(agent->interfaces, (GDestroyNotify)g_free);
	g_free(agent->local_ufrag);
	g_free(agent->local_pwd);
	g_free(agent->old_local_ufrag);
	g_free(agent->old_local_pwd);
	g_free(agent->remote_ufrag);
	g_free(agent->remote_pwd);
	g_free(agent->old_remote_ufrag);
	g_free(agent->old_remote_pwd);
	g_slist_free_full(agent->local_candidates, g_free);
	g_slist_free_full(agent->remote_candidates, g_free);
	g_hash_table_destroy(agent->gathering_tr);
	g_hash_table_destroy(agent->checks_tr);
	g_free(agent);
}

janus_jice_agent *janus_jice_agent_new(void *handle, gboolean full, gboolean controlling, gboolean ipv6, gboolean tcp) {
	janus_jice_agent *agent = (janus_jice_agent *)g_malloc0(sizeof(janus_jice_agent));
	agent->handle = (janus_ice_handle *)handle;
	agent->full = full;
	agent->controlling = controlling;
	agent->ipv6 = ipv6;
	agent->tcp = tcp;
	agent->stream_id = 1;
	agent->component_id = 1;
	agent->gathering_tr = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
	agent->checks_tr = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);
	agent->local_ufrag = janus_jice_random_string(4);
	agent->local_pwd = janus_jice_random_string(22);
	agent->tie = janus_random_uint64();
	janus_refcount_init(&agent->ref, janus_jice_agent_free);
	return agent;
}

int janus_jice_agent_set_localcand_cb(janus_jice_agent *agent,
		void(*localcand_cb)(void *, janus_jice_candidate *)) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return -1;
	if(localcand_cb) {
		/* Setting callback */
		agent->localcand_cb = localcand_cb;
	} else {
		/* Disabling callback */
		agent->localcand_cb = NULL;
	}
	return 0;
}

int janus_jice_agent_set_remotecand_cb(janus_jice_agent *agent,
		void(*remotecand_cb)(void *, janus_jice_candidate *)) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return -1;
	if(remotecand_cb) {
		/* Setting callback */
		agent->remotecand_cb = remotecand_cb;
	} else {
		/* Disabling callback */
		agent->remotecand_cb = NULL;
	}
	return 0;
}

int janus_jice_agent_set_state_cb(janus_jice_agent *agent,
		void(*state_cb)(void *, janus_jice_state)) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return -1;
	if(state_cb) {
		/* Setting callback */
		agent->state_cb = state_cb;
	} else {
		/* Disabling callback */
		agent->state_cb = NULL;
	}
	return 0;
}

int janus_jice_agent_set_selectedpair_cb(janus_jice_agent *agent,
		void(*selectedpair_cb)(void *, janus_jice_candidate *, janus_jice_candidate *)) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return -1;
	if(selectedpair_cb) {
		/* Setting callback */
		agent->selectedpair_cb = selectedpair_cb;
	} else {
		/* Disabling callback */
		agent->selectedpair_cb = NULL;
	}
	return 0;
}

int janus_jice_agent_set_recv_cb(janus_jice_agent *agent,
		void(*recv_cb)(void *, char *, guint)) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return -1;
	if(recv_cb) {
		/* Setting callback */
		agent->recv_cb = recv_cb;
	} else {
		/* Disabling callback */
		agent->recv_cb = NULL;
	}
	return 0;
}

int janus_jice_agent_add_interface(janus_jice_agent *agent, char *iface) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !iface)
		return -1;
	agent->interfaces = g_slist_append(agent->interfaces, g_strdup(iface));
	return 0;
}

int janus_jice_agent_set_port_range(janus_jice_agent *agent, guint16 min_port, guint16 max_port) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !min_port || !max_port || min_port > max_port)
		return -1;
	agent->min_port = min_port;
	agent->max_port = max_port;
	return 0;
}

int janus_jice_agent_add_stun_server(janus_jice_agent *agent, char *address, guint16 port) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !address || !port)
		return -1;
	/* Resolve address */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(address, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Could not resolve %s...\n", address);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	janus_jice_stunturn_server *stun = g_malloc0(sizeof(janus_jice_stunturn_server));
	stun->type = JANUS_JICE_UDP;
	stun->server = g_strdup(address);
	stun->port = port;
	stun->address.sin_family = AF_INET;
	stun->address.sin_port = htons(port);
	stun->address.sin_addr = addr.ipv4;
	stun->address6.sin6_family = AF_INET6;
	stun->address6.sin6_port = htons(port);
	stun->address6.sin6_addr = addr.ipv6;
	agent->stunturn_servers = g_slist_append(agent->stunturn_servers, stun);
	return 0;
}

int janus_jice_agent_add_turn_server(janus_jice_agent *agent, char *address, guint16 port,
		janus_jice_protocol protocol, char *user, char *pwd) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !address || !port)
		return -1;
	if(protocol != JANUS_JICE_TURN_UDP && protocol != JANUS_JICE_TURN_TCP && protocol != JANUS_JICE_TURN_TLS)
		return -2;
	/* TODO We don't support TURN yet, so this is just a placeholder */
	JANUS_LOG(JICE_LOG_WARN, "[jice] TURN not supported yet, will ignore this server when gathering\n");
	/* Resolve address */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(address, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Could not resolve %s...\n", address);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	janus_jice_stunturn_server *turn = g_malloc0(sizeof(janus_jice_stunturn_server));
	turn->type = protocol;
	turn->server = g_strdup(address);
	turn->port = port;
	if(user)
		turn->user = g_strdup(user);
	if(pwd)
		turn->pwd = g_strdup(pwd);
	turn->address.sin_family = AF_INET;
	turn->address.sin_port = htons(port);
	turn->address.sin_addr = addr.ipv4;
	turn->address6.sin6_family = AF_INET6;
	turn->address6.sin6_port = htons(port);
	turn->address6.sin6_addr = addr.ipv6;
	agent->stunturn_servers = g_slist_append(agent->stunturn_servers, turn);
	return 0;
}

void janus_jice_agent_start_gathering(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return;
	if(!g_atomic_int_compare_and_exchange(&agent->gathering, 0, 1))
		return;
	/* Fire an event to start gathering */
	GSource *start = g_timeout_source_new_seconds(0);
	g_source_set_callback(start, janus_jice_gathering_internal, agent, NULL);
	g_source_attach(start, agent->handle->icectx);
	g_source_unref(start);
}

char *janus_jice_agent_get_local_ufrag(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	return g_strdup(agent->local_ufrag);
}

char *janus_jice_agent_get_local_pwd(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	return g_strdup(agent->local_pwd);
}

int janus_jice_agent_set_remote_credentials(janus_jice_agent *agent, char *ufrag, char *pwd) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !ufrag || !pwd)
		return -1;
	if(agent->remote_ufrag) {
		/* ICE restart? */
		g_free(agent->old_remote_ufrag);
		agent->old_remote_ufrag = agent->remote_ufrag;
		g_free(agent->old_remote_pwd);
		agent->old_remote_pwd = agent->remote_pwd;
	}
	agent->remote_ufrag = g_strdup(ufrag);
	agent->remote_pwd = g_strdup(pwd);
	return 0;
}

char *janus_jice_agent_get_remote_ufrag(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	return g_strdup(agent->remote_ufrag);
}

char *janus_jice_agent_get_remote_pwd(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	return g_strdup(agent->remote_pwd);
}

int janus_jice_agent_add_remote_candidate(janus_jice_agent *agent, janus_jice_candidate *candidate) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !candidate)
		return -1;
	/* Fire an event to notify the stack about the new remote candidate */
	candidate->agent = agent;
	candidate->notified = TRUE;
	GSource *newcand = g_timeout_source_new_seconds(0);
	g_source_set_callback(newcand, janus_jice_new_candidate_internal, candidate, NULL);
	g_source_attach(newcand, agent->handle->icectx);
	g_source_unref(newcand);
	return 0;
}

void janus_jice_agent_start_checks(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return;
	/* Fire an event to start connectivity checks */
	GSource *start = g_timeout_source_new_seconds(0);
	g_source_set_callback(start, janus_jice_checking_internal, agent, NULL);
	g_source_attach(start, agent->handle->icectx);
	g_source_unref(start);
}

GSList *janus_jice_agent_get_local_candidates(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	/* FIXME We should clone candidates as well */
	return g_slist_copy(agent->local_candidates);
}

GSList *janus_jice_agent_get_remote_candidates(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return NULL;
	/* FIXME We should clone candidates as well */
	return g_slist_copy(agent->remote_candidates);
}

int janus_jice_agent_send(janus_jice_agent *agent, char *buf, int len) {
	if(!agent || g_atomic_int_get(&agent->destroyed) || !buf || len < 1)
		return -1;
	if(!agent->selected_pair || !agent->selected_pair->local || !agent->selected_pair->remote)
		return -2;
	/* Note: we assume this is invoked from the main loop, so this is NOT thread safe */
	janus_jice_packet *pkt = janus_jice_packet_new(FALSE, buf, len, TRUE);
	pkt->agent = agent;
	pkt->fd = agent->selected_pair->local->fd;
	memcpy(&pkt->address, &agent->selected_pair->remote->address, sizeof(struct sockaddr));
	return janus_jice_send_internal(agent, pkt);
}

void janus_jice_agent_restart(janus_jice_agent *agent) {
	if(!agent || g_atomic_int_get(&agent->destroyed))
		return;
	/* Fire an event to trigger an ICE restart */
	GSource *restart = g_timeout_source_new_seconds(0);
	g_source_set_callback(restart, janus_jice_restart_internal, agent, NULL);
	g_source_attach(restart, agent->handle->icectx);
	g_source_unref(restart);
}

void janus_jice_agent_destroy(janus_jice_agent *agent) {
	if(agent && g_atomic_int_compare_and_exchange(&agent->destroyed, 0, 1))
		janus_refcount_decrease(&agent->ref);
}


/* Helper method to create a socket for a quick STUN request */
static int janus_ice_test_stun_fd(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = 0;
	address.sin_addr.s_addr = INADDR_ANY;
	if(bind(fd, (struct sockaddr *)(&address), sizeof(struct sockaddr)) < 0) {
		JANUS_LOG(JICE_LOG_FATAL, "[jice] Bind failed for STUN BINDING test\n");
		close(fd);
		return -1;
	}
	socklen_t addrlen = sizeof(address);
	getsockname(fd, (struct sockaddr *)&address, &addrlen);
	JANUS_LOG(JICE_LOG_INFO, "[jice] STUN client bound to port %"SCNu16"\n", ntohs(address.sin_port));
	return fd;
}

/* Helper method to quickly resolve a STUN address */
static int janus_ice_test_stun_resolve(char *server, int port, struct sockaddr *remote) {
	if(!server || !remote)
		return -1;
	/* Resolve address to get an IP */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(server, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Could not resolve %s...\n", server);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	JANUS_LOG(JICE_LOG_INFO, "[jice] %s resolved to %s\n", server, (char *)janus_network_address_string_from_buffer(&addr_buf));
	struct sockaddr_in *remote4 = (struct sockaddr_in *)remote;
	remote4->sin_family = AF_INET;
	remote4->sin_port = htons(port);
	remote4->sin_addr = addr.ipv4;
	return 0;
}

/* Helper method to actually perform the STUN request */
static int janus_jice_test_stun_send(int fd, struct sockaddr *remote, struct sockaddr *mapped_address) {
	if(fd < 1 || !remote || !mapped_address)
		return -1;
	/* Send a binding request */
	char buf[1500];
	guint reqlen = 0;
	janus_stun_msg *request = janus_jice_create_binding_request(&reqlen);
	int len = sendto(fd, request, reqlen, 0, remote, sizeof(*remote));
	janus_stun_msg_destroy(request);
	if(len < 0) {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Error sending STUN request... %d (%s)\n", errno, strerror(errno));
		return len;
	}
	/* Wait for a response */
	struct pollfd fds;
	while(TRUE) {
		fds.fd = fd;
		fds.events = POLLIN;
		fds.revents = 0;
		if(poll(&fds, 1, 5000) < 0) {
			if(errno == EINTR)
				continue;
			JANUS_LOG(JICE_LOG_ERR, "[jice] Error polling... %d (%s)\n", errno, strerror(errno));
			return -1;
		}
		break;
	}
	if(fds.revents & POLLIN) {
		socklen_t addrlen = sizeof(remote);
		len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&remote, &addrlen);
		JANUS_LOG(JICE_LOG_INFO, "[jice]   >> Got %d bytes...\n", len);
		janus_stun_msg *response = (janus_stun_msg *)buf;
		char buffer[40];
		janus_stun_msg_get_transaction_as_string(response, buffer);
		janus_stun_typemask_print(response);
		JANUS_LOG(JICE_LOG_INFO, "[jice]   << c=%d (%s), m=%d (%s), l=%d/%d, t=%"SCNx32"/%s\n",
			janus_stun_msg_get_class(response),
			janus_stun_class_string(janus_stun_msg_get_class(response)),
			janus_stun_msg_get_method(response),
			janus_stun_method_string(janus_stun_msg_get_method(response)),
			janus_stun_msg_get_length(response), len,
			janus_stun_msg_get_cookie(response), buffer);
		if((janus_stun_msg_get_length(response)+20) > len) {
			JANUS_LOG(JICE_LOG_ERR, "[jice] Length plus header is larger than the packet size, broken message...\n");
			return -1;
		}
		if((janus_stun_msg_get_length(response)+20) != len) {
			JANUS_LOG(JICE_LOG_WARN, "[jice] Length plus header is different than the packet size, possibly broken message?\n");
		}
		if(len > 0 && janus_stun_msg_get_length(response) > 0) {
			uint16_t index = janus_stun_msg_get_length(response), total = len-20;
			char *start = response->attributes;
			while(total > 0) {
				/* Parse attribute */
				janus_stun_attr *attr = (janus_stun_attr *)start;
				if((janus_stun_attr_get_length(attr)+4) > total) {
					JANUS_LOG(JICE_LOG_ERR, "[jice] \t\tAttribute length exceeds size of the packet, broken message...\n");
					return -1;
				}
				switch(janus_stun_attr_get_type(attr)) {
					case JANUS_STUN_ATTR_MAPPED_ADDRESS:
					case JANUS_STUN_ATTR_ALTERNATE_SERVER: {
						janus_stun_attr_mapped_address *address = (janus_stun_attr_mapped_address *)attr->value;
						int family = ntohs(address->family);
						uint16_t port = ntohs(address->port);
						char ip[64];
						ip[0] = '\0';
						if(family == 1) {
							/* IPv4 */
							unsigned char *ipv4 = (unsigned char *)address->address;
							g_snprintf(ip, sizeof(ip), "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
							/* Update the return value */
							struct sockaddr_in *addr4 = (struct sockaddr_in *)mapped_address;
							addr4->sin_family = AF_INET;
							addr4->sin_port = htons(port);
							memcpy(&addr4->sin_addr.s_addr, address->address, sizeof(struct in_addr));
						} else {
							/* TODO IPv6 */
						}
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tFamily:  %s\n", family == 1 ? "IPv4" : "IPv6");
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tPort:    %"SCNu16"\n", port);
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tAddress: %s\n", ip);
						break;
					}
					case JANUS_STUN_ATTR_XOR_MAPPED_ADDRESS:
					case JANUS_STUN_ATTR_XOR_PEER_ADDRESS:
					case JANUS_STUN_ATTR_XOR_RELAYED_ADDRESS: {
						janus_stun_attr_xor_mapped_address *address = (janus_stun_attr_xor_mapped_address *)attr->value;
						int family = ntohs(address->family);
						uint16_t port = ntohs(htons(ntohs(address->port) ^ 0x2112));
						char ip[64];
						ip[0] = '\0';
						if(family == 1) {
							/* IPv4 */
							uint32_t addr;
							memcpy(&addr, address->address, sizeof(uint32_t));
							addr = htonl(ntohl(addr) ^ JANUS_STUN_MAGIC_COOKIE);
							unsigned char *ipv4 = (unsigned char *)&addr;
							g_snprintf(ip, sizeof(ip), "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
							/* Update the return value */
							struct sockaddr_in *addr4 = (struct sockaddr_in *)mapped_address;
							addr4->sin_family = AF_INET;
							addr4->sin_port = htons(port);
							memcpy(&addr4->sin_addr.s_addr, &addr, sizeof(struct in_addr));
						} else {
							/* TODO IPv6 */
						}
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tFamily:  %s\n", family == 1 ? "IPv4" : "IPv6");
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tPort:    %"SCNu16"\n", port);
						JANUS_LOG(JICE_LOG_INFO, "[jice] \t\tAddress: %s\n", ip);
						break;
					}
					default: {
						/* Skip */
						break;
					}
				}

				/* Go to next attribute, if any */
				int padding = 0;
				if(janus_stun_attr_get_length(attr)%4)
					padding = 4-janus_stun_attr_get_length(attr)%4;
				start += 4+padding+janus_stun_attr_get_length(attr);
				index += 4+padding+janus_stun_attr_get_length(attr);
				total -= 4+padding+janus_stun_attr_get_length(attr);
			}
		}
	} else {
		JANUS_LOG(JICE_LOG_ERR, "[jice] Error receiving response...\n");
		return -1;
	}
	return 0;
}

/* Mostly a helper to quickly perform a STUN request, e.g., for testing purposes or at startup */
int janus_jice_test_stun(char *server, guint16 port, struct sockaddr *mapped_address) {
	if(!server || port < 1 || !mapped_address)
		return -1;
	/* Get a file descriptor */
	int fd = janus_ice_test_stun_fd();
	if(fd < 0)
		return -1;
	/* Resolve the STUN server to get an address we can use */
	struct sockaddr_in remote;
	if(janus_ice_test_stun_resolve(server, port, (struct sockaddr *)&remote) < 0) {
		close(fd);
		return -1;
	}
	/* Send the STUN request */
	if(janus_jice_test_stun_send(fd, (struct sockaddr *)&remote, mapped_address) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* Helper method to detect the NAT type */
int janus_jice_detect_nat_type(char *local_ip, char *serverA, guint16 portA, char *serverB, guint16 portB) {
	if(!serverA || portA < 1 || !serverB || portB < 1)
		return -1;
	/* Get a file descriptor: we'll use the same for both STUN servers */
	int fd = janus_ice_test_stun_fd();
	if(fd < 0)
		return -1;
	/* Resolve STUN servers to get addresses we can use */
	struct sockaddr_in local, remoteA, remoteB;
	if(janus_ice_test_stun_resolve(local_ip, 0, (struct sockaddr *)&local) < 0 ||
			janus_ice_test_stun_resolve(serverA, portA, (struct sockaddr *)&remoteA) < 0 ||
			janus_ice_test_stun_resolve(serverB, portB, (struct sockaddr *)&remoteB) < 0) {
		close(fd);
		return -1;
	}
	/* Send the STUN request */
	struct sockaddr_in mappedA, mappedB;
	if(janus_jice_test_stun_send(fd, (struct sockaddr *)&remoteA, (struct sockaddr *)&mappedA) < 0 ||
			janus_jice_test_stun_send(fd, (struct sockaddr *)&remoteB, (struct sockaddr *)&mappedB) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	/* Compare the mapped addresses, to detect the NAT type */
	if(mappedA.sin_addr.s_addr != mappedB.sin_addr.s_addr) {
		JANUS_LOG(LOG_WARN, "[jice] Different addresses?! That shouldn't happen...\n");
		return 0;
	}
	if(mappedA.sin_addr.s_addr == local.sin_addr.s_addr) {
		JANUS_LOG(LOG_INFO, "[jice] No NAT detected\n");
		return 0;
	}
	if(mappedA.sin_port == mappedB.sin_port) {
		JANUS_LOG(LOG_INFO, "[jice] Detected NAT: Regular NAT (same results)\n");
	} else {
		JANUS_LOG(LOG_INFO, "[jice] Detected NAT: Symmetric NAT (different mapped port)\n");
	}
	return 0;
}
