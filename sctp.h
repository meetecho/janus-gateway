/*! \file    sctp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SCTP processing for data channels (headers)
 * \details  Implementation (based on libusrsctp) of the SCTP Data Channels.
 * The code takes care of the SCTP association between peers and the server,
 * and allows for sending and receiving text messages (binary stuff yet to
 * be implemented) after that.
 *
 * \note Right now, the code is heavily based on the rtcweb.c sample code
 * provided in the \c usrsctp library code, and as such the copyright notice
 * that appears at the beginning of that code is ideally present here as
 * well: http://code.google.com/p/sctp-refimpl/source/browse/trunk/KERN/usrsctp/programs/rtcweb.c
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef _JANUS_SCTP_H
#define _JANUS_SCTP_H

#ifdef HAVE_SCTP

#define INET 1
#define INET6 1

/* Uncomment the line below to enable SCTP debugging to files */
//~ #define DEBUG_SCTP

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <usrsctp.h>
#include <glib.h>

#include "mutex.h"
#include "refcount.h"


/*! \brief SCTP stuff initialization
 * \returns 0 on success, a negative integer otherwise */
int janus_sctp_init(void);

/*! \brief SCTP stuff de-initialization */
void janus_sctp_deinit(void);


#define BUFFER_SIZE (1<<16)
#define NUMBER_OF_CHANNELS (150)
#define NUMBER_OF_STREAMS (300)

#define DATA_CHANNEL_PPID_CONTROL           50
#define DATA_CHANNEL_PPID_DOMSTRING         51
#define DATA_CHANNEL_PPID_BINARY_PARTIAL    52
#define DATA_CHANNEL_PPID_BINARY            53
#define DATA_CHANNEL_PPID_DOMSTRING_PARTIAL 54

#define DATA_CHANNEL_CLOSED     0
#define DATA_CHANNEL_CONNECTING 1
#define DATA_CHANNEL_OPEN       2
#define DATA_CHANNEL_CLOSING    3

#define DATA_CHANNEL_FLAGS_SEND_REQ 0x00000001
#define DATA_CHANNEL_FLAGS_SEND_RSP 0x00000002
#define DATA_CHANNEL_FLAGS_SEND_ACK 0x00000004

struct janus_dtls_srtp;
struct janus_ice_handle;

typedef struct janus_sctp_channel {
	/*! \brief SCTP channel ID */
	uint32_t id;
	/*! \brief SCTP channel label */
	char label[64];
	/*! \brief Value of the PR-SCTP policy (http://tools.ietf.org/html/rfc6458) */
	uint32_t pr_value;
	/*! \brief PR-SCTP policy to use (http://tools.ietf.org/html/rfc6458) */
	uint16_t pr_policy;
	/*! \brief Stream ID (both inbound and outbound) */
	uint16_t stream;
	/*! \brief Whether this channel is unordered or not */
	uint8_t unordered;
	/*! \brief State of the channel */
	uint8_t state;
	/*! \brief Flags for this channel */
	uint32_t flags;
} janus_sctp_channel;

typedef struct janus_sctp_association {
	/*! \brief Pointer to the DTLS instance related to this SCTP association */
	struct janus_dtls_srtp *dtls;
	/*! \brief Pointer to the ICE handle related to this SCTP association */
	struct janus_ice_handle *handle;
	/*! \brief Identifier of the handle owning this SCTP association (for debugging purposes only) */
	uint64_t handle_id;
	/*! \brief Array of SCTP channels */
	struct janus_sctp_channel channels[NUMBER_OF_CHANNELS];
	/*! \brief Array of streams (both inbound and outbound) */
	struct janus_sctp_channel *stream_channel[NUMBER_OF_STREAMS];
	/*! \brief Array of stream buffers */
	uint16_t stream_buffer[NUMBER_OF_STREAMS];
	/*! \brief Number of stream buffers */
	uint32_t stream_buffer_counter;
	/*! \brief UDP-encapsulation socket related to this association */
	struct socket *sock;
	/*! \brief Local port to be used for SCTP */
	uint16_t local_port;
	/*! \brief Remote port to be used for SCTP */
	uint16_t remote_port;
	/*! \brief Buffer for handling partial messages */
	char *buffer;
	/*! \brief Current size of the buffer for handling partial messages */
	size_t buflen;
	/*! \brief Current offset of the buffer for handling partial messages */
	size_t offset;
#ifdef DEBUG_SCTP
	FILE *debug_dump;
#endif
	/*! \brief Mutex to lock/unlock this instance */
	janus_mutex mutex;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_sctp_association;


#define DATA_CHANNEL_OPEN_REQUEST  3	/* FIXME was 0, but should be 3 as per http://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-05 */
#define DATA_CHANNEL_OPEN_RESPONSE 1
#define DATA_CHANNEL_ACK           2

#define DATA_CHANNEL_RELIABLE							0x00
#define DATA_CHANNEL_RELIABLE_UNORDERED					0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT			0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED	0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED				0x02
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED	0x82

/* http://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-05 */
typedef struct janus_datachannel_open_request {
	/*! \brief Message type (DATA_CHANNEL_OPEN_REQUEST) */
	uint8_t msg_type;
	/*! \brief Channel type */
	uint8_t channel_type;
	/*! \brief Priority */
	uint16_t priority;
	/*! \brief Reliability parameters */
	uint32_t reliability_params;
	/*! \brief Label length */
	uint16_t label_length;
	/*! \brief Protocol length */
	uint16_t protocol_length;
	/*! \brief Optional label */
	char label[0];
	/* We ignore the Protocol field */
} janus_datachannel_open_request;

typedef struct janus_datachannel_open_response {
	/*! \brief Message type (DATA_CHANNEL_OPEN_RESPONSE) */
	uint8_t msg_type;
	/*! \brief Whether there's an error or not */
	uint8_t error;
	/*! \brief Response flags */
	uint16_t flags;
	/*! \brief Reverse stream ID */
	uint16_t reverse_stream;
} janus_datachannel_open_response;

typedef struct janus_datachannel_ack {
	/*! \brief Message type (DATA_CHANNEL_ACK) */
	uint8_t msg_type;
} janus_datachannel_ack;



/*! \brief Create and setup a new SCTP association
 * \param[in] dtls Pointer to the DTLS instance that will encapsulate SCTP messages
 * \param[in] handle Pointer to the ICE handle that will send out SCTP messages.
 * \param[in] udp_port The port as negotiated in the sctpmap attribute (http://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-06)
 * \returns A janus_sctp_association instance if successful, NULL otherwise */
janus_sctp_association *janus_sctp_association_create(struct janus_dtls_srtp *dtls, struct janus_ice_handle *handle, uint16_t udp_port);

/*! \brief Destroy an existing SCTP association
 * \param[in] sctp The SCTP association to get rid of */
void janus_sctp_association_destroy(janus_sctp_association *sctp);

/*! \brief Callback to notify the SCTP stack when data has been decapsulated from DTLS
 * \param[in] sctp The SCTP association this data is for
 * \param[in] buf The data buffer
 * \param[in] len The buffer length */
void janus_sctp_data_from_dtls(janus_sctp_association *sctp, char *buf, int len);

/*! \brief Method to send data via SCTP to the peer
 * \param[in] sctp The SCTP association this data is from
 * @param[in] label The label of the data channel to use
 * \param[in] buf The data buffer
 * \param[in] len The buffer length */
void janus_sctp_send_data(janus_sctp_association *sctp, char *label, char *buf, int len);

#endif

#endif
