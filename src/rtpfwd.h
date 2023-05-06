/*! \file    rtpfwd.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    RTP forwarders (headers)
 * \details  Implementation of the so called RTP forwarders, that is an
 * helper mechanism that core and/or plugins can make use of to quickly
 * and simply forward RTP streams to a separate UDP address out of the
 * context of any signalling. Such a mechanism can be used, for instance,
 * for scalabiloty purposes, monitoring, or feeding external applications
 * with media traffic handled by Janus..
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_RTPFWD_H
#define JANUS_RTPFWD_H

#include "rtp.h"
#include "rtpsrtp.h"


/* \brief RTP forwarders code initialization
 * @returns 0 in case of success, a negative integer on errors */
int janus_rtp_forwarders_init(void);
/* \brief RTP forwarders code de-initialization */
void janus_rtp_forwarders_deinit(void);

/*! \brief Helper struct for implementing RTP forwarders */
typedef struct janus_rtp_forwarder {
	/* \brief Opaque pointer to the owner of this forwarder */
	void *source;
	/* \brief Context of the forwarder */
	char *context;
	/* \brief Unique ID (within the context) of the forwarder */
	uint32_t stream_id;
	/* \brief Socket used for sending RTP packets */
	int udp_fd;
	/* \brief Whether this is a video forwarder */
	gboolean is_video;
	/* \brief Whether this is an audio forwarder */
	gboolean is_data;
	/* \brief SSRC to put in forwarded RTP packets */
	uint32_t ssrc;
	/* \brief Payload type to put in forwarded RTP packets */
	int payload_type;
	/* \brief Substream to forward, in case this is part of a simulcast stream */
	int substream;
	/* \brief Recipient address (IPv4) */
	struct sockaddr_in serv_addr;
	/* \brief Recipient address (IPv6) */
	struct sockaddr_in6 serv_addr6;
	/* \brief RTCP socket, if needed */
	int rtcp_fd;
	/* \brief RTCP local and remote ports, if needed */
	uint16_t local_rtcp_port, remote_rtcp_port;
	/* \brief Callback to invoke when receiving RTCP messages, if any */
	void (*rtcp_callback)(struct janus_rtp_forwarder *rf, char *buffer, int len);
	/* \brief RTCP GSource, if needed */
	GSource *rtcp_recv;
	/* \brief Whether simulcast automatic selection is enabled for this forwarder */
	gboolean simulcast;
	/* \brief RTP swtiching context, if needed */
	janus_rtp_switching_context rtp_context;
	/* \brief Simulcast context, if needed */
	janus_rtp_simulcasting_context sim_context;
	/* \brief Whether SRTP is enabled for this forwarder */
	gboolean is_srtp;
	/* \brief The SRTP context, in case SRTP is enabled */
	srtp_t srtp_ctx;
	/* \brief The SRTP policy, in case SRTP is enabled */
	srtp_policy_t srtp_policy;
	/* \brief Opaque metadata property, in case it's useful to the owner
	 * \note This can be anything (e.g., a string, an allocated struct, etc.),
	 * as long as it can be freed with a single call to g_free(), as
	 * that's all that will be done when getting rid of the forwarder */
	void *metadata;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_rtp_forwarder;
/*! \brief Helper method to create a new janus_rtp_forwarder instance
 * @param[in] ctx The context of this forwarder (e.g., the plugin name)
 * @param[in] id The unique forwarder ID to assign as part of the context (0=autogenerate)
 * @param[in] udp_fd The socket to use for sending RTP packets
 * @param[in] host The address to forward the RTP packets to
 * @param[in] port The port to forward the RTP packets to
 * @param[in] ssrc The SSRC to put in outgoing RTP packets
 * @param[in] pt The payload type to put in outgoing RTP packets
 * @param[in] srtp_suite In case SRTP must be enabled, the SRTP suite to use
 * @param[in] srtp_crypto In case SRTP must be enabled, the base64-encoded SRTP crypto material to use
 * @param[in] simulcast Whether the RTP forwarder should act as a simulcast viewer
 * 		(meaning it will only forward the highest quality available substream)
 * @param[in] substream In case we want to forward a specific simulcast substream, which substream it is
 * 	\note Do NOT mix the simulcast and substream properties, as they implement different behaviours
 * @param[in] is_video Whether this a video forwarder
 * @param[in] is_data Whether this a data channel forwarder
 * @returns A pointer to a valid janus_rtp_forwarder instance, if successfull, NULL otherwise */
janus_rtp_forwarder *janus_rtp_forwarder_create(const char *ctx,
	uint32_t stream_id, int udp_fd, const char *host, int port,
	uint32_t ssrc, int pt, int srtp_suite, const char *srtp_crypto,
	gboolean simulcast, int substream, gboolean is_video, gboolean is_data);
/*! \brief Helper method to add RTCP support to an existing forwarder
 * @note Notice that only a single RTCP handler can be added to a forwarder,
 * and once added it cannot be removed until the forwarder is destroyed
 * @param[in] rf The janus_rtp_forwarder instance to add RTCP to
 * @param[in] rtcp_port The port to latch to for RTCP purposes
 * @param[in] rtcp_callback The function to invoke when RTCP feedback is received
 * @returns 0 if successful, a negative integer otherwise */
int janus_rtp_forwarder_add_rtcp(janus_rtp_forwarder *rf, int rtcp_port,
	void (*rtcp_callback)(janus_rtp_forwarder *rf, char *buffer, int len));
/*! \brief Helper method to forward an RTP packet within the context of a forwarder
 * @note This is equivalent to calling janus_rtp_forwarder_send_rtp_full
 * with all the extra arguments that are usually not required set to NULL
 * @param[in] rf The janus_rtp_forwarder instance to use
 * @param[in] buffer The RTP packet buffer
 * @param[in] len The length of the RTP packet buffer
 * @param[in] substream In case the forwarder is relaying a single simulcast
 * 		substream, the substream the packet belongs to (pass -1 to ignore) */
void janus_rtp_forwarder_send_rtp(janus_rtp_forwarder *rf, char *buffer, int len, int substream);
/*! \brief Extended version of janus_rtp_forwarder_send_rtp, to be used when the forwarder
 * is configured to act as a simulcast receiver, and so will call janus_rtp_simulcasting_context_process_rtp
 * @param[in] rf The janus_rtp_forwarder instance to use
 * @param[in] buffer The RTP packet buffer
 * @param[in] len The length of the RTP packet buffer
 * @param[in] substream In case the forwarder is relaying a single simulcast
 * 		substream, the substream the packet belongs to (pass -1 to ignore)
 * @param[in] ssrcs The simulcast SSRCs to refer to (may be updated if rids are involved)
 * @param[in] rids The simulcast rids to refer to, if any
 * @param[in] vcodec Video codec of the RTP payload
 * @param[in] rid_mutex A mutex that must be acquired before reading the rids array, if any */
void janus_rtp_forwarder_send_rtp_full(janus_rtp_forwarder *rf, char *buffer, int len, int substream,
	uint32_t *ssrcs, char **rids, janus_videocodec vcodec, janus_mutex *rid_mutex);
/*! \brief Helper method to free a janus_rtp_forwarder instance
 * @param[in] rf The janus_rtp_forwarder instance to free */
void janus_rtp_forwarder_destroy(janus_rtp_forwarder *rf);

#endif
