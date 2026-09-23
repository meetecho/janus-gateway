/*! \file    rtpws.h
 * \author   Mirko Brankovic <mirkobrankovic@gmail.com>
 * \copyright GNU General Public License v3
 * \brief    RTP over WebSocket support (headers)
 * \details  Integration of RTP over WebSocket functionality in the
 * Janus core, as a feature that plugins can leverage. Plugins register
 * peers (opaque bindings) that clients connect to via WS/WSS; binary
 * frames carry full RTP packets in both directions, or raw codec payloads
 * when the peer is created in payload-only framing mode.
 *
 * Notice the functionality documented here is only available if Janus was
 * built with libwebsockets support (--enable-websockets).
 *
 * \ingroup protocols
 * \ref protocols
 */

#ifndef JANUS_RTPWS_H
#define JANUS_RTPWS_H

#include <glib.h>
#include <stdint.h>

#include "refcount.h"


/*! \brief RTP-over-WebSocket code initialization
 * @param[in] enabled Whether RTP-over-WS support should be enabled
 * @param[in] port Local port to bind the media listener to
 * @param[in] path URL path fragment advertised to clients (e.g. /rtp-ws)
 * @param[in] public_url Optional public base URL (wss://host); when empty, a local URL is built
 * @param[in] secure Whether to use TLS (WSS) on the media listener
 * @param[in] cert_pem Certificate PEM path for WSS
 * @param[in] cert_key Certificate key PEM path for WSS
 * @param[in] cert_pwd Optional password for the certificate key
 * @param[in] server_name Gateway server-name advertised to clients in the call_info handshake
 * @param[in] allow_ws_bind Whether to accept browser-first connect-then-bind (see rtpws::allow_ws_bind)
 * @returns 0 in case of success, a negative integer on errors */
int janus_rtp_ws_init(gboolean enabled, uint16_t port, const char *path, const char *public_url,
	gboolean secure, const char *cert_pem, const char *cert_key, const char *cert_pwd,
	const char *server_name, gboolean allow_ws_bind);
/*! \brief RTP-over-WebSocket code de-initialization */
void janus_rtp_ws_deinit(void);
/*! \brief Whether RTP-over-WS was enabled in the configuration */
gboolean janus_rtp_ws_is_enabled(void);
/*! \brief Whether RTP-over-WS support was compiled in */
gboolean janus_rtp_ws_is_available(void);
/*! \brief Error to show when RTP-over-WS was requested but not compiled in */
const char *janus_rtp_ws_compile_error(void);

struct janus_rtp_ws_peer;

/*! \brief Callback invoked when an RTP packet is received on a peer connection
 * @note This is invoked from a dedicated delivery thread, not the libwebsockets thread */
typedef void (*janus_rtp_ws_incoming_rtp_cb)(struct janus_rtp_ws_peer *peer, char *buffer, int len);
/*! \brief Callback invoked when the WebSocket client disconnects */
typedef void (*janus_rtp_ws_client_gone_cb)(struct janus_rtp_ws_peer *peer);

/*! \brief Helper struct for a plugin-bound RTP-over-WS peer */
typedef struct janus_rtp_ws_peer {
	/*! \brief Opaque pointer for the plugin owner */
	void *user_data;
	/*! \brief Unique session token used in the media URL */
	char *session_id;
	/*! \brief Codec name sent in the call_info JSON handshake */
	const char *codec_name;
	int sample_rate;
	int channels;
	int ptime_ms;
	int payload_type;
	/*! \brief Framing on the wire: FALSE = full RTP packets (default), TRUE = raw
	 * codec payloads (no RTP header). Payload mode is meant for external AI/STT/TTS
	 * clients that don't want to parse or emit RTP; the core strips the header on
	 * the way out and synthesizes one on the way in. */
	gboolean payload_only;
	/*! \brief RTP header state synthesized for inbound raw payloads (payload mode only) */
	guint32 synth_ssrc;
	guint16 synth_seq;
	guint32 synth_ts;
	gboolean synth_started;
	janus_rtp_ws_incoming_rtp_cb incoming_rtp;
	janus_rtp_ws_client_gone_cb client_gone;
	/*! \brief Core-private connection state, opaque so plugins don't need the
	 * libwebsockets headers. Valid for as long as you hold a peer reference. */
	void *extra;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_rtp_ws_peer;

/*! \brief Create a new RTP-over-WS peer binding
 * @param[in] user_data Opaque owner pointer passed to callbacks
 * @param[in] incoming_rtp Callback for received RTP packets
 * @param[in] client_gone Optional callback when the WS client disconnects
 * @param[in] codec_name Codec name for the call_info handshake
 * @param[in] sample_rate Sampling rate in Hz
 * @param[in] channels Number of channels
 * @param[in] ptime_ms Packet time in ms
 * @param[in] payload_type RTP payload type
 * @param[in] payload_only If TRUE, exchange raw codec payloads instead of full RTP packets
 * @returns A valid peer instance, or NULL on errors */
janus_rtp_ws_peer *janus_rtp_ws_peer_create(void *user_data,
	janus_rtp_ws_incoming_rtp_cb incoming_rtp, janus_rtp_ws_client_gone_cb client_gone,
	const char *codec_name, int sample_rate, int channels, int ptime_ms, int payload_type,
	gboolean payload_only);
/*! \brief Build the WS/WSS URL clients should connect to for this peer */
char *janus_rtp_ws_peer_build_url(janus_rtp_ws_peer *peer);
/*! \brief Queue an RTP packet for delivery to the peer over WebSocket */
int janus_rtp_ws_peer_send_rtp(janus_rtp_ws_peer *peer, const char *rtp, int len);
/*! \brief Destroy a peer binding and detach it from the media listener */
void janus_rtp_ws_peer_destroy(janus_rtp_ws_peer *peer);

#endif
