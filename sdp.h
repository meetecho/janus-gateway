/*! \file    sdp.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP processing (headers)
 * \details  Implementation of an SDP
 * parser/merger/generator in the gateway. Each SDP coming from peers is
 * stripped/anonymized before it is passed to the plugins: all
 * DTLS/ICE/transport related information is removed, only leaving the
 * relevant information in place. SDP coming from plugins is stripped/anonymized
 * as well, and merged with the proper DTLS/ICE/transport information before
 * it is sent to the peers. The actual SDP processing (parsing SDP strings,
 * representation of SDP as an internal format, and so on) is done via
 * the tools provided in sdp-utils.h.
 * 
 * \todo Right now, we only support sessions with up to a single audio
 * and/or a single video stream (as in, a single audio and/or video
 * m-line) plus an optional DataChannel. Later versions of the gateway
 * will add support for more media streams of the same type in a session.
 * 
 * \ingroup protocols
 * \ref protocols
 */
 
#ifndef _JANUS_SDP_H
#define _JANUS_SDP_H


#include <inttypes.h>

#include "sdp-utils.h"

/** @name Janus SDP setup
 */
///@{
/*! \brief Janus SDP processor initialization
 * @returns 0 in case of success, -1 in case of an error */
int janus_sdp_init(void);
/*! \brief Janus SDP processor deinitialization */
void janus_sdp_deinit(void);
///@}


/** @name Janus SDP helper methods
 */
///@{
/*! \brief Method to pre-parse a session description
 * \details This method is only used to quickly check how many audio and video lines are in an SDP, and to generate a Janus SDP instance
 * @param[in] jsep_sdp The SDP that the browser peer originated
 * @param[out] audio The number of audio m-lines
 * @param[out] video The number of video m-lines
 * @param[out] data The number of SCTP m-lines
 * @param[out] bundle Whether BUNDLE has been negotiated or not
 * @param[out] rtcpmux Whether rtcp-mux has been negotiated or not
 * @param[out] trickle Whether ICE trickling is being used (no candidates) or not
 * @returns The Janus SDP object in case of success, NULL in case the SDP is invalid */
janus_sdp *janus_sdp_preparse(const char *jsep_sdp, int *audio, int *video, int *data, int *bundle, int *rtcpmux, int *trickle);

/*! \brief Method to parse a session description
 * \details This method will parse a session description coming from a peer, and set up the ICE candidates accordingly
 * @param[in] handle Opaque pointer to the ICE handle this session description will modify
 * @param[in] sdp The Janus SDP object to parse
 * @returns 0 in case of success, -1 in case of an error */
int janus_sdp_parse(void *handle, janus_sdp *sdp);

/*! \brief Method to parse a single candidate
 * \details This method will parse a single remote candidate provided by a peer, whether it is trickling or not
 * @param[in] stream Opaque pointer to the ICE stream this candidate refers to
 * @param[in] candidate The remote candidate to process
 * @param[in] trickle Whether this is a trickle candidate, or coming from the SDP
 * @returns 0 in case of success, a non-zero integer in case of an error */
int janus_sdp_parse_candidate(void *stream, const char *candidate, int trickle);

/*! \brief Method to parse a SSRC attribute
 * \details This method will parse a SSRC attribute, and set it for the peer
 * @param[in] stream Opaque pointer to the ICE stream this candidate refers to
 * @param[in] ssrc_attr The SSRC attribute value to parse
 * @param[in] video Whether this is a video SSRC or not
 * @returns 0 in case of success, a non-zero integer in case of an error */
int janus_sdp_parse_ssrc(void *stream, const char *ssrc_attr, int video);

/*! \brief Method to strip/anonymize a session description
 * @param[in] sdp The session description to strip/anonymize
 * @returns A string containing the stripped/anonymized session description in case of success, NULL if the SDP is invalid */
char *janus_sdp_anonymize(const char *sdp);

/*! \brief Method to merge a stripped session description and the right transport information
 * @param[in] handle Opaque pointer to the ICE handle this session description is related to
 * @param[in] sdp The stripped session description to merge
 * @returns A string containing the full session description in case of success, NULL if the SDP is invalid */
char *janus_sdp_merge(void *handle, const char *sdp);
///@}

#endif
