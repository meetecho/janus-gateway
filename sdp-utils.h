/*! \file    sdp-utils.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP utilities (headers)
 * \details  Implementation of an internal SDP representation. Allows
 * to parse SDP strings to an internal janus_sdp object, the manipulation
 * of such object by playing with its properties, and a serialization
 * to an SDP string that can be passed around. Since they don't have any
 * core dependencies, these utilities can be used by plugins as well.
 *
 * \ingroup core
 * \ref core
 */

#ifndef _JANUS_SDP_UTILS_H
#define _JANUS_SDP_UTILS_H


#include <inttypes.h>
#include <glib.h>

#include "refcount.h"

/*! \brief Janus SDP internal object representation */
typedef struct janus_sdp {
	/*! \brief v= */
	int version;
	/*! \brief o= name */
	char *o_name;
	/*! \brief o= session ID */
	guint64 o_sessid;
	/*! \brief o= version */
	guint64 o_version;
	/*! \brief o= protocol */
	gboolean o_ipv4;
	/*! \brief o= address */
	char *o_addr;
	/*! \brief s= */
	char *s_name;
	/*! \brief t= start */
	guint64 t_start;
	/*! \brief t= stop */
	guint64 t_stop;
	/*! \brief c= protocol (not rendered for WebRTC usage) */
	gboolean c_ipv4;
	/*! \brief c= address (not rendered for WebRTC usage) */
	char *c_addr;
	/*! \brief List of global a= attributes */
	GList *attributes;
	/*! \brief List of m= m-lines */
	GList *m_lines;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_sdp;

/*! \brief Helper enumeration to quickly identify m-line media types */
typedef enum janus_sdp_mtype {
	/*! \brief m=audio */
	JANUS_SDP_AUDIO,
	/*! \brief m=video */
	JANUS_SDP_VIDEO,
	/*! \brief m=application */
	JANUS_SDP_APPLICATION,
	/*! \brief m=whatever (we don't care, unsupported) */
	JANUS_SDP_OTHER
} janus_sdp_mtype;
/*! \brief Helper method to get a janus_sdp_mtype from a string
 * @param[in] type The type to parse as a string (e.g., "audio")
 * @returns The corresponding janus_sdp_mtype value */
janus_sdp_mtype janus_sdp_parse_mtype(const char *type);
/*! \brief Helper method to get the string associated to a janus_sdp_mtype value
 * @param[in] type The type to stringify
 * @returns The type as a string, if valid, or NULL otherwise */
const char *janus_sdp_mtype_str(janus_sdp_mtype type);

/*! \brief Helper enumeration to quickly identify m-line directions */
typedef enum janus_sdp_mdirection {
	/*! \brief default=sendrecv */
	JANUS_SDP_DEFAULT,
	/*! \brief sendrecv */
	JANUS_SDP_SENDRECV,
	/*! \brief sendonly */
	JANUS_SDP_SENDONLY,
	/*! \brief recvonly */
	JANUS_SDP_RECVONLY,
	/*! \brief inactive */
	JANUS_SDP_INACTIVE,
	/*! \brief invalid direction (when parsing) */
	JANUS_SDP_INVALID
} janus_sdp_mdirection;
/*! \brief Helper method to get a janus_sdp_mdirection from a string
 * @param[in] direction The direction to parse as a string (e.g., "sendrecv")
 * @returns The corresponding janus_sdp_mdirection value */
janus_sdp_mdirection janus_sdp_parse_mdirection(const char *direction);
/*! \brief Helper method to get the string associated to a janus_sdp_mdirection value
 * @param[in] direction The direction to stringify
 * @returns The direction as a string, if valid, or NULL otherwise */
const char *janus_sdp_mdirection_str(janus_sdp_mdirection direction);

/*! \brief Helper method to return the preferred audio and video codecs in an SDP offer or answer,
 * (where by preferred we mean the codecs we prefer ourselves, and not the m-line SDP order)
 * as long as the m-line direction is not disabled (port=0 or direction=inactive) in the SDP
 * \note The acodec and vcodec arguments are input/output, and they'll be set to a static value
 * in janus_preferred_audio_codecs and janus_preferred_video_codecs, so don't free them.
 * @param[in] sdp The Janus SDP object to parse
 * @param[out] acodec The audio codec that was found
 * @param[out] vcodec The video codec that was found */
void janus_sdp_find_preferred_codecs(janus_sdp *sdp, const char **acodec, const char **vcodec);
/*! \brief Helper method to return the first audio and video codecs in an SDP offer or answer,
 * (no matter whether we personally prefer them ourselves or not)
 * as long as the m-line direction is not disabled (port=0 or direction=inactive) in the SDP
 * \note The acodec and vcodec arguments are input/output, and they'll be set to a static value
 * in janus_preferred_audio_codecs and janus_preferred_video_codecs, so don't free them.
 * @param[in] sdp The Janus SDP object to parse
 * @param[out] acodec The audio codec that was found
 * @param[out] vcodec The video codec that was found */
void janus_sdp_find_first_codecs(janus_sdp *sdp, const char **acodec, const char **vcodec);
/*! \brief Helper method to match a codec to one of the preferred codecs
 * \note Don't free the returned value, as it's a constant value
 * @param[in] type The type of media to match
 * @param[in] codec The codec to match
 * @returns The codec, if found, or NULL otherwise */
const char *janus_sdp_match_preferred_codec(janus_sdp_mtype type, char *codec);

/*! \brief SDP m-line representation */
typedef struct janus_sdp_mline {
	/*! \brief Media type as a janus_sdp_mtype enumerator */
	janus_sdp_mtype type;
	/*! \brief Media type (string) */
	char *type_str;
	/*! \brief Media port */
	guint16 port;
	/*! \brief Media protocol */
	char *proto;
	/*! \brief List of formats */
	GList *fmts;
	/*! \brief List of payload types */
	GList *ptypes;
	/*! \brief Media c= protocol */
	gboolean c_ipv4;
	/*! \brief Media c= address */
	char *c_addr;
	/*! \brief Media b= type */
	char *b_name;
	/*! \brief Media b= value */
	uint32_t b_value;
	/*! \brief Media direction */
	janus_sdp_mdirection direction;
	/*! \brief List of m-line attributes */
	GList *attributes;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_sdp_mline;
/*! \brief Helper method to quickly create a janus_sdp_mline instance
 * @note The \c type_str property of the new m-line is created automatically
 * depending on the provided \c type attribute. If \c type is JANUS_SDP_OTHER,
 * though, \c type_str will NOT we allocated, and will be up to the caller.
 * @param[in] type Type of the media (audio/video/application) as a janus_sdp_mtype
 * @param[in] port Port to advertise
 * @param[in] proto Profile to advertise
 * @param[in] direction Direction of the media as a janus_sdp_direction
 * @returns A pointer to a valid janus_sdp_mline instance, if successfull, NULL otherwise */
janus_sdp_mline *janus_sdp_mline_create(janus_sdp_mtype type, guint16 port, const char *proto, janus_sdp_mdirection direction);
/*! \brief Helper method to free a janus_sdp_mline instance
 * @note This method does not remove the m-line from the janus_sdp instance, that's up to the caller
 * @param[in] mline The janus_sdp_mline instance to free */
void janus_sdp_mline_destroy(janus_sdp_mline *mline);
/*! \brief Helper method to get the janus_sdp_mline associated to a media type
 * @note This currently returns the first m-line of the specified type it finds: in
 * general, it shouldn't be an issue as we currently only support a single stream
 * of the same type per session anyway... this will need to be fixed in the future.
 * @param[in] sdp The Janus SDP object to search
 * @param[in] type The type of media to search
 * @returns The janus_sdp_mline instance, if found, or NULL otherwise */
janus_sdp_mline *janus_sdp_mline_find(janus_sdp *sdp, janus_sdp_mtype type);
/*! \brief Helper method to remove the janus_sdp_mline associated to a media type from the SDP
 * @note This currently removes the first m-line of the specified type it finds: in
 * general, it shouldn't be an issue as we currently only support a single stream
 * of the same type per session anyway... this will need to be fixed in the future.
 * @param[in] sdp The Janus SDP object to modify
 * @param[in] type The type of media to remove
 * @returns 0 if successful, a negative integer otherwise */
int janus_sdp_mline_remove(janus_sdp *sdp, janus_sdp_mtype type);

/*! \brief SDP a= attribute representation */
typedef struct janus_sdp_attribute {
	/*! \brief Attribute name */
	char *name;
	/*! \brief Attribute value */
	char *value;
	/*! \brief Attribute direction (e.g., for extmap) */
	janus_sdp_mdirection direction;
	/*! \brief Atomic flag to check if this instance has been destroyed */
	volatile gint destroyed;
	/*! \brief Reference counter for this instance */
	janus_refcount ref;
} janus_sdp_attribute;
/*! \brief Helper method to quickly create a janus_sdp_attribute instance
 * @param[in] name Name of the attribute
 * @param[in] value Value of the attribute, as a printf compliant string (variable arguments)
 * @returns A pointer to a valid janus_sdp_attribute instance, if successfull, NULL otherwise */
janus_sdp_attribute *janus_sdp_attribute_create(const char *name, const char *value, ...) G_GNUC_PRINTF(2, 3);
/*! \brief Helper method to free a janus_sdp_attribute instance
 * @note This method does not remove the attribute from the global or m-line attributes, that's up to the caller
 * @param[in] attr The janus_sdp_attribute instance to free */
void janus_sdp_attribute_destroy(janus_sdp_attribute *attr);
/*! \brief Helper method to add an attribute to a media line
 * @param[in] mline The m-line to add the attribute to
 * @param[in] attr The attribute to add
 * @returns 0 in case of success, -1 otherwise */
int janus_sdp_attribute_add_to_mline(janus_sdp_mline *mline, janus_sdp_attribute *attr);

/*! \brief Method to parse an SDP string to a janus_sdp object
 * @param[in] sdp The SDP string to parse
 * @param[in,out] error Buffer to receive a reason for an error, if any
 * @param[in] errlen The length of the error buffer
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise; in case
 * of errors, if provided the error string is filled with a reason  */
janus_sdp *janus_sdp_parse(const char *sdp, char *error, size_t errlen);

/*! \brief Helper method to quickly remove all traces (m-line, rtpmap, fmtp, etc.) of a payload type
 * @param[in] sdp The janus_sdp object to remove the payload type from
 * @param[in] pt The payload type to remove
 * @returns 0 in case of success, a negative integer otherwise */
int janus_sdp_remove_payload_type(janus_sdp *sdp, int pt);

/*! \brief Method to serialize a janus_sdp object to an SDP string
 * @param[in] sdp The janus_sdp object to serialize
 * @returns A pointer to a string with the serialized SDP, if successful, NULL otherwise */
char *janus_sdp_write(janus_sdp *sdp);

/*! \brief Method to quickly generate a janus_sdp instance from a few selected fields
 * @note This allocates the \c o_addr, \c s_name and \c c_addr properties: if you
 * want to replace them, don't forget to \c g_free the original pointers first.
 * @param[in] name The session name (if NULL, a default value will be set)
 * @param[in] address The IP to set in o= and c= fields (if NULL, a default value will be set)
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise */
janus_sdp *janus_sdp_new(const char *name, const char *address);

/*! \brief Method to destroy a Janus SDP object
 * @param[in] sdp The Janus SDP object to free */
void janus_sdp_destroy(janus_sdp *sdp);

typedef enum janus_sdp_oa_type {
/*! \brief When generating an offer or answer automatically, accept/reject audio if offered (depends on value that follows) */
JANUS_SDP_OA_AUDIO = 1,
/*! \brief When generating an offer or answer automatically, accept/reject video if offered (depends on value that follows) */
JANUS_SDP_OA_VIDEO,
/*! \brief When generating an offer or answer automatically, accept/reject datachannels if offered (depends on value that follows) */
JANUS_SDP_OA_DATA,
/*! \brief When generating an offer or answer automatically, use this direction for audio (depends on value that follows) */
JANUS_SDP_OA_AUDIO_DIRECTION,
/*! \brief When generating an offer or answer automatically, use this direction for video (depends on value that follows) */
JANUS_SDP_OA_VIDEO_DIRECTION,
/*! \brief When generating an offer or answer automatically, use this codec for audio (depends on value that follows) */
JANUS_SDP_OA_AUDIO_CODEC,
/*! \brief When generating an offer or answer automatically, use this codec for video (depends on value that follows) */
JANUS_SDP_OA_VIDEO_CODEC,
/*! \brief When generating an offer (this is ignored for answers), use this payload type for audio (depends on value that follows) */
JANUS_SDP_OA_AUDIO_PT,
/*! \brief When generating an offer (this is ignored for answers), use this payload type for video (depends on value that follows) */
JANUS_SDP_OA_VIDEO_PT,
/*! \brief When generating an offer or answer automatically, do or do not negotiate telephone events (FIXME telephone-event/8000 only) */
JANUS_SDP_OA_AUDIO_DTMF,
/*! \brief When generating an offer or answer automatically, add this custom fmtp string for audio */
JANUS_SDP_OA_AUDIO_FMTP,
/*! \brief When generating an offer or answer automatically, do or do not add the rtcpfb attributes we typically negotiate (fir, nack, pli, remb) */
JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS,
/*! \brief When generating an offer or answer automatically, do or do not add the default fmtp attribute for H.264 (profile-level-id=42e01f;packetization-mode=1) */
JANUS_SDP_OA_VIDEO_H264_FMTP,
/*! \brief When generating an offer (this is ignored for answers), use the old "DTLS/SCTP" instead of the new "UDP/DTLS/SCTP (default=TRUE for now, depends on what follows) */
JANUS_SDP_OA_DATA_LEGACY,
/*! \brief When generating an answer (this is ignored for offers), accept this extension (by default, we reject them all; can be used multiple times) */
JANUS_SDP_OA_ACCEPT_EXTMAP,
/*! \brief MUST be used as the last argument in janus_sdp_generate_offer and janus_sdp_generate_answer */
JANUS_SDP_OA_DONE = 0
} janus_sdp_oa_type;

/*! \brief Method to generate a janus_sdp offer, using variable arguments to dictate
 * what to negotiate (e.g., in terms of media to offer, directions, etc.). Variable
 * arguments are in the form of a sequence of name-value terminated by a JANUS_SDP_OA_DONE, e.g.:
 \verbatim
	janus_sdp *offer = janus_sdp_generate_offer("My session", "127.0.0.1",
		JANUS_SDP_OA_AUDIO, TRUE,
		JANUS_SDP_OA_AUDIO_PT, 100,
		JANUS_SDP_OA_AUDIO_DIRECTION, JANUS_SDP_SENDONLY,
		JANUS_SDP_OA_AUDIO_CODEC, "opus",
		JANUS_SDP_OA_VIDEO, FALSE,
		JANUS_SDP_OA_DATA, FALSE,
		JANUS_SDP_OA_DONE);
 \endverbatim
 * to only offer a \c sendonly Opus audio stream being offered with 100 as
 * payload type, and avoid video and datachannels. Refer to the property names in
 * the header file for a complete list of how you can drive the offer.
 * The default, if not specified, is to offer everything, using Opus with pt=111
 * for audio, VP8 with pt=96 as video, and data channels, all as \c sendrecv.
 * @param[in] name The session name (if NULL, a default value will be set)
 * @param[in] address The IP to set in o= and c= fields (if NULL, a default value will be set)
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise */
janus_sdp *janus_sdp_generate_offer(const char *name, const char *address, ...);
/*! \brief Method to generate a janus_sdp answer to a provided janus_sdp offer, using variable arguments
 * to dictate how to respond (e.g., in terms of media to accept, reject, directions, etc.). Variable
 * arguments are in the form of a sequence of name-value terminated by a JANUS_SDP_OA_DONE, e.g.:
 \verbatim
	janus_sdp *answer = janus_sdp_generate_answer(offer,
		JANUS_SDP_OA_AUDIO, TRUE,
		JANUS_SDP_OA_AUDIO_DIRECTION, JANUS_SDP_RECVONLY,
		JANUS_SDP_OA_AUDIO_CODEC, "opus",
		JANUS_SDP_OA_VIDEO, FALSE,
		JANUS_SDP_OA_DATA, FALSE,
		JANUS_SDP_OA_DONE);
 \endverbatim
 * to only accept the audio stream being offered, but as \c recvonly, use Opus
 * and reject both video and datachannels. Refer to the property names in
 * the header file for a complete list of how you can drive the answer.
 * The default, if not specified, is to accept everything as \c sendrecv.
 * @param[in] offer The Janus SDP offer to respond to
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise */
janus_sdp *janus_sdp_generate_answer(janus_sdp *offer, ...);

/*! \brief Helper to get the payload type associated to a specific codec
 * @param sdp The Janus SDP instance to process
 * @param codec The codec to find, as a string
 * @returns The payload type, if found, or -1 otherwise */
int janus_sdp_get_codec_pt(janus_sdp *sdp, const char *codec);

/*! \brief Helper to get the codec name associated to a specific payload type
 * @param sdp The Janus SDP instance to process
 * @param pt The payload type to find
 * @returns The codec name, if found, or NULL otherwise */
const char *janus_sdp_get_codec_name(janus_sdp *sdp, int pt);

/*! \brief Helper to get the rtpmap associated to a specific codec
 * @param codec The codec name, as a string (e.g., "opus")
 * @returns The rtpmap value, if found (e.g., "opus/48000/2"), or -1 otherwise */
const char *janus_sdp_get_codec_rtpmap(const char *codec);

#endif
