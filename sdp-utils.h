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

#ifndef JANUS_SDP_UTILS_H
#define JANUS_SDP_UTILS_H


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

/*! \brief Helper method to return the preferred audio or video codec in an SDP offer or answer,
 * (where by preferred we mean the codecs we prefer ourselves, and not the m-line SDP order)
 * as long as the m-line direction is not disabled (port=0 or direction=inactive) in the SDP
 * \note The codec argument is input/output, and it will be set to a static value
 * in janus_preferred_audio_codecs or janus_preferred_video_codecs, so don't free it.
 * @param[in] sdp The Janus SDP object to parse
 * @param[in] type Whether we're looking at an audio or video codec
 * @param[in] index The m-line to refer to (use -1 for the first m-line that matches)
 * @param[out] codec The audio or video codec that was found */
void janus_sdp_find_preferred_codec(janus_sdp *sdp, janus_sdp_mtype type, int index, const char **codec);
/*! \brief Helper method to return the first audio or video codec in an SDP offer or answer,
 * (no matter whether we personally prefer them ourselves or not)
 * as long as the m-line direction is not disabled (port=0 or direction=inactive) in the SDP
 * \note The codec argument is input/output, and it will be set to a static value
 * in janus_preferred_audio_codecs or janus_preferred_video_codecs, so don't free it.
 * @param[in] sdp The Janus SDP object to parse
 * @param[in] type Whether we're looking at an audio or video codec
 * @param[in] index The m-line to refer to (use -1 for the first m-line that matches)
 * @param[out] codec The audio or video codec that was found */
void janus_sdp_find_first_codec(janus_sdp *sdp, janus_sdp_mtype type, int index, const char **codec);
/*! \brief Helper method to match a codec to one of the preferred codecs
 * \note Don't free the returned value, as it's a constant value
 * @param[in] type The type of media to match
 * @param[in] codec The codec to match
 * @returns The codec, if found, or NULL otherwise */
const char *janus_sdp_match_preferred_codec(janus_sdp_mtype type, char *codec);

/*! \brief SDP m-line representation */
typedef struct janus_sdp_mline {
	/*! \brief Media index in the SDP */
	int index;
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
 * @note This currently returns the first m-line of the specified type it finds: as
 * such, it's mostly here for making things easier for plugins not doing multistream.
 * @param[in] sdp The Janus SDP object to search
 * @param[in] type The type of media to search
 * @returns The janus_sdp_mline instance, if found, or NULL otherwise */
janus_sdp_mline *janus_sdp_mline_find(janus_sdp *sdp, janus_sdp_mtype type);
/*! \brief Helper method to get the janus_sdp_mline by its index
 * @param[in] sdp The Janus SDP object to search
 * @param[in] index The index of the m-line in the SDP
 * @returns The janus_sdp_mline instance, if found, or NULL otherwise */
janus_sdp_mline *janus_sdp_mline_find_by_index(janus_sdp *sdp, int index);
/*! \brief Helper method to remove the janus_sdp_mline associated to a media type from the SDP
 * @note This currently removes the first m-line of the specified type it finds: as
 * such, it's mostly here for making things easier for plugins not doing multistream.
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
 * @param[in] index The m-line to remove the payload type from (use -1 for the first m-line that matches)
 * @param[in] pt The payload type to remove
 * @returns 0 in case of success, a negative integer otherwise */
int janus_sdp_remove_payload_type(janus_sdp *sdp, int index, int pt);

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
/*! \brief Add a new m-line of the specific kind (used as a separator for audio, video and data details passed to janus_sdp_generate_offer) */
JANUS_SDP_OA_MLINE = 1,
/*! \brief Whether we should enable a specific m-line when offering/answering (depends on what follows, true by default) */
JANUS_SDP_OA_ENABLED,
/*! \brief When generating an offer or answer automatically, use this direction for media (depends on value that follows, sendrecv by default) */
JANUS_SDP_OA_DIRECTION,
/*! \brief When generating an offer automatically, use this mid media (depends on value that follows, needs to be a string) */
JANUS_SDP_OA_MID,
/*! \brief When generating an offer or answer automatically, use this codec (depends on value that follows, opus/vp8 by default) */
JANUS_SDP_OA_CODEC,
/*! \brief When generating an offer (this is ignored for answers), negotiate this extension: needs two arguments, extmap value and extension ID (can be used multiple times) */
JANUS_SDP_OA_EXTENSION,
/*! \brief When generating an offer (this is ignored for answers), negotiate these extensions: needs a hashtable with the mappings to a specific extmap
 * @note This is only used internally, and will be ignored if provided; in plugins, you should stick to JANUS_SDP_OA_EXTENSION */
JANUS_SDP_OA_EXTENSIONS,
/*! \brief When generating an answer (this is ignored for offers), accept this extension (by default, we reject them all; can be used multiple times) */
JANUS_SDP_OA_ACCEPT_EXTMAP,
/*! \brief When generating an offer (this is ignored for answers), use this payload type (depends on value that follows) */
JANUS_SDP_OA_PT,
/*! \brief When generating an offer or answer automatically, add this custom fmtp string
 * @note When dealing with video, this property is ignored if JANUS_SDP_OA_VP9_PROFILE or JANUS_SDP_OA_H264_PROFILE is used on a compliant codec. */
JANUS_SDP_OA_FMTP,
/*! \brief When generating an offer or answer automatically, do or do not negotiate telephone events (FIXME telephone-event/8000 only, true by default) */
JANUS_SDP_OA_AUDIO_DTMF,
/*! \brief When generating an offer or answer automatically, use this profile for VP9 (depends on value that follows) */
JANUS_SDP_OA_VP9_PROFILE,
/*! \brief When generating an offer or answer automatically, use this profile for H.264 (depends on value that follows) */
JANUS_SDP_OA_H264_PROFILE,
/*! \brief When generating an offer or answer automatically, do or do not add the rtcpfb attributes we typically negotiate (fir, nack, pli, remb; true by defaukt) */
JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS,
/*! \brief When generating an offer (this is ignored for answers), use the old "DTLS/SCTP" instead of the new "UDP/DTLS/SCTP (depends on what follows, false by default) */
JANUS_SDP_OA_DATA_LEGACY,
/*! \brief MUST be used as the last argument in janus_sdp_generate_offer, janus_sdp_generate_offer_mline and janus_sdp_generate_answer */
JANUS_SDP_OA_DONE = 0
} janus_sdp_oa_type;
const char *janus_sdp_oa_type_str(janus_sdp_oa_type type);

/*! \brief Method to generate a janus_sdp offer, using variable arguments to dictate
 * what to negotiate (e.g., in terms of media to offer, directions, etc.). Variable
 * arguments are in the form of a sequence of name-value terminated by a JANUS_SDP_OA_DONE, e.g.:
 \verbatim
	janus_sdp *offer = janus_sdp_generate_offer("My session", "127.0.0.1",
		JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
			JANUS_SDP_OA_PT, 100,
			JANUS_SDP_OA_DIRECTION, JANUS_SDP_SENDONLY,
			JANUS_SDP_OA_CODEC, "opus",
		JANUS_SDP_OA_MLINE, JANUS_SDP_VIDEO,
			JANUS_SDP_OA_PT, 101,
			JANUS_SDP_OA_DIRECTION, JANUS_SDP_RECVONLY,
			JANUS_SDP_OA_CODEC, "vp8",
 \endverbatim
 * to offer a \c sendonly Opus audio stream being offered with 100 as
 * payload type, and a \c recvonly VP8 video stream with 101 as payload type.
 * Refer to the property names in the header file for a complete
 * list of how you can drive the offer. Other media streams can be added,
 * as long as you prefix/specify them with JANUS_SDP_OA_MLINE as done here.
 * The default, if not specified, is to not offer anything, meaning it
 * will be up to you to add m-lines subsequently.
 * @param[in] name The session name (if NULL, a default value will be set)
 * @param[in] address The IP to set in o= and c= fields (if NULL, a default value will be set)
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise */
janus_sdp *janus_sdp_generate_offer(const char *name, const char *address, ...);
/*! \brief Method to add a single m-line to a new offer, using the same
 * variable arguments janus_sdp_generate_offer supports. This is useful
 * whenever you need to create a new offer, but don't know in advance
 * how many m-lines you'll need, or it would be hard to do programmatically
 * in a single call to janus_sdp_generate_offer. The first argument
 * MUST be JANUS_SDP_OA_MLINE, specifying the type of the media.
 * \note In case case you add audio and don't specify anything else, the
 * default is to use Opus and payload type 111. For video, the default
 * is VP8 and payload type 96. The default media direction is \c sendrecv.
 * @param[in] offer The Janus SDP offer to add the new m-line to
 * @returns 0 if successful, a negative integer othwerwise */
int janus_sdp_generate_offer_mline(janus_sdp *offer, ...);
/*! \brief Method to generate a janus_sdp answer to a provided janus_sdp offer.
 * Notice that this doesn't address the individual m-lines: it will just
 * create an empty response, create the corresponding m-lines, but leave
 * them all "rejected". To answer each m-line you'll have to iterate on
 * the offer m-lines and call janus_sdp_generate_answer_mline instead, e.g.:
 \verbatim
	janus_sdp *answer = janus_sdp_generate_answer(offer);
	GList *temp = offer->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		janus_sdp_generate_answer_mline(offer, answer, m,
			[..]
			JANUS_SDP_OA_DONE);
		temp = temp->next;
	}
 \endverbatim
 * to only accept the audio stream being offered, but as \c recvonly, use Opus
 * and reject both video and datachannels. Refer to the property names in
 * the header file for a complete list of how you can drive the answer.
 * The default, if not specified, is to accept everything as \c sendrecv.
 * @param[in] offer The Janus SDP offer to respond to
 * @returns A pointer to a janus_sdp object, if successful, NULL otherwise */
janus_sdp *janus_sdp_generate_answer(janus_sdp *offer);
/*! \brief Method to respond to a single m-line in an offer, using the same
 * variable arguments janus_sdp_generate_offer_mline supports. The first
 * argument MUST be JANUS_SDP_OA_MLINE, specifying the type of the media, e.g.:
 \verbatim
	janus_sdp_generate_answer_mline(offer, answer, offer_mline,
		JANUS_SDP_OA_MLINE, JANUS_SDP_AUDIO,
			JANUS_SDP_OA_CODEC, "opus",
			JANUS_SDP_OA_DIRECTION, JANUS_SDP_RECVONLY,
		JANUS_SDP_OA_DONE);
 \endverbatim
 * to respond to an offered m-line with recvonly audio and use Opus.
 * @param[in] offer The Janus SDP offer
 * @param[in] answer The Janus SDP answer to add the new m-line to
 * @param[in] offered The Janus SDP m-line from the offer to respond to
 * @returns 0 if successful, a negative integer othwerwise */
int janus_sdp_generate_answer_mline(janus_sdp *offer, janus_sdp *answer, janus_sdp_mline *offered, ...);

/*! \brief Helper to get the payload type associated to a specific codec in an m-line
 * @note This version doesn't involve profiles, which means that in case
 * of multiple payload types associated to the same codec because of
 * different profiles (e.g., VP9 and H.264), this will simply return the
 * first payload type associated with it the codec itself.
 * @param sdp The Janus SDP instance to process
 * @param index The m-line to refer to (use -1 for the first m-line that matches)
 * @param codec The codec to find, as a string
 * @returns The payload type, if found, or -1 otherwise */
int janus_sdp_get_codec_pt(janus_sdp *sdp, int index, const char *codec);

/*! \brief Helper to get the payload type associated to a specific codec,
 * in an m-line, taking into account a codec profile as a hint as well
 * @note The profile will only be used if the codec supports it, and the
 * core is aware of it: right now, this is only VP9 and H.264. If the codec
 * is there but the profile is not found, then no payload type is returned.
 * @param sdp The Janus SDP instance to process
 * @param index The m-line to refer to (use -1 for the first m-line that matches)
 * @param codec The codec to find, as a string
 * @param profile The codec profile to use as a hint, as a string
 * @returns The payload type, if found, or -1 otherwise */
int janus_sdp_get_codec_pt_full(janus_sdp *sdp, int index, const char *codec, const char *profile);

/*! \brief Helper to get the codec name associated to a specific payload type in an m-line
 * @param sdp The Janus SDP instance to process
 * @param index The m-line to refer to (use -1 for the first m-line that matches)
 * @param pt The payload type to find
 * @returns The codec name, if found, or NULL otherwise */
const char *janus_sdp_get_codec_name(janus_sdp *sdp, int index, int pt);

/*! \brief Helper to get the rtpmap associated to a specific codec
 * @param codec The codec name, as a string (e.g., "opus")
 * @returns The rtpmap value, if found (e.g., "opus/48000/2"), or NULL otherwise */
const char *janus_sdp_get_codec_rtpmap(const char *codec);

/*! \brief Helper to get the fmtp associated to a specific payload type
 * @param sdp The Janus SDP instance to process
 * @param index The m-line to refer to (use -1 for the first m-line that matches)
 * @param pt The payload type to find
 * @returns The fmtp content, if found, or NULL otherwise */
const char *janus_sdp_get_fmtp(janus_sdp *sdp, int index, int pt);

#endif
