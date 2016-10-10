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
	JANUS_SDP_INACTIVE
} janus_sdp_mdirection;

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
	int b_value;
	/*! \brief Media direction */
	janus_sdp_mdirection direction;
	/*! \brief List of m-line attributes */
	GList *attributes;
} janus_sdp_mline;

/*! \brief SDP a= attribute representation */
typedef struct janus_sdp_attribute {
	/*! \brief Attribute name */
	char *name;
	/*! \brief Attribute value */
	char *value;
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

/*! \brief Method to free a Janus SDP object
 * @param[in] sdp The Janus SDP object to free */
void janus_sdp_free(janus_sdp *sdp);

#endif
